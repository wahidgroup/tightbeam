//! The FDR refinement checking subsystem.
//!
//! [`DefaultRefinementChecker`] implements [`RefinementChecker`] for trace,
//! failures, and divergence refinement.

use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use crate::clock::{Clock, MonotonicInstant, SystemClock};
use crate::testing::fdr::config::FdrConfig;
use crate::testing::fdr::explorer::{CacheKey, MemoizationCache, RefinementChecker, RefinementOutcome};
use crate::testing::fdr::verdict::{Failure, Trace};
use crate::testing::specs::csp::{Action, Event, Process, State};

/// The result of a search for a single trace in a specification.
///
/// It distinguishes a definitive absence from a search cut short by a timeout
/// or a resource limit, so a bounded search reports `Inconclusive` instead of a
/// counterexample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceSearch {
	Found,
	Absent,
	Inconclusive,
}

/// The time budget of one search, measured from its start instant.
struct TimeoutChecker {
	start: MonotonicInstant,
	timeout: Duration,
}

impl TimeoutChecker {
	fn new(timeout_ms: u64) -> Self {
		Self { start: SystemClock.monotonic(), timeout: Duration::from_millis(timeout_ms) }
	}

	fn is_expired(&self) -> bool {
		let elapsed = SystemClock.monotonic().saturating_duration_since(self.start);
		elapsed >= self.timeout
	}
}

/// The default [`RefinementChecker`], which explores a [`Process`]
/// breadth-first under the configured bounds.
pub struct DefaultRefinementChecker<'a, M>
where
	M: MemoizationCache,
{
	/// The search configuration, which sets the depth bound and the timeout.
	config: Arc<FdrConfig>,
	/// The process under verification.
	process: &'a Process,
	/// The shared memoization cache for computed traces, failures, and
	/// divergences.
	cache: Rc<RefCell<M>>,
}

impl<'a, M> DefaultRefinementChecker<'a, M>
where
	M: MemoizationCache,
{
	/// Creates a refinement checker over `process` that shares `cache`.
	pub fn new(process: &'a Process, config: Arc<FdrConfig>, cache: Rc<RefCell<M>>) -> Self {
		Self { config, process, cache }
	}

	/// Returns the search configuration.
	pub fn config(&self) -> &FdrConfig {
		&self.config
	}

	/// Returns the process under verification.
	pub fn process(&self) -> &Process {
		self.process
	}

	/// Returns [`RefinementChecker::MAX_TRACES`] for this checker type.
	fn max_traces() -> usize {
		<Self as RefinementChecker>::MAX_TRACES
	}

	fn max_queue_size() -> usize {
		<Self as RefinementChecker>::MAX_QUEUE_SIZE
	}

	fn max_visited() -> usize {
		<Self as RefinementChecker>::MAX_VISITED
	}

	/// Returns whether the queue, the visited set, or the trace set has reached
	/// its bound.
	fn check_limits(queue_len: usize, visited_len: usize, traces_count: usize) -> bool {
		queue_len >= Self::max_queue_size() || visited_len >= Self::max_visited() || traces_count >= Self::max_traces()
	}

	/// Applies one step to a trace. A hidden step leaves the trace as it is,
	/// and an observable step extends it by its event.
	fn process_transition(trace: Trace, action: &Action) -> Trace {
		if action.is_hidden() {
			trace
		} else {
			let mut new_trace = trace;
			new_trace.push(action.event);
			new_trace
		}
	}

	/// A breadth-first traversal with a per-state callback, which the failure
	/// and divergence computations run on.
	///
	/// - `on_state` runs once at each pair of state and trace that the traversal reaches.
	/// - A state takes each step that [`Action::keeps_within`] admits, so the
	///   traversal visits a state whose trace holds `max_depth` events, and
	///   that state takes its hidden steps alone. The traversal therefore
	///   covers each trace of at most `max_depth` events.
	/// - The returned `bool` is `true` when the traversal ran to exhaustion,
	///   and `false` when the queue limit, the visited limit, or the timeout
	///   cut it.
	fn bfs_with_callbacks<T, FState>(
		&self,
		process: &Process,
		max_depth: usize,
		mut data: T,
		mut on_state: FState,
	) -> (T, bool)
	where
		FState: FnMut(&mut T, State, &Trace),
	{
		let timeout_checker = TimeoutChecker::new(self.config.timeout_ms);
		let mut queue = VecDeque::new();
		let mut visited = HashSet::new();
		let mut complete = true;
		queue.push_back((process.initial, Vec::new()));

		while let Some((state, trace)) = queue.pop_front() {
			let at_a_limit = queue.len() >= Self::max_queue_size() || visited.len() >= Self::max_visited();
			if at_a_limit || timeout_checker.is_expired() {
				complete = false;
				break;
			}

			let visit_key = (state, trace.clone());
			if visited.contains(&visit_key) {
				continue;
			}
			visited.insert(visit_key);

			on_state(&mut data, state, &trace);

			// A hidden step keeps the trace's length, so a state at the bound
			// takes it.
			for action in process.enabled(state) {
				if !action.keeps_within(&trace, max_depth) {
					continue;
				}

				for next_state in process.step(state, &action.event) {
					let next_trace = Self::process_transition(trace.clone(), &action);
					queue.push_back((next_state, next_trace));
				}
			}
		}

		(data, complete)
	}

	/// Returns whether the specification failures hold a failure with the trace
	/// `impl_trace` whose refusal set contains `impl_refusal` (impl_refusal ⊆
	/// spec_refusal).
	fn failure_exists_in_spec(
		spec_failures: impl AsRef<[Failure]>,
		impl_trace: &Trace,
		impl_refusal: &HashSet<Event>,
	) -> bool {
		let spec_failures = spec_failures.as_ref();
		for (spec_trace, spec_refusal) in spec_failures {
			if spec_trace == impl_trace && impl_refusal.is_subset(spec_refusal) {
				return true;
			}
		}
		false
	}

	/// Searches for one trace in a spec, which costs less than a computation
	/// of every trace of the spec.
	///
	/// The search is a BFS over `(state, matched-prefix-length)` pairs:
	///
	/// - An observable action that matches the next target event advances the prefix.
	/// - A hidden (τ) action advances the state and leaves the prefix as it is.
	///
	/// The shared visited set is the only bound on τ exploration. A timeout or
	/// a resource limit yields `Inconclusive` instead of `Absent`, because a
	/// bounded search that runs out of budget is not a counterexample.
	fn trace_exists_in_spec(
		spec: &Process,
		target_trace: &Trace,
		max_depth: usize,
		max_queue_size: usize,
		max_visited: usize,
		timeout_checker: &TimeoutChecker,
	) -> TraceSearch {
		if target_trace.len() > max_depth {
			return TraceSearch::Absent;
		}

		let mut queue = VecDeque::new();
		let mut visited = HashSet::new();
		queue.push_back((spec.initial, 0usize));

		while let Some((state, trace_idx)) = queue.pop_front() {
			if timeout_checker.is_expired() {
				return TraceSearch::Inconclusive;
			}

			if queue.len() >= max_queue_size || visited.len() >= max_visited {
				return TraceSearch::Inconclusive;
			}

			if !visited.insert((state, trace_idx)) {
				continue;
			}

			if trace_idx >= target_trace.len() {
				return TraceSearch::Found;
			}

			let next_event = &target_trace[trace_idx];
			for action in spec.enabled(state) {
				if action.is_hidden() {
					for next_state in spec.step(state, &action.event) {
						queue.push_back((next_state, trace_idx));
					}
				} else if &action.event == next_event {
					for next_state in spec.step(state, &action.event) {
						queue.push_back((next_state, trace_idx + 1));
					}
				}
			}
		}

		TraceSearch::Absent
	}
}

impl<'a, M> RefinementChecker for DefaultRefinementChecker<'a, M>
where
	M: MemoizationCache,
{
	/// Checks trace refinement, where spec ⊑ impl means traces(impl) ⊆
	/// traces(spec).
	///
	/// The check reads every impl trace, because a check of the longest trace
	/// alone misses the forbidden events on the sibling branches of an impl
	/// that branches.
	///
	/// Reference: Roscoe (1998, 2010)
	fn check_trace_refinement(&mut self, spec: &Process, impl_process: &Process) -> RefinementOutcome<Trace> {
		let (impl_traces, impl_complete) = self.compute_traces(impl_process, self.config.max_depth);

		// The check projects each trace onto the observable alphabet of the
		// spec before the comparison, as `Process::project` explains.
		let projected: HashSet<Trace> = impl_traces.iter().map(|trace| spec.project(trace)).collect();

		// Sorted iteration keeps the reported witness deterministic, whatever
		// the order of the HashSet.
		let mut ordered: Vec<&Trace> = projected.iter().collect();
		ordered.sort_unstable();

		// One time budget covers the whole membership scan so a large
		// trace set cannot multiply the configured timeout.
		let timeout_checker = TimeoutChecker::new(self.config.timeout_ms);
		let max_queue = Self::max_queue_size();
		let max_visited = Self::max_visited();

		let mut inconclusive = false;
		for trace in ordered {
			match Self::trace_exists_in_spec(
				spec,
				trace,
				self.config.max_depth,
				max_queue,
				max_visited,
				&timeout_checker,
			) {
				TraceSearch::Found => {}
				TraceSearch::Absent => return RefinementOutcome::Violated(trace.clone()),
				TraceSearch::Inconclusive => inconclusive = true,
			}
		}

		if inconclusive {
			return RefinementOutcome::Inconclusive;
		}

		RefinementOutcome::Holds { complete: impl_complete }
	}

	/// Checks failures refinement, where spec ⊑ impl means failures(impl) ⊆
	/// failures(spec).
	///
	/// For each impl failure (trace, impl_refusal), the spec must hold a
	/// failure (trace, spec_refusal) where impl_refusal ⊆ spec_refusal.
	///
	/// Reference: Roscoe (1998, 2010)
	fn check_failures_refinement(&mut self, spec: &Process, impl_process: &Process) -> RefinementOutcome<Failure> {
		let (spec_failures, spec_complete) = self.compute_failures(spec, self.config.max_depth);
		let (impl_failures, impl_complete) = self.compute_failures(impl_process, self.config.max_depth);
		for (impl_trace, impl_refusal) in &impl_failures {
			if !<DefaultRefinementChecker<'a, M>>::failure_exists_in_spec(&spec_failures, impl_trace, impl_refusal) {
				// A missing entry in a truncated spec set is not a proven
				// violation: it may live in the unexplored remainder.
				if !spec_complete {
					return RefinementOutcome::Inconclusive;
				}

				return RefinementOutcome::Violated((impl_trace.clone(), impl_refusal.clone()));
			}
		}

		RefinementOutcome::Holds { complete: spec_complete && impl_complete }
	}

	/// Checks divergence refinement, where spec ⊑ impl means
	/// divergences(impl) ⊆ divergences(spec).
	///
	/// A divergence after a trace makes each extension of that trace a
	/// divergence (axiom D1), so the spec covers an impl divergence when it
	/// diverges after a prefix of it, the whole trace included.
	///
	/// Reference: Roscoe (1998, 2010)
	fn check_divergence_refinement(&mut self, spec: &Process, impl_process: &Process) -> RefinementOutcome<Trace> {
		let (spec_divergences, spec_complete) = self.compute_divergences(spec, self.config.max_depth);
		let (impl_divergences, impl_complete) = self.compute_divergences(impl_process, self.config.max_depth);

		let mut ordered: Vec<&Trace> = impl_divergences.iter().collect();
		ordered.sort_unstable();

		for impl_div in ordered {
			let mut prefixes = (0..=impl_div.len()).filter_map(|end| impl_div.get(..end));
			let covered = prefixes.any(|prefix| spec_divergences.contains(prefix));
			if !covered {
				if !spec_complete {
					return RefinementOutcome::Inconclusive;
				}

				return RefinementOutcome::Violated(impl_div.clone());
			}
		}

		RefinementOutcome::Holds { complete: spec_complete && impl_complete }
	}

	fn compute_traces(&mut self, process: &Process, max_depth: usize) -> (HashSet<Trace>, bool) {
		let key = CacheKey::new(process, max_depth);
		if let Some((cached, complete)) = self.cache.borrow().get_cached_traces(&key) {
			return (cached.into_iter().collect(), complete);
		}

		let timeout_checker = TimeoutChecker::new(self.config.timeout_ms);
		let mut traces = HashSet::new();
		traces.insert(Vec::new());

		let mut complete = true;
		let mut queue = VecDeque::new();
		let mut visited = HashSet::new();

		queue.push_back((process.initial, Vec::new()));

		while let Some((state, trace)) = queue.pop_front() {
			if timeout_checker.is_expired() {
				complete = false;
				break;
			}

			if Self::check_limits(queue.len(), visited.len(), traces.len()) {
				complete = false;
				break;
			}

			let visit_key = (state, trace.clone());
			if visited.contains(&visit_key) {
				continue;
			}

			visited.insert(visit_key);

			let enabled_actions = process.enabled(state);
			for action in enabled_actions {
				if !action.keeps_within(&trace, max_depth) {
					continue;
				}

				let next_states = process.step(state, &action.event);
				for next_state in next_states {
					if Self::check_limits(queue.len(), visited.len(), traces.len()) {
						complete = false;
						break;
					}

					let new_trace = Self::process_transition(trace.clone(), &action);
					if action.is_observable() {
						traces.insert(new_trace.clone());
					}

					queue.push_back((next_state, new_trace));
				}
			}
		}

		let traces_vec: Vec<Trace> = traces.iter().cloned().collect();
		self.cache.borrow_mut().cache_traces(key, traces_vec, complete);

		(traces, complete)
	}

	fn compute_failures(&mut self, process: &Process, max_depth: usize) -> (Vec<Failure>, bool) {
		let key = CacheKey::new(process, max_depth);
		if let Some((cached, complete)) = self.cache.borrow().get_cached_failures(&key) {
			return (cached, complete);
		}

		// The search records a failure at a stable or accepting state alone,
		// as `Process::failure_refusals` decides.
		let failures = Vec::new();
		let (failures, complete) = self.bfs_with_callbacks(process, max_depth, failures, |failures, state, trace| {
			if let Some(refusals) = self.compute_refusals(process, state) {
				let failure = (trace.clone(), refusals);
				if !failures.contains(&failure) {
					failures.push(failure);
				}
			}
		});

		self.cache.borrow_mut().cache_failures(key, failures.clone(), complete);

		(failures, complete)
	}

	/// Computes the divergences of `process`, each trace after which a state
	/// that the process reaches can diverge.
	///
	/// [`Process::divergent_states`] decides each state once, and the search
	/// reads that answer at each state and trace it reaches. The `bool` is
	/// `true` when the set covers each trace of at most `max_depth` events, and
	/// `false` when a timeout or a resource limit cut the search short.
	fn compute_divergences(&mut self, process: &Process, max_depth: usize) -> (HashSet<Trace>, bool) {
		let key = CacheKey::new(process, max_depth);
		if let Some((cached, complete)) = self.cache.borrow().get_cached_divergences(&key) {
			return (cached.into_iter().collect(), complete);
		}

		let divergent = process.divergent_states();
		let found = HashSet::new();
		let (divergences, complete) = self.bfs_with_callbacks(process, max_depth, found, |found, state, trace| {
			if divergent.contains(state) {
				found.insert(trace.clone());
			}
		});

		let divergences_vec: Vec<Trace> = divergences.iter().cloned().collect();
		self.cache.borrow_mut().cache_divergences(key, divergences_vec, complete);

		(divergences, complete)
	}
}

#[cfg(test)]
mod tests {
	use std::cell::RefCell;
	use std::collections::HashSet;
	use std::rc::Rc;
	use std::sync::Arc;

	use super::DefaultRefinementChecker;
	use crate::testing::fdr::verdict::{Failure, Trace};
	use crate::testing::fdr::{DefaultCache, FdrConfig, RefinementChecker, RefinementOutcome};
	use crate::testing::fixtures::TestProcess;
	use crate::testing::specs::csp::{Event, Process, State};

	/// A fixture that builds the process of a row.
	type Fixture = fn() -> Process;

	/// The process of [`TestProcess::accepting`] with `Done` its one accepting
	/// state, so `Idle` refuses `b` alone.
	fn idling() -> Process {
		TestProcess {
			observable: &["a", "b"],
			transitions: &[("Idle", "a", "Done")],
			terminal: &["Done"],
			..TestProcess::of("Idling", "Idle")
		}
		.build()
	}

	/// A process that takes `a`, then `b`, then spins on the hidden `t` at
	/// `S2`, so it can diverge after two events.
	fn spinning_after_a_b() -> Process {
		TestProcess {
			observable: &["a", "b"],
			hidden: &["t"],
			transitions: &[("S0", "a", "S1"), ("S1", "b", "S2"), ("S2", "t", "S2")],
			..TestProcess::of("SpinningAfterAB", "S0")
		}
		.build()
	}

	/// A process that takes `a`, then stops at the accepting `S1`.
	fn stopping_after_a() -> Process {
		TestProcess::chain("StoppingAfterA", &["S0", "S1"], &["a"])
	}

	/// A process that takes `a`, then the hidden `t` to the accepting `S2`.
	fn settling_after_a() -> Process {
		TestProcess {
			observable: &["a"],
			hidden: &["t"],
			transitions: &[("S0", "a", "S1"), ("S1", "t", "S2")],
			terminal: &["S2"],
			..TestProcess::of("SettlingAfterA", "S0")
		}
		.build()
	}

	/// A process that takes `a` or `b` at `S0` and comes back, so its traces
	/// of at most 14 events number 32,767, past `MAX_VISITED`.
	fn looping_on_a_and_b() -> Process {
		TestProcess {
			observable: &["a", "b"],
			transitions: &[("S0", "a", "S0"), ("S0", "b", "S0")],
			..TestProcess::of("LoopingOnAAndB", "S0")
		}
		.build()
	}

	/// A process over `a` and `b` that stops at its accepting initial state.
	fn stopped() -> Process {
		TestProcess { observable: &["a", "b"], terminal: &["S0"], ..TestProcess::of("Stopped", "S0") }.build()
	}

	/// A process over `a` and `b` that takes `event` once, then stops at the
	/// accepting `S1`. The event varies, so the process takes the builder that
	/// [`TestProcess`] wraps.
	fn once(event: &'static str) -> Process {
		Process::builder("Once")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_transition(State("S0"), Event(event), State("S1"))
			.add_terminal(State("S1"))
			.build()
			.expect("a process with an initial state builds")
	}

	/// A process whose `S0` offers `a` beside the hidden `t`, which leads to
	/// `b`.
	fn hidden_beside_a() -> Process {
		TestProcess {
			observable: &["a", "b"],
			hidden: &["t"],
			transitions: &[("S0", "a", "S1"), ("S0", "t", "S2"), ("S2", "b", "S3")],
			terminal: &["S1", "S3"],
			..TestProcess::of("HiddenBesideA", "S0")
		}
		.build()
	}

	/// A process whose hidden `t` and `u` branch at `S0`, to `a` and to `b`.
	fn two_hidden_branches() -> Process {
		TestProcess {
			observable: &["a", "b"],
			hidden: &["t", "u"],
			transitions: &[("S0", "t", "S1"), ("S0", "u", "S2"), ("S1", "a", "S3"), ("S2", "b", "S4")],
			terminal: &["S3", "S4"],
			..TestProcess::of("TwoHiddenBranches", "S0")
		}
		.build()
	}

	/// The checker of `process` under the default configuration.
	fn checker_of(process: &Process) -> DefaultRefinementChecker<'_, DefaultCache> {
		checker_under(process, FdrConfig::default())
	}

	/// The checker of `process` under `config`.
	fn checker_under(process: &Process, config: FdrConfig) -> DefaultRefinementChecker<'_, DefaultCache> {
		let cache = Rc::new(RefCell::new(DefaultCache::new()));
		DefaultRefinementChecker::new(process, Arc::new(config), cache)
	}

	/// The divergences of `process` within `depth` observable events.
	fn divergences_of(process: &Process, depth: usize) -> HashSet<Trace> {
		let (divergences, _complete) = checker_of(process).compute_divergences(process, depth);
		divergences
	}

	/// The failures of `process` within `depth` observable events.
	fn failures_of(process: &Process, depth: usize) -> Vec<Failure> {
		let (failures, _complete) = checker_of(process).compute_failures(process, depth);
		failures
	}

	/// The traces of `process` within `depth` observable events.
	fn traces_of(process: &Process, depth: usize) -> HashSet<Trace> {
		let (traces, _complete) = checker_of(process).compute_traces(process, depth);
		traces
	}

	// The divergences of a process are the traces after which it can spin on
	// hidden events, within the depth bound.
	crate::tb_cases! {
		fn the_divergence_search_finds((process, depth, divergences): (Fixture, usize, HashSet<Trace>)) {
			let found = divergences_of(&process(), depth);
			assert_eq!(found, divergences);
		}

		cases {
			/// `S1` and `S2` can spin after `a`.
			the_trace_of_a_reachable_hidden_cycle => (TestProcess::spinning, 8, HashSet::from([vec![Event("a")]])),
			/// `S1` spins after one event, the bound.
			a_divergence_after_max_depth_events => (
				TestProcess::spinning_after_a,
				1,
				HashSet::from([vec![Event("a")]]),
			),
			/// `S2` lies two events deep, past the bound of one.
			no_divergence_past_max_depth => (spinning_after_a_b, 1, HashSet::new()),
		}
	}

	// The failures of a process hold the refusal of each stable state it
	// reaches, within the depth bound.
	crate::tb_cases! {
		fn the_failures_include((process, depth, failure): (Fixture, usize, Failure)) {
			let found = failures_of(&process(), depth);
			assert!(found.contains(&failure));
		}

		cases {
			every_observable_event_at_an_accepting_state => (
				TestProcess::accepting,
				8,
				(vec![], HashSet::from([Event("a"), Event("b")])),
			),
			a_failure_after_max_depth_events => (
				TestProcess::spinning,
				2,
				(vec![Event("a"), Event("b")], HashSet::from([Event("a"), Event("b")])),
			),
			a_failure_behind_a_hidden_step_at_max_depth => (
				settling_after_a,
				1,
				(vec![Event("a")], HashSet::from([Event("a")])),
			),
		}
	}

	// A divergence search that runs out of time or past `MAX_VISITED` claims no
	// completeness.
	crate::tb_cases! {
		fn a_divergence_search_is_incomplete((process, config, depth): (Fixture, FdrConfig, usize)) {
			let process = process();
			let mut checker = checker_under(&process, config);

			let (_divergences, complete) = checker.compute_divergences(&process, depth);
			assert!(!complete);
		}

		cases {
			past_its_timeout => (TestProcess::spinning, FdrConfig { timeout_ms: 0, ..Default::default() }, 8),
			/// 32,767 pairs of state and trace pass the visited limit.
			past_the_visited_limit => (looping_on_a_and_b, FdrConfig::default(), 14),
		}
	}

	// Trace refinement refutes the first event of the subject that the spec
	// cannot follow, and names it as the witness.
	crate::tb_cases! {
		fn trace_refinement_refutes((spec, subject, witness): (Fixture, Fixture, Trace)) {
			let (spec, subject) = (spec(), subject());
			let mut checker = checker_of(&subject);

			let outcome = checker.check_trace_refinement(&spec, &subject);
			assert_eq!(outcome, RefinementOutcome::Violated(witness));
		}

		cases {
			an_event_after_an_accepting_state => (stopped, TestProcess::accepting, vec![Event("a")]),
			an_event_beside_a_hidden_step => (|| once("b"), hidden_beside_a, vec![Event("a")]),
			an_event_after_a_second_hidden_branch => (|| once("a"), two_hidden_branches, vec![Event("b")]),
		}
	}

	/// A trace search stops at the depth bound, so `b`, two events deep, lies
	/// past the bound of one.
	#[test]
	fn the_trace_search_takes_no_observable_step_past_max_depth() {
		let traces = traces_of(&spinning_after_a_b(), 1);
		assert_eq!(traces, HashSet::from([vec![], vec![Event("a")]]));
	}

	/// Divergence refinement refutes a subject that diverges at the depth
	/// bound where the spec stops.
	#[test]
	fn divergence_refinement_refutes_a_divergence_at_the_depth_bound() {
		let (spec, subject) = (stopping_after_a(), TestProcess::spinning_after_a());
		let mut checker = checker_under(&spec, FdrConfig { max_depth: 1, ..Default::default() });

		let outcome = checker.check_divergence_refinement(&spec, &subject);
		assert_eq!(outcome, RefinementOutcome::Violated(vec![Event("a")]));
	}

	/// The cache keeps the incompleteness of a divergence search that ran out
	/// of time, so its second answer claims no completeness either.
	#[test]
	fn a_divergence_search_past_its_timeout_caches_its_incompleteness() {
		let process = TestProcess::spinning();
		let mut checker = checker_under(&process, FdrConfig { timeout_ms: 0, ..Default::default() });
		let (_divergences, _complete) = checker.compute_divergences(&process, 8);

		let (_cached, complete) = checker.compute_divergences(&process, 8);
		assert!(!complete);
	}

	/// Divergence refinement holds for a subject whose divergences extend a
	/// divergence of the spec.
	#[test]
	fn divergence_refinement_holds_for_an_extension_of_a_spec_divergence() {
		let (spec, subject) = (TestProcess::spinning_after_a(), spinning_after_a_b());
		let mut checker = checker_of(&spec);

		let outcome = checker.check_divergence_refinement(&spec, &subject);
		assert_eq!(outcome, RefinementOutcome::Holds { complete: true });
	}

	/// The observable action of an event in both alphabets extends the trace.
	#[test]
	fn the_observable_action_of_an_event_in_both_alphabets_extends_the_trace() {
		let traces = traces_of(&TestProcess::e_in_both_alphabets(), 8);
		assert!(traces.contains(&vec![Event("e")]));
	}

	/// The search of a spec matches the observable action of an event in both
	/// alphabets, so the process refines itself.
	#[test]
	fn the_spec_search_matches_the_observable_action_of_an_event_in_both_alphabets() {
		let process = TestProcess::e_in_both_alphabets();
		let mut checker = checker_of(&process);

		let outcome = checker.check_trace_refinement(&process, &process);
		assert_eq!(outcome, RefinementOutcome::Holds { complete: true });
	}

	/// Failures refinement refutes the refusal of `a` and `b` at the accepting
	/// `Idle`, which the spec lacks.
	#[test]
	fn failures_refinement_refutes_a_refusal_that_the_spec_lacks() {
		let (spec, subject) = (idling(), TestProcess::accepting());
		let mut checker = checker_of(&subject);

		let outcome = checker.check_failures_refinement(&spec, &subject);
		let refused_at_idle = (vec![], HashSet::from([Event("a"), Event("b")]));
		assert_eq!(outcome, RefinementOutcome::Violated(refused_at_idle));
	}

	/// Failures refinement holds for a refusal that the spec allows.
	#[test]
	fn failures_refinement_holds_for_a_refusal_that_the_spec_allows() {
		let (spec, subject) = (TestProcess::accepting(), idling());
		let mut checker = checker_of(&subject);

		let outcome = checker.check_failures_refinement(&spec, &subject);
		assert_eq!(outcome, RefinementOutcome::Holds { complete: true });
	}

	/// A set cached at one depth answers no search at another, so `S2`, two
	/// events deep, lies within a bound of eight.
	#[test]
	fn a_set_cached_at_one_depth_answers_no_search_at_another() {
		let process = spinning_after_a_b();
		let mut checker = checker_of(&process);
		let (_within_one, _complete) = checker.compute_divergences(&process, 1);

		let (within_eight, _complete) = checker.compute_divergences(&process, 8);
		assert_eq!(within_eight, HashSet::from([vec![Event("a"), Event("b")]]));
	}

	/// A cache serves each process its own set, though the two processes share
	/// their name.
	#[test]
	fn a_cache_serves_each_process_its_own_set() {
		let (first, second) = (once("a"), once("b"));
		let mut checker = checker_of(&first);
		let (_first_traces, _complete) = checker.compute_traces(&first, 8);

		let (traces, _complete) = checker.compute_traces(&second, 8);
		assert_eq!(traces, HashSet::from([vec![], vec![Event("b")]]));
	}
}
