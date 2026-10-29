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
	use crate::testing::fdr::{DefaultCache, FdrConfig, RefinementChecker, RefinementOutcome};
	use crate::testing::specs::csp::{Event, Process, ProcessBuildError, State};

	/// A process that can stop at `Idle`, which also offers `a`, and at
	/// `Done`, which `a` leads to.
	fn accepting() -> Result<Process, ProcessBuildError> {
		Process::builder("Accepting")
			.initial_state(State("Idle"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_transition(State("Idle"), Event("a"), State("Done"))
			.add_terminal(State("Idle"))
			.add_terminal(State("Done"))
			.build()
	}

	/// The process of [`accepting`] with `Done` its one accepting state, so
	/// `Idle` refuses `b` alone.
	fn idling() -> Result<Process, ProcessBuildError> {
		Process::builder("Idling")
			.initial_state(State("Idle"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_transition(State("Idle"), Event("a"), State("Done"))
			.add_terminal(State("Done"))
			.build()
	}

	/// A process whose hidden `t` and `u` take `S1` to `S2` and back, with the
	/// observable exit `b` at `S2`, so it can diverge after `a`.
	fn spinning() -> Result<Process, ProcessBuildError> {
		Process::builder("Spinning")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_hidden(Event("t"))
			.add_hidden(Event("u"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_transition(State("S1"), Event("t"), State("S2"))
			.add_transition(State("S2"), Event("u"), State("S1"))
			.add_transition(State("S2"), Event("b"), State("S3"))
			.add_terminal(State("S3"))
			.build()
	}

	/// A process that takes `a`, then spins on the hidden `t` at `S1`, so it
	/// can diverge after one event.
	fn spinning_after_a() -> Result<Process, ProcessBuildError> {
		Process::builder("SpinningAfterA")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_hidden(Event("t"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_transition(State("S1"), Event("t"), State("S1"))
			.build()
	}

	/// A process that takes `a`, then `b`, then spins on the hidden `t` at
	/// `S2`, so it can diverge after two events.
	fn spinning_after_a_b() -> Result<Process, ProcessBuildError> {
		Process::builder("SpinningAfterAB")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_hidden(Event("t"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_transition(State("S1"), Event("b"), State("S2"))
			.add_transition(State("S2"), Event("t"), State("S2"))
			.build()
	}

	/// A process that takes `a`, then stops at the accepting `S1`.
	fn stopping_after_a() -> Result<Process, ProcessBuildError> {
		Process::builder("StoppingAfterA")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_terminal(State("S1"))
			.build()
	}

	/// A process that takes `a`, then the hidden `t` to the accepting `S2`.
	fn settling_after_a() -> Result<Process, ProcessBuildError> {
		Process::builder("SettlingAfterA")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_hidden(Event("t"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_transition(State("S1"), Event("t"), State("S2"))
			.add_terminal(State("S2"))
			.build()
	}

	/// A process that takes `a` or `b` at `S0` and comes back, so its traces
	/// of at most 14 events number 32,767, past `MAX_VISITED`.
	fn looping_on_a_and_b() -> Result<Process, ProcessBuildError> {
		Process::builder("LoopingOnAAndB")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_transition(State("S0"), Event("a"), State("S0"))
			.add_transition(State("S0"), Event("b"), State("S0"))
			.build()
	}

	/// A process over `a` and `b` that stops at its accepting initial state.
	fn stopped() -> Result<Process, ProcessBuildError> {
		Process::builder("Stopped")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_terminal(State("S0"))
			.build()
	}

	/// A process over `a` and `b` that takes `event` once, then stops at the
	/// accepting `S1`.
	fn once(event: Event) -> Result<Process, ProcessBuildError> {
		Process::builder("Once")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_transition(State("S0"), event, State("S1"))
			.add_terminal(State("S1"))
			.build()
	}

	/// A process whose `S0` offers `a` beside the hidden `t`, which leads to
	/// `b`.
	fn hidden_beside_a() -> Result<Process, ProcessBuildError> {
		Process::builder("HiddenBesideA")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_hidden(Event("t"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_transition(State("S0"), Event("t"), State("S2"))
			.add_transition(State("S2"), Event("b"), State("S3"))
			.add_terminal(State("S1"))
			.add_terminal(State("S3"))
			.build()
	}

	/// A process whose hidden `t` and `u` branch at `S0`, to `a` and to `b`.
	fn two_hidden_branches() -> Result<Process, ProcessBuildError> {
		Process::builder("TwoHiddenBranches")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_hidden(Event("t"))
			.add_hidden(Event("u"))
			.add_transition(State("S0"), Event("t"), State("S1"))
			.add_transition(State("S0"), Event("u"), State("S2"))
			.add_transition(State("S1"), Event("a"), State("S3"))
			.add_transition(State("S2"), Event("b"), State("S4"))
			.add_terminal(State("S3"))
			.add_terminal(State("S4"))
			.build()
	}

	/// A process whose `e`, in the observable and in the hidden alphabet,
	/// takes `S0` to the accepting `S1`.
	fn e_in_both_alphabets() -> Result<Process, ProcessBuildError> {
		Process::builder("EInBothAlphabets")
			.initial_state(State("S0"))
			.add_observable(Event("e"))
			.add_hidden(Event("e"))
			.add_transition(State("S0"), Event("e"), State("S1"))
			.add_terminal(State("S1"))
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

	#[test]
	fn a_reachable_hidden_cycle_makes_its_trace_a_divergence() -> Result<(), ProcessBuildError> {
		let process = spinning()?;
		let mut checker = checker_of(&process);

		let (divergences, _complete) = checker.compute_divergences(&process, 8);
		let after_a = HashSet::from([vec![Event("a")]]);
		assert_eq!(divergences, after_a, "`S1` and `S2` can spin after `a`");
		Ok(())
	}

	#[test]
	fn an_accepting_state_fails_with_every_observable_event() -> Result<(), ProcessBuildError> {
		let process = accepting()?;
		let mut checker = checker_of(&process);

		let (failures, _complete) = checker.compute_failures(&process, 8);
		let refused_at_idle = (vec![], HashSet::from([Event("a"), Event("b")]));
		assert!(failures.contains(&refused_at_idle), "the failures were {failures:?}");
		Ok(())
	}

	#[test]
	fn a_divergence_after_max_depth_events_is_a_divergence() -> Result<(), ProcessBuildError> {
		let process = spinning_after_a()?;
		let mut checker = checker_of(&process);

		let (divergences, _complete) = checker.compute_divergences(&process, 1);
		let after_a = HashSet::from([vec![Event("a")]]);
		assert_eq!(divergences, after_a, "`S1` spins after one event, the bound");
		Ok(())
	}

	#[test]
	fn a_failure_after_max_depth_events_is_a_failure() -> Result<(), ProcessBuildError> {
		let process = spinning()?;
		let mut checker = checker_of(&process);

		let (failures, _complete) = checker.compute_failures(&process, 2);
		let refused_at_s3 = (vec![Event("a"), Event("b")], HashSet::from([Event("a"), Event("b")]));
		assert!(failures.contains(&refused_at_s3), "the failures were {failures:?}");
		Ok(())
	}

	#[test]
	fn the_search_takes_no_observable_step_past_max_depth() -> Result<(), ProcessBuildError> {
		let process = spinning_after_a_b()?;
		let mut checker = checker_of(&process);

		let (divergences, _complete) = checker.compute_divergences(&process, 1);
		assert!(divergences.is_empty(), "`S2` lies two events deep, past the bound of one");
		Ok(())
	}

	#[test]
	fn the_trace_search_takes_no_observable_step_past_max_depth() -> Result<(), ProcessBuildError> {
		let process = spinning_after_a_b()?;
		let mut checker = checker_of(&process);

		let (traces, _complete) = checker.compute_traces(&process, 1);
		let up_to_one_event = HashSet::from([vec![], vec![Event("a")]]);
		assert_eq!(traces, up_to_one_event, "`b` lies two events deep, past the bound of one");
		Ok(())
	}

	#[test]
	fn divergence_refinement_refutes_a_divergence_at_the_depth_bound() -> Result<(), ProcessBuildError> {
		let spec = stopping_after_a()?;
		let subject = spinning_after_a()?;
		let mut checker = checker_under(&spec, FdrConfig { max_depth: 1, ..Default::default() });

		let outcome = checker.check_divergence_refinement(&spec, &subject);
		assert_eq!(outcome, RefinementOutcome::Violated(vec![Event("a")]));
		Ok(())
	}

	#[test]
	fn a_divergence_search_past_its_timeout_is_incomplete() -> Result<(), ProcessBuildError> {
		let process = spinning()?;
		let mut checker = checker_under(&process, FdrConfig { timeout_ms: 0, ..Default::default() });

		let (_divergences, complete) = checker.compute_divergences(&process, 8);
		assert!(!complete, "a search that ran out of time claims no completeness");
		Ok(())
	}

	#[test]
	fn a_failure_behind_a_hidden_step_at_max_depth_is_a_failure() -> Result<(), ProcessBuildError> {
		let process = settling_after_a()?;
		let mut checker = checker_of(&process);

		let (failures, _complete) = checker.compute_failures(&process, 1);
		let refused_at_s2 = (vec![Event("a")], HashSet::from([Event("a")]));
		assert!(failures.contains(&refused_at_s2), "the failures were {failures:?}");
		Ok(())
	}

	#[test]
	fn a_divergence_search_past_its_timeout_caches_its_incompleteness() -> Result<(), ProcessBuildError> {
		let process = spinning()?;
		let mut checker = checker_under(&process, FdrConfig { timeout_ms: 0, ..Default::default() });
		let (_divergences, _complete) = checker.compute_divergences(&process, 8);

		let (_cached, complete) = checker.compute_divergences(&process, 8);
		assert!(!complete, "the cache keeps the incompleteness of the first search");
		Ok(())
	}

	#[test]
	fn a_divergence_search_past_its_limits_is_incomplete() -> Result<(), ProcessBuildError> {
		let process = looping_on_a_and_b()?;
		let mut checker = checker_of(&process);

		let (_divergences, complete) = checker.compute_divergences(&process, 14);
		assert!(!complete, "32,767 pairs of state and trace pass the visited limit");
		Ok(())
	}

	#[test]
	fn trace_refinement_refutes_an_event_after_an_accepting_state() -> Result<(), ProcessBuildError> {
		let spec = stopped()?;
		let subject = accepting()?;
		let mut checker = checker_of(&subject);

		let outcome = checker.check_trace_refinement(&spec, &subject);
		assert_eq!(outcome, RefinementOutcome::Violated(vec![Event("a")]));
		Ok(())
	}

	#[test]
	fn trace_refinement_refutes_an_event_beside_a_hidden_step() -> Result<(), ProcessBuildError> {
		let spec = once(Event("b"))?;
		let subject = hidden_beside_a()?;
		let mut checker = checker_of(&subject);

		let outcome = checker.check_trace_refinement(&spec, &subject);
		assert_eq!(outcome, RefinementOutcome::Violated(vec![Event("a")]));
		Ok(())
	}

	#[test]
	fn trace_refinement_refutes_an_event_after_a_second_hidden_branch() -> Result<(), ProcessBuildError> {
		let spec = once(Event("a"))?;
		let subject = two_hidden_branches()?;
		let mut checker = checker_of(&subject);

		let outcome = checker.check_trace_refinement(&spec, &subject);
		assert_eq!(outcome, RefinementOutcome::Violated(vec![Event("b")]));
		Ok(())
	}

	#[test]
	fn divergence_refinement_holds_for_an_extension_of_a_spec_divergence() -> Result<(), ProcessBuildError> {
		let spec = spinning_after_a()?;
		let subject = spinning_after_a_b()?;
		let mut checker = checker_of(&spec);

		let outcome = checker.check_divergence_refinement(&spec, &subject);
		assert_eq!(outcome, RefinementOutcome::Holds { complete: true });
		Ok(())
	}

	#[test]
	fn the_observable_action_of_an_event_in_both_alphabets_extends_the_trace() -> Result<(), ProcessBuildError> {
		let process = e_in_both_alphabets()?;
		let mut checker = checker_of(&process);

		let (traces, _complete) = checker.compute_traces(&process, 8);
		assert!(traces.contains(&vec![Event("e")]), "the traces were {traces:?}");
		Ok(())
	}

	#[test]
	fn the_spec_search_matches_the_observable_action_of_an_event_in_both_alphabets() -> Result<(), ProcessBuildError> {
		let process = e_in_both_alphabets()?;
		let mut checker = checker_of(&process);

		let outcome = checker.check_trace_refinement(&process, &process);
		assert_eq!(outcome, RefinementOutcome::Holds { complete: true });
		Ok(())
	}

	#[test]
	fn failures_refinement_refutes_a_refusal_that_the_spec_lacks() -> Result<(), ProcessBuildError> {
		let spec = idling()?;
		let subject = accepting()?;
		let mut checker = checker_of(&subject);

		let outcome = checker.check_failures_refinement(&spec, &subject);
		let refused_at_idle = (vec![], HashSet::from([Event("a"), Event("b")]));
		assert_eq!(outcome, RefinementOutcome::Violated(refused_at_idle));
		Ok(())
	}

	#[test]
	fn failures_refinement_holds_for_a_refusal_that_the_spec_allows() -> Result<(), ProcessBuildError> {
		let spec = accepting()?;
		let subject = idling()?;
		let mut checker = checker_of(&subject);

		let outcome = checker.check_failures_refinement(&spec, &subject);
		assert_eq!(outcome, RefinementOutcome::Holds { complete: true });
		Ok(())
	}

	#[test]
	fn a_set_cached_at_one_depth_answers_no_search_at_another() -> Result<(), ProcessBuildError> {
		let process = spinning_after_a_b()?;
		let mut checker = checker_of(&process);
		let (_within_one, _complete) = checker.compute_divergences(&process, 1);

		let (within_eight, _complete) = checker.compute_divergences(&process, 8);
		let after_a_b = HashSet::from([vec![Event("a"), Event("b")]]);
		assert_eq!(within_eight, after_a_b, "`S2` lies two events deep, within a bound of eight");
		Ok(())
	}

	#[test]
	fn a_cache_serves_each_process_its_own_set() -> Result<(), ProcessBuildError> {
		let first = once(Event("a"))?;
		let second = once(Event("b"))?;
		let mut checker = checker_of(&first);
		let (_first_traces, _complete) = checker.compute_traces(&first, 8);

		let (traces, _complete) = checker.compute_traces(&second, 8);
		let empty_and_b = HashSet::from([vec![], vec![Event("b")]]);
		assert_eq!(traces, empty_and_b, "the two processes share a name alone");
		Ok(())
	}
}
