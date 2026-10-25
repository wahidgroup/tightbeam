//! The FDR refinement checking subsystem.
//!
//! [`DefaultRefinementChecker`] implements [`RefinementChecker`] for trace,
//! failures, and divergence refinement.

use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use crate::testing::fdr::config::FdrConfig;
use crate::testing::fdr::explorer::{MemoizationCache, RefinementChecker, RefinementOutcome};
use crate::testing::fdr::verdict::{Failure, Trace};
use crate::testing::specs::csp::{Event, Process, State};
use crate::utils::time::{Clock, MonotonicInstant, SystemClock};

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

	/// Applies one transition to a trace. A τ-transition leaves the trace and
	/// the depth as they are, and an observable event extends both.
	fn process_transition(process: &Process, event: &Event, trace: Trace, depth: usize) -> (Trace, usize) {
		if process.hidden.contains(event) {
			(trace, depth)
		} else {
			let mut new_trace = trace;
			new_trace.push(*event);
			(new_trace, depth + 1)
		}
	}

	/// Extracts the trace of a linear process, which has a single
	/// deterministic path.
	///
	/// Returns `None` when the process is not linear: it branches, cycles,
	/// deadlocks, runs to `max_depth`, or passes 1000 visited states.
	fn extract_linear_trace(process: &Process, max_depth: usize) -> Option<Trace> {
		let mut trace = Vec::new();
		let mut current_state = process.initial;
		let mut visited_states = HashSet::new();
		visited_states.insert(current_state);

		loop {
			if process.terminal.contains(&current_state) {
				return Some(trace);
			}

			if trace.len() >= max_depth {
				return None; // A walk at the depth limit is not linear.
			}

			// The depth limit counts observable events only, so this bound
			// stops a long run of τ-transitions.
			if visited_states.len() > 1000 {
				return None; // A walk past 1000 states counts as not linear.
			}

			// Follow the τ-transitions (hidden events) first, one at a time,
			// until the state enables none. They leave the trace as it is.
			let mut has_tau_transitions = true;
			while has_tau_transitions {
				has_tau_transitions = false;
				let current_enabled = process.enabled(current_state);
				for action in &current_enabled {
					if process.hidden.contains(&action.event) {
						let next_states = process.step(current_state, &action.event);
						if next_states.len() != 1 {
							return None; // Two τ targets make a branch.
						}
						current_state = next_states[0];

						if !visited_states.insert(current_state) {
							return None; // A revisited state is a cycle.
						}

						has_tau_transitions = true;
						break; // The scan starts again at the next state.
					}
				}

				if process.terminal.contains(&current_state) {
					return Some(trace);
				}
			}

			// The state is stable here, so only observable actions remain.
			let stable_enabled = process.enabled(current_state);
			let observable_actions: Vec<_> = stable_enabled
				.iter()
				.filter(|action| !process.hidden.contains(&action.event))
				.collect();

			// A linear process enables at most one observable action.
			if observable_actions.len() > 1 {
				return None; // A branch on observable events is not linear.
			}

			if let Some(action) = observable_actions.first() {
				let next_states = process.step(current_state, &action.event);

				// A linear process has exactly one next state.
				if next_states.len() != 1 {
					return None; // A nondeterministic step is not linear.
				}

				trace.push(action.event);
				current_state = next_states[0];

				if !visited_states.insert(current_state) {
					return None; // A revisited state is a cycle.
				}
			} else {
				// The state enables no action, so it is terminal or a deadlock.
				if process.terminal.contains(&current_state) {
					return Some(trace);
				}
				return None; // A deadlock is not a linear trace.
			}
		}
	}

	/// A breadth-first traversal with a per-state and a per-transition
	/// callback, which the failure and divergence computations run on.
	///
	/// - `on_state` returns `true` to skip the transitions of a state.
	/// - A state whose trace holds `max_depth` events is still visited, and
	///   takes its hidden steps alone. The traversal therefore covers each trace
	///   of at most `max_depth` events, as `compute_traces` does.
	/// - The returned `bool` is `true` when the traversal ran to exhaustion, and
	///   `false` when the queue limit, the visited limit, or the timeout cut it.
	fn bfs_with_callbacks<T, FState, FTransition>(
		&self,
		process: &Process,
		max_depth: usize,
		mut data: T,
		mut on_state: FState,
		mut on_transition: FTransition,
	) -> (T, bool)
	where
		FState: FnMut(&mut T, State, &Trace, usize) -> bool,
		FTransition: FnMut(&mut T, &mut VecDeque<(State, Trace, usize)>, State, Trace, usize, &Event, State),
	{
		let timeout_checker = TimeoutChecker::new(self.config.timeout_ms);
		let mut queue = VecDeque::new();
		let mut visited = HashSet::new();
		let mut complete = true;
		queue.push_back((process.initial, Vec::new(), 0usize));

		while let Some((state, trace, depth)) = queue.pop_front() {
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

			let skip_transitions = on_state(&mut data, state, &trace, depth);
			if skip_transitions {
				continue;
			}

			// A hidden step keeps the trace's length, so a state at the bound
			// still takes it.
			let at_the_bound = trace.len() >= max_depth;
			for action in process.enabled(state) {
				if at_the_bound && !process.hidden.contains(&action.event) {
					continue;
				}

				for next_state in process.step(state, &action.event) {
					on_transition(&mut data, &mut queue, state, trace.clone(), depth, &action.event, next_state);
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
	/// bounded search that ran out of budget is not a counterexample.
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
				if spec.hidden.contains(&action.event) {
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
		// spec, because an implementation recorded from a running system also
		// carries the steps that the spec models internally. See
		// `Process::project`.
		let projected: HashSet<Trace> = impl_traces.iter().map(|trace| spec.project(trace)).collect();

		// Sorted iteration keeps the reported witness deterministic
		// regardless of HashSet ordering.
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
	/// Reference: Roscoe (1998, 2010)
	fn check_divergence_refinement(&mut self, spec: &Process, impl_process: &Process) -> RefinementOutcome<Trace> {
		let (spec_divergences, spec_complete) = self.compute_divergences(spec, self.config.max_depth);
		let (impl_divergences, impl_complete) = self.compute_divergences(impl_process, self.config.max_depth);

		let mut ordered: Vec<&Trace> = impl_divergences.iter().collect();
		ordered.sort_unstable();

		for impl_div in ordered {
			if !spec_divergences.contains(impl_div) {
				if !spec_complete {
					return RefinementOutcome::Inconclusive;
				}

				return RefinementOutcome::Violated(impl_div.clone());
			}
		}

		RefinementOutcome::Holds { complete: spec_complete && impl_complete }
	}

	fn compute_traces(&mut self, process: &Process, max_depth: usize) -> (HashSet<Trace>, bool) {
		let structure = process.structure_digest();
		if let Some((cached, complete)) = self.cache.borrow().get_cached_traces(structure) {
			return (cached.into_iter().collect(), complete);
		}

		// A linear process yields its one trace directly, which skips the
		// search.
		if let Some(linear_trace) = Self::extract_linear_trace(process, max_depth) {
			let mut traces = HashSet::new();
			traces.insert(linear_trace.clone());

			self.cache.borrow_mut().cache_traces(structure, vec![linear_trace], true);

			return (traces, true);
		}

		let timeout_checker = TimeoutChecker::new(self.config.timeout_ms);
		let mut traces = HashSet::new();
		traces.insert(Vec::new());

		let mut complete = true;
		let mut queue = VecDeque::new();
		let mut visited = HashSet::new();

		queue.push_back((process.initial, Vec::new(), 0usize));

		while let Some((state, trace, depth)) = queue.pop_front() {
			if timeout_checker.is_expired() {
				complete = false;
				break;
			}

			if Self::check_limits(queue.len(), visited.len(), traces.len()) {
				complete = false;
				break;
			}

			if trace.len() >= max_depth {
				continue;
			}

			let visit_key = (state, trace.clone());
			if visited.contains(&visit_key) {
				continue;
			}

			visited.insert(visit_key);

			let enabled_actions = process.enabled(state);
			for action in enabled_actions {
				let next_states = process.step(state, &action.event);
				for next_state in next_states {
					if Self::check_limits(queue.len(), visited.len(), traces.len()) {
						complete = false;
						break;
					}

					let (new_trace, new_depth) = Self::process_transition(process, &action.event, trace.clone(), depth);
					if !process.hidden.contains(&action.event) {
						traces.insert(new_trace.clone());
					}

					queue.push_back((next_state, new_trace, new_depth));
				}
			}
		}

		let traces_vec: Vec<Trace> = traces.iter().cloned().collect();
		self.cache.borrow_mut().cache_traces(structure, traces_vec, complete);

		(traces, complete)
	}

	fn compute_failures(&mut self, process: &Process, max_depth: usize) -> (Vec<Failure>, bool) {
		let structure = process.structure_digest();
		if let Some((cached, complete)) = self.cache.borrow().get_cached_failures(structure) {
			return (cached, complete);
		}

		// The search records a failure at a stable or accepting state alone,
		// as `Process::failure_refusals` decides.
		let failures = Vec::new();
		let visited = HashSet::new();
		let data = (failures, visited);
		let ((failures, _), complete) = self.bfs_with_callbacks(
			process,
			max_depth,
			data,
			|(failures, visited), state, trace, _depth| {
				let visit_key = (state, trace.clone());
				if visited.contains(&visit_key) {
					return true;
				}

				visited.insert(visit_key);

				if let Some(refusals) = self.compute_refusals(process, state) {
					let failure = (trace.clone(), refusals);
					if !failures.contains(&failure) {
						failures.push(failure);
					}
				}

				false
			},
			|(_failures, _visited), queue, _state, trace, depth, event, next_state| {
				let (new_trace, new_depth) = Self::process_transition(process, event, trace, depth);
				queue.push_back((next_state, new_trace, new_depth));
			},
		);

		self.cache.borrow_mut().cache_failures(structure, failures.clone(), complete);

		(failures, complete)
	}

	/// Computes the divergences of `process`, each trace after which a state
	/// that the process reaches can diverge.
	///
	/// [`Process::divergent_states`] decides each state once, and the search
	/// reads that answer at each state and trace it reaches. It runs on
	/// [`Self::bfs_with_callbacks`], so the divergences and the failures share
	/// one depth bound, one set of limits, and one timeout.
	fn compute_divergences(&mut self, process: &Process, max_depth: usize) -> (HashSet<Trace>, bool) {
		let structure = process.structure_digest();
		if let Some((cached, complete)) = self.cache.borrow().get_cached_divergences(structure) {
			return (cached.into_iter().collect(), complete);
		}

		let divergent = process.divergent_states();
		let (divergences, complete) = self.bfs_with_callbacks(
			process,
			max_depth,
			HashSet::new(),
			|divergences, state, trace, _depth| {
				if divergent.contains(state) {
					divergences.insert(trace.clone());
				}

				false
			},
			|_divergences, queue, _state, trace, depth, event, next_state| {
				let (next_trace, next_depth) = Self::process_transition(process, event, trace, depth);
				queue.push_back((next_state, next_trace, next_depth));
			},
		);

		let divergences_vec: Vec<Trace> = divergences.iter().cloned().collect();
		self.cache.borrow_mut().cache_divergences(structure, divergences_vec, complete);

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

	/// A process that can stop at `Idle`, where it still offers `a`, and at
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

	/// A process that takes `a`, then stops at `S1`, which can diverge
	/// nowhere.
	fn stopping_after_a() -> Result<Process, ProcessBuildError> {
		Process::builder("StoppingAfterA")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_transition(State("S0"), Event("a"), State("S1"))
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
}
