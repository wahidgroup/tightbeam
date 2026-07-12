//! FDR refinement checking subsystem
//!
//! This module contains the RefinementChecker trait implementation.

use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::testing::fdr::config::{Failure, FdrConfig, Trace};
use crate::testing::fdr::explorer::{MemoizationCache, RefinementChecker, RefinementOutcome};
use crate::testing::specs::csp::{Event, Process, State};

/// Result of searching for a single trace in a specification
///
/// Distinguishes a definitive absence from a search cut short by timeout or
/// resource limits, so bounded search is never reported as a counter-example.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceSearch {
	Found,
	Absent,
	Inconclusive,
}

/// Timeout checker helper
struct TimeoutChecker {
	start: Instant,
	timeout: Duration,
}

impl TimeoutChecker {
	fn new(timeout_ms: u64) -> Self {
		Self { start: Instant::now(), timeout: Duration::from_millis(timeout_ms) }
	}

	fn is_expired(&self) -> bool {
		self.start.elapsed() >= self.timeout
	}
}

/// Default refinement checker implementation
pub struct DefaultRefinementChecker<'a, M>
where
	M: MemoizationCache,
{
	/// Configuration
	config: Arc<FdrConfig>,
	/// Process being verified
	process: &'a Process,
	/// Shared memoization cache
	cache: Rc<RefCell<M>>,
}

impl<'a, M> DefaultRefinementChecker<'a, M>
where
	M: MemoizationCache,
{
	/// Create new refinement checker with shared cache
	pub fn new(process: &'a Process, config: Arc<FdrConfig>, cache: Rc<RefCell<M>>) -> Self {
		Self { config, process, cache }
	}

	/// Get configuration
	pub fn config(&self) -> &FdrConfig {
		&self.config
	}

	/// Get process
	pub fn process(&self) -> &Process {
		self.process
	}

	/// Helper methods to access trait constants
	fn max_traces() -> usize {
		<Self as RefinementChecker>::MAX_TRACES
	}

	fn max_queue_size() -> usize {
		<Self as RefinementChecker>::MAX_QUEUE_SIZE
	}

	fn max_visited() -> usize {
		<Self as RefinementChecker>::MAX_VISITED
	}

	/// Check if limits are exceeded before enqueueing
	fn check_limits(queue_len: usize, visited_len: usize, traces_count: usize) -> bool {
		queue_len >= Self::max_queue_size() || visited_len >= Self::max_visited() || traces_count >= Self::max_traces()
	}

	/// Check if a state is stable (no τ-transitions enabled)
	fn is_stable_state(process: &Process, state: State) -> bool {
		let enabled_actions = process.enabled(state);
		!enabled_actions.iter().any(|action| process.hidden.contains(&action.event))
	}

	/// Process a transition, handling τ-transitions vs observable events
	/// Process a transition, handling τ-transitions vs observable events
	fn process_transition(process: &Process, event: &Event, trace: Trace, depth: usize) -> (Trace, usize) {
		if process.hidden.contains(event) {
			// τ-transition: don't extend trace
			(trace, depth)
		} else {
			// Observable event: extend trace
			let mut new_trace = trace;
			new_trace.push(*event);
			(new_trace, depth + 1)
		}
	}

	/// Extract trace from a linear process (single deterministic path)
	/// Returns None if the process is not linear (has branching)
	fn extract_linear_trace(process: &Process, max_depth: usize) -> Option<Trace> {
		let mut trace = Vec::new();
		let mut current_state = process.initial;
		let mut visited_states = HashSet::new();
		visited_states.insert(current_state);

		loop {
			// Check if we've reached a terminal state
			if process.terminal.contains(&current_state) {
				return Some(trace);
			}

			// Check depth limit
			if trace.len() >= max_depth {
				return None; // Not linear if we hit depth limit
			}

			// Check for cycles
			if visited_states.len() > 1000 {
				return None; // Likely not linear if we've visited many states
			}

			// First, follow any τ-transitions (hidden events) - they don't extend the trace
			// Process all τ-transitions in sequence until we reach a state with no τ-transitions
			let mut has_tau_transitions = true;
			while has_tau_transitions {
				has_tau_transitions = false;
				let current_enabled = process.enabled(current_state);
				for action in &current_enabled {
					if process.hidden.contains(&action.event) {
						let next_states = process.step(current_state, &action.event);
						if next_states.len() != 1 {
							return None; // Non-deterministic τ-transition
						}
						current_state = next_states[0];

						// Check for cycles
						if !visited_states.insert(current_state) {
							return None; // Cycle detected
						}

						has_tau_transitions = true;
						break; // Restart check from new state
					}
				}

				// Check terminal after τ-transitions
				if process.terminal.contains(&current_state) {
					return Some(trace);
				}
			}

			// Now check for observable actions at the stable state
			let stable_enabled = process.enabled(current_state);
			let observable_actions: Vec<_> = stable_enabled
				.iter()
				.filter(|action| !process.hidden.contains(&action.event))
				.collect();

			// Linear process: at most one observable action
			if observable_actions.len() > 1 {
				return None; // Not linear - has branching in observable events
			}

			// If we have an observable action, follow it
			if let Some(action) = observable_actions.first() {
				let next_states = process.step(current_state, &action.event);

				// Linear process must have exactly one next state
				if next_states.len() != 1 {
					return None; // Not linear - has non-determinism
				}

				// Add event to trace
				trace.push(action.event);
				current_state = next_states[0];

				// Check for cycles
				if !visited_states.insert(current_state) {
					return None; // Cycle detected - not a simple linear trace
				}
			} else {
				// No enabled actions - deadlock or terminal state
				if process.terminal.contains(&current_state) {
					return Some(trace);
				}
				return None; // Deadlock - not a valid linear trace
			}
		}
	}

	/// Generic BFS helper for trace and failure computation
	///
	/// The returned `bool` is true when the traversal ran to exhaustion;
	/// false when queue/visited limits truncated it.
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
		let mut queue = VecDeque::new();
		let mut visited = HashSet::new();
		let mut complete = true;
		queue.push_back((process.initial, Vec::new(), 0usize));

		while let Some((state, trace, depth)) = queue.pop_front() {
			if queue.len() >= Self::max_queue_size() || visited.len() >= Self::max_visited() {
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

			let skip_transitions = on_state(&mut data, state, &trace, depth);
			if skip_transitions {
				continue;
			}

			for action in process.enabled(state) {
				for next_state in process.step(state, &action.event) {
					on_transition(&mut data, &mut queue, state, trace.clone(), depth, &action.event, next_state);
				}
			}
		}

		(data, complete)
	}

	/// Check if a τ-transition would create a cycle
	fn has_tau_cycle(&self, tau_states_seen: &HashSet<(State, Trace)>, next_state: State, trace: &Trace) -> bool {
		let next_key = (next_state, trace.clone());
		tau_states_seen.contains(&next_key)
	}

	/// Check if an implementation failure exists in the specification failures.
	/// Returns true if a matching spec failure is found where impl_refusal ⊆ spec_refusal.
	fn failure_exists_in_spec(spec_failures: &[Failure], impl_trace: &Trace, impl_refusal: &HashSet<Event>) -> bool {
		for (spec_trace, spec_refusal) in spec_failures {
			if spec_trace == impl_trace && impl_refusal.is_subset(spec_refusal) {
				return true;
			}
		}
		false
	}

	/// Search for a specific trace in a spec without computing all traces.
	///
	/// BFS over `(state, matched-prefix-length)` pairs: observable actions
	/// matching the next target event advance the prefix, hidden (τ)
	/// actions advance the state silently. τ exploration is bounded by the
	/// shared visited set only.
	///
	/// Timeout or resource limits yield `Inconclusive`, never `Absent`:
	/// a bounded search that ran out of budget is not a counterexample.
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
	fn check_trace_refinement(&mut self, spec: &Process, impl_process: &Process) -> RefinementOutcome<Trace> {
		// Trace refinement: impl ⊑ spec means traces(impl) ⊆ traces(spec).
		// Every impl trace is checked -- checking only the longest trace
		// misses forbidden events on sibling branches of a branching impl
		// Reference: Roscoe (1998, 2010)
		let (impl_traces, impl_complete) = self.compute_traces(impl_process, self.config.max_depth);

		// Sorted iteration keeps the reported witness deterministic
		// regardless of HashSet ordering.
		let mut ordered: Vec<&Trace> = impl_traces.iter().collect();
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

	fn check_failures_refinement(&mut self, spec: &Process, impl_process: &Process) -> RefinementOutcome<Failure> {
		// Failures refinement: impl ⊑ spec means failures(impl) ⊆ failures(spec)
		// For each impl failure (trace, impl_refusal), there must exist a spec failure
		// (trace, spec_refusal) where impl_refusal ⊆ spec_refusal.
		// Reference: Roscoe (1998, 2010)
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

	fn check_divergence_refinement(&mut self, spec: &Process, impl_process: &Process) -> RefinementOutcome<Trace> {
		// Divergence refinement: impl ⊑ spec means divergences(impl) ⊆ divergences(spec)
		// Reference: Roscoe (1998, 2010)
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

		// Fast path: For linear trace processes, extract trace directly
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

		// Failures are only recorded at stable states (no τ-transitions enabled)
		// Reference: Roscoe (1998, 2010)
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

				if Self::is_stable_state(process, state) {
					let refusals = self.compute_refusals(process, state);
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

	fn compute_divergences(&mut self, process: &Process, max_depth: usize) -> (HashSet<Trace>, bool) {
		let structure = process.structure_digest();
		if let Some((cached, complete)) = self.cache.borrow().get_cached_divergences(structure) {
			return (cached.into_iter().collect(), complete);
		}

		let mut divergences = HashSet::new();
		let mut queue = VecDeque::new();
		let mut initial_tau_seen = HashSet::new();

		initial_tau_seen.insert((process.initial, Vec::new()));
		queue.push_back((process.initial, Vec::new(), initial_tau_seen));

		let mut global_visited = HashSet::new();
		while let Some((state, trace, tau_states_seen)) = queue.pop_front() {
			if trace.len() >= max_depth {
				continue;
			}

			let visit_key = (state, trace.clone());
			if global_visited.contains(&visit_key) {
				continue;
			}

			for action in process.enabled(state) {
				for next_state in process.step(state, &action.event) {
					if process.hidden.contains(&action.event) {
						if self.has_tau_cycle(&tau_states_seen, next_state, &trace) {
							divergences.insert(trace.clone());
							continue;
						}

						let mut new_tau_seen = tau_states_seen.clone();
						new_tau_seen.insert((next_state, trace.clone()));
						queue.push_back((next_state, trace.clone(), new_tau_seen));
					} else {
						let mut new_trace = trace.clone();
						new_trace.push(action.event);

						let mut new_tau_seen = HashSet::new();
						new_tau_seen.insert((next_state, new_trace.clone()));
						queue.push_back((next_state, new_trace, new_tau_seen));
					}
				}
			}

			global_visited.insert(visit_key);
		}

		let divergences_vec: Vec<Trace> = divergences.iter().cloned().collect();
		self.cache.borrow_mut().cache_divergences(structure, divergences_vec, true);

		(divergences, true)
	}

	/// Compute refusal set for a stable state.
	/// Refusal set = all observable events minus enabled events.
	/// Reference: Roscoe (1998, 2010)
	fn compute_refusals(&self, process: &Process, state: State) -> HashSet<Event> {
		let enabled_events: HashSet<Event> = process
			.enabled(state)
			.iter()
			.filter_map(|action| {
				if !process.hidden.contains(&action.event) {
					Some(action.event)
				} else {
					None
				}
			})
			.collect();

		process
			.observable
			.iter()
			.filter(|&event| !enabled_events.contains(event))
			.cloned()
			.collect()
	}
}
