//! FDR refinement checking subsystem
//!
//! This module contains the RefinementChecker trait implementation.

use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::testing::fdr::config::{Failure, FdrConfig, Trace};
use crate::testing::fdr::explorer::{MemoizationCache, RefinementChecker};
use crate::testing::specs::csp::{Event, Process, State};

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
	config: FdrConfig,
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
	pub fn new(process: &'a Process, config: FdrConfig, cache: Rc<RefCell<M>>) -> Self {
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
			new_trace.push(event.clone());
			(new_trace, depth + 1)
		}
	}

	/// Generic BFS helper for trace and failure computation
	fn bfs_with_callbacks<T, FState, FTransition>(
		&self,
		process: &Process,
		max_depth: usize,
		mut data: T,
		mut on_state: FState,
		mut on_transition: FTransition,
	) -> T
	where
		FState: FnMut(&mut T, State, &Trace, usize) -> bool,
		FTransition: FnMut(&mut T, &mut VecDeque<(State, Trace, usize)>, State, Trace, usize, &Event, State),
	{
		let mut queue = VecDeque::new();
		let mut visited = HashSet::new();
		queue.push_back((process.initial, Vec::new(), 0usize));

		while let Some((state, trace, depth)) = queue.pop_front() {
			if queue.len() >= Self::max_queue_size() || visited.len() >= Self::max_visited() {
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

		data
	}

	/// Check if a τ-transition would create a cycle
	fn has_tau_cycle(&self, tau_states_seen: &HashSet<(State, Trace)>, next_state: State, trace: &Trace) -> bool {
		let next_key = (next_state, trace.clone());
		tau_states_seen.contains(&next_key)
	}

	/// Check if a specific trace exists in a spec without computing all traces
	fn trace_exists_in_spec(
		spec: &Process,
		target_trace: &Trace,
		max_depth: usize,
		max_queue_size: usize,
		max_visited: usize,
		timeout_ms: u64,
	) -> bool {
		if target_trace.len() > max_depth {
			return false;
		}

		let timeout_checker = TimeoutChecker::new(timeout_ms);
		let mut queue = VecDeque::new();
		let mut visited = HashSet::new();
		queue.push_back((spec.initial, 0usize));

		while let Some((state, trace_idx)) = queue.pop_front() {
			if timeout_checker.is_expired() {
				return false;
			}

			if queue.len() >= max_queue_size || visited.len() >= max_visited {
				return false;
			}

			let visit_key = (state, trace_idx);
			if visited.contains(&visit_key) {
				continue;
			}
			visited.insert(visit_key);

			if trace_idx >= target_trace.len() {
				return true;
			}

			// Process observable events first
			let next_event = &target_trace[trace_idx];
			let enabled_actions = spec.enabled(state);
			for action in &enabled_actions {
				if &action.event == next_event {
					for next_state in spec.step(state, &action.event) {
						if queue.len() >= max_queue_size || visited.len() >= max_visited {
							break;
						}
						queue.push_back((next_state, trace_idx + 1));
					}
				}
			}

			// Explore τ-transitions
			for action in &enabled_actions {
				if spec.hidden.contains(&action.event) {
					for next_state in spec.step(state, &action.event) {
						if queue.len() >= max_queue_size || visited.len() >= max_visited {
							break;
						}
						queue.push_back((next_state, trace_idx));
					}
				}
			}
		}

		false
	}
}

impl<'a, M> RefinementChecker for DefaultRefinementChecker<'a, M>
where
	M: MemoizationCache,
{
	fn check_trace_refinement(&mut self, spec: &Process, impl_process: &Process) -> (bool, Option<Trace>) {
		// Trace refinement: impl ⊑ spec means traces(impl) ⊆ traces(spec)
		// For deterministic linear processes, we only check the longest trace.
		// Reference: Pedersen & Chalmers (2024)
		let impl_traces = self.compute_traces(impl_process, self.config.max_depth);
		let longest_trace = impl_traces.iter().max_by_key(|t| t.len()).cloned();
		if let Some(full_trace) = longest_trace {
			let max_queue = Self::max_queue_size();
			let max_visited = Self::max_visited();

			if !Self::trace_exists_in_spec(
				spec,
				&full_trace,
				self.config.max_depth,
				max_queue,
				max_visited,
				self.config.timeout_ms,
			) {
				return (false, Some(full_trace));
			}

			(true, None)
		} else {
			(false, Some(Vec::new()))
		}
	}

	fn check_failures_refinement(&mut self, spec: &Process, impl_process: &Process) -> (bool, Option<Failure>) {
		// Failures refinement: impl ⊑ spec means failures(impl) ⊆ failures(spec)
		// For each impl failure (trace, impl_refusal), there must exist a spec failure
		// (trace, spec_refusal) where impl_refusal ⊆ spec_refusal.
		// Reference: Roscoe (1998, 2010)
		let spec_failures = self.compute_failures(spec, self.config.max_depth);
		let impl_failures = self.compute_failures(impl_process, self.config.max_depth);
		for (impl_trace, impl_refusal) in &impl_failures {
			let mut found = false;
			for (spec_trace, spec_refusal) in &spec_failures {
				if spec_trace == impl_trace && impl_refusal.is_subset(spec_refusal) {
					found = true;
					break;
				}
			}
			if !found {
				return (false, Some((impl_trace.clone(), impl_refusal.clone())));
			}
		}

		(true, None)
	}

	fn check_divergence_refinement(&mut self, spec: &Process, impl_process: &Process) -> (bool, Option<Trace>) {
		// Divergence refinement: impl ⊑ spec means divergences(impl) ⊆ divergences(spec)
		// Reference: Roscoe (1998, 2010)
		let spec_divergences = self.compute_divergences(spec, self.config.max_depth);
		let impl_divergences = self.compute_divergences(impl_process, self.config.max_depth);
		for impl_div in &impl_divergences {
			if !spec_divergences.contains(impl_div) {
				return (false, Some(impl_div.clone()));
			}
		}

		(true, None)
	}

	fn compute_traces(&mut self, process: &Process, max_depth: usize) -> HashSet<Trace> {
		if let Some(cached) = self.cache.borrow().get_cached_traces(process.name) {
			return cached.into_iter().collect();
		}

		let timeout_checker = TimeoutChecker::new(self.config.timeout_ms);
		let mut traces = HashSet::new();
		traces.insert(Vec::new());

		let mut queue = VecDeque::new();
		let mut visited = HashSet::new();
		queue.push_back((process.initial, Vec::new(), 0usize));

		while let Some((state, trace, depth)) = queue.pop_front() {
			if timeout_checker.is_expired() {
				break;
			}

			if Self::check_limits(queue.len(), visited.len(), traces.len()) {
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
		self.cache.borrow_mut().cache_traces(process.name.to_string(), traces_vec);

		traces
	}

	fn compute_failures(&mut self, process: &Process, max_depth: usize) -> Vec<Failure> {
		if let Some(cached) = self.cache.borrow().get_cached_failures(process.name) {
			return cached;
		}

		// Failures are only recorded at stable states (no τ-transitions enabled)
		// Reference: Roscoe (1998, 2010)
		let failures = Vec::new();
		let visited = HashSet::new();
		let data = (failures, visited);
		let (failures, _) = self.bfs_with_callbacks(
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

		self.cache
			.borrow_mut()
			.cache_failures(process.name.to_string(), failures.clone());

		failures
	}

	fn compute_divergences(&mut self, process: &Process, max_depth: usize) -> HashSet<Trace> {
		if let Some(cached) = self.cache.borrow().get_cached_divergences(process.name) {
			return cached.into_iter().collect();
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
						new_trace.push(action.event.clone());
						let mut new_tau_seen = HashSet::new();
						new_tau_seen.insert((next_state, new_trace.clone()));
						queue.push_back((next_state, new_trace, new_tau_seen));
					}
				}
			}

			global_visited.insert(visit_key);
		}

		let divergences_vec: Vec<Trace> = divergences.iter().cloned().collect();
		self.cache
			.borrow_mut()
			.cache_divergences(process.name.to_string(), divergences_vec);

		divergences
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
					Some(action.event.clone())
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
