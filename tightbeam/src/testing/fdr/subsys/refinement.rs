//! FDR refinement checking subsystem
//!
//! This module contains the RefinementChecker trait implementation.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::testing::fdr::config::{FdrConfig, Failure, Trace};
use crate::testing::fdr::explorer::{MemoizationCache, RefinementChecker};
use crate::testing::specs::csp::{Event, Process, State};

/// Default refinement checker implementation
pub struct DefaultRefinementChecker<'a> {
	/// Configuration
	config: FdrConfig,
	/// Process being verified
	process: &'a Process,
	/// Memoization cache: process name -> traces
	traces_cache: RefCell<HashMap<String, Vec<Trace>>>,
	/// Memoization cache: process name -> failures
	failures_cache: RefCell<HashMap<String, Vec<Failure>>>,
	/// Memoization cache: process name -> divergences
	divergences_cache: RefCell<HashMap<String, Vec<Trace>>>,
}

impl<'a> DefaultRefinementChecker<'a> {
	/// Create new refinement checker
	pub fn new(process: &'a Process, config: FdrConfig) -> Self {
		Self {
			config,
			process,
			traces_cache: RefCell::new(HashMap::new()),
			failures_cache: RefCell::new(HashMap::new()),
			divergences_cache: RefCell::new(HashMap::new()),
		}
	}

	/// Get configuration
	pub fn config(&self) -> &FdrConfig {
		&self.config
	}

	/// Get process
	pub fn process(&self) -> &Process {
		self.process
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
		FState: FnMut(&mut T, State, &Trace, usize) -> bool, // return true to skip transitions
		FTransition: FnMut(&mut T, &mut VecDeque<(State, Trace, usize)>, State, Trace, usize, &Event, State),
	{
		let mut queue = VecDeque::new();
		queue.push_back((process.initial, Vec::new(), 0usize));

		while let Some((state, trace, depth)) = queue.pop_front() {
			if depth >= max_depth {
				continue;
			}

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

	/// Helper: Check if a τ-transition would create a cycle
	fn has_tau_cycle(&self, tau_states_seen: &HashSet<(State, Trace)>, next_state: State, trace: &Trace) -> bool {
		let next_key = (next_state, trace.clone());
		tau_states_seen.contains(&next_key)
	}
}

impl<'a> RefinementChecker for DefaultRefinementChecker<'a> {
	fn check_trace_refinement(&mut self, spec: &Process, impl_process: &Process) -> (bool, Option<Trace>) {
		let spec_traces = self.compute_traces(spec, self.config.max_depth);
		let impl_traces = self.compute_traces(impl_process, self.config.max_depth);

		for impl_trace in &impl_traces {
			if !spec_traces.contains(impl_trace) {
				return (false, Some(impl_trace.clone()));
			}
		}

		(true, None)
	}

	fn check_failures_refinement(&mut self, spec: &Process, impl_process: &Process) -> (bool, Option<Failure>) {
		let spec_failures = self.compute_failures(spec, self.config.max_depth);
		let impl_failures = self.compute_failures(impl_process, self.config.max_depth);

		for impl_failure in &impl_failures {
			if !spec_failures.contains(impl_failure) {
				return (false, Some(impl_failure.clone()));
			}
		}

		(true, None)
	}

	fn check_divergence_refinement(&mut self, spec: &Process, impl_process: &Process) -> (bool, Option<Trace>) {
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
		// Check cache first
		if let Some(cached) = self.get_cached_traces(process.name) {
			return cached.into_iter().collect();
		}

		let mut traces = HashSet::new();
		traces.insert(Vec::new()); // ⟨⟩ is always a valid trace

		traces = self.bfs_with_callbacks(
			process,
			max_depth,
			traces,
			|_traces, state, _trace, _depth| {
				process.is_terminal(state) // Skip transitions if terminal
			},
			|traces, queue, _state, trace, depth, event, next_state| {
				if process.hidden.contains(event) {
					// τ-transition: don't extend trace
					queue.push_back((next_state, trace, depth));
				} else {
					// Observable event: extend trace
					let mut new_trace = trace;
					new_trace.push(event.clone());
					traces.insert(new_trace.clone());
					queue.push_back((next_state, new_trace, depth + 1));
				}
			},
		);

		// Cache the result
		let traces_vec: Vec<Trace> = traces.iter().cloned().collect();
		self.cache_traces(process.name.to_string(), traces_vec);

		traces
	}

	fn compute_failures(&mut self, process: &Process, max_depth: usize) -> Vec<Failure> {
		// Check cache first
		if let Some(cached) = self.get_cached_failures(process.name) {
			return cached;
		}

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
					return true; // Skip if already visited
				}

				visited.insert(visit_key);

				// Compute refusal set and record failure
				let refusals = self.compute_refusals(process, state);
				let failure = (trace.clone(), refusals);
				if !failures.contains(&failure) {
					failures.push(failure);
				}

				process.is_terminal(state) // Skip transitions if terminal
			},
			|(_failures, _visited), queue, _state, trace, depth, event, next_state| {
				if process.hidden.contains(event) {
					// τ-transition: don't extend trace
					queue.push_back((next_state, trace, depth));
				} else {
					// Observable event: extend trace
					let mut new_trace = trace;
					new_trace.push(event.clone());
					queue.push_back((next_state, new_trace, depth + 1));
				}
			},
		);

		// Cache the result
		self.cache_failures(process.name.to_string(), failures.clone());

		failures
	}

	fn compute_divergences(&mut self, process: &Process, max_depth: usize) -> HashSet<Trace> {
		// Check cache first
		if let Some(cached) = self.get_cached_divergences(process.name) {
			return cached.into_iter().collect();
		}

		let mut divergences = HashSet::new();
		let mut queue = VecDeque::new();

		// Initialize queue with starting state
		// tau_states_seen tracks (state, trace) pairs seen in the current
		// τ-run to detect cycles
		let mut initial_tau_seen = HashSet::new();
		initial_tau_seen.insert((process.initial, Vec::new()));
		queue.push_back((process.initial, Vec::new(), initial_tau_seen));

		// global_visited prevents re-exploring (state, trace) pairs that have
		// been fully processed Note: We don't mark as visited if a divergence
		// is found, as other paths might also diverge
		let mut global_visited = HashSet::new();
		while let Some((state, trace, tau_states_seen)) = queue.pop_front() {
			// Depth cutoff based on trace length
			if trace.len() >= max_depth {
				continue;
			}

			// Skip if this (state, trace) has already been fully explored
			let visit_key = (state, trace.clone());
			if global_visited.contains(&visit_key) {
				continue;
			}

			// Process all enabled actions from current state
			for action in process.enabled(state) {
				for next_state in process.step(state, &action.event) {
					if process.hidden.contains(&action.event) {
						// Hidden (τ) transition: check for τ-cycle
						if self.has_tau_cycle(&tau_states_seen, next_state, &trace) {
							// Found divergence: τ-cycle detected
							divergences.insert(trace.clone());
							continue; // Don't explore further from this cycle
						}

						// Continue τ-run: extend tau_states_seen
						let mut new_tau_seen = tau_states_seen.clone();
						new_tau_seen.insert((next_state, trace.clone()));
						queue.push_back((next_state, trace.clone(), new_tau_seen));
					} else {
						// Observable event: reset τ-tracking for new trace
						let mut new_trace = trace.clone();
						new_trace.push(action.event.clone());
						let mut new_tau_seen = HashSet::new();
						new_tau_seen.insert((next_state, new_trace.clone()));
						queue.push_back((next_state, new_trace, new_tau_seen));
					}
				}
			}

			// Mark as visited only after fully exploring all actions (no divergence found)
			global_visited.insert(visit_key);
		}

		// Cache the result
		let divergences_vec: Vec<Trace> = divergences.iter().cloned().collect();
		self.cache_divergences(process.name.to_string(), divergences_vec);

		divergences
	}

	fn compute_refusals(&self, process: &Process, state: State) -> HashSet<Event> {
		let mut refusals = HashSet::new();
		for event in &process.observable {
			let enabled = process.enabled(state).iter().any(|action| &action.event == event);
			if !enabled {
				refusals.insert(event.clone());
			}
		}
		refusals
	}
}

impl<'a> MemoizationCache for DefaultRefinementChecker<'a> {
	fn get_cached_traces(&self, process_name: &str) -> Option<Vec<Trace>> {
		self.traces_cache.borrow().get(process_name).cloned()
	}

	fn cache_traces(&mut self, process_name: String, traces: Vec<Trace>) {
		self.traces_cache.borrow_mut().insert(process_name, traces);
	}

	fn get_cached_failures(&self, process_name: &str) -> Option<Vec<Failure>> {
		self.failures_cache.borrow().get(process_name).cloned()
	}

	fn cache_failures(&mut self, process_name: String, failures: Vec<Failure>) {
		self.failures_cache.borrow_mut().insert(process_name, failures);
	}

	fn get_cached_divergences(&self, process_name: &str) -> Option<Vec<Trace>> {
		self.divergences_cache.borrow().get(process_name).cloned()
	}

	fn cache_divergences(&mut self, process_name: String, divergences: Vec<Trace>) {
		self.divergences_cache.borrow_mut().insert(process_name, divergences);
	}
}
