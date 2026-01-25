//! Exploration subsystem
//!
//! This module contains the exploration engine implementation and helper
//! functions for the FDR exploration loop. These handle state space traversal,
//! seed management, and basic property verification.

use std::borrow::Cow;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

#[cfg(feature = "testing-timing")]
use core::time::Duration;

use crate::testing::fdr::config::{Failure, FdrConfig, RefusalSet, Trace};
use crate::testing::fdr::explorer::{ExplorationCore, ExplorationState, SeedResult, SeededRng};
use crate::testing::specs::csp::{Action, Event, Process, State};

#[cfg(feature = "testing-fault")]
use crate::testing::fdr::config::{FaultInjection, FaultModel, InjectedFaultRecord};
#[cfg(feature = "testing-timing")]
use crate::testing::fdr::subsys::timing::check_event_wcet_violation;
#[cfg(feature = "testing-timing")]
use crate::testing::fdr::subsys::timing::check_timing_violations;
#[cfg(feature = "testing-timing")]
use crate::testing::timing::{TimingConstraint, TimingConstraints};

/// Default exploration engine implementation
pub struct DefaultExplorationEngine<'a> {
	/// Process being explored
	process: &'a Process,
	/// Configuration
	config: Arc<FdrConfig>,
	/// Results per seed
	seed_results: Vec<(u64, SeedResult)>,
	/// States visited (for statistics)
	visited_states: HashSet<State>,
}

impl<'a> DefaultExplorationEngine<'a> {
	/// Create new exploration engine
	pub fn new(process: &'a Process, config: Arc<FdrConfig>) -> Self {
		Self { process, config, seed_results: Vec::new(), visited_states: HashSet::new() }
	}

	/// Get seed results (for use by FdrExplorer)
	pub fn seed_results(&self) -> &[(u64, SeedResult)] {
		&self.seed_results
	}

	/// Get seed results mutably (for use by FdrExplorer)
	pub fn seed_results_mut(&mut self) -> &mut Vec<(u64, SeedResult)> {
		&mut self.seed_results
	}

	/// Get visited states (for use by FdrExplorer)
	pub fn visited_states(&self) -> &HashSet<State> {
		&self.visited_states
	}

	/// Get visited states mutably (for use by FdrExplorer)
	pub fn visited_states_mut(&mut self) -> &mut HashSet<State> {
		&mut self.visited_states
	}

	/// Explore single seed (different scheduling)
	fn explore_seed_internal(&mut self, seed: u64) -> SeedResult {
		Self::explore_seed_core(self.process, &self.config, seed, |state| {
			self.visited_states.insert(state);
		})
	}

	/// Static version of explore_seed for parallel execution
	/// Returns (SeedResult, visited_states)
	#[cfg(feature = "rayon")]
	pub fn explore_seed_static(process: &Process, config: &FdrConfig, seed: u64) -> (SeedResult, HashSet<State>) {
		let mut visited_states = HashSet::new();
		let result = Self::explore_seed_core(process, config, seed, |state| {
			visited_states.insert(state);
		});
		(result, visited_states)
	}

	/// Core exploration logic shared between internal and static versions
	fn explore_seed_core<F>(process: &Process, config: &FdrConfig, seed: u64, mut track_visited: F) -> SeedResult
	where
		F: FnMut(State),
	{
		let mut rng = SeededRng::new(seed);
		let mut queue = VecDeque::new();

		// Initial exploration state
		let initial = ExplorationState::initial(process.initial);
		queue.push_back(initial);

		// Track best result for this seed
		let mut longest_trace = Vec::new();
		let mut failures = Vec::new();
		#[cfg(feature = "testing-fault")]
		let mut injected_faults = Vec::new();

		while let Some(state) = queue.pop_front() {
			// Track visited states
			track_visited(state.process_state);

			// Depth cutoff
			if state.trace.len() >= config.max_depth {
				if state.trace.len() > longest_trace.len() {
					longest_trace = state.trace.clone();
				}

				// Record failure at depth limit
				let refusals = Self::compute_refusals_helper(process, state.process_state);
				failures.push((state.trace.clone(), refusals));

				continue;
			}

			// Divergence detection
			if state.internal_run > config.max_internal_run {
				return SeedResult::Divergence(state.trace.clone(), state.hidden_events.clone());
			}

			// Terminal state: record trace and mark success
			if process.is_terminal(state.process_state) {
				if state.trace.len() > longest_trace.len() {
					longest_trace = state.trace.clone();
				}

				// Terminal state can refuse everything
				let refusals = process.observable.iter().cloned().collect();
				failures.push((state.trace.clone(), refusals));

				continue;
			}

			// Get enabled actions
			let actions = process.enabled(state.process_state);
			if actions.is_empty() {
				// Deadlock: no enabled actions in non-terminal state
				return SeedResult::Deadlock(state.trace.clone(), state.process_state);
			}

			// Record stable state refusals before taking action
			if state.internal_run == 0 {
				let refusals = Self::compute_refusals_helper(process, state.process_state);
				failures.push((state.trace.clone(), refusals));
			}

			// Select action using seeded RNG at choice points
			let action = Self::select_action_helper(&mut rng, process, state.process_state, &actions);

			// Check for fault injection (if feature enabled)
			#[cfg(feature = "testing-fault")]
			if let Some(ref fault_model) = config.fault_model {
				if let Some(fault_record) =
					Self::check_fault_injection(fault_model, process, state.process_state, &action.event, &mut rng)
				{
					// Fault injected - record for verdict tracking
					injected_faults.push(fault_record);
					// For now, we continue exploration (fault is noted but doesn't stop execution)
					// Future enhancement: add error recovery transitions
				}
			}

			// Execute transition
			Self::execute_transition_helper(process, &state, action, &mut queue);
		}

		// Return success with longest trace found and collected failures
		#[cfg(feature = "testing-fault")]
		{
			SeedResult::Success(longest_trace, failures, injected_faults)
		}
		#[cfg(not(feature = "testing-fault"))]
		{
			SeedResult::Success(longest_trace, failures)
		}
	}
}

impl<'a> ExplorationCore for DefaultExplorationEngine<'a> {
	fn process(&self) -> &Process {
		self.process
	}

	fn config(&self) -> &FdrConfig {
		&self.config
	}

	fn explore_seed(&mut self, seed: u64) -> SeedResult {
		self.explore_seed_internal(seed)
	}

	fn traces(&self) -> Vec<Trace> {
		self.seed_results
			.iter()
			.filter_map(|(_, result)| match result {
				#[cfg(feature = "testing-fault")]
				SeedResult::Success(trace, _failures, _faults) => Some(trace.clone()),
				#[cfg(not(feature = "testing-fault"))]
				SeedResult::Success(trace, _failures) => Some(trace.clone()),
				_ => None,
			})
			.collect()
	}

	fn failures(&self) -> Vec<Failure> {
		let mut failures = Vec::new();
		for (_, result) in &self.seed_results {
			#[cfg(feature = "testing-fault")]
			if let SeedResult::Success(_trace, seed_failures, _faults) = result {
				failures.extend(seed_failures.clone());
			}
			#[cfg(not(feature = "testing-fault"))]
			if let SeedResult::Success(_trace, seed_failures) = result {
				failures.extend(seed_failures.clone());
			}
		}
		failures
	}

	fn states_visited(&self) -> usize {
		self.visited_states.len()
	}

	fn seeds_completed(&self) -> u32 {
		self.seed_results.len() as u32
	}

	fn add_seed_result(&mut self, seed: u64, result: SeedResult) {
		self.seed_results.push((seed, result));
	}

	fn update_visited_states(&mut self, visited: &HashSet<State>) {
		self.visited_states.extend(visited.iter().cloned());
	}

	fn compute_refusals(&self, process: &Process, state: State) -> HashSet<Event> {
		Self::compute_refusals_helper(process, state)
	}
}

impl<'a> DefaultExplorationEngine<'a> {
	/// Compute refusal set at a given state
	///
	/// Refusal set = all observable events minus enabled observable events.
	/// Hidden events (τ-transitions) are filtered out as they cannot be refused.
	/// Reference: Roscoe (1998, 2010)
	fn compute_refusals_helper(process: &Process, state: State) -> RefusalSet {
		// Only consider observable events (filter out hidden τ-transitions)
		let enabled_events: HashSet<_> = process
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

		// Refusal set = all observable events minus enabled observable events
		process
			.observable
			.iter()
			.filter(|&event| !enabled_events.contains(event))
			.cloned()
			.collect()
	}

	/// Select action at a choice point using RNG
	fn select_action_helper<'b>(
		rng: &mut SeededRng,
		process: &'b Process,
		process_state: State,
		actions: &'b [Action],
	) -> &'b Action {
		if process.choice.contains(&process_state) {
			// Nondeterministic choice point: use RNG to select
			rng.choose(actions).unwrap_or(&actions[0])
		} else if actions.len() == 1 {
			// Deterministic: only one choice
			&actions[0]
		} else {
			// Multiple actions but not marked as choice state: use RNG anyway
			rng.choose(actions).unwrap_or(&actions[0])
		}
	}

	/// Check for fault injection at current (state, event) combination
	#[cfg(feature = "testing-fault")]
	fn check_fault_injection(
		fault_model: &FaultModel,
		process: &Process,
		state: State,
		event: &Event,
		rng: &mut SeededRng,
	) -> Option<InjectedFaultRecord> {
		// Construct lookup key with zero-allocation Cow::Borrowed for lookup
		let state_key_str = format!("{}.{}", process.name, state.0);
		let lookup_key = (Cow::Borrowed(state_key_str.as_str()), Cow::Borrowed(event.0));

		// Check if fault should be injected at this point
		fault_model
			.injection_points
			.get(&lookup_key)
			.and_then(|injection: &FaultInjection| {
				// Use SeededRng's get_next() and convert to basis points range (0-10000)
				let rng_value = (rng.get_next() % 10001) as u16;
				if rng_value < injection.probability_bps.get() {
					let error = (injection.error_factory)();
					// Clone only when actually injecting fault (rare path)
					Some(InjectedFaultRecord {
						csp_state: state_key_str.clone(),
						event_label: event.0.to_string(),
						error_message: error.to_string(),
						probability_bps: injection.probability_bps.get(),
					})
				} else {
					None
				}
			})
	}

	/// Execute transition and enqueue next states
	fn execute_transition_helper(
		process: &Process,
		state: &ExplorationState,
		action: &Action,
		queue: &mut VecDeque<ExplorationState>,
	) {
		#[cfg(feature = "testing-timing")]
		{
			use crate::testing::fdr::subsys::timing::check_timed_transition_guard;

			// Check timing guards if timed transitions exist
			if let Some(ref timed_transitions) = process.timed_transitions {
				if let Some(transitions) = timed_transitions.get(&(state.process_state, action.event)) {
					// Filter transitions by guard satisfaction
					let valid_transitions: Vec<_> = transitions
						.iter()
						.filter(|tt| check_timed_transition_guard(tt, &state.clock_values))
						.collect();

					if valid_transitions.is_empty() {
						// Prune branch: no valid transitions (guards not satisfied)
						return;
					}

					// Process each valid timed transition
					for timed_trans in valid_transitions {
						let mut next_exploration = state.branch();
						let next_state = timed_trans.to;

						// Reset clocks if specified
						next_exploration.reset_clocks(&timed_trans.reset_clocks);

						if process.hidden.contains(&action.event) {
							// Hidden (τ) transition
							next_exploration.record_hidden(action.event, next_state);
						} else {
							// Observable transition
							next_exploration.record_observable(action.event, next_state);

							// Update timing if timing constraints exist
							if let Some(ref constraints) = process.timing_constraints {
								// Look up WCET for this event
								let wcet = Self::lookup_wcet(&action.event, constraints);
								if check_event_wcet_violation(&action.event, wcet, constraints) {
									// Prune this branch: WCET violation
									continue;
								}

								next_exploration.update_timing(&action.event, wcet);
								// Advance clocks by WCET
								next_exploration.update_clocks(wcet);

								// Check other timing violations (deadline, path WCET) before adding to queue
								if Self::check_timing_violations(&next_exploration, constraints) {
									// Prune this branch: timing violation
									continue;
								}
							} else {
								// No timing constraints: advance clocks by zero (or skip)
								// For now, we skip clock advancement if no timing constraints
							}
						}

						queue.push_back(next_exploration);
					}

					// Return early since we handled timed transitions
					return;
				}
			}
		}

		// Regular transitions (no timed transitions or no match)
		let next_states = process.step(state.process_state, &action.event);
		for next_state in next_states {
			let mut next_exploration = state.branch();
			if process.hidden.contains(&action.event) {
				// Hidden (τ) transition
				next_exploration.record_hidden(action.event, next_state);
			} else {
				// Observable transition
				next_exploration.record_observable(action.event, next_state);

				// Update timing if timing constraints exist
				#[cfg(feature = "testing-timing")]
				{
					if let Some(ref constraints) = process.timing_constraints {
						// Look up WCET for this event
						// Check if this event's WCET violates its constraint
						let wcet = Self::lookup_wcet(&action.event, constraints);
						if check_event_wcet_violation(&action.event, wcet, constraints) {
							// Prune this branch: WCET violation
							continue;
						}

						next_exploration.update_timing(&action.event, wcet);
						// Advance clocks by WCET
						next_exploration.update_clocks(wcet);

						// Check other timing violations (deadline, path WCET) before adding to queue
						if Self::check_timing_violations(&next_exploration, constraints) {
							// Prune this branch: timing violation
							continue;
						}
					}
				}
			}

			queue.push_back(next_exploration);
		}
	}

	/// Look up WCET for an event from timing constraints
	#[cfg(feature = "testing-timing")]
	fn lookup_wcet(event: &Event, constraints: &TimingConstraints) -> Duration {
		if let Some(constraint) = constraints.get(event) {
			match constraint {
				TimingConstraint::Wcet(wcet_config) => wcet_config.duration,
				_ => Duration::ZERO, // Jitter/deadline don't contribute to WCET
			}
		} else {
			Duration::ZERO // No constraint = zero time (conservative)
		}
	}

	/// Check if exploration state violates timing constraints
	#[cfg(feature = "testing-timing")]
	fn check_timing_violations(state: &ExplorationState, constraints: &TimingConstraints) -> bool {
		check_timing_violations(&state.trace, state.elapsed_time, &state.event_times, constraints)
	}
}
