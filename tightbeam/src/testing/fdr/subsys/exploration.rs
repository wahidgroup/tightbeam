//! The exploration subsystem of FDR.
//!
//! The module holds the exploration engine and the helper functions of the
//! FDR exploration loop. They handle state space traversal, seed management,
//! and basic property verification.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

#[cfg(feature = "testing-timing")]
use core::time::Duration;

use crate::testing::fdr::config::FdrConfig;
use crate::testing::fdr::explorer::{ExplorationCore, ExplorationState, SeedResult, SeededRng};
use crate::testing::fdr::verdict::{Failure, RefusalSet, Trace};
use crate::testing::specs::csp::{Action, Event, Process, State};

#[cfg(feature = "testing-fault")]
use crate::testing::fdr::config::{FaultInjection, FaultModel, InjectedFaultRecord};
#[cfg(feature = "testing-timing")]
use crate::testing::timing::{TimingConstraint, TimingConstraints};

/// The default exploration engine.
pub struct DefaultExplorationEngine<'a> {
	/// The process under exploration.
	process: &'a Process,
	/// The FDR configuration of the exploration.
	config: Arc<FdrConfig>,
	/// The result of each seed.
	seed_results: Vec<(u64, SeedResult)>,
	/// The states that exploration visited, for statistics.
	visited_states: HashSet<State>,
	/// The count of branches pruned for timing violations across all seeds.
	timing_pruned: usize,
}

impl<'a> DefaultExplorationEngine<'a> {
	/// Create an exploration engine of `process` under `config`.
	pub fn new(process: &'a Process, config: Arc<FdrConfig>) -> Self {
		Self {
			process,
			config,
			seed_results: Vec::new(),
			visited_states: HashSet::new(),
			timing_pruned: 0,
		}
	}

	/// Get the seed results, for use by `FdrExplorer`.
	pub fn seed_results(&self) -> &[(u64, SeedResult)] {
		&self.seed_results
	}

	/// Get the seed results mutably, for use by `FdrExplorer`.
	pub fn seed_results_mut(&mut self) -> &mut Vec<(u64, SeedResult)> {
		&mut self.seed_results
	}

	/// Get the visited states, for use by `FdrExplorer`.
	pub fn visited_states(&self) -> &HashSet<State> {
		&self.visited_states
	}

	/// Get the visited states mutably, for use by `FdrExplorer`.
	pub fn visited_states_mut(&mut self) -> &mut HashSet<State> {
		&mut self.visited_states
	}

	/// Explore one seed, which runs its own schedule.
	fn explore_seed_internal(&mut self, seed: u64) -> SeedResult {
		let mut pruned = 0usize;
		let result = Self::explore_seed_core(
			self.process,
			&self.config,
			seed,
			|state| {
				self.visited_states.insert(state);
			},
			&mut pruned,
		);

		self.timing_pruned += pruned;

		result
	}

	/// The static form of `explore_seed`, which both the rayon-parallel and the
	/// sequential exploration loops call. It returns the seed result, the
	/// visited states, and the count of timing-pruned branches.
	pub fn explore_seed_static(
		process: &Process,
		config: &FdrConfig,
		seed: u64,
	) -> (SeedResult, HashSet<State>, usize) {
		let mut visited_states = HashSet::new();
		let mut pruned = 0usize;
		let result = Self::explore_seed_core(
			process,
			config,
			seed,
			|state| {
				visited_states.insert(state);
			},
			&mut pruned,
		);

		(result, visited_states, pruned)
	}

	/// The exploration logic that the internal and the static forms share.
	///
	/// `timing_pruned` counts the branches dropped for WCET or deadline
	/// violations, so model-level timing violations surface in the verdict
	/// instead of silently vanishing from exploration.
	fn explore_seed_core<F>(
		process: &Process,
		config: &FdrConfig,
		seed: u64,
		mut track_visited: F,
		timing_pruned: &mut usize,
	) -> SeedResult
	where
		F: FnMut(State),
	{
		let mut rng = SeededRng::new(seed);
		let mut queue = VecDeque::new();

		let initial = ExplorationState::initial(process.initial);
		queue.push_back(initial);

		// The longest trace is the best result of this seed.
		let mut longest_trace = Vec::new();
		let mut failures = Vec::new();
		#[cfg(feature = "testing-fault")]
		let mut injected_faults: Vec<InjectedFaultRecord> = Vec::new();

		while let Some(state) = queue.pop_front() {
			track_visited(state.process_state);

			// Exploration cuts a trace off at the maximum depth.
			if state.trace.len() >= config.max_depth {
				if state.trace.len() > longest_trace.len() {
					longest_trace = state.trace.clone();
				}

				// The cut-off trace records its refusals as a failure.
				let refusals = Self::compute_refusals_helper(process, state.process_state);
				failures.push((state.trace.clone(), refusals));

				continue;
			}

			// A run of hidden events past the limit is a divergence.
			if state.internal_run > config.max_internal_run {
				#[cfg(feature = "testing-fault")]
				return SeedResult::Divergence(state.trace.clone(), state.hidden_events.clone(), injected_faults);
				#[cfg(not(feature = "testing-fault"))]
				return SeedResult::Divergence(state.trace.clone(), state.hidden_events.clone());
			}

			// A terminal state ends the trace successfully.
			if process.is_terminal(state.process_state) {
				if state.trace.len() > longest_trace.len() {
					longest_trace = state.trace.clone();
				}

				// A terminal state refuses every observable event.
				let refusals = process.observable.iter().cloned().collect();
				failures.push((state.trace.clone(), refusals));

				continue;
			}

			let actions = process.enabled(state.process_state);
			if actions.is_empty() {
				// A non-terminal state with no enabled action is a deadlock.
				#[cfg(feature = "testing-fault")]
				return SeedResult::Deadlock(state.trace.clone(), state.process_state, injected_faults);
				#[cfg(not(feature = "testing-fault"))]
				return SeedResult::Deadlock(state.trace.clone(), state.process_state);
			}

			// A stable state records its refusals before it takes an action.
			if state.internal_run == 0 {
				let refusals = Self::compute_refusals_helper(process, state.process_state);
				failures.push((state.trace.clone(), refusals));
			}

			// Select the action, and retry past fault-suppressed transitions.
			// An injected fault makes the chosen event fail, so exploration
			// skips that transition and falls back to the remaining enabled
			// actions. A state left with no usable action is a fault-induced
			// deadlock (recovery failure).
			#[cfg(feature = "testing-fault")]
			let action = {
				let mut candidates: Vec<&Action> = actions.iter().collect();
				loop {
					let candidate =
						Self::select_action_helper_from(&mut rng, process, state.process_state, &candidates);
					let fault = config.fault_model.as_ref().and_then(|fault_model| {
						Self::check_fault_injection(
							fault_model,
							process,
							state.process_state,
							&candidate.event,
							&mut rng,
						)
					});

					let Some(fault_record) = fault else {
						break candidate;
					};

					injected_faults.push(fault_record);
					candidates.retain(|a| a.event != candidate.event);

					if candidates.is_empty() {
						return SeedResult::Deadlock(state.trace.clone(), state.process_state, injected_faults);
					}
				}
			};
			#[cfg(not(feature = "testing-fault"))]
			let action = Self::select_action_helper(&mut rng, process, state.process_state, &actions);

			Self::execute_transition_helper(process, &state, action, &mut queue, timing_pruned);
		}

		// The seed succeeds with its longest trace and its collected failures.
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

	fn timing_pruned(&self) -> usize {
		self.timing_pruned
	}

	fn add_timing_pruned(&mut self, count: usize) {
		self.timing_pruned += count;
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
	/// Compute the refusal set of `state`.
	///
	/// The refusal set is every observable event minus the enabled observable
	/// events. The set leaves out hidden events (τ-transitions), because a
	/// process cannot refuse them. Reference: Roscoe (1998, 2010).
	fn compute_refusals_helper(process: &Process, state: State) -> RefusalSet {
		// The filter drops hidden τ-transitions from the enabled set.
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

		process
			.observable
			.iter()
			.filter(|&event| !enabled_events.contains(event))
			.cloned()
			.collect()
	}

	/// Select the action at a choice point with the RNG.
	#[cfg(not(feature = "testing-fault"))]
	fn select_action_helper<'b>(
		rng: &mut SeededRng,
		process: &'b Process,
		process_state: State,
		actions: &'b (impl AsRef<[Action]> + ?Sized),
	) -> &'b Action {
		let actions = actions.as_ref();
		if process.choice.contains(&process_state) {
			// A nondeterministic choice point selects with the RNG.
			rng.choose(actions).unwrap_or(&actions[0])
		} else if actions.len() == 1 {
			// A state with one action takes it.
			&actions[0]
		} else {
			// An unmarked state with more than one action uses the RNG too.
			rng.choose(actions).unwrap_or(&actions[0])
		}
	}

	/// Select the action from a candidate list, in fault mode.
	///
	/// It runs the policy of `select_action_helper` over the candidates that
	/// remain after fault suppression removed the failing events.
	#[cfg(feature = "testing-fault")]
	fn select_action_helper_from<'b>(
		rng: &mut SeededRng,
		process: &Process,
		process_state: State,
		actions: &[&'b Action],
	) -> &'b Action {
		if actions.len() > 1 || process.choice.contains(&process_state) {
			rng.choose(actions).copied().unwrap_or(actions[0])
		} else {
			actions[0]
		}
	}

	/// Check for a fault injection at the current (state, event) pair.
	#[cfg(feature = "testing-fault")]
	fn check_fault_injection(
		fault_model: &FaultModel,
		process: &Process,
		state: State,
		event: &Event,
		rng: &mut SeededRng,
	) -> Option<InjectedFaultRecord> {
		// The "proc.state" lookup key costs one allocation. The Cow-keyed map
		// borrows it, so the lookup reads the fault-injection table in place.
		let state_key_str = format!("{}.{}", process.name, state.0);

		fault_model
			.state_injection(&state_key_str, event.0)
			.and_then(|injection: &FaultInjection| {
				let rng_value = rng.get_next();
				if injection.should_inject(rng_value) {
					let error = (injection.error_factory)();
					// Only the rare injecting path clones the key.
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

	/// Execute a transition and enqueue the next states.
	///
	/// Exploration drops the branches that violate WCET or deadline
	/// constraints, and each drop increments `timing_pruned`, so the verdict
	/// records that timing-violating paths existed.
	fn execute_transition_helper(
		process: &Process,
		state: &ExplorationState,
		action: &Action,
		queue: &mut VecDeque<ExplorationState>,
		timing_pruned: &mut usize,
	) {
		#[cfg(not(feature = "testing-timing"))]
		let _ = &timing_pruned;

		#[cfg(feature = "testing-timing")]
		{
			// Timed transitions, when present, check their timing guards.
			if let Some(ref timed_transitions) = process.timed_transitions {
				if let Some(transitions) = timed_transitions.get(&(state.process_state, action.event)) {
					// A transition passes when the clocks satisfy its guard.
					let valid_transitions: Vec<_> = transitions
						.iter()
						.filter(|tt| tt.guard_satisfied(&state.clock_values))
						.collect();

					if valid_transitions.is_empty() {
						// With no satisfied guard, the branch prunes.
						return;
					}

					for timed_trans in valid_transitions {
						let mut next_exploration = state.branch();
						let next_state = timed_trans.to;

						// The transition resets the clocks it names.
						next_exploration.reset_clocks(&timed_trans.reset_clocks);

						if process.hidden.contains(&action.event) {
							// This branch is a hidden (τ) transition.
							next_exploration.record_hidden(action.event, next_state);
						} else {
							// This branch is an observable transition.
							next_exploration.record_observable(action.event, next_state);

							// Timing constraints add the WCET of the event.
							if let Some(ref constraints) = process.timing_constraints {
								let wcet = Self::lookup_wcet(&action.event, constraints);
								if constraints.wcet_violated(&action.event, wcet) {
									// A WCET violation prunes this branch.
									*timing_pruned += 1;
									continue;
								}

								next_exploration.update_timing(&action.event, wcet);
								next_exploration.update_clocks(wcet);

								// The deadline and path WCET checks run
								// before the branch joins the queue.
								if Self::check_timing_violations(&next_exploration, constraints) {
									// A timing violation prunes this branch.
									*timing_pruned += 1;
									continue;
								}
							}
						}

						queue.push_back(next_exploration);
					}

					// The timed transitions handled the event, so the call
					// skips the regular step below.
					return;
				}
			}
		}

		// Regular transitions run when no timed transition exists or matches.
		let next_states = process.step(state.process_state, &action.event);
		for next_state in next_states {
			let mut next_exploration = state.branch();
			if process.hidden.contains(&action.event) {
				// This branch is a hidden (τ) transition.
				next_exploration.record_hidden(action.event, next_state);
			} else {
				// This branch is an observable transition.
				next_exploration.record_observable(action.event, next_state);

				// Timing constraints add the WCET of the event.
				#[cfg(feature = "testing-timing")]
				{
					if let Some(ref constraints) = process.timing_constraints {
						let wcet = Self::lookup_wcet(&action.event, constraints);
						if constraints.wcet_violated(&action.event, wcet) {
							// A WCET violation prunes this branch.
							*timing_pruned += 1;
							continue;
						}

						next_exploration.update_timing(&action.event, wcet);
						next_exploration.update_clocks(wcet);

						// The deadline and path WCET checks run before the
						// branch joins the queue.
						if Self::check_timing_violations(&next_exploration, constraints) {
							// A timing violation prunes this branch.
							*timing_pruned += 1;
							continue;
						}
					}
				}
			}

			queue.push_back(next_exploration);
		}
	}

	/// Look up the WCET of `event` in the timing constraints.
	#[cfg(feature = "testing-timing")]
	fn lookup_wcet(event: &Event, constraints: &TimingConstraints) -> Duration {
		if let Some(constraint) = constraints.get(event) {
			match constraint {
				TimingConstraint::Wcet(wcet_config) => wcet_config.duration,
				_ => Duration::ZERO, // Jitter and deadlines add no WCET.
			}
		} else {
			Duration::ZERO // An unconstrained event costs zero (conservative).
		}
	}

	/// Check whether `state` violates the timing constraints.
	#[cfg(feature = "testing-timing")]
	fn check_timing_violations(state: &ExplorationState, constraints: &TimingConstraints) -> bool {
		constraints.violated_by(&state.trace, state.elapsed_time, &state.event_times)
	}
}
