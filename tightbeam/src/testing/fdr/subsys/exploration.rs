//! The exploration subsystem of FDR.
//!
//! The module holds the exploration engine and the helper functions of the FDR
//! exploration loop. They handle state space traversal, seed management, and
//! the deadlock and divergence checks.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use crate::testing::fdr::config::FdrConfig;
use crate::testing::fdr::explorer::{ExplorationCore, ExplorationState, SeedResult, SeededRng};
use crate::testing::fdr::verdict::{Failure, RefusalSet, Trace};
use crate::testing::specs::csp::{Action, Event, Process, State};

#[cfg(feature = "testing-fault")]
use crate::testing::fdr::config::{FaultInjection, FaultModel, InjectedFaultRecord};
#[cfg(feature = "testing-timing")]
use crate::testing::timing::TimingConstraints;

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
	/// An exploration engine of `process` under `config`.
	pub fn new(process: &'a Process, config: Arc<FdrConfig>) -> Self {
		Self {
			process,
			config,
			seed_results: Vec::new(),
			visited_states: HashSet::new(),
			timing_pruned: 0,
		}
	}

	/// The result of each seed that the engine recorded.
	pub fn seed_results(&self) -> &[(u64, SeedResult)] {
		&self.seed_results
	}

	/// A mutable view of the result of each seed that the engine recorded.
	pub fn seed_results_mut(&mut self) -> &mut Vec<(u64, SeedResult)> {
		&mut self.seed_results
	}

	/// The states that exploration visited.
	pub fn visited_states(&self) -> &HashSet<State> {
		&self.visited_states
	}

	/// A mutable view of the states that exploration visited.
	pub fn visited_states_mut(&mut self) -> &mut HashSet<State> {
		&mut self.visited_states
	}

	/// Explores one seed under its own RNG schedule, and adds its visited
	/// states and its count of timing-pruned branches to the engine.
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
	/// `timing_pruned` counts the branches dropped for WCET, deadline, or path
	/// WCET violations, so the verdict reports the model-level timing
	/// violations that exploration pruned.
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

			// An action is enabled at these clocks when one of its edges has no
			// guard or a guard that holds.
			#[cfg(feature = "testing-timing")]
			let actions = process.enabled_under(state.process_state, &state.clock_values);
			#[cfg(not(feature = "testing-timing"))]
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

			// An injected fault makes the chosen event fail, so exploration
			// skips that transition and selects again from the remaining
			// enabled actions. A state left with no usable action is a
			// fault-induced deadlock (recovery failure).
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
	/// The refusal set of `state`.
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

	/// Selects the action that exploration takes from `actions`, with the RNG
	/// wherever more than one action is enabled.
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

	/// Selects the action from a candidate list, in fault mode.
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

	/// The fault record when the fault model holds an injection for this
	/// `(state, event)` pair and the RNG draw fires it.
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
					// Only a path that injects a fault clones the key.
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

	/// Executes a transition and queues the next states.
	///
	/// Exploration drops the branches that violate a WCET, deadline, or path
	/// WCET constraint, and each drop increments `timing_pruned`, so the
	/// verdict records that a path violated timing.
	fn execute_transition_helper(
		process: &Process,
		state: &ExplorationState,
		action: &Action,
		queue: &mut VecDeque<ExplorationState>,
		timing_pruned: &mut usize,
	) {
		#[cfg(not(feature = "testing-timing"))]
		let _ = &timing_pruned;

		// Each edge that the clocks allow is a branch, which resets the clocks
		// that the edge names.
		#[cfg(feature = "testing-timing")]
		let successors = process.successors(state.process_state, &action.event, &state.clock_values);
		#[cfg(feature = "testing-timing")]
		let branches = successors.map(|successor| {
			let mut branch = state.branch();
			branch.reset_clocks(successor.resets);
			(branch, successor.to)
		});
		#[cfg(not(feature = "testing-timing"))]
		let targets = process.step(state.process_state, &action.event);
		#[cfg(not(feature = "testing-timing"))]
		let branches = targets.into_iter().map(|to| (state.branch(), to));

		for (mut next_exploration, next_state) in branches {
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
						let wcet = constraints.wcet_of(&action.event);
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

	/// Whether `state` violates the timing constraints.
	#[cfg(feature = "testing-timing")]
	fn check_timing_violations(state: &ExplorationState, constraints: &TimingConstraints) -> bool {
		constraints.violated_by(&state.trace, state.elapsed_time, &state.event_times)
	}
}
