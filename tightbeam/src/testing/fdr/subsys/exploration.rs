//! Exploration subsystem
//!
//! This module contains the exploration engine implementation and helper functions
//! for the FDR exploration loop. These handle state space traversal, seed management,
//! and basic property verification.

use std::collections::{HashSet, VecDeque};

use crate::testing::fdr::config::{Failure, FdrConfig, RefusalSet, Trace};
use crate::testing::fdr::explorer::{ExplorationCore, ExplorationState, SeedResult, SeededRng};
use crate::testing::specs::csp::{Action, Event, Process, State};

/// Default exploration engine implementation
pub struct DefaultExplorationEngine<'a> {
	/// Process being explored
	process: &'a Process,
	/// Configuration
	config: FdrConfig,
	/// Results per seed
	seed_results: Vec<(u64, SeedResult)>,
	/// States visited (for statistics)
	visited_states: HashSet<State>,
}

impl<'a> DefaultExplorationEngine<'a> {
	/// Create new exploration engine
	pub fn new(process: &'a Process, config: FdrConfig) -> Self {
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

			// Execute transition
			Self::execute_transition_helper(process, &state, action, &mut queue);
		}

		// Return success with longest trace found and collected failures
		SeedResult::Success(longest_trace, failures)
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
		let result = self.explore_seed_internal(seed);
		self.seed_results.push((seed, result.clone()));
		result
	}

	fn check_determinism(&mut self) {
		// Determinism checking is handled by FdrExplorer using seed_results
		// This is a no-op at the exploration level
	}

	fn traces(&self) -> Vec<Trace> {
		self.seed_results
			.iter()
			.filter_map(|(_, result)| match result {
				SeedResult::Success(trace, _failures) => Some(trace.clone()),
				_ => None,
			})
			.collect()
	}

	fn failures(&self) -> Vec<Failure> {
		let mut failures = Vec::new();
		for (_, result) in &self.seed_results {
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
		use std::collections::HashSet;
		// Only consider observable events (filter out hidden τ-transitions)
		let enabled_events: HashSet<_> = process
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
			rng.choose(actions).expect("actions not empty")
		} else if actions.len() == 1 {
			// Deterministic: only one choice
			&actions[0]
		} else {
			// Multiple actions but not marked as choice state: use RNG anyway
			rng.choose(actions).expect("actions not empty")
		}
	}

	/// Execute transition and enqueue next states
	fn execute_transition_helper(
		process: &Process,
		state: &ExplorationState,
		action: &Action,
		queue: &mut VecDeque<ExplorationState>,
	) {
		let next_states = process.step(state.process_state, &action.event);
		for next_state in next_states {
			let mut next_exploration = state.branch();
			if process.hidden.contains(&action.event) {
				// Hidden (τ) transition
				next_exploration.record_hidden(action.event.clone(), next_state);
			} else {
				// Observable transition
				next_exploration.record_observable(action.event.clone(), next_state);
			}

			queue.push_back(next_exploration);
		}
	}
}
