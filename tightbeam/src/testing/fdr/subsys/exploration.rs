//! The exploration subsystem of FDR.
//!
//! It holds the exploration engine and the functions of the FDR exploration
//! loop. They walk the state space of a process once per seed and check each
//! state they visit for divergence and deadlock. The module also adds to
//! [`Process`] the divergence of a state on a branch of the walk.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, OnceLock};

#[cfg(feature = "rayon")]
use core::ops::Range;

use crate::testing::fdr::config::FdrConfig;
use crate::testing::fdr::explorer::{ExplorationCore, ExplorationState, SeedResult, SeededRng};
use crate::testing::fdr::verdict::Trace;
use crate::testing::specs::csp::{Action, DivergentStates, Event, Process, State};

#[cfg(feature = "testing-fault")]
use crate::testing::fdr::config::{FaultInjection, FaultModel, InjectedFaultRecord};
#[cfg(feature = "testing-timing")]
use crate::testing::timing::TimingConstraints;

/// The default exploration engine, which walks one process once per seed and
/// keeps the result of each seed.
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
	/// The divergent states of the process, which the first walk computes and
	/// each later walk reads.
	divergent: OnceLock<DivergentStates>,
}

/// What the walk of one seed found.
struct SeedWalk {
	/// The result of the seed.
	result: SeedResult,
	/// The states that the walk visited.
	visited: HashSet<State>,
	/// The count of the branches that the walk pruned for timing violations.
	timing_pruned: usize,
}

impl<'a> DefaultExplorationEngine<'a> {
	/// Creates the engine of `process` under `config`, with an empty list of
	/// seed results and an empty set of visited states.
	pub fn new(process: &'a Process, config: Arc<FdrConfig>) -> Self {
		Self {
			process,
			config,
			seed_results: Vec::new(),
			visited_states: HashSet::new(),
			timing_pruned: 0,
			divergent: OnceLock::new(),
		}
	}

	/// A mutable view of the result of each seed that the engine recorded.
	pub fn seed_results_mut(&mut self) -> &mut Vec<(u64, SeedResult)> {
		&mut self.seed_results
	}

	/// A mutable view of the states that exploration visited.
	pub fn visited_states_mut(&mut self) -> &mut HashSet<State> {
		&mut self.visited_states
	}

	/// The divergent states of the process, which the first call computes.
	fn divergent(&self) -> &DivergentStates {
		self.divergent.get_or_init(|| self.process.divergent_states())
	}

	/// Adds the visited states and the timing prunes of `walk` to the engine,
	/// and returns the result of its seed.
	fn absorb(&mut self, walk: SeedWalk) -> SeedResult {
		self.visited_states.extend(walk.visited);
		self.timing_pruned += walk.timing_pruned;

		walk.result
	}

	/// Walks the schedule of `seed` through the process.
	fn walk(&self, seed: u64) -> SeedWalk {
		let mut visited = HashSet::new();
		let mut timing_pruned = 0usize;
		let result = self.walk_into(seed, &mut visited, &mut timing_pruned);

		SeedWalk { result, visited, timing_pruned }
	}

	/// The walk of `seed` under its own RNG schedule.
	///
	/// `visited` receives each state the seed visits. `timing_pruned` counts
	/// the branches dropped for deadline or path WCET violations, so the
	/// verdict reports the model-level timing violations exploration pruned.
	fn walk_into(&self, seed: u64, visited: &mut HashSet<State>, timing_pruned: &mut usize) -> SeedResult {
		let process = self.process;
		let config = &self.config;
		let mut rng = SeededRng::new(seed);
		let mut queue = VecDeque::new();

		// A run starts each clock that the process names at zero.
		#[cfg_attr(
			not(feature = "testing-timing"),
			expect(unused_mut, reason = "only a timed run starts clocks")
		)]
		let mut initial = ExplorationState::initial(process.initial);
		#[cfg(feature = "testing-timing")]
		{
			let clocks: Vec<String> = process.initial_clocks().into_keys().collect();
			initial.reset_clocks(clocks);
		}
		queue.push_back(initial);

		// The seed reports the longest trace that it reaches.
		let mut longest_trace = Vec::new();
		let mut failures = Vec::new();
		#[cfg(feature = "testing-fault")]
		let mut injected_faults: Vec<InjectedFaultRecord> = Vec::new();

		while let Some(state) = queue.pop_front() {
			visited.insert(state.process_state());

			// A state from which a run of hidden events reaches a cycle of
			// hidden events diverges, so the seed ends with a divergence.
			if let Some(run) = process.divergence_at(self.divergent(), &state) {
				#[cfg(feature = "testing-fault")]
				return SeedResult::Divergence(state.trace().to_vec(), state.process_state(), run, injected_faults);
				#[cfg(not(feature = "testing-fault"))]
				return SeedResult::Divergence(state.trace().to_vec(), state.process_state(), run);
			}

			// Exploration cuts a trace off at the maximum depth. An unstable
			// state at the bound takes its hidden steps, so the walk reaches
			// the failure behind them.
			if state.trace().len() >= config.max_depth {
				if state.trace().len() > longest_trace.len() {
					longest_trace = state.trace().to_vec();
				}

				// A stable or accepting cut-off state records its refusals as a
				// failure, and the walk ends there.
				if let Some(refusals) = self.compute_refusals(process, state.process_state()) {
					failures.push((state.trace().to_vec(), refusals));
					continue;
				}
			}

			// A run of hidden events past the limit is a divergence.
			if state.current_run().len() > config.max_internal_run {
				let run = state.current_run().to_vec();
				#[cfg(feature = "testing-fault")]
				return SeedResult::Divergence(state.trace().to_vec(), state.process_state(), run, injected_faults);
				#[cfg(not(feature = "testing-fault"))]
				return SeedResult::Divergence(state.trace().to_vec(), state.process_state(), run);
			}

			// An accepting state can end the trace successfully, and the walk
			// goes on through each action it enables.
			let accepting = process.is_terminal(state.process_state());
			if accepting && state.trace().len() > longest_trace.len() {
				longest_trace = state.trace().to_vec();
			}

			// An action is enabled at these clocks when one of its edges has no
			// guard or a guard that holds.
			#[cfg(feature = "testing-timing")]
			let mut actions = process.enabled_under(state.process_state(), state.clock_values());
			#[cfg(not(feature = "testing-timing"))]
			let mut actions = process.enabled(state.process_state());
			if actions.is_empty() && !accepting {
				// A state that can neither terminate nor act is a deadlock.
				#[cfg(feature = "testing-fault")]
				return SeedResult::Deadlock(state.trace().to_vec(), state.process_state(), injected_faults);
				#[cfg(not(feature = "testing-fault"))]
				return SeedResult::Deadlock(state.trace().to_vec(), state.process_state());
			}

			// A stable or accepting state records its refusals before it takes
			// an action.
			if let Some(refusals) = self.compute_refusals(process, state.process_state()) {
				failures.push((state.trace().to_vec(), refusals));
			}

			// A state at the bound takes its hidden steps alone, as
			// `Action::keeps_within` decides, and a state left with no step
			// ends the walk.
			actions.retain(|action| action.keeps_within(state.trace(), config.max_depth));
			if actions.is_empty() {
				continue;
			}

			// An injected fault fails the chosen event, and the walk selects
			// again from the enabled actions that remain. A state with no
			// usable action is a fault-induced deadlock (recovery failure).
			#[cfg(feature = "testing-fault")]
			let action = {
				let mut candidates: Vec<&Action> = actions.iter().collect();
				loop {
					let candidate =
						Self::select_action_helper_from(&mut rng, process, state.process_state(), &candidates);
					let fault = config.fault_model.as_ref().and_then(|fault_model| {
						Self::check_fault_injection(
							fault_model,
							process,
							state.process_state(),
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
						return SeedResult::Deadlock(state.trace().to_vec(), state.process_state(), injected_faults);
					}
				}
			};
			#[cfg(not(feature = "testing-fault"))]
			let action = Self::select_action_helper(&mut rng, process, state.process_state(), &actions);

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
	type ForProcess<'p> = DefaultExplorationEngine<'p>;

	fn for_process<'p>(&self, process: &'p Process) -> DefaultExplorationEngine<'p> {
		let config = Arc::clone(&self.config);
		DefaultExplorationEngine::new(process, config)
	}

	fn process(&self) -> &Process {
		self.process
	}

	fn config(&self) -> &FdrConfig {
		&self.config
	}

	fn explore_seed(&mut self, seed: u64) -> SeedResult {
		let walk = self.walk(seed);
		self.absorb(walk)
	}

	/// Walks the seeds in parallel on the `rayon` pool, then adds what each
	/// walk found to the engine and records its result, in seed order.
	#[cfg(feature = "rayon")]
	fn explore_seeds(&mut self, seeds: Range<u64>) -> &[(u64, SeedResult)] {
		use rayon::prelude::*;

		let engine = &*self;
		let walks: Vec<(u64, SeedWalk)> = seeds.into_par_iter().map(|seed| (seed, engine.walk(seed))).collect();
		let start = self.seed_results.len();
		for (seed, walk) in walks {
			let result = self.absorb(walk);
			self.seed_results.push((seed, result));
		}

		self.seed_results.get(start..).unwrap_or_default()
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

	fn visited_states(&self) -> &HashSet<State> {
		&self.visited_states
	}

	fn timing_pruned(&self) -> usize {
		self.timing_pruned
	}

	fn add_seed_result(&mut self, seed: u64, result: SeedResult) {
		self.seed_results.push((seed, result));
	}

	fn seed_results(&self) -> &[(u64, SeedResult)] {
		&self.seed_results
	}
}

impl<'a> DefaultExplorationEngine<'a> {
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

	/// Selects the action that exploration takes from `actions`, under
	/// `testing-fault`.
	///
	/// It applies the policy of `select_action_helper` to the candidates left
	/// after each injected fault removes the event it fails.
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
		// The `Process.State` lookup key costs one allocation. The Cow-keyed
		// map borrows it, so the lookup reads the fault-injection table in
		// place.
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
	/// It drops each branch that violates a deadline or path WCET constraint
	/// and counts the drop in `timing_pruned`, so the verdict records that a
	/// path violated timing.
	fn execute_transition_helper(
		process: &Process,
		state: &ExplorationState,
		action: &Action,
		queue: &mut VecDeque<ExplorationState>,
		#[cfg_attr(
			not(feature = "testing-timing"),
			expect(unused_variables, reason = "only the timing checks prune a branch")
		)]
		timing_pruned: &mut usize,
	) {
		// Each edge that the clocks allow is a branch, which resets the clocks
		// that the edge names.
		#[cfg(feature = "testing-timing")]
		let successors = process.successors(state.process_state(), &action.event, state.clock_values());
		#[cfg(feature = "testing-timing")]
		let branches = successors.map(|successor| {
			let mut branch = state.branch();
			branch.reset_clocks(successor.resets);
			(branch, successor.to)
		});
		#[cfg(not(feature = "testing-timing"))]
		let targets = process.step(state.process_state(), &action.event);
		#[cfg(not(feature = "testing-timing"))]
		let branches = targets.into_iter().map(|to| (state.branch(), to));

		for (mut next_exploration, next_state) in branches {
			if action.is_hidden() {
				// A hidden (τ) transition extends the run of hidden events.
				next_exploration.record_hidden(action.event, next_state);
			} else {
				// An observable transition extends the trace and ends the run
				// of hidden events.
				next_exploration.record_observable(action.event, next_state);

				// The timing constraints charge the WCET of the event to the
				// elapsed time and the clocks of the branch.
				#[cfg(feature = "testing-timing")]
				{
					if let Some(ref constraints) = process.timing_constraints {
						let wcet = constraints.wcet_of(&action.event);
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
		constraints.violated_by(state.trace(), state.elapsed_time(), state.event_times())
	}
}

impl Process {
	/// The hidden events of a run by which `branch` can diverge from its
	/// state, or `None` when it cannot, where `divergent` holds the divergent
	/// states of this process.
	///
	/// [`Process::divergent_states`] decides a process with no timed
	/// transition. A guard can block a hidden edge, so the clocks of `branch`
	/// decide a timed process, through `Process::divergence_under`.
	fn divergence_at(&self, divergent: &DivergentStates, branch: &ExplorationState) -> Option<Vec<Event>> {
		if !divergent.contains(branch.process_state()) {
			return None;
		}

		#[cfg(feature = "testing-timing")]
		if self.has_timed_transitions() {
			return self.divergence_under(branch.process_state(), branch.clock_values());
		}

		divergent.witness(branch.process_state())
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashSet;
	use std::sync::Arc;

	use super::DefaultExplorationEngine;
	use crate::testing::fdr::config::FdrConfig;
	use crate::testing::fdr::explorer::{ExplorationCore, SeedResult};
	use crate::testing::fdr::verdict::Failure;
	use crate::testing::specs::csp::{Event, Process, ProcessBuildError, State};

	/// A process whose hidden `t` sits between `a` and `c`, so `S1` enables a
	/// hidden event and `S2` is stable though a hidden event reached it.
	fn hiding() -> Result<Process, ProcessBuildError> {
		Process::builder("Hiding")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("c"))
			.add_hidden(Event("t"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_transition(State("S1"), Event("t"), State("S2"))
			.add_transition(State("S2"), Event("c"), State("S3"))
			.add_terminal(State("S3"))
			.build()
	}

	/// The process of `hiding` with `c` at `S1` as well, so `S1` enables a
	/// hidden and an observable event, and `t` leads to the accepting `S2`.
	fn hiding_beside_c() -> Result<Process, ProcessBuildError> {
		Process::builder("HidingBesideC")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("c"))
			.add_hidden(Event("t"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_transition(State("S1"), Event("t"), State("S2"))
			.add_transition(State("S1"), Event("c"), State("S3"))
			.add_terminal(State("S2"))
			.add_terminal(State("S3"))
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

	/// A process whose `a` leads from `S0` to `S1`, which can neither terminate
	/// nor act.
	fn stuck_after_a() -> Result<Process, ProcessBuildError> {
		Process::builder("StuckAfterA")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.build()
	}

	/// A process whose `a` leads from `S0` to `S1`, which spins on the hidden
	/// `t`.
	fn spinning_after_a() -> Result<Process, ProcessBuildError> {
		Process::builder("SpinningAfterA")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_hidden(Event("t"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_transition(State("S1"), Event("t"), State("S1"))
			.build()
	}

	/// The result of seed 0 of `process` under `config`.
	fn result_of(process: &Process, config: FdrConfig) -> SeedResult {
		let mut engine = DefaultExplorationEngine::new(process, Arc::new(config));
		engine.explore_seed(0)
	}

	/// The failures that seed 0 of `process` under `config` records, a seed
	/// that runs to its end.
	fn failures_of(process: &Process, config: FdrConfig) -> Vec<Failure> {
		match result_of(process, config) {
			#[cfg(feature = "testing-fault")]
			SeedResult::Success(_trace, failures, _faults) => failures,
			#[cfg(not(feature = "testing-fault"))]
			SeedResult::Success(_trace, failures) => failures,
			ended => panic!("seed 0 ended in {ended:?}"),
		}
	}

	#[test]
	fn the_walk_records_a_failure_at_each_stable_state() -> Result<(), ProcessBuildError> {
		let process = hiding()?;

		let failures = failures_of(&process, FdrConfig::default());
		let expected: Vec<Failure> = vec![
			(vec![], HashSet::from([Event("c")])),
			(vec![Event("a")], HashSet::from([Event("a")])),
			(vec![Event("a"), Event("c")], HashSet::from([Event("a"), Event("c")])),
		];
		assert_eq!(failures, expected, "`S1` enables `t`, and `S2` is stable");
		Ok(())
	}

	#[test]
	fn the_walk_records_the_failure_behind_a_hidden_step_at_max_depth() -> Result<(), ProcessBuildError> {
		let process = hiding()?;
		let config = FdrConfig { max_depth: 1, ..Default::default() };

		let failures = failures_of(&process, config);
		let expected: Vec<Failure> = vec![
			(vec![], HashSet::from([Event("c")])),
			(vec![Event("a")], HashSet::from([Event("a")])),
		];
		assert_eq!(failures, expected, "`S1` takes the hidden `t` at the bound to the stable `S2`");
		Ok(())
	}

	#[test]
	fn the_walk_takes_no_observable_step_past_max_depth() -> Result<(), ProcessBuildError> {
		let process = hiding_beside_c()?;
		let config = FdrConfig { max_depth: 1, ..Default::default() };

		let failures = failures_of(&process, config);
		let expected: Vec<Failure> = vec![
			(vec![], HashSet::from([Event("c")])),
			(vec![Event("a")], HashSet::from([Event("a"), Event("c")])),
		];
		assert_eq!(failures, expected, "`S1` lies at the bound, so it takes `t` and leaves `c`");
		Ok(())
	}

	#[test]
	fn the_walk_extends_the_trace_by_the_alphabet_of_its_action() -> Result<(), ProcessBuildError> {
		let process = e_in_both_alphabets()?;

		let failures = failures_of(&process, FdrConfig::default());
		let expected: Vec<Failure> = vec![(vec![Event("e")], HashSet::from([Event("e")]))];
		assert_eq!(failures, expected, "seed 0 takes the observable action of `e`");
		Ok(())
	}

	#[test]
	fn a_state_that_can_neither_terminate_nor_act_ends_the_seed_in_a_deadlock() -> Result<(), ProcessBuildError> {
		let process = stuck_after_a()?;
		let result = result_of(&process, FdrConfig::default());
		assert!(matches!(result, SeedResult::Deadlock(..)), "the result was {result:?}");
		Ok(())
	}

	#[test]
	fn a_state_on_a_hidden_cycle_ends_the_seed_in_a_divergence() -> Result<(), ProcessBuildError> {
		let process = spinning_after_a()?;
		let result = result_of(&process, FdrConfig::default());
		assert!(matches!(result, SeedResult::Divergence(..)), "the result was {result:?}");
		Ok(())
	}

	#[test]
	fn a_seed_that_reaches_an_accepting_state_succeeds() -> Result<(), ProcessBuildError> {
		let process = hiding()?;
		let result = result_of(&process, FdrConfig::default());
		assert!(matches!(result, SeedResult::Success(..)), "the result was {result:?}");
		Ok(())
	}
}
