//! The engine subsystem of FDR.
//!
//! This module holds [`FdrExplorer`], which runs exploration and refinement
//! checks through subsystems that a caller can replace.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

#[cfg(feature = "rayon")]
use std::collections::HashSet;

use super::cache::DefaultCache;
use super::exploration::DefaultExplorationEngine;
use super::refinement::DefaultRefinementChecker;
use crate::testing::fdr::config::FdrConfig;
use crate::testing::fdr::explorer::{ExplorationCore, RefinementChecker, RefinementOutcome, SeedResult};
use crate::testing::fdr::verdict::{Decision, FdrVerdict};
use crate::testing::specs::csp::{Event, Process, State};

/// The FDR explorer, generic over its two subsystems.
///
/// The type parameters name the subsystems:
/// - `E` is the exploration engine, an [`ExplorationCore`].
/// - `R` is the refinement checker, a [`RefinementChecker`].
///
/// The refinement checker owns its memoization cache.
pub struct FdrExplorer<'a, E, R>
where
	E: ExplorationCore,
	R: RefinementChecker,
{
	/// The process under verification.
	process: &'a Process,

	/// The FDR configuration, which the subsystems share.
	config: Arc<FdrConfig>,

	/// The exploration engine, which runs each seed.
	explorer: E,

	/// The refinement checker, which tests the process against each spec.
	refinement: R,

	/// The verdict that the run accumulates.
	verdict: FdrVerdict,
}

/// The FDR explorer with the default exploration engine and refinement checker.
pub type DefaultFdrExplorer<'a> =
	FdrExplorer<'a, DefaultExplorationEngine<'a>, DefaultRefinementChecker<'a, DefaultCache>>;

impl<'a, E, R> FdrExplorer<'a, E, R>
where
	E: ExplorationCore,
	R: RefinementChecker,
{
	/// An explorer of `process` under `config` with the given subsystems.
	///
	/// The refinement checker owns the cache, which it receives at its
	/// construction.
	pub fn new(process: &'a Process, config: FdrConfig, explorer: E, refinement: R) -> Self {
		Self {
			process,
			config: Arc::new(config),
			explorer,
			refinement,
			verdict: FdrVerdict::default(),
		}
	}

	/// An explorer of `process` under a shared `config` with the given
	/// subsystems.
	///
	/// Use it when the subsystems already share `config` through an [`Arc`].
	pub fn new_with_arc(process: &'a Process, config: Arc<FdrConfig>, explorer: E, refinement: R) -> Self {
		Self { process, config, explorer, refinement, verdict: FdrVerdict::default() }
	}

	/// Runs Layer 3 and reports what it decided.
	///
	/// This one exit path decides schedulability, so a spec that misses its
	/// deadlines cannot reach a consumer as a verdict that held.
	pub fn explore(&mut self) -> FdrVerdict {
		let mut verdict = self.explore_modes();
		verdict.schedulable = self.schedulability();

		verdict
	}

	/// What schedulability analysis decided about the configured specs.
	///
	/// A spec with no schedulability block has no task set. An analysis error
	/// decides [`Decision::Refuted`] and not [`Decision::Unknown`], because
	/// every `SchedulabilityError` names a defect in the declared task set,
	/// such as a period with no WCET.
	#[cfg(feature = "testing-schedulability")]
	fn schedulability(&self) -> Decision {
		let mut decision = Decision::NotAsserted;
		for spec in self.config.specs.iter() {
			let analysed = match spec.schedulability_violated() {
				Ok(false) => Decision::Holds,
				Ok(true) | Err(_) => Decision::Refuted,
			};

			decision = decision.and(analysed);
		}

		decision
	}

	/// A build without `testing-schedulability` leaves schedulability
	/// [`Decision::NotAsserted`].
	#[cfg(not(feature = "testing-schedulability"))]
	fn schedulability(&self) -> Decision {
		Decision::NotAsserted
	}

	/// Whether this run asserts deadlock freedom and divergence freedom.
	///
	/// Fault injection measures what the faults cause, so the deadlock it
	/// reaches is an observation for the error-recovery counters and the FMEA
	/// report, not a claim.
	#[cfg(feature = "testing-fault")]
	fn asserts_freedom(&self) -> bool {
		self.config.fault_model.is_none()
	}

	/// A build without `testing-fault` has no fault model, so every run asserts
	/// freedom.
	#[cfg(not(feature = "testing-fault"))]
	fn asserts_freedom(&self) -> bool {
		true
	}

	/// Runs the exploration mode that the configuration selects.
	fn explore_modes(&mut self) -> FdrVerdict {
		// Mode 1: a fault model with specs explores each spec under faults.
		#[cfg(feature = "testing-fault")]
		if self.config.fault_model.is_some() && !self.config.specs.is_empty() {
			// The run tests whether each spec models the error conditions that
			// the faults cause.
			self.explore_specification_with_faults();
			#[cfg(feature = "testing-fmea")]
			self.generate_fmea_if_configured();
			return self.verdict.clone();
		}

		// Mode 2: specs with no fault model run the refinement checks.
		if !self.config.specs.is_empty() {
			self.check_refinement();
			#[cfg(feature = "testing-fmea")]
			self.generate_fmea_if_configured();
			return self.verdict.clone();
		}

		// Mode 3: a run with no spec explores the process over every seed.
		if self.asserts_freedom() {
			self.verdict.divergence_free = Decision::Holds;
			self.verdict.deadlock_free = Decision::Holds;
		}

		#[cfg(feature = "rayon")]
		{
			use rayon::prelude::*;
			let seeds: Vec<u64> = (0..self.config.seeds).map(|s| s as u64).collect();
			let process = self.process;
			let config = &self.config;

			let results: Vec<(u64, SeedResult, HashSet<State>, usize)> = seeds
				.par_iter()
				.map(|&seed| {
					let (result, visited, pruned) =
						DefaultExplorationEngine::explore_seed_static(process, config, seed);
					(seed, result, visited, pruned)
				})
				.collect();

			for (seed, result, visited, pruned) in results {
				self.update_verdict_from_result(seed, &result);
				self.explorer.add_seed_result(seed, result);
				self.explorer.update_visited_states(&visited);
				self.explorer.add_timing_pruned(pruned);
			}
		}

		#[cfg(not(feature = "rayon"))]
		{
			for seed in 0..self.config.seeds {
				let result = self.explorer.explore_seed(seed as u64);
				self.update_verdict_from_result(seed as u64, &result);
				self.explorer.add_seed_result(seed as u64, result);
			}
		}

		self.verdict.traces_explored = self.explorer.traces().len();
		self.verdict.states_visited = self.explorer.states_visited();
		self.verdict.timing_pruned = self.explorer.timing_pruned();

		self.check_determinism();

		#[cfg(feature = "testing-fmea")]
		self.generate_fmea_if_configured();

		self.verdict.clone()
	}

	/// Adds the result of `seed` to the verdict.
	///
	/// A seed that injected a fault feeds the error-recovery counters, which
	/// FMEA detection ratings divide.
	fn update_verdict_from_result(&mut self, seed: u64, result: &SeedResult) {
		match result {
			#[cfg(feature = "testing-fault")]
			SeedResult::Divergence(_trace, hidden, faults) => {
				self.verdict.divergence_free = self.verdict.divergence_free.refute();
				self.verdict.divergence_witness = Some((seed, hidden.clone()));
				self.verdict.failing_seed = Some(seed);
				if !faults.is_empty() {
					self.verdict.error_recovery_failed += 1;
				}
				self.verdict.faults_injected.extend(faults.clone());
			}
			#[cfg(not(feature = "testing-fault"))]
			SeedResult::Divergence(_trace, hidden) => {
				self.verdict.divergence_free = self.verdict.divergence_free.refute();
				self.verdict.divergence_witness = Some((seed, hidden.clone()));
				self.verdict.failing_seed = Some(seed);
			}
			#[cfg(feature = "testing-fault")]
			SeedResult::Deadlock(trace, state, faults) => {
				self.verdict.deadlock_free = self.verdict.deadlock_free.refute();
				self.verdict.deadlock_witness = Some((seed, trace.clone(), *state));
				self.verdict.failing_seed = Some(seed);
				if !faults.is_empty() {
					self.verdict.error_recovery_failed += 1;
				}
				self.verdict.faults_injected.extend(faults.clone());
			}
			#[cfg(not(feature = "testing-fault"))]
			SeedResult::Deadlock(trace, state) => {
				self.verdict.deadlock_free = self.verdict.deadlock_free.refute();
				self.verdict.deadlock_witness = Some((seed, trace.clone(), *state));
				self.verdict.failing_seed = Some(seed);
			}
			#[cfg(feature = "testing-fault")]
			SeedResult::Success(_trace, _failures, faults) => {
				self.verdict.seeds_completed += 1;
				if !faults.is_empty() {
					self.verdict.error_recovery_successful += 1;
				}
				self.verdict.faults_injected.extend(faults.clone());
			}
			#[cfg(not(feature = "testing-fault"))]
			SeedResult::Success(..) => {
				self.verdict.seeds_completed += 1;
			}
		}
	}

	/// Explores every configured spec under fault injection, over every seed.
	///
	/// A run that stressed only `specs[0]` would skip the rest without a
	/// signal, so the loop covers every spec.
	#[cfg(feature = "testing-fault")]
	fn explore_specification_with_faults(&mut self) {
		if self.config.specs.is_empty() {
			return;
		}

		let config = Arc::clone(&self.config);
		for spec_process in &config.specs {
			#[cfg(feature = "rayon")]
			{
				use rayon::prelude::*;
				let seeds: Vec<u64> = (0..config.seeds).map(|s| s as u64).collect();

				let results: Vec<(u64, SeedResult, HashSet<State>, usize)> = seeds
					.par_iter()
					.map(|&seed| {
						let (result, visited, pruned) =
							DefaultExplorationEngine::explore_seed_static(spec_process, &config, seed);
						(seed, result, visited, pruned)
					})
					.collect();

				for (seed, result, visited, pruned) in results {
					self.update_verdict_from_result(seed, &result);
					self.explorer.add_seed_result(seed, result);
					self.explorer.update_visited_states(&visited);
					self.explorer.add_timing_pruned(pruned);
				}
			}

			#[cfg(not(feature = "rayon"))]
			{
				let results: Vec<_> = (0..config.seeds)
					.map(|seed| {
						let seed = seed as u64;
						let (result, visited, pruned) =
							DefaultExplorationEngine::explore_seed_static(spec_process, &config, seed);
						(seed, result, visited, pruned)
					})
					.collect();

				for (seed, result, visited, pruned) in results {
					self.update_verdict_from_result(seed, &result);
					self.explorer.add_seed_result(seed, result);
					self.explorer.update_visited_states(&visited);
					self.explorer.add_timing_pruned(pruned);
				}
			}
		}

		self.verdict.traces_explored = self.explorer.traces().len();
		self.verdict.states_visited = self.explorer.states_visited();
		self.verdict.timing_pruned = self.explorer.timing_pruned();

		self.check_determinism();
	}

	/// Builds the FMEA report when the FMEA configuration sets `auto_generate`
	/// and the run injected a fault.
	#[cfg(feature = "testing-fmea")]
	fn generate_fmea_if_configured(&mut self) {
		if let Some(ref fmea_config) = self.config.fmea_config {
			if fmea_config.auto_generate && !self.verdict.faults_injected.is_empty() {
				match self.verdict.fmea_report(self.process, Some(fmea_config.clone())) {
					Ok(report) => self.verdict.fmea_report = Some(report),
					Err(e) => eprintln!("Warning: FMEA generation failed: {}", e),
				}
			}
		}
	}

	/// Records whether the process is structurally deterministic.
	///
	/// A process with no hidden action and no multi-target `(state, event)`
	/// transition is deterministic in CSP (Roscoe 2010, §10.5). External choice
	/// is deterministic, so the check passes it.
	fn check_determinism(&mut self) {
		let mut states: Vec<State> = self.process.states.iter().copied().collect();
		states.sort_unstable_by_key(|state| state.0);

		let mut witness = None;
		'states: for state in states {
			for action in self.process.enabled(state) {
				if action.is_hidden() || self.process.step(state, &action.event).len() > 1 {
					witness = Some((state, action.event));
					break 'states;
				}
			}
		}

		self.verdict.is_deterministic = witness.is_none();
		self.verdict.determinism_witness = witness;
	}

	/// Checks `process ⊑ spec` in the models that the subject admits.
	///
	/// The check always asks traces refinement. It asks failures and
	/// divergences only of a subject whose observation carries refusals, or the
	/// checker would grade the subject on refusals it synthesized. Under
	/// `fail_fast`, each pass stops at its first violation.
	fn check_refinement(&mut self) {
		if self.config.specs.is_empty() {
			return;
		}

		// The check reads the spec list through an `Arc` clone and not a copy,
		// because a clone of `Vec<Process>` duplicates every state set and
		// transition map that the checker only reads.
		let config = Arc::clone(&self.config);
		let specs = config.specs.as_slice();
		self.verdict.unmodelled_events = self.unmodelled_events();

		self.verdict.trace_refines = self.check_refinement_for_specs(
			specs,
			|r, s| r.check_trace_refinement(s, self.process),
			|v, w| {
				v.trace_refinement_witness = Some(w);
			},
		);

		if !self.process.observation.carries_refusals() {
			return;
		}

		self.verdict.failures_refines = self.check_refinement_for_specs(
			specs,
			|r, s| r.check_failures_refinement(s, self.process),
			|v, w| {
				v.failures_refinement_witness = Some(w);
			},
		);

		self.verdict.divergence_refines = self.check_refinement_for_specs(
			specs,
			|r, s| r.check_divergence_refinement(s, self.process),
			|v, w| {
				v.divergence_refinement_witness = Some(w);
			},
		);
	}

	/// The events the subject can perform that no configured spec models,
	/// sorted by name.
	///
	/// An event one spec models is modelled, so the specs intersect rather
	/// than accumulate.
	fn unmodelled_events(&self) -> Vec<Event> {
		let Some((first, rest)) = self.config.specs.split_first() else {
			return Vec::new();
		};

		let mut shared = first.unmodelled(self.process);
		for spec in rest {
			let modelled_by_spec = spec.unmodelled(self.process);
			shared.retain(|event| modelled_by_spec.contains(event));
		}

		shared
	}

	/// What one refinement model decided across every spec.
	///
	/// A check that ran out of budget decides [`Decision::Unknown`]: no
	/// counterexample refutes nothing, and an unexhausted search proves
	/// nothing. A truncated enumeration decides the same way, because
	/// refinement quantifies over every trace of the subject.
	fn check_refinement_for_specs<W, F, G>(
		&mut self,
		specs: impl AsRef<[Process]>,
		check: F,
		record_witness: G,
	) -> Decision
	where
		F: Fn(&mut R, &Process) -> RefinementOutcome<W>,
		G: Fn(&mut FdrVerdict, W),
	{
		let specs = specs.as_ref();
		let mut decision = Decision::NotAsserted;
		for spec in specs {
			match check(&mut self.refinement, spec) {
				RefinementOutcome::Holds { complete } => {
					let held = match complete {
						true => Decision::Holds,
						false => Decision::Unknown,
					};

					decision = decision.and(held);
				}
				RefinementOutcome::Violated(witness) => {
					record_witness(&mut self.verdict, witness);
					decision = decision.and(Decision::Refuted);
					if self.config.fail_fast {
						return decision;
					}
				}
				RefinementOutcome::Inconclusive => decision = decision.and(Decision::Unknown),
			}
		}

		decision
	}
}

impl<'a> DefaultFdrExplorer<'a> {
	/// An explorer of `process` under `config` with the default subsystems.
	///
	/// The default subsystems are [`DefaultExplorationEngine`] and
	/// [`DefaultRefinementChecker`] over a [`DefaultCache`].
	/// [`FdrExplorer::new`] takes other subsystems.
	///
	/// `config` is an owned [`FdrConfig`] or an `Arc<FdrConfig>`.
	pub fn with_defaults(process: &'a Process, config: impl Into<Arc<FdrConfig>>) -> Self {
		let config = config.into();
		let explorer_config = Arc::clone(&config);
		let explorer = DefaultExplorationEngine::new(process, explorer_config);
		let cache = Rc::new(RefCell::new(DefaultCache::new()));
		let refinement_config = Arc::clone(&config);
		let refinement = DefaultRefinementChecker::new(process, refinement_config, cache);

		FdrExplorer::new_with_arc(process, config, explorer, refinement)
	}
}

#[cfg(test)]
mod tests {
	#[cfg(feature = "testing-timing")]
	use core::time::Duration;

	use super::Decision;
	use crate::testing::fdr::{DefaultFdrExplorer, FdrConfig};
	use crate::testing::specs::csp::{Event, Process, ProcessBuildError, State};

	#[cfg(feature = "testing-timing")]
	use crate::testing::timing::TimingGuard;

	/// A spec that models `start` and nothing else.
	fn narrow_spec() -> Result<Process, ProcessBuildError> {
		Process::builder("NarrowSpec")
			.initial_state(State("S0"))
			.add_observable(Event("start"))
			.add_transition(State("S0"), Event("start"), State("S1"))
			.add_terminal(State("S1"))
			.build()
	}

	/// A subject in which `arm` takes `S0` to `S1` when `clk` reads at most
	/// 5 ms, and `S1` is not terminal and offers no event.
	#[cfg(feature = "testing-timing")]
	fn guarded_deadlock() -> Result<Process, ProcessBuildError> {
		let guard = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));

		Process::builder("GuardedDeadlock")
			.initial_state(State("S0"))
			.add_observable(Event("arm"))
			.add_timed_transition(State("S0"), Event("arm"), State("S1"), Some(guard), Vec::new())
			.build()
	}

	/// A subject in which `start` takes `S0` to `S1` and resets `clk`, and
	/// `arm` takes `S1` to the terminal `S2` when `clk` reads at most 5 ms.
	#[cfg(feature = "testing-timing")]
	fn reset_then_guard() -> Result<Process, ProcessBuildError> {
		let guard = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));

		Process::builder("ResetThenGuard")
			.initial_state(State("S0"))
			.add_observable(Event("start"))
			.add_observable(Event("arm"))
			.add_timed_transition(State("S0"), Event("start"), State("S1"), None, ["clk".to_string()])
			.add_timed_transition(State("S1"), Event("arm"), State("S2"), Some(guard), Vec::new())
			.add_terminal(State("S2"))
			.build()
	}

	/// A subject that performs `start`, then an event no spec mentions.
	fn wider_subject() -> Result<Process, ProcessBuildError> {
		Process::builder("WiderSubject")
			.initial_state(State("T0"))
			.add_observable(Event("start"))
			.add_observable(Event("audit"))
			.add_transition(State("T0"), Event("start"), State("T1"))
			.add_transition(State("T1"), Event("audit"), State("T2"))
			.add_terminal(State("T2"))
			.build()
	}

	#[test]
	fn refinement_reports_what_the_projection_discarded() -> Result<(), ProcessBuildError> {
		let subject = wider_subject()?;
		let config = FdrConfig { specs: vec![narrow_spec()?], ..Default::default() };
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, config);

		let verdict = explorer.explore();
		assert_eq!(verdict.unmodelled_events, vec![Event("audit")]);
		assert_eq!(
			verdict.trace_refines,
			Decision::Holds,
			"`audit` is projected away, so it is coverage and not a counterexample"
		);

		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_guarded_process_over_a_deadlock_is_not_deadlock_free() -> Result<(), ProcessBuildError> {
		let subject = guarded_deadlock()?;
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, FdrConfig::default());

		let verdict = explorer.explore();
		assert_eq!(verdict.deadlock_free, Decision::Refuted);

		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_reset_clock_lets_exploration_take_the_guard_behind_it() -> Result<(), ProcessBuildError> {
		let subject = reset_then_guard()?;
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, FdrConfig::default());

		let verdict = explorer.explore();
		assert_eq!(verdict.deadlock_free, Decision::Holds);

		Ok(())
	}
}
