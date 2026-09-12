//! FDR exploration engine subsystem
//!
//! This module contains the core FdrExplorer struct that orchestrates
//! exploration and refinement checking by delegating to pluggable subsystems.

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
use crate::testing::fdr::verdict::{Decision, Failure, FdrVerdict, Trace};
use crate::testing::specs::csp::{Event, Process, State};

/// FDR exploration engine (pluggable design)
///
/// Generic over subsystem implementations:
/// - `E`: Exploration engine (implements `ExplorationCore`)
/// - `R`: Refinement checker (implements `RefinementChecker`)
///
/// The refinement checker manages its own memoization cache internally.
pub struct FdrExplorer<'a, E, R>
where
	E: ExplorationCore,
	R: RefinementChecker,
{
	/// Process being verified
	process: &'a Process,

	/// Configuration
	config: Arc<FdrConfig>,

	/// Exploration engine
	explorer: E,

	/// Refinement checker
	refinement: R,

	/// Verdict accumulator
	verdict: FdrVerdict,
}

/// Default FDR explorer using default subsystem implementations
pub type DefaultFdrExplorer<'a> =
	FdrExplorer<'a, DefaultExplorationEngine<'a>, DefaultRefinementChecker<'a, DefaultCache>>;

impl<'a, E, R> FdrExplorer<'a, E, R>
where
	E: ExplorationCore,
	R: RefinementChecker,
{
	/// Create new FDR explorer with custom subsystems
	///
	/// The cache is managed by the refinement checker, which receives it during construction.
	pub fn new(process: &'a Process, config: FdrConfig, explorer: E, refinement: R) -> Self {
		Self {
			process,
			config: Arc::new(config),
			explorer,
			refinement,
			verdict: FdrVerdict::default(),
		}
	}

	/// Create new FDR explorer with custom subsystems using `Arc<FdrConfig>`
	///
	/// Use this when you've already created an `Arc<FdrConfig>` to share across subsystems.
	pub fn new_with_arc(process: &'a Process, config: Arc<FdrConfig>, explorer: E, refinement: R) -> Self {
		Self { process, config, explorer, refinement, verdict: FdrVerdict::default() }
	}

	/// Run Layer 3 and report what it decided.
	///
	/// Schedulability is decided on this one exit path, so a spec that misses
	/// its deadlines cannot reach a consumer as a verdict that held.
	pub fn explore(&mut self) -> FdrVerdict {
		let mut verdict = self.explore_modes();
		verdict.schedulable = self.schedulability();

		verdict
	}

	/// What schedulability analysis decided about the configured specs.
	///
	/// A spec declaring no schedulability block has no task set. An analysis
	/// error refutes rather than leaving the question open: every
	/// `SchedulabilityError` names a defect in the declared task set, such as
	/// a period with no WCET.
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

	/// Where schedulability analysis does not compile in.
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

	/// Where no fault model can be configured.
	#[cfg(not(feature = "testing-fault"))]
	fn asserts_freedom(&self) -> bool {
		true
	}

	/// Run multi-seed exploration
	fn explore_modes(&mut self) -> FdrVerdict {
		// Mode 1: Specification robustness testing (fault model + specs)
		// When fault_model is provided with specs, explore the spec WITH faults
		#[cfg(feature = "testing-fault")]
		if self.config.fault_model.is_some() && !self.config.specs.is_empty() {
			// Explore the specification process with faults injected
			// This tests if the SPEC correctly models error conditions
			self.explore_specification_with_faults();
			#[cfg(feature = "testing-fmea")]
			self.generate_fmea_if_configured();
			return self.verdict.clone();
		}

		// Mode 2: Refinement checking (specs without fault model)
		if !self.config.specs.is_empty() {
			self.check_refinement();
			#[cfg(feature = "testing-fmea")]
			self.generate_fmea_if_configured();
			return self.verdict.clone();
		}

		// Mode 3: Single-process multi-seed exploration
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

	/// Update verdict based on seed result
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

	/// Explore every configured spec with fault injection
	///
	/// Every spec, not just `specs[0]`: stressing only the first silently
	/// skips the rest.
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

	/// Generate FMEA report if configured
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

	/// Structural determinism check
	///
	/// No hidden actions and no multi-target `(state, event)` transition is
	/// sufficient for CSP determinism (Roscoe 2010, §10.5). External choice is
	/// deterministic and is not flagged.
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

	/// Check `process ⊑ spec` in the models the subject admits
	///
	/// Traces refinement is always asked. Failures and divergences are asked
	/// only of a subject whose refusals are known, or the checker would grade
	/// it on refusals it synthesized. Under `fail_fast`, each pass stops at
	/// its first violation.
	fn check_refinement(&mut self) {
		if self.config.specs.is_empty() {
			return;
		}

		// The spec list is read through a refcount rather than a copy: cloning
		// `Vec<Process>` duplicates every state set and transition map that
		// the checker only ever reads.
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
	fn check_refinement_for_specs<W, F, G>(&mut self, specs: &[Process], check: F, record_witness: G) -> Decision
	where
		F: Fn(&mut R, &Process) -> RefinementOutcome<W>,
		G: Fn(&mut FdrVerdict, W),
	{
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

	/// Get traces explored (for compatibility)
	pub fn traces(&self) -> Vec<Trace> {
		self.explorer.traces()
	}

	/// Get failures collected (for compatibility)
	pub fn failures(&self) -> Vec<Failure> {
		self.explorer.failures()
	}
}

impl<'a> DefaultFdrExplorer<'a> {
	/// Create new FDR explorer with default subsystems
	///
	/// This is a convenience constructor that uses the default implementations
	/// of all subsystems. For custom subsystems, use `FdrExplorer::new` directly.
	///
	/// Accepts either owned `FdrConfig` or `Arc<FdrConfig>`.
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
	use super::Decision;
	use crate::testing::fdr::{DefaultFdrExplorer, FdrConfig};
	use crate::testing::specs::csp::{Event, Process, ProcessBuildError, State};

	/// A spec that models `start` and nothing else.
	fn narrow_spec() -> Result<Process, ProcessBuildError> {
		Process::builder("NarrowSpec")
			.initial_state(State("S0"))
			.add_observable(Event("start"))
			.add_transition(State("S0"), Event("start"), State("S1"))
			.add_terminal(State("S1"))
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
}
