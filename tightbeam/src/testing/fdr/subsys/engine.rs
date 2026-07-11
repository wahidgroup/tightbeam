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
use crate::testing::fdr::config::{Failure, FdrConfig, FdrVerdict, Trace};
use crate::testing::fdr::explorer::{ExplorationCore, RefinementChecker, RefinementOutcome, SeedResult};
use crate::testing::specs::csp::{Process, State};

#[cfg(feature = "testing-fmea")]
use crate::testing::fmea::generate_fmea_report;

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

	/// Run multi-seed exploration
	pub fn explore(&mut self) -> FdrVerdict {
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

		// Determinism is informational (see FdrVerdict::is_deterministic):
		// only divergence and deadlock freedom decide the verdict.
		self.verdict.passed = self.verdict.divergence_free && self.verdict.deadlock_free;

		#[cfg(feature = "testing-fmea")]
		self.generate_fmea_if_configured();

		self.verdict.clone()
	}

	/// Update verdict based on seed result
	///
	/// With `testing-fault`, seeds that injected at least one fault feed
	/// the error-recovery counters: completion despite faults counts as a
	/// recovery, deadlock/divergence after a fault counts as a failed
	/// recovery. FMEA detection ratings divide these observed counts.
	fn update_verdict_from_result(&mut self, seed: u64, result: &SeedResult) {
		match result {
			#[cfg(feature = "testing-fault")]
			SeedResult::Divergence(_trace, hidden, faults) => {
				self.verdict.divergence_free = false;
				self.verdict.passed = false;
				self.verdict.divergence_witness = Some((seed, hidden.clone()));
				self.verdict.failing_seed = Some(seed);
				if !faults.is_empty() {
					self.verdict.error_recovery_failed += 1;
				}
				self.verdict.faults_injected.extend(faults.clone());
			}
			#[cfg(not(feature = "testing-fault"))]
			SeedResult::Divergence(_trace, hidden) => {
				self.verdict.divergence_free = false;
				self.verdict.passed = false;
				self.verdict.divergence_witness = Some((seed, hidden.clone()));
				self.verdict.failing_seed = Some(seed);
			}
			#[cfg(feature = "testing-fault")]
			SeedResult::Deadlock(trace, state, faults) => {
				self.verdict.deadlock_free = false;
				self.verdict.passed = false;
				self.verdict.deadlock_witness = Some((seed, trace.clone(), *state));
				self.verdict.failing_seed = Some(seed);
				if !faults.is_empty() {
					self.verdict.error_recovery_failed += 1;
				}
				self.verdict.faults_injected.extend(faults.clone());
			}
			#[cfg(not(feature = "testing-fault"))]
			SeedResult::Deadlock(trace, state) => {
				self.verdict.deadlock_free = false;
				self.verdict.passed = false;
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

	/// Explore specification processes with fault injection
	/// This tests whether the specifications correctly model error conditions
	///
	/// Every configured spec is explored (not just `specs[0]`): a fault
	/// model that only stresses the first spec silently skips the rest.
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

		// Determinism is informational (see FdrVerdict::is_deterministic).
		self.verdict.passed = self.verdict.divergence_free && self.verdict.deadlock_free;
	}

	/// Generate FMEA report if configured
	#[cfg(feature = "testing-fmea")]
	fn generate_fmea_if_configured(&mut self) {
		if let Some(ref fmea_config) = self.config.fmea_config {
			if fmea_config.auto_generate && !self.verdict.faults_injected.is_empty() {
				match generate_fmea_report(&self.verdict, self.process, Some(fmea_config.clone())) {
					Ok(report) => self.verdict.fmea_report = Some(report),
					Err(e) => eprintln!("Warning: FMEA generation failed: {}", e),
				}
			}
		}
	}

	/// Structural determinism check
	///
	/// Proves determinism when the LTS has no hidden (τ) actions and no
	/// `(state, event)` transition with multiple targets -- a sufficient
	/// condition for CSP determinism (Roscoe 2010, §10.5). External choice
	/// (distinct events at one state) is deterministic and is not flagged.
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

	/// Run refinement checking mode
	///
	/// When `config.specs` is non-empty, checks: process ⊑ spec
	/// (implementation refines specification) in all three semantic models:
	/// traces, failures, and divergences. Failures refinement runs
	/// unconditionally -- trace + divergence refinement suffices only for
	/// deterministic processes (Roscoe 2010, §12), and skipping it would
	/// let refusal-only violations pass unverified.
	///
	/// Updates verdict with refinement results and witnesses. If
	/// `config.fail_fast` is true (default), each pass stops at its first
	/// violation. An inconclusive check (timeout/resource bound) sets
	/// `passed = false` and `complete = false` without recording a witness.
	fn check_refinement(&mut self) {
		if self.config.specs.is_empty() {
			return;
		}

		let specs = self.config.specs.clone();

		let mut inconclusive = false;

		inconclusive |= self.check_refinement_for_specs(
			&specs,
			|r, s| r.check_trace_refinement(s, self.process),
			|v, w| {
				v.trace_refines = false;
				v.trace_refinement_witness = Some(w);
			},
		);

		inconclusive |= self.check_refinement_for_specs(
			&specs,
			|r, s| r.check_failures_refinement(s, self.process),
			|v, w| {
				v.failures_refines = false;
				v.failures_refinement_witness = Some(w);
			},
		);

		inconclusive |= self.check_refinement_for_specs(
			&specs,
			|r, s| r.check_divergence_refinement(s, self.process),
			|v, w| {
				v.divergence_refines = false;
				v.divergence_refinement_witness = Some(w);
			},
		);

		self.verdict.passed = self.verdict.trace_refines
			&& self.verdict.failures_refines
			&& self.verdict.divergence_refines
			&& !inconclusive;
	}

	/// Helper to check a refinement type across all specs
	///
	/// Returns true when any spec's check was inconclusive.
	fn check_refinement_for_specs<W, F, G>(&mut self, specs: &[Process], check: F, record_violation: G) -> bool
	where
		F: Fn(&mut R, &Process) -> RefinementOutcome<W>,
		G: Fn(&mut FdrVerdict, W),
	{
		let mut inconclusive = false;
		for spec in specs {
			match check(&mut self.refinement, spec) {
				RefinementOutcome::Holds { complete } => {
					if !complete {
						self.verdict.complete = false;
					}
				}
				RefinementOutcome::Violated(witness) => {
					self.verdict.passed = false;
					record_violation(&mut self.verdict, witness);
					if self.config.fail_fast {
						return inconclusive;
					}
				}
				RefinementOutcome::Inconclusive => {
					self.verdict.complete = false;
					inconclusive = true;
				}
			}
		}

		inconclusive
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
		let explorer = DefaultExplorationEngine::new(process, Arc::clone(&config));
		let cache = Rc::new(RefCell::new(DefaultCache::new()));
		let refinement = DefaultRefinementChecker::new(process, Arc::clone(&config), cache);
		FdrExplorer::new_with_arc(process, config, explorer, refinement)
	}
}
