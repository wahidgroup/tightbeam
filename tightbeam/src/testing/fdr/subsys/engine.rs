//! FDR exploration engine subsystem
//!
//! This module contains the core FdrExplorer struct that orchestrates
//! exploration and refinement checking by delegating to pluggable subsystems.

use std::cell::RefCell;
use std::rc::Rc;

#[cfg(feature = "rayon")]
use std::collections::HashSet;

use super::cache::DefaultCache;
use super::exploration::DefaultExplorationEngine;
use super::refinement::DefaultRefinementChecker;
use crate::testing::fdr::config::{Failure, FdrConfig, FdrVerdict, Trace};
use crate::testing::fdr::explorer::{ExplorationCore, RefinementChecker, SeedResult};
use crate::testing::specs::csp::Process;

#[cfg(feature = "rayon")]
use crate::testing::specs::csp::State;

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
	config: FdrConfig,

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
			return self.verdict.clone();
		}

		// Mode 2: Refinement checking (specs without fault model)
		if !self.config.specs.is_empty() {
			self.check_refinement();
			return self.verdict.clone();
		}

		// Mode 3: Single-process multi-seed exploration
		#[cfg(feature = "rayon")]
		{
			use rayon::prelude::*;
			let seeds: Vec<u64> = (0..self.config.seeds).map(|s| s as u64).collect();
			let process = self.process;
			let config = &self.config;

			let results: Vec<(u64, SeedResult, HashSet<State>)> = seeds
				.par_iter()
				.map(|&seed| {
					let (result, visited) = DefaultExplorationEngine::explore_seed_static(process, config, seed);
					(seed, result, visited)
				})
				.collect();

			for (seed, result, visited) in results {
				self.explorer.add_seed_result(seed, result.clone());
				self.explorer.update_visited_states(&visited);
				self.update_verdict_from_result(seed, &result);
			}
		}

		#[cfg(not(feature = "rayon"))]
		{
			for seed in 0..self.config.seeds {
				let result = self.explorer.explore_seed(seed as u64);
				self.update_verdict_from_result(seed as u64, &result);
			}
		}

		self.verdict.traces_explored = self.explorer.traces().len();
		self.verdict.states_visited = self.explorer.states_visited();

		self.check_determinism();

		self.verdict.passed = self.verdict.divergence_free
			&& self.verdict.deadlock_free
			&& (self.verdict.is_deterministic || self.verdict.determinism_witness.is_none());

		self.verdict.clone()
	}

	/// Update verdict based on seed result
	fn update_verdict_from_result(&mut self, seed: u64, result: &SeedResult) {
		match result {
			SeedResult::Divergence(_trace, hidden) => {
				self.verdict.divergence_free = false;
				self.verdict.passed = false;
				self.verdict.divergence_witness = Some((seed, hidden.clone()));
				self.verdict.failing_seed = Some(seed);
			}
			SeedResult::Deadlock(trace, state) => {
				self.verdict.deadlock_free = false;
				self.verdict.passed = false;
				self.verdict.deadlock_witness = Some((seed, trace.clone(), *state));
				self.verdict.failing_seed = Some(seed);
			}
			#[cfg(feature = "testing-fault")]
			SeedResult::Success(_trace, _failures, faults) => {
				self.verdict.seeds_completed += 1;
				self.verdict.faults_injected.extend(faults.clone());
			}
			#[cfg(not(feature = "testing-fault"))]
			SeedResult::Success(..) => {
				self.verdict.seeds_completed += 1;
			}
		}
	}

	/// Explore specification process with fault injection
	/// This tests whether the specification correctly models error conditions
	#[cfg(feature = "testing-fault")]
	fn explore_specification_with_faults(&mut self) {
		if self.config.specs.is_empty() {
			return;
		}

		// Get the spec process (first one if multiple)
		let spec_process = &self.config.specs[0];
		let config = &self.config;

		#[cfg(feature = "rayon")]
		{
			use rayon::prelude::*;
			let seeds: Vec<u64> = (0..config.seeds).map(|s| s as u64).collect();

			let results: Vec<(u64, SeedResult, HashSet<State>)> = seeds
				.par_iter()
				.map(|&seed| {
					let (result, visited) = DefaultExplorationEngine::explore_seed_static(spec_process, config, seed);
					(seed, result, visited)
				})
				.collect();

			for (seed, result, visited) in results {
				self.explorer.add_seed_result(seed, result.clone());
				self.explorer.update_visited_states(&visited);
				self.update_verdict_from_result(seed, &result);
			}
		}

		#[cfg(not(feature = "rayon"))]
		{
			for seed in 0..config.seeds {
				let (result, visited) =
					DefaultExplorationEngine::explore_seed_static(spec_process, config, seed as u64);
				self.explorer.add_seed_result(seed as u64, result.clone());
				self.explorer.update_visited_states(&visited);
				self.update_verdict_from_result(seed as u64, &result);
			}
		}

		self.verdict.traces_explored = self.explorer.traces().len();
		self.verdict.states_visited = self.explorer.states_visited();

		self.check_determinism();

		self.verdict.passed = self.verdict.divergence_free
			&& self.verdict.deadlock_free
			&& (self.verdict.is_deterministic || self.verdict.determinism_witness.is_none());
	}

	/// Check for witnesses to nondeterminism
	fn check_determinism(&mut self) {
		let traces = self.explorer.traces();

		if traces.len() > 1 {
			let first_trace = &traces[0];
			for trace in &traces[1..] {
				if trace != first_trace {
					self.verdict.is_deterministic = false;
					break;
				}
			}
		}
	}

	/// Run refinement checking mode
	///
	/// When `config.specs` is non-empty, checks: process ⊑ spec
	/// (implementation refines specification). Updates verdict with refinement
	/// results and witnesses. If `config.fail_fast` is true (default), stops
	/// at first violation.
	fn check_refinement(&mut self) {
		if self.config.specs.is_empty() {
			return;
		}

		let specs = self.config.specs.clone();

		// Check trace refinement
		self.check_refinement_for_specs(
			&specs,
			|r, s| r.check_trace_refinement(s, self.process),
			|v, w| {
				v.trace_refines = false;
				v.trace_refinement_witness = w;
			},
		);

		// Skip failures refinement for deterministic linear trace processes.
		// For deterministic processes, trace + divergence refinement is sufficient.
		// Reference: Roscoe (1998, 2010), Pedersen & Chalmers (2024)
		self.check_refinement_for_specs(
			&specs,
			|r, s| r.check_divergence_refinement(s, self.process),
			|v, w| {
				v.divergence_refines = false;
				v.divergence_refinement_witness = w;
			},
		);

		if self.verdict.trace_refines && self.verdict.divergence_refines {
			self.verdict.passed = true;
		}
	}

	/// Helper to check a refinement type across all specs
	fn check_refinement_for_specs<W, F, G>(&mut self, specs: &[Process], check: F, update_witness: G)
	where
		F: Fn(&mut R, &Process) -> (bool, Option<W>),
		G: Fn(&mut FdrVerdict, Option<W>),
	{
		for spec in specs {
			let (passed, witness) = check(&mut self.refinement, spec);
			if !passed {
				self.verdict.passed = false;
				update_witness(&mut self.verdict, witness);
				if self.config.fail_fast {
					return;
				}
			}
		}
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
	pub fn with_defaults(process: &'a Process, config: FdrConfig) -> Self {
		let explorer = DefaultExplorationEngine::new(process, config.clone());
		let cache = Rc::new(RefCell::new(DefaultCache::new()));
		let refinement = DefaultRefinementChecker::new(process, config.clone(), cache);
		FdrExplorer::new(process, config, explorer, refinement)
	}
}
