//! FDR exploration engine subsystem
//!
//! This module contains the core FdrExplorer struct that orchestrates exploration
//! and refinement checking by delegating to pluggable subsystems.

#[cfg(feature = "rayon")]
use std::collections::HashSet;

use crate::testing::fdr::config::{FdrConfig, FdrVerdict, Trace, Failure};
use crate::testing::fdr::explorer::{ExplorationCore, MemoizationCache, RefinementChecker, SeedResult};
use crate::testing::specs::csp::Process;

#[cfg(feature = "rayon")]
use crate::testing::specs::csp::State;

use super::cache::DefaultCache;
use super::exploration::DefaultExplorationEngine;
use super::refinement::DefaultRefinementChecker;

/// FDR exploration engine (pluggable design)
///
/// Generic over subsystem implementations:
/// - `E`: Exploration engine (implements `ExplorationCore`)
/// - `R`: Refinement checker (implements `RefinementChecker`)
/// - `M`: Memoization cache (implements `MemoizationCache`)
pub struct FdrExplorer<'a, E, R, M>
where
	E: ExplorationCore,
	R: RefinementChecker,
	M: MemoizationCache,
{
	/// Process being verified
	process: &'a Process,

	/// Configuration
	config: FdrConfig,

	/// Exploration engine
	explorer: E,

	/// Refinement checker
	refinement: R,

	/// Memoization cache
	/// 
	/// Note: Currently unused. The `DefaultRefinementChecker` implements
	/// `MemoizationCache` itself and maintains its own internal cache.
	/// This field is kept for extensibility - custom refinement checkers
	/// may use the shared cache instead of maintaining their own.
	#[allow(dead_code)]
	cache: M,

	/// Verdict accumulator
	verdict: FdrVerdict,
}

/// Default FDR explorer using default subsystem implementations
pub type DefaultFdrExplorer<'a> = FdrExplorer<'a, DefaultExplorationEngine<'a>, DefaultRefinementChecker<'a>, DefaultCache>;

impl<'a, E, R, M> FdrExplorer<'a, E, R, M>
where
	E: ExplorationCore,
	R: RefinementChecker,
	M: MemoizationCache,
{
	/// Create new FDR explorer with custom subsystems
	pub fn new(process: &'a Process, config: FdrConfig, explorer: E, refinement: R, cache: M) -> Self {
		Self {
			process,
			config,
			explorer,
			refinement,
			cache,
			verdict: FdrVerdict::default(),
		}
	}

	/// Run multi-seed exploration
	pub fn explore(&mut self) -> FdrVerdict {
		// Mode 1: Refinement checking (when specs provided)
		if !self.config.specs.is_empty() {
			self.check_refinement();
			return self.verdict.clone();
		}

		// Mode 2: Single-process multi-seed exploration
		#[cfg(feature = "rayon")]
		{
			use rayon::prelude::*;
			// Parallel exploration with rayon
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

			// Aggregate results
			for (seed, result, visited) in results {
				self.explorer.add_seed_result(seed, result.clone());
				self.explorer.update_visited_states(&visited);
				self.update_verdict_from_result(seed, &result);
			}
		}

		#[cfg(not(feature = "rayon"))]
		{
			// Sequential exploration
			for seed in 0..self.config.seeds {
				let result = self.explorer.explore_seed(seed as u64);
				self.update_verdict_from_result(seed as u64, &result);
			}
		}

		self.verdict.traces_explored = self.explorer.traces().len();
		self.verdict.states_visited = self.explorer.states_visited();

		// Check determinism across all seeds
		self.check_determinism();

		// Update overall verdict
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
			SeedResult::Success(_, _) => {
				self.verdict.seeds_completed += 1;
			}
		}
	}

	/// Check for witnesses to nondeterminism
	fn check_determinism(&mut self) {
		// Get traces from explorer
		let traces = self.explorer.traces();

		// Check if all traces are identical (deterministic)
		if traces.len() > 1 {
			let first_trace = &traces[0];
			for trace in &traces[1..] {
				if trace != first_trace {
					// Found nondeterminism - we can't determine the seed from traces alone
					// This is a limitation, but determinism checking at this level
					// requires access to seed_results which the explorer may not expose
					self.verdict.is_deterministic = false;
					break;
				}
			}
		}
	}

	/// Run refinement checking mode
	///
	/// When `config.specs` is non-empty, checks:
	/// - For each spec in specs: spec ⊑ process
	///
	/// Updates verdict with refinement results and witnesses.
	/// If `config.fail_fast` is true (default), stops at first violation.
	fn check_refinement(&mut self) {
		if self.config.specs.is_empty() {
			return;
		}

		// Clone specs to avoid borrowing conflict
		let specs = self.config.specs.clone();

		// Check each refinement type
		self.check_refinement_for_specs(&specs, |r, s| r.check_trace_refinement(s, self.process), |v, w| {
			v.trace_refines = false;
			v.trace_refinement_witness = w;
		});

		self.check_refinement_for_specs(&specs, |r, s| r.check_failures_refinement(s, self.process), |v, w| {
			v.failures_refines = false;
			v.failures_refinement_witness = w;
		});

		self.check_refinement_for_specs(&specs, |r, s| r.check_divergence_refinement(s, self.process), |v, w| {
			v.divergence_refines = false;
			v.divergence_refinement_witness = w;
		});

		// All refinement checks passed
		if self.verdict.trace_refines && self.verdict.failures_refines && self.verdict.divergence_refines {
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
		let refinement = DefaultRefinementChecker::new(process, config.clone());
		let cache = DefaultCache::new();
		FdrExplorer::new(process, config, explorer, refinement, cache)
	}
}
