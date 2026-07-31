//! FDR memoization cache subsystem
//!
//! This module contains the MemoizationCache trait implementation.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::testing::fdr::config::{Failure, Trace};
use crate::testing::fdr::explorer::MemoizationCache;

/// Default memoization cache implementation
///
/// Keyed on [`crate::testing::specs::csp::Process::structure_digest`] values so structurally
/// different processes never share entries, even when algebra operators
/// give them identical names. Each entry stores the completeness
/// flag of the computation that produced it.
pub struct DefaultCache {
	/// Memoization cache: structure digest -> (traces, complete)
	traces_cache: RefCell<HashMap<u64, (Vec<Trace>, bool)>>,
	/// Memoization cache: structure digest -> (failures, complete)
	failures_cache: RefCell<HashMap<u64, (Vec<Failure>, bool)>>,
	/// Memoization cache: structure digest -> (divergences, complete)
	divergences_cache: RefCell<HashMap<u64, (Vec<Trace>, bool)>>,
}

impl DefaultCache {
	/// Create new cache
	pub fn new() -> Self {
		Self {
			traces_cache: RefCell::new(HashMap::new()),
			failures_cache: RefCell::new(HashMap::new()),
			divergences_cache: RefCell::new(HashMap::new()),
		}
	}
}

impl Default for DefaultCache {
	fn default() -> Self {
		Self::new()
	}
}

impl MemoizationCache for DefaultCache {
	fn get_cached_traces(&self, structure: u64) -> Option<(Vec<Trace>, bool)> {
		self.traces_cache.borrow().get(&structure).cloned()
	}

	fn cache_traces(&mut self, structure: u64, traces: Vec<Trace>, complete: bool) {
		self.traces_cache.borrow_mut().insert(structure, (traces, complete));
	}

	fn get_cached_failures(&self, structure: u64) -> Option<(Vec<Failure>, bool)> {
		self.failures_cache.borrow().get(&structure).cloned()
	}

	fn cache_failures(&mut self, structure: u64, failures: Vec<Failure>, complete: bool) {
		self.failures_cache.borrow_mut().insert(structure, (failures, complete));
	}

	fn get_cached_divergences(&self, structure: u64) -> Option<(Vec<Trace>, bool)> {
		self.divergences_cache.borrow().get(&structure).cloned()
	}

	fn cache_divergences(&mut self, structure: u64, divergences: Vec<Trace>, complete: bool) {
		self.divergences_cache.borrow_mut().insert(structure, (divergences, complete));
	}
}
