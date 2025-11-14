//! FDR memoization cache subsystem
//!
//! This module contains the MemoizationCache trait implementation.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::testing::fdr::config::{Failure, Trace};
use crate::testing::fdr::explorer::MemoizationCache;

/// Default memoization cache implementation
pub struct DefaultCache {
	/// Memoization cache: process name -> traces
	traces_cache: RefCell<HashMap<String, Vec<Trace>>>,
	/// Memoization cache: process name -> failures
	failures_cache: RefCell<HashMap<String, Vec<Failure>>>,
	/// Memoization cache: process name -> divergences
	divergences_cache: RefCell<HashMap<String, Vec<Trace>>>,
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
	fn get_cached_traces(&self, process_name: &str) -> Option<Vec<Trace>> {
		self.traces_cache.borrow().get(process_name).cloned()
	}

	fn cache_traces(&mut self, process_name: String, traces: Vec<Trace>) {
		self.traces_cache.borrow_mut().insert(process_name, traces);
	}

	fn get_cached_failures(&self, process_name: &str) -> Option<Vec<Failure>> {
		self.failures_cache.borrow().get(process_name).cloned()
	}

	fn cache_failures(&mut self, process_name: String, failures: Vec<Failure>) {
		self.failures_cache.borrow_mut().insert(process_name, failures);
	}

	fn get_cached_divergences(&self, process_name: &str) -> Option<Vec<Trace>> {
		self.divergences_cache.borrow().get(process_name).cloned()
	}

	fn cache_divergences(&mut self, process_name: String, divergences: Vec<Trace>) {
		self.divergences_cache.borrow_mut().insert(process_name, divergences);
	}
}
