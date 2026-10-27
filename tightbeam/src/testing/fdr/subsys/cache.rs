//! The memoization cache subsystem of FDR.
//!
//! [`DefaultCache`] is the house implementation of [`MemoizationCache`].

use std::collections::HashMap;

use crate::testing::fdr::explorer::{CacheKey, MemoizationCache};
use crate::testing::fdr::verdict::{Failure, Trace};

/// The default [`MemoizationCache`], with one map for each kind of set.
///
/// Each map keys on [`CacheKey`], so a set of one depth bound never answers a
/// search at another, and two processes share an entry only when their
/// structures are equal. Each entry stores the completeness flag of the
/// computation that produced it.
pub struct DefaultCache {
	/// The traces under each key, and whether the set is complete.
	traces_cache: HashMap<CacheKey, (Vec<Trace>, bool)>,
	/// The failures under each key, and whether the set is complete.
	failures_cache: HashMap<CacheKey, (Vec<Failure>, bool)>,
	/// The divergences under each key, and whether the set is complete.
	divergences_cache: HashMap<CacheKey, (Vec<Trace>, bool)>,
}

impl DefaultCache {
	/// Creates an empty cache.
	pub fn new() -> Self {
		Self {
			traces_cache: HashMap::new(),
			failures_cache: HashMap::new(),
			divergences_cache: HashMap::new(),
		}
	}
}

impl Default for DefaultCache {
	fn default() -> Self {
		Self::new()
	}
}

impl MemoizationCache for DefaultCache {
	fn get_cached_traces(&self, key: &CacheKey) -> Option<(Vec<Trace>, bool)> {
		self.traces_cache.get(key).cloned()
	}

	fn cache_traces(&mut self, key: CacheKey, traces: impl IntoIterator<Item = Trace>, complete: bool) {
		let traces: Vec<Trace> = traces.into_iter().collect();
		self.traces_cache.insert(key, (traces, complete));
	}

	fn get_cached_failures(&self, key: &CacheKey) -> Option<(Vec<Failure>, bool)> {
		self.failures_cache.get(key).cloned()
	}

	fn cache_failures(&mut self, key: CacheKey, failures: impl IntoIterator<Item = Failure>, complete: bool) {
		let failures: Vec<Failure> = failures.into_iter().collect();
		self.failures_cache.insert(key, (failures, complete));
	}

	fn get_cached_divergences(&self, key: &CacheKey) -> Option<(Vec<Trace>, bool)> {
		self.divergences_cache.get(key).cloned()
	}

	fn cache_divergences(&mut self, key: CacheKey, divergences: impl IntoIterator<Item = Trace>, complete: bool) {
		let divergences: Vec<Trace> = divergences.into_iter().collect();
		self.divergences_cache.insert(key, (divergences, complete));
	}
}
