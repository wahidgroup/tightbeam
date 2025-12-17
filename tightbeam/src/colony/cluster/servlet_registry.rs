//! Servlet registry with bio-inspired pheromone-based routing
//!
//! Implements Ant Colony Optimization (ACO) and Artificial Bee Colony (ABC)
//! principles for emergent load balancing and self-healing servlet discovery.
//!
//! # Key Concepts
//!
//! - **Pheromone**: Success metric that grows with successful requests and decays over time
//! - **Trial Count**: Failure metric from ABC - entries are abandoned after too many failures
//! - **Evaporation**: Natural decay of pheromone to forget stale routes
//!
//! # Usage
//!
//! ```ignore
//! let registry = ServletRegistry::new(PheromoneConf::default());
//!
//! // On hive registration, entries are created with initial pheromone
//! registry.add_entries_from_hive(&hive_id, &servlet_types)?;
//!
//! // On successful work:
//! registry.reinforce(&servlet_addr, quality);
//!
//! // On failed work:
//! registry.weaken(&servlet_addr);
//!
//! // Periodic maintenance:
//! registry.evaporate();
//! registry.remove_abandoned();
//! ```

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::time::Duration;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use super::error::ClusterError;
use super::SharedId;
use crate::utils::BasisPoints;

// ============================================================================
// Configuration
// ============================================================================

/// Default pheromone configuration constants
pub const DEFAULT_EVAPORATION_RATE_BPS: u16 = 1000; // 10% per interval
pub const DEFAULT_EVAPORATION_INTERVAL_SECS: u64 = 30;
pub const DEFAULT_INITIAL_PHEROMONE: u64 = 5000; // 50% of max
pub const DEFAULT_ABANDONMENT_LIMIT: u32 = 5;
pub const MAX_PHEROMONE: u64 = 10000; // 100% (basis points)

/// Configuration for pheromone-based servlet tracking
#[derive(Debug, Clone)]
pub struct PheromoneConf {
	/// Decay rate per evaporation cycle in basis points (1000 = 10%)
	pub evaporation_rate: BasisPoints,
	/// How often to run evaporation
	pub evaporation_interval: Duration,
	/// Starting pheromone level for new entries
	pub initial_pheromone: u64,
	/// Max consecutive failures before abandonment
	pub abandonment_limit: u32,
}

impl Default for PheromoneConf {
	fn default() -> Self {
		Self {
			evaporation_rate: BasisPoints::new(DEFAULT_EVAPORATION_RATE_BPS),
			evaporation_interval: Duration::from_secs(DEFAULT_EVAPORATION_INTERVAL_SECS),
			initial_pheromone: DEFAULT_INITIAL_PHEROMONE,
			abandonment_limit: DEFAULT_ABANDONMENT_LIMIT,
		}
	}
}

// ============================================================================
// Servlet Entry
// ============================================================================

/// A servlet instance tracked with pheromone-based scoring
///
/// Combines ACO pheromone trails with ABC trial-based abandonment
/// for emergent load balancing and failure detection.
#[derive(Debug)]
pub struct ServletEntry {
	/// Network address for this servlet
	pub address: SharedId,
	/// Type identifier (e.g., b"calculator", b"auth")
	pub servlet_type: SharedId,
	/// Parent hive that owns this servlet
	pub hive_id: SharedId,

	// ACO fields
	/// Current pheromone level (0-10000 basis points)
	pub pheromone: AtomicU64,
	/// When pheromone was last reinforced
	pub last_reinforced: Instant,

	// ABC fields
	/// Consecutive failures since last success
	pub trial_count: AtomicU32,
	/// Threshold for abandonment
	pub abandonment_limit: u32,
}

impl ServletEntry {
	/// Create a new entry with initial pheromone
	pub fn new(
		address: SharedId,
		servlet_type: SharedId,
		hive_id: SharedId,
		initial_pheromone: u64,
		abandonment_limit: u32,
	) -> Self {
		Self {
			address,
			servlet_type,
			hive_id,
			pheromone: AtomicU64::new(initial_pheromone),
			last_reinforced: Instant::now(),
			trial_count: AtomicU32::new(0),
			abandonment_limit,
		}
	}

	/// Check if this entry should be abandoned (too many failures)
	pub fn is_abandoned(&self) -> bool {
		self.trial_count.load(Ordering::Relaxed) >= self.abandonment_limit
	}

	/// Get current pheromone level
	pub fn pheromone_level(&self) -> u64 {
		self.pheromone.load(Ordering::Relaxed)
	}

	/// Reinforce pheromone on success
	///
	/// Quality is added directly to pheromone, capped at MAX_PHEROMONE
	pub fn reinforce(&self, quality: u64) {
		let current = self.pheromone.load(Ordering::Relaxed);
		let new_value = current.saturating_add(quality).min(MAX_PHEROMONE);
		self.pheromone.store(new_value, Ordering::Relaxed);
		// Reset trial count on success
		self.trial_count.store(0, Ordering::Relaxed);
	}

	/// Weaken entry on failure (increment trial count)
	pub fn weaken(&self) {
		self.trial_count.fetch_add(1, Ordering::Relaxed);
	}

	/// Apply evaporation decay
	///
	/// Rate is in basis points (1000 = 10% decay)
	pub fn evaporate(&self, rate: BasisPoints) {
		let current = self.pheromone.load(Ordering::Relaxed);
		let decay = (current * rate.get() as u64) / 10000;
		let new_value = current.saturating_sub(decay);
		self.pheromone.store(new_value, Ordering::Relaxed);
	}
}

impl Clone for ServletEntry {
	fn clone(&self) -> Self {
		Self {
			address: Arc::clone(&self.address),
			servlet_type: Arc::clone(&self.servlet_type),
			hive_id: Arc::clone(&self.hive_id),
			pheromone: AtomicU64::new(self.pheromone.load(Ordering::Relaxed)),
			last_reinforced: self.last_reinforced,
			trial_count: AtomicU32::new(self.trial_count.load(Ordering::Relaxed)),
			abandonment_limit: self.abandonment_limit,
		}
	}
}

// ============================================================================
// Servlet Registry
// ============================================================================

/// Registry of servlet entries with pheromone-based routing
///
/// Tracks individual servlet instances across hives, enabling
/// bio-inspired load balancing via pheromone reinforcement/evaporation.
pub struct ServletRegistry {
	/// Map of servlet address -> entry
	entries: RwLock<HashMap<SharedId, ServletEntry>>,
	/// Reverse index: servlet_type -> Vec<address>
	type_index: RwLock<HashMap<SharedId, Vec<SharedId>>>,
	/// Reverse index: hive_id -> Vec<address>
	hive_index: RwLock<HashMap<SharedId, Vec<SharedId>>>,
	/// Configuration
	config: PheromoneConf,
}

impl ServletRegistry {
	/// Create a new registry with the given configuration
	pub fn new(config: PheromoneConf) -> Self {
		Self {
			entries: RwLock::new(HashMap::new()),
			type_index: RwLock::new(HashMap::new()),
			hive_index: RwLock::new(HashMap::new()),
			config,
		}
	}

	/// Add a servlet entry
	pub fn add(&self, entry: ServletEntry) -> Result<(), ClusterError> {
		let addr = Arc::clone(&entry.address);
		let servlet_type = Arc::clone(&entry.servlet_type);
		let hive_id = Arc::clone(&entry.hive_id);

		// Add to main entries map
		{
			let mut entries = self.entries.write()?;
			entries.insert(Arc::clone(&addr), entry);
		}

		// Add to type index
		{
			let mut type_idx = self.type_index.write()?;
			type_idx.entry(servlet_type).or_default().push(Arc::clone(&addr));
		}

		// Add to hive index
		{
			let mut hive_idx = self.hive_index.write()?;
			hive_idx.entry(hive_id).or_default().push(addr);
		}

		Ok(())
	}

	/// Add entries for all servlet types from a hive
	///
	/// Creates one entry per servlet type, using hive address as servlet address
	/// (servlet-level addresses can be added later via direct registration)
	pub fn add_entries_from_hive(
		&self,
		hive_id: &SharedId,
		hive_address: &SharedId,
		servlet_types: &[SharedId],
	) -> Result<(), ClusterError> {
		for servlet_type in servlet_types {
			let entry = ServletEntry::new(
				Arc::clone(hive_address),
				Arc::clone(servlet_type),
				Arc::clone(hive_id),
				self.config.initial_pheromone,
				self.config.abandonment_limit,
			);
			self.add(entry)?;
		}
		Ok(())
	}

	/// Remove a servlet entry by address
	pub fn remove(&self, address: &[u8]) -> Result<Option<ServletEntry>, ClusterError> {
		let entry = {
			let mut entries = self.entries.write()?;
			entries.remove(address)
		};

		if let Some(ref e) = entry {
			// Remove from type index
			{
				let mut type_idx = self.type_index.write()?;
				if let Some(addrs) = type_idx.get_mut(&e.servlet_type) {
					addrs.retain(|a| a.as_ref() != address);
					if addrs.is_empty() {
						type_idx.remove(&e.servlet_type);
					}
				}
			}

			// Remove from hive index
			{
				let mut hive_idx = self.hive_index.write()?;
				if let Some(addrs) = hive_idx.get_mut(&e.hive_id) {
					addrs.retain(|a| a.as_ref() != address);
					if addrs.is_empty() {
						hive_idx.remove(&e.hive_id);
					}
				}
			}
		}

		Ok(entry)
	}

	/// Remove all entries belonging to a hive
	pub fn remove_by_hive(&self, hive_id: &[u8]) -> Result<Vec<ServletEntry>, ClusterError> {
		let addresses: Vec<SharedId> = {
			let hive_idx = self.hive_index.read()?;
			hive_idx.get(hive_id).cloned().unwrap_or_default()
		};

		let mut removed = Vec::with_capacity(addresses.len());
		for addr in &addresses {
			if let Some(entry) = self.remove(addr)? {
				removed.push(entry);
			}
		}

		Ok(removed)
	}

	/// Get entries for a servlet type (for load balancing)
	pub fn entries_for_type(&self, servlet_type: &[u8]) -> Result<Vec<ServletEntry>, ClusterError> {
		let addresses: Vec<SharedId> = {
			let type_idx = self.type_index.read()?;
			type_idx.get(servlet_type).cloned().unwrap_or_default()
		};

		let entries = self.entries.read()?;
		let result: Vec<ServletEntry> = addresses
			.iter()
			.filter_map(|addr| entries.get(addr.as_ref()).cloned())
			.filter(|e| !e.is_abandoned())
			.collect();

		Ok(result)
	}

	/// Reinforce pheromone for a servlet on success
	pub fn reinforce(&self, address: &[u8], quality: u64) -> Result<bool, ClusterError> {
		let entries = self.entries.read()?;
		if let Some(entry) = entries.get(address) {
			entry.reinforce(quality);
			Ok(true)
		} else {
			Ok(false)
		}
	}

	/// Weaken a servlet on failure (increment trial count)
	pub fn weaken(&self, address: &[u8]) -> Result<bool, ClusterError> {
		let entries = self.entries.read()?;
		if let Some(entry) = entries.get(address) {
			entry.weaken();
			Ok(true)
		} else {
			Ok(false)
		}
	}

	/// Apply evaporation to all entries
	pub fn evaporate(&self) -> Result<(), ClusterError> {
		let entries = self.entries.read()?;
		let rate = self.config.evaporation_rate;
		for entry in entries.values() {
			entry.evaporate(rate);
		}
		Ok(())
	}

	/// Remove all abandoned entries (trial_count >= abandonment_limit)
	pub fn remove_abandoned(&self) -> Result<usize, ClusterError> {
		let abandoned: Vec<SharedId> = {
			let entries = self.entries.read()?;
			entries
				.iter()
				.filter(|(_, e)| e.is_abandoned())
				.map(|(addr, _)| Arc::clone(addr))
				.collect()
		};

		let count = abandoned.len();
		for addr in &abandoned {
			self.remove(addr)?;
		}

		Ok(count)
	}

	/// Get configuration
	pub fn config(&self) -> &PheromoneConf {
		&self.config
	}

	/// Count of tracked servlets
	pub fn len(&self) -> Result<usize, ClusterError> {
		let entries = self.entries.read()?;
		Ok(entries.len())
	}

	/// Check if registry is empty
	pub fn is_empty(&self) -> Result<bool, ClusterError> {
		Ok(self.len()? == 0)
	}
}

impl Default for ServletRegistry {
	fn default() -> Self {
		Self::new(PheromoneConf::default())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// =========================================================================
	// Test Helpers
	// =========================================================================

	/// Create a test entry with specified pheromone and abandonment limit
	fn test_entry(pheromone: u64, abandonment_limit: u32) -> ServletEntry {
		ServletEntry::new(
			Arc::from(b"addr".as_slice()),
			Arc::from(b"type".as_slice()),
			Arc::from(b"hive".as_slice()),
			pheromone,
			abandonment_limit,
		)
	}

	/// Create a named test entry for registry tests
	fn named_entry(addr: &[u8], servlet_type: &[u8], hive: &[u8]) -> ServletEntry {
		ServletEntry::new(
			Arc::from(addr),
			Arc::from(servlet_type),
			Arc::from(hive),
			DEFAULT_INITIAL_PHEROMONE,
			DEFAULT_ABANDONMENT_LIMIT,
		)
	}

	// =========================================================================
	// ServletEntry Tests - Data-Driven
	// =========================================================================

	/// Test cases: (initial_pheromone, reinforce_amount, expected_result)
	const REINFORCE_CASES: &[(u64, u64, u64)] = &[
		(5000, 1000, 6000),                  // normal add
		(9500, 1000, MAX_PHEROMONE),         // caps at max
		(0, 500, 500),                       // from zero
		(MAX_PHEROMONE, 100, MAX_PHEROMONE), // already at max
	];

	#[test]
	fn entry_reinforce_pheromone() {
		for &(initial, amount, expected) in REINFORCE_CASES {
			let entry = test_entry(initial, 5);
			entry.reinforce(amount);
			assert_eq!(entry.pheromone_level(), expected);
		}
	}

	/// Test cases: (initial_pheromone, decay_rate_bps, expected_result)
	const EVAPORATE_CASES: &[(u64, u16, u64)] = &[
		(10000, 1000, 9000), // 10% decay
		(5000, 2000, 4000),  // 20% decay
		(100, 5000, 50),     // 50% decay
		(0, 1000, 0),        // already zero
	];

	#[test]
	fn entry_evaporate_pheromone() {
		for &(initial, rate, expected) in EVAPORATE_CASES {
			let entry = test_entry(initial, 5);
			entry.evaporate(BasisPoints::new(rate));
			assert_eq!(entry.pheromone_level(), expected);
		}
	}

	#[test]
	fn entry_weaken_increments_trials() {
		let entry = test_entry(5000, 5);
		for expected in 1..=3 {
			entry.weaken();
			assert_eq!(entry.trial_count.load(Ordering::Relaxed), expected);
		}
	}

	#[test]
	fn entry_abandoned_after_limit() {
		let limit = 3;
		let entry = test_entry(5000, limit);

		// Not abandoned until reaching limit
		for _ in 0..limit {
			assert!(!entry.is_abandoned());
			entry.weaken();
		}
		assert!(entry.is_abandoned());
	}

	#[test]
	fn entry_reinforce_resets_trials() {
		let entry = test_entry(5000, 5);
		entry.weaken();
		entry.weaken();
		assert_eq!(entry.trial_count.load(Ordering::Relaxed), 2);

		entry.reinforce(100);
		assert_eq!(entry.trial_count.load(Ordering::Relaxed), 0);
	}

	// =========================================================================
	// ServletRegistry Tests
	// =========================================================================

	#[test]
	fn registry_add_and_lookup() {
		let registry = ServletRegistry::default();
		let entry = named_entry(b"addr1", b"calculator", b"hive1");
		registry.add(entry).ok();

		let found = registry.entries_for_type(b"calculator").ok().unwrap_or_default();
		assert_eq!(found.len(), 1);
		assert_eq!(found[0].address.as_ref(), b"addr1");
	}

	#[test]
	fn registry_remove_abandoned_prunes_entries() {
		let limit = 2;
		let config = PheromoneConf { abandonment_limit: limit, ..Default::default() };
		let registry = ServletRegistry::new(config);

		let entry = test_entry(5000, limit);
		registry.add(entry).ok();

		// Weaken to abandonment
		for _ in 0..limit {
			registry.weaken(b"addr").ok();
		}

		assert!(matches!(registry.remove_abandoned().ok(), Some(1)));
		assert!(matches!(registry.len().ok(), Some(0)));
	}
}
