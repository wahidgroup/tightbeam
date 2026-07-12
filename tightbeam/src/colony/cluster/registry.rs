//! Hive registry for managing registered hives and servlet type indexing

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::utils::BasisPoints;

use super::error::ClusterError;
use crate::colony::common::RegisterHiveRequest;

/// Shared byte slice for hive and servlet identifiers
pub type SharedId = Arc<[u8]>;

/// Entry for a registered hive in the cluster
#[derive(Debug, Clone)]
pub struct HiveEntry {
	/// Hive control address
	pub address: SharedId,
	/// Available servlet types
	pub servlet_types: Arc<[SharedId]>,
	/// Last reported utilization
	pub utilization: BasisPoints,
	/// Timestamp of last successful heartbeat
	pub last_seen: Instant,
	/// Optional metadata from registration
	pub metadata: Option<Arc<[u8]>>,
	/// Consecutive heartbeat failures
	pub failure_count: u32,
}

/// Registry of hives with servlet type indexing
///
/// Maintains a mapping of hives and a reverse index from servlet types
/// to hives that support them. Thread-safe for concurrent access.
pub struct HiveRegistry {
	/// Map of hive_id -> HiveEntry
	hives: RwLock<HashMap<SharedId, HiveEntry>>,
	/// Reverse index: servlet_type -> Vec<hive_id>
	servlet_index: RwLock<HashMap<SharedId, Vec<SharedId>>>,
	/// Heartbeat timeout for eviction
	timeout: Duration,
}

impl HiveRegistry {
	/// Create a new registry with the given heartbeat timeout
	pub fn new(timeout: Duration) -> Self {
		Self {
			hives: RwLock::new(HashMap::new()),
			servlet_index: RwLock::new(HashMap::new()),
			timeout,
		}
	}

	/// Register a hive and index its servlet types
	///
	/// If the hive was already registered, updates its entry and re-indexes.
	/// Takes ownership for zero-copy conversion to `Arc<[u8]>`.
	pub fn register(&self, request: RegisterHiveRequest) -> Result<(), ClusterError> {
		let hive_id: SharedId = request.hive_addr.into();
		// Extract servlet types from servlet_addresses
		let servlet_types: Arc<[SharedId]> = request
			.servlet_addresses
			.iter()
			.map(|info| Arc::from(info.servlet_id.as_slice()))
			.collect();

		let metadata: Option<Arc<[u8]>> = request.metadata.map(Into::into);

		let address = Arc::clone(&hive_id);
		let entry_servlet_types = Arc::clone(&servlet_types);
		let entry = HiveEntry {
			address,
			servlet_types: entry_servlet_types,
			utilization: BasisPoints::default(),
			last_seen: Instant::now(),
			metadata,
			failure_count: 0,
		};

		// Remove old index entries if re-registering
		self.unregister(&hive_id)?;

		// Add to hives map
		{
			let mut hives = self.hives.write()?;
			let hive_id = Arc::clone(&hive_id);
			hives.insert(hive_id, entry);
		}

		{
			let mut index = self.servlet_index.write()?;
			for servlet_type in servlet_types.iter() {
				let servlet_type = Arc::clone(servlet_type);
				let hive_id = Arc::clone(&hive_id);
				index.entry(servlet_type).or_default().push(hive_id);
			}
		}

		Ok(())
	}

	/// Unregister a hive and remove from indices
	pub fn unregister(&self, hive_id: &[u8]) -> Result<Option<HiveEntry>, ClusterError> {
		// Remove from hives map (O(1) lookup via Borrow<[u8]>)
		let entry = {
			let mut hives = self.hives.write()?;
			hives.remove(hive_id)
		};

		// Remove from servlet index
		if let Some(ref entry) = entry {
			let mut index = self.servlet_index.write()?;
			for servlet_type in entry.servlet_types.iter() {
				if let Some(hive_ids) = index.get_mut(servlet_type) {
					hive_ids.retain(|id| id.as_ref() != hive_id);
					if hive_ids.is_empty() {
						index.remove(servlet_type);
					}
				}
			}
		}

		Ok(entry)
	}

	/// Find all hives that support a servlet type
	pub fn hives_for_type(&self, servlet_type: &[u8]) -> Result<Vec<HiveEntry>, ClusterError> {
		// O(1) lookup via Borrow<[u8]>
		let index = self.servlet_index.read()?;
		let hive_ids = match index.get(servlet_type) {
			Some(ids) => ids.clone(),
			None => return Ok(Vec::new()),
		};
		drop(index);

		let hives = self.hives.read()?;
		let entries: Vec<HiveEntry> = hive_ids.iter().filter_map(|id| hives.get(id.as_ref()).cloned()).collect();

		Ok(entries)
	}

	/// Update hive utilization from heartbeat
	pub fn update_utilization(&self, hive_id: &[u8], utilization: BasisPoints) -> Result<bool, ClusterError> {
		let mut hives = self.hives.write()?;
		// O(1) lookup via Borrow<[u8]>
		if let Some(entry) = hives.get_mut(hive_id) {
			entry.utilization = utilization;
			entry.last_seen = Instant::now();
			Ok(true)
		} else {
			Ok(false)
		}
	}

	/// Increment failure count for a hive, returning the new count
	pub fn increment_failure(&self, hive_id: &[u8]) -> Result<u32, ClusterError> {
		let mut hives = self.hives.write()?;
		if let Some(entry) = hives.get_mut(hive_id) {
			entry.failure_count = entry.failure_count.saturating_add(1);
			Ok(entry.failure_count)
		} else {
			Ok(0)
		}
	}

	/// Reset failure count for a hive
	pub fn reset_failure(&self, hive_id: &[u8]) -> Result<(), ClusterError> {
		let mut hives = self.hives.write()?;
		if let Some(entry) = hives.get_mut(hive_id) {
			entry.failure_count = 0;
		}
		Ok(())
	}

	/// Touch a hive: update last_seen, utilization, and reset failure count
	pub fn touch(&self, hive_id: &[u8], utilization: BasisPoints) -> Result<(), ClusterError> {
		let mut hives = self.hives.write()?;
		if let Some(entry) = hives.get_mut(hive_id) {
			entry.last_seen = Instant::now();
			entry.utilization = utilization;
			entry.failure_count = 0;
		}
		Ok(())
	}

	/// Evict stale hives that haven't sent heartbeat within timeout
	///
	/// Returns the evicted entries so callers can retire dependent state
	/// (e.g. servlet registry rows) for each evicted hive.
	pub fn evict_stale(&self) -> Result<Vec<HiveEntry>, ClusterError> {
		let now = Instant::now();
		let stale_ids: Vec<SharedId> = {
			let hives = self.hives.read()?;
			hives
				.iter()
				.filter(|(_, entry)| now.duration_since(entry.last_seen) > self.timeout)
				.map(|(id, _)| Arc::clone(id))
				.collect()
		};

		let mut evicted = Vec::with_capacity(stale_ids.len());
		for id in &stale_ids {
			if let Some(entry) = self.unregister(id)? {
				evicted.push(entry);
			}
		}

		Ok(evicted)
	}

	/// List all available servlet types across all registered hives
	pub fn to_available_servlets(&self) -> Result<Vec<Vec<u8>>, ClusterError> {
		let index = self.servlet_index.read()?;
		Ok(index.keys().map(|k| k.to_vec()).collect())
	}

	/// Get a snapshot of all registered hives
	pub fn all_hives(&self) -> Result<Vec<HiveEntry>, ClusterError> {
		let hives = self.hives.read()?;
		Ok(hives.values().cloned().collect())
	}

	/// Count the number of registered hives
	pub fn len(&self) -> Result<usize, ClusterError> {
		let hives = self.hives.read()?;
		Ok(hives.len())
	}

	/// Check if the registry is empty
	pub fn is_empty(&self) -> Result<bool, ClusterError> {
		Ok(self.len()? == 0)
	}
}

impl Default for HiveRegistry {
	fn default() -> Self {
		Self::new(Duration::from_secs(15))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::hive::ServletInfo;

	fn request(addr: &[u8], servlets: &[&[u8]]) -> RegisterHiveRequest {
		RegisterHiveRequest {
			issued_at_ms: 0,
			hive_addr: addr.to_vec(),
			metadata: None,
			servlet_addresses: servlets
				.iter()
				.map(|s| ServletInfo { servlet_id: s.to_vec(), address: addr.to_vec() })
				.collect(),
		}
	}

	#[test]
	fn evict_stale_returns_evicted_entries() -> Result<(), ClusterError> {
		let registry = HiveRegistry::new(Duration::ZERO);
		registry.register(request(b"hive1", &[b"ping"]))?;

		std::thread::sleep(Duration::from_millis(1));

		let evicted = registry.evict_stale()?;
		assert_eq!(evicted.len(), 1);
		assert_eq!(evicted[0].address.as_ref(), b"hive1");
		assert_eq!(registry.len()?, 0);

		Ok(())
	}

	#[test]
	fn evict_stale_keeps_fresh_hives() -> Result<(), ClusterError> {
		let registry = HiveRegistry::new(Duration::from_secs(3600));
		registry.register(request(b"hive1", &[b"ping"]))?;

		let evicted = registry.evict_stale()?;
		assert!(evicted.is_empty());
		assert_eq!(registry.len()?, 1);

		Ok(())
	}
}
