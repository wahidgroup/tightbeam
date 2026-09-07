//! Hive registry: membership, utilization, and servlet-type reverse index.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use super::error::ClusterError;
use crate::colony::common::{type_canonical_bytes, RegisterHiveRequest};
use crate::utils::BasisPoints;

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
	/// DER-encoded signer identifier bound at registration (x509 control plane)
	pub signer_id: Option<SharedId>,
}

impl HiveEntry {
	/// This hive's control address, parsed for the dialing protocol.
	///
	/// Returns the stored bytes beside the parsed form. [`None`] means the
	/// stored address parses for this protocol, so a caller dials only an
	/// address this entry holds.
	pub fn dial_target<A: core::str::FromStr>(&self) -> Option<(SharedId, A)> {
		let address = Arc::clone(&self.address);
		core::str::from_utf8(&address)
			.ok()
			.and_then(|raw| raw.parse().ok())
			.map(|parsed| (address, parsed))
	}
}

/// Registered hives and the servlet-type index they produce.
///
/// The index is derived from each entry's `servlet_types`, so both live
/// behind one lock and under one owner. A signer check and the insert it
/// guards run under a single guard, and a type lookup sees hives the map
/// still holds (CWE-362, CWE-367).
#[derive(Default)]
struct Members {
	hives: HashMap<SharedId, HiveEntry>,
	by_type: HashMap<SharedId, Vec<SharedId>>,
}

impl Members {
	/// Whether `incoming` may claim `hive_id`.
	///
	/// A hive with a bound signer accepts re-registration only from that
	/// signer. An unbound hive accepts any (CWE-639).
	fn admits_signer(&self, hive_id: &[u8], incoming: Option<&SharedId>) -> bool {
		let Some(existing) = self.hives.get(hive_id) else {
			return true;
		};

		match (&existing.signer_id, incoming) {
			(Some(bound), Some(candidate)) => bound.as_ref() == candidate.as_ref(),
			(Some(_), None) => false,
			(None, _) => true,
		}
	}

	/// Replaces any prior registration and reindexes its servlet types.
	fn insert(&mut self, hive_id: SharedId, entry: HiveEntry) {
		self.remove(hive_id.as_ref());

		for servlet_type in entry.servlet_types.iter() {
			self.by_type
				.entry(Arc::clone(servlet_type))
				.or_default()
				.push(Arc::clone(&hive_id));
		}

		self.hives.insert(hive_id, entry);
	}

	fn remove(&mut self, hive_id: &[u8]) -> Option<HiveEntry> {
		let entry = self.hives.remove(hive_id)?;
		for servlet_type in entry.servlet_types.iter() {
			let Some(hive_ids) = self.by_type.get_mut(servlet_type) else {
				continue;
			};

			hive_ids.retain(|id| id.as_ref() != hive_id);
			if hive_ids.is_empty() {
				self.by_type.remove(servlet_type);
			}
		}

		Some(entry)
	}

	fn for_type(&self, servlet_type: &[u8]) -> Vec<HiveEntry> {
		let Some(hive_ids) = self.by_type.get(servlet_type) else {
			return Vec::new();
		};

		hive_ids.iter().filter_map(|id| self.hives.get(id.as_ref()).cloned()).collect()
	}

	fn signer_for(&self, hive_id: &[u8]) -> Option<SharedId> {
		self.hives.get(hive_id).and_then(|entry| entry.signer_id.clone())
	}

	/// Records a heartbeat. `false` when the hive left the registry.
	fn record_utilization(&mut self, hive_id: &[u8], utilization: BasisPoints) -> bool {
		let Some(entry) = self.hives.get_mut(hive_id) else {
			return false;
		};

		entry.utilization = utilization;
		entry.last_seen = Instant::now();

		true
	}

	fn increment_failure(&mut self, hive_id: &[u8]) -> u32 {
		let Some(entry) = self.hives.get_mut(hive_id) else {
			return 0;
		};

		entry.failure_count = entry.failure_count.saturating_add(1);
		entry.failure_count
	}

	fn reset_failure(&mut self, hive_id: &[u8]) {
		if let Some(entry) = self.hives.get_mut(hive_id) {
			entry.failure_count = 0;
		}
	}

	fn touch(&mut self, hive_id: &[u8], utilization: BasisPoints) {
		if let Some(entry) = self.hives.get_mut(hive_id) {
			entry.last_seen = Instant::now();
			entry.utilization = utilization;
			entry.failure_count = 0;
		}
	}

	fn available_servlets(&self) -> Vec<SharedId> {
		self.by_type.keys().map(Arc::clone).collect()
	}

	fn all(&self) -> Vec<HiveEntry> {
		self.hives.values().cloned().collect()
	}

	fn len(&self) -> usize {
		self.hives.len()
	}

	fn stale(&self, now: Instant, timeout: Duration) -> Vec<SharedId> {
		self.hives
			.iter()
			.filter(|(_, entry)| now.duration_since(entry.last_seen) > timeout)
			.map(|(id, _)| Arc::clone(id))
			.collect()
	}
}

/// Registry of hives with servlet type indexing
///
/// Maintains a mapping of hives and a reverse index from servlet types
/// to hives that support them. Thread-safe for concurrent access.
pub struct HiveRegistry {
	members: RwLock<Members>,
	/// Heartbeat timeout for eviction
	timeout: Duration,
}

impl HiveRegistry {
	/// Create a new registry with the given heartbeat timeout
	pub fn new(timeout: Duration) -> Self {
		Self { members: RwLock::new(Members::default()), timeout }
	}

	/// Register a hive and index its servlet types
	///
	/// If the hive was already registered, updates its entry and re-indexes.
	/// Takes ownership for zero-copy conversion to `Arc<[u8]>`.
	pub fn register(&self, request: RegisterHiveRequest) -> Result<(), ClusterError> {
		self.register_with_signer(request, None)
	}

	/// Register a hive and bind the authenticated control-plane signer
	///
	/// `signer_id` is the DER-encoded `SignerIdentifier` from the registration
	/// frame. Later `ServletAddressUpdate` calls must present the same signer
	/// for this hive id (CWE-639).
	///
	/// Re-registration of an existing hive is allowed only when the incoming
	/// signer matches the already-bound signer.
	pub fn register_with_signer(
		&self,
		request: RegisterHiveRequest,
		signer_id: Option<SharedId>,
	) -> Result<(), ClusterError> {
		let hive_id: SharedId = request.hive_addr.into();

		// Index by servlet TYPE: instance URNs collapse onto their type
		// key so work routed by type finds every instance-bearing hive.
		let mut seen = HashSet::new();
		let servlet_types: Arc<[SharedId]> = request
			.servlet_addresses
			.iter()
			.filter_map(|info| {
				let type_key: SharedId = Arc::from(type_canonical_bytes(&info.servlet_id).as_slice());
				seen.insert(Arc::clone(&type_key)).then_some(type_key)
			})
			.collect();

		let metadata: Option<Arc<[u8]>> = request.metadata.map(Into::into);
		let signer_id_ref = signer_id.clone();

		let address = Arc::clone(&hive_id);
		let entry_servlet_types = Arc::clone(&servlet_types);
		let entry = HiveEntry {
			address,
			servlet_types: entry_servlet_types,
			utilization: BasisPoints::default(),
			last_seen: Instant::now(),
			metadata,
			failure_count: 0,
			signer_id,
		};

		let mut members = self.members.write()?;
		if !members.admits_signer(hive_id.as_ref(), signer_id_ref.as_ref()) {
			return Err(ClusterError::SignerMismatch);
		}

		members.insert(hive_id, entry);
		Ok(())
	}

	/// Signer bound to `hive_id` at registration, if any
	pub fn signer_for(&self, hive_id: &[u8]) -> Result<Option<SharedId>, ClusterError> {
		let members = self.members.read()?;
		Ok(members.signer_for(hive_id))
	}

	/// Unregister a hive and remove from indices
	pub fn unregister(&self, hive_id: &[u8]) -> Result<Option<HiveEntry>, ClusterError> {
		Ok(self.members.write()?.remove(hive_id))
	}

	/// Find all hives that support a servlet type
	pub fn hives_for_type(&self, servlet_type: &[u8]) -> Result<Vec<HiveEntry>, ClusterError> {
		Ok(self.members.read()?.for_type(servlet_type))
	}

	/// Update hive utilization from heartbeat
	pub fn update_utilization(&self, hive_id: &[u8], utilization: BasisPoints) -> Result<bool, ClusterError> {
		Ok(self.members.write()?.record_utilization(hive_id, utilization))
	}

	/// Increment failure count for a hive, returning the new count
	pub fn increment_failure(&self, hive_id: &[u8]) -> Result<u32, ClusterError> {
		Ok(self.members.write()?.increment_failure(hive_id))
	}

	/// Reset failure count for a hive
	pub fn reset_failure(&self, hive_id: &[u8]) -> Result<(), ClusterError> {
		self.members.write()?.reset_failure(hive_id);
		Ok(())
	}

	/// Touch a hive: update last_seen, utilization, and reset failure count
	pub fn touch(&self, hive_id: &[u8], utilization: BasisPoints) -> Result<(), ClusterError> {
		self.members.write()?.touch(hive_id, utilization);
		Ok(())
	}

	/// Evict stale hives that haven't sent heartbeat within timeout
	///
	/// Returns the evicted entries so callers can retire dependent state
	/// (e.g. servlet registry rows) for each evicted hive.
	pub fn evict_stale(&self) -> Result<Vec<HiveEntry>, ClusterError> {
		let now = Instant::now();
		let mut members = self.members.write()?;

		let stale_ids = members.stale(now, self.timeout);
		let evicted = stale_ids.iter().filter_map(|id| members.remove(id.as_ref())).collect();
		Ok(evicted)
	}

	/// List all available servlet types across all registered hives
	pub fn to_available_servlets(&self) -> Result<Vec<SharedId>, ClusterError> {
		let members = self.members.read()?;
		Ok(members.available_servlets())
	}

	/// Get a snapshot of all registered hives
	pub fn all_hives(&self) -> Result<Vec<HiveEntry>, ClusterError> {
		let members = self.members.read()?;
		Ok(members.all())
	}

	/// Count the number of registered hives
	pub fn len(&self) -> Result<usize, ClusterError> {
		let members = self.members.read()?;
		Ok(members.len())
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
	use crate::colony::common::ColonyNamespace;
	use crate::colony::hive::ServletInfo;

	fn request(addr: &[u8], servlets: &[&str]) -> RegisterHiveRequest {
		let namespace = ColonyNamespace::default();
		RegisterHiveRequest {
			hive_addr: addr.to_vec(),
			metadata: None,
			servlet_addresses: servlets
				.iter()
				.map(|s| ServletInfo {
					servlet_id: namespace.servlet(s).expect("test names satisfy the mint grammar"),
					address: addr.to_vec(),
				})
				.collect(),
		}
	}

	fn type_key(name: &str) -> Vec<u8> {
		let namespace = ColonyNamespace::default();
		let urn = namespace.servlet(name).expect("test names satisfy the mint grammar");
		type_canonical_bytes(&urn)
	}

	#[test]
	fn register_deduplicates_type_index() -> Result<(), ClusterError> {
		let registry = HiveRegistry::default();
		registry.register(request(b"hive1", &["ping", "ping"]))?;

		let hives = registry.hives_for_type(&type_key("ping"))?;
		assert_eq!(hives.len(), 1);
		assert_eq!(hives[0].servlet_types.len(), 1);
		Ok(())
	}

	/// (ttl, expected_evicted_len, expected_remaining_len)
	const EVICT_STALE_CASES: &[(Duration, usize, usize)] = &[(Duration::ZERO, 1, 0), (Duration::from_secs(3600), 0, 1)];

	#[test]
	fn evict_stale_behavior() -> Result<(), ClusterError> {
		for &(ttl, evicted_len, remaining_len) in EVICT_STALE_CASES {
			let registry = HiveRegistry::new(ttl);
			registry.register(request(b"hive1", &["ping"]))?;

			std::thread::sleep(Duration::from_millis(1));

			let evicted = registry.evict_stale()?;
			assert_eq!(evicted.len(), evicted_len);
			assert_eq!(registry.len()?, remaining_len);
		}

		Ok(())
	}

	struct SignerRebindCase {
		first: Option<&'static [u8]>,
		second: Option<&'static [u8]>,
		expect_ok: bool,
		bound_after: Option<&'static [u8]>,
	}

	fn signer_rebind_cases() -> Vec<SignerRebindCase> {
		vec![
			SignerRebindCase {
				first: Some(b"sid-a"),
				second: Some(b"sid-b"),
				expect_ok: false,
				bound_after: Some(b"sid-a"),
			},
			SignerRebindCase {
				first: Some(b"sid-a"),
				second: Some(b"sid-a"),
				expect_ok: true,
				bound_after: Some(b"sid-a"),
			},
			SignerRebindCase {
				first: None,
				second: Some(b"sid-a"),
				expect_ok: true,
				bound_after: Some(b"sid-a"),
			},
			SignerRebindCase {
				first: Some(b"sid-a"),
				second: None,
				expect_ok: false,
				bound_after: Some(b"sid-a"),
			},
		]
	}

	#[test]
	fn register_with_signer_rejects_cross_signer_hijack() -> Result<(), ClusterError> {
		for case in signer_rebind_cases() {
			let registry = HiveRegistry::new(Duration::from_secs(3600));
			registry.register_with_signer(request(b"hive1", &["ping"]), case.first.map(Arc::from))?;

			let result = registry.register_with_signer(request(b"hive1", &["ping"]), case.second.map(Arc::from));
			assert_eq!(result.is_ok(), case.expect_ok);
			if !case.expect_ok {
				assert!(matches!(result, Err(ClusterError::SignerMismatch)));
			}

			let bound = registry.signer_for(b"hive1")?;
			assert_eq!(bound.as_deref(), case.bound_after);
		}

		Ok(())
	}

	/// Two signers race to claim one hive id. Exactly one binds, because the
	/// check and the insert share a guard (CWE-639).
	#[test]
	fn concurrent_registration_binds_one_signer() -> Result<(), ClusterError> {
		use std::thread;

		let contested = b"hive-contested";
		for _ in 0..2_000 {
			let registry = Arc::new(HiveRegistry::default());
			let first: SharedId = Arc::from(b"signer-one".as_slice());
			let second: SharedId = Arc::from(b"signer-two".as_slice());

			let one = Arc::clone(&registry);
			let one_signer = Arc::clone(&first);
			let left = thread::spawn(move || one.register_with_signer(request(contested, &["echo"]), Some(one_signer)));

			let two = Arc::clone(&registry);
			let two_signer = Arc::clone(&second);
			let right =
				thread::spawn(move || two.register_with_signer(request(contested, &["echo"]), Some(two_signer)));

			let outcomes = [left.join().expect("thread joins"), right.join().expect("thread joins")];
			let accepted = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
			assert_eq!(accepted, 1);

			let bound = registry.signer_for(contested)?.expect("the winner bound a signer");
			assert!(bound.as_ref() == first.as_ref() || bound.as_ref() == second.as_ref());
		}

		Ok(())
	}

	/// Removing a hive drops it from the type index in the same guard, so a
	/// lookup names the hives the map holds.
	#[test]
	fn unregister_clears_the_type_index() -> Result<(), ClusterError> {
		let registry = HiveRegistry::default();
		registry.register(request(b"hive-a", &["echo"]))?;
		registry.unregister(b"hive-a")?;

		assert!(registry.hives_for_type(&type_key("echo"))?.is_empty());
		assert!(registry.to_available_servlets()?.is_empty());
		Ok(())
	}
}
