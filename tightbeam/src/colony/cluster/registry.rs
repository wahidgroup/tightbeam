//! Hive registry: membership, utilization, and servlet-type reverse index.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, Instant};

use super::error::ClusterError;
use crate::colony::cluster::servlet_registry::{ServletEntry, ServletRegistry};
use crate::colony::common::RegisterHiveRequest;
use crate::utils::BasisPoints;

/// Shared byte slice for hive and servlet identifiers
pub type SharedId = Arc<[u8]>;

/// Entry for a registered hive in the cluster
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HiveEntry {
	/// Hive control address
	pub address: SharedId,
	/// Last reported utilization
	pub utilization: BasisPoints,
	/// Timestamp of last successful heartbeat
	pub last_seen: Instant,
	/// Optional metadata from registration
	pub metadata: Option<Arc<[u8]>>,
	/// Consecutive heartbeat failures
	pub failure_count: u32,
	/// DER-encoded signer identifier bound at registration.
	///
	/// Every registration binds one. An entry with no signer would accept
	/// re-registration from anyone, so that state is not representable
	/// (CWE-639).
	pub signer_id: SharedId,
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

/// Registered hives, keyed by control address.
///
/// Which servlet types a hive serves is not held here: [`ServletRegistry`]
/// owns every route, and a hive's address update changes that registry alone.
/// A second index here would answer from a picture no mutator kept current.
///
/// A signer check and the insert it guards run under a single guard
/// (CWE-362, CWE-367).
#[derive(Default)]
struct Members {
	hives: HashMap<SharedId, HiveEntry>,
}

impl Members {
	/// Whether `incoming` may claim `hive_id`.
	///
	/// A registered hive accepts re-registration only from the signer bound
	/// at its first registration. An unregistered id is free (CWE-639).
	fn admits_signer(&self, hive_id: impl AsRef<[u8]>, incoming: &SharedId) -> bool {
		let hive_id = hive_id.as_ref();
		let Some(existing) = self.hives.get(hive_id) else {
			return true;
		};

		existing.signer_id.as_ref() == incoming.as_ref()
	}

	/// Replaces any prior registration, returning the entry it displaced.
	fn insert(&mut self, hive_id: SharedId, entry: HiveEntry) -> Option<HiveEntry> {
		self.hives.insert(hive_id, entry)
	}

	fn remove(&mut self, hive_id: impl AsRef<[u8]>) -> Option<HiveEntry> {
		let hive_id = hive_id.as_ref();
		self.hives.remove(hive_id)
	}

	fn signer_for(&self, hive_id: impl AsRef<[u8]>) -> Option<SharedId> {
		let hive_id = hive_id.as_ref();
		self.hives.get(hive_id).map(|entry| Arc::clone(&entry.signer_id))
	}

	/// Records a heartbeat. `false` when the hive left the registry.
	fn record_utilization(&mut self, hive_id: impl AsRef<[u8]>, utilization: BasisPoints) -> bool {
		let hive_id = hive_id.as_ref();
		let Some(entry) = self.hives.get_mut(hive_id) else {
			return false;
		};

		entry.utilization = utilization;
		entry.last_seen = Instant::now();

		true
	}

	fn increment_failure(&mut self, hive_id: impl AsRef<[u8]>) -> u32 {
		let hive_id = hive_id.as_ref();
		let Some(entry) = self.hives.get_mut(hive_id) else {
			return 0;
		};

		entry.failure_count = entry.failure_count.saturating_add(1);
		entry.failure_count
	}

	fn reset_failure(&mut self, hive_id: impl AsRef<[u8]>) {
		let hive_id = hive_id.as_ref();
		if let Some(entry) = self.hives.get_mut(hive_id) {
			entry.failure_count = 0;
		}
	}

	fn touch(&mut self, hive_id: impl AsRef<[u8]>, utilization: BasisPoints) {
		let hive_id = hive_id.as_ref();
		if let Some(entry) = self.hives.get_mut(hive_id) {
			entry.last_seen = Instant::now();
			entry.utilization = utilization;
			entry.failure_count = 0;
		}
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

/// Registry of hives keyed by control address.
///
/// Which servlet types a hive serves is answered by [`ServletRegistry`],
/// which owns every route.
///
/// # Lock order
///
/// This registry takes its one lock inside each method and never yields a
/// guard or calls a caller-supplied closure while holding it, so no method
/// here can be part of a nested acquisition. The membership view relies on
/// that to touch this registry and [`ServletRegistry`] in sequence.
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

	/// Register a hive and bind its control-plane signer.
	///
	/// Returns the registration this call displaced, when the hive was
	/// already registered. A caller that installs dependent state next
	/// needs it to put the previous registration back if that install
	/// fails, so dropping it forfeits the rollback.
	///
	/// # Signer binding
	///
	/// `signer_id` is the DER-encoded `SignerIdentifier` from the
	/// registration frame. Later `ServletAddressUpdate` calls must present
	/// the same signer for this hive id, and re-registration is admitted
	/// only from the signer bound first (CWE-639).
	///
	/// # Errors
	///
	/// - [`ClusterError::SignerMismatch`] -- a different signer already holds this hive id.
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	pub(crate) fn register(
		&self,
		request: RegisterHiveRequest,
		signer_id: SharedId,
	) -> Result<Option<HiveEntry>, ClusterError> {
		let hive_id: SharedId = request.hive_addr.into();
		let metadata: Option<Arc<[u8]>> = request.metadata.map(Into::into);
		let claimed = Arc::clone(&signer_id);

		let address = Arc::clone(&hive_id);
		let entry = HiveEntry {
			address,
			utilization: BasisPoints::default(),
			last_seen: Instant::now(),
			metadata,
			failure_count: 0,
			signer_id,
		};

		let mut members = self.members.write()?;
		if !members.admits_signer(hive_id.as_ref(), &claimed) {
			return Err(ClusterError::SignerMismatch);
		}

		Ok(members.insert(hive_id, entry))
	}

	/// Put back a registration a rollback displaced.
	///
	/// # Signer check
	///
	/// The restored entry passes the same signer check its registration passed,
	/// under one guard, so this mutator is no way around the binding
	/// [`HiveRegistry::register`] enforces (CWE-639). A restore the check
	/// refuses leaves the id unregistered, which is the state a refused
	/// registration leaves behind anyway.
	///
	/// # Poisoned lock
	///
	/// A poisoned lock is a panic this crate forbids, so a restore that
	/// cannot take the lock leaves the failed registration removed rather
	/// than failing the caller a second time.
	pub(crate) fn restore(&self, hive_id: SharedId, entry: HiveEntry) {
		let Ok(mut members) = self.members.write() else {
			return;
		};

		let claimed = Arc::clone(&entry.signer_id);
		if members.admits_signer(hive_id.as_ref(), &claimed) {
			members.insert(hive_id, entry);
		}
	}

	/// Signer bound to `hive_id` at registration, if any
	pub fn signer_for(&self, hive_id: impl AsRef<[u8]>) -> Result<Option<SharedId>, ClusterError> {
		let hive_id = hive_id.as_ref();
		let members = self.members.read()?;
		Ok(members.signer_for(hive_id))
	}

	/// Whether `claimed` is the signer bound to `hive_id` at registration.
	///
	/// An unregistered hive answers `false`, unlike
	/// [`Members::admits_signer`], which is asked about a free id. An
	/// update names a hive that is already serving, so a claim on an id
	/// nobody holds is unattributable (CWE-639).
	pub(crate) fn binds_signer(&self, hive_id: impl AsRef<[u8]>, claimed: &SharedId) -> bool {
		let hive_id = hive_id.as_ref();
		match self.signer_for(hive_id) {
			Ok(Some(bound)) => bound.as_ref() == claimed.as_ref(),
			_ => false,
		}
	}

	/// Unregister a hive and return the entry it held
	pub(crate) fn unregister(&self, hive_id: impl AsRef<[u8]>) -> Result<Option<HiveEntry>, ClusterError> {
		let hive_id = hive_id.as_ref();
		Ok(self.members.write()?.remove(hive_id))
	}

	/// Update hive utilization from heartbeat
	pub fn update_utilization(
		&self,
		hive_id: impl AsRef<[u8]>,
		utilization: BasisPoints,
	) -> Result<bool, ClusterError> {
		let hive_id = hive_id.as_ref();
		Ok(self.members.write()?.record_utilization(hive_id, utilization))
	}

	/// Increment failure count for a hive, returning the new count
	pub fn increment_failure(&self, hive_id: impl AsRef<[u8]>) -> Result<u32, ClusterError> {
		let hive_id = hive_id.as_ref();
		Ok(self.members.write()?.increment_failure(hive_id))
	}

	/// Reset failure count for a hive
	pub fn reset_failure(&self, hive_id: impl AsRef<[u8]>) -> Result<(), ClusterError> {
		let hive_id = hive_id.as_ref();
		self.members.write()?.reset_failure(hive_id);
		Ok(())
	}

	/// Touch a hive: update last_seen, utilization, and reset failure count
	pub fn touch(&self, hive_id: impl AsRef<[u8]>, utilization: BasisPoints) -> Result<(), ClusterError> {
		let hive_id = hive_id.as_ref();
		self.members.write()?.touch(hive_id, utilization);
		Ok(())
	}

	/// Evict stale hives that haven't sent heartbeat within timeout
	///
	/// Returns the evicted entries so callers can retire dependent state
	/// (e.g. servlet registry rows) for each evicted hive.
	pub(crate) fn evict_stale(&self) -> Result<Vec<HiveEntry>, ClusterError> {
		self.evict_stale_at(Instant::now())
	}

	/// Eviction judged against `now`, for a caller that owns the instant.
	fn evict_stale_at(&self, now: Instant) -> Result<Vec<HiveEntry>, ClusterError> {
		let mut members = self.members.write()?;

		let stale_ids = members.stale(now, self.timeout);
		let evicted = stale_ids.iter().filter_map(|id| members.remove(id.as_ref())).collect();
		Ok(evicted)
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

/// The two registries one hive's membership spans.
///
/// A hive's entry lives in [`HiveRegistry`] and its servlet routes live in
/// [`ServletRegistry`]. The pair enters and leaves together, so admission and
/// retirement are operations here rather than a sequence each caller repeats.
/// Retiring only the hive entry would leave routes that point at a hive the
/// colony has stopped beating.
pub(crate) struct ColonyMembership<'a> {
	hives: &'a HiveRegistry,
	servlets: &'a ServletRegistry,
	/// Held by every operation here, so the pair moves as one step even
	/// though each registry takes its own lock.
	admission: &'a Mutex<()>,
}

impl<'a> ColonyMembership<'a> {
	/// Views the pair of registries a gateway serves.
	///
	/// `admission` is the gateway's own, so every view it hands out shares
	/// one serialised path.
	pub(crate) fn new(hives: &'a HiveRegistry, servlets: &'a ServletRegistry, admission: &'a Mutex<()>) -> Self {
		Self { hives, servlets, admission }
	}

	/// Holds the admission path for one whole membership move.
	///
	/// The guarded value is `()`, so a poisoned lock carries no damaged
	/// state and this lock recovers the guard instead of refusing the
	/// caller.
	fn hold_admission(&self) -> MutexGuard<'_, ()> {
		self.admission.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Admits one hive with the servlet slate it registered.
	///
	/// A slate that fails to install rolls the hive entry back, so a
	/// refused registration leaves neither registry holding half of it.
	///
	/// # Errors
	///
	/// - [`ClusterError::SignerMismatch`] -- a different signer holds this hive id.
	/// - [`ClusterError::LockPoisoned`] -- either registry is poisoned.
	pub(crate) fn admit(
		&self,
		request: RegisterHiveRequest,
		signer_id: SharedId,
		slate: Vec<ServletEntry>,
	) -> Result<(), ClusterError> {
		let hive_addr: SharedId = Arc::from(request.hive_addr.as_slice());
		let _admission = self.hold_admission();

		let displaced = self.hives.register(request, signer_id)?;
		self.servlets.reconcile_by_hive(&hive_addr, slate).inspect_err(|_| {
			// Rolling back a re-registration means restoring what it
			// replaced, not deleting a hive that was serving before this
			// request arrived.
			match displaced {
				Some(ref previous) => self.hives.restore(Arc::clone(&hive_addr), previous.clone()),
				None => self.drop_membership(&hive_addr),
			}
		})
	}

	/// Applies one hive's servlet address delta under its signer bind.
	///
	/// The signer check and the route write share the admission hold, so a
	/// retirement running beside this update cannot lose the race and have
	/// the routes it dropped reinstalled behind it (CWE-362, CWE-367).
	///
	/// # Errors
	///
	/// - [`ClusterError::SignerMismatch`] -- `signer_id` is not the signer bound at registration.
	/// - [`ClusterError::LockPoisoned`] -- the servlet registry is poisoned.
	pub(crate) fn update_addresses(
		&self,
		hive_id: impl AsRef<[u8]>,
		signer_id: &SharedId,
		added: impl IntoIterator<Item = ServletEntry>,
		removed: &[&[u8]],
	) -> Result<(), ClusterError> {
		let hive_id = hive_id.as_ref();
		let _admission = self.hold_admission();

		if !self.hives.binds_signer(hive_id, signer_id) {
			return Err(ClusterError::SignerMismatch);
		}

		self.servlets.apply_address_update(hive_id, added, removed)
	}

	/// Retires one hive and every route it owned.
	///
	/// A poisoned lock is a panic the crate forbids, so a registry that
	/// refuses the write leaves the other retirement in place rather than
	/// failing the caller.
	pub(crate) fn retire(&self, hive_addr: impl AsRef<[u8]>) {
		let _admission = self.hold_admission();

		self.drop_membership(hive_addr);
	}

	/// Retires one hive for a caller already holding `admission`.
	fn drop_membership(&self, hive_addr: impl AsRef<[u8]>) {
		let hive_addr = hive_addr.as_ref();

		let _ = self.hives.unregister(hive_addr);
		let _ = self.servlets.remove_by_hive(hive_addr);
	}

	/// Retires every hive whose lease expired, returning what left.
	pub(crate) fn retire_stale(&self) -> Vec<HiveEntry> {
		let _admission = self.hold_admission();

		let stale = self.hives.evict_stale().unwrap_or_default();
		for entry in &stale {
			let _ = self.servlets.remove_by_hive(&entry.address);
		}

		stale
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::cluster::servlet_registry::LocalRoute;
	use crate::colony::common::ColonyNamespace;
	use crate::colony::hive::ServletInfo;
	use crate::tb_cases;

	/// The signer every fixture registration binds. Registration always
	/// names one, so the tests name one too.
	fn test_signer() -> SharedId {
		Arc::from(b"test-signer".as_slice())
	}

	fn request(addr: impl AsRef<[u8]>, servlets: &[&str]) -> RegisterHiveRequest {
		let addr = addr.as_ref();
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

	/// One local route for `hive_addr`, the shape a registration installs.
	fn slate(hive_addr: &SharedId, servlet: &str) -> Vec<ServletEntry> {
		let namespace = ColonyNamespace::default();
		let urn = namespace.servlet(servlet).expect("test names satisfy the mint grammar");
		vec![ServletEntry::local(
			LocalRoute {
				address: Arc::clone(hive_addr),
				servlet_type: Arc::from(urn.type_canonical_bytes().as_slice()),
				hive_id: Arc::clone(hive_addr),
			},
			1,
			3,
		)]
	}

	#[test]
	fn retiring_a_hive_drops_the_routes_it_owned() -> Result<(), ClusterError> {
		let hives = HiveRegistry::default();
		let servlets = ServletRegistry::default();
		let admission = Mutex::new(());
		let membership = ColonyMembership::new(&hives, &servlets, &admission);
		let hive_addr: SharedId = Arc::from(b"hive1".as_slice());

		membership.admit(request(b"hive1", &["ping"]), test_signer(), slate(&hive_addr, "ping"))?;
		assert_eq!(hives.len()?, 1);
		assert_eq!(servlets.len()?, 1);

		membership.retire(&hive_addr);
		assert_eq!(hives.len()?, 0);
		assert_eq!(servlets.len()?, 0);
		Ok(())
	}

	// A lease outlives its ttl or it does not, judged at an instant the
	// test names rather than one it waits for.
	tb_cases! {
		fn evict_stale((ttl, evicted_len, remaining_len): (Duration, usize, usize)) -> Result<(), ClusterError> {
			let registry = HiveRegistry::new(ttl);
			registry.register(request(b"hive1", &["ping"]), test_signer())?;

			let a_second_later = Instant::now() + Duration::from_secs(1);
			let evicted = registry.evict_stale_at(a_second_later)?;

			assert_eq!(evicted.len(), evicted_len);
			assert_eq!(registry.len()?, remaining_len);

			Ok(())
		}
		cases {
			expires_immediately => (Duration::ZERO, 1, 0),
			outlives_the_probe => (Duration::from_secs(3600), 0, 1),
		}
	}

	struct SignerRebindCase {
		first: &'static [u8],
		second: &'static [u8],
		expect_ok: bool,
	}

	// A hive id stays bound to the signer that first claimed it. An unbound
	// hive is absent from this table because it is absent from the type:
	// every registration binds a signer.
	tb_cases! {
		fn register_signer_rebind(case: SignerRebindCase) -> Result<(), ClusterError> {
			let registry = HiveRegistry::new(Duration::from_secs(3600));
			registry.register(request(b"hive1", &["ping"]), Arc::from(case.first))?;

			let result = registry.register(request(b"hive1", &["ping"]), Arc::from(case.second));
			assert_eq!(result.is_ok(), case.expect_ok);
			if !case.expect_ok {
				assert!(matches!(result, Err(ClusterError::SignerMismatch)));
			}

			// The signer bound first always survives the attempt.
			let bound = registry.signer_for(b"hive1")?;
			assert_eq!(bound.as_deref(), Some(case.first));

			Ok(())
		}
		cases {
			refuses_a_different_signer => SignerRebindCase { first: b"sid-a", second: b"sid-b", expect_ok: false },
			admits_the_bound_signer => SignerRebindCase { first: b"sid-a", second: b"sid-a", expect_ok: true },
		}
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
			let left = thread::spawn(move || one.register(request(contested, &["echo"]), one_signer));

			let two = Arc::clone(&registry);
			let two_signer = Arc::clone(&second);
			let right = thread::spawn(move || two.register(request(contested, &["echo"]), two_signer));

			let outcomes = [left.join().expect("thread joins"), right.join().expect("thread joins")];
			let accepted = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
			assert_eq!(accepted, 1);

			let bound = registry.signer_for(contested)?.expect("the winner bound a signer");
			assert!(bound.as_ref() == first.as_ref() || bound.as_ref() == second.as_ref());
		}

		Ok(())
	}

	/// Poison the route lock, so the next slate install refuses.
	///
	/// This is the only way `reconcile_by_hive` fails: a rollback is
	/// otherwise unreachable, and an unreachable rollback is one nothing
	/// can check.
	fn poison_routes(servlets: &ServletRegistry) {
		let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			let _held = servlets.routes.write().expect("the lock is live until this panic");
			panic!("poison the route lock");
		}));

		assert!(refused.is_err());
		assert!(servlets.local_servlets().is_err());
	}

	/// A re-registration whose slate will not install must leave the
	/// registration it displaced serving, not delete a live hive.
	#[test]
	fn a_refused_reregistration_restores_the_hive_it_displaced() -> Result<(), ClusterError> {
		let hives = HiveRegistry::default();
		let servlets = ServletRegistry::default();
		let admission = Mutex::new(());
		let membership = ColonyMembership::new(&hives, &servlets, &admission);
		let hive_addr: SharedId = Arc::from(b"hive-a".as_slice());

		membership.admit(request(b"hive-a", &["echo"]), test_signer(), slate(&hive_addr, "echo"))?;
		poison_routes(&servlets);

		let refused = membership.admit(request(b"hive-a", &["ping"]), test_signer(), slate(&hive_addr, "ping"));

		assert!(refused.is_err());
		assert_eq!(hives.len()?, 1);
		assert_eq!(hives.signer_for(&hive_addr)?, Some(test_signer()));
		Ok(())
	}

	/// A first registration whose slate will not install must leave neither
	/// registry holding half of it.
	#[test]
	fn a_refused_first_registration_leaves_no_half() -> Result<(), ClusterError> {
		let hives = HiveRegistry::default();
		let servlets = ServletRegistry::default();
		let admission = Mutex::new(());
		let membership = ColonyMembership::new(&hives, &servlets, &admission);
		let hive_addr: SharedId = Arc::from(b"hive-a".as_slice());

		poison_routes(&servlets);
		let refused = membership.admit(request(b"hive-a", &["echo"]), test_signer(), slate(&hive_addr, "echo"));

		assert!(refused.is_err());
		assert_eq!(hives.len()?, 0);
		Ok(())
	}
}
