//! The hive registry holds membership and utilization. Servlet routes live
//! in [`ServletRegistry`], and the colony membership view moves a hive
//! through both registries as one step.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Duration;

use super::error::ClusterError;
use crate::colony::cluster::servlet_registry::{DialTarget, HiveSlate, ServletRegistry};
use crate::colony::common::RegisterHiveRequest;
use crate::utils::time::{Clock, MonotonicInstant};
use crate::utils::BasisPoints;

/// Shared byte slice for hive and servlet identifiers.
pub type SharedId = Arc<[u8]>;

/// Entry for a registered hive in the cluster.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HiveEntry {
	/// The hive's control address.
	pub address: SharedId,
	/// The utilization the hive last reported.
	pub utilization: BasisPoints,
	/// The instant of the last successful heartbeat, read on the gateway
	/// clock.
	pub last_seen: MonotonicInstant,
	/// The metadata the hive supplied at registration, if any.
	pub metadata: Option<Arc<[u8]>>,
	/// The number of consecutive heartbeat failures.
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
	/// stored address does not parse for this protocol, so a caller dials
	/// only an address this entry holds.
	pub fn dial_target<A: core::str::FromStr>(&self) -> Option<(SharedId, A)> {
		let address = Arc::clone(&self.address);
		let parsed = DialTarget::of_registered(&address).protocol_address().ok()?;
		Some((address, parsed))
	}
}

/// Registered hives, keyed by control address.
///
/// [`ServletRegistry`] owns every route and answers which servlet types a
/// hive serves. A hive's address update changes that registry alone, so the
/// one index every mutator keeps current is the one readers ask.
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

	/// Records a heartbeat seen at `now`, and answers whether the hive is
	/// still registered to record it against.
	fn record_utilization(
		&mut self,
		hive_id: impl AsRef<[u8]>,
		utilization: BasisPoints,
		now: MonotonicInstant,
	) -> bool {
		let hive_id = hive_id.as_ref();
		let Some(entry) = self.hives.get_mut(hive_id) else {
			return false;
		};

		entry.utilization = utilization;
		entry.last_seen = now;

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

	fn touch(&mut self, hive_id: impl AsRef<[u8]>, utilization: BasisPoints, now: MonotonicInstant) {
		let hive_id = hive_id.as_ref();
		if let Some(entry) = self.hives.get_mut(hive_id) {
			entry.last_seen = now;
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

	fn stale(&self, now: MonotonicInstant, timeout: Duration) -> Vec<SharedId> {
		self.hives
			.iter()
			.filter(|(_, entry)| now.saturating_duration_since(entry.last_seen) > timeout)
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
///
/// # Poisoned lock
///
/// A move under the member lock can leave a half-written table if the code
/// under the guard panics, so every method propagates
/// [`ClusterError::LockPoisoned`] rather than reading around it. A poisoned
/// std lock never clears, so the caller that sees it is the one that ends.
pub struct HiveRegistry {
	members: RwLock<Members>,
	/// The silence after which a hive is evicted.
	timeout: Duration,
	/// The clock leases are stamped and judged on.
	clock: Arc<dyn Clock>,
}

impl HiveRegistry {
	/// Creates a registry that evicts a hive silent for `timeout`, judged on
	/// `clock`.
	pub fn new(timeout: Duration, clock: Arc<dyn Clock>) -> Self {
		Self { members: RwLock::new(Members::default()), timeout, clock }
	}

	/// Registers a hive and binds its control-plane signer.
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
			last_seen: self.clock.monotonic(),
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

	/// Puts back a registration a rollback displaced.
	///
	/// # Signer check
	///
	/// The restored entry passes the same signer check its registration
	/// passed, under one guard, so this mutator offers no way around the
	/// binding [`HiveRegistry::register`] enforces (CWE-639). A restore the
	/// check refuses leaves the id unregistered, which is the state a refused
	/// registration leaves behind anyway.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	pub(crate) fn restore(&self, hive_id: SharedId, entry: HiveEntry) -> Result<(), ClusterError> {
		let mut members = self.members.write()?;
		let claimed = Arc::clone(&entry.signer_id);
		if members.admits_signer(hive_id.as_ref(), &claimed) {
			members.insert(hive_id, entry);
		}

		Ok(())
	}

	/// The signer bound to `hive_id` at registration, if any.
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
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	pub(crate) fn binds_signer(&self, hive_id: impl AsRef<[u8]>, claimed: &SharedId) -> Result<bool, ClusterError> {
		let hive_id = hive_id.as_ref();
		let bound = self.signer_for(hive_id)?;
		Ok(bound.is_some_and(|signer| signer.as_ref() == claimed.as_ref()))
	}

	/// Unregisters a hive and returns the entry it held.
	pub(crate) fn unregister(&self, hive_id: impl AsRef<[u8]>) -> Result<Option<HiveEntry>, ClusterError> {
		let hive_id = hive_id.as_ref();
		Ok(self.members.write()?.remove(hive_id))
	}

	/// Records the utilization a heartbeat reported, and answers whether the
	/// hive is still registered to record it against.
	pub fn update_utilization(
		&self,
		hive_id: impl AsRef<[u8]>,
		utilization: BasisPoints,
	) -> Result<bool, ClusterError> {
		let hive_id = hive_id.as_ref();
		let now = self.clock.monotonic();
		Ok(self.members.write()?.record_utilization(hive_id, utilization, now))
	}

	/// Counts one more heartbeat failure for a hive and returns the new count.
	pub fn increment_failure(&self, hive_id: impl AsRef<[u8]>) -> Result<u32, ClusterError> {
		let hive_id = hive_id.as_ref();
		Ok(self.members.write()?.increment_failure(hive_id))
	}

	/// Clears a hive's heartbeat failure count.
	pub fn reset_failure(&self, hive_id: impl AsRef<[u8]>) -> Result<(), ClusterError> {
		let hive_id = hive_id.as_ref();
		self.members.write()?.reset_failure(hive_id);
		Ok(())
	}

	/// Records a live heartbeat: the lease is renewed at the registry's
	/// clock, the utilization is stored, and the failure count is cleared.
	pub fn touch(&self, hive_id: impl AsRef<[u8]>, utilization: BasisPoints) -> Result<(), ClusterError> {
		let hive_id = hive_id.as_ref();
		let now = self.clock.monotonic();
		self.members.write()?.touch(hive_id, utilization, now);
		Ok(())
	}

	/// Evicts every hive whose lease has been silent longer than the timeout.
	///
	/// Returns the evicted entries, so a caller can retire the state that
	/// depended on each hive, such as its servlet routes.
	pub(crate) fn evict_stale(&self) -> Result<Vec<HiveEntry>, ClusterError> {
		let now = self.clock.monotonic();
		let mut members = self.members.write()?;

		let stale_ids = members.stale(now, self.timeout);
		let evicted = stale_ids.iter().filter_map(|id| members.remove(id.as_ref())).collect();
		Ok(evicted)
	}

	/// A snapshot of every registered hive.
	pub fn all_hives(&self) -> Result<Vec<HiveEntry>, ClusterError> {
		let members = self.members.read()?;
		Ok(members.all())
	}

	/// The number of registered hives.
	pub fn len(&self) -> Result<usize, ClusterError> {
		let members = self.members.read()?;
		Ok(members.len())
	}

	/// Whether no hive is registered.
	pub fn is_empty(&self) -> Result<bool, ClusterError> {
		Ok(self.len()? == 0)
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
	/// one serialized path.
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
	/// - [`ClusterError::ServletNotOwned`] -- the slate claims an address another owner holds.
	/// - [`ClusterError::LockPoisoned`] -- either registry is poisoned.
	pub(crate) fn admit(
		&self,
		request: RegisterHiveRequest,
		signer_id: SharedId,
		slate: HiveSlate,
	) -> Result<(), ClusterError> {
		let hive_addr: SharedId = Arc::from(request.hive_addr.as_slice());
		let _admission = self.hold_admission();

		let displaced = self.hives.register(request, signer_id)?;
		let Err(refused) = self.servlets.reconcile_by_hive(slate) else {
			return Ok(());
		};

		// A re-registration rolls back by restoring what it replaced, so a
		// hive that was serving before this request arrived keeps serving.
		match displaced {
			Some(previous) => self.hives.restore(hive_addr, previous)?,
			None => self.drop_membership(&hive_addr)?,
		}

		Err(refused)
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
	/// - [`ClusterError::ServletNotOwned`] -- an address belongs to another owner.
	/// - [`ClusterError::ServletNotFound`] -- a removal names an absent address.
	/// - [`ClusterError::LockPoisoned`] -- either registry is poisoned.
	pub(crate) fn update_addresses(
		&self,
		signer_id: &SharedId,
		added: HiveSlate,
		removed: &[&[u8]],
	) -> Result<(), ClusterError> {
		let _admission = self.hold_admission();

		if !self.hives.binds_signer(added.hive_id(), signer_id)? {
			return Err(ClusterError::SignerMismatch);
		}

		self.servlets.apply_address_update(added, removed)
	}

	/// Retires one hive and every route it owned.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- either registry is poisoned.
	pub(crate) fn retire(&self, hive_addr: impl AsRef<[u8]>) -> Result<(), ClusterError> {
		let _admission = self.hold_admission();

		self.drop_membership(hive_addr)
	}

	/// Retires one hive for a caller already holding `admission`.
	fn drop_membership(&self, hive_addr: impl AsRef<[u8]>) -> Result<(), ClusterError> {
		let hive_addr = hive_addr.as_ref();

		self.hives.unregister(hive_addr)?;
		self.servlets.remove_by_hive(hive_addr)?;

		Ok(())
	}

	/// Retires every hive whose lease expired, returning what left.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- either registry is poisoned.
	pub(crate) fn retire_stale(&self) -> Result<Vec<HiveEntry>, ClusterError> {
		let _admission = self.hold_admission();

		let stale = self.hives.evict_stale()?;
		for entry in &stale {
			self.servlets.remove_by_hive(&entry.address)?;
		}

		Ok(stale)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::cluster::servlet_registry::PheromoneConfig;
	use crate::colony::common::ColonyNamespace;
	use crate::colony::hive::ServletInfo;
	use crate::tb_cases;
	use crate::utils::time::ManualClock;

	/// A clock that moves only when the test advances it.
	fn manual_clock() -> Arc<dyn Clock> {
		Arc::new(ManualClock::default())
	}

	/// A hive registry with the default fixture lease, on a manual clock.
	fn hive_registry() -> HiveRegistry {
		HiveRegistry::new(Duration::from_secs(15), manual_clock())
	}

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
	fn slate(hive_addr: &SharedId, servlet: &str) -> HiveSlate {
		let servlets = request(hive_addr, &[servlet]).servlet_addresses;
		PheromoneConfig::default().servlet_slate(&servlets, hive_addr)
	}

	/// The pair of registries one gateway serves, with the admission lock
	/// that binds them.
	struct Colony {
		hives: HiveRegistry,
		servlets: ServletRegistry,
		admission: Mutex<()>,
	}

	impl Colony {
		fn new() -> Self {
			Self {
				hives: hive_registry(),
				servlets: ServletRegistry::new(PheromoneConfig::default(), manual_clock()),
				admission: Mutex::new(()),
			}
		}

		fn membership(&self) -> ColonyMembership<'_> {
			ColonyMembership::new(&self.hives, &self.servlets, &self.admission)
		}
	}

	#[test]
	fn retiring_a_hive_drops_the_routes_it_owned() -> Result<(), ClusterError> {
		let colony = Colony::new();
		let hive_addr: SharedId = Arc::from(b"hive1".as_slice());

		colony
			.membership()
			.admit(request(b"hive1", &["ping"]), test_signer(), slate(&hive_addr, "ping"))?;
		assert_eq!(colony.hives.len()?, 1);
		assert_eq!(colony.servlets.len()?, 1);

		colony.membership().retire(&hive_addr)?;
		assert_eq!(colony.hives.len()?, 0);
		assert_eq!(colony.servlets.len()?, 0);
		Ok(())
	}

	// A lease outlives its ttl or it does not, judged after the test moves
	// the registry's clock rather than after it waits. A lease exactly at
	// the ttl is still live, so the boundary row pins `>` against `>=`.
	tb_cases! {
		fn evict_stale((ttl, evicted_len, remaining_len): (Duration, usize, usize)) -> Result<(), ClusterError> {
			let clock = Arc::new(ManualClock::default());
			let registry = HiveRegistry::new(ttl, Arc::clone(&clock) as Arc<dyn Clock>);
			registry.register(request(b"hive1", &["ping"]), test_signer())?;

			clock.advance(Duration::from_secs(1));
			let evicted = registry.evict_stale()?;

			assert_eq!(evicted.len(), evicted_len);
			assert_eq!(registry.len()?, remaining_len);

			Ok(())
		}
		cases {
			expires_immediately => (Duration::ZERO, 1, 0),
			at_the_ttl => (Duration::from_secs(1), 0, 1),
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
			let registry = HiveRegistry::new(Duration::from_secs(3600), manual_clock());
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

	/// What one race between two signers for one hive id left behind: how
	/// many registrations were accepted, and which signer was bound.
	struct RaceOutcome {
		accepted: usize,
		bound: Option<SharedId>,
	}

	/// Races `first` and `second` to claim `contested` on a fresh registry.
	fn race_to_claim(contested: &'static [u8], first: &SharedId, second: &SharedId) -> RaceOutcome {
		let registry = Arc::new(hive_registry());

		let one = Arc::clone(&registry);
		let one_signer = Arc::clone(first);
		let left = std::thread::spawn(move || one.register(request(contested, &["echo"]), one_signer));

		let two = Arc::clone(&registry);
		let two_signer = Arc::clone(second);
		let right = std::thread::spawn(move || two.register(request(contested, &["echo"]), two_signer));

		let outcomes = [left.join().expect("thread joins"), right.join().expect("thread joins")];
		let accepted = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
		let bound = registry.signer_for(contested).expect("the registry lock is live");

		RaceOutcome { accepted, bound }
	}

	/// Runs [`race_to_claim`] many times and answers how many races bound
	/// exactly one of the two signers.
	fn races_binding_one_signer(rounds: usize) -> usize {
		let first: SharedId = Arc::from(b"signer-one".as_slice());
		let second: SharedId = Arc::from(b"signer-two".as_slice());
		let names_a_racer = |bound: &Option<SharedId>| {
			let bound = bound.as_deref();
			bound == Some(first.as_ref()) || bound == Some(second.as_ref())
		};

		(0..rounds)
			.map(|_| race_to_claim(b"hive-contested", &first, &second))
			.filter(|outcome| outcome.accepted == 1 && names_a_racer(&outcome.bound))
			.count()
	}

	/// Two signers race to claim one hive id. Exactly one binds, because the
	/// check and the insert share a guard (CWE-639).
	#[test]
	fn concurrent_registration_binds_one_signer() {
		let rounds = 2_000;

		let clean = races_binding_one_signer(rounds);

		assert_eq!(clean, rounds);
	}

	/// Poisons the route lock, so the next slate install refuses.
	///
	/// Each fixture slate claims only its own hive's address, so a poisoned
	/// lock is how these tests make `reconcile_by_hive` fail and reach the
	/// rollback.
	fn poison_routes(servlets: &ServletRegistry) {
		let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			let _held = servlets.routes.write().expect("the lock is live until this panic");
			panic!("poison the route lock");
		}));

		assert!(refused.is_err());
		assert!(servlets.local_servlets().is_err());
	}

	/// A re-registration whose slate will not install must leave the
	/// registration it displaced serving.
	#[test]
	fn a_refused_reregistration_restores_the_hive_it_displaced() -> Result<(), ClusterError> {
		let colony = Colony::new();
		let hive_addr: SharedId = Arc::from(b"hive-a".as_slice());

		colony
			.membership()
			.admit(request(b"hive-a", &["echo"]), test_signer(), slate(&hive_addr, "echo"))?;
		poison_routes(&colony.servlets);

		let refused =
			colony
				.membership()
				.admit(request(b"hive-a", &["ping"]), test_signer(), slate(&hive_addr, "ping"));

		assert!(refused.is_err());
		assert_eq!(colony.hives.len()?, 1);
		assert_eq!(colony.hives.signer_for(&hive_addr)?, Some(test_signer()));
		Ok(())
	}

	/// A first registration whose slate will not install must leave neither
	/// registry holding half of it.
	#[test]
	fn a_refused_first_registration_leaves_no_half() -> Result<(), ClusterError> {
		let colony = Colony::new();
		let hive_addr: SharedId = Arc::from(b"hive-a".as_slice());

		poison_routes(&colony.servlets);
		let refused =
			colony
				.membership()
				.admit(request(b"hive-a", &["echo"]), test_signer(), slate(&hive_addr, "echo"));

		assert!(refused.is_err());
		assert_eq!(colony.hives.len()?, 0);
		Ok(())
	}
}
