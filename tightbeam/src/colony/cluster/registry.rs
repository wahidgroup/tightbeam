//! The hive registry holds membership and utilization. Servlet routes live
//! in [`ServletRegistry`], and the colony membership view moves a hive
//! through both registries as one step.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Duration;

use super::error::ClusterError;
use crate::basis_points::BasisPoints;
use crate::clock::{Clock, MonotonicInstant};
use crate::cms::signed_data::SignerIdentifier;
use crate::colony::bound_dial::{BoundDial, ExpectedSigner};
use crate::colony::cluster::servlet_registry::{DialTarget, HiveSlate, ServletRegistry};
use crate::colony::protocol::RegisterHiveRequest;
use crate::policy::TransitStatus;

/// The shared byte slice of a hive or servlet identifier.
pub type SharedId = Arc<[u8]>;

/// The entry of a registered hive in the cluster.
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
	/// The signer identifier bound at registration, read once from the frame
	/// that registered the hive.
	///
	/// Every registration binds one, so the field is required. An entry with no
	/// signer would accept re-registration from anyone (CWE-639).
	pub signer: Arc<SignerIdentifier>,
}

impl HiveEntry {
	/// The dial of this hive's control address, bound to the signer of its
	/// registration.
	///
	/// The control plane answers under the identity that signs the hive's
	/// registrations, so a heartbeat admits that identity alone (CWE-346).
	pub(crate) fn bound_dial<'a, P: 'a>(&self) -> BoundDial<'a, P> {
		let target = DialTarget::of_registered(&self.address);

		BoundDial::new(target, ExpectedSigner::Hive(Arc::clone(&self.signer)))
	}
}

/// The registered hives, keyed by control address.
///
/// A hive's address update changes [`ServletRegistry`] alone, so readers ask
/// that registry, the one index every mutator keeps current.
///
/// A signer check and the insert it guards run under one guard (CWE-362,
/// CWE-367).
#[derive(Default)]
struct Members {
	hives: HashMap<SharedId, HiveEntry>,
}

impl Members {
	/// Whether `incoming` may claim `hive_id`.
	///
	/// A registered hive accepts re-registration only from the signer bound
	/// at its first registration. An unregistered id is free (CWE-639).
	fn admits_signer(&self, hive_id: impl AsRef<[u8]>, incoming: &SignerIdentifier) -> bool {
		let hive_id = hive_id.as_ref();
		let Some(existing) = self.hives.get(hive_id) else {
			return true;
		};

		existing.signer.as_ref() == incoming
	}

	/// Replaces any prior registration and returns the entry it displaced.
	fn insert(&mut self, hive_id: SharedId, entry: HiveEntry) -> Option<HiveEntry> {
		self.hives.insert(hive_id, entry)
	}

	fn remove(&mut self, hive_id: impl AsRef<[u8]>) -> Option<HiveEntry> {
		let hive_id = hive_id.as_ref();
		self.hives.remove(hive_id)
	}

	fn signer_for(&self, hive_id: impl AsRef<[u8]>) -> Option<Arc<SignerIdentifier>> {
		let hive_id = hive_id.as_ref();
		self.hives.get(hive_id).map(|entry| Arc::clone(&entry.signer))
	}

	fn entry(&self, hive_id: impl AsRef<[u8]>) -> Option<HiveEntry> {
		let hive_id = hive_id.as_ref();
		self.hives.get(hive_id).cloned()
	}

	/// Counts one failure of a registered hive and returns its new count, or
	/// `None` for a hive that holds no entry.
	fn increment_member_failure(&mut self, hive_id: impl AsRef<[u8]>) -> Option<u32> {
		let entry = self.hives.get_mut(hive_id.as_ref())?;
		entry.failure_count = entry.failure_count.saturating_add(1);
		Some(entry.failure_count)
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

/// The registry of hives, keyed by control address.
///
/// [`ServletRegistry`] owns every route and answers which servlet types a
/// hive serves.
///
/// # Lock order
///
/// Each method takes this registry's one lock, runs only registry code under
/// the guard, and releases it before it returns. So a call here is its
/// caller's innermost acquisition, and the membership view relies on that to
/// touch this registry and [`ServletRegistry`] in sequence.
///
/// # Poisoned lock
///
/// A panic under the member lock can leave a half-written table, so every
/// method propagates [`ClusterError::LockPoisoned`] rather than read around
/// it. A poisoned std lock never clears, so the caller that sees it is the
/// one that ends.
pub struct HiveRegistry {
	members: RwLock<Members>,
	/// The silence after which the registry evicts a hive.
	timeout: Duration,
	/// The clock that stamps and judges leases.
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
	/// Returns the registration this call displaced, if any. A caller that next
	/// installs dependent state needs it to put the previous registration back
	/// if that install fails, so dropping it forfeits the rollback.
	///
	/// # Signer binding
	///
	/// `signer` is the [`SignerIdentifier`] of the registration frame. Later
	/// `ServletAddressUpdate` calls must present the same signer for this hive
	/// id, and the registry admits re-registration only from the signer it
	/// bound first (CWE-639).
	///
	/// # Errors
	///
	/// - [`ClusterError::SignerMismatch`] -- a different signer already holds this hive id.
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	fn register(
		&self,
		request: RegisterHiveRequest,
		signer: Arc<SignerIdentifier>,
	) -> Result<Option<HiveEntry>, ClusterError> {
		let hive_id: SharedId = request.hive_addr.into();
		let metadata: Option<Arc<[u8]>> = request.metadata.map(Into::into);
		let claimed = Arc::clone(&signer);

		let address = Arc::clone(&hive_id);
		let entry = HiveEntry {
			address,
			utilization: BasisPoints::default(),
			last_seen: self.clock.monotonic(),
			metadata,
			failure_count: 0,
			signer,
		};

		let mut members = self.members.write()?;
		if !members.admits_signer(hive_id.as_ref(), &claimed) {
			return Err(ClusterError::SignerMismatch);
		}

		Ok(members.insert(hive_id, entry))
	}

	/// Puts back the registration that a rolled-back registration displaced.
	///
	/// # Signer check
	///
	/// The restored entry passes its registration's signer check under one
	/// guard, so this mutator keeps the binding that [`HiveRegistry::register`]
	/// enforces (CWE-639). The check refuses only while another signer holds
	/// the id, and a refusal leaves the table as it is, as for a refused
	/// registration.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	fn restore(&self, hive_id: SharedId, entry: HiveEntry) -> Result<(), ClusterError> {
		let mut members = self.members.write()?;
		let claimed = Arc::clone(&entry.signer);
		if members.admits_signer(hive_id.as_ref(), &claimed) {
			members.insert(hive_id, entry);
		}

		Ok(())
	}

	/// The signer bound to `hive_id` at registration, if any.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	pub fn signer_for(&self, hive_id: impl AsRef<[u8]>) -> Result<Option<Arc<SignerIdentifier>>, ClusterError> {
		let hive_id = hive_id.as_ref();
		let members = self.members.read()?;
		Ok(members.signer_for(hive_id))
	}

	/// The registration of the hive at `hive_id`, if one is held.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	pub(crate) fn entry(&self, hive_id: impl AsRef<[u8]>) -> Result<Option<HiveEntry>, ClusterError> {
		let hive_id = hive_id.as_ref();
		let members = self.members.read()?;
		Ok(members.entry(hive_id))
	}

	/// Whether `claimed` is the signer bound to `hive_id` at registration.
	///
	/// An unregistered hive answers `false`, unlike [`Members::admits_signer`],
	/// which answers `true` for a free id. An update names a hive that holds a
	/// registration, so a claim on an id that nobody holds is unattributable
	/// (CWE-639).
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	fn binds_signer(&self, hive_id: impl AsRef<[u8]>, claimed: &SignerIdentifier) -> Result<bool, ClusterError> {
		let hive_id = hive_id.as_ref();
		let bound = self.signer_for(hive_id)?;
		Ok(bound.is_some_and(|signer| signer.as_ref() == claimed))
	}

	/// Unregisters a hive and returns the entry it held.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	fn unregister(&self, hive_id: impl AsRef<[u8]>) -> Result<Option<HiveEntry>, ClusterError> {
		let hive_id = hive_id.as_ref();
		Ok(self.members.write()?.remove(hive_id))
	}

	/// Counts one more heartbeat failure for a registered hive and returns the
	/// new count, or `None` for a hive that holds no entry.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	fn increment_member_failure(&self, hive_id: impl AsRef<[u8]>) -> Result<Option<u32>, ClusterError> {
		let hive_id = hive_id.as_ref();
		Ok(self.members.write()?.increment_member_failure(hive_id))
	}

	/// Records a live heartbeat. It renews the lease on the registry's clock,
	/// stores the utilization, and clears the failure count.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	fn touch(&self, hive_id: impl AsRef<[u8]>, utilization: BasisPoints) -> Result<(), ClusterError> {
		let hive_id = hive_id.as_ref();
		let now = self.clock.monotonic();
		self.members.write()?.touch(hive_id, utilization, now);
		Ok(())
	}

	/// Evicts every hive whose lease is silent for longer than the timeout.
	///
	/// Returns the evicted entries, so a caller can retire the state that
	/// depends on each hive, such as its servlet routes.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	fn evict_stale(&self) -> Result<Vec<HiveEntry>, ClusterError> {
		let now = self.clock.monotonic();
		let mut members = self.members.write()?;

		let stale_ids = members.stale(now, self.timeout);
		let evicted = stale_ids.iter().filter_map(|id| members.remove(id.as_ref())).collect();
		Ok(evicted)
	}

	/// A snapshot of every registered hive.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	pub fn all_hives(&self) -> Result<Vec<HiveEntry>, ClusterError> {
		let members = self.members.read()?;
		Ok(members.all())
	}

	/// The number of registered hives.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	pub fn len(&self) -> Result<usize, ClusterError> {
		let members = self.members.read()?;
		Ok(members.len())
	}

	/// Whether no hive is registered.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	pub fn is_empty(&self) -> Result<bool, ClusterError> {
		Ok(self.len()? == 0)
	}
}

/// What one counted heartbeat failure does to the membership of its hive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureCount {
	/// The failure counted, and the hive stays below the bound with this
	/// many failures.
	Counted(u32),
	/// The failure reached the bound, so the hive left with its routes.
	/// `remaining` is the count of hives in the registry after the retire.
	Retired { remaining: usize },
	/// The hive holds no entry, so the failure counts against no member and
	/// retires none.
	Unregistered,
}

/// What one heartbeat answer does to the membership of its hive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BeatOutcome {
	/// The hive answered alive, so its lease renewed and its count cleared.
	Live,
	/// The hive answered dead or refused, so the beat counted one failure.
	Failed {
		/// The hive's status, or the status that a dial fault forwards as.
		status: TransitStatus,
		/// What the counted failure did to the membership.
		failures: FailureCount,
	},
}

/// One hive that a lease sweep retired, beside the count of hives in the
/// registry after its retire.
#[derive(Debug, Clone)]
pub(crate) struct RetiredHive {
	/// The entry the hive held.
	pub(crate) entry: HiveEntry,
	/// The count of hives in the registry after this hive left.
	pub(crate) remaining: usize,
}

/// The two registries one hive's membership spans.
///
/// A hive's entry is in [`HiveRegistry`] and its servlet routes are in
/// [`ServletRegistry`]. The pair enters and leaves together, so admission and
/// retirement are operations here, not a sequence each caller repeats.
/// Retiring the entry alone would leave routes to a retired hive.
pub(crate) struct ColonyMembership<'a> {
	hives: &'a HiveRegistry,
	servlets: &'a ServletRegistry,
	/// Every operation here holds this lock, so the pair moves as one step
	/// even though each registry takes its own lock.
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
	/// The guarded value is `()`, so a poisoned lock carries no damaged state,
	/// and the guard recovers rather than refuse the caller.
	fn hold_admission(&self) -> MutexGuard<'_, ()> {
		self.admission.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Admits one hive with the servlet slate it registered, and returns the
	/// count of hives in the registry after the install.
	///
	/// A slate that fails to install rolls the hive entry back, so a
	/// refused registration leaves no half of it in either registry. The
	/// count reads under the same admission hold as the install, so no other
	/// membership move lands between them.
	///
	/// # Errors
	///
	/// - [`ClusterError::SignerMismatch`] -- a different signer holds this hive id.
	/// - [`ClusterError::ServletNotOwned`] -- the slate claims an address another owner holds.
	/// - [`ClusterError::LockPoisoned`] -- either registry is poisoned.
	pub(crate) fn admit(
		&self,
		request: RegisterHiveRequest,
		signer: Arc<SignerIdentifier>,
		slate: HiveSlate,
	) -> Result<usize, ClusterError> {
		let hive_addr: SharedId = Arc::from(request.hive_addr.as_slice());
		let _admission = self.hold_admission();

		let displaced = self.hives.register(request, signer)?;
		let Err(refused) = self.servlets.reconcile_by_hive(slate) else {
			return self.hives.len();
		};

		// A re-registration rolls back to the entry it replaced, so a hive
		// that served before this request arrived continues to serve.
		match displaced {
			Some(previous) => self.hives.restore(hive_addr, previous)?,
			None => self.drop_membership(&hive_addr)?,
		}

		Err(refused)
	}

	/// Applies one hive's servlet address delta under its signer bind.
	///
	/// The signer check and the route write share the admission hold, so a
	/// concurrent retirement cannot have its dropped routes reinstalled behind
	/// it (CWE-362, CWE-367).
	///
	/// # Errors
	///
	/// - [`ClusterError::SignerMismatch`] -- `signer` is not the signer bound at registration.
	/// - [`ClusterError::ServletNotOwned`] -- an address belongs to another owner.
	/// - [`ClusterError::ServletNotFound`] -- a removal names an absent address.
	/// - [`ClusterError::LockPoisoned`] -- either registry is poisoned.
	pub(crate) fn update_addresses(
		&self,
		signer: &SignerIdentifier,
		added: HiveSlate,
		removed: &[&[u8]],
	) -> Result<(), ClusterError> {
		let _admission = self.hold_admission();

		if !self.hives.binds_signer(added.hive_id(), signer)? {
			return Err(ClusterError::SignerMismatch);
		}

		self.servlets.apply_address_update(added, removed)
	}

	/// Settles one heartbeat answer of the hive at `hive_addr`.
	///
	/// - A live answer renews the lease, stores the utilization it carries, and clears the failure count.
	/// - A dead or refused answer counts one failure, and the failure that
	///   reaches `max_failures` retires the hive with every route it owned.
	///
	/// The lease or the count, the retire, and the read of the remaining hives
	/// hold one admission, so a retire's count names the registry it left.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- either registry is poisoned.
	pub(crate) fn settle_beat(
		&self,
		hive_addr: impl AsRef<[u8]>,
		answer: Result<BasisPoints, TransitStatus>,
		max_failures: u32,
	) -> Result<BeatOutcome, ClusterError> {
		let hive_addr = hive_addr.as_ref();
		let _admission = self.hold_admission();

		let outcome = match answer {
			Ok(utilization) => {
				self.hives.touch(hive_addr, utilization)?;
				BeatOutcome::Live
			}
			Err(status) => {
				let failures = self.count_failure(hive_addr, max_failures)?;
				BeatOutcome::Failed { status, failures }
			}
		};

		Ok(outcome)
	}

	/// Counts one heartbeat failure for the hive at `hive_addr`, for a caller
	/// that already holds `admission`, and retires the hive with every route
	/// it owned once its count reaches `max_failures`.
	fn count_failure(&self, hive_addr: impl AsRef<[u8]>, max_failures: u32) -> Result<FailureCount, ClusterError> {
		let hive_addr = hive_addr.as_ref();

		let Some(failures) = self.hives.increment_member_failure(hive_addr)? else {
			return Ok(FailureCount::Unregistered);
		};
		if failures < max_failures {
			return Ok(FailureCount::Counted(failures));
		}

		self.drop_membership(hive_addr)?;

		let remaining = self.hives.len()?;
		Ok(FailureCount::Retired { remaining })
	}

	/// Retires one hive for a caller that already holds `admission`.
	fn drop_membership(&self, hive_addr: impl AsRef<[u8]>) -> Result<(), ClusterError> {
		let hive_addr = hive_addr.as_ref();

		self.hives.unregister(hive_addr)?;
		self.servlets.remove_by_hive(hive_addr)?;

		Ok(())
	}

	/// Retires every hive whose lease expired, and returns each one that left
	/// beside the count of hives its retire left.
	///
	/// The sweep evicts its hives in one write, in the order it returns them,
	/// so each retire counts the hives that outlast the sweep plus the stale
	/// hives after it in that order. The last count names the registry that the
	/// whole sweep left.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- either registry is poisoned.
	pub(crate) fn retire_stale(&self) -> Result<Vec<RetiredHive>, ClusterError> {
		let _admission = self.hold_admission();

		let stale = self.hives.evict_stale()?;
		for entry in &stale {
			self.servlets.remove_by_hive(&entry.address)?;
		}

		let outlasting = self.hives.len()?;
		let swept = stale.len();
		let retired = stale.into_iter().enumerate().map(|(position, entry)| {
			let following = swept.saturating_sub(position).saturating_sub(1);
			RetiredHive { entry, remaining: outlasting.saturating_add(following) }
		});

		Ok(retired.collect())
	}
}

#[cfg(test)]
mod tests {
	use core::mem::discriminant;
	use core::str::from_utf8;

	use super::*;
	use crate::clock::ManualClock;
	use crate::colony::cluster::ClusterConfig;
	use crate::colony::protocol::ServletInfo;
	use crate::colony::urn::ColonyNamespace;
	use crate::der::asn1::OctetString;
	use crate::tb_cases;
	use crate::testing::fixtures::TestClock;
	use crate::testing::TestResult;
	use crate::x509::ext::pkix::SubjectKeyIdentifier;

	/// A hive registry whose lease is `ttl`, beside the manual clock it reads.
	fn hive_registry_on(ttl: Duration) -> (HiveRegistry, Arc<ManualClock>) {
		let clock = TestClock::manual();
		(HiveRegistry::new(ttl, TestClock::erased(&clock)), clock)
	}

	/// A hive registry with the default fixture lease, on a manual clock.
	fn hive_registry() -> HiveRegistry {
		hive_registry_on(Duration::from_secs(15)).0
	}

	/// A signer named by the subject key identifier `id`.
	fn signer_named(id: &[u8]) -> Arc<SignerIdentifier> {
		let key_id = OctetString::new(id).expect("a fixture key identifier fits an OCTET STRING");
		Arc::new(SignerIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(key_id)))
	}

	/// The signer every fixture registration binds. Registration always
	/// names one, so the tests name one too.
	fn test_signer() -> Arc<SignerIdentifier> {
		signer_named(b"test-signer")
	}

	/// A registration of `servlets` at `addr`, whose locators each name that
	/// same address, as a hive advertises its own instances.
	fn request(addr: impl AsRef<[u8]>, servlets: &[&str]) -> RegisterHiveRequest {
		let addr = addr.as_ref();
		let locator = from_utf8(addr).expect("fixture addresses are UTF-8");
		let servlet_at = |servlet: &&str| ServletInfo {
			servlet_id: ColonyNamespace::instance_fixture(servlet, locator),
			address: addr.to_vec(),
			signer: ServletInfo::fixture_signer(),
		};

		let servlet_addresses = servlets.iter().map(servlet_at).collect();
		RegisterHiveRequest { hive_addr: addr.to_vec(), metadata: None, servlet_addresses }
	}

	/// One local route for `hive_addr`, the shape a registration installs.
	fn slate(hive_addr: &SharedId, servlet: &str) -> HiveSlate {
		let servlets = request(hive_addr, &[servlet]).servlet_addresses;
		let slate = ClusterConfig::fixture().servlet_slate(&servlets, hive_addr);
		slate.expect("fixture locators name their own address")
	}

	/// The pair of registries one gateway serves, with the admission lock
	/// that binds them, and the manual clock of its hive lease.
	struct Colony {
		hives: HiveRegistry,
		servlets: ServletRegistry,
		admission: Mutex<()>,
		clock: Arc<ManualClock>,
	}

	impl Colony {
		/// The registries of a gateway under the default fixture lease.
		fn new() -> Self {
			Self::with_lease(Duration::from_secs(15))
		}

		/// The registries of a gateway whose hive lease is `ttl`.
		fn with_lease(ttl: Duration) -> Self {
			let (hives, clock) = hive_registry_on(ttl);
			Self { hives, servlets: ServletRegistry::fixture(), admission: Mutex::new(()), clock }
		}

		fn membership(&self) -> ColonyMembership<'_> {
			ColonyMembership::new(&self.hives, &self.servlets, &self.admission)
		}
	}

	/// Admits the hive at `addr` into `colony` with one route of `servlet`.
	fn admit(colony: &Colony, addr: &[u8], servlet: &str) -> Result<(), ClusterError> {
		let hive_addr: SharedId = Arc::from(addr);
		let membership = colony.membership();
		let admitted = membership.admit(request(addr, &[servlet]), test_signer(), slate(&hive_addr, servlet));
		admitted.map(drop)
	}

	/// Admits a hive at each of `addrs` into `colony`, each with one route.
	fn admit_hives(colony: &Colony, addrs: &[&[u8]]) {
		let admitted = addrs.iter().try_for_each(|addr| admit(colony, addr, "ping"));
		admitted.expect("a fresh colony admits each fixture hive");
	}

	/// The status of a beat that the hive refused.
	const REFUSED: TransitStatus = TransitStatus::Unavailable;

	/// The outcome of a refused beat whose failure did what `failures` names.
	fn refused_beat(failures: FailureCount) -> BeatOutcome {
		BeatOutcome::Failed { status: REFUSED, failures }
	}

	/// A hive whose beats fail `max_failures` times in a row leaves the
	/// registry with every route it owned.
	#[test]
	fn a_hive_whose_beats_fail_max_failures_times_leaves_with_its_routes() -> TestResult {
		let colony = Colony::new();
		admit_hives(&colony, &[b"hive1"]);

		let membership = colony.membership();
		membership.settle_beat(b"hive1", Err(REFUSED), 2)?;
		membership.settle_beat(b"hive1", Err(REFUSED), 2)?;

		assert_eq!((colony.hives.len()?, colony.servlets.len()?), (0, 0));
		Ok(())
	}

	// A failure below the bound counts and keeps the hive. The failure that
	// reaches it retires the hive, and names the hives that the retire left.
	// A failure of a hive the registry does not hold retires none.
	tb_cases! {
		fn a_counted_failure(
			(beaten, max_failures, expected, hives_after): (&[u8], u32, FailureCount, usize)
		) -> TestResult {
			let colony = Colony::new();
			admit_hives(&colony, &[b"hive1", b"hive2"]);

			let settled = colony.membership().settle_beat(beaten, Err(REFUSED), max_failures)?;

			assert_eq!((settled, colony.hives.len()?), (refused_beat(expected), hives_after));
			Ok(())
		}
		cases {
			below_the_bound_counts => (b"hive1", 2, FailureCount::Counted(1), 2),
			at_the_bound_retires => (b"hive1", 1, FailureCount::Retired { remaining: 1 }, 1),
			of_an_unregistered_hive_retires_none => (b"hive9", 0, FailureCount::Unregistered, 2),
		}
	}

	/// A live beat stores the utilization that the hive reported.
	#[test]
	fn a_live_beat_records_the_utilization_it_reported() -> TestResult {
		let colony = Colony::new();
		admit_hives(&colony, &[b"hive1"]);

		colony.membership().settle_beat(b"hive1", Ok(crate::bps!(5000)), 2)?;

		let hives = colony.hives.all_hives()?.into_iter();
		let utilization: Vec<BasisPoints> = hives.map(|hive| hive.utilization).collect();
		assert_eq!(utilization, [crate::bps!(5000)]);
		Ok(())
	}

	/// A live beat clears the failures counted before it, so the next refused
	/// beat counts from one.
	#[test]
	fn a_live_beat_clears_the_failures_counted_before_it() -> TestResult {
		let colony = Colony::new();
		admit_hives(&colony, &[b"hive1"]);

		let membership = colony.membership();
		membership.settle_beat(b"hive1", Err(REFUSED), 3)?;
		membership.settle_beat(b"hive1", Ok(BasisPoints::default()), 3)?;

		let settled = membership.settle_beat(b"hive1", Err(REFUSED), 3)?;
		assert_eq!(settled, refused_beat(FailureCount::Counted(1)));
		Ok(())
	}

	/// A registered hive lists at the address it registered from.
	#[test]
	fn a_registered_hive_lists_at_its_address() -> TestResult {
		let registry = hive_registry();
		registry.register(request(b"127.0.0.1:8080", &["ping", "calc"]), test_signer())?;

		let hives = registry.all_hives()?.into_iter();
		let addresses: Vec<SharedId> = hives.map(|hive| hive.address).collect();
		assert_eq!(addresses, [SharedId::from(b"127.0.0.1:8080".as_slice())]);
		Ok(())
	}

	/// An unregistered hive leaves the registry, and the call returns the
	/// entry it removed.
	#[test]
	fn an_unregistered_hive_leaves_the_registry() -> TestResult {
		let registry = hive_registry();
		registry.register(request(b"127.0.0.1:8080", &["ping"]), test_signer())?;

		let removed = registry.unregister(b"127.0.0.1:8080")?.map(|hive| hive.address);

		let left = SharedId::from(b"127.0.0.1:8080".as_slice());
		assert_eq!((removed, registry.len()?), (Some(left), 0));
		Ok(())
	}

	/// `all_hives` lists every registered hive with the metadata it
	/// registered, in address order.
	#[test]
	fn all_hives_lists_every_registered_hive() -> TestResult {
		let registry = hive_registry();
		let mut described = request(b"hive2", &["calc"]);
		described.metadata = Some(b"metadata".to_vec());
		registry.register(request(b"hive1", &["ping"]), test_signer())?;
		registry.register(described, test_signer())?;

		let hives = registry.all_hives()?.into_iter();
		let mut listed: Vec<(SharedId, Option<Arc<[u8]>>)> = hives.map(|hive| (hive.address, hive.metadata)).collect();
		listed.sort();

		let expected = [
			(SharedId::from(b"hive1".as_slice()), None),
			(SharedId::from(b"hive2".as_slice()), Some(Arc::from(b"metadata".as_slice()))),
		];
		assert_eq!(listed, expected);
		Ok(())
	}

	/// The hives that one lease sweep retired, in the sweep's order, each
	/// with the count that its retire left.
	#[test]
	fn a_lease_sweep_counts_down_the_hives_each_retire_leaves() -> TestResult {
		let colony = Colony::with_lease(Duration::from_millis(10));
		colony.hives.register(request(b"hive1", &["ping"]), test_signer())?;
		colony.hives.register(request(b"hive2", &["ping"]), test_signer())?;
		colony.clock.advance(Duration::from_secs(1));

		let retired = colony.membership().retire_stale()?;
		let remaining: Vec<usize> = retired.iter().map(|hive| hive.remaining).collect();
		assert_eq!(remaining, [1, 0]);
		Ok(())
	}

	// The test judges whether a lease outlives its ttl after it moves the
	// registry's clock, rather than after it waits. A lease exactly at the ttl
	// stays live, so the boundary row pins `>` against `>=`.
	tb_cases! {
		fn a_lease_evicts_only_past_its_ttl((ttl, evicted_len, remaining_len): (Duration, usize, usize)) -> TestResult {
			let (registry, clock) = hive_registry_on(ttl);
			registry.register(request(b"hive1", &["ping"]), test_signer())?;

			clock.advance(Duration::from_secs(1));

			let evicted = registry.evict_stale()?;
			assert_eq!((evicted.len(), registry.len()?), (evicted_len, remaining_len));
			Ok(())
		}
		cases {
			expires_immediately => (Duration::ZERO, 1, 0),
			at_the_ttl => (Duration::from_secs(1), 0, 1),
			outlives_the_probe => (Duration::from_secs(3600), 0, 1),
		}
	}

	/// A second claim to one hive id: the signer that claims it first, the
	/// signer that claims it second, and the refusal of the second claim.
	type Rebind = (&'static [u8], &'static [u8], Option<ClusterError>);

	// A hive id stays bound to the signer that first claimed it, and the
	// signer bound first survives the attempt. The type requires a signer on
	// every registration, so the rows cover a bound hive alone.
	tb_cases! {
		fn a_hive_id_stays_bound_to_its_first_signer((first, second, refusal): Rebind) -> TestResult {
			let registry = hive_registry();
			registry.register(request(b"hive1", &["ping"]), signer_named(first))?;

			let result = registry.register(request(b"hive1", &["ping"]), signer_named(second));

			let bound = registry.signer_for(b"hive1")?;
			let expected = (refusal.as_ref().map(discriminant), Some(signer_named(first)));
			assert_eq!((ClusterError::variant_of(&result), bound), expected);
			Ok(())
		}
		cases {
			refuses_a_different_signer => (b"sid-a", b"sid-b", Some(ClusterError::SignerMismatch)),
			admits_the_bound_signer => (b"sid-a", b"sid-a", None),
		}
	}

	/// What one race between two signers for one hive id left behind: how
	/// many registrations the registry accepted, and which signer it bound.
	struct RaceOutcome {
		accepted: usize,
		bound: Option<Arc<SignerIdentifier>>,
	}

	/// Races `first` and `second` to claim `contested` on a fresh registry.
	fn race_to_claim(
		contested: &'static [u8],
		first: &Arc<SignerIdentifier>,
		second: &Arc<SignerIdentifier>,
	) -> RaceOutcome {
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

	/// Runs [`race_to_claim`] `rounds` times and answers how many races bound
	/// exactly one of the two signers.
	fn races_binding_one_signer(rounds: usize) -> usize {
		let first = signer_named(b"signer-one");
		let second = signer_named(b"signer-two");
		let names_a_racer = |bound: &Option<Arc<SignerIdentifier>>| {
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
		servlets.poison_routes();
		servlets.local_servlets().expect_err("a poisoned route lock refuses each read");
	}

	/// A re-registration whose slate will not install must leave the
	/// registration it displaced in service.
	#[test]
	fn a_refused_reregistration_restores_the_hive_it_displaced() -> TestResult {
		let colony = Colony::new();
		admit_hives(&colony, &[b"hive-a"]);
		poison_routes(&colony.servlets);

		let refused = admit(&colony, b"hive-a", "echo");
		let bound = colony.hives.signer_for(b"hive-a")?;
		assert!(matches!(refused, Err(ClusterError::LockPoisoned)));
		assert_eq!((colony.hives.len()?, bound), (1, Some(test_signer())));
		Ok(())
	}

	/// A first registration whose slate will not install must leave no half
	/// of it in either registry.
	#[test]
	fn a_refused_first_registration_leaves_no_half() -> TestResult {
		let colony = Colony::new();
		poison_routes(&colony.servlets);

		let refused = admit(&colony, b"hive-a", "echo");
		assert!(matches!(refused, Err(ClusterError::LockPoisoned)));
		assert_eq!(colony.hives.len()?, 0);
		Ok(())
	}
}
