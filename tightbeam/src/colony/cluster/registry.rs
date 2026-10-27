//! The hive registry holds membership and utilization. Servlet routes live
//! in [`ServletRegistry`], and the colony membership view moves a hive
//! through both registries as one step.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Duration;

use super::error::ClusterError;
use crate::cms::signed_data::SignerIdentifier;
use crate::colony::bound_dial::{BoundDial, ExpectedSigner};
use crate::colony::cluster::servlet_registry::{DialTarget, HiveSlate, ServletRegistry};
use crate::colony::protocol::RegisterHiveRequest;
use crate::utils::time::{Clock, MonotonicInstant};
use crate::utils::BasisPoints;

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

	/// Records a heartbeat seen at `now`, and answers whether the hive holds a
	/// registration to record it against.
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
		self.increment_member_failure(hive_id).unwrap_or(0)
	}

	/// Counts one failure of a registered hive and returns its new count, or
	/// `None` for a hive that holds no entry.
	fn increment_member_failure(&mut self, hive_id: impl AsRef<[u8]>) -> Option<u32> {
		let entry = self.hives.get_mut(hive_id.as_ref())?;
		entry.failure_count = entry.failure_count.saturating_add(1);
		Some(entry.failure_count)
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
	pub(crate) fn register(
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
	pub(crate) fn restore(&self, hive_id: SharedId, entry: HiveEntry) -> Result<(), ClusterError> {
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
	pub(crate) fn binds_signer(
		&self,
		hive_id: impl AsRef<[u8]>,
		claimed: &SignerIdentifier,
	) -> Result<bool, ClusterError> {
		let hive_id = hive_id.as_ref();
		let bound = self.signer_for(hive_id)?;
		Ok(bound.is_some_and(|signer| signer.as_ref() == claimed))
	}

	/// Unregisters a hive and returns the entry it held.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	pub(crate) fn unregister(&self, hive_id: impl AsRef<[u8]>) -> Result<Option<HiveEntry>, ClusterError> {
		let hive_id = hive_id.as_ref();
		Ok(self.members.write()?.remove(hive_id))
	}

	/// Records the utilization a heartbeat reported, and answers whether the
	/// hive holds a registration to record it against.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
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
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	pub fn increment_failure(&self, hive_id: impl AsRef<[u8]>) -> Result<u32, ClusterError> {
		let hive_id = hive_id.as_ref();
		Ok(self.members.write()?.increment_failure(hive_id))
	}

	/// Counts one more heartbeat failure for a registered hive and returns the
	/// new count, or `None` for a hive that holds no entry.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	pub(crate) fn increment_member_failure(&self, hive_id: impl AsRef<[u8]>) -> Result<Option<u32>, ClusterError> {
		let hive_id = hive_id.as_ref();
		Ok(self.members.write()?.increment_member_failure(hive_id))
	}

	/// Clears a hive's heartbeat failure count.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	pub fn reset_failure(&self, hive_id: impl AsRef<[u8]>) -> Result<(), ClusterError> {
		let hive_id = hive_id.as_ref();
		self.members.write()?.reset_failure(hive_id);
		Ok(())
	}

	/// Records a live heartbeat. It renews the lease on the registry's clock,
	/// stores the utilization, and clears the failure count.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the member table is poisoned.
	pub fn touch(&self, hive_id: impl AsRef<[u8]>, utilization: BasisPoints) -> Result<(), ClusterError> {
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
	pub(crate) fn evict_stale(&self) -> Result<Vec<HiveEntry>, ClusterError> {
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
	/// The guarded value is `()`, so a poisoned lock carries no damaged
	/// state and this method recovers the guard rather than refuse the
	/// caller.
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

	/// Counts one heartbeat failure for the hive at `hive_addr`, and retires it
	/// with every route it owned once its count reaches `max_failures`.
	///
	/// The count, the retire, and the read of the remaining hives hold one
	/// admission, so a retire's count names the registry it left.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- either registry is poisoned.
	pub(crate) fn count_failure(
		&self,
		hive_addr: impl AsRef<[u8]>,
		max_failures: u32,
	) -> Result<FailureCount, ClusterError> {
		let hive_addr = hive_addr.as_ref();
		let _admission = self.hold_admission();

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
	use core::str::from_utf8;

	use super::*;
	use crate::colony::cluster::servlet_registry::PheromoneConfig;
	use crate::colony::cluster::{CertificateSpec, ClusterConfig, ClusterTlsConfig};
	use crate::colony::protocol::ServletInfo;
	use crate::colony::urn::ColonyNamespace;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::der::asn1::OctetString;
	use crate::tb_cases;
	use crate::testing::{TestCertificate, TestKey};
	use crate::utils::time::ManualClock;
	use crate::x509::ext::pkix::SubjectKeyIdentifier;

	/// A clock that moves only when the test advances it.
	fn manual_clock() -> Arc<dyn Clock> {
		Arc::new(ManualClock::default())
	}

	/// A hive registry with the default fixture lease, on a manual clock.
	fn hive_registry() -> HiveRegistry {
		HiveRegistry::new(Duration::from_secs(15), manual_clock())
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

	/// A config with every default, which the fixtures build their slates
	/// through.
	fn test_config() -> ClusterConfig {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let tls = ClusterTlsConfig::new(
			CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key))),
			Arc::new(Secp256k1KeyProvider::from(key)),
		)
		.expect("the test certificate must decode");

		ClusterConfig::new(tls)
	}

	/// A registration of `servlets` at `addr`, whose locators each name that
	/// same address, as a hive advertises its own instances.
	fn request(addr: impl AsRef<[u8]>, servlets: &[&str]) -> RegisterHiveRequest {
		let addr = addr.as_ref();
		let locator = from_utf8(addr).expect("fixture addresses are UTF-8");
		let namespace = ColonyNamespace::default();
		RegisterHiveRequest {
			hive_addr: addr.to_vec(),
			metadata: None,
			servlet_addresses: servlets
				.iter()
				.map(|s| ServletInfo {
					servlet_id: namespace
						.servlet(s)
						.and_then(|servlet_type| servlet_type.servlet_instance(locator))
						.expect("test names satisfy the mint grammar"),
					address: addr.to_vec(),
					signer: ServletInfo::fixture_signer(),
				})
				.collect(),
		}
	}

	/// One local route for `hive_addr`, the shape a registration installs.
	fn slate(hive_addr: &SharedId, servlet: &str) -> HiveSlate {
		let servlets = request(hive_addr, &[servlet]).servlet_addresses;
		test_config()
			.servlet_slate(&servlets, hive_addr)
			.expect("fixture locators name their own address")
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

		let counted = colony.membership().count_failure(&hive_addr, 1)?;
		assert_eq!(counted, FailureCount::Retired { remaining: 0 });
		assert_eq!(colony.hives.len()?, 0);
		assert_eq!(colony.servlets.len()?, 0);
		Ok(())
	}

	/// Admits a hive at each of `addrs` into `colony`, each with one route.
	fn admit_hives(colony: &Colony, addrs: &[&[u8]]) -> Result<(), ClusterError> {
		addrs.iter().try_for_each(|addr| {
			let hive_addr: SharedId = Arc::from(*addr);
			let membership = colony.membership();
			let admitted = membership.admit(request(addr, &["ping"]), test_signer(), slate(&hive_addr, "ping"));
			admitted.map(drop)
		})
	}

	// A failure below the bound counts and keeps the hive. The failure that
	// reaches it retires the hive, and names the hives that the retire left.
	tb_cases! {
		fn a_counted_failure((max_failures, expected, hives_after): (u32, FailureCount, usize)) -> Result<(), ClusterError> {
			let colony = Colony::new();
			admit_hives(&colony, &[b"hive1", b"hive2"])?;

			let counted = colony.membership().count_failure(b"hive1", max_failures)?;
			assert_eq!(counted, expected);
			assert_eq!(colony.hives.len()?, hives_after);
			Ok(())
		}
		cases {
			below_the_bound_counts => (2, FailureCount::Counted(1), 2),
			at_the_bound_retires => (1, FailureCount::Retired { remaining: 1 }, 1),
		}
	}

	#[test]
	fn a_failure_of_an_unregistered_hive_retires_none() -> Result<(), ClusterError> {
		let colony = Colony::new();
		admit_hives(&colony, &[b"hive1"])?;

		let counted = colony.membership().count_failure(b"hive9", 0)?;
		assert_eq!(counted, FailureCount::Unregistered);
		assert_eq!(colony.hives.len()?, 1);
		Ok(())
	}

	/// The hives that one lease sweep retired, in the sweep's order, each
	/// with the count that its retire left.
	#[test]
	fn a_lease_sweep_counts_down_the_hives_each_retire_leaves() -> Result<(), ClusterError> {
		let clock = Arc::new(ManualClock::default());
		let hives = HiveRegistry::new(Duration::from_millis(10), Arc::clone(&clock) as Arc<dyn Clock>);
		let servlets = ServletRegistry::new(PheromoneConfig::default(), manual_clock());
		let admission = Mutex::new(());
		let membership = ColonyMembership::new(&hives, &servlets, &admission);
		hives.register(request(b"hive1", &["ping"]), test_signer())?;
		hives.register(request(b"hive2", &["ping"]), test_signer())?;

		clock.advance(Duration::from_secs(1));

		let retired = membership.retire_stale()?;
		let remaining: Vec<usize> = retired.iter().map(|hive| hive.remaining).collect();
		assert_eq!(remaining, [1, 0]);
		Ok(())
	}

	// The test judges whether a lease outlives its ttl after it moves the
	// registry's clock, rather than after it waits. A lease exactly at the ttl
	// stays live, so the boundary row pins `>` against `>=`.
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

	// A hive id stays bound to the signer that first claimed it. The type
	// requires a signer on every registration, so the rows cover a bound hive
	// alone.
	tb_cases! {
		fn register_signer_rebind(case: SignerRebindCase) -> Result<(), ClusterError> {
			let registry = HiveRegistry::new(Duration::from_secs(3600), manual_clock());
			registry.register(request(b"hive1", &["ping"]), signer_named(case.first))?;

			let result = registry.register(request(b"hive1", &["ping"]), signer_named(case.second));
			assert_eq!(result.is_ok(), case.expect_ok);
			if !case.expect_ok {
				assert!(matches!(result, Err(ClusterError::SignerMismatch)));
			}

			// The signer bound first always survives the attempt.
			let bound = registry.signer_for(b"hive1")?;
			assert_eq!(bound, Some(signer_named(case.first)));

			Ok(())
		}
		cases {
			refuses_a_different_signer => SignerRebindCase { first: b"sid-a", second: b"sid-b", expect_ok: false },
			admits_the_bound_signer => SignerRebindCase { first: b"sid-a", second: b"sid-a", expect_ok: true },
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
		assert!(servlets.local_servlets().is_err());
	}

	/// A re-registration whose slate will not install must leave the
	/// registration it displaced in service.
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

	/// A first registration whose slate will not install must leave no half
	/// of it in either registry.
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
