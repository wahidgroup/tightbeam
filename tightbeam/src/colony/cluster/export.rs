//! The export boundary for federated peers.
//!
//! A gateway serves first-party callers (its own clients and hives) and
//! external peer gateways from other organizations. The export boundary
//! decides which servlet types peers may reach.
//!
//! # Planes
//!
//! - **Discoverability**: the advertise beat filters the slate through
//!   [`PeerConfig::exported_types`](super::PeerConfig), so peers never
//!   learn unexported types from ads or slate rumors.
//! - **Enforcement**: the built-in allowlist, any configured
//!   [`ExportGrant`], and any configured [`ExportGate`] evaluate unary
//!   work and routed stream opens. The gateway still refuses a peer that
//!   guesses a type name, unless a grant opens that target.
//!
//! # Allowlist
//!
//! The built-in allowlist is fail-closed when an export list is set. The
//! rules apply in order:
//!
//! 1. An exported target passes for everyone.
//! 2. An unexported relayed request is refused. The hop marker is
//!    unauthenticated defense in depth, and the identity rule below holds
//!    against a forged budget.
//! 3. An unexported origin request passes only for a first-party session:
//!    not relayed, a member of `hive_trust`, and not of `peer_trust`.
//! 4. Any other unexported request is refused.
//!
//! A grant that matches may still allow a refused target before deny gates run.
//!
//! # Grants
//!
//! [`ExportGrant`] opens one unexported target to selected caller identities.
//! Configure grants through [`ClusterConfigBuilder::with_export_grant`]. A
//! target passes when it is exported, granted, or a first-party origin, and a
//! deny gate still overrides a grant.
//!
//! # Custom gates
//!
//! [`ExportGate`] adds per-identity rules keyed on [`SessionContext`].
//! Configure gates through [`ClusterConfigBuilder::with_export_gate`]. Every
//! gate must pass, so a gate only narrows what the allow sources admit.
//!
//! # Mutual TLS
//!
//! First-party recognition requires mutual TLS. The accept plane stores
//! a session certificate only when
//! [`ClusterTlsConfig::client_authentication`] demands mutual TLS. Under
//! anonymous clients:
//!
//! - Every session is anonymous, so an export list also blocks unexported targets on the origin plane.
//! - With an export list set, the gateway emits a posture warning at startup.
//!
//! # Sources
//!
//! - CWE-285, improper authorization: <https://cwe.mitre.org/data/definitions/285.html>
//!
//! [`ClusterTlsConfig::client_authentication`]: super::ClusterTlsConfig::client_authentication
//! [`ClusterConfigBuilder::with_export_grant`]: super::ClusterConfigBuilder::with_export_grant
//! [`ClusterConfigBuilder::with_export_gate`]: super::ClusterConfigBuilder::with_export_gate

use core::str::from_utf8;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use super::peer::ColonyCertificate;
use super::{ClusterConfig, ClusterError, PeerConfig, SharedId};
use crate::crypto::hash::Digest;
use crate::crypto::x509::store::CertificateTrust;
use crate::crypto::x509::Certificate;
use crate::policy::{SessionContext, TransitStatus};
use crate::urn::Urn;

/// A live export allowlist that discoverability and enforcement share.
///
/// Install it through [`ClusterConfigBuilder::with_export_allowlist`], or a
/// static list through [`ClusterConfigBuilder::with_exported_types`]. `None` on
/// [`PeerConfig::exported_types`](super::PeerConfig) exports every type the
/// gateway serves locally.
///
/// # Planes
///
/// - **Enforcement** calls [`ExportAllowlist::contains`] on each work or
///   stream open, so a mutable list takes effect on the next request.
/// - **Discoverability** calls [`ExportAllowlist::allows_canonical`] per
///   local servlet key on each advertise beat, so the slate tracks the
///   same live membership with no owned key set.
///
/// # Keys
///
/// List entries are servlet type URNs without an instance tail, so their
/// canonical bytes equal the registry's type keys. An entry with an instance
/// tail would answer [`ExportAllowlist::contains`] on that exact target but
/// never match an advertised type key.
///
/// [`ClusterConfigBuilder::with_export_allowlist`]: super::ClusterConfigBuilder::with_export_allowlist
/// [`ClusterConfigBuilder::with_exported_types`]: super::ClusterConfigBuilder::with_exported_types
pub trait ExportAllowlist: Send + Sync {
	/// Whether `target` is on the export list.
	fn contains(&self, target: &Urn<'_>) -> bool;

	/// Whether a canonical registry type key is exported.
	///
	/// The default parses `key` and asks [`ExportAllowlist::contains`], so the
	/// two views agree. A key that fails to parse answers `false`. The built-in
	/// lists override it with a lookup in a cached set that borrows `key`.
	fn allows_canonical(&self, key: &[u8]) -> bool {
		let Ok(canonical) = from_utf8(key) else {
			return false;
		};
		let Ok(target) = canonical.parse::<Urn<'static>>() else {
			return false;
		};

		self.contains(&target)
	}
}

/// A fixed export list installed at config build.
#[derive(Clone, Debug)]
pub struct StaticExportList {
	types: Vec<Urn<'static>>,
	keys: HashSet<Vec<u8>>,
}

impl StaticExportList {
	/// Builds an allowlist from the given servlet type URNs.
	pub fn new(types: impl IntoIterator<Item = Urn<'static>>) -> Self {
		let types: Vec<Urn<'static>> = types.into_iter().collect();
		let keys = types.iter().map(Urn::canonical_bytes).collect();
		Self { types, keys }
	}
}

impl ExportAllowlist for StaticExportList {
	fn contains(&self, target: &Urn<'_>) -> bool {
		self.types.iter().any(|allowed| allowed == target)
	}

	fn allows_canonical(&self, key: &[u8]) -> bool {
		self.keys.contains(key)
	}
}

/// The URN list and its canonical key cache under one lock, so the two views
/// of the membership mutate atomically and agree through every update.
#[derive(Default)]
struct ExportMembership {
	types: Vec<Urn<'static>>,
	keys: HashSet<Vec<u8>>,
}

impl ExportMembership {
	fn new(types: impl IntoIterator<Item = Urn<'static>>) -> Self {
		let types: Vec<Urn<'static>> = types.into_iter().collect();
		let keys = types.iter().map(Urn::canonical_bytes).collect();
		Self { types, keys }
	}
}

/// An interior-mutable export list for tests and fuzz harnesses that run long.
///
/// - Mutations are visible to the next [`ExportAllowlist::contains`] and
///   [`ExportAllowlist::allows_canonical`] call.
/// - A poisoned lock reads as an empty list, so both planes stay fail-closed.
/// - A mutation on a poisoned lock reports [`ClusterError::LockPoisoned`], so
///   the operator learns of the lost change.
#[derive(Default)]
pub struct DynamicExportList {
	membership: RwLock<ExportMembership>,
}

impl DynamicExportList {
	/// Builds a mutable allowlist from the given servlet type URNs.
	pub fn new(types: impl IntoIterator<Item = Urn<'static>>) -> Self {
		Self { membership: RwLock::new(ExportMembership::new(types)) }
	}

	/// Replaces the export membership with `types`.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the list's lock is poisoned.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::{DynamicExportList, ExportAllowlist};
	/// use tightbeam::colony::urn::ColonyNamespace;
	///
	/// let ping = ColonyNamespace::default().servlet("ping")?;
	/// let list = DynamicExportList::default();
	///
	/// list.set([ping.clone()])?;
	/// assert!(list.contains(&ping));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn set(&self, types: impl IntoIterator<Item = Urn<'static>>) -> Result<(), ClusterError> {
		// The membership comes from the caller's iterator before the lock, so
		// the lock guards the swap of a finished value alone.
		let membership = ExportMembership::new(types);

		let mut guard = self.membership.write()?;
		*guard = membership;

		Ok(())
	}

	/// Inserts `target` when the list lacks it.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the list's lock is poisoned.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::{DynamicExportList, ExportAllowlist};
	/// use tightbeam::colony::urn::ColonyNamespace;
	///
	/// let ping = ColonyNamespace::default().servlet("ping")?;
	/// let list = DynamicExportList::default();
	///
	/// list.insert(ping.clone())?;
	/// assert!(list.allows_canonical(&ping.canonical_bytes()));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn insert(&self, target: Urn<'static>) -> Result<(), ClusterError> {
		let mut guard = self.membership.write()?;
		if !guard.types.iter().any(|allowed| allowed == &target) {
			guard.keys.insert(target.canonical_bytes());
			guard.types.push(target);
		}

		Ok(())
	}

	/// Removes every entry equal to `target`.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the list's lock is poisoned.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::{DynamicExportList, ExportAllowlist};
	/// use tightbeam::colony::urn::ColonyNamespace;
	///
	/// let ping = ColonyNamespace::default().servlet("ping")?;
	/// let list = DynamicExportList::new([ping.clone()]);
	///
	/// list.remove(&ping)?;
	/// assert!(!list.contains(&ping));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn remove(&self, target: &Urn<'_>) -> Result<(), ClusterError> {
		let mut guard = self.membership.write()?;

		// The loop collects the keys of the entries it drops, so a stored entry
		// that compares equal under another canonical form still drops its own
		// cached key.
		let mut dropped = Vec::new();
		guard.types.retain(|allowed| {
			if allowed == target {
				dropped.push(allowed.canonical_bytes());
				return false;
			}

			true
		});
		for key in dropped {
			guard.keys.remove(&key);
		}

		Ok(())
	}
}

impl ExportAllowlist for DynamicExportList {
	fn contains(&self, target: &Urn<'_>) -> bool {
		let Ok(guard) = self.membership.read() else {
			return false;
		};
		guard.types.iter().any(|allowed| allowed == target)
	}

	fn allows_canonical(&self, key: &[u8]) -> bool {
		let Ok(guard) = self.membership.read() else {
			return false;
		};
		guard.keys.contains(key)
	}
}

/// A custom export gate for servlet targets that cross the gateway.
///
/// Every configured gate must answer [`TransitStatus::Ok`], so the gates
/// narrow what the allow sources (the exported list, the grants, the
/// first-party origin rule) admit.
///
/// # Call sites
///
/// The gateway evaluates it where the servlet target is known:
///
/// - The unary work arm.
/// - The streaming and duplex open handlers.
pub trait ExportGate: Send + Sync {
	/// Decides whether `session` may reach `target` on this gateway.
	///
	/// - `target`: the servlet type under enforcement.
	/// - `session`: the caller identity facts
	///   ([`SessionContext::peer_certificate`]). A rule reads its peer key when
	///   it asks a [`PeerListGate`](crate::colony::hive::PeerListGate) through
	///   [`GatePolicy::evaluate`](crate::policy::GatePolicy::evaluate).
	/// - `planes`: the two federation trust planes, for a gate that reuses the
	///   first-party classifier ([`TrustPlanes::classify_session`]) beside its
	///   own rules.
	/// - `relayed`: `true` when the request already spent relay budget, so it
	///   entered through a peer gateway.
	fn evaluate(
		&self,
		target: &Urn<'_>,
		session: &SessionContext,
		planes: &TrustPlanes<'_>,
		relayed: bool,
	) -> TransitStatus;
}

/// A positive grant that widens the export boundary for selected callers.
///
/// A grant is one allow source beside the exported list and the first-party
/// origin rule, so it may only widen access to its target. Every
/// [`ExportGate`] still runs afterward, so a deny gate overrides any grant.
///
/// # Subject rule
///
/// The session identity is the adjacent authenticated principal. On a relayed
/// request it is the peer gateway that relayed the request, not the original
/// caller, so a grant that matches a relayed request trusts that relay
/// gateway. A conservative grant tests `!relayed`.
///
/// # Discoverability
///
/// The advertised slate lists exported types alone, because grants are
/// per session and each advertise beat builds one ad that every peer
/// receives. A granted type is a private interface whose URN the grantee
/// learns out of band.
pub trait ExportGrant: Send + Sync {
	/// Whether `session` is positively granted `target` on this gateway.
	///
	/// - `target`: the servlet type under the grant.
	/// - `session`: the identity of the adjacent authenticated caller.
	/// - `relayed`: `true` when the request already spent relay budget.
	fn grants(&self, target: &Urn<'_>, session: &SessionContext, relayed: bool) -> bool;
}

/// The allow source that decided a passed export boundary.
///
/// The boundary returns it only when the full verdict passes, deny gates
/// included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportDecision {
	/// The built-in allowlist allowed the target.
	Allowed,
	/// A positive grant was the allow source that decided.
	Granted,
}

/// Which servlet types a gateway exports to its peers.
///
/// It is the one home of the rule that a gateway with no export list exports
/// every type. The boundary verdict, the advertise filter, and the posture
/// warning each ask it.
#[derive(Clone, Copy)]
pub(crate) struct ExportScope<'a>(Option<&'a dyn ExportAllowlist>);

impl<'a> From<&'a PeerConfig> for ExportScope<'a> {
	fn from(peer: &'a PeerConfig) -> Self {
		Self(peer.exported_types.as_deref())
	}
}

impl ExportScope<'_> {
	/// Whether `target` is exported: every type with no list, or a type the
	/// list contains.
	pub(crate) fn exports(&self, target: &Urn<'_>) -> bool {
		self.0.is_none_or(|list| list.contains(target))
	}

	/// Whether the canonical registry type `key` is exported, by the rule of
	/// [`Self::exports`].
	pub(crate) fn exports_canonical(&self, key: &[u8]) -> bool {
		self.0.is_none_or(|list| list.allows_canonical(key))
	}

	/// Whether the gateway exports every type, because it has no export
	/// list.
	pub(crate) fn is_unbounded(&self) -> bool {
		self.0.is_none()
	}
}

/// The live-configuration view of the export boundary.
///
/// It is a sealed composition that wire handlers derive from
/// [`ClusterConfig`] through [`From`] alone. The unary work arm and the
/// stream open handlers share one core through
/// [`ColonyConfig::evaluate_export_gates`].
///
/// [`ColonyConfig::evaluate_export_gates`]: super::ColonyConfig::evaluate_export_gates
pub(crate) struct ExportPolicy<'a> {
	scope: ExportScope<'a>,
	planes: TrustPlanes<'a>,
	grants: &'a [Arc<dyn ExportGrant>],
	gates: &'a [Arc<dyn ExportGate>],
}

impl<'a> From<&'a ClusterConfig> for ExportPolicy<'a> {
	fn from(config: &'a ClusterConfig) -> Self {
		Self {
			scope: ExportScope::from(&config.peer),
			planes: TrustPlanes::from(&config.tls),
			grants: &config.export_grants,
			gates: &config.export_gates,
		}
	}
}

impl ExportPolicy<'_> {
	/// Decides the boundary verdict on a resolved servlet target, after
	/// [`GatePolicy`](crate::policy::GatePolicy) has evaluated.
	///
	/// The steps run in order:
	///
	/// 1. The built-in allowlist answers.
	/// 2. When it refuses, any configured grant may still allow the target.
	/// 3. Every deny gate then evaluates, so a deny gate overrides a grant. A
	///    gate verdict of [`TransitStatus::Unknown`] normalizes to
	///    [`TransitStatus::Internal`] before it reaches the wire.
	pub(crate) fn verdict(
		&self,
		target: &Urn<'_>,
		session: &SessionContext,
		relayed: bool,
	) -> Result<ExportDecision, TransitStatus> {
		let allowlist = self.allowlist(target, session, relayed);

		let mut decision = ExportDecision::Allowed;
		if allowlist != TransitStatus::Ok {
			if !self.granted(target, session, relayed) {
				return Err(allowlist);
			}

			decision = ExportDecision::Granted;
		}

		for gate in self.gates {
			let status = gate.evaluate(target, session, &self.planes, relayed).normalized_verdict();
			if status != TransitStatus::Ok {
				return Err(status);
			}
		}

		Ok(decision)
	}

	/// The built-in allowlist verdict on a resolved servlet target, by the
	/// rules of the module's Allowlist section. A first-party session is one
	/// that [`TrustPlanes::classify_session`] places by its key.
	///
	/// The export scope reads the live allowlist on each request, so the
	/// enforcement plane and the advertise filter agree. [`Self::verdict`]
	/// applies grants after this step refuses.
	fn allowlist(&self, target: &Urn<'_>, session: &SessionContext, relayed: bool) -> TransitStatus {
		if self.scope.exports(target) {
			return TransitStatus::Ok;
		}
		if relayed {
			return TransitStatus::PermissionDenied;
		}
		if matches!(self.planes.classify_session(session), Party::FirstParty) {
			return TransitStatus::Ok;
		}

		TransitStatus::PermissionDenied
	}

	/// Whether any configured grant allows `session` to reach `target`. The
	/// first match decides, and an empty grant list allows nothing, so the
	/// boundary stays fail-closed.
	fn granted(&self, target: &Urn<'_>, session: &SessionContext, relayed: bool) -> bool {
		self.grants.iter().any(|grant| grant.grants(target, session, relayed))
	}
}

/// Which trust plane a caller certificate belongs to.
///
/// Classification encodes store precedence: peer membership wins over
/// hive membership. A certificate held by both stores is therefore
/// [`Party::Peer`], never [`Party::FirstParty`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Party {
	/// A member of the hive plane and not the peer plane.
	FirstParty,
	/// A member of the peer plane, whatever its hive membership.
	Peer,
	/// The caller is anonymous (`None`), or neither plane trusts it.
	Untrusted,
}

/// The two federation trust planes as one classifier.
///
/// A gateway trusts its own hives on the first-party plane and federated
/// peers on the peer plane. [`TrustPlanes`] borrows both stores as one
/// unit, so the precedence rule ("peer membership wins") lives in one
/// place and a call site cannot transpose the two stores.
///
/// # Fail-closed
///
/// With no hive store, the planes classify nobody as first-party, so the
/// boundary refuses callers it cannot place. Membership is a trust-store
/// lookup of the caller's key, not chain path validation: through
/// [`CertificateTrust::trusts_public_key`] for a certificate, and through
/// [`CertificateTrust::find_by_canonical_key`] for a session.
#[derive(Clone, Copy)]
pub struct TrustPlanes<'a> {
	hive: Option<&'a dyn CertificateTrust>,
	peer: Option<&'a dyn CertificateTrust>,
}

/// The named hive and peer trust-store borrows for [`TrustPlanes::new`].
///
/// The fields are named, so a call site cannot swap the two plane stores,
/// which share one type.
#[derive(Clone, Copy)]
pub struct TrustPlaneStores<'a> {
	/// The first-party (hive and client) trust plane.
	pub hive: Option<&'a dyn CertificateTrust>,
	/// The federated peer trust plane.
	pub peer: Option<&'a dyn CertificateTrust>,
}

impl<'a> From<&'a super::ClusterTlsConfig> for TrustPlanes<'a> {
	fn from(tls: &'a super::ClusterTlsConfig) -> Self {
		Self { hive: tls.hive_trust.as_deref(), peer: tls.peer_trust.as_deref() }
	}
}

impl<'a> TrustPlanes<'a> {
	/// Pairs a hive-plane and a peer-plane trust store, for a caller that holds
	/// the two stores directly, such as a test harness.
	///
	/// Prefer [`From`] on a [`ClusterTlsConfig`](super::ClusterTlsConfig) where
	/// one is available, as the enforcement path does.
	#[must_use]
	pub fn new(stores: TrustPlaneStores<'a>) -> Self {
		Self { hive: stores.hive, peer: stores.peer }
	}

	/// Classifies `cert` against the two planes.
	///
	/// Peer membership wins and is public-key identity: a caller whose
	/// key is enrolled in `peer_trust` is [`Party::Peer`], even when the
	/// presented certificate object lives only in `hive_trust`. Anonymous
	/// (`None`) and unknown certificates are [`Party::Untrusted`].
	#[must_use]
	pub fn classify(&self, cert: Option<&Certificate>) -> Party {
		let Some(cert) = cert else {
			return Party::Untrusted;
		};

		self.classify_by(|trust| trust.trusts_public_key(cert))
	}

	/// Classifies the peer a session proved by the canonical key the session
	/// holds, under the precedence of [`TrustPlanes::classify`]. The house
	/// store finds the key with no decode.
	///
	/// Custom [`ExportGate`] implementations classify the caller here
	/// beside their own per-identity rules.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::{Party, TrustPlaneStores, TrustPlanes};
	/// use tightbeam::policy::SessionContext;
	///
	/// // A session that proved no peer holds no key, so no plane places it.
	/// let planes = TrustPlanes::new(TrustPlaneStores { hive: None, peer: None });
	/// assert_eq!(planes.classify_session(&SessionContext::default()), Party::Untrusted);
	/// ```
	#[must_use]
	pub fn classify_session(&self, session: &SessionContext) -> Party {
		let Some(key) = session.peer_key() else {
			return Party::Untrusted;
		};

		self.classify_by(|trust| trust.find_by_canonical_key(key).is_some())
	}

	/// The plane of the first store that `holds` admits, peer before hive.
	fn classify_by(&self, holds: impl Fn(&dyn CertificateTrust) -> bool) -> Party {
		if self.peer.is_some_and(&holds) {
			return Party::Peer;
		}
		if self.hive.is_some_and(&holds) {
			return Party::FirstParty;
		}

		Party::Untrusted
	}

	/// The store that verifies a frame `party` signs: the hive store for a
	/// first party, the peer store for a peer, and [`None`] for an untrusted
	/// party or a plane with no store.
	pub(crate) fn store(&self, party: Party) -> Option<&'a dyn CertificateTrust> {
		match party {
			Party::FirstParty => self.hive,
			Party::Peer => self.peer,
			Party::Untrusted => None,
		}
	}

	/// The store that names a peer gateway this gateway dials.
	///
	/// A configured peer plane names its peers. A gateway with no peer plane
	/// dials its peers on the hive pool, so the hive store names them.
	pub(crate) fn peer_dial(&self) -> Option<&'a dyn CertificateTrust> {
		self.peer.or(self.hive)
	}

	/// The one name a peer gateway goes by: the fingerprint, under the colony
	/// digest `D`, of the certificate that [`Self::peer_dial`] holds for the
	/// key of `cert`.
	///
	/// - A route keys the gateway that signed its advertisement by it.
	/// - A hop names the certificate its answer presents by it.
	/// - The discovery table counts a signer by it.
	/// - A gateway that rotated its certificate under one key keeps one name.
	///
	/// It is [`None`] with no such store, or for a key outside it.
	pub(crate) fn peer_identity<D: Digest>(&self, cert: &Certificate) -> Option<SharedId> {
		let trust = self.peer_dial()?;
		let enrolled = trust.enrolled_certificate(cert)?;
		enrolled.fingerprint_id::<D>()
	}

	/// The slate key of `cert`, the signer of a frame verified on the plane of
	/// `party`, under the colony digest `D`.
	///
	/// - A peer goes by its name under [`Self::peer_identity`], the rule a hop
	///   names its answer by, so a route keys the gateway a hop admits.
	/// - A first party goes by the fingerprint of `cert` itself.
	pub(crate) fn signer_id<D: Digest>(&self, party: Party, cert: &Certificate) -> Option<SharedId> {
		match party {
			Party::Peer => self.peer_identity::<D>(cert),
			Party::FirstParty | Party::Untrusted => cert.fingerprint_id::<D>(),
		}
	}
}

#[cfg(test)]
mod tests {
	use std::panic::{catch_unwind, AssertUnwindSafe};
	use std::sync::Arc;

	use super::*;
	use crate::colony::urn::ColonyNamespace;
	use crate::tb_cases;
	use crate::testing::fixtures::{poison_write, TestStore};
	use crate::testing::{TestCertificate, TestKey, TestResult};

	fn servlet(name: impl AsRef<str>) -> Urn<'static> {
		ColonyNamespace::servlet_fixture(name)
	}

	/// A certificate under a distinct key, so a trust store that holds
	/// [`TestCertificate::insecure_fixed`] does not hold it.
	fn foreign_certificate() -> Certificate {
		TestCertificate::self_signed(&TestKey::fixed(0x02))
	}

	/// The certificate of the fixed key that names `cn`, under the colony URN
	/// `urn:tightbeam:colony:test`.
	fn named(cn: &str) -> Certificate {
		let key = TestKey::insecure_fixed_signing();
		TestCertificate::with_cn_and_uri_sans(&key, cn, &["urn:tightbeam:colony:test"])
	}

	/// The trust stores and the export list of one export boundary, which
	/// the planes and the policy borrow.
	struct Boundary {
		exported: Option<StaticExportList>,
		hive: Option<Arc<dyn CertificateTrust>>,
		peer: Option<Arc<dyn CertificateTrust>>,
	}

	impl Boundary {
		/// The boundary that exports `exported` (every type for `None`), whose
		/// hive and peer planes each anchor the certificate they name.
		fn of(exported: Option<&[&str]>, hive: Option<&Certificate>, peer: Option<&Certificate>) -> Self {
			let store = |certificate: &Certificate| -> Arc<dyn CertificateTrust> {
				Arc::new(TestStore::holding([certificate.clone()]))
			};

			let exported = exported.map(|names| StaticExportList::new(names.iter().map(servlet)));
			Self { exported, hive: hive.map(store), peer: peer.map(store) }
		}

		/// The hive and peer planes of this boundary.
		fn planes(&self) -> TrustPlanes<'_> {
			TrustPlanes::new(TrustPlaneStores { hive: self.hive.as_deref(), peer: self.peer.as_deref() })
		}

		/// The policy of this boundary, with no grant and no gate.
		fn policy(&self) -> ExportPolicy<'_> {
			let exported = self.exported.as_ref().map(|list| list as &dyn ExportAllowlist);
			policy(exported, self.planes())
		}
	}

	/// The planes that anchor a certificate, and the certificate a party
	/// presents to them.
	type Classified = (Option<Certificate>, Option<Certificate>, Certificate, Party);

	// The hive plane alone names the first party. A certificate the peer
	// plane anchors is a peer, even when the hive plane anchors it too or
	// anchors another certificate of the same key, and a certificate no plane
	// anchors is untrusted.
	tb_cases! {
		fn a_certificate_classifies_by_the_planes_that_anchor_it((hive, peer, presented, party): Classified) {
			let boundary = Boundary::of(None, hive.as_ref(), peer.as_ref());
			assert_eq!(boundary.planes().classify(Some(&presented)), party);
		}
		cases {
			hive_anchored => (
				Some(TestCertificate::insecure_fixed()),
				None,
				TestCertificate::insecure_fixed(),
				Party::FirstParty,
			),
			hive_anchored_beside_a_peer_store => (
				Some(TestCertificate::insecure_fixed()),
				Some(foreign_certificate()),
				TestCertificate::insecure_fixed(),
				Party::FirstParty,
			),
			peer_only => (
				Some(TestCertificate::insecure_fixed()),
				Some(foreign_certificate()),
				foreign_certificate(),
				Party::Peer,
			),
			dual_anchored => (
				Some(TestCertificate::insecure_fixed()),
				Some(TestCertificate::insecure_fixed()),
				TestCertificate::insecure_fixed(),
				Party::Peer,
			),
			same_key_hive_named => (Some(named("hive")), Some(named("peer")), named("hive"), Party::Peer),
			same_key_peer_named => (Some(named("hive")), Some(named("peer")), named("peer"), Party::Peer),
			no_hive_trust => (None, None, TestCertificate::insecure_fixed(), Party::Untrusted),
		}
	}

	/// A session classifies by the canonical key it holds, so a peer that
	/// presented the compressed form of a peer-plane key is a peer.
	#[test]
	fn a_session_classifies_by_its_canonical_key() {
		let peer_cert = foreign_certificate();
		let boundary = Boundary::of(None, Some(&TestCertificate::insecure_fixed()), Some(&peer_cert));

		let session = SessionContext::for_peer(Arc::new(TestCertificate::with_compressed_key(peer_cert)));
		assert_eq!(boundary.planes().classify_session(&session), Party::Peer);
	}

	/// A session that proved no peer classifies as untrusted.
	#[test]
	fn first_party_rejects_anonymous_session() {
		let planes = no_planes();
		assert_eq!(planes.classify_session(&SessionContext::default()), Party::Untrusted);
	}

	/// The boundary of `exported` over `planes`, with no grant and no gate.
	fn policy<'a>(exported: Option<&'a dyn ExportAllowlist>, planes: TrustPlanes<'a>) -> ExportPolicy<'a> {
		ExportPolicy { scope: ExportScope(exported), planes, grants: &[], gates: &[] }
	}

	/// A session whose handshake proved the holder of `cert`.
	fn session_of(cert: &Certificate) -> SessionContext {
		SessionContext::for_peer(Arc::new(cert.clone()))
	}

	/// The two planes with no store on either.
	fn no_planes() -> TrustPlanes<'static> {
		TrustPlanes::new(TrustPlaneStores { hive: None, peer: None })
	}

	/// One export decision: the boundary, the session of the request, its
	/// target, whether a relay hop carried it, and the verdict.
	type Decision = (Boundary, SessionContext, &'static str, bool, TransitStatus);

	// A gateway with no export list passes every target. Under a list, a
	// relayed request passes an exported target alone, and an origin request
	// for an unexported target passes for the first party alone.
	tb_cases! {
		fn the_export_verdict((boundary, session, target, relayed, status): Decision) {
			let verdict = boundary.policy().allowlist(&servlet(target), &session, relayed);

			assert_eq!(verdict, status);
		}
		cases {
			no_list_passes_every_target => (
				Boundary::of(None, None, None),
				session_of(&TestCertificate::insecure_fixed()),
				"ledger",
				true,
				TransitStatus::Ok,
			),
			exported_target_for_an_external_peer => (
				Boundary::of(Some(&["ping"]), None, None),
				session_of(&TestCertificate::insecure_fixed()),
				"ping",
				true,
				TransitStatus::Ok,
			),
			unexported_target_for_an_external_peer => (
				Boundary::of(Some(&["ping"]), Some(&TestCertificate::insecure_fixed()), Some(&foreign_certificate())),
				session_of(&foreign_certificate()),
				"ledger",
				false,
				TransitStatus::PermissionDenied,
			),
			/// The hop marker refuses an unexported relayed request even for a
			/// first-party session, which the origin rule would admit.
			unexported_relayed_request => (
				Boundary::of(Some(&["ping"]), Some(&TestCertificate::insecure_fixed()), None),
				session_of(&TestCertificate::insecure_fixed()),
				"ledger",
				true,
				TransitStatus::PermissionDenied,
			),
			unexported_origin_target_for_the_first_party => (
				Boundary::of(Some(&["ping"]), Some(&TestCertificate::insecure_fixed()), Some(&foreign_certificate())),
				session_of(&TestCertificate::insecure_fixed()),
				"ledger",
				false,
				TransitStatus::Ok,
			),
			unexported_origin_target_for_a_dual_anchored_cert => (
				Boundary::of(
					Some(&["ping"]),
					Some(&TestCertificate::insecure_fixed()),
					Some(&TestCertificate::insecure_fixed()),
				),
				session_of(&TestCertificate::insecure_fixed()),
				"ledger",
				false,
				TransitStatus::PermissionDenied,
			),
			unexported_anonymous_origin_target => (
				Boundary::of(Some(&["ping"]), Some(&TestCertificate::insecure_fixed()), None),
				SessionContext::default(),
				"ledger",
				false,
				TransitStatus::PermissionDenied,
			),
			empty_list_for_an_external_peer => (
				Boundary::of(Some(&[]), Some(&TestCertificate::insecure_fixed()), None),
				session_of(&foreign_certificate()),
				"ping",
				false,
				TransitStatus::PermissionDenied,
			),
		}
	}

	/// A type inserted into a dynamic list reaches the verdict and the
	/// canonical keys at once.
	#[test]
	fn an_inserted_type_passes_the_verdict_and_the_keys() -> TestResult {
		let list = DynamicExportList::new([servlet("ping")]);
		list.insert(servlet("ledger"))?;

		let boundary = policy(Some(&list), no_planes());
		let verdict = boundary.allowlist(&servlet("ledger"), &SessionContext::default(), true);
		let allowed = list.allows_canonical(&servlet("ledger").canonical_bytes());
		assert_eq!((verdict, allowed), (TransitStatus::Ok, true));
		Ok(())
	}

	/// A type removed from a dynamic list leaves the verdict and the
	/// canonical keys at once.
	#[test]
	fn a_removed_type_fails_the_verdict_and_the_keys() -> TestResult {
		let list = DynamicExportList::new([servlet("ping"), servlet("ledger")]);
		list.remove(&servlet("ledger"))?;

		let boundary = policy(Some(&list), no_planes());
		let verdict = boundary.allowlist(&servlet("ledger"), &SessionContext::default(), true);
		let allowed = list.allows_canonical(&servlet("ledger").canonical_bytes());
		assert_eq!((verdict, allowed), (TransitStatus::PermissionDenied, false));
		Ok(())
	}

	/// A static list admits the canonical key of each type it exports, and no
	/// other key.
	#[test]
	fn static_list_filters_slate_to_exported_keys() {
		let exports = StaticExportList::new([servlet("ping")]);
		assert!(exports.allows_canonical(&servlet("ping").canonical_bytes()));
		assert!(!exports.allows_canonical(&servlet("ledger").canonical_bytes()));
	}

	/// A list of one type that implements `contains` alone.
	///
	/// Each house list overrides the canonical lookup, so a list of its own
	/// runs the default lookup of the trait.
	struct ContainsOnlyList(Urn<'static>);

	impl ExportAllowlist for ContainsOnlyList {
		fn contains(&self, target: &Urn<'_>) -> bool {
			&self.0 == target
		}
	}

	/// The default canonical lookup of a list answers as its `contains` does,
	/// and admits no key that names no type.
	#[test]
	fn default_canonical_lookup_delegates_to_contains() {
		let list = ContainsOnlyList(servlet("ping"));
		assert!(list.allows_canonical(&servlet("ping").canonical_bytes()));
		assert!(!list.allows_canonical(&servlet("ledger").canonical_bytes()));
		assert!(!list.allows_canonical(&[0xFF]));
	}

	/// A grant of the type `ledger` alone.
	///
	/// The crate holds no house grant, so a grant is an implementor's own.
	struct GrantTarget;

	impl ExportGrant for GrantTarget {
		fn grants(&self, target: &Urn<'_>, _session: &SessionContext, _relayed: bool) -> bool {
			target == &servlet("ledger")
		}
	}

	/// The boundary of a gateway that exports every type, under `grants`,
	/// with no gate.
	fn granting(grants: &[Arc<dyn ExportGrant>]) -> ExportPolicy<'_> {
		let planes = no_planes();
		ExportPolicy { scope: ExportScope(None), planes, grants, gates: &[] }
	}

	// A grant list grants a target when one of its grants names it, so an
	// empty list grants nothing.
	tb_cases! {
		fn a_grant_list_grants_what_one_grant_names(
			(grants, target, granted): (Vec<Arc<dyn ExportGrant>>, &str, bool)
		) {
			let policy = granting(&grants);

			let verdict = policy.granted(&servlet(target), &SessionContext::default(), false);

			assert_eq!(verdict, granted);
		}
		cases {
			a_named_target => (vec![Arc::new(GrantTarget)], "ledger", true),
			an_unnamed_target => (vec![Arc::new(GrantTarget)], "ping", false),
			no_grants => (Vec::new(), "ledger", false),
		}
	}

	/// A list whose lock a writer poisoned when it panicked while it held the
	/// guard.
	fn poisoned_list() -> DynamicExportList {
		let list = DynamicExportList::new([servlet("ping")]);
		poison_write(&list.membership);
		list
	}

	/// A caller's iterator that panics inside a replacement leaves the list's
	/// lock unpoisoned, because the list builds its membership before it
	/// takes the lock.
	#[test]
	fn a_panicking_iterator_leaves_the_list_lock_unpoisoned() {
		let list = DynamicExportList::new([servlet("ping")]);
		let types = core::iter::from_fn(|| -> Option<Urn<'static>> { panic!("the caller's iterator panics") });

		let panicked = catch_unwind(AssertUnwindSafe(|| list.set(types)));
		assert!(panicked.is_err());
		assert!(!list.membership.is_poisoned());
	}

	/// One write of a dynamic list.
	type ListWrite = fn(&DynamicExportList) -> Result<(), ClusterError>;

	// A replacement, an insertion, and a removal on a poisoned lock each
	// report the fault to the operator.
	tb_cases! {
		fn a_poisoned_list_reports_the_poisoned_lock(write: ListWrite) {
			let list = poisoned_list();
			let written = write(&list);
			assert!(matches!(written, Err(ClusterError::LockPoisoned)));
		}
		cases {
			on_set => |list| list.set([servlet("ledger")]),
			on_insert => |list| list.insert(servlet("ledger")),
			on_remove => |list| list.remove(&servlet("ping")),
		}
	}
}
