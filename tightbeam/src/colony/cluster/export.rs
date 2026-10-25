//! Export boundary for federated peers.
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
//! [`ExportGrant`] opens one unexported target to selected caller
//! identities. Configure grants through
//! [`ClusterConfigBuilder::with_export_grant`]. Allow sources compose as
//! union: exported, granted, or first-party origin. Deny gates still override
//! a grant.
//!
//! # Custom gates
//!
//! [`ExportGate`] adds per-identity rules keyed on [`SessionContext`].
//! Configure gates through [`ClusterConfigBuilder::with_export_gate`]. Gates
//! compose as intersection with the allow sources, so a gate may only narrow
//! access.
//!
//! # Mutual TLS
//!
//! First-party recognition requires mutual TLS. The accept plane stores
//! a session certificate only when [`ClusterTlsConfig::client_validators`]
//! is configured. Without that configuration:
//!
//! - Every session is anonymous, so an export list also blocks unexported targets on the origin plane.
//! - With an export list set, the gateway emits a posture warning at startup.
//!
//! # Sources
//!
//! - CWE-285, improper authorization: <https://cwe.mitre.org/data/definitions/285.html>
//!
//! [`ClusterTlsConfig::client_validators`]: super::ClusterTlsConfig::client_validators
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
/// Install it through [`ClusterConfigBuilder::with_export_allowlist`], or
/// install a static list through
/// [`ClusterConfigBuilder::with_exported_types`]. `None` on
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
	/// The provided method parses `key` and delegates to
	/// [`ExportAllowlist::contains`], so the two views always agree.
	/// The built-in lists override it with a cached-set lookup that
	/// borrows `key`. It answers `false` for a key that fails to parse.
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
	/// Build an allowlist from the given servlet type URNs.
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
	/// Build a mutable allowlist from the given servlet type URNs.
	pub fn new(types: impl IntoIterator<Item = Urn<'static>>) -> Self {
		Self { membership: RwLock::new(ExportMembership::new(types)) }
	}

	/// Replace the export membership with `types`.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the list's lock is poisoned.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::{DynamicExportList, ExportAllowlist};
	/// use tightbeam::colony::common::ColonyNamespace;
	///
	/// let ping = ColonyNamespace::default().servlet("ping")?;
	/// let list = DynamicExportList::default();
	///
	/// list.set([ping.clone()])?;
	/// assert!(list.contains(&ping));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn set(&self, types: impl IntoIterator<Item = Urn<'static>>) -> Result<(), ClusterError> {
		// The membership is built from the caller's iterator before the lock
		// is taken, so the lock guards the swap of a finished value alone.
		let membership = ExportMembership::new(types);

		let mut guard = self.membership.write()?;
		*guard = membership;

		Ok(())
	}

	/// Insert `target` when it is not already listed.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the list's lock is poisoned.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::{DynamicExportList, ExportAllowlist};
	/// use tightbeam::colony::common::ColonyNamespace;
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

	/// Remove every entry equal to `target`.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the list's lock is poisoned.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::{DynamicExportList, ExportAllowlist};
	/// use tightbeam::colony::common::ColonyNamespace;
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

		// The loop collects keys from the entries it drops rather than
		// recompute them from `target`, so a stored entry that compares equal
		// under a different canonical form still drops its own cached key.
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
/// Every configured gate must answer [`TransitStatus::Ok`], so gates
/// compose as intersection with the allow sources (exported list, grants,
/// and the first-party origin rule).
///
/// # Call sites
///
/// The gateway evaluates it where the servlet target is known:
///
/// - The unary work arm.
/// - The streaming and duplex open handlers.
pub trait ExportGate: Send + Sync {
	/// Decide whether `session` may reach `target` on this gateway.
	///
	/// - `target`: servlet type under enforcement
	/// - `session`: caller identity facts (see
	///   [`SessionContext::peer_certificate`]), whose peer key a rule reads
	///   when it asks a [`PeerListGate`](crate::colony::hive::PeerListGate)
	///   through [`GatePolicy::evaluate`](crate::policy::GatePolicy::evaluate)
	/// - `planes`: the two federation trust planes, for gates that reuse
	///   the first-party classifier through
	///   [`TrustPlanes::classify_session`] beside their own rules
	/// - `relayed`: `true` when the request already spent relay budget
	///   and therefore entered through a peer gateway rather than a
	///   direct client
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
/// A grant adds one allow source beside the exported list and the
/// first-party origin rule. Allow sources compose as union, so a grant
/// may only widen access to the granted target. Every configured
/// [`ExportGate`] still evaluates afterward, so a deny gate overrides
/// any grant.
///
/// # Subject rule
///
/// The session identity is the adjacent authenticated principal. On a
/// relayed request that principal is the peer gateway that relayed it, not
/// the original caller. A grant that matches a relayed request therefore
/// expresses federation-level trust in that relay gateway. Conservative
/// grants test `!relayed`.
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
	/// - `target`: servlet type under the grant
	/// - `session`: adjacent authenticated caller identity
	/// - `relayed`: `true` when the request already spent relay budget
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
	/// The allow sources compose as union, and the steps run in order:
	///
	/// 1. The built-in allowlist answers.
	/// 2. When it refuses, any configured grant may still allow the target.
	/// 3. Every deny gate then evaluates, so a deny gate overrides a grant. A
	///    gate verdict of [`TransitStatus::Unknown`] normalizes to
	///    [`TransitStatus::Internal`] before it reaches the wire.
	///
	/// [`ExportDecision::Granted`] reports a grant as the allow source that
	/// decided, and only when the full verdict passes.
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

	/// The built-in allowlist verdict on a resolved servlet target.
	///
	/// The verdict asks the export scope, which reads the live allowlist on
	/// each request, so the enforcement plane and the advertise filter stay
	/// aligned. [`Self::verdict`] applies grants after this step refuses.
	///
	/// The rules apply in order:
	///
	/// 1. An exported target passes for everyone. With no export list, every target is exported.
	/// 2. An unexported relayed request is refused. The hop marker is
	///    unauthenticated defense in depth, and the identity rule below holds
	///    against a forged budget.
	/// 3. An unexported origin request passes only for a first-party session,
	///    which [`TrustPlanes::classify_session`] places by its key.
	/// 4. Any other unexported request is refused.
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

	/// Whether any configured grant allows `session` to reach `target`.
	///
	/// Grants compose as union, so the first match decides. An empty grant
	/// list allows nothing, which keeps the boundary fail-closed.
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
	/// A member of the peer plane. Peer membership wins over hive
	/// membership, so a certificate held by both stores lands here.
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
	/// Pair a hive-plane and a peer-plane trust store.
	///
	/// Prefer [`From`] on a [`ClusterTlsConfig`](super::ClusterTlsConfig), as
	/// the enforcement path does, where one is available. This constructor
	/// serves callers that hold the two stores directly, such as a test
	/// harness. Pass planes through [`TrustPlaneStores`], so a caller cannot
	/// swap hive and peer by position.
	#[must_use]
	pub fn new(stores: TrustPlaneStores<'a>) -> Self {
		Self { hive: stores.hive, peer: stores.peer }
	}

	/// Classify `cert` against the two planes.
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

	/// Classify the peer a session proved by the canonical key the session
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
	use super::*;
	use crate::colony::common::ColonyNamespace;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::x509::store::{CertificateTrustBuilder, TrustBuilder};
	use crate::testing::{TestCertificate, TestKey};
	use std::panic::{catch_unwind, AssertUnwindSafe};
	use std::sync::Arc;

	fn servlet(name: &(impl AsRef<str> + ?Sized)) -> Urn<'static> {
		let name = name.as_ref();
		ColonyNamespace::default()
			.servlet(name)
			.expect("test names satisfy the mint grammar")
	}

	fn test_certificate() -> Certificate {
		TestCertificate::self_signed(&TestKey::insecure_fixed_signing())
	}

	/// A certificate under a distinct key, so a trust store built from
	/// [`test_certificate`] does not hold it.
	fn foreign_certificate() -> Certificate {
		let key = k256::ecdsa::SigningKey::from_bytes(&[2u8; 32].into()).expect("distinct test key");
		TestCertificate::self_signed(&key)
	}

	fn trust_of(cert: &Certificate) -> Arc<dyn CertificateTrust> {
		let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(cert.clone())
			.expect("test certificates satisfy the trust builder")
			.build();
		Arc::new(store)
	}

	#[test]
	fn first_party_classifies_hive_anchored_cert() {
		let cert = test_certificate();
		let hive = trust_of(&cert);
		let planes = TrustPlanes::new(TrustPlaneStores { hive: Some(hive.as_ref()), peer: None });
		assert_eq!(planes.classify(Some(&cert)), Party::FirstParty);
	}

	/// Named plane fields keep hive and peer stores distinct under classify.
	#[test]
	fn trust_plane_stores_named_fields_are_distinct() {
		let hive_cert = test_certificate();
		let peer_cert = foreign_certificate();
		let hive = trust_of(&hive_cert);
		let peer = trust_of(&peer_cert);
		let planes = TrustPlanes::new(TrustPlaneStores { hive: Some(hive.as_ref()), peer: Some(peer.as_ref()) });
		assert_eq!(planes.classify(Some(&hive_cert)), Party::FirstParty);
		assert_eq!(planes.classify(Some(&peer_cert)), Party::Peer);
	}

	#[test]
	fn first_party_rejects_peer_only_cert() {
		let cert = foreign_certificate();
		let hive = trust_of(&test_certificate());
		let peer = trust_of(&cert);
		let planes = TrustPlanes::new(TrustPlaneStores { hive: Some(hive.as_ref()), peer: Some(peer.as_ref()) });

		assert_eq!(planes.classify(Some(&cert)), Party::Peer);
	}

	#[test]
	fn first_party_rejects_dual_anchored_cert() {
		let cert = test_certificate();
		let hive = trust_of(&cert);
		let peer = trust_of(&cert);
		let planes = TrustPlanes::new(TrustPlaneStores { hive: Some(hive.as_ref()), peer: Some(peer.as_ref()) });
		assert_eq!(planes.classify(Some(&cert)), Party::Peer);
	}

	#[test]
	fn peer_wins_when_same_key_has_distinct_certificates() {
		let key = TestKey::insecure_fixed_signing();
		let hive_cert = TestCertificate::with_cn_and_uri_sans(&key, "hive", &["urn:tightbeam:colony:test"]);
		let peer_cert = TestCertificate::with_cn_and_uri_sans(&key, "peer", &["urn:tightbeam:colony:test"]);

		let hive = trust_of(&hive_cert);
		let peer = trust_of(&peer_cert);
		let planes = TrustPlanes::new(TrustPlaneStores { hive: Some(hive.as_ref()), peer: Some(peer.as_ref()) });
		assert_eq!(planes.classify(Some(&hive_cert)), Party::Peer);
		assert_eq!(planes.classify(Some(&peer_cert)), Party::Peer);
	}

	/// A session classifies by the canonical key it holds, so a peer that
	/// presented the compressed form of a peer-plane key is a peer.
	#[test]
	fn a_session_classifies_by_its_canonical_key() {
		let hive = trust_of(&test_certificate());
		let peer_cert = foreign_certificate();
		let peer = trust_of(&peer_cert);
		let planes = TrustPlanes::new(TrustPlaneStores { hive: Some(hive.as_ref()), peer: Some(peer.as_ref()) });

		let session = SessionContext::for_peer(Arc::new(TestCertificate::with_compressed_key(peer_cert)));
		assert_eq!(planes.classify_session(&session), Party::Peer);
	}

	#[test]
	fn first_party_rejects_anonymous_session() {
		let planes = TrustPlanes::new(TrustPlaneStores { hive: None, peer: None });
		assert_eq!(planes.classify_session(&SessionContext::default()), Party::Untrusted);
	}

	#[test]
	fn first_party_without_hive_trust_classifies_nobody() {
		let cert = test_certificate();
		let planes = TrustPlanes::new(TrustPlaneStores { hive: None, peer: None });
		assert_eq!(planes.classify(Some(&cert)), Party::Untrusted);
	}

	fn static_list(types: impl IntoIterator<Item = Urn<'static>>) -> StaticExportList {
		StaticExportList::new(types)
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

	/// The hive plane `hive` beside the peer plane `peer`.
	fn planes<'a>(hive: &'a Arc<dyn CertificateTrust>, peer: Option<&'a Arc<dyn CertificateTrust>>) -> TrustPlanes<'a> {
		let peer = peer.map(|peer| peer.as_ref());
		TrustPlanes::new(TrustPlaneStores { hive: Some(hive.as_ref()), peer })
	}

	#[test]
	fn verdict_without_export_list_passes_every_target() {
		let cert = test_certificate();

		let verdict = policy(None, no_planes()).allowlist(&servlet("ledger"), &session_of(&cert), true);

		assert_eq!(verdict, TransitStatus::Ok);
	}

	#[test]
	fn verdict_passes_exported_target_for_external_peer() {
		let cert = test_certificate();
		let exported = static_list([servlet("ping")]);

		let verdict = policy(Some(&exported), no_planes()).allowlist(&servlet("ping"), &session_of(&cert), true);

		assert_eq!(verdict, TransitStatus::Ok);
	}

	#[test]
	fn verdict_refuses_unexported_target_for_external_peer() {
		let cert = foreign_certificate();
		let hive = trust_of(&test_certificate());
		let peer = trust_of(&cert);
		let exported = static_list([servlet("ping")]);
		let boundary = policy(Some(&exported), planes(&hive, Some(&peer)));

		let verdict = boundary.allowlist(&servlet("ledger"), &session_of(&cert), false);

		assert_eq!(verdict, TransitStatus::PermissionDenied);
	}

	/// The hop marker refuses an unexported relayed request even for a
	/// first-party session, which the origin rule would admit.
	#[test]
	fn verdict_refuses_unexported_relayed_request() {
		let cert = test_certificate();
		let hive = trust_of(&cert);
		let exported = static_list([servlet("ping")]);
		let boundary = policy(Some(&exported), planes(&hive, None));

		let verdict = boundary.allowlist(&servlet("ledger"), &session_of(&cert), true);

		assert_eq!(verdict, TransitStatus::PermissionDenied);
	}

	#[test]
	fn verdict_passes_unexported_origin_target_for_first_party() {
		let cert = test_certificate();
		let hive = trust_of(&cert);
		let peer = trust_of(&foreign_certificate());
		let exported = static_list([servlet("ping")]);
		let boundary = policy(Some(&exported), planes(&hive, Some(&peer)));

		let verdict = boundary.allowlist(&servlet("ledger"), &session_of(&cert), false);

		assert_eq!(verdict, TransitStatus::Ok);
	}

	#[test]
	fn verdict_refuses_unexported_origin_target_for_dual_anchored_cert() {
		let cert = test_certificate();
		let hive = trust_of(&cert);
		let peer = trust_of(&cert);
		let exported = static_list([servlet("ping")]);
		let boundary = policy(Some(&exported), planes(&hive, Some(&peer)));

		let verdict = boundary.allowlist(&servlet("ledger"), &session_of(&cert), false);

		assert_eq!(verdict, TransitStatus::PermissionDenied);
	}

	#[test]
	fn verdict_refuses_unexported_anonymous_origin_target() {
		let hive = trust_of(&test_certificate());
		let exported = static_list([servlet("ping")]);
		let boundary = policy(Some(&exported), planes(&hive, None));

		let verdict = boundary.allowlist(&servlet("ledger"), &SessionContext::default(), false);

		assert_eq!(verdict, TransitStatus::PermissionDenied);
	}

	#[test]
	fn empty_export_list_refuses_every_target_for_external_peer() {
		let cert = foreign_certificate();
		let hive = trust_of(&test_certificate());
		let exported = static_list([]);
		let boundary = policy(Some(&exported), planes(&hive, None));

		let verdict = boundary.allowlist(&servlet("ping"), &session_of(&cert), false);

		assert_eq!(verdict, TransitStatus::PermissionDenied);
	}

	#[test]
	fn dynamic_allowlist_mutation_visible_to_verdict_and_keys() -> Result<(), ClusterError> {
		let list = DynamicExportList::new([servlet("ping")]);
		let ledger = servlet("ledger");
		let ledger_key = ledger.canonical_bytes();
		let boundary = policy(Some(&list), no_planes());
		let anonymous = SessionContext::default();
		assert_eq!(boundary.allowlist(&ledger, &anonymous, true), TransitStatus::PermissionDenied);
		assert!(!list.allows_canonical(&ledger_key));

		list.insert(ledger.clone())?;

		assert_eq!(boundary.allowlist(&ledger, &anonymous, true), TransitStatus::Ok);
		assert!(list.allows_canonical(&ledger_key));

		list.remove(&ledger)?;

		assert_eq!(boundary.allowlist(&ledger, &anonymous, true), TransitStatus::PermissionDenied);
		assert!(!list.allows_canonical(&ledger_key));
		Ok(())
	}

	#[test]
	fn static_list_filters_slate_to_exported_keys() {
		let exports = static_list([servlet("ping")]);
		assert!(exports.allows_canonical(&servlet("ping").canonical_bytes()));
		assert!(!exports.allows_canonical(&servlet("ledger").canonical_bytes()));
	}

	struct ContainsOnlyList(Urn<'static>);

	impl ExportAllowlist for ContainsOnlyList {
		fn contains(&self, target: &Urn<'_>) -> bool {
			&self.0 == target
		}
	}

	#[test]
	fn default_canonical_lookup_delegates_to_contains() {
		let list = ContainsOnlyList(servlet("ping"));
		assert!(list.allows_canonical(&servlet("ping").canonical_bytes()));
		assert!(!list.allows_canonical(&servlet("ledger").canonical_bytes()));
		assert!(!list.allows_canonical(&[0xFF]));
	}

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

	#[test]
	fn granted_matches_any_grant() {
		let grants: Vec<Arc<dyn ExportGrant>> = vec![Arc::new(GrantTarget)];
		let policy = granting(&grants);
		assert!(policy.granted(&servlet("ledger"), &SessionContext::default(), false));
		assert!(!policy.granted(&servlet("ping"), &SessionContext::default(), false));
	}

	#[test]
	fn empty_grant_list_allows_nothing() {
		let policy = granting(&[]);
		assert!(!policy.granted(&servlet("ledger"), &SessionContext::default(), false));
	}

	/// A list whose lock a writer poisoned when it panicked while it held the
	/// guard.
	fn poisoned_list() -> DynamicExportList {
		let list = DynamicExportList::new([servlet("ping")]);
		let panicked = catch_unwind(AssertUnwindSafe(|| {
			let _held = list.membership.write().expect("the lock is live until this panic");
			panic!("poison the export list lock");
		}));

		assert!(panicked.is_err());
		assert!(list.membership.is_poisoned());
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

	/// A replacement on a poisoned lock reports the fault to the operator.
	#[test]
	fn a_set_on_a_poisoned_list_reports_the_poisoned_lock() {
		let list = poisoned_list();

		let set = list.set([servlet("ledger")]);

		assert!(matches!(set, Err(ClusterError::LockPoisoned)));
	}

	/// An insertion on a poisoned lock reports the fault to the operator.
	#[test]
	fn an_insert_on_a_poisoned_list_reports_the_poisoned_lock() {
		let list = poisoned_list();

		let inserted = list.insert(servlet("ledger"));

		assert!(matches!(inserted, Err(ClusterError::LockPoisoned)));
	}

	/// A removal on a poisoned lock reports the fault to the operator.
	#[test]
	fn a_remove_on_a_poisoned_list_reports_the_poisoned_lock() {
		let list = poisoned_list();

		let removed = list.remove(&servlet("ping"));

		assert!(matches!(removed, Err(ClusterError::LockPoisoned)));
	}
}
