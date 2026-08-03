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
//!   work and routed stream opens. A peer that guesses a type name is
//!   still refused unless a grant opens that target.
//!
//! # Allowlist
//!
//! The built-in allowlist is fail-closed when an export list is set. The
//! rules apply in order:
//!
//! 1. An exported target passes for everyone.
//! 2. An unexported relayed request is refused. The hop marker is
//!    unauthenticated defense in depth; the identity rule below holds
//!    against a forged budget.
//! 3. An unexported origin request passes only for a first-party session:
//!    not relayed, a member of `hive_trust`, and not of `peer_trust`.
//! 4. Any other unexported request is refused.
//!
//! A matching grant may still allow a refused target before deny gates run.
//!
//! # Grants
//!
//! [`ExportGrant`] opens one unexported target to selected caller
//! identities. Configure grants through
//! [`ClusterConfigBuilder::with_export_grant`](super::ClusterConfigBuilder::with_export_grant).
//! Allow sources compose as union: exported, granted, or first-party
//! origin. Deny gates still override a grant.
//!
//! # Custom gates
//!
//! [`ExportGate`] adds per-identity rules keyed on [`SessionContext`].
//! Configure gates through
//! [`ClusterConfigBuilder::with_export_gate`](super::ClusterConfigBuilder::with_export_gate).
//! Gates compose as intersection with the allow sources, so a gate may
//! only narrow access.
//!
//! # Mutual TLS
//!
//! First-party recognition requires mutual TLS. The accept plane stores
//! a session certificate only when `ClusterTlsConfig::client_validators`
//! is configured. Without that, every session is anonymous and an export
//! list also blocks unexported targets on the origin plane. The gateway
//! emits a startup posture warning in that configuration when the accept
//! loop starts.
//!
//! # Sources
//!
//! - CWE-285, improper authorization:
//!   <https://cwe.mitre.org/data/definitions/285.html>

use core::str::from_utf8;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use super::ClusterConfig;
use crate::colony::common::canonical_bytes;
use crate::crypto::x509::store::CertificateTrust;
use crate::crypto::x509::Certificate;
use crate::policy::{SessionContext, TransitStatus};
use crate::utils::urn::Urn;

/// Live export allowlist shared by discoverability and enforcement.
///
/// Install through
/// [`ClusterConfigBuilder::with_export_allowlist`](super::ClusterConfigBuilder::with_export_allowlist)
/// or the static helper
/// [`ClusterConfigBuilder::with_exported_types`](super::ClusterConfigBuilder::with_exported_types).
/// `None` on [`PeerConfig::exported_types`](super::PeerConfig) means every
/// locally served type is exported.
///
/// # Planes
///
/// - **Enforcement** calls [`ExportAllowlist::contains`] on each work or
///   stream open, so a mutable list takes effect on the next request.
/// - **Discoverability** calls [`ExportAllowlist::allows_canonical`] per
///   local servlet key on each advertise beat, so the slate tracks the
///   same live membership without building an owned key set.
///
/// # Keys
///
/// List entries are servlet type URNs without an instance tail, so their
/// canonical bytes equal the registry's type keys. An instance-bearing
/// entry would answer [`ExportAllowlist::contains`] on that exact target
/// but never match an advertised type key.
pub trait ExportAllowlist: Send + Sync {
	/// Whether `target` is on the export list.
	fn contains(&self, target: &Urn<'_>) -> bool;

	/// Whether a canonical registry type key is exported.
	///
	/// The provided method parses `key` and delegates to
	/// [`ExportAllowlist::contains`], so the two views cannot diverge.
	/// The built-in lists override it with a cached-set lookup that
	/// borrows `key`. A key that fails to parse is not exported.
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

/// Fixed export list installed at config build.
#[derive(Clone, Debug)]
pub struct StaticExportList {
	types: Vec<Urn<'static>>,
	keys: HashSet<Vec<u8>>,
}

impl StaticExportList {
	/// Build an allowlist from the given servlet type URNs.
	pub fn new(types: impl IntoIterator<Item = Urn<'static>>) -> Self {
		let types: Vec<Urn<'static>> = types.into_iter().collect();
		let keys = types.iter().map(canonical_bytes).collect();
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

/// URN list and its canonical key cache under one lock, so the two views
/// of the membership mutate atomically and cannot diverge mid-update.
#[derive(Default)]
struct ExportMembership {
	types: Vec<Urn<'static>>,
	keys: HashSet<Vec<u8>>,
}

impl ExportMembership {
	fn new(types: impl IntoIterator<Item = Urn<'static>>) -> Self {
		let types: Vec<Urn<'static>> = types.into_iter().collect();
		let keys = types.iter().map(canonical_bytes).collect();
		Self { types, keys }
	}
}

/// Interior-mutable export list for tests and long-running fuzz harnesses.
///
/// Mutations are visible to the next [`ExportAllowlist::contains`] and
/// [`ExportAllowlist::allows_canonical`] call. Poisoned locks treat the
/// list as empty so both planes stay fail-closed.
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
	pub fn set(&self, types: impl IntoIterator<Item = Urn<'static>>) {
		if let Ok(mut guard) = self.membership.write() {
			*guard = ExportMembership::new(types);
		}
	}

	/// Insert `target` when it is not already listed.
	pub fn insert(&self, target: Urn<'static>) {
		if let Ok(mut guard) = self.membership.write() {
			if !guard.types.iter().any(|allowed| allowed == &target) {
				guard.keys.insert(canonical_bytes(&target));
				guard.types.push(target);
			}
		}
	}

	/// Remove every entry equal to `target`.
	pub fn remove(&self, target: &Urn<'_>) {
		if let Ok(mut guard) = self.membership.write() {
			// Keys are collected from the retained-out entries, not
			// recomputed from `target`, so a stored entry that compares
			// equal under a different canonical form still drops its
			// own cached key.
			let mut dropped = Vec::new();
			guard.types.retain(|allowed| {
				if allowed == target {
					dropped.push(canonical_bytes(allowed));
					return false;
				}

				true
			});
			for key in dropped {
				guard.keys.remove(&key);
			}
		}
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

/// Custom export gate for servlet targets crossing the gateway.
///
/// Every configured gate must answer [`TransitStatus::Ok`], so gates
/// compose as intersection with the allow sources (exported list, grants,
/// and the first-party origin rule).
///
/// # Call sites
///
/// Evaluated where the servlet target is known:
///
/// - Unary work arm
/// - Streaming and duplex open handlers
pub trait ExportGate: Send + Sync {
	/// Decide whether `session` may reach `target` on this gateway.
	///
	/// - `target`: servlet type under enforcement
	/// - `session`: caller identity facts (see
	///   [`SessionContext::peer_certificate`] and
	///   [`SessionContext::peer_public_key`])
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

/// Positive grant widening the export boundary for selected callers.
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
/// relayed request that principal is the relaying peer gateway, not the
/// original caller. A grant that matches a relayed request therefore
/// expresses federation-level trust in the relaying gateway.
/// Conservative grants test `!relayed`.
///
/// # Discoverability
///
/// Granted types never appear on the advertised slate, because grants
/// are per-session and ads are minted per beat. A granted type is a
/// private interface whose URN the grantee learns out of band.
pub trait ExportGrant: Send + Sync {
	/// Whether `session` is positively granted `target` on this gateway.
	///
	/// - `target`: servlet type under the grant
	/// - `session`: adjacent authenticated caller identity
	/// - `relayed`: `true` when the request already spent relay budget
	fn grants(&self, target: &Urn<'_>, session: &SessionContext, relayed: bool) -> bool;
}

/// Whether any configured grant allows `session` to reach `target`.
///
/// Grants compose as union, so the first match decides. An empty grant
/// list allows nothing, which keeps the boundary fail-closed.
fn session_granted(grants: &[Arc<dyn ExportGrant>], target: &Urn<'_>, session: &SessionContext, relayed: bool) -> bool {
	grants.iter().any(|grant| grant.grants(target, session, relayed))
}

/// Deciding allow source of a passed export boundary.
///
/// Returned only when the full verdict passes, including deny gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportDecision {
	/// The built-in allowlist allowed the target.
	Allowed,
	/// A positive grant was the deciding allow source.
	Granted,
}

/// Live-configuration view of the export boundary.
///
/// Sealed composition derived from [`ClusterConfig`] through [`From`].
/// Wire handlers never construct this view by hand. The unary work arm
/// and the stream open handlers share one core through
/// [`evaluate_export_gates`](super::runtime::verify::evaluate_export_gates).
pub(crate) struct ExportPolicy<'a> {
	exported: Option<&'a dyn ExportAllowlist>,
	planes: TrustPlanes<'a>,
	grants: &'a [Arc<dyn ExportGrant>],
	gates: &'a [Arc<dyn ExportGate>],
}

impl<'a> From<&'a ClusterConfig> for ExportPolicy<'a> {
	fn from(config: &'a ClusterConfig) -> Self {
		Self {
			exported: config.peer.exported_types.as_deref(),
			planes: TrustPlanes::from(&config.tls),
			grants: &config.export_grants,
			gates: &config.export_gates,
		}
	}
}

impl ExportPolicy<'_> {
	/// Boundary verdict on a resolved servlet target.
	///
	/// The allow sources compose as union. When the built-in allowlist
	/// refuses, any configured grant may still allow the target. Every
	/// deny gate then evaluates, so a deny gate overrides a grant.
	///
	/// [`ExportDecision::Granted`] reports a grant as the deciding
	/// allow source only when the full verdict passes. A gate verdict
	/// of [`TransitStatus::Unknown`] normalizes to
	/// [`TransitStatus::Internal`] before it reaches the wire.
	///
	/// `GatePolicy` is evaluated separately before this step.
	pub(crate) fn verdict(
		&self,
		target: &Urn<'_>,
		session: &SessionContext,
		relayed: bool,
	) -> Result<ExportDecision, TransitStatus> {
		let allowlist = export_verdict(self.exported, &self.planes, target, session.peer_certificate(), relayed);

		let mut decision = ExportDecision::Allowed;
		if allowlist != TransitStatus::Ok {
			if !session_granted(self.grants, target, session, relayed) {
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
	/// Anonymous (`None`), or trusted by neither plane.
	Untrusted,
}

/// The two federation trust planes as one classifier.
///
/// A gateway trusts its own hives on the first-party plane and federated
/// peers on the peer plane. [`TrustPlanes`] borrows both stores as one
/// unit so the precedence rule ("peer membership wins") lives in exactly
/// one place, and a call site cannot transpose the two stores.
///
/// Build one from a [`ClusterTlsConfig`](super::ClusterTlsConfig) through
/// [`From`] on the enforcement path. [`TrustPlanes::new`] takes a
/// [`TrustPlaneStores`] carrier so hive and peer borrows stay named.
///
/// # Fail-closed
///
/// A missing hive store classifies nobody as first-party, so the boundary
/// refuses callers it cannot place. Membership is trust-store lookup
/// through [`CertificateTrust::is_trusted`], not chain path validation.
#[derive(Clone, Copy)]
pub struct TrustPlanes<'a> {
	hive: Option<&'a dyn CertificateTrust>,
	peer: Option<&'a dyn CertificateTrust>,
}

/// Named hive/peer trust-store borrows for [`TrustPlanes::new`].
///
/// Named fields prevent swapping the two same-typed plane stores at the
/// call site.
#[derive(Clone, Copy)]
pub struct TrustPlaneStores<'a> {
	/// First-party (hive/client) trust plane.
	pub hive: Option<&'a dyn CertificateTrust>,
	/// Federated peer trust plane.
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
	/// Prefer [`From`] on a [`ClusterTlsConfig`](super::ClusterTlsConfig)
	/// where one is available. This constructor serves callers that hold
	/// the two stores directly, such as a test harness. Pass planes through
	/// [`TrustPlaneStores`] so hive and peer cannot be swapped by position.
	#[must_use]
	pub fn new(stores: TrustPlaneStores<'a>) -> Self {
		Self { hive: stores.hive, peer: stores.peer }
	}

	/// Classify `cert` against the two planes.
	///
	/// Peer membership wins: a certificate in both stores is
	/// [`Party::Peer`]. Anonymous (`None`) and unknown certificates are
	/// [`Party::Untrusted`].
	#[must_use]
	pub fn classify(&self, cert: Option<&Certificate>) -> Party {
		let Some(cert) = cert else {
			return Party::Untrusted;
		};
		if self.peer.is_some_and(|trust| trust.is_trusted(cert)) {
			return Party::Peer;
		}
		if self.hive.is_some_and(|trust| trust.is_trusted(cert)) {
			return Party::FirstParty;
		}

		Party::Untrusted
	}

	/// [`TrustPlanes::classify`] on a session's authenticated identity.
	///
	/// Custom [`ExportGate`] implementations classify the caller here
	/// beside their own per-identity rules.
	#[must_use]
	pub fn classify_session(&self, session: &SessionContext) -> Party {
		self.classify(session.peer_certificate())
	}

	/// Whether `cert` is a first-party caller.
	#[must_use]
	pub fn is_first_party(&self, cert: Option<&Certificate>) -> bool {
		matches!(self.classify(cert), Party::FirstParty)
	}
}

/// Built-in allowlist verdict on a resolved servlet target.
///
/// `exported` is the configured allowlist, or `None` when the gateway
/// exports every type. The verdict reads the live allowlist on each
/// request so the enforcement plane and the advertise filter stay aligned.
/// Grants are applied by the gateway after this allowlist refuses; this
/// function is the allowlist step alone.
///
/// The rules apply in order:
///
/// 1. An exported target passes for everyone.
/// 2. An unexported relayed request is refused. The hop marker is
///    unauthenticated defense in depth; the identity rule below holds
///    against a forged budget.
/// 3. An unexported origin request passes only for a first-party session.
/// 4. Any other unexported request is refused.
pub(crate) fn export_verdict(
	exported: Option<&dyn ExportAllowlist>,
	planes: &TrustPlanes<'_>,
	target: &Urn<'_>,
	cert: Option<&Certificate>,
	relayed: bool,
) -> TransitStatus {
	let Some(exported) = exported else {
		return TransitStatus::Ok;
	};
	if exported.contains(target) {
		return TransitStatus::Ok;
	}
	if relayed {
		return TransitStatus::PermissionDenied;
	}
	if planes.is_first_party(cert) {
		return TransitStatus::Ok;
	}

	TransitStatus::PermissionDenied
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::common::ColonyNamespace;
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::x509::store::{CertificateTrustBuilder, TrustBuilder};
	use crate::testing::{create_test_certificate, create_test_signing_key};
	use std::sync::Arc;

	fn servlet(name: &str) -> Urn<'static> {
		ColonyNamespace::default()
			.servlet(name)
			.expect("test names satisfy the mint grammar")
	}

	fn test_certificate() -> Certificate {
		create_test_certificate(&create_test_signing_key())
	}

	/// A certificate under a distinct key, so a trust store built from
	/// [`test_certificate`] does not hold it.
	fn foreign_certificate() -> Certificate {
		let key = k256::ecdsa::SigningKey::from_bytes(&[2u8; 32].into()).expect("distinct test key");
		create_test_certificate(&key)
	}

	fn trust_of(cert: &Certificate) -> Arc<dyn CertificateTrust> {
		let store = CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
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

	#[test]
	fn verdict_without_export_list_passes_every_target() {
		let cert = test_certificate();
		assert_eq!(
			export_verdict(
				None,
				&TrustPlanes::new(TrustPlaneStores { hive: None, peer: None }),
				&servlet("ledger"),
				Some(&cert),
				true
			),
			TransitStatus::Ok
		);
	}

	#[test]
	fn verdict_passes_exported_target_for_external_peer() {
		let exported = static_list([servlet("ping")]);
		assert_eq!(
			export_verdict(
				Some(&exported),
				&TrustPlanes::new(TrustPlaneStores { hive: None, peer: None }),
				&servlet("ping"),
				Some(&test_certificate()),
				true
			),
			TransitStatus::Ok
		);
	}

	#[test]
	fn verdict_refuses_unexported_target_for_external_peer() {
		let cert = foreign_certificate();
		let hive = trust_of(&test_certificate());
		let peer = trust_of(&cert);
		let exported = static_list([servlet("ping")]);
		assert_eq!(
			export_verdict(
				Some(&exported),
				&TrustPlanes::new(TrustPlaneStores { hive: Some(hive.as_ref()), peer: Some(peer.as_ref()) }),
				&servlet("ledger"),
				Some(&cert),
				false
			),
			TransitStatus::PermissionDenied
		);
	}

	#[test]
	fn verdict_refuses_unexported_relayed_request() {
		let exported = static_list([servlet("ping")]);
		assert_eq!(
			export_verdict(
				Some(&exported),
				&TrustPlanes::new(TrustPlaneStores { hive: None, peer: None }),
				&servlet("ledger"),
				None,
				true
			),
			TransitStatus::PermissionDenied
		);
	}

	#[test]
	fn verdict_passes_unexported_origin_target_for_first_party() {
		let cert = test_certificate();
		let hive = trust_of(&cert);
		let peer = trust_of(&foreign_certificate());
		let exported = static_list([servlet("ping")]);
		assert_eq!(
			export_verdict(
				Some(&exported),
				&TrustPlanes::new(TrustPlaneStores { hive: Some(hive.as_ref()), peer: Some(peer.as_ref()) }),
				&servlet("ledger"),
				Some(&cert),
				false
			),
			TransitStatus::Ok
		);
	}

	#[test]
	fn verdict_refuses_unexported_origin_target_for_dual_anchored_cert() {
		let cert = test_certificate();
		let hive = trust_of(&cert);
		let peer = trust_of(&cert);
		let exported = static_list([servlet("ping")]);
		assert_eq!(
			export_verdict(
				Some(&exported),
				&TrustPlanes::new(TrustPlaneStores { hive: Some(hive.as_ref()), peer: Some(peer.as_ref()) }),
				&servlet("ledger"),
				Some(&cert),
				false
			),
			TransitStatus::PermissionDenied
		);
	}

	#[test]
	fn verdict_refuses_unexported_anonymous_origin_target() {
		let hive = trust_of(&test_certificate());
		let exported = static_list([servlet("ping")]);
		assert_eq!(
			export_verdict(
				Some(&exported),
				&TrustPlanes::new(TrustPlaneStores { hive: Some(hive.as_ref()), peer: None }),
				&servlet("ledger"),
				None,
				false
			),
			TransitStatus::PermissionDenied
		);
	}

	#[test]
	fn empty_export_list_refuses_every_target_for_external_peer() {
		let cert = foreign_certificate();
		let hive = trust_of(&test_certificate());
		let exported = static_list([]);
		assert_eq!(
			export_verdict(
				Some(&exported),
				&TrustPlanes::new(TrustPlaneStores { hive: Some(hive.as_ref()), peer: None }),
				&servlet("ping"),
				Some(&cert),
				false
			),
			TransitStatus::PermissionDenied
		);
	}

	#[test]
	fn dynamic_allowlist_mutation_visible_to_verdict_and_keys() {
		let list = DynamicExportList::new([servlet("ping")]);
		let ledger = servlet("ledger");
		let ledger_key = canonical_bytes(&ledger);

		assert_eq!(
			export_verdict(
				Some(&list),
				&TrustPlanes::new(TrustPlaneStores { hive: None, peer: None }),
				&ledger,
				None,
				true
			),
			TransitStatus::PermissionDenied
		);
		assert!(!list.allows_canonical(&ledger_key));

		list.insert(ledger.clone());

		assert_eq!(
			export_verdict(
				Some(&list),
				&TrustPlanes::new(TrustPlaneStores { hive: None, peer: None }),
				&ledger,
				None,
				true
			),
			TransitStatus::Ok
		);
		assert!(list.allows_canonical(&ledger_key));

		list.remove(&ledger);

		assert_eq!(
			export_verdict(
				Some(&list),
				&TrustPlanes::new(TrustPlaneStores { hive: None, peer: None }),
				&ledger,
				None,
				true
			),
			TransitStatus::PermissionDenied
		);
		assert!(!list.allows_canonical(&ledger_key));
	}

	#[test]
	fn static_list_filters_slate_to_exported_keys() {
		let exports = static_list([servlet("ping")]);
		assert!(exports.allows_canonical(&canonical_bytes(&servlet("ping"))));
		assert!(!exports.allows_canonical(&canonical_bytes(&servlet("ledger"))));
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
		assert!(list.allows_canonical(&canonical_bytes(&servlet("ping"))));
		assert!(!list.allows_canonical(&canonical_bytes(&servlet("ledger"))));
		assert!(!list.allows_canonical(&[0xFF]));
	}

	struct GrantTarget;

	impl ExportGrant for GrantTarget {
		fn grants(&self, target: &Urn<'_>, _session: &SessionContext, _relayed: bool) -> bool {
			target == &servlet("ledger")
		}
	}

	#[test]
	fn session_granted_matches_any_grant() {
		let grants: Vec<Arc<dyn ExportGrant>> = vec![Arc::new(GrantTarget)];
		assert!(session_granted(&grants, &servlet("ledger"), &SessionContext::default(), false));
		assert!(!session_granted(&grants, &servlet("ping"), &SessionContext::default(), false));
	}

	#[test]
	fn empty_grant_list_allows_nothing() {
		assert!(!session_granted(&[], &servlet("ledger"), &SessionContext::default(), false));
	}
}
