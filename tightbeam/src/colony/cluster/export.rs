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

use std::collections::HashSet;
use std::sync::Arc;

use super::ClusterConfig;
use crate::colony::common::canonical_bytes;
use crate::crypto::x509::store::CertificateTrust;
use crate::crypto::x509::Certificate;
use crate::policy::{SessionContext, TransitStatus};
use crate::utils::urn::Urn;

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
	/// - `relayed`: `true` when the request already spent relay budget
	///   and therefore entered through a peer gateway rather than a
	///   direct client
	fn evaluate(&self, target: &Urn<'_>, session: &SessionContext, relayed: bool) -> TransitStatus;
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
pub(crate) enum ExportDecision {
	/// The built-in allowlist allowed the target.
	Allowed,
	/// A positive grant was the deciding allow source.
	Granted,
}

/// Live-configuration view of the export boundary.
///
/// One composition point for every enforcement call site. A target passes
/// when it is exported, granted, or a first-party origin request, and
/// every deny gate must then agree.
pub(crate) struct ExportPolicy<'a> {
	exported: Option<&'a [Urn<'static>]>,
	hive_trust: Option<&'a dyn CertificateTrust>,
	peer_trust: Option<&'a dyn CertificateTrust>,
	grants: &'a [Arc<dyn ExportGrant>],
	gates: &'a [Arc<dyn ExportGate>],
}

impl<'a> From<&'a ClusterConfig> for ExportPolicy<'a> {
	fn from(config: &'a ClusterConfig) -> Self {
		Self {
			exported: config.peer.exported_types.as_deref(),
			hive_trust: config.tls.hive_trust.as_deref(),
			peer_trust: config.tls.peer_trust.as_deref(),
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
	pub(crate) fn verdict(
		&self,
		target: &Urn<'_>,
		session: &SessionContext,
		relayed: bool,
	) -> Result<ExportDecision, TransitStatus> {
		let allowlist = export_verdict(
			self.exported,
			self.hive_trust,
			self.peer_trust,
			target,
			session.peer_certificate(),
			relayed,
		);
		let mut decision = ExportDecision::Allowed;
		if allowlist != TransitStatus::Ok {
			if !session_granted(self.grants, target, session, relayed) {
				return Err(allowlist);
			}

			decision = ExportDecision::Granted;
		}

		for gate in self.gates {
			let status = gate.evaluate(target, session, relayed).normalized_verdict();
			if status != TransitStatus::Ok {
				return Err(status);
			}
		}

		Ok(decision)
	}
}

/// First-party classification of a caller certificate.
///
/// A certificate is first-party when it is a member of `hive_trust` and
/// not of `peer_trust`. The check is trust-store membership through
/// `is_trusted`, not chain path validation.
///
/// # Classification
///
/// - First-party: a member of `hive_trust` and not of `peer_trust`
/// - External peer: a member of `peer_trust` (peer membership wins,
///   even when `hive_trust` also holds the certificate)
/// - Never first-party: anonymous callers (`None`), peer-only sessions,
///   and sessions in neither store
///
/// # Fail-closed
///
/// A missing `hive_trust` store classifies nobody as first-party, so the
/// boundary refuses callers it cannot place.
#[must_use]
pub fn cert_is_first_party(
	cert: Option<&Certificate>,
	hive_trust: Option<&dyn CertificateTrust>,
	peer_trust: Option<&dyn CertificateTrust>,
) -> bool {
	let Some(cert) = cert else {
		return false;
	};
	if peer_trust.is_some_and(|trust| trust.is_trusted(cert)) {
		return false;
	}

	hive_trust.is_some_and(|trust| trust.is_trusted(cert))
}

/// [`cert_is_first_party`] on a session's authenticated identity.
///
/// Custom [`ExportGate`] implementations call this to reuse the
/// first-party classifier beside their own per-identity rules.
#[must_use]
pub fn session_is_first_party(
	session: &SessionContext,
	hive_trust: Option<&dyn CertificateTrust>,
	peer_trust: Option<&dyn CertificateTrust>,
) -> bool {
	cert_is_first_party(session.peer_certificate(), hive_trust, peer_trust)
}

/// Built-in allowlist verdict on a resolved servlet target.
///
/// `exported` is the configured export list, or `None` when the gateway
/// exports every type. The verdict reads the live configuration on each
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
	exported: Option<&[Urn<'static>]>,
	hive_trust: Option<&dyn CertificateTrust>,
	peer_trust: Option<&dyn CertificateTrust>,
	target: &Urn<'_>,
	cert: Option<&Certificate>,
	relayed: bool,
) -> TransitStatus {
	let Some(exported) = exported else {
		return TransitStatus::Ok;
	};
	if exported.iter().any(|allowed| allowed == target) {
		return TransitStatus::Ok;
	}
	if relayed {
		return TransitStatus::PermissionDenied;
	}
	if cert_is_first_party(cert, hive_trust, peer_trust) {
		return TransitStatus::Ok;
	}

	TransitStatus::PermissionDenied
}

/// Canonical-byte lookup set of an exported-type list.
///
/// The advertise beat builds this once per task and filters the slate
/// against it, so ads and rumors disclose exported types only.
pub(crate) fn export_set(exported: &[Urn<'static>]) -> HashSet<Vec<u8>> {
	exported.iter().map(canonical_bytes).collect()
}

/// Whether a canonical type key belongs on the advertised slate.
///
/// `None` means no export list is configured, which exports every type.
pub(crate) fn slate_exported(exports: Option<&HashSet<Vec<u8>>>, canonical: &[u8]) -> bool {
	match exports {
		Some(set) => set.contains(canonical),
		None => true,
	}
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
		assert!(cert_is_first_party(Some(&cert), Some(hive.as_ref()), None));
	}

	#[test]
	fn first_party_rejects_peer_only_cert() {
		let cert = foreign_certificate();
		let hive = trust_of(&test_certificate());
		let peer = trust_of(&cert);

		assert!(!cert_is_first_party(Some(&cert), Some(hive.as_ref()), Some(peer.as_ref())));
	}

	#[test]
	fn first_party_rejects_dual_anchored_cert() {
		let cert = test_certificate();
		let hive = trust_of(&cert);
		let peer = trust_of(&cert);

		assert!(!cert_is_first_party(Some(&cert), Some(hive.as_ref()), Some(peer.as_ref())));
	}

	#[test]
	fn first_party_rejects_anonymous_session() {
		assert!(!session_is_first_party(&SessionContext::default(), None, None));
	}

	#[test]
	fn first_party_without_hive_trust_classifies_nobody() {
		let cert = test_certificate();
		assert!(!cert_is_first_party(Some(&cert), None, None));
	}

	#[test]
	fn verdict_without_export_list_passes_every_target() {
		let cert = test_certificate();
		assert_eq!(
			export_verdict(None, None, None, &servlet("ledger"), Some(&cert), true),
			TransitStatus::Ok
		);
	}

	#[test]
	fn verdict_passes_exported_target_for_external_peer() {
		let exported = [servlet("ping")];
		assert_eq!(
			export_verdict(Some(&exported), None, None, &servlet("ping"), Some(&test_certificate()), true),
			TransitStatus::Ok
		);
	}

	#[test]
	fn verdict_refuses_unexported_target_for_external_peer() {
		let cert = foreign_certificate();
		let hive = trust_of(&test_certificate());
		let peer = trust_of(&cert);
		let exported = [servlet("ping")];
		assert_eq!(
			export_verdict(
				Some(&exported),
				Some(hive.as_ref()),
				Some(peer.as_ref()),
				&servlet("ledger"),
				Some(&cert),
				false
			),
			TransitStatus::PermissionDenied
		);
	}

	#[test]
	fn verdict_refuses_unexported_relayed_request() {
		let exported = [servlet("ping")];
		assert_eq!(
			export_verdict(Some(&exported), None, None, &servlet("ledger"), None, true),
			TransitStatus::PermissionDenied
		);
	}

	#[test]
	fn verdict_passes_unexported_origin_target_for_first_party() {
		let cert = test_certificate();
		let hive = trust_of(&cert);
		let peer = trust_of(&foreign_certificate());
		let exported = [servlet("ping")];
		assert_eq!(
			export_verdict(
				Some(&exported),
				Some(hive.as_ref()),
				Some(peer.as_ref()),
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
		let exported = [servlet("ping")];
		assert_eq!(
			export_verdict(
				Some(&exported),
				Some(hive.as_ref()),
				Some(peer.as_ref()),
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
		let exported = [servlet("ping")];
		assert_eq!(
			export_verdict(Some(&exported), Some(hive.as_ref()), None, &servlet("ledger"), None, false),
			TransitStatus::PermissionDenied
		);
	}

	#[test]
	fn empty_export_list_refuses_every_target_for_external_peer() {
		let cert = foreign_certificate();
		let hive = trust_of(&test_certificate());
		assert_eq!(
			export_verdict(Some(&[]), Some(hive.as_ref()), None, &servlet("ping"), Some(&cert), false),
			TransitStatus::PermissionDenied
		);
	}

	#[test]
	fn export_set_filters_slate_to_exported_keys() {
		let exports = export_set(&[servlet("ping")]);
		let exported_key = canonical_bytes(&servlet("ping"));
		let hidden_key = canonical_bytes(&servlet("ledger"));
		assert!(slate_exported(Some(&exports), &exported_key));
		assert!(!slate_exported(Some(&exports), &hidden_key));
	}

	#[test]
	fn missing_export_list_exports_all() {
		let key = canonical_bytes(&servlet("ledger"));
		assert!(slate_exported(None, &key));
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
