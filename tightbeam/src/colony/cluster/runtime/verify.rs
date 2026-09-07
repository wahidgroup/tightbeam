//! Origin, freshness, and export-boundary checks for cluster control traffic.
//!
//! The gateway runs these predicates before or beside request dispatch.
//! Gate policies evaluate on every admitted session. The export boundary
//! evaluates once a servlet target is known. Origin and freshness checks
//! apply to signed control frames on the hive and peer planes.
//!
//! # Gate policies
//!
//! [`evaluate_gates`] runs configured [`GatePolicy`] instances before the
//! request envelope is decoded. Stream opens carry no request frame, so they
//! pass `None` for the frame argument.
//!
//! # Export boundary
//!
//! [`evaluate_export_gates`] runs [`ExportPolicy`] where the servlet target
//! is resolved: allowlist, then grants, then deny gates.
//! [`HopBudget::is_relayed`] supplies the `relayed` flag. Verdict algebra and
//! posture warnings live in [`crate::colony::cluster::export`].
//!
//! # Origin and freshness
//!
//! [`verify_hive_origin`] and [`verify_peer_origin`] verify frame signatures
//! against the configured trust stores. [`GatewayReplayGuard`] rejects
//! stale or replayed signed control frames.
//!
//! [`GatewayReplayGuard`]: super::freshness::GatewayReplayGuard

use crate::colony::cluster::export::{ExportDecision, ExportPolicy};
use crate::colony::cluster::peer::cert_fingerprint_id;
use crate::colony::cluster::ClusterConfig;
use crate::colony::hive::{verify_frame_signature, TrustVerification};
use crate::instrumentation::events::{CLUSTER_EXPORT_GRANTED, CLUSTER_EXPORT_REFUSED, CLUSTER_GATE_BLOCKED};
use crate::policy::{GatePolicy, SessionContext, TransitStatus};
use crate::trace::TraceCollector;
use crate::utils::urn::Urn;
use crate::Frame;
use crate::TightBeamError;

/// Trace an export boundary outcome with the caller principal and relay
/// context.
///
/// Refusals emit [`CLUSTER_EXPORT_REFUSED`] and deciding grants emit
/// [`CLUSTER_EXPORT_GRANTED`], sharing one enrichment convention.
///
/// # Payload
///
/// The event value carries the `relayed` flag. When mutual TLS captured a
/// caller certificate, the payload is its fingerprint (matching the
/// peer-advertisement refusal convention). Anonymous sessions emit no payload.
fn trace_export_outcome(
	trace: &TraceCollector,
	outcome: Urn<'static>,
	session: &SessionContext,
	relayed: bool,
) -> Result<(), TightBeamError> {
	let fingerprint = session.peer_certificate().and_then(cert_fingerprint_id);
	let event = trace.event_with(outcome, &[], relayed)?;
	match fingerprint.as_ref() {
		Some(id) => event.with_payload(id.as_ref()).emit(),
		None => event.emit(),
	}

	Ok(())
}

/// Whether the frame signer is also a member of `tls.peer_trust`.
///
/// Peer membership wins across the whole trust plane. A signer the peer
/// store trusts is an external peer, so it must not act on the hive
/// plane even when `hive_trust` also trusts it.
fn signer_is_peer(config: &ClusterConfig, frame: &Frame) -> bool {
	config
		.tls
		.peer_trust
		.as_ref()
		.is_some_and(|trust| matches!(verify_frame_signature(trust.as_ref(), frame), TrustVerification::Verified))
}

impl ClusterConfig {
	/// Run configured [`GatePolicy`] instances with no audit side effects.
	pub(crate) fn policies_allow(&self, frame: Option<&Frame>, session: &SessionContext) -> Result<(), TransitStatus> {
		let config = self;

		for policy in config.policies.iter() {
			let status = GatePolicy::evaluate(policy.as_ref(), frame, session).normalized_verdict();
			if status != TransitStatus::Ok {
				return Err(status);
			}
		}

		Ok(())
	}

	/// Run collector gate policies before decoding the request envelope.
	///
	/// Each configured policy must return [`TransitStatus::Ok`], so the first
	/// refusal short-circuits dispatch.
	///
	/// - `frame`: request envelope when present; `None` for stream opens that carry no unary frame
	/// - `session`: caller identity and transport facts for the admitted connection
	/// - `trace`: collector that receives [`CLUSTER_GATE_BLOCKED`] on refusal
	pub(crate) fn evaluate_gates(
		&self,
		frame: Option<&Frame>,
		session: &SessionContext,
		trace: &TraceCollector,
	) -> Result<TransitStatus, TightBeamError> {
		let config = self;
		let Err(status) = config.policies_allow(frame, session) else {
			return Ok(TransitStatus::Ok);
		};

		trace.event(CLUSTER_GATE_BLOCKED)?.emit();

		Ok(status)
	}

	/// Enforce the export boundary on a resolved servlet target.
	///
	/// The verdict algebra lives in [`ExportPolicy`], read from live
	/// configuration so enforcement stays aligned with the advertise filter.
	/// This wrapper adds the audit plane.
	///
	/// 1. Run [`ExportPolicy::verdict`] (allowlist, grants, then deny gates).
	/// 2. Trace [`CLUSTER_EXPORT_REFUSED`] or [`CLUSTER_EXPORT_GRANTED`] with
	///    the caller certificate fingerprint and the relayed flag.
	///
	/// The granted event fires only when the full verdict passes, because a
	/// grant overridden by a deny gate did not decide the outcome.
	///
	/// - `target`: servlet type under enforcement
	/// - `session`: caller identity facts for the admitted connection
	/// - `relayed`: `true` when [`HopBudget::is_relayed`] marks the request as peer-relayed
	/// - `trace`: collector that receives the boundary audit events
	///
	/// # Call sites
	///
	/// - Unary work arm in [`super::dispatch`]
	/// - Streaming and duplex open handlers in [`super`]
	///
	/// # Sources
	///
	/// - CWE-285, improper authorization:
	///   <https://cwe.mitre.org/data/definitions/285.html>
	/// - ISO/IEC 27001:2022 A.8.15, logging:
	///   <https://www.iso.org/standard/82875.html>
	pub(crate) fn evaluate_export_gates(
		&self,
		target: &Urn<'_>,
		session: &SessionContext,
		relayed: bool,
		trace: &TraceCollector,
	) -> Result<TransitStatus, TightBeamError> {
		match ExportPolicy::from(self).verdict(target, session, relayed) {
			Ok(ExportDecision::Allowed) => Ok(TransitStatus::Ok),
			Ok(ExportDecision::Granted) => {
				trace_export_outcome(trace, CLUSTER_EXPORT_GRANTED, session, relayed)?;

				Ok(TransitStatus::Ok)
			}
			Err(status) => {
				trace_export_outcome(trace, CLUSTER_EXPORT_REFUSED, session, relayed)?;

				Ok(status)
			}
		}
	}

	/// Verify hive-origin control frames against `tls.hive_trust`.
	///
	/// - A missing trust store or a failed signature yields [`TransitStatus::PermissionDenied`].
	/// - A frame without a signature yields [`TransitStatus::Unauthenticated`].
	///
	/// A signer that `tls.peer_trust` also trusts is refused: peer membership
	/// wins, so an identity held by both stores never acts on the hive plane.
	///
	/// # Sources
	///
	/// - CWE-306, missing authentication for critical function:
	///   <https://cwe.mitre.org/data/definitions/306.html>
	pub(crate) fn verify_hive_origin(&self, frame: &Frame) -> TransitStatus {
		match self.tls.hive_trust.as_ref() {
			Some(trust) => match verify_frame_signature(trust.as_ref(), frame) {
				TrustVerification::Verified if signer_is_peer(self, frame) => TransitStatus::PermissionDenied,
				TrustVerification::Verified => TransitStatus::Ok,
				TrustVerification::MissingSignature => TransitStatus::Unauthenticated,
				_ => TransitStatus::PermissionDenied,
			},
			None => TransitStatus::PermissionDenied,
		}
	}

	/// Verify peer-origin control frames against `tls.peer_trust`.
	///
	/// - A missing trust store or a failed signature yields [`TransitStatus::PermissionDenied`].
	/// - A frame without a signature yields [`TransitStatus::Unauthenticated`].
	///
	/// # Sources
	///
	/// - CWE-306, missing authentication for critical function:
	///   <https://cwe.mitre.org/data/definitions/306.html>
	pub(crate) fn verify_peer_origin(&self, frame: &Frame) -> TransitStatus {
		match self.tls.peer_trust.as_ref() {
			Some(trust) => match verify_frame_signature(trust.as_ref(), frame) {
				TrustVerification::Verified => TransitStatus::Ok,
				TrustVerification::MissingSignature => TransitStatus::Unauthenticated,
				_ => TransitStatus::PermissionDenied,
			},
			None => TransitStatus::PermissionDenied,
		}
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use super::*;
	use crate::builder::frame::FrameBuilder;
	use crate::builder::TypeBuilder;
	use crate::colony::cluster::{
		CertificateSpec, ClusterTlsConfig, ExportGate, ExportGrant, StaticExportList, TrustPlanes,
	};
	use crate::colony::common::ColonyNamespace;
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
	use crate::crypto::sign::{secp256k1_signer_identifier, sign_canonical, SignatureAlgorithmIdentifier};
	use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
	use crate::crypto::x509::Certificate;
	use crate::der::oid::AssociatedOid;
	use crate::spki::AlgorithmIdentifierOwned;
	use crate::testing::{create_test_certificate, create_test_message, create_test_signing_key};
	use crate::Version;

	fn servlet(name: &str) -> Urn<'static> {
		ColonyNamespace::default()
			.servlet(name)
			.expect("test names satisfy the mint grammar")
	}

	/// Config exporting only "ping", so "ledger" needs a grant.
	fn exporting_config() -> ClusterConfig {
		let key: Secp256k1SigningKey = create_test_signing_key();
		let mut config = ClusterConfig::new(ClusterTlsConfig {
			certificate: CertificateSpec::Der(&[]),
			key: Arc::new(Secp256k1KeyProvider::from(key)),
			validators: Vec::new(),
			client_validators: Vec::new(),
			hive_trust: None,
			peer_trust: None,
		});
		config.peer.exported_types = Some(Arc::new(StaticExportList::new(vec![servlet("ping")])));

		config
	}

	struct GrantAll;

	impl ExportGrant for GrantAll {
		fn grants(&self, _target: &Urn<'_>, _session: &SessionContext, _relayed: bool) -> bool {
			true
		}
	}

	struct OriginOnlyGrant;

	impl ExportGrant for OriginOnlyGrant {
		fn grants(&self, _target: &Urn<'_>, _session: &SessionContext, relayed: bool) -> bool {
			!relayed
		}
	}

	struct IdentityGrant;

	impl ExportGrant for IdentityGrant {
		fn grants(&self, _target: &Urn<'_>, session: &SessionContext, _relayed: bool) -> bool {
			session.peer_public_key().is_some()
		}
	}

	struct DenyAllGate;

	impl ExportGate for DenyAllGate {
		fn evaluate(
			&self,
			_target: &Urn<'_>,
			_session: &SessionContext,
			_planes: &TrustPlanes<'_>,
			_relayed: bool,
		) -> TransitStatus {
			TransitStatus::PermissionDenied
		}
	}

	struct UnknownGate;

	impl ExportGate for UnknownGate {
		fn evaluate(
			&self,
			_target: &Urn<'_>,
			_session: &SessionContext,
			_planes: &TrustPlanes<'_>,
			_relayed: bool,
		) -> TransitStatus {
			TransitStatus::Unknown
		}
	}

	struct UnknownPolicy;

	impl GatePolicy for UnknownPolicy {
		fn evaluate(&self, _message: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
			TransitStatus::Unknown
		}
	}

	fn trust_of(cert: &Certificate) -> Arc<dyn CertificateTrust> {
		let store = CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
			.with_certificate(cert.clone())
			.expect("test certificates satisfy the trust builder")
			.build();
		Arc::new(store)
	}

	/// A control frame signed by `key` under the canonical convention.
	fn signed_control_frame(key: &Secp256k1SigningKey) -> Frame {
		let frame = FrameBuilder::from(Version::V1)
			.with_id("verify-origin")
			.with_order(1)
			.with_message(create_test_message(None))
			.build()
			.expect("test frame builds");

		let tbs = frame.to_tbs().expect("test frame encodes");
		let signature: Secp256k1Signature = sign_canonical::<Sha3_256, _>(key, &tbs).expect("test key signs");
		let sig_alg = AlgorithmIdentifierOwned { oid: Secp256k1Signature::ALGORITHM_OID, parameters: None };
		let digest_alg = AlgorithmIdentifierOwned { oid: Sha3_256::OID, parameters: None };
		let sid = secp256k1_signer_identifier(key.verifying_key()).expect("test key yields a signer id");

		frame
			.attach_signature(signature.to_bytes(), sig_alg, digest_alg, sid)
			.expect("test signature attaches")
	}

	#[test]
	fn grant_widens_unexported_target() -> Result<(), TightBeamError> {
		let mut config = exporting_config();
		config.export_grants.push(Arc::new(GrantAll));

		let verdict = config.evaluate_export_gates(
			&servlet("ledger"),
			&SessionContext::default(),
			false,
			&TraceCollector::default(),
		);
		assert_eq!(verdict?, TransitStatus::Ok);

		Ok(())
	}

	#[test]
	fn deny_gate_overrides_grant() -> Result<(), TightBeamError> {
		let mut config = exporting_config();
		config.export_grants.push(Arc::new(GrantAll));
		config.export_gates.push(Arc::new(DenyAllGate));

		let verdict = config.evaluate_export_gates(
			&servlet("ledger"),
			&SessionContext::default(),
			false,
			&TraceCollector::default(),
		);
		assert_eq!(verdict?, TransitStatus::PermissionDenied);

		Ok(())
	}

	#[test]
	fn anonymous_session_matches_no_identity_grant() -> Result<(), TightBeamError> {
		let mut config = exporting_config();
		config.export_grants.push(Arc::new(IdentityGrant));

		let verdict = config.evaluate_export_gates(
			&servlet("ledger"),
			&SessionContext::default(),
			false,
			&TraceCollector::default(),
		);

		assert_eq!(verdict?, TransitStatus::PermissionDenied);

		Ok(())
	}

	#[test]
	fn origin_only_grant_refuses_relayed_request() -> Result<(), TightBeamError> {
		let mut config = exporting_config();
		config.export_grants.push(Arc::new(OriginOnlyGrant));

		let verdict = config.evaluate_export_gates(
			&servlet("ledger"),
			&SessionContext::default(),
			true,
			&TraceCollector::default(),
		);
		assert_eq!(verdict?, TransitStatus::PermissionDenied);

		Ok(())
	}

	#[test]
	fn origin_only_grant_passes_origin_request() -> Result<(), TightBeamError> {
		let mut config = exporting_config();
		config.export_grants.push(Arc::new(OriginOnlyGrant));

		let verdict = config.evaluate_export_gates(
			&servlet("ledger"),
			&SessionContext::default(),
			false,
			&TraceCollector::default(),
		);
		assert_eq!(verdict?, TransitStatus::Ok);

		Ok(())
	}

	#[test]
	fn unknown_export_gate_verdict_normalizes_to_internal() -> Result<(), TightBeamError> {
		let mut config = exporting_config();
		config.export_gates.push(Arc::new(UnknownGate));

		let verdict = config.evaluate_export_gates(
			&servlet("ping"),
			&SessionContext::default(),
			false,
			&TraceCollector::default(),
		);
		assert_eq!(verdict?, TransitStatus::Internal);

		Ok(())
	}

	#[test]
	fn unknown_gate_policy_verdict_normalizes_to_internal() -> Result<(), TightBeamError> {
		let mut config = exporting_config();
		config.policies.push(Arc::new(UnknownPolicy));

		let verdict = config.evaluate_gates(None, &SessionContext::default(), &TraceCollector::default());
		assert_eq!(verdict?, TransitStatus::Internal);

		Ok(())
	}

	#[test]
	fn hive_origin_passes_hive_only_signer() {
		let key: Secp256k1SigningKey = create_test_signing_key();
		let frame = signed_control_frame(&key);
		let mut config = exporting_config();
		config.tls.hive_trust = Some(trust_of(&create_test_certificate(&key)));

		assert_eq!(config.verify_hive_origin(&frame), TransitStatus::Ok);
	}

	#[test]
	fn hive_origin_refuses_dual_anchored_signer() {
		let key: Secp256k1SigningKey = create_test_signing_key();
		let frame = signed_control_frame(&key);
		let cert = create_test_certificate(&key);
		let mut config = exporting_config();
		config.tls.hive_trust = Some(trust_of(&cert));
		config.tls.peer_trust = Some(trust_of(&cert));

		assert_eq!(config.verify_hive_origin(&frame), TransitStatus::PermissionDenied);
	}
}
