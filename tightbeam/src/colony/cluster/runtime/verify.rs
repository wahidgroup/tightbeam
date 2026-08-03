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
//! [`spent_relay_budget`] supplies the `relayed` flag. Verdict algebra and
//! posture warnings live in [`crate::colony::cluster::export`].
//!
//! # Origin and freshness
//!
//! [`verify_hive_origin`] and [`verify_peer_origin`] verify frame signatures
//! against the configured trust stores. [`verify_control_freshness`] rejects
//! stale or replayed signed control frames.

use crate::colony::cluster::runtime::bounds::GatewayReplayGuard;
use crate::colony::cluster::ClusterConfig;
use crate::colony::common::current_timestamp_ms;
use crate::colony::hive::{verify_frame_signature, TrustVerification};
use crate::constants::DEFAULT_HOP_BUDGET;
use crate::der::Encode;
use crate::instrumentation::events::CLUSTER_GATE_BLOCKED;
use crate::policy::{GatePolicy, SessionContext, TransitStatus};
use crate::trace::TraceCollector;
use crate::utils::urn::Urn;
use crate::Frame;

#[cfg(feature = "x509")]
mod x509 {
	pub(crate) use crate::colony::cluster::export::{ExportDecision, ExportPolicy};
	pub(crate) use crate::colony::cluster::peer::cert_fingerprint_id;
	pub(crate) use crate::instrumentation::events::{CLUSTER_EXPORT_GRANTED, CLUSTER_EXPORT_REFUSED};
}

#[cfg(feature = "x509")]
use x509::*;

/// Whether a request already spent relay budget.
///
/// A hop budget below the origin sentinel marks the request as relayed
/// through a peer gateway rather than from a direct client.
///
/// # Call sites
///
/// The unary work arm and the streaming/duplex open handlers derive the export
/// boundary's `relayed` flag through this predicate.
pub(crate) fn spent_relay_budget(hops_remaining: u8) -> bool {
	hops_remaining != DEFAULT_HOP_BUDGET
}

/// Run configured [`GatePolicy`] instances with no audit side effects.
pub(crate) fn policies_allow(
	frame: Option<&Frame>,
	session: &SessionContext,
	config: &ClusterConfig,
) -> Result<(), TransitStatus> {
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
/// - `frame`: request envelope when present; `None` for stream opens that carry
///   no unary frame
/// - `session`: caller identity and transport facts for the admitted connection
/// - `config`: live cluster configuration, including the policy list
/// - `trace`: collector that receives [`CLUSTER_GATE_BLOCKED`] on refusal
pub(crate) fn evaluate_gates(
	frame: Option<&Frame>,
	session: &SessionContext,
	config: &ClusterConfig,
	trace: &TraceCollector,
) -> Result<(), TransitStatus> {
	match policies_allow(frame, session, config) {
		Ok(()) => Ok(()),
		Err(status) => {
			trace.event(CLUSTER_GATE_BLOCKED).map_err(|_| status)?;
			Err(status)
		}
	}
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
/// - `relayed`: `true` when [`spent_relay_budget`] marks the request as
///   peer-relayed
/// - `config`: live cluster configuration, including export lists, grants,
///   and gates
/// - `trace`: collector that receives the boundary audit events
///
/// # Call sites
///
/// - Unary work arm in [`super::dispatch`]
/// - Streaming and duplex open handlers in [`super::gateway`]
///
/// # Sources
///
/// - CWE-285, improper authorization:
///   <https://cwe.mitre.org/data/definitions/285.html>
/// - ISO/IEC 27001:2022 A.8.15, logging:
///   <https://www.iso.org/standard/82875.html>
pub(crate) fn evaluate_export_gates(
	target: &Urn<'_>,
	session: &SessionContext,
	relayed: bool,
	config: &ClusterConfig,
	trace: &TraceCollector,
) -> Result<(), TransitStatus> {
	#[cfg(feature = "x509")]
	{
		match ExportPolicy::from(config).verdict(target, session, relayed) {
			Ok(ExportDecision::Allowed) => Ok(()),
			Ok(ExportDecision::Granted) => {
				trace_export_outcome(trace, CLUSTER_EXPORT_GRANTED, session, relayed);

				Ok(())
			}
			Err(status) => {
				trace_export_outcome(trace, CLUSTER_EXPORT_REFUSED, session, relayed);

				Err(status)
			}
		}
	}
	#[cfg(not(feature = "x509"))]
	{
		let _ = (target, session, relayed, config, trace);
		Ok(())
	}
}

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
#[cfg(feature = "x509")]
fn trace_export_outcome(trace: &TraceCollector, outcome: Urn<'static>, session: &SessionContext, relayed: bool) {
	let fingerprint = session.peer_certificate().and_then(cert_fingerprint_id);
	if let Ok(event) = trace.event_with(outcome, &[], relayed) {
		match fingerprint.as_ref() {
			Some(id) => event.with_payload(id.as_ref()).emit(),
			None => event.emit(),
		}
	}
}

/// Whether the frame signer is also a member of `tls.peer_trust`.
///
/// Peer membership wins across the whole trust plane. A signer the peer
/// store trusts is an external peer, so it must not act on the hive
/// plane even when `hive_trust` also trusts it.
#[cfg(feature = "x509")]
fn signer_is_peer(config: &ClusterConfig, frame: &Frame) -> bool {
	config
		.tls
		.peer_trust
		.as_ref()
		.is_some_and(|trust| matches!(verify_frame_signature(trust.as_ref(), frame), TrustVerification::Verified))
}

/// Verify hive-origin control frames against `tls.hive_trust`.
///
/// A missing trust store or a failed signature yields
/// [`TransitStatus::PermissionDenied`]. A frame without a signature yields
/// [`TransitStatus::Unauthenticated`]. A signer that `tls.peer_trust`
/// also trusts is refused: peer membership wins, so an identity held by
/// both stores never acts on the hive plane.
///
/// # Sources
///
/// - CWE-306, missing authentication for critical function:
///   <https://cwe.mitre.org/data/definitions/306.html>
pub(crate) fn verify_hive_origin(config: &ClusterConfig, frame: &Frame) -> TransitStatus {
	#[cfg(feature = "x509")]
	{
		match config.tls.hive_trust.as_ref() {
			Some(trust) => match verify_frame_signature(trust.as_ref(), frame) {
				TrustVerification::Verified if signer_is_peer(config, frame) => TransitStatus::PermissionDenied,
				TrustVerification::Verified => TransitStatus::Ok,
				TrustVerification::MissingSignature => TransitStatus::Unauthenticated,
				_ => TransitStatus::PermissionDenied,
			},
			None => TransitStatus::PermissionDenied,
		}
	}
	#[cfg(not(feature = "x509"))]
	{
		let _ = (config, frame);
		TransitStatus::Ok
	}
}

/// Verify peer-origin control frames against `tls.peer_trust`.
///
/// A missing trust store or a failed signature yields
/// [`TransitStatus::PermissionDenied`]. A frame without a signature yields
/// [`TransitStatus::Unauthenticated`].
///
/// # Sources
///
/// - CWE-306, missing authentication for critical function:
///   <https://cwe.mitre.org/data/definitions/306.html>
pub(crate) fn verify_peer_origin(config: &ClusterConfig, frame: &Frame) -> TransitStatus {
	#[cfg(feature = "x509")]
	{
		match config.tls.peer_trust.as_ref() {
			Some(trust) => match verify_frame_signature(trust.as_ref(), frame) {
				TrustVerification::Verified => TransitStatus::Ok,
				TrustVerification::MissingSignature => TransitStatus::Unauthenticated,
				_ => TransitStatus::PermissionDenied,
			},
			None => TransitStatus::PermissionDenied,
		}
	}
	#[cfg(not(feature = "x509"))]
	{
		let _ = (config, frame);
		TransitStatus::Ok
	}
}

/// Reject stale or replayed signed control frames.
///
/// Freshness binds `metadata.order` and the signer signature through the
/// gateway replay guard.
///
/// The checks apply in order:
///
/// 1. Reject when `metadata.order` falls outside the freshness window.
/// 2. Require non-repudiation (`signer_info`) on the frame.
/// 3. Insert the signature in the replay guard; refuse duplicates.
///
/// # Sources
///
/// - CWE-294, authentication bypass by capture-replay:
///   <https://cwe.mitre.org/data/definitions/294.html>
pub(crate) fn verify_control_freshness(frame: &Frame, replay_guard: &GatewayReplayGuard) -> TransitStatus {
	#[cfg(feature = "x509")]
	{
		let now = current_timestamp_ms();
		if !replay_guard.is_fresh(frame.metadata.order, now) {
			return TransitStatus::PermissionDenied;
		}

		let Some(signer_info) = frame.nonrepudiation.as_ref() else {
			return TransitStatus::Unauthenticated;
		};
		let Ok(signer_id) = Encode::to_der(&signer_info.sid) else {
			return TransitStatus::PermissionDenied;
		};
		if !replay_guard.check_and_insert(&signer_id, signer_info.signature.as_bytes(), now) {
			return TransitStatus::PermissionDenied;
		}

		TransitStatus::Ok
	}
	#[cfg(not(feature = "x509"))]
	{
		let _ = (frame, replay_guard);
		TransitStatus::Ok
	}
}

#[cfg(all(test, feature = "x509"))]
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
	fn grant_widens_unexported_target() {
		let mut config = exporting_config();
		config.export_grants.push(Arc::new(GrantAll));

		let verdict = evaluate_export_gates(
			&servlet("ledger"),
			&SessionContext::default(),
			false,
			&config,
			&TraceCollector::default(),
		);
		assert_eq!(verdict, Ok(()));
	}

	#[test]
	fn deny_gate_overrides_grant() {
		let mut config = exporting_config();
		config.export_grants.push(Arc::new(GrantAll));
		config.export_gates.push(Arc::new(DenyAllGate));

		let verdict = evaluate_export_gates(
			&servlet("ledger"),
			&SessionContext::default(),
			false,
			&config,
			&TraceCollector::default(),
		);
		assert_eq!(verdict, Err(TransitStatus::PermissionDenied));
	}

	#[test]
	fn anonymous_session_matches_no_identity_grant() {
		let mut config = exporting_config();
		config.export_grants.push(Arc::new(IdentityGrant));

		let verdict = evaluate_export_gates(
			&servlet("ledger"),
			&SessionContext::default(),
			false,
			&config,
			&TraceCollector::default(),
		);

		assert_eq!(verdict, Err(TransitStatus::PermissionDenied));
	}

	#[test]
	fn origin_only_grant_refuses_relayed_request() {
		let mut config = exporting_config();
		config.export_grants.push(Arc::new(OriginOnlyGrant));

		let verdict = evaluate_export_gates(
			&servlet("ledger"),
			&SessionContext::default(),
			true,
			&config,
			&TraceCollector::default(),
		);
		assert_eq!(verdict, Err(TransitStatus::PermissionDenied));
	}

	#[test]
	fn origin_only_grant_passes_origin_request() {
		let mut config = exporting_config();
		config.export_grants.push(Arc::new(OriginOnlyGrant));

		let verdict = evaluate_export_gates(
			&servlet("ledger"),
			&SessionContext::default(),
			false,
			&config,
			&TraceCollector::default(),
		);
		assert_eq!(verdict, Ok(()));
	}

	#[test]
	fn unknown_export_gate_verdict_normalizes_to_internal() {
		let mut config = exporting_config();
		config.export_gates.push(Arc::new(UnknownGate));

		let verdict = evaluate_export_gates(
			&servlet("ping"),
			&SessionContext::default(),
			false,
			&config,
			&TraceCollector::default(),
		);

		assert_eq!(verdict, Err(TransitStatus::Internal));
	}

	#[test]
	fn unknown_gate_policy_verdict_normalizes_to_internal() {
		let mut config = exporting_config();
		config.policies.push(Arc::new(UnknownPolicy));

		let verdict = evaluate_gates(None, &SessionContext::default(), &config, &TraceCollector::default());
		assert_eq!(verdict, Err(TransitStatus::Internal));
	}

	#[test]
	fn hive_origin_passes_hive_only_signer() {
		let key: Secp256k1SigningKey = create_test_signing_key();
		let frame = signed_control_frame(&key);
		let mut config = exporting_config();
		config.tls.hive_trust = Some(trust_of(&create_test_certificate(&key)));

		assert_eq!(verify_hive_origin(&config, &frame), TransitStatus::Ok);
	}

	#[test]
	fn hive_origin_refuses_dual_anchored_signer() {
		let key: Secp256k1SigningKey = create_test_signing_key();
		let frame = signed_control_frame(&key);
		let cert = create_test_certificate(&key);
		let mut config = exporting_config();
		config.tls.hive_trust = Some(trust_of(&cert));
		config.tls.peer_trust = Some(trust_of(&cert));

		assert_eq!(verify_hive_origin(&config, &frame), TransitStatus::PermissionDenied);
	}
}
