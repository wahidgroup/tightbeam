//! Origin, freshness, and export-boundary checks for cluster control traffic.
//!
//! The gateway runs these predicates before or beside request dispatch.
//! Gate policies evaluate on every admitted session. The export boundary
//! evaluates once a servlet target is known. Origin and freshness checks
//! apply to signed control frames on the hive and peer planes.
//!
//! # Gate policies
//!
//! [`ClusterConfig::evaluate_gates`] runs configured [`GatePolicy`] instances before the
//! request envelope is decoded. Stream opens carry no request frame, so they
//! pass `None` for the frame argument.
//!
//! # Export boundary
//!
//! [`ClusterConfig::evaluate_export_gates`] runs [`ExportPolicy`] where the servlet target
//! is resolved: allowlist, then grants, then deny gates.
//! [`HopBudget::is_relayed`] supplies the `relayed` flag. Verdict algebra and
//! posture warnings live in [`crate::colony::cluster::export`].
//!
//! # Origin and freshness
//!
//! [`ClusterConfig::verify_hive`] and [`ClusterConfig::verify_peer`] verify one
//! control frame and return [`VerifiedControlFrame`]. [`GatewayReplayGuard`] rejects
//! stale or replayed signed control frames.
//!
//! [`GatewayReplayGuard`]: super::freshness::GatewayReplayGuard

use crate::colony::cluster::export::{ExportDecision, ExportPolicy, Party, TrustPlanes};
use crate::colony::cluster::peer::ColonyCertificate;
use crate::colony::cluster::{ClusterConfig, SharedId};
use crate::crypto::x509::store::TrustVerification;
use crate::crypto::x509::Certificate;
use crate::instrumentation::events::{CLUSTER_EXPORT_GRANTED, CLUSTER_EXPORT_REFUSED, CLUSTER_GATE_BLOCKED};
use crate::policy::{GatePolicy, SessionContext, TransitStatus};
use crate::trace::TraceCollector;
use crate::utils::urn::Urn;
use crate::Frame;
use crate::TightBeamError;

/// One caller under export-boundary audit.
///
/// A refusal and a deciding grant describe the same caller, so they share
/// one enrichment convention rather than each assembling its own.
struct ExportAudit<'a> {
	trace: &'a TraceCollector,
	session: &'a SessionContext,
	relayed: bool,
}

impl ExportAudit<'_> {
	/// Emit `outcome` for this caller.
	///
	/// The event value carries the `relayed` flag. Where mutual TLS
	/// captured a caller certificate, the payload is its fingerprint,
	/// matching the peer-advertisement refusal convention. An anonymous
	/// session emits no payload.
	fn record(&self, outcome: Urn<'static>) -> Result<(), TightBeamError> {
		let fingerprint = self.session.peer_certificate().and_then(ColonyCertificate::fingerprint_id);
		let event = self.trace.event_with(outcome, &[], self.relayed)?;
		match fingerprint.as_ref() {
			Some(id) => event.with_payload(id.as_ref()).emit(),
			None => event.emit(),
		}

		Ok(())
	}
}

/// Owned slate key minted with [`VerifiedControlFrame`].
///
/// Only [`ClusterConfig::verify_plane`] constructs this. Gossip may
/// carry the id across `.await` without the borrowed certificate, and
/// a bare [`SharedId`] cannot stand in for it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VerifiedSignerId(SharedId);

impl VerifiedSignerId {
	/// Borrow the slate key for registry and audit payloads.
	#[must_use]
	pub(crate) fn as_shared(&self) -> &SharedId {
		&self.0
	}
}

/// One verified inbound control frame.
///
/// Minted only by [`ClusterConfig::verify_hive`] or
/// [`ClusterConfig::verify_peer`]. The signature check runs once.
/// [`Party`] comes from [`TrustPlanes::classify`] on the certificate
/// that check resolved, so a later step does not verify or look the
/// signer up again.
pub(crate) struct VerifiedControlFrame<'a> {
	frame: &'a Frame,
	signer_cert: &'a Certificate,
	party: Party,
	fingerprint: VerifiedSignerId,
}

impl<'a> VerifiedControlFrame<'a> {
	/// The frame this parse verified.
	#[must_use]
	pub(crate) fn frame(&self) -> &'a Frame {
		self.frame
	}

	/// Certificate the signature verified against.
	#[must_use]
	pub(crate) fn signer_cert(&self) -> &'a Certificate {
		self.signer_cert
	}

	/// Plane membership of [`Self::signer_cert`].
	#[must_use]
	pub(crate) fn party(&self) -> Party {
		self.party
	}

	/// Slate key for [`Self::signer_cert`].
	#[must_use]
	pub(crate) fn fingerprint(&self) -> VerifiedSignerId {
		self.fingerprint.clone()
	}
}

impl ClusterConfig {
	/// Verify `frame` once on `required` and classify the resolved certificate.
	///
	/// Peer membership wins: a public key enrolled in `tls.peer_trust`
	/// is [`Party::Peer`], so a hive-plane parse refuses it even when the
	/// presented certificate object lives only in `hive_trust`. A missing
	/// store or a failed signature refuses. A frame without a signature
	/// is unauthenticated.
	fn verify_plane<'a>(
		&'a self,
		frame: &'a Frame,
		required: Party,
	) -> Result<VerifiedControlFrame<'a>, TransitStatus> {
		let store = match required {
			Party::FirstParty => self.tls.hive_trust.as_deref(),
			Party::Peer => self.tls.peer_trust.as_deref(),
			Party::Untrusted => return Err(TransitStatus::PermissionDenied),
		};
		let Some(trust) = store else {
			return Err(TransitStatus::PermissionDenied);
		};
		let signer_cert = match trust.verify_frame(frame) {
			TrustVerification::Verified(cert) => cert,
			TrustVerification::MissingSignature => return Err(TransitStatus::Unauthenticated),
			TrustVerification::UnknownSigner | TrustVerification::Invalid => {
				return Err(TransitStatus::PermissionDenied);
			}
		};
		let party = TrustPlanes::from(&self.tls).classify(Some(signer_cert));
		if party != required {
			return Err(TransitStatus::PermissionDenied);
		}
		let fingerprint = signer_cert
			.fingerprint_id()
			.map(VerifiedSignerId)
			.ok_or(TransitStatus::PermissionDenied)?;

		Ok(VerifiedControlFrame { frame, signer_cert, party, fingerprint })
	}

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
		let audit = ExportAudit { trace, session, relayed };
		match ExportPolicy::from(self).verdict(target, session, relayed) {
			Ok(ExportDecision::Allowed) => Ok(TransitStatus::Ok),
			Ok(ExportDecision::Granted) => {
				audit.record(CLUSTER_EXPORT_GRANTED)?;

				Ok(TransitStatus::Ok)
			}
			Err(status) => {
				audit.record(CLUSTER_EXPORT_REFUSED)?;

				Ok(status)
			}
		}
	}

	/// Verify one hive-plane control frame.
	///
	/// The result carries the signer certificate and [`Party::FirstParty`].
	/// A public key that `tls.peer_trust` also enrolls is [`Party::Peer`]
	/// and is refused: peer membership wins by key identity, so a rotated
	/// certificate for a peer key never acts on the hive plane.
	///
	/// # Sources
	///
	/// - CWE-306, missing authentication for critical function:
	///   <https://cwe.mitre.org/data/definitions/306.html>
	pub(crate) fn verify_hive<'a>(&'a self, frame: &'a Frame) -> Result<VerifiedControlFrame<'a>, TransitStatus> {
		self.verify_plane(frame, Party::FirstParty)
	}

	/// Verify one peer-plane control frame.
	///
	/// The result carries the signer certificate and [`Party::Peer`].
	///
	/// # Sources
	///
	/// - CWE-306, missing authentication for critical function:
	///   <https://cwe.mitre.org/data/definitions/306.html>
	pub(crate) fn verify_peer<'a>(&'a self, frame: &'a Frame) -> Result<VerifiedControlFrame<'a>, TransitStatus> {
		self.verify_plane(frame, Party::Peer)
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
	use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, CertificateTrustStore, TrustBuilder};
	use crate::crypto::x509::Certificate;
	use crate::der::oid::AssociatedOid;
	use crate::spki::AlgorithmIdentifierOwned;
	use crate::testing::{TestCertificate, TestKey, TestMessage};
	use crate::Version;

	fn servlet(name: &(impl AsRef<str> + ?Sized)) -> Urn<'static> {
		let name = name.as_ref();
		ColonyNamespace::default()
			.servlet(name)
			.expect("test names satisfy the mint grammar")
	}

	/// Config exporting only "ping", so "ledger" needs a grant.
	fn exporting_config() -> ClusterConfig {
		let key: Secp256k1SigningKey = TestKey::signing();
		let mut config = ClusterConfig::new(
			ClusterTlsConfig::new(
				CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key))),
				Arc::new(Secp256k1KeyProvider::from(key)),
			)
			.expect("the test certificate must decode"),
		);
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
		let store = CertificateTrustBuilder::from(Secp256k1Policy)
			.with_certificate(cert.clone())
			.expect("test certificates satisfy the trust builder")
			.build();
		Arc::new(store)
	}

	/// A control frame signed by `key` under the canonical convention.
	fn signed_control_frame(key: &Secp256k1SigningKey) -> Frame {
		let mut frame = FrameBuilder::from(Version::V1)
			.with_id("verify-origin")
			.with_order(1)
			.with_message(TestMessage::sample(None))
			.build()
			.expect("test frame builds");

		let tbs = frame.to_tbs().expect("test frame encodes");
		let signature: Secp256k1Signature = sign_canonical::<Sha3_256, _>(key, &tbs).expect("test key signs");
		let sig_alg = AlgorithmIdentifierOwned { oid: Secp256k1Signature::ALGORITHM_OID, parameters: None };
		let digest_alg = AlgorithmIdentifierOwned { oid: Sha3_256::OID, parameters: None };
		let sid = secp256k1_signer_identifier(key.verifying_key()).expect("test key yields a signer id");

		frame
			.attach_signature(signature.to_bytes(), sig_alg, digest_alg, sid)
			.expect("test signature attaches");
		frame
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
		let key: Secp256k1SigningKey = TestKey::signing();
		let frame = signed_control_frame(&key);
		let cert = TestCertificate::self_signed(&key);

		let mut config = exporting_config();
		config.tls.hive_trust = Some(trust_of(&cert));

		let verified = config.verify_hive(&frame);
		assert!(matches!(
			verified,
			Ok(ref proof)
				if proof.party() == Party::FirstParty
					&& proof.frame().metadata().id() == frame.metadata().id()
					&& CertificateTrustStore::to_fingerprint::<Sha3_256>(proof.signer_cert()).ok()
						== CertificateTrustStore::to_fingerprint::<Sha3_256>(&cert).ok()
		));
	}

	#[test]
	fn hive_origin_refuses_dual_anchored_signer() {
		let key: Secp256k1SigningKey = TestKey::signing();
		let frame = signed_control_frame(&key);
		let cert = TestCertificate::self_signed(&key);

		let mut config = exporting_config();
		config.tls.hive_trust = Some(trust_of(&cert));
		config.tls.peer_trust = Some(trust_of(&cert));
		assert!(matches!(config.verify_hive(&frame), Err(TransitStatus::PermissionDenied)));
	}

	#[test]
	fn hive_origin_refuses_peer_key_under_rotated_certificate() {
		let key: Secp256k1SigningKey = TestKey::signing();
		let frame = signed_control_frame(&key);
		let hive_cert = TestCertificate::with_cn_and_uri_sans(&key, "hive", &["urn:tightbeam:colony:test"]);
		let peer_cert = TestCertificate::with_cn_and_uri_sans(&key, "peer", &["urn:tightbeam:colony:test"]);

		let mut config = exporting_config();
		config.tls.hive_trust = Some(trust_of(&hive_cert));
		config.tls.peer_trust = Some(trust_of(&peer_cert));
		assert!(matches!(config.verify_hive(&frame), Err(TransitStatus::PermissionDenied)));
	}

	#[test]
	fn peer_origin_accepts_dual_anchored_signer() {
		let key: Secp256k1SigningKey = TestKey::signing();
		let frame = signed_control_frame(&key);
		let cert = TestCertificate::self_signed(&key);

		let mut config = exporting_config();
		config.tls.hive_trust = Some(trust_of(&cert));
		config.tls.peer_trust = Some(trust_of(&cert));
		assert!(matches!(config.verify_peer(&frame), Ok(verified) if verified.party() == Party::Peer));
	}
}
