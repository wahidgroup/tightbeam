//! Origin, freshness, and export-boundary checks for cluster control traffic.
//!
//! The gateway runs these predicates before or beside request dispatch:
//!
//! - Gate policies evaluate on every admitted session.
//! - The export boundary evaluates once a servlet target is known.
//! - Origin and freshness checks apply to signed control frames on the hive and peer planes.
//!
//! # Gate policies
//!
//! [`ClusterConfig::evaluate_gates`] runs configured [`GatePolicy`] instances
//! before the request envelope is decoded. Stream opens carry no request frame,
//! so they pass `None` for the frame argument.
//!
//! # Export boundary
//!
//! [`ClusterConfig::evaluate_export_gates`] runs [`ExportPolicy`] where the
//! servlet target is resolved: allowlist, then grants, then deny gates.
//! [`HopBudget::is_relayed`] supplies the `relayed` flag. Verdict algebra and
//! posture warnings live in [`crate::colony::cluster::export`].
//!
//! # Origin and freshness
//!
//! [`ClusterConfig::verify_hive`] and [`ClusterConfig::verify_peer`] verify one
//! control frame and return [`VerifiedControlFrame`]. [`GatewayReplayGuard`]
//! rejects stale or replayed signed control frames.
//!
//! [`GatewayReplayGuard`]: super::freshness::GatewayReplayGuard

use crate::colony::cluster::export::{ExportDecision, ExportPolicy, Party, TrustPlanes};
use crate::colony::cluster::peer::ColonyCertificate;
use crate::colony::cluster::runtime::gossip_tasks::{GossipOrigin, GossipPipelineCtx};
use crate::colony::cluster::runtime::LoopFault;
use crate::colony::cluster::{ClusterConfig, SharedId};
use crate::crypto::sign::VerifiedSignature;
use crate::crypto::x509::store::TrustVerification;
use crate::crypto::x509::Certificate;
use crate::instrumentation::events::{
	CLUSTER_EXPORT_GRANTED, CLUSTER_EXPORT_REFUSED, CLUSTER_GATE_BLOCKED, CLUSTER_GOSSIP_ORIGIN_UNKNOWN,
};
use crate::policy::{GatePolicy, SessionContext, TransitStatus};
use crate::trace::TraceCollector;
use crate::transport::Protocol;
use crate::urn::Urn;
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
	/// session emits the event alone.
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

/// The owned slate key created with [`VerifiedControlFrame`].
///
/// Only [`ClusterConfig::verify_plane`] constructs this. Gossip may carry the
/// id across `.await` without the borrowed certificate, and the newtype keeps
/// it distinct from a bare [`SharedId`].
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VerifiedSignerId(SharedId);

impl VerifiedSignerId {
	/// Borrow the slate key for registry and audit payloads.
	#[must_use]
	pub(crate) fn as_shared(&self) -> &SharedId {
		&self.0
	}

	/// Take the slate key for a registry entry that owns it.
	#[must_use]
	pub(crate) fn into_shared(self) -> SharedId {
		self.0
	}
}

/// Why a control frame failed verification on its plane.
///
/// The trust store tells an unknown signer from a forged signature. This type
/// carries that verdict past the parse, so a caller that settles a refusal
/// reads what the store said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyRefusal {
	/// The frame carries no signature.
	Unsigned,
	/// The plane's trust store holds no certificate for the signer.
	UnknownSigner,
	/// The signer is trusted, and the signature fails verification.
	Forged,
	/// The signer belongs to another plane than the one the frame arrived on.
	WrongPlane,
	/// The plane has no trust store to verify against.
	NoStore,
	/// The signer certificate yields no fingerprint to key its slate by.
	Unidentifiable,
}

impl From<VerifyRefusal> for TransitStatus {
	/// The status a refused frame is answered with.
	///
	/// A frame with no signature is unauthenticated. Every other refusal
	/// names a signer this plane does not admit.
	fn from(refusal: VerifyRefusal) -> Self {
		match refusal {
			VerifyRefusal::Unsigned => Self::Unauthenticated,
			VerifyRefusal::UnknownSigner
			| VerifyRefusal::Forged
			| VerifyRefusal::WrongPlane
			| VerifyRefusal::NoStore
			| VerifyRefusal::Unidentifiable => Self::PermissionDenied,
		}
	}
}

impl VerifyRefusal {
	/// Settles a refused rumor origin for the relay that carried the rumor,
	/// and returns the status the relay is answered with.
	///
	/// Trust stores need not agree, so an origin this gateway does not hold
	/// is the edge of a subnet and no fault of the relay.
	///
	/// - [`Self::UnknownSigner`] drops the rumor and spends one token of the
	///   relay's own rate bucket, so a relay that sends rumors under made-up
	///   origins is bounded by the budget its own rumors draw on (CWE-770).
	/// - With a token it answers [`TransitStatus::Unauthenticated`], which
	///   tells the relay to stop offering that origin here. With the bucket
	///   empty it answers [`TransitStatus::ResourceExhausted`].
	/// - Every other refusal is a rumor the relay should have refused itself, so the relay is scored.
	/// - `frame` is the relay's own signed frame, whose signer keys that
	///   bucket. A frame that names no signer has no bucket to spend, so it is
	///   scored too.
	///
	/// # Errors
	///
	/// - [`LoopFault::Registry`] -- the route registry is poisoned.
	/// - [`LoopFault::Runtime`] -- the trace refused the event.
	pub(crate) fn settle_origin<P: Protocol>(
		self,
		pipeline: &GossipPipelineCtx<P>,
		frame: &Frame,
		relay: &VerifiedSignerId,
	) -> Result<TransitStatus, LoopFault> {
		match (self, frame.signer_id()) {
			(Self::UnknownSigner, Some(relay_key)) => {
				let now = pipeline.config.clock.unix();
				match pipeline.config.gossip.admission.allow(&relay_key, now) {
					Ok(true) => {
						let event = pipeline.trace.event(CLUSTER_GOSSIP_ORIGIN_UNKNOWN)?;
						event.with_payload(relay.as_shared().as_ref()).emit();

						Ok(TransitStatus::Unauthenticated)
					}
					Ok(false) => Ok(TransitStatus::ResourceExhausted),
					Err(_) => Ok(TransitStatus::Unavailable),
				}
			}
			(Self::UnknownSigner, None)
			| (Self::Unsigned | Self::Forged | Self::WrongPlane | Self::NoStore | Self::Unidentifiable, _) => {
				pipeline.weaken_invalid_relay(GossipOrigin::Relay, Some(relay))?;

				Ok(self.into())
			}
		}
	}
}

/// One verified inbound control frame.
///
/// Only [`ClusterConfig::verify_hive`] or [`ClusterConfig::verify_peer`]
/// creates one. The signature check runs once. [`Party`] comes from
/// [`TrustPlanes::classify`] on the certificate that check resolved, so a
/// later step reuses this verification and this signer lookup.
pub(crate) struct VerifiedControlFrame<'a> {
	frame: &'a Frame,
	signer_cert: &'a Certificate,
	signature: VerifiedSignature,
	party: Party,
	fingerprint: VerifiedSignerId,
}

impl<'a> VerifiedControlFrame<'a> {
	/// The frame this parse verified.
	#[must_use]
	pub(crate) fn frame(&self) -> &'a Frame {
		self.frame
	}

	/// The certificate the signature verified against.
	#[must_use]
	pub(crate) fn signer_cert(&self) -> &'a Certificate {
		self.signer_cert
	}

	/// The signature that verified, the frame's replay key.
	#[must_use]
	pub(crate) fn signature(&self) -> &VerifiedSignature {
		&self.signature
	}

	/// Give up the signature that verified, so it moves rather than copies.
	#[must_use]
	pub(crate) fn into_signature(self) -> VerifiedSignature {
		self.signature
	}

	/// The plane membership of [`Self::signer_cert`].
	#[must_use]
	pub(crate) fn party(&self) -> Party {
		self.party
	}

	/// The slate key for [`Self::signer_cert`].
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
	) -> Result<VerifiedControlFrame<'a>, VerifyRefusal> {
		let store = match required {
			Party::FirstParty => self.tls.hive_trust.as_deref(),
			Party::Peer => self.tls.peer_trust.as_deref(),
			Party::Untrusted => return Err(VerifyRefusal::NoStore),
		};
		let Some(trust) = store else {
			return Err(VerifyRefusal::NoStore);
		};
		let (signer, signature) = match trust.verify_frame(frame) {
			TrustVerification::Verified(signer, signature) => (signer, signature),
			TrustVerification::MissingSignature => return Err(VerifyRefusal::Unsigned),
			TrustVerification::UnknownSigner => return Err(VerifyRefusal::UnknownSigner),
			TrustVerification::Invalid => return Err(VerifyRefusal::Forged),
		};

		let signer_cert = signer.certificate().as_ref();

		let party = TrustPlanes::from(&self.tls).classify(Some(signer_cert));
		if party != required {
			return Err(VerifyRefusal::WrongPlane);
		}

		// A peer's slate key is its name under `Self::peer_identity`, the rule
		// a hop names its answer by, so a route keys the gateway a hop admits.
		let fingerprint = match party {
			Party::Peer => self.peer_identity(signer_cert),
			Party::FirstParty | Party::Untrusted => signer_cert.fingerprint_id(),
		};

		let fingerprint = fingerprint.map(VerifiedSignerId).ok_or(VerifyRefusal::Unidentifiable)?;
		Ok(VerifiedControlFrame { frame, signer_cert, signature, party, fingerprint })
	}

	/// The slate key of the gateway that holds `cert`'s key, the one name a
	/// peer gateway goes by: the fingerprint of the certificate that
	/// [`ClusterTlsConfig::peer_dial_trust`] holds for that key.
	///
	/// - A route keys the gateway that signed its advertisement by it.
	/// - A hop names the certificate its answer presents by it.
	/// - The discovery table counts a signer by it.
	/// - A gateway that rotated its certificate under one key keeps one name.
	///
	/// It is `None` with no such store, or for a key outside it.
	///
	/// [`ClusterTlsConfig::peer_dial_trust`]: crate::colony::cluster::ClusterTlsConfig::peer_dial_trust
	pub(crate) fn peer_identity(&self, cert: &Certificate) -> Option<SharedId> {
		let trust = self.tls.peer_dial_trust()?;
		let enrolled = trust.enrolled_certificate(cert)?;
		enrolled.fingerprint_id()
	}

	/// Run configured [`GatePolicy`] instances and leave the audit event to
	/// the caller.
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
	/// - `frame`: request envelope when present, or `None` for stream opens that carry no unary frame
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
	/// - CWE-285, improper authorization: <https://cwe.mitre.org/data/definitions/285.html>
	/// - ISO/IEC 27001:2022 A.8.15, logging: <https://www.iso.org/standard/82875.html>
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
	pub(crate) fn verify_hive<'a>(&'a self, frame: &'a Frame) -> Result<VerifiedControlFrame<'a>, VerifyRefusal> {
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
	pub(crate) fn verify_peer<'a>(&'a self, frame: &'a Frame) -> Result<VerifiedControlFrame<'a>, VerifyRefusal> {
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
	use crate::crypto::sign::PrehashSigner;
	use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, CertificateTrustStore, TrustBuilder};
	use crate::crypto::x509::Certificate;
	use crate::tb_cases;
	use crate::testing::{TestCertificate, TestKey, TestMessage};
	use crate::Version;

	fn servlet(name: &(impl AsRef<str> + ?Sized)) -> Urn<'static> {
		let name = name.as_ref();
		ColonyNamespace::default()
			.servlet(name)
			.expect("test names satisfy the mint grammar")
	}

	/// A config that exports only "ping", so "ledger" needs a grant.
	fn exporting_config() -> ClusterConfig {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
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

	/// A peer gateway key, distinct from the fixed key the config presents.
	fn peer_key() -> Secp256k1SigningKey {
		Secp256k1SigningKey::from_bytes(&[2u8; 32].into()).expect("the fixture scalar is a valid key")
	}

	/// A config whose peer plane enrolls `enrolled` alone.
	fn config_enrolling(enrolled: &Certificate) -> ClusterConfig {
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_certificate(enrolled.clone());
		let store = builder.expect("the test certificate satisfies the trust builder").build();

		let mut config = exporting_config();
		config.tls.peer_trust = Some(Arc::new(store));
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
			session.peer_key().is_some()
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
		let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(cert.clone())
			.expect("test certificates satisfy the trust builder")
			.build();
		Arc::new(store)
	}

	/// A control frame signed by `key` under the canonical convention.
	fn signed_control_frame(key: &Secp256k1SigningKey) -> Frame {
		control_frame_claiming(key, key)
	}

	/// A control frame signed with `signer` that names `claimed` as its signer.
	fn control_frame_claiming(signer: &Secp256k1SigningKey, claimed: &Secp256k1SigningKey) -> Frame {
		let mut frame = FrameBuilder::from(Version::V1)
			.with_id("verify-origin")
			.with_order(1)
			.with_message(TestMessage::sample(None))
			.build()
			.expect("test frame builds");

		let claimed_certificate = TestCertificate::self_signed(claimed);
		let draft = frame.signing_draft::<Secp256k1Signature>(&claimed_certificate);
		let draft = draft.expect("test frame drafts its signature");
		let signature: Secp256k1Signature = signer.sign_prehash(draft.prehash()).expect("test key signs");
		let signer_info = draft.complete(signature.to_bytes(), None).expect("the signature completes");

		frame.attach_signer_info(signer_info).expect("test signature attaches");
		frame
	}

	/// A gateway that rotated its certificate under one key keeps the slate
	/// key of the certificate the peer plane enrolled.
	#[test]
	fn peer_identity_names_a_rotated_certificate_by_its_enrolled_one() {
		let key = peer_key();
		let enrolled = TestCertificate::with_cn_and_uri_sans(&key, "enrolled", &["urn:tightbeam:colony:test"]);
		let rotated = TestCertificate::with_cn_and_uri_sans(&key, "rotated", &["urn:tightbeam:colony:test"]);
		let config = config_enrolling(&enrolled);

		let named = config.peer_identity(&rotated);
		assert_eq!(named, enrolled.fingerprint_id());
		assert_ne!(named, rotated.fingerprint_id());
	}

	/// A certificate whose key the peer plane does not hold names no gateway,
	/// so a bound hop it answers fails closed.
	#[test]
	fn peer_identity_names_no_gateway_for_an_unenrolled_key() {
		let enrolled = TestCertificate::self_signed(&peer_key());
		let stranger = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let config = config_enrolling(&enrolled);

		let named = config.peer_identity(&stranger);
		assert_eq!(named, None);
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

	tb_cases! {
		fn a_refusal_maps_to_the_status_its_frame_is_answered_with((refusal, status): (VerifyRefusal, TransitStatus)) {
			assert_eq!(TransitStatus::from(refusal), status);
		}
		cases {
			unsigned => (VerifyRefusal::Unsigned, TransitStatus::Unauthenticated),
			unknown_signer => (VerifyRefusal::UnknownSigner, TransitStatus::PermissionDenied),
			forged => (VerifyRefusal::Forged, TransitStatus::PermissionDenied),
			wrong_plane => (VerifyRefusal::WrongPlane, TransitStatus::PermissionDenied),
			no_store => (VerifyRefusal::NoStore, TransitStatus::PermissionDenied),
			unidentifiable => (VerifyRefusal::Unidentifiable, TransitStatus::PermissionDenied),
		}
	}

	/// A frame of the control shape that carries no signature.
	fn unsigned_control_frame() -> Frame {
		let frame = FrameBuilder::from(Version::V1)
			.with_id("verify-origin")
			.with_order(1)
			.with_message(TestMessage::sample(None))
			.build();
		frame.expect("test frame builds")
	}

	#[test]
	fn peer_origin_names_a_signer_the_store_does_not_hold() {
		let frame = signed_control_frame(&peer_key());
		let enrolled_key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();

		let config = config_enrolling(&TestCertificate::self_signed(&enrolled_key));
		assert!(matches!(config.verify_peer(&frame), Err(VerifyRefusal::UnknownSigner)));
	}

	#[test]
	fn peer_origin_names_a_forged_signature_under_a_held_signer() {
		let forger: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let frame = control_frame_claiming(&forger, &peer_key());

		let config = config_enrolling(&TestCertificate::self_signed(&peer_key()));
		assert!(matches!(config.verify_peer(&frame), Err(VerifyRefusal::Forged)));
	}

	#[test]
	fn peer_origin_names_a_frame_with_no_signature() {
		let frame = unsigned_control_frame();
		let config = config_enrolling(&TestCertificate::self_signed(&peer_key()));
		assert!(matches!(config.verify_peer(&frame), Err(VerifyRefusal::Unsigned)));
	}

	#[test]
	fn peer_origin_names_a_plane_with_no_store() {
		let frame = signed_control_frame(&peer_key());
		assert!(matches!(exporting_config().verify_peer(&frame), Err(VerifyRefusal::NoStore)));
	}

	#[test]
	fn a_gateway_with_no_colony_is_in_no_flood() {
		assert!(exporting_config().flood().is_none());
	}

	#[test]
	fn hive_origin_passes_hive_only_signer() {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
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
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let frame = signed_control_frame(&key);
		let cert = TestCertificate::self_signed(&key);

		let mut config = exporting_config();
		config.tls.hive_trust = Some(trust_of(&cert));
		config.tls.peer_trust = Some(trust_of(&cert));
		assert!(matches!(config.verify_hive(&frame), Err(VerifyRefusal::WrongPlane)));
	}

	#[test]
	fn hive_origin_refuses_peer_key_under_rotated_certificate() {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let frame = signed_control_frame(&key);
		let hive_cert = TestCertificate::with_cn_and_uri_sans(&key, "hive", &["urn:tightbeam:colony:test"]);
		let peer_cert = TestCertificate::with_cn_and_uri_sans(&key, "peer", &["urn:tightbeam:colony:test"]);

		let mut config = exporting_config();
		config.tls.hive_trust = Some(trust_of(&hive_cert));
		config.tls.peer_trust = Some(trust_of(&peer_cert));
		assert!(matches!(config.verify_hive(&frame), Err(VerifyRefusal::WrongPlane)));
	}

	#[test]
	fn peer_origin_accepts_dual_anchored_signer() {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let frame = signed_control_frame(&key);
		let cert = TestCertificate::self_signed(&key);

		let mut config = exporting_config();
		config.tls.hive_trust = Some(trust_of(&cert));
		config.tls.peer_trust = Some(trust_of(&cert));
		assert!(matches!(config.verify_peer(&frame), Ok(verified) if verified.party() == Party::Peer));
	}
}
