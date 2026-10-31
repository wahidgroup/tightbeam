//! Origin, freshness, and export-boundary checks for cluster control traffic.
//!
//! The gateway runs these predicates before or beside request dispatch:
//!
//! - Gate policies run on every unary request and stream open of an admitted session.
//! - The export boundary runs once the gateway knows the servlet target.
//! - Origin and freshness checks apply to signed control frames on the hive and peer planes.
//!
//! # Gate policies
//!
//! [`ClusterConfig::evaluate_gates`] runs the configured [`GatePolicy`]
//! instances before the gateway decodes the request envelope. Stream opens
//! carry no request frame, so they pass `None` for it.
//!
//! # Export boundary
//!
//! [`ColonyConfig::evaluate_export_gates`] runs [`ExportPolicy`] where the
//! gateway resolves the servlet target: the allowlist, then the grants, then
//! the deny gates. [`HopBudget::is_relayed`] supplies the `relayed` flag. The
//! verdict algebra and the posture warnings are in
//! [`crate::colony::cluster::export`].
//!
//! # Origin and freshness
//!
//! [`ColonyConfig::verify_hive`] and [`ColonyConfig::verify_peer`] verify one
//! control frame and return [`VerifiedControlFrame`]. [`GatewayReplayGuard`]
//! rejects stale or replayed signed control frames.
//!
//! [`GatewayReplayGuard`]: super::freshness::GatewayReplayGuard
//! [`HopBudget::is_relayed`]: crate::colony::cluster::HopBudget::is_relayed

use std::sync::Arc;

use crate::cms::signed_data::SignerIdentifier;
use crate::colony::cluster::export::{ExportDecision, ExportPolicy, Party, TrustPlanes};
use crate::colony::cluster::peer::ColonyCertificate;
use crate::colony::cluster::runtime::bounds::{ColonyConfig, ColonyDigest};
use crate::colony::cluster::runtime::gossip_tasks::{GossipOrigin, GossipPipelineCtx};
use crate::colony::cluster::runtime::LoopFault;
use crate::colony::cluster::{ClusterConfig, SharedId};
use crate::crypto::hash::Digest;
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
/// A refusal and a grant that decides the outcome describe the same caller, so
/// both records carry the same label, value, and payload.
struct ExportAudit<'a> {
	trace: &'a TraceCollector,
	session: &'a SessionContext,
	relayed: bool,
}

impl ExportAudit<'_> {
	/// Emit `outcome` for this caller, answered with `status`.
	///
	/// The value is the `relayed` flag, and the payload is the fingerprint of
	/// the caller's certificate under `D`. Only a kept record computes it.
	fn record<D: Digest>(&self, outcome: Urn<'static>, status: TransitStatus) -> Result<(), TightBeamError> {
		let label = self.label(status);
		let caller = self.session.peer_certificate();
		let evidence = || caller.and_then(ColonyCertificate::fingerprint_id::<D>);
		let trace = self.trace;
		trace.emit_event_with_value_and_rendered_evidence(outcome, label, self.relayed, evidence)?;

		Ok(())
	}
}

/// Writes [`ExportAudit::label`] from one list of the statuses.
///
/// Each label is a constant, and a missing status fails to compile.
macro_rules! export_labels {
	($($status:ident),+ $(,)?) => {
		impl ExportAudit<'_> {
			/// The label of a verdict with `status`, such as `Ok/relayed`.
			///
			/// The sink keeps the label alone, so the label names the route.
			const fn label(&self, status: TransitStatus) -> &'static str {
				match (status, self.relayed) {
					$(
						(TransitStatus::$status, false) => concat!(stringify!($status), "/direct"),
						(TransitStatus::$status, true) => concat!(stringify!($status), "/relayed"),
					)+
				}
			}
		}
	};
}

export_labels!(
	Ok,
	Cancelled,
	Unknown,
	InvalidArgument,
	DeadlineExceeded,
	NotFound,
	AlreadyExists,
	PermissionDenied,
	ResourceExhausted,
	FailedPrecondition,
	Aborted,
	OutOfRange,
	Unimplemented,
	Internal,
	Unavailable,
	DataLoss,
	Unauthenticated,
);

/// The owned slate key that each [`VerifiedControlFrame`] carries.
///
/// Only [`ColonyConfig::verify_plane`] constructs this. Gossip may carry the
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

/// The traces that the records of one request go on.
///
/// A record goes on the audit trace once a proven peer or a verified signature
/// proves its origin, and on the connection trace before that (CWE-778).
pub(crate) struct RequestAudit {
	/// The audit trace of the gateway.
	audit: Arc<TraceCollector>,
	/// The trace of a record that no verified frame signature backs.
	unproven: Arc<TraceCollector>,
}

impl RequestAudit {
	/// The audit of a request on `session`, over `audit` and `connections`.
	pub(crate) fn of(audit: &Arc<TraceCollector>, connections: &Arc<TraceCollector>, session: &SessionContext) -> Self {
		let proven = session.proven_peer().is_some();
		let unproven = if proven {
			audit
		} else {
			connections
		};

		Self { audit: Arc::clone(audit), unproven: Arc::clone(unproven) }
	}

	/// The audit of a request whose sender the caller verified, on `audit`.
	pub(crate) fn proven(audit: &Arc<TraceCollector>) -> Self {
		Self { audit: Arc::clone(audit), unproven: Arc::clone(audit) }
	}

	/// The trace of a record that no verified frame signature backs.
	pub(crate) fn unproven(&self) -> &TraceCollector {
		&self.unproven
	}

	/// The trace of a record that the verified signature of `signer` backs.
	pub(crate) fn signed(&self, signer: Option<&VerifiedSignerId>) -> &TraceCollector {
		match signer {
			Some(_) => &self.audit,
			None => &self.unproven,
		}
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
	/// The status that answers a refused frame.
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
	/// and returns the status that answers the relay.
	///
	/// Trust stores need not agree, so an origin this gateway does not hold
	/// marks the edge of a subnet, not a fault of the relay.
	///
	/// - [`Self::UnknownSigner`] drops the rumor and spends one token of the relay's rate bucket (CWE-770).
	/// - With a token, it answers [`TransitStatus::Unauthenticated`], so the relay stops offering the origin.
	/// - With the bucket empty, it answers [`TransitStatus::ResourceExhausted`].
	/// - The signer of `frame`, the relay's own signed frame, keys the bucket.
	/// - Every other refusal scores the relay, which should have refused the
	///   rumor, and so does a `frame` that names no signer.
	///
	/// # Errors
	///
	/// - [`LoopFault::Registry`] -- the route registry is poisoned, or the rate admission faulted.
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
						let trace = &pipeline.trace;
						let evidence = || Some(relay.as_shared().as_ref());
						trace.emit_marker_with_evidence(CLUSTER_GOSSIP_ORIGIN_UNKNOWN, evidence)?;

						Ok(TransitStatus::Unauthenticated)
					}
					Ok(false) => Ok(TransitStatus::ResourceExhausted),
					Err(error) => Err(LoopFault::Registry(error)),
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
/// Only [`ColonyConfig::verify_hive`] or [`ColonyConfig::verify_peer`] creates
/// one. The signature check runs once, and [`Party`] comes from
/// [`TrustPlanes::classify`] on the certificate that the check resolved, so a
/// later step reuses this verification and this signer lookup.
pub(crate) struct VerifiedControlFrame<'a> {
	frame: &'a Frame,
	signer_cert: &'a Certificate,
	/// The signer that the verified SignerInfo names (RFC 5652 §5.3).
	signer_identifier: &'a SignerIdentifier,
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

	/// The signer that the verified SignerInfo names (RFC 5652 §5.3), which a
	/// hive registration binds to its hive.
	#[must_use]
	pub(crate) fn signer_identifier(&self) -> &'a SignerIdentifier {
		self.signer_identifier
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
	/// Run the configured [`GatePolicy`] instances and leave the audit event
	/// to the caller.
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

	/// Run the configured gate policies before the gateway decodes the request
	/// envelope.
	///
	/// Each configured policy must return [`TransitStatus::Ok`], so the first
	/// refusal short-circuits dispatch.
	///
	/// - `frame`: the request envelope when present, or `None` for a stream open that carries no unary frame
	/// - `session`: the identity and transport facts of the caller's admitted connection
	/// - `trace`: the collector that receives [`CLUSTER_GATE_BLOCKED`] on a refusal
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

		trace.emit_event_with_value_and_evidence(CLUSTER_GATE_BLOCKED, status.as_str(), status, None)?;

		Ok(status)
	}
}

impl<P: Protocol> ColonyConfig<P> {
	/// Verify `frame` once on `required` and classify the resolved certificate.
	///
	/// Peer membership wins ([`Self::verify_hive`]). An absent store or a
	/// failed signature refuses, and a frame without a signature is
	/// unauthenticated.
	fn verify_plane<'a>(
		&'a self,
		frame: &'a Frame,
		required: Party,
	) -> Result<VerifiedControlFrame<'a>, VerifyRefusal> {
		let planes = TrustPlanes::from(&self.tls);
		let Some(trust) = planes.store(required) else {
			return Err(VerifyRefusal::NoStore);
		};
		let (signer, signature) = match trust.verify_frame(frame) {
			TrustVerification::Verified(signer, signature) => (signer, signature),
			TrustVerification::MissingSignature => return Err(VerifyRefusal::Unsigned),
			TrustVerification::UnknownSigner => return Err(VerifyRefusal::UnknownSigner),
			TrustVerification::Invalid => return Err(VerifyRefusal::Forged),
		};

		let signer_cert = signer.certificate().as_ref();
		let Some(signer_info) = frame.nonrepudiation() else {
			return Err(VerifyRefusal::Unsigned);
		};

		let party = planes.classify(Some(signer_cert));
		if party != required {
			return Err(VerifyRefusal::WrongPlane);
		}

		let fingerprint = planes.signer_id::<ColonyDigest<P>>(party, signer_cert);
		let fingerprint = fingerprint.map(VerifiedSignerId).ok_or(VerifyRefusal::Unidentifiable)?;
		let signer_identifier = &signer_info.sid;
		Ok(VerifiedControlFrame { frame, signer_cert, signer_identifier, signature, party, fingerprint })
	}

	/// The slate key of the gateway that holds `cert`'s key, under the colony
	/// digest, by the rule of [`TrustPlanes::peer_identity`].
	///
	/// It is `None` with no peer dial store, or for a key outside it.
	pub(crate) fn peer_identity(&self, cert: &Certificate) -> Option<SharedId> {
		TrustPlanes::from(&self.tls).peer_identity::<ColonyDigest<P>>(cert)
	}

	/// Enforce the export boundary on a resolved servlet target.
	///
	/// The verdict algebra is in [`ExportPolicy`], read from the live
	/// configuration, so enforcement stays aligned with the advertise filter.
	/// It adds the audit plane.
	///
	/// 1. Run [`ExportPolicy::verdict`] (the allowlist, the grants, then the deny gates).
	/// 2. Trace [`CLUSTER_EXPORT_REFUSED`] or [`CLUSTER_EXPORT_GRANTED`] with
	///    the status, the caller certificate fingerprint under the colony
	///    digest, and the relayed flag.
	///
	/// The granted event fires only when the full verdict passes, because a
	/// deny gate that overrides a grant decides the outcome itself.
	///
	/// - `target`: the servlet type under enforcement
	/// - `session`: the identity facts of the caller's admitted connection
	/// - `relayed`: `true` when [`HopBudget::is_relayed`] marks the request as peer-relayed
	/// - `trace`: the collector that receives the boundary audit events
	///
	/// # Call sites
	///
	/// [`ColonyConfig::admit_target`] alone calls it, for the unary work arm
	/// in [`super::dispatch`] and the streaming and duplex open handlers in
	/// [`super`].
	///
	/// # Sources
	///
	/// - CWE-285, improper authorization: <https://cwe.mitre.org/data/definitions/285.html>
	/// - ISO/IEC 27001:2022 A.8.15, logging: <https://www.iso.org/standard/82875.html>
	///
	/// [`HopBudget::is_relayed`]: crate::colony::cluster::HopBudget::is_relayed
	pub(crate) fn evaluate_export_gates(
		&self,
		target: &Urn<'_>,
		session: &SessionContext,
		relayed: bool,
		trace: &TraceCollector,
	) -> Result<TransitStatus, TightBeamError> {
		let config: &ClusterConfig = self;
		let audit = ExportAudit { trace, session, relayed };
		let (outcome, status) = match ExportPolicy::from(config).verdict(target, session, relayed) {
			Ok(ExportDecision::Allowed) => return Ok(TransitStatus::Ok),
			Ok(ExportDecision::Granted) => (CLUSTER_EXPORT_GRANTED, TransitStatus::Ok),
			Err(status) => (CLUSTER_EXPORT_REFUSED, status),
		};

		audit.record::<ColonyDigest<P>>(outcome, status)?;
		Ok(status)
	}

	/// Verify one hive-plane control frame.
	///
	/// The result carries the signer certificate and [`Party::FirstParty`].
	/// A public key that `tls.peer_trust` also enrolls is [`Party::Peer`], and
	/// the parse refuses it: peer membership wins by key identity, so a rotated
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
	use crate::colony::cluster::{ExportGate, ExportGrant, StaticExportList, TrustPlanes};
	use crate::colony::urn::ColonyNamespace;
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
	use crate::crypto::sign::PrehashSigner;
	use crate::crypto::x509::store::CertificateTrust;
	use crate::crypto::x509::Certificate;
	use crate::tb_cases;
	use crate::testing::fixtures::{TestGate, TestStore};
	use crate::testing::{TestCertificate, TestKey, TestMessage, TestResult};
	use crate::transport::TokioListener;
	use crate::Version;

	fn servlet(name: &str) -> Urn<'static> {
		ColonyNamespace::servlet_fixture(name)
	}

	/// A config that exports only "ping", so "ledger" needs a grant.
	fn exporting_config() -> ClusterConfig {
		let mut config = ClusterConfig::fixture();
		config.peer.exported_types = Some(Arc::new(StaticExportList::new([servlet("ping")])));
		config
	}

	/// A peer gateway key, distinct from the fixed key the config presents.
	fn peer_key() -> Secp256k1SigningKey {
		TestKey::fixed(0x02)
	}

	/// The certificate of [`peer_key`].
	fn peer_certificate() -> Certificate {
		TestCertificate::self_signed(&peer_key())
	}

	/// A house store that holds `certificate` alone.
	fn trust_of(certificate: &Certificate) -> Arc<dyn CertificateTrust> {
		Arc::new(TestStore::holding([certificate.clone()]))
	}

	/// A house gateway of [`exporting_config`] whose hive plane anchors `hive`
	/// and whose peer plane anchors `peer`, each plane empty for `None`.
	fn anchored(hive: Option<&Certificate>, peer: Option<&Certificate>) -> ColonyConfig<TokioListener> {
		let mut config = exporting_config();
		config.tls.hive_trust = hive.map(trust_of);
		config.tls.peer_trust = peer.map(trust_of);
		ColonyConfig::house(config)
	}

	/// A house gateway whose peer plane enrolls [`peer_certificate`] alone.
	fn peer_enrolling() -> ColonyConfig<TokioListener> {
		anchored(None, Some(&peer_certificate()))
	}

	/// A grant of every target.
	///
	/// The crate holds no house grant, so a grant is an implementor's own.
	struct GrantAll;

	impl ExportGrant for GrantAll {
		fn grants(&self, _target: &Urn<'_>, _session: &SessionContext, _relayed: bool) -> bool {
			true
		}
	}

	/// A grant of each origin request.
	///
	/// The crate holds no house grant, so a grant is an implementor's own.
	struct OriginOnlyGrant;

	impl ExportGrant for OriginOnlyGrant {
		fn grants(&self, _target: &Urn<'_>, _session: &SessionContext, relayed: bool) -> bool {
			!relayed
		}
	}

	/// A grant of each session that proved a key.
	///
	/// The crate holds no house grant, so a grant is an implementor's own.
	struct IdentityGrant;

	impl ExportGrant for IdentityGrant {
		fn grants(&self, _target: &Urn<'_>, session: &SessionContext, _relayed: bool) -> bool {
			session.peer_key().is_some()
		}
	}

	/// An export gate that answers every target with the status it holds.
	///
	/// The crate holds no house export gate, so a gate is an implementor's
	/// own.
	struct GateAnswering(TransitStatus);

	impl ExportGate for GateAnswering {
		fn evaluate(
			&self,
			_target: &Urn<'_>,
			_session: &SessionContext,
			_planes: &TrustPlanes<'_>,
			_relayed: bool,
		) -> TransitStatus {
			self.0
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

	/// A control frame signed by `key` under the canonical convention.
	fn signed_control_frame(key: &Secp256k1SigningKey) -> Frame {
		control_frame_claiming(key, key)
	}

	/// A control frame signed with `signer` that names `claimed` as its signer.
	fn control_frame_claiming(signer: &Secp256k1SigningKey, claimed: &Secp256k1SigningKey) -> Frame {
		let mut frame = unsigned_control_frame();
		let claimed_certificate = TestCertificate::self_signed(claimed);
		let draft = frame.signing_draft::<Secp256k1Signature>(&claimed_certificate);
		let draft = draft.expect("test frame drafts its signature");
		let signature: Secp256k1Signature = signer.sign_prehash(draft.prehash()).expect("test key signs");
		let signer_info = draft.complete(signature.to_bytes(), None).expect("the signature completes");

		frame.attach_signer_info(signer_info).expect("test signature attaches");
		frame
	}

	/// The certificate of the fixed test key that names `cn`, under the colony
	/// URN `urn:tightbeam:colony:test`.
	fn named(cn: &str) -> Certificate {
		let key = TestKey::insecure_fixed_signing();
		TestCertificate::with_cn_and_uri_sans(&key, cn, &["urn:tightbeam:colony:test"])
	}

	/// A control frame that the fixed test key signs, beside the certificate
	/// of that key.
	fn fixed_signed() -> (Frame, Certificate) {
		(
			signed_control_frame(&TestKey::insecure_fixed_signing()),
			TestCertificate::insecure_fixed(),
		)
	}

	/// A gateway that rotated its certificate under one key keeps the slate
	/// key of the certificate the peer plane enrolled.
	#[test]
	fn peer_identity_names_a_rotated_certificate_by_its_enrolled_one() {
		let key = peer_key();
		let enrolled = TestCertificate::with_cn_and_uri_sans(&key, "enrolled", &["urn:tightbeam:colony:test"]);
		let rotated = TestCertificate::with_cn_and_uri_sans(&key, "rotated", &["urn:tightbeam:colony:test"]);
		let config = anchored(None, Some(&enrolled));

		let named = config.peer_identity(&rotated);
		assert_eq!(named, enrolled.fingerprint_id::<Sha3_256>());
		assert_ne!(named, rotated.fingerprint_id::<Sha3_256>());
	}

	/// A certificate whose key the peer plane does not hold names no gateway,
	/// so a bound hop it answers fails closed.
	#[test]
	fn peer_identity_names_no_gateway_for_an_unenrolled_key() {
		let config = peer_enrolling();
		let named = config.peer_identity(&TestCertificate::insecure_fixed());
		assert_eq!(named, None);
	}

	/// The grants and the export gates of a gateway that exports "ping"
	/// alone, the target of a request, whether a relay carried it, and the
	/// verdict on it.
	type Judged = (
		Vec<Arc<dyn ExportGrant>>,
		Vec<Arc<dyn ExportGate>>,
		&'static str,
		bool,
		TransitStatus,
	);

	// A grant widens the export list to an unexported target, a gate that
	// denies overrides a grant, and an unknown gate verdict normalizes to
	// `Internal`. An identity grant matches no anonymous session, and an
	// origin-only grant passes an origin request alone.
	tb_cases! {
		fn export_gates_judge_a_target((grants, gates, target, relayed, verdict): Judged) -> TestResult {
			let mut config = exporting_config();
			config.export_grants = grants;
			config.export_gates = gates;
			let (session, trace) = (SessionContext::default(), TraceCollector::default());
			let gateway = ColonyConfig::house(config);

			let judged = gateway.evaluate_export_gates(&servlet(target), &session, relayed, &trace)?;

			assert_eq!(judged, verdict);
			Ok(())
		}
		cases {
			a_grant_widens_an_unexported_target => (
				vec![Arc::new(GrantAll)],
				Vec::new(),
				"ledger",
				false,
				TransitStatus::Ok,
			),
			a_deny_gate_overrides_a_grant => (
				vec![Arc::new(GrantAll)],
				vec![Arc::new(GateAnswering(TransitStatus::PermissionDenied))],
				"ledger",
				false,
				TransitStatus::PermissionDenied,
			),
			an_anonymous_session_matches_no_identity_grant => (
				vec![Arc::new(IdentityGrant)],
				Vec::new(),
				"ledger",
				false,
				TransitStatus::PermissionDenied,
			),
			an_origin_only_grant_refuses_a_relayed_request => (
				vec![Arc::new(OriginOnlyGrant)],
				Vec::new(),
				"ledger",
				true,
				TransitStatus::PermissionDenied,
			),
			an_origin_only_grant_passes_an_origin_request => (
				vec![Arc::new(OriginOnlyGrant)],
				Vec::new(),
				"ledger",
				false,
				TransitStatus::Ok,
			),
			an_unknown_gate_verdict_normalizes_to_internal => (
				Vec::new(),
				vec![Arc::new(GateAnswering(TransitStatus::Unknown))],
				"ping",
				false,
				TransitStatus::Internal,
			),
		}
	}

	/// An unknown verdict of a gate policy normalizes to `Internal`.
	#[test]
	fn unknown_gate_policy_verdict_normalizes_to_internal() -> TestResult {
		let mut config = exporting_config();
		config.policies.push(Arc::new(TestGate(TransitStatus::Unknown)));

		let verdict = config.evaluate_gates(None, &SessionContext::default(), &TraceCollector::default())?;
		assert_eq!(verdict, TransitStatus::Internal);
		Ok(())
	}

	// Each refusal answers its frame with the status of its cause.
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

	// The peer plane names why it refuses a frame: a signer it does not hold,
	// a forged signature under a signer it holds, a frame with no signature,
	// and a plane with no store.
	tb_cases! {
		fn verify_peer_names_its_refusal(
			(frame, config, refusal): (Frame, ColonyConfig<TokioListener>, VerifyRefusal)
		) {
			let verified = config.verify_peer(&frame);

			assert_eq!(verified.err(), Some(refusal));
		}
		cases {
			unknown_signer => (
				signed_control_frame(&peer_key()),
				anchored(None, Some(&TestCertificate::insecure_fixed())),
				VerifyRefusal::UnknownSigner,
			),
			forged => (
				control_frame_claiming(&TestKey::insecure_fixed_signing(), &peer_key()),
				peer_enrolling(),
				VerifyRefusal::Forged,
			),
			unsigned => (unsigned_control_frame(), peer_enrolling(), VerifyRefusal::Unsigned),
			no_store => (
				signed_control_frame(&peer_key()),
				ColonyConfig::house(exporting_config()),
				VerifyRefusal::NoStore,
			),
		}
	}

	/// A gateway with no colony URN is in no flood.
	#[test]
	fn a_gateway_with_no_colony_is_in_no_flood() {
		assert!(exporting_config().flood().is_none());
	}

	/// The hive plane passes a frame of a signer that it alone anchors, as the
	/// first party, and names the frame and the certificate of its signer.
	#[test]
	fn hive_origin_passes_hive_only_signer() {
		let (frame, cert) = fixed_signed();
		let config = anchored(Some(&cert), None);
		let verified = config.verify_hive(&frame);

		let read = verified.map(|proof| {
			let signer = proof.signer_cert().fingerprint_id::<Sha3_256>();
			(proof.party(), proof.frame().metadata().id().to_vec(), signer)
		});
		let expected = (
			Party::FirstParty,
			frame.metadata().id().to_vec(),
			cert.fingerprint_id::<Sha3_256>(),
		);
		assert_eq!(read, Ok(expected));
	}

	// The hive plane refuses a key that the peer plane holds too, under the
	// one certificate or under a rotated certificate of that key.
	tb_cases! {
		fn verify_hive_refuses_a_key_the_peer_plane_holds((hive, peer): (Certificate, Certificate)) {
			let (frame, _) = fixed_signed();
			let config = anchored(Some(&hive), Some(&peer));

			let verified = config.verify_hive(&frame);
			assert_eq!(verified.err(), Some(VerifyRefusal::WrongPlane));
		}
		cases {
			dual_anchored => (TestCertificate::insecure_fixed(), TestCertificate::insecure_fixed()),
			rotated_peer_certificate => (named("hive"), named("peer")),
		}
	}

	/// The peer plane passes a signer that both planes anchor, as a peer.
	#[test]
	fn peer_origin_accepts_dual_anchored_signer() {
		let (frame, cert) = fixed_signed();
		let config = anchored(Some(&cert), Some(&cert));

		let verified = config.verify_peer(&frame);

		assert!(matches!(verified, Ok(verified) if verified.party() == Party::Peer));
	}

	/// The instrument records of an export refusal, read from a collector that
	/// records the digest of each payload.
	#[cfg(feature = "instrument")]
	mod audit {
		use core::cell::Cell;

		use super::*;
		use crate::crypto::x509::utils::Fingerprint;
		use crate::instrumentation::TbInstrumentationConfig;
		use crate::testing::fixtures::TestTrace;

		std::thread_local! {
			/// The digests that [`CountingDigest`] starts on this thread.
			static DIGESTS: Cell<usize> = const { Cell::new(0) };
		}

		/// A SHA3-256 that counts each digest it starts.
		///
		/// The count of fingerprints a record computes is the behavior under
		/// test, and the house digest keeps no count, so this wrapper of the
		/// house digest counts its starts.
		#[derive(Clone)]
		struct CountingDigest(Sha3_256);

		impl Default for CountingDigest {
			fn default() -> Self {
				DIGESTS.with(|digests| digests.set(digests.get().saturating_add(1)));
				Self(Sha3_256::default())
			}
		}

		impl digest::OutputSizeUser for CountingDigest {
			type OutputSize = <Sha3_256 as digest::OutputSizeUser>::OutputSize;
		}

		impl digest::Update for CountingDigest {
			fn update(&mut self, data: &[u8]) {
				digest::Update::update(&mut self.0, data);
			}
		}

		impl digest::FixedOutput for CountingDigest {
			fn finalize_into(self, out: &mut digest::Output<Self>) {
				digest::FixedOutput::finalize_into(self.0, out);
			}
		}

		impl digest::HashMarker for CountingDigest {}

		/// The count of digests that one export refusal of a certified caller
		/// starts on a trace that holds `max_events` events.
		fn fingerprints_of_a_refusal(max_events: u32) -> usize {
			let config = TbInstrumentationConfig { enable_payloads: true, max_events, ..Default::default() };
			let trace = TestTrace::with_config(config);
			// A full sink keeps its overflow warning in place of the first
			// record past its bound, so this record takes that place.
			trace.emit(CLUSTER_EXPORT_REFUSED, "warning");
			let session = SessionContext::for_peer(Arc::new(peer_certificate()));
			let audit = ExportAudit { trace: &trace, session: &session, relayed: false };
			let before = DIGESTS.with(Cell::get);

			let recorded = audit.record::<CountingDigest>(CLUSTER_EXPORT_REFUSED, TransitStatus::PermissionDenied);
			recorded.expect("the trace takes the record");

			DIGESTS.with(Cell::get).saturating_sub(before)
		}

		// A record that the sink drops computes no fingerprint of its caller,
		// and a kept record computes it once.
		tb_cases! {
			fn an_export_record_computes_fingerprints_as_its_sink_keeps_it((max_events, fingerprints): (u32, usize)) {
				assert_eq!(fingerprints_of_a_refusal(max_events), fingerprints);
			}
			cases {
				dropped => (0, 0),
				kept => (u32::MAX, 1),
			}
		}

		// An export label names its status by its variant, then the route of
		// the request.
		tb_cases! {
			fn an_export_label_names_its_status_as_the_status_does((status, label): (TransitStatus, &str)) {
				let (trace, session) = (TraceCollector::default(), SessionContext::default());
				let audit = ExportAudit { trace: &trace, session: &session, relayed: true };
				assert_eq!(audit.label(status), label);
			}
			cases {
				ok => (TransitStatus::Ok, "Ok/relayed"),
				cancelled => (TransitStatus::Cancelled, "Cancelled/relayed"),
				unknown => (TransitStatus::Unknown, "Unknown/relayed"),
				invalid_argument => (TransitStatus::InvalidArgument, "InvalidArgument/relayed"),
				deadline_exceeded => (TransitStatus::DeadlineExceeded, "DeadlineExceeded/relayed"),
				not_found => (TransitStatus::NotFound, "NotFound/relayed"),
				already_exists => (TransitStatus::AlreadyExists, "AlreadyExists/relayed"),
				permission_denied => (TransitStatus::PermissionDenied, "PermissionDenied/relayed"),
				resource_exhausted => (TransitStatus::ResourceExhausted, "ResourceExhausted/relayed"),
				failed_precondition => (TransitStatus::FailedPrecondition, "FailedPrecondition/relayed"),
				aborted => (TransitStatus::Aborted, "Aborted/relayed"),
				out_of_range => (TransitStatus::OutOfRange, "OutOfRange/relayed"),
				unimplemented => (TransitStatus::Unimplemented, "Unimplemented/relayed"),
				internal => (TransitStatus::Internal, "Internal/relayed"),
				unavailable => (TransitStatus::Unavailable, "Unavailable/relayed"),
				data_loss => (TransitStatus::DataLoss, "DataLoss/relayed"),
				unauthenticated => (TransitStatus::Unauthenticated, "Unauthenticated/relayed"),
			}
		}

		/// The verdict of a house gateway on "ledger" for `session`, beside the
		/// trace that holds the records the verdict leaves.
		fn refusal_trace(session: &SessionContext, relayed: bool) -> (TransitStatus, TraceCollector) {
			let trace = TestTrace::with_payloads();
			let gateway = ColonyConfig::house(exporting_config());
			let verdict = gateway.evaluate_export_gates(&servlet("ledger"), session, relayed, &trace);
			let verdict = verdict.expect("the trace takes the export record");

			(verdict, trace)
		}

		/// A refusal of a certified caller records the caller's fingerprint
		/// under the colony digest as its payload.
		#[test]
		fn a_refusal_records_the_fingerprint_of_its_caller() -> TestResult {
			let fingerprint = Fingerprint::<Sha3_256>::from_certificate(&peer_certificate())?;
			let session = SessionContext::for_peer(Arc::new(peer_certificate()));
			let (verdict, trace) = refusal_trace(&session, false);

			let expected: [u8; 32] = Sha3_256::digest(fingerprint.as_slice()).into();
			let evidence = TestTrace::payloads(&trace, CLUSTER_EXPORT_REFUSED);
			assert_eq!((verdict, evidence), (TransitStatus::PermissionDenied, vec![Some(expected)]));
			Ok(())
		}

		// A refusal names its status and its route in its label, because the
		// sink keeps the label and drops the value that carries the relayed
		// flag.
		tb_cases! {
			fn a_refusal_names_its_status_and_route((relayed, expected): (bool, &str)) {
				let (verdict, trace) = refusal_trace(&SessionContext::default(), relayed);
				let labels = TestTrace::labels(&trace, CLUSTER_EXPORT_REFUSED);
				assert_eq!((verdict, labels), (TransitStatus::PermissionDenied, vec![Some(String::from(expected))]));
			}
			cases {
				direct => (false, "PermissionDenied/direct"),
				relayed => (true, "PermissionDenied/relayed"),
			}
		}

		/// The fingerprint of the signer that `gateway` proves on its peer
		/// plane for `frame`.
		fn verified_signer(gateway: &ColonyConfig<TokioListener>, frame: &Frame) -> VerifiedSignerId {
			let verified = gateway.verify_peer(frame).map(|verified| verified.fingerprint());
			verified.expect("the peer plane enrolls the signer of the frame")
		}

		/// A refusal after the frame verified on its plane names the
		/// fingerprint of the signer that the verification proved.
		#[test]
		fn a_verified_refusal_names_its_signer() -> TestResult {
			use crate::colony::cluster::runtime::refuse::Refusal;
			use crate::instrumentation::events::CLUSTER_GOSSIP_REFUSED;

			let (trace, connections) = (Arc::new(TestTrace::with_payloads()), Arc::new(TraceCollector::new()));
			let frame = signed_control_frame(&peer_key());
			let signer = verified_signer(&peer_enrolling(), &frame);
			let audit = RequestAudit::of(&trace, &connections, &SessionContext::default());
			let refusal = Refusal::to(&frame, &audit).by(&signer);
			refusal.gossip(TransitStatus::PermissionDenied)?;

			let expected: [u8; 32] = Sha3_256::digest(signer.as_shared().as_ref()).into();
			assert_eq!(TestTrace::payloads(&trace, CLUSTER_GOSSIP_REFUSED), [Some(expected)]);
			Ok(())
		}
	}
}
