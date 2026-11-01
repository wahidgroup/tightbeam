//! The integration tests of the dual-signed session receipt.

#![cfg(all(
	feature = "transport-hpke",
	feature = "transport-multiplex",
	feature = "tcp",
	feature = "tokio",
	feature = "testing",
	feature = "instrument"
))]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tightbeam::asn1::Any;
use tightbeam::cms::cert::CertificateChoices;
use tightbeam::cms::signed_data::{SignedData, SignerInfo};
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::Signed;
use tightbeam::crypto::x509::{KeyPurposes, PeerCertificate, Signing};
use tightbeam::der::asn1::{OctetString, SetOfVec};
use tightbeam::der::{AnyRef, Decode, Encode, Reader, SliceReader, Tag, TagNumber, Tagged};
use tightbeam::exactly;
use tightbeam::marker::MaybeSendFuture;
use tightbeam::oids::RECEIPT_ANSWER;
use tightbeam::tb_assert_spec;
use tightbeam::tb_cases;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::MUX_APPLICATION_CODE_FLOOR;
use tightbeam::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, TransportAuthorizer, TransportOffer,
	SETTLEMENT_UNSUPPORTED_CODE,
};
use tightbeam::transport::handshake::receipt::{
	ApprovalRefusal, ReceiptApprover, ReceiptRole, SessionObserver, SessionReceipt, SessionVerdict, StoredReceipt,
};
use tightbeam::transport::handshake::HandshakeError;
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioStream};
use tightbeam::transport::{EncryptedMessageIO, MessageIO, TransportError};
use tightbeam::x509::attr::Attribute;
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;

use tightbeam::instrumentation::events;

use crate::common::result::TestResult;
use crate::common::security::{
	expectation_failure, ClientMaterials, GrantingAuthorizer, PayingApprover as AnsweringApprover, RecordingObserver,
	ServerMaterials, SettleSpyAuthorizer,
};
use crate::common::transport::{
	bind_mutual_listener, establish_mutual_transports, establish_mutual_transports_of, serve_one_handshake_message,
	MutualSessionHooks, MutualTransports,
};
use crate::transport::fixtures::{bind_encrypted_listener, connect_mutual_client, connect_pinned_client, join_task};

/// The settlement challenge that the authorizer binds into every receipt.
const CHALLENGE: &[u8] = b"receipt-invoice-42";

/// The settlement answer that the approver countersigns.
const RESPONSE: &[u8] = b"receipt-preimage-42";

/// The application code of a settle refusal.
const SETTLE_REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR + 7;

/// The application code of a client approval refusal.
const APPROVAL_REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR + 8;

/// The budgets that the client requests in every scenario.
const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

/// The offer of the server: multiplexing of four streams, with no budget.
fn server_offer() -> TransportOffer {
	TransportOffer::mux(4)
}

/// The offer of the client: [`server_offer`] with the [`REQUEST`] budgets.
fn budget_offer() -> TransportOffer {
	server_offer().with_budgets(REQUEST)
}

/// `client` with [`budget_offer`] as its multiplexing offer.
fn with_budget_offer(client: TcpTransport<TokioStream>) -> TcpTransport<TokioStream> {
	client.with_mux_offer(Some(budget_offer()))
}

/// `client` with [`budget_offer`] and `approver` as its receipt approver.
fn with_budget_approver(client: TcpTransport<TokioStream>, approver: Arc<PayingApprover>) -> TcpTransport<TokioStream> {
	with_budget_offer(client).with_receipt_approver(approver as Arc<dyn ReceiptApprover>)
}

/// An authorizer that binds `CHALLENGE` into every grant. Settlement succeeds
/// only for the expected answer, and only when `accept_settlement` is set.
///
/// The crate leaves the authorization hook to the application and ships no
/// authorizer, so no real instance runs.
struct ChallengingAuthorizer {
	challenge: OctetString,
	expected_response: OctetString,
	accept_settlement: bool,
}

impl ChallengingAuthorizer {
	/// An authorizer that settles [`RESPONSE`] when `accept_settlement` is
	/// set, and refuses every settlement otherwise.
	fn new(accept_settlement: bool) -> Result<Self, TightBeamError> {
		Ok(Self {
			challenge: OctetString::new(CHALLENGE)?,
			expected_response: OctetString::new(RESPONSE)?,
			accept_settlement,
		})
	}
}

impl TransportAuthorizer for ChallengingAuthorizer {
	fn authorize<'a>(
		&'a self,
		offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		Box::pin(async move {
			let challenge = self.challenge.to_owned();
			Ok(AuthorizationGrant { budgets: offer.requested_budgets, challenge: Some(challenge) })
		})
	}

	fn settle<'a>(
		&'a self,
		_receipt: &'a SessionReceipt,
		response: Option<&'a [u8]>,
		_client: &'a Certificate,
	) -> MaybeSendFuture<'a, Result<(), AuthorizationRefusal>> {
		Box::pin(async move {
			let expected = self.accept_settlement && response == Some(self.expected_response.as_bytes());
			if expected {
				return Ok(());
			}

			Err(AuthorizationRefusal { code: SETTLE_REFUSAL_CODE })
		})
	}
}

/// An approver that pays with the settlement answer or refuses with its code.
/// It counts its consultations, so a scenario can prove the hook never fired.
///
/// The crate leaves the approval hook to the application and ships no
/// approver, so no real instance runs.
struct PayingApprover {
	response: OctetString,
	refusal: Option<u32>,
	approve_calls: AtomicUsize,
}

impl PayingApprover {
	/// An approver that answers every challenge with [`RESPONSE`].
	fn paying() -> Result<Self, TightBeamError> {
		Ok(Self {
			response: OctetString::new(RESPONSE)?,
			refusal: None,
			approve_calls: AtomicUsize::new(0),
		})
	}

	/// An approver that refuses every receipt with `code`.
	fn refusing(code: u32) -> Result<Self, TightBeamError> {
		Ok(Self {
			response: OctetString::new(RESPONSE)?,
			refusal: Some(code),
			approve_calls: AtomicUsize::new(0),
		})
	}

	/// The number of receipts that this approver was consulted on.
	fn approve_calls(&self) -> usize {
		self.approve_calls.load(Ordering::SeqCst)
	}
}

impl ReceiptApprover for PayingApprover {
	fn approve<'a>(
		&'a self,
		_receipt: &'a SessionReceipt,
	) -> MaybeSendFuture<'a, Result<Option<OctetString>, ApprovalRefusal>> {
		self.approve_calls.fetch_add(1, Ordering::SeqCst);
		Box::pin(async move {
			if let Some(code) = self.refusal {
				return Err(ApprovalRefusal { code });
			}

			Ok(Some(self.response.to_owned()))
		})
	}
}

/// Establishes a mutual session on `trace` whose receipt the client
/// countersigns with [`RESPONSE`] and the server settles, and whose server
/// reports each outcome to `observer` when one is set.
async fn establish_settled_session_observed(
	observer: Option<Arc<dyn SessionObserver>>,
	trace: &TraceCollector,
) -> Result<MutualTransports, TightBeamError> {
	let hooks = MutualSessionHooks {
		authorizer: Some(Arc::new(ChallengingAuthorizer::new(true)?)),
		approver: Some(Arc::new(PayingApprover::paying()?)),
		observer,
		trace: Some(trace.share()),
	};

	establish_mutual_transports(budget_offer(), server_offer(), hooks).await
}

/// Establishes a settled session on `trace`, as
/// [`establish_settled_session_observed`] does with no observer.
async fn establish_settled_session(trace: &TraceCollector) -> Result<MutualTransports, TightBeamError> {
	establish_settled_session_observed(None, trace).await
}

/// The `[0]` tag of the `certificates` of a `SignedData`.
const CERTIFICATES: Tag = Tag::ContextSpecific { constructed: true, number: TagNumber::N0 };

/// `artifact` as a third party reads it back from its DER.
///
/// `tightbeam::encode` puts each universal SET in DER order. The
/// `certificates`, an IMPLICIT SET OF that only the schema names, go in DER
/// order here, as the signers write them (X.690 § 11.6).
fn stored_artifact(artifact: &SignedData) -> Signed<SignedData> {
	let encoded = tightbeam::encode(artifact).expect("an artifact encodes");
	let outer = AnyRef::from_der(&encoded).expect("an encoded artifact is one TLV");
	let mut fields = SliceReader::new(outer.value()).expect("an artifact holds its fields");
	let mut arranged = Vec::new();
	while !fields.is_finished() {
		let field = fields.tlv_bytes().expect("each field of an artifact is one TLV");
		arranged.push(in_der_order(AnyRef::from_der(field).expect("a field TLV decodes")));
	}

	let rearranged = Any::new(Tag::Sequence, arranged.concat()).expect("the fields fit a SEQUENCE");
	let der = rearranged.to_der().expect("a SEQUENCE encodes");
	Signed::<SignedData>::from_der(&der).expect("the arranged artifact is a SignedData")
}

/// The DER of `field`, with the elements of a `certificates` field in DER
/// order.
fn in_der_order(field: AnyRef<'_>) -> Vec<u8> {
	if field.tag() != CERTIFICATES {
		return field.to_der().expect("a field encodes");
	}

	let mut reader = SliceReader::new(field.value()).expect("the certificates hold their elements");
	let mut elements = Vec::new();
	while !reader.is_finished() {
		elements.push(reader.tlv_bytes().expect("each certificate is one TLV"));
	}

	elements.sort_unstable();
	let certificates = Any::new(CERTIFICATES, elements.concat()).expect("the certificates fit their tag");
	certificates.to_der().expect("the certificates encode")
}

/// The verdict of a third party on `artifact`: the parse of
/// [`StoredReceipt::try_from`], then [`StoredReceipt::verify`] under the
/// server and client certificates.
fn third_party_verdict(
	artifact: &SignedData,
	server_certificate: &Certificate,
	client_certificate: &Certificate,
) -> Result<(), HandshakeError> {
	let stored = StoredReceipt::try_from(stored_artifact(artifact))?;

	let server = server_certificate.to_owned();
	let server = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(server, KeyPurposes::HOUSE.server);
	let server = server.expect("the server certificate serves the server role");
	let client = client_certificate.to_owned();
	let client = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(client, KeyPurposes::HOUSE.client);
	let client = client.expect("the client certificate serves the client role");
	stored.verify(&server, &client)
}

/// Whether a third party verifies `artifact`, as [`third_party_verdict`]
/// answers.
fn third_party_verifies(
	artifact: &SignedData,
	server_certificate: &Certificate,
	client_certificate: &Certificate,
) -> Result<bool, TightBeamError> {
	let verdict = third_party_verdict(artifact, server_certificate, client_certificate);
	Ok(verdict.is_ok())
}

/// `octets` with the first bit of its first octet flipped.
fn flipped(octets: &OctetString) -> OctetString {
	let mut bytes = octets.as_bytes().to_vec();
	bytes[0] ^= 0x01;
	OctetString::new(bytes).expect("the bytes of an OCTET STRING fit one")
}

/// Applies `mutate` to the receipt that `artifact` signs as its body, and
/// writes the changed body back, with every signature left as it was.
fn tamper_body(artifact: &mut SignedData, mutate: fn(&mut SessionReceipt)) {
	let econtent = artifact.encap_content_info.econtent.as_ref();
	let econtent = econtent.expect("a receipt artifact carries its body");

	let body: OctetString = econtent.decode_as().expect("the body is an OCTET STRING");
	let mut receipt = SessionReceipt::from_der(body.as_bytes()).expect("the body is a receipt");
	mutate(&mut receipt);

	let body = OctetString::new(receipt.to_der().expect("a receipt encodes")).expect("a receipt fits an OCTET STRING");
	let econtent = Any::from_der(&body.to_der().expect("the body encodes")).expect("an encoded body decodes");

	artifact.encap_content_info.econtent = Some(econtent);
}

/// Applies `mutate` to the `SignerInfo` of `role` in `artifact`.
fn tamper_signer(artifact: &mut SignedData, role: ReceiptRole, mutate: fn(&mut SignerInfo)) {
	let stored = StoredReceipt::try_from(stored_artifact(artifact)).expect("a settled artifact parses");
	let target = stored.signer(role).expect("a settled artifact holds a signer of each role");
	let target = target.to_owned();

	let mut rebuilt = Vec::new();
	for signer in artifact.signer_infos.0.iter() {
		let mut signer = signer.to_owned();
		if signer == target {
			mutate(&mut signer);
		}

		rebuilt.push(signer);
	}

	artifact.signer_infos = rebuilt.try_into().expect("the rebuilt signers keep their order");
}

/// Flips a bit of the signature of `signer`.
fn flip_signature(signer: &mut SignerInfo) {
	signer.signature = flipped(&signer.signature);
}

/// Sets the settlement answer that `signer` signs to `answer`, or strips it
/// when `answer` is `None`.
fn set_answer_attr(signer: &mut SignerInfo, answer: Option<&'static [u8]>) {
	let attrs = signer.signed_attrs.take();
	let attrs = attrs.expect("the client SignerInfo carries signed attributes");

	let kept = attrs.iter().filter(|attribute| attribute.oid != RECEIPT_ANSWER);
	let mut rebuilt: Vec<Attribute> = kept.cloned().collect();
	if let Some(answer) = answer {
		let answer = OctetString::new(answer).expect("an answer fits an OCTET STRING");
		let value = Any::encode_from(&answer).expect("an OCTET STRING encodes");
		let mut values = SetOfVec::new();
		values.insert(value).expect("one value fits a SET OF");
		rebuilt.push(Attribute { oid: RECEIPT_ANSWER, values });
	}

	signer.signed_attrs = Some(rebuilt.try_into().expect("the rebuilt attributes fit a SET OF"));
}

/// A change that a tamper row makes to a settled artifact.
type Tamper = fn(&mut SignedData);

/// Raises the client-to-server budget in the signed body.
fn drift_budget(artifact: &mut SignedData) {
	tamper_body(artifact, |receipt| receipt.budgets.client_to_server += 1);
}

/// Raises the credit unit in the signed body.
fn drift_credit_unit(artifact: &mut SignedData) {
	tamper_body(artifact, |receipt| receipt.credit_unit += 1);
}

/// Swaps the settlement challenge in the signed body.
fn swap_challenge(artifact: &mut SignedData) {
	tamper_body(artifact, |receipt| {
		let challenge = OctetString::new(*b"receipt-invoice-43").expect("a challenge fits an OCTET STRING");
		receipt.ancillary = Some(challenge);
	});
}

/// Flips a bit of the server signature.
fn flip_server_signature(artifact: &mut SignedData) {
	tamper_signer(artifact, ReceiptRole::Server, flip_signature);
}

/// Flips a bit of the client countersignature.
fn flip_client_countersignature(artifact: &mut SignedData) {
	tamper_signer(artifact, ReceiptRole::Client, flip_signature);
}

/// Swaps the settlement answer that the client countersigned.
fn swap_answer(artifact: &mut SignedData) {
	tamper_signer(artifact, ReceiptRole::Client, |signer| {
		set_answer_attr(signer, Some(b"receipt-preimage-43"));
	});
}

/// Strips the settlement answer that the client countersigned.
fn strip_answer(artifact: &mut SignedData) {
	tamper_signer(artifact, ReceiptRole::Client, |signer| set_answer_attr(signer, None));
}

/// The artifact of the receipt that the client of a settled session retains,
/// with the certificates of its two signers.
struct SettledArtifact {
	/// The dual-signed artifact of the receipt.
	artifact: SignedData,
	/// The certificate of the server that signed the receipt.
	server_certificate: Arc<Certificate>,
	/// The certificate of the client that countersigned the receipt.
	client_certificate: Arc<Certificate>,
}

impl SettledArtifact {
	/// The artifact that the client of `session` retains.
	fn of(session: &MutualTransports) -> Self {
		let stored = session.client.session_receipt();
		let stored = stored.expect("the client of a settled session retains its receipt");

		SettledArtifact {
			artifact: SignedData::clone(stored.artifact()),
			server_certificate: Arc::clone(&session.server_certificate),
			client_certificate: Arc::clone(&session.client_certificate),
		}
	}

	/// The artifact of a fresh settled session.
	async fn fresh() -> Self {
		let session = establish_settled_session(&TraceCollector::new()).await;
		SettledArtifact::of(&session.expect("a settled session establishes"))
	}

	/// The verdict of a third party on `artifact` under the certificates of
	/// this settlement.
	fn verdict_on(&self, artifact: &SignedData) -> Result<(), HandshakeError> {
		third_party_verdict(artifact, &self.server_certificate, &self.client_certificate)
	}
}

tb_assert_spec! {
	pub ReceiptRoundTripSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(2)),
			(events::SESSION_RECEIPT_REFUSED, exactly!(0))
		]
	}
}

tb_scenario! {
	name: receipt_round_trip_dual_signed,
	spec: ReceiptRoundTripSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let session = establish_settled_session(&trace).await?;

			let client_receipt = session.client.session_receipt();
			let server_receipt = session.server.session_receipt();
			assert_eq!(client_receipt, server_receipt, "both endpoints must retain one receipt");

			let stored = client_receipt.ok_or_else(|| expectation_failure("client must retain the receipt"))?;
			let settings = session
				.client
				.negotiated_mux()
				.ok_or_else(|| expectation_failure("client must negotiate multiplexing"))?;

			assert_eq!(stored.receipt().budgets, REQUEST, "the receipt must state the requested budgets");
			assert_eq!(stored.receipt().credit_unit, settings.credit_unit().get(), "the receipt must state the negotiated credit unit");

			let challenge = stored.receipt().ancillary.as_ref().map(OctetString::as_bytes);
			let answer = stored.ancillary_response().map(OctetString::as_bytes);
			assert_eq!(challenge, Some(CHALLENGE), "the receipt must bind the settlement challenge");
			assert_eq!(answer, Some(RESPONSE), "the client receipt must bind the settlement answer");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ReceiptEmptyAnswerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(2))
		]
	}
}

// An empty answer is digest-identical to an absent one, because both
// endpoints canonicalize it to absent.
tb_scenario! {
	name: receipt_empty_answer_normalized,
	spec: ReceiptEmptyAnswerSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let hooks = MutualSessionHooks {
				authorizer: Some(Arc::new(GrantingAuthorizer::challenge_free())),
				approver: Some(Arc::new(AnsweringApprover::answering(b"")?)),
				observer: None,
				trace: Some(trace.share()),
			};

			let session = establish_mutual_transports(budget_offer(), server_offer(), hooks).await?;

			let client_receipt = session.client.session_receipt();
			let server_receipt = session.server.session_receipt();
			let stored_absent = client_receipt.is_some_and(|stored| stored.ancillary_response().is_none());
			assert!(stored_absent, "an empty answer must be stored as absent");
			assert_eq!(client_receipt, server_receipt, "both endpoints must retain one receipt");

			Ok(())
		}
	}
}

/// The settle hook receives the certificate of the client that countersigned
/// the receipt, so an authorizer can refuse a token that another client
/// spends (CWE-294).
#[tokio::test]
async fn settle_receives_the_certificate_of_the_client_that_spends_the_token() -> TestResult {
	let authorizer = Arc::new(SettleSpyAuthorizer::challenging(CHALLENGE)?);
	let hooks = MutualSessionHooks {
		authorizer: Some(Arc::clone(&authorizer) as Arc<dyn TransportAuthorizer>),
		approver: Some(Arc::new(PayingApprover::paying()?)),
		..MutualSessionHooks::default()
	};

	let session = establish_mutual_transports(budget_offer(), server_offer(), hooks).await?;
	assert_eq!(authorizer.settled_clients(), [Certificate::clone(&session.client_certificate)]);
	Ok(())
}

/// A third party verifies both signatures of a settled receipt offline.
#[tokio::test]
async fn a_third_party_verifies_a_settled_receipt_offline() {
	let settled = SettledArtifact::fresh().await;

	let verdict = settled.verdict_on(&settled.artifact);
	assert!(matches!(verdict, Ok(())));
}

// A third party refuses an artifact whose signed field, signature, or
// countersigned answer a tamper altered, because no signature verifies over
// the altered bytes.
tb_cases! {
	async fn a_tampered_artifact_fails_offline_verification(tamper: Tamper) {
		let settled = SettledArtifact::fresh().await;
		let mut tampered = settled.artifact.clone();
		tamper(&mut tampered);

		let verdict = settled.verdict_on(&tampered);
		assert!(matches!(verdict, Err(HandshakeError::SignatureVerificationFailed)));
	}
	cases {
		budget_drift_in_the_signed_body => drift_budget,
		credit_unit_drift_in_the_signed_body => drift_credit_unit,
		challenge_swap_in_the_signed_body => swap_challenge,
		server_signature_bit_flip => flip_server_signature,
		client_countersignature_bit_flip => flip_client_countersignature,
		settlement_answer_swap => swap_answer,
		settlement_answer_stripped => strip_answer,
	}
}

/// Client materials that present the certificate and the key of the server of
/// `materials`, so both signers of a receipt present one certificate.
fn twin_client(materials: &ServerMaterials) -> ClientMaterials {
	let certificate = Arc::clone(&materials.certificate);
	let key_provider = Arc::clone(&materials.key_provider);
	ClientMaterials { certificate, key_provider }
}

/// The count of the signers of `artifact`, beside the certificates that its
/// certificate set holds.
fn signers_and_certificates(artifact: &SignedData) -> (usize, Vec<Certificate>) {
	let signers = artifact.signer_infos.0.len();
	let choices = artifact.certificates.iter().flat_map(|set| set.0.iter());
	let certificates = choices.filter_map(|choice| match choice {
		CertificateChoices::Certificate(certificate) => Some(certificate.to_owned()),
		CertificateChoices::Other(_) => None,
	});
	(signers, certificates.collect())
}

/// A countersignature adds the certificate of its signer to the receipt only
/// when the certificate set lacks it, so a receipt whose two signers present
/// one certificate holds that certificate once.
#[tokio::test]
async fn a_receipt_whose_signers_share_a_certificate_holds_it_once() -> TestResult {
	let materials = ServerMaterials::fixed();
	let twin = twin_client(&materials);
	let hooks = MutualSessionHooks::default();
	let purposes = KeyPurposes::HOUSE;

	let session = establish_mutual_transports_of(budget_offer(), budget_offer(), hooks, &materials, &twin, purposes);
	let session = session.await?;
	let receipt = session.client.session_receipt();
	let signed = receipt.map(|stored| signers_and_certificates(stored.artifact()));
	assert_eq!(signed, Some((2, vec![Certificate::clone(&materials.certificate)])));
	Ok(())
}

tb_assert_spec! {
	pub ReceiptSettleRejectionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(1)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(1)),
			(events::SESSION_RECEIPT_REFUSED, exactly!(1), equals!(SETTLE_REFUSAL_CODE))
		]
	}
}

// HPKE completes client-side when it sends the closing, and a rejection
// surfaces on the first read.
tb_scenario! {
	name: receipt_settle_rejection_fails_closed,
	spec: ReceiptSettleRejectionSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::fixed();
			let client_materials = ClientMaterials::generate();
			let (listener, addr) = bind_mutual_listener(&materials, &client_materials.certificate).await?;

			let server_trace = trace.share();
			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(server_offer()))
					.with_transport_authorizer(Arc::new(ChallengingAuthorizer::new(false)?))
					.with_trace(server_trace);

				serve_one_handshake_message(&mut transport).await?;
				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(transport.session_receipt().cloned())
			});

			let mut client = connect_mutual_client(addr, &materials.certificate, &client_materials).await?;
			client = with_budget_approver(client, Arc::new(PayingApprover::paying()?)).with_trace(trace.share());

			// The client completes optimistically, and its session fails on
			// the first read.
			client.perform_client_handshake().await?;

			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			let server_rejected = matches!(
				server_result,
				Err(TightBeamError::TransportError(TransportError::HandshakeError(
					HandshakeError::SettlementRejected { code: SETTLE_REFUSAL_CODE }
				)))
			);
			assert!(server_rejected, "the server must reject the settlement with its code");

			let first_read = client.read_envelope_bytes().await;
			assert!(first_read.is_err(), "the client session must fail on its first read after the rejection");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ReceiptAbandonedSettlementSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_RECEIPT_REFUSED, exactly!(1), equals!(APPROVAL_REFUSAL_CODE)),
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(0)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(0))
		]
	}
}

tb_scenario! {
	name: receipt_abandoned_settlement_never_activates,
	spec: ReceiptAbandonedSettlementSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::fixed();
			let client_materials = ClientMaterials::generate();
			let (listener, addr) = bind_mutual_listener(&materials, &client_materials.certificate).await?;

			let server_trace = trace.share();
			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(server_offer()))
					.with_transport_authorizer(Arc::new(ChallengingAuthorizer::new(true)?))
					.with_trace(server_trace);

				serve_one_handshake_message(&mut transport).await?;
				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(())
			});

			let mut client = connect_mutual_client(addr, &materials.certificate, &client_materials).await?;
			client = with_budget_approver(client, Arc::new(PayingApprover::refusing(APPROVAL_REFUSAL_CODE)?))
				.with_trace(trace.share());

			let client_result = client.perform_client_handshake().await;

			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			let client_refused = matches!(
				client_result,
				Err(TransportError::HandshakeError(HandshakeError::ApprovalRefused {
					code: APPROVAL_REFUSAL_CODE,
				}))
			);
			assert!(client_refused, "the client must refuse the receipt with the approver's code");
			assert!(server_result.is_err(), "the server must never activate");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ReceiptOutcomeActivatedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(2))
		]
	}
}

tb_scenario! {
	name: receipt_outcome_recorded_on_activation,
	spec: ReceiptOutcomeActivatedSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let observer = Arc::new(RecordingObserver::default());
			let session = establish_settled_session_observed(Some(Arc::clone(&observer) as Arc<dyn SessionObserver>), &trace).await?;

			let outcomes = observer.recorded();
			assert_eq!(outcomes.len(), 1, "the observer must see one outcome");

			let stored = session
				.server
				.session_receipt()
				.ok_or_else(|| expectation_failure("server must retain the receipt"))?;
			let matches_stored = outcomes.first().is_some_and(|outcome| {
				outcome.verdict == SessionVerdict::Activated
					&& outcome.receipt == *stored.receipt()
					&& outcome.artifact == *stored.artifact()
					&& outcome.countersignature.is_some()
					&& outcome.ancillary_response.as_ref() == stored.ancillary_response()
					&& outcome.client_certificate.as_deref() == Some(session.client_certificate.as_ref())
			});
			assert!(matches_stored, "the activated outcome must carry the stored evidence");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ReceiptOutcomeRefusedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_RECEIPT_REFUSED, exactly!(1), equals!(SETTLE_REFUSAL_CODE)),
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(1)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(1))
		]
	}
}

// A refused countersignature remains evidence that a third party can verify.
tb_scenario! {
	name: receipt_outcome_preserves_refused_evidence,
	spec: ReceiptOutcomeRefusedSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::fixed();
			let client_materials = ClientMaterials::generate();
			let (listener, addr) = bind_mutual_listener(&materials, &client_materials.certificate).await?;

			let observer = Arc::new(RecordingObserver::default());
			let server_observer = Arc::clone(&observer);
			let server_trace = trace.share();
			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(server_offer()))
					.with_transport_authorizer(Arc::new(ChallengingAuthorizer::new(false)?))
					.with_session_observer(server_observer as Arc<dyn SessionObserver>)
					.with_trace(server_trace);

				serve_one_handshake_message(&mut transport).await?;
				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(())
			});

			let mut client = connect_mutual_client(addr, &materials.certificate, &client_materials).await?;
			client = with_budget_approver(client, Arc::new(PayingApprover::paying()?)).with_trace(trace.share());

			// The client completes optimistically, ahead of the refusal.
			client.perform_client_handshake().await?;

			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			assert!(server_result.is_err(), "settle refusal must abort the server handshake");

			let outcomes = observer.recorded();
			assert_eq!(outcomes.len(), 1, "the observer must see one outcome");

			let refused_by_client = outcomes.first().is_some_and(|outcome| {
				outcome.verdict == SessionVerdict::SettlementRejected { code: SETTLE_REFUSAL_CODE }
					&& outcome.client_certificate.as_deref() == Some(client_materials.certificate.as_ref())
			});
			assert!(refused_by_client, "the outcome must name the refusal and the client that countersigned");

			let evidence = outcomes
				.first()
				.filter(|outcome| outcome.countersignature.is_some())
				.map(|outcome| outcome.artifact.to_owned())
				.ok_or_else(|| expectation_failure("refusal outcome must carry the countersignature"))?;
			let verifies = third_party_verifies(&evidence, &materials.certificate, &client_materials.certificate)?;
			assert!(verifies, "the refused evidence must verify offline");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ReceiptNoApproverSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_RECEIPT_REFUSED, exactly!(1), equals!(SETTLEMENT_UNSUPPORTED_CODE)),
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(0)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(0))
		]
	}
}

// A client with no receipt approver refuses a settlement challenge with
// `SETTLEMENT_UNSUPPORTED_CODE`, and the server never activates, so silence is
// never consent to a settlement demand.
tb_scenario! {
	name: receipt_challenge_without_approver_fails_closed,
	spec: ReceiptNoApproverSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::fixed();
			let client_materials = ClientMaterials::generate();
			let (listener, addr) = bind_mutual_listener(&materials, &client_materials.certificate).await?;

			let server_trace = trace.share();
			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(server_offer()))
					.with_transport_authorizer(Arc::new(ChallengingAuthorizer::new(true)?))
					.with_trace(server_trace);

				serve_one_handshake_message(&mut transport).await?;
				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(())
			});

			let mut client = connect_mutual_client(addr, &materials.certificate, &client_materials).await?;
			client = with_budget_offer(client).with_trace(trace.share());

			let client_result = client.perform_client_handshake().await;
			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			let client_failed_closed = matches!(
				client_result,
				Err(TransportError::HandshakeError(HandshakeError::ApprovalRefused {
					code: SETTLEMENT_UNSUPPORTED_CODE,
				}))
			);
			assert!(client_failed_closed, "the client must fail closed with the unsupported settlement code");
			assert!(server_result.is_err(), "the server must never activate");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ReceiptMutualAuthSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(2), equals!("mutual-auth-required"))
		]
	}
}

// Budgets need mutual authentication: a server with no client validators
// cannot verify a countersignature, and a client with no identity cannot
// countersign. The refusing endpoint of each case records one refusal.
tb_scenario! {
	name: receipt_budgets_require_mutual_auth,
	spec: ReceiptMutualAuthSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::fixed();
			let client_materials = ClientMaterials::generate();

			// The first server has no client validators.
			let (listener, addr) = bind_encrypted_listener(&materials).await?;
			let server_trace = trace.share();
			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(server_offer()))
					.with_transport_authorizer(Arc::new(ChallengingAuthorizer::new(false)?))
					.with_trace(server_trace);

				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(())
			});

			let mut client = connect_pinned_client(addr, &materials.certificate).await?;
			client = with_budget_approver(client, Arc::new(PayingApprover::paying()?));

			let client_result = client.perform_client_handshake().await;
			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			let server_refused = matches!(
				server_result,
				Err(TightBeamError::TransportError(TransportError::HandshakeError(
					HandshakeError::MutualAuthRequired
				)))
			);
			assert!(server_refused, "the server must refuse to issue a receipt it cannot verify");
			assert!(client_result.is_err(), "the client of a refusing server must fail its handshake");

			// The second client pins the server, and it has no identity to
			// countersign with.
			let (listener, addr) = bind_mutual_listener(&materials, &client_materials.certificate).await?;
			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(server_offer()))
					.with_transport_authorizer(Arc::new(ChallengingAuthorizer::new(false)?));

				serve_one_handshake_message(&mut transport).await?;
				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(())
			});

			let approver = Arc::new(PayingApprover::paying()?);
			let mut client = connect_pinned_client(addr, &materials.certificate).await?;
			client = with_budget_approver(client, Arc::clone(&approver)).with_trace(trace.share());

			let client_result = client.perform_client_handshake().await;
			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			assert!(server_result.is_err(), "client abort must fail the server handshake");

			let client_refused = matches!(
				client_result,
				Err(TransportError::HandshakeError(HandshakeError::MutualAuthRequired))
			);
			assert!(client_refused, "an identityless client must refuse to countersign");

			// The identity check runs before the approver, because a settlement
			// answer is irreversible.
			assert_eq!(approver.approve_calls(), 0, "an identityless client must refuse before it consults the approver");

			Ok(())
		}
	}
}
