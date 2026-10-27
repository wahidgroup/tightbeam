//! The integration tests of the dual-signed session receipt.

#![cfg(all(
	feature = "transport-hpke",
	feature = "transport-policy",
	feature = "transport-multiplex",
	feature = "tcp",
	feature = "tokio",
	feature = "testing",
	feature = "instrument"
))]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tightbeam::asn1::Any;
use tightbeam::cms::signed_data::{SignedData, SignerInfo};
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::Signed;
use tightbeam::crypto::x509::{KeyPurposes, PeerCertificate, Signing};
use tightbeam::der::asn1::{OctetString, SetOfVec};
use tightbeam::der::{Decode, Encode};
use tightbeam::exactly;
use tightbeam::oids::RECEIPT_ANSWER;
use tightbeam::tb_assert_spec;
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
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::x509::attr::Attribute;
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;

use tightbeam::instrumentation::events;

use crate::common::security::{
	expectation_failure, ClientMaterials, GrantingAuthorizer, PayingApprover as AnsweringApprover, RecordingObserver,
	ServerMaterials,
};
use crate::transport::support::{
	bind_encrypted_listener, bind_mutual_listener, connect_mutual_client, connect_pinned_client,
	establish_mutual_transports, join_task, serve_one_handshake_message, MutualSessionHooks, MutualTransports,
};

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

fn server_offer() -> TransportOffer {
	TransportOffer::mux(4)
}

fn budget_offer() -> TransportOffer {
	server_offer().with_budgets(REQUEST)
}

fn with_budget_offer(client: TcpTransport<TokioStream>) -> TcpTransport<TokioStream> {
	client.with_mux_offer(Some(budget_offer()))
}

fn with_budget_approver(client: TcpTransport<TokioStream>, approver: Arc<PayingApprover>) -> TcpTransport<TokioStream> {
	with_budget_offer(client).with_receipt_approver(approver as Arc<dyn ReceiptApprover>)
}

/// An authorizer that binds `CHALLENGE` into every grant. Settlement succeeds
/// only for the expected answer, and only when `accept_settlement` is set.
struct ChallengingAuthorizer {
	challenge: OctetString,
	expected_response: OctetString,
	accept_settlement: bool,
}

impl ChallengingAuthorizer {
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
struct PayingApprover {
	response: OctetString,
	refusal: Option<u32>,
	approve_calls: AtomicUsize,
}

impl PayingApprover {
	fn paying() -> Result<Self, TightBeamError> {
		Ok(Self {
			response: OctetString::new(RESPONSE)?,
			refusal: None,
			approve_calls: AtomicUsize::new(0),
		})
	}

	fn refusing(code: u32) -> Result<Self, TightBeamError> {
		Ok(Self {
			response: OctetString::new(RESPONSE)?,
			refusal: Some(code),
			approve_calls: AtomicUsize::new(0),
		})
	}

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

async fn establish_settled_session(trace: &TraceCollector) -> Result<MutualTransports, TightBeamError> {
	establish_settled_session_observed(None, trace).await
}

/// `artifact` as a third party reads it back from storage.
fn stored_artifact(artifact: &SignedData) -> Result<Signed<SignedData>, TightBeamError> {
	let der = tightbeam::encode(artifact)?;
	Ok(Signed::<SignedData>::from_der(&der)?)
}

/// Whether a third party verifies `artifact` through [`StoredReceipt::verify`]
/// under the server and client certificates.
fn third_party_verifies(
	artifact: &SignedData,
	server_certificate: &Certificate,
	client_certificate: &Certificate,
) -> Result<bool, TightBeamError> {
	let Ok(stored) = StoredReceipt::try_from(stored_artifact(artifact)?) else {
		return Ok(false);
	};

	let server = server_certificate.to_owned();
	let server = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(server, KeyPurposes::HOUSE.server)?;
	let client = client_certificate.to_owned();
	let client = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(client, KeyPurposes::HOUSE.client)?;
	let verdict = stored.verify(&server, &client);
	Ok(verdict.is_ok())
}

fn flipped(octets: &OctetString) -> Result<OctetString, TightBeamError> {
	let mut bytes = octets.as_bytes().to_vec();
	bytes[0] ^= 0x01;
	Ok(OctetString::new(bytes)?)
}

fn tamper_body(
	artifact: &mut SignedData,
	mutate: fn(&mut SessionReceipt) -> Result<(), TightBeamError>,
) -> Result<(), TightBeamError> {
	let econtent = artifact
		.encap_content_info
		.econtent
		.as_ref()
		.ok_or_else(|| expectation_failure("receipt artifact must carry its body"))?;

	let body: OctetString = econtent.decode_as()?;
	let mut receipt = SessionReceipt::from_der(body.as_bytes())?;
	mutate(&mut receipt)?;

	let body = OctetString::new(receipt.to_der()?)?;
	let econtent = Any::from_der(&body.to_der()?)?;

	artifact.encap_content_info.econtent = Some(econtent);
	Ok(())
}

fn tamper_signer(
	artifact: &mut SignedData,
	role: ReceiptRole,
	mutate: fn(&mut SignerInfo) -> Result<(), TightBeamError>,
) -> Result<(), TightBeamError> {
	let stored = StoredReceipt::try_from(stored_artifact(artifact)?)?;
	let target = stored.signer(role)?.to_owned();

	let mut rebuilt = Vec::new();
	for signer in artifact.signer_infos.0.iter() {
		let mut signer = signer.to_owned();
		if signer == target {
			mutate(&mut signer)?;
		}

		rebuilt.push(signer);
	}

	artifact.signer_infos = rebuilt.try_into()?;
	Ok(())
}

fn flip_signature(signer: &mut SignerInfo) -> Result<(), TightBeamError> {
	signer.signature = flipped(&signer.signature)?;
	Ok(())
}

fn set_answer_attr(signer: &mut SignerInfo, answer: Option<&'static [u8]>) -> Result<(), TightBeamError> {
	let attrs = signer
		.signed_attrs
		.take()
		.ok_or_else(|| expectation_failure("client SignerInfo must carry signed attributes"))?;

	let mut rebuilt: Vec<Attribute> = attrs
		.iter()
		.filter(|attribute| attribute.oid != RECEIPT_ANSWER)
		.cloned()
		.collect();
	if let Some(answer) = answer {
		let value = Any::encode_from(&OctetString::new(answer)?)?;
		let mut values = SetOfVec::new();
		values.insert(value)?;
		rebuilt.push(Attribute { oid: RECEIPT_ANSWER, values });
	}

	signer.signed_attrs = Some(rebuilt.try_into()?);
	Ok(())
}

type Tamper = fn(&mut SignedData) -> Result<(), TightBeamError>;

/// Raises the client-to-server budget in the signed body.
fn drift_budget(artifact: &mut SignedData) -> Result<(), TightBeamError> {
	tamper_body(artifact, |receipt| {
		receipt.budgets.client_to_server += 1;
		Ok(())
	})
}

/// Raises the credit unit in the signed body.
fn drift_credit_unit(artifact: &mut SignedData) -> Result<(), TightBeamError> {
	tamper_body(artifact, |receipt| {
		receipt.credit_unit += 1;
		Ok(())
	})
}

/// Swaps the settlement challenge in the signed body.
fn swap_challenge(artifact: &mut SignedData) -> Result<(), TightBeamError> {
	tamper_body(artifact, |receipt| {
		receipt.ancillary = Some(OctetString::new(*b"receipt-invoice-43")?);
		Ok(())
	})
}

/// Flips a bit of the server signature.
fn flip_server_signature(artifact: &mut SignedData) -> Result<(), TightBeamError> {
	tamper_signer(artifact, ReceiptRole::Server, flip_signature)
}

/// Flips a bit of the client countersignature.
fn flip_client_countersignature(artifact: &mut SignedData) -> Result<(), TightBeamError> {
	tamper_signer(artifact, ReceiptRole::Client, flip_signature)
}

/// Swaps the settlement answer that the client countersigned.
fn swap_answer(artifact: &mut SignedData) -> Result<(), TightBeamError> {
	tamper_signer(artifact, ReceiptRole::Client, |signer| {
		set_answer_attr(signer, Some(b"receipt-preimage-43"))
	})
}

/// Strips the settlement answer that the client countersigned.
fn strip_answer(artifact: &mut SignedData) -> Result<(), TightBeamError> {
	tamper_signer(artifact, ReceiptRole::Client, |signer| set_answer_attr(signer, None))
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

/// The artifact of a session that settles on a runtime of its own, for a
/// case-table test, which runs off the async runtime.
fn settled_artifact() -> SettledArtifact {
	let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build();
	let runtime = runtime.expect("a current-thread runtime builds");
	let settled = runtime.block_on(establish_settled_session(&TraceCollector::new()));
	let session = settled.expect("a settled session establishes");
	let stored = session.client.session_receipt().expect("the client retains the receipt");

	SettledArtifact {
		artifact: SignedData::clone(stored.artifact()),
		server_certificate: Arc::clone(&session.server_certificate),
		client_certificate: Arc::clone(&session.client_certificate),
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
			assert_eq!(stored.receipt().credit_unit, settings.credit_unit, "the receipt must state the negotiated credit unit");

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

/// A third party verifies both signatures of a settled receipt offline.
#[tokio::test]
async fn receipt_third_party_verifiable() -> Result<(), TightBeamError> {
	let session = establish_settled_session(&TraceCollector::new()).await?;
	let stored = session
		.client
		.session_receipt()
		.ok_or_else(|| expectation_failure("client must retain the receipt"))?;

	let verifies = third_party_verifies(stored.artifact(), &session.server_certificate, &session.client_certificate)?;
	assert!(verifies, "a third party must verify both signatures offline");
	Ok(())
}

// A third party refuses an artifact that a tamper altered, whichever signed
// field, signature, or countersigned answer the tamper altered.
tightbeam::tb_cases! {
	fn a_tampered_artifact_fails_offline_verification(tamper: Tamper) -> Result<(), TightBeamError> {
		let settled = settled_artifact();
		let mut tampered = settled.artifact.clone();
		tamper(&mut tampered)?;

		let verifies = third_party_verifies(&tampered, &settled.server_certificate, &settled.client_certificate)?;
		assert!(!verifies, "a tampered artifact must fail offline verification");
		Ok(())
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
			let materials = ServerMaterials::generate();
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
			let materials = ServerMaterials::generate();
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
			let materials = ServerMaterials::generate();
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

// Silence is never consent to a settlement demand.
tb_scenario! {
	name: receipt_challenge_without_approver_fails_closed,
	spec: ReceiptNoApproverSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
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
// countersign. The refusing endpoint of each sub-case carries the trace, so
// each records one identity refusal.
tb_scenario! {
	name: receipt_budgets_require_mutual_auth,
	spec: ReceiptMutualAuthSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
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
