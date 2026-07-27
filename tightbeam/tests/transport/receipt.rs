//! Dual-signed session receipt integration tests.

#![cfg(all(
	feature = "transport-ecies",
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
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};
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
use tightbeam::transport::{EncryptedMessageIO, MessageIO, TransportError, X509ClientConfig};
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::x509::attr::Attribute;
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;

use tightbeam::instrumentation::events;
use tightbeam::utils::urn::Urn;

pub(crate) const ANSWER_BOUND: Urn<'static> = Urn::new("test", "event:receipt/answer-bound");
pub(crate) const BOTH_SIGNATURES_VERIFY_OFFLINE: Urn<'static> =
	Urn::new("test", "event:receipt/both-signatures-verify-offline");
pub(crate) const CHALLENGE_BOUND: Urn<'static> = Urn::new("test", "event:receipt/challenge-bound");
pub(crate) const CLIENT_COMPLETES_OPTIMISTICALLY: Urn<'static> =
	Urn::new("test", "event:receipt/client-completes-optimistically");
pub(crate) const CLIENT_FAILS_CLOSED_UNSUPPORTED: Urn<'static> =
	Urn::new("test", "event:receipt/client-fails-closed-unsupported");
pub(crate) const CLIENT_REFUSES_WITH_CODE: Urn<'static> = Urn::new("test", "event:receipt/client-refuses-with-code");
pub(crate) const CLIENT_RETAINS_RECEIPT: Urn<'static> = Urn::new("test", "event:receipt/client-retains-receipt");
pub(crate) const CLIENT_SESSION_DEAD_ON_FIRST_USE: Urn<'static> =
	Urn::new("test", "event:receipt/client-session-dead-on-first-use");
pub(crate) const EMPTY_ANSWER_STORED_AS_ABSENT: Urn<'static> =
	Urn::new("test", "event:receipt/empty-answer-stored-as-absent");
pub(crate) const ENDPOINTS_RETAIN_IDENTICAL_RECEIPTS: Urn<'static> =
	Urn::new("test", "event:receipt/endpoints-retain-identical-receipts");
pub(crate) const IDENTITYLESS_CLIENT_NEVER_CONSULTS_APPROVER: Urn<'static> =
	Urn::new("test", "event:receipt/identityless-client-never-consults-approver");
pub(crate) const IDENTITYLESS_CLIENT_REFUSES_TO_COUNTERSIGN: Urn<'static> =
	Urn::new("test", "event:receipt/identityless-client-refuses-to-countersign");
pub(crate) const RECEIPTS_IDENTICAL: Urn<'static> = Urn::new("test", "event:receipt/receipts-identical");
pub(crate) const RECEIPT_MATCHES_NEGOTIATION: Urn<'static> =
	Urn::new("test", "event:receipt/receipt-matches-negotiation");
pub(crate) const REFUSAL_OUTCOME_RECORDED: Urn<'static> = Urn::new("test", "event:receipt/refusal-outcome-recorded");
pub(crate) const REFUSED_RECEIPT_VERIFIES_OFFLINE: Urn<'static> =
	Urn::new("test", "event:receipt/refused-receipt-verifies-offline");
pub(crate) const SERVER_NEVER_ACTIVATES: Urn<'static> = Urn::new("test", "event:receipt/server-never-activates");
pub(crate) const SERVER_REFUSES_TO_ISSUE_UNVERIFIABLE_RECEIPT: Urn<'static> =
	Urn::new("test", "event:receipt/server-refuses-to-issue-unverifiable-receipt");
pub(crate) const SERVER_REJECTS_WITH_CODE: Urn<'static> = Urn::new("test", "event:receipt/server-rejects-with-code");
pub(crate) const SERVER_RETAINS_RECEIPT: Urn<'static> = Urn::new("test", "event:receipt/server-retains-receipt");
pub(crate) const SINGLE_OUTCOME_RECORDED: Urn<'static> = Urn::new("test", "event:receipt/single-outcome-recorded");
pub(crate) const TAMPERED_ARTIFACT_FAILS_VERIFICATION: Urn<'static> =
	Urn::new("test", "event:receipt/tampered-artifact-fails-verification");
pub(crate) const VERDICT_ACTIVATED_WITH_EVIDENCE: Urn<'static> =
	Urn::new("test", "event:receipt/verdict-activated-with-evidence");

use crate::common::security::{
	expectation_failure, ClientMaterials, GrantingAuthorizer, PayingApprover as AnsweringApprover, RecordingObserver,
	ServerMaterials,
};
use crate::transport::support::{
	bind_encrypted_listener, bind_mutual_listener, connect_mutual_client, connect_pinned_client,
	establish_mutual_transports, join_task, serve_one_handshake_message, MutualSessionHooks, MutualTransports,
};

/// Settlement challenge the authorizer binds into every receipt.
const CHALLENGE: &[u8] = b"receipt-invoice-42";

/// Settlement answer the approver countersigns.
const RESPONSE: &[u8] = b"receipt-preimage-42";

/// Application code for a settle refusal.
const SETTLE_REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR + 7;

/// Application code for a client approval refusal.
const APPROVAL_REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR + 8;

/// Budgets requested by the client in every scenario.
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

/// Settlement succeeds only for the expected answer.
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

/// Counts consultations so scenarios can prove the hook never fired.
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

fn verifying_key_from(certificate: &Certificate) -> Result<Secp256k1VerifyingKey, TightBeamError> {
	let sec1 = certificate
		.tbs_certificate
		.subject_public_key_info
		.subject_public_key
		.raw_bytes();

	Secp256k1VerifyingKey::from_sec1_bytes(sec1)
		.map_err(|_| expectation_failure("certificate must carry a valid SEC1 public key"))
}

/// Third-party verify via [`StoredReceipt::verify`].
fn third_party_verifies(
	artifact: &SignedData,
	server_certificate: &Certificate,
	client_certificate: &Certificate,
) -> Result<bool, TightBeamError> {
	let Ok(stored) = StoredReceipt::try_from(artifact.to_owned()) else {
		return Ok(false);
	};

	let server_key = verifying_key_from(server_certificate)?;
	let client_key = verifying_key_from(client_certificate)?;
	let verdict = stored.verify::<Sha3_256, Secp256k1Signature, _>(&server_key, &client_key);
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
	let stored = StoredReceipt::try_from(artifact.to_owned())?;
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

/// Tamper cases: body, signatures, settlement answer.
const TAMPER_CASES: &[(&str, Tamper)] = &[
	("budget drift in the signed body", |artifact| {
		tamper_body(artifact, |receipt| {
			receipt.budgets.client_to_server += 1;
			Ok(())
		})
	}),
	("credit-unit drift in the signed body", |artifact| {
		tamper_body(artifact, |receipt| {
			receipt.credit_unit += 1;
			Ok(())
		})
	}),
	("challenge swap in the signed body", |artifact| {
		tamper_body(artifact, |receipt| {
			receipt.ancillary = Some(OctetString::new(*b"receipt-invoice-43")?);
			Ok(())
		})
	}),
	("server signature bit flip", |artifact| {
		tamper_signer(artifact, ReceiptRole::Server, flip_signature)
	}),
	("client countersignature bit flip", |artifact| {
		tamper_signer(artifact, ReceiptRole::Client, flip_signature)
	}),
	("settlement answer swap", |artifact| {
		tamper_signer(artifact, ReceiptRole::Client, |signer| {
			set_answer_attr(signer, Some(b"receipt-preimage-43"))
		})
	}),
	("settlement answer stripped", |artifact| {
		tamper_signer(artifact, ReceiptRole::Client, |signer| set_answer_attr(signer, None))
	}),
];

tb_assert_spec! {
	pub ReceiptRoundTripSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(2)),
			(events::SESSION_RECEIPT_REFUSED, exactly!(0)),
			(CLIENT_RETAINS_RECEIPT, exactly!(1), equals!(true)),
			(SERVER_RETAINS_RECEIPT, exactly!(1), equals!(true)),
			(RECEIPTS_IDENTICAL, exactly!(1), equals!(true)),
			(RECEIPT_MATCHES_NEGOTIATION, exactly!(1), equals!(true)),
			(CHALLENGE_BOUND, exactly!(1), equals!(true)),
			(ANSWER_BOUND, exactly!(1), equals!(true))
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
			trace.event_with(CLIENT_RETAINS_RECEIPT, &[], client_receipt.is_some())?;
			trace.event_with(SERVER_RETAINS_RECEIPT, &[], server_receipt.is_some())?;
			trace.event_with(RECEIPTS_IDENTICAL, &[], client_receipt == server_receipt)?;

			let stored = client_receipt.ok_or_else(|| expectation_failure("client must retain the receipt"))?;
			let settings = session
				.client
				.negotiated_mux()
				.ok_or_else(|| expectation_failure("client must negotiate multiplexing"))?;

			let is_budget_matched = stored.receipt().budgets == REQUEST;
			let is_credit_unit_matched = stored.receipt().credit_unit == settings.credit_unit;
			trace.event_with(RECEIPT_MATCHES_NEGOTIATION, &[], is_budget_matched && is_credit_unit_matched)?;

			let challenge = stored.receipt().ancillary.as_ref().map(OctetString::as_bytes);
			let answer = stored.ancillary_response().map(OctetString::as_bytes);
			trace.event_with(CHALLENGE_BOUND, &[], challenge == Some(CHALLENGE))?;
			trace.event_with(ANSWER_BOUND, &[], answer == Some(RESPONSE))?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ReceiptEmptyAnswerSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(2)),
			(EMPTY_ANSWER_STORED_AS_ABSENT, exactly!(1), equals!(true)),
			(ENDPOINTS_RETAIN_IDENTICAL_RECEIPTS, exactly!(1), equals!(true))
		]
	}
}

// Empty answer digest-identical to absent; both endpoints canonicalize to absent.
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
			trace.event_with(EMPTY_ANSWER_STORED_AS_ABSENT, &[], stored_absent)?;
			trace.event_with(
				ENDPOINTS_RETAIN_IDENTICAL_RECEIPTS,
				&[],
				client_receipt == server_receipt,
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ReceiptThirdPartySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(BOTH_SIGNATURES_VERIFY_OFFLINE, exactly!(1), equals!(true)),
			(TAMPERED_ARTIFACT_FAILS_VERIFICATION, exactly!(7), equals!(true))
		]
	}
}

tb_scenario! {
	name: receipt_third_party_verifiable,
	spec: ReceiptThirdPartySpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let session = establish_settled_session(&trace).await?;
			let stored = session
				.client
				.session_receipt()
				.ok_or_else(|| expectation_failure("client must retain the receipt"))?;

			let artifact = stored.artifact();
			let pristine_verifies = third_party_verifies(artifact, &session.server_certificate, &session.client_certificate)?;
			trace.event_with(BOTH_SIGNATURES_VERIFY_OFFLINE, &[], pristine_verifies)?;

			for (forgery, tamper) in TAMPER_CASES {
				let mut tampered = stored.artifact().to_owned();
				tamper(&mut tampered)?;

				let forgery_verifies =
					third_party_verifies(&tampered, &session.server_certificate, &session.client_certificate)?;
				trace.event_with(
					TAMPERED_ARTIFACT_FAILS_VERIFICATION,
					vec![*forgery],
					!forgery_verifies,
				)?;
			}

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ReceiptSettleRejectionSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(1)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(1)),
			(events::SESSION_RECEIPT_REFUSED, exactly!(1)),
			(SERVER_REJECTS_WITH_CODE, exactly!(1), equals!(true)),
			(CLIENT_COMPLETES_OPTIMISTICALLY, exactly!(1), equals!(true)),
			(CLIENT_SESSION_DEAD_ON_FIRST_USE, exactly!(1), equals!(true))
		]
	}
}

// ECIES completes client-side on key exchange send; rejection surfaces on first read.
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
			let client_result = client.perform_client_handshake().await;

			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			let server_rejected = matches!(
				server_result,
				Err(TightBeamError::TransportError(TransportError::HandshakeError(
					HandshakeError::SettlementRejected { code: SETTLE_REFUSAL_CODE }
				)))
			);
			trace.event_with(SERVER_REJECTS_WITH_CODE, &[], server_rejected)?;

			// Client completed optimistically; dead session on first read.
			trace.event_with(
				CLIENT_COMPLETES_OPTIMISTICALLY,
				&[],
				client_result.is_ok(),
			)?;

			let first_read = client.read_envelope().await;
			trace.event_with(
				CLIENT_SESSION_DEAD_ON_FIRST_USE,
				&[],
				first_read.is_err(),
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ReceiptAbandonedSettlementSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::SESSION_RECEIPT_REFUSED, exactly!(1)),
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(0)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(0)),
			(CLIENT_REFUSES_WITH_CODE, exactly!(1), equals!(true)),
			(SERVER_NEVER_ACTIVATES, exactly!(1), equals!(true))
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
			trace.event_with(CLIENT_REFUSES_WITH_CODE, &[], client_refused)?;
			trace.event_with(
				SERVER_NEVER_ACTIVATES,
				&[],
				server_result.is_err(),
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ReceiptOutcomeActivatedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(2)),
			(SINGLE_OUTCOME_RECORDED, exactly!(1), equals!(true)),
			(VERDICT_ACTIVATED_WITH_EVIDENCE, exactly!(1), equals!(true))
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
			trace.event_with(SINGLE_OUTCOME_RECORDED, &[], outcomes.len() == 1)?;

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
			trace.event_with(VERDICT_ACTIVATED_WITH_EVIDENCE, &[], matches_stored)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ReceiptOutcomeRefusedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::SESSION_RECEIPT_REFUSED, exactly!(1)),
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(1)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(1)),
			(REFUSAL_OUTCOME_RECORDED, exactly!(1), equals!(true)),
			(REFUSED_RECEIPT_VERIFIES_OFFLINE, exactly!(1), equals!(true))
		]
	}
}

// Refused countersignature remains third-party verifiable evidence.
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
			let _ = client.perform_client_handshake().await;

			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			if server_result.is_ok() {
				return Err(expectation_failure("settle refusal must abort the server handshake"));
			}

			let outcomes = observer.recorded();
			let refusal_recorded = outcomes.len() == 1
				&& outcomes.first().is_some_and(|outcome| {
					outcome.verdict == SessionVerdict::SettlementRejected { code: SETTLE_REFUSAL_CODE }
						&& outcome.client_certificate.as_deref() == Some(client_materials.certificate.as_ref())
				});
			trace.event_with(REFUSAL_OUTCOME_RECORDED, &[], refusal_recorded)?;

			let evidence = outcomes
				.first()
				.filter(|outcome| outcome.countersignature.is_some())
				.map(|outcome| outcome.artifact.to_owned())
				.ok_or_else(|| expectation_failure("refusal outcome must carry the countersignature"))?;
			trace.event_with(
				REFUSED_RECEIPT_VERIFIES_OFFLINE,
				&[],
				third_party_verifies(&evidence, &materials.certificate, &client_materials.certificate)?,
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ReceiptNoApproverSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::SESSION_RECEIPT_REFUSED, exactly!(1)),
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(0)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(0)),
			(CLIENT_FAILS_CLOSED_UNSUPPORTED, exactly!(1), equals!(true)),
			(SERVER_NEVER_ACTIVATES, exactly!(1), equals!(true))
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

			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(server_offer()))
					.with_transport_authorizer(Arc::new(ChallengingAuthorizer::new(true)?));

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
			trace.event_with(CLIENT_FAILS_CLOSED_UNSUPPORTED, &[], client_failed_closed)?;
			trace.event_with(SERVER_NEVER_ACTIVATES, &[], server_result.is_err())?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ReceiptMutualAuthSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(SERVER_REFUSES_TO_ISSUE_UNVERIFIABLE_RECEIPT, exactly!(1), equals!(true)),
			(IDENTITYLESS_CLIENT_REFUSES_TO_COUNTERSIGN, exactly!(1), equals!(true)),
			(IDENTITYLESS_CLIENT_NEVER_CONSULTS_APPROVER, exactly!(1), equals!(true))
		]
	}
}

// Budgets without mutual auth: server cannot verify countersignature; client cannot countersign.
tb_scenario! {
	name: receipt_budgets_require_mutual_auth,
	spec: ReceiptMutualAuthSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let client_materials = ClientMaterials::generate();

			// Server: no client validators.
			let (listener, addr) = bind_encrypted_listener(&materials).await?;
			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(server_offer()))
					.with_transport_authorizer(Arc::new(ChallengingAuthorizer::new(false)?));

				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(())
			});

			let mut client = connect_pinned_client(addr, &materials.certificate).await?;
			client = with_budget_approver(client, Arc::new(PayingApprover::paying()?));
			let _ = client.perform_client_handshake().await;

			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			let server_refused = matches!(
				server_result,
				Err(TightBeamError::TransportError(TransportError::HandshakeError(
					HandshakeError::MutualAuthRequired
				)))
			);
			trace.event_with(
				SERVER_REFUSES_TO_ISSUE_UNVERIFIABLE_RECEIPT,
				&[],
				server_refused,
			)?;

			// Client: pinned, no identity to countersign with.
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
			client = with_budget_approver(client, Arc::clone(&approver));
			let client_result = client.perform_client_handshake().await;

			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			if server_result.is_ok() {
				return Err(expectation_failure("client abort must fail the server handshake"));
			}

			let client_refused = matches!(
				client_result,
				Err(TransportError::HandshakeError(HandshakeError::MutualAuthRequired))
			);
			trace.event_with(
				IDENTITYLESS_CLIENT_REFUSES_TO_COUNTERSIGN,
				&[],
				client_refused,
			)?;

			// Identity check before approver: settlement answer is irreversible.
			trace.event_with(
				IDENTITYLESS_CLIENT_NEVER_CONSULTS_APPROVER,
				&[],
				approver.approve_calls() == 0,
			)?;

			Ok(())
		}
	}
}
