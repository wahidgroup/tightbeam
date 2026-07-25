//! Dual-signed session receipt integration tests.
//!
//! Drives budget-bearing mutual-auth ECIES handshakes over TCP and verifies:
//!
//! - Round trip: both endpoints retain the same dual-signed receipt with
//!   the negotiated budgets, credit unit, challenge, and answer
//! - Third-party verification: both signatures verify from the receipt
//!   body and the certificates alone. Tampering with the body, either
//!   signature, or the settlement answer fails
//! - Settle rejection: the authorizer's refusal aborts the handshake
//!   with its application code and no receipt is retained
//! - Abandoned settlement: the client approver's refusal aborts before
//!   the countersignature and the server session never activates
//! - Fail-closed matrix: a challenge without an approver, and budgets
//!   without mutual authentication on either side, abort the handshake
//! - Session outcomes: the observer receives activation and refusal
//!   verdicts with the full evidence

#![cfg(all(
	feature = "transport-ecies",
	feature = "transport-policy",
	feature = "transport-multiplex",
	feature = "tcp",
	feature = "tokio",
	feature = "testing"
))]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};
use tightbeam::der::asn1::OctetString;
use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::transport::envelopes::MUX_APPLICATION_CODE_FLOOR;
use tightbeam::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, TransportAuthorizer, TransportOffer,
	SETTLEMENT_UNSUPPORTED_CODE,
};
use tightbeam::transport::handshake::receipt::{
	ApprovalRefusal, ReceiptApprover, SessionObserver, SessionReceipt, SessionVerdict, StoredReceipt,
};
use tightbeam::transport::handshake::HandshakeError;
use tightbeam::transport::{EncryptedMessageIO, MessageIO, TransportError};
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;

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

fn budget_offer() -> TransportOffer {
	TransportOffer::mux(4).with_budgets(REQUEST)
}

/// Grants the requested budgets with a settlement challenge attached.
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
			let challenge = self.challenge.clone();
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

/// Approves receipts by answering the challenge with the canned
/// response, or refuses with the configured code. Counts every
/// consultation so a scenario can prove the hook never fired.
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

			Ok(Some(self.response.clone()))
		})
	}
}

/// Establish a settled budget-bearing session: challenge issued,
/// answered, countersigned, and settled. The observer, when given,
/// receives the server's session outcome.
async fn establish_settled_session_observed(
	observer: Option<Arc<dyn SessionObserver>>,
) -> Result<MutualTransports, TightBeamError> {
	let hooks = MutualSessionHooks {
		authorizer: Some(Arc::new(ChallengingAuthorizer::new(true)?)),
		approver: Some(Arc::new(PayingApprover::paying()?)),
		observer,
	};

	let client_offer = budget_offer();
	let server_offer = TransportOffer::mux(4);
	establish_mutual_transports(client_offer, server_offer, hooks).await
}

/// Establish a settled budget-bearing session without observation.
async fn establish_settled_session() -> Result<MutualTransports, TightBeamError> {
	establish_settled_session_observed(None).await
}

/// SEC1 verifying key from a certificate's SPKI, as a third party
/// holding only the certificate would extract it.
fn verifying_key_from(certificate: &Certificate) -> Result<Secp256k1VerifyingKey, TightBeamError> {
	let sec1 = certificate
		.tbs_certificate
		.subject_public_key_info
		.subject_public_key
		.raw_bytes();

	Secp256k1VerifyingKey::from_sec1_bytes(sec1)
		.map_err(|_| expectation_failure("certificate must carry a valid SEC1 public key"))
}

/// Verify the artifact exactly as a third party would: keys extracted
/// from the two certificates, checked through the library's canonical
/// [`StoredReceipt::verify`] entry point.
fn third_party_verifies(
	stored: &StoredReceipt,
	server_certificate: &Certificate,
	client_certificate: &Certificate,
) -> Result<bool, TightBeamError> {
	let server_key = verifying_key_from(server_certificate)?;
	let client_key = verifying_key_from(client_certificate)?;
	let verdict = stored.verify::<Sha3_256, Secp256k1Signature, _>(&server_key, &client_key);
	Ok(verdict.is_ok())
}

/// Return `octets` with the first byte flipped.
fn flipped(octets: &OctetString) -> Result<OctetString, TightBeamError> {
	let mut bytes = octets.as_bytes().to_vec();
	bytes[0] ^= 0x01;
	Ok(OctetString::new(bytes)?)
}

/// Mutation applied to a pristine stored receipt before re-verification.
type Tamper = fn(&mut StoredReceipt) -> Result<(), TightBeamError>;

/// Every part of the dual-signed artifact a forger could touch: the
/// signed body fields, either signature, and the countersigned response.
const TAMPER_CASES: &[(&str, Tamper)] = &[
	("budget drift in the signed body", |stored| {
		stored.receipt.budgets.client_to_server += 1;
		Ok(())
	}),
	("credit-unit drift in the signed body", |stored| {
		stored.receipt.credit_unit += 1;
		Ok(())
	}),
	("challenge swap in the signed body", |stored| {
		stored.receipt.ancillary = Some(OctetString::new(*b"receipt-invoice-43")?);
		Ok(())
	}),
	("server signature bit flip", |stored| {
		stored.server_signature = flipped(&stored.server_signature)?;
		Ok(())
	}),
	("client countersignature bit flip", |stored| {
		stored.client_signature = flipped(&stored.client_signature)?;
		Ok(())
	}),
	("settlement answer swap", |stored| {
		stored.ancillary_response = Some(OctetString::new(*b"receipt-preimage-43")?);
		Ok(())
	}),
	("settlement answer stripped", |stored| {
		stored.ancillary_response = None;
		Ok(())
	}),
];

tb_assert_spec! {
	pub ReceiptRoundTripSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(client_retains_receipt, exactly!(1), equals!(true)),
			(server_retains_receipt, exactly!(1), equals!(true)),
			(receipts_identical, exactly!(1), equals!(true)),
			(receipt_matches_negotiation, exactly!(1), equals!(true)),
			(challenge_bound, exactly!(1), equals!(true)),
			(answer_bound, exactly!(1), equals!(true))
		]
	}
}

// A budget-bearing mutual-auth handshake with a settlement challenge
// completes with the same dual-signed receipt on both endpoints, bound
// to the negotiated budgets, credit unit, challenge, and answer.
tb_scenario! {
	name: receipt_round_trip_dual_signed,
	spec: ReceiptRoundTripSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let session = establish_settled_session().await?;

			let client_receipt = session.client.session_receipt();
			let server_receipt = session.server.session_receipt();
			trace.event_with(ReceiptRoundTripSpec::client_retains_receipt, &[], client_receipt.is_some())?;
			trace.event_with(ReceiptRoundTripSpec::server_retains_receipt, &[], server_receipt.is_some())?;
			trace.event_with(ReceiptRoundTripSpec::receipts_identical, &[], client_receipt == server_receipt)?;

			let stored = client_receipt.ok_or_else(|| expectation_failure("client must retain the receipt"))?;
			let settings = session
				.client
				.negotiated_mux()
				.ok_or_else(|| expectation_failure("client must negotiate multiplexing"))?;

			let is_budget_matched = stored.receipt.budgets == REQUEST;
			let is_credit_unit_matched = stored.receipt.credit_unit == settings.credit_unit;
			trace.event_with(ReceiptRoundTripSpec::receipt_matches_negotiation, &[], is_budget_matched && is_credit_unit_matched)?;

			let challenge = stored.receipt.ancillary.as_ref().map(OctetString::as_bytes);
			let answer = stored.ancillary_response.as_ref().map(OctetString::as_bytes);
			trace.event_with(ReceiptRoundTripSpec::challenge_bound, &[], challenge == Some(CHALLENGE))?;
			trace.event_with(ReceiptRoundTripSpec::answer_bound, &[], answer == Some(RESPONSE))?;

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
			(empty_answer_stored_as_absent, exactly!(1), equals!(true)),
			(endpoints_retain_identical_receipts, exactly!(1), equals!(true))
		]
	}
}

// An approver answering with zero bytes countersigns exactly what an
// unanswering approver would: the digest appends the raw answer bytes,
// so the two are cryptographically indistinguishable. Both endpoints
// therefore canonicalize the empty answer to absent and retain the
// same artifact.
tb_scenario! {
	name: receipt_empty_answer_normalized,
	spec: ReceiptEmptyAnswerSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let hooks = MutualSessionHooks {
				authorizer: Some(Arc::new(GrantingAuthorizer::challenge_free())),
				approver: Some(Arc::new(AnsweringApprover::answering(b"")?)),
				observer: None,
			};
			let session = establish_mutual_transports(budget_offer(), TransportOffer::mux(4), hooks).await?;

			let client_receipt = session.client.session_receipt();
			let server_receipt = session.server.session_receipt();
			let stored_absent = client_receipt.is_some_and(|stored| stored.ancillary_response.is_none());
			trace.event_with(ReceiptEmptyAnswerSpec::empty_answer_stored_as_absent, &[], stored_absent)?;
			trace.event_with(
				ReceiptEmptyAnswerSpec::endpoints_retain_identical_receipts,
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
			(both_signatures_verify_offline, exactly!(1), equals!(true)),
			(tampered_artifact_fails_verification, exactly!(7), equals!(true))
		]
	}
}

// The stored receipt is a self-contained artifact: given only the two
// certificates, both signatures verify through the library's canonical
// entry point. Tampering with the signed body, either signature, or
// the countersigned settlement answer breaks it.
tb_scenario! {
	name: receipt_third_party_verifiable,
	spec: ReceiptThirdPartySpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let session = establish_settled_session().await?;
			let stored = session
				.client
				.session_receipt()
				.ok_or_else(|| expectation_failure("client must retain the receipt"))?;

			let pristine_verifies =
				third_party_verifies(stored, &session.server_certificate, &session.client_certificate)?;
			trace.event_with(ReceiptThirdPartySpec::both_signatures_verify_offline, &[], pristine_verifies)?;

			for (forgery, tamper) in TAMPER_CASES {
				let mut tampered = stored.clone();
				tamper(&mut tampered)?;

				let forgery_verifies =
					third_party_verifies(&tampered, &session.server_certificate, &session.client_certificate)?;
				trace.event_with(
					ReceiptThirdPartySpec::tampered_artifact_fails_verification,
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
			(server_rejects_with_code, exactly!(1), equals!(true)),
			(client_completes_optimistically, exactly!(1), equals!(true)),
			(client_session_dead_on_first_use, exactly!(1), equals!(true))
		]
	}
}

// The authorizer's settle refusal aborts the handshake after the
// countersignature: the server surfaces the application code and never
// retains a receipt. ECIES completes client-side on the key exchange
// send, so the client observes the rejection on its first read.
tb_scenario! {
	name: receipt_settle_rejection_fails_closed,
	spec: ReceiptSettleRejectionSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let client_materials = ClientMaterials::generate();
			let (listener, addr) = bind_mutual_listener(&materials, &client_materials.certificate).await?;

			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(TransportOffer::mux(4)))
					.with_transport_authorizer(Arc::new(ChallengingAuthorizer::new(false)?));

				serve_one_handshake_message(&mut transport).await?;
				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(transport.session_receipt().cloned())
			});

			let mut client = connect_mutual_client(addr, &materials.certificate, &client_materials).await?;
			client = client
				.with_mux_offer(Some(budget_offer()))
				.with_receipt_approver(Arc::new(PayingApprover::paying()?));
			let client_result = client.perform_client_handshake().await;

			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			let server_rejected = matches!(
				server_result,
				Err(TightBeamError::TransportError(TransportError::HandshakeError(
					HandshakeError::SettlementRejected { code: SETTLE_REFUSAL_CODE }
				)))
			);
			trace.event_with(ReceiptSettleRejectionSpec::server_rejects_with_code, &[], server_rejected)?;

			// The client completed optimistically. The dead session
			// surfaces on the first read against the aborted server.
			trace.event_with(
				ReceiptSettleRejectionSpec::client_completes_optimistically,
				&[],
				client_result.is_ok(),
			)?;

			let first_read = client.read_envelope().await;
			trace.event_with(
				ReceiptSettleRejectionSpec::client_session_dead_on_first_use,
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
			(client_refuses_with_code, exactly!(1), equals!(true)),
			(server_never_activates, exactly!(1), equals!(true))
		]
	}
}

// The client approver walks away from the challenge: the handshake
// aborts before the countersignature ever exists and the server's
// budget-bearing session never activates.
tb_scenario! {
	name: receipt_abandoned_settlement_never_activates,
	spec: ReceiptAbandonedSettlementSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let client_materials = ClientMaterials::generate();
			let (listener, addr) = bind_mutual_listener(&materials, &client_materials.certificate).await?;

			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(TransportOffer::mux(4)))
					.with_transport_authorizer(Arc::new(ChallengingAuthorizer::new(true)?));

				serve_one_handshake_message(&mut transport).await?;
				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(())
			});

			let mut client = connect_mutual_client(addr, &materials.certificate, &client_materials).await?;
			client = client
				.with_mux_offer(Some(budget_offer()))
				.with_receipt_approver(Arc::new(PayingApprover::refusing(APPROVAL_REFUSAL_CODE)?));
			let client_result = client.perform_client_handshake().await;

			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			let client_refused = matches!(
				client_result,
				Err(TransportError::HandshakeError(HandshakeError::ApprovalRefused {
					code: APPROVAL_REFUSAL_CODE,
				}))
			);
			trace.event_with(ReceiptAbandonedSettlementSpec::client_refuses_with_code, &[], client_refused)?;
			trace.event_with(
				ReceiptAbandonedSettlementSpec::server_never_activates,
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
			(single_outcome_recorded, exactly!(1), equals!(true)),
			(verdict_activated_with_evidence, exactly!(1), equals!(true))
		]
	}
}

// A settled budget-bearing session hands the observer exactly one
// outcome: verdict Activated, carrying the same dual-signed artifact
// the endpoints retained plus the client identity of record.
tb_scenario! {
	name: receipt_outcome_recorded_on_activation,
	spec: ReceiptOutcomeActivatedSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let observer = Arc::new(RecordingObserver::default());
			let session = establish_settled_session_observed(Some(Arc::clone(&observer) as Arc<dyn SessionObserver>)).await?;

			let outcomes = observer.recorded();
			trace.event_with(ReceiptOutcomeActivatedSpec::single_outcome_recorded, &[], outcomes.len() == 1)?;

			let stored = session
				.server
				.session_receipt()
				.ok_or_else(|| expectation_failure("server must retain the receipt"))?;
			let matches_stored = outcomes.first().is_some_and(|outcome| {
				outcome.verdict == SessionVerdict::Activated
					&& outcome.receipt == stored.receipt
					&& outcome.server_signature == stored.server_signature
					&& outcome.client_signature.as_ref() == Some(&stored.client_signature)
					&& outcome.ancillary_response == stored.ancillary_response
					&& outcome.client_certificate.as_deref() == Some(session.client_certificate.as_ref())
			});
			trace.event_with(ReceiptOutcomeActivatedSpec::verdict_activated_with_evidence, &[], matches_stored)?;

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
			(refusal_outcome_recorded, exactly!(1), equals!(true)),
			(refused_receipt_verifies_offline, exactly!(1), equals!(true))
		]
	}
}

// A settle refusal aborts the handshake, but the countersigned receipt
// is the strongest evidence of the disputed agreement: the observer
// receives it with the refusal code, and both signatures still verify
// offline from the certificates alone.
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
			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(TransportOffer::mux(4)))
					.with_transport_authorizer(Arc::new(ChallengingAuthorizer::new(false)?))
					.with_session_observer(server_observer as Arc<dyn SessionObserver>);

				serve_one_handshake_message(&mut transport).await?;
				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(())
			});

			let mut client = connect_mutual_client(addr, &materials.certificate, &client_materials).await?;
			client = client
				.with_mux_offer(Some(budget_offer()))
				.with_receipt_approver(Arc::new(PayingApprover::paying()?));
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
			trace.event_with(ReceiptOutcomeRefusedSpec::refusal_outcome_recorded, &[], refusal_recorded)?;

			// The refused countersigned receipt remains third-party
			// verifiable evidence, reconstructed from the outcome alone.
			let evidence = outcomes
				.first()
				.and_then(|outcome| {
					let client_signature = outcome.client_signature.clone()?;
					Some(StoredReceipt {
						receipt: outcome.receipt.clone(),
						server_signature: outcome.server_signature.clone(),
						client_signature,
						ancillary_response: outcome.ancillary_response.clone(),
					})
				})
				.ok_or_else(|| expectation_failure("refusal outcome must carry the countersignature"))?;
			trace.event_with(
				ReceiptOutcomeRefusedSpec::refused_receipt_verifies_offline,
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
			(client_fails_closed_unsupported, exactly!(1), equals!(true)),
			(server_never_activates, exactly!(1), equals!(true))
		]
	}
}

// A challenge-bearing receipt arriving at a client with no configured
// approver must fail closed with the reserved unsupported code: silence
// is never consent to a settlement demand.
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
					.with_mux_offer(Some(TransportOffer::mux(4)))
					.with_transport_authorizer(Arc::new(ChallengingAuthorizer::new(true)?));

				serve_one_handshake_message(&mut transport).await?;
				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(())
			});

			let mut client = connect_mutual_client(addr, &materials.certificate, &client_materials).await?;
			client = client.with_mux_offer(Some(budget_offer()));
			let client_result = client.perform_client_handshake().await;

			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			let client_failed_closed = matches!(
				client_result,
				Err(TransportError::HandshakeError(HandshakeError::ApprovalRefused {
					code: SETTLEMENT_UNSUPPORTED_CODE,
				}))
			);
			trace.event_with(ReceiptNoApproverSpec::client_fails_closed_unsupported, &[], client_failed_closed)?;
			trace.event_with(ReceiptNoApproverSpec::server_never_activates, &[], server_result.is_err())?;

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
			(server_refuses_to_issue_unverifiable_receipt, exactly!(1), equals!(true)),
			(identityless_client_refuses_to_countersign, exactly!(1), equals!(true)),
			(identityless_client_never_consults_approver, exactly!(1), equals!(true))
		]
	}
}

// Budgets without mutual authentication fail closed on both sides: a
// server with no client validators cannot verify any countersignature
// and refuses to issue a receipt at all, and an identity-less client
// offered a receipt has nothing to countersign with and aborts.
tb_scenario! {
	name: receipt_budgets_require_mutual_auth,
	spec: ReceiptMutualAuthSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let client_materials = ClientMaterials::generate();

			// Server side: no client validators, authorizer grants budgets.
			let (listener, addr) = bind_encrypted_listener(&materials).await?;
			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(TransportOffer::mux(4)))
					.with_transport_authorizer(Arc::new(ChallengingAuthorizer::new(false)?));

				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(())
			});

			let mut client = connect_pinned_client(addr, &materials.certificate).await?;
			client = client
				.with_mux_offer(Some(budget_offer()))
				.with_receipt_approver(Arc::new(PayingApprover::paying()?));
			let _ = client.perform_client_handshake().await;

			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			let server_refused = matches!(
				server_result,
				Err(TightBeamError::TransportError(TransportError::HandshakeError(
					HandshakeError::MutualAuthRequired
				)))
			);
			trace.event_with(
				ReceiptMutualAuthSpec::server_refuses_to_issue_unverifiable_receipt,
				&[],
				server_refused,
			)?;

			// Client side: server issues a receipt (validators present),
			// but the pinned client carries no identity to countersign with.
			let (listener, addr) = bind_mutual_listener(&materials, &client_materials.certificate).await?;
			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(TransportOffer::mux(4)))
					.with_transport_authorizer(Arc::new(ChallengingAuthorizer::new(false)?));

				serve_one_handshake_message(&mut transport).await?;
				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(())
			});

			let approver = Arc::new(PayingApprover::paying()?);
			let mut client = connect_pinned_client(addr, &materials.certificate).await?;
			client = client
				.with_mux_offer(Some(budget_offer()))
				.with_receipt_approver(Arc::clone(&approver) as _);
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
				ReceiptMutualAuthSpec::identityless_client_refuses_to_countersign,
				&[],
				client_refused,
			)?;

			// Approval can spend an irreversible settlement answer, so
			// the identity check must run first: the approver was never
			// consulted for a session that could not countersign.
			trace.event_with(
				ReceiptMutualAuthSpec::identityless_client_never_consults_approver,
				&[],
				approver.approve_calls() == 0,
			)?;

			Ok(())
		}
	}
}
