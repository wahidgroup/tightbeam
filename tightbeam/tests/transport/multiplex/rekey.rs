//! In-band epoch renewal (rekey) integration tests.

use core::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tightbeam::at_least;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};
use tightbeam::der::asn1::OctetString;
use tightbeam::der::Encode;
use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::transport::envelopes::{GoAwayReason, MuxEnvelope, MuxRekeyRequestPackage, MUX_APPLICATION_CODE_FLOOR};
use tightbeam::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, TransportAuthorizer, TransportOffer,
};
use tightbeam::transport::handshake::receipt::{ApprovalRefusal, ReceiptApprover, SessionReceipt, StoredReceipt};
use tightbeam::transport::multiplex::{MuxAcceptor, MuxConnector, MuxHandle, MuxRole};
use tightbeam::transport::{EnvelopeSink, EnvelopeSource, TransportEnvelope};
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;
use tokio::time::{sleep, timeout};

use crate::common::security::expectation_failure;
use crate::transport::support::{
	await_receipt_rotation, establish_mutual_transports, mux_frame, mux_offer, MutualSessionHooks, MutualTransports,
};

use super::common::*;

use tightbeam::instrumentation::events;
use tightbeam::utils::urn::Urn;

pub(crate) const CHAINED_RECEIPT_VERIFIES_AGAINST_ORIGINAL_CERTS: Urn<'static> =
	Urn::new("test", "event:rekey/chained-receipt-verifies-against-original-certs");
pub(crate) const CLEARTEXT_HARVEST_YIELDS_NOTHING: Urn<'static> =
	Urn::new("test", "event:rekey/cleartext-harvest-yields-nothing");
pub(crate) const CONSECUTIVE_EPOCHS_ROTATE_DISTINCT_RECEIPTS: Urn<'static> =
	Urn::new("test", "event:rekey/consecutive-epochs-rotate-distinct-receipts");
pub(crate) const DUPLICATE_REQUEST_VIOLATES_PROTOCOL: Urn<'static> =
	Urn::new("test", "event:rekey/duplicate-request-violates-protocol");
pub(crate) const EMITS_SURVIVE_BUDGET_WATERMARK: Urn<'static> =
	Urn::new("test", "event:rekey/emits-survive-budget-watermark");
pub(crate) const EMITS_SURVIVE_SETTLED_RENEWAL: Urn<'static> =
	Urn::new("test", "event:rekey/emits-survive-settled-renewal");
pub(crate) const EMITS_SURVIVE_TWO_RENEWALS: Urn<'static> = Urn::new("test", "event:rekey/emits-survive-two-renewals");
pub(crate) const ENDPOINTS_AGREE_ON_EPOCH_RECEIPT: Urn<'static> =
	Urn::new("test", "event:rekey/endpoints-agree-on-epoch-receipt");
pub(crate) const EPOCH_RECEIPT_ROTATES: Urn<'static> = Urn::new("test", "event:rekey/epoch-receipt-rotates");
pub(crate) const FIRST_REQUEST_ANSWERED: Urn<'static> = Urn::new("test", "event:rekey/first-request-answered");
pub(crate) const PREMATURE_REQUEST_VIOLATES_PROTOCOL: Urn<'static> =
	Urn::new("test", "event:rekey/premature-request-violates-protocol");
pub(crate) const RECEIPTLESS_DRAIN_KEEPS_TODAYS_PATH: Urn<'static> =
	Urn::new("test", "event:rekey/receiptless-drain-keeps-todays-path");
pub(crate) const RECEIPTLESS_SESSION_HAS_NO_EPOCH_RECEIPT: Urn<'static> =
	Urn::new("test", "event:rekey/receiptless-session-has-no-epoch-receipt");
pub(crate) const RECEIPTLESS_TRANSFER_SURVIVES_DRAIN: Urn<'static> =
	Urn::new("test", "event:rekey/receiptless-transfer-survives-drain");
pub(crate) const REFUSAL_CODE_REACHES_CLIENT: Urn<'static> =
	Urn::new("test", "event:rekey/refusal-code-reaches-client");
pub(crate) const REFUSAL_CODE_REACHES_SERVER: Urn<'static> =
	Urn::new("test", "event:rekey/refusal-code-reaches-server");
pub(crate) const RENEWAL_REQUEST_REACHES_SERVER: Urn<'static> =
	Urn::new("test", "event:rekey/renewal-request-reaches-server");
pub(crate) const SETTLE_HOOK_FIRES_ON_RENEWAL: Urn<'static> =
	Urn::new("test", "event:rekey/settle-hook-fires-on-renewal");
pub(crate) const STALLED_RENEWAL_DRAINS_CLEAN: Urn<'static> =
	Urn::new("test", "event:rekey/stalled-renewal-drains-clean");
pub(crate) const TRAFFIC_STRADDLES_KEY_SWITCH: Urn<'static> =
	Urn::new("test", "event:rekey/traffic-straddles-key-switch");

/// Settlement challenge the authorizer binds into every epoch receipt.
const RENEWAL_CHALLENGE: &[u8] = b"epoch-invoice-7";

/// Settlement answer the approver countersigns at each renewal.
const RENEWAL_RESPONSE: &[u8] = b"epoch-preimage-7";

/// Application code for a renewal settle refusal.
const SETTLE_REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR + 31;

/// Application code for a renewal approval refusal.
const APPROVAL_REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR + 32;

/// Fifth single-chunk emit tips budget into drain reserve (caps 1/1, 1 KiB chunk).
const RENEWAL_TRIGGER_BUDGETS: MuxBudgets = MuxBudgets { client_to_server: 10, server_to_client: 4096 };

/// Record watermark drives renewal, not budget.
const AMPLE_BUDGETS: MuxBudgets = MuxBudgets { client_to_server: 1_000_000, server_to_client: 1_000_000 };

fn rekey_config() -> MuxEndpointConfig {
	MuxEndpointConfig { rekey: true, ..MuxEndpointConfig::default() }
}

async fn establish_renewal_session(hooks: MutualSessionHooks) -> Result<MutualTransports, TightBeamError> {
	let client_offer = chunked_offer(1).with_budgets(RENEWAL_TRIGGER_BUDGETS);
	let server_offer = chunked_offer(1).with_budgets(RENEWAL_TRIGGER_BUDGETS);
	establish_mutual_transports(client_offer, server_offer, hooks).await
}

async fn emit_series(handle: &MuxHandle, label: &str, count: usize) -> Result<bool, TightBeamError> {
	for index in 0..count {
		let frame = mux_frame(&format!("{label}-{index}"));
		let echoed = handle.emit_on_stream(&frame).await?;
		if !is_echo(echoed, &frame) {
			return Ok(false);
		}
	}

	Ok(true)
}

/// Poll until epoch receipt differs from `previous` (timeout-bounded).
async fn await_rotation(handle: &MuxHandle, previous: Option<&StoredReceipt>) -> Option<Arc<StoredReceipt>> {
	await_receipt_rotation(|| handle.session_receipt(), previous).await
}

async fn await_matching_receipt(handle: &MuxHandle, expected: &StoredReceipt) -> bool {
	let matched = timeout(Duration::from_secs(2), async {
		while handle.session_receipt().as_deref() != Some(expected) {
			sleep(Duration::from_millis(5)).await;
		}
	})
	.await;

	matched.is_ok()
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

fn rekey_request_envelope(seed: u8) -> Result<TransportEnvelope, TightBeamError> {
	let package = MuxRekeyRequestPackage::new(vec![seed; 32])?;
	Ok(MuxEnvelope::RekeyRequest(package).into())
}

/// Skip stream traffic until `RekeyRequest`.
async fn read_until_rekey_request(reader: &mut SplitReader) -> Result<(), TightBeamError> {
	timeout(Duration::from_secs(2), async {
		loop {
			let envelope = reader.read_envelope().await?;
			let is_rekey_request = matches!(envelope, TransportEnvelope::Mux(MuxEnvelope::RekeyRequest(_)));
			if is_rekey_request {
				return Ok(());
			}
		}
	})
	.await
	.map_err(|_| expectation_failure("client must open the renewal before the read timeout"))?
}

/// Skip echo/credit traffic until `RekeyResponse`.
async fn read_until_rekey_response(reader: &mut SplitReader) -> Result<(), TightBeamError> {
	timeout(Duration::from_secs(2), async {
		loop {
			let envelope = reader.read_envelope().await?;
			let is_rekey_response = matches!(envelope, TransportEnvelope::Mux(MuxEnvelope::RekeyResponse(_)));
			if is_rekey_response {
				return Ok(());
			}
		}
	})
	.await
	.map_err(|_| expectation_failure("server must answer the renewal request before the read timeout"))?
}

/// Settlement challenge on every renewal; counts `settle` consultations.
struct RenewalAuthorizer {
	challenge: OctetString,
	expected_response: OctetString,
	accept_settlement: bool,
	settle_calls: AtomicUsize,
}

impl RenewalAuthorizer {
	fn new(accept_settlement: bool) -> Result<Self, TightBeamError> {
		Ok(Self {
			challenge: OctetString::new(RENEWAL_CHALLENGE)?,
			expected_response: OctetString::new(RENEWAL_RESPONSE)?,
			accept_settlement,
			settle_calls: AtomicUsize::new(0),
		})
	}

	fn settle_calls(&self) -> usize {
		self.settle_calls.load(Ordering::SeqCst)
	}
}

impl TransportAuthorizer for RenewalAuthorizer {
	fn authorize<'a>(
		&'a self,
		offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		Box::pin(async move { Ok(AuthorizationGrant { budgets: offer.requested_budgets, challenge: None }) })
	}

	fn challenge_renewal<'a>(
		&'a self,
		_prior: &'a SessionReceipt,
	) -> MaybeSendFuture<'a, Result<Option<OctetString>, AuthorizationRefusal>> {
		Box::pin(async move { Ok(Some(self.challenge.to_owned())) })
	}

	fn settle<'a>(
		&'a self,
		receipt: &'a SessionReceipt,
		response: Option<&'a [u8]>,
	) -> MaybeSendFuture<'a, Result<(), AuthorizationRefusal>> {
		Box::pin(async move {
			if receipt.ancillary.is_none() {
				return Ok(());
			}

			self.settle_calls.fetch_add(1, Ordering::SeqCst);

			let answered = self.accept_settlement && response == Some(self.expected_response.as_bytes());
			if answered {
				return Ok(());
			}

			Err(AuthorizationRefusal { code: SETTLE_REFUSAL_CODE })
		})
	}
}

/// Answers challenge-bearing receipts; handshake receipts pass without answer.
struct RenewalApprover {
	response: OctetString,
}

impl RenewalApprover {
	fn answering() -> Result<Self, TightBeamError> {
		Ok(Self { response: OctetString::new(RENEWAL_RESPONSE)? })
	}
}

impl ReceiptApprover for RenewalApprover {
	fn approve<'a>(
		&'a self,
		receipt: &'a SessionReceipt,
	) -> MaybeSendFuture<'a, Result<Option<OctetString>, ApprovalRefusal>> {
		Box::pin(async move { Ok(receipt.ancillary.as_ref().map(|_| self.response.to_owned())) })
	}
}

/// Approves the initial handshake receipt, then refuses every renewal
/// with [`APPROVAL_REFUSAL_CODE`].
#[derive(Default)]
struct RenewalRefusingApprover {
	calls: AtomicUsize,
}

impl ReceiptApprover for RenewalRefusingApprover {
	fn approve<'a>(
		&'a self,
		_receipt: &'a SessionReceipt,
	) -> MaybeSendFuture<'a, Result<Option<OctetString>, ApprovalRefusal>> {
		let call = self.calls.fetch_add(1, Ordering::SeqCst);
		Box::pin(async move {
			if call == 0 {
				return Ok(None);
			}

			Err(ApprovalRefusal { code: APPROVAL_REFUSAL_CODE })
		})
	}
}

tb_assert_spec! {
	pub MuxRekeyBudgetRenewalSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::MUX_REKEY_REQUESTED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(2)),
			(events::MUX_REKEY_REFUSED, exactly!(0)),
			(events::MUX_REKEY_VERIFY_FAILED, exactly!(0)),
			(EMITS_SURVIVE_BUDGET_WATERMARK, exactly!(1), equals!(true)),
			(EPOCH_RECEIPT_ROTATES, exactly!(1), equals!(true)),
			(ENDPOINTS_AGREE_ON_EPOCH_RECEIPT, exactly!(1), equals!(true))
		]
	}
}

// Without renewal this session drains at the fifth emit (mux_budget_exhaustion_drains).
tb_scenario! {
	name: mux_rekey_budget_renewal_extends_session,
	spec: MuxRekeyBudgetRenewalSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let session = establish_renewal_session(MutualSessionHooks::default()).await?;
			let handshake_receipt = session.client.session_receipt();
			let initial = handshake_receipt.map(|receipt| receipt.to_owned());
			let pair = spawn_echo_pair_with(session.client, session.server, rekey_config(), rekey_config(), trace.share())?;

			let all_echoed = emit_series(&pair.client.handle, "rekey-budget", 8).await?;
			trace.event_with(EMITS_SURVIVE_BUDGET_WATERMARK, &[], all_echoed)?;

			let rotated = await_rotation(&pair.client.handle, initial.as_ref()).await;
			trace.event_with(EPOCH_RECEIPT_ROTATES, &[], rotated.is_some())?;

			let epoch_receipt = rotated.ok_or_else(|| expectation_failure("client must rotate the epoch receipt"))?;
			trace.event_with(
				ENDPOINTS_AGREE_ON_EPOCH_RECEIPT,
				&[],
				await_matching_receipt(&pair.server.handle, &epoch_receipt).await,
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyRecordRenewalSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::MUX_REKEY_REQUESTED, at_least!(1)),
			(events::MUX_REKEY_RECEIPT_ISSUED, at_least!(1)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, at_least!(1)),
			(events::MUX_REKEY_RENEWED, at_least!(2)),
			(TRAFFIC_STRADDLES_KEY_SWITCH, exactly!(1), equals!(true)),
			(EPOCH_RECEIPT_ROTATES, exactly!(1), equals!(true))
		]
	}
}

pub(crate) const STREAMED_TRAFFIC_STRADDLES_KEY_SWITCH: Urn<'static> =
	Urn::new("test", "event:rekey/streamed-traffic-straddles-key-switch");
pub(crate) const STREAMING_EPOCH_RECEIPT_ROTATES: Urn<'static> =
	Urn::new("test", "event:rekey/streaming-epoch-receipt-rotates");

tb_assert_spec! {
	pub MuxRekeyStreamingRenewalSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::MUX_REKEY_REQUESTED, at_least!(1)),
			(events::MUX_REKEY_RENEWED, at_least!(2)),
			(STREAMED_TRAFFIC_STRADDLES_KEY_SWITCH, exactly!(1), equals!(true)),
			(STREAMING_EPOCH_RECEIPT_ROTATES, exactly!(1), equals!(true))
		]
	}
}

// Same record watermark as the chunked-traffic renewal, but every
// request travels through open_stream against serve_streaming: the
// sink's per-push records and the drain-driven grants must both cross
// the epoch switch intact.
tb_scenario! {
	name: mux_rekey_renewal_survives_streaming_traffic,
	spec: MuxRekeyStreamingRenewalSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let client_offer = chunked_offer(4).with_budgets(AMPLE_BUDGETS);
			let server_offer = chunked_offer(4).with_budgets(AMPLE_BUDGETS);
			let session = establish_mutual_transports(client_offer, server_offer, MutualSessionHooks::default()).await?;
			let handshake_receipt = session.client.session_receipt();
			let initial = handshake_receipt.map(|receipt| receipt.to_owned());

			let client_config = MuxEndpointConfig { rekey_limit: Some(100), ..rekey_config() };
			let client_transport = session.client.with_trace(trace.share());
			let (client_end, _) = spawn_mux_endpoint_with(client_transport, MuxRole::Client, client_config)?;
			let server_transport = session.server.with_trace(trace.share());
			let (_, responder) = spawn_mux_endpoint_with(server_transport, MuxRole::Server, rekey_config())?;

			let chunks_seen = Arc::new(AtomicUsize::new(0));
			let _serve = tokio::spawn(responder.serve_streaming(streaming_echo_handler(Arc::clone(&chunks_seen))));

			let mut all_echoed = true;
			for index in 0..20 {
				let frame = large_mux_frame(&format!("rekey-streaming-{index}"));
				let payload = frame.to_der()?;
				let (sink, response) = client_end.handle.open_stream()?;
				push_split(sink, &payload).await?;

				let echoed = response.await?;
				all_echoed = all_echoed && is_echo(echoed, &frame);
			}

			trace.event_with(STREAMED_TRAFFIC_STRADDLES_KEY_SWITCH, &[], all_echoed)?;

			let rotated = await_rotation(&client_end.handle, initial.as_ref()).await;
			trace.event_with(STREAMING_EPOCH_RECEIPT_ROTATES, &[], rotated.is_some())?;

			Ok(())
		}
	}
}

// 20 × 6 records = 120 against limit 100; traffic straddles key switch.
tb_scenario! {
	name: mux_rekey_record_renewal_survives_chunked_traffic,
	spec: MuxRekeyRecordRenewalSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let client_offer = chunked_offer(4).with_budgets(AMPLE_BUDGETS);
			let server_offer = chunked_offer(4).with_budgets(AMPLE_BUDGETS);
			let session = establish_mutual_transports(client_offer, server_offer, MutualSessionHooks::default()).await?;
			let handshake_receipt = session.client.session_receipt();
			let initial = handshake_receipt.map(|receipt| receipt.to_owned());

			let client_config = MuxEndpointConfig { rekey_limit: Some(100), ..rekey_config() };
			let pair =
				spawn_echo_pair_with(session.client, session.server, client_config, rekey_config(), trace.share())?;

			let mut all_echoed = true;
			for index in 0..20 {
				let frame = large_mux_frame(&format!("rekey-record-{index}"));
				let echoed = pair.client.handle.emit_on_stream(&frame).await?;
				all_echoed = all_echoed && is_echo(echoed, &frame);
			}

			trace.event_with(TRAFFIC_STRADDLES_KEY_SWITCH, &[], all_echoed)?;

			let rotated = await_rotation(&pair.client.handle, initial.as_ref()).await;
			trace.event_with(EPOCH_RECEIPT_ROTATES, &[], rotated.is_some())?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyEpochChainSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::MUX_REKEY_REQUESTED, exactly!(2)),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(2)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(2)),
			(events::MUX_REKEY_RENEWED, exactly!(4)),
			(events::MUX_REKEY_REFUSED, exactly!(0)),
			(EMITS_SURVIVE_TWO_RENEWALS, exactly!(1), equals!(true)),
			(CONSECUTIVE_EPOCHS_ROTATE_DISTINCT_RECEIPTS, exactly!(1), equals!(true)),
			(CHAINED_RECEIPT_VERIFIES_AGAINST_ORIGINAL_CERTS, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_rekey_consecutive_epochs_chain_receipts,
	spec: MuxRekeyEpochChainSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let session = establish_renewal_session(MutualSessionHooks::default()).await?;
			let handshake_receipt = session.client.session_receipt();
			let initial = handshake_receipt.map(|receipt| receipt.to_owned());
			let server_certificate = session.server_certificate.to_owned();
			let client_certificate = session.client_certificate.to_owned();
			let pair = spawn_echo_pair_with(session.client, session.server, rekey_config(), rekey_config(), trace.share())?;

			let first_batch = emit_series(&pair.client.handle, "rekey-chain-a", 5).await?;
			let first = await_rotation(&pair.client.handle, initial.as_ref()).await;

			let second_batch = emit_series(&pair.client.handle, "rekey-chain-b", 5).await?;
			let second = await_rotation(&pair.client.handle, first.as_deref()).await;

			trace.event_with(EMITS_SURVIVE_TWO_RENEWALS, &[], first_batch && second_batch)?;

			let distinct = {
				let first_rotated = first.is_some();
				let second_rotated = second.is_some();
				let epochs_differ = initial.as_ref() != second.as_deref();
				first_rotated && second_rotated && epochs_differ
			};
			trace.event_with(CONSECUTIVE_EPOCHS_ROTATE_DISTINCT_RECEIPTS, &[], distinct)?;

			let latest = second.ok_or_else(|| expectation_failure("second renewal must rotate the receipt"))?;
			let server_key = verifying_key_from(&server_certificate)?;
			let client_key = verifying_key_from(&client_certificate)?;
			let verdict = latest.verify::<Sha3_256, Secp256k1Signature, _>(&server_key, &client_key);
			trace.event_with(
				CHAINED_RECEIPT_VERIFIES_AGAINST_ORIGINAL_CERTS,
				&[],
				verdict.is_ok(),
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeySettledChallengeSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::MUX_REKEY_REQUESTED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(2)),
			(events::MUX_REKEY_REFUSED, exactly!(0)),
			(events::MUX_REKEY_VERIFY_FAILED, exactly!(0)),
			(EMITS_SURVIVE_SETTLED_RENEWAL, exactly!(1), equals!(true)),
			(SETTLE_HOOK_FIRES_ON_RENEWAL, exactly!(1), equals!(true)),
			(EPOCH_RECEIPT_ROTATES, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_rekey_renewal_settles_challenge,
	spec: MuxRekeySettledChallengeSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let renewal_authorizer = Arc::new(RenewalAuthorizer::new(true)?);
			let renewal_approver = RenewalApprover::answering()?;
			let approver: Arc<dyn ReceiptApprover> = Arc::new(renewal_approver);
			let hooks = MutualSessionHooks {
				authorizer: Some(Arc::clone(&renewal_authorizer) as Arc<dyn TransportAuthorizer>),
				approver: Some(approver),
				observer: None,
				trace: None,
			};
			let session = establish_renewal_session(hooks).await?;
			let handshake_receipt = session.client.session_receipt();
			let initial = handshake_receipt.map(|receipt| receipt.to_owned());
			let pair = spawn_echo_pair_with(session.client, session.server, rekey_config(), rekey_config(), trace.share())?;

			let all_echoed = emit_series(&pair.client.handle, "rekey-settle", 8).await?;
			trace.event_with(EMITS_SURVIVE_SETTLED_RENEWAL, &[], all_echoed)?;

			let rotated = await_rotation(&pair.client.handle, initial.as_ref()).await;
			trace.event_with(
				SETTLE_HOOK_FIRES_ON_RENEWAL,
				&[],
				renewal_authorizer.settle_calls() >= 1,
			)?;
			trace.event_with(EPOCH_RECEIPT_ROTATES, &[], rotated.is_some())?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeySettleRefusalSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::MUX_REKEY_REQUESTED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(1)),
			(events::MUX_REKEY_REFUSED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(0)),
			(events::MUX_EMIT_DRAINING, exactly!(1)),
			(REFUSAL_CODE_REACHES_CLIENT, exactly!(1), equals!(true))
		]
	}
}

// Client switched at Ack; server installs receive cipher then drains with refusal code.
tb_scenario! {
	name: mux_rekey_settlement_refusal_drains,
	spec: MuxRekeySettleRefusalSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let renewal_authorizer = RenewalAuthorizer::new(false)?;
			let authorizer: Arc<dyn TransportAuthorizer> = Arc::new(renewal_authorizer);
			let renewal_approver = RenewalApprover::answering()?;
			let hooks = MutualSessionHooks {
				authorizer: Some(authorizer),
				approver: Some(Arc::new(renewal_approver)),
				observer: None,
				trace: None,
			};
			let session = establish_renewal_session(hooks).await?;
			let pair = spawn_echo_pair_with(session.client, session.server, rekey_config(), rekey_config(), trace.share())?;

			let _renewal_trigger = emit_series(&pair.client.handle, "rekey-refused-settle", 5).await?;
			trace.event_with(
				REFUSAL_CODE_REACHES_CLIENT,
				&[],
				await_goaway_reason(&pair.client.handle, GoAwayReason::Application(SETTLE_REFUSAL_CODE)).await,
			)?;

			// Stimulus only: the refusal itself emits `events::MUX_EMIT_DRAINING`.
			let _late = pair.client.handle.emit_on_stream(&mux_frame("rekey-late")).await;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyApprovalRefusalSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::MUX_REKEY_REQUESTED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(0)),
			(events::MUX_REKEY_REFUSED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(0)),
			(events::MUX_EMIT_DRAINING, exactly!(1)),
			(REFUSAL_CODE_REACHES_SERVER, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_rekey_approval_refusal_drains,
	spec: MuxRekeyApprovalRefusalSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let refusing_approver = RenewalRefusingApprover::default();
			let approver: Arc<dyn ReceiptApprover> = Arc::new(refusing_approver);
			let hooks = MutualSessionHooks {
				authorizer: None,
				approver: Some(approver),
				observer: None,
				trace: None,
			};
			let session = establish_renewal_session(hooks).await?;
			let pair = spawn_echo_pair_with(session.client, session.server, rekey_config(), rekey_config(), trace.share())?;

			let _renewal_trigger = emit_series(&pair.client.handle, "rekey-refused-approval", 5).await?;
			trace.event_with(
				REFUSAL_CODE_REACHES_SERVER,
				&[],
				await_goaway_reason(&pair.server.handle, GoAwayReason::Application(APPROVAL_REFUSAL_CODE)).await,
			)?;

			// Stimulus only: the refusal itself emits `events::MUX_EMIT_DRAINING`.
			let _late = pair.client.handle.emit_on_stream(&mux_frame("rekey-late")).await;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyMinSpendSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::MUX_PROTOCOL_ERROR, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(0)),
			(events::MUX_REKEY_RENEWED, exactly!(0)),
			(PREMATURE_REQUEST_VIOLATES_PROTOCOL, exactly!(1), equals!(true))
		]
	}
}

// CWE-400: RekeyRequest below minimum-spend floor -> GoAway(ProtocolError).
tb_scenario! {
	name: mux_rekey_request_below_min_spend_violates,
	spec: MuxRekeyMinSpendSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let client_offer = mux_offer(4).with_budgets(AMPLE_BUDGETS);
			let server_offer = mux_offer(4).with_budgets(AMPLE_BUDGETS);
			let session = establish_mutual_transports(client_offer, server_offer, MutualSessionHooks::default()).await?;
			let mut link = split_server_mux_client_raw(session.client, session.server, rekey_config(), trace.share())?;
			let _server_serve = spawn_immediate_echo(link.responder);

			link.client_writer.write_envelope(rekey_request_envelope(7)?).await?;
			trace.event_with(
				PREMATURE_REQUEST_VIOLATES_PROTOCOL,
				&[],
				read_until_goaway(&mut link.client_reader, GoAwayReason::ProtocolError).await?,
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyDuplicateRequestSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::MUX_PROTOCOL_ERROR, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(0)),
			(FIRST_REQUEST_ANSWERED, exactly!(1), equals!(true)),
			(DUPLICATE_REQUEST_VIOLATES_PROTOCOL, exactly!(1), equals!(true))
		]
	}
}

// CWE-400: duplicate RekeyRequest while exchange in flight -> GoAway(ProtocolError).
tb_scenario! {
	name: mux_rekey_duplicate_request_violates,
	spec: MuxRekeyDuplicateRequestSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let client_offer = mux_offer(4).with_budgets(AMPLE_BUDGETS);
			let server_offer = mux_offer(4).with_budgets(AMPLE_BUDGETS);
			let session = establish_mutual_transports(client_offer, server_offer, MutualSessionHooks::default()).await?;
			let mut link = split_server_mux_client_raw(session.client, session.server, rekey_config(), trace.share())?;
			let _server_serve = spawn_immediate_echo(link.responder);

			// Spend minimum records so first request is accepted
			for index in 0..4u32 {
				let stream_id = client_stream_id(index);
				write_muxed_request(&mut link.client_writer, stream_id, mux_frame("rekey-spend")).await?;
			}

			link.client_writer.write_envelope(rekey_request_envelope(7)?).await?;

			let answered = read_until_rekey_response(&mut link.client_reader).await;
			trace.event_with(FIRST_REQUEST_ANSWERED, &[], answered.is_ok())?;

			link.client_writer.write_envelope(rekey_request_envelope(9)?).await?;
			trace.event_with(
				DUPLICATE_REQUEST_VIOLATES_PROTOCOL,
				&[],
				read_until_goaway(&mut link.client_reader, GoAwayReason::ProtocolError).await?,
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyTimeoutSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::MUX_REKEY_REQUESTED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(0)),
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(RENEWAL_REQUEST_REACHES_SERVER, exactly!(1), equals!(true)),
			(STALLED_RENEWAL_DRAINS_CLEAN, exactly!(1), equals!(true))
		]
	}
}

// Renewal deadline bounds stalled exchange -> GoAway(Shutdown).
tb_scenario! {
	name: mux_rekey_timeout_drains_clean,
	spec: MuxRekeyTimeoutSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let client_offer = chunked_offer(4).with_budgets(AMPLE_BUDGETS);
			let server_offer = chunked_offer(4).with_budgets(AMPLE_BUDGETS);
			let session = establish_mutual_transports(client_offer, server_offer, MutualSessionHooks::default()).await?;

			// Record limit below renewal floor: first write opens renewal server never answers
			let client_config = MuxEndpointConfig {
				rekey_limit: Some(80),
				renewal_deadline: Some(Duration::from_millis(200)),
				..rekey_config()
			};
			let endpoint_pair = spawn_mux_endpoint_with(session.client.with_trace(trace.share()), MuxRole::Client, client_config)?;
			let (client_end, _client_responder) = endpoint_pair;
			let server_halves = session.server.into_split()?;
			let (mut server_reader, _server_writer) = server_halves;

			let emit_task = spawn_emit(&client_end.handle, mux_frame("rekey-timeout"));
			read_until_rekey_request(&mut server_reader).await?;
			trace.event_with(RENEWAL_REQUEST_REACHES_SERVER, &[], true)?;

			trace.event_with(
				STALLED_RENEWAL_DRAINS_CLEAN,
				&[],
				read_until_goaway(&mut server_reader, GoAwayReason::Shutdown).await?,
			)?;

			abort_emit(emit_task).await;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyInertPathsSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::MUX_REKEY_REQUESTED, exactly!(0)),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(0)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(0)),
			(events::MUX_REKEY_RENEWED, exactly!(0)),
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(events::MUX_GOAWAY_RECV, exactly!(1)),
			(events::MUX_EMIT_DRAINING, exactly!(1)),
			(CLEARTEXT_HARVEST_YIELDS_NOTHING, exactly!(1), equals!(true)),
			(RECEIPTLESS_SESSION_HAS_NO_EPOCH_RECEIPT, exactly!(1), equals!(true)),
			(RECEIPTLESS_TRANSFER_SURVIVES_DRAIN, exactly!(1), equals!(true)),
			(RECEIPTLESS_DRAIN_KEEPS_TODAYS_PATH, exactly!(1), equals!(true))
		]
	}
}

// Receiptless/cleartext: no rekey wiring; record limit -> GoAway(Shutdown).
tb_scenario! {
	name: mux_rekey_inert_paths_keep_todays_behavior,
	spec: MuxRekeyInertPathsSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (mut cleartext_client, mut cleartext_server) = establish_cleartext_transports().await?;
			let client_harvest = MuxConnector::take_rekey(&mut cleartext_client)?;
			let server_harvest = MuxAcceptor::take_rekey(&mut cleartext_server)?;
			let harvest_empty = client_harvest.is_none() && server_harvest.is_none();
			trace.event_with(
				CLEARTEXT_HARVEST_YIELDS_NOTHING,
				&[],
				harvest_empty,
			)?;

			let (client, server) = establish_transports(Some(chunked_offer(1)), Some(chunked_offer(1))).await?;
			let server_config = MuxEndpointConfig { rekey_limit: Some(18), ..rekey_config() };
			let pair = spawn_echo_pair_with(client, server, rekey_config(), server_config, trace.share())?;
			trace.event_with(
				RECEIPTLESS_SESSION_HAS_NO_EPOCH_RECEIPT,
				&[],
				pair.client.handle.session_receipt().is_none(),
			)?;

			let frame = large_mux_frame("rekey-inert");
			let echoed = pair.client.handle.emit_on_stream(&frame).await?;
			trace.event_with(
				RECEIPTLESS_TRANSFER_SURVIVES_DRAIN,
				&[],
				is_echo(echoed, &frame),
			)?;

			trace.event_with(
				RECEIPTLESS_DRAIN_KEEPS_TODAYS_PATH,
				&[],
				await_goaway_reason(&pair.client.handle, GoAwayReason::Shutdown).await,
			)?;

			// Stimulus only: the refusal itself emits `events::MUX_EMIT_DRAINING`.
			let _late = pair.client.handle.emit_on_stream(&mux_frame("rekey-inert-late")).await;

			Ok(())
		}
	}
}
