//! The integration tests of in-band epoch renewal, the rekey.

use core::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tightbeam::at_least;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::x509::{KeyPurposes, PeerCertificate, Signing};
use tightbeam::der::asn1::OctetString;
use tightbeam::der::Encode;
use tightbeam::exactly;
use tightbeam::marker::MaybeSendFuture;
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
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;
use tokio::time::timeout;

use crate::common::security::{expectation_failure, ClientMaterials, ServerMaterials};
use crate::transport::support::{
	await_receipt_rotation, await_transport, establish_mutual_transports, establish_mutual_transports_of, mux_frame,
	mux_offer, MutualSessionHooks, MutualTransports,
};

use super::common::*;

use tightbeam::instrumentation::events;

/// The settlement challenge the authorizer binds into every epoch receipt.
const RENEWAL_CHALLENGE: &[u8] = b"epoch-invoice-7";

/// The settlement answer the approver countersigns at each renewal.
const RENEWAL_RESPONSE: &[u8] = b"epoch-preimage-7";

/// The application code of a renewal that the authorizer's `settle` refuses.
const SETTLE_REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR + 31;

/// The application code of a renewal that the approver refuses.
const APPROVAL_REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR + 32;

/// The budgets under which the fifth single-chunk emit tips the budget into
/// the drain reserve, with a stream cap of 1 on each side and a 1 KiB chunk.
const RENEWAL_TRIGGER_BUDGETS: MuxBudgets = MuxBudgets { client_to_server: 10, server_to_client: 4096 };

/// The budgets, large enough that the record watermark drives the renewal.
const AMPLE_BUDGETS: MuxBudgets = MuxBudgets { client_to_server: 1_000_000, server_to_client: 1_000_000 };

fn rekey_config() -> MuxEndpointConfig {
	MuxEndpointConfig { rekey: true, ..MuxEndpointConfig::default() }
}

async fn establish_renewal_session(hooks: MutualSessionHooks) -> Result<MutualTransports, TightBeamError> {
	let client_offer = chunked_offer(1).with_budgets(RENEWAL_TRIGGER_BUDGETS);
	let server_offer = chunked_offer(1).with_budgets(RENEWAL_TRIGGER_BUDGETS);
	establish_mutual_transports(client_offer, server_offer, hooks).await
}

async fn emit_series(handle: &MuxHandle, label: impl AsRef<str>, count: usize) -> Result<bool, TightBeamError> {
	let label = label.as_ref();
	for index in 0..count {
		let frame = mux_frame(format!("{label}-{index}"));
		let echoed = handle.emit_on_stream(&frame).await?;
		if !is_echo(echoed, &frame) {
			return Ok(false);
		}
	}

	Ok(true)
}

/// Emit `count` chunked frames labeled from `label`, one after another, and
/// report whether each one echoed.
///
/// # Errors
///
/// - [`TightBeamError`] -- the failure of an emit.
async fn emit_large_series(handle: &MuxHandle, label: impl AsRef<str>, count: usize) -> Result<bool, TightBeamError> {
	let label = label.as_ref();
	let mut all_echoed = true;
	for index in 0..count {
		let frame = large_mux_frame(format!("{label}-{index}"));
		let echoed = handle.emit_on_stream(&frame).await?;
		all_echoed = all_echoed && is_echo(echoed, &frame);
	}

	Ok(all_echoed)
}

/// Stream `count` chunked frames labeled from `label` through `open_stream`,
/// one after another, and report whether each one echoed.
///
/// # Errors
///
/// - [`TightBeamError`] -- the encode, open, push, or response failure of a stream.
async fn stream_large_series(handle: &MuxHandle, label: impl AsRef<str>, count: usize) -> Result<bool, TightBeamError> {
	let label = label.as_ref();
	let mut all_echoed = true;
	for index in 0..count {
		let frame = large_mux_frame(format!("{label}-{index}"));
		let payload = frame.to_der()?;
		let (sink, response) = handle.open_stream()?;
		push_split(sink, &payload).await?;

		let echoed = response.await?;
		all_echoed = all_echoed && is_echo(echoed, &frame);
	}

	Ok(all_echoed)
}

/// Write `count` single-chunk requests from the raw client, one per fresh
/// stream, so the server sees the records a renewal must spend first.
///
/// # Errors
///
/// - [`TightBeamError`] -- the encode or write failure of a request.
async fn spend_records(writer: &mut SplitWriter, count: u32) -> Result<(), TightBeamError> {
	for index in 0..count {
		let stream_id = client_stream_id(index);
		write_muxed_request(writer, stream_id, mux_frame("rekey-spend")).await?;
	}

	Ok(())
}

/// Poll until the epoch receipt differs from `previous`, bounded by a timeout.
async fn await_rotation(handle: &MuxHandle, previous: Option<&StoredReceipt>) -> Option<Arc<StoredReceipt>> {
	await_receipt_rotation(|| handle.session_receipt(), previous).await
}

async fn await_matching_receipt(handle: &MuxHandle, expected: &StoredReceipt) -> bool {
	await_transport(|| handle.session_receipt().as_deref() == Some(expected)).await
}

/// A hand-built rekey request that carries `seed` as its randomness and a
/// fresh ephemeral point.
fn rekey_request_envelope(seed: u8) -> Result<TransportEnvelope, TightBeamError> {
	let ephemeral = k256::SecretKey::random(&mut rand_core::OsRng).public_key();
	let package = MuxRekeyRequestPackage::new(vec![seed; 32], &ephemeral)?;
	Ok(MuxEnvelope::RekeyRequest(package).into())
}

/// Skip stream traffic until a `RekeyRequest` arrives.
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

/// Skip echo and credit traffic until a `RekeyResponse` arrives.
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

/// An authorizer that poses a settlement challenge on every renewal and
/// counts the `settle` consultations.
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
		_client: &'a Certificate,
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

/// An approver that answers challenge-bearing receipts. Handshake receipts
/// pass without an answer.
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

/// An approver that approves the initial handshake receipt, then refuses
/// every renewal with [`APPROVAL_REFUSAL_CODE`].
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
		assertions: [
			(events::MUX_REKEY_REQUESTED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(2)),
			(events::MUX_REKEY_REFUSED, exactly!(0)),
			(events::MUX_REKEY_VERIFY_FAILED, exactly!(0))
		]
	}
}

// Without renewal this session drains at the fifth emit
// (mux_budget_exhaustion_drains).
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
			assert!(all_echoed, "every emit must echo across the budget renewal");

			let rotated = await_rotation(&pair.client.handle, initial.as_ref()).await;
			let epoch_receipt = rotated.ok_or_else(|| expectation_failure("client must rotate the epoch receipt"))?;
			let agreed = await_matching_receipt(&pair.server.handle, &epoch_receipt).await;
			assert!(agreed, "both endpoints must hold the same epoch receipt");

			let renewed = await_transport(|| trace.recorded(events::MUX_REKEY_RENEWED) >= 2).await;
			assert!(renewed, "both endpoints must record the renewal");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyRecordRenewalSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_REKEY_REQUESTED, at_least!(1)),
			(events::MUX_REKEY_RECEIPT_ISSUED, at_least!(1)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, at_least!(1)),
			(events::MUX_REKEY_RENEWED, at_least!(2))
		]
	}
}

tb_assert_spec! {
	pub MuxRekeyStreamingRenewalSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_REKEY_REQUESTED, at_least!(1)),
			(events::MUX_REKEY_RENEWED, at_least!(2))
		]
	}
}

// The record watermark matches the chunked-traffic renewal, and every request
// travels through `open_stream` against `serve_streaming`. The sink's per-push
// records and the drain-driven grants must both cross the epoch switch intact.
tb_scenario! {
	name: mux_rekey_renewal_survives_streaming_traffic,
	spec: MuxRekeyStreamingRenewalSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let client_offer = chunked_offer(4).with_budgets(AMPLE_BUDGETS);
			let server_offer = chunked_offer(4).with_budgets(AMPLE_BUDGETS);
			let session = establish_mutual_transports(client_offer, server_offer, MutualSessionHooks::default()).await?;

			let client_config = MuxEndpointConfig { rekey_limit: Some(100), ..rekey_config() };
			let client_transport = session.client.with_trace(trace.share());
			let (client_end, _) = spawn_mux_endpoint_with(client_transport, MuxRole::Client, client_config)?;
			let server_transport = session.server.with_trace(trace.share());
			let (_server_end, responder) = spawn_mux_endpoint_with(server_transport, MuxRole::Server, rekey_config())?;

			let chunks_seen = Arc::new(AtomicUsize::new(0));
			let _serve = tokio::spawn(responder.serve_streaming(streaming_echo_handler(Arc::clone(&chunks_seen))));

			let all_echoed = stream_large_series(&client_end.handle, "rekey-streaming", 20).await?;
			assert!(all_echoed, "streamed traffic must echo across the key switch");

			let renewed = await_transport(|| trace.recorded(events::MUX_REKEY_RENEWED) >= 2).await;
			assert!(renewed, "both endpoints must record the renewal");

			Ok(())
		}
	}
}

// 20 × 6 records = 120 against a limit of 100, so the traffic straddles the key
// switch.
tb_scenario! {
	name: mux_rekey_record_renewal_survives_chunked_traffic,
	spec: MuxRekeyRecordRenewalSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let client_offer = chunked_offer(4).with_budgets(AMPLE_BUDGETS);
			let server_offer = chunked_offer(4).with_budgets(AMPLE_BUDGETS);
			let session = establish_mutual_transports(client_offer, server_offer, MutualSessionHooks::default()).await?;

			let client_config = MuxEndpointConfig { rekey_limit: Some(100), ..rekey_config() };
			let pair =
				spawn_echo_pair_with(session.client, session.server, client_config, rekey_config(), trace.share())?;

			let all_echoed = emit_large_series(&pair.client.handle, "rekey-record", 20).await?;
			assert!(all_echoed, "chunked traffic must echo across the key switch");

			let renewed = await_transport(|| trace.recorded(events::MUX_REKEY_RENEWED) >= 2).await;
			assert!(renewed, "both endpoints must record the renewal");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyEpochChainSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_REKEY_REQUESTED, exactly!(2)),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(2)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(2)),
			(events::MUX_REKEY_RENEWED, exactly!(4)),
			(events::MUX_REKEY_REFUSED, exactly!(0))
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
			let server_certificate: PeerCertificate<Signing<DefaultCryptoProvider>> =
				PeerCertificate::parse(session.server_certificate.to_owned(), KeyPurposes::HOUSE.server)?;
			let client_certificate: PeerCertificate<Signing<DefaultCryptoProvider>> =
				PeerCertificate::parse(session.client_certificate.to_owned(), KeyPurposes::HOUSE.client)?;
			let pair = spawn_echo_pair_with(session.client, session.server, rekey_config(), rekey_config(), trace.share())?;

			let first_batch = emit_series(&pair.client.handle, "rekey-chain-a", 5).await?;
			let first = await_rotation(&pair.client.handle, initial.as_ref()).await;
			let first = first.ok_or_else(|| expectation_failure("first renewal must rotate the receipt"))?;
			let second_batch = emit_series(&pair.client.handle, "rekey-chain-b", 5).await?;
			let second = await_rotation(&pair.client.handle, Some(&*first)).await;
			let second = second.ok_or_else(|| expectation_failure("second renewal must rotate the receipt"))?;
			assert!(first_batch && second_batch, "every emit must echo across both renewals");

			let distinct = initial.as_ref() != Some(&*second);
			assert!(distinct, "two renewals must rotate to a receipt distinct from the handshake receipt");

			let verdict = second.verify(&server_certificate, &client_certificate);
			assert!(verdict.is_ok(), "the second epoch receipt must verify against the handshake certificates");

			let renewed = await_transport(|| trace.recorded(events::MUX_REKEY_RENEWED) >= 4).await;
			assert!(renewed, "both endpoints must record both renewals");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeySettledChallengeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_REKEY_REQUESTED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(2)),
			(events::MUX_REKEY_REFUSED, exactly!(0)),
			(events::MUX_REKEY_VERIFY_FAILED, exactly!(0))
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
			let pair = spawn_echo_pair_with(session.client, session.server, rekey_config(), rekey_config(), trace.share())?;

			let all_echoed = emit_series(&pair.client.handle, "rekey-settle", 8).await?;
			assert!(all_echoed, "every emit must echo across the settled renewal");

			let renewed = await_transport(|| trace.recorded(events::MUX_REKEY_RENEWED) >= 2).await;
			assert!(renewed, "both endpoints must record the renewal");
			assert!(renewal_authorizer.settle_calls() >= 1, "the authorizer must settle the challenged renewal");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeySettleRefusalSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_REKEY_REQUESTED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(1)),
			(events::MUX_REKEY_REFUSED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(0)),
			(events::MUX_EMIT_DRAINING, exactly!(1)),
			(events::MUX_GOAWAY_RECV, exactly!(1), equals!(u32::from(GoAwayReason::Application(SETTLE_REFUSAL_CODE))))
		]
	}
}

// The client switches at the Ack. The server installs the receive cipher, then
// drains with the settlement refusal code.
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
			let received = await_transport(|| trace.recorded(events::MUX_GOAWAY_RECV) > 0).await;
			assert!(received, "the client must receive the GoAway that carries the settlement refusal");

			// The late emit is a stimulus alone. Its refusal emits
			// `events::MUX_EMIT_DRAINING`.
			let _late = pair.client.handle.emit_on_stream(&mux_frame("rekey-late")).await;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyApprovalRefusalSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_REKEY_REQUESTED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(1)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(0)),
			(events::MUX_REKEY_REFUSED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(0)),
			(events::MUX_EMIT_DRAINING, exactly!(1)),
			(events::MUX_GOAWAY_RECV, exactly!(1), equals!(u32::from(GoAwayReason::Application(APPROVAL_REFUSAL_CODE))))
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
			let received = await_transport(|| trace.recorded(events::MUX_GOAWAY_RECV) > 0).await;
			assert!(received, "the server must receive the GoAway that carries the approval refusal");

			// The late emit is a stimulus alone. Its refusal emits
			// `events::MUX_EMIT_DRAINING`.
			let _late = pair.client.handle.emit_on_stream(&mux_frame("rekey-late")).await;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyMinSpendSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_PROTOCOL_ERROR, exactly!(1)),
			(events::MUX_GOAWAY_SENT, exactly!(1), equals!(u32::from(GoAwayReason::ProtocolError))),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(0)),
			(events::MUX_REKEY_RENEWED, exactly!(0))
		]
	}
}

// CWE-400: a RekeyRequest below the minimum-spend floor draws
// GoAway(ProtocolError).
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

			let violated = read_until_goaway(&mut link.client_reader, GoAwayReason::ProtocolError).await?;
			assert!(violated, "a request below the minimum spend must draw a ProtocolError GoAway");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyDuplicateRequestSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_PROTOCOL_ERROR, exactly!(1)),
			(events::MUX_GOAWAY_SENT, exactly!(1), equals!(u32::from(GoAwayReason::ProtocolError))),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(0)),
			(events::MUX_REKEY_VERIFY_FAILED, exactly!(0))
		]
	}
}

// CWE-400: a duplicate RekeyRequest while an exchange is in flight draws
// GoAway(ProtocolError).
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

			// The server answers a first request only after the minimum spend.
			spend_records(&mut link.client_writer, 4).await?;

			link.client_writer.write_envelope(rekey_request_envelope(7)?).await?;
			read_until_rekey_response(&mut link.client_reader).await?;
			link.client_writer.write_envelope(rekey_request_envelope(9)?).await?;

			let violated = read_until_goaway(&mut link.client_reader, GoAwayReason::ProtocolError).await?;
			assert!(violated, "a duplicate request must draw a ProtocolError GoAway");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyTimeoutSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_REKEY_REQUESTED, exactly!(1)),
			(events::MUX_REKEY_RENEWED, exactly!(0)),
			(events::MUX_REKEY_EXPIRED, exactly!(1)),
			(events::MUX_GOAWAY_SENT, exactly!(1), equals!(u32::from(GoAwayReason::Shutdown)))
		]
	}
}

// The renewal deadline bounds a stalled exchange with GoAway(Shutdown).
tb_scenario! {
	name: mux_rekey_timeout_drains_clean,
	spec: MuxRekeyTimeoutSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let client_offer = chunked_offer(4).with_budgets(AMPLE_BUDGETS);
			let server_offer = chunked_offer(4).with_budgets(AMPLE_BUDGETS);
			let session = establish_mutual_transports(client_offer, server_offer, MutualSessionHooks::default()).await?;

			// The record limit sits below the renewal floor, so the first write
			// opens a renewal. The server never answers it.
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

			let drained = read_until_goaway(&mut server_reader, GoAwayReason::Shutdown).await?;
			assert!(drained, "the stalled renewal must drain with a Shutdown GoAway");

			let recorded = await_transport(|| trace.recorded(events::MUX_GOAWAY_SENT) > 0).await;
			assert!(recorded, "the client must record the GoAway of the expired renewal");

			abort_emit(emit_task).await;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyInertPathsSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_REKEY_REQUESTED, exactly!(0)),
			(events::MUX_REKEY_RECEIPT_ISSUED, exactly!(0)),
			(events::MUX_REKEY_RECEIPT_COUNTERSIGNED, exactly!(0)),
			(events::MUX_REKEY_RENEWED, exactly!(0)),
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(events::MUX_GOAWAY_RECV, exactly!(1), equals!(u32::from(GoAwayReason::Shutdown))),
			(events::MUX_EMIT_DRAINING, exactly!(1))
		]
	}
}

// Receiptless or cleartext sessions have no rekey path, so the record limit
// draws GoAway(Shutdown).
tb_scenario! {
	name: mux_rekey_inert_paths_keep_todays_behavior,
	spec: MuxRekeyInertPathsSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (mut cleartext_client, mut cleartext_server) = establish_cleartext_transports().await?;
			let client_harvest = MuxConnector::take_rekey(&mut cleartext_client)?;
			let server_harvest = MuxAcceptor::take_rekey(&mut cleartext_server)?;
			let harvest_empty = client_harvest.is_none() && server_harvest.is_none();
			assert!(harvest_empty, "a cleartext link must yield no rekey materials");

			let (client, server) = establish_transports(Some(chunked_offer(1)), Some(chunked_offer(1))).await?;
			let server_config = MuxEndpointConfig { rekey_limit: Some(18), ..rekey_config() };
			let pair = spawn_echo_pair_with(client, server, rekey_config(), server_config, trace.share())?;
			let receiptless = pair.client.handle.session_receipt().is_none();
			assert!(receiptless, "a receiptless session must expose no epoch receipt");

			let frame = large_mux_frame("rekey-inert");
			let echoed = pair.client.handle.emit_on_stream(&frame).await?;
			assert!(is_echo(echoed, &frame), "the chunked transfer must echo across the drain");

			let received = await_transport(|| trace.recorded(events::MUX_GOAWAY_RECV) > 0).await;
			assert!(received, "the client must receive the drain GoAway of the server");

			// The late emit is a stimulus alone. Its refusal emits
			// `events::MUX_EMIT_DRAINING`.
			let _late = pair.client.handle.emit_on_stream(&mux_frame("rekey-inert-late")).await;

			Ok(())
		}
	}
}

/// A mutual session whose server certificate names the house server purpose
/// alone and whose client certificate names the house client purpose alone.
async fn establish_purposed_session() -> Result<MutualTransports, TightBeamError> {
	let materials = ServerMaterials::generate().with_key_purpose(KeyPurposes::HOUSE.server);
	let client_materials = ClientMaterials::generate().with_key_purpose(KeyPurposes::HOUSE.client);

	let client_offer = chunked_offer(1).with_budgets(AMPLE_BUDGETS);
	let server_offer = chunked_offer(1).with_budgets(AMPLE_BUDGETS);
	let hooks = MutualSessionHooks::default();
	let key_purposes = KeyPurposes::HOUSE;
	establish_mutual_transports_of(client_offer, server_offer, hooks, &materials, &client_materials, key_purposes).await
}

/// The client reads its server's certificate under the server purpose, so a
/// certificate of that purpose alone yields the client's rekey materials.
#[tokio::test]
async fn a_client_detaches_its_rekey_materials_under_the_server_purpose() -> Result<(), TightBeamError> {
	let MutualTransports { mut client, .. } = establish_purposed_session().await?;
	let rekey = MuxConnector::take_rekey(&mut client)?;
	assert!(rekey.is_some());
	Ok(())
}

/// The server reads its client's certificate under the client purpose, so a
/// certificate of that purpose alone yields the server's rekey materials.
#[tokio::test]
async fn a_server_detaches_its_rekey_materials_under_the_client_purpose() -> Result<(), TightBeamError> {
	let MutualTransports { mut server, .. } = establish_purposed_session().await?;
	let rekey = MuxAcceptor::take_rekey(&mut server)?;
	assert!(rekey.is_some());
	Ok(())
}
