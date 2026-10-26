//! Mux scenarios for chunking, credit, budgets, flow violations, and
//! authorizers.

use core::time::Duration;
use std::sync::Arc;

use tokio::time::timeout;

use tightbeam::der::Decode;
use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::tb_assert_spec;
use tightbeam::tb_process_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::{
	GoAwayReason, MuxCreditPackage, MuxDataPackage, MuxEnvelope, MuxOpenPackage, MuxStreamKind,
};
use tightbeam::transport::handshake::negotiation::{MuxBudgets, NegotiationError};
use tightbeam::transport::handshake::HandshakeError;
use tightbeam::transport::{
	EncryptedMessageIO, EnvelopeSink, EnvelopeSource, TransportEnvelope, TransportError, TransportFailure,
};
use tightbeam::urn::Urn;
use tightbeam::{Frame, TightBeamError};

use crate::common::security::{expectation_failure, ServerMaterials};
use crate::transport::support::{
	await_ok, await_transport, await_within_deadline, bind_encrypted_listener, bind_encrypted_listener_with_timeout,
	connect_pinned_client, establish_mutual_transports, join_task, mux_frame, mux_offer, serve_one_handshake_message,
	MutualSessionHooks,
};

use super::common::*;

pub(crate) const CONTROL_STILL_FLOWS: Urn<'static> = tightbeam::urn!("test", "event:credit/control-still-flows");
pub(crate) const DRAIN_COMPLETES_CLEAN: Urn<'static> = tightbeam::urn!("test", "event:credit/drain-completes-clean");

/// Two concurrent chunked frames each echo on their own stream.
#[tokio::test]
async fn mux_chunked_large_frames_roundtrip_and_interleave() -> Result<(), TightBeamError> {
	let config = MuxEndpointConfig::default();
	let pair = establish_echo_pair(chunked_offer(4), chunked_offer(4), config, TraceCollector::new()).await?;
	let first = large_mux_frame("mux-chunked-first");
	let second = large_mux_frame("mux-chunked-second");
	let (first_echo, second_echo) = tokio::join!(
		pair.client.handle.emit_on_stream(&first),
		pair.client.handle.emit_on_stream(&second),
	);

	assert!(is_echo(first_echo?, &first), "the first chunked frame must echo");
	assert!(is_echo(second_echo?, &second), "the second chunked frame must echo");
	Ok(())
}

/// Reads the next envelope as the first chunk of a chunked open on
/// `stream_id`, and returns its payload.
///
/// # Errors
///
/// - [`TightBeamError`] -- an expectation failure when the envelope is another record, or the read failure.
async fn read_partial_open(reader: &mut SplitReader, stream_id: u32) -> Result<Vec<u8>, TightBeamError> {
	let open = reader.read_envelope().await?;
	match open {
		TransportEnvelope::Mux(MuxEnvelope::Open(package)) if !package.last() && package.stream_id() == stream_id => {
			Ok(package.payload().to_vec())
		}
		_ => Err(expectation_failure(
			"the open chunk must spend the initial credit of its stream",
		)),
	}
}

/// A sender parks at the initial credit of its stream, and the transfer
/// resumes on the grant.
#[tokio::test]
async fn mux_stream_credit_stall_and_resume() -> Result<(), TightBeamError> {
	let server_offer = chunked_offer(4).with_initial_stream_credit(1);
	let mut link = establish_client_mux_server_raw_with(chunked_offer(4), server_offer, TraceCollector::new()).await?;

	let frame = large_mux_frame("mux-credit-stall");
	let emit_task = spawn_emit(&link.client.handle, frame.to_owned());
	let payload = read_partial_open(&mut link.server_reader, client_stream_id(0)).await?;

	let stalled = timeout(Duration::from_millis(200), link.server_reader.read_envelope())
		.await
		.is_err();
	assert!(stalled, "the sender must stall at the initial credit of its stream");

	let grant = MuxCreditPackage::new(client_stream_id(0), 64);
	link.server_writer.write_envelope(grant.into()).await?;

	let payload = read_remaining_chunks(&mut link.server_reader, client_stream_id(0), payload).await?;
	let received = Frame::from_der(&payload)?;
	assert_eq!(received, frame, "the transfer must resume on the grant");

	let ack = mux_frame("mux-stall-ack");
	write_muxed_echo(&mut link.server_writer, client_stream_id(0), &Arc::new(ack.to_owned())).await?;

	let resolved = await_ok(emit_task, "stalled emit task must not panic").await?;
	assert!(is_echo(resolved, &ack), "the stalled stream must still echo");
	Ok(())
}

tb_assert_spec! {
	pub MuxZeroBudgetSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(events::MUX_BUDGET_REFUSED, exactly!(1)),
			(CONTROL_STILL_FLOWS, exactly!(1), equals!(true)),
			(DRAIN_COMPLETES_CLEAN, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxZeroBudgetProcess,
	events {
		observable {
			events::MUX_BUDGET_REFUSED,
			CONTROL_STILL_FLOWS,
			DRAIN_COMPLETES_CLEAN
		}
		hidden { }
	}
	states {
		Idle => { events::MUX_BUDGET_REFUSED => DataRefused },
		DataRefused => { CONTROL_STILL_FLOWS => ControlOk },
		ControlOk => { DRAIN_COMPLETES_CLEAN => Done },
		Done => { }
	}
	terminal { Done }
}

// Under a zero budget, a data emit fails at once, while a ping and the
// shutdown succeed.
tb_scenario! {
	name: mux_zero_budget_refuses_data_drains_clean,
	config: ScenarioConfig::builder()
		.with_spec(MuxZeroBudgetSpec::latest())
		.with_csp(MuxZeroBudgetProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let budgets = MuxBudgets { client_to_server: 0, server_to_client: 0 };
			let client_offer = mux_offer(4).with_budgets(budgets);
			let server_offer = mux_offer(4).with_budgets(budgets);
			let hooks = MutualSessionHooks::default();
			let session = establish_mutual_transports(client_offer, server_offer, hooks).await?;
			let config = MuxEndpointConfig::default();
			let pair = spawn_echo_pair(session.client, session.server, config, trace.share())?;

			let refused = pair.client.handle.emit_on_stream(&mux_frame("mux-zero-budget")).await;
			assert!(is_budget_exhausted(&refused), "a data emit under a zero budget must fail as budget exhausted");

			trace.event_with(
				CONTROL_STILL_FLOWS,
				&[],
				pair.client.handle.ping().await.is_ok(),
			)?;

			let drained = pair.client.handle.shutdown().await;
			trace.event_with(DRAIN_COMPLETES_CLEAN, &[], drained.is_ok())?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxBudgetExhaustionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(events::MUX_EMIT_DRAINING, exactly!(1)),
			(events::MUX_GOAWAY_RECV, exactly!(1), equals!(u32::from(GoAwayReason::BudgetExhausted)))
		]
	}
}

// With caps of 1/1 and a 1 KiB chunk, the reserve is 5 credits, so a grant of 6
// runs out on the first emit.
tb_scenario! {
	name: mux_budget_exhaustion_drains,
	spec: MuxBudgetExhaustionSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let budgets = MuxBudgets { client_to_server: 6, server_to_client: 4096 };
			let client_offer = chunked_offer(1).with_budgets(budgets);
			let server_offer = chunked_offer(1).with_budgets(budgets);
			let hooks = MutualSessionHooks::default();
			let session = establish_mutual_transports(client_offer, server_offer, hooks).await?;
			let config = MuxEndpointConfig::default();
			let pair = spawn_echo_pair(session.client, session.server, config, trace.share())?;

			let frame = mux_frame("mux-budget-last");
			let echoed = pair.client.handle.emit_on_stream(&frame).await?;
			assert!(is_echo(echoed, &frame), "the emit that reaches the reserve must still echo");

			// The late emit is a stimulus alone: its refusal emits
			// `events::MUX_EMIT_DRAINING`.
			let _late = pair.client.handle.emit_on_stream(&mux_frame("mux-budget-late")).await;

			let received = await_transport(|| trace.recorded(events::MUX_GOAWAY_RECV) > 0).await;
			assert!(received, "the server must receive the GoAway of the exhausted budget");

			Ok(())
		}
	}
}

async fn protocol_error_goaway_after(
	link: ServerMuxClientRaw,
	envelopes: impl IntoIterator<Item = TransportEnvelope>,
) -> Result<bool, TightBeamError> {
	let envelopes: Vec<TransportEnvelope> = envelopes.into_iter().collect();
	let ServerMuxClientRaw { server: _server, responder, mut client_reader, mut client_writer } = link;
	let _serve = spawn_immediate_echo(responder);

	for envelope in envelopes {
		client_writer.write_envelope(envelope).await?;
	}

	let goaway = read_until_goaway(&mut client_reader, GoAwayReason::ProtocolError).await?;
	Ok(goaway)
}

async fn oversize_chunk_rejected(trace: TraceCollector) -> Result<bool, TightBeamError> {
	let client_offer = chunked_offer(4);
	let server_offer = chunked_offer(4);
	let config = MuxEndpointConfig::default();
	let link = establish_server_mux_client_raw_with(client_offer, server_offer, config, trace).await?;

	let oversize = MuxOpenPackage::new(1, true, MuxStreamKind::Unary, vec![0u8; 2048])?;
	let envelopes = vec![oversize.into()];

	protocol_error_goaway_after(link, envelopes).await
}

async fn credit_overrun_rejected(trace: TraceCollector) -> Result<bool, TightBeamError> {
	let client_offer = chunked_offer(4);
	let server_offer = chunked_offer(4).with_initial_stream_credit(1);
	let grantor = Arc::new(NeverGrant);
	let config = MuxEndpointConfig { grantor: Some(grantor), ..MuxEndpointConfig::default() };
	let link = establish_server_mux_client_raw_with(client_offer, server_offer, config, trace).await?;

	let chunk = vec![0u8; 1024];
	let open = MuxOpenPackage::new(1, false, MuxStreamKind::Unary, chunk.to_owned())?;
	let overrun = MuxDataPackage::new(1, false, chunk)?;
	let envelopes = vec![open.into(), overrun.into()];

	protocol_error_goaway_after(link, envelopes).await
}

// Five partial opens exceed the concurrent stream cap of 4 (RFC 9113 § 5.1.2,
// <https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2>).
async fn reassembly_flood_rejected(trace: TraceCollector) -> Result<bool, TightBeamError> {
	let client_offer = chunked_offer(4);
	let server_offer = chunked_offer(4);
	let config = MuxEndpointConfig::default();
	let link = establish_server_mux_client_raw_with(client_offer, server_offer, config, trace).await?;

	let partial = vec![0u8; 16];
	let envelopes = vec![
		MuxOpenPackage::new(client_stream_id(0), false, MuxStreamKind::Unary, partial.to_owned())?.into(),
		MuxOpenPackage::new(client_stream_id(1), false, MuxStreamKind::Unary, partial.to_owned())?.into(),
		MuxOpenPackage::new(client_stream_id(2), false, MuxStreamKind::Unary, partial.to_owned())?.into(),
		MuxOpenPackage::new(client_stream_id(3), false, MuxStreamKind::Unary, partial.to_owned())?.into(),
		MuxOpenPackage::new(client_stream_id(4), false, MuxStreamKind::Unary, partial)?.into(),
	];

	protocol_error_goaway_after(link, envelopes).await
}

async fn budget_overrun_rejected(trace: TraceCollector) -> Result<bool, TightBeamError> {
	let budgets = MuxBudgets { client_to_server: 1, server_to_client: 4096 };
	let client_offer = chunked_offer(4).with_budgets(budgets);
	let server_offer = chunked_offer(4).with_budgets(budgets);
	let hooks = MutualSessionHooks::default();
	let session = establish_mutual_transports(client_offer, server_offer, hooks).await?;
	let config = MuxEndpointConfig::default();
	let link = split_server_mux_client_raw(session.client, session.server, config, trace)?;

	let first = muxed_request_envelope(1, mux_frame("mux-budget-first"))?;
	let over = muxed_request_envelope(3, mux_frame("mux-budget-over"))?;
	let envelopes = vec![first, over];

	protocol_error_goaway_after(link, envelopes).await
}

tb_assert_spec! {
	pub MuxFlowViolationSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_PROTOCOL_ERROR, exactly!(4)),
			(events::MUX_GOAWAY_SENT, exactly!(4), equals!(u32::from(GoAwayReason::ProtocolError)))
		]
	}
}

tb_scenario! {
	name: mux_flow_control_violations_rejected,
	spec: MuxFlowViolationSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let oversize = oversize_chunk_rejected(trace.share()).await?;
			assert!(oversize, "an oversize chunk must draw a ProtocolError GoAway");

			let credit = credit_overrun_rejected(trace.share()).await?;
			assert!(credit, "a credit overrun must draw a ProtocolError GoAway");

			let flood = reassembly_flood_rejected(trace.share()).await?;
			assert!(flood, "a reassembly flood must draw a ProtocolError GoAway");

			let budget = budget_overrun_rejected(trace.share()).await?;
			assert!(budget, "a budget overrun must draw a ProtocolError GoAway");

			Ok(())
		}
	}
}

/// An authorizer that halves the requested budgets binds the same reduced
/// grant on both sides.
#[tokio::test]
async fn mux_authorizer_reduced_grant_both_sides() -> Result<(), TightBeamError> {
	let request = MuxBudgets { client_to_server: 10, server_to_client: 10 };
	let hooks = MutualSessionHooks { authorizer: Some(Arc::new(HalvingAuthorizer)), ..MutualSessionHooks::default() };
	let session = establish_mutual_transports(mux_offer(4).with_budgets(request), mux_offer(4), hooks).await?;

	let client_settings = session
		.client
		.negotiated_mux()
		.ok_or_else(|| expectation_failure("client must negotiate multiplexing"))?;
	let server_settings = session
		.server
		.negotiated_mux()
		.ok_or_else(|| expectation_failure("server must negotiate multiplexing"))?;

	let client_grant = (client_settings.send_budget, client_settings.recv_budget);
	let server_grant = (server_settings.send_budget, server_settings.recv_budget);
	assert_eq!(client_grant, (Some(5), Some(5)), "the client must take the halved grant");
	assert_eq!(server_grant, (Some(5), Some(5)), "the server must bind the halved grant");
	Ok(())
}

tb_assert_spec! {
	pub MuxAuthorizerRefusalSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_AUTHORIZATION_REFUSED, exactly!(1), equals!(REFUSAL_CODE))
		]
	}
}

// The authorizer refuses before the accept enters the transcript, so both sides
// fail closed.
tb_scenario! {
	name: mux_authorizer_refusal_fails_closed,
	spec: MuxAuthorizerRefusalSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let (listener, addr) = bind_encrypted_listener(&materials).await?;
			let server_trace = trace.share();

			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(mux_offer(4)))
					.with_transport_authorizer(Arc::new(RefusingAuthorizer))
					.with_trace(server_trace);

				serve_one_handshake_message(&mut transport).await?;
				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(())
			});

			let request = MuxBudgets { client_to_server: 10, server_to_client: 10 };
			let mut client = connect_pinned_client(addr, &materials.certificate).await?;
			client = client.with_mux_offer(Some(mux_offer(4).with_budgets(request)));

			let client_result = client.perform_client_handshake().await;
			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			let refused_with_code = matches!(
				server_result,
				Err(TightBeamError::TransportError(TransportError::HandshakeError(
					HandshakeError::NegotiationError(NegotiationError::AuthorizationRefused { code: REFUSAL_CODE })
				)))
			);
			assert!(refused_with_code, "the server must refuse the session with the authorizer's code");
			assert!(client_result.is_err(), "the client handshake must fail closed when the server refuses it");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxAuthorizerDeadlineSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_EXPIRED, exactly!(1))
		]
	}
}

// The handshake deadline bounds a hung authorizer, and the server fails with
// `DeadlineExceeded`.
tb_scenario! {
	name: mux_hung_authorizer_bounded_by_handshake_deadline,
	spec: MuxAuthorizerDeadlineSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let (listener, addr) =
				bind_encrypted_listener_with_timeout(&materials, Duration::from_millis(200)).await?;
			let server_trace = trace.share();

			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(mux_offer(4)))
					.with_transport_authorizer(Arc::new(HangingAuthorizer))
					.with_trace(server_trace);

				serve_one_handshake_message(&mut transport).await?;
				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(())
			});

			let request = MuxBudgets { client_to_server: 10, server_to_client: 10 };
			let mut client = connect_pinned_client(addr, &materials.certificate).await?;
			client = client.with_mux_offer(Some(mux_offer(4).with_budgets(request)));
			let client_task = tokio::spawn(async move { client.perform_client_handshake().await });

			let server_join = join_task(server_task, "server handshake task must not panic");
			let server_bounded = await_within_deadline(server_join, "hung authorizer must not stall the server past the deadline");
			let server_result = server_bounded.await??;
			let expired = matches!(
				server_result,
				Err(TightBeamError::TransportError(TransportError::OperationFailed(
					TransportFailure::DeadlineExceeded
				)))
			);
			assert!(expired, "the handshake deadline must end the server handshake");

			let client_join = join_task(client_task, "client handshake task must not panic");
			let client_bounded = await_within_deadline(client_join, "client must fail closed once the server abandons the handshake");
			let client_result = client_bounded.await??;
			assert!(client_result.is_err(), "the client handshake must fail closed when the server abandons it");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyChunkedDrainSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(events::MUX_GOAWAY_RECV, exactly!(1), equals!(u32::from(GoAwayReason::Shutdown))),
			(events::MUX_EMIT_DRAINING, exactly!(1))
		]
	}
}

// The rekey limit of 18 records is below the 15 response records plus the
// reserve of 5 (caps 1/1, chunk 1024), so the transfer crosses the drain floor,
// and the reserve keeps headroom for the GoAway.
tb_scenario! {
	name: mux_rekey_drain_with_inflight_chunked_transfer,
	spec: MuxRekeyChunkedDrainSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let config = MuxEndpointConfig { rekey_limit: Some(18), ..MuxEndpointConfig::default() };
			let pair = establish_echo_pair(chunked_offer(1), chunked_offer(1), config, trace.share()).await?;

			let frame = large_mux_frame("mux-rekey-chunked");
			let echoed = pair.client.handle.emit_on_stream(&frame).await?;
			assert!(is_echo(echoed, &frame), "the chunked transfer must echo across the drain");

			let received = await_transport(|| trace.recorded(events::MUX_GOAWAY_RECV) > 0).await;
			assert!(received, "the client must receive the drain GoAway of the server");

			// The late emit is a stimulus alone: its refusal emits
			// `events::MUX_EMIT_DRAINING`.
			let _late = pair.client.handle.emit_on_stream(&mux_frame("mux-rekey-late")).await;

			Ok(())
		}
	}
}
