//! Mux chunking, credit, budgets, flow violations, authorizers.

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
use tightbeam::utils::urn::Urn;
use tightbeam::{Frame, TightBeamError};

use crate::common::security::{expectation_failure, ServerMaterials};
use crate::transport::support::{
	await_ok, bind_encrypted_listener, bind_encrypted_listener_with_timeout, connect_pinned_client,
	establish_mutual_transports, join_task, mux_frame, mux_offer, serve_one_handshake_message, MutualSessionHooks,
};

use super::common::*;

pub(crate) const BUDGET_OVERRUN_ANSWERED_WITH_GOAWAY: Urn<'static> =
	Urn::new("test", "event:credit/budget-overrun-answered-with-goaway");
pub(crate) const CHUNKED_TRANSFER_SURVIVES_DRAIN: Urn<'static> =
	Urn::new("test", "event:credit/chunked-transfer-survives-drain");
pub(crate) const CLIENT_FAILS_CLOSED: Urn<'static> = Urn::new("test", "event:credit/client-fails-closed");
pub(crate) const CLIENT_VIEWS_REDUCED_GRANT: Urn<'static> = Urn::new("test", "event:credit/client-views-reduced-grant");
pub(crate) const CONTROL_STILL_FLOWS: Urn<'static> = Urn::new("test", "event:credit/control-still-flows");
pub(crate) const CREDIT_OVERRUN_ANSWERED_WITH_GOAWAY: Urn<'static> =
	Urn::new("test", "event:credit/credit-overrun-answered-with-goaway");
pub(crate) const DRAIN_COMPLETES_CLEAN: Urn<'static> = Urn::new("test", "event:credit/drain-completes-clean");
pub(crate) const DRAIN_REASON_SURFACES: Urn<'static> = Urn::new("test", "event:credit/drain-reason-surfaces");
pub(crate) const EXHAUSTING_EMIT_STILL_ECHOES: Urn<'static> =
	Urn::new("test", "event:credit/exhausting-emit-still-echoes");
pub(crate) const FIRST_LARGE_FRAME_ECHOED: Urn<'static> = Urn::new("test", "event:credit/first-large-frame-echoed");
pub(crate) const OPEN_CHUNK_SPENDS_INITIAL_CREDIT: Urn<'static> =
	Urn::new("test", "event:credit/open-chunk-spends-initial-credit");
pub(crate) const OVERSIZE_CHUNK_ANSWERED_WITH_GOAWAY: Urn<'static> =
	Urn::new("test", "event:credit/oversize-chunk-answered-with-goaway");
pub(crate) const PEER_OBSERVES_BUDGET_EXHAUSTED: Urn<'static> =
	Urn::new("test", "event:credit/peer-observes-budget-exhausted");
pub(crate) const REASSEMBLY_FLOOD_ANSWERED_WITH_GOAWAY: Urn<'static> =
	Urn::new("test", "event:credit/reassembly-flood-answered-with-goaway");
pub(crate) const SECOND_LARGE_FRAME_ECHOED: Urn<'static> = Urn::new("test", "event:credit/second-large-frame-echoed");
pub(crate) const SENDER_STALLS_AT_INITIAL_CREDIT: Urn<'static> =
	Urn::new("test", "event:credit/sender-stalls-at-initial-credit");
pub(crate) const SERVER_BOUNDS_HUNG_AUTHORIZER: Urn<'static> =
	Urn::new("test", "event:credit/server-bounds-hung-authorizer");
pub(crate) const SERVER_REFUSES_WITH_CODE: Urn<'static> = Urn::new("test", "event:credit/server-refuses-with-code");
pub(crate) const SERVER_VIEWS_REDUCED_GRANT: Urn<'static> = Urn::new("test", "event:credit/server-views-reduced-grant");
pub(crate) const STALLED_STREAM_STILL_ECHOES: Urn<'static> =
	Urn::new("test", "event:credit/stalled-stream-still-echoes");
pub(crate) const TRANSFER_RESUMES_ON_GRANT: Urn<'static> = Urn::new("test", "event:credit/transfer-resumes-on-grant");
pub(crate) const ZERO_BUDGET_EMIT_REFUSED: Urn<'static> = Urn::new("test", "event:credit/zero-budget-emit-refused");

tb_assert_spec! {
	pub MuxChunkedRoundtripSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(FIRST_LARGE_FRAME_ECHOED, exactly!(1), equals!(true)),
			(SECOND_LARGE_FRAME_ECHOED, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_chunked_large_frames_roundtrip_and_interleave,
	spec: MuxChunkedRoundtripSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let pair = establish_echo_pair(chunked_offer(4), chunked_offer(4), MuxEndpointConfig::default(), trace.share())
				.await?;
			let first = large_mux_frame("mux-chunked-first");
			let second = large_mux_frame("mux-chunked-second");
			let (first_echo, second_echo) = tokio::join!(
				pair.client.handle.emit_on_stream(&first),
				pair.client.handle.emit_on_stream(&second),
			);

			trace.event_with(
				FIRST_LARGE_FRAME_ECHOED,
				&[],
				is_echo(first_echo?, &first),
			)?;
			trace.event_with(
				SECOND_LARGE_FRAME_ECHOED,
				&[],
				is_echo(second_echo?, &second),
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxCreditStallSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(OPEN_CHUNK_SPENDS_INITIAL_CREDIT, exactly!(1), equals!(true)),
			(SENDER_STALLS_AT_INITIAL_CREDIT, exactly!(1), equals!(true)),
			(TRANSFER_RESUMES_ON_GRANT, exactly!(1), equals!(true)),
			(STALLED_STREAM_STILL_ECHOES, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxCreditStallProcess,
	events {
		observable {
			OPEN_CHUNK_SPENDS_INITIAL_CREDIT,
			SENDER_STALLS_AT_INITIAL_CREDIT,
			TRANSFER_RESUMES_ON_GRANT,
			STALLED_STREAM_STILL_ECHOES
		}
		hidden { }
	}
	states {
		Idle => { OPEN_CHUNK_SPENDS_INITIAL_CREDIT => Opened },
		Opened => { SENDER_STALLS_AT_INITIAL_CREDIT => Stalled },
		Stalled => { TRANSFER_RESUMES_ON_GRANT => Resumed },
		Resumed => { STALLED_STREAM_STILL_ECHOES => Done },
		Done => { }
	}
	terminal { Done }
}

tb_scenario! {
	name: mux_stream_credit_stall_and_resume,
	config: ScenarioConfig::builder()
		.with_spec(MuxCreditStallSpec::latest())
		.with_csp(MuxCreditStallProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let server_offer = chunked_offer(4).with_initial_stream_credit(1);
			let mut link =
				establish_client_mux_server_raw_with(chunked_offer(4), server_offer, trace.share()).await?;

			let frame = large_mux_frame("mux-credit-stall");
			let emit_task = spawn_emit(&link.client.handle, frame.to_owned());

			let open = link.server_reader.read_envelope().await?;
			let (payload, open_ok) = match open {
				TransportEnvelope::Mux(MuxEnvelope::Open(package))
					if !package.last() && package.stream_id() == client_stream_id(0) =>
				{
					(package.payload().to_vec(), true)
				}
				_ => (Vec::new(), false),
			};

			trace.event_with(OPEN_CHUNK_SPENDS_INITIAL_CREDIT, &[], open_ok)?;

			let stalled = timeout(Duration::from_millis(200), link.server_reader.read_envelope())
				.await
				.is_err();
			trace.event_with(SENDER_STALLS_AT_INITIAL_CREDIT, &[], stalled)?;

			let grant = MuxCreditPackage::new(client_stream_id(0), 64);
			link.server_writer.write_envelope(grant.into()).await?;

			let payload = read_remaining_chunks(&mut link.server_reader, client_stream_id(0), payload).await?;
			let received = Frame::from_der(&payload)?;

			let ack = mux_frame("mux-stall-ack");
			write_muxed_echo(&mut link.server_writer, client_stream_id(0), &Arc::new(ack.to_owned())).await?;

			let resolved = await_ok(emit_task, "stalled emit task must not panic").await?;
			trace.event_with(TRANSFER_RESUMES_ON_GRANT, &[], received == frame)?;
			trace.event_with(STALLED_STREAM_STILL_ECHOES, &[], is_echo(resolved, &ack))?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxZeroBudgetSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(ZERO_BUDGET_EMIT_REFUSED, exactly!(1), equals!(true)),
			(CONTROL_STILL_FLOWS, exactly!(1), equals!(true)),
			(DRAIN_COMPLETES_CLEAN, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxZeroBudgetProcess,
	events {
		observable {
			ZERO_BUDGET_EMIT_REFUSED,
			CONTROL_STILL_FLOWS,
			DRAIN_COMPLETES_CLEAN
		}
		hidden { }
	}
	states {
		Idle => { ZERO_BUDGET_EMIT_REFUSED => DataRefused },
		DataRefused => { CONTROL_STILL_FLOWS => ControlOk },
		ControlOk => { DRAIN_COMPLETES_CLEAN => Done },
		Done => { }
	}
	terminal { Done }
}

// Zero budget: data emits fail fast; ping/shutdown still work.
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
			trace.event_with(ZERO_BUDGET_EMIT_REFUSED, &[], is_budget_exhausted(&refused))?;

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
		gate: Ok,
		assertions: [
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(events::MUX_EMIT_DRAINING, exactly!(1)),
			(events::MUX_GOAWAY_RECV, exactly!(1)),
			(EXHAUSTING_EMIT_STILL_ECHOES, exactly!(1), equals!(true)),
			(PEER_OBSERVES_BUDGET_EXHAUSTED, exactly!(1), equals!(true))
		]
	}
}

// Caps 1/1, 1 KiB chunk: reserve = 5 credits; grant 6 exhausts on first emit.
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
			trace.event_with(
				EXHAUSTING_EMIT_STILL_ECHOES,
				&[],
				is_echo(echoed, &frame),
			)?;

			// Stimulus only: the refusal itself emits `events::MUX_EMIT_DRAINING`.
			let _late = pair.client.handle.emit_on_stream(&mux_frame("mux-budget-late")).await;

			trace.event_with(
				PEER_OBSERVES_BUDGET_EXHAUSTED,
				&[],
				await_goaway_reason(&pair.server.handle, GoAwayReason::BudgetExhausted).await,
			)?;

			Ok(())
		}
	}
}

async fn protocol_error_goaway_after(
	link: ServerMuxClientRaw,
	envelopes: Vec<TransportEnvelope>,
) -> Result<bool, TightBeamError> {
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

// Five partial opens exceeds cap 4 ([RFC 9113 § 5.1.2](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2)).
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
		gate: Ok,
		assertions: [
			(events::MUX_PROTOCOL_ERROR, exactly!(4)),
			(OVERSIZE_CHUNK_ANSWERED_WITH_GOAWAY, exactly!(1), equals!(true)),
			(CREDIT_OVERRUN_ANSWERED_WITH_GOAWAY, exactly!(1), equals!(true)),
			(REASSEMBLY_FLOOD_ANSWERED_WITH_GOAWAY, exactly!(1), equals!(true)),
			(BUDGET_OVERRUN_ANSWERED_WITH_GOAWAY, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_flow_control_violations_rejected,
	spec: MuxFlowViolationSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let oversize = oversize_chunk_rejected(trace.share()).await?;
			trace.event_with(OVERSIZE_CHUNK_ANSWERED_WITH_GOAWAY, &[], oversize)?;

			let credit = credit_overrun_rejected(trace.share()).await?;
			trace.event_with(CREDIT_OVERRUN_ANSWERED_WITH_GOAWAY, &[], credit)?;

			let flood = reassembly_flood_rejected(trace.share()).await?;
			trace.event_with(REASSEMBLY_FLOOD_ANSWERED_WITH_GOAWAY, &[], flood)?;

			let budget = budget_overrun_rejected(trace.share()).await?;
			trace.event_with(BUDGET_OVERRUN_ANSWERED_WITH_GOAWAY, &[], budget)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxAuthorizerSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(CLIENT_VIEWS_REDUCED_GRANT, exactly!(1), equals!(true)),
			(SERVER_VIEWS_REDUCED_GRANT, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_authorizer_reduced_grant_both_sides,
	spec: MuxAuthorizerSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let request = MuxBudgets { client_to_server: 10, server_to_client: 10 };
			let hooks =
				MutualSessionHooks { authorizer: Some(Arc::new(HalvingAuthorizer)), ..MutualSessionHooks::default() };
			let session =
				establish_mutual_transports(mux_offer(4).with_budgets(request), mux_offer(4), hooks).await?;

			let client_settings = session
				.client
				.negotiated_mux()
				.ok_or_else(|| expectation_failure("client must negotiate multiplexing"))?;
			let server_settings = session
				.server
				.negotiated_mux()
				.ok_or_else(|| expectation_failure("server must negotiate multiplexing"))?;

			trace.event_with(
				CLIENT_VIEWS_REDUCED_GRANT,
				&[],
				client_settings.send_budget == Some(5) && client_settings.recv_budget == Some(5),
			)?;
			trace.event_with(
				SERVER_VIEWS_REDUCED_GRANT,
				&[],
				server_settings.send_budget == Some(5) && server_settings.recv_budget == Some(5),
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxAuthorizerRefusalSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(SERVER_REFUSES_WITH_CODE, exactly!(1), equals!(true)),
			(CLIENT_FAILS_CLOSED, exactly!(1), equals!(true))
		]
	}
}

// Refusal before accept enters transcript: fail closed both sides.
tb_scenario! {
	name: mux_authorizer_refusal_fails_closed,
	spec: MuxAuthorizerRefusalSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let (listener, addr) = bind_encrypted_listener(&materials).await?;

			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(mux_offer(4)))
					.with_transport_authorizer(Arc::new(RefusingAuthorizer));

				serve_one_handshake_message(&mut transport).await?;
				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(())
			});

			let request = MuxBudgets { client_to_server: 10, server_to_client: 10 };
			let mut client = connect_pinned_client(addr, &materials.certificate).await?;
			client = client.with_mux_offer(Some(mux_offer(4).with_budgets(request)));

			let client_result = client.perform_client_handshake().await;
			let server_result = join_task(server_task, "server handshake task must not panic").await?;
			trace.event_with(
				SERVER_REFUSES_WITH_CODE,
				&[],
				matches!(
					server_result,
					Err(TightBeamError::TransportError(TransportError::HandshakeError(
						HandshakeError::NegotiationError(NegotiationError::AuthorizationRefused {
							code: REFUSAL_CODE,
						})
					)))
				),
			)?;
			trace.event_with(CLIENT_FAILS_CLOSED, &[], client_result.is_err())?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxAuthorizerDeadlineSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(SERVER_BOUNDS_HUNG_AUTHORIZER, exactly!(1), equals!(true)),
			(CLIENT_FAILS_CLOSED, exactly!(1), equals!(true))
		]
	}
}

// Hung authorizer: handshake deadline -> DeadlineExceeded.
tb_scenario! {
	name: mux_hung_authorizer_bounded_by_handshake_deadline,
	spec: MuxAuthorizerDeadlineSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let (listener, addr) =
				bind_encrypted_listener_with_timeout(&materials, Duration::from_millis(200)).await?;

			let server_task = tokio::spawn(async move {
				let (transport, _) = listener.accept().await?;
				let mut transport = transport
					.with_mux_offer(Some(mux_offer(4)))
					.with_transport_authorizer(Arc::new(HangingAuthorizer));

				serve_one_handshake_message(&mut transport).await?;
				serve_one_handshake_message(&mut transport).await?;
				Ok::<_, TightBeamError>(())
			});

			let request = MuxBudgets { client_to_server: 10, server_to_client: 10 };
			let mut client = connect_pinned_client(addr, &materials.certificate).await?;
			client = client.with_mux_offer(Some(mux_offer(4).with_budgets(request)));
			let client_task = tokio::spawn(async move { client.perform_client_handshake().await });

			let server_join = join_task(server_task, "server handshake task must not panic");
			let server_result = timeout(Duration::from_secs(5), server_join)
				.await
				.map_err(|_| expectation_failure("hung authorizer must not stall the server past the deadline"))??;
			trace.event_with(
				SERVER_BOUNDS_HUNG_AUTHORIZER,
				&[],
				matches!(
					server_result,
					Err(TightBeamError::TransportError(TransportError::OperationFailed(
						TransportFailure::DeadlineExceeded
					)))
				),
			)?;

			let client_join = join_task(client_task, "client handshake task must not panic");
			let client_result = timeout(Duration::from_secs(5), client_join)
				.await
				.map_err(|_| expectation_failure("client must fail closed once the server abandons the handshake"))??;
			trace.event_with(CLIENT_FAILS_CLOSED, &[], client_result.is_err())?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxRekeyChunkedDrainSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(events::MUX_GOAWAY_RECV, exactly!(1)),
			(events::MUX_EMIT_DRAINING, exactly!(1)),
			(CHUNKED_TRANSFER_SURVIVES_DRAIN, exactly!(1), equals!(true)),
			(DRAIN_REASON_SURFACES, exactly!(1), equals!(true))
		]
	}
}

// limit=18: 15 response records + reserve 5 (caps 1/1, chunk 1024); headroom for GoAway.
tb_scenario! {
	name: mux_rekey_drain_with_inflight_chunked_transfer,
	spec: MuxRekeyChunkedDrainSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let config = MuxEndpointConfig { rekey_limit: Some(18), ..MuxEndpointConfig::default() };
			let pair = establish_echo_pair(chunked_offer(1), chunked_offer(1), config, trace.share()).await?;

			let frame = large_mux_frame("mux-rekey-chunked");
			let echoed = pair.client.handle.emit_on_stream(&frame).await?;
			trace.event_with(
				CHUNKED_TRANSFER_SURVIVES_DRAIN,
				&[],
				is_echo(echoed, &frame),
			)?;

			trace.event_with(
				DRAIN_REASON_SURFACES,
				&[],
				await_goaway_reason(&pair.client.handle, GoAwayReason::Shutdown).await,
			)?;

			// Stimulus only: the refusal itself emits `events::MUX_EMIT_DRAINING`.
			let _late = pair.client.handle.emit_on_stream(&mux_frame("mux-rekey-late")).await;

			Ok(())
		}
	}
}
