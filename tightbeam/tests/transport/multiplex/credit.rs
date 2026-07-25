//! Chunking, stream credit, session budgets, flow violations, authorizers.

use core::time::Duration;
use std::sync::Arc;

use tightbeam::der::Decode;
use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_process_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ScenarioConf, SetupEnv};
use tightbeam::transport::envelopes::{GoAwayReason, MuxCreditPackage, MuxDataPackage, MuxEnvelope, MuxOpenPackage};
use tightbeam::transport::handshake::negotiation::{MuxBudgets, NegotiationError};
use tightbeam::transport::handshake::HandshakeError;
use tightbeam::transport::{
	EncryptedMessageIO, EnvelopeSink, EnvelopeSource, TransportEnvelope, TransportError,
};
use tightbeam::{Frame, TightBeamError};
use tokio::time::timeout;

use crate::common::security::{expectation_failure, ServerMaterials};
use crate::transport::support::{
	await_ok, bind_encrypted_listener, connect_pinned_client, establish_mutual_transports, join_task,
	serve_one_handshake_message, MutualSessionHooks,
};

use super::common::*;

tb_assert_spec! {
	pub MuxChunkedRoundtripSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(first_large_frame_echoed, exactly!(1), equals!(true)),
			(second_large_frame_echoed, exactly!(1), equals!(true))
		]
	}
}

// Frames beyond the negotiated chunk size segment into Open/Data
// series, reassemble on the peer, and echo back chunked.
tb_scenario! {
	name: mux_chunked_large_frames_roundtrip_and_interleave,
	spec: MuxChunkedRoundtripSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let pair = establish_echo_pair(chunked_offer(4), chunked_offer(4), MuxEndpointConfig::default()).await?;
			let first = large_mux_frame("mux-chunked-first");
			let second = large_mux_frame("mux-chunked-second");
			let (first_echo, second_echo) = tokio::join!(
				pair.client.handle.emit_on_stream(&first),
				pair.client.handle.emit_on_stream(&second),
			);

			trace.event_with(
				MuxChunkedRoundtripSpec::first_large_frame_echoed,
				&[],
				is_echo(first_echo?, &first),
			)?;
			trace.event_with(
				MuxChunkedRoundtripSpec::second_large_frame_echoed,
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
			(open_chunk_spends_initial_credit, exactly!(1), equals!(true)),
			(sender_stalls_at_initial_credit, exactly!(1), equals!(true)),
			(transfer_resumes_on_grant, exactly!(1), equals!(true)),
			(stalled_stream_still_echoes, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxCreditStallProcess,
	events {
		observable {
			MuxCreditStallSpec::open_chunk_spends_initial_credit,
			MuxCreditStallSpec::sender_stalls_at_initial_credit,
			MuxCreditStallSpec::transfer_resumes_on_grant,
			MuxCreditStallSpec::stalled_stream_still_echoes
		}
		hidden { }
	}
	states {
		Idle => { MuxCreditStallSpec::open_chunk_spends_initial_credit => Opened },
		Opened => { MuxCreditStallSpec::sender_stalls_at_initial_credit => Stalled },
		Stalled => { MuxCreditStallSpec::transfer_resumes_on_grant => Resumed },
		Resumed => { MuxCreditStallSpec::stalled_stream_still_echoes => Done },
		Done => { }
	}
	terminal { Done }
}

// With one chunk of initial credit, the sender parks after the Open
// chunk until the receiver grants more, then the transfer resumes
// and completes.
tb_scenario! {
	name: mux_stream_credit_stall_and_resume,
	config: ScenarioConf::builder()
		.with_spec(MuxCreditStallSpec::latest())
		.with_csp(MuxCreditStallProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let server_offer = chunked_offer(4).with_initial_stream_credit(1);
			let mut link = establish_client_mux_server_raw_with(chunked_offer(4), server_offer).await?;

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

			trace.event_with(MuxCreditStallSpec::open_chunk_spends_initial_credit, &[], open_ok)?;

			let stalled = timeout(Duration::from_millis(200), link.server_reader.read_envelope())
				.await
				.is_err();
			trace.event_with(MuxCreditStallSpec::sender_stalls_at_initial_credit, &[], stalled)?;

			let grant = MuxCreditPackage::new(client_stream_id(0), 64);
			link.server_writer.write_envelope(grant.into()).await?;

			let payload = read_remaining_chunks(&mut link.server_reader, client_stream_id(0), payload).await?;
			let received = Frame::from_der(&payload)?;

			let ack = mux_frame("mux-stall-ack");
			write_muxed_echo(&mut link.server_writer, client_stream_id(0), &Arc::new(ack.to_owned())).await?;

			let resolved = await_ok(emit_task, "stalled emit task must not panic").await?;
			trace.event_with(MuxCreditStallSpec::transfer_resumes_on_grant, &[], received == frame)?;
			trace.event_with(MuxCreditStallSpec::stalled_stream_still_echoes, &[], is_echo(resolved, &ack))?;

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
			(zero_budget_emit_refused, exactly!(1), equals!(true)),
			(control_still_flows, exactly!(1), equals!(true)),
			(drain_completes_clean, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxZeroBudgetProcess,
	events {
		observable {
			MuxZeroBudgetSpec::zero_budget_emit_refused,
			MuxZeroBudgetSpec::control_still_flows,
			MuxZeroBudgetSpec::drain_completes_clean
		}
		hidden { }
	}
	states {
		Idle => { MuxZeroBudgetSpec::zero_budget_emit_refused => DataRefused },
		DataRefused => { MuxZeroBudgetSpec::control_still_flows => ControlOk },
		ControlOk => { MuxZeroBudgetSpec::drain_completes_clean => Done },
		Done => { }
	}
	terminal { Done }
}

// A zero-credit grant meters the session shut: data emits fail fast
// with the typed budget error while control (ping, shutdown drain)
// keeps working.
tb_scenario! {
	name: mux_zero_budget_refuses_data_drains_clean,
	config: ScenarioConf::builder()
		.with_spec(MuxZeroBudgetSpec::latest())
		.with_csp(MuxZeroBudgetProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let budgets = MuxBudgets { client_to_server: 0, server_to_client: 0 };
			let client_offer = mux_offer(4).with_budgets(budgets);
			let server_offer = mux_offer(4);
			let hooks = MutualSessionHooks::default();
			let session = establish_mutual_transports(client_offer, server_offer, hooks).await?;
			let config = MuxEndpointConfig::default();
			let pair = spawn_echo_pair(session.client, session.server, config)?;

			let refused = pair.client.handle.emit_on_stream(&mux_frame("mux-zero-budget")).await;
			trace.event_with(MuxZeroBudgetSpec::zero_budget_emit_refused, &[], is_budget_exhausted(&refused))?;

			trace.event_with(
				MuxZeroBudgetSpec::control_still_flows,
				&[],
				pair.client.handle.ping().await.is_ok(),
			)?;

			let drained = pair.client.handle.shutdown().await;
			trace.event_with(MuxZeroBudgetSpec::drain_completes_clean, &[], drained.is_ok())?;

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
			(exhausting_emit_still_echoes, exactly!(1), equals!(true)),
			(late_emit_draining, exactly!(1), equals!(true)),
			(peer_observes_budget_exhausted, exactly!(1), equals!(true))
		]
	}
}

// The emit that drops the balance to the drain reserve triggers
// GoAway(BudgetExhausted): the in-flight stream still resolves, later
// emits are refused as Draining, and the peer surfaces the reason.
// Caps 1/1 with 1 KiB chunk and unit make the reserve exactly 5
// credits, so a 6-credit grant exhausts on the first emit.
tb_scenario! {
	name: mux_budget_exhaustion_drains,
	spec: MuxBudgetExhaustionSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let budgets = MuxBudgets { client_to_server: 6, server_to_client: 4096 };
			let client_offer = chunked_offer(1).with_budgets(budgets);
			let server_offer = chunked_offer(1);
			let hooks = MutualSessionHooks::default();
			let session = establish_mutual_transports(client_offer, server_offer, hooks).await?;
			let config = MuxEndpointConfig::default();
			let pair = spawn_echo_pair(session.client, session.server, config)?;

			let frame = mux_frame("mux-budget-last");
			let echoed = pair.client.handle.emit_on_stream(&frame).await?;
			trace.event_with(
				MuxBudgetExhaustionSpec::exhausting_emit_still_echoes,
				&[],
				is_echo(echoed, &frame),
			)?;

			let late = pair.client.handle.emit_on_stream(&mux_frame("mux-budget-late")).await;
			trace.event_with(MuxBudgetExhaustionSpec::late_emit_draining, &[], is_draining(&late))?;

			trace.event_with(
				MuxBudgetExhaustionSpec::peer_observes_budget_exhausted,
				&[],
				await_goaway_reason(&pair.server.handle, GoAwayReason::BudgetExhausted).await,
			)?;

			Ok(())
		}
	}
}

/// Write `envelopes` on a raw client against an immediate-echo server;
/// true when the peer answers with GoAway(ProtocolError).
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

// 2 KiB open exceeds the 1 KiB advertised chunk ceiling.
async fn oversize_chunk_rejected() -> Result<bool, TightBeamError> {
	let client_offer = chunked_offer(4);
	let server_offer = chunked_offer(4);
	let config = MuxEndpointConfig::default();
	let link = establish_server_mux_client_raw_with(client_offer, server_offer, config).await?;

	let oversize = MuxOpenPackage::new(1, true, vec![0u8; 2048])?;
	let envelopes = vec![oversize.into()];

	protocol_error_goaway_after(link, envelopes).await
}

// Second chunk after the one-chunk initial window, with a grantor that
// never replenishes.
async fn credit_overrun_rejected() -> Result<bool, TightBeamError> {
	let client_offer = chunked_offer(4);
	let server_offer = chunked_offer(4).with_initial_stream_credit(1);
	let config = MuxEndpointConfig { rekey_limit: None, cancel_budget: None, grantor: Some(Arc::new(NeverGrant)) };
	let link = establish_server_mux_client_raw_with(client_offer, server_offer, config).await?;

	let chunk = vec![0u8; 1024];
	let open = MuxOpenPackage::new(1, false, chunk.to_owned())?;
	let overrun = MuxDataPackage::new(1, false, chunk)?;
	let envelopes = vec![open.into(), overrun.into()];

	protocol_error_goaway_after(link, envelopes).await
}

// Cap is 4 peer-initiated streams; five concurrent partial opens is
// one over ([RFC 9113 § 5.1.2](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2)).
async fn reassembly_flood_rejected() -> Result<bool, TightBeamError> {
	let client_offer = chunked_offer(4);
	let server_offer = chunked_offer(4);
	let config = MuxEndpointConfig::default();
	let link = establish_server_mux_client_raw_with(client_offer, server_offer, config).await?;

	let partial = vec![0u8; 16];
	let envelopes = vec![
		MuxOpenPackage::new(client_stream_id(0), false, partial.to_owned())?.into(),
		MuxOpenPackage::new(client_stream_id(1), false, partial.to_owned())?.into(),
		MuxOpenPackage::new(client_stream_id(2), false, partial.to_owned())?.into(),
		MuxOpenPackage::new(client_stream_id(3), false, partial.to_owned())?.into(),
		MuxOpenPackage::new(client_stream_id(4), false, partial)?.into(),
	];

	protocol_error_goaway_after(link, envelopes).await
}

// One-credit inbound budget: first request spends it, second overruns.
async fn budget_overrun_rejected() -> Result<bool, TightBeamError> {
	let budgets = MuxBudgets { client_to_server: 1, server_to_client: 4096 };
	let client_offer = chunked_offer(4).with_budgets(budgets);
	let server_offer = chunked_offer(4);
	let hooks = MutualSessionHooks::default();
	let session = establish_mutual_transports(client_offer, server_offer, hooks).await?;
	let config = MuxEndpointConfig::default();
	let link = split_server_mux_client_raw(session.client, session.server, config)?;

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
			(oversize_chunk_answered_with_goaway, exactly!(1), equals!(true)),
			(credit_overrun_answered_with_goaway, exactly!(1), equals!(true)),
			(reassembly_flood_answered_with_goaway, exactly!(1), equals!(true)),
			(budget_overrun_answered_with_goaway, exactly!(1), equals!(true))
		]
	}
}

// Flow-control violations (chunk ceiling, stream credit, reassembly
// flood, session budget) are protocol violations answered with
// GoAway(ProtocolError), each on a fresh connection.
tb_scenario! {
	name: mux_flow_control_violations_rejected,
	spec: MuxFlowViolationSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let oversize = oversize_chunk_rejected().await?;
			trace.event_with(MuxFlowViolationSpec::oversize_chunk_answered_with_goaway, &[], oversize)?;

			let credit = credit_overrun_rejected().await?;
			trace.event_with(MuxFlowViolationSpec::credit_overrun_answered_with_goaway, &[], credit)?;

			let flood = reassembly_flood_rejected().await?;
			trace.event_with(MuxFlowViolationSpec::reassembly_flood_answered_with_goaway, &[], flood)?;

			let budget = budget_overrun_rejected().await?;
			trace.event_with(MuxFlowViolationSpec::budget_overrun_answered_with_goaway, &[], budget)?;

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
			(client_views_reduced_grant, exactly!(1), equals!(true)),
			(server_views_reduced_grant, exactly!(1), equals!(true))
		]
	}
}

// A server-side TransportAuthorizer replaces the local-config grant:
// the halved budgets land in the signed accept and both endpoints
// derive the same reduced directional views.
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
				MuxAuthorizerSpec::client_views_reduced_grant,
				&[],
				client_settings.send_budget == Some(5) && client_settings.recv_budget == Some(5),
			)?;
			trace.event_with(
				MuxAuthorizerSpec::server_views_reduced_grant,
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
			(server_refuses_with_code, exactly!(1), equals!(true)),
			(client_fails_closed, exactly!(1), equals!(true))
		]
	}
}

// A refusing TransportAuthorizer aborts the handshake before the
// accept enters the transcript: the server surfaces the application
// refusal code and the client never completes a session.
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
				MuxAuthorizerRefusalSpec::server_refuses_with_code,
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
			trace.event_with(MuxAuthorizerRefusalSpec::client_fails_closed, &[], client_result.is_err())?;

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
			(chunked_transfer_survives_drain, exactly!(1), equals!(true)),
			(drain_reason_surfaces, exactly!(1), equals!(true)),
			(late_emit_draining, exactly!(1), equals!(true))
		]
	}
}

// The rekey record limit trips while the server writes its chunked echo:
// the dynamic headroom lets the owed response flush inside the drain.
//
// Record math at 15 chunks per direction (payload ~15.3 KiB, chunk
// 1024): the batched default grantor stays silent for 15 inbound
// chunks under its 64-chunk window, so the server's only records
// are the 15 response records. The static reserve is 5 (caps 1/1).
// limit ≤ 15 + 5 guarantees the trip even after every unsent chunk
// drains, and limit ≥ 15 + 1 leaves records for the full response
// plus the GoAway when the trip fires on the first response record.
tb_scenario! {
	name: mux_rekey_drain_with_inflight_chunked_transfer,
	spec: MuxRekeyChunkedDrainSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let config = MuxEndpointConfig { rekey_limit: Some(18), cancel_budget: None, grantor: None };
			let pair = establish_echo_pair(chunked_offer(1), chunked_offer(1), config).await?;

			let frame = large_mux_frame("mux-rekey-chunked");
			let echoed = pair.client.handle.emit_on_stream(&frame).await?;
			trace.event_with(
				MuxRekeyChunkedDrainSpec::chunked_transfer_survives_drain,
				&[],
				is_echo(echoed, &frame),
			)?;

			trace.event_with(
				MuxRekeyChunkedDrainSpec::drain_reason_surfaces,
				&[],
				await_goaway_reason(&pair.client.handle, GoAwayReason::Shutdown).await,
			)?;

			let late = pair.client.handle.emit_on_stream(&mux_frame("mux-rekey-late")).await;
			trace.event_with(MuxRekeyChunkedDrainSpec::late_emit_draining, &[], is_draining(&late))?;

			Ok(())
		}
	}
}

