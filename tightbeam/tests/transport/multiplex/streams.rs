//! Concurrent streams, caps, cancel, and server-initiated streams.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tightbeam::exactly;
use tightbeam::policy::TransitStatus;
use tightbeam::tb_assert_spec;
use tightbeam::tb_process_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ClientEnv, ScenarioConf, SetupEnv};
use tightbeam::transport::envelopes::MuxEnvelope;
use tightbeam::transport::{EnvelopeSource, MessageCollector, ResponseHandler, TransportEnvelope};
use tightbeam::Frame;
use tokio::sync::Notify;

use crate::common::security::ServerMaterials;
use crate::transport::support::{await_ok, bind_encrypted_listener, join_task};

use super::common::*;

tb_assert_spec! {
	pub MuxInterleavedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(first_stream_echoed, exactly!(1), equals!(true)),
			(second_stream_echoed, exactly!(1), equals!(true))
		]
	}
}

/// Interleaved-scenario fixture. Both closures share the same frames so
/// the server can hold the first until the second lands.
struct InterleavedContext {
	materials: ServerMaterials,
	frame_first: Frame,
	frame_second: Frame,
}

impl InterleavedContext {
	fn generate() -> Self {
		Self {
			materials: ServerMaterials::generate(),
			frame_first: mux_frame("mux-first"),
			frame_second: mux_frame("mux-second"),
		}
	}
}

// Two concurrent streams: server answers reverse order. Correlate by ID.
tb_scenario! {
	name: mux_interleaved_out_of_order,
	spec: MuxInterleavedSpec,
	environment ServiceClient {
		context: InterleavedContext::generate(),
		server: |env| async move {
			let handler = order_forcing_echo(env.context.frame_first.to_owned(), Arc::new(Notify::new()));
			start_mux_server(&env.context.materials, 4, handler).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let client = connect_mux_client(addr, &ctx.materials, 4).await?;
			let (first, second) = tokio::join!(
				client.handle().emit_on_stream(&ctx.frame_first),
				client.handle().emit_on_stream(&ctx.frame_second),
			);

			trace.event_with(MuxInterleavedSpec::first_stream_echoed, &[], is_echo(first?, &ctx.frame_first))?;
			trace.event_with(MuxInterleavedSpec::second_stream_echoed, &[], is_echo(second?, &ctx.frame_second))?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxCapExhaustionSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(negotiated_cap_is_one, exactly!(1), equals!(true)),
			(second_emit_streams_exhausted, exactly!(1), equals!(true)),
			(held_emit_echoes_after_release, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxCapExhaustionProcess,
	events {
		observable {
			MuxCapExhaustionSpec::negotiated_cap_is_one,
			MuxCapExhaustionSpec::second_emit_streams_exhausted,
			MuxCapExhaustionSpec::held_emit_echoes_after_release
		}
		hidden { }
	}
	states {
		Idle => { MuxCapExhaustionSpec::negotiated_cap_is_one => CapKnown },
		CapKnown => { MuxCapExhaustionSpec::second_emit_streams_exhausted => Exhausted },
		Exhausted => { MuxCapExhaustionSpec::held_emit_echoes_after_release => Done },
		Done => { }
	}
	terminal { Done }
}

// Cap=1: second concurrent emit StreamsExhausted. Succeeds after the
// held slot frees.
tb_scenario! {
	name: mux_cap_exhaustion,
	config: ScenarioConf::builder()
		.with_spec(MuxCapExhaustionSpec::latest())
		.with_csp(MuxCapExhaustionProcess)
		.build(),
	environment ServiceClient {
		context: GatedMuxContext::generate(),
		server: |env| async move {
			start_mux_server(&env.context.materials, 1, gated_echo(Arc::clone(&env.context))).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let client = connect_mux_client(addr, &ctx.materials, 4).await?;
			trace.event_with(
				MuxCapExhaustionSpec::negotiated_cap_is_one,
				&[],
				client.settings.local_initiated_cap == 1,
			)?;

			let frame_held = mux_frame("mux-held");
			let held_task = spawn_emit(client.handle(), frame_held.to_owned());

			ctx.started.notified().await;

			let exhausted = client.handle().emit_on_stream(&mux_frame("mux-extra")).await;
			trace.event_with(
				MuxCapExhaustionSpec::second_emit_streams_exhausted,
				&[],
				is_streams_exhausted(&exhausted),
			)?;

			ctx.release.notify_one();

			let echoed = await_ok(held_task, "held emit task must not panic").await?;
			trace.event_with(
				MuxCapExhaustionSpec::held_emit_echoes_after_release,
				&[],
				is_echo(echoed, &frame_held),
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxNonNegotiatedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(handshake_negotiated_no_mux, exactly!(1), equals!(true)),
			(muxed_envelope_invalid_message, exactly!(1), equals!(true))
		]
	}
}

// Muxed envelope on a non-mux connection must be InvalidMessage.
tb_scenario! {
	name: mux_non_negotiated_rejected,
	spec: MuxNonNegotiatedSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (client, server) = establish_transports(None, None).await?;
			trace.event_with(
				MuxNonNegotiatedSpec::handshake_negotiated_no_mux,
				&[],
				client.negotiated_mux().is_none(),
			)?;

			let server_task = tokio::spawn(async move {
				let mut transport = server.with_handler(Some);
				transport.handle_request().await
			});

			let (_reader, mut writer) = client.into_split()?;
			write_muxed_request(&mut writer, 1, mux_frame("mux-rogue")).await?;

			let result = join_task(server_task, "single-flight server task must not panic").await?;
			trace.event_with(
				MuxNonNegotiatedSpec::muxed_envelope_invalid_message,
				&[],
				is_invalid_message(&result),
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxCancelAbortSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(followup_echoes_on_freed_slot, exactly!(1), equals!(true)),
			(handler_aborted_on_cancel, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxCancelAbortProcess,
	events {
		observable {
			MuxCancelAbortSpec::followup_echoes_on_freed_slot,
			MuxCancelAbortSpec::handler_aborted_on_cancel
		}
		hidden { }
	}
	states {
		Idle => { MuxCancelAbortSpec::followup_echoes_on_freed_slot => FollowupOk },
		FollowupOk => { MuxCancelAbortSpec::handler_aborted_on_cancel => Done },
		Done => { }
	}
	terminal { Done }
}

// Drop unresolved emit: frees cap slot and aborts the server handler.
tb_scenario! {
	name: mux_cancel_frees_slot_and_aborts_handler,
	config: ScenarioConf::builder()
		.with_spec(MuxCancelAbortSpec::latest())
		.with_csp(MuxCancelAbortProcess)
		.build(),
	environment ServiceClient {
		context: AbortContext::generate(),
		server: |env| async move {
			start_mux_server(&env.context.materials, 1, first_parks_then_echo(Arc::clone(&env.context))).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let client = connect_mux_client(addr, &ctx.materials, 1).await?;
			let cancelled_task = spawn_emit(client.handle(), mux_frame("mux-cancelled"));

			ctx.started.notified().await;

			abort_emit(cancelled_task).await;

			let frame_followup = mux_frame("mux-followup");
			let echoed = client.handle().emit_on_stream(&frame_followup).await?;

			trace.event_with(
				MuxCancelAbortSpec::followup_echoes_on_freed_slot,
				&[],
				is_echo(echoed, &frame_followup),
			)?;
			trace.event_with(
				MuxCancelAbortSpec::handler_aborted_on_cancel,
				&[],
				ctx.aborted.load(Ordering::SeqCst),
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxCancelRaceSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(cancel_observed_on_wire, exactly!(1), equals!(true)),
			(followup_echoes_after_race, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxCancelRaceProcess,
	events {
		observable {
			MuxCancelRaceSpec::cancel_observed_on_wire,
			MuxCancelRaceSpec::followup_echoes_after_race
		}
		hidden { }
	}
	states {
		Idle => { MuxCancelRaceSpec::cancel_observed_on_wire => CancelSeen },
		CancelSeen => { MuxCancelRaceSpec::followup_echoes_after_race => Done },
		Done => { }
	}
	terminal { Done }
}

// Stale response after cancel is discarded. Later streams stay healthy.
tb_scenario! {
	name: mux_cancel_response_race_discarded,
	config: ScenarioConf::builder()
		.with_spec(MuxCancelRaceSpec::latest())
		.with_csp(MuxCancelRaceProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let mut link = establish_client_mux_server_raw(4).await?;
			let frame_cancelled = mux_frame("mux-raced");

			let raced_task = spawn_emit(&link.client.handle, frame_cancelled.to_owned());
			let raced_stream_id = read_muxed_request_id(&mut link.server_reader).await?;

			abort_emit(raced_task).await;

			let cancel = link.server_reader.read_envelope().await?;
			let cancel_ok = matches!(
				&cancel,
				TransportEnvelope::Mux(MuxEnvelope::Cancel(package)) if package.stream_id() == raced_stream_id
			);

			trace.event_with(MuxCancelRaceSpec::cancel_observed_on_wire, &[], cancel_ok)?;

			write_muxed_echo(&mut link.server_writer, raced_stream_id, &Arc::new(frame_cancelled)).await?;

			let followup_echoed = raw_echo_roundtrip(&mut link, &mux_frame("mux-alive")).await?;
			trace.event_with(MuxCancelRaceSpec::followup_echoes_after_race, &[], followup_echoed)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxEndGarbageSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(busy_garbage_resolves_as_busy, exactly!(1), equals!(true)),
			(followup_echoes_after_garbage, exactly!(1), equals!(true))
		]
	}
}

// Garbage End payloads must stay per-stream: a stale end (cancelled
// stream) is discarded unread and a non-Ok trailer resolves its
// stream without decoding. Neither may tear down the connection.
tb_scenario! {
	name: mux_end_garbage_payload_tolerated,
	spec: MuxEndGarbageSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let mut link = establish_client_mux_server_raw(4).await?;
			let garbage = vec![0xDE, 0xAD];

			// Stale end: cancelled stream carrying garbage. Must be discarded.
			let stale_task = spawn_emit(&link.client.handle, mux_frame("mux-stale-garbage"));
			let stale_id = read_muxed_request_id(&mut link.server_reader).await?;

			abort_emit(stale_task).await;
			let _cancel = link.server_reader.read_envelope().await?;

			write_muxed_end(&mut link.server_writer, stale_id, TransitStatus::Ok, garbage.to_owned()).await?;

			// ResourceExhausted trailer carrying garbage. Must resolve per-stream as ResourceExhausted.
			let busy_task = spawn_emit(&link.client.handle, mux_frame("mux-busy-garbage"));
			let busy_id = read_muxed_request_id(&mut link.server_reader).await?;

			write_muxed_end(&mut link.server_writer, busy_id, TransitStatus::ResourceExhausted, garbage).await?;

			let busy = join_task(busy_task, "busy emit task must not panic").await?;
			trace.event_with(MuxEndGarbageSpec::busy_garbage_resolves_as_busy, &[], is_busy(&busy))?;

			// Connection must remain healthy: a follow-up stream still echoes.
			let followup_echoed = raw_echo_roundtrip(&mut link, &mux_frame("mux-after-garbage")).await?;
			trace.event_with(MuxEndGarbageSpec::followup_echoes_after_garbage, &[], followup_echoed)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxServerInitiatedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(server_stream_echoed_by_client, exactly!(1), equals!(true))
		]
	}
}

// Server initiates an even stream. Client `serve` echoes.
tb_scenario! {
	name: mux_server_initiated_roundtrip,
	spec: MuxServerInitiatedSpec,
	environment ServiceClient {
		context: ServerInitContext::generate(),
		server: |SetupEnv { trace, context: ctx }| async move {
			let (listener, addr) = bind_encrypted_listener(&ctx.materials).await?;
			let task = tokio::spawn(async move {
				let Ok((server, _responder)) = accept_mux_server(listener, mux_offer(4)).await else {
					return;
				};

				let frame = mux_frame("mux-server-init");
				let echoed = server
					.handle
					.emit_on_stream(&frame)
					.await
					.is_ok_and(|reply| is_echo(reply, &frame));

				trace
					.event_with(MuxServerInitiatedSpec::server_stream_echoed_by_client, &[], echoed)
					.expect("server_stream_echoed_by_client must record");

				ctx.done.notify_one();
			});
			Ok((task, addr))
		},
		client: |ClientEnv { context: ctx, addr, .. }| async move {
			let client = connect_mux_client(addr, &ctx.materials, 4).await?;
			let _client_serve = spawn_immediate_echo(client.responder);

			// Hold the client endpoint alive until the server-side emit
			// resolved and recorded its event.
			ctx.done.notified().await;
			Ok(())
		}
	}
}
