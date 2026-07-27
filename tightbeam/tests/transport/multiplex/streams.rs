//! Concurrent streams, caps, cancel, and server-initiated streams.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::sync::Notify;

use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::tb_assert_spec;
use tightbeam::tb_process_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ClientEnv, ScenarioConf, SetupEnv};
use tightbeam::transport::envelopes::MuxEnvelope;
use tightbeam::transport::{EnvelopeSource, MessageCollector, ResponseHandler, TransportEnvelope};
use tightbeam::utils::urn::Urn;
use tightbeam::Frame;

use crate::common::security::ServerMaterials;
use crate::transport::support::{
	await_ok, bind_encrypted_listener, join_task, mux_frame, mux_offer, record_spawned_event,
};

use super::common::*;

pub(crate) const BUSY_GARBAGE_RESOLVES_AS_BUSY: Urn<'static> =
	Urn::new("test", "event:streams/busy-garbage-resolves-as-busy");
pub(crate) const CANCEL_OBSERVED_ON_WIRE: Urn<'static> = Urn::new("test", "event:streams/cancel-observed-on-wire");
pub(crate) const FIRST_STREAM_ECHOED: Urn<'static> = Urn::new("test", "event:streams/first-stream-echoed");
pub(crate) const FOLLOWUP_ECHOES_AFTER_GARBAGE: Urn<'static> =
	Urn::new("test", "event:streams/followup-echoes-after-garbage");
pub(crate) const FOLLOWUP_ECHOES_AFTER_RACE: Urn<'static> =
	Urn::new("test", "event:streams/followup-echoes-after-race");
pub(crate) const FOLLOWUP_ECHOES_ON_FREED_SLOT: Urn<'static> =
	Urn::new("test", "event:streams/followup-echoes-on-freed-slot");
pub(crate) const HANDLER_ABORTED_ON_CANCEL: Urn<'static> = Urn::new("test", "event:streams/handler-aborted-on-cancel");
pub(crate) const HANDSHAKE_NEGOTIATED_NO_MUX: Urn<'static> =
	Urn::new("test", "event:streams/handshake-negotiated-no-mux");
pub(crate) const HELD_EMIT_ECHOES_AFTER_RELEASE: Urn<'static> =
	Urn::new("test", "event:streams/held-emit-echoes-after-release");
pub(crate) const MUXED_ENVELOPE_INVALID_MESSAGE: Urn<'static> =
	Urn::new("test", "event:streams/muxed-envelope-invalid-message");
pub(crate) const NEGOTIATED_CAP_IS_ONE: Urn<'static> = Urn::new("test", "event:streams/negotiated-cap-is-one");
pub(crate) const SECOND_EMIT_STREAMS_EXHAUSTED: Urn<'static> =
	Urn::new("test", "event:streams/second-emit-streams-exhausted");
pub(crate) const SECOND_STREAM_ECHOED: Urn<'static> = Urn::new("test", "event:streams/second-stream-echoed");
pub(crate) const SERVER_STREAM_ECHOED_BY_CLIENT: Urn<'static> =
	Urn::new("test", "event:streams/server-stream-echoed-by-client");

tb_assert_spec! {
	pub MuxInterleavedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(FIRST_STREAM_ECHOED, exactly!(1), equals!(true)),
			(SECOND_STREAM_ECHOED, exactly!(1), equals!(true))
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
			start_mux_server(&env.context.materials, 4, handler, env.trace).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let client = connect_mux_client(addr, &ctx.materials, 4, trace.share()).await?;
			let (first, second) = tokio::join!(
				client.handle().emit_on_stream(&ctx.frame_first),
				client.handle().emit_on_stream(&ctx.frame_second),
			);

			trace.event_with(FIRST_STREAM_ECHOED, &[], is_echo(first?, &ctx.frame_first))?;
			trace.event_with(SECOND_STREAM_ECHOED, &[], is_echo(second?, &ctx.frame_second))?;
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
			(events::MUX_STREAMS_EXHAUSTED, exactly!(1)),
			(NEGOTIATED_CAP_IS_ONE, exactly!(1), equals!(true)),
			(SECOND_EMIT_STREAMS_EXHAUSTED, exactly!(1), equals!(true)),
			(HELD_EMIT_ECHOES_AFTER_RELEASE, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxCapExhaustionProcess,
	events {
		observable {
			NEGOTIATED_CAP_IS_ONE,
			events::MUX_STREAMS_EXHAUSTED,
			SECOND_EMIT_STREAMS_EXHAUSTED,
			HELD_EMIT_ECHOES_AFTER_RELEASE
		}
		hidden { }
	}
	states {
		Idle => { NEGOTIATED_CAP_IS_ONE => CapKnown },
		CapKnown => { events::MUX_STREAMS_EXHAUSTED => SlotDenied },
		SlotDenied => { SECOND_EMIT_STREAMS_EXHAUSTED => Exhausted },
		Exhausted => { HELD_EMIT_ECHOES_AFTER_RELEASE => Done },
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
			start_mux_server(&env.context.materials, 1, gated_echo(Arc::clone(&env.context)), env.trace).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let client = connect_mux_client(addr, &ctx.materials, 4, trace.share()).await?;
			trace.event_with(
				NEGOTIATED_CAP_IS_ONE,
				&[],
				client.settings.local_initiated_cap == 1,
			)?;

			let frame_held = mux_frame("mux-held");
			let held_task = spawn_emit(client.handle(), frame_held.to_owned());

			ctx.started.notified().await;

			let exhausted = client.handle().emit_on_stream(&mux_frame("mux-extra")).await;
			trace.event_with(
				SECOND_EMIT_STREAMS_EXHAUSTED,
				&[],
				is_streams_exhausted(&exhausted),
			)?;

			ctx.release.notify_one();

			let echoed = await_ok(held_task, "held emit task must not panic").await?;
			trace.event_with(
				HELD_EMIT_ECHOES_AFTER_RELEASE,
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
			(HANDSHAKE_NEGOTIATED_NO_MUX, exactly!(1), equals!(true)),
			(MUXED_ENVELOPE_INVALID_MESSAGE, exactly!(1), equals!(true))
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
				HANDSHAKE_NEGOTIATED_NO_MUX,
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
				MUXED_ENVELOPE_INVALID_MESSAGE,
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
			(FOLLOWUP_ECHOES_ON_FREED_SLOT, exactly!(1), equals!(true)),
			(HANDLER_ABORTED_ON_CANCEL, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxCancelAbortProcess,
	events {
		observable {
			FOLLOWUP_ECHOES_ON_FREED_SLOT,
			HANDLER_ABORTED_ON_CANCEL
		}
		hidden { }
	}
	states {
		Idle => { FOLLOWUP_ECHOES_ON_FREED_SLOT => FollowupOk },
		FollowupOk => { HANDLER_ABORTED_ON_CANCEL => Done },
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
			start_mux_server(&env.context.materials, 1, first_parks_then_echo(Arc::clone(&env.context)), env.trace).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let client = connect_mux_client(addr, &ctx.materials, 1, trace.share()).await?;
			let cancelled_task = spawn_emit(client.handle(), mux_frame("mux-cancelled"));

			ctx.started.notified().await;

			abort_emit(cancelled_task).await;

			let frame_followup = mux_frame("mux-followup");
			let echoed = client.handle().emit_on_stream(&frame_followup).await?;

			trace.event_with(
				FOLLOWUP_ECHOES_ON_FREED_SLOT,
				&[],
				is_echo(echoed, &frame_followup),
			)?;
			trace.event_with(
				HANDLER_ABORTED_ON_CANCEL,
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
			(CANCEL_OBSERVED_ON_WIRE, exactly!(1), equals!(true)),
			(FOLLOWUP_ECHOES_AFTER_RACE, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxCancelRaceProcess,
	events {
		observable {
			CANCEL_OBSERVED_ON_WIRE,
			FOLLOWUP_ECHOES_AFTER_RACE
		}
		hidden { }
	}
	states {
		Idle => { CANCEL_OBSERVED_ON_WIRE => CancelSeen },
		CancelSeen => { FOLLOWUP_ECHOES_AFTER_RACE => Done },
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
			let mut link = establish_client_mux_server_raw(4, trace.share()).await?;
			let frame_cancelled = mux_frame("mux-raced");

			let raced_task = spawn_emit(&link.client.handle, frame_cancelled.to_owned());
			let raced_stream_id = read_muxed_request_id(&mut link.server_reader).await?;

			abort_emit(raced_task).await;

			let cancel = link.server_reader.read_envelope().await?;
			let cancel_ok = matches!(
				&cancel,
				TransportEnvelope::Mux(MuxEnvelope::Cancel(package)) if package.stream_id() == raced_stream_id
			);

			trace.event_with(CANCEL_OBSERVED_ON_WIRE, &[], cancel_ok)?;

			write_muxed_echo(&mut link.server_writer, raced_stream_id, &Arc::new(frame_cancelled)).await?;

			let followup_echoed = raw_echo_roundtrip(&mut link, &mux_frame("mux-alive")).await?;
			trace.event_with(FOLLOWUP_ECHOES_AFTER_RACE, &[], followup_echoed)?;

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
			(BUSY_GARBAGE_RESOLVES_AS_BUSY, exactly!(1), equals!(true)),
			(FOLLOWUP_ECHOES_AFTER_GARBAGE, exactly!(1), equals!(true))
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
			let mut link = establish_client_mux_server_raw(4, trace.share()).await?;
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
			trace.event_with(BUSY_GARBAGE_RESOLVES_AS_BUSY, &[], is_busy(&busy))?;

			// Connection must remain healthy: a follow-up stream still echoes.
			let followup_echoed = raw_echo_roundtrip(&mut link, &mux_frame("mux-after-garbage")).await?;
			trace.event_with(FOLLOWUP_ECHOES_AFTER_GARBAGE, &[], followup_echoed)?;

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
			(SERVER_STREAM_ECHOED_BY_CLIENT, exactly!(1), equals!(true))
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
				let Ok((server, _responder)) = accept_mux_server(listener, mux_offer(4), trace.share()).await else {
					return;
				};

				let frame = mux_frame("mux-server-init");
				let echoed = server
					.handle
					.emit_on_stream(&frame)
					.await
					.is_ok_and(|reply| is_echo(reply, &frame));

				record_spawned_event(&trace, SERVER_STREAM_ECHOED_BY_CLIENT, echoed);

				ctx.done.notify_one();
			});
			Ok((task, addr))
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let client = connect_mux_client(addr, &ctx.materials, 4, trace.share()).await?;
			let _client_serve = spawn_immediate_echo(client.responder);

			// Hold the client endpoint alive until the server-side emit
			// resolved and recorded its event.
			ctx.done.notified().await;
			Ok(())
		}
	}
}
