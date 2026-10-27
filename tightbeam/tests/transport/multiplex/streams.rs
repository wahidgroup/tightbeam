//! Mux scenarios for concurrent streams, caps, cancel, and server-initiated
//! streams.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::sync::Notify;

use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::tb_assert_spec;
use tightbeam::tb_process_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ClientEnv, ScenarioConfig};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::MuxEnvelope;
use tightbeam::transport::{EnvelopeSource, TransportEnvelope};
use tightbeam::urn::Urn;
use tightbeam::TightBeamError;

use crate::common::security::{expectation_failure, ServerMaterials};
use crate::transport::support::{await_ok, bind_encrypted_listener, join_task, mux_frame, mux_offer, respond_echo};

use super::common::*;

pub(crate) const FOLLOWUP_ECHOES_ON_FREED_SLOT: Urn<'static> =
	tightbeam::urn!("test", "event:streams/followup-echoes-on-freed-slot");
pub(crate) const HELD_EMIT_ECHOES_AFTER_RELEASE: Urn<'static> =
	tightbeam::urn!("test", "event:streams/held-emit-echoes-after-release");

/// Two concurrent streams: the server answers in reverse order, and the client
/// correlates each reply by its stream ID.
#[tokio::test]
async fn mux_interleaved_out_of_order() -> Result<(), TightBeamError> {
	let materials = ServerMaterials::generate();
	let frame_first = mux_frame("mux-first");
	let frame_second = mux_frame("mux-second");
	let handler = order_forcing_echo(frame_first.to_owned(), Arc::new(Notify::new()));
	let (_server, addr) = start_mux_server(&materials, 4, handler, TraceCollector::new()).await?;

	let client = connect_mux_client(addr, &materials, 4, TraceCollector::new()).await?;
	let (first, second) = tokio::join!(
		client.handle().emit_on_stream(&frame_first),
		client.handle().emit_on_stream(&frame_second),
	);

	assert!(is_echo(first?, &frame_first), "the held first stream must echo its own frame");
	assert!(is_echo(second?, &frame_second), "the second stream must echo its own frame");
	Ok(())
}

tb_assert_spec! {
	pub MuxCapExhaustionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_STREAMS_EXHAUSTED, exactly!(1)),
			(HELD_EMIT_ECHOES_AFTER_RELEASE, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxCapExhaustionProcess,
	events {
		observable {
			events::MUX_STREAMS_EXHAUSTED,
			HELD_EMIT_ECHOES_AFTER_RELEASE
		}
		hidden { }
	}
	states {
		Idle => { events::MUX_STREAMS_EXHAUSTED => SlotDenied },
		SlotDenied => { HELD_EMIT_ECHOES_AFTER_RELEASE => Done },
		Done => { }
	}
	terminal { Done }
}

// With a cap of 1, a second concurrent emit fails with `StreamsExhausted`, and
// it succeeds once the held slot frees.
tb_scenario! {
	name: mux_cap_exhaustion,
	config: ScenarioConfig::builder()
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
			assert_eq!(client.settings.local_initiated_cap, 1, "the client must take the server's cap of 1");

			let frame_held = mux_frame("mux-held");
			let held_task = spawn_emit(client.handle(), frame_held.to_owned());

			ctx.started.wait("the held emit must start the gated handler").await?;

			let exhausted = client.handle().emit_on_stream(&mux_frame("mux-extra")).await;
			assert!(is_streams_exhausted(&exhausted), "the second emit must fail at the cap of 1");

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

/// A muxed envelope on a connection that negotiated no multiplexing fails as
/// `InvalidMessage`.
#[tokio::test]
async fn mux_non_negotiated_rejected() -> Result<(), TightBeamError> {
	let (client, server) = establish_transports(None, None).await?;
	let unmuxed = client.negotiated_mux().is_none();
	assert!(unmuxed, "a handshake with no mux offer must negotiate no multiplexing");

	let server_task = tokio::spawn(respond_echo(server));

	let (_reader, mut writer) = client.into_split()?;
	write_muxed_request(&mut writer, 1, mux_frame("mux-rogue")).await?;

	let result = join_task(server_task, "single-flight server task must not panic").await?;
	let invalid = is_invalid_message(&result);
	assert!(
		invalid,
		"a muxed envelope on a single-flight connection must fail as InvalidMessage"
	);
	Ok(())
}

tb_assert_spec! {
	pub MuxCancelAbortSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_STREAM_CANCELLED, exactly!(1)),
			(FOLLOWUP_ECHOES_ON_FREED_SLOT, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxCancelAbortProcess,
	events {
		observable {
			events::MUX_STREAM_CANCELLED,
			FOLLOWUP_ECHOES_ON_FREED_SLOT
		}
		hidden { }
	}
	states {
		Idle => { events::MUX_STREAM_CANCELLED => Aborted },
		Aborted => { FOLLOWUP_ECHOES_ON_FREED_SLOT => Done },
		Done => { }
	}
	terminal { Done }
}

// A drop of an unresolved emit frees its cap slot and aborts the server
// handler.
tb_scenario! {
	name: mux_cancel_frees_slot_and_aborts_handler,
	config: ScenarioConfig::builder()
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

			ctx.started.wait("the first handler must park before the cancel").await?;

			abort_emit(cancelled_task).await;

			let frame_followup = mux_frame("mux-followup");
			let echoed = client.handle().emit_on_stream(&frame_followup).await?;

			trace.event_with(
				FOLLOWUP_ECHOES_ON_FREED_SLOT,
				&[],
				is_echo(echoed, &frame_followup),
			)?;
			assert!(ctx.aborted.load(Ordering::SeqCst), "the cancel must abort the parked handler");

			Ok(())
		}
	}
}

/// Read the next envelope, and require it to be the cancel of `stream_id`.
///
/// # Errors
///
/// - [`TightBeamError`] -- the read fails.
/// - An expectation failure -- the envelope is another record.
async fn expect_cancel(link: &mut ClientMuxServerRaw, stream_id: u32) -> Result<(), TightBeamError> {
	let cancel = link.server_reader.read_envelope().await?;
	match cancel {
		TransportEnvelope::Mux(MuxEnvelope::Cancel(package)) if package.stream_id() == stream_id => Ok(()),
		_ => Err(expectation_failure("the raced stream must go out as a cancel on the wire")),
	}
}

/// The client discards a stale response after a cancel, and later streams stay
/// healthy.
#[tokio::test]
async fn mux_cancel_response_race_discarded() -> Result<(), TightBeamError> {
	let mut link = establish_client_mux_server_raw(4, TraceCollector::new()).await?;
	let frame_cancelled = mux_frame("mux-raced");

	let raced_task = spawn_emit(&link.client.handle, frame_cancelled.to_owned());
	let raced_stream_id = read_muxed_request_id(&mut link.server_reader).await?;

	abort_emit(raced_task).await;
	expect_cancel(&mut link, raced_stream_id).await?;

	write_muxed_echo(&mut link.server_writer, raced_stream_id, &Arc::new(frame_cancelled)).await?;

	let followup_echoed = raw_echo_roundtrip(&mut link, &mux_frame("mux-alive")).await?;
	assert!(followup_echoed, "a stream after the race must still echo");
	Ok(())
}

/// Garbage End payloads stay per-stream: the client discards a stale end (of a
/// cancelled stream) unread, and a non-Ok trailer resolves its stream without
/// a decode. Neither may tear down the connection.
#[tokio::test]
async fn mux_end_garbage_payload_tolerated() -> Result<(), TightBeamError> {
	let mut link = establish_client_mux_server_raw(4, TraceCollector::new()).await?;
	let garbage = vec![0xDE, 0xAD];

	// A stale end on a cancelled stream carries garbage, and the client
	// must discard it.
	let stale_task = spawn_emit(&link.client.handle, mux_frame("mux-stale-garbage"));
	let stale_id = read_muxed_request_id(&mut link.server_reader).await?;

	abort_emit(stale_task).await;
	let _cancel = link.server_reader.read_envelope().await?;

	write_muxed_end(&mut link.server_writer, stale_id, TransitStatus::Ok, garbage.to_owned()).await?;

	// A `ResourceExhausted` trailer that carries garbage must resolve
	// its stream alone as `ResourceExhausted`.
	let busy_task = spawn_emit(&link.client.handle, mux_frame("mux-busy-garbage"));
	let busy_id = read_muxed_request_id(&mut link.server_reader).await?;

	write_muxed_end(&mut link.server_writer, busy_id, TransitStatus::ResourceExhausted, garbage).await?;

	let busy = join_task(busy_task, "busy emit task must not panic").await?;
	assert!(
		is_busy(&busy),
		"a ResourceExhausted trailer with a garbage payload must resolve its stream as busy"
	);

	// The connection must stay up, so a follow-up stream echoes.
	let followup_echoed = raw_echo_roundtrip(&mut link, &mux_frame("mux-after-garbage")).await?;
	assert!(followup_echoed, "the connection must stay up after garbage trailers");
	Ok(())
}

/// The server initiates an even stream, and the client's `serve` echoes it.
#[tokio::test]
async fn mux_server_initiated_roundtrip() -> Result<(), TightBeamError> {
	let materials = ServerMaterials::generate();
	let (listener, addr) = bind_encrypted_listener(&materials).await?;
	let server_task = tokio::spawn(async move {
		let (server, _responder) = accept_mux_server(listener, mux_offer(4), TraceCollector::new()).await?;

		let frame = mux_frame("mux-server-init");
		let reply = server.handle.emit_on_stream(&frame).await?;
		Ok::<_, TightBeamError>(is_echo(reply, &frame))
	});

	let client = connect_mux_client(addr, &materials, 4, TraceCollector::new()).await?;
	let _client_serve = spawn_immediate_echo(client.responder);

	// The client endpoint lives until the server-side emit resolves.
	let echoed = await_ok(server_task, "the server task must not panic").await?;
	assert!(echoed, "the client's serve must echo the server-initiated stream");
	Ok(())
}
