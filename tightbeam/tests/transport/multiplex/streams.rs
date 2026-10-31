//! The integration tests of concurrent mux streams, stream caps, cancel, and
//! server-initiated streams.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::sync::Notify;

use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::tb_assert_spec;
use tightbeam::tb_cases;
use tightbeam::tb_process_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ClientEnv, ScenarioConfig};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::MuxEnvelope;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::{EnvelopeSource, TransportEnvelope, TransportError, TransportFailure};
use tightbeam::urn::Urn;
use tightbeam::{Frame, TightBeamError};

use crate::common::poll::joined;
use crate::common::result::TestResult;
use crate::common::security::ServerMaterials;
use crate::common::transport::respond_echo;
use crate::transport::fixtures::{await_ok, bind_encrypted_listener, mux_frame};

use super::common::*;

pub(crate) const FOLLOWUP_ECHOES_ON_FREED_SLOT: Urn<'static> =
	tightbeam::urn!("test", "event:streams/followup-echoes-on-freed-slot");
pub(crate) const HELD_EMIT_ECHOES_AFTER_RELEASE: Urn<'static> =
	tightbeam::urn!("test", "event:streams/held-emit-echoes-after-release");

// Two concurrent streams on each link: the server answers them in reverse
// order, and the client correlates each reply by its stream ID.
tb_cases! {
	async fn two_streams_answer_out_of_order(link: Link) -> TestResult {
		let mux = link.endpoints().await;
		let frame_first = mux_frame("mux-first");
		let frame_second = mux_frame("mux-second");
		let handler = order_forcing_echo(frame_first.to_owned(), Arc::new(Notify::new()));
		let _serve = tokio::spawn(mux.responder.serve(handler));

		let (first, second) = tokio::join!(
			mux.client.handle.emit_on_stream(&frame_first),
			mux.client.handle.emit_on_stream(&frame_second),
		);
		assert_eq!((first?, second?), (Some(frame_first), Some(frame_second)));
		Ok(())
	}
	cases {
		cleartext => Link::Cleartext,
		encrypted => Link::Encrypted,
	}
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
			assert_eq!(client.settings.local_initiated_cap(), 1, "the client must take the server's cap of 1");

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

/// A handshake in which neither side offers multiplexing negotiates none.
#[tokio::test]
async fn a_handshake_with_no_mux_offer_negotiates_none() -> TestResult {
	let (client, _server) = establish_transports(None, None).await?;
	let negotiated = client.negotiated_mux();
	assert_eq!(negotiated, None);
	Ok(())
}

/// A muxed envelope on a connection that negotiated no multiplexing fails as
/// `InvalidMessage`.
#[tokio::test]
async fn a_muxed_envelope_on_a_single_flight_connection_fails_as_invalid() -> TestResult {
	let (client, server) = establish_transports(None, None).await?;
	let server_task = tokio::spawn(respond_echo(server));

	let (_reader, mut writer) = client.into_split()?;
	write_muxed_request(&mut writer, 1, mux_frame("mux-rogue")).await?;

	let served = joined(server_task).await;
	assert!(matches!(served, Err(TransportError::InvalidMessage)));
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

/// Reads the next envelope, and requires it to be the cancel of `stream_id`.
async fn expect_cancel(link: &mut ClientMuxServerRaw, stream_id: u32) {
	let cancel = link.server_reader.read_envelope().await;
	let cancel = cancel.expect("the raw server reads the next envelope");
	assert!(matches!(
		cancel,
		TransportEnvelope::Mux(MuxEnvelope::Cancel(package)) if package.stream_id() == stream_id
	));
}

/// The client discards a stale response after a cancel, and later streams stay
/// healthy.
#[tokio::test]
async fn a_response_after_a_cancel_is_discarded() -> TestResult {
	let mut link = establish_client_mux_server_raw(4, TraceCollector::new()).await?;
	let frame_cancelled = mux_frame("mux-raced");

	let raced_task = spawn_emit(&link.client.handle, frame_cancelled.to_owned());
	let raced_stream_id = read_muxed_request_id(&mut link.server_reader).await?;

	abort_emit(raced_task).await;
	expect_cancel(&mut link, raced_stream_id).await;

	write_muxed_echo(&mut link.server_writer, raced_stream_id, &Arc::new(frame_cancelled)).await?;

	let followup = mux_frame("mux-alive");
	let echoed = raw_echo_roundtrip(&mut link, &followup).await;
	assert_eq!(echoed, Some(followup));
	Ok(())
}

/// The payload of each garbage `End` trailer of [`after_garbage_trailers`].
const GARBAGE: [u8; 2] = [0xDE, 0xAD];

/// A raw link after two garbage `End` trailers, beside the emit of the
/// stream that the second one answers.
struct GarbageTrailers {
	/// The link that carried both trailers.
	link: ClientMuxServerRaw,
	/// The emit that the `ResourceExhausted` trailer answers.
	busy: EmitTask,
}

/// A raw link after two garbage `End` trailers: an `Ok` one on a cancelled
/// stream, which the client discards unread, and a `ResourceExhausted` one
/// on a live stream, which resolves that stream without a decode.
async fn after_garbage_trailers() -> GarbageTrailers {
	let link = establish_client_mux_server_raw(4, TraceCollector::new()).await;
	let mut link = link.expect("the raw link establishes");

	// A stale end on a cancelled stream carries garbage, and the client
	// must discard it.
	let stale_task = spawn_emit(&link.client.handle, mux_frame("mux-stale-garbage"));
	let stale_id = read_muxed_request_id(&mut link.server_reader).await;
	let stale_id = stale_id.expect("the stale request arrives");

	abort_emit(stale_task).await;
	expect_cancel(&mut link, stale_id).await;

	let stale_end = write_muxed_end(&mut link.server_writer, stale_id, TransitStatus::Ok, GARBAGE).await;
	stale_end.expect("the raw server writes the stale end");

	// A `ResourceExhausted` trailer that carries garbage must resolve
	// its stream alone as `ResourceExhausted`.
	let busy = spawn_emit(&link.client.handle, mux_frame("mux-busy-garbage"));
	let busy_id = read_muxed_request_id(&mut link.server_reader).await;
	let busy_id = busy_id.expect("the busy request arrives");

	let busy_end = write_muxed_end(&mut link.server_writer, busy_id, TransitStatus::ResourceExhausted, GARBAGE).await;
	busy_end.expect("the raw server writes the busy end");
	GarbageTrailers { link, busy }
}

/// A `ResourceExhausted` trailer whose payload is garbage resolves its stream
/// alone as `ResourceExhausted`, with no decode of the payload.
#[tokio::test]
async fn a_garbage_trailer_resolves_its_stream_alone() {
	let trailers = after_garbage_trailers().await;
	let busy = joined(trailers.busy).await;
	assert!(matches!(
		busy,
		Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted))
	));
}

/// Garbage `End` payloads stay per-stream, so a follow-up stream echoes after
/// both garbage trailers.
#[tokio::test]
async fn garbage_trailers_leave_the_connection_up() {
	let mut trailers = after_garbage_trailers().await;
	let followup = mux_frame("mux-after-garbage");

	let echoed = raw_echo_roundtrip(&mut trailers.link, &followup).await;
	assert_eq!(echoed, Some(followup));
}

/// The server initiates an even stream, and the client's `serve` echoes it.
#[tokio::test]
async fn a_client_serve_echoes_a_server_initiated_stream() -> TestResult {
	let materials = ServerMaterials::fixed();
	let (listener, addr) = bind_encrypted_listener(&materials).await?;
	let frame = mux_frame("mux-server-init");
	let sent = Frame::clone(&frame);
	let server_task = tokio::spawn(async move {
		let (server, _responder) = accept_mux_server(listener, TransportOffer::mux(4), TraceCollector::new()).await?;

		let reply = server.handle.emit_on_stream(&sent).await?;
		Ok::<_, TightBeamError>(reply)
	});

	let client = connect_mux_client(addr, &materials, 4, TraceCollector::new()).await?;
	let _client_serve = spawn_immediate_echo(client.responder);

	// The client endpoint lives until the server-side emit resolves.
	let reply = joined(server_task).await?;
	assert_eq!(reply, Some(frame));
	Ok(())
}
