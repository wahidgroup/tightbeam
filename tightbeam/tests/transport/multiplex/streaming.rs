//! Streaming consumer API: chunk-level dispatch over the unified
//! stream wire.

use core::sync::atomic::AtomicUsize;
use core::time::Duration;
use std::sync::Arc;

use tokio::sync::Notify;
use tokio::time::timeout;

use tightbeam::der::{Decode, Encode};
use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::multiplex::{MuxResponder, MuxRole, StreamBody};
use tightbeam::transport::{TransportError, TransportFailure};
use tightbeam::utils::urn::Urn;
use tightbeam::Frame;
use tightbeam::TightBeamError;

use super::common::*;
use crate::common::security::expectation_failure;
use crate::transport::support::await_ok;

/// Client endpoint and server responder over freshly established
/// chunked transports: the setup every streaming scenario shares.
async fn streaming_endpoints(
	trace: &TraceCollector,
	server_offer: TransportOffer,
) -> Result<(MuxEndpoint, MuxResponder), TightBeamError> {
	let (client, server) = establish_transports(Some(chunked_offer(4)), Some(server_offer)).await?;
	let (client_end, _) = spawn_mux_endpoint(client.with_trace(trace.share()), MuxRole::Client)?;
	let (_, responder) = spawn_mux_endpoint(server.with_trace(trace.share()), MuxRole::Server)?;

	Ok((client_end, responder))
}

pub(crate) const STREAMING_ECHO_MATCHES: Urn<'static> = Urn::new("test", "event:streaming/echo-matches");
pub(crate) const STREAMING_HANDLER_SAW_MULTIPLE_CHUNKS: Urn<'static> =
	Urn::new("test", "event:streaming/handler-saw-multiple-chunks");

tb_assert_spec! {
	pub MuxStreamingRoundtripSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(STREAMING_ECHO_MATCHES, exactly!(1), equals!(true)),
			(STREAMING_HANDLER_SAW_MULTIPLE_CHUNKS, exactly!(1), equals!(true))
		]
	}
}

pub(crate) const OPEN_STREAM_ECHO_MATCHES: Urn<'static> = Urn::new("test", "event:streaming/open-stream-echo-matches");
pub(crate) const OPEN_STREAM_SERVER_SAW_CHUNKS: Urn<'static> =
	Urn::new("test", "event:streaming/open-stream-server-saw-chunks");

tb_assert_spec! {
	pub MuxOpenStreamSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(OPEN_STREAM_ECHO_MATCHES, exactly!(1), equals!(true)),
			(OPEN_STREAM_SERVER_SAW_CHUNKS, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_open_stream_pushes_chunks_and_awaits_response,
	spec: MuxOpenStreamSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (client_end, responder) = streaming_endpoints(&trace, chunked_offer(4)).await?;
			let chunks_seen = Arc::new(AtomicUsize::new(0));
			let _serve = tokio::spawn(responder.serve_streaming(streaming_echo_handler(Arc::clone(&chunks_seen))));

			let frame = large_mux_frame("mux-open-stream-echo");
			let payload = frame.to_der()?;
			let (sink, response) = client_end.handle.open_stream()?;
			push_split(sink, &payload).await?;

			let echoed = response.await?;
			trace.event_with(OPEN_STREAM_ECHO_MATCHES, &[], is_echo(echoed, &frame))?;
			trace.event_with(OPEN_STREAM_SERVER_SAW_CHUNKS, &[], saw_multiple_chunks(&chunks_seen))?;

			Ok(())
		}
	}
}

pub(crate) const OPEN_DUPLEX_REPLY_MATCHES: Urn<'static> =
	Urn::new("test", "event:streaming/open-duplex-reply-matches");
pub(crate) const OPEN_DUPLEX_REPLY_CHUNKED: Urn<'static> =
	Urn::new("test", "event:streaming/open-duplex-reply-chunked");

tb_assert_spec! {
	pub MuxOpenDuplexSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(OPEN_DUPLEX_REPLY_MATCHES, exactly!(1), equals!(true)),
			(OPEN_DUPLEX_REPLY_CHUNKED, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_open_duplex_receives_streamed_reply,
	spec: MuxOpenDuplexSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (client_end, responder) = streaming_endpoints(&trace, chunked_offer(4)).await?;
			let handler_chunks = Arc::new(AtomicUsize::new(0));
			let _serve = tokio::spawn(responder.serve_duplex(duplex_echo_handler(handler_chunks)));

			let frame = large_mux_frame("mux-open-duplex-echo");
			let payload = frame.to_der()?;
			let (sink, mut reply) = client_end.handle.open_duplex()?;
			push_split(sink, &payload).await?;

			let drained = drain_body(&mut reply).await;
			let echoed = Frame::from_der(&drained.bytes)?;
			trace.event_with(OPEN_DUPLEX_REPLY_MATCHES, &[], echoed == frame)?;
			trace.event_with(OPEN_DUPLEX_REPLY_CHUNKED, &[], drained.chunks > 1)?;

			Ok(())
		}
	}
}

pub(crate) const DUPLEX_ECHO_MATCHES: Urn<'static> = Urn::new("test", "event:streaming/duplex-echo-matches");
pub(crate) const DUPLEX_HANDLER_STREAMED_CHUNKS: Urn<'static> =
	Urn::new("test", "event:streaming/duplex-handler-streamed-chunks");

tb_assert_spec! {
	pub MuxDuplexEchoSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(DUPLEX_ECHO_MATCHES, exactly!(1), equals!(true)),
			(DUPLEX_HANDLER_STREAMED_CHUNKS, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_duplex_handler_streams_reply_chunks,
	spec: MuxDuplexEchoSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (client_end, responder) = streaming_endpoints(&trace, chunked_offer(4)).await?;
			let chunks_streamed = Arc::new(AtomicUsize::new(0));
			let _serve = tokio::spawn(responder.serve_duplex(duplex_echo_handler(Arc::clone(&chunks_streamed))));

			let frame = large_mux_frame("mux-duplex-echo");
			let echoed = client_end.handle.emit_on_stream(&frame).await?;

			trace.event_with(DUPLEX_ECHO_MATCHES, &[], is_echo(echoed, &frame))?;
			trace.event_with(DUPLEX_HANDLER_STREAMED_CHUNKS, &[], saw_multiple_chunks(&chunks_streamed))?;

			Ok(())
		}
	}
}

tb_scenario! {
	name: mux_streaming_handler_consumes_chunks_incrementally,
	spec: MuxStreamingRoundtripSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (client_end, responder) = streaming_endpoints(&trace, chunked_offer(4)).await?;
			let chunks_seen = Arc::new(AtomicUsize::new(0));
			let _serve = tokio::spawn(responder.serve_streaming(streaming_echo_handler(Arc::clone(&chunks_seen))));

			let frame = large_mux_frame("mux-streaming-echo");
			let echoed = client_end.handle.emit_on_stream(&frame).await?;

			trace.event_with(STREAMING_ECHO_MATCHES, &[], is_echo(echoed, &frame))?;
			trace.event_with(STREAMING_HANDLER_SAW_MULTIPLE_CHUNKS, &[], saw_multiple_chunks(&chunks_seen))?;

			Ok(())
		}
	}
}

/// Fires its notify when dropped: observes handler unwinding whether
/// the abort lands or the handler returns after its body severs.
struct NotifyOnDrop(Arc<Notify>);

impl Drop for NotifyOnDrop {
	fn drop(&mut self) {
		self.0.notify_one();
	}
}

/// Handler that signals entry, then consumes the body until it ends,
/// flagging its unwind through the drop guard.
fn hanging_streaming_handler(started: Arc<Notify>, unwound: Arc<Notify>) -> impl Fn(StreamBody) -> HandlerFuture {
	move |mut body| {
		let started = Arc::clone(&started);
		let unwound = Arc::clone(&unwound);
		Box::pin(async move {
			let _guard = NotifyOnDrop(unwound);
			started.notify_one();

			let drained = drain_body(&mut body).await;
			echo_reassembled(&drained.bytes)
		})
	}
}

pub(crate) const CANCELLED_RESPONSE_SURFACES: Urn<'static> =
	Urn::new("test", "event:streaming/cancelled-response-surfaces");
pub(crate) const CANCEL_UNWINDS_HANDLER: Urn<'static> = Urn::new("test", "event:streaming/cancel-unwinds-handler");

tb_assert_spec! {
	pub MuxStreamingCancelSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(CANCELLED_RESPONSE_SURFACES, exactly!(1), equals!(true)),
			(CANCEL_UNWINDS_HANDLER, exactly!(1), equals!(true))
		]
	}
}

// Dropping the sink mid-stream cancels: the response resolves
// Cancelled locally and the server discards the in-flight body,
// unwinding its handler.
tb_scenario! {
	name: mux_streaming_cancel_discards_inflight_body,
	spec: MuxStreamingCancelSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (client_end, responder) = streaming_endpoints(&trace, chunked_offer(4)).await?;
			let started = Arc::new(Notify::new());
			let unwound = Arc::new(Notify::new());
			let handler = hanging_streaming_handler(Arc::clone(&started), Arc::clone(&unwound));
			let _serve = tokio::spawn(responder.serve_streaming(handler));

			let (mut sink, response) = client_end.handle.open_stream()?;
			// Pushes go out eagerly: the first one carries the open
			// and starts the handler
			sink.push(b"first-chunk").await?;
			sink.push(b"second-chunk").await?;
			timeout(Duration::from_secs(5), started.notified())
				.await
				.map_err(|_| expectation_failure("handler must start before the cancel"))?;

			drop(sink);

			let outcome = response.await;
			trace.event_with(
				CANCELLED_RESPONSE_SURFACES,
				&[],
				matches!(outcome, Err(TransportError::OperationFailed(TransportFailure::Cancelled))),
			)?;

			let handler_unwound = timeout(Duration::from_secs(5), unwound.notified()).await.is_ok();
			trace.event_with(CANCEL_UNWINDS_HANDLER, &[], handler_unwound)?;

			Ok(())
		}
	}
}

pub(crate) const DUPLEX_CANCEL_FAILS_REPLY: Urn<'static> =
	Urn::new("test", "event:streaming/duplex-cancel-fails-reply");

tb_assert_spec! {
	pub MuxDuplexCancelSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(DUPLEX_CANCEL_FAILS_REPLY, exactly!(1), equals!(true))
		]
	}
}

// Dropping the duplex sink before close cancels the stream: the reply
// body fails with Cancelled instead of waiting on a trailer that will
// never arrive.
tb_scenario! {
	name: mux_duplex_sink_drop_fails_reply_body,
	spec: MuxDuplexCancelSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (client_end, responder) = streaming_endpoints(&trace, chunked_offer(4)).await?;
			let handler_chunks = Arc::new(AtomicUsize::new(0));
			let _serve = tokio::spawn(responder.serve_duplex(duplex_echo_handler(handler_chunks)));

			let (mut sink, mut reply) = client_end.handle.open_duplex()?;
			sink.push(b"first-chunk").await?;
			sink.push(b"second-chunk").await?;

			drop(sink);

			// Echoed chunks may already sit ahead of the cancel event;
			// drain to the terminal outcome
			let drained = drain_body(&mut reply).await;
			trace.event_with(
				DUPLEX_CANCEL_FAILS_REPLY,
				&[],
				matches!(
					drained.failure,
					Some(TransportError::OperationFailed(TransportFailure::Cancelled))
				),
			)?;

			Ok(())
		}
	}
}

/// Handler that signals entry, parks until released, then consumes and
/// echoes. The slow consumer is used for backpressure scenarios.
fn gated_streaming_echo(started: Arc<Notify>, release: Arc<Notify>) -> impl Fn(StreamBody) -> HandlerFuture {
	move |mut body| {
		let started = Arc::clone(&started);
		let release = Arc::clone(&release);
		Box::pin(async move {
			started.notify_one();
			release.notified().await;

			let drained = drain_body(&mut body).await;
			if drained.failure.is_some() {
				return echo_reassembled(&[]);
			}

			echo_reassembled(&drained.bytes)
		})
	}
}

pub(crate) const PUSH_STALLS_WITHOUT_DRAIN: Urn<'static> =
	Urn::new("test", "event:streaming/push-stalls-without-drain");
pub(crate) const PUSH_RESUMES_ON_CONSUMPTION: Urn<'static> =
	Urn::new("test", "event:streaming/push-resumes-on-consumption");

tb_assert_spec! {
	pub MuxStreamingBackpressureSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PUSH_STALLS_WITHOUT_DRAIN, exactly!(1), equals!(true)),
			(PUSH_RESUMES_ON_CONSUMPTION, exactly!(1), equals!(true))
		]
	}
}

// End-to-end backpressure: with one chunk of initial credit and a
// parked consumer, the pushing side stalls; grants follow only from
// consumer drain, so releasing the handler resumes the transfer.
tb_scenario! {
	name: mux_streaming_slow_consumer_stalls_then_resumes,
	spec: MuxStreamingBackpressureSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let server_offer = chunked_offer(4).with_initial_stream_credit(1);
			let (client_end, responder) = streaming_endpoints(&trace, server_offer).await?;
			let started = Arc::new(Notify::new());
			let release = Arc::new(Notify::new());
			let handler = gated_streaming_echo(Arc::clone(&started), Arc::clone(&release));
			let _serve = tokio::spawn(responder.serve_streaming(handler));

			let frame = large_mux_frame("mux-streaming-backpressure");
			let payload = frame.to_der()?;
			let handle = client_end.handle.clone();
			let mut transfer = tokio::spawn(async move {
				let (mut sink, response) = handle.open_stream()?;
				sink.push(&payload).await?;
				sink.close().await?;
				response.await
			});

			timeout(Duration::from_secs(5), started.notified())
				.await
				.map_err(|_| expectation_failure("handler must start on the open chunk"))?;

			// Sampling probe, not proof: a slow enough machine could
			// keep a healthy transfer in flight past the window. The
			// resume assertion below bounds the exposure - the
			// transfer must still complete once the handler drains
			let stalled = timeout(Duration::from_millis(200), &mut transfer).await.is_err();
			trace.event_with(PUSH_STALLS_WITHOUT_DRAIN, &[], stalled)?;

			release.notify_one();
			let echoed = await_ok(transfer, "stalled transfer must not panic").await?;
			trace.event_with(PUSH_RESUMES_ON_CONSUMPTION, &[], is_echo(echoed, &frame))?;

			Ok(())
		}
	}
}

pub(crate) const PING_PONG_REPLIES_MATCH: Urn<'static> = Urn::new("test", "event:streaming/ping-pong-replies-match");
pub(crate) const PING_PONG_ENDS_CLEAN: Urn<'static> = Urn::new("test", "event:streaming/ping-pong-ends-clean");

tb_assert_spec! {
	pub MuxDuplexPingPongSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PING_PONG_REPLIES_MATCH, exactly!(1), equals!(true)),
			(PING_PONG_ENDS_CLEAN, exactly!(1), equals!(true))
		]
	}
}

// Eager pushes make duplex conversational: awaiting each echoed reply
// between pushes must progress chunk for chunk instead of parking on a
// held-back record, and `close_with` flags the final chunk itself.
tb_scenario! {
	name: mux_duplex_ping_pong_awaits_reply_between_pushes,
	spec: MuxDuplexPingPongSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (client_end, responder) = streaming_endpoints(&trace, chunked_offer(4)).await?;
			let handler_chunks = Arc::new(AtomicUsize::new(0));
			let _serve = tokio::spawn(responder.serve_duplex(duplex_echo_handler(handler_chunks)));

			let (mut sink, mut reply) = client_end.handle.open_duplex()?;
			let exchange = async move {
				let mut matched = true;
				for ping in [&b"ping-one"[..], b"ping-two", b"ping-three"] {
					sink.push(ping).await?;
					let pong = reply.chunk().await?;
					matched &= pong.as_deref() == Some(ping);
				}

				sink.close_with(b"ping-final").await?;
				let pong = reply.chunk().await?;
				matched &= pong.as_deref() == Some(&b"ping-final"[..]);

				let terminal = reply.chunk().await?;
				Ok::<_, TransportError>((matched, terminal.is_none()))
			};
			let (matched, ended_clean) = timeout(Duration::from_secs(5), exchange)
				.await
				.map_err(|_| expectation_failure("a chunk-for-chunk exchange must progress with eager pushes"))??;

			trace.event_with(PING_PONG_REPLIES_MATCH, &[], matched)?;
			trace.event_with(PING_PONG_ENDS_CLEAN, &[], ended_clean)?;

			Ok(())
		}
	}
}

pub(crate) const INTO_FRAME_DECODES_REPLY: Urn<'static> = Urn::new("test", "event:streaming/into-frame-decodes-reply");

tb_assert_spec! {
	pub MuxDuplexIntoFrameSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(INTO_FRAME_DECODES_REPLY, exactly!(1), equals!(true))
		]
	}
}

// The collection sugar end to end: `close_with` carries the final
// request chunk and `into_frame` reassembles the chunked reply.
tb_scenario! {
	name: mux_duplex_reply_collects_into_frame,
	spec: MuxDuplexIntoFrameSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (client_end, responder) = streaming_endpoints(&trace, chunked_offer(4)).await?;
			let handler_chunks = Arc::new(AtomicUsize::new(0));
			let _serve = tokio::spawn(responder.serve_duplex(duplex_echo_handler(handler_chunks)));

			let frame = large_mux_frame("mux-duplex-into-frame");
			let payload = frame.to_der()?;
			let middle = payload.len() / 2;

			let (mut sink, reply) = client_end.handle.open_duplex()?;
			sink.push(&payload[..middle]).await?;
			sink.close_with(&payload[middle..]).await?;

			let echoed = reply.into_frame().await?;
			trace.event_with(INTO_FRAME_DECODES_REPLY, &[], echoed == frame)?;

			Ok(())
		}
	}
}
