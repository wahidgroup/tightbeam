//! Scenarios for the streaming consumer API, which carries each chunk on the
//! stream records that every stream kind shares.

use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::sync::Arc;

use tokio::sync::Notify;
use tokio::time::timeout;

use tightbeam::der::{Decode, Encode};
use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::multiplex::{MuxResponder, MuxRole, RequestSink, StreamBody};
use tightbeam::transport::{TransportError, TransportFailure};
use tightbeam::Frame;
use tightbeam::TightBeamError;

use super::common::*;
use crate::transport::support::{await_ok, await_within_deadline, HandlerSignal};

/// Returns a client endpoint, a server responder, and the server endpoint
/// whose drivers keep the connection running, over freshly established
/// chunked transports, the setup every streaming scenario shares.
async fn streaming_endpoints(
	trace: &TraceCollector,
	server_offer: TransportOffer,
) -> Result<(MuxEndpoint, MuxResponder, MuxEndpoint), TightBeamError> {
	let (client, server) = establish_transports(Some(chunked_offer(4)), Some(server_offer)).await?;
	let (client_end, _) = spawn_mux_endpoint(client.with_trace(trace.share()), MuxRole::Client)?;
	let (server_end, responder) = spawn_mux_endpoint(server.with_trace(trace.share()), MuxRole::Server)?;

	Ok((client_end, responder, server_end))
}

/// A streamed request pushes its chunks to a streaming handler and awaits the
/// unary response.
#[tokio::test]
async fn mux_open_stream_pushes_chunks_and_awaits_response() -> Result<(), TightBeamError> {
	let (client_end, responder, _server_end) = streaming_endpoints(&TraceCollector::new(), chunked_offer(4)).await?;
	let chunks_seen = Arc::new(AtomicUsize::new(0));
	let _serve = tokio::spawn(responder.serve_streaming(streaming_echo_handler(Arc::clone(&chunks_seen))));

	let frame = large_mux_frame("mux-open-stream-echo");
	let payload = frame.to_der()?;
	let (sink, response) = client_end.handle.open_stream()?;
	push_split(sink, &payload).await?;

	let echoed = response.await?;
	let chunked = saw_multiple_chunks(&chunks_seen);
	assert!(is_echo(echoed, &frame), "the streamed request must echo");
	assert!(chunked, "the streaming handler must see more than one chunk");
	Ok(())
}

/// A duplex stream receives its reply as a streamed body.
#[tokio::test]
async fn mux_open_duplex_receives_streamed_reply() -> Result<(), TightBeamError> {
	let (client_end, responder, _server_end) = streaming_endpoints(&TraceCollector::new(), chunked_offer(4)).await?;
	let handler_chunks = Arc::new(AtomicUsize::new(0));
	let _serve = tokio::spawn(responder.serve_duplex(duplex_echo_handler(handler_chunks)));

	let frame = large_mux_frame("mux-open-duplex-echo");
	let payload = frame.to_der()?;
	let (sink, mut reply) = client_end.handle.open_duplex()?;
	push_split(sink, &payload).await?;

	let drained = drain_body(&mut reply).await;
	let echoed = Frame::from_der(&drained.bytes)?;
	assert_eq!(echoed, frame, "the duplex reply must reassemble to the request");
	assert!(drained.chunks > 1, "the duplex reply must arrive in more than one chunk");
	Ok(())
}

/// Whether the responder refuses a unary-kind emit with `Unimplemented`.
async fn emit_refused_unimplemented(endpoint: &MuxEndpoint, label: impl AsRef<str>) -> bool {
	let label = label.as_ref();
	matches!(
		endpoint.handle.emit_on_stream(&large_mux_frame(label)).await,
		Err(TransportError::OperationFailed(TransportFailure::Unimplemented))
	)
}

tb_assert_spec! {
	pub MuxUnaryKindVsDuplexSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_STREAM_REFUSED, exactly!(1), equals!(TransitStatus::Unimplemented))
		]
	}
}

// Kind dispatch is strict: a unary-kind stream against a duplex-only
// responder refuses with `Unimplemented` and never enters the handler.
tb_scenario! {
	name: mux_unary_kind_refused_by_duplex_server,
	spec: MuxUnaryKindVsDuplexSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (client_end, responder, _server_end) = streaming_endpoints(&trace, chunked_offer(4)).await?;
			let chunks_streamed = Arc::new(AtomicUsize::new(0));
			let _serve = tokio::spawn(responder.serve_duplex(duplex_echo_handler(Arc::clone(&chunks_streamed))));

			let refused = emit_refused_unimplemented(&client_end, "mux-unary-vs-duplex").await;
			assert!(refused, "a unary-kind emit against a duplex-only responder must fail as Unimplemented");
			assert_eq!(chunks_streamed.load(Ordering::Relaxed), 0, "the refused stream must not reach the handler");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxUnaryKindVsStreamingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_STREAM_REFUSED, exactly!(1), equals!(TransitStatus::Unimplemented))
		]
	}
}

// Kind dispatch is as strict against a streaming-only responder.
tb_scenario! {
	name: mux_unary_kind_refused_by_streaming_server,
	spec: MuxUnaryKindVsStreamingSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (client_end, responder, _server_end) = streaming_endpoints(&trace, chunked_offer(4)).await?;
			let chunks_seen = Arc::new(AtomicUsize::new(0));
			let _serve = tokio::spawn(responder.serve_streaming(streaming_echo_handler(Arc::clone(&chunks_seen))));

			let refused = emit_refused_unimplemented(&client_end, "mux-unary-vs-streaming").await;
			assert!(refused, "a unary-kind emit against a streaming-only responder must fail as Unimplemented");
			assert_eq!(chunks_seen.load(Ordering::Relaxed), 0, "the refused stream must not reach the handler");

			Ok(())
		}
	}
}

/// A guard that raises its signal on drop, so it observes the handler unwind
/// whether the abort lands or the handler returns after its body severs.
struct RaiseOnDrop(Arc<HandlerSignal>);

impl Drop for RaiseOnDrop {
	fn drop(&mut self) {
		self.0.raise();
	}
}

/// Returns a handler that signals entry, consumes the body until it ends, and
/// flags its unwind through the drop guard.
fn hanging_streaming_handler(
	started: Arc<HandlerSignal>,
	unwound: Arc<HandlerSignal>,
) -> impl Fn(StreamBody) -> HandlerFuture {
	move |mut body| {
		let started = Arc::clone(&started);
		let unwound = Arc::clone(&unwound);
		Box::pin(async move {
			let _guard = RaiseOnDrop(unwound);
			started.raise();

			let drained = drain_body(&mut body).await;
			echo_reassembled(&drained.bytes)
		})
	}
}

/// A drop of the sink mid-stream cancels the stream: the response resolves
/// `Cancelled` locally, and the server discards the in-flight body and unwinds
/// its handler.
#[tokio::test]
async fn mux_streaming_cancel_discards_inflight_body() -> Result<(), TightBeamError> {
	let (client_end, responder, _server_end) = streaming_endpoints(&TraceCollector::new(), chunked_offer(4)).await?;
	let started = Arc::new(HandlerSignal::default());
	let unwound = Arc::new(HandlerSignal::default());
	let handler = hanging_streaming_handler(Arc::clone(&started), Arc::clone(&unwound));
	let _serve = tokio::spawn(responder.serve_streaming(handler));

	let (mut sink, response) = client_end.handle.open_stream()?;
	// Pushes go out eagerly: the first one carries the open and starts the
	// handler.
	sink.push(b"first-chunk").await?;
	sink.push(b"second-chunk").await?;
	started.wait("handler must start before the cancel").await?;

	drop(sink);

	let outcome = response.await;
	let cancelled = matches!(outcome, Err(TransportError::OperationFailed(TransportFailure::Cancelled)));
	assert!(cancelled, "dropping the sink must resolve the response as cancelled");
	assert!(unwound.raised().await, "a peer cancel must unwind the streaming handler");
	Ok(())
}

/// A drop of the duplex sink before close cancels the stream: the reply body
/// fails with `Cancelled` instead of a wait on a trailer that never arrives.
#[tokio::test]
async fn mux_duplex_sink_drop_fails_reply_body() -> Result<(), TightBeamError> {
	let (client_end, responder, _server_end) = streaming_endpoints(&TraceCollector::new(), chunked_offer(4)).await?;
	let handler_chunks = Arc::new(AtomicUsize::new(0));
	let _serve = tokio::spawn(responder.serve_duplex(duplex_echo_handler(handler_chunks)));

	let (mut sink, mut reply) = client_end.handle.open_duplex()?;
	sink.push(b"first-chunk").await?;
	sink.push(b"second-chunk").await?;

	drop(sink);

	// Echoed chunks may already sit ahead of the cancel event, so drain to the
	// terminal outcome.
	let drained = drain_body(&mut reply).await;
	let cancelled = matches!(
		drained.failure,
		Some(TransportError::OperationFailed(TransportFailure::Cancelled))
	);
	assert!(cancelled, "dropping the duplex sink must fail the reply body as cancelled");
	Ok(())
}

/// Returns a handler that signals entry, parks until its release, and then
/// consumes and echoes. The backpressure scenarios use it as the slow consumer.
fn gated_streaming_echo(started: Arc<HandlerSignal>, release: Arc<Notify>) -> impl Fn(StreamBody) -> HandlerFuture {
	move |mut body| {
		let started = Arc::clone(&started);
		let release = Arc::clone(&release);
		Box::pin(async move {
			started.raise();
			release.notified().await;

			let drained = drain_body(&mut body).await;
			if drained.failure.is_some() {
				return echo_reassembled([]);
			}

			echo_reassembled(&drained.bytes)
		})
	}
}

/// End-to-end backpressure: with one chunk of initial credit and a parked
/// consumer, the client's push stalls. Grants follow only from the consumer's
/// drain, so the handler's release resumes the transfer.
#[tokio::test]
async fn mux_streaming_slow_consumer_stalls_then_resumes() -> Result<(), TightBeamError> {
	let server_offer = chunked_offer(4).with_initial_stream_credit(1);
	let (client_end, responder, _server_end) = streaming_endpoints(&TraceCollector::new(), server_offer).await?;
	let started = Arc::new(HandlerSignal::default());
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

	started.wait("handler must start on the open chunk").await?;

	// A slow enough machine can keep a healthy transfer in flight past the
	// window, so this sample is only a probe. The resume assertion bounds the
	// exposure, because the transfer must complete once the handler drains.
	let stalled = timeout(Duration::from_millis(200), &mut transfer).await.is_err();
	assert!(stalled, "the push must stall while the consumer holds its body");

	release.notify_one();

	let echoed = await_ok(transfer, "stalled transfer must not panic").await?;
	let finished = is_echo(echoed, &frame);
	assert!(finished, "the stalled transfer must finish once the consumer drains");
	Ok(())
}

/// The pings of the conversation in [`exchange_pings`], in the order they go
/// out.
const PINGS: [&[u8]; 3] = [b"ping-one", b"ping-two", b"ping-three"];

/// Push each of [`PINGS`] and await its echoed reply before the next push,
/// then close with a final ping and read the reply to its end.
///
/// The result is whether each reply matched its push, and whether the reply
/// body ended clean on its `Ok` trailer.
///
/// # Errors
///
/// - [`TransportError`] -- the push, close, or read failure of the exchange.
async fn exchange_pings(mut sink: RequestSink, mut reply: StreamBody) -> Result<(bool, bool), TransportError> {
	let mut matched = true;
	for ping in PINGS {
		sink.push(ping).await?;
		let pong = reply.chunk().await?;
		matched &= pong.as_deref() == Some(ping);
	}

	sink.close_with(b"ping-final").await?;

	let pong = reply.chunk().await?;
	matched &= pong.as_deref() == Some(&b"ping-final"[..]);

	let terminal = reply.chunk().await?;
	Ok((matched, terminal.is_none()))
}

/// Eager pushes make duplex conversational: an exchange that awaits each
/// echoed reply between pushes must progress chunk for chunk, not park on a
/// held-back record, and `close_with` flags the final chunk itself.
#[tokio::test]
async fn mux_duplex_ping_pong_awaits_reply_between_pushes() -> Result<(), TightBeamError> {
	let (client_end, responder, _server_end) = streaming_endpoints(&TraceCollector::new(), chunked_offer(4)).await?;
	let handler_chunks = Arc::new(AtomicUsize::new(0));
	let _serve = tokio::spawn(responder.serve_duplex(duplex_echo_handler(handler_chunks)));

	let (sink, reply) = client_end.handle.open_duplex()?;
	let exchange = exchange_pings(sink, reply);
	let progressed = await_within_deadline(exchange, "a chunk-for-chunk exchange must progress with eager pushes");

	let (matched, ended_clean) = progressed.await??;
	assert!(matched, "each duplex reply must match its push");
	assert!(ended_clean, "the duplex reply must end on its Ok trailer");
	Ok(())
}

/// The collection sugar runs end to end: `close_with` carries the final
/// request chunk, and `into_frame` reassembles the chunked reply.
#[tokio::test]
async fn mux_duplex_reply_collects_into_frame() -> Result<(), TightBeamError> {
	let (client_end, responder, _server_end) = streaming_endpoints(&TraceCollector::new(), chunked_offer(4)).await?;
	let handler_chunks = Arc::new(AtomicUsize::new(0));
	let _serve = tokio::spawn(responder.serve_duplex(duplex_echo_handler(handler_chunks)));

	let frame = large_mux_frame("mux-duplex-into-frame");
	let payload = frame.to_der()?;
	let middle = payload.len() / 2;

	let (mut sink, reply) = client_end.handle.open_duplex()?;
	sink.push(&payload[..middle]).await?;
	sink.close_with(&payload[middle..]).await?;

	let echoed = reply.into_frame().await?;
	assert_eq!(echoed, frame, "into_frame must reassemble the chunked reply");
	Ok(())
}
