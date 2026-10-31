//! The integration tests of the streaming consumer API, which carries each
//! chunk on the stream records that every stream kind shares.

use core::future::pending;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, Notify};

use tightbeam::der::{Decode, Encode};
use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::tb_assert_spec;
use tightbeam::tb_cases;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::multiplex::{
	BufferedGrantor, CreditGrantor, MuxResponder, MuxRole, RequestSink, StreamBody, StreamId,
};
use tightbeam::transport::{ResponsePackage, TransportError, TransportFailure};
use tightbeam::Frame;
use tightbeam::TightBeamError;

use super::common::*;
use crate::common::poll::{joined, within_hang_guard};
use crate::common::result::TestResult;
use crate::transport::fixtures::HandlerSignal;

/// Returns a client endpoint, a server responder, and the server endpoint
/// whose drivers keep the connection running, over freshly established
/// chunked transports, the setup every streaming scenario shares.
async fn streaming_endpoints(
	trace: &TraceCollector,
	server_offer: TransportOffer,
) -> Result<(MuxEndpoint, MuxResponder, MuxEndpoint), TightBeamError> {
	let MuxLink { client, server, responder } = MuxLink::encrypted(server_offer, trace).await;
	Ok((client, responder, server))
}

/// What a streamed request of a large frame showed on its way through a
/// streaming echo handler.
struct StreamedEcho {
	/// The frame that the request carried.
	sent: Frame,
	/// The response that the request resolved to.
	echoed: Option<Frame>,
	/// The count of chunks that the handler read.
	chunks: usize,
}

/// Opens a stream on a fresh link of `link`, pushes a large frame on it in
/// two parts to a streaming echo handler, and returns what it showed.
async fn streamed_echo(link: Link) -> StreamedEcho {
	let mux = link.endpoints().await;
	let chunks_seen = Arc::new(AtomicUsize::new(0));
	let _serve = tokio::spawn(mux.responder.serve_streaming(streaming_echo_handler(Arc::clone(&chunks_seen))));

	let sent = large_mux_frame("mux-streamed-echo");
	let payload = sent.to_der().expect("a test frame encodes");
	let (sink, response) = mux.client.handle.open_stream().expect("a fresh link opens a stream");
	push_split(sink, &payload).await.expect("the push reaches the handler");

	let echoed = response.await.expect("the streamed request draws its response");
	StreamedEcho { sent, echoed, chunks: chunks_seen.load(Ordering::SeqCst) }
}

// A streamed request on each link pushes its chunks to a streaming handler,
// and its unary response echoes the frame it carried.
tb_cases! {
	async fn a_streamed_request_echoes(link: Link) {
		let streamed = streamed_echo(link).await;
		assert_eq!(streamed.echoed, Some(streamed.sent));
	}
	cases {
		cleartext => Link::Cleartext,
		encrypted => Link::Encrypted,
	}
}

// A streamed request of a large frame on each link reaches its handler in
// more than one chunk.
tb_cases! {
	async fn a_streamed_request_arrives_in_more_than_one_chunk(link: Link) {
		let streamed = streamed_echo(link).await;
		assert!(streamed.chunks > 1);
	}
	cases {
		cleartext => Link::Cleartext,
		encrypted => Link::Encrypted,
	}
}

/// The client endpoint of a fresh encrypted link whose server serves
/// [`duplex_echo_handler`], beside the server endpoint, whose drivers keep the
/// link up.
async fn duplex_echo_endpoints() -> (MuxEndpoint, MuxEndpoint) {
	let mux = Link::Encrypted.endpoints().await;
	let handler_chunks = Arc::new(AtomicUsize::new(0));
	tokio::spawn(mux.responder.serve_duplex(duplex_echo_handler(handler_chunks)));
	(mux.client, mux.server)
}

/// The frame that a duplex stream carries to an echo handler, beside the
/// reply body drained to its end.
async fn duplex_echo() -> (Frame, DrainedBody) {
	let (client, _server) = duplex_echo_endpoints().await;

	let frame = large_mux_frame("mux-open-duplex-echo");
	let payload = frame.to_der().expect("a test frame encodes");
	let (sink, mut reply) = client.handle.open_duplex().expect("a fresh link opens a duplex stream");
	push_split(sink, &payload).await.expect("the push reaches the handler");
	(frame, drain_body(&mut reply).await)
}

/// A duplex stream receives its reply as a streamed body, which reassembles
/// to the request.
#[tokio::test]
async fn a_duplex_reply_reassembles_to_its_request() -> TestResult {
	let (frame, drained) = duplex_echo().await;

	let echoed = Frame::from_der(&drained.bytes)?;
	assert_eq!(echoed, frame);
	Ok(())
}

/// The streamed reply of a large frame on a duplex stream arrives in more
/// than one chunk.
#[tokio::test]
async fn a_duplex_reply_arrives_in_more_than_one_chunk() {
	let (_frame, drained) = duplex_echo().await;
	assert!(drained.chunks > 1);
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

/// A guard that raises its signal on drop, so it observes the abort of the
/// handler that holds it.
struct RaiseOnDrop(Arc<HandlerSignal>);

impl Drop for RaiseOnDrop {
	fn drop(&mut self) {
		self.0.raise();
	}
}

/// Returns a handler that signals entry, hands its body to `bodies`, and parks
/// for good, so an abort alone unwinds it. The drop guard flags the unwind.
fn parked_streaming_handler(
	started: Arc<HandlerSignal>,
	unwound: Arc<HandlerSignal>,
	bodies: mpsc::UnboundedSender<StreamBody>,
) -> impl Fn(StreamBody) -> HandlerFuture {
	move |body| {
		let started = Arc::clone(&started);
		let unwound = Arc::clone(&unwound);
		let bodies = bodies.clone();
		Box::pin(async move {
			let _guard = RaiseOnDrop(unwound);
			bodies.send(body).expect("the stream holds the receiver of the bodies");
			started.raise();

			pending::<ResponsePackage>().await
		})
	}
}

/// A stream whose sink the client dropped mid-stream, after its handler
/// started on the first two chunks.
struct CancelledStream {
	/// The outcome that the response of the stream resolved to.
	outcome: Result<Option<Frame>, TransportError>,
	/// The body that the handler handed over as it parked.
	body: StreamBody,
	/// The signal that the handler raises as it unwinds.
	unwound: Arc<HandlerSignal>,
	/// The client endpoint, which stays up while the cancel travels.
	_client: MuxEndpoint,
	/// The server endpoint, whose drivers carry the cancel to the handler.
	_server: MuxEndpoint,
}

/// Opens a stream on `trace` to a handler that parks for good, pushes two
/// chunks on it, drops the sink once the handler starts, and returns what the
/// stream showed.
async fn cancelled_mid_stream(trace: &TraceCollector) -> CancelledStream {
	let mux = MuxLink::encrypted(chunked_offer(4), trace).await;
	let started = Arc::new(HandlerSignal::default());
	let unwound = Arc::new(HandlerSignal::default());
	let (bodies, mut handed_over) = mpsc::unbounded_channel();
	let handler = parked_streaming_handler(Arc::clone(&started), Arc::clone(&unwound), bodies);
	let _serve = tokio::spawn(mux.responder.serve_streaming(handler));

	let (mut sink, response) = mux.client.handle.open_stream().expect("a fresh link opens a stream");
	// Pushes go out eagerly: the first one carries the open and starts the
	// handler.
	sink.push(b"first-chunk").await.expect("the first chunk goes out");
	sink.push(b"second-chunk").await.expect("the second chunk goes out");
	started.raised().await;

	drop(sink);

	let outcome = response.await;
	let body = handed_over
		.try_recv()
		.expect("the handler hands over its body before its start");
	CancelledStream { outcome, body, unwound, _client: mux.client, _server: mux.server }
}

/// A drop of the sink mid-stream cancels the stream, so the response resolves
/// `Cancelled` locally.
#[tokio::test]
async fn a_dropped_sink_resolves_its_response_cancelled() {
	let cancelled = cancelled_mid_stream(&TraceCollector::new()).await;
	assert!(matches!(
		cancelled.outcome,
		Err(TransportError::OperationFailed(TransportFailure::Cancelled))
	));
}

tb_assert_spec! {
	pub MuxPeerCancelSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_STREAM_CANCELLED, exactly!(1))
		]
	}
}

/// A drop of the sink mid-stream reaches the server as a peer cancel, whose
/// abort alone unwinds the parked streaming handler.
#[tokio::test]
async fn a_peer_cancel_unwinds_the_streaming_handler() -> TestResult {
	grade_case(MuxPeerCancelSpec::latest(), |trace| async move {
		let cancelled = cancelled_mid_stream(&trace).await;
		cancelled.unwound.raised().await;
	})
	.await
}

/// A peer cancel discards the in-flight body, so a reader of that body reads a
/// failure after the chunks that arrived, with no clean end.
#[tokio::test]
async fn a_peer_cancel_fails_the_body_in_flight() {
	let mut cancelled = cancelled_mid_stream(&TraceCollector::new()).await;
	let drained = within_hang_guard(drain_body(&mut cancelled.body), "the peer cancel ends the body").await;
	assert!(matches!(drained.failure, Some(TransportError::ConnectionClosed)));
}

/// A drop of the duplex sink before close cancels the stream: the reply body
/// fails with `Cancelled` instead of a wait on a trailer that never arrives.
#[tokio::test]
async fn a_dropped_duplex_sink_fails_its_reply_body_cancelled() -> TestResult {
	let (client, _server) = duplex_echo_endpoints().await;

	let (mut sink, mut reply) = client.handle.open_duplex()?;
	sink.push(b"first-chunk").await?;
	sink.push(b"second-chunk").await?;

	drop(sink);

	// Echoed chunks may already sit ahead of the cancel event, so drain to the
	// terminal outcome.
	let drained = drain_body(&mut reply).await;
	assert!(matches!(
		drained.failure,
		Some(TransportError::OperationFailed(TransportFailure::Cancelled))
	));
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

/// A [`BufferedGrantor`] that records the `(received, limit)` of each drain
/// report. The reader consults the grantor of a streaming body on a drain
/// report alone, so the record stays empty while the consumer parks.
#[derive(Default)]
struct RecordingGrantor {
	/// The policy that answers each report.
	policy: BufferedGrantor,
	/// The reports, in arrival order.
	reports: Mutex<Vec<(u64, u64)>>,
}

impl RecordingGrantor {
	/// The reports so far.
	fn reports(&self) -> Vec<(u64, u64)> {
		self.reports.lock().expect("a report holds the lock without a panic").to_vec()
	}
}

impl CreditGrantor for RecordingGrantor {
	fn replenish(&self, stream_id: StreamId, received: u64, limit: u64) -> Option<u64> {
		self.reports
			.lock()
			.expect("a report holds the lock without a panic")
			.push((received, limit));
		self.policy.replenish(stream_id, received, limit)
	}
}

/// A link whose server grants one chunk of initial credit per stream and takes
/// its replenishment from `grantor`.
async fn one_credit_link(grantor: Arc<RecordingGrantor>) -> MuxLink {
	let server_offer = chunked_offer(4).with_initial_stream_credit(1);
	let transports = establish_transports(Some(chunked_offer(4)), Some(server_offer)).await;
	let (client, server) = transports.expect("the pinned client completes its handshake");
	let config = MuxEndpointConfig { grantor: Some(grantor), ..MuxEndpointConfig::default() };

	let client = spawn_mux_endpoint(client, MuxRole::Client);
	let (client, _client_responder) = client.expect("the handshake negotiates multiplexing");
	let server = spawn_mux_endpoint_with(server, MuxRole::Server, config);
	let (server, responder) = server.expect("the handshake negotiates multiplexing");
	MuxLink { client, server, responder }
}

/// End-to-end backpressure: with one chunk of initial credit and a parked
/// consumer, the client's push stalls. Grants follow only from the consumer's
/// drain, so the handler's release resumes the transfer.
///
/// - The ack of a ping fences the stall, because the reader acts on every record ahead of the probe.
/// - The first drain report shows the initial credit of one chunk as the limit of the push.
#[tokio::test]
async fn a_slow_consumer_stalls_the_push_until_it_drains() -> TestResult {
	let grantor = Arc::new(RecordingGrantor::default());
	let mux = one_credit_link(Arc::clone(&grantor)).await;
	let started = Arc::new(HandlerSignal::default());
	let release = Arc::new(Notify::new());
	let handler = gated_streaming_echo(Arc::clone(&started), Arc::clone(&release));
	let _serve = tokio::spawn(mux.responder.serve_streaming(handler));

	let frame = large_mux_frame("mux-streaming-backpressure");
	let payload = frame.to_der()?;
	let (mut sink, response) = mux.client.handle.open_stream()?;
	let transfer = tokio::spawn(async move {
		sink.push(&payload).await?;
		sink.close().await
	});

	started.raised().await;

	mux.client.handle.ping().await?;
	assert_eq!((transfer.is_finished(), grantor.reports()), (false, Vec::new()));

	release.notify_one();

	joined(transfer).await?;
	let echoed = response.await?;
	assert_eq!((grantor.reports().first().copied(), echoed), (Some((1, 1)), Some(frame)));
	Ok(())
}

/// The pings of the conversation in [`exchange_pings`], in the order they go
/// out.
const PINGS: [&[u8]; 3] = [b"ping-one", b"ping-two", b"ping-three"];

/// The ping that closes the conversation in [`exchange_pings`].
const FINAL_PING: &[u8] = b"ping-final";

/// Pushes each of [`PINGS`] and awaits its echoed reply before the next push,
/// then closes with [`FINAL_PING`] and reads the reply to its end.
///
/// The result is each reply chunk in the order it arrived, beside the chunk
/// that ends the reply body.
async fn exchange_pings(mut sink: RequestSink, mut reply: StreamBody) -> (Vec<Option<Vec<u8>>>, Option<Vec<u8>>) {
	let mut pongs = Vec::new();
	for ping in PINGS {
		sink.push(ping).await.expect("a ping goes out");
		pongs.push(reply.chunk().await.expect("the reply body reads its next chunk"));
	}

	sink.close_with(FINAL_PING).await.expect("the final ping goes out");
	pongs.push(reply.chunk().await.expect("the reply body reads its next chunk"));

	let terminal = reply.chunk().await.expect("the reply body reads its end");
	(pongs, terminal)
}

/// Eager pushes make duplex conversational: an exchange that awaits each
/// echoed reply between pushes must progress chunk for chunk, not park on a
/// held-back record, and `close_with` flags the final chunk itself, so the
/// reply ends on its `Ok` trailer after the last pong.
#[tokio::test]
async fn a_duplex_exchange_awaits_each_reply_between_pushes() -> TestResult {
	let (client, _server) = duplex_echo_endpoints().await;
	let (sink, reply) = client.handle.open_duplex()?;

	let exchange = exchange_pings(sink, reply);
	let transcript = within_hang_guard(exchange, "the duplex exchange ends within the hang guard").await;
	assert_eq!(
		transcript,
		(
			vec![
				Some(b"ping-one".to_vec()),
				Some(b"ping-two".to_vec()),
				Some(b"ping-three".to_vec()),
				Some(b"ping-final".to_vec()),
			],
			None,
		)
	);
	Ok(())
}

/// The collection sugar runs end to end: `close_with` carries the final
/// request chunk, and `into_frame` reassembles the chunked reply.
#[tokio::test]
async fn a_duplex_reply_collects_into_its_frame() -> TestResult {
	let (client, _server) = duplex_echo_endpoints().await;

	let frame = large_mux_frame("mux-duplex-into-frame");
	let payload = frame.to_der()?;
	let middle = payload.len() / 2;

	let (mut sink, reply) = client.handle.open_duplex()?;
	sink.push(&payload[..middle]).await?;
	sink.close_with(&payload[middle..]).await?;

	let echoed = reply.into_frame().await?;
	assert_eq!(echoed, frame);
	Ok(())
}
