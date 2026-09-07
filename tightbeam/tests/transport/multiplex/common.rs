//! Multiplex transport test fixtures.

use core::future::{poll_fn, Future};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use core::task::Poll;
use core::time::Duration;
use std::net::SocketAddr;
use std::sync::Arc;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::der::{Decode, Encode};
use tightbeam::policy::TransitStatus;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::{
	CancelReason, GoAwayPackage, GoAwayReason, MuxCancelPackage, MuxEndPackage, MuxEnvelope, MuxOpenPackage,
	MuxStreamKind, MUX_APPLICATION_CODE_FLOOR,
};
use tightbeam::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, MuxSettings, TransportAuthorizer, TransportOffer,
};
use tightbeam::transport::multiplex::{
	CreditGrantor, MuxAcceptor, MuxConnector, MuxHandle, MuxResponder, MuxRole, MuxTransport, ReplySink, RequestSink,
	SpawnedMux, StreamBody, StreamId,
};
use tightbeam::transport::tcp::r#async::{
	TcpTransport, TokioListener, TokioReadHalf, TokioStream, TokioWriteHalf, TransportReader, TransportWriter,
};
use tightbeam::transport::{
	EncryptedMessageIO, EnvelopeSink, EnvelopeSource, ResponsePackage, TransportEnvelope, TransportError,
	TransportFailure,
};
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::{Frame, TightBeamError};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::common::security::{expectation_failure, ServerMaterials};
use crate::transport::support::{
	await_ok, bind_encrypted_listener, connect_pinned_client, join_task, mux_frame, mux_offer,
	serve_one_handshake_message,
};

pub type SplitReader = TransportReader<TokioReadHalf>;
pub type SplitWriter = TransportWriter<TokioWriteHalf>;
pub type EmitTask = JoinHandle<Result<Option<Frame>, TransportError>>;
pub type ServeTask = JoinHandle<Result<(), TransportError>>;
pub type HandlerFuture = Pin<Box<dyn Future<Output = ResponsePackage> + Send>>;
pub type StatusFuture = Pin<Box<dyn Future<Output = TransitStatus> + Send>>;

pub fn large_mux_frame(label: &str) -> Frame {
	// Sized so the encoded frame spans roughly fifteen 1024-byte chunks,
	// enough to cross the rekey record limits the drain scenarios configure.
	let padding = "x".repeat(15000);
	mux_frame(&format!("{label}-{padding}"))
}

pub fn chunked_offer(cap: u32) -> TransportOffer {
	mux_offer(cap).with_chunk_payload_size(1024)
}

pub fn client_stream_id(index: u32) -> u32 {
	index * 2 + 1
}

pub async fn establish_transports(
	client_offer: Option<TransportOffer>,
	server_offer: Option<TransportOffer>,
) -> Result<(TcpTransport<TokioStream>, TcpTransport<TokioStream>), TightBeamError> {
	let materials = ServerMaterials::generate();
	let (listener, addr) = bind_encrypted_listener(&materials).await?;

	let server_task = tokio::spawn(async move {
		let (mut transport, _) = listener.accept().await?;
		if let Some(offer) = server_offer {
			transport = transport.with_mux_offer(Some(offer));
		}

		// ECIES is exactly two client messages: ClientHello, ClientKeyExchange.
		serve_one_handshake_message(&mut transport).await?;
		serve_one_handshake_message(&mut transport).await?;
		Ok::<_, TightBeamError>(transport)
	});

	let mut client = connect_pinned_client(addr, &materials.certificate).await?;
	if let Some(offer) = client_offer {
		client = client.with_mux_offer(Some(offer));
	}

	client.perform_client_handshake().await?;

	let server = await_ok(server_task, "server handshake task must not panic").await?;
	Ok((client, server))
}

pub struct MuxEndpoint {
	pub handle: MuxHandle,
	pub _reader_task: JoinHandle<()>,
}

/// Per-endpoint limits for hardening scenarios.
#[derive(Default)]
pub struct MuxEndpointConfig {
	pub rekey_limit: Option<u64>,
	pub cancel_budget: Option<u32>,
	pub grantor: Option<Arc<dyn CreditGrantor>>,
	pub rekey: bool,
	pub renewal_deadline: Option<Duration>,
}

/// Shared tail of encrypted and cleartext endpoint constructors.
pub fn spawn_mux_tasks<R, W>(mut mux: MuxTransport<R, W>, cancel_budget: Option<u32>) -> (MuxEndpoint, MuxResponder)
where
	R: EnvelopeSource + Send + 'static,
	W: EnvelopeSink + Send + 'static,
{
	if let Some(budget) = cancel_budget {
		mux = mux.with_cancel_budget(budget);
	}

	let SpawnedMux { handle, responder, reader_task } = mux.spawn();
	let endpoint = MuxEndpoint { handle, _reader_task: reader_task };

	(endpoint, responder)
}

pub fn spawn_mux_endpoint_with(
	mut transport: TcpTransport<TokioStream>,
	role: MuxRole,
	config: MuxEndpointConfig,
) -> Result<(MuxEndpoint, MuxResponder), TightBeamError> {
	let settings = transport
		.negotiated_mux()
		.ok_or_else(|| expectation_failure("handshake must negotiate multiplexing"))?;

	let mut rekey = None;
	if config.rekey {
		rekey = match role {
			MuxRole::Client => MuxConnector::take_rekey(&mut transport)?,
			MuxRole::Server => MuxAcceptor::take_rekey(&mut transport)?,
		};
	}

	let (reader, mut writer) = transport.into_split()?;
	if let Some(limit) = config.rekey_limit {
		writer = writer.with_rekey_limit(limit);
	}

	let mut mux = MuxTransport::new(reader, writer, role, settings);
	if let Some(grantor) = config.grantor {
		mux = mux.with_credit_grantor(grantor);
	}
	if let Some(context) = rekey {
		mux = mux.with_rekey(context);
	}
	if let Some(deadline) = config.renewal_deadline {
		mux = mux.with_renewal_deadline(deadline);
	}

	let endpoint_pair = spawn_mux_tasks(mux, config.cancel_budget);
	Ok(endpoint_pair)
}

pub fn spawn_mux_endpoint(
	transport: TcpTransport<TokioStream>,
	role: MuxRole,
) -> Result<(MuxEndpoint, MuxResponder), TightBeamError> {
	spawn_mux_endpoint_with(transport, role, MuxEndpointConfig::default())
}

pub fn spawn_cleartext_mux_endpoint(
	transport: TcpTransport<TokioStream>,
	role: MuxRole,
	settings: MuxSettings,
	cancel_budget: Option<u32>,
	trace: TraceCollector,
) -> Result<(MuxEndpoint, MuxResponder), TightBeamError> {
	let (reader, writer) = transport.with_trace(trace).into_split_cleartext()?;
	let mux = MuxTransport::new(reader, writer, role, settings);
	let endpoint_pair = spawn_mux_tasks(mux, cancel_budget);
	Ok(endpoint_pair)
}

pub async fn establish_cleartext_transports(
) -> Result<(TcpTransport<TokioStream>, TcpTransport<TokioStream>), TightBeamError> {
	let listener = TokioListener::<DefaultCryptoProvider>::bind("127.0.0.1:0").await?;
	let addr = listener.local_addr()?;

	let accept_task = tokio::spawn(async move {
		let (transport, _) = listener.accept().await?;
		Ok::<_, TightBeamError>(transport)
	});

	let stream = TcpStream::connect(addr).await?;
	let client_stream = TokioStream::from(stream);
	let client = TcpTransport::from(client_stream);

	let server = await_ok(accept_task, "cleartext accept task must not panic").await?;
	Ok((client, server))
}

/// Server-side trace entrypoint: the accepted connection carries the
/// collector, every downstream plane inherits it.
pub async fn accept_mux_server(
	listener: TokioListener,
	offer: TransportOffer,
	trace: TraceCollector,
) -> Result<(MuxEndpoint, MuxResponder), TightBeamError> {
	let (transport, _) = listener.accept().await?;
	let mut transport = transport.with_mux_offer(Some(offer)).with_trace(trace);

	// ECIES is exactly two client messages: ClientHello, ClientKeyExchange.
	serve_one_handshake_message(&mut transport).await?;
	serve_one_handshake_message(&mut transport).await?;

	spawn_mux_endpoint(transport, MuxRole::Server)
}

pub async fn start_mux_server<H, Fut>(
	materials: &ServerMaterials,
	cap: u32,
	handler: H,
	trace: TraceCollector,
) -> Result<(JoinHandle<()>, SocketAddr), TightBeamError>
where
	H: Fn(Arc<Frame>) -> Fut + Send + Sync + 'static,
	Fut: Future<Output = ResponsePackage> + Send,
{
	let (listener, addr) = bind_encrypted_listener(materials).await?;
	let serve_task = tokio::spawn(async move {
		let Ok((_endpoint, responder)) = accept_mux_server(listener, mux_offer(cap), trace).await else {
			return;
		};
		let _ = responder.serve(handler).await;
	});

	Ok((serve_task, addr))
}

pub struct MuxClient {
	pub endpoint: MuxEndpoint,
	pub responder: MuxResponder,
	pub settings: MuxSettings,
}

impl MuxClient {
	pub fn handle(&self) -> &MuxHandle {
		&self.endpoint.handle
	}
}

/// Client-side trace entrypoint: the connection carries the collector,
/// every downstream plane inherits it.
pub async fn connect_mux_client(
	addr: SocketAddr,
	materials: &ServerMaterials,
	cap: u32,
	trace: TraceCollector,
) -> Result<MuxClient, TightBeamError> {
	let client = connect_pinned_client(addr, &materials.certificate).await?;
	let mut client = client.with_mux_offer(Some(mux_offer(cap))).with_trace(trace);
	client.perform_client_handshake().await?;

	let settings = client
		.negotiated_mux()
		.ok_or_else(|| expectation_failure("client must negotiate multiplexing"))?;
	let (endpoint, responder) = spawn_mux_endpoint(client, MuxRole::Client)?;
	Ok(MuxClient { endpoint, responder, settings })
}

/// Muxed client against raw server halves (test owns wire ordering).
pub struct ClientMuxServerRaw {
	pub client: MuxEndpoint,
	pub server_reader: SplitReader,
	pub server_writer: SplitWriter,
}

pub async fn establish_client_mux_server_raw_with(
	client_offer: TransportOffer,
	server_offer: TransportOffer,
	trace: TraceCollector,
) -> Result<ClientMuxServerRaw, TightBeamError> {
	let (client, server) = establish_transports(Some(client_offer), Some(server_offer)).await?;
	let (client_end, _client_responder) = spawn_mux_endpoint(client.with_trace(trace), MuxRole::Client)?;
	let (server_reader, server_writer) = server.into_split()?;

	Ok(ClientMuxServerRaw { client: client_end, server_reader, server_writer })
}

pub async fn establish_client_mux_server_raw(
	cap: u32,
	trace: TraceCollector,
) -> Result<ClientMuxServerRaw, TightBeamError> {
	establish_client_mux_server_raw_with(mux_offer(cap), mux_offer(cap), trace).await
}

pub async fn raw_echo_roundtrip(link: &mut ClientMuxServerRaw, frame: &Frame) -> Result<bool, TightBeamError> {
	let emit_task = spawn_emit(&link.client.handle, frame.to_owned());
	let (stream_id, message) = read_muxed_request(&mut link.server_reader).await?;
	write_muxed_echo(&mut link.server_writer, stream_id, &message).await?;

	let echoed = await_ok(emit_task, "echo emit task must not panic").await?;
	Ok(is_echo(echoed, frame))
}

/// Muxed server against raw client halves (test drives requests on the wire).
pub struct ServerMuxClientRaw {
	pub server: MuxEndpoint,
	pub responder: MuxResponder,
	pub client_reader: SplitReader,
	pub client_writer: SplitWriter,
}

pub fn split_server_mux_client_raw(
	client: TcpTransport<TokioStream>,
	server: TcpTransport<TokioStream>,
	server_config: MuxEndpointConfig,
	trace: TraceCollector,
) -> Result<ServerMuxClientRaw, TightBeamError> {
	let (server_end, responder) = spawn_mux_endpoint_with(server.with_trace(trace), MuxRole::Server, server_config)?;
	let (client_reader, client_writer) = client.into_split()?;
	Ok(ServerMuxClientRaw { server: server_end, responder, client_reader, client_writer })
}

pub async fn establish_server_mux_client_raw_with(
	client_offer: TransportOffer,
	server_offer: TransportOffer,
	server_config: MuxEndpointConfig,
	trace: TraceCollector,
) -> Result<ServerMuxClientRaw, TightBeamError> {
	let (client, server) = establish_transports(Some(client_offer), Some(server_offer)).await?;
	split_server_mux_client_raw(client, server, server_config, trace)
}

pub async fn establish_server_mux_client_raw(
	client_cap: u32,
	server_cap: u32,
	server_config: MuxEndpointConfig,
	trace: TraceCollector,
) -> Result<ServerMuxClientRaw, TightBeamError> {
	establish_server_mux_client_raw_with(mux_offer(client_cap), mux_offer(server_cap), server_config, trace).await
}

pub struct MuxPair {
	pub client: MuxEndpoint,
	pub server: MuxEndpoint,
	pub _server_serve: ServeTask,
}

pub fn spawn_echo_pair_with(
	client: TcpTransport<TokioStream>,
	server: TcpTransport<TokioStream>,
	client_config: MuxEndpointConfig,
	server_config: MuxEndpointConfig,
	trace: TraceCollector,
) -> Result<MuxPair, TightBeamError> {
	let (client_end, _client_responder) =
		spawn_mux_endpoint_with(client.with_trace(trace.share()), MuxRole::Client, client_config)?;
	let (server_end, server_responder) =
		spawn_mux_endpoint_with(server.with_trace(trace), MuxRole::Server, server_config)?;

	Ok(MuxPair {
		client: client_end,
		server: server_end,
		_server_serve: spawn_immediate_echo(server_responder),
	})
}

pub fn spawn_echo_pair(
	client: TcpTransport<TokioStream>,
	server: TcpTransport<TokioStream>,
	server_config: MuxEndpointConfig,
	trace: TraceCollector,
) -> Result<MuxPair, TightBeamError> {
	spawn_echo_pair_with(client, server, MuxEndpointConfig::default(), server_config, trace)
}

pub async fn establish_echo_pair(
	client_offer: TransportOffer,
	server_offer: TransportOffer,
	server_config: MuxEndpointConfig,
	trace: TraceCollector,
) -> Result<MuxPair, TightBeamError> {
	let (client, server) = establish_transports(Some(client_offer), Some(server_offer)).await?;
	spawn_echo_pair(client, server, server_config, trace)
}

pub fn echo_response(frame: &Arc<Frame>) -> ResponsePackage {
	ResponsePackage::new(TransitStatus::Ok, Some(Frame::clone(frame)))
}

/// Terminal outcome of a fully drained [`StreamBody`].
pub struct DrainedBody {
	/// Every chunk's bytes, in arrival order.
	pub bytes: Vec<u8>,
	/// Chunks consumed before the terminal event.
	pub chunks: usize,
	/// The failure that ended the body, `None` on a clean end.
	pub failure: Option<TransportError>,
}

/// Drain a stream body to its terminal outcome, collecting chunks.
pub async fn drain_body(body: &mut StreamBody) -> DrainedBody {
	let mut bytes = Vec::new();
	let mut chunks = 0usize;
	loop {
		match body.chunk().await {
			Ok(Some(chunk)) => {
				chunks += 1;
				bytes.extend_from_slice(&chunk);
			}
			Ok(None) => return DrainedBody { bytes, chunks, failure: None },
			Err(err) => return DrainedBody { bytes, chunks, failure: Some(err) },
		}
	}
}

/// Whether a counting handler observed a chunked (multi-record) body.
pub fn saw_multiple_chunks(counter: &AtomicUsize) -> bool {
	counter.load(Ordering::SeqCst) > 1
}

/// Echo of a body reassembled from streamed chunks.
pub fn echo_reassembled(buffer: &[u8]) -> ResponsePackage {
	match Frame::from_der(buffer) {
		Ok(frame) => ResponsePackage::new(TransitStatus::Ok, Some(frame)),
		Err(_) => ResponsePackage::new(TransitStatus::InvalidArgument, None),
	}
}

/// Streaming echo handler: consumes the body chunk by chunk, counts
/// arrivals, then echoes the reassembled frame.
pub fn streaming_echo_handler(chunks_seen: Arc<AtomicUsize>) -> impl Fn(StreamBody) -> HandlerFuture {
	move |mut body| {
		let counter = Arc::clone(&chunks_seen);
		Box::pin(async move {
			let drained = drain_body(&mut body).await;

			counter.fetch_add(drained.chunks, Ordering::SeqCst);

			if drained.failure.is_some() {
				return ResponsePackage::new(TransitStatus::Cancelled, None);
			}

			echo_reassembled(&drained.bytes)
		})
	}
}

/// Push a payload through a request sink as two chunks, then close:
/// the smallest sequence exercising the held-back `last` framing.
pub async fn push_split(mut sink: RequestSink, payload: &[u8]) -> Result<(), TransportError> {
	let middle = payload.len() / 2;
	sink.push(&payload[..middle]).await?;
	sink.push(&payload[middle..]).await?;

	sink.close().await
}

/// Duplex echo handler: streams every request chunk straight back,
/// counting arrivals, and ends the reply with the trailer status.
pub fn duplex_echo_handler(chunks_seen: Arc<AtomicUsize>) -> impl Fn(StreamBody, ReplySink) -> StatusFuture {
	move |mut body, mut reply| {
		let counter = Arc::clone(&chunks_seen);
		Box::pin(async move {
			loop {
				match body.chunk().await {
					Ok(Some(chunk)) => {
						counter.fetch_add(1, Ordering::SeqCst);
						if reply.push(&chunk).await.is_err() {
							return TransitStatus::Cancelled;
						}
					}
					Ok(None) => return TransitStatus::Ok,
					Err(_) => return TransitStatus::Cancelled,
				}
			}
		})
	}
}

pub fn gated_echo_handler(started: Arc<Notify>, release: Arc<Notify>) -> impl Fn(Arc<Frame>) -> HandlerFuture {
	move |frame| {
		let started = Arc::clone(&started);
		let release = Arc::clone(&release);
		Box::pin(async move {
			started.notify_one();
			release.notified().await;
			echo_response(&frame)
		})
	}
}

pub fn spawn_gated_echo(responder: MuxResponder) -> (Arc<Notify>, Arc<Notify>, ServeTask) {
	let started = Arc::new(Notify::new());
	let release = Arc::new(Notify::new());
	let handler = gated_echo_handler(Arc::clone(&started), Arc::clone(&release));

	(started, release, tokio::spawn(responder.serve(handler)))
}

pub struct GatedMuxContext {
	pub materials: ServerMaterials,
	pub started: Notify,
	pub release: Notify,
}

impl GatedMuxContext {
	pub fn generate() -> Self {
		Self {
			materials: ServerMaterials::generate(),
			started: Notify::new(),
			release: Notify::new(),
		}
	}
}

pub fn gated_echo(ctx: Arc<GatedMuxContext>) -> impl Fn(Arc<Frame>) -> HandlerFuture {
	move |frame| {
		let ctx = Arc::clone(&ctx);
		Box::pin(async move {
			ctx.started.notify_one();
			ctx.release.notified().await;
			echo_response(&frame)
		})
	}
}

pub fn immediate_echo_handler() -> impl Fn(Arc<Frame>) -> core::future::Ready<ResponsePackage> {
	|frame| core::future::ready(echo_response(&frame))
}

pub fn spawn_immediate_echo(responder: MuxResponder) -> ServeTask {
	tokio::spawn(responder.serve(immediate_echo_handler()))
}

/// Hold `held_frame` until a different frame arrives (then release the hold).
pub fn order_forcing_echo(held_frame: Frame, gate: Arc<Notify>) -> impl Fn(Arc<Frame>) -> HandlerFuture {
	move |frame: Arc<Frame>| {
		let held_frame = held_frame.to_owned();
		let gate = Arc::clone(&gate);
		Box::pin(async move {
			if *frame == held_frame {
				gate.notified().await;
			} else {
				gate.notify_one();
			}

			echo_response(&frame)
		})
	}
}

/// Cancel-abort fixture; drop witness records handler abort.
pub struct AbortContext {
	pub materials: ServerMaterials,
	pub started: Notify,
	pub never: Notify,
	pub aborted: AtomicBool,
	pub calls: AtomicU32,
}

impl AbortContext {
	pub fn generate() -> Self {
		Self {
			materials: ServerMaterials::generate(),
			started: Notify::new(),
			never: Notify::new(),
			aborted: AtomicBool::new(false),
			calls: AtomicU32::new(0),
		}
	}
}

pub fn first_parks_then_echo(ctx: Arc<AbortContext>) -> impl Fn(Arc<Frame>) -> HandlerFuture {
	move |frame: Arc<Frame>| {
		let ctx = Arc::clone(&ctx);
		Box::pin(async move {
			if ctx.calls.fetch_add(1, Ordering::SeqCst) == 0 {
				let _witness = DropWitness(Arc::clone(&ctx));
				ctx.started.notify_one();
				ctx.never.notified().await;
			}

			echo_response(&frame)
		})
	}
}

pub fn spawn_emit(handle: &MuxHandle, frame: Frame) -> EmitTask {
	let handle = handle.to_owned();
	tokio::spawn(async move { handle.emit_on_stream(&frame).await })
}

/// Abort an in-flight emit. Drop guard removes pending and queues MuxCancel.
pub async fn abort_emit(task: EmitTask) {
	task.abort();

	let join = task.await;
	assert!(
		join.is_err_and(|error| error.is_cancelled()),
		"aborted emit task must report cancellation"
	);
}

pub async fn read_muxed_request<R: EnvelopeSource>(reader: &mut R) -> Result<(u32, Arc<Frame>), TightBeamError> {
	let envelope = reader.read_envelope().await?;
	match envelope {
		TransportEnvelope::Mux(MuxEnvelope::Open(package)) if package.last() => {
			let frame = Frame::from_der(package.payload())?;
			Ok((package.stream_id(), Arc::new(frame)))
		}
		_ => Err(expectation_failure("peer must receive a single-chunk muxed open")),
	}
}

pub async fn read_muxed_request_id<R: EnvelopeSource>(reader: &mut R) -> Result<u32, TightBeamError> {
	let (stream_id, _frame) = read_muxed_request(reader).await?;
	Ok(stream_id)
}

pub async fn expect_muxed_request(
	reader: &mut SplitReader,
	expected_id: u32,
	msg: &'static str,
) -> Result<Arc<Frame>, TightBeamError> {
	let (stream_id, frame) = read_muxed_request(reader).await?;
	if stream_id != expected_id {
		return Err(expectation_failure(msg));
	}

	Ok(frame)
}

pub fn muxed_request_envelope(stream_id: u32, frame: Frame) -> Result<TransportEnvelope, TightBeamError> {
	let payload = frame.to_der()?;
	Ok(MuxOpenPackage::new(stream_id, true, MuxStreamKind::Unary, payload)?.into())
}

pub async fn write_muxed_request<W: EnvelopeSink>(
	writer: &mut W,
	stream_id: u32,
	frame: Frame,
) -> Result<(), TightBeamError> {
	writer.write_envelope(muxed_request_envelope(stream_id, frame)?).await?;
	Ok(())
}

pub async fn write_muxed_end(
	writer: &mut SplitWriter,
	stream_id: u32,
	status: TransitStatus,
	payload: Vec<u8>,
) -> Result<(), TightBeamError> {
	let response = MuxEndPackage::new(stream_id, status, payload)?;
	writer.write_envelope(response.into()).await?;
	Ok(())
}

pub async fn write_muxed_echo(
	writer: &mut SplitWriter,
	stream_id: u32,
	frame: &Arc<Frame>,
) -> Result<(), TightBeamError> {
	let payload = frame.as_ref().to_der()?;
	write_muxed_end(writer, stream_id, TransitStatus::Ok, payload).await
}

pub async fn write_goaway(
	writer: &mut SplitWriter,
	last_stream_id: u32,
	reason: GoAwayReason,
) -> Result<(), TightBeamError> {
	let package = GoAwayPackage::new(last_stream_id, reason);
	writer.write_envelope(package.into()).await?;
	Ok(())
}

/// Write a muxed request then its cancel (Rapid Reset open/cancel pair).
pub async fn write_open_cancel<W: EnvelopeSink>(
	writer: &mut W,
	stream_id: u32,
	frame: Frame,
) -> Result<(), TightBeamError> {
	write_muxed_request(writer, stream_id, frame).await?;
	let cancel = MuxCancelPackage::new(stream_id, CancelReason::Cancelled);
	writer.write_envelope(cancel.into()).await?;
	Ok(())
}

pub fn is_muxed_response(envelope: &TransportEnvelope, stream_id: u32) -> bool {
	matches!(
		envelope,
		TransportEnvelope::Mux(MuxEnvelope::End(package)) if package.stream_id() == stream_id
	)
}

/// Poll `shutdown` once so GoAway is sent and the allocator halts, then
/// return the pinned future for the caller to await the drain.
pub async fn kick_shutdown(
	handle: &MuxHandle,
) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
	let mut shutdown_future = Box::pin(handle.shutdown());
	poll_fn(|cx| {
		let _ = shutdown_future.as_mut().poll(cx);
		Poll::Ready(())
	})
	.await;

	shutdown_future
}

pub fn is_echo(result: Option<Frame>, expected: &Frame) -> bool {
	result.as_ref() == Some(expected)
}

pub fn is_streams_exhausted(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(result, Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted)))
}

pub fn is_busy(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(
		result,
		Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted))
	)
}

pub fn is_draining(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(result, Err(TransportError::Draining))
}

pub fn is_connection_closed(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(result, Err(TransportError::ConnectionClosed))
}

pub fn is_invalid_message<T>(result: &Result<T, TransportError>) -> bool {
	matches!(result, Err(TransportError::InvalidMessage))
}

pub fn is_policy_rejection(result: &Result<(), TransportError>) -> bool {
	matches!(result, Err(TransportError::OperationFailed(TransportFailure::PolicyRejection)))
}

pub fn is_budget_exhausted(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(result, Err(TransportError::OperationFailed(TransportFailure::BudgetExhausted)))
}

pub async fn read_remaining_chunks(
	reader: &mut SplitReader,
	stream_id: u32,
	mut payload: Vec<u8>,
) -> Result<Vec<u8>, TightBeamError> {
	loop {
		let envelope = reader.read_envelope().await?;
		let TransportEnvelope::Mux(MuxEnvelope::Data(package)) = envelope else {
			return Err(expectation_failure("sender must continue with data chunks"));
		};
		if package.stream_id() != stream_id {
			return Err(expectation_failure("continuation chunks must stay on their stream"));
		}

		payload.extend_from_slice(package.payload());

		if package.last() {
			return Ok(payload);
		}
	}
}

/// Skip stream traffic until GoAway(`reason`).
pub async fn read_until_goaway(reader: &mut SplitReader, reason: GoAwayReason) -> Result<bool, TightBeamError> {
	timeout(Duration::from_secs(2), async {
		loop {
			let envelope = reader.read_envelope().await?;
			if let TransportEnvelope::Mux(MuxEnvelope::GoAway(package)) = &envelope {
				return Ok(package.reason() == reason);
			}
		}
	})
	.await
	.map_err(|_| expectation_failure("GoAway must arrive before the read timeout"))?
}

/// Poll `goaway_reason()` until `reason` or timeout.
pub async fn await_goaway_reason(handle: &MuxHandle, reason: GoAwayReason) -> bool {
	let observed = timeout(Duration::from_secs(2), async {
		while handle.goaway_reason() != Some(reason) {
			sleep(Duration::from_millis(5)).await;
		}
	})
	.await;

	observed.is_ok()
}

/// Receiver policy that never raises a stream's limit, pinning the
/// sender to the initial credit window.
pub struct NeverGrant;

impl CreditGrantor for NeverGrant {
	fn replenish(&self, _stream_id: StreamId, _received: u64, _limit: u64) -> Option<u64> {
		None
	}
}

/// Authorizer granting half of each requested budget direction.
pub struct HalvingAuthorizer;

impl TransportAuthorizer for HalvingAuthorizer {
	fn authorize<'a>(
		&'a self,
		offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		Box::pin(async move {
			let granted = offer.requested_budgets.map(|budgets| MuxBudgets {
				client_to_server: budgets.client_to_server / 2,
				server_to_client: budgets.server_to_client / 2,
			});

			Ok(AuthorizationGrant::from(granted))
		})
	}
}

/// Application refusal code carried by [`RefusingAuthorizer`].
pub const REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR;

pub struct RefusingAuthorizer;

impl TransportAuthorizer for RefusingAuthorizer {
	fn authorize<'a>(
		&'a self,
		_offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		Box::pin(async move { Err(AuthorizationRefusal { code: REFUSAL_CODE }) })
	}
}

/// Authorizer whose backend never responds, simulating a hung
/// authorization service on the unauthenticated handshake path.
pub struct HangingAuthorizer;

impl TransportAuthorizer for HangingAuthorizer {
	fn authorize<'a>(
		&'a self,
		_offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		Box::pin(core::future::pending())
	}
}

pub fn is_goaway(envelope: &TransportEnvelope, reason: GoAwayReason, last_stream_id: Option<u32>) -> bool {
	match envelope {
		TransportEnvelope::Mux(MuxEnvelope::GoAway(package)) => {
			let reason_ok = package.reason() == reason;
			let last_ok = match last_stream_id {
				Some(expected) => package.last_stream_id() == expected,
				None => true,
			};

			reason_ok && last_ok
		}
		_ => false,
	}
}

/// Observes abort of an in-flight handler: flag flips only on cancellation.
pub struct DropWitness(pub Arc<AbortContext>);

impl Drop for DropWitness {
	fn drop(&mut self) {
		self.0.aborted.store(true, Ordering::SeqCst);
	}
}

/// One rekey headroom case:
/// `drain_headroom = 2 * (local_cap + peer_cap) + 1`.
pub struct RekeyCase {
	pub server_local_cap: u32,
	pub server_peer_cap: u32,
	pub rekey_limit: u64,
}

impl RekeyCase {
	pub fn headroom(&self) -> u64 {
		u64::from(self.server_local_cap)
			.saturating_add(u64::from(self.server_peer_cap))
			.saturating_mul(2)
			.saturating_add(1)
	}

	pub fn responses_before_goaway(&self) -> u32 {
		let headroom = self.headroom();
		debug_assert!(self.rekey_limit > headroom);
		(self.rekey_limit - headroom) as u32
	}
}

/// Budget + 1 Rapid Reset pairs -> GoAway(EnhanceYourCalm) + PolicyRejection.
///
/// Verifies the wire answer (reason and abuse watermark) inline and returns
/// whether the responder surfaced a policy rejection.
pub async fn run_cancel_abuse<R, W>(
	mut client_reader: R,
	mut client_writer: W,
	responder: MuxResponder,
	cancel_budget: u32,
) -> Result<bool, TightBeamError>
where
	R: EnvelopeSource,
	W: EnvelopeSink,
{
	// Handlers park forever so every cancel aborts a live handler.
	let (_started, _never_released, serve_task) = spawn_gated_echo(responder);

	let stream_ids: Vec<u32> = (0..=cancel_budget).map(client_stream_id).collect();
	let abuse_stream_id = client_stream_id(cancel_budget);
	let frame = mux_frame("mux-abuse");
	for stream_id in stream_ids {
		write_open_cancel(&mut client_writer, stream_id, frame.to_owned()).await?;
	}

	let goaway = client_reader.read_envelope().await?;
	assert!(
		is_goaway(&goaway, GoAwayReason::EnhanceYourCalm, Some(abuse_stream_id)),
		"cancel abuse must be answered with GoAway(EnhanceYourCalm) at the abuse watermark"
	);

	let refused = join_task(serve_task, "responder task must not panic").await?;
	Ok(is_policy_rejection(&refused))
}

pub struct ServerInitContext {
	pub materials: ServerMaterials,
	pub done: Notify,
}

impl ServerInitContext {
	pub fn generate() -> Self {
		Self { materials: ServerMaterials::generate(), done: Notify::new() }
	}
}

/// `handler_calls` proves pings bypass the responder.
pub struct PingContext {
	pub materials: ServerMaterials,
	pub handler_calls: AtomicU32,
	pub server_ping_done: Notify,
}

impl PingContext {
	pub fn generate() -> Self {
		Self {
			materials: ServerMaterials::generate(),
			handler_calls: AtomicU32::new(0),
			server_ping_done: Notify::new(),
		}
	}
}
