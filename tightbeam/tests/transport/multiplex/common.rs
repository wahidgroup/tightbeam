//! Multiplex transport test fixtures.

use core::future::{pending, poll_fn, Future, Pending};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use core::task::Poll;
use core::time::Duration;
use std::net::SocketAddr;
use std::sync::Arc;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::der::{Decode, Encode};
use tightbeam::policy::{SessionContext, TransitStatus};
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
use tightbeam::transport::EndpointConfig;
use tightbeam::transport::{
	EncryptedMessageIO, EnvelopeSink, EnvelopeSource, ResponsePackage, TransportEnvelope, TransportError,
	TransportFailure,
};
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::{Frame, TightBeamError};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::common::security::{expectation_failure, ServerMaterials};
use crate::transport::support::{
	await_ok, await_transport, bind_encrypted_listener, connect_pinned_client, join_task, mux_frame, mux_offer,
	serve_one_handshake_message,
};

/// Receive half of a split TCP test transport.
pub type SplitReader = TransportReader<TokioReadHalf>;
/// Send half of a split TCP test transport.
pub type SplitWriter = TransportWriter<TokioWriteHalf>;
/// Spawned emit that resolves to the reply frame or the emit error.
pub type EmitTask = JoinHandle<Result<Option<Frame>, TransportError>>;
/// Spawned responder loop that resolves when serving ends.
pub type ServeTask = JoinHandle<Result<(), TransportError>>;
/// Boxed unary or streaming handler future that answers with a response.
pub type HandlerFuture = Pin<Box<dyn Future<Output = ResponsePackage> + Send>>;
/// Boxed duplex handler future that answers with the trailer status.
pub type StatusFuture = Pin<Box<dyn Future<Output = TransitStatus> + Send>>;

/// Frame labeled `label` whose encoding spans many mux chunks.
pub fn large_mux_frame(label: impl AsRef<str>) -> Frame {
	let label = label.as_ref();
	// Sized so the encoded frame spans roughly fifteen 1024-byte chunks,
	// enough to cross the rekey record limits the drain scenarios configure.
	let padding = "x".repeat(15000);
	mux_frame(format!("{label}-{padding}"))
}

/// Mux offer at `cap` streams with a 1024-byte chunk payload size.
pub fn chunked_offer(cap: u32) -> TransportOffer {
	mux_offer(cap).with_chunk_payload_size(1024)
}

/// The ID of the client-initiated stream at `index`, counting from zero.
pub fn client_stream_id(index: u32) -> u32 {
	index * 2 + 1
}

/// Complete an ECIES handshake between a pinned client and an encrypted
/// server, with each side's optional mux offer.
///
/// # Errors
///
/// The bind, connect, or handshake failure of either side.
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

/// A spawned mux endpoint.
pub struct MuxEndpoint {
	/// Handle that opens and emits on streams.
	pub handle: MuxHandle,
	/// Reader driver task, held so it runs for the endpoint's lifetime.
	pub _reader_task: JoinHandle<()>,
}

/// Per-endpoint limits for hardening scenarios.
#[derive(Default)]
pub struct MuxEndpointConfig {
	/// Send-cipher rekey record limit override for the writer half.
	pub rekey_limit: Option<u64>,
	/// Peer cancel budget override for the responder.
	pub cancel_budget: Option<u32>,
	/// Receiver-side credit policy override.
	pub grantor: Option<Arc<dyn CreditGrantor>>,
	/// Whether to attach the in-band rekey context.
	pub rekey: bool,
	/// Time budget override for one renewal exchange.
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

/// Split a handshaken transport into a spawned mux endpoint for `role`, with
/// every override in `config` applied.
///
/// # Errors
///
/// An expectation failure when the handshake negotiated no multiplexing, or
/// the rekey harvest or split failure.
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

/// Spawn a mux endpoint for `role` with the default configuration.
///
/// # Errors
///
/// The [`spawn_mux_endpoint_with`] set.
pub fn spawn_mux_endpoint(
	transport: TcpTransport<TokioStream>,
	role: MuxRole,
) -> Result<(MuxEndpoint, MuxResponder), TightBeamError> {
	spawn_mux_endpoint_with(transport, role, MuxEndpointConfig::default())
}

/// Spawn a cleartext mux endpoint for `role` under explicit `settings`,
/// because a cleartext transport negotiates none.
///
/// # Errors
///
/// The split failure of the transport.
pub fn spawn_cleartext_mux_endpoint(
	transport: TcpTransport<TokioStream>,
	role: MuxRole,
	settings: MuxSettings,
	cancel_budget: Option<u32>,
	trace: TraceCollector,
) -> Result<(MuxEndpoint, MuxResponder), TightBeamError> {
	let (reader, writer) = transport.with_trace(trace).into_split()?;
	let mux = MuxTransport::new(reader, writer, role, settings);
	let endpoint_pair = spawn_mux_tasks(mux, cancel_budget);
	Ok(endpoint_pair)
}

/// Connect a cleartext client to a cleartext listener and return both
/// transports.
///
/// # Errors
///
/// The bind, connect, or accept failure.
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
	let client = TcpTransport::new(client_stream, EndpointConfig::cleartext());

	let server = await_ok(accept_task, "cleartext accept task must not panic").await?;
	Ok((client, server))
}

/// Accept one encrypted mux server as the server-side trace entrypoint.
///
/// The accepted connection carries the collector, and every downstream plane
/// inherits it.
///
/// # Errors
///
/// The accept or handshake failure, or the [`spawn_mux_endpoint`] set.
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

/// Bind an encrypted listener and spawn a task that accepts one mux server
/// and serves `handler` on it.
///
/// # Errors
///
/// The bind failure of the listener.
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

/// A connected mux client with its negotiated settings.
pub struct MuxClient {
	/// Spawned client endpoint.
	pub endpoint: MuxEndpoint,
	/// Responder for peer-initiated streams on the client.
	pub responder: MuxResponder,
	/// Settings the handshake negotiated.
	pub settings: MuxSettings,
}

impl MuxClient {
	/// Handle of the client endpoint.
	pub fn handle(&self) -> &MuxHandle {
		&self.endpoint.handle
	}
}

/// Connect one encrypted mux client as the client-side trace entrypoint.
///
/// The connection carries the collector, and every downstream plane inherits
/// it.
///
/// # Errors
///
/// An expectation failure when the client negotiated no multiplexing, or the
/// connect, handshake, or spawn failure.
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

/// Muxed client against raw server halves, so the test owns wire ordering.
pub struct ClientMuxServerRaw {
	/// Muxed client endpoint.
	pub client: MuxEndpoint,
	/// Raw receive half of the server.
	pub server_reader: SplitReader,
	/// Raw send half of the server.
	pub server_writer: SplitWriter,
}

/// Build a [`ClientMuxServerRaw`] from explicit client and server offers.
///
/// # Errors
///
/// The [`establish_transports`] and [`spawn_mux_endpoint`] sets, or the split
/// failure of the server.
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

/// Build a [`ClientMuxServerRaw`] with both sides offering `cap` streams.
///
/// # Errors
///
/// The [`establish_client_mux_server_raw_with`] set.
pub async fn establish_client_mux_server_raw(
	cap: u32,
	trace: TraceCollector,
) -> Result<ClientMuxServerRaw, TightBeamError> {
	establish_client_mux_server_raw_with(mux_offer(cap), mux_offer(cap), trace).await
}

/// Emit `frame` from the muxed client, echo it from the raw server, and report
/// whether the echo matched.
///
/// # Errors
///
/// The read or write failure of the raw server, or a panicked emit task.
pub async fn raw_echo_roundtrip(link: &mut ClientMuxServerRaw, frame: &Frame) -> Result<bool, TightBeamError> {
	let emit_task = spawn_emit(&link.client.handle, frame.to_owned());
	let (stream_id, message) = read_muxed_request(&mut link.server_reader).await?;
	write_muxed_echo(&mut link.server_writer, stream_id, &message).await?;

	let echoed = await_ok(emit_task, "echo emit task must not panic").await?;
	Ok(is_echo(echoed, frame))
}

/// Muxed server against raw client halves, so the test drives requests on the
/// wire.
pub struct ServerMuxClientRaw {
	/// Muxed server endpoint.
	pub server: MuxEndpoint,
	/// Responder that serves the client's streams.
	pub responder: MuxResponder,
	/// Raw receive half of the client.
	pub client_reader: SplitReader,
	/// Raw send half of the client.
	pub client_writer: SplitWriter,
}

/// Spawn the muxed server and split the client into raw halves.
///
/// # Errors
///
/// The [`spawn_mux_endpoint_with`] set, or the split failure of the client.
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

/// Build a [`ServerMuxClientRaw`] from explicit client and server offers.
///
/// # Errors
///
/// The [`establish_transports`] and [`split_server_mux_client_raw`] sets.
pub async fn establish_server_mux_client_raw_with(
	client_offer: TransportOffer,
	server_offer: TransportOffer,
	server_config: MuxEndpointConfig,
	trace: TraceCollector,
) -> Result<ServerMuxClientRaw, TightBeamError> {
	let (client, server) = establish_transports(Some(client_offer), Some(server_offer)).await?;
	split_server_mux_client_raw(client, server, server_config, trace)
}

/// Build a [`ServerMuxClientRaw`] with each side offering its own cap.
///
/// # Errors
///
/// The [`establish_server_mux_client_raw_with`] set.
pub async fn establish_server_mux_client_raw(
	client_cap: u32,
	server_cap: u32,
	server_config: MuxEndpointConfig,
	trace: TraceCollector,
) -> Result<ServerMuxClientRaw, TightBeamError> {
	establish_server_mux_client_raw_with(mux_offer(client_cap), mux_offer(server_cap), server_config, trace).await
}

/// Two muxed endpoints with an echo responder serving the server side.
pub struct MuxPair {
	/// Muxed client endpoint.
	pub client: MuxEndpoint,
	/// Muxed server endpoint.
	pub server: MuxEndpoint,
	/// Echo responder task, held so it serves for the pair's lifetime.
	pub _server_serve: ServeTask,
}

/// Spawn both endpoints with their own configurations and start the server's
/// immediate echo.
///
/// # Errors
///
/// The [`spawn_mux_endpoint_with`] set of either side.
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

/// Spawn an echo pair whose client takes the default configuration.
///
/// # Errors
///
/// The [`spawn_echo_pair_with`] set.
pub fn spawn_echo_pair(
	client: TcpTransport<TokioStream>,
	server: TcpTransport<TokioStream>,
	server_config: MuxEndpointConfig,
	trace: TraceCollector,
) -> Result<MuxPair, TightBeamError> {
	spawn_echo_pair_with(client, server, MuxEndpointConfig::default(), server_config, trace)
}

/// Handshake both transports and spawn an echo pair over them.
///
/// # Errors
///
/// The [`establish_transports`] and [`spawn_echo_pair`] sets.
pub async fn establish_echo_pair(
	client_offer: TransportOffer,
	server_offer: TransportOffer,
	server_config: MuxEndpointConfig,
	trace: TraceCollector,
) -> Result<MuxPair, TightBeamError> {
	let (client, server) = establish_transports(Some(client_offer), Some(server_offer)).await?;
	spawn_echo_pair(client, server, server_config, trace)
}

/// An Ok response that carries a copy of `frame`.
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
pub fn echo_reassembled(buffer: impl AsRef<[u8]>) -> ResponsePackage {
	let buffer = buffer.as_ref();
	match Frame::from_der(buffer) {
		Ok(frame) => ResponsePackage::new(TransitStatus::Ok, Some(frame)),
		Err(_) => ResponsePackage::new(TransitStatus::InvalidArgument, None),
	}
}

/// Streaming echo handler that consumes the body chunk by chunk, counts
/// arrivals, and then echoes the reassembled frame.
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

/// Push a payload through a request sink as two chunks, and then close it.
///
/// This is the smallest sequence that exercises the held-back `last` framing.
///
/// # Errors
///
/// The push or close failure of the sink.
pub async fn push_split(mut sink: RequestSink, payload: impl AsRef<[u8]>) -> Result<(), TransportError> {
	let payload = payload.as_ref();
	let middle = payload.len() / 2;
	sink.push(&payload[..middle]).await?;
	sink.push(&payload[middle..]).await?;

	sink.close().await
}

/// Duplex echo handler that streams every request chunk straight back, counts
/// arrivals, and ends the reply with the trailer status.
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

/// Echo handler that signals `started` and waits for `release` before it
/// answers.
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

/// Serve [`gated_echo_handler`] on `responder`, returning its started and
/// release signals and the serve task.
pub fn spawn_gated_echo(responder: MuxResponder) -> (Arc<Notify>, Arc<Notify>, ServeTask) {
	let started = Arc::new(Notify::new());
	let release = Arc::new(Notify::new());
	let handler = gated_echo_handler(Arc::clone(&started), Arc::clone(&release));

	(started, release, tokio::spawn(responder.serve(handler)))
}

/// Server materials and the signals a gated echo handler waits on.
pub struct GatedMuxContext {
	/// Server certificate and key for the encrypted listener.
	pub materials: ServerMaterials,
	/// Signalled when a handler starts.
	pub started: Notify,
	/// Signalled to let a parked handler answer.
	pub release: Notify,
}

impl GatedMuxContext {
	/// Fresh materials and unsignalled notifiers.
	pub fn generate() -> Self {
		Self {
			materials: ServerMaterials::generate(),
			started: Notify::new(),
			release: Notify::new(),
		}
	}
}

/// Echo handler that signals `ctx.started` and waits for `ctx.release`
/// before it answers.
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

/// Echo handler that answers at once.
pub fn immediate_echo_handler() -> impl Fn(Arc<Frame>) -> core::future::Ready<ResponsePackage> {
	|frame| core::future::ready(echo_response(&frame))
}

/// Serve [`immediate_echo_handler`] on `responder`.
pub fn spawn_immediate_echo(responder: MuxResponder) -> ServeTask {
	tokio::spawn(responder.serve(immediate_echo_handler()))
}

/// Echo handler that holds `held_frame` until a different frame arrives,
/// which releases the hold.
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

/// Cancel-abort fixture. Its drop witness records the handler abort.
pub struct AbortContext {
	/// Server certificate and key for the encrypted listener.
	pub materials: ServerMaterials,
	/// Signalled when the first handler starts.
	pub started: Notify,
	/// Left unsignalled, so the first handler parks until it is aborted.
	pub never: Notify,
	/// Set by the drop witness when the parked handler is aborted.
	pub aborted: AtomicBool,
	/// Count of handler calls.
	pub calls: AtomicU32,
}

impl AbortContext {
	/// Fresh materials, unsignalled notifiers, and zeroed counters.
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

/// Echo handler whose first call parks forever under a drop witness, and
/// whose later calls echo at once.
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

/// Spawn an emit of `frame` on its own stream.
pub fn spawn_emit(handle: &MuxHandle, frame: Frame) -> EmitTask {
	let handle = handle.to_owned();
	tokio::spawn(async move { handle.emit_on_stream(&frame).await })
}

/// Abort an in-flight emit, whose drop guard removes the pending stream and
/// queues a `MuxCancel`.
///
/// # Panics
///
/// When the aborted task reports anything other than cancellation.
pub async fn abort_emit(task: EmitTask) {
	task.abort();

	let join = task.await;
	assert!(
		join.is_err_and(|error| error.is_cancelled()),
		"aborted emit task must report cancellation"
	);
}

/// Read one single-chunk muxed open and decode its frame.
///
/// # Errors
///
/// An expectation failure when the next envelope is not a single-chunk open,
/// or the read or decode failure.
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

/// Read one single-chunk muxed open and return its stream ID.
///
/// # Errors
///
/// The [`read_muxed_request`] set.
pub async fn read_muxed_request_id<R: EnvelopeSource>(reader: &mut R) -> Result<u32, TightBeamError> {
	let (stream_id, _frame) = read_muxed_request(reader).await?;
	Ok(stream_id)
}

/// Read one single-chunk muxed open and require it on `expected_id`.
///
/// # Errors
///
/// An expectation failure that carries `msg` when the open is on another
/// stream, or the [`read_muxed_request`] set.
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

/// A single-chunk unary open on `stream_id` that carries `frame`.
///
/// # Errors
///
/// The encode failure of the frame or the open package.
pub fn muxed_request_envelope(stream_id: u32, frame: Frame) -> Result<TransportEnvelope, TightBeamError> {
	let payload = frame.to_der()?;
	Ok(MuxOpenPackage::new(stream_id, true, MuxStreamKind::Unary, payload)?.into())
}

/// Write a single-chunk unary open on `stream_id`.
///
/// # Errors
///
/// The [`muxed_request_envelope`] set, or the write failure.
pub async fn write_muxed_request<W: EnvelopeSink>(
	writer: &mut W,
	stream_id: u32,
	frame: Frame,
) -> Result<(), TightBeamError> {
	writer.write_envelope(muxed_request_envelope(stream_id, frame)?).await?;
	Ok(())
}

/// Write an `End` trailer on `stream_id` with `status` and `payload`.
///
/// # Errors
///
/// The encode or write failure.
pub async fn write_muxed_end(
	writer: &mut SplitWriter,
	stream_id: u32,
	status: TransitStatus,
	payload: impl Into<Vec<u8>>,
) -> Result<(), TightBeamError> {
	let payload: Vec<u8> = payload.into();
	let response = MuxEndPackage::new(stream_id, status, payload)?;
	writer.write_envelope(response.into()).await?;
	Ok(())
}

/// Answer `stream_id` with an Ok trailer that echoes `frame`.
///
/// # Errors
///
/// The encode or write failure.
pub async fn write_muxed_echo(
	writer: &mut SplitWriter,
	stream_id: u32,
	frame: &Arc<Frame>,
) -> Result<(), TightBeamError> {
	let payload = frame.as_ref().to_der()?;
	write_muxed_end(writer, stream_id, TransitStatus::Ok, payload).await
}

/// Write a GoAway at `last_stream_id` with `reason`.
///
/// # Errors
///
/// The write failure.
pub async fn write_goaway(
	writer: &mut SplitWriter,
	last_stream_id: u32,
	reason: GoAwayReason,
) -> Result<(), TightBeamError> {
	let package = GoAwayPackage::new(last_stream_id, reason);
	writer.write_envelope(package.into()).await?;
	Ok(())
}

/// Write a muxed request and then its cancel, which is the Rapid Reset open
/// and cancel pair.
///
/// # Errors
///
/// The [`write_muxed_request`] set, or the write failure of the cancel.
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

/// Whether `envelope` is an `End` trailer on `stream_id`.
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

/// Whether `result` is exactly `expected`.
pub fn is_echo(result: Option<Frame>, expected: &Frame) -> bool {
	result.as_ref() == Some(expected)
}

/// Whether the emit failed on the local stream cap.
pub fn is_streams_exhausted(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(result, Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted)))
}

/// Whether the peer refused the emit as resource exhausted.
pub fn is_busy(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(
		result,
		Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted))
	)
}

/// Whether the emit failed because the connection is draining.
pub fn is_draining(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(result, Err(TransportError::Draining))
}

/// Whether the emit failed on a closed connection.
pub fn is_connection_closed(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(result, Err(TransportError::ConnectionClosed))
}

/// Whether the result failed as an invalid message.
pub fn is_invalid_message<T>(result: &Result<T, TransportError>) -> bool {
	matches!(result, Err(TransportError::InvalidMessage))
}

/// Whether serving ended on a policy rejection.
pub fn is_policy_rejection(result: &Result<(), TransportError>) -> bool {
	matches!(result, Err(TransportError::OperationFailed(TransportFailure::PolicyRejection)))
}

/// Whether the emit failed on the outbound session budget.
pub fn is_budget_exhausted(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(result, Err(TransportError::OperationFailed(TransportFailure::BudgetExhausted)))
}

/// Append the continuation chunks of `stream_id` to `payload` until its
/// `last` chunk.
///
/// # Errors
///
/// An expectation failure when a record is not a data chunk on `stream_id`,
/// or the read failure.
pub async fn read_remaining_chunks(
	reader: &mut SplitReader,
	stream_id: u32,
	payload: impl Into<Vec<u8>>,
) -> Result<Vec<u8>, TightBeamError> {
	let mut payload: Vec<u8> = payload.into();
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

/// Skip stream traffic until a GoAway arrives, and report whether it carries
/// `reason`.
///
/// # Errors
///
/// An expectation failure when no GoAway arrives within two seconds, or the
/// read failure.
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

/// Poll [`MuxHandle::goaway_reason`] until it reports `reason` or the wait
/// times out.
pub async fn await_goaway_reason(handle: &MuxHandle, reason: GoAwayReason) -> bool {
	await_transport(|| handle.goaway_reason() == Some(reason)).await
}

/// Receiver policy that keeps every stream's limit at the initial credit
/// window, which pins the sender there.
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

/// Authorizer that refuses every offer with [`REFUSAL_CODE`].
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

/// Whether `envelope` is a GoAway with `reason`, at `last_stream_id` when one
/// is given.
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

/// Drop witness that records the abort of an in-flight handler, because its
/// flag flips only on cancellation.
pub struct DropWitness(pub Arc<AbortContext>);

impl Drop for DropWitness {
	fn drop(&mut self) {
		self.0.aborted.store(true, Ordering::SeqCst);
	}
}

/// One rekey headroom case, where
/// `drain_headroom = 2 * (local_cap + peer_cap) + 1`.
pub struct RekeyCase {
	/// Streams the server may initiate.
	pub server_local_cap: u32,
	/// Peer-initiated streams the server accepts.
	pub server_peer_cap: u32,
	/// Send-cipher rekey record limit under test.
	pub rekey_limit: u64,
}

impl RekeyCase {
	/// The drain headroom in records for this case.
	pub fn headroom(&self) -> u64 {
		u64::from(self.server_local_cap)
			.saturating_add(u64::from(self.server_peer_cap))
			.saturating_mul(2)
			.saturating_add(1)
	}

	/// Responses the server sends before the drain floor forces its GoAway.
	///
	/// # Panics
	///
	/// In a debug build, when `rekey_limit` does not exceed the headroom.
	pub fn responses_before_goaway(&self) -> u32 {
		let headroom = self.headroom();
		debug_assert!(self.rekey_limit > headroom);
		(self.rekey_limit - headroom) as u32
	}
}

/// One Rapid Reset pair past the budget draws GoAway(EnhanceYourCalm) and a
/// PolicyRejection.
///
/// The run checks the wire answer, which is the reason and the abuse
/// watermark, inline and returns whether the responder surfaced a policy
/// rejection.
///
/// # Errors
///
/// The [`run_cancel_abuse_against`] set.
pub async fn run_cancel_abuse<R, W>(
	client_reader: R,
	client_writer: W,
	responder: MuxResponder,
	cancel_budget: u32,
) -> Result<bool, TightBeamError>
where
	R: EnvelopeSource,
	W: EnvelopeSink,
{
	// Handlers park forever so every cancel aborts a live handler.
	let (_started, _never_released, serve_task) = spawn_gated_echo(responder);
	run_cancel_abuse_against(client_reader, client_writer, serve_task, cancel_budget).await
}

/// Cancel abuse against an already-serving endpoint whose handlers park
/// forever, so every cancel aborts a live handler. The responder and the
/// `MuxAcceptor::serve` paths share it.
///
/// # Errors
///
/// An expectation failure when no GoAway arrives within two seconds, or the
/// write, read, or join failure.
///
/// # Panics
///
/// When the GoAway carries another reason or watermark.
pub async fn run_cancel_abuse_against<R, W>(
	mut client_reader: R,
	mut client_writer: W,
	serve_task: ServeTask,
	cancel_budget: u32,
) -> Result<bool, TightBeamError>
where
	R: EnvelopeSource,
	W: EnvelopeSink,
{
	let stream_ids: Vec<u32> = (0..=cancel_budget).map(client_stream_id).collect();
	let abuse_stream_id = client_stream_id(cancel_budget);
	let frame = mux_frame("mux-abuse");
	for stream_id in stream_ids {
		write_open_cancel(&mut client_writer, stream_id, frame.to_owned()).await?;
	}

	let goaway = timeout(Duration::from_secs(2), client_reader.read_envelope())
		.await
		.map_err(|_| expectation_failure("GoAway must arrive before the read timeout"))??;
	assert!(
		is_goaway(&goaway, GoAwayReason::EnhanceYourCalm, Some(abuse_stream_id)),
		"cancel abuse must be answered with GoAway(EnhanceYourCalm) at the abuse watermark"
	);

	let refused = join_task(serve_task, "responder task must not panic").await?;
	Ok(is_policy_rejection(&refused))
}

/// Unary `MuxService` closure whose handlers never answer, so every peer
/// cancel aborts a live handler.
pub fn parked_unary_service() -> impl Fn(Frame, SessionContext) -> Pending<Result<Option<Frame>, TightBeamError>> {
	|_frame, _session| pending()
}

/// Server materials and the signal a server-initiated stream test waits on.
pub struct ServerInitContext {
	/// Server certificate and key for the encrypted listener.
	pub materials: ServerMaterials,
	/// Signalled once the server-side emit has resolved.
	pub done: Notify,
}

impl ServerInitContext {
	/// Fresh materials and an unsignalled notifier.
	pub fn generate() -> Self {
		Self { materials: ServerMaterials::generate(), done: Notify::new() }
	}
}

/// Ping fixture, whose `handler_calls` count proves pings bypass the
/// responder.
pub struct PingContext {
	/// Server certificate and key for the encrypted listener.
	pub materials: ServerMaterials,
	/// Count of calls the unary handler received.
	pub handler_calls: AtomicU32,
	/// Signalled once the server's own ping has resolved.
	pub server_ping_done: Notify,
}

impl PingContext {
	/// Fresh materials, a zeroed counter, and an unsignalled notifier.
	pub fn generate() -> Self {
		Self {
			materials: ServerMaterials::generate(),
			handler_calls: AtomicU32::new(0),
			server_ping_done: Notify::new(),
		}
	}
}
