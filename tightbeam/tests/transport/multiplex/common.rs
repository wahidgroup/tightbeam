//! The fixtures of the multiplex transport tests.

use core::error::Error;
use core::future::{pending, poll_fn, ready, Future, Pending};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use core::task::Poll;
use core::time::Duration;
use std::net::SocketAddr;
use std::sync::Arc;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::der::{Decode, Encode};
use tightbeam::marker::MaybeSendFuture;
use tightbeam::policy::{SessionContext, TransitStatus};
use tightbeam::testing::macros::BuiltAssertSpec;
use tightbeam::testing::{HookContext, ScenarioConfig, Violations};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::{
	CancelReason, GoAwayPackage, GoAwayReason, MuxCancelPackage, MuxEndPackage, MuxEnvelope, MuxOpenPackage,
	MuxStreamKind, MUX_APPLICATION_CODE_FLOOR,
};
use tightbeam::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, MuxSettings, TransportAuthorizer, TransportOffer,
};
use tightbeam::transport::multiplex::{
	CreditGrantor, MuxAcceptor, MuxConnector, MuxDrivers, MuxHandle, MuxResponder, MuxRole, MuxTransport, ReplySink,
	RequestSink, SpawnedMux, StreamBody, StreamId,
};
use tightbeam::transport::tcp::r#async::{
	TcpTransport, TokioListener, TokioReadHalf, TokioStream, TokioWriteHalf, TransportReader, TransportWriter,
};
use tightbeam::transport::EndpointConfig;
use tightbeam::transport::{
	EncryptedMessageIO, EnvelopeSink, EnvelopeSource, ResponsePackage, TransportEnvelope, TransportError,
	TransportFailure,
};
use tightbeam::{Frame, TightBeamError};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::common::security::{expectation_failure, ServerMaterials};
use crate::transport::support::{
	await_ok, bind_encrypted_listener, connect_pinned_client, join_task, mux_frame, mux_offer,
	serve_one_handshake_message, HandlerSignal,
};

/// The receive half of a split TCP test transport.
pub type SplitReader = TransportReader<TokioReadHalf>;
/// The send half of a split TCP test transport.
pub type SplitWriter = TransportWriter<TokioWriteHalf>;
/// A spawned emit that resolves to the reply frame or the emit error.
pub type EmitTask = JoinHandle<Result<Option<Frame>, TransportError>>;
/// A spawned responder loop that resolves when its serve call returns.
pub type ServeTask = JoinHandle<Result<(), TransportError>>;
/// A boxed unary or streaming handler future that answers with a response.
pub type HandlerFuture = Pin<Box<dyn Future<Output = ResponsePackage> + Send>>;
/// A boxed duplex handler future that answers with the trailer status.
pub type StatusFuture = Pin<Box<dyn Future<Output = TransitStatus> + Send>>;

/// A frame labeled `label` whose encoding spans many mux chunks.
pub fn large_mux_frame(label: impl AsRef<str>) -> Frame {
	let label = label.as_ref();
	// The padding sizes the encoded frame to roughly fifteen 1024-byte chunks,
	// enough to cross the rekey record limits that the drain scenarios set.
	let padding = "x".repeat(15000);
	mux_frame(format!("{label}-{padding}"))
}

/// A mux offer of `cap` streams with a chunk payload size of 1024 bytes.
pub fn chunked_offer(cap: u32) -> TransportOffer {
	mux_offer(cap).with_chunk_payload_size(1024)
}

/// The ID of the client-initiated stream at the zero-based `index`.
pub fn client_stream_id(index: u32) -> u32 {
	index * 2 + 1
}

/// Completes an HPKE handshake between a pinned client and an encrypted
/// server, with each side's optional mux offer.
///
/// # Errors
///
/// - [`TightBeamError`] -- the bind, connect, or handshake failure of either side, or a panicked server task.
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

		// An HPKE handshake takes two client messages: the hello and the
		// closing.
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
	/// The handle that opens streams and emits on them.
	pub handle: MuxHandle,
	/// The driver tasks, which run until the connection ends or the endpoint
	/// drops.
	pub _drivers: MuxDrivers,
}

/// Per-endpoint limits for the scenarios that harden an endpoint.
#[derive(Default)]
pub struct MuxEndpointConfig {
	/// An override of the rekey record limit of the writer half.
	pub rekey_limit: Option<u64>,
	/// An override of the responder's budget for peer cancels.
	pub cancel_budget: Option<u32>,
	/// An override of the credit policy on the receive side.
	pub grantor: Option<Arc<dyn CreditGrantor>>,
	/// Whether to attach the in-band rekey context.
	pub rekey: bool,
	/// An override of the time budget for one renewal exchange.
	pub renewal_deadline: Option<Duration>,
}

/// Applies the optional cancel budget and spawns the drivers, the shared
/// tail of the encrypted and cleartext endpoint constructors.
pub fn spawn_mux_tasks<R, W>(mut mux: MuxTransport<R, W>, cancel_budget: Option<u32>) -> (MuxEndpoint, MuxResponder)
where
	R: EnvelopeSource + Send + 'static,
	W: EnvelopeSink + Send + 'static,
{
	if let Some(budget) = cancel_budget {
		mux = mux.with_cancel_budget(budget);
	}

	let SpawnedMux { handle, responder, drivers } = mux.spawn();
	let endpoint = MuxEndpoint { handle, _drivers: drivers };

	(endpoint, responder)
}

/// Splits a handshaken transport into a spawned mux endpoint for `role`, with
/// every override in `config` applied.
///
/// # Errors
///
/// - [`TightBeamError`] -- an expectation failure when the handshake negotiated
///   no multiplexing, or the rekey harvest or split failure.
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

	let mut mux = match rekey {
		Some(context) => MuxTransport::with_rekey(reader, writer, context, settings),
		None => MuxTransport::new(reader, writer, role, settings),
	};
	if let Some(grantor) = config.grantor {
		mux = mux.with_credit_grantor(grantor);
	}
	if let Some(deadline) = config.renewal_deadline {
		mux = mux.with_renewal_deadline(deadline);
	}

	let endpoint_pair = spawn_mux_tasks(mux, config.cancel_budget);
	Ok(endpoint_pair)
}

/// Spawns a mux endpoint for `role` with the default configuration.
///
/// # Errors
///
/// - [`TightBeamError`] -- the errors of [`spawn_mux_endpoint_with`].
pub fn spawn_mux_endpoint(
	transport: TcpTransport<TokioStream>,
	role: MuxRole,
) -> Result<(MuxEndpoint, MuxResponder), TightBeamError> {
	spawn_mux_endpoint_with(transport, role, MuxEndpointConfig::default())
}

/// Spawns a cleartext mux endpoint for `role` under explicit `settings`,
/// because a cleartext transport negotiates none.
///
/// # Errors
///
/// - [`TightBeamError`] -- the split failure of the transport.
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

/// Connects a cleartext client to a cleartext listener and returns both
/// transports.
///
/// # Errors
///
/// - [`TightBeamError`] -- the bind, connect, or accept failure, or a panicked accept task.
pub async fn establish_cleartext_transports(
) -> Result<(TcpTransport<TokioStream>, TcpTransport<TokioStream>), TightBeamError> {
	let listener = TokioListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
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

/// Accepts one encrypted mux server as the server-side trace entrypoint. The
/// accepted connection carries the collector, which every downstream plane
/// inherits.
///
/// # Errors
///
/// - [`TightBeamError`] -- the accept or handshake failure, or the errors of [`spawn_mux_endpoint`].
pub async fn accept_mux_server(
	listener: TokioListener,
	offer: TransportOffer,
	trace: TraceCollector,
) -> Result<(MuxEndpoint, MuxResponder), TightBeamError> {
	let (transport, _) = listener.accept().await?;
	let mut transport = transport.with_mux_offer(Some(offer)).with_trace(trace);

	// An HPKE handshake takes two client messages: the hello and the closing.
	serve_one_handshake_message(&mut transport).await?;
	serve_one_handshake_message(&mut transport).await?;

	spawn_mux_endpoint(transport, MuxRole::Server)
}

/// Binds an encrypted listener and spawns a task that accepts one mux server
/// and serves `handler` on it.
///
/// # Errors
///
/// - [`TightBeamError`] -- the bind failure of the listener.
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
		// The serve loop ends when the connection does, and a scenario reads
		// its outcome from the trace.
		let _ = responder.serve(handler).await;
	});

	Ok((serve_task, addr))
}

/// A connected mux client with its negotiated settings.
pub struct MuxClient {
	/// The spawned client endpoint.
	pub endpoint: MuxEndpoint,
	/// The responder for the streams that the peer opens on the client.
	pub responder: MuxResponder,
	/// The settings that the handshake negotiated.
	pub settings: MuxSettings,
}

impl MuxClient {
	/// The handle of the client endpoint.
	pub fn handle(&self) -> &MuxHandle {
		&self.endpoint.handle
	}
}

/// Connects one encrypted mux client as the client-side trace entrypoint. The
/// connection carries the collector, which every downstream plane inherits.
///
/// # Errors
///
/// - [`TightBeamError`] -- an expectation failure when the client negotiated no
///   multiplexing, or the connect, handshake, or spawn failure.
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

/// A muxed client against raw server halves, so the test owns the wire order.
pub struct ClientMuxServerRaw {
	/// The muxed client endpoint.
	pub client: MuxEndpoint,
	/// The raw receive half of the server.
	pub server_reader: SplitReader,
	/// The raw send half of the server.
	pub server_writer: SplitWriter,
}

/// Builds a [`ClientMuxServerRaw`] from explicit client and server offers.
///
/// # Errors
///
/// - [`TightBeamError`] -- the errors of [`establish_transports`] and
///   [`spawn_mux_endpoint`], or the split failure of the server.
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

/// Builds a [`ClientMuxServerRaw`] where both sides offer `cap` streams.
///
/// # Errors
///
/// - [`TightBeamError`] -- the errors of [`establish_client_mux_server_raw_with`].
pub async fn establish_client_mux_server_raw(
	cap: u32,
	trace: TraceCollector,
) -> Result<ClientMuxServerRaw, TightBeamError> {
	establish_client_mux_server_raw_with(mux_offer(cap), mux_offer(cap), trace).await
}

/// Emits `frame` from the muxed client, echoes it from the raw server, and
/// reports whether the echo matched.
///
/// # Errors
///
/// - [`TightBeamError`] -- the read or write failure of the raw server, or a panicked emit task.
pub async fn raw_echo_roundtrip(link: &mut ClientMuxServerRaw, frame: &Frame) -> Result<bool, TightBeamError> {
	let emit_task = spawn_emit(&link.client.handle, frame.to_owned());
	let (stream_id, message) = read_muxed_request(&mut link.server_reader).await?;
	write_muxed_echo(&mut link.server_writer, stream_id, &message).await?;

	let echoed = await_ok(emit_task, "echo emit task must not panic").await?;
	Ok(is_echo(echoed, frame))
}

/// A muxed server against raw client halves, so the test drives requests on
/// the wire.
pub struct ServerMuxClientRaw {
	/// The muxed server endpoint.
	pub server: MuxEndpoint,
	/// The responder that serves the client's streams.
	pub responder: MuxResponder,
	/// The raw receive half of the client.
	pub client_reader: SplitReader,
	/// The raw send half of the client.
	pub client_writer: SplitWriter,
}

/// Spawns the muxed server and splits the client into raw halves.
///
/// # Errors
///
/// - [`TightBeamError`] -- the errors of [`spawn_mux_endpoint_with`], or the split failure of the client.
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

/// Builds a [`ServerMuxClientRaw`] from explicit client and server offers.
///
/// # Errors
///
/// - [`TightBeamError`] -- the errors of [`establish_transports`] and [`split_server_mux_client_raw`].
pub async fn establish_server_mux_client_raw_with(
	client_offer: TransportOffer,
	server_offer: TransportOffer,
	server_config: MuxEndpointConfig,
	trace: TraceCollector,
) -> Result<ServerMuxClientRaw, TightBeamError> {
	let (client, server) = establish_transports(Some(client_offer), Some(server_offer)).await?;
	split_server_mux_client_raw(client, server, server_config, trace)
}

/// Builds a [`ServerMuxClientRaw`] where each side offers its own cap.
///
/// # Errors
///
/// - [`TightBeamError`] -- the errors of [`establish_server_mux_client_raw_with`].
pub async fn establish_server_mux_client_raw(
	client_cap: u32,
	server_cap: u32,
	server_config: MuxEndpointConfig,
	trace: TraceCollector,
) -> Result<ServerMuxClientRaw, TightBeamError> {
	establish_server_mux_client_raw_with(mux_offer(client_cap), mux_offer(server_cap), server_config, trace).await
}

/// Two muxed endpoints with an echo responder that serves the server side.
pub struct MuxPair {
	/// The muxed client endpoint.
	pub client: MuxEndpoint,
	/// The muxed server endpoint.
	pub server: MuxEndpoint,
	/// The echo responder task, which serves until the connection ends.
	pub _server_serve: ServeTask,
}

/// Spawns both endpoints with their own configurations and starts the
/// immediate echo of the server.
///
/// # Errors
///
/// - [`TightBeamError`] -- the errors of [`spawn_mux_endpoint_with`] on either side.
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

/// Spawns an echo pair whose client takes the default configuration.
///
/// # Errors
///
/// - [`TightBeamError`] -- the errors of [`spawn_echo_pair_with`].
pub fn spawn_echo_pair(
	client: TcpTransport<TokioStream>,
	server: TcpTransport<TokioStream>,
	server_config: MuxEndpointConfig,
	trace: TraceCollector,
) -> Result<MuxPair, TightBeamError> {
	spawn_echo_pair_with(client, server, MuxEndpointConfig::default(), server_config, trace)
}

/// Runs the handshake of both transports and spawns an echo pair over them.
///
/// # Errors
///
/// - [`TightBeamError`] -- the errors of [`establish_transports`] and [`spawn_echo_pair`].
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

/// The terminal outcome of a fully drained [`StreamBody`].
pub struct DrainedBody {
	/// The bytes of every chunk, in arrival order.
	pub bytes: Vec<u8>,
	/// The count of chunks that the drain consumes before the terminal event.
	pub chunks: usize,
	/// The failure that ends the body, or `None` on a clean end.
	pub failure: Option<TransportError>,
}

/// Drains a stream body to its terminal outcome, and collects its chunks.
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

/// Whether a handler that counts chunks observed a chunked (multi-record) body.
pub fn saw_multiple_chunks(counter: &AtomicUsize) -> bool {
	counter.load(Ordering::SeqCst) > 1
}

/// The echo of a body reassembled from streamed chunks.
pub fn echo_reassembled(buffer: impl AsRef<[u8]>) -> ResponsePackage {
	let buffer = buffer.as_ref();
	match Frame::from_der(buffer) {
		Ok(frame) => ResponsePackage::new(TransitStatus::Ok, Some(frame)),
		Err(_) => ResponsePackage::new(TransitStatus::InvalidArgument, None),
	}
}

/// A streaming echo handler that consumes the body chunk by chunk, counts
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

/// Pushes a payload through a request sink as two chunks, and then closes it.
///
/// It is the smallest sequence that sends more than one data chunk before the
/// empty `last`-flagged record of the close.
///
/// # Errors
///
/// - [`TransportError`] -- the push or close failure of the sink.
pub async fn push_split(mut sink: RequestSink, payload: impl AsRef<[u8]>) -> Result<(), TransportError> {
	let payload = payload.as_ref();
	let middle = payload.len() / 2;
	sink.push(&payload[..middle]).await?;
	sink.push(&payload[middle..]).await?;
	sink.close().await
}

/// A duplex echo handler that streams every request chunk straight back,
/// counts arrivals, and ends the reply with the trailer status.
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

/// An echo handler that raises `started` and waits for `release` before it
/// answers.
pub fn gated_echo_handler(started: Arc<HandlerSignal>, release: Arc<Notify>) -> impl Fn(Arc<Frame>) -> HandlerFuture {
	move |frame| {
		let started = Arc::clone(&started);
		let release = Arc::clone(&release);
		Box::pin(async move {
			started.raise();
			release.notified().await;
			echo_response(&frame)
		})
	}
}

/// Serves [`gated_echo_handler`] on `responder`, and returns its started and
/// release signals and the serve task.
pub fn spawn_gated_echo(responder: MuxResponder) -> (Arc<HandlerSignal>, Arc<Notify>, ServeTask) {
	let started = Arc::new(HandlerSignal::default());
	let release = Arc::new(Notify::new());
	let handler = gated_echo_handler(Arc::clone(&started), Arc::clone(&release));

	(started, release, tokio::spawn(responder.serve(handler)))
}

/// Server materials and the signals a gated echo handler waits on.
pub struct GatedMuxContext {
	/// The server certificate and key for the encrypted listener.
	pub materials: ServerMaterials,
	/// The signal a handler raises when it starts.
	pub started: HandlerSignal,
	/// The notifier that lets a parked handler answer.
	pub release: Notify,
}

impl GatedMuxContext {
	/// A context of fresh materials, an unraised signal, and an unsignalled
	/// notifier.
	pub fn generate() -> Self {
		Self {
			materials: ServerMaterials::generate(),
			started: HandlerSignal::default(),
			release: Notify::new(),
		}
	}
}

/// An echo handler that raises `ctx.started` and waits for `ctx.release`
/// before it answers.
pub fn gated_echo(ctx: Arc<GatedMuxContext>) -> impl Fn(Arc<Frame>) -> HandlerFuture {
	move |frame| {
		let ctx = Arc::clone(&ctx);
		Box::pin(async move {
			ctx.started.raise();
			ctx.release.notified().await;
			echo_response(&frame)
		})
	}
}

/// An echo handler that answers at once.
pub fn immediate_echo_handler() -> impl Fn(Arc<Frame>) -> core::future::Ready<ResponsePackage> {
	|frame| core::future::ready(echo_response(&frame))
}

/// Serves [`immediate_echo_handler`] on `responder`.
pub fn spawn_immediate_echo(responder: MuxResponder) -> ServeTask {
	tokio::spawn(responder.serve(immediate_echo_handler()))
}

/// An echo handler that holds `held_frame` until a different frame arrives,
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

/// The cancel-abort fixture, whose drop witness records the handler abort.
pub struct AbortContext {
	/// The server certificate and key for the encrypted listener.
	pub materials: ServerMaterials,
	/// The signal the first handler raises when it starts.
	pub started: HandlerSignal,
	/// A notifier that stays unsignalled, so the first handler parks until a
	/// cancel aborts it.
	pub never: Notify,
	/// The flag the drop witness sets when a cancel aborts the parked handler.
	pub aborted: AtomicBool,
	/// The count of handler calls.
	pub calls: AtomicU32,
}

impl AbortContext {
	/// A context of fresh materials, an unraised signal, an unsignalled
	/// notifier, and zeroed counters.
	pub fn generate() -> Self {
		Self {
			materials: ServerMaterials::generate(),
			started: HandlerSignal::default(),
			never: Notify::new(),
			aborted: AtomicBool::new(false),
			calls: AtomicU32::new(0),
		}
	}
}

/// An echo handler whose first call parks forever under a drop witness, and
/// whose later calls echo at once.
pub fn first_parks_then_echo(ctx: Arc<AbortContext>) -> impl Fn(Arc<Frame>) -> HandlerFuture {
	move |frame: Arc<Frame>| {
		let ctx = Arc::clone(&ctx);
		Box::pin(async move {
			if ctx.calls.fetch_add(1, Ordering::SeqCst) == 0 {
				let _witness = DropWitness(Arc::clone(&ctx));
				ctx.started.raise();
				ctx.never.notified().await;
			}

			echo_response(&frame)
		})
	}
}

/// Spawns an emit of `frame` on its own stream.
pub fn spawn_emit(handle: &MuxHandle, frame: Frame) -> EmitTask {
	let handle = handle.to_owned();
	tokio::spawn(async move { handle.emit_on_stream(&frame).await })
}

/// Aborts an in-flight emit, whose drop guard removes the pending stream and
/// queues a `MuxCancel`.
///
/// # Panics
///
/// The call panics when the aborted task reports anything other than
/// cancellation.
pub async fn abort_emit(task: EmitTask) {
	task.abort();

	let join = task.await;
	assert!(
		join.is_err_and(|error| error.is_cancelled()),
		"aborted emit task must report cancellation"
	);
}

/// Reads one single-chunk muxed open and decodes its frame.
///
/// # Errors
///
/// - [`TightBeamError`] -- an expectation failure when the next envelope is not
///   a single-chunk open, or the read or decode failure.
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

/// Reads one single-chunk muxed open and returns its stream ID.
///
/// # Errors
///
/// - [`TightBeamError`] -- the errors of [`read_muxed_request`].
pub async fn read_muxed_request_id<R: EnvelopeSource>(reader: &mut R) -> Result<u32, TightBeamError> {
	let (stream_id, _frame) = read_muxed_request(reader).await?;
	Ok(stream_id)
}

/// Reads one single-chunk muxed open and requires it on `expected_id`.
///
/// # Errors
///
/// - [`TightBeamError`] -- an expectation failure that carries `msg` when the
///   open is on another stream, or the errors of [`read_muxed_request`].
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
/// - [`TightBeamError`] -- the encode failure of the frame or the open package.
pub fn muxed_request_envelope(stream_id: u32, frame: Frame) -> Result<TransportEnvelope, TightBeamError> {
	let payload = frame.to_der()?;
	Ok(MuxOpenPackage::new(stream_id, true, MuxStreamKind::Unary, payload)?.into())
}

/// Writes a single-chunk unary open on `stream_id`.
///
/// # Errors
///
/// - [`TightBeamError`] -- the errors of [`muxed_request_envelope`], or the write failure.
pub async fn write_muxed_request<W: EnvelopeSink>(
	writer: &mut W,
	stream_id: u32,
	frame: Frame,
) -> Result<(), TightBeamError> {
	writer.write_envelope(muxed_request_envelope(stream_id, frame)?).await?;
	Ok(())
}

/// Writes an `End` trailer on `stream_id` with `status` and `payload`.
///
/// # Errors
///
/// - [`TightBeamError`] -- the encode or write failure.
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

/// Answers `stream_id` with an Ok trailer that echoes `frame`.
///
/// # Errors
///
/// - [`TightBeamError`] -- the encode or write failure.
pub async fn write_muxed_echo(
	writer: &mut SplitWriter,
	stream_id: u32,
	frame: &Arc<Frame>,
) -> Result<(), TightBeamError> {
	let payload = frame.as_ref().to_der()?;
	write_muxed_end(writer, stream_id, TransitStatus::Ok, payload).await
}

/// Writes a GoAway at `last_stream_id` with `reason`.
///
/// # Errors
///
/// - [`TightBeamError`] -- the write failure.
pub async fn write_goaway(
	writer: &mut SplitWriter,
	last_stream_id: u32,
	reason: GoAwayReason,
) -> Result<(), TightBeamError> {
	let package = GoAwayPackage::new(last_stream_id, reason);
	writer.write_envelope(package.into()).await?;
	Ok(())
}

/// Writes a muxed request, then its cancel: the Rapid Reset open and cancel
/// pair.
///
/// # Errors
///
/// - [`TightBeamError`] -- the errors of [`write_muxed_request`], or the write failure of the cancel.
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

/// Polls `shutdown` once so the handle sends a GoAway and the allocator halts,
/// and then returns a future for the caller to await the drain.
///
/// A shutdown that the first poll completes hands its output to the returned
/// future, which yields it at once.
pub async fn kick_shutdown(
	handle: &MuxHandle,
) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
	let mut shutdown_future = Box::pin(handle.shutdown());
	// One poll sends the GoAway and halts the allocator.
	let first = poll_fn(|cx| Poll::Ready(shutdown_future.as_mut().poll(cx))).await;

	match first {
		Poll::Ready(output) => Box::pin(ready(output)),
		Poll::Pending => shutdown_future,
	}
}

/// Whether `result` equals `expected`.
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

/// Whether the emit failed because the connection drains.
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

/// Whether the serve loop ended on a policy rejection.
pub fn is_policy_rejection(result: &Result<(), TransportError>) -> bool {
	matches!(result, Err(TransportError::OperationFailed(TransportFailure::PolicyRejection)))
}

/// Whether the emit failed on the outbound session budget.
pub fn is_budget_exhausted(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(result, Err(TransportError::OperationFailed(TransportFailure::BudgetExhausted)))
}

/// Appends the continuation chunks of `stream_id` to `payload` until its
/// `last` chunk.
///
/// # Errors
///
/// - [`TightBeamError`] -- an expectation failure when a record is not a data
///   chunk on `stream_id`, or the read failure.
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

/// Skips stream traffic until a GoAway arrives, and reports whether it carries
/// `reason`.
///
/// # Errors
///
/// - [`TightBeamError`] -- an expectation failure when no GoAway arrives within
///   two seconds, or the read failure.
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

/// A receiver policy that keeps every stream's limit at the initial credit
/// window, which pins the sender there.
pub struct NeverGrant;

impl CreditGrantor for NeverGrant {
	fn replenish(&self, _stream_id: StreamId, _received: u64, _limit: u64) -> Option<u64> {
		None
	}
}

/// An authorizer that grants half of each requested budget direction.
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

/// The application refusal code that [`RefusingAuthorizer`] carries.
pub const REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR;

/// An authorizer that refuses every offer with [`REFUSAL_CODE`].
pub struct RefusingAuthorizer;

impl TransportAuthorizer for RefusingAuthorizer {
	fn authorize<'a>(
		&'a self,
		_offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		Box::pin(async move { Err(AuthorizationRefusal { code: REFUSAL_CODE }) })
	}
}

/// An authorizer whose backend hangs forever, which simulates a hung
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

/// A drop witness that records the abort of an in-flight handler. The call it
/// guards parks forever, so only a cancel drops it.
pub struct DropWitness(pub Arc<AbortContext>);

impl Drop for DropWitness {
	fn drop(&mut self) {
		self.0.aborted.store(true, Ordering::SeqCst);
	}
}

/// One rekey headroom case, where
/// `drain_headroom = 2 * (local_cap + peer_cap) + 1`.
pub struct RekeyCase {
	/// The count of streams that the server may initiate.
	pub server_local_cap: u32,
	/// The count of peer-initiated streams that the server accepts.
	pub server_peer_cap: u32,
	/// The rekey record limit of the send cipher under test.
	pub rekey_limit: u64,
}

impl RekeyCase {
	/// The drain headroom of this case, in records.
	pub fn headroom(&self) -> u64 {
		u64::from(self.server_local_cap)
			.saturating_add(u64::from(self.server_peer_cap))
			.saturating_mul(2)
			.saturating_add(1)
	}

	/// The count of responses that the server sends before the drain floor
	/// forces its GoAway.
	///
	/// # Panics
	///
	/// A debug build panics when `rekey_limit` does not exceed the headroom.
	pub fn responses_before_goaway(&self) -> u32 {
		let headroom = self.headroom();
		debug_assert!(self.rekey_limit > headroom);
		(self.rekey_limit - headroom) as u32
	}
}

/// One Rapid Reset pair past the budget draws GoAway(EnhanceYourCalm) and a
/// PolicyRejection.
///
/// The run asserts the reason and the abuse watermark of the GoAway inline,
/// and returns whether the responder reports a policy rejection.
///
/// # Errors
///
/// - [`TightBeamError`] -- the errors of [`run_cancel_abuse_against`].
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

/// Runs cancel abuse against a serving endpoint whose handlers park forever,
/// so every cancel aborts a live handler. The responder path and the
/// [`MuxAcceptor::serve`] path share it.
///
/// # Errors
///
/// - [`TightBeamError`] -- an expectation failure when no GoAway arrives within
///   two seconds, or the write, read, or join failure.
///
/// # Panics
///
/// The call panics when the GoAway carries a reason or a watermark other than
/// the expected one.
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

/// A unary `MuxService` closure whose handlers stay pending, so every peer
/// cancel aborts a live handler.
pub fn parked_unary_service() -> impl Fn(Frame, SessionContext) -> Pending<Result<Option<Frame>, TightBeamError>> {
	|_frame, _session| pending()
}

/// The ping fixture, whose flag carries the outcome of the server's ping to
/// the client's task.
pub struct PingContext {
	/// The server certificate and key for the encrypted listener.
	pub materials: ServerMaterials,
	/// The signal the server task raises once its own ping resolves.
	pub server_ping_done: HandlerSignal,
	/// Whether the client acked the server's ping, which the server task
	/// stores before it raises `server_ping_done`.
	pub server_ping_acked: AtomicBool,
}

impl PingContext {
	/// A context of fresh materials, an unraised signal, and a cleared ack
	/// flag.
	pub fn generate() -> Self {
		Self {
			materials: ServerMaterials::generate(),
			server_ping_done: HandlerSignal::default(),
			server_ping_acked: AtomicBool::new(false),
		}
	}
}

/// Runs one case of a case table on its own runtime, and grades the trace of
/// the case against `spec`, as `tb_scenario!` grades a scenario.
///
/// `case` drives the endpoints with a share of the trace, and the grade takes
/// the result of `case` beside the trace.
///
/// # Errors
///
/// - [`ScenarioConfigError`] -- `spec` builds no configuration.
/// - [`std::io::Error`] -- the runtime of the case fails to build.
/// - [`TightBeamError`] -- the grade refuses an exploration event.
/// - [`Violations`] -- the grade finds a violation.
///
/// [`ScenarioConfigError`]: tightbeam::testing::ScenarioConfigError
pub fn grade_case<F, Fut>(spec: &'static BuiltAssertSpec, case: F) -> Result<(), Box<dyn Error>>
where
	F: FnOnce(TraceCollector) -> Fut,
	Fut: Future<Output = Result<(), TightBeamError>>,
{
	let config = ScenarioConfig::builder().with_spec(spec).build()?;
	let trace = config.trace();
	let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;

	let outcome = runtime.block_on(case(trace.share()));
	let graded = HookContext::build(&config, &trace, outcome)?;
	graded.outcome().map_err(Violations::clone)?;

	Ok(())
}
