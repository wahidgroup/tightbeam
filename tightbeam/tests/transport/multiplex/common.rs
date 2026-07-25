//! Shared fixtures and helpers for multiplex transport scenarios.

use core::future::{poll_fn, Future};
use core::pin::Pin;
use core::task::Poll;
use core::time::Duration;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::der::{Decode, Encode};
use tightbeam::policy::TransitStatus;
use tightbeam::testing::create_v0_tightbeam;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::{
	CancelReason, GoAwayPackage, GoAwayReason, MuxCancelPackage, MuxEndPackage, MuxEnvelope, MuxOpenPackage,
	MUX_APPLICATION_CODE_FLOOR,
};
use tightbeam::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, MuxSettings, TransportAuthorizer, TransportOffer,
};
use tightbeam::transport::multiplex::{CreditGrantor, MuxHandle, MuxResponder, MuxRole, MuxTransport, StreamId};
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
	await_ok, bind_encrypted_listener, connect_pinned_client, join_task, serve_one_handshake_message,
};

pub(super) type SplitReader = TransportReader<TokioReadHalf>;
pub(super) type SplitWriter = TransportWriter<TokioWriteHalf>;
pub(super) type EmitTask = JoinHandle<Result<Option<Frame>, TransportError>>;
pub(super) type ServeTask = JoinHandle<Result<(), TransportError>>;
pub(super) type HandlerFuture = Pin<Box<dyn Future<Output = ResponsePackage> + Send>>;

pub(super) fn mux_frame(label: &str) -> Frame {
	create_v0_tightbeam(Some(label), None)
}

/// Frame whose DER spans several chunks at the smallest chunk size.
pub(super) fn large_mux_frame(label: &str) -> Frame {
	let padding = "x".repeat(5000);
	mux_frame(&format!("{label}-{padding}"))
}

pub(super) fn mux_offer(cap: u32) -> TransportOffer {
	TransportOffer::mux(cap)
}

/// Offer advertising the smallest legal chunk payload so a
/// [`large_mux_frame`] segments into several records.
pub(super) fn chunked_offer(cap: u32) -> TransportOffer {
	mux_offer(cap).with_chunk_payload_size(1024)
}

/// nth client-initiated stream id (0-based): 1, 3, 5, and so on
pub(super) fn client_stream_id(index: u32) -> u32 {
	index * 2 + 1
}

/// Full ECIES handshake on both ends with the given transport offers.
pub(super) async fn establish_transports(
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

/// Split a handshaken transport and spawn its mux drivers.
pub(super) struct MuxEndpoint {
	pub(super) handle: MuxHandle,
	pub(super) _reader_task: ServeTask,
	pub(super) _writer_task: ServeTask,
}

/// Optional per-endpoint overrides for hardening-limit scenarios.
#[derive(Default)]
pub(super) struct MuxEndpointConfig {
	pub(super) rekey_limit: Option<u64>,
	pub(super) cancel_budget: Option<u32>,
	pub(super) grantor: Option<Arc<dyn CreditGrantor>>,
}

/// Apply the optional cancel budget and spawn both drivers.
///
/// Shared tail of the encrypted and cleartext endpoint constructors.
pub(super) fn spawn_mux_tasks<R, W>(
	mut mux: MuxTransport<R, W>,
	cancel_budget: Option<u32>,
) -> (MuxEndpoint, MuxResponder)
where
	R: EnvelopeSource + Send + 'static,
	W: EnvelopeSink + Send + 'static,
{
	if let Some(budget) = cancel_budget {
		mux = mux.with_cancel_budget(budget);
	}

	let (handle, reader_driver, writer_driver, responder) = mux.into_parts();
	let endpoint = MuxEndpoint {
		handle,
		_reader_task: tokio::spawn(reader_driver.drive()),
		_writer_task: tokio::spawn(writer_driver.drive()),
	};

	(endpoint, responder)
}

pub(super) fn spawn_mux_endpoint_with(
	transport: TcpTransport<TokioStream>,
	role: MuxRole,
	config: MuxEndpointConfig,
) -> Result<(MuxEndpoint, MuxResponder), TightBeamError> {
	let settings = transport
		.negotiated_mux()
		.ok_or_else(|| expectation_failure("handshake must negotiate multiplexing"))?;

	let (reader, mut writer) = transport.into_split()?;
	if let Some(limit) = config.rekey_limit {
		writer = writer.with_rekey_limit(limit);
	}

	let mut mux = MuxTransport::new(reader, writer, role, settings);
	if let Some(grantor) = config.grantor {
		mux = mux.with_credit_grantor(grantor);
	}

	let endpoint_pair = spawn_mux_tasks(mux, config.cancel_budget);
	Ok(endpoint_pair)
}

pub(super) fn spawn_mux_endpoint(
	transport: TcpTransport<TokioStream>,
	role: MuxRole,
) -> Result<(MuxEndpoint, MuxResponder), TightBeamError> {
	spawn_mux_endpoint_with(transport, role, MuxEndpointConfig::default())
}

/// Split a never-handshaken transport into cleartext halves and spawn
/// its mux drivers with caller-supplied symmetric settings.
pub(super) fn spawn_cleartext_mux_endpoint(
	transport: TcpTransport<TokioStream>,
	role: MuxRole,
	settings: MuxSettings,
	cancel_budget: Option<u32>,
) -> Result<(MuxEndpoint, MuxResponder), TightBeamError> {
	let (reader, writer) = transport.into_split_cleartext()?;
	let mux = MuxTransport::new(reader, writer, role, settings);
	let endpoint_pair = spawn_mux_tasks(mux, cancel_budget);
	Ok(endpoint_pair)
}

/// Raw TCP pair with no handshake and no encryption material.
pub(super) async fn establish_cleartext_transports(
) -> Result<(TcpTransport<TokioStream>, TcpTransport<TokioStream>), TightBeamError> {
	let listener = TokioListener::<DefaultCryptoProvider>::bind("127.0.0.1:0").await?;
	let addr = listener.local_addr()?;

	let accept_task = tokio::spawn(async move {
		let (transport, _) = listener.accept().await?;
		Ok::<_, TightBeamError>(transport)
	});

	let stream = TcpStream::connect(addr).await?;
	let client = TcpTransport::from(TokioStream::from(stream));

	let server = await_ok(accept_task, "cleartext accept task must not panic").await?;
	Ok((client, server))
}

/// ServiceClient server side: accept one connection, drive the server
/// handshake with `offer`, and spawn the server mux endpoint.
pub(super) async fn accept_mux_server(
	listener: TokioListener,
	offer: TransportOffer,
) -> Result<(MuxEndpoint, MuxResponder), TightBeamError> {
	let (transport, _) = listener.accept().await?;
	let mut transport = transport.with_mux_offer(Some(offer));

	// ECIES is exactly two client messages: ClientHello, ClientKeyExchange.
	serve_one_handshake_message(&mut transport).await?;
	serve_one_handshake_message(&mut transport).await?;

	spawn_mux_endpoint(transport, MuxRole::Server)
}

/// ServiceClient server closure body: bind an encrypted listener, then
/// accept one mux connection offering `cap` streams and serve `handler`
/// until the connection ends.
pub(super) async fn start_mux_server<H, Fut>(
	materials: &ServerMaterials,
	cap: u32,
	handler: H,
) -> Result<(JoinHandle<()>, SocketAddr), TightBeamError>
where
	H: Fn(Arc<Frame>) -> Fut + Send + Sync + 'static,
	Fut: Future<Output = ResponsePackage> + Send,
{
	let (listener, addr) = bind_encrypted_listener(materials).await?;
	let serve_task = tokio::spawn(async move {
		let Ok((_endpoint, responder)) = accept_mux_server(listener, mux_offer(cap)).await else {
			return;
		};
		let _ = responder.serve(handler).await;
	});

	Ok((serve_task, addr))
}

/// Client half of a ServiceClient scenario: mux endpoint plus its
/// responder and the negotiated settings.
pub(super) struct MuxClient {
	pub(super) endpoint: MuxEndpoint,
	pub(super) responder: MuxResponder,
	pub(super) settings: MuxSettings,
}

impl MuxClient {
	pub(super) fn handle(&self) -> &MuxHandle {
		&self.endpoint.handle
	}
}

/// ServiceClient client side: pinned client offering `cap` streams,
/// full handshake, client mux endpoint spawned.
pub(super) async fn connect_mux_client(
	addr: SocketAddr,
	materials: &ServerMaterials,
	cap: u32,
) -> Result<MuxClient, TightBeamError> {
	let client = connect_pinned_client(addr, &materials.certificate).await?;
	let mut client = client.with_mux_offer(Some(mux_offer(cap)));
	client.perform_client_handshake().await?;

	let settings = client
		.negotiated_mux()
		.ok_or_else(|| expectation_failure("client must negotiate multiplexing"))?;
	let (endpoint, responder) = spawn_mux_endpoint(client, MuxRole::Client)?;
	Ok(MuxClient { endpoint, responder, settings })
}

/// Muxed client against raw server halves (test owns wire ordering).
pub(super) struct ClientMuxServerRaw {
	pub(super) client: MuxEndpoint,
	pub(super) server_reader: SplitReader,
	pub(super) server_writer: SplitWriter,
}

pub(super) async fn establish_client_mux_server_raw_with(
	client_offer: TransportOffer,
	server_offer: TransportOffer,
) -> Result<ClientMuxServerRaw, TightBeamError> {
	let (client, server) = establish_transports(Some(client_offer), Some(server_offer)).await?;
	let (client_end, _client_responder) = spawn_mux_endpoint(client, MuxRole::Client)?;
	let (server_reader, server_writer) = server.into_split()?;

	Ok(ClientMuxServerRaw { client: client_end, server_reader, server_writer })
}

pub(super) async fn establish_client_mux_server_raw(cap: u32) -> Result<ClientMuxServerRaw, TightBeamError> {
	establish_client_mux_server_raw_with(mux_offer(cap), mux_offer(cap)).await
}

/// Round-trip one frame through the raw server halves. True when the
/// spawned emit got its echo back intact.
pub(super) async fn raw_echo_roundtrip(link: &mut ClientMuxServerRaw, frame: &Frame) -> Result<bool, TightBeamError> {
	let emit_task = spawn_emit(&link.client.handle, frame.to_owned());
	let (stream_id, message) = read_muxed_request(&mut link.server_reader).await?;
	write_muxed_echo(&mut link.server_writer, stream_id, &message).await?;

	let echoed = await_ok(emit_task, "echo emit task must not panic").await?;
	Ok(is_echo(echoed, frame))
}

/// Muxed server against raw client halves (test drives requests on the wire).
pub(super) struct ServerMuxClientRaw {
	pub(super) server: MuxEndpoint,
	pub(super) responder: MuxResponder,
	pub(super) client_reader: SplitReader,
	pub(super) client_writer: SplitWriter,
}

/// Split established transports into a muxed server against raw
/// client halves.
pub(super) fn split_server_mux_client_raw(
	client: TcpTransport<TokioStream>,
	server: TcpTransport<TokioStream>,
	server_config: MuxEndpointConfig,
) -> Result<ServerMuxClientRaw, TightBeamError> {
	let (server_end, responder) = spawn_mux_endpoint_with(server, MuxRole::Server, server_config)?;
	let (client_reader, client_writer) = client.into_split()?;
	Ok(ServerMuxClientRaw { server: server_end, responder, client_reader, client_writer })
}

pub(super) async fn establish_server_mux_client_raw_with(
	client_offer: TransportOffer,
	server_offer: TransportOffer,
	server_config: MuxEndpointConfig,
) -> Result<ServerMuxClientRaw, TightBeamError> {
	let (client, server) = establish_transports(Some(client_offer), Some(server_offer)).await?;
	split_server_mux_client_raw(client, server, server_config)
}

pub(super) async fn establish_server_mux_client_raw(
	client_cap: u32,
	server_cap: u32,
	server_config: MuxEndpointConfig,
) -> Result<ServerMuxClientRaw, TightBeamError> {
	establish_server_mux_client_raw_with(mux_offer(client_cap), mux_offer(server_cap), server_config).await
}

/// Both endpoints muxed over one handshake, server serving immediate
/// echo. For scenarios exercising negotiated chunking and budgets
/// end to end.
pub(super) struct MuxPair {
	pub(super) client: MuxEndpoint,
	pub(super) server: MuxEndpoint,
	pub(super) _server_serve: ServeTask,
}

/// Spawn both mux endpoints over established transports, server
/// serving immediate echo.
pub(super) fn spawn_echo_pair(
	client: TcpTransport<TokioStream>,
	server: TcpTransport<TokioStream>,
	server_config: MuxEndpointConfig,
) -> Result<MuxPair, TightBeamError> {
	let (client_end, _client_responder) = spawn_mux_endpoint(client, MuxRole::Client)?;
	let (server_end, server_responder) = spawn_mux_endpoint_with(server, MuxRole::Server, server_config)?;

	Ok(MuxPair {
		client: client_end,
		server: server_end,
		_server_serve: spawn_immediate_echo(server_responder),
	})
}

pub(super) async fn establish_echo_pair(
	client_offer: TransportOffer,
	server_offer: TransportOffer,
	server_config: MuxEndpointConfig,
) -> Result<MuxPair, TightBeamError> {
	let (client, server) = establish_transports(Some(client_offer), Some(server_offer)).await?;
	spawn_echo_pair(client, server, server_config)
}

pub(super) fn echo_response(frame: &Arc<Frame>) -> ResponsePackage {
	ResponsePackage::new(TransitStatus::Ok, Some(Frame::clone(frame)))
}

/// Handler that signals `started`, parks until `release`, then echoes.
pub(super) fn gated_echo_handler(started: Arc<Notify>, release: Arc<Notify>) -> impl Fn(Arc<Frame>) -> HandlerFuture {
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

/// Spawn a gated echo server. Returns the start/release gates for the test.
pub(super) fn spawn_gated_echo(responder: MuxResponder) -> (Arc<Notify>, Arc<Notify>, ServeTask) {
	let started = Arc::new(Notify::new());
	let release = Arc::new(Notify::new());
	let handler = gated_echo_handler(Arc::clone(&started), Arc::clone(&release));

	(started, release, tokio::spawn(responder.serve(handler)))
}

/// Gated-echo fixture. Every server handler signals `started` and
/// parks until `release`.
pub(super) struct GatedMuxContext {
	pub(super) materials: ServerMaterials,
	pub(super) started: Notify,
	pub(super) release: Notify,
}

impl GatedMuxContext {
	pub(super) fn generate() -> Self {
		Self {
			materials: ServerMaterials::generate(),
			started: Notify::new(),
			release: Notify::new(),
		}
	}
}

/// Handler parking every request on the context gates, then echoing.
pub(super) fn gated_echo(ctx: Arc<GatedMuxContext>) -> impl Fn(Arc<Frame>) -> HandlerFuture {
	move |frame| {
		let ctx = Arc::clone(&ctx);
		Box::pin(async move {
			ctx.started.notify_one();
			ctx.release.notified().await;
			echo_response(&frame)
		})
	}
}

pub(super) fn immediate_echo_handler() -> impl Fn(Arc<Frame>) -> core::future::Ready<ResponsePackage> {
	|frame| core::future::ready(echo_response(&frame))
}

pub(super) fn spawn_immediate_echo(responder: MuxResponder) -> ServeTask {
	tokio::spawn(responder.serve(immediate_echo_handler()))
}

/// Hold `held_frame` until a different frame arrives (then release the hold).
pub(super) fn order_forcing_echo(held_frame: Frame, gate: Arc<Notify>) -> impl Fn(Arc<Frame>) -> HandlerFuture {
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

/// Cancel-abort fixture. The first request parks until aborted. The
/// drop witness records the abort.
pub(super) struct AbortContext {
	pub(super) materials: ServerMaterials,
	pub(super) started: Notify,
	pub(super) never: Notify,
	pub(super) aborted: AtomicBool,
	pub(super) calls: AtomicU32,
}

impl AbortContext {
	pub(super) fn generate() -> Self {
		Self {
			materials: ServerMaterials::generate(),
			started: Notify::new(),
			never: Notify::new(),
			aborted: AtomicBool::new(false),
			calls: AtomicU32::new(0),
		}
	}
}

/// First invocation parks forever (until aborted). Later ones echo.
pub(super) fn first_parks_then_echo(ctx: Arc<AbortContext>) -> impl Fn(Arc<Frame>) -> HandlerFuture {
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

pub(super) fn spawn_emit(handle: &MuxHandle, frame: Frame) -> EmitTask {
	let handle = handle.to_owned();
	tokio::spawn(async move { handle.emit_on_stream(&frame).await })
}

/// Abort an in-flight emit. Drop guard removes pending and queues MuxCancel.
pub(super) async fn abort_emit(task: EmitTask) {
	task.abort();

	let join = task.await;
	assert!(
		join.is_err_and(|error| error.is_cancelled()),
		"aborted emit task must report cancellation"
	);
}

pub(super) async fn read_muxed_request<R: EnvelopeSource>(reader: &mut R) -> Result<(u32, Arc<Frame>), TightBeamError> {
	let envelope = reader.read_envelope().await?;
	match envelope {
		TransportEnvelope::Mux(MuxEnvelope::Open(package)) if package.last() => {
			let frame = Frame::from_der(package.payload())?;
			Ok((package.stream_id(), Arc::new(frame)))
		}
		_ => Err(expectation_failure("peer must receive a single-chunk muxed open")),
	}
}

/// Read a muxed open and return only its stream id.
pub(super) async fn read_muxed_request_id<R: EnvelopeSource>(reader: &mut R) -> Result<u32, TightBeamError> {
	let (stream_id, _frame) = read_muxed_request(reader).await?;
	Ok(stream_id)
}

pub(super) async fn expect_muxed_request(
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

pub(super) fn muxed_request_envelope(stream_id: u32, frame: Frame) -> Result<TransportEnvelope, TightBeamError> {
	let payload = frame.to_der()?;
	Ok(MuxOpenPackage::new(stream_id, true, payload)?.into())
}

pub(super) async fn write_muxed_request<W: EnvelopeSink>(
	writer: &mut W,
	stream_id: u32,
	frame: Frame,
) -> Result<(), TightBeamError> {
	writer.write_envelope(muxed_request_envelope(stream_id, frame)?).await?;
	Ok(())
}

pub(super) async fn write_muxed_end(
	writer: &mut SplitWriter,
	stream_id: u32,
	status: TransitStatus,
	payload: Vec<u8>,
) -> Result<(), TightBeamError> {
	let response = MuxEndPackage::new(stream_id, status, payload)?;
	writer.write_envelope(response.into()).await?;
	Ok(())
}

pub(super) async fn write_muxed_echo(
	writer: &mut SplitWriter,
	stream_id: u32,
	frame: &Arc<Frame>,
) -> Result<(), TightBeamError> {
	let payload = frame.as_ref().to_der()?;
	write_muxed_end(writer, stream_id, TransitStatus::Ok, payload).await
}

pub(super) async fn write_goaway(
	writer: &mut SplitWriter,
	last_stream_id: u32,
	reason: GoAwayReason,
) -> Result<(), TightBeamError> {
	let package = GoAwayPackage::new(last_stream_id, reason);
	writer.write_envelope(package.into()).await?;
	Ok(())
}

/// Write a muxed request then its cancel (Rapid Reset open/cancel pair).
pub(super) async fn write_open_cancel<W: EnvelopeSink>(
	writer: &mut W,
	stream_id: u32,
	frame: Frame,
) -> Result<(), TightBeamError> {
	write_muxed_request(writer, stream_id, frame).await?;
	let cancel = MuxCancelPackage::new(stream_id, CancelReason::Cancelled);
	writer.write_envelope(cancel.into()).await?;
	Ok(())
}

pub(super) fn is_muxed_response(envelope: &TransportEnvelope, stream_id: u32) -> bool {
	matches!(
		envelope,
		TransportEnvelope::Mux(MuxEnvelope::End(package)) if package.stream_id() == stream_id
	)
}

/// Poll `shutdown` once so GoAway is sent and the allocator halts, then
/// return the pinned future for the caller to await the drain.
pub(super) async fn kick_shutdown(
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

pub(super) fn is_echo(result: Option<Frame>, expected: &Frame) -> bool {
	result.as_ref() == Some(expected)
}

pub(super) fn is_streams_exhausted(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(result, Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted)))
}

pub(super) fn is_busy(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(
		result,
		Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted))
	)
}

pub(super) fn is_draining(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(result, Err(TransportError::Draining))
}

pub(super) fn is_connection_closed(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(result, Err(TransportError::ConnectionClosed))
}

pub(super) fn is_invalid_message<T>(result: &Result<T, TransportError>) -> bool {
	matches!(result, Err(TransportError::InvalidMessage))
}

pub(super) fn is_policy_rejection(result: &Result<(), TransportError>) -> bool {
	matches!(result, Err(TransportError::OperationFailed(TransportFailure::PolicyRejection)))
}

pub(super) fn is_budget_exhausted(result: &Result<Option<Frame>, TransportError>) -> bool {
	matches!(result, Err(TransportError::OperationFailed(TransportFailure::BudgetExhausted)))
}

/// Drain continuation chunks for `stream_id` until `last`, extending
/// `payload` with each chunk in arrival order.
pub(super) async fn read_remaining_chunks(
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

/// Read envelopes until a GoAway arrives. True when it carries
/// `reason`. Stream traffic racing the GoAway is skipped.
pub(super) async fn read_until_goaway(reader: &mut SplitReader, reason: GoAwayReason) -> Result<bool, TightBeamError> {
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

/// Poll a handle until its reader surfaces the peer GoAway `reason`
/// (timeout-bounded, the reader task races this observer).
pub(super) async fn await_goaway_reason(handle: &MuxHandle, reason: GoAwayReason) -> bool {
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
pub(super) struct NeverGrant;

impl CreditGrantor for NeverGrant {
	fn replenish(&self, _stream_id: StreamId, _received: u64, _limit: u64) -> Option<u64> {
		None
	}
}

/// Authorizer granting half of each requested budget direction.
pub(super) struct HalvingAuthorizer;

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
pub(super) const REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR;

/// Authorizer refusing every session with [`REFUSAL_CODE`].
pub(super) struct RefusingAuthorizer;

impl TransportAuthorizer for RefusingAuthorizer {
	fn authorize<'a>(
		&'a self,
		_offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		Box::pin(async move { Err(AuthorizationRefusal { code: REFUSAL_CODE }) })
	}
}

pub(super) fn is_goaway(envelope: &TransportEnvelope, reason: GoAwayReason, last_stream_id: Option<u32>) -> bool {
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
pub(super) struct DropWitness(pub(super) Arc<AbortContext>);

impl Drop for DropWitness {
	fn drop(&mut self) {
		self.0.aborted.store(true, Ordering::SeqCst);
	}
}

/// One rekey headroom case:
/// `drain_headroom = 2 * (local_cap + peer_cap) + 1`.
pub(super) struct RekeyCase {
	pub(super) server_local_cap: u32,
	pub(super) server_peer_cap: u32,
	pub(super) rekey_limit: u64,
}

impl RekeyCase {
	pub(super) fn headroom(&self) -> u64 {
		u64::from(self.server_local_cap)
			.saturating_add(u64::from(self.server_peer_cap))
			.saturating_mul(2)
			.saturating_add(1)
	}

	pub(super) fn responses_before_goaway(&self) -> u32 {
		let headroom = self.headroom();
		debug_assert!(self.rekey_limit > headroom);
		(self.rekey_limit - headroom) as u32
	}
}

/// Both wire observations of a cancel-abuse run.
pub(super) struct CancelAbuseOutcome {
	pub(super) goaway_enhance_your_calm: bool,
	pub(super) responder_policy_rejection: bool,
}

/// Record both cancel-abuse observations under the scenario's keys.
pub(super) fn record_cancel_abuse(
	trace: &TraceCollector,
	outcome: &CancelAbuseOutcome,
	goaway_key: &'static str,
	rejection_key: &'static str,
) -> Result<(), TightBeamError> {
	trace.event_with(goaway_key, &[], outcome.goaway_enhance_your_calm)?;
	trace.event_with(rejection_key, &[], outcome.responder_policy_rejection)?;
	Ok(())
}

/// Exhaust a server's cancel budget from raw client halves: budget + 1
/// open/cancel pairs must yield GoAway(EnhanceYourCalm) and
/// PolicyRejection from the responder. Shared by the encrypted and
/// cleartext cancel-abuse scenarios.
pub(super) async fn run_cancel_abuse<R, W>(
	mut client_reader: R,
	mut client_writer: W,
	responder: MuxResponder,
	cancel_budget: u32,
) -> Result<CancelAbuseOutcome, TightBeamError>
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
	let goaway_enhance_your_calm = is_goaway(&goaway, GoAwayReason::EnhanceYourCalm, Some(abuse_stream_id));

	let refused = join_task(serve_task, "responder task must not panic").await?;
	let responder_policy_rejection = is_policy_rejection(&refused);

	Ok(CancelAbuseOutcome { goaway_enhance_your_calm, responder_policy_rejection })
}

/// Server-initiated fixture. `done` releases the client (keeping its
/// endpoint alive) once the server-side emit resolves and records its
/// event.
pub(super) struct ServerInitContext {
	pub(super) materials: ServerMaterials,
	pub(super) done: Notify,
}

impl ServerInitContext {
	pub(super) fn generate() -> Self {
		Self { materials: ServerMaterials::generate(), done: Notify::new() }
	}
}

/// Ping-roundtrip fixture. `server_ping_done` holds the client open
/// until the server-to-client probe records its event. `handler_calls`
/// proves pings never touch the handler.
pub(super) struct PingContext {
	pub(super) materials: ServerMaterials,
	pub(super) handler_calls: AtomicU32,
	pub(super) server_ping_done: Notify,
}

impl PingContext {
	pub(super) fn generate() -> Self {
		Self {
			materials: ServerMaterials::generate(),
			handler_calls: AtomicU32::new(0),
			server_ping_done: Notify::new(),
		}
	}
}
