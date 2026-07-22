//! Multiplexed transport integration tests.
//!
//! Drives ECIES handshakes with transport negotiation over TCP,
//! assembles `MuxTransport` routers from the split halves, and verifies:
//!
//! - Concurrent interleaved streams with out-of-order response correlation
//! - Local-initiated cap exhaustion answered with `StreamsExhausted`
//! - Muxed envelopes rejected on a connection that never negotiated mux
//! - Cancelling an in-flight stream frees its cap slot and aborts the handler
//! - A response racing a cancel on the connection is discarded cleanly
//! - Garbage End payloads on stale or non-Accepted streams never kill the connection
//! - GoAway drains in-flight streams and rejects new ones
//! - Rekey drain headroom table (`2 * (local_cap + peer_cap) + 1` vs record limit)
//! - Cancel-budget boundary: N cancels OK, N+1 yields GoAway(EnhanceYourCalm)
//! - Server-initiated stream roundtrip (client `serve`, server `emit_on_stream`)
//! - Peer GoAway fails pending above `last_stream_id` and rejects new streams
//! - Non-mux envelope on a mux peer: GoAway(ProtocolError) and pending fail
//! - Stream-grammar violations: GoAway(ProtocolError)
//! - Connection drop mid-emit: `ConnectionClosed`
//! - Cleartext mux: interleaved echo and cancel-budget GoAway
//! - Ping round-trip both directions without touching the handler
//! - Ping probe answered with its ack on the wire, stale acks tolerated
//! - Ping refused as `Draining` once GoAway is sent

#![cfg(all(
	feature = "transport-ecies",
	feature = "transport-policy",
	feature = "tcp",
	feature = "tokio",
	feature = "testing"
))]

/// DER of `Mux(Open { stream_id: 1, last: true, payload: [] })`.
///
/// Pins the wire format from both sides: mux build asserts the encoder
/// produces exactly these bytes, non-mux build asserts they fail to
/// decode.
const MUX_OPEN_WIRE_DER: [u8; 14] = [
	0xA4, 0x0C, 0xA0, 0x0A, 0x30, 0x08, 0x02, 0x01, 0x01, 0x01, 0x01, 0xFF, 0x04, 0x00,
];

#[cfg(feature = "transport-multiplex")]
mod negotiated {
	use core::future::{poll_fn, Future};
	use core::pin::Pin;
	use core::task::Poll;
	use std::net::SocketAddr;
	use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
	use std::sync::Arc;

	use tightbeam::asn1::{MessagePriority, Metadata, Version};
	use tightbeam::crypto::profiles::DefaultCryptoProvider;
	use tightbeam::der::{Decode, Encode};
	use tightbeam::exactly;
	use tightbeam::policy::TransitStatus;
	use tightbeam::tb_assert_spec;
	use tightbeam::tb_scenario;
	use tightbeam::testing::{create_v0_tightbeam, ClientEnv, SetupEnv};
	use tightbeam::trace::TraceCollector;
	use tightbeam::transport::envelopes::{
		CancelReason, GoAwayPackage, GoAwayReason, MuxCancelPackage, MuxCreditPackage, MuxDataPackage, MuxEndPackage,
		MuxEnvelope, MuxOpenPackage, MuxPingPackage,
	};
	use tightbeam::transport::handshake::negotiation::{MuxSettings, TransportOffer};
	use tightbeam::transport::multiplex::{MuxHandle, MuxResponder, MuxRole, MuxTransport};
	use tightbeam::transport::tcp::r#async::{
		TcpTransport, TokioListener, TokioReadHalf, TokioStream, TokioWriteHalf, TransportReader, TransportWriter,
	};
	use tightbeam::transport::{
		EncryptedMessageIO, EnvelopeSink, EnvelopeSource, MessageCollector, ResponseHandler, ResponsePackage,
		TransportEnvelope, TransportError, TransportFailure,
	};
	use tightbeam::{Frame, TightBeamError};
	use tokio::net::TcpStream;
	use tokio::sync::Notify;
	use tokio::task::JoinHandle;

	use crate::common::security::{expectation_failure, ServerMaterials};
	use crate::transport::support::{
		await_ok, bind_encrypted_listener, connect_pinned_client, join_task, serve_one_handshake_message,
	};

	type SplitReader = TransportReader<TokioReadHalf>;
	type SplitWriter = TransportWriter<TokioWriteHalf>;
	type EmitTask = JoinHandle<Result<Option<Frame>, TransportError>>;
	type ServeTask = JoinHandle<Result<(), TransportError>>;
	type HandlerFuture = Pin<Box<dyn Future<Output = ResponsePackage> + Send>>;

	fn mux_frame(label: &str) -> Frame {
		create_v0_tightbeam(Some(label), None)
	}

	fn mux_offer(cap: u32) -> TransportOffer {
		TransportOffer::mux(cap)
	}

	/// nth client-initiated stream id (0-based): 1, 3, 5, and so on
	fn client_stream_id(index: u32) -> u32 {
		index * 2 + 1
	}

	/// Full ECIES handshake on both ends with the given transport offers.
	async fn establish_transports(
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

	async fn establish_matched_transports(
		cap: u32,
	) -> Result<(TcpTransport<TokioStream>, TcpTransport<TokioStream>), TightBeamError> {
		let offer = mux_offer(cap);
		establish_transports(Some(offer), Some(offer)).await
	}

	/// Split a handshaken transport and spawn its mux drivers.
	struct MuxEndpoint {
		handle: MuxHandle,
		_reader_task: ServeTask,
		_writer_task: ServeTask,
	}

	/// Optional per-endpoint overrides for hardening-limit scenarios.
	#[derive(Default)]
	struct MuxEndpointConfig {
		rekey_limit: Option<u64>,
		cancel_budget: Option<u32>,
	}

	/// Apply the optional cancel budget and spawn both drivers.
	///
	/// Shared tail of the encrypted and cleartext endpoint constructors.
	fn spawn_mux_tasks<R, W>(mut mux: MuxTransport<R, W>, cancel_budget: Option<u32>) -> (MuxEndpoint, MuxResponder)
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

	fn spawn_mux_endpoint_with(
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

		let mux = MuxTransport::new(reader, writer, role, settings);
		let endpoint_pair = spawn_mux_tasks(mux, config.cancel_budget);
		Ok(endpoint_pair)
	}

	fn spawn_mux_endpoint(
		transport: TcpTransport<TokioStream>,
		role: MuxRole,
	) -> Result<(MuxEndpoint, MuxResponder), TightBeamError> {
		spawn_mux_endpoint_with(transport, role, MuxEndpointConfig::default())
	}

	/// Split a never-handshaken transport into cleartext halves and spawn
	/// its mux drivers with caller-supplied symmetric settings.
	fn spawn_cleartext_mux_endpoint(
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
	async fn establish_cleartext_transports(
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
	async fn accept_mux_server(
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
	async fn start_mux_server<H, Fut>(
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
	struct MuxClient {
		endpoint: MuxEndpoint,
		responder: MuxResponder,
		settings: MuxSettings,
	}

	impl MuxClient {
		fn handle(&self) -> &MuxHandle {
			&self.endpoint.handle
		}
	}

	/// ServiceClient client side: pinned client offering `cap` streams,
	/// full handshake, client mux endpoint spawned.
	async fn connect_mux_client(
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
	struct ClientMuxServerRaw {
		client: MuxEndpoint,
		server_reader: SplitReader,
		server_writer: SplitWriter,
	}

	async fn establish_client_mux_server_raw(cap: u32) -> Result<ClientMuxServerRaw, TightBeamError> {
		let (client, server) = establish_matched_transports(cap).await?;
		let (client_end, _client_responder) = spawn_mux_endpoint(client, MuxRole::Client)?;
		let (server_reader, server_writer) = server.into_split()?;

		Ok(ClientMuxServerRaw { client: client_end, server_reader, server_writer })
	}

	/// Round-trip one frame through the raw server halves; true when the
	/// spawned emit got its echo back intact.
	async fn raw_echo_roundtrip(link: &mut ClientMuxServerRaw, frame: &Frame) -> Result<bool, TightBeamError> {
		let emit_task = spawn_emit(&link.client.handle, frame.clone());
		let (stream_id, message) = read_muxed_request(&mut link.server_reader).await?;
		write_muxed_echo(&mut link.server_writer, stream_id, &message).await?;

		let echoed = await_ok(emit_task, "echo emit task must not panic").await?;
		Ok(is_echo(echoed, frame))
	}

	/// Muxed server against raw client halves (test drives requests on the wire).
	struct ServerMuxClientRaw {
		server: MuxEndpoint,
		responder: MuxResponder,
		client_reader: SplitReader,
		client_writer: SplitWriter,
	}

	async fn establish_server_mux_client_raw(
		client_cap: u32,
		server_cap: u32,
		server_config: MuxEndpointConfig,
	) -> Result<ServerMuxClientRaw, TightBeamError> {
		let (client, server) = establish_transports(Some(mux_offer(client_cap)), Some(mux_offer(server_cap))).await?;
		let (server_end, responder) = spawn_mux_endpoint_with(server, MuxRole::Server, server_config)?;
		let (client_reader, client_writer) = client.into_split()?;

		Ok(ServerMuxClientRaw { server: server_end, responder, client_reader, client_writer })
	}

	fn echo_response(frame: &Arc<Frame>) -> ResponsePackage {
		ResponsePackage::new(TransitStatus::Accepted, Some(Frame::clone(frame)))
	}

	/// Handler that signals `started`, parks until `release`, then echoes.
	fn gated_echo_handler(started: Arc<Notify>, release: Arc<Notify>) -> impl Fn(Arc<Frame>) -> HandlerFuture {
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
	fn spawn_gated_echo(responder: MuxResponder) -> (Arc<Notify>, Arc<Notify>, ServeTask) {
		let started = Arc::new(Notify::new());
		let release = Arc::new(Notify::new());
		let handler = gated_echo_handler(Arc::clone(&started), Arc::clone(&release));

		(started, release, tokio::spawn(responder.serve(handler)))
	}

	/// Gated-echo fixture. Every server handler signals `started` and
	/// parks until `release`.
	struct GatedMuxContext {
		materials: ServerMaterials,
		started: Notify,
		release: Notify,
	}

	impl GatedMuxContext {
		fn generate() -> Self {
			Self {
				materials: ServerMaterials::generate(),
				started: Notify::new(),
				release: Notify::new(),
			}
		}
	}

	/// Handler parking every request on the context gates, then echoing.
	fn gated_echo(ctx: Arc<GatedMuxContext>) -> impl Fn(Arc<Frame>) -> HandlerFuture {
		move |frame| {
			let ctx = Arc::clone(&ctx);
			Box::pin(async move {
				ctx.started.notify_one();
				ctx.release.notified().await;
				echo_response(&frame)
			})
		}
	}

	fn immediate_echo_handler() -> impl Fn(Arc<Frame>) -> core::future::Ready<ResponsePackage> {
		|frame| core::future::ready(echo_response(&frame))
	}

	fn spawn_immediate_echo(responder: MuxResponder) -> ServeTask {
		tokio::spawn(responder.serve(immediate_echo_handler()))
	}

	/// Hold `held_frame` until a different frame arrives (then release the hold).
	fn order_forcing_echo(held_frame: Frame, gate: Arc<Notify>) -> impl Fn(Arc<Frame>) -> HandlerFuture {
		move |frame: Arc<Frame>| {
			let held_frame = held_frame.clone();
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
	struct AbortContext {
		materials: ServerMaterials,
		started: Notify,
		never: Notify,
		aborted: AtomicBool,
		calls: AtomicU32,
	}

	impl AbortContext {
		fn generate() -> Self {
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
	fn first_parks_then_echo(ctx: Arc<AbortContext>) -> impl Fn(Arc<Frame>) -> HandlerFuture {
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

	fn spawn_emit(handle: &MuxHandle, frame: Frame) -> EmitTask {
		let handle = handle.clone();
		tokio::spawn(async move { handle.emit_on_stream(&frame).await })
	}

	/// Abort an in-flight emit. Drop guard removes pending and queues MuxCancel.
	async fn abort_emit(task: EmitTask) {
		task.abort();

		let join = task.await;
		assert!(
			join.is_err_and(|error| error.is_cancelled()),
			"aborted emit task must report cancellation"
		);
	}

	async fn read_muxed_request<R: EnvelopeSource>(reader: &mut R) -> Result<(u32, Arc<Frame>), TightBeamError> {
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
	async fn read_muxed_request_id<R: EnvelopeSource>(reader: &mut R) -> Result<u32, TightBeamError> {
		let (stream_id, _frame) = read_muxed_request(reader).await?;
		Ok(stream_id)
	}

	async fn expect_muxed_request(
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

	async fn write_muxed_request<W: EnvelopeSink>(
		writer: &mut W,
		stream_id: u32,
		frame: Frame,
	) -> Result<(), TightBeamError> {
		let payload = frame.to_der()?;
		let request = MuxOpenPackage::new(stream_id, true, payload)?;
		writer.write_envelope(request.into()).await?;
		Ok(())
	}

	async fn write_muxed_end(
		writer: &mut SplitWriter,
		stream_id: u32,
		status: TransitStatus,
		payload: Vec<u8>,
	) -> Result<(), TightBeamError> {
		let response = MuxEndPackage::new(stream_id, status, payload)?;
		writer.write_envelope(response.into()).await?;
		Ok(())
	}

	async fn write_muxed_echo(
		writer: &mut SplitWriter,
		stream_id: u32,
		frame: &Arc<Frame>,
	) -> Result<(), TightBeamError> {
		let payload = frame.as_ref().to_der()?;
		write_muxed_end(writer, stream_id, TransitStatus::Accepted, payload).await
	}

	async fn write_goaway(
		writer: &mut SplitWriter,
		last_stream_id: u32,
		reason: GoAwayReason,
	) -> Result<(), TightBeamError> {
		let package = GoAwayPackage::new(last_stream_id, reason);
		writer.write_envelope(package.into()).await?;
		Ok(())
	}

	/// Write a muxed request then its cancel (Rapid Reset open/cancel pair).
	async fn write_open_cancel<W: EnvelopeSink>(
		writer: &mut W,
		stream_id: u32,
		frame: Frame,
	) -> Result<(), TightBeamError> {
		write_muxed_request(writer, stream_id, frame).await?;
		let cancel = MuxCancelPackage::new(stream_id, CancelReason::Cancelled);
		writer.write_envelope(cancel.into()).await?;
		Ok(())
	}

	fn is_muxed_response(envelope: &TransportEnvelope, stream_id: u32) -> bool {
		matches!(
			envelope,
			TransportEnvelope::Mux(MuxEnvelope::End(package)) if package.stream_id() == stream_id
		)
	}

	/// Poll `shutdown` once so GoAway is sent and the allocator halts, then
	/// return the pinned future for the caller to await the drain.
	async fn kick_shutdown(
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

	fn is_echo(result: Option<Frame>, expected: &Frame) -> bool {
		result.as_ref() == Some(expected)
	}

	fn is_streams_exhausted(result: &Result<Option<Frame>, TransportError>) -> bool {
		matches!(result, Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted)))
	}

	fn is_busy(result: &Result<Option<Frame>, TransportError>) -> bool {
		matches!(result, Err(TransportError::OperationFailed(TransportFailure::Busy)))
	}

	fn is_draining(result: &Result<Option<Frame>, TransportError>) -> bool {
		matches!(result, Err(TransportError::Draining))
	}

	fn is_connection_closed(result: &Result<Option<Frame>, TransportError>) -> bool {
		matches!(result, Err(TransportError::ConnectionClosed))
	}

	fn is_invalid_message<T>(result: &Result<T, TransportError>) -> bool {
		matches!(result, Err(TransportError::InvalidMessage))
	}

	fn is_policy_rejection(result: &Result<(), TransportError>) -> bool {
		matches!(result, Err(TransportError::OperationFailed(TransportFailure::PolicyRejection)))
	}

	fn is_goaway(envelope: &TransportEnvelope, reason: GoAwayReason, last_stream_id: Option<u32>) -> bool {
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
	struct DropWitness(Arc<AbortContext>);

	impl Drop for DropWitness {
		fn drop(&mut self) {
			self.0.aborted.store(true, Ordering::SeqCst);
		}
	}

	/// One rekey headroom case:
	/// `drain_headroom = 2 * (local_cap + peer_cap) + 1`.
	struct RekeyCase {
		server_local_cap: u32,
		server_peer_cap: u32,
		rekey_limit: u64,
	}

	impl RekeyCase {
		fn headroom(&self) -> u64 {
			u64::from(self.server_local_cap)
				.saturating_add(u64::from(self.server_peer_cap))
				.saturating_mul(2)
				.saturating_add(1)
		}

		fn responses_before_goaway(&self) -> u32 {
			let headroom = self.headroom();
			debug_assert!(self.rekey_limit > headroom);
			(self.rekey_limit - headroom) as u32
		}
	}

	tb_assert_spec! {
		pub MuxInterleavedSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(first_stream_echoed, exactly!(1), equals!(true)),
				(second_stream_echoed, exactly!(1), equals!(true))
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
				let handler = order_forcing_echo(env.context.frame_first.clone(), Arc::new(Notify::new()));
				start_mux_server(&env.context.materials, 4, handler).await
			},
			client: |ClientEnv { trace, context: ctx, addr }| async move {
				let client = connect_mux_client(addr, &ctx.materials, 4).await?;

				let (first, second) = tokio::join!(
					client.handle().emit_on_stream(&ctx.frame_first),
					client.handle().emit_on_stream(&ctx.frame_second),
				);

				trace.event_with(MuxInterleavedSpec::first_stream_echoed, &[], is_echo(first?, &ctx.frame_first))?;
				trace.event_with(MuxInterleavedSpec::second_stream_echoed, &[], is_echo(second?, &ctx.frame_second))?;
				Ok(())
			}
		}
	}

	tb_assert_spec! {
		pub MuxCapExhaustionSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(negotiated_cap_is_one, exactly!(1), equals!(true)),
				(second_emit_streams_exhausted, exactly!(1), equals!(true)),
				(held_emit_echoes_after_release, exactly!(1), equals!(true))
			]
		}
	}

	// Cap=1: second concurrent emit StreamsExhausted. Succeeds after the
	// held slot frees.
	tb_scenario! {
		name: mux_cap_exhaustion,
		spec: MuxCapExhaustionSpec,
		environment ServiceClient {
			context: GatedMuxContext::generate(),
			server: |env| async move {
				start_mux_server(&env.context.materials, 1, gated_echo(Arc::clone(&env.context))).await
			},
			client: |ClientEnv { trace, context: ctx, addr }| async move {
				let client = connect_mux_client(addr, &ctx.materials, 4).await?;
				trace.event_with(
					MuxCapExhaustionSpec::negotiated_cap_is_one,
					&[],
					client.settings.local_initiated_cap == 1,
				)?;

				let frame_held = mux_frame("mux-held");
				let held_task = spawn_emit(client.handle(), frame_held.clone());

				ctx.started.notified().await;

				let exhausted = client.handle().emit_on_stream(&mux_frame("mux-extra")).await;
				trace.event_with(
					MuxCapExhaustionSpec::second_emit_streams_exhausted,
					&[],
					is_streams_exhausted(&exhausted),
				)?;

				ctx.release.notify_one();

				let echoed = await_ok(held_task, "held emit task must not panic").await?;
				trace.event_with(
					MuxCapExhaustionSpec::held_emit_echoes_after_release,
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
			gate: Accepted,
			assertions: [
				(handshake_negotiated_no_mux, exactly!(1), equals!(true)),
				(muxed_envelope_invalid_message, exactly!(1), equals!(true))
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
					MuxNonNegotiatedSpec::handshake_negotiated_no_mux,
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
					MuxNonNegotiatedSpec::muxed_envelope_invalid_message,
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
			gate: Accepted,
			assertions: [
				(followup_echoes_on_freed_slot, exactly!(1), equals!(true)),
				(handler_aborted_on_cancel, exactly!(1), equals!(true))
			]
		}
	}

	// Drop unresolved emit: frees cap slot and aborts the server handler.
	tb_scenario! {
		name: mux_cancel_frees_slot_and_aborts_handler,
		spec: MuxCancelAbortSpec,
		environment ServiceClient {
			context: AbortContext::generate(),
			server: |env| async move {
				start_mux_server(&env.context.materials, 1, first_parks_then_echo(Arc::clone(&env.context))).await
			},
			client: |ClientEnv { trace, context: ctx, addr }| async move {
				let client = connect_mux_client(addr, &ctx.materials, 1).await?;
				let cancelled_task = spawn_emit(client.handle(), mux_frame("mux-cancelled"));

				ctx.started.notified().await;

				abort_emit(cancelled_task).await;

				let frame_followup = mux_frame("mux-followup");
				let echoed = client.handle().emit_on_stream(&frame_followup).await?;

				trace.event_with(
					MuxCancelAbortSpec::followup_echoes_on_freed_slot,
					&[],
					is_echo(echoed, &frame_followup),
				)?;
				trace.event_with(
					MuxCancelAbortSpec::handler_aborted_on_cancel,
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
			gate: Accepted,
			assertions: [
				(cancel_observed_on_wire, exactly!(1), equals!(true)),
				(followup_echoes_after_race, exactly!(1), equals!(true))
			]
		}
	}

	// Stale response after cancel is discarded. Later streams stay healthy.
	tb_scenario! {
		name: mux_cancel_response_race_discarded,
		spec: MuxCancelRaceSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let mut link = establish_client_mux_server_raw(4).await?;
				let frame_cancelled = mux_frame("mux-raced");

				let raced_task = spawn_emit(&link.client.handle, frame_cancelled.clone());
				let raced_stream_id = read_muxed_request_id(&mut link.server_reader).await?;

				abort_emit(raced_task).await;

				let cancel = link.server_reader.read_envelope().await?;
				let cancel_ok = matches!(
					&cancel,
					TransportEnvelope::Mux(MuxEnvelope::Cancel(package)) if package.stream_id() == raced_stream_id
				);

				trace.event_with(MuxCancelRaceSpec::cancel_observed_on_wire, &[], cancel_ok)?;

				write_muxed_echo(&mut link.server_writer, raced_stream_id, &Arc::new(frame_cancelled)).await?;

				let followup_echoed = raw_echo_roundtrip(&mut link, &mux_frame("mux-alive")).await?;
				trace.event_with(MuxCancelRaceSpec::followup_echoes_after_race, &[], followup_echoed)?;

				Ok(())
			}
		}
	}

	tb_assert_spec! {
		pub MuxEndGarbageSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(busy_garbage_resolves_as_busy, exactly!(1), equals!(true)),
				(followup_echoes_after_garbage, exactly!(1), equals!(true))
			]
		}
	}

	// Garbage End payloads must stay per-stream: a stale end (cancelled
	// stream) is discarded unread and a non-Accepted trailer resolves its
	// stream without decoding. Neither may tear down the connection.
	tb_scenario! {
		name: mux_end_garbage_payload_tolerated,
		spec: MuxEndGarbageSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let mut link = establish_client_mux_server_raw(4).await?;
				let garbage = vec![0xDE, 0xAD];

				// Stale end: cancelled stream carrying garbage. Must be discarded.
				let stale_task = spawn_emit(&link.client.handle, mux_frame("mux-stale-garbage"));
				let stale_id = read_muxed_request_id(&mut link.server_reader).await?;

				abort_emit(stale_task).await;
				let _cancel = link.server_reader.read_envelope().await?;
				write_muxed_end(&mut link.server_writer, stale_id, TransitStatus::Accepted, garbage.clone()).await?;

				// Busy trailer carrying garbage. Must resolve per-stream as Busy.
				let busy_task = spawn_emit(&link.client.handle, mux_frame("mux-busy-garbage"));
				let busy_id = read_muxed_request_id(&mut link.server_reader).await?;

				write_muxed_end(&mut link.server_writer, busy_id, TransitStatus::Busy, garbage).await?;
				let busy = join_task(busy_task, "busy emit task must not panic").await?;
				trace.event_with(MuxEndGarbageSpec::busy_garbage_resolves_as_busy, &[], is_busy(&busy))?;

				// Connection must remain healthy: a follow-up stream still echoes.
				let followup_echoed = raw_echo_roundtrip(&mut link, &mux_frame("mux-after-garbage")).await?;
				trace.event_with(MuxEndGarbageSpec::followup_echoes_after_garbage, &[], followup_echoed)?;

				Ok(())
			}
		}
	}

	tb_assert_spec! {
		pub MuxGoAwayDrainSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(late_emit_refused_draining, exactly!(1), equals!(true)),
				(inflight_drains_to_echo, exactly!(1), equals!(true))
			]
		}
	}

	// Shutdown GoAway drains in-flight work and rejects new streams as Draining.
	tb_scenario! {
		name: mux_goaway_drains_and_rejects_new,
		spec: MuxGoAwayDrainSpec,
		environment ServiceClient {
			context: GatedMuxContext::generate(),
			server: |env| async move {
				start_mux_server(&env.context.materials, 4, gated_echo(Arc::clone(&env.context))).await
			},
			client: |ClientEnv { trace, context: ctx, addr }| async move {
				let client = connect_mux_client(addr, &ctx.materials, 4).await?;

				let frame_inflight = mux_frame("mux-inflight");
				let inflight_task = spawn_emit(client.handle(), frame_inflight.clone());

				ctx.started.notified().await;

				let shutdown_future = kick_shutdown(client.handle()).await;
				let late = client.handle().emit_on_stream(&mux_frame("mux-late")).await;

				trace.event_with(MuxGoAwayDrainSpec::late_emit_refused_draining, &[], is_draining(&late))?;

				ctx.release.notify_one();

				let echoed = await_ok(inflight_task, "in-flight emit task must not panic").await?;
				trace.event_with(MuxGoAwayDrainSpec::inflight_drains_to_echo, &[], is_echo(echoed, &frame_inflight))?;

				shutdown_future.await?;
				Ok(())
			}
		}
	}

	/// Drive one rekey case over raw client halves against a muxed server.
	async fn run_rekey_case(case: RekeyCase) -> Result<bool, TightBeamError> {
		let responses_before_goaway = case.responses_before_goaway();
		let mut link = establish_server_mux_client_raw(
			case.server_local_cap,
			case.server_peer_cap,
			MuxEndpointConfig { rekey_limit: Some(case.rekey_limit), cancel_budget: None },
		)
		.await?;
		let _server_serve = spawn_immediate_echo(link.responder);

		let mut last_stream_id = 0u32;
		let mut responses_ok = true;
		for index in 0..responses_before_goaway {
			let stream_id = client_stream_id(index);
			last_stream_id = stream_id;
			write_muxed_request(&mut link.client_writer, stream_id, mux_frame("mux-rekey")).await?;

			let response = link.client_reader.read_envelope().await?;
			responses_ok &= is_muxed_response(&response, stream_id);
		}

		let goaway = link.client_reader.read_envelope().await?;
		let goaway_ok = is_goaway(&goaway, GoAwayReason::Shutdown, Some(last_stream_id));
		let late = link.server.handle.emit_on_stream(&mux_frame("mux-rekey-late")).await;
		let draining_ok = is_draining(&late);

		Ok(responses_ok && goaway_ok && draining_ok)
	}

	tb_assert_spec! {
		pub MuxRekeyHeadroomSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(rekey_case_holds, exactly!(4), equals!(true))
			]
		}
	}

	// Table of rekey drain headroom points:
	// `2 * (local_cap + peer_cap) + 1` vs record limit.
	tb_scenario! {
		name: mux_rekey_headroom_table,
		spec: MuxRekeyHeadroomSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				for case in [
					RekeyCase { server_local_cap: 2, server_peer_cap: 1, rekey_limit: 8 },
					RekeyCase { server_local_cap: 2, server_peer_cap: 1, rekey_limit: 9 },
					RekeyCase { server_local_cap: 4, server_peer_cap: 2, rekey_limit: 14 },
					RekeyCase { server_local_cap: 4, server_peer_cap: 2, rekey_limit: 15 },
				] {
					let holds = run_rekey_case(case).await?;
					trace.event_with(MuxRekeyHeadroomSpec::rekey_case_holds, &[], holds)?;
				}

				Ok(())
			}
		}
	}

	/// Both wire observations of a cancel-abuse run.
	struct CancelAbuseOutcome {
		goaway_enhance_your_calm: bool,
		responder_policy_rejection: bool,
	}

	/// Record both cancel-abuse observations under the scenario's keys.
	fn record_cancel_abuse(
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
	async fn run_cancel_abuse<R, W>(
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
			write_open_cancel(&mut client_writer, stream_id, frame.clone()).await?;
		}

		let goaway = client_reader.read_envelope().await?;
		let goaway_enhance_your_calm = is_goaway(&goaway, GoAwayReason::EnhanceYourCalm, Some(abuse_stream_id));

		let refused = join_task(serve_task, "responder task must not panic").await?;
		let responder_policy_rejection = is_policy_rejection(&refused);

		Ok(CancelAbuseOutcome { goaway_enhance_your_calm, responder_policy_rejection })
	}

	tb_assert_spec! {
		pub MuxCancelBudgetSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(goaway_enhance_your_calm, exactly!(1), equals!(true)),
				(responder_policy_rejection, exactly!(1), equals!(true))
			]
		}
	}

	// Budget N: N aborting cancels OK. N+1 yields GoAway(EnhanceYourCalm) and PolicyRejection.
	tb_scenario! {
		name: mux_cancel_budget_boundary,
		spec: MuxCancelBudgetSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let cancel_budget = 2;
				let link = establish_server_mux_client_raw(
					8,
					8,
					MuxEndpointConfig { rekey_limit: None, cancel_budget: Some(cancel_budget) },
				)
				.await?;

				let outcome =
					run_cancel_abuse(link.client_reader, link.client_writer, link.responder, cancel_budget).await?;

				record_cancel_abuse(
					&trace,
					&outcome,
					MuxCancelBudgetSpec::goaway_enhance_your_calm,
					MuxCancelBudgetSpec::responder_policy_rejection,
				)?;

				Ok(())
			}
		}
	}

	/// Server-initiated fixture. `done` releases the client (keeping its
	/// endpoint alive) once the server-side emit resolves and records its
	/// event.
	struct ServerInitContext {
		materials: ServerMaterials,
		done: Notify,
	}

	impl ServerInitContext {
		fn generate() -> Self {
			Self { materials: ServerMaterials::generate(), done: Notify::new() }
		}
	}

	tb_assert_spec! {
		pub MuxServerInitiatedSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(server_stream_echoed_by_client, exactly!(1), equals!(true))
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
					let Ok((server, _responder)) = accept_mux_server(listener, mux_offer(4)).await else {
						return;
					};

					let frame = mux_frame("mux-server-init");
					let echoed = server
						.handle
						.emit_on_stream(&frame)
						.await
						.is_ok_and(|reply| is_echo(reply, &frame));

					let _ = trace.event_with(MuxServerInitiatedSpec::server_stream_echoed_by_client, &[], echoed);

					ctx.done.notify_one();
				});
				Ok((task, addr))
			},
			client: |ClientEnv { context: ctx, addr, .. }| async move {
				let client = connect_mux_client(addr, &ctx.materials, 4).await?;
				let _client_serve = spawn_immediate_echo(client.responder);

				// Hold the client endpoint alive until the server-side emit
				// resolved and recorded its event.
				ctx.done.notified().await;
				Ok(())
			}
		}
	}

	tb_assert_spec! {
		pub MuxPeerGoAwaySpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(stream_above_watermark_draining, exactly!(1), equals!(true)),
				(stream_at_watermark_echoed, exactly!(1), equals!(true)),
				(late_emit_refused_draining, exactly!(1), equals!(true))
			]
		}
	}

	// Peer GoAway: keep ≤ watermark, fail pending above as Draining.
	tb_scenario! {
		name: mux_peer_goaway_fails_pending_above,
		spec: MuxPeerGoAwaySpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let mut link = establish_client_mux_server_raw(4).await?;

				let frame_kept = mux_frame("mux-kept");
				let kept_id = client_stream_id(0);
				let kept_task = spawn_emit(&link.client.handle, frame_kept.clone());
				let kept_message = expect_muxed_request(
					&mut link.server_reader,
					kept_id,
					"first client-initiated stream must be id 1",
				)
				.await?;

				let dropped_id = client_stream_id(1);
				let dropped_task = spawn_emit(&link.client.handle, mux_frame("mux-dropped"));
				let _ = expect_muxed_request(
					&mut link.server_reader,
					dropped_id,
					"second client-initiated stream must be id 3",
				)
				.await?;

				write_goaway(&mut link.server_writer, kept_id, GoAwayReason::Shutdown).await?;

				let dropped = join_task(dropped_task, "dropped emit task must not panic").await?;
				trace.event_with(MuxPeerGoAwaySpec::stream_above_watermark_draining, &[], is_draining(&dropped))?;

				write_muxed_echo(&mut link.server_writer, kept_id, &kept_message).await?;

				let kept = await_ok(kept_task, "kept emit task must not panic").await?;
				trace.event_with(MuxPeerGoAwaySpec::stream_at_watermark_echoed, &[], is_echo(kept, &frame_kept))?;

				let late = link.client.handle.emit_on_stream(&mux_frame("mux-after-peer-goaway")).await;
				trace.event_with(MuxPeerGoAwaySpec::late_emit_refused_draining, &[], is_draining(&late))?;

				Ok(())
			}
		}
	}

	tb_assert_spec! {
		pub MuxProtocolViolationSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(goaway_protocol_error, exactly!(1), equals!(true)),
				(pending_fails_connection_closed, exactly!(1), equals!(true))
			]
		}
	}

	// Non-mux envelope on mux peer: GoAway(ProtocolError) + pending ConnectionClosed.
	tb_scenario! {
		name: mux_protocol_violation_goaway_and_pending_fail,
		spec: MuxProtocolViolationSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let mut link = establish_client_mux_server_raw(4).await?;

				let inflight_task = spawn_emit(&link.client.handle, mux_frame("mux-proto-down"));
				let _ = expect_muxed_request(
					&mut link.server_reader,
					client_stream_id(0),
					"in-flight stream must be the first client id",
				)
				.await?;

				link.server_writer
					.write_envelope(TransportEnvelope::new_request(mux_frame("mux-proto-rogue")))
					.await?;

				let goaway = link.server_reader.read_envelope().await?;
				trace.event_with(
					MuxProtocolViolationSpec::goaway_protocol_error,
					&[],
					is_goaway(&goaway, GoAwayReason::ProtocolError, Some(0)),
				)?;

				let failed = join_task(inflight_task, "in-flight emit task must not panic").await?;
				trace.event_with(
					MuxProtocolViolationSpec::pending_fails_connection_closed,
					&[],
					is_connection_closed(&failed),
				)?;

				Ok(())
			}
		}
	}

	/// Frame claiming a V2+ field (priority) on a V0 frame: decodes fine
	/// but must fail version validation at the mux router.
	fn version_incompatible_frame_der() -> Result<Vec<u8>, TightBeamError> {
		let mut metadata = Metadata::default();
		metadata.priority = Some(MessagePriority::Standard);

		let frame = Frame {
			version: Version::V0,
			metadata,
			message: Vec::new(),
			integrity: None,
			nonrepudiation: None,
		};

		let der = frame.to_der()?;
		Ok(der)
	}

	/// Each offender gets a fresh mux server so one violation cannot mask
	/// the next.
	async fn violation_answered_with_goaway(offender: TransportEnvelope) -> Result<bool, TightBeamError> {
		let mut link = establish_server_mux_client_raw(4, 4, MuxEndpointConfig::default()).await?;
		let _server_serve = spawn_immediate_echo(link.responder);

		link.client_writer.write_envelope(offender).await?;

		let goaway = link.client_reader.read_envelope().await?;
		let rejected = is_goaway(&goaway, GoAwayReason::ProtocolError, None);
		Ok(rejected)
	}

	tb_assert_spec! {
		pub MuxGrammarViolationSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(offender_answered_with_goaway, exactly!(6), equals!(true))
			]
		}
	}

	// Every encodable stream-grammar violation must be answered with
	// GoAway(ProtocolError).
	tb_scenario! {
		name: mux_stream_grammar_violations_rejected,
		spec: MuxGrammarViolationSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let chunk = mux_frame("mux-violation").to_der()?;
				let offenders: Vec<TransportEnvelope> = vec![
					// Continuation chunk: chunking is never negotiated
					MuxDataPackage::new(1, true, chunk.clone())?.into(),
					// Credit grant: chunking is never negotiated
					MuxCreditPackage::new(1, 8).into(),
					// Open promising later chunks
					MuxOpenPackage::new(1, false, chunk)?.into(),
					// Open whose payload is not a frame
					MuxOpenPackage::new(1, true, vec![0xDE, 0xAD])?.into(),
					// Open without a message (requests must carry one)
					MuxOpenPackage::new(1, true, Vec::new())?.into(),
					// Open whose frame claims fields its version forbids
					MuxOpenPackage::new(1, true, version_incompatible_frame_der()?)?.into(),
				];

				for offender in offenders {
					let rejected = violation_answered_with_goaway(offender).await?;
					trace.event_with(MuxGrammarViolationSpec::offender_answered_with_goaway, &[], rejected)?;
				}

				Ok(())
			}
		}
	}

	tb_assert_spec! {
		pub MuxConnectionDropSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(emit_fails_connection_closed, exactly!(1), equals!(true))
			]
		}
	}

	// Peer close mid-emit surfaces ConnectionClosed after reader EOF.
	tb_scenario! {
		name: mux_connection_drop_mid_emit,
		spec: MuxConnectionDropSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let mut link = establish_client_mux_server_raw(4).await?;

				let emit_task = spawn_emit(&link.client.handle, mux_frame("mux-drop"));
				let _ = expect_muxed_request(
					&mut link.server_reader,
					client_stream_id(0),
					"dropped stream must be the first client id",
				)
				.await?;

				drop(link.server_reader);
				drop(link.server_writer);

				let failed = join_task(emit_task, "emit task must not panic").await?;
				trace.event_with(
					MuxConnectionDropSpec::emit_fails_connection_closed,
					&[],
					is_connection_closed(&failed),
				)?;

				Ok(())
			}
		}
	}

	tb_assert_spec! {
		pub MuxCleartextInterleavedSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(first_stream_echoed, exactly!(1), equals!(true)),
				(second_stream_echoed, exactly!(1), equals!(true))
			]
		}
	}

	// Cleartext mux over raw TCP: no handshake, symmetric out-of-band
	// settings, two interleaved streams answered out of order.
	tb_scenario! {
		name: mux_cleartext_interleaved_echo,
		spec: MuxCleartextInterleavedSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let (client, server) = establish_cleartext_transports().await?;
				let settings = MuxSettings::symmetric(4);
				let (client_end, _client_responder) =
					spawn_cleartext_mux_endpoint(client, MuxRole::Client, settings, None)?;
				let (_server_end, server_responder) =
					spawn_cleartext_mux_endpoint(server, MuxRole::Server, settings, None)?;

				let frame_first = mux_frame("clear-first");
				let frame_second = mux_frame("clear-second");
				let gate = Arc::new(Notify::new());
				let handler = order_forcing_echo(frame_first.clone(), gate);
				let _server_serve = tokio::spawn(server_responder.serve(handler));

				let (first, second) = tokio::join!(
					client_end.handle.emit_on_stream(&frame_first),
					client_end.handle.emit_on_stream(&frame_second),
				);

				trace.event_with(
					MuxCleartextInterleavedSpec::first_stream_echoed,
					&[],
					is_echo(first?, &frame_first),
				)?;
				trace.event_with(
					MuxCleartextInterleavedSpec::second_stream_echoed,
					&[],
					is_echo(second?, &frame_second),
				)?;

				Ok(())
			}
		}
	}

	tb_assert_spec! {
		pub MuxCleartextCancelBudgetSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(goaway_enhance_your_calm, exactly!(1), equals!(true)),
				(responder_policy_rejection, exactly!(1), equals!(true))
			]
		}
	}

	// Cancel-budget hardening holds on cleartext links too: budget + 1
	// open/cancel pairs answered with GoAway(EnhanceYourCalm).
	tb_scenario! {
		name: mux_cleartext_cancel_budget,
		spec: MuxCleartextCancelBudgetSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let (client, server) = establish_cleartext_transports().await?;
				let cancel_budget = 2;
				let settings = MuxSettings::symmetric(8);
				let (_server_end, responder) =
					spawn_cleartext_mux_endpoint(server, MuxRole::Server, settings, Some(cancel_budget))?;
				let (client_reader, client_writer) = client.into_split_cleartext()?;

				let outcome = run_cancel_abuse(client_reader, client_writer, responder, cancel_budget).await?;
				record_cancel_abuse(
					&trace,
					&outcome,
					MuxCleartextCancelBudgetSpec::goaway_enhance_your_calm,
					MuxCleartextCancelBudgetSpec::responder_policy_rejection,
				)?;

				Ok(())
			}
		}
	}

	/// Ping-roundtrip fixture. `server_ping_done` holds the client open
	/// until the server-to-client probe records its event. `handler_calls`
	/// proves pings never touch the handler.
	struct PingContext {
		materials: ServerMaterials,
		handler_calls: AtomicU32,
		server_ping_done: Notify,
	}

	impl PingContext {
		fn generate() -> Self {
			Self {
				materials: ServerMaterials::generate(),
				handler_calls: AtomicU32::new(0),
				server_ping_done: Notify::new(),
			}
		}
	}

	tb_assert_spec! {
		pub MuxPingRoundtripSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(client_ping_acked, exactly!(1), equals!(true)),
				(server_ping_acked, exactly!(1), equals!(true)),
				(stream_echoes_after_pings, exactly!(1), equals!(true)),
				(handler_saw_only_stream, exactly!(1), equals!(true))
			]
		}
	}

	// Ping resolves in both directions and never invokes the handler.
	// The server-to-client probe is acked with no responder serving the
	// client side, proving the ack terminates in the reader driver.
	tb_scenario! {
		name: mux_ping_roundtrip,
		spec: MuxPingRoundtripSpec,
		environment ServiceClient {
			context: PingContext::generate(),
			server: |SetupEnv { trace, context: ping }| async move {
				let (listener, addr) = bind_encrypted_listener(&ping.materials).await?;
				let task = tokio::spawn(async move {
					let Ok((server, responder)) = accept_mux_server(listener, mux_offer(4)).await else {
						return;
					};

					let ping_ctx = Arc::clone(&ping);
					let handler = move |frame: Arc<Frame>| {
						ping_ctx.handler_calls.fetch_add(1, Ordering::SeqCst);
						core::future::ready(echo_response(&frame))
					};
					let _serve = tokio::spawn(responder.serve(handler));

					let acked = server.handle.ping().await.is_ok();
					let _ = trace.event_with(MuxPingRoundtripSpec::server_ping_acked, &[], acked);
					ping.server_ping_done.notify_one();
				});
				Ok((task, addr))
			},
			client: |ClientEnv { trace, context: ping, addr }| async move {
				let client = connect_mux_client(addr, &ping.materials, 4).await?;

				trace.event_with(MuxPingRoundtripSpec::client_ping_acked, &[], client.handle().ping().await.is_ok())?;
				ping.server_ping_done.notified().await;

				let frame = mux_frame("mux-ping-alive");
				let echoed = client.handle().emit_on_stream(&frame).await?;
				trace.event_with(MuxPingRoundtripSpec::stream_echoes_after_pings, &[], is_echo(echoed, &frame))?;
				trace.event_with(
					MuxPingRoundtripSpec::handler_saw_only_stream,
					&[],
					ping.handler_calls.load(Ordering::SeqCst) == 1,
				)?;

				Ok(())
			}
		}
	}

	tb_assert_spec! {
		pub MuxPingWireAckSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(probe_answered_with_matching_ack, exactly!(1), equals!(true)),
				(followup_echoes_after_stray_ack, exactly!(1), equals!(true))
			]
		}
	}

	// A probe written on raw halves is answered with its ack, and an
	// unsolicited ack is discarded without tearing down the connection.
	tb_scenario! {
		name: mux_ping_wire_ack,
		spec: MuxPingWireAckSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let mut link = establish_client_mux_server_raw(4).await?;

				let probe = MuxPingPackage::new(false, 42);
				link.server_writer.write_envelope(probe.into()).await?;

				let ack = link.server_reader.read_envelope().await?;
				let ack_ok = matches!(
					&ack,
					TransportEnvelope::Mux(MuxEnvelope::Ping(package)) if package.ack() && package.opaque() == 42
				);

				trace.event_with(MuxPingWireAckSpec::probe_answered_with_matching_ack, &[], ack_ok)?;

				let stray_ack = MuxPingPackage::new(true, 999);
				link.server_writer.write_envelope(stray_ack.into()).await?;

				let followup_echoed = raw_echo_roundtrip(&mut link, &mux_frame("mux-ping-follow-up")).await?;
				trace.event_with(MuxPingWireAckSpec::followup_echoes_after_stray_ack, &[], followup_echoed)?;

				Ok(())
			}
		}
	}

	tb_assert_spec! {
		pub MuxPingDrainingSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(ping_refused_draining, exactly!(1), equals!(true)),
				(inflight_drains_to_echo, exactly!(1), equals!(true))
			]
		}
	}

	// Once GoAway is sent, new pings are refused as `Draining` while the
	// in-flight stream still drains to completion.
	tb_scenario! {
		name: mux_ping_draining,
		spec: MuxPingDrainingSpec,
		environment ServiceClient {
			context: GatedMuxContext::generate(),
			server: |env| async move {
				start_mux_server(&env.context.materials, 4, gated_echo(Arc::clone(&env.context))).await
			},
			client: |ClientEnv { trace, context: ctx, addr }| async move {
				let client = connect_mux_client(addr, &ctx.materials, 4).await?;

				let frame_inflight = mux_frame("mux-ping-inflight");
				let inflight_task = spawn_emit(client.handle(), frame_inflight.clone());
				ctx.started.notified().await;

				let shutdown_future = kick_shutdown(client.handle()).await;
				let refused = client.handle().ping().await;
				trace.event_with(
					MuxPingDrainingSpec::ping_refused_draining,
					&[],
					matches!(refused, Err(TransportError::Draining)),
				)?;

				ctx.release.notify_one();

				let echoed = await_ok(inflight_task, "in-flight emit task must not panic").await?;
				trace.event_with(MuxPingDrainingSpec::inflight_drains_to_echo, &[], is_echo(echoed, &frame_inflight))?;

				shutdown_future.await?;
				Ok(())
			}
		}
	}

	/// Pins [`super::MUX_OPEN_WIRE_DER`] to real encoder output so the
	/// non-mux rejection test rejects the same bytes a mux build emits.
	#[test]
	fn mux_open_wire_literal_matches_encoder() -> Result<(), TightBeamError> {
		let open_package = MuxOpenPackage::new(1, true, Vec::new())?;
		let envelope = TransportEnvelope::from(open_package);

		let encoded = envelope.to_der()?;
		assert_eq!(encoded, super::MUX_OPEN_WIRE_DER, "wire literal must match encoder output");
		Ok(())
	}
}

#[cfg(not(feature = "transport-multiplex"))]
mod without_multiplex {
	use tightbeam::der::Decode;
	use tightbeam::transport::TransportEnvelope;

	/// Context tag 4 (`Mux`) is not a valid `TransportEnvelope`
	/// alternative when multiplexing is compiled out, so the envelope must
	/// fail to decode instead of being silently misinterpreted.
	#[test]
	fn muxed_wire_tag_fails_decode_on_non_mux_build() {
		assert!(
			TransportEnvelope::from_der(&super::MUX_OPEN_WIRE_DER).is_err(),
			"mux wire tag must not decode when multiplexing is compiled out"
		);
	}
}
