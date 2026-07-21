//! Multiplexed transport integration tests.
//!
//! Drives ECIES handshakes with transport negotiation over TCP,
//! assembles `MuxTransport` routers from the split halves, and verifies:
//!
//! - Concurrent interleaved streams with out-of-order response correlation
//! - Local-initiated cap exhaustion answered with `Busy`
//! - Muxed envelopes rejected on a connection that never negotiated mux
//! - Cancelling an in-flight stream frees its cap slot and aborts the handler
//! - A response racing a cancel on the connection is discarded cleanly
//! - GoAway drains in-flight streams and rejects new ones
//! - Rekey drain headroom table (`2 * (local_cap + peer_cap) + 1` vs record limit)
//! - Cancel-budget boundary: N cancels OK, N+1 yields GoAway(EnhanceYourCalm)
//! - Server-initiated stream roundtrip (client `serve`, server `emit_on_stream`)
//! - Peer GoAway fails pending above `last_stream_id` and rejects new streams
//! - Non-mux envelope on a mux peer: GoAway(ProtocolError) and pending fail
//! - Connection drop mid-emit: `ConnectionClosed`
//! - Cleartext mux (no handshake, symmetric settings): interleaved echo and
//!   cancel-budget GoAway parallel the encrypted scenarios

#![cfg(all(
	feature = "transport-ecies",
	feature = "transport-policy",
	feature = "tcp",
	feature = "tokio",
	feature = "testing"
))]

#[cfg(feature = "transport-multiplex")]
mod negotiated {
	use core::future::{poll_fn, Future};
	use core::pin::Pin;
	use core::task::Poll;
	use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
	use std::sync::Arc;

	use tightbeam::crypto::profiles::DefaultCryptoProvider;
	use tightbeam::exactly;
	use tightbeam::policy::TransitStatus;
	use tightbeam::tb_assert_spec;
	use tightbeam::tb_scenario;
	use tightbeam::testing::config::ScenarioConf;
	use tightbeam::testing::create_v0_tightbeam;
	use tightbeam::trace::TraceCollector;
	use tightbeam::transport::envelopes::{
		CancelReason, GoAwayPackage, GoAwayReason, MuxCancelPackage, MuxedRequestPackage, MuxedResponsePackage,
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

	tb_assert_spec! {
		pub MultiplexTransportSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				("mux_interleaved_out_of_order", exactly!(1), equals!(true)),
				("mux_cap_exhaustion_busy", exactly!(1), equals!(true)),
				("mux_non_negotiated_rejected", exactly!(1), equals!(true)),
				("mux_cancel_frees_slot_and_aborts_handler", exactly!(1), equals!(true)),
				("mux_cancel_response_race_discarded", exactly!(1), equals!(true)),
				("mux_goaway_drains_and_rejects_new", exactly!(1), equals!(true)),
				("mux_rekey_headroom_table", exactly!(1), equals!(true)),
				("mux_cancel_budget_boundary", exactly!(1), equals!(true)),
				("mux_server_initiated_roundtrip", exactly!(1), equals!(true)),
				("mux_peer_goaway_fails_pending_above", exactly!(1), equals!(true)),
				("mux_protocol_violation_goaway_and_pending_fail", exactly!(1), equals!(true)),
				("mux_connection_drop_mid_emit", exactly!(1), equals!(true)),
				("mux_cleartext_interleaved_echo", exactly!(1), equals!(true)),
				("mux_cleartext_cancel_budget", exactly!(1), equals!(true))

			]
		}
	}

	tb_scenario! {
		name: multiplex_transport,
		config: ScenarioConf::<()>::builder()
			.with_spec(MultiplexTransportSpec::latest())
			.build(),
		environment Bare {
			exec: |trace| async move {
				mux_interleaved_out_of_order(&trace).await?;
				mux_cap_exhaustion_busy(&trace).await?;
				mux_non_negotiated_rejected(&trace).await?;
				mux_cancel_frees_slot_and_aborts_handler(&trace).await?;
				mux_cancel_response_race_discarded(&trace).await?;
				mux_goaway_drains_and_rejects_new(&trace).await?;
				mux_rekey_headroom_table(&trace).await?;
				mux_cancel_budget_boundary(&trace).await?;
				mux_server_initiated_roundtrip(&trace).await?;
				mux_peer_goaway_fails_pending_above(&trace).await?;
				mux_protocol_violation_goaway_and_pending_fail(&trace).await?;
				mux_connection_drop_mid_emit(&trace).await?;
				mux_cleartext_interleaved_echo(&trace).await?;
				mux_cleartext_cancel_budget(&trace).await?;
				Ok(())
			}
		}
	}

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
			let (mut transport, _) = listener.accept().await.map_err(TransportError::from)?;
			if let Some(offer) = server_offer {
				transport = transport.with_mux_config(offer);
			}

			// ECIES is exactly two client messages: ClientHello, ClientKeyExchange.
			serve_one_handshake_message(&mut transport).await?;
			serve_one_handshake_message(&mut transport).await?;
			Ok::<_, TightBeamError>(transport)
		});

		let mut client = connect_pinned_client(addr, &materials.certificate).await?;
		if let Some(offer) = client_offer {
			client = client.with_mux_config(offer);
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

	/// Client and server mux endpoints after a negotiated handshake.
	struct MuxPair {
		client: MuxEndpoint,
		server: MuxEndpoint,
		client_responder: MuxResponder,
		server_responder: MuxResponder,
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
		let listener = TokioListener::<DefaultCryptoProvider>::bind("127.0.0.1:0")
			.await
			.map_err(TransportError::from)?;
		let addr = listener.local_addr().map_err(TransportError::from)?;

		let accept_task = tokio::spawn(async move {
			let (transport, _) = listener.accept().await.map_err(TransportError::from)?;
			Ok::<_, TightBeamError>(transport)
		});

		let stream = TcpStream::connect(addr).await.map_err(TransportError::from)?;
		let client = TcpTransport::from(TokioStream::from(stream));

		let server = await_ok(accept_task, "cleartext accept task must not panic").await?;
		Ok((client, server))
	}

	/// Handshake with matching mux caps and spawn both endpoints.
	async fn establish_mux_pair(cap: u32) -> Result<MuxPair, TightBeamError> {
		let (client, server) = establish_matched_transports(cap).await?;
		let (client_end, client_responder) = spawn_mux_endpoint(client, MuxRole::Client)?;
		let (server_end, server_responder) = spawn_mux_endpoint(server, MuxRole::Server)?;

		Ok(MuxPair { client: client_end, server: server_end, client_responder, server_responder })
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

	/// First invocation parks forever (until aborted). Later ones echo.
	fn first_parks_then_echo(
		started: Arc<Notify>,
		never: Arc<Notify>,
		aborted: Arc<AtomicBool>,
		calls: Arc<AtomicU32>,
	) -> impl Fn(Arc<Frame>) -> HandlerFuture {
		move |frame: Arc<Frame>| {
			let started = Arc::clone(&started);
			let never = Arc::clone(&never);
			let aborted = Arc::clone(&aborted);
			let calls = Arc::clone(&calls);

			Box::pin(async move {
				if calls.fetch_add(1, Ordering::SeqCst) == 0 {
					let _witness = DropWitness(aborted);
					started.notify_one();
					never.notified().await;
				}

				echo_response(&frame)
			})
		}
	}

	fn spawn_emit(handle: &MuxHandle, frame: Frame) -> EmitTask {
		let handle = handle.clone();
		tokio::spawn(async move { handle.emit_on_stream(frame).await })
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
			TransportEnvelope::MuxedRequest(package) => Ok((package.stream_id(), Arc::clone(package.message()))),
			_ => Err(expectation_failure("peer must receive a muxed request")),
		}
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
		let request = MuxedRequestPackage::new(stream_id, frame);
		writer.write_envelope(request.into()).await?;
		Ok(())
	}

	async fn write_muxed_echo(
		writer: &mut SplitWriter,
		stream_id: u32,
		frame: &Arc<Frame>,
	) -> Result<(), TightBeamError> {
		let response = MuxedResponsePackage::new(stream_id, echo_response(frame));
		writer.write_envelope(response.into()).await?;
		Ok(())
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
			TransportEnvelope::MuxedResponse(package) if package.stream_id() == stream_id
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
			TransportEnvelope::GoAway(package) => {
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
	struct DropWitness(Arc<AtomicBool>);

	impl Drop for DropWitness {
		fn drop(&mut self) {
			self.0.store(true, Ordering::SeqCst);
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

	/// Two concurrent streams: server answers reverse order. Correlate by ID.
	async fn mux_interleaved_out_of_order(trace: &TraceCollector) -> Result<(), TightBeamError> {
		let pair = establish_mux_pair(4).await?;
		let frame_first = mux_frame("mux-first");
		let frame_second = mux_frame("mux-second");

		let gate = Arc::new(Notify::new());
		let handler = order_forcing_echo(frame_first.clone(), gate);
		let _server_serve = tokio::spawn(pair.server_responder.serve(handler));

		let (first, second) = tokio::join!(
			pair.client.handle.emit_on_stream(frame_first.clone()),
			pair.client.handle.emit_on_stream(frame_second.clone()),
		);

		let ok = is_echo(first?, &frame_first) && is_echo(second?, &frame_second);
		trace.event_with("mux_interleaved_out_of_order", &[], ok)?;
		Ok(())
	}

	/// Cap=1: second concurrent emit Busy. Succeeds after the held slot frees.
	async fn mux_cap_exhaustion_busy(trace: &TraceCollector) -> Result<(), TightBeamError> {
		let (client, server) = establish_transports(Some(mux_offer(4)), Some(mux_offer(1))).await?;
		let settings = client
			.negotiated_mux()
			.ok_or_else(|| expectation_failure("client must negotiate multiplexing"))?;
		let cap_ok = settings.local_initiated_cap == 1;

		let (client_end, _) = spawn_mux_endpoint(client, MuxRole::Client)?;
		let (_, server_responder) = spawn_mux_endpoint(server, MuxRole::Server)?;
		let (started, release, _server_serve) = spawn_gated_echo(server_responder);

		let frame_held = mux_frame("mux-held");
		let held_task = spawn_emit(&client_end.handle, frame_held.clone());
		started.notified().await;

		let busy = client_end.handle.emit_on_stream(mux_frame("mux-extra")).await;
		let busy_ok = is_busy(&busy);
		release.notify_one();

		let echoed = await_ok(held_task, "held emit task must not panic").await?;
		let echo_ok = is_echo(echoed, &frame_held);

		trace.event_with("mux_cap_exhaustion_busy", &[], cap_ok && busy_ok && echo_ok)?;
		Ok(())
	}

	/// Muxed envelope on a non-mux connection must be InvalidMessage.
	async fn mux_non_negotiated_rejected(trace: &TraceCollector) -> Result<(), TightBeamError> {
		let (client, server) = establish_transports(None, None).await?;
		let no_mux = client.negotiated_mux().is_none();

		let server_task = tokio::spawn(async move {
			let mut transport = server.with_handler(Some);
			transport.handle_request().await
		});

		let (_reader, mut writer) = client.into_split()?;
		write_muxed_request(&mut writer, 1, mux_frame("mux-rogue")).await?;

		let result = join_task(server_task, "lock-step server task must not panic").await?;
		let rejected = is_invalid_message(&result);

		trace.event_with("mux_non_negotiated_rejected", &[], no_mux && rejected)?;
		Ok(())
	}

	/// Drop unresolved emit: frees cap slot and aborts the server handler.
	async fn mux_cancel_frees_slot_and_aborts_handler(trace: &TraceCollector) -> Result<(), TightBeamError> {
		let pair = establish_mux_pair(1).await?;

		let started = Arc::new(Notify::new());
		let never = Arc::new(Notify::new());
		let aborted = Arc::new(AtomicBool::new(false));
		let calls = Arc::new(AtomicU32::new(0));
		let handler = first_parks_then_echo(
			Arc::clone(&started),
			Arc::clone(&never),
			Arc::clone(&aborted),
			Arc::clone(&calls),
		);
		let _server_serve = tokio::spawn(pair.server_responder.serve(handler));

		let cancelled_task = spawn_emit(&pair.client.handle, mux_frame("mux-cancelled"));
		started.notified().await;
		abort_emit(cancelled_task).await;

		let frame_followup = mux_frame("mux-followup");
		let echoed = pair.client.handle.emit_on_stream(frame_followup.clone()).await?;
		let ok = is_echo(echoed, &frame_followup) && aborted.load(Ordering::SeqCst);

		trace.event_with("mux_cancel_frees_slot_and_aborts_handler", &[], ok)?;
		Ok(())
	}

	/// Stale response after cancel is discarded. Later streams stay healthy.
	async fn mux_cancel_response_race_discarded(trace: &TraceCollector) -> Result<(), TightBeamError> {
		let mut link = establish_client_mux_server_raw(4).await?;
		let frame_cancelled = mux_frame("mux-raced");
		let frame_followup = mux_frame("mux-alive");

		let raced_task = spawn_emit(&link.client.handle, frame_cancelled.clone());
		let raced_stream_id = {
			let (id, _) = read_muxed_request(&mut link.server_reader).await?;
			id
		};

		abort_emit(raced_task).await;

		let cancel = link.server_reader.read_envelope().await?;
		let cancel_ok = matches!(
			&cancel,
			TransportEnvelope::MuxCancel(package) if package.stream_id() == raced_stream_id
		);

		write_muxed_echo(&mut link.server_writer, raced_stream_id, &Arc::new(frame_cancelled)).await?;

		let followup_task = spawn_emit(&link.client.handle, frame_followup.clone());
		let (followup_id, followup_message) = read_muxed_request(&mut link.server_reader).await?;
		write_muxed_echo(&mut link.server_writer, followup_id, &followup_message).await?;

		let echoed = await_ok(followup_task, "follow-up emit task must not panic").await?;
		let ok = cancel_ok && is_echo(echoed, &frame_followup);

		trace.event_with("mux_cancel_response_race_discarded", &[], ok)?;
		Ok(())
	}

	/// Shutdown GoAway drains in-flight work and rejects new streams as Draining.
	async fn mux_goaway_drains_and_rejects_new(trace: &TraceCollector) -> Result<(), TightBeamError> {
		let pair = establish_mux_pair(4).await?;
		let (started, release, _server_serve) = spawn_gated_echo(pair.server_responder);

		let frame_inflight = mux_frame("mux-inflight");
		let inflight_task = spawn_emit(&pair.client.handle, frame_inflight.clone());
		started.notified().await;

		let shutdown_future = kick_shutdown(&pair.client.handle).await;
		let late = pair.client.handle.emit_on_stream(mux_frame("mux-late")).await;
		let draining_ok = is_draining(&late);

		release.notify_one();

		let echoed = await_ok(inflight_task, "in-flight emit task must not panic").await?;
		let drain_ok = is_echo(echoed, &frame_inflight);
		shutdown_future.await?;

		trace.event_with("mux_goaway_drains_and_rejects_new", &[], draining_ok && drain_ok)?;
		Ok(())
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
		let late = link.server.handle.emit_on_stream(mux_frame("mux-rekey-late")).await;
		let draining_ok = is_draining(&late);

		Ok(responses_ok && goaway_ok && draining_ok)
	}

	/// Table of rekey drain headroom points:
	/// `2 * (local_cap + peer_cap) + 1` vs record limit.
	async fn mux_rekey_headroom_table(trace: &TraceCollector) -> Result<(), TightBeamError> {
		let mut ok = true;
		for case in [
			RekeyCase { server_local_cap: 2, server_peer_cap: 1, rekey_limit: 8 },
			RekeyCase { server_local_cap: 2, server_peer_cap: 1, rekey_limit: 9 },
			RekeyCase { server_local_cap: 4, server_peer_cap: 2, rekey_limit: 14 },
			RekeyCase { server_local_cap: 4, server_peer_cap: 2, rekey_limit: 15 },
		] {
			ok &= run_rekey_case(case).await?;
		}

		trace.event_with("mux_rekey_headroom_table", &[], ok)?;
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
			write_open_cancel(&mut client_writer, stream_id, frame.clone()).await?;
		}

		let goaway = client_reader.read_envelope().await?;
		let goaway_ok = is_goaway(&goaway, GoAwayReason::EnhanceYourCalm, Some(abuse_stream_id));

		let refused = join_task(serve_task, "responder task must not panic").await?;
		let refused_ok = is_policy_rejection(&refused);

		Ok(goaway_ok && refused_ok)
	}

	/// Budget N: N aborting cancels OK. N+1 yields GoAway(EnhanceYourCalm) and PolicyRejection.
	async fn mux_cancel_budget_boundary(trace: &TraceCollector) -> Result<(), TightBeamError> {
		let cancel_budget = 2;
		let link = establish_server_mux_client_raw(
			8,
			8,
			MuxEndpointConfig { rekey_limit: None, cancel_budget: Some(cancel_budget) },
		)
		.await?;

		let ok = run_cancel_abuse(link.client_reader, link.client_writer, link.responder, cancel_budget).await?;
		trace.event_with("mux_cancel_budget_boundary", &[], ok)?;
		Ok(())
	}

	/// Server initiates an even stream. Client `serve` echoes.
	async fn mux_server_initiated_roundtrip(trace: &TraceCollector) -> Result<(), TightBeamError> {
		let pair = establish_mux_pair(4).await?;
		let _client_serve = spawn_immediate_echo(pair.client_responder);

		let frame = mux_frame("mux-server-init");
		let echoed = pair.server.handle.emit_on_stream(frame.clone()).await?;
		trace.event_with("mux_server_initiated_roundtrip", &[], is_echo(echoed, &frame))?;
		Ok(())
	}

	/// Peer GoAway: keep ≤ watermark, fail pending above as Draining.
	async fn mux_peer_goaway_fails_pending_above(trace: &TraceCollector) -> Result<(), TightBeamError> {
		let mut link = establish_client_mux_server_raw(4).await?;

		let frame_kept = mux_frame("mux-kept");
		let kept_id = client_stream_id(0);
		let kept_task = spawn_emit(&link.client.handle, frame_kept.clone());
		let kept_message =
			expect_muxed_request(&mut link.server_reader, kept_id, "first client-initiated stream must be id 1")
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
		let dropped_ok = is_draining(&dropped);

		write_muxed_echo(&mut link.server_writer, kept_id, &kept_message).await?;
		let kept = await_ok(kept_task, "kept emit task must not panic").await?;
		let kept_ok = is_echo(kept, &frame_kept);

		let late = link.client.handle.emit_on_stream(mux_frame("mux-after-peer-goaway")).await;
		let late_ok = is_draining(&late);

		trace.event_with("mux_peer_goaway_fails_pending_above", &[], dropped_ok && kept_ok && late_ok)?;
		Ok(())
	}

	/// Non-mux envelope on mux peer: GoAway(ProtocolError) + pending ConnectionClosed.
	async fn mux_protocol_violation_goaway_and_pending_fail(trace: &TraceCollector) -> Result<(), TightBeamError> {
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
		let goaway_ok = is_goaway(&goaway, GoAwayReason::ProtocolError, Some(0));

		let failed = join_task(inflight_task, "in-flight emit task must not panic").await?;
		let closed_ok = is_connection_closed(&failed);

		trace.event_with("mux_protocol_violation_goaway_and_pending_fail", &[], goaway_ok && closed_ok)?;
		Ok(())
	}

	/// Peer close mid-emit surfaces ConnectionClosed after reader EOF.
	async fn mux_connection_drop_mid_emit(trace: &TraceCollector) -> Result<(), TightBeamError> {
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
		trace.event_with("mux_connection_drop_mid_emit", &[], is_connection_closed(&failed))?;
		Ok(())
	}

	/// Cleartext mux over raw TCP: no handshake, symmetric out-of-band
	/// settings, two interleaved streams answered out of order.
	async fn mux_cleartext_interleaved_echo(trace: &TraceCollector) -> Result<(), TightBeamError> {
		let (client, server) = establish_cleartext_transports().await?;
		let settings = MuxSettings::symmetric(4);
		let (client_end, _client_responder) = spawn_cleartext_mux_endpoint(client, MuxRole::Client, settings, None)?;
		let (_server_end, server_responder) = spawn_cleartext_mux_endpoint(server, MuxRole::Server, settings, None)?;

		let frame_first = mux_frame("clear-first");
		let frame_second = mux_frame("clear-second");
		let gate = Arc::new(Notify::new());
		let handler = order_forcing_echo(frame_first.clone(), gate);
		let _server_serve = tokio::spawn(server_responder.serve(handler));

		let (first, second) = tokio::join!(
			client_end.handle.emit_on_stream(frame_first.clone()),
			client_end.handle.emit_on_stream(frame_second.clone()),
		);

		let ok = is_echo(first?, &frame_first) && is_echo(second?, &frame_second);
		trace.event_with("mux_cleartext_interleaved_echo", &[], ok)?;
		Ok(())
	}

	/// Cancel-budget hardening holds on cleartext links too: budget + 1
	/// open/cancel pairs answered with GoAway(EnhanceYourCalm).
	async fn mux_cleartext_cancel_budget(trace: &TraceCollector) -> Result<(), TightBeamError> {
		let (client, server) = establish_cleartext_transports().await?;
		let cancel_budget = 2;
		let settings = MuxSettings::symmetric(8);
		let (_server_end, responder) =
			spawn_cleartext_mux_endpoint(server, MuxRole::Server, settings, Some(cancel_budget))?;
		let (client_reader, client_writer) = client.into_split_cleartext()?;

		let ok = run_cancel_abuse(client_reader, client_writer, responder, cancel_budget).await?;
		trace.event_with("mux_cleartext_cancel_budget", &[], ok)?;
		Ok(())
	}
}

#[cfg(not(feature = "transport-multiplex"))]
mod without_multiplex {
	use tightbeam::der::Decode;
	use tightbeam::transport::TransportEnvelope;

	/// Context tag 4 (`MuxedRequest`) is not a valid `TransportEnvelope`
	/// alternative when multiplexing is compiled out, so the envelope must
	/// fail to decode instead of being silently misinterpreted.
	#[test]
	fn muxed_wire_tag_fails_decode_on_non_mux_build() {
		let muxed_request_der = [0xA4, 0x07, 0x30, 0x05, 0x02, 0x01, 0x01, 0x30, 0x00];
		assert!(TransportEnvelope::from_der(&muxed_request_der).is_err());
	}
}
