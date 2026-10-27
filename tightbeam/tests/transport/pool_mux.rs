//! The integration tests of pooled multiplexing.

#![cfg(all(
	feature = "transport-hpke",
	feature = "transport-policy",
	feature = "transport-multiplex",
	feature = "tcp",
	feature = "tokio",
	feature = "x509",
	feature = "testing",
	feature = "instrument"
))]

use core::future::Future;
use core::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::utils::time::{Clock, ManualClock};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use tightbeam::at_least;
use tightbeam::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::crypto::x509::store::{CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::{CertificateSpec, KeyCurves};
use tightbeam::der::asn1::OctetString;
use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::policy::{AcceptAllGate, GatePolicy, SessionContext, TransitStatus};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::server;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::fixtures::TestTrace;
use tightbeam::testing::macros::BuiltAssertSpec;
use tightbeam::testing::{ClientEnv, ScenarioConfig, ScenarioConfigError, SetupEnv, TestCertificate, TestIdentity};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::MUX_APPLICATION_CODE_FLOOR;
use tightbeam::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, TransportAuthorizer, TransportOffer,
};
use tightbeam::transport::handshake::receipt::SessionReceipt;
use tightbeam::transport::multiplex::{
	CallContext, MuxAcceptor, MuxRole, MuxService, MuxTransport, ReplySink, StreamBody,
};
use tightbeam::transport::policy::CollectorGateConfig;
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{
	ClientBuilder, ConnectionBuilder, ConnectionPool, EncryptedProtocol, PoolConfig, PooledClient, ResponsePackage,
	TransportEncryptionConfig, TransportError, TransportFailure,
};
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::x509::Certificate;
use tightbeam::{Frame, TightBeamError};

use crate::common::security::{
	pinning_trust_store, random_signing_key, test_certificate, PayingApprover, ServerMaterials,
};
use crate::transport::support::{
	await_ok, await_receipt_rotation, await_transport, await_within_deadline, bind_encrypted_listener,
	bind_mutual_listener, mux_frame, mux_offer, HandlerSignal,
};

type EmitTask = JoinHandle<Result<Option<Frame>, TransportError>>;

async fn bind_pool_listener(
	materials: &ServerMaterials,
) -> Result<(TokioListener, TightBeamSocketAddr), TightBeamError> {
	let (listener, addr) = bind_encrypted_listener(materials).await?;
	Ok((listener, TightBeamSocketAddr(addr)))
}

async fn start_echo_server(
	materials: &ServerMaterials,
	offer: Option<TransportOffer>,
) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError> {
	let (listener, addr) = bind_pool_listener(materials).await?;
	let handle = server! {
		protocol TokioListener: listener,
		policies: { with_mux_offer: [ offer.to_owned() ] },
		handle: move |frame: Frame| async move { Ok(Some(frame)) }
	};

	Ok((handle, addr))
}

/// Serves every accepted connection with `service` through the `server!`
/// service form, on the audit trail of `trace`. Mux takeover routes all stream
/// kinds, and non-mux peers get the single-flight unary loop.
async fn start_service_server<S>(
	materials: &ServerMaterials,
	trace: TraceCollector,
	service: S,
) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError>
where
	S: MuxService,
{
	let (listener, addr) = bind_pool_listener(materials).await?;
	// The accept loop re-applies policies per connection, so the share call
	// must stay an expression that gives each accept a fresh value.
	let acceptor = server! {
		protocol TokioListener: listener,
		policies: {
			with_trace: [ trace.share() ],
			with_mux_offer: [ Some(mux_offer(8)) ]
		},
		service: service
	};

	Ok((acceptor, addr))
}

async fn start_gated_service_server<S, G>(
	materials: &ServerMaterials,
	trace: TraceCollector,
	service: S,
	gate: G,
) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError>
where
	S: MuxService,
	G: GatePolicy + Clone + 'static,
{
	let (listener, addr) = bind_pool_listener(materials).await?;
	// The accept loop re-applies policies per connection, so the share and
	// clone calls must stay expressions that give each accept a fresh value.
	let acceptor = server! {
		protocol TokioListener: listener,
		policies: {
			with_trace: [ trace.share() ],
			with_mux_offer: [ Some(mux_offer(8)) ],
			with_collector_gate: [ gate.clone() ]
		},
		service: service
	};

	Ok((acceptor, addr))
}

/// A streaming-only service that answers with the collected body length as
/// a frame label. Unary and duplex kinds refuse with `Unimplemented` through
/// the [`MuxService`] defaults.
#[derive(Clone)]
struct LengthService;

impl MuxService for LengthService {
	async fn streaming(&self, body: StreamBody, _cx: CallContext) -> Result<Option<Frame>, TightBeamError> {
		let bytes = body.into_bytes().await?;
		Ok(Some(mux_frame(bytes.len().to_string())))
	}
}

/// A duplex-only service that echoes every request chunk back through the
/// reply sink.
#[derive(Clone)]
struct DuplexEchoService;

impl MuxService for DuplexEchoService {
	async fn duplex(&self, mut body: StreamBody, mut reply: ReplySink, _cx: CallContext) -> Result<(), TightBeamError> {
		while let Some(chunk) = body.chunk().await? {
			reply.push(&chunk).await?;
		}
		Ok(())
	}
}

/// A full-service handler. Unary echoes the frame, streaming reports the
/// collected length, and duplex echoes chunk by chunk.
#[derive(Clone)]
struct MixedService;

impl MuxService for MixedService {
	async fn unary(&self, frame: Frame, _cx: CallContext) -> Result<Option<Frame>, TightBeamError> {
		Ok(Some(frame))
	}

	async fn streaming(&self, body: StreamBody, _cx: CallContext) -> Result<Option<Frame>, TightBeamError> {
		let bytes = body.into_bytes().await?;
		Ok(Some(mux_frame(bytes.len().to_string())))
	}

	async fn duplex(&self, mut body: StreamBody, mut reply: ReplySink, _cx: CallContext) -> Result<(), TightBeamError> {
		while let Some(chunk) = body.chunk().await? {
			reply.push(&chunk).await?;
		}
		Ok(())
	}
}

/// The idle pruning of a test pool: the timeout, and the clock the pool judges
/// it against.
struct IdlePrune {
	timeout: Duration,
	clock: Arc<dyn Clock>,
}

fn mux_pool_with_idle_timeout(
	materials: &ServerMaterials,
	offer: Option<TransportOffer>,
	max_connections: usize,
	idle: Option<IdlePrune>,
	trace: &TraceCollector,
) -> Result<Arc<ConnectionPool<TokioListener>>, TightBeamError> {
	let trust_store = pinning_trust_store(&materials.certificate)?;
	let mut config = PoolConfig { max_connections, mux_offer: offer.map(Arc::new), ..PoolConfig::default() };
	let mut builder = ConnectionPool::<TokioListener>::builder();
	if let Some(IdlePrune { timeout, clock }) = idle {
		config.idle_timeout = Some(timeout);
		builder = builder.with_clock(clock);
	}

	let pool = Arc::new(
		builder
			.with_config(config)
			.with_trust_store(trust_store)
			.with_trace(trace.share())
			.build(),
	);
	Ok(pool)
}

fn mux_pool(
	materials: &ServerMaterials,
	offer: Option<TransportOffer>,
	max_connections: usize,
	trace: &TraceCollector,
) -> Result<Arc<ConnectionPool<TokioListener>>, TightBeamError> {
	mux_pool_with_idle_timeout(materials, offer, max_connections, None, trace)
}

async fn echo_roundtrip(
	client: &mut PooledClient<TokioListener>,
	label: impl AsRef<str>,
) -> Result<bool, TightBeamError> {
	let label = label.as_ref();
	let frame = mux_frame(label);

	let reply = client.emit(frame.to_owned(), None).await?;
	Ok(reply == Some(frame))
}

tb_assert_spec! {
	pub MuxLeaseShareSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::POOL_REUSE_MUX, exactly!(1)),
			(events::POOL_MUX_DECLINED, exactly!(0))
		]
	}
}

tb_scenario! {
	name: pooled_mux_shares_one_connection_across_leases,
	spec: MuxLeaseShareSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_echo_server(&env.context, Some(mux_offer(8))).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;

			let mut lease_one = pool.connect(addr).await?;
			let mut lease_two = pool.connect(addr).await?;

			let frame_one = mux_frame("mux-share-1");
			let frame_two = mux_frame("mux-share-2");
			let (reply_one, reply_two) =
				tokio::join!(lease_one.emit(frame_one.to_owned(), None), lease_two.emit(frame_two.to_owned(), None),);

			assert_eq!(reply_one?, Some(frame_one), "the first lease must get its own echo");
			assert_eq!(reply_two?, Some(frame_two), "the second lease must get its own echo");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PooledStreamSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1))
		]
	}
}

// Streaming reaches through the orchestration layer: a pooled lease opens
// the stream, and the streaming-only service collects and answers.
tb_scenario! {
	name: pooled_open_stream_reaches_streaming_server,
	spec: PooledStreamSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_service_server(&env.context, env.trace.share(), LengthService).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;
			let lease = pool.connect(addr).await?;

			let (mut sink, response) = lease.open_stream()?;
			sink.push(b"abcd").await?;
			sink.close_with(b"efgh").await?;

			let reply = response.await?;
			assert_eq!(
				reply.map(|frame| frame.message().to_owned()),
				Some(mux_frame("8").message().to_owned()),
				"the streaming service must answer the body length"
			);
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PooledDuplexSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1))
		]
	}
}

// Duplex reaches through the orchestration layer: a pooled lease opens the
// duplex, and the duplex-only service echoes chunk by chunk.
tb_scenario! {
	name: pooled_open_duplex_echoes_through_serve_wrapper,
	spec: PooledDuplexSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_service_server(&env.context, env.trace.share(), DuplexEchoService).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;
			let lease = pool.connect(addr).await?;
			let (mut sink, mut body) = lease.open_duplex()?;

			sink.push(b"ping").await?;
			let first = body.chunk().await?;
			sink.close_with(b"pong").await?;

			let second = body.chunk().await?;
			let terminal = body.chunk().await?;
			assert_eq!(first.as_deref(), Some(b"ping".as_ref()), "the duplex must echo the first chunk");
			assert_eq!(second.as_deref(), Some(b"pong".as_ref()), "the duplex must echo the closing chunk");
			assert!(terminal.is_none(), "the duplex must end after its last echo");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PooledMixedKindsSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::POOL_REUSE_MUX, exactly!(2))
		]
	}
}

// Unary, streaming, and duplex interactions run concurrently on one pooled
// connection against one service.
tb_scenario! {
	name: pooled_mixed_kinds_share_one_connection,
	spec: PooledMixedKindsSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_service_server(&env.context, env.trace.share(), MixedService).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;
			// Leases are exclusive per in-flight interaction, and one pooled
			// connection carries all three.
			let mut unary_lease = pool.connect(addr).await?;
			let stream_lease = pool.connect(addr).await?;
			let duplex_lease = pool.connect(addr).await?;

			let (mut stream_sink, stream_response) = stream_lease.open_stream()?;
			let (mut duplex_sink, mut duplex_body) = duplex_lease.open_duplex()?;
			let unary_frame = mux_frame("mixed-unary");

			let streaming = async move {
				stream_sink.push(b"abcd").await?;
				stream_sink.close_with(b"efgh").await?;
				stream_response.await
			};
			let duplex = async move {
				duplex_sink.push(b"ping").await?;
				let echoed = duplex_body.chunk().await?;
				duplex_sink.close().await?;

				let terminal = duplex_body.chunk().await?;
				Ok::<_, TransportError>((echoed, terminal))
			};
			let (unary_reply, stream_reply, duplex_reply) =
				tokio::join!(unary_lease.emit(unary_frame.to_owned(), None), streaming, duplex);

			let (echoed, terminal) = duplex_reply?;
			assert_eq!(unary_reply?, Some(unary_frame), "the unary call must get its echo");
			assert_eq!(
				stream_reply?.map(|frame| frame.message().to_owned()),
				Some(mux_frame("8").message().to_owned()),
				"the streaming call must get the body length"
			);
			assert_eq!(echoed.as_deref(), Some(b"ping".as_ref()), "the duplex call must get its echo");
			assert!(terminal.is_none(), "the duplex call must end after its echo");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub UnservedKindSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_STREAM_REFUSED, exactly!(2), equals!(TransitStatus::Unimplemented))
		]
	}
}

// A kind the service does not implement refuses its stream with
// `Unimplemented`, and the connection goes on to serve other streams.
tb_scenario! {
	name: unserved_kind_answers_unimplemented,
	spec: UnservedKindSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_service_server(&env.context, env.trace.share(), LengthService).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;
			let mut lease = pool.connect(addr).await?;

			// Duplex against the streaming-only service: the trailer
			// carries the refusal into the reply body.
			let (duplex_sink, mut duplex_body) = lease.open_duplex()?;
			duplex_sink.close().await?;
			let duplex_refused = matches!(
				duplex_body.chunk().await,
				Err(TransportError::OperationFailed(TransportFailure::Unimplemented))
			);

			// Unary against the same service: the response future surfaces the
			// refusal, and the connection goes on to serve the streaming kind.
			let unary_refused = matches!(
				lease.emit(mux_frame("unserved"), None).await,
				Err(TransportError::OperationFailed(TransportFailure::Unimplemented))
			);

			let (sink, response) = lease.open_stream()?;
			sink.close_with(b"abcd").await?;

			let served = response.await?.map(|frame| frame.message().to_owned()) == Some(mux_frame("4").message().to_owned());
			assert!(duplex_refused, "the duplex call must read the refusal of its kind");
			assert!(unary_refused, "the unary call must read the refusal of its kind");
			assert!(served, "the connection must still serve the streaming kind");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxPeerCertificateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1))
		]
	}
}

// A caller that gates policy on peer identity reads the certificate off the
// lease before its first emit. A mux connection handshakes eagerly at dial,
// so its lease must expose the validated peer certificate too.
tb_scenario! {
	name: pooled_mux_lease_exposes_peer_certificate,
	spec: MuxPeerCertificateSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_echo_server(&env.context, Some(mux_offer(8))).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;
			let lease = pool.connect(addr).await?;

			let pinned = lease.peer_certificate() == Some(&materials.certificate);
			assert!(pinned, "a mux lease must expose the certificate its dial pinned");
			Ok(())
		}
	}
}

/// A mux lease refuses `conn()`, the accessor of an exclusive lease.
#[tokio::test]
async fn mux_lease_conn_reports_invalid_state() -> Result<(), TightBeamError> {
	let materials = ServerMaterials::generate();
	let (_server, addr) = start_echo_server(&materials, Some(mux_offer(8))).await?;
	let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &TraceCollector::default())?;

	let mut lease = pool.connect(addr).await?;
	let conn = lease.conn();
	assert!(
		matches!(conn, Err(TransportError::InvalidState)),
		"a mux lease must refuse conn() with InvalidState"
	);
	Ok(())
}

struct GatedContext {
	materials: ServerMaterials,
	started: HandlerSignal,
	release: Notify,
}

impl GatedContext {
	fn generate() -> Self {
		Self {
			materials: ServerMaterials::generate(),
			started: HandlerSignal::default(),
			release: Notify::new(),
		}
	}
}

async fn start_gated_echo_server(
	ctx: &Arc<GatedContext>,
	offer: Option<TransportOffer>,
) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError> {
	let (listener, addr) = bind_pool_listener(&ctx.materials).await?;
	let first = Arc::new(AtomicBool::new(true));
	let handler_ctx = Arc::clone(ctx);
	let handle = server! {
		protocol TokioListener: listener,
		policies: { with_mux_offer: [ offer.to_owned() ] },
		handle: move |frame: Frame| {
			let ctx = Arc::clone(&handler_ctx);
			let first = Arc::clone(&first);
			async move {
				if first.swap(false, Ordering::SeqCst) {
					ctx.started.raise();
					ctx.release.notified().await;
				}

				Ok(Some(frame))
			}
		}
	};

	Ok((handle, addr))
}

async fn spawn_held_emit(
	ctx: &GatedContext,
	mut lease: PooledClient<TokioListener>,
) -> Result<EmitTask, TightBeamError> {
	let held_task = tokio::spawn(async move { lease.emit(mux_frame("mux-held"), None).await });
	ctx.started.wait("the held emit must start the gated handler").await?;
	Ok(held_task)
}

async fn release_held_emit(ctx: &GatedContext, held_task: EmitTask) -> Result<bool, TightBeamError> {
	ctx.release.notify_one();
	let held_reply = await_ok(held_task, "held emit task must not panic").await?;
	Ok(held_reply.is_some())
}

tb_assert_spec! {
	pub MuxFailoverDialSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(2)),
			(events::POOL_REUSE_MUX, exactly!(1)),
			(events::POOL_FAILOVER, exactly!(1)),
			(events::POOL_EXHAUSTED, exactly!(0))
		]
	}
}

tb_scenario! {
	name: pooled_mux_failover_opens_additional_connection,
	spec: MuxFailoverDialSpec,
	environment ServiceClient {
		context: GatedContext::generate(),
		server: |env| async move { start_gated_echo_server(&env.context, Some(mux_offer(1))).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = mux_pool(&ctx.materials, Some(mux_offer(4)), 2, &trace)?;

			let held_lease = pool.connect(addr).await?;
			let mut second_lease = pool.connect(addr).await?;
			let held_task = spawn_held_emit(&ctx, held_lease).await?;

			let failed_over = echo_roundtrip(&mut second_lease, "mux-second").await?;
			assert!(failed_over, "the overflow emit must echo after its failover");

			let held_completed = release_held_emit(&ctx, held_task).await?;
			assert!(held_completed, "the held emit must complete once the handler releases it");
			Ok(())
		}
	}
}

/// Two trusted server identities for one address.
///
/// `gate` holds the first identity's materials and the hold on the first
/// frame it serves. `second` is a distinct identity, which takes the address
/// over once the first listener closes.
struct IdentityFlipContext {
	gate: GatedContext,
	second: SigningIdentity,
}

impl IdentityFlipContext {
	fn generate() -> Self {
		let second_key = random_signing_key();

		// The CN differs, so the trust store validates the second certificate
		// as its own anchor, not as a child of the first subject.
		let second_certificate = TestCertificate::with_cn_and_uri_sans(&second_key, "pool-mux-second-identity", &[]);
		let second = TestIdentity::presenting(second_certificate, &second_key);
		Self { gate: GatedContext::generate(), second }
	}

	/// A pool that trusts both identities, as a peer trust store that holds
	/// two peers' certificates does.
	fn pool_trusting_both(&self, trace: &TraceCollector) -> Result<Arc<ConnectionPool<TokioListener>>, TightBeamError> {
		let trust_store = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation)
			.with_certificate(Certificate::clone(&self.gate.materials.certificate))?
			.with_certificate(self.second.certificate().clone())?
			.build();
		let config = PoolConfig {
			max_connections: 2,
			mux_offer: Some(Arc::new(mux_offer(4))),
			..PoolConfig::default()
		};

		let pool = ConnectionPool::<TokioListener>::builder()
			.with_config(config)
			.with_trust_store(Arc::new(trust_store))
			.with_trace(trace.share())
			.build();
		Ok(Arc::new(pool))
	}

	/// The listener configuration of the second identity.
	fn second_encryption(&self) -> TransportEncryptionConfig<tightbeam::crypto::profiles::DefaultCryptoProvider> {
		TransportEncryptionConfig::new(self.second.clone())
	}
}

/// Serves one accepted connection as a mux echo server with a stream cap of
/// `cap`, and runs `before_echo` ahead of each echo.
///
/// The driver tasks run detached, so the connection outlives the listener
/// that accepted it.
async fn serve_mux_echo_before<F, Fut>(
	transport: TcpTransport<TokioStream>,
	cap: u32,
	before_echo: F,
) -> Result<(), TransportError>
where
	F: Fn() -> Fut + Send + Sync + 'static,
	Fut: Future<Output = ()> + Send + 'static,
{
	let mut transport = transport.with_mux_offer(Some(mux_offer(cap)));
	let negotiated = transport.negotiate_mux().await?;
	let settings = negotiated.ok_or(TransportError::InvalidState)?;

	let (reader, writer) = transport.into_split()?;
	let mux = MuxTransport::new(reader, writer, MuxRole::Server, settings);
	let (_handle, reader_driver, writer_driver, responder) = mux.into_parts();

	let echo = move |frame: Arc<Frame>| {
		let hook = before_echo();
		async move {
			hook.await;
			ResponsePackage::new(TransitStatus::Ok, Some(Frame::clone(&frame)))
		}
	};

	tokio::spawn(reader_driver.drive());
	tokio::spawn(writer_driver.drive());
	tokio::spawn(responder.serve(echo));

	Ok(())
}

/// Starts the first identity on a fresh address with a stream cap of 1.
///
/// The acceptor serves one connection, whose first frame the gate holds, and
/// then ends. Its end drops the listener, so the address is free for the
/// second identity while the accepted connection stays up.
async fn start_first_identity_server(
	ctx: &Arc<IdentityFlipContext>,
) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError> {
	let (listener, addr) = bind_pool_listener(&ctx.gate.materials).await?;
	let first = Arc::new(AtomicBool::new(true));
	let hold_ctx = Arc::clone(ctx);
	let acceptor = tokio::spawn(async move {
		let Ok((transport, _)) = listener.accept().await else {
			return;
		};

		let hold = move || {
			let ctx = Arc::clone(&hold_ctx);
			let first = Arc::clone(&first);
			async move {
				if first.swap(false, Ordering::SeqCst) {
					ctx.gate.started.raise();
					ctx.gate.release.notified().await;
				}
			}
		};
		// The accepted connection serves on detached tasks. A negotiation
		// failure ends this one connection, and the scenario reads the outcome
		// from the trace.
		let _ = serve_mux_echo_before(transport, 1, hold).await;
	});

	Ok((acceptor, addr))
}

/// Binds `addr` under `encryption`, and retries every 20 ms, up to 100 times,
/// while the listener that held the port releases it.
async fn rebind_under(
	addr: TightBeamSocketAddr,
	encryption: impl Fn() -> TransportEncryptionConfig<tightbeam::crypto::profiles::DefaultCryptoProvider>,
) -> Result<TokioListener, TightBeamError> {
	let mut bound = TokioListener::bind_with(addr, encryption()).await;
	let mut retries_left = 100;
	while bound.is_err() && retries_left > 0 {
		sleep(Duration::from_millis(20)).await;
		bound = TokioListener::bind_with(addr, encryption()).await;
		retries_left -= 1;
	}

	let (listener, _) = bound?;
	Ok(listener)
}

/// Rebinds `addr` under the second identity and serves every accepted
/// connection as a mux echo server with a stream cap of 1, on the audit trail
/// of `trace`. The server records a gate verdict for each frame it collects.
async fn start_second_identity_server(
	ctx: &IdentityFlipContext,
	addr: TightBeamSocketAddr,
	trace: TraceCollector,
) -> Result<JoinHandle<()>, TightBeamError> {
	let listener = rebind_under(addr, || ctx.second_encryption()).await?;
	// The accept loop re-applies policies per connection, so the share call
	// must stay an expression that gives each accept a fresh value.
	let acceptor = server! {
		protocol TokioListener: listener,
		policies: {
			with_trace: [ trace.share() ],
			with_mux_offer: [ Some(mux_offer(1)) ]
		},
		handle: move |frame: Frame| async move { Ok(Some(frame)) }
	};

	Ok(acceptor)
}

tb_assert_spec! {
	pub MuxFailoverIdentitySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(3)),
			(events::GATE_ACCEPT, exactly!(0)),
			(events::GATE_REJECT, exactly!(0)),
			(events::POOL_FAILOVER_REFUSED, exactly!(2)),
			(events::POOL_DIAL, exactly!(2)),
			(events::POOL_REUSE_MUX, exactly!(2)),
			(events::POOL_FAILOVER, exactly!(2))
		]
	}
}

// A lease pins the identity of its handshake. The cap-full connection fails
// an emit over to a fresh dial that another trusted identity answers, so the
// emit fails and the frame stays with the caller.
//
// - The second emit fails over onto the pooled connection of the other
//   identity, so the pool counts two failovers, refusals, and reuses against
//   two dials.
// - The second server records a gate verdict per frame it collects, so zero
//   verdicts mean it collected none.
// - The three handshakes are the two pool dials and the second server, the
//   one server that holds the trace.
tb_scenario! {
	name: pooled_mux_failover_refuses_another_identity,
	spec: MuxFailoverIdentitySpec,
	environment ServiceClient {
		context: IdentityFlipContext::generate(),
		server: |env| async move { start_first_identity_server(&env.context).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = ctx.pool_trusting_both(&trace)?;
			let held_lease = pool.connect(addr).await?;
			let mut pinned_lease = pool.connect(addr).await?;
			let pinned_first = pinned_lease.peer_certificate() == Some(&*ctx.gate.materials.certificate);
			let held_task = spawn_held_emit(&ctx.gate, held_lease).await?;
			let _second_server = start_second_identity_server(&ctx, addr, trace.share()).await?;

			let refused = pinned_lease.emit(mux_frame("mux-after-pin"), None).await;
			let refused_again = pinned_lease.emit(mux_frame("mux-after-refusal"), None).await;
			assert!(pinned_first, "the lease must pin the certificate of the first identity");
			assert!(
				matches!(refused, Err(TransportError::InvalidCertificate(CertificateValidationError::CertificateNotPinned))),
				"a failover that another identity answers must fail as not pinned"
			);
			assert!(
				matches!(refused_again, Err(TransportError::InvalidCertificate(CertificateValidationError::CertificateNotPinned))),
				"the lease must stay refused on the pooled connection of the other identity"
			);

			let held_completed = release_held_emit(&ctx.gate, held_task).await?;
			assert!(held_completed, "the held emit must complete once the handler releases it");

			let recorded = trace.drain_events();
			let refusals = recorded.into_iter().filter(|event| event.urn == events::POOL_FAILOVER_REFUSED);
			let labels: Vec<_> = refusals.map(|event| event.label.map(String::from)).collect();
			let not_pinned = Some(String::from("certificate-not-pinned"));
			assert_eq!(labels, [not_pinned.clone(), not_pinned], "each refusal must name the refused pin");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxFailoverReuseSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(2)),
			(events::POOL_REUSE_MUX, exactly!(3)),
			(events::POOL_FAILOVER, exactly!(2)),
			(events::POOL_EXHAUSTED, exactly!(0))
		]
	}
}

// At `max_connections`, failover reuses headroom instead of a dial, which
// would fail with `ResourceExhausted`.
tb_scenario! {
	name: pooled_mux_failover_reuses_pooled_headroom,
	spec: MuxFailoverReuseSpec,
	environment ServiceClient {
		context: GatedContext::generate(),
		server: |env| async move { start_gated_echo_server(&env.context, Some(mux_offer(1))).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = mux_pool(&ctx.materials, Some(mux_offer(4)), 2, &trace)?;

			// Three leases land on connection one, the only pool entry.
			let held_lease = pool.connect(addr).await?;
			let mut fill_lease = pool.connect(addr).await?;
			let mut reuse_lease = pool.connect(addr).await?;
			let held_task = spawn_held_emit(&ctx, held_lease).await?;

			// Once connection one saturates, failover dials connection two.
			let filled = echo_roundtrip(&mut fill_lease, "mux-fill").await?;
			assert!(filled, "the fill lease must echo after its failover");

			let reused = echo_roundtrip(&mut reuse_lease, "mux-reuse").await?;
			assert!(reused, "the reuse lease must echo after its failover");

			let held_completed = release_held_emit(&ctx, held_task).await?;
			assert!(held_completed, "the held emit must complete once the handler releases it");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxNoHeadroomSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::POOL_REUSE_MUX, exactly!(1)),
			(events::POOL_FAILOVER, exactly!(1)),
			(events::POOL_EXHAUSTED, exactly!(1))
		]
	}
}

tb_scenario! {
	name: pooled_mux_without_headroom_reports_busy,
	spec: MuxNoHeadroomSpec,
	environment ServiceClient {
		context: GatedContext::generate(),
		server: |env| async move { start_gated_echo_server(&env.context, Some(mux_offer(1))).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = mux_pool(&ctx.materials, Some(mux_offer(4)), 1, &trace)?;

			let held_lease = pool.connect(addr).await?;
			let mut second_lease = pool.connect(addr).await?;
			let held_task = spawn_held_emit(&ctx, held_lease).await?;

			let refused = second_lease.emit(mux_frame("mux-refused"), None).await;
			assert!(
				matches!(refused, Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted))),
				"an emit with no headroom and no dial left must fail with ResourceExhausted"
			);

			let held_completed = release_held_emit(&ctx, held_task).await?;
			assert!(held_completed, "the held emit must complete once the handler releases it");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxDeclinedFallbackSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::POOL_MUX_DECLINED, exactly!(1)),
			(events::POOL_REUSE_MUX, exactly!(0))
		]
	}
}

tb_scenario! {
	name: pooled_mux_declined_falls_back_to_exclusive_lease,
	spec: MuxDeclinedFallbackSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_echo_server(&env.context, None).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;
			let mut lease = pool.connect(addr).await?;

			let echoed = echo_roundtrip(&mut lease, "mux-declined").await?;
			assert!(echoed, "the exclusive lease must echo");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxDeclinedIdleReuseSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::POOL_MUX_DECLINED, exactly!(1)),
			(events::POOL_REUSE_READY, exactly!(1)),
			(events::POOL_EXHAUSTED, exactly!(0))
		]
	}
}

// With `max_connections` at 1, the pool reuses the idle exclusive connection
// instead of a dial, which would fail with `ResourceExhausted`.
tb_scenario! {
	name: pooled_mux_declined_reuses_idle_exclusive_lease,
	spec: MuxDeclinedIdleReuseSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_echo_server(&env.context, None).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;

			let first_lease = pool.connect(addr).await?;
			drop(first_lease);

			let mut reused_lease = pool.connect(addr).await?;
			let echoed = echo_roundtrip(&mut reused_lease, "mux-idle-reuse").await?;
			assert!(echoed, "the reused exclusive lease must echo");
			Ok(())
		}
	}
}

struct ManualContext {
	materials: ServerMaterials,
	connection_tasks: Mutex<Vec<JoinHandle<Result<(), TransportError>>>>,
}

impl ManualContext {
	fn generate() -> Self {
		Self { materials: ServerMaterials::generate(), connection_tasks: Mutex::new(Vec::new()) }
	}

	fn register_tasks(&self, spawned: impl IntoIterator<Item = JoinHandle<Result<(), TransportError>>>) {
		let spawned: Vec<JoinHandle<Result<(), TransportError>>> = spawned.into_iter().collect();
		let mut registry = match self.connection_tasks.lock() {
			Ok(tasks) => tasks,
			Err(poisoned) => poisoned.into_inner(),
		};
		registry.extend(spawned);
	}

	/// Aborts the connection tasks so the split halves drop and TCP closes.
	async fn abort_connections(&self) {
		let drained: Vec<_> = {
			let mut tasks = match self.connection_tasks.lock() {
				Ok(tasks) => tasks,
				Err(poisoned) => poisoned.into_inner(),
			};
			tasks.drain(..).collect()
		};
		for task in drained {
			task.abort();
			// The await waits for the task to end, which is all this teardown
			// needs. Its answer is a cancellation, or the task's own result
			// when the task ended first.
			let _ = task.await;
		}
	}
}

async fn serve_manual_mux_connection(
	transport: TcpTransport<TokioStream>,
	ctx: Arc<ManualContext>,
) -> Result<(), TransportError> {
	let mut transport = transport.with_mux_offer(Some(mux_offer(4)));
	let negotiated = transport.negotiate_mux().await?;
	let settings = negotiated.ok_or(TransportError::InvalidState)?;

	let (reader, writer) = transport.into_split()?;
	let mux = MuxTransport::new(reader, writer, MuxRole::Server, settings);
	let (_handle, reader_driver, writer_driver, responder) = mux.into_parts();

	let echo = |frame: Arc<Frame>| {
		let response = ResponsePackage::new(TransitStatus::Ok, Some(Frame::clone(&frame)));
		core::future::ready(response)
	};
	let spawned = vec![
		tokio::spawn(reader_driver.drive()),
		tokio::spawn(writer_driver.drive()),
		tokio::spawn(responder.serve(echo)),
	];

	ctx.register_tasks(spawned);
	Ok(())
}

async fn start_manual_mux_echo_server(
	ctx: &Arc<ManualContext>,
) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError> {
	let (listener, addr) = bind_pool_listener(&ctx.materials).await?;
	let acceptor_ctx = Arc::clone(ctx);
	let acceptor = tokio::spawn(async move {
		while let Ok((transport, _)) = listener.accept().await {
			let ctx = Arc::clone(&acceptor_ctx);
			tokio::spawn(serve_manual_mux_connection(transport, ctx));
		}
	});

	Ok((acceptor, addr))
}

tb_assert_spec! {
	pub MuxEvictionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(2)),
			(events::POOL_EVICTED, exactly!(1))
		]
	}
}

tb_scenario! {
	name: pooled_mux_evicts_dead_connection_and_reconnects,
	spec: MuxEvictionSpec,
	environment ServiceClient {
		context: ManualContext::generate(),
		server: |env| async move { start_manual_mux_echo_server(&env.context).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = mux_pool(&ctx.materials, Some(mux_offer(4)), 4, &trace)?;

			let mut lease = pool.connect(addr).await?;
			let echoed_before = echo_roundtrip(&mut lease, "mux-before").await?;
			assert!(echoed_before, "the lease must echo before the teardown");

			ctx.abort_connections().await;

			let dead = lease.emit(mux_frame("mux-during"), None).await;
			assert!(dead.is_err(), "an emit on the aborted connection must fail");

			let mut fresh = pool.connect(addr).await?;
			let echoed_after = echo_roundtrip(&mut fresh, "mux-after").await?;
			assert!(echoed_after, "the fresh lease must echo after the eviction");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxIdlePruneSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(2)),
			(events::POOL_PRUNED_IDLE, exactly!(1)),
			(events::POOL_EXHAUSTED, exactly!(0))
		]
	}
}

// The `idle_timeout` prune frees the cap-1 slot, so the next connect dials.
tb_scenario! {
	name: pooled_mux_prunes_idle_connection,
	spec: MuxIdlePruneSpec,
	environment ServiceClient {
		context: ManualContext::generate(),
		server: |env| async move { start_manual_mux_echo_server(&env.context).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let idle_timeout = Duration::from_millis(50);
			let clock = Arc::new(ManualClock::default());
			let idle = IdlePrune { timeout: idle_timeout, clock: Arc::clone(&clock) as Arc<dyn Clock> };
			let pool = mux_pool_with_idle_timeout(&ctx.materials, Some(mux_offer(4)), 1, Some(idle), &trace)?;

			let mut lease = pool.connect(addr).await?;
			let echoed_before = echo_roundtrip(&mut lease, "mux-idle-before").await?;
			assert!(echoed_before, "the first lease must echo before the idle prune");

			drop(lease);
			clock.advance(idle_timeout * 2);

			let mut fresh = pool.connect(addr).await?;
			let echoed_after = echo_roundtrip(&mut fresh, "mux-idle-after").await?;
			assert!(echoed_after, "the fresh lease must echo after the idle prune");
			Ok(())
		}
	}
}

/// Serves the first connection on `listener` as a multiplexed server that
/// holds its writer and its responder, so the server never closes the
/// connection, and returns once its reader reads the close of the client.
async fn serve_until_the_client_closes(listener: TokioListener) -> Result<(), TransportError> {
	let (transport, _) = listener.accept().await?;
	let mut transport = transport.with_mux_offer(Some(mux_offer(4)));
	let negotiated = transport.negotiate_mux().await?;
	let settings = negotiated.ok_or(TransportError::InvalidState)?;

	let (reader, writer) = transport.into_split()?;
	let mux = MuxTransport::new(reader, writer, MuxRole::Server, settings);
	let (_handle, reader_driver, _writer_driver, _responder) = mux.into_parts();

	// The reader ends on the close of the client, and either answer of the
	// drive is that close.
	let _closed = reader_driver.drive().await;
	Ok(())
}

/// A dropped pool ends the driver tasks of each multiplexed connection it
/// held, so the peer reads the close (CWE-772).
#[tokio::test]
async fn dropping_a_pool_ends_its_multiplexed_connections() -> Result<(), TightBeamError> {
	let materials = ServerMaterials::generate();
	let (listener, addr) = bind_pool_listener(&materials).await?;
	let served = tokio::spawn(serve_until_the_client_closes(listener));
	let pool = mux_pool(&materials, Some(mux_offer(4)), 1, &TraceCollector::new())?;

	drop(pool.connect(addr).await?);
	drop(pool);

	let ended = await_within_deadline(served, "the peer of the dropped pool must read its close").await?;
	assert!(ended.is_ok_and(|served| served.is_ok()));
	Ok(())
}

/// A server that offers multiplexing serves a single-flight client through its
/// single-flight loop.
#[tokio::test]
async fn single_flight_client_round_trips_on_mux_server() -> Result<(), TightBeamError> {
	let materials = ServerMaterials::generate();
	let (_server, addr) = start_echo_server(&materials, Some(mux_offer(8))).await?;
	let mut client = single_flight_client(&materials, addr).await?;

	let frame = mux_frame("single-flight");
	let reply = client.emit(frame.to_owned(), None).await?;
	assert_eq!(reply, Some(frame), "a mux-offering server must serve a single-flight client");
	Ok(())
}

/// A single-flight client against the pinned server of `materials`.
async fn single_flight_client(
	materials: &ServerMaterials,
	addr: TightBeamSocketAddr,
) -> Result<tightbeam::transport::client::GenericClient<TokioListener>, TightBeamError> {
	let trust_store = pinning_trust_store(&materials.certificate)?;
	let client = ClientBuilder::<TokioListener>::builder()
		.with_trust_store(trust_store)
		.build()
		.connect(addr)
		.await?;
	Ok(client)
}

/// With `max_connections: [ 1 ]` the accept loop holds one permit per live
/// connection: a second connection queues in the listener backlog until
/// the first connection's task ends.
#[tokio::test]
async fn accept_cap_queues_second_connection() -> Result<(), TightBeamError> {
	let materials = ServerMaterials::generate();
	let (listener, addr) = bind_pool_listener(&materials).await?;
	let _server = server! {
		protocol TokioListener: listener,
		policies: { max_connections: [ 1 ] },
		handle: move |frame: Frame| async move { Ok(Some(frame)) }
	};

	let mut held = single_flight_client(&materials, addr).await?;
	let echoed = held.emit(mux_frame("held"), None).await?;
	assert!(echoed.is_some(), "first connection should echo while holding the only permit");

	let mut queued = single_flight_client(&materials, addr).await?;
	let starved = tokio::time::timeout(Duration::from_millis(500), queued.emit(mux_frame("queued"), None)).await;
	assert!(starved.is_err(), "second connection must starve until the permit frees");

	drop(queued);
	drop(held);

	let mut fresh = single_flight_client(&materials, addr).await?;
	let fresh_emit = fresh.emit(mux_frame("after-release"), None);
	let bounded = await_within_deadline(fresh_emit, "the fresh emit must resolve once the permit frees");
	let released = bounded.await?;
	assert!(
		matches!(released, Ok(Some(_))),
		"a new connection should be served once the held permit releases"
	);
	Ok(())
}

struct GateContext {
	materials: ServerMaterials,
	handler_invoked: AtomicBool,
}

impl GateContext {
	fn generate() -> Self {
		Self { materials: ServerMaterials::generate(), handler_invoked: AtomicBool::new(false) }
	}
}

#[derive(Clone)]
struct ForbidAllGate;

impl GatePolicy for ForbidAllGate {
	fn evaluate(&self, _message: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		TransitStatus::PermissionDenied
	}
}

/// A buggy gate: `Unknown` is not a verdict a gate may legally return.
#[derive(Clone)]
struct UnknownGate;

impl GatePolicy for UnknownGate {
	fn evaluate(&self, _message: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		TransitStatus::Unknown
	}
}

/// Grades `spec` against a scenario trace whose config sets
/// `enable_internal_detail`, so a gated server records the policy step and the
/// handler span that the gate specs count.
fn detailed_config(spec: &'static BuiltAssertSpec) -> Result<ScenarioConfig, ScenarioConfigError> {
	ScenarioConfig::builder()
		.with_spec(spec)
		.with_trace(TestTrace::with_detail(true))
		.build()
}

tb_assert_spec! {
	pub MuxGateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::GATE_REJECT, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::POLICY_EVAL, exactly!(1)),
			(events::HANDLER_ENTER, exactly!(0))
		]
	}
}

tb_scenario! {
	name: mux_serve_gate_rejects_without_handler,
	config: detailed_config(MuxGateSpec::latest()),
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |SetupEnv { context: materials, trace }| async move {
			let (listener, addr) = bind_pool_listener(&materials).await?;
			let handle = server! {
				protocol TokioListener: listener,
				policies: {
					with_trace: [ trace.share() ],
					with_mux_offer: [ Some(mux_offer(8)) ],
					with_collector_gate: [ ForbidAllGate ]
				},
				handle: move |frame: Frame| async move { Ok(Some(frame)) }
			};
			Ok((handle, addr))
		},
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;
			let mut client = pool.connect(addr).await?;

			let outcome = client.emit(mux_frame("gated"), None).await;
			assert!(
				matches!(outcome, Err(TransportError::OperationFailed(TransportFailure::PermissionDenied))),
				"the gate's PermissionDenied must reach the unary caller"
			);
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxStreamGateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::GATE_REJECT, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::POLICY_EVAL, exactly!(1)),
			(events::HANDLER_ENTER, exactly!(0))
		]
	}
}

// Collector gates must refuse streaming before the service body runs, as
// they do for unary dispatch.
tb_scenario! {
	name: mux_serve_gate_rejects_streaming_without_handler,
	config: detailed_config(MuxStreamGateSpec::latest()),
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |SetupEnv { context: materials, trace }| async move {
			start_gated_service_server(&materials, trace.share(), LengthService, ForbidAllGate).await
		},
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;
			let lease = pool.connect(addr).await?;
			let (sink, response) = lease.open_stream()?;

			sink.close_with(b"gated-stream").await?;

			let outcome = response.await;
			assert!(
				matches!(outcome, Err(TransportError::OperationFailed(TransportFailure::PermissionDenied))),
				"the gate's PermissionDenied must reach the streaming caller"
			);
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxDuplexGateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::GATE_REJECT, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::POLICY_EVAL, exactly!(1)),
			(events::HANDLER_ENTER, exactly!(0))
		]
	}
}

// Collector gates must refuse duplex before the service body runs, as they
// do for unary dispatch.
tb_scenario! {
	name: mux_serve_gate_rejects_duplex_without_handler,
	config: detailed_config(MuxDuplexGateSpec::latest()),
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |SetupEnv { context: materials, trace }| async move {
			start_gated_service_server(&materials, trace.share(), DuplexEchoService, ForbidAllGate).await
		},
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;
			let lease = pool.connect(addr).await?;

			let (sink, mut body) = lease.open_duplex()?;
			sink.close().await?;

			let outcome = body.chunk().await;
			assert!(
				matches!(outcome, Err(TransportError::OperationFailed(TransportFailure::PermissionDenied))),
				"the gate's PermissionDenied must reach the duplex caller"
			);
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxGateListSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::GATE_REJECT, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::POLICY_EVAL, exactly!(1)),
			(events::HANDLER_ENTER, exactly!(0))
		]
	}
}

// A bracketed gate list composes: the first gate that refuses decides, so a
// trailing permissive gate must not silently displace the deny gate.
tb_scenario! {
	name: mux_serve_gate_list_composes_first_refusal,
	config: detailed_config(MuxGateListSpec::latest()),
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |SetupEnv { context: materials, trace }| async move {
			let (listener, addr) = bind_pool_listener(&materials).await?;
			let handle = server! {
				protocol TokioListener: listener,
				policies: {
					with_trace: [ trace.share() ],
					with_mux_offer: [ Some(mux_offer(8)) ],
					with_collector_gate: [ ForbidAllGate, AcceptAllGate ]
				},
				handle: move |frame: Frame| async move { Ok(Some(frame)) }
			};
			Ok((handle, addr))
		},
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;
			let mut client = pool.connect(addr).await?;

			let outcome = client.emit(mux_frame("gate-list"), None).await;
			assert!(
				matches!(outcome, Err(TransportError::OperationFailed(TransportFailure::PermissionDenied))),
				"the first refusal of the gate list must reach the caller"
			);
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxUnknownGateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::GATE_REJECT, exactly!(1), equals!(TransitStatus::Internal)),
			(events::POLICY_EVAL, exactly!(1)),
			(events::HANDLER_ENTER, exactly!(0))
		]
	}
}

// `Unknown` from a gate is a local bug, not a peer-attributable verdict:
// the mux serve path normalizes it to `Internal`, so both planes answer
// identically.
tb_scenario! {
	name: mux_serve_unknown_gate_answers_internal,
	config: detailed_config(MuxUnknownGateSpec::latest()),
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |SetupEnv { context: materials, trace }| async move {
			let (listener, addr) = bind_pool_listener(&materials).await?;
			let handle = server! {
				protocol TokioListener: listener,
				policies: {
					with_trace: [ trace.share() ],
					with_mux_offer: [ Some(mux_offer(8)) ],
					with_collector_gate: [ UnknownGate ]
				},
				handle: move |frame: Frame| async move { Ok(Some(frame)) }
			};
			Ok((handle, addr))
		},
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;
			let mut client = pool.connect(addr).await?;

			let outcome = client.emit(mux_frame("unknown-gate"), None).await;
			assert!(
				matches!(outcome, Err(TransportError::OperationFailed(TransportFailure::Internal))),
				"the gate's Unknown must reach the caller as Internal"
			);
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxHandlerFailureSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(2)),
			(events::HANDLER_FAILED, exactly!(1), equals!(TransitStatus::Internal))
		]
	}
}

tb_scenario! {
	name: mux_serve_handler_failure_answers_internal,
	spec: MuxHandlerFailureSpec,
	environment ServiceClient {
		context: GateContext::generate(),
		server: |SetupEnv { context: ctx, trace }| async move {
			let (listener, addr) = bind_pool_listener(&ctx.materials).await?;
			let handler_ctx = Arc::clone(&ctx);
			let handle = server! {
				protocol TokioListener: listener,
				policies: {
					with_trace: [ trace.share() ],
					with_mux_offer: [ Some(mux_offer(8)) ]
				},
				handle: move |frame: Frame| {
					let ctx = Arc::clone(&handler_ctx);
					async move {
						// The first frame fails and later frames echo, so the
						// same connection must survive a handler failure.
						if ctx.handler_invoked.swap(true, Ordering::SeqCst) {
							Ok(Some(frame))
						} else {
							Err(TightBeamError::MissingResponse)
						}
					}
				}
			};
			Ok((handle, addr))
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = mux_pool(&ctx.materials, Some(mux_offer(8)), 1, &trace)?;
			let mut client = pool.connect(addr).await?;

			let failed = client.emit(mux_frame("poison"), None).await;
			assert!(
				matches!(failed, Err(TransportError::OperationFailed(TransportFailure::Internal))),
				"the handler failure must reach the caller as Internal"
			);

			let follow_up = mux_frame("recovery");
			let echoed = client.emit(follow_up.to_owned(), None).await?;
			assert_eq!(echoed, Some(follow_up), "the connection must serve the next call after a handler failure");
			Ok(())
		}
	}
}

/// The settlement challenge the metering authorizer binds into every
/// receipt.
const METERED_CHALLENGE: &[u8] = b"pool-invoice-1";

/// The settlement answer the pool-forwarded approver countersigns.
const METERED_RESPONSE: &[u8] = b"pool-preimage-1";

/// The application code for an unanswered metering settlement.
const METERED_REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR + 33;

/// The budgets under which the fifth single-chunk emit triggers in-band
/// renewal, with caps of 1/1 and a 1 KiB chunk.
const METERED_BUDGETS: MuxBudgets = MuxBudgets { client_to_server: 10, server_to_client: 4096 };

fn metered_offer() -> Option<TransportOffer> {
	let offer = TransportOffer::mux(1)
		.with_chunk_payload_size(1024)
		.with_budgets(METERED_BUDGETS);
	Some(offer)
}

/// An authorizer that settles at handshake and at renewal. An unanswered
/// challenge fails closed.
struct MeteredAuthorizer {
	challenge: OctetString,
	expected_response: OctetString,
}

impl MeteredAuthorizer {
	fn new() -> Result<Self, TightBeamError> {
		Ok(Self {
			challenge: OctetString::new(METERED_CHALLENGE)?,
			expected_response: OctetString::new(METERED_RESPONSE)?,
		})
	}
}

impl TransportAuthorizer for MeteredAuthorizer {
	fn authorize<'a>(
		&'a self,
		offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		Box::pin(async move {
			let grant =
				AuthorizationGrant { budgets: offer.requested_budgets, challenge: Some(self.challenge.to_owned()) };
			Ok(grant)
		})
	}

	fn challenge_renewal<'a>(
		&'a self,
		_prior: &'a SessionReceipt,
	) -> MaybeSendFuture<'a, Result<Option<OctetString>, AuthorizationRefusal>> {
		Box::pin(async move { Ok(Some(self.challenge.to_owned())) })
	}

	fn settle<'a>(
		&'a self,
		_receipt: &'a SessionReceipt,
		response: Option<&'a [u8]>,
		_client: &'a Certificate,
	) -> MaybeSendFuture<'a, Result<(), AuthorizationRefusal>> {
		Box::pin(async move {
			if response == Some(self.expected_response.as_bytes()) {
				return Ok(());
			}

			Err(AuthorizationRefusal { code: METERED_REFUSAL_CODE })
		})
	}
}

struct MeteredContext {
	materials: ServerMaterials,
	client_certificate: Arc<Certificate>,
	client_provider: Arc<dyn SigningKeyProvider>,
}

impl MeteredContext {
	fn generate() -> Self {
		let signing_key = random_signing_key();
		let client_certificate = Arc::new(test_certificate(&signing_key));
		let client_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(signing_key));
		Self { materials: ServerMaterials::generate(), client_certificate, client_provider }
	}
}

async fn start_metered_echo_server(
	ctx: &MeteredContext,
) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError> {
	let (listener, addr) = bind_mutual_listener(&ctx.materials, &ctx.client_certificate).await?;
	let addr = TightBeamSocketAddr(addr);
	let authorizer: Arc<dyn TransportAuthorizer> = Arc::new(MeteredAuthorizer::new()?);
	let handle = server! {
		protocol TokioListener: listener,
		policies: {
			with_mux_offer: [ metered_offer() ],
			with_transport_authorizer: [ Arc::clone(&authorizer) ]
		},
		handle: move |frame: Frame| async move { Ok(Some(frame)) }
	};

	Ok((handle, addr))
}

fn metered_pool(
	ctx: &MeteredContext,
	trace: &TraceCollector,
) -> Result<Arc<ConnectionPool<TokioListener>>, TightBeamError> {
	let trust_store = pinning_trust_store(&ctx.materials.certificate)?;
	let client_certificate = ctx.client_certificate.as_ref().to_owned();
	let identity = CertificateSpec::Built(Box::new(client_certificate));
	let client_provider = Arc::clone(&ctx.client_provider);
	let receipt_approver = Arc::new(PayingApprover::answering(METERED_RESPONSE)?);
	let config = PoolConfig { idle_timeout: None, max_connections: 1, mux_offer: metered_offer().map(Arc::new) };
	let builder = ConnectionPool::<TokioListener>::builder()
		.with_config(config)
		.with_trust_store(trust_store)
		.with_client_identity(SigningIdentity::from_spec(identity, client_provider)?)
		.with_receipt_approver(receipt_approver)
		.with_trace(trace.share());

	let pool = Arc::new(builder.build());
	Ok(pool)
}

async fn metered_series(lease: &mut PooledClient<TokioListener>, count: usize) -> Result<bool, TightBeamError> {
	for index in 0..count {
		let echoed = echo_roundtrip(lease, &format!("metered-{index}")).await?;
		if !echoed {
			return Ok(false);
		}
	}

	Ok(true)
}

tb_assert_spec! {
	pub PooledMeteringSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::SESSION_RECEIPT_SETTLED, exactly!(1)),
			(events::MUX_REKEY_REQUESTED, at_least!(1)),
			(events::MUX_REKEY_RENEWED, at_least!(1))
		]
	}
}

tb_scenario! {
	name: pooled_mux_metering_settles_and_rotates_receipt,
	spec: PooledMeteringSpec,
	environment ServiceClient {
		context: MeteredContext::generate(),
		server: |env| async move { start_metered_echo_server(&env.context).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = metered_pool(&ctx, &trace)?;
			let mut lease = pool.connect(addr).await?;
			let initial = lease.session_receipt();

			let echoed = metered_series(&mut lease, 8).await?;
			assert!(echoed, "every emit must echo across the in-band renewal");

			let renewed = await_transport(|| trace.recorded(events::MUX_REKEY_RENEWED) >= 1).await;
			let rotated = await_receipt_rotation(|| lease.session_receipt(), initial.as_deref()).await;
			assert!(initial.is_some(), "the lease must expose the receipt that the handshake settled");
			assert!(renewed, "the in-band renewal must complete within the wait");
			assert!(rotated.is_some(), "the lease must expose the receipt that the renewal rotated");
			Ok(())
		}
	}
}
