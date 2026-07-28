//! Pooled multiplexing integration tests.

#![cfg(all(
	feature = "transport-ecies",
	feature = "transport-policy",
	feature = "transport-multiplex",
	feature = "tcp",
	feature = "tokio",
	feature = "x509",
	feature = "testing",
	feature = "instrument"
))]

use core::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use tightbeam::at_least;
use tightbeam::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
use tightbeam::crypto::x509::CertificateSpec;
use tightbeam::der::asn1::OctetString;
use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::policy::{AcceptAllGate, GatePolicy, SessionContext, TransitStatus};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::server;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ClientEnv, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::MUX_APPLICATION_CODE_FLOOR;
use tightbeam::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, TransportAuthorizer, TransportOffer,
};
use tightbeam::transport::handshake::receipt::SessionReceipt;
use tightbeam::transport::multiplex::{MuxAcceptor, MuxRole, MuxTransport, ReplySink, StreamBody};
use tightbeam::transport::policy::PolicyConf;
use tightbeam::transport::serve::MuxService;
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{
	ClientBuilder, ConnectionBuilder, ConnectionPool, PoolConfig, PooledClient, ResponsePackage, TransportError,
	TransportFailure,
};
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::utils::urn::Urn;
use tightbeam::x509::Certificate;
use tightbeam::{Frame, TightBeamError};

use crate::common::security::{
	pinning_trust_store, random_signing_key, test_certificate, PayingApprover, ServerMaterials,
};
use crate::transport::support::{
	await_ok, await_receipt_rotation, bind_encrypted_listener, bind_mutual_listener, mux_frame, mux_offer,
};

pub(crate) const CAPPED_FAILOVER_REUSES_POOLED_HEADROOM: Urn<'static> =
	Urn::new("test", "event:pool-mux/capped-failover-reuses-pooled-headroom");
pub(crate) const CONN_REPORTS_INVALID_STATE: Urn<'static> =
	Urn::new("test", "event:pool-mux/conn-reports-invalid-state");
pub(crate) const DECLINED_LEASE_IS_EXCLUSIVE: Urn<'static> =
	Urn::new("test", "event:pool-mux/declined-lease-is-exclusive");
pub(crate) const EMITS_SURVIVE_RENEWAL: Urn<'static> = Urn::new("test", "event:pool-mux/emits-survive-renewal");
pub(crate) const EMIT_ECHOES_BEFORE_IDLE: Urn<'static> = Urn::new("test", "event:pool-mux/emit-echoes-before-idle");
pub(crate) const EMIT_ECHOES_BEFORE_TEARDOWN: Urn<'static> =
	Urn::new("test", "event:pool-mux/emit-echoes-before-teardown");
pub(crate) const EMIT_FAILS_ON_DEAD_CONNECTION: Urn<'static> =
	Urn::new("test", "event:pool-mux/emit-fails-on-dead-connection");
pub(crate) const EXCLUSIVE_LEASE_ECHOES: Urn<'static> = Urn::new("test", "event:pool-mux/exclusive-lease-echoes");
pub(crate) const FIRST_FAILOVER_ECHOES_ON_NEW_DIAL: Urn<'static> =
	Urn::new("test", "event:pool-mux/first-failover-echoes-on-new-dial");
pub(crate) const FIRST_LEASE_ECHOES: Urn<'static> = Urn::new("test", "event:pool-mux/first-lease-echoes");
pub(crate) const FRESH_CONNECT_ECHOES_AFTER_EVICTION: Urn<'static> =
	Urn::new("test", "event:pool-mux/fresh-connect-echoes-after-eviction");
pub(crate) const FRESH_CONNECT_ECHOES_AFTER_PRUNE: Urn<'static> =
	Urn::new("test", "event:pool-mux/fresh-connect-echoes-after-prune");
pub(crate) const GATE_LIST_FIRST_REFUSAL_WINS: Urn<'static> =
	Urn::new("test", "event:pool-mux/gate-list-first-refusal-wins");
pub(crate) const GATE_STATUS_SURFACES_TO_CLIENT: Urn<'static> =
	Urn::new("test", "event:pool-mux/gate-status-surfaces-to-client");
pub(crate) const GATE_STREAM_STATUS_SURFACES_TO_CLIENT: Urn<'static> =
	Urn::new("test", "event:pool-mux/gate-stream-status-surfaces-to-client");
pub(crate) const GATE_DUPLEX_STATUS_SURFACES_TO_CLIENT: Urn<'static> =
	Urn::new("test", "event:pool-mux/gate-duplex-status-surfaces-to-client");
pub(crate) const GATE_UNKNOWN_ANSWERS_INTERNAL: Urn<'static> =
	Urn::new("test", "event:pool-mux/gate-unknown-answers-internal");
pub(crate) const HANDLER_FAILURE_SURFACES_INTERNAL: Urn<'static> =
	Urn::new("test", "event:pool-mux/handler-failure-surfaces-internal");
pub(crate) const HANDLER_NEVER_INVOKED: Urn<'static> = Urn::new("test", "event:pool-mux/handler-never-invoked");
pub(crate) const STREAM_HANDLER_NEVER_INVOKED: Urn<'static> =
	Urn::new("test", "event:pool-mux/stream-handler-never-invoked");
pub(crate) const DUPLEX_HANDLER_NEVER_INVOKED: Urn<'static> =
	Urn::new("test", "event:pool-mux/duplex-handler-never-invoked");
pub(crate) const HANDLER_RECOVERS_AFTER_FAILURE: Urn<'static> =
	Urn::new("test", "event:pool-mux/handler-recovers-after-failure");
pub(crate) const HELD_EMIT_COMPLETES_AFTER_RELEASE: Urn<'static> =
	Urn::new("test", "event:pool-mux/held-emit-completes-after-release");
pub(crate) const LEASE_EXPOSES_SETTLED_RECEIPT: Urn<'static> =
	Urn::new("test", "event:pool-mux/lease-exposes-settled-receipt");
pub(crate) const LEASE_OBSERVES_ROTATED_RECEIPT: Urn<'static> =
	Urn::new("test", "event:pool-mux/lease-observes-rotated-receipt");
pub(crate) const OVERFLOW_EMIT_ECHOES_ON_SECOND_CONNECTION: Urn<'static> =
	Urn::new("test", "event:pool-mux/overflow-emit-echoes-on-second-connection");
pub(crate) const REFUSED_EMIT_SURFACES_BUSY: Urn<'static> =
	Urn::new("test", "event:pool-mux/refused-emit-surfaces-busy");
pub(crate) const REUSED_LEASE_ECHOES: Urn<'static> = Urn::new("test", "event:pool-mux/reused-lease-echoes");
pub(crate) const REUSED_LEASE_IS_EXCLUSIVE: Urn<'static> = Urn::new("test", "event:pool-mux/reused-lease-is-exclusive");
pub(crate) const SECOND_CONNECTION_DIALED: Urn<'static> = Urn::new("test", "event:pool-mux/second-connection-dialed");
pub(crate) const SECOND_LEASE_ECHOES: Urn<'static> = Urn::new("test", "event:pool-mux/second-lease-echoes");
pub(crate) const POOLED_DUPLEX_ECHOES_CHUNKS: Urn<'static> =
	Urn::new("test", "event:pool-mux/pooled-duplex-echoes-chunks");
pub(crate) const POOLED_MIXED_KINDS_SHARE_ONE_CONNECTION: Urn<'static> =
	Urn::new("test", "event:pool-mux/pooled-mixed-kinds-share-one-connection");
pub(crate) const POOLED_STREAM_RESPONSE_REPORTS_LENGTH: Urn<'static> =
	Urn::new("test", "event:pool-mux/pooled-stream-response-reports-length");
pub(crate) const UNSERVED_KIND_ANSWERS_UNIMPLEMENTED: Urn<'static> =
	Urn::new("test", "event:pool-mux/unserved-kind-answers-unimplemented");
pub(crate) const SINGLE_FLIGHT_ECHO_ON_MUX_SERVER: Urn<'static> =
	Urn::new("test", "event:pool-mux/single-flight-echo-on-mux-server");

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

/// Serve every accepted connection with `service` through the `server!`
/// service form: mux takeover routes all stream kinds, non-mux peers get
/// the single-flight unary loop.
async fn start_service_server<S>(
	materials: &ServerMaterials,
	service: S,
) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError>
where
	S: MuxService,
{
	let (listener, addr) = bind_pool_listener(materials).await?;
	let acceptor = server! {
		protocol TokioListener: listener,
		policies: { with_mux_offer: [ Some(mux_offer(8)) ] },
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
	// Accept-loop re-applies policies per connection: share/clone must
	// stay as expressions so each accept gets a fresh value.
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

/// Streaming-only service: answers with the collected body length as
/// a frame label. Unary and duplex kinds refuse with `Unimplemented`
/// through the [`MuxService`] defaults.
#[derive(Clone)]
struct LengthService;

impl MuxService for LengthService {
	async fn streaming(&self, body: StreamBody, _session: SessionContext) -> Result<Option<Frame>, TightBeamError> {
		let bytes = body.into_bytes().await?;
		Ok(Some(mux_frame(&bytes.len().to_string())))
	}
}

/// Duplex-only service: echoes every request chunk back through the reply sink.
#[derive(Clone)]
struct DuplexEchoService;

impl MuxService for DuplexEchoService {
	async fn duplex(
		&self,
		mut body: StreamBody,
		mut reply: ReplySink,
		_session: SessionContext,
	) -> Result<(), TightBeamError> {
		while let Some(chunk) = body.chunk().await? {
			reply.push(&chunk).await?;
		}
		Ok(())
	}
}

/// Full-service handler: unary echoes the frame, streaming reports
/// the collected length, duplex echoes chunk by chunk.
#[derive(Clone)]
struct MixedService;

impl MuxService for MixedService {
	async fn unary(&self, frame: Frame, _session: SessionContext) -> Result<Option<Frame>, TightBeamError> {
		Ok(Some(frame))
	}

	async fn streaming(&self, body: StreamBody, _session: SessionContext) -> Result<Option<Frame>, TightBeamError> {
		let bytes = body.into_bytes().await?;
		Ok(Some(mux_frame(&bytes.len().to_string())))
	}

	async fn duplex(
		&self,
		mut body: StreamBody,
		mut reply: ReplySink,
		_session: SessionContext,
	) -> Result<(), TightBeamError> {
		while let Some(chunk) = body.chunk().await? {
			reply.push(&chunk).await?;
		}
		Ok(())
	}
}

fn mux_pool_with_idle_timeout(
	materials: &ServerMaterials,
	offer: Option<TransportOffer>,
	max_connections: usize,
	idle_timeout: Option<Duration>,
	trace: &TraceCollector,
) -> Result<Arc<ConnectionPool<TokioListener>>, TightBeamError> {
	let trust_store = pinning_trust_store(&materials.certificate)?;
	let config = PoolConfig { idle_timeout, max_connections, mux_offer: offer };
	let pool = Arc::new(
		ConnectionPool::<TokioListener>::builder()
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

async fn echo_roundtrip(client: &mut PooledClient<TokioListener>, label: &str) -> Result<bool, TightBeamError> {
	let frame = mux_frame(label);
	let reply = client.emit(frame.to_owned(), None).await?;
	Ok(reply == Some(frame))
}

tb_assert_spec! {
	pub MuxLeaseShareSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::POOL_REUSE_MUX, exactly!(1)),
			(events::POOL_MUX_DECLINED, exactly!(0)),
			(FIRST_LEASE_ECHOES, exactly!(1), equals!(true)),
			(SECOND_LEASE_ECHOES, exactly!(1), equals!(true))
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

			trace.event_with(FIRST_LEASE_ECHOES, &[], reply_one? == Some(frame_one))?;
			trace.event_with(SECOND_LEASE_ECHOES, &[], reply_two? == Some(frame_two))?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PooledStreamSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(POOLED_STREAM_RESPONSE_REPORTS_LENGTH, exactly!(1), equals!(true))
		]
	}
}

// Streaming reaches through the orchestration layer: pooled lease opens
// the stream, the streaming-only service collects and answers.
tb_scenario! {
	name: pooled_open_stream_reaches_streaming_server,
	spec: PooledStreamSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_service_server(&env.context, LengthService).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;
			let lease = pool.connect(addr).await?;

			let (mut sink, response) = lease.open_stream()?;
			sink.push(b"abcd").await?;
			sink.close_with(b"efgh").await?;
			let reply = response.await?;

			trace.event_with(
				POOLED_STREAM_RESPONSE_REPORTS_LENGTH,
				&[],
				reply.map(|frame| frame.message.to_owned()) == Some(mux_frame("8").message.to_owned()),
			)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PooledDuplexSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(POOLED_DUPLEX_ECHOES_CHUNKS, exactly!(1), equals!(true))
		]
	}
}

// Duplex reaches through the orchestration layer: pooled lease opens
// the duplex, the duplex-only service echoes chunk by chunk.
tb_scenario! {
	name: pooled_open_duplex_echoes_through_serve_wrapper,
	spec: PooledDuplexSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_service_server(&env.context, DuplexEchoService).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;
			let lease = pool.connect(addr).await?;

			let (mut sink, mut body) = lease.open_duplex()?;
			sink.push(b"ping").await?;
			let first = body.chunk().await?;
			sink.close_with(b"pong").await?;
			let second = body.chunk().await?;
			let terminal = body.chunk().await?;

			trace.event_with(
				POOLED_DUPLEX_ECHOES_CHUNKS,
				&[],
				first.as_deref() == Some(b"ping".as_ref())
					&& second.as_deref() == Some(b"pong".as_ref())
					&& terminal.is_none(),
			)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PooledMixedKindsSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(POOLED_MIXED_KINDS_SHARE_ONE_CONNECTION, exactly!(1), equals!(true))
		]
	}
}

// The point of stream kinds: unary, streaming, and duplex interactions run
// concurrently on one pooled connection against one service.
tb_scenario! {
	name: pooled_mixed_kinds_share_one_connection,
	spec: PooledMixedKindsSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_service_server(&env.context, MixedService).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;
			// Leases are exclusive per in-flight interaction; one pooled
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
			trace.event_with(
				POOLED_MIXED_KINDS_SHARE_ONE_CONNECTION,
				&[],
				unary_reply? == Some(unary_frame)
					&& stream_reply?.map(|frame| frame.message.to_owned())
						== Some(mux_frame("8").message.to_owned())
					&& echoed.as_deref() == Some(b"ping".as_ref())
					&& terminal.is_none(),
			)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub UnservedKindSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(UNSERVED_KIND_ANSWERS_UNIMPLEMENTED, exactly!(1), equals!(true))
		]
	}
}

// A kind the service does not implement refuses its stream with
// `Unimplemented` while leaving the connection serving other streams.
tb_scenario! {
	name: unserved_kind_answers_unimplemented,
	spec: UnservedKindSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_service_server(&env.context, LengthService).await },
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

			// Unary against the same service: the response future
			// surfaces the refusal, and the connection still serves
			// the streaming kind afterwards.
			let unary_refused = matches!(
				lease.emit(mux_frame("unserved"), None).await,
				Err(TransportError::OperationFailed(TransportFailure::Unimplemented))
			);

			let (sink, response) = lease.open_stream()?;
			sink.close_with(b"abcd").await?;

			let served = response.await?.map(|frame| frame.message.to_owned()) == Some(mux_frame("4").message.to_owned());
			trace.event_with(
				UNSERVED_KIND_ANSWERS_UNIMPLEMENTED,
				&[],
				duplex_refused && unary_refused && served,
			)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxLeaseConnSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(CONN_REPORTS_INVALID_STATE, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_lease_conn_reports_invalid_state,
	spec: MuxLeaseConnSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_echo_server(&env.context, Some(mux_offer(8))).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(mux_offer(8)), 1, &trace)?;

			let mut lease = pool.connect(addr).await?;
			let conn = lease.conn();

			trace.event_with(
				CONN_REPORTS_INVALID_STATE,
				&[],
				matches!(conn, Err(TransportError::InvalidState)),
			)?;
			Ok(())
		}
	}
}

struct GatedContext {
	materials: ServerMaterials,
	started: Notify,
	release: Notify,
}

impl GatedContext {
	fn generate() -> Self {
		Self {
			materials: ServerMaterials::generate(),
			started: Notify::new(),
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
					ctx.started.notify_one();
					ctx.release.notified().await;
				}

				Ok(Some(frame))
			}
		}
	};

	Ok((handle, addr))
}

async fn spawn_held_emit(ctx: &GatedContext, mut lease: PooledClient<TokioListener>) -> EmitTask {
	let held_task = tokio::spawn(async move { lease.emit(mux_frame("mux-held"), None).await });
	ctx.started.notified().await;
	held_task
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
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(2)),
			(events::POOL_REUSE_MUX, exactly!(1)),
			(events::POOL_FAILOVER, exactly!(1)),
			(events::POOL_EXHAUSTED, exactly!(0)),
			(OVERFLOW_EMIT_ECHOES_ON_SECOND_CONNECTION, exactly!(1), equals!(true)),
			(HELD_EMIT_COMPLETES_AFTER_RELEASE, exactly!(1), equals!(true))
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
			let held_task = spawn_held_emit(&ctx, held_lease).await;

			let failed_over = echo_roundtrip(&mut second_lease, "mux-second").await?;
			trace.event_with(OVERFLOW_EMIT_ECHOES_ON_SECOND_CONNECTION, &[], failed_over)?;

			let held_completed = release_held_emit(&ctx, held_task).await?;
			trace.event_with(HELD_EMIT_COMPLETES_AFTER_RELEASE, &[], held_completed)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxFailoverReuseSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(2)),
			(events::POOL_REUSE_MUX, exactly!(3)),
			(events::POOL_FAILOVER, exactly!(2)),
			(events::POOL_EXHAUSTED, exactly!(0)),
			(FIRST_FAILOVER_ECHOES_ON_NEW_DIAL, exactly!(1), equals!(true)),
			(CAPPED_FAILOVER_REUSES_POOLED_HEADROOM, exactly!(1), equals!(true)),
			(HELD_EMIT_COMPLETES_AFTER_RELEASE, exactly!(1), equals!(true))
		]
	}
}

// Pool at max_connections: failover reuses headroom instead of dialing (ResourceExhausted).
tb_scenario! {
	name: pooled_mux_failover_reuses_pooled_headroom,
	spec: MuxFailoverReuseSpec,
	environment ServiceClient {
		context: GatedContext::generate(),
		server: |env| async move { start_gated_echo_server(&env.context, Some(mux_offer(1))).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = mux_pool(&ctx.materials, Some(mux_offer(4)), 2, &trace)?;

			// Three leases on connection one (only pool entry).
			let held_lease = pool.connect(addr).await?;
			let mut fill_lease = pool.connect(addr).await?;
			let mut reuse_lease = pool.connect(addr).await?;
			let held_task = spawn_held_emit(&ctx, held_lease).await;

			// Saturated: failover dials connection two.
			let filled = echo_roundtrip(&mut fill_lease, "mux-fill").await?;
			trace.event_with(FIRST_FAILOVER_ECHOES_ON_NEW_DIAL, &[], filled)?;

			let reused = echo_roundtrip(&mut reuse_lease, "mux-reuse").await?;
			trace.event_with(CAPPED_FAILOVER_REUSES_POOLED_HEADROOM, &[], reused)?;

			let held_completed = release_held_emit(&ctx, held_task).await?;
			trace.event_with(HELD_EMIT_COMPLETES_AFTER_RELEASE, &[], held_completed)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxNoHeadroomSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::POOL_REUSE_MUX, exactly!(1)),
			(events::POOL_FAILOVER, exactly!(1)),
			(events::POOL_EXHAUSTED, exactly!(1)),
			(REFUSED_EMIT_SURFACES_BUSY, exactly!(1), equals!(true)),
			(HELD_EMIT_COMPLETES_AFTER_RELEASE, exactly!(1), equals!(true))
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
			let held_task = spawn_held_emit(&ctx, held_lease).await;

			let refused = second_lease.emit(mux_frame("mux-refused"), None).await;
			trace.event_with(
				REFUSED_EMIT_SURFACES_BUSY,
				&[],
				matches!(refused, Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted))),
			)?;

			let held_completed = release_held_emit(&ctx, held_task).await?;
			trace.event_with(HELD_EMIT_COMPLETES_AFTER_RELEASE, &[], held_completed)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxDeclinedFallbackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::POOL_MUX_DECLINED, exactly!(1)),
			(events::POOL_REUSE_MUX, exactly!(0)),
			(DECLINED_LEASE_IS_EXCLUSIVE, exactly!(1), equals!(true)),
			(EXCLUSIVE_LEASE_ECHOES, exactly!(1), equals!(true))
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
			trace.event_with(DECLINED_LEASE_IS_EXCLUSIVE, &[], lease.conn().is_ok())?;

			let echoed = echo_roundtrip(&mut lease, "mux-declined").await?;
			trace.event_with(EXCLUSIVE_LEASE_ECHOES, &[], echoed)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxDeclinedIdleReuseSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::POOL_MUX_DECLINED, exactly!(1)),
			(events::POOL_REUSE_READY, exactly!(1)),
			(events::POOL_EXHAUSTED, exactly!(0)),
			(REUSED_LEASE_IS_EXCLUSIVE, exactly!(1), equals!(true)),
			(REUSED_LEASE_ECHOES, exactly!(1), equals!(true))
		]
	}
}

// Cap 1: reuse idle exclusive connection instead of dialing (ResourceExhausted).
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
			trace.event_with(REUSED_LEASE_IS_EXCLUSIVE, &[], reused_lease.conn().is_ok())?;

			let echoed = echo_roundtrip(&mut reused_lease, "mux-idle-reuse").await?;
			trace.event_with(REUSED_LEASE_ECHOES, &[], echoed)?;
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

	fn register_tasks(&self, spawned: Vec<JoinHandle<Result<(), TransportError>>>) {
		let mut registry = match self.connection_tasks.lock() {
			Ok(tasks) => tasks,
			Err(poisoned) => poisoned.into_inner(),
		};
		registry.extend(spawned);
	}

	fn connection_task_count(&self) -> usize {
		match self.connection_tasks.lock() {
			Ok(tasks) => tasks.len(),
			Err(poisoned) => poisoned.into_inner().len(),
		}
	}

	/// Abort connection tasks so split halves drop and TCP closes.
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
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(2)),
			(events::POOL_EVICTED, exactly!(1)),
			(EMIT_ECHOES_BEFORE_TEARDOWN, exactly!(1), equals!(true)),
			(EMIT_FAILS_ON_DEAD_CONNECTION, exactly!(1), equals!(true)),
			(FRESH_CONNECT_ECHOES_AFTER_EVICTION, exactly!(1), equals!(true))
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
			trace.event_with(EMIT_ECHOES_BEFORE_TEARDOWN, &[], echoed_before)?;

			ctx.abort_connections().await;

			let dead = lease.emit(mux_frame("mux-during"), None).await;
			trace.event_with(EMIT_FAILS_ON_DEAD_CONNECTION, &[], dead.is_err())?;

			let mut fresh = pool.connect(addr).await?;
			let echoed_after = echo_roundtrip(&mut fresh, "mux-after").await?;
			trace.event_with(FRESH_CONNECT_ECHOES_AFTER_EVICTION, &[], echoed_after)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxIdlePruneSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(2)),
			(events::POOL_PRUNED_IDLE, exactly!(1)),
			(events::POOL_EXHAUSTED, exactly!(0)),
			(EMIT_ECHOES_BEFORE_IDLE, exactly!(1), equals!(true)),
			(FRESH_CONNECT_ECHOES_AFTER_PRUNE, exactly!(1), equals!(true)),
			(SECOND_CONNECTION_DIALED, exactly!(1), equals!(true))
		]
	}
}

// idle_timeout prune frees cap-1 slot; manual server registers 3 tasks per connection.
tb_scenario! {
	name: pooled_mux_prunes_idle_connection,
	spec: MuxIdlePruneSpec,
	environment ServiceClient {
		context: ManualContext::generate(),
		server: |env| async move { start_manual_mux_echo_server(&env.context).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let idle_timeout = Duration::from_millis(50);
			let pool = mux_pool_with_idle_timeout(&ctx.materials, Some(mux_offer(4)), 1, Some(idle_timeout), &trace)?;

			let mut lease = pool.connect(addr).await?;
			let echoed_before = echo_roundtrip(&mut lease, "mux-idle-before").await?;
			trace.event_with(EMIT_ECHOES_BEFORE_IDLE, &[], echoed_before)?;
			drop(lease);

			sleep(idle_timeout * 2).await;

			let mut fresh = pool.connect(addr).await?;
			let echoed_after = echo_roundtrip(&mut fresh, "mux-idle-after").await?;
			trace.event_with(FRESH_CONNECT_ECHOES_AFTER_PRUNE, &[], echoed_after)?;

			trace.event_with(SECOND_CONNECTION_DIALED, &[], ctx.connection_task_count() == 6)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxServesSingleFlightSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(SINGLE_FLIGHT_ECHO_ON_MUX_SERVER, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: single_flight_client_round_trips_on_mux_server,
	spec: MuxServesSingleFlightSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_echo_server(&env.context, Some(mux_offer(8))).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let trust_store = pinning_trust_store(&materials.certificate)?;
			let mut client = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(trust_store)
				.build()
				.connect(addr)
				.await?;

			let frame = mux_frame("single-flight");
			let reply = client.emit(frame.to_owned(), None).await?;
			trace.event_with(SINGLE_FLIGHT_ECHO_ON_MUX_SERVER, &[], reply == Some(frame))?;
			Ok(())
		}
	}
}

/// Single-flight client against `materials`' pinned server.
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
	let released = tokio::time::timeout(Duration::from_secs(5), fresh.emit(mux_frame("after-release"), None)).await;
	assert!(
		matches!(released, Ok(Ok(Some(_)))),
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

/// Streaming service that records whether the handler body ran.
struct ProbeLengthService {
	gate: Arc<GateContext>,
}

impl MuxService for ProbeLengthService {
	async fn streaming(&self, body: StreamBody, _session: SessionContext) -> Result<Option<Frame>, TightBeamError> {
		self.gate.handler_invoked.store(true, Ordering::SeqCst);
		let bytes = body.into_bytes().await?;
		Ok(Some(mux_frame(&bytes.len().to_string())))
	}
}

/// Duplex service that records whether the handler body ran.
struct ProbeDuplexService {
	gate: Arc<GateContext>,
}

impl MuxService for ProbeDuplexService {
	async fn duplex(
		&self,
		mut body: StreamBody,
		mut reply: ReplySink,
		_session: SessionContext,
	) -> Result<(), TightBeamError> {
		self.gate.handler_invoked.store(true, Ordering::SeqCst);
		while let Some(chunk) = body.chunk().await? {
			reply.push(&chunk).await?;
		}
		Ok(())
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

tb_assert_spec! {
	pub MuxGateSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::GATE_REJECT, exactly!(1)),
			(GATE_STATUS_SURFACES_TO_CLIENT, exactly!(1), equals!(true)),
			(HANDLER_NEVER_INVOKED, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_serve_gate_rejects_without_handler,
	spec: MuxGateSpec,
	environment ServiceClient {
		context: GateContext::generate(),
		server: |SetupEnv { context: ctx, trace }| async move {
			let (listener, addr) = bind_pool_listener(&ctx.materials).await?;
			let handler_ctx = Arc::clone(&ctx);
			let handle = server! {
				protocol TokioListener: listener,
				policies: {
					with_trace: [ trace.share() ],
					with_mux_offer: [ Some(mux_offer(8)) ],
					with_collector_gate: [ ForbidAllGate ]
				},
				handle: move |frame: Frame| {
					let ctx = Arc::clone(&handler_ctx);
					async move {
						ctx.handler_invoked.store(true, Ordering::SeqCst);
						Ok(Some(frame))
					}
				}
			};
			Ok((handle, addr))
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = mux_pool(&ctx.materials, Some(mux_offer(8)), 1, &trace)?;
			let mut client = pool.connect(addr).await?;

			let outcome = client.emit(mux_frame("gated"), None).await;
			trace.event_with(
				GATE_STATUS_SURFACES_TO_CLIENT,
				&[],
				matches!(outcome, Err(TransportError::OperationFailed(TransportFailure::PermissionDenied))),
			)?;

			trace.event_with(HANDLER_NEVER_INVOKED, &[], !ctx.handler_invoked.load(Ordering::SeqCst))?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxStreamGateSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::GATE_REJECT, exactly!(1)),
			(GATE_STREAM_STATUS_SURFACES_TO_CLIENT, exactly!(1), equals!(true)),
			(STREAM_HANDLER_NEVER_INVOKED, exactly!(1), equals!(true))
		]
	}
}

// Collector gates must refuse streaming before the service body runs,
// matching unary dispatch.
tb_scenario! {
	name: mux_serve_gate_rejects_streaming_without_handler,
	spec: MuxStreamGateSpec,
	environment ServiceClient {
		context: GateContext::generate(),
		server: |SetupEnv { context: ctx, trace }| async move {
			let service = ProbeLengthService { gate: Arc::clone(&ctx) };
			start_gated_service_server(&ctx.materials, trace.share(), service, ForbidAllGate).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = mux_pool(&ctx.materials, Some(mux_offer(8)), 1, &trace)?;
			let lease = pool.connect(addr).await?;

			let (sink, response) = lease.open_stream()?;
			sink.close_with(b"gated-stream").await?;

			let outcome = response.await;
			trace.event_with(
				GATE_STREAM_STATUS_SURFACES_TO_CLIENT,
				&[],
				matches!(outcome, Err(TransportError::OperationFailed(TransportFailure::PermissionDenied))),
			)?;

			trace.event_with(
				STREAM_HANDLER_NEVER_INVOKED,
				&[],
				!ctx.handler_invoked.load(Ordering::SeqCst),
			)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxDuplexGateSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::GATE_REJECT, exactly!(1)),
			(GATE_DUPLEX_STATUS_SURFACES_TO_CLIENT, exactly!(1), equals!(true)),
			(DUPLEX_HANDLER_NEVER_INVOKED, exactly!(1), equals!(true))
		]
	}
}

// Collector gates must refuse duplex before the service body runs,
// matching unary dispatch.
tb_scenario! {
	name: mux_serve_gate_rejects_duplex_without_handler,
	spec: MuxDuplexGateSpec,
	environment ServiceClient {
		context: GateContext::generate(),
		server: |SetupEnv { context: ctx, trace }| async move {
			let service = ProbeDuplexService { gate: Arc::clone(&ctx) };
			start_gated_service_server(&ctx.materials, trace.share(), service, ForbidAllGate).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = mux_pool(&ctx.materials, Some(mux_offer(8)), 1, &trace)?;
			let lease = pool.connect(addr).await?;

			let (sink, mut body) = lease.open_duplex()?;
			sink.close().await?;

			let outcome = body.chunk().await;
			trace.event_with(
				GATE_DUPLEX_STATUS_SURFACES_TO_CLIENT,
				&[],
				matches!(outcome, Err(TransportError::OperationFailed(TransportFailure::PermissionDenied))),
			)?;

			trace.event_with(
				DUPLEX_HANDLER_NEVER_INVOKED,
				&[],
				!ctx.handler_invoked.load(Ordering::SeqCst),
			)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxGateListSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::GATE_REJECT, exactly!(1)),
			(GATE_LIST_FIRST_REFUSAL_WINS, exactly!(1), equals!(true)),
			(HANDLER_NEVER_INVOKED, exactly!(1), equals!(true))
		]
	}
}

// A bracketed gate list composes: the first refusing gate decides, so a
// trailing permissive gate must not silently displace the deny gate.
tb_scenario! {
	name: mux_serve_gate_list_composes_first_refusal,
	spec: MuxGateListSpec,
	environment ServiceClient {
		context: GateContext::generate(),
		server: |SetupEnv { context: ctx, trace }| async move {
			let (listener, addr) = bind_pool_listener(&ctx.materials).await?;
			let handler_ctx = Arc::clone(&ctx);
			let handle = server! {
				protocol TokioListener: listener,
				policies: {
					with_trace: [ trace.share() ],
					with_mux_offer: [ Some(mux_offer(8)) ],
					with_collector_gate: [ ForbidAllGate, AcceptAllGate ]
				},
				handle: move |frame: Frame| {
					let ctx = Arc::clone(&handler_ctx);
					async move {
						ctx.handler_invoked.store(true, Ordering::SeqCst);
						Ok(Some(frame))
					}
				}
			};
			Ok((handle, addr))
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = mux_pool(&ctx.materials, Some(mux_offer(8)), 1, &trace)?;
			let mut client = pool.connect(addr).await?;

			let outcome = client.emit(mux_frame("gate-list"), None).await;
			trace.event_with(
				GATE_LIST_FIRST_REFUSAL_WINS,
				&[],
				matches!(outcome, Err(TransportError::OperationFailed(TransportFailure::PermissionDenied))),
			)?;

			trace.event_with(HANDLER_NEVER_INVOKED, &[], !ctx.handler_invoked.load(Ordering::SeqCst))?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxUnknownGateSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::GATE_REJECT, exactly!(1)),
			(GATE_UNKNOWN_ANSWERS_INTERNAL, exactly!(1), equals!(true)),
			(HANDLER_NEVER_INVOKED, exactly!(1), equals!(true))
		]
	}
}

// `Unknown` from a gate is a local bug, not a peer-attributable verdict:
// the seam normalizes it to `Internal` so both planes answer identically.
tb_scenario! {
	name: mux_serve_unknown_gate_answers_internal,
	spec: MuxUnknownGateSpec,
	environment ServiceClient {
		context: GateContext::generate(),
		server: |SetupEnv { context: ctx, trace }| async move {
			let (listener, addr) = bind_pool_listener(&ctx.materials).await?;
			let handler_ctx = Arc::clone(&ctx);
			let handle = server! {
				protocol TokioListener: listener,
				policies: {
					with_trace: [ trace.share() ],
					with_mux_offer: [ Some(mux_offer(8)) ],
					with_collector_gate: [ UnknownGate ]
				},
				handle: move |frame: Frame| {
					let ctx = Arc::clone(&handler_ctx);
					async move {
						ctx.handler_invoked.store(true, Ordering::SeqCst);
						Ok(Some(frame))
					}
				}
			};
			Ok((handle, addr))
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = mux_pool(&ctx.materials, Some(mux_offer(8)), 1, &trace)?;
			let mut client = pool.connect(addr).await?;

			let outcome = client.emit(mux_frame("unknown-gate"), None).await;
			trace.event_with(
				GATE_UNKNOWN_ANSWERS_INTERNAL,
				&[],
				matches!(outcome, Err(TransportError::OperationFailed(TransportFailure::Internal))),
			)?;

			trace.event_with(HANDLER_NEVER_INVOKED, &[], !ctx.handler_invoked.load(Ordering::SeqCst))?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxHandlerFailureSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(2)),
			(HANDLER_FAILURE_SURFACES_INTERNAL, exactly!(1), equals!(true)),
			(HANDLER_RECOVERS_AFTER_FAILURE, exactly!(1), equals!(true))
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
						// First frame fails, later frames echo: the same
						// connection must survive a handler failure.
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
			trace.event_with(
				HANDLER_FAILURE_SURFACES_INTERNAL,
				&[],
				matches!(failed, Err(TransportError::OperationFailed(TransportFailure::Internal))),
			)?;

			let follow_up = mux_frame("recovery");
			let echoed = client.emit(follow_up.to_owned(), None).await?;
			trace.event_with(HANDLER_RECOVERS_AFTER_FAILURE, &[], echoed == Some(follow_up))?;
			Ok(())
		}
	}
}

/// Settlement challenge the metering authorizer binds into every receipt.
const METERED_CHALLENGE: &[u8] = b"pool-invoice-1";

/// Settlement answer the pool-forwarded approver countersigns.
const METERED_RESPONSE: &[u8] = b"pool-preimage-1";

/// Application code for an unanswered metering settlement.
const METERED_REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR + 33;

/// Fifth single-chunk emit triggers in-band renewal (caps 1/1, 1 KiB chunk).
const METERED_BUDGETS: MuxBudgets = MuxBudgets { client_to_server: 10, server_to_client: 4096 };

fn metered_offer() -> Option<TransportOffer> {
	let offer = TransportOffer::mux(1)
		.with_chunk_payload_size(1024)
		.with_budgets(METERED_BUDGETS);
	Some(offer)
}

/// Settlement at handshake and renewal; unanswered challenge fails closed.
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
	let config = PoolConfig { idle_timeout: None, max_connections: 1, mux_offer: metered_offer() };
	let builder = ConnectionPool::<TokioListener>::builder()
		.with_config(config)
		.with_trust_store(trust_store)
		.with_client_identity(identity, client_provider)?
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
		gate: Ok,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::MUX_REKEY_REQUESTED, at_least!(1)),
			(events::MUX_REKEY_RENEWED, at_least!(1)),
			(LEASE_EXPOSES_SETTLED_RECEIPT, exactly!(1), equals!(true)),
			(EMITS_SURVIVE_RENEWAL, exactly!(1), equals!(true)),
			(LEASE_OBSERVES_ROTATED_RECEIPT, exactly!(1), equals!(true))
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
			trace.event_with(LEASE_EXPOSES_SETTLED_RECEIPT, &[], initial.is_some())?;

			let echoed = metered_series(&mut lease, 8).await?;
			trace.event_with(EMITS_SURVIVE_RENEWAL, &[], echoed)?;

			let rotated = await_receipt_rotation(|| lease.session_receipt(), initial.as_deref()).await;
			trace.event_with(LEASE_OBSERVES_ROTATED_RECEIPT, &[], rotated.is_some())?;
			Ok(())
		}
	}
}
