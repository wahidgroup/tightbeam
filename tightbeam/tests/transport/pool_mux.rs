//! Pooled multiplexing integration tests.
//!
//! Drives `ConnectionPool` with a `mux_offer` against `server!` endpoints
//! and verifies:
//!
//! - Leases share one multiplexed connection per destination
//! - `conn()` on a multiplexed lease reports `InvalidState`
//! - Stream-cap exhaustion fails over to an additional connection
//! - Pool-capacity exhaustion surfaces `Busy` instead of failing over
//! - A peer that declines multiplexing yields an exclusive lease
//! - A dead multiplexed connection is evicted and re-established
//! - An idle multiplexed connection is pruned after the idle timeout
//! - Single-flight clients round-trip against a mux-offering server

#![cfg(all(
	feature = "transport-ecies",
	feature = "transport-policy",
	feature = "transport-multiplex",
	feature = "tcp",
	feature = "tokio",
	feature = "x509",
	feature = "testing"
))]

use core::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::server;
use tightbeam::testing::create_v0_tightbeam;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::multiplex::{MuxAcceptor, MuxRole, MuxTransport};
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{
	ClientBuilder, ConnectionBuilder, ConnectionPool, PoolConfig, ResponsePackage, TransportError, TransportFailure,
};
use tightbeam::{Frame, TightBeamError};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::common::security::{pinning_trust_store, ServerMaterials};
use crate::transport::support::bind_encrypted_listener;

/// Echo server built from the `server!` macro with an optional mux offer.
struct MuxEchoServer {
	materials: ServerMaterials,
	addr: TightBeamSocketAddr,
	_handle: JoinHandle<()>,
}

async fn start_mux_echo_server(offer: Option<TransportOffer>) -> Result<MuxEchoServer, TightBeamError> {
	let materials = ServerMaterials::generate();
	let (listener, socket_addr) = bind_encrypted_listener(&materials).await?;

	let handle = server! {
		protocol TokioListener: listener,
		policies: { with_mux_offer: [ offer ] },
		handle: move |frame: Frame| async move { Ok(Some(frame)) }
	};

	let server = MuxEchoServer { materials, addr: TightBeamSocketAddr(socket_addr), _handle: handle };
	Ok(server)
}

/// Echo server whose FIRST request parks until `release` fires; `started`
/// fires when the request is being held.
struct GatedMuxServer {
	server: MuxEchoServer,
	started: Arc<Notify>,
	release: Arc<Notify>,
}

async fn start_gated_mux_echo_server(offer: Option<TransportOffer>) -> Result<GatedMuxServer, TightBeamError> {
	let materials = ServerMaterials::generate();
	let (listener, socket_addr) = bind_encrypted_listener(&materials).await?;

	let started = Arc::new(Notify::new());
	let release = Arc::new(Notify::new());
	let first = Arc::new(AtomicBool::new(true));

	let handler_started = Arc::clone(&started);
	let handler_release = Arc::clone(&release);
	let handle = server! {
		protocol TokioListener: listener,
		policies: { with_mux_offer: [ offer ] },
		handle: move |frame: Frame| {
			let started = Arc::clone(&handler_started);
			let release = Arc::clone(&handler_release);
			let first = Arc::clone(&first);
			async move {
				if first.swap(false, Ordering::SeqCst) {
					started.notify_one();
					release.notified().await;
				}
				Ok(Some(frame))
			}
		}
	};

	let server = MuxEchoServer { materials, addr: TightBeamSocketAddr(socket_addr), _handle: handle };
	Ok(GatedMuxServer { server, started, release })
}

fn mux_pool_with_idle_timeout(
	materials: &ServerMaterials,
	offer: Option<TransportOffer>,
	max_connections: usize,
	idle_timeout: Option<Duration>,
) -> Result<Arc<ConnectionPool<TokioListener>>, TightBeamError> {
	let trust_store = pinning_trust_store(&materials.certificate)?;
	let config = PoolConfig { idle_timeout, max_connections, mux_offer: offer };
	let pool = Arc::new(
		ConnectionPool::<TokioListener>::builder()
			.with_config(config)
			.with_trust_store(trust_store)
			.build(),
	);

	Ok(pool)
}

fn mux_pool(
	materials: &ServerMaterials,
	offer: Option<TransportOffer>,
	max_connections: usize,
) -> Result<Arc<ConnectionPool<TokioListener>>, TightBeamError> {
	mux_pool_with_idle_timeout(materials, offer, max_connections, None)
}

/// Two leases against a pool capped at ONE connection: emits succeed
/// concurrently only if both leases share the same multiplexed connection.
#[tokio::test]
async fn pooled_mux_shares_one_connection_across_leases() -> Result<(), TightBeamError> {
	let server = start_mux_echo_server(Some(TransportOffer::mux(8))).await?;
	let pool = mux_pool(&server.materials, Some(TransportOffer::mux(8)), 1)?;

	let mut lease_one = pool.connect(server.addr).await?;
	let mut lease_two = pool.connect(server.addr).await?;

	let frame_one = create_v0_tightbeam(Some("mux-share-1"), None);
	let frame_two = create_v0_tightbeam(Some("mux-share-2"), None);
	let (reply_one, reply_two) =
		tokio::join!(lease_one.emit(frame_one.clone(), None), lease_two.emit(frame_two.clone(), None),);

	assert_eq!(
		reply_one?,
		Some(frame_one),
		"first lease must round-trip on the shared connection"
	);
	assert_eq!(
		reply_two?,
		Some(frame_two),
		"second lease must round-trip on the shared connection"
	);
	Ok(())
}

/// A multiplexed lease has no exclusive connection to hand out.
#[tokio::test]
async fn mux_lease_conn_reports_invalid_state() -> Result<(), TightBeamError> {
	let server = start_mux_echo_server(Some(TransportOffer::mux(8))).await?;
	let pool = mux_pool(&server.materials, Some(TransportOffer::mux(8)), 1)?;

	let mut lease = pool.connect(server.addr).await?;
	let conn = lease.conn();

	assert!(
		matches!(conn, Err(TransportError::InvalidState)),
		"conn() on a multiplexed lease must report InvalidState"
	);
	Ok(())
}

/// Server cap 1 with pool headroom: the second concurrent emit exhausts the
/// stream cap and must fail over to a fresh connection.
#[tokio::test]
async fn pooled_mux_failover_opens_additional_connection() -> Result<(), TightBeamError> {
	let gated = start_gated_mux_echo_server(Some(TransportOffer::mux(1))).await?;
	let pool = mux_pool(&gated.server.materials, Some(TransportOffer::mux(4)), 2)?;

	let mut held_lease = pool.connect(gated.server.addr).await?;
	let mut second_lease = pool.connect(gated.server.addr).await?;

	let frame_held = create_v0_tightbeam(Some("mux-held"), None);
	let held_task = tokio::spawn(async move { held_lease.emit(frame_held, None).await });

	gated.started.notified().await;

	let frame_second = create_v0_tightbeam(Some("mux-second"), None);
	let reply_second = second_lease.emit(frame_second.clone(), None).await?;
	assert_eq!(
		reply_second,
		Some(frame_second),
		"cap-exhausted emit must fail over to an additional connection"
	);

	gated.release.notify_one();
	let held_reply = held_task.await.map_err(|_| TightBeamError::MissingResponse)??;
	assert!(held_reply.is_some(), "held emit must complete after release");
	Ok(())
}

/// Server cap 1 with NO pool headroom: the second concurrent emit cannot
/// fail over and must surface the pool's `Busy`.
#[tokio::test]
async fn pooled_mux_without_headroom_reports_busy() -> Result<(), TightBeamError> {
	let gated = start_gated_mux_echo_server(Some(TransportOffer::mux(1))).await?;
	let pool = mux_pool(&gated.server.materials, Some(TransportOffer::mux(4)), 1)?;

	let mut held_lease = pool.connect(gated.server.addr).await?;
	let mut second_lease = pool.connect(gated.server.addr).await?;

	let frame_held = create_v0_tightbeam(Some("mux-held"), None);
	let held_task = tokio::spawn(async move { held_lease.emit(frame_held, None).await });

	gated.started.notified().await;

	let refused = second_lease.emit(create_v0_tightbeam(Some("mux-refused"), None), None).await;
	assert!(
		matches!(refused, Err(TransportError::OperationFailed(TransportFailure::Busy))),
		"emit without failover headroom must surface the pool's Busy"
	);

	gated.release.notify_one();
	let held_reply = held_task.await.map_err(|_| TightBeamError::MissingResponse)??;
	assert!(held_reply.is_some(), "held emit must complete after release");
	Ok(())
}

/// A peer that never offers multiplexing declines the pool's offer: the
/// lease is exclusive and round-trips single-flight.
#[tokio::test]
async fn pooled_mux_declined_falls_back_to_exclusive_lease() -> Result<(), TightBeamError> {
	let server = start_mux_echo_server(None).await?;
	let pool = mux_pool(&server.materials, Some(TransportOffer::mux(8)), 1)?;

	let mut lease = pool.connect(server.addr).await?;
	assert!(lease.conn().is_ok(), "declined mux must yield an exclusive lease");

	let frame = create_v0_tightbeam(Some("mux-declined"), None);
	let reply = lease.emit(frame.clone(), None).await?;
	assert_eq!(reply, Some(frame), "exclusive fallback lease must round-trip");
	Ok(())
}

/// After a declined offer, the returned exclusive connection is idle in the
/// pool: the next connect must reuse it instead of dialing (at cap 1, a
/// dial would report `Busy`).
#[tokio::test]
async fn pooled_mux_declined_reuses_idle_exclusive_lease() -> Result<(), TightBeamError> {
	let server = start_mux_echo_server(None).await?;
	let pool = mux_pool(&server.materials, Some(TransportOffer::mux(8)), 1)?;

	let first_lease = pool.connect(server.addr).await?;
	drop(first_lease);

	let mut reused_lease = pool.connect(server.addr).await?;
	assert!(reused_lease.conn().is_ok(), "reused lease must be exclusive");

	let frame = create_v0_tightbeam(Some("mux-idle-reuse"), None);
	let reply = reused_lease.emit(frame.clone(), None).await?;
	assert_eq!(reply, Some(frame), "idle exclusive connection must be reused and round-trip");
	Ok(())
}

/// Per-connection driver and responder tasks of a [`ManualMuxServer`].
type ConnectionTasks = Arc<Mutex<Vec<JoinHandle<Result<(), TransportError>>>>>;

/// Mux echo server assembled from the public `MuxAcceptor` and
/// `MuxTransport` building blocks. Per-connection tasks are collected so
/// the test can tear live connections down.
struct ManualMuxServer {
	materials: ServerMaterials,
	addr: TightBeamSocketAddr,
	connection_tasks: ConnectionTasks,
	_acceptor: JoinHandle<()>,
}

impl ManualMuxServer {
	/// Abort every live connection task and await termination so the split
	/// halves are dropped (connection closed) before returning.
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

/// Negotiate one accepted connection and run its mux plane, registering
/// every spawned task for later teardown. Aborting all of them drops the
/// split halves, which closes the TCP connection.
async fn serve_manual_mux_connection(
	transport: TcpTransport<TokioStream>,
	tasks: ConnectionTasks,
) -> Result<(), TransportError> {
	let offer = TransportOffer::mux(4);
	let mut transport = transport.with_mux_offer(Some(offer));
	let negotiated = transport.negotiate_mux().await?;
	let settings = negotiated.ok_or(TransportError::InvalidState)?;

	let (reader, writer) = transport.into_split()?;
	let mux = MuxTransport::new(reader, writer, MuxRole::Server, settings);
	let (_handle, reader_driver, writer_driver, responder) = mux.into_parts();

	let echo = |frame: Arc<Frame>| {
		let response = ResponsePackage::new(TransitStatus::Accepted, Some(Frame::clone(&frame)));
		core::future::ready(response)
	};
	let spawned = vec![
		tokio::spawn(reader_driver.drive()),
		tokio::spawn(writer_driver.drive()),
		tokio::spawn(responder.serve(echo)),
	];
	if let Ok(mut registry) = tasks.lock() {
		registry.extend(spawned);
	}
	Ok(())
}

async fn start_manual_mux_echo_server() -> Result<ManualMuxServer, TightBeamError> {
	let materials = ServerMaterials::generate();
	let (listener, socket_addr) = bind_encrypted_listener(&materials).await?;

	let connection_tasks: ConnectionTasks = Arc::default();
	let acceptor_tasks = Arc::clone(&connection_tasks);
	let acceptor = tokio::spawn(async move {
		while let Ok((transport, _)) = listener.accept().await {
			let tasks = Arc::clone(&acceptor_tasks);
			tokio::spawn(serve_manual_mux_connection(transport, tasks));
		}
	});

	let server = ManualMuxServer {
		materials,
		addr: TightBeamSocketAddr(socket_addr),
		connection_tasks,
		_acceptor: acceptor,
	};
	Ok(server)
}

/// Tearing down the peer's serve task kills the connection: the lease's
/// emit fails, the entry is evicted, and the next connect re-establishes.
#[tokio::test]
async fn pooled_mux_evicts_dead_connection_and_reconnects() -> Result<(), TightBeamError> {
	let server = start_manual_mux_echo_server().await?;
	let pool = mux_pool(&server.materials, Some(TransportOffer::mux(4)), 4)?;

	let mut lease = pool.connect(server.addr).await?;
	let frame_before = create_v0_tightbeam(Some("mux-before"), None);
	let reply_before = lease.emit(frame_before.clone(), None).await?;
	assert_eq!(reply_before, Some(frame_before), "emit must round-trip before teardown");

	server.abort_connections().await;

	let dead = lease.emit(create_v0_tightbeam(Some("mux-during"), None), None).await;
	assert!(dead.is_err(), "emit on a torn-down connection must fail");

	let mut fresh = pool.connect(server.addr).await?;
	let frame_after = create_v0_tightbeam(Some("mux-after"), None);
	let reply_after = fresh.emit(frame_after.clone(), None).await?;
	assert_eq!(
		reply_after,
		Some(frame_after),
		"pool must evict the dead connection and re-establish"
	);
	Ok(())
}

/// An idle multiplexed connection is pruned after `idle_timeout`: the
/// pruned entry releases its pool slot (a cap-1 redial would otherwise
/// report `Busy`) and the next connect dials a fresh connection. The
/// manual server registers three tasks per connection, so a second
/// accepted connection doubles the registry.
#[tokio::test]
async fn pooled_mux_prunes_idle_connection() -> Result<(), TightBeamError> {
	let server = start_manual_mux_echo_server().await?;
	let idle_timeout = Duration::from_millis(50);
	let pool = mux_pool_with_idle_timeout(&server.materials, Some(TransportOffer::mux(4)), 1, Some(idle_timeout))?;

	let mut lease = pool.connect(server.addr).await?;
	let frame_before = create_v0_tightbeam(Some("mux-idle-before"), None);
	let reply_before = lease.emit(frame_before.clone(), None).await?;
	assert_eq!(reply_before, Some(frame_before), "emit must round-trip before idling out");
	drop(lease);

	sleep(idle_timeout * 2).await;

	let mut fresh = pool.connect(server.addr).await?;
	let frame_after = create_v0_tightbeam(Some("mux-idle-after"), None);
	let reply_after = fresh.emit(frame_after.clone(), None).await?;
	assert_eq!(
		reply_after,
		Some(frame_after),
		"connect after the idle timeout must round-trip on a fresh connection"
	);

	let connection_tasks = match server.connection_tasks.lock() {
		Ok(tasks) => tasks.len(),
		Err(poisoned) => poisoned.into_inner().len(),
	};
	assert_eq!(connection_tasks, 6, "idle entry must be pruned and a fresh connection dialed");
	Ok(())
}

/// A client that never offers multiplexing is served single-flight by a
/// mux-offering `server!` endpoint.
#[tokio::test]
async fn single_flight_client_round_trips_on_mux_server() -> Result<(), TightBeamError> {
	let server = start_mux_echo_server(Some(TransportOffer::mux(8))).await?;

	let trust_store = pinning_trust_store(&server.materials.certificate)?;
	let mut client = ClientBuilder::<TokioListener>::builder()
		.with_trust_store(trust_store)
		.build()
		.connect(server.addr)
		.await?;

	let frame = create_v0_tightbeam(Some("single-flight"), None);
	let reply = client.emit(frame.clone(), None).await?;
	assert_eq!(
		reply,
		Some(frame),
		"single-flight client must round-trip on a mux-offering server"
	);
	Ok(())
}
