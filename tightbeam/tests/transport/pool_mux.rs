//! Pooled multiplexing integration tests.
//!
//! `tb_scenario!` ServiceClient scenarios drive `ConnectionPool`s with a
//! `mux_offer` against `server!` endpoints over real TCP with ECIES
//! handshakes. Each scenario's assert spec pins its behaviors:
//!
//! - Leases share one multiplexed connection per destination
//! - `conn()` on a multiplexed lease reports `InvalidState`
//! - Stream-cap exhaustion fails over to an additional connection
//! - Failover at the pool cap reuses pooled stream headroom over dialing
//! - Pool-capacity exhaustion surfaces `Busy` instead of failing over
//! - A peer that declines multiplexing yields an exclusive lease
//! - A declined offer leaves an idle exclusive connection for reuse
//! - A dead multiplexed connection is evicted and re-established
//! - An idle multiplexed connection is pruned after the idle timeout
//! - Single-flight clients round-trip against a mux-offering server
//! - The collector gate applies on the mux path without invoking the handler

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

use tightbeam::exactly;
use tightbeam::policy::{GatePolicy, TransitStatus};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::server;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{create_v0_tightbeam, ClientEnv, SetupEnv};
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::multiplex::{MuxAcceptor, MuxRole, MuxTransport};
use tightbeam::transport::policy::PolicyConf;
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{
	ClientBuilder, ConnectionBuilder, ConnectionPool, PoolConfig, PooledClient, ResponsePackage, TransportError,
	TransportFailure,
};
use tightbeam::{Frame, TightBeamError};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::common::security::{pinning_trust_store, ServerMaterials};
use crate::transport::support::{await_ok, bind_encrypted_listener};

type EmitTask = JoinHandle<Result<Option<Frame>, TransportError>>;

fn mux_frame(label: &str) -> Frame {
	create_v0_tightbeam(Some(label), None)
}

/// Mux offer with `cap` concurrent streams, in the `Option` shape the
/// pool and `server!` policies take.
fn mux_offer(cap: u32) -> Option<TransportOffer> {
	Some(TransportOffer::mux(cap))
}

/// Encrypted listener plus its address in the pool's protocol type.
async fn bind_pool_listener(
	materials: &ServerMaterials,
) -> Result<(TokioListener, TightBeamSocketAddr), TightBeamError> {
	let (listener, addr) = bind_encrypted_listener(materials).await?;
	Ok((listener, TightBeamSocketAddr(addr)))
}

/// `server!` accept loop echoing every frame, with an optional mux offer.
async fn start_echo_server(
	materials: &ServerMaterials,
	offer: Option<TransportOffer>,
) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError> {
	let (listener, addr) = bind_pool_listener(materials).await?;
	let handle = server! {
		protocol TokioListener: listener,
		policies: { with_mux_offer: [ offer ] },
		handle: move |frame: Frame| async move { Ok(Some(frame)) }
	};

	Ok((handle, addr))
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

/// Round-trip one labeled frame on the lease. Returns true when echoed intact.
async fn echo_roundtrip(client: &mut PooledClient<TokioListener>, label: &str) -> Result<bool, TightBeamError> {
	let frame = mux_frame(label);
	let reply = client.emit(frame.clone(), None).await?;
	Ok(reply == Some(frame))
}

// Leases share one multiplexed connection

tb_assert_spec! {
	pub MuxLeaseShareSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			(first_lease_echoes, exactly!(1), equals!(true)),
			(second_lease_echoes, exactly!(1), equals!(true))
		]
	}
}

// Two leases against a pool capped at ONE connection: emits succeed
// concurrently only if both leases share the same multiplexed connection.
tb_scenario! {
	name: pooled_mux_shares_one_connection_across_leases,
	spec: MuxLeaseShareSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_echo_server(&env.context, mux_offer(8)).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, mux_offer(8), 1)?;

			let mut lease_one = pool.connect(addr).await?;
			let mut lease_two = pool.connect(addr).await?;

			let frame_one = mux_frame("mux-share-1");
			let frame_two = mux_frame("mux-share-2");
			let (reply_one, reply_two) =
				tokio::join!(lease_one.emit(frame_one.clone(), None), lease_two.emit(frame_two.clone(), None),);

			trace.event_with(MuxLeaseShareSpec::first_lease_echoes, &[], reply_one? == Some(frame_one))?;
			trace.event_with(MuxLeaseShareSpec::second_lease_echoes, &[], reply_two? == Some(frame_two))?;
			Ok(())
		}
	}
}

// A mux lease refuses the exclusive accessor

tb_assert_spec! {
	pub MuxLeaseConnSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			(conn_reports_invalid_state, exactly!(1), equals!(true))
		]
	}
}

// A multiplexed lease has no exclusive connection to hand out.
tb_scenario! {
	name: mux_lease_conn_reports_invalid_state,
	spec: MuxLeaseConnSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_echo_server(&env.context, mux_offer(8)).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, mux_offer(8), 1)?;

			let mut lease = pool.connect(addr).await?;
			let conn = lease.conn();

			trace.event_with(
				MuxLeaseConnSpec::conn_reports_invalid_state,
				&[],
				matches!(conn, Err(TransportError::InvalidState)),
			)?;
			Ok(())
		}
	}
}

// Gated echo server - fixtures for the failover scenarios

/// Gated-scenario fixture. The server's first request parks until
/// `release` fires. `started` fires while the request is held.
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

/// `server!` echo endpoint parking its first request on the context gates.
async fn start_gated_echo_server(
	ctx: &Arc<GatedContext>,
	offer: Option<TransportOffer>,
) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError> {
	let (listener, addr) = bind_pool_listener(&ctx.materials).await?;
	let first = Arc::new(AtomicBool::new(true));
	let handler_ctx = Arc::clone(ctx);
	let handle = server! {
		protocol TokioListener: listener,
		policies: { with_mux_offer: [ offer ] },
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

/// Emit on the lease in a task the gated server will hold, and wait until
/// the handler reports it is being held.
async fn spawn_held_emit(ctx: &GatedContext, mut lease: PooledClient<TokioListener>) -> EmitTask {
	let held_task = tokio::spawn(async move { lease.emit(mux_frame("mux-held"), None).await });
	ctx.started.notified().await;
	held_task
}

/// Release the gated handler and confirm the held emit completes.
async fn release_held_emit(ctx: &GatedContext, held_task: EmitTask) -> Result<bool, TightBeamError> {
	ctx.release.notify_one();
	let held_reply = await_ok(held_task, "held emit task must not panic").await?;
	Ok(held_reply.is_some())
}

// Cap exhaustion fails over to an additional connection

tb_assert_spec! {
	pub MuxFailoverDialSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			(overflow_emit_echoes_on_second_connection, exactly!(1), equals!(true)),
			(held_emit_completes_after_release, exactly!(1), equals!(true))
		]
	}
}

// Server cap 1 with pool headroom: the second concurrent emit exhausts the
// stream cap and must fail over to a fresh connection.
tb_scenario! {
	name: pooled_mux_failover_opens_additional_connection,
	spec: MuxFailoverDialSpec,
	environment ServiceClient {
		context: GatedContext::generate(),
		server: |env| async move { start_gated_echo_server(&env.context, mux_offer(1)).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = mux_pool(&ctx.materials, mux_offer(4), 2)?;

			let held_lease = pool.connect(addr).await?;
			let mut second_lease = pool.connect(addr).await?;
			let held_task = spawn_held_emit(&ctx, held_lease).await;

			let failed_over = echo_roundtrip(&mut second_lease, "mux-second").await?;
			trace.event_with(MuxFailoverDialSpec::overflow_emit_echoes_on_second_connection, &[], failed_over)?;

			let held_completed = release_held_emit(&ctx, held_task).await?;
			trace.event_with(MuxFailoverDialSpec::held_emit_completes_after_release, &[], held_completed)?;
			Ok(())
		}
	}
}

// Failover at the pool cap reuses pooled stream headroom

tb_assert_spec! {
	pub MuxFailoverReuseSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			(first_failover_echoes_on_new_dial, exactly!(1), equals!(true)),
			(capped_failover_reuses_pooled_headroom, exactly!(1), equals!(true)),
			(held_emit_completes_after_release, exactly!(1), equals!(true))
		]
	}
}

// With the pool at `max_connections`, cap-exhaustion failover must move
// onto the pooled connection with stream headroom instead of dialing
// (a dial would report `Busy`).
tb_scenario! {
	name: pooled_mux_failover_reuses_pooled_headroom,
	spec: MuxFailoverReuseSpec,
	environment ServiceClient {
		context: GatedContext::generate(),
		server: |env| async move { start_gated_echo_server(&env.context, mux_offer(1)).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = mux_pool(&ctx.materials, mux_offer(4), 2)?;

			// All three leases share connection one (the only entry so far).
			let held_lease = pool.connect(addr).await?;
			let mut fill_lease = pool.connect(addr).await?;
			let mut reuse_lease = pool.connect(addr).await?;
			let held_task = spawn_held_emit(&ctx, held_lease).await;

			// Connection one is saturated: this failover dials connection
			// two, filling the pool.
			let filled = echo_roundtrip(&mut fill_lease, "mux-fill").await?;
			trace.event_with(MuxFailoverReuseSpec::first_failover_echoes_on_new_dial, &[], filled)?;

			let reused = echo_roundtrip(&mut reuse_lease, "mux-reuse").await?;
			trace.event_with(MuxFailoverReuseSpec::capped_failover_reuses_pooled_headroom, &[], reused)?;

			let held_completed = release_held_emit(&ctx, held_task).await?;
			trace.event_with(MuxFailoverReuseSpec::held_emit_completes_after_release, &[], held_completed)?;
			Ok(())
		}
	}
}

// Pool-capacity exhaustion surfaces Busy

tb_assert_spec! {
	pub MuxNoHeadroomSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			(refused_emit_surfaces_busy, exactly!(1), equals!(true)),
			(held_emit_completes_after_release, exactly!(1), equals!(true))
		]
	}
}

// Server cap 1 with NO pool headroom: the second concurrent emit cannot
// fail over and must surface the pool's `Busy`.
tb_scenario! {
	name: pooled_mux_without_headroom_reports_busy,
	spec: MuxNoHeadroomSpec,
	environment ServiceClient {
		context: GatedContext::generate(),
		server: |env| async move { start_gated_echo_server(&env.context, mux_offer(1)).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = mux_pool(&ctx.materials, mux_offer(4), 1)?;

			let held_lease = pool.connect(addr).await?;
			let mut second_lease = pool.connect(addr).await?;
			let held_task = spawn_held_emit(&ctx, held_lease).await;

			let refused = second_lease.emit(mux_frame("mux-refused"), None).await;
			trace.event_with(
				MuxNoHeadroomSpec::refused_emit_surfaces_busy,
				&[],
				matches!(refused, Err(TransportError::OperationFailed(TransportFailure::Busy))),
			)?;

			let held_completed = release_held_emit(&ctx, held_task).await?;
			trace.event_with(MuxNoHeadroomSpec::held_emit_completes_after_release, &[], held_completed)?;
			Ok(())
		}
	}
}

// Declined mux offer falls back to an exclusive lease

tb_assert_spec! {
	pub MuxDeclinedFallbackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			(declined_lease_is_exclusive, exactly!(1), equals!(true)),
			(exclusive_lease_echoes, exactly!(1), equals!(true))
		]
	}
}

// A peer that never offers multiplexing declines the pool's offer: the
// lease is exclusive and round-trips single-flight.
tb_scenario! {
	name: pooled_mux_declined_falls_back_to_exclusive_lease,
	spec: MuxDeclinedFallbackSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_echo_server(&env.context, None).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, mux_offer(8), 1)?;

			let mut lease = pool.connect(addr).await?;
			trace.event_with(MuxDeclinedFallbackSpec::declined_lease_is_exclusive, &[], lease.conn().is_ok())?;

			let echoed = echo_roundtrip(&mut lease, "mux-declined").await?;
			trace.event_with(MuxDeclinedFallbackSpec::exclusive_lease_echoes, &[], echoed)?;
			Ok(())
		}
	}
}

// Declined mux offer leaves an idle exclusive connection for reuse

tb_assert_spec! {
	pub MuxDeclinedIdleReuseSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			(reused_lease_is_exclusive, exactly!(1), equals!(true)),
			(reused_lease_echoes, exactly!(1), equals!(true))
		]
	}
}

// After a declined offer, the returned exclusive connection is idle in the
// pool: the next connect must reuse it instead of dialing (at cap 1, a
// dial would report `Busy`).
tb_scenario! {
	name: pooled_mux_declined_reuses_idle_exclusive_lease,
	spec: MuxDeclinedIdleReuseSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_echo_server(&env.context, None).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, mux_offer(8), 1)?;

			let first_lease = pool.connect(addr).await?;
			drop(first_lease);

			let mut reused_lease = pool.connect(addr).await?;
			trace.event_with(MuxDeclinedIdleReuseSpec::reused_lease_is_exclusive, &[], reused_lease.conn().is_ok())?;

			let echoed = echo_roundtrip(&mut reused_lease, "mux-idle-reuse").await?;
			trace.event_with(MuxDeclinedIdleReuseSpec::reused_lease_echoes, &[], echoed)?;
			Ok(())
		}
	}
}

// Manual mux server - fixtures for teardown scenarios

/// Teardown-scenario fixture. Assembles a mux echo server from public
/// `MuxAcceptor` and `MuxTransport` building blocks. Per-connection tasks
/// are collected so the client can tear live connections down.
struct ManualContext {
	/// Server materials shared with the client.
	materials: ServerMaterials,
	/// Tasks spawned per connection for later teardown.
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
	ctx: Arc<ManualContext>,
) -> Result<(), TransportError> {
	let mut transport = transport.with_mux_offer(mux_offer(4));
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
	ctx.register_tasks(spawned);
	Ok(())
}

/// Accept loop serving manual mux connections into the context registry.
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

// Dead connection is evicted and re-established

tb_assert_spec! {
	pub MuxEvictionSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			(emit_echoes_before_teardown, exactly!(1), equals!(true)),
			(emit_fails_on_dead_connection, exactly!(1), equals!(true)),
			(fresh_connect_echoes_after_eviction, exactly!(1), equals!(true))
		]
	}
}

// Tearing down the peer's serve task kills the connection: the lease's
// emit fails, the entry is evicted, and the next connect re-establishes.
tb_scenario! {
	name: pooled_mux_evicts_dead_connection_and_reconnects,
	spec: MuxEvictionSpec,
	environment ServiceClient {
		context: ManualContext::generate(),
		server: |env| async move { start_manual_mux_echo_server(&env.context).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = mux_pool(&ctx.materials, mux_offer(4), 4)?;

			let mut lease = pool.connect(addr).await?;
			let echoed_before = echo_roundtrip(&mut lease, "mux-before").await?;
			trace.event_with(MuxEvictionSpec::emit_echoes_before_teardown, &[], echoed_before)?;

			ctx.abort_connections().await;

			let dead = lease.emit(mux_frame("mux-during"), None).await;
			trace.event_with(MuxEvictionSpec::emit_fails_on_dead_connection, &[], dead.is_err())?;

			let mut fresh = pool.connect(addr).await?;
			let echoed_after = echo_roundtrip(&mut fresh, "mux-after").await?;
			trace.event_with(MuxEvictionSpec::fresh_connect_echoes_after_eviction, &[], echoed_after)?;
			Ok(())
		}
	}
}

// Idle connection is pruned after the idle timeout

tb_assert_spec! {
	pub MuxIdlePruneSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			(emit_echoes_before_idle, exactly!(1), equals!(true)),
			(fresh_connect_echoes_after_prune, exactly!(1), equals!(true)),
			(second_connection_dialed, exactly!(1), equals!(true))
		]
	}
}

// An idle multiplexed connection is pruned after `idle_timeout`: the
// pruned entry releases its pool slot (a cap-1 redial would otherwise
// report `Busy`) and the next connect dials a fresh connection. The
// manual server registers three tasks per connection, so a second
// accepted connection doubles the registry.
tb_scenario! {
	name: pooled_mux_prunes_idle_connection,
	spec: MuxIdlePruneSpec,
	environment ServiceClient {
		context: ManualContext::generate(),
		server: |env| async move { start_manual_mux_echo_server(&env.context).await },
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let idle_timeout = Duration::from_millis(50);
			let pool = mux_pool_with_idle_timeout(&ctx.materials, mux_offer(4), 1, Some(idle_timeout))?;

			let mut lease = pool.connect(addr).await?;
			let echoed_before = echo_roundtrip(&mut lease, "mux-idle-before").await?;
			trace.event_with(MuxIdlePruneSpec::emit_echoes_before_idle, &[], echoed_before)?;
			drop(lease);

			sleep(idle_timeout * 2).await;

			let mut fresh = pool.connect(addr).await?;
			let echoed_after = echo_roundtrip(&mut fresh, "mux-idle-after").await?;
			trace.event_with(MuxIdlePruneSpec::fresh_connect_echoes_after_prune, &[], echoed_after)?;

			trace.event_with(MuxIdlePruneSpec::second_connection_dialed, &[], ctx.connection_task_count() == 6)?;
			Ok(())
		}
	}
}

// Single-flight client on a mux-offering server

tb_assert_spec! {
	pub MuxServesSingleFlightSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			(single_flight_echo_on_mux_server, exactly!(1), equals!(true))
		]
	}
}

// A client that never offers multiplexing is served single-flight by a
// mux-offering `server!` endpoint.
tb_scenario! {
	name: single_flight_client_round_trips_on_mux_server,
	spec: MuxServesSingleFlightSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move { start_echo_server(&env.context, mux_offer(8)).await },
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let trust_store = pinning_trust_store(&materials.certificate)?;
			let mut client = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(trust_store)
				.build()
				.connect(addr)
				.await?;

			let frame = mux_frame("single-flight");
			let reply = client.emit(frame.clone(), None).await?;
			trace.event_with(MuxServesSingleFlightSpec::single_flight_echo_on_mux_server, &[], reply == Some(frame))?;
			Ok(())
		}
	}
}

// Collector gate applies on the mux path

/// Gate-scenario fixture. The client checks `handler_invoked` after its
/// gated emit.
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
	fn evaluate(&self, _message: &Frame) -> TransitStatus {
		TransitStatus::Forbidden
	}
}

tb_assert_spec! {
	pub MuxGateSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			(gate_status_surfaces_to_client, exactly!(1), equals!(true)),
			(handler_never_invoked, exactly!(1), equals!(true))
		]
	}
}

// Collector gate rejecting on the mux path: the caller observes the
// gate's status and the handler never runs.
tb_scenario! {
	name: mux_serve_gate_rejects_without_handler,
	spec: MuxGateSpec,
	environment ServiceClient {
		context: GateContext::generate(),
		server: |SetupEnv { context: ctx, .. }| async move {
			let (listener, addr) = bind_pool_listener(&ctx.materials).await?;
			let handler_ctx = Arc::clone(&ctx);
			let handle = server! {
				protocol TokioListener: listener,
				policies: {
					with_mux_offer: [ mux_offer(8) ],
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
			let pool = mux_pool(&ctx.materials, mux_offer(8), 1)?;
			let mut client = pool.connect(addr).await?;

			let outcome = client.emit(mux_frame("gated"), None).await;
			trace.event_with(
				MuxGateSpec::gate_status_surfaces_to_client,
				&[],
				matches!(outcome, Err(TransportError::OperationFailed(TransportFailure::Forbidden))),
			)?;

			trace.event_with(MuxGateSpec::handler_never_invoked, &[], !ctx.handler_invoked.load(Ordering::SeqCst))?;
			Ok(())
		}
	}
}
