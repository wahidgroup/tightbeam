//! Environment parameter structs for `tb_scenario!` closures.
//!
//! Every scenario closure receives exactly one of these. The fields are
//! uniform across environments: `trace` is a [`TraceCollector`] share, or a
//! `FuzzTraceCollector` share in a scenario that names `fuzz: afl`, and
//! `context` is always the scenario context from the `context:` key (unit
//! when omitted), shared as `Arc<C>`.
//!
//! Use the conventional parameter name `env`:
//!
//! ```ignore
//! client: |env| async move {
//!     let mut client = connect_cluster(&env.context, env.cluster.addr()).await?;
//!     env.trace.event(MySpec::routing_accepted)?;
//!     env.cluster.stop();
//!     Ok(())
//! }
//! ```
//!
//! Or destructure the struct in the closure pattern to name the fields:
//!
//! ```ignore
//! client: |ClusterEnv { trace, context: certs, cluster }| async move { ... }
//! ```

use std::sync::Arc;

use crate::trace::TraceCollector;

/// The parameter of the setup-phase closures: Bare `exec`, ServiceClient
/// `server`, Cluster and Hive `start`, Cluster `hives`, Servlet `start`, and
/// Worker `setup`.
pub struct SetupEnv<C = (), T = TraceCollector> {
	/// The trace handle that records into the scenario's collector.
	pub trace: T,
	/// Scenario fixture from the `context:` key, shared as `Arc<C>`.
	pub context: Arc<C>,
}

/// The parameter of the ServiceClient `client` and Servlet `setup` closures.
/// It carries `trace`, the shared `context`, and the bound `addr` as separate
/// fields, and the closure builds its own connection (pool, trusted client,
/// or raw transport).
pub struct ClientEnv<C, A, T = TraceCollector> {
	/// The trace handle that records into the scenario's collector.
	pub trace: T,
	/// Scenario fixture from the `context:` key, shared as `Arc<C>`.
	pub context: Arc<C>,
	/// The bound server address, from the ServiceClient `server` closure or
	/// from the servlet that the Servlet `start` closure returned.
	pub addr: A,
}

/// The parameter of the Cluster `client` closure, which owns the value that
/// `start` returned.
///
/// `G` is usually one gateway. A multi-org harness may return a larger
/// topology (seed plus peers) as `G`, and the client then owns one consuming
/// teardown for that value.
pub struct ClusterEnv<C, G, T = TraceCollector> {
	/// The trace handle that records into the scenario's collector.
	pub trace: T,
	/// Scenario fixture from the `context:` key, shared as `Arc<C>`.
	pub context: Arc<C>,
	/// The value that `start` returned, which the closure owns for registry
	/// checks and the consuming `stop`.
	pub cluster: G,
}

/// The parameter of the Hive `client` closure, which owns the established
/// hive instance.
pub struct HiveEnv<C, H, T = TraceCollector> {
	/// The trace handle that records into the scenario's collector.
	pub trace: T,
	/// Scenario fixture from the `context:` key, shared as `Arc<C>`.
	pub context: Arc<C>,
	/// The established hive instance, which the closure owns.
	pub hive: H,
}

/// The parameter of the Servlet `client` closure, with the client that the
/// default connect or the scenario's `setup:` closure connected.
pub struct ServletEnv<C, K, T = TraceCollector> {
	/// The trace handle that records into the scenario's collector.
	pub trace: T,
	/// Scenario fixture from the `context:` key, shared as `Arc<C>`.
	pub context: Arc<C>,
	/// The connected client of the servlet under test.
	pub client: K,
}

/// The parameter of the Worker `stimulus` closure, which owns the worker
/// started from the builder that `setup` returned.
pub struct WorkerEnv<C, W> {
	/// The trace handle that records into the scenario's collector.
	pub trace: TraceCollector,
	/// Scenario fixture from the `context:` key, shared as `Arc<C>`.
	pub context: Arc<C>,
	/// The worker started from the builder of `setup`, which the closure owns.
	pub worker: W,
}
