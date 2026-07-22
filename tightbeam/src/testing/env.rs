//! Environment parameter structs for `tb_scenario!` closures.
//!
//! Every scenario closure receives exactly one of these. The fields are
//! uniform across environments: `trace` is always a plain
//! [`TraceCollector`] share and `context` is always the scenario context
//! from the `context:` key (unit when omitted), shared as `Arc<C>`.
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
//! or destructure in the closure pattern for naked field names:
//!
//! ```ignore
//! client: |ClusterEnv { trace, context: certs, cluster }| async move { ... }
//! ```

use std::sync::Arc;

use crate::trace::TraceCollector;

/// Setup-phase closures: Bare `exec`, ServiceClient `server`, Cluster and
/// Hive `start`, Cluster `hives`, Servlet `start`, Worker `setup`.
pub struct SetupEnv<C = ()> {
	/// Trace handle recording into the scenario's collector.
	pub trace: TraceCollector,
	/// Scenario fixture from the `context:` key, shared as `Arc<C>`.
	pub context: Arc<C>,
}

/// ServiceClient `client` and Servlet `setup` closures. Carries `trace`,
/// shared `context`, and bound `addr` as separate fields. The closure
/// builds its own connection (pool, trusted client, raw transport).
pub struct ClientEnv<C, A> {
	/// Trace handle recording into the scenario's collector.
	pub trace: TraceCollector,
	/// Scenario fixture from the `context:` key, shared as `Arc<C>`.
	pub context: Arc<C>,
	/// Bound server address reported by the server closure.
	pub addr: A,
}

/// Cluster `client` closure: owns the cluster instance so registry
/// assertions and the consuming `stop` are available.
pub struct ClusterEnv<C, G> {
	/// Trace handle recording into the scenario's collector.
	pub trace: TraceCollector,
	/// Scenario fixture from the `context:` key, shared as `Arc<C>`.
	pub context: Arc<C>,
	/// Started cluster instance, owned by the closure.
	pub cluster: G,
}

/// Hive `client` closure: owns the established hive instance.
pub struct HiveEnv<C, H> {
	/// Trace handle recording into the scenario's collector.
	pub trace: TraceCollector,
	/// Scenario fixture from the `context:` key, shared as `Arc<C>`.
	pub context: Arc<C>,
	/// Established hive instance, owned by the closure.
	pub hive: H,
}

/// Servlet `client` closure: connected client from the default connect
/// or the scenario's `setup:` closure.
pub struct ServletEnv<C, T> {
	/// Trace handle recording into the scenario's collector.
	pub trace: TraceCollector,
	/// Scenario fixture from the `context:` key, shared as `Arc<C>`.
	pub context: Arc<C>,
	/// Connected client for the servlet under test.
	pub client: T,
}

/// Worker `stimulus` closure: owns the worker built by `setup`.
pub struct WorkerEnv<C, W> {
	/// Trace handle recording into the scenario's collector.
	pub trace: TraceCollector,
	/// Scenario fixture from the `context:` key, shared as `Arc<C>`.
	pub context: Arc<C>,
	/// Worker instance built by `setup`, owned by the closure.
	pub worker: W,
}
