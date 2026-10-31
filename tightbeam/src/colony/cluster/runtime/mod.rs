//! The runtime of the cluster gateway: its accept loop, its background tasks,
//! and its mux routing.
//!
//! [`ClusterGateway`] owns the listener, heartbeat, evaporation, and advertise
//! tasks. [`GatewayMuxService`] serves each inbound connection: it routes
//! unary control frames to dispatch and splices streamed or duplex opens by
//! servlet target.
//!
//! Each surface a request reaches has its own sibling module: dispatch,
//! registration, work, streaming, gossip, and heartbeat.

mod advertise;
mod bounds;
mod dispatch;
mod freshness;
mod gossip_handler;
mod gossip_tasks;
mod heartbeat;
mod hop;
mod refuse;
mod registration;
mod streaming;
mod verify;
mod work;

pub(crate) use bounds::{ColonyConfig, ColonyDialProtocol};
pub use freshness::FreshnessWindow;
pub(crate) use verify::{VerifiedControlFrame, VerifiedSignerId};

#[cfg(test)]
pub(crate) use bounds::ColonyDigest;

use core::future::Future;
use std::sync::{Arc, Mutex};

use self::bounds::{GatewayAcceptProtocol, GatewayColonyProtocol, GatewayRuntimeCtx};
use self::freshness::GatewayReplayGuard;
use self::heartbeat::HiveBeat;
use self::hop::HivePlane;
use self::verify::RequestAudit;
use crate::clock::Clock;
use crate::colony::cluster::export::ExportScope;
use crate::colony::cluster::peer::WireHopBudget;
use crate::colony::cluster::{
	Cluster, ClusterConfig, ClusterError, ClusterHeartbeat, HeartbeatConfig, HiveRegistry, HopBudget, PeerRouteInfo,
	ServletRegistry, SharedId,
};
use crate::colony::protocol::HeartbeatResult;
use crate::constants::DEFAULT_MAX_SERVER_CONNECTIONS;
use crate::crypto::x509::CanonicalKey;
use crate::macros::server::{serve_connection_service, AcceptedConnection};
use crate::policy::{SessionContext, TransitStatus};
use crate::runtime::{rt, TaskGroup};
use crate::trace::{TraceCollector, TraceHandle};
use crate::transport::accept::{AcceptPlane, ConnectionTerms};
use crate::transport::multiplex::{CallContext, MuxCapable, MuxService, ReplySink, StreamBody};
use crate::transport::policy::PolicyConfig;
use crate::transport::{AsyncListenerTrait, Protocol};
use crate::urn::Urn;
use crate::Frame;
use crate::TightBeamError;

use crate::instrumentation::events::{
	CLUSTER_EDGE_REFUSED, CLUSTER_EXPORT_IDENTITY_UNAVAILABLE, CLUSTER_EXPORT_UNBOUNDED, CLUSTER_LOOP_POISONED,
};

/// Why one background loop of the gateway ended.
///
/// Every loop reads registries and tables and records to the trace, and
/// either can refuse. The two variants keep the refusals apart, so the exit
/// records a local fault by name and lets a trace fault end the loop silently,
/// which is the effect a `testing-fault` injection observes.
#[cfg_attr(test, derive(Debug))]
pub(crate) enum LoopFault {
	/// The trace refused an event, or a task the loop awaited did not join.
	Runtime(TightBeamError),
	/// A local fault: a registry, table, or journal this loop reads is
	/// poisoned or failed, or a local step of the loop failed, such as the
	/// build, the signature, or the send of a repair.
	Registry(ClusterError),
}

impl LoopFault {
	/// Splits this fault into the local fault that a request refuses, returned
	/// as `Ok`, and the runtime fault that ends the request.
	///
	/// A request that meets a local fault answers
	/// [`TransitStatus::Unavailable`], and a runtime fault passes up to the
	/// caller unchanged.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the runtime fault: the trace refused an event, or a task did not join.
	pub(crate) fn local(self) -> Result<ClusterError, TightBeamError> {
		match self {
			Self::Registry(error) => Ok(error),
			Self::Runtime(error) => Err(error),
		}
	}

	/// Records a registry fault on `trace`, the one observer a detached loop
	/// has.
	///
	/// A runtime fault ends the loop silently. The trace already holds its own
	/// refusal, and a task that did not join leaves no record.
	pub(crate) fn record(self, trace: &TraceCollector) {
		let Ok(error) = self.local() else {
			return;
		};

		// A trace that refuses this record has refused the loop already,
		// so nothing else can carry the fault.
		let recorded = trace.emit_marker_with_evidence(CLUSTER_LOOP_POISONED, || Some(error.to_string()));
		drop(recorded);
	}
}

impl From<TightBeamError> for LoopFault {
	fn from(error: TightBeamError) -> Self {
		Self::Runtime(error)
	}
}

impl From<ClusterError> for LoopFault {
	fn from(error: ClusterError) -> Self {
		Self::Registry(error)
	}
}

impl ClusterConfig {
	/// Emits each export-posture warning once, when the gateway starts.
	///
	/// Two configurations weaken the organization edge with no explicit
	/// operator choice at request time, so the gateway surfaces each for audit.
	///
	/// # Warnings
	///
	/// - A federated gateway with no export list serves and advertises every
	///   local type to external peers ([`CLUSTER_EXPORT_UNBOUNDED`]).
	/// - An export list with no captured client identity leaves every session
	///   anonymous, so unexported targets are unreachable from the origin
	///   plane as well ([`CLUSTER_EXPORT_IDENTITY_UNAVAILABLE`]).
	///
	/// # Sources
	///
	/// - NIST SP 800-53 Rev. 5 CM-6, configuration settings:
	///   <https://doi.org/10.6028/NIST.SP.800-53r5>
	fn warn_export_posture(&self, trace: &TraceCollector) -> Result<(), TightBeamError> {
		let federation_active = self.tls.peer_trust.is_some() || !self.peer.peers.is_empty();
		if ExportScope::from(&self.peer).is_unbounded() {
			if federation_active {
				trace.emit_marker(CLUSTER_EXPORT_UNBOUNDED)?;
			}
		} else {
			let requires_certificate = self.tls.peer_authentication().requires_certificate();
			let identity_captured = requires_certificate && self.tls.hive_trust.is_some();
			if !identity_captured {
				trace.emit_marker(CLUSTER_EXPORT_IDENTITY_UNAVAILABLE)?;
			}
		}

		Ok(())
	}
}

/// A live cluster gateway over the colony protocol `P` and the edge protocol
/// `E`.
///
/// The gateway owns the accept, heartbeat, evaporation, and advertise tasks for
/// the colony bind address and, when configured, a second edge accept plane.
/// Callers reach cluster state only through [`Cluster`] and
/// [`ClusterHeartbeat`].
///
/// # Digest
///
/// The gateway runs the digest of its provider, the
/// [`DigestProvider::Digest`] of [`Protocol::CryptoProvider`]. It names each
/// gateway by its certificate's fingerprint under that digest, and digests
/// each rumor and frame witness under it. Every gateway of a colony runs one
/// provider, so all of them name a peer and digest a rumor alike.
///
/// [`DigestProvider::Digest`]: crate::crypto::profiles::DigestProvider::Digest
///
/// # Edge accept plane
///
/// - `E` defaults to `P`, so a gateway without an edge declaration uses a single accept plane.
/// - `E` runs the provider of `P`, because both planes present the one identity of the gateway.
/// - When [`ClusterConfig::edge_bind_addr`] is set, the gateway binds a second
///   listener over `E` with the same TLS material.
/// - A separate edge mux service serves edge connections, and its one route is `Work` submission.
/// - Hives and peers use the colony plane at [`Cluster::addr`].
pub struct ClusterGateway<P, E = P>
where
	P: Protocol,
	E: Protocol,
{
	registry: Arc<HiveRegistry>,
	servlet_registry: Arc<ServletRegistry>,
	config: ColonyConfig<P>,
	/// The plane a heartbeat dials its hive on.
	hive_plane: HivePlane<P>,
	/// The colony accept plane task, which [`Cluster::join`] awaits together
	/// with the edge task.
	server_handle: Option<rt::JoinHandle>,
	/// The edge accept plane task, present when
	/// [`ClusterConfig::edge_bind_addr`] is set.
	edge_handle: Option<rt::JoinHandle>,
	/// Every background task this gateway started.
	tasks: TaskGroup,
	addr: P::Address,
	edge_addr: Option<E::Address>,
	trace: Arc<TraceCollector>,
	/// The trace that each connection of the colony and edge planes records
	/// on, which [`Cluster::connection_trace`] returns.
	connections: Arc<TraceCollector>,
}

impl<P, E> ClusterGateway<P, E>
where
	P: Protocol,
	E: Protocol,
{
	/// The bound address of the edge accept plane, or `None` when
	/// [`ClusterConfig::edge_bind_addr`] is unset.
	///
	/// External clients dial this address. Hives register on
	/// [`Cluster::addr`].
	pub fn edge_addr(&self) -> Option<&E::Address> {
		self.edge_addr.as_ref()
	}
}

impl<P, E> ClusterGateway<P, E>
where
	P: Protocol,
	E: Protocol,
{
	fn abort_tasks(&mut self) {
		self.tasks.abort_all();
		rt::take_and_abort(&mut self.edge_handle);
		rt::take_and_abort(&mut self.server_handle);
	}
}

impl<P, E> Cluster for ClusterGateway<P, E>
where
	P: GatewayColonyProtocol,
	E: GatewayAcceptProtocol + Protocol<CryptoProvider = P::CryptoProvider>,
{
	type Protocol = P;
	type Address = P::Address;

	async fn start(trace: Arc<TraceCollector>, config: ClusterConfig) -> Result<Self, TightBeamError> {
		// The freshness window MUST stay within journal retention (CWE-294).
		// The clamp runs before `Arc` wraps the config, which fixes the window
		// for its lifetime.
		let config = {
			let mut config = config;
			let retention = config.gossip.journal.retention();
			if config.gossip.seen_ttl > retention {
				config.gossip.seen_ttl = retention;
			}

			// The certificate and the namespace stay writable until here,
			// so membership binds to the pair this gateway serves.
			config.bind_colony_membership();
			config
		};

		// The gossip section stays writable until here as well, so the start
		// mints the ingress key once, under the namespace of this gateway, and
		// refuses an ingress that the namespace does not route.
		let config = ColonyConfig::<P>::new(config)?;

		// The `colony` feature enables `x509`, so the gateway always serves
		// TLS.
		let bind_addr = match config.bind_address()? {
			Some(bind_addr) => bind_addr,
			None => P::default_bind_address().map_err(TightBeamError::transport)?,
		};

		let (listener, addr) = P::bind_with(bind_addr, config.tls.accept_encryption())
			.await
			.map_err(TightBeamError::transport)?;

		let control_window = config.control_freshness_window;
		let registry = Arc::new(HiveRegistry::new(config.heartbeat.timeout, Arc::clone(&config.clock)));
		let routes = ServletRegistry::new(config.pheromone.clone(), Arc::clone(&config.clock))
			.with_ad_tombstone_window(control_window);

		let servlet_registry = Arc::new(routes);
		let pools = config.tls.pools::<P>(&config.pool_config, &config.clock, &trace);
		let hive_plane = HivePlane::new(pools.hive, Arc::clone(&trace));
		let peer_plane = hive_plane.peers(pools.peer, config.clone());

		let replay_guard_for_server = GatewayReplayGuard::new(control_window, Arc::clone(&config.clock));
		let tasks = TaskGroup::default();

		// Records that no credential backs stay off the audit trace (CWE-778).
		let connections = Arc::new(trace.connections());
		let ctx = GatewayRuntimeCtx {
			registry: Arc::clone(&registry),
			servlet_registry: Arc::clone(&servlet_registry),
			admission: Arc::new(Mutex::new(())),
			config: config.clone(),
			hive_plane: hive_plane.clone(),
			peer_plane,
			trace: Arc::clone(&trace),
			connections: Arc::clone(&connections),
			replay_guard: replay_guard_for_server,
			tasks: tasks.clone(),
			ledgers: Arc::default(),
		};

		// Bind every configured accept plane before any accept loop spawns.
		// An edge parse or bind failure then returns `Err` before the colony
		// listener leaves here, so a failed start spawns no accept task.
		let (edge_listener, edge_addr) = match config.edge_bind_address::<E::Address>()? {
			Some(edge_bind) => {
				let (edge_listener, edge_addr) = E::bind_with(edge_bind, config.tls.accept_encryption())
					.await
					.map_err(TightBeamError::transport)?;

				(Some(edge_listener), Some(edge_addr))
			}
			None => (None, None),
		};

		// The gateway decides its advertised address before any task spawns,
		// so a gateway that federates on the wildcard address refuses to start
		// and closes every listener it bound.
		let gateway_bytes: Vec<u8> = addr.clone().into();
		let gateway_addr = config.peer.advertised_address(gateway_bytes)?;

		// Export posture is colony-wide configuration, so the one startup
		// path reports it once for all accept planes, and only for a gateway
		// that starts.
		config.warn_export_posture(&trace)?;

		// Each field of the context is reference-counted, so a clone is cheap.
		let server_handle = ctx.clone().serve_colony::<P::Listener>(listener);

		// The edge plane serves [`EdgeMuxService`], whose only route is work
		// submission.
		let serve_edge = |edge_listener| ctx.clone().serve_edge::<E::Listener>(edge_listener);
		let edge_handle = edge_listener.map(serve_edge);

		tasks.adopt(ctx.clone().spawn_heartbeat());

		let relay_trail_ttl = config.relay_trail_ttl();

		tasks.adopt(ctx.clone().spawn_evaporation(relay_trail_ttl));
		tasks.adopt(ctx.clone().spawn_advertise(gateway_addr));

		Ok(Self {
			registry,
			servlet_registry,
			config,
			hive_plane,
			server_handle: Some(server_handle),
			edge_handle,
			tasks,
			addr,
			edge_addr,
			trace,
			connections,
		})
	}

	fn addr(&self) -> &Self::Address {
		&self.addr
	}

	fn available_servlets(&self) -> Result<Vec<SharedId>, ClusterError> {
		// The routes are the one home of the types this gateway serves, so
		// this list follows each instance a hive scales in or out.
		self.servlet_registry.local_servlets()
	}

	fn peer_servlets(&self) -> Result<Vec<SharedId>, ClusterError> {
		let entries = self.servlet_registry.peer_entries()?;
		let mut types: Vec<SharedId> = entries.iter().map(|entry| Arc::clone(entry.servlet_type())).collect();
		types.sort_unstable();
		types.dedup();

		Ok(types)
	}

	fn peer_routes(&self) -> Result<Vec<PeerRouteInfo>, ClusterError> {
		let entries = self.servlet_registry.peer_entries()?;
		let routes = entries.iter().filter_map(|entry| entry.peer_route_info()).collect();
		Ok(routes)
	}

	fn hive_count(&self) -> Result<usize, ClusterError> {
		self.registry.len()
	}

	fn trace(&self) -> Arc<TraceCollector> {
		Arc::clone(&self.trace)
	}

	fn connection_trace(&self) -> Arc<TraceCollector> {
		Arc::clone(&self.connections)
	}

	fn stop(mut self) {
		self.abort_tasks();
	}

	async fn join(mut self) -> Result<(), rt::JoinError> {
		let colony = self.server_handle.take();
		let edge = self.edge_handle.take();
		match (colony, edge) {
			(Some(colony), Some(edge)) => {
				let (colony_res, edge_res) = tokio::join!(colony, edge);
				colony_res?;
				edge_res
			}
			(Some(colony), None) => rt::join(colony).await,
			(None, Some(edge)) => rt::join(edge).await,
			(None, None) => Ok(()),
		}
	}
}

impl<P, E> ClusterHeartbeat for ClusterGateway<P, E>
where
	P: GatewayColonyProtocol,
	E: GatewayAcceptProtocol + Protocol<CryptoProvider = P::CryptoProvider>,
{
	fn registry(&self) -> &Arc<HiveRegistry> {
		&self.registry
	}

	fn heartbeat_config(&self) -> &HeartbeatConfig {
		&self.config.heartbeat
	}

	async fn send_heartbeat(&self, addr: Self::Address) -> Result<HeartbeatResult, ClusterError> {
		let hive_id: Vec<u8> = addr.into();
		let Some(hive) = self.registry.entry(&hive_id)? else {
			return Err(ClusterError::InvalidAddress(hive_id));
		};

		HiveBeat::new(&self.config, &self.hive_plane).send(&hive).await
	}
}

impl<P, E> Drop for ClusterGateway<P, E>
where
	P: Protocol,
	E: Protocol,
{
	fn drop(&mut self) {
		self.abort_tasks();
	}
}

/// The gateway's [`MuxService`] for the colony accept plane.
///
/// Unary frames route through cluster dispatch. Streamed and duplex opens route
/// by the target [`Urn`] on their [`CallContext`].
///
/// # Routing
///
/// - `Local` trail: the service dials the servlet on the hive plane.
/// - `Peer` trail: the service splices the stream to the peer gateway (see
///   [`GatewayRuntimeCtx::splice_streaming`] and
///   [`GatewayRuntimeCtx::splice_duplex`]).
///
/// # Export boundary
///
/// Stream and duplex opens pass [`GatewayRuntimeCtx::guard_stream_open`], which
/// applies the boundary order of the Work arm before the open routes.
struct GatewayMuxService<P>
where
	P: Protocol,
{
	ctx: GatewayRuntimeCtx<P>,
}

/// The gateway's [`MuxService`] for an edge accept plane.
///
/// An edge plane serves external clients, so work submission is its only
/// route. The type carries that boundary. Its unary arm narrows the envelope
/// to a work request through [`GatewayRuntimeCtx::handle_edge_request`], and
/// its stream and duplex arms refuse with `PermissionDenied`. Registration,
/// peer advertisement, and gossip stay on the colony plane.
struct EdgeMuxService<P>
where
	P: Protocol,
{
	ctx: GatewayRuntimeCtx<P>,
}

impl<P> MuxService for GatewayMuxService<P>
where
	P: GatewayColonyProtocol,
{
	fn unary(
		&self,
		frame: Frame,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let ctx = self.ctx.clone();
		async move { ctx.handle_request(frame, cx.into_session()).await }
	}

	fn streaming(
		&self,
		body: StreamBody,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let ctx = self.ctx.clone();
		async move {
			let audit = ctx.audit(cx.session());
			let (target, budget) = ctx.guard_stream_open(&cx, &audit)?;
			ctx.splice_streaming(body, target, budget, &audit).await
		}
	}

	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		cx: CallContext,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send {
		let ctx = self.ctx.clone();
		async move {
			let audit = ctx.audit(cx.session());
			let (target, budget) = ctx.guard_stream_open(&cx, &audit)?;
			ctx.splice_duplex(body, reply, target, budget, &audit).await
		}
	}
}

impl<P> MuxService for EdgeMuxService<P>
where
	P: GatewayColonyProtocol,
{
	fn unary(
		&self,
		frame: Frame,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let ctx = self.ctx.clone();
		async move { ctx.handle_edge_request(frame, cx.into_session()).await }
	}

	fn streaming(
		&self,
		_body: StreamBody,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let refused = self.ctx.refuse_edge_open("streaming", &cx);
		core::future::ready(Err(refused))
	}

	fn duplex(
		&self,
		_body: StreamBody,
		_reply: ReplySink,
		cx: CallContext,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send {
		let refused = self.ctx.refuse_edge_open("duplex", &cx);
		core::future::ready(Err(refused))
	}
}

impl<P: Protocol> GatewayRuntimeCtx<P> {
	/// Records a call that the edge plane refuses, and returns the status that
	/// the caller reads.
	///
	/// The edge plane serves work submission alone, so it answers every other
	/// call with [`TransitStatus::PermissionDenied`] and records
	/// [`CLUSTER_EDGE_REFUSED`].
	///
	/// - `call` names the kind of the call: `unary`, `streaming`, or `duplex`.
	/// - `session` names the caller by the canonical key its handshake proved.
	///   A frame's signer is a claim the edge plane does not verify, so the
	///   record never names it (CWE-345).
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refused the event, the fault the `testing-fault` feature injects.
	fn refuse_edge_call(&self, call: &'static str, session: &SessionContext) -> Result<TransitStatus, TightBeamError> {
		let status = TransitStatus::PermissionDenied;
		let caller = session.peer_key().map(CanonicalKey::as_der);
		let audit = self.audit(session);
		let trace = audit.unproven();
		trace.emit_event_with_value_and_evidence(CLUSTER_EDGE_REFUSED, call, status, caller)?;

		Ok(status)
	}

	/// Refuses a stream that the edge plane opened, through
	/// [`Self::refuse_edge_call`], and returns the failure that ends the
	/// stream: the refusal, or the fault of a trace that refused the event.
	fn refuse_edge_open(&self, call: &'static str, cx: &CallContext) -> TightBeamError {
		let refused = self.refuse_edge_call(call, cx.session());
		refused.map_or_else(|fault| fault, TransitStatus::refusal)
	}

	/// The boundary guard that the streaming and duplex open handlers share.
	///
	/// An open passes the same boundary a unary request passes:
	///
	/// 1. Run [`ClusterConfig::evaluate_gates`] with no request frame.
	/// 2. Resolve the servlet target from the call context.
	/// 3. Run [`ColonyConfig::admit_target`] on that target, the hop budget of
	///    the open, and the session.
	///
	/// An unrouted open names no servlet type, so it fails with
	/// `Unimplemented`.
	fn guard_stream_open(
		&self,
		cx: &CallContext,
		audit: &RequestAudit,
	) -> Result<(Urn<'static>, HopBudget), TightBeamError> {
		let trace = audit.unproven();
		let gate_status = self.config.evaluate_gates(None, cx.session(), trace)?;
		if gate_status != TransitStatus::Ok {
			return Err(gate_status.refusal());
		}

		let Some(target) = cx.target().cloned() else {
			return Err(TightBeamError::unimplemented());
		};

		let wire = WireHopBudget::new(cx.hops_remaining());
		let admitted = self.config.admit_target(&target, wire, cx.session(), trace)?;
		let budget = admitted.map_err(TransitStatus::refusal)?;

		Ok((target, budget))
	}
}

impl<P: GatewayColonyProtocol> GatewayRuntimeCtx<P> {
	/// Serves the colony accept plane through [`GatewayMuxService`].
	///
	/// `L` is the bound listener, which feeds the service over the colony pool
	/// protocol `P`. Each connection records on the connection trace.
	pub(crate) fn serve_colony<L>(self, listener: L) -> rt::JoinHandle
	where
		L: AsyncListenerTrait + Sync + 'static,
		L::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	{
		let terms = self.connection_terms();
		let clock = Arc::clone(&self.config.clock);
		let service = GatewayMuxService::<P> { ctx: self };
		Self::accept_into(listener, terms, clock, service)
	}

	/// Serves an edge accept plane through [`EdgeMuxService`].
	///
	/// The service type restricts the plane to work submission, so the type
	/// alone tells dispatch which plane a request arrived on. Each connection
	/// records on the connection trace.
	pub(crate) fn serve_edge<L>(self, listener: L) -> rt::JoinHandle
	where
		L: AsyncListenerTrait + Sync + 'static,
		L::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	{
		let terms = self.connection_terms();
		let clock = Arc::clone(&self.config.clock);
		let service = EdgeMuxService::<P> { ctx: self };
		Self::accept_into(listener, terms, clock, service)
	}

	/// The terms that the gateway sets on each connection it serves: the
	/// connection trace, and the mux offer of its pool config.
	fn connection_terms(&self) -> ConnectionTerms {
		let mux_offer = self.config.pool_config.mux_offer.as_ref().map(Arc::clone);
		let trace = TraceHandle::new(Arc::clone(&self.connections));
		ConnectionTerms::new(trace, mux_offer)
	}

	/// Accepts on `listener` and dispatches every connection through `service`.
	///
	/// Each admitted transport takes `terms`, the connection trace and the mux
	/// offer, before its handshake. Accept retries wait on `clock`, the
	/// gateway's own.
	///
	/// # Warning
	///
	/// The connection trace records each peer, including one that never
	/// authenticates. Give the gateway's trace an `EventSink` that forwards
	/// through `EventSink::sibling`, or drain the connection trace.
	fn accept_into<L, S>(listener: L, terms: ConnectionTerms, clock: Arc<dyn Clock>, service: S) -> rt::JoinHandle
	where
		L: AsyncListenerTrait + Sync + 'static,
		L::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
		S: MuxService + Send + Sync + 'static,
	{
		let service = Arc::new(service);
		let plane = AcceptPlane::new(DEFAULT_MAX_SERVER_CONNECTIONS, clock);
		rt::spawn(plane.accept_owned(listener, terms, move |transport: L::Transport| {
			let service = Arc::clone(&service);
			async move { serve_connection_service(transport, service, None, None).await }
		}))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::cluster::ClusterTlsConfig;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::x509::KeyPurposes;
	use crate::testing::fixtures::TestIdentity;
	use crate::testing::TestResult;

	/// The accept planes hold the gateway's identity to the purposes its TLS
	/// config names, so the transport and the colony read one purpose set.
	#[test]
	fn the_accept_planes_take_the_configured_key_purposes() -> TestResult {
		let configured = KeyPurposes { server: KeyPurposes::HOUSE.client, ..KeyPurposes::HOUSE };
		let tls = ClusterTlsConfig::from_identity(TestIdentity::insecure_fixed(), configured)?;

		let accept = tls.accept_encryption::<DefaultCryptoProvider>();
		assert_eq!(accept.key_purposes, configured);
		Ok(())
	}

	/// The cluster error of a gateway start that `started` refused.
	fn cluster_error<T>(started: Result<T, TightBeamError>) -> ClusterError {
		match started {
			Err(TightBeamError::ClusterError(error)) => *error,
			_ => panic!("the start refuses with a cluster error"),
		}
	}

	/// A bind address that does not parse is a fault of the operator's
	/// configuration, so the start names it as a cluster error with the
	/// octets it refused.
	#[tokio::test]
	async fn a_malformed_bind_address_is_a_cluster_error() {
		use crate::transport::TokioListener;

		let config = ClusterConfig { bind_addr: Some(String::from("not-a-socket")), ..ClusterConfig::fixture() };
		let started = ClusterGateway::<TokioListener>::start(Arc::new(TraceCollector::new()), config).await;
		assert!(matches!(cluster_error(started), ClusterError::InvalidAddress(named) if named == b"not-a-socket"));
	}

	/// The namespace stays writable after the gossip ingress is set, so the
	/// start refuses an ingress that the namespace it serves cannot route.
	#[tokio::test]
	async fn a_gossip_ingress_outside_the_namespace_refuses_the_start() -> TestResult {
		use crate::colony::urn::ColonyNamespace;
		use crate::transport::TokioListener;

		let acme = ColonyNamespace::new("acme", "prod")?;
		let builder = ClusterConfig::builder(ClusterTlsConfig::fixture());
		let builder = builder.with_gossip_ingress(ColonyNamespace::servlet_fixture("feed"))?;
		let config = builder.with_namespace(acme).build();

		let started = ClusterGateway::<TokioListener>::start(Arc::new(TraceCollector::new()), config).await;
		assert!(matches!(
			cluster_error(started),
			ClusterError::UnknownServletType(named) if named == b"urn:tightbeam::servlet:feed"
		));
		Ok(())
	}

	/// A runtime fault passes up to the caller of a request, so the request
	/// ends with the fault the trace observed.
	#[test]
	fn a_runtime_fault_passes_up() {
		let runtime = LoopFault::Runtime(TightBeamError::ChannelClosed).local();
		assert!(matches!(runtime, Err(TightBeamError::ChannelClosed)));
	}

	/// A request refuses a local fault, and the fault comes back for the
	/// refusal to name.
	#[test]
	fn a_local_fault_refuses() {
		let local = LoopFault::Registry(ClusterError::LockPoisoned).local();
		assert!(matches!(local, Ok(ClusterError::LockPoisoned)));
	}

	/// An anonymous stream gate refusal records on the connection trace.
	#[cfg(feature = "testing")]
	#[test]
	fn an_anonymous_stream_gate_refusal_records_on_the_connection_trace() {
		use crate::colony::cluster::runtime::bounds::fixtures::Audited;
		use crate::colony::urn::ColonyNamespace;
		use crate::instrumentation::events::CLUSTER_GATE_BLOCKED;
		use crate::testing::fixtures::TestGate;
		use crate::transport::error::{TransportError, TransportFailure};
		use crate::transport::multiplex::StreamRoute;

		let mut config = ClusterConfig::fixture();
		config.policies.push(Arc::new(TestGate(TransitStatus::PermissionDenied)));

		let audited = Audited::of(config);
		let route = StreamRoute::to(ColonyNamespace::servlet_fixture("ping"));
		let cx = CallContext::new(SessionContext::default(), route);
		let audit = audited.gateway.audit(cx.session());

		let opened = audited.gateway.guard_stream_open(&cx, &audit);
		assert!(matches!(
			opened,
			Err(TightBeamError::TransportError(TransportError::OperationFailed(
				TransportFailure::PermissionDenied
			)))
		));
		assert_eq!(audited.counts(CLUSTER_GATE_BLOCKED), (0, 1));
	}

	/// The request context ages the tombstone of a withdrawn advertisement on
	/// the control freshness window of its gateway, as the start does, so a
	/// replay of the older advertisement stays refused for that window
	/// (CWE-294). The advertisement is a minute old, past the default window.
	#[test]
	fn a_withdrawal_tombstone_lasts_the_control_freshness_window() -> TestResult {
		use crate::colony::cluster::runtime::bounds::fixtures::Audited;
		use crate::colony::cluster::{AdmittedPeerAd, PeerCaps, ServletEntry};
		use crate::testing::fixtures::TestClock;

		let clock = TestClock::manual();
		let window = core::time::Duration::from_secs(3_600);
		let config = ClusterConfig {
			control_freshness_window: window,
			clock: TestClock::erased(&clock),
			..ClusterConfig::fixture()
		};

		let audited = Audited::of(config);
		let routes = &audited.gateway.servlet_registry;
		let (dial, issued) = ("127.0.0.1:9000", clock.unix().get() - 60_000);
		let route = || ServletEntry::peer_fixture(b"calc", b"origin", dial);
		let install = AdmittedPeerAd::fixture(b"origin", dial, [route()], issued);
		let withdrawal = AdmittedPeerAd::fixture(b"origin", dial, Vec::new(), issued + 1);

		routes.reconcile_peer_slate(install, PeerCaps::default())?;
		routes.reconcile_peer_slate(withdrawal, PeerCaps::default())?;

		let replay = AdmittedPeerAd::fixture(b"origin", dial, [route()], issued);
		let replayed = routes.reconcile_peer_slate(replay, PeerCaps::default());
		assert!(matches!(replayed, Err(ClusterError::StalePeerAd)));
		Ok(())
	}
}
