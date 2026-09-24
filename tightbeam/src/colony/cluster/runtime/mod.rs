//! Cluster gateway runtime: accept loop, background tasks, and mux routing.
//!
//! [`ClusterGateway`] owns the listener, heartbeat, evaporation, and advertise
//! tasks. Incoming connections are served through [`GatewayMuxService`], which
//! routes unary control frames to dispatch and splices streamed or duplex opens
//! by servlet target.
//!
//! Each sibling module owns one of the surfaces a request reaches: dispatch,
//! registration, work, streaming, gossip, and heartbeat.

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

pub(crate) use verify::{VerifiedControlFrame, VerifiedSignerId};
mod work;

use core::future::Future;
use core::marker::PhantomData;
use core::time::Duration;
use std::sync::{Arc, Mutex};

use self::bounds::{ClusterDigest, ClusterPool, GatewayAcceptProtocol, GatewayColonyProtocol, GatewayRuntimeCtx};
use self::freshness::GatewayReplayGuard;
use self::heartbeat::HiveBeat;
use crate::colony::cluster::peer::WireHopBudget;
use crate::colony::cluster::{
	Cluster, ClusterConfig, ClusterError, ClusterHeartbeat, HeartbeatConfig, HiveRegistry, HopBudget, PeerRouteInfo,
	ServletRegistry, SharedId,
};
use crate::colony::common::{HeartbeatResult, TaskGroup};
use crate::colony::servlet::servlet_runtime::rt;
use crate::constants::{DEFAULT_AD_RUMOR_REFRESH_MS, DEFAULT_MAX_SERVER_CONNECTIONS};
use crate::crypto::hash::Sha3_256;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::macros::server::{serve_connection_service, AcceptedConnection};
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::transport::accept::AcceptPlane;
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::multiplex::{MuxCapable, ReplySink, StreamBody};
use crate::transport::policy::PolicyConfig;
use crate::transport::serve::{unimplemented_error, CallContext, MuxService};
use crate::transport::{AsyncListenerTrait, Protocol, TransportEncryptionConfig, TransportError};
use crate::utils::time::Clock;
use crate::utils::urn::Urn;
use crate::Frame;
use crate::TightBeamError;

use crate::instrumentation::events::{
	CLUSTER_EXPORT_IDENTITY_UNAVAILABLE, CLUSTER_EXPORT_UNBOUNDED, CLUSTER_LOOP_POISONED,
};

/// Why one background loop of the gateway ended.
///
/// Every loop reads registries and tables and records to the trace, and
/// either can refuse. The two refusals are kept apart so the exit records
/// a poisoned lock by name and lets a trace fault end the loop silently,
/// which is the effect a `testing-fault` injection observes.
pub(crate) enum LoopFault {
	/// The trace refused an event, or a task the loop awaited did not join.
	Runtime(TightBeamError),
	/// A registry, table or journal this loop reads is poisoned.
	Registry(ClusterError),
}

impl LoopFault {
	/// Records a registry fault on `trace`, the one observer a detached
	/// loop has. A runtime fault is the trace's own refusal, so the trace
	/// already holds it.
	pub(crate) fn record(self, trace: &TraceCollector) {
		let Self::Registry(error) = self else {
			return;
		};

		// A trace that refuses this record has refused the loop already,
		// so nothing else can carry the fault.
		let fault = error.to_string();
		let recorded = trace
			.event(CLUSTER_LOOP_POISONED)
			.map(|event| event.with_payload(&fault).emit());
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
	/// Emit one-time export-posture warnings when the gateway starts.
	///
	/// Two configurations weaken the organization edge without an explicit
	/// operator choice at request time, so the gateway surfaces each
	/// condition once for audit.
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
	///   <https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#/control?version=5.1&number=CM-6>
	fn warn_export_posture(&self, trace: &TraceCollector) -> Result<(), TightBeamError> {
		let federation_active = self.tls.peer_trust.is_some() || !self.peer.peers.is_empty();
		match self.peer.exported_types.as_ref() {
			None => {
				if federation_active {
					trace.event(CLUSTER_EXPORT_UNBOUNDED)?.emit();
				}
			}
			Some(_) => {
				let requires_certificate = self.tls.peer_authentication().requires_certificate();
				let identity_captured = requires_certificate && self.tls.hive_trust.is_some();
				if !identity_captured {
					trace.event(CLUSTER_EXPORT_IDENTITY_UNAVAILABLE)?.emit();
				}
			}
		}

		Ok(())
	}

	/// Builds the accept-side TLS config the colony and edge listeners share.
	///
	/// Both planes present the same certificate and key so an external edge
	/// client pins the same gateway identity that hives already trust. The
	/// client authentication is [`ClusterTlsConfig::peer_authentication`].
	///
	/// `ClusterTlsConfig::new` already decoded the certificate, so assembly
	/// here always returns `Ok`.
	///
	/// [`ClusterTlsConfig::peer_authentication`]: crate::colony::cluster::ClusterTlsConfig::peer_authentication
	fn accept_encryption_config(&self) -> Result<TransportEncryptionConfig<DefaultCryptoProvider>, TightBeamError> {
		let (certificate, key_manager) = self.tls.identity().parts();
		let encryption_config = TransportEncryptionConfig::new(certificate, key_manager);
		let encryption_config =
			encryption_config.with_client_validators(self.tls.client_validators.iter().map(Arc::clone));

		Ok(encryption_config)
	}
}

fn protocol_error<E: Into<TransportError>>(error: E) -> TightBeamError {
	TightBeamError::from(error.into())
}

/// Running cluster gateway for protocol `P`, digest `D`, and edge protocol `E`.
///
/// Owns the accept, heartbeat, evaporation, and advertise tasks for the
/// colony bind address and, when configured, a second edge accept plane.
/// Callers reach cluster state only through [`Cluster`] and
/// [`ClusterHeartbeat`].
///
/// # Edge accept plane
///
/// - `E` defaults to `P`, so a gateway without an edge declaration uses a single accept plane.
/// - When [`ClusterConfig::edge_bind_addr`] is set, the gateway binds a second
///   listener over `E` with the same TLS material.
/// - Edge connections are served by a separate edge mux service, whose one
///   route is `Work` submission.
/// - Hives and peers keep using the colony plane at [`Cluster::addr`].
pub struct ClusterGateway<P, D = Sha3_256, E = P>
where
	P: Protocol,
	E: Protocol,
{
	registry: Arc<HiveRegistry>,
	servlet_registry: Arc<ServletRegistry>,
	config: Arc<ClusterConfig>,
	pool: Arc<ClusterPool<P>>,
	/// The accept planes, which [`Cluster::join`] awaits.
	server_handle: Option<rt::JoinHandle>,
	edge_handle: Option<rt::JoinHandle>,
	/// Every background task this gateway started.
	tasks: TaskGroup,
	addr: P::Address,
	edge_addr: Option<E::Address>,
	trace: Arc<TraceCollector>,
	_digest: PhantomData<D>,
}

impl<P, D, E> ClusterGateway<P, D, E>
where
	P: Protocol,
	E: Protocol,
{
	/// Bound edge accept plane address, or `None` when
	/// [`ClusterConfig::edge_bind_addr`] was unset.
	///
	/// External clients dial this address. Hives keep registering on
	/// [`Cluster::addr`].
	pub fn edge_addr(&self) -> Option<&E::Address> {
		self.edge_addr.as_ref()
	}
}

impl<P, D, E> ClusterGateway<P, D, E>
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

impl<P, D, E> Cluster for ClusterGateway<P, D, E>
where
	P: GatewayColonyProtocol,
	E: GatewayAcceptProtocol,
	D: ClusterDigest,
{
	type Protocol = P;
	type Address = P::Address;

	async fn start(trace: Arc<TraceCollector>, config: ClusterConfig) -> Result<Self, TightBeamError> {
		// The admission freshness window MUST stay within journal retention
		// (CWE-294). A rumor older than retention has no digest left, so a
		// wider window would re-admit a replay as new. The clamp runs before
		// config is wrapped in Arc, which fixes the window for its lifetime.
		let config = {
			let mut config = config;
			let retention = config.gossip.journal.retention();
			if config.gossip.seen_ttl > retention {
				config.gossip.seen_ttl = retention;
			}

			// The certificate and the namespace stay writable until here,
			// so membership binds to the pair this gateway actually serves.
			config.bind_colony_membership();
			config
		};

		let config = Arc::new(config);

		// The `colony` feature enables `x509`, so the gateway always serves
		// TLS.
		let bind_addr = match config.bind_addr.as_deref() {
			Some(raw) => raw.parse().map_err(|_| TransportError::InvalidMessage)?,
			None => P::default_bind_address().map_err(protocol_error)?,
		};

		let (listener, addr) = P::bind_with(bind_addr, config.accept_encryption_config()?)
			.await
			.map_err(protocol_error)?;

		let control_window = config.control_freshness_window;
		let registry = Arc::new(HiveRegistry::new(config.heartbeat.timeout, Arc::clone(&config.clock)));
		let routes = ServletRegistry::new(config.pheromone.clone(), Arc::clone(&config.clock))
			.with_ad_tombstone_window(control_window);

		let servlet_registry = Arc::new(routes);
		let pools = config.pool_config.build_cluster_pools::<P>(&config.tls, &config.clock)?;
		let pool = pools.hive;
		let peer_pool = pools.peer;

		let replay_guard_for_server = GatewayReplayGuard::new(control_window, Arc::clone(&config.clock));
		let tasks = TaskGroup::default();
		let ctx = GatewayRuntimeCtx {
			registry: Arc::clone(&registry),
			servlet_registry: Arc::clone(&servlet_registry),
			admission: Arc::new(Mutex::new(())),
			config: Arc::clone(&config),
			pool: Arc::clone(&pool),
			peer_pool: peer_pool.as_ref().map(Arc::clone),
			trace: Arc::clone(&trace),
			replay_guard: replay_guard_for_server,
			tasks: tasks.clone(),
		};

		// Bind every configured accept plane before spawning any accept
		// loop. An edge parse or bind failure returns `Err` while the colony
		// listener is still local, so a failed start leaves every accept
		// task unspawned.
		let (edge_listener, edge_addr) = match config.edge_bind_addr.as_deref() {
			Some(raw) => {
				let edge_bind: E::Address = raw.parse().map_err(|_| TransportError::InvalidMessage)?;
				let (edge_listener, edge_addr) = E::bind_with(edge_bind, config.accept_encryption_config()?)
					.await
					.map_err(protocol_error)?;

				(Some(edge_listener), Some(edge_addr))
			}
			None => (None, None),
		};

		// Export posture is colony-wide configuration, so the one startup
		// path reports it once for all accept planes.
		config.warn_export_posture(&trace)?;

		// Every field of the context is an `Arc`, so the clone is cheap.
		let server_handle = ctx.clone().serve_colony::<P::Listener, D>(listener);

		// The edge plane serves [`EdgeMuxService`], whose only route is work
		// submission.
		let edge_handle = edge_listener.map(|edge_listener| ctx.clone().serve_edge::<E::Listener, D>(edge_listener));

		tasks.adopt(ctx.clone().spawn_heartbeat::<D>());

		// Three refresh intervals of silence retire a relay trail: one missed
		// refresh is churn, three means the refresh path died. The default
		// refresh interval floors the TTL, so an aggressive `rumor_refresh`
		// keeps a healthy fallback in place.
		let relay_trail_ttl = config
			.rumor_refresh()
			.saturating_mul(3)
			.max(Duration::from_millis(DEFAULT_AD_RUMOR_REFRESH_MS));

		tasks.adopt(ctx.clone().spawn_evaporation(relay_trail_ttl));

		{
			let gateway_bytes: Vec<u8> = addr.clone().into();
			tasks.adopt(ctx.clone().spawn_advertise::<D>(Arc::from(gateway_bytes)));
		}

		Ok(Self {
			registry,
			servlet_registry,
			config,
			pool,
			server_handle: Some(server_handle),
			edge_handle,
			tasks,
			addr,
			edge_addr,
			trace,
			_digest: PhantomData,
		})
	}

	fn addr(&self) -> &Self::Address {
		&self.addr
	}

	fn available_servlets(&self) -> Result<Vec<SharedId>, ClusterError> {
		// Routes are the one home for which types this gateway serves, so
		// a hive scaling an instance in or out is reflected here without a
		// second index to keep current.
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

impl<P, D, E> ClusterHeartbeat for ClusterGateway<P, D, E>
where
	P: GatewayColonyProtocol,
	E: GatewayAcceptProtocol,
	D: ClusterDigest,
{
	fn registry(&self) -> &Arc<HiveRegistry> {
		&self.registry
	}

	fn heartbeat_config(&self) -> &HeartbeatConfig {
		&self.config.heartbeat
	}

	async fn send_heartbeat(&self, addr: Self::Address) -> Result<HeartbeatResult, ClusterError> {
		HiveBeat::new(&self.config, &self.pool).send::<D>(addr).await
	}
}

impl<P, D, E> Drop for ClusterGateway<P, D, E>
where
	P: Protocol,
	E: Protocol,
{
	fn drop(&mut self) {
		self.abort_tasks();
	}
}

/// Gateway implementation of [`MuxService`] for the colony accept plane.
///
/// Unary frames route through cluster dispatch. Streamed and duplex opens route
/// by the target [`Urn`] on their [`CallContext`].
///
/// # Routing
///
/// - `Local` trail: dial the servlet on the hive plane.
/// - `Peer` trail: splice the stream to the peer gateway (see
///   [`GatewayRuntimeCtx::splice_streaming`] and
///   [`GatewayRuntimeCtx::splice_duplex`]).
///
/// # Export boundary
///
/// Stream and duplex opens share the Work-arm boundary order:
///
/// 1. [`ClusterConfig::evaluate_gates`] before routing.
/// 2. Resolve the servlet target from the call context.
/// 3. Derive `relayed` from [`HopBudget::is_relayed`].
/// 4. [`ClusterConfig::evaluate_export_gates`].
struct GatewayMuxService<P, D>
where
	P: Protocol,
{
	ctx: GatewayRuntimeCtx<P>,
	_digest: PhantomData<D>,
}

/// Gateway implementation of [`MuxService`] for an edge accept plane.
///
/// An edge plane serves external clients, so work submission is its only
/// route. The type carries that boundary. Its unary arm narrows the envelope
/// to a work request through [`GatewayRuntimeCtx::handle_edge_request`], and
/// its stream and duplex arms refuse with `PermissionDenied`. Registration,
/// peer advertisement, and gossip stay on the colony plane.
struct EdgeMuxService<P, D>
where
	P: Protocol,
{
	ctx: GatewayRuntimeCtx<P>,
	_digest: PhantomData<D>,
}

impl<P, D> MuxService for GatewayMuxService<P, D>
where
	P: GatewayColonyProtocol,
	D: ClusterDigest,
{
	fn unary(
		&self,
		frame: Frame,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let ctx = self.ctx.clone();
		async move { ctx.handle_request::<D>(frame, cx.into_session()).await }
	}

	fn streaming(
		&self,
		body: StreamBody,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let ctx = self.ctx.clone();
		async move {
			let (target, budget) = ctx.guard_stream_open(&cx)?;
			ctx.splice_streaming(body, target, budget).await
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
			let (target, budget) = ctx.guard_stream_open(&cx)?;
			ctx.splice_duplex(body, reply, target, budget).await
		}
	}
}

impl<P, D> MuxService for EdgeMuxService<P, D>
where
	P: GatewayColonyProtocol,
	D: ClusterDigest,
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
		_cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		core::future::ready(Err(TransitStatus::PermissionDenied.refusal()))
	}

	fn duplex(
		&self,
		_body: StreamBody,
		_reply: ReplySink,
		_cx: CallContext,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send {
		core::future::ready(Err(TransitStatus::PermissionDenied.refusal()))
	}
}

impl<P: Protocol> GatewayRuntimeCtx<P> {
	/// Boundary guard shared by the streaming and duplex open handlers.
	///
	/// An open passes the same boundary a unary request passes:
	///
	/// 1. [`ClusterConfig::evaluate_gates`] with no request frame.
	/// 2. Resolve the servlet target from the call context.
	/// 3. Derive `relayed` from [`HopBudget::is_relayed`].
	/// 4. [`ClusterConfig::evaluate_export_gates`] on that target and session.
	///
	/// An unrouted open names no servlet type, so it fails with
	/// `Unimplemented`.
	fn guard_stream_open(&self, cx: &CallContext) -> Result<(Urn<'static>, HopBudget), TightBeamError> {
		let gate_status = self.config.evaluate_gates(None, cx.session(), &self.trace)?;
		if gate_status != TransitStatus::Ok {
			return Err(gate_status.refusal());
		}

		let Some(target) = cx.target().cloned() else {
			return Err(unimplemented_error());
		};

		let budget = HopBudget::from_wire(WireHopBudget::new(cx.hops_remaining()), self.config.peer.max_hops);
		let is_relayed = budget.is_relayed();
		let session = cx.session();
		let export_status = self.config.evaluate_export_gates(&target, session, is_relayed, &self.trace)?;
		if export_status != TransitStatus::Ok {
			return Err(export_status.refusal());
		}

		Ok((target, budget))
	}
}

impl<P: GatewayColonyProtocol> GatewayRuntimeCtx<P> {
	/// Serves the colony accept plane through [`GatewayMuxService`].
	///
	/// `L` is the listener actually bound, which feeds the service over the
	/// colony pool protocol `P`.
	pub(crate) fn serve_colony<L, D>(self, listener: L) -> rt::JoinHandle
	where
		L: AsyncListenerTrait + Sync + 'static,
		L::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
		D: ClusterDigest,
	{
		let mux_offer = self.config.pool_config.mux_offer.as_ref().map(Arc::clone);
		let clock = Arc::clone(&self.config.clock);
		let service = GatewayMuxService::<P, D> { ctx: self, _digest: PhantomData };
		Self::accept_into(listener, mux_offer, clock, service)
	}

	/// Serves an edge accept plane through [`EdgeMuxService`].
	///
	/// The service type is what restricts the plane to work submission, so
	/// this path carries no plane flag into dispatch.
	pub(crate) fn serve_edge<L, D>(self, listener: L) -> rt::JoinHandle
	where
		L: AsyncListenerTrait + Sync + 'static,
		L::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
		D: ClusterDigest,
	{
		let mux_offer = self.config.pool_config.mux_offer.as_ref().map(Arc::clone);
		let clock = Arc::clone(&self.config.clock);
		let service = EdgeMuxService::<P, D> { ctx: self, _digest: PhantomData };
		Self::accept_into(listener, mux_offer, clock, service)
	}

	/// Accepts on `listener`, dispatching every connection through `service`.
	///
	/// Each admitted transport shares one mux offer by reference count, and
	/// accept retries wait on `clock`, the gateway's own.
	fn accept_into<L, S>(
		listener: L,
		mux_offer: Option<Arc<TransportOffer>>,
		clock: Arc<dyn Clock>,
		service: S,
	) -> rt::JoinHandle
	where
		L: AsyncListenerTrait + Sync + 'static,
		L::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
		S: MuxService + Send + Sync + 'static,
	{
		let service = Arc::new(service);

		let plane = AcceptPlane::new(DEFAULT_MAX_SERVER_CONNECTIONS, clock);
		rt::spawn(plane.accept_on(listener, move |mut transport: L::Transport| {
			// Clone the Arc so each accept shares the mux offer without
			// copying authorization octets.
			transport = transport.with_mux_offer(mux_offer.clone());

			let service = Arc::clone(&service);
			async move { serve_connection_service(transport, service, None, None).await }
		}))
	}
}
