//! The runtime of the cluster gateway: its accept loop, its background tasks,
//! and its mux routing.
//!
//! [`ClusterGateway`] owns the listener, heartbeat, evaporation, and advertise
//! tasks. [`GatewayMuxService`] serves each inbound connection: it routes
//! unary control frames to dispatch and splices streamed or duplex opens by
//! servlet target.
//!
//! Each surface a request reaches has a sibling module of its own: dispatch,
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

#[cfg(test)]
pub(crate) use bounds::ColonyDigest;
pub(crate) use bounds::{ColonyConfig, ColonyDialProtocol};
pub use freshness::FreshnessWindow;
pub(crate) use verify::{VerifiedControlFrame, VerifiedSignerId};
mod work;

use core::future::Future;
use core::time::Duration;
use std::sync::{Arc, Mutex};

use self::bounds::{GatewayAcceptProtocol, GatewayColonyProtocol, GatewayRuntimeCtx};
use self::freshness::GatewayReplayGuard;
use self::heartbeat::HiveBeat;
use self::hop::{HivePlane, PeerPlane};
use crate::colony::cluster::export::ExportScope;
use crate::colony::cluster::peer::WireHopBudget;
use crate::colony::cluster::{
	Cluster, ClusterConfig, ClusterError, ClusterHeartbeat, HeartbeatConfig, HiveRegistry, HopBudget, PeerRouteInfo,
	ServletRegistry, SharedId,
};
use crate::colony::common::{HeartbeatResult, TaskGroup};
use crate::constants::{DEFAULT_AD_RUMOR_REFRESH_MS, DEFAULT_MAX_SERVER_CONNECTIONS};
use crate::macros::server::{serve_connection_service, AcceptedConnection};
use crate::policy::TransitStatus;
use crate::runtime::rt;
use crate::trace::TraceCollector;
use crate::transport::accept::AcceptPlane;
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::multiplex::{CallContext, MuxCapable, MuxService, ReplySink, StreamBody};
use crate::transport::policy::PolicyConfig;
use crate::transport::{AsyncListenerTrait, Protocol, TransportError};
use crate::urn::Urn;
use crate::utils::time::Clock;
use crate::Frame;
use crate::TightBeamError;

use crate::instrumentation::events::{
	CLUSTER_EXPORT_IDENTITY_UNAVAILABLE, CLUSTER_EXPORT_UNBOUNDED, CLUSTER_LOOP_POISONED,
};

/// Why one background loop of the gateway ended.
///
/// Every loop reads registries and tables and records to the trace, and
/// either can refuse. The two variants keep the refusals apart, so the exit
/// records a poisoned lock by name and lets a trace fault end the loop
/// silently, which is the effect a `testing-fault` injection observes.
pub(crate) enum LoopFault {
	/// The trace refused an event, or a task the loop awaited did not join.
	Runtime(TightBeamError),
	/// A registry, table, or journal this loop reads is poisoned.
	Registry(ClusterError),
}

impl LoopFault {
	/// Records a registry fault on `trace`, the one observer a detached loop
	/// has.
	///
	/// A runtime fault ends the loop silently. The trace already holds its own
	/// refusal, and a task that did not join leaves no record.
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
	/// Emits each export-posture warning once, when the gateway starts.
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
		if ExportScope::from(&self.peer).is_unbounded() {
			if federation_active {
				trace.event(CLUSTER_EXPORT_UNBOUNDED)?.emit();
			}
		} else {
			let requires_certificate = self.tls.peer_authentication().requires_certificate();
			let identity_captured = requires_certificate && self.tls.hive_trust.is_some();
			if !identity_captured {
				trace.event(CLUSTER_EXPORT_IDENTITY_UNAVAILABLE)?.emit();
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
/// gateway by the fingerprint of its certificate under that digest, and it
/// digests each rumor and frame witness under it. Every gateway of a colony
/// runs one provider, so each one names a peer and digests a rumor alike.
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

		let config = ColonyConfig::<P>::new(config);

		// The `colony` feature enables `x509`, so the gateway always serves
		// TLS.
		let bind_addr = match config.bind_addr.as_deref() {
			Some(raw) => raw.parse().map_err(|_| TransportError::InvalidMessage)?,
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
		let pools = config.tls.pools::<P>(&config.pool_config, &config.clock);
		let hive_plane = HivePlane::new(pools.hive, Arc::clone(&trace));
		let build_peer_plane = |peer_pool| PeerPlane::new(peer_pool, config.clone(), Arc::clone(&trace));
		let peer_plane = pools.peer.map(build_peer_plane);

		let replay_guard_for_server = GatewayReplayGuard::new(control_window, Arc::clone(&config.clock));
		let tasks = TaskGroup::default();
		let ctx = GatewayRuntimeCtx {
			registry: Arc::clone(&registry),
			servlet_registry: Arc::clone(&servlet_registry),
			admission: Arc::new(Mutex::new(())),
			config: config.clone(),
			hive_plane: hive_plane.clone(),
			peer_plane,
			trace: Arc::clone(&trace),
			replay_guard: replay_guard_for_server,
			tasks: tasks.clone(),
			ledgers: Arc::default(),
		};

		// Bind every configured accept plane before any accept loop spawns.
		// An edge parse or bind failure then returns `Err` while the colony
		// listener is still local, so a failed start spawns no accept task.
		let (edge_listener, edge_addr) = match config.edge_bind_addr.as_deref() {
			Some(raw) => {
				let edge_bind: E::Address = raw.parse().map_err(|_| TransportError::InvalidMessage)?;
				let (edge_listener, edge_addr) = E::bind_with(edge_bind, config.tls.accept_encryption())
					.await
					.map_err(TightBeamError::transport)?;

				(Some(edge_listener), Some(edge_addr))
			}
			None => (None, None),
		};

		// Export posture is colony-wide configuration, so the one startup
		// path reports it once for all accept planes.
		config.warn_export_posture(&trace)?;

		// The gateway decides its advertised address before any task spawns,
		// so a gateway that federates on the wildcard address refuses to start
		// and closes every listener it bound.
		let gateway_bytes: Vec<u8> = addr.clone().into();
		let gateway_addr = config.peer.advertised_address(gateway_bytes)?;

		// Each field of the context is reference-counted, so a clone is cheap.
		let server_handle = ctx.clone().serve_colony::<P::Listener>(listener);

		// The edge plane serves [`EdgeMuxService`], whose only route is work
		// submission.
		let edge_handle = edge_listener.map(|edge_listener| ctx.clone().serve_edge::<E::Listener>(edge_listener));

		tasks.adopt(ctx.clone().spawn_heartbeat());

		// Three missed refreshes retire a relay trail: one miss is churn, and
		// three mean the refresh path died. The default interval floors the
		// TTL, so an aggressive `rumor_refresh` keeps a healthy fallback.
		let relay_trail_ttl = config
			.rumor_refresh()
			.saturating_mul(3)
			.max(Duration::from_millis(DEFAULT_AD_RUMOR_REFRESH_MS));

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
		})
	}

	fn addr(&self) -> &Self::Address {
		&self.addr
	}

	fn available_servlets(&self) -> Result<Vec<SharedId>, ClusterError> {
		// The routes are the one home of the types this gateway serves, so
		// this list follows each instance a hive scales in or out, with no
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
/// - `Local` trail: dial the servlet on the hive plane.
/// - `Peer` trail: splice the stream to the peer gateway (see
///   [`GatewayRuntimeCtx::splice_streaming`] and
///   [`GatewayRuntimeCtx::splice_duplex`]).
///
/// # Export boundary
///
/// Stream and duplex opens pass [`GatewayRuntimeCtx::guard_stream_open`], which
/// applies the Work-arm boundary order before routing.
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
	/// The boundary guard that the streaming and duplex open handlers share.
	///
	/// An open passes the same boundary a unary request passes:
	///
	/// 1. Run [`ClusterConfig::evaluate_gates`] with no request frame.
	/// 2. Resolve the servlet target from the call context.
	/// 3. Derive `relayed` from [`HopBudget::is_relayed`].
	/// 4. Run [`ColonyConfig::evaluate_export_gates`] on that target and session.
	///
	/// An unrouted open names no servlet type, so it fails with
	/// `Unimplemented`.
	fn guard_stream_open(&self, cx: &CallContext) -> Result<(Urn<'static>, HopBudget), TightBeamError> {
		let gate_status = self.config.evaluate_gates(None, cx.session(), &self.trace)?;
		if gate_status != TransitStatus::Ok {
			return Err(gate_status.refusal());
		}

		let Some(target) = cx.target().cloned() else {
			return Err(TightBeamError::unimplemented());
		};

		let budget = HopBudget::from_wire(WireHopBudget::new(cx.hops_remaining()), self.config.peer.max_hops);
		let is_relayed = budget.is_relayed();
		let session = cx.session();
		let config = &self.config;
		let trace = &self.trace;

		let export_status = config.evaluate_export_gates(&target, session, is_relayed, trace)?;
		if export_status != TransitStatus::Ok {
			return Err(export_status.refusal());
		}

		Ok((target, budget))
	}
}

impl<P: GatewayColonyProtocol> GatewayRuntimeCtx<P> {
	/// Serves the colony accept plane through [`GatewayMuxService`].
	///
	/// `L` is the bound listener, which feeds the service over the colony pool
	/// protocol `P`.
	pub(crate) fn serve_colony<L>(self, listener: L) -> rt::JoinHandle
	where
		L: AsyncListenerTrait + Sync + 'static,
		L::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	{
		let mux_offer = self.config.pool_config.mux_offer.as_ref().map(Arc::clone);
		let clock = Arc::clone(&self.config.clock);
		let service = GatewayMuxService::<P> { ctx: self };
		Self::accept_into(listener, mux_offer, clock, service)
	}

	/// Serves an edge accept plane through [`EdgeMuxService`].
	///
	/// The service type restricts the plane to work submission, so the type
	/// alone tells dispatch which plane a request arrived on.
	pub(crate) fn serve_edge<L>(self, listener: L) -> rt::JoinHandle
	where
		L: AsyncListenerTrait + Sync + 'static,
		L::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	{
		let mux_offer = self.config.pool_config.mux_offer.as_ref().map(Arc::clone);
		let clock = Arc::clone(&self.config.clock);
		let service = EdgeMuxService::<P> { ctx: self };
		Self::accept_into(listener, mux_offer, clock, service)
	}

	/// Accepts on `listener` and dispatches every connection through `service`.
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
			// Each accept clones the `Arc`, so it shares the mux offer and
			// copies no authorization octet.
			transport = transport.with_mux_offer(mux_offer.clone());

			let service = Arc::clone(&service);
			async move { serve_connection_service(transport, service, None, None).await }
		}))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::cluster::ClusterTlsConfig;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::crypto::sign::SigningIdentity;
	use crate::crypto::x509::KeyPurposes;
	use crate::testing::{TestCertificate, TestKey};

	// The accept planes hold the gateway's identity to the purposes its TLS
	// config names, so the transport and the colony read one purpose set.
	#[test]
	fn the_accept_planes_take_the_configured_key_purposes() -> Result<(), TightBeamError> {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let certificate = TestCertificate::self_signed(&key);
		let identity = SigningIdentity::new(certificate, Arc::new(Secp256k1KeyProvider::from(key)))?;
		let configured = KeyPurposes { server: KeyPurposes::HOUSE.client, ..KeyPurposes::HOUSE };
		let tls = ClusterTlsConfig::from_identity(identity, configured)?;

		let accept = tls.accept_encryption::<DefaultCryptoProvider>();
		assert_eq!(accept.key_purposes, configured);
		Ok(())
	}
}
