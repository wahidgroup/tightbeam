//! Cluster gateway runtime: accept loop, background tasks, and mux routing.
//!
//! [`ClusterGateway`] owns the listener, heartbeat, evaporation, and advertise
//! tasks. Incoming connections are served through [`GatewayMuxService`], which
//! routes unary control frames to dispatch and splices streamed or duplex
//! opens by servlet target.
//!
//! # Export posture
//!
//! [`spawn_gateway_server`] calls [`warn_export_posture`] once before the
//! accept loop starts. Stream and duplex handlers enforce the same export
//! boundary as the unary Work arm through
//! [`super::verify::evaluate_export_gates`] (allowlist, grants, and gates).

use core::future::Future;
use core::marker::PhantomData;
use core::time::Duration;
use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::colony::cluster::outbound::build_cluster_pools;
use crate::colony::cluster::runtime::bounds::{
	ClusterDigest, ClusterPool, GatewayAcceptProtocol, GatewayColonyProtocol, GatewayPlane, GatewayRuntimeCtx,
};
use crate::colony::cluster::runtime::dispatch::handle_gateway_request;
use crate::colony::cluster::runtime::gossip_tasks::{build_advertise_task, peer_dial_pool};
use crate::colony::cluster::runtime::heartbeat::{send_heartbeat_async, spawn_evaporation_loop, spawn_heartbeat_loop};
use crate::colony::cluster::runtime::streaming::{refuse, splice_duplex, splice_streaming};
use crate::colony::cluster::runtime::verify::{evaluate_export_gates, evaluate_gates, spent_relay_budget};
use crate::colony::cluster::{
	Cluster, ClusterConfig, ClusterError, ClusterHeartbeat, HeartbeatConfig, HiveRegistry, PeerRouteInfo,
	ServletRegistry, SharedId,
};
use crate::colony::common::{take_and_abort, HeartbeatResult};
use crate::colony::servlet::servlet_runtime::rt;
use crate::constants::{DEFAULT_AD_RUMOR_REFRESH_MS, DEFAULT_MAX_SERVER_CONNECTIONS};
use crate::crypto::hash::Sha3_256;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::crypto::x509::Certificate;
use crate::macros::server::{serve_connection_service, AcceptedConnection};
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::transport::handshake::HandshakeKeyManager;
use crate::transport::multiplex::{MuxCapable, ReplySink, StreamBody};
use crate::transport::policy::PolicyConfig;
use crate::transport::serve::{unimplemented_error, CallContext, MuxService};
use crate::transport::{AsyncListenerTrait, Protocol, TransportEncryptionConfig, TransportError};
use crate::utils::urn::Urn;
use crate::Frame;
use crate::TightBeamError;

#[cfg(feature = "x509")]
use crate::colony::hive::ReplayGuard;
#[cfg(feature = "x509")]
use crate::instrumentation::events::{CLUSTER_EXPORT_IDENTITY_UNAVAILABLE, CLUSTER_EXPORT_UNBOUNDED};

/// Emit one-time export-posture warnings when the gateway starts.
///
/// Two configurations weaken the organization edge without an explicit operator
/// choice at request time, so the gateway surfaces each condition once for
/// audit.
///
/// # Warnings
///
/// - Federated gateway with no export list: serves and advertises every local
///   type to external peers ([`CLUSTER_EXPORT_UNBOUNDED`]).
/// - Export list without captured client identity: every session stays
///   anonymous, so unexported targets are unreachable from the origin plane
///   as well ([`CLUSTER_EXPORT_IDENTITY_UNAVAILABLE`]).
///
/// # Sources
///
/// - NIST SP 800-53 Rev. 5 CM-6, configuration settings:
///   <https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#/control?version=5.1&number=CM-6>
#[cfg(feature = "x509")]
fn warn_export_posture(config: &ClusterConfig, trace: &TraceCollector) {
	let federation_active = config.tls.peer_trust.is_some() || !config.peer.peers.is_empty();
	match config.peer.exported_types.as_ref() {
		None => {
			if federation_active {
				if let Ok(event) = trace.event(CLUSTER_EXPORT_UNBOUNDED) {
					event.emit();
				}
			}
		}
		Some(_) => {
			let identity_captured = !config.tls.client_validators.is_empty() && config.tls.hive_trust.is_some();
			if !identity_captured {
				if let Ok(event) = trace.event(CLUSTER_EXPORT_IDENTITY_UNAVAILABLE) {
					event.emit();
				}
			}
		}
	}
}

#[cfg(not(feature = "x509"))]
fn warn_export_posture(config: &ClusterConfig, trace: &TraceCollector) {
	let _ = (config, trace);
}

/// Assemble the accept-side TLS configuration shared by the colony and
/// edge listeners.
///
/// Both planes present the same certificate and key so an external edge
/// client pins the same gateway identity that hives already trust. An
/// empty `client_validators` list means server-auth only.
#[cfg(feature = "x509")]
fn accept_encryption_config(
	config: &ClusterConfig,
) -> Result<TransportEncryptionConfig<DefaultCryptoProvider>, TightBeamError> {
	let cert_obj = Certificate::try_from(config.tls.certificate.clone())?;
	let key_mgr = HandshakeKeyManager::new(Arc::clone(&config.tls.key));
	let mut encryption_config = TransportEncryptionConfig::new(cert_obj, key_mgr);
	if !config.tls.client_validators.is_empty() {
		let validators: Vec<_> = config.tls.client_validators.iter().map(Arc::clone).collect();
		encryption_config = encryption_config.with_client_validators(validators);
	}

	Ok(encryption_config)
}

fn protocol_error<E: Into<TransportError>>(error: E) -> TightBeamError {
	TightBeamError::from(error.into())
}

/// Running cluster gateway for protocol `P`, digest `D`, and edge
/// protocol `E`.
///
/// Owns the accept, heartbeat, evaporation, and advertise tasks for the
/// colony bind address and, when configured, a second edge accept plane.
/// Callers reach cluster state only through [`Cluster`] and
/// [`ClusterHeartbeat`].
///
/// # Edge accept plane
///
/// `E` defaults to `P`, so a gateway without an edge declaration uses a
/// single accept plane. When [`ClusterConfig::edge_bind_addr`] is set, the
/// gateway binds a second listener over `E` with the same TLS material.
/// Edge connections share the colony mux service but dispatch on the
/// edge plane, which admits `Work` frames only. Hives and peers keep
/// using the colony plane at [`Cluster::addr`].
pub struct ClusterGateway<P, D = Sha3_256, E = P>
where
	P: Protocol,
	E: Protocol,
{
	registry: Arc<HiveRegistry>,
	servlet_registry: Arc<ServletRegistry>,
	config: Arc<ClusterConfig>,
	pool: Arc<ClusterPool<P>>,
	server_handle: Option<rt::JoinHandle>,
	edge_handle: Option<rt::JoinHandle>,
	heartbeat_handle: Option<rt::JoinHandle>,
	evaporation_handle: Option<rt::JoinHandle>,
	advertise_handle: Option<rt::JoinHandle>,
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
		take_and_abort(&mut self.advertise_handle);
		take_and_abort(&mut self.evaporation_handle);
		take_and_abort(&mut self.heartbeat_handle);
		take_and_abort(&mut self.edge_handle);
		take_and_abort(&mut self.server_handle);
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
		// The admission freshness window MUST NOT outlive journal retention
		// (CWE-294). A rumor older than retention has no digest left, so a
		// wider window would re-admit a replay as new. The clamp runs before
		// config is wrapped in Arc, so callers cannot widen the window afterward.
		#[cfg(feature = "x509")]
		let config = {
			let mut config = config;
			let retention = Duration::from_millis(config.gossip.journal.retention_ms());
			if config.gossip.seen_ttl > retention {
				config.gossip.seen_ttl = retention;
			}

			config
		};

		let config = Arc::new(config);

		// When x509 is enabled, the gateway always serves TLS. An empty
		// client_validators list means server-auth only (no captured identity).
		let bind_addr = match config.bind_addr.as_deref() {
			Some(raw) => raw.parse().map_err(|_| TransportError::InvalidMessage)?,
			None => P::default_bind_address().map_err(protocol_error)?,
		};

		#[cfg(feature = "x509")]
		let (listener, addr) = P::bind_with(bind_addr, accept_encryption_config(&config)?)
			.await
			.map_err(protocol_error)?;

		#[cfg(not(feature = "x509"))]
		let (listener, addr) = P::bind(bind_addr).await.map_err(protocol_error)?;

		let registry = Arc::new(HiveRegistry::new(config.heartbeat.timeout));
		let servlet_registry = Arc::new(
			ServletRegistry::new(config.pheromone.clone())
				.with_ad_tombstone_window_ms(config.control_freshness_window_ms),
		);

		let pools = build_cluster_pools::<P>(config.pool_config.clone(), &config.tls)?;
		let pool = pools.hive;
		let peer_pool = pools.peer;

		#[cfg(feature = "x509")]
		let replay_guard_for_server = Arc::new(ReplayGuard::new(config.control_freshness_window_ms));
		#[cfg(not(feature = "x509"))]
		let replay_guard_for_server = ();

		let ctx = GatewayRuntimeCtx {
			registry: Arc::clone(&registry),
			servlet_registry: Arc::clone(&servlet_registry),
			config: Arc::clone(&config),
			pool: Arc::clone(&pool),
			peer_pool: peer_pool.as_ref().map(Arc::clone),
			trace: Arc::clone(&trace),
			replay_guard: replay_guard_for_server,
		};

		// Bind every configured accept plane before spawning any accept
		// loop. An edge parse or bind failure returns Err with the colony
		// listener still local, so no detached accept task remains.
		let (edge_listener, edge_addr) = match config.edge_bind_addr.as_deref() {
			Some(raw) => {
				let edge_bind: E::Address = raw.parse().map_err(|_| TransportError::InvalidMessage)?;

				#[cfg(feature = "x509")]
				let (edge_listener, edge_addr) = E::bind_with(edge_bind, accept_encryption_config(&config)?)
					.await
					.map_err(protocol_error)?;

				#[cfg(not(feature = "x509"))]
				let (edge_listener, edge_addr) = E::bind(edge_bind).await.map_err(protocol_error)?;

				(Some(edge_listener), Some(edge_addr))
			}
			None => (None, None),
		};

		// The context is all Arc::clone
		let server_handle = spawn_gateway_server::<P, P::Listener, D>(listener, ctx.clone(), GatewayPlane::Colony);

		// The edge plane serves the same mux service restricted to Work
		// dispatch (see [`GatewayPlane`]).
		let edge_handle = edge_listener.map(|edge_listener| {
			// The context is all Arc::clone
			spawn_gateway_server::<P, E::Listener, D>(edge_listener, ctx.clone(), GatewayPlane::Edge)
		});

		let heartbeat_handle = spawn_heartbeat_loop::<P, D>(
			Arc::clone(&registry),
			Arc::clone(&servlet_registry),
			Arc::clone(&config),
			Arc::clone(&pool),
			Arc::clone(&trace),
		);

		// Three refresh intervals of silence retire a relay trail: one missed
		// refresh is churn, three means the refresh path died. The default
		// refresh interval floors the TTL, so an aggressive `rumor_refresh`
		// cannot churn healthy fallbacks.
		let relay_trail_ttl = config
			.peer
			.rumor_refresh
			.saturating_mul(3)
			.max(Duration::from_millis(DEFAULT_AD_RUMOR_REFRESH_MS));
		let evaporation_handle = spawn_evaporation_loop(
			Arc::clone(&servlet_registry),
			config.pheromone.evaporation_interval,
			relay_trail_ttl,
			Arc::clone(&trace),
		);

		#[cfg(feature = "x509")]
		let advertise_handle = {
			let advertise_pool = peer_dial_pool(&peer_pool, &pool);
			let gateway_bytes: Vec<u8> = addr.clone().into();
			let gateway_addr: Arc<[u8]> = Arc::from(gateway_bytes);
			Some(build_advertise_task::<P, D>(
				Arc::clone(&servlet_registry),
				advertise_pool,
				Arc::clone(&pool),
				Arc::clone(&config),
				gateway_addr,
				Arc::clone(&trace),
			))
		};
		#[cfg(not(feature = "x509"))]
		let advertise_handle = None;

		Ok(Self {
			registry,
			servlet_registry,
			config,
			pool,
			server_handle: Some(server_handle),
			edge_handle,
			heartbeat_handle: Some(heartbeat_handle),
			evaporation_handle: Some(evaporation_handle),
			advertise_handle,
			addr,
			edge_addr,
			trace,
			_digest: PhantomData,
		})
	}

	fn addr(&self) -> &Self::Address {
		&self.addr
	}

	fn available_servlets(&self) -> Vec<SharedId> {
		self.registry.to_available_servlets().unwrap_or_default()
	}

	fn peer_servlets(&self) -> Vec<SharedId> {
		let mut types: Vec<SharedId> = self
			.servlet_registry
			.peer_entries()
			.unwrap_or_default()
			.into_iter()
			.map(|entry| Arc::clone(entry.servlet_type()))
			.collect();
		types.sort_unstable();
		types.dedup();
		types
	}

	fn peer_routes(&self) -> Vec<PeerRouteInfo> {
		self.servlet_registry
			.peer_entries()
			.unwrap_or_default()
			.into_iter()
			.filter_map(|entry| entry.peer_route_info())
			.collect()
	}

	fn hive_count(&self) -> usize {
		self.registry.len().unwrap_or(0)
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
		send_heartbeat_async::<P, D>(Arc::clone(&self.pool), Arc::clone(&self.config), addr).await
	}
}

impl<P, D, E> Drop for ClusterGateway<P, D, E>
where
	P: Protocol,
	E: Protocol,
{
	fn drop(&mut self) {
		take_and_abort(&mut self.advertise_handle);
		take_and_abort(&mut self.evaporation_handle);
		take_and_abort(&mut self.heartbeat_handle);
		take_and_abort(&mut self.edge_handle);
		take_and_abort(&mut self.server_handle);
	}
}

/// Gateway implementation of [`MuxService`].
///
/// Unary frames route through cluster dispatch. Streamed and duplex opens route
/// by the target [`Urn`] on their [`CallContext`].
///
/// # Routing
///
/// - `Local` trail: dial the servlet on the hive plane.
/// - `Peer` trail: splice the stream to the peer gateway (see
///   [`splice_streaming`] and [`splice_duplex`]).
///
/// # Export boundary
///
/// Stream and duplex opens refuse on [`GatewayPlane::Edge`] before any
/// gate or route work. On the colony plane they share the Work-arm
/// boundary order:
///
/// 1. [`evaluate_gates`] before routing.
/// 2. Resolve the servlet target from the call context.
/// 3. Derive `relayed` from [`spent_relay_budget`].
/// 4. [`evaluate_export_gates`] (allowlist, grants, then deny gates).
struct GatewayMuxService<P, D>
where
	P: Protocol,
{
	ctx: GatewayRuntimeCtx<P>,
	plane: GatewayPlane,
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
		let plane = self.plane;
		async move { handle_gateway_request::<P, D>(frame, cx.into_session(), ctx, plane).await }
	}

	fn streaming(
		&self,
		body: StreamBody,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let ctx = self.ctx.clone();
		let plane = self.plane;
		async move {
			let target = guard_stream_open(&cx, &ctx, plane)?;
			splice_streaming::<P>(body, target, cx.hops_remaining(), ctx).await
		}
	}

	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		cx: CallContext,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send {
		let ctx = self.ctx.clone();
		let plane = self.plane;
		async move {
			let target = guard_stream_open(&cx, &ctx, plane)?;

			splice_duplex::<P>(body, reply, target, cx.hops_remaining(), ctx).await
		}
	}
}

/// Boundary guard shared by the streaming and duplex open handlers.
///
/// The edge accept plane admits unary `Work` only, so stream and duplex
/// opens refuse there before any gate or route work. On the colony
/// plane, evaluation mirrors the unary Work arm:
///
/// 1. [`evaluate_gates`] with no request frame.
/// 2. Resolve the servlet target from the call context.
/// 3. Derive `relayed` from [`spent_relay_budget`].
/// 4. [`evaluate_export_gates`] on that target and session.
///
/// An unrouted open names no servlet type, so it fails with `Unimplemented`.
fn guard_stream_open<P>(
	cx: &CallContext,
	ctx: &GatewayRuntimeCtx<P>,
	plane: GatewayPlane,
) -> Result<Urn<'static>, TightBeamError>
where
	P: Protocol,
{
	if plane == GatewayPlane::Edge {
		return Err(refuse(TransitStatus::PermissionDenied));
	}

	if let Err(status) = evaluate_gates(None, cx.session(), &ctx.config, &ctx.trace) {
		return Err(refuse(status));
	}

	let Some(target) = cx.target().cloned() else {
		return Err(unimplemented_error());
	};

	let relayed = spent_relay_budget(cx.hops_remaining());
	if let Err(status) = evaluate_export_gates(&target, cx.session(), relayed, &ctx.config, &ctx.trace) {
		return Err(refuse(status));
	}

	Ok(target)
}

/// Backoff after one failed accept before the loop resumes.
///
/// A refused handshake or a transient socket fault (for example EMFILE)
/// MUST NOT kill the accept loop, but resuming without delay would spin
/// the task hot on a persistent bind-level fault.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Bind the accept loop that admits peers and dispatches control frames.
///
/// `L` is the listener actually bound: the colony protocol listener or the
/// edge protocol listener. Both feed the same [`GatewayMuxService`] over
/// the colony pool protocol `P`. Colony accepts call [`warn_export_posture`]
/// once before the loop starts. Each admitted transport shares one mux offer
/// by reference count.
pub(crate) fn spawn_gateway_server<P, L, D>(
	listener: L,
	ctx: GatewayRuntimeCtx<P>,
	plane: GatewayPlane,
) -> rt::JoinHandle
where
	P: GatewayColonyProtocol,
	L: AsyncListenerTrait + Sync + 'static,
	L::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	D: ClusterDigest,
{
	// The posture concerns colony-wide export configuration, so it is
	// reported once, not once per accept plane.
	if plane == GatewayPlane::Colony {
		warn_export_posture(&ctx.config, &ctx.trace);
	}

	let mux_offer = ctx.config.pool_config.mux_offer.as_ref().map(Arc::clone);
	let service = Arc::new(GatewayMuxService::<P, D> { ctx, plane, _digest: PhantomData });

	rt::spawn(async move {
		let permits = Arc::new(Semaphore::new(DEFAULT_MAX_SERVER_CONNECTIONS));
		loop {
			let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
				break;
			};
			// let-else drops the failed accept (and its non-Send error)
			// before the backoff await, so the loop future stays Send.
			let Ok((mut transport, _addr)) = listener.accept().await else {
				rt::sleep(ACCEPT_ERROR_BACKOFF).await;
				continue;
			};

			// Clone the Arc so each accept shares the mux offer without
			// copying authorization octets.
			transport = transport.with_mux_offer(mux_offer.clone());

			let service = Arc::clone(&service);
			rt::spawn(async move {
				let _permit = permit;
				serve_connection_service(transport, service, None, None).await;
			});
		}
	})
}
