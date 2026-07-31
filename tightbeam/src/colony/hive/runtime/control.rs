//! Hive control-plane accept loop and cluster command handlers.

use core::sync::atomic::{AtomicU16, Ordering};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::colony::common::{
	canonical_bytes, reply_frame, reply_frame_with_priority, ClusterCommand, ClusterCommandResponse,
};
use crate::colony::hive::runtime::{insert_instance, remove_instance, servlet_slate, HiveContextImpl};
use crate::colony::hive::{
	BackpressureGate, HashMapRegistry, HiveManagementRequest, HiveManagementResponse, ServletRegistration,
	ServletRegistry, SpawnerFn,
};
use crate::colony::servlet::servlet_runtime::rt;
use crate::constants::DEFAULT_MAX_SERVER_CONNECTIONS;
use crate::decode;
use crate::macros::server::{into_shared_session_handler, serve_connection, AcceptedConnection};
use crate::policy::{GatePolicy, SessionContext, TransitStatus};
use crate::trace::TraceCollector;
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::multiplex::MuxCapable;
use crate::transport::policy::PolicyConfig;
use crate::transport::{AsyncListenerTrait, Protocol};
use crate::utils::urn::Urn;
use crate::utils::BasisPoints;
use crate::{Frame, MessagePriority, TightBeamError};

#[cfg(feature = "x509")]
use crate::colony::hive::{ClusterCircuitBreaker, ClusterSecurityGate, ReplayGuard};
#[cfg(feature = "x509")]
use crate::crypto::x509::store::CertificateTrust;

/// Shared state for hive control-plane request handling.
pub struct HiveControlCtx<P: Protocol> {
	/// Registry of running servlet instances keyed by instance URN bytes.
	pub servlets: Arc<HashMapRegistry>,
	/// Spawner closures keyed by servlet type URN for scale-up and manage spawn.
	pub spawners: Arc<HashMap<Urn<'static>, SpawnerFn>>,
	/// Trace handle shared with spawned servlets and control-plane events.
	pub trace: Arc<TraceCollector>,
	/// Hive-wide utilization in basis points for heartbeats and backpressure.
	pub utilization: Arc<AtomicU16>,
	/// Per-instance utilization cache when a servlet does not self-report.
	pub utilization_map: Arc<Mutex<HashMap<Vec<u8>, u16>>>,
	/// Instant when drain began; `Some` refuses non-heartbeat manage commands.
	pub draining_since: Arc<RwLock<Option<Instant>>>,
	/// Intra-hive routing context updated as instances are inserted or removed.
	pub hive_context: Arc<HiveContextImpl<P>>,
	/// Utilization threshold that trips [`BackpressureGate`] on manage traffic.
	pub bp_threshold: BasisPoints,
	#[cfg(feature = "x509")]
	/// Circuit breaker shared with [`ClusterSecurityGate`] for auth failures.
	pub circuit_breaker: Arc<ClusterCircuitBreaker>,
	#[cfg(feature = "x509")]
	/// Freshness window and replay set for signed cluster commands.
	pub replay_guard: Arc<ReplayGuard>,
	#[cfg(feature = "x509")]
	/// Trust store for certificate-based cluster command authentication.
	pub trust_store: Option<Arc<dyn CertificateTrust>>,
}

/// Spawn the hive control accept loop that dispatches [`handle_command`].
pub fn spawn_control_server<P>(
	listener: P::Listener,
	mux_offer: Option<TransportOffer>,
	ctx: HiveControlCtx<P>,
) -> rt::JoinHandle
where
	P: Protocol + Send + Sync + 'static,
	P::Listener: AsyncListenerTrait + Sync + 'static,
	<P::Listener as Protocol>::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	P::Address: Clone + Send + Sync + 'static,
	P::Transport: Send + Sync + 'static,
{
	let ctx = Arc::new(ctx);
	let handler = into_shared_session_handler(move |frame: Frame, session| {
		// Arc::clone: refcount bump for the shared control context.
		let ctx = Arc::clone(&ctx);
		async move { handle_command(frame, session, ctx).await }
	});

	rt::spawn(async move {
		let permits = Arc::new(tokio::sync::Semaphore::new(DEFAULT_MAX_SERVER_CONNECTIONS));
		loop {
			let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
				break;
			};
			match listener.accept().await {
				Ok((mut transport, _addr)) => {
					// TODO: MuxCapable stores owned Option<TransportOffer>
					// (small ints + optional token). Arc would not help until
					// the trait accepts a shared handle.
					transport = transport.with_mux_offer(mux_offer.clone());

					let handler = Arc::clone(&handler);
					rt::spawn(async move {
						let _permit = permit;
						serve_connection(transport, handler, None, None).await;
					});
				}
				Err(_) => break,
			}
		}
	})
}

/// Authenticate, gate, and dispatch one cluster command frame.
pub async fn handle_command<P>(
	frame: Frame,
	session: SessionContext,
	ctx: Arc<HiveControlCtx<P>>,
) -> Result<Option<Frame>, TightBeamError>
where
	P: Protocol + Send + Sync + 'static,
	P::Transport: Send + Sync + 'static,
{
	let is_heartbeat = decode::<ClusterCommand>(&frame.message)
		.map(|cmd| cmd.heartbeat.is_some())
		.unwrap_or(false);

	// Security gate runs before drain so unauthenticated peers cannot probe draining.
	#[cfg(feature = "x509")]
	if let Some(reply) = security_gate_reply(&frame, &session, &ctx, is_heartbeat)? {
		return Ok(Some(reply));
	}

	let is_draining = ctx.draining_since.read().map(|g| g.is_some()).unwrap_or(false);

	// Refuse non-heartbeat manage while draining; reply in the manage CHOICE shape.
	if is_draining && !is_heartbeat {
		return reply_frame(
			&frame.metadata.id,
			ClusterCommandResponse::manage(HiveManagementResponse::stop_err(TransitStatus::Unavailable)),
		);
	}

	// Authenticated heartbeats skip backpressure so health checks survive load.
	// Exemption is after the security gate so unauthenticated peers get no bypass.
	if !is_heartbeat {
		if let Some(reply) = backpressure_reply(&frame, &session, &ctx)? {
			return Ok(Some(reply));
		}
	}

	let Ok(cmd) = decode::<ClusterCommand>(&frame.message) else {
		return Ok(None);
	};

	if cmd.heartbeat.is_some() {
		return heartbeat_reply(&frame, &ctx);
	}

	if let Some(manage) = cmd.manage {
		return handle_manage(frame, manage, ctx).await;
	}

	Ok(None)
}

/// Spawn, list, or stop servlets for one management request.
pub async fn handle_manage<P>(
	frame: Frame,
	request: HiveManagementRequest,
	ctx: Arc<HiveControlCtx<P>>,
) -> Result<Option<Frame>, TightBeamError>
where
	P: Protocol + Send + Sync + 'static,
	P::Transport: Send + Sync + 'static,
{
	if let Some(spawn) = request.spawn {
		return manage_spawn(frame, spawn.servlet_type, ctx).await;
	}

	if request.list.is_some() {
		return manage_list(&frame, &ctx);
	}

	if let Some(stop) = request.stop {
		return manage_stop(frame, stop.servlet_id, ctx);
	}

	Ok(None)
}

#[cfg(feature = "x509")]
fn security_gate_reply<P>(
	frame: &Frame,
	session: &SessionContext,
	ctx: &HiveControlCtx<P>,
	is_heartbeat: bool,
) -> Result<Option<Frame>, TightBeamError>
where
	P: Protocol,
{
	let security_status = match &ctx.trust_store {
		Some(store) => {
			let gate = ClusterSecurityGate::new(
				Arc::clone(&ctx.circuit_breaker),
				Arc::clone(store),
				Arc::clone(&ctx.replay_guard),
			);
			GatePolicy::evaluate(&gate, Some(frame), session)
		}
		None => TransitStatus::PermissionDenied,
	};

	if security_status == TransitStatus::Ok {
		return Ok(None);
	}

	// Reject in the CHOICE shape the sender decodes (heartbeat vs manage).
	// A mismatched shape counts as MalformedResponse and can evict the hive.
	if is_heartbeat {
		return reply_frame_with_priority(
			&frame.metadata.id,
			MessagePriority::NetworkControl,
			ClusterCommandResponse::heartbeat(security_status, BasisPoints::default(), 0),
		);
	}

	reply_frame(
		&frame.metadata.id,
		ClusterCommandResponse::manage(HiveManagementResponse::stop_err(security_status)),
	)
}

fn backpressure_reply<P>(
	frame: &Frame,
	session: &SessionContext,
	ctx: &HiveControlCtx<P>,
) -> Result<Option<Frame>, TightBeamError>
where
	P: Protocol,
{
	let bp_gate = BackpressureGate::new(Arc::clone(&ctx.utilization), ctx.bp_threshold);
	if GatePolicy::evaluate(&bp_gate, Some(frame), session) != TransitStatus::ResourceExhausted {
		return Ok(None);
	}

	reply_frame(
		&frame.metadata.id,
		ClusterCommandResponse::manage(HiveManagementResponse::stop_err(TransitStatus::ResourceExhausted)),
	)
}

fn heartbeat_reply<P>(frame: &Frame, ctx: &HiveControlCtx<P>) -> Result<Option<Frame>, TightBeamError>
where
	P: Protocol,
{
	let util = BasisPoints::new_saturating(ctx.utilization.load(Ordering::Relaxed));
	let status = if util.get() >= ctx.bp_threshold.get() {
		TransitStatus::ResourceExhausted
	} else {
		TransitStatus::Ok
	};
	let active_count = ctx.servlets.count() as u32;

	reply_frame_with_priority(
		&frame.metadata.id,
		MessagePriority::NetworkControl,
		ClusterCommandResponse::heartbeat(status, util, active_count),
	)
}

async fn manage_spawn<P>(
	frame: Frame,
	servlet_type: Urn<'static>,
	ctx: Arc<HiveControlCtx<P>>,
) -> Result<Option<Frame>, TightBeamError>
where
	P: Protocol + Send + Sync + 'static,
	P::Transport: Send + Sync + 'static,
{
	let spawn_denied = || {
		forget_replay(&frame, &ctx);
		reply_frame(
			&frame.metadata.id,
			ClusterCommandResponse::manage(HiveManagementResponse::spawn_err(TransitStatus::PermissionDenied)),
		)
	};

	let Some(spawner) = ctx.spawners.get(&servlet_type) else {
		return spawn_denied();
	};

	let Ok(new_servlet) = spawner(Arc::clone(&ctx.trace)).await else {
		return spawn_denied();
	};

	let registration = ServletRegistration { servlet: new_servlet, spawner: Arc::clone(spawner), servlet_type };

	let Ok((instance, addr_bytes)) = insert_instance(&*ctx.servlets, &*ctx.hive_context, registration) else {
		return spawn_denied();
	};

	// Real copy: manage response carries owned address bytes.
	let address = addr_bytes.as_ref().to_vec();
	reply_frame(
		&frame.metadata.id,
		ClusterCommandResponse::manage(HiveManagementResponse::spawn_ok(address, instance)),
	)
}

fn manage_list<P>(frame: &Frame, ctx: &HiveControlCtx<P>) -> Result<Option<Frame>, TightBeamError>
where
	P: Protocol,
{
	let list = servlet_slate(&*ctx.servlets);
	reply_frame(
		&frame.metadata.id,
		ClusterCommandResponse::manage(HiveManagementResponse::list_ok(list)),
	)
}

fn manage_stop<P>(
	frame: Frame,
	servlet_id: Urn<'static>,
	ctx: Arc<HiveControlCtx<P>>,
) -> Result<Option<Frame>, TightBeamError>
where
	P: Protocol,
{
	let id_bytes = canonical_bytes(&servlet_id);
	if remove_instance(&*ctx.servlets, &*ctx.hive_context, &id_bytes).is_some() {
		return reply_frame(
			&frame.metadata.id,
			ClusterCommandResponse::manage(HiveManagementResponse::stop_ok()),
		);
	}

	forget_replay(&frame, &ctx);

	reply_frame(
		&frame.metadata.id,
		ClusterCommandResponse::manage(HiveManagementResponse::stop_err(TransitStatus::PermissionDenied)),
	)
}

fn forget_replay<P>(_frame: &Frame, _ctx: &HiveControlCtx<P>)
where
	P: Protocol,
{
	#[cfg(feature = "x509")]
	if let Some(signer_info) = _frame.nonrepudiation.as_ref() {
		_ctx.replay_guard.forget(signer_info.signature.as_bytes());
	}
}
