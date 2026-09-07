//! Hive control-plane accept loop and cluster command handlers.

use core::sync::atomic::{AtomicU16, Ordering};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::colony::common::{
	canonical_bytes, reply_frame, reply_frame_with_priority, ClusterCommand, ClusterCommandResponse, DrainMode,
};
use crate::colony::hive::runtime::{HiveContextImpl, HiveInstances};
use crate::colony::hive::{
	BackpressureGate, HashMapRegistry, HiveManagementRequest, HiveManagementResponse, ServletRegistration,
	ServletRegistry, SpawnerFn,
};
use crate::colony::servlet::servlet_runtime::rt;
use crate::decode;
use crate::macros::server::{into_shared_session_handler, serve_connection, AcceptedConnection};
use crate::policy::{GatePolicy, SessionContext, TransitStatus};
use crate::trace::TraceCollector;
use crate::transport::accept::AcceptPlane;
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::multiplex::MuxCapable;
use crate::transport::policy::PolicyConfig;
use crate::transport::{AsyncListenerTrait, Protocol};
use crate::utils::urn::Urn;
use crate::utils::BasisPoints;
use crate::{Frame, MessagePriority, TightBeamError};

use crate::colony::hive::{ClusterCircuitBreaker, ClusterSecurityGate, ReplayGuard};
use crate::crypto::x509::store::CertificateTrust;

/// Shared state for hive control-plane request handling.
/// Commands currently being handled.
///
/// A drain waits on this: a control connection idles between commands by
/// design, so an open connection counts as work only while it holds a
/// command.
#[derive(Clone, Default)]
pub struct InFlight(Arc<core::sync::atomic::AtomicUsize>);

impl InFlight {
	/// Counts one command for as long as the returned guard lives.
	pub fn enter(&self) -> InFlightGuard {
		self.0.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
		InFlightGuard(Arc::clone(&self.0))
	}

	/// Whether no command is currently being handled.
	pub fn is_idle(&self) -> bool {
		self.0.load(core::sync::atomic::Ordering::Acquire) == 0
	}
}

/// Releases its count on drop, so an early return still settles the drain.
pub struct InFlightGuard(Arc<core::sync::atomic::AtomicUsize>);

impl Drop for InFlightGuard {
	fn drop(&mut self) {
		self.0.fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
	}
}

pub struct HiveControlCtx<P: Protocol> {
	/// Registry of running servlet instances keyed by instance URN bytes.
	pub servlets: Arc<HashMapRegistry>,
	/// Spawner closures keyed by servlet type URN for scale-up and manage spawn.
	pub spawners: Arc<HashMap<Urn<'static>, SpawnerFn>>,
	/// Trace handle shared with spawned servlets and control-plane events.
	pub trace: Arc<TraceCollector>,
	/// Hive-wide utilization in basis points for heartbeats and backpressure.
	pub utilization: Arc<AtomicU16>,
	/// Per-instance utilization cache for a servlet that reports none.
	pub utilization_map: Arc<Mutex<HashMap<Vec<u8>, u16>>>,
	/// Drain state. Draining refuses every manage command but the heartbeat.
	pub drain: DrainMode,
	/// Commands in flight, which a drain waits to reach zero.
	pub in_flight: InFlight,
	/// Intra-hive routing context updated as instances are inserted or removed.
	pub hive_context: Arc<HiveContextImpl<P>>,
	/// Utilization threshold that trips [`BackpressureGate`] on manage traffic.
	pub bp_threshold: BasisPoints,
	/// Circuit breaker shared with [`ClusterSecurityGate`] for auth failures.
	pub circuit_breaker: Arc<ClusterCircuitBreaker>,
	/// Freshness window and replay set for signed cluster commands.
	pub replay_guard: Arc<ReplayGuard>,
	/// Trust store for certificate-based cluster command authentication.
	pub trust_store: Option<Arc<dyn CertificateTrust>>,
}

impl<P> HiveControlCtx<P>
where
	P: Protocol + Send + Sync + 'static,
	P::Listener: AsyncListenerTrait + Sync + 'static,
	<P::Listener as Protocol>::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	P::Address: Clone + Send + Sync + 'static,
	P::Transport: Send + Sync + 'static,
{
	/// Serves the hive control plane on `listener`.
	///
	/// Each accepted connection dispatches through
	/// [`HiveControlCtx::handle_command`] against this context.
	pub fn serve(self, listener: P::Listener, mux_offer: Option<Arc<TransportOffer>>) -> rt::JoinHandle {
		let ctx = Arc::new(self);
		let handler = into_shared_session_handler(move |frame: Frame, session| {
			let ctx = Arc::clone(&ctx);
			async move { ctx.handle_command(frame, session).await }
		});

		rt::spawn(AcceptPlane::default().accept_on(
			listener,
			move |mut transport: <P::Listener as Protocol>::Transport| {
				// Share the mux offer with each accepted control connection.
				transport = transport.with_mux_offer(mux_offer.clone());

				let handler = Arc::clone(&handler);
				async move { serve_connection(transport, handler, None, None).await }
			},
		))
	}
}

impl<P> HiveControlCtx<P>
where
	P: Protocol + Send + Sync + 'static,
	P::Transport: Send + Sync + 'static,
{
	/// Authenticate, gate, and dispatch one cluster command frame.
	pub async fn handle_command(
		self: Arc<Self>,
		frame: Frame,
		session: SessionContext,
	) -> Result<Option<Frame>, TightBeamError> {
		let ctx = self;
		let _in_flight = ctx.in_flight.enter();

		let is_heartbeat = decode::<ClusterCommand>(&frame.message)
			.map(|cmd| cmd.heartbeat.is_some())
			.unwrap_or(false);

		// Security gate runs before drain so drain state answers authenticated peers.
		if let Some(reply) = security_gate_reply(&frame, &session, &ctx, is_heartbeat)? {
			return Ok(Some(reply));
		}

		// Refuse non-heartbeat manage while draining, in the manage CHOICE shape.
		if ctx.drain.is_draining() && !is_heartbeat {
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
			return ctx.handle_manage(frame, manage).await;
		}

		Ok(None)
	}

	/// Spawn, list, or stop servlets for one management request.
	pub async fn handle_manage(
		self: Arc<Self>,
		frame: Frame,
		request: HiveManagementRequest,
	) -> Result<Option<Frame>, TightBeamError> {
		let ctx = self;
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
}

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
	let active_count = ctx.servlets.count() as u32;
	let status = if util.get() >= ctx.bp_threshold.get() {
		TransitStatus::ResourceExhausted
	} else {
		TransitStatus::Ok
	};

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
	let instances = HiveInstances::new(&ctx.servlets, &ctx.hive_context);
	let Ok((instance, addr_bytes)) = instances.insert(registration) else {
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
	let list = ctx.servlets.slate();
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
	let instances = HiveInstances::new(&ctx.servlets, &ctx.hive_context);
	if instances.remove(&id_bytes).is_some() {
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
	if let Some(signer_info) = _frame.nonrepudiation.as_ref() {
		_ctx.replay_guard.forget(signer_info.signature.as_bytes());
	}
}
