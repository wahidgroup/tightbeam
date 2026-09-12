//! Hive control-plane accept loop and cluster command handlers.

use core::sync::atomic::{AtomicU16, Ordering};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::colony::common::{
	reply_frame, reply_frame_with_priority, ClusterCommand, ClusterCommandResponse, DrainMode,
};
use crate::colony::hive::runtime::{HiveContextImpl, HiveInstances};
use crate::colony::hive::{
	BackpressureGate, HashMapRegistry, HiveManagementRequest, HiveManagementResponse, ServletRegistration,
	ServletRegistry, SpawnerFn,
};
use crate::colony::servlet::servlet_runtime::rt;
use crate::decode;
use crate::macros::server::{serve_connection, AcceptedConnection, SharedHandler};
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
		let handler = SharedHandler::from(move |frame: Frame, session| {
			let ctx = Arc::clone(&ctx);
			async move { ctx.handle_command(frame, session).await }
		});

		rt::spawn(AcceptPlane::default().accept_on(
			listener,
			move |mut transport: <P::Listener as Protocol>::Transport| {
				// Share the mux offer with each accepted control connection.
				transport = transport.with_mux_offer(mux_offer.clone());

				let handler = handler.clone();
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
		if let Some(reply) = ctx.security_gate_reply(&frame, &session, is_heartbeat)? {
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
			if let Some(reply) = ctx.backpressure_reply(&frame, &session)? {
				return Ok(Some(reply));
			}
		}

		let Ok(cmd) = decode::<ClusterCommand>(&frame.message) else {
			return Ok(None);
		};

		if cmd.heartbeat.is_some() {
			return ctx.heartbeat_reply(&frame);
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
			return ctx.manage_spawn(frame, spawn.servlet_type).await;
		}

		if request.list.is_some() {
			return ctx.manage_list(&frame);
		}

		if let Some(stop) = request.stop {
			return ctx.manage_stop(frame, stop.servlet_id);
		}

		Ok(None)
	}
}

impl<P: Protocol> HiveControlCtx<P> {
	fn security_gate_reply(
		&self,
		frame: &Frame,
		session: &SessionContext,
		is_heartbeat: bool,
	) -> Result<Option<Frame>, TightBeamError>
	where
		P: Protocol,
	{
		let security_status = match &self.trust_store {
			Some(store) => {
				let gate = ClusterSecurityGate::new(
					Arc::clone(&self.circuit_breaker),
					Arc::clone(store),
					Arc::clone(&self.replay_guard),
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

		let response = HiveManagementResponse::stop_err(security_status);
		let response = ClusterCommandResponse::manage(response);
		reply_frame(&frame.metadata.id, response)
	}

	fn backpressure_reply(&self, frame: &Frame, session: &SessionContext) -> Result<Option<Frame>, TightBeamError>
	where
		P: Protocol,
	{
		let bp_gate = BackpressureGate::new(Arc::clone(&self.utilization), self.bp_threshold);
		if GatePolicy::evaluate(&bp_gate, Some(frame), session) != TransitStatus::ResourceExhausted {
			return Ok(None);
		}

		let response = HiveManagementResponse::stop_err(TransitStatus::ResourceExhausted);
		let response = ClusterCommandResponse::manage(response);
		reply_frame(&frame.metadata.id, response)
	}

	fn heartbeat_reply(&self, frame: &Frame) -> Result<Option<Frame>, TightBeamError>
	where
		P: Protocol,
	{
		let util = BasisPoints::new_saturating(self.utilization.load(Ordering::Relaxed));
		let active_count = self.servlets.count() as u32;
		let status = if util.get() >= self.bp_threshold.get() {
			TransitStatus::ResourceExhausted
		} else {
			TransitStatus::Ok
		};

		let response = ClusterCommandResponse::heartbeat(status, util, active_count);
		reply_frame_with_priority(&frame.metadata.id, MessagePriority::NetworkControl, response)
	}

	async fn manage_spawn(
		self: Arc<Self>,
		frame: Frame,
		servlet_type: Urn<'static>,
	) -> Result<Option<Frame>, TightBeamError>
	where
		P: Protocol + Send + Sync + 'static,
		P::Transport: Send + Sync + 'static,
	{
		let spawn_denied = || {
			self.forget_replay(&frame);
			reply_frame(
				&frame.metadata.id,
				ClusterCommandResponse::manage(HiveManagementResponse::spawn_err(TransitStatus::PermissionDenied)),
			)
		};

		let Some(spawner) = self.spawners.get(&servlet_type) else {
			return spawn_denied();
		};

		let Ok(new_servlet) = spawner(Arc::clone(&self.trace)).await else {
			return spawn_denied();
		};

		let registration = ServletRegistration { servlet: new_servlet, spawner: Arc::clone(spawner), servlet_type };
		let instances = HiveInstances::new(&self.servlets, &self.hive_context);
		let Ok((instance, addr_bytes)) = instances.insert(registration) else {
			return spawn_denied();
		};

		// Real copy: manage response carries owned address bytes.
		let address = addr_bytes.as_ref().to_vec();
		let response = HiveManagementResponse::spawn_ok(address, instance);
		let response = ClusterCommandResponse::manage(response);
		reply_frame(&frame.metadata.id, response)
	}

	fn manage_list(&self, frame: &Frame) -> Result<Option<Frame>, TightBeamError>
	where
		P: Protocol,
	{
		let list = self.servlets.slate();
		let response = HiveManagementResponse::list_ok(list);
		let response = ClusterCommandResponse::manage(response);
		reply_frame(&frame.metadata.id, response)
	}

	fn manage_stop(self: Arc<Self>, frame: Frame, servlet_id: Urn<'static>) -> Result<Option<Frame>, TightBeamError>
	where
		P: Protocol,
	{
		let id_bytes = servlet_id.canonical_bytes();
		let instances = HiveInstances::new(&self.servlets, &self.hive_context);
		if instances.remove(&id_bytes).is_some() {
			return reply_frame(
				&frame.metadata.id,
				ClusterCommandResponse::manage(HiveManagementResponse::stop_ok()),
			);
		}

		self.forget_replay(&frame);

		let response = HiveManagementResponse::stop_err(TransitStatus::PermissionDenied);
		let response = ClusterCommandResponse::manage(response);
		reply_frame(&frame.metadata.id, response)
	}

	fn forget_replay(&self, frame: &Frame)
	where
		P: Protocol,
	{
		if let Some(signer_info) = frame.nonrepudiation.as_ref() {
			self.replay_guard.forget(signer_info.signature.as_bytes());
		}
	}
}
