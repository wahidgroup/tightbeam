//! The hive control plane: its accept loop, its cluster command handlers, and
//! the in-flight count that a drain waits on.

use core::pin::pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;

use futures::future::{select, Either};
use tokio::sync::Notify;

use crate::colony::common::{
	ClusterCommandKind, ClusterCommandResponse, DrainMode, HiveManagement, SpawnServletParams, StopServletParams,
};
use crate::colony::hive::gates::{AdmitRefusal, AdmittedCommand, CommandRefusal};
use crate::colony::hive::runtime::{HiveContextImpl, HiveInstances, InsertRefusal};
use crate::colony::hive::{
	BackpressureGate, ClusterSecurityGate, HashMapRegistry, HiveManagementResponse, ServletRegistration,
	ServletRegistry, SpawnerFn,
};
use crate::colony::servlet::servlet_runtime::rt;
use crate::macros::server::{serve_connection, AcceptedConnection, SharedHandler};
use crate::policy::{GatePolicy, SessionContext, TransitStatus};
use crate::trace::TraceCollector;
use crate::transport::accept::AcceptPlane;
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::multiplex::MuxCapable;
use crate::transport::policy::PolicyConfig;
use crate::transport::{AsyncListenerTrait, Protocol};
use crate::utils::time::Clock;
use crate::utils::urn::Urn;
use crate::{Frame, TightBeamError};

/// The count of cluster commands that the hive is handling.
///
/// A drain waits on this: a control connection idles between commands by
/// design, so an open connection counts as work only while it holds a
/// command. The last guard to drop wakes every waiter, so a drain ends the
/// moment the hive falls idle rather than on a poll.
#[derive(Clone, Default)]
pub struct InFlight(Arc<InFlightState>);

/// The count and the waiters it wakes when it reaches zero.
#[derive(Default)]
struct InFlightState {
	count: AtomicUsize,
	idle: Notify,
}

/// How a wait on [`InFlight`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
	/// Every command in flight finished.
	Idle,
	/// The timeout passed on the hive clock with commands still in flight.
	TimedOut,
}

impl InFlight {
	/// Counts one command for as long as the returned guard lives.
	pub fn enter(&self) -> InFlightGuard {
		self.0.count.fetch_add(1, Ordering::AcqRel);
		InFlightGuard(Arc::clone(&self.0))
	}

	/// Whether the in-flight count is zero.
	pub fn is_idle(&self) -> bool {
		self.0.count.load(Ordering::Acquire) == 0
	}

	/// Resolves once no command is in flight.
	///
	/// The notification is registered before the count is read, so a guard
	/// that drops between the read and the await still wakes this waiter.
	pub async fn idle(&self) {
		loop {
			let notified = self.0.idle.notified();
			if self.is_idle() {
				return;
			}

			notified.await;
		}
	}

	/// Waits for the hive to fall idle, or for `timeout` to pass on `clock`.
	///
	/// The two are raced rather than polled, so a hive on a clock that
	/// only a test advances still settles the moment its last command
	/// finishes.
	pub async fn settle(&self, clock: &dyn Clock, timeout: Duration) -> Settled {
		let idle = pin!(self.idle());
		let expired = pin!(clock.sleep(timeout));

		match select(idle, expired).await {
			Either::Left(_) => Settled::Idle,
			Either::Right(_) => Settled::TimedOut,
		}
	}
}

/// Releases its count on drop, so an early return still settles the drain.
pub struct InFlightGuard(Arc<InFlightState>);

impl Drop for InFlightGuard {
	fn drop(&mut self) {
		let before = self.0.count.fetch_sub(1, Ordering::AcqRel);
		if before == 1 {
			self.0.idle.notify_waiters();
		}
	}
}

/// The shared state that the hive control plane handles each command against.
pub struct HiveControlCtx<P: Protocol> {
	/// The registry of running servlet instances, keyed by instance URN bytes.
	pub servlets: Arc<HashMapRegistry>,
	/// The spawner closures, keyed by servlet type URN, that scale-up and a
	/// manage spawn call.
	pub spawners: Arc<HashMap<Urn<'static>, SpawnerFn>>,
	/// The trace handle shared with spawned servlets and control-plane events.
	pub trace: Arc<TraceCollector>,
	/// The one decider for whether this hive is taking work, and the one
	/// home for the utilization it reads.
	pub backpressure: BackpressureGate,
	/// The drain state. A draining hive refuses all commands but the heartbeat.
	pub drain: DrainMode,
	/// Commands in flight, which a drain waits to reach zero.
	pub in_flight: InFlight,
	/// The intra-hive routing context, which [`HiveInstances`] updates as
	/// instances are inserted or removed.
	pub hive_context: Arc<HiveContextImpl<P>>,
	/// The one admission gate for cluster commands. It is [`None`] when the
	/// hive has no trust store, and then every command is refused.
	pub security: Option<ClusterSecurityGate>,
}

impl<P> HiveControlCtx<P>
where
	P: Protocol + Send + Sync + 'static,
	P::Listener: AsyncListenerTrait + Sync + 'static,
	<P::Listener as Protocol>::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	P::Address: Clone + Send + Sync + 'static,
	P::Transport: Send + Sync + 'static,
{
	/// Serves the hive control plane on `listener` through `plane`.
	///
	/// Each accepted connection dispatches through
	/// [`HiveControlCtx::handle_command`] against this context.
	pub fn serve(
		self,
		listener: P::Listener,
		plane: AcceptPlane,
		mux_offer: Option<Arc<TransportOffer>>,
	) -> rt::JoinHandle {
		let ctx = Arc::new(self);
		let handler = SharedHandler::from(move |frame: Frame, session| {
			let ctx = Arc::clone(&ctx);
			async move { ctx.handle_command(frame, session).await }
		});

		rt::spawn(
			plane.accept_on(listener, move |mut transport: <P::Listener as Protocol>::Transport| {
				transport = transport.with_mux_offer(mux_offer.clone());

				let handler = handler.clone();
				async move { serve_connection(transport, handler, None, None).await }
			}),
		)
	}
}

impl<P> HiveControlCtx<P>
where
	P: Protocol + Send + Sync + 'static,
	P::Transport: Send + Sync + 'static,
{
	/// Authenticates, gates, and dispatches one cluster command frame.
	pub async fn handle_command(
		self: Arc<Self>,
		frame: Frame,
		session: SessionContext,
	) -> Result<Option<Frame>, TightBeamError> {
		let ctx = self;
		let _in_flight = ctx.in_flight.enter();

		// Security admission runs before drain, so drain state answers
		// authenticated peers only. A refusal answers in the alternative the
		// sender decodes, because a mismatched shape counts as
		// `ClusterError::MalformedResponse` and can evict the hive.
		let admitted = match ctx.admit(frame, &session) {
			Ok(admitted) => admitted,
			Err(refusal) => return refusal.reply(),
		};

		// A draining hive refuses every command except the heartbeat, and the
		// refusal answers in the alternative the command names.
		if ctx.drain.is_draining() && !admitted.is_heartbeat() {
			return admitted.refuse(CommandRefusal::Draining);
		}

		// Authenticated heartbeats skip backpressure so health checks survive
		// load. The exemption follows admission, so an unauthenticated peer
		// gets no bypass.
		if !admitted.is_heartbeat() && ctx.under_backpressure(&admitted, &session) {
			return admitted.refuse(CommandRefusal::Backpressure);
		}

		ctx.dispatch(admitted).await
	}

	/// Answers one admitted command in the shape its body names.
	async fn dispatch(self: Arc<Self>, admitted: AdmittedCommand) -> Result<Option<Frame>, TightBeamError> {
		match admitted.body() {
			ClusterCommandKind::Heartbeat(_) => self.heartbeat_reply(&admitted),
			ClusterCommandKind::Manage(HiveManagement::Spawn(spawn)) => self.manage_spawn(spawn, &admitted).await,
			ClusterCommandKind::Manage(HiveManagement::List(_)) => self.manage_list(&admitted),
			ClusterCommandKind::Manage(HiveManagement::Stop(stop)) => self.manage_stop(stop, &admitted),
		}
	}
}

impl<P: Protocol> HiveControlCtx<P> {
	fn admit(&self, frame: Frame, session: &SessionContext) -> Result<AdmittedCommand, Box<AdmitRefusal>> {
		let Some(gate) = &self.security else {
			return Err(AdmitRefusal::denied(frame, TransitStatus::PermissionDenied));
		};

		gate.admit(frame, session)
	}

	/// Whether the backpressure gate refuses `admitted` right now.
	fn under_backpressure(&self, admitted: &AdmittedCommand, session: &SessionContext) -> bool {
		let verdict = GatePolicy::evaluate(&self.backpressure, Some(admitted.frame()), session);

		verdict == TransitStatus::ResourceExhausted
	}

	fn heartbeat_reply(&self, admitted: &AdmittedCommand) -> Result<Option<Frame>, TightBeamError>
	where
		P: Protocol,
	{
		let load = self.backpressure.report();
		let active_count = self.servlets.count() as u32;
		let response = ClusterCommandResponse::heartbeat(load.status, load.utilization, active_count);

		admitted.reply(response)
	}

	async fn manage_spawn(
		&self,
		spawn: &SpawnServletParams,
		admitted: &AdmittedCommand,
	) -> Result<Option<Frame>, TightBeamError>
	where
		P: Protocol + Send + Sync + 'static,
		P::Transport: Send + Sync + 'static,
	{
		let servlet_type = spawn.servlet_type.clone();
		let Some(spawner) = self.spawners.get(&servlet_type) else {
			return admitted.refuse(CommandRefusal::UnknownServletType);
		};

		let Ok(new_servlet) = spawner(Arc::clone(&self.trace)).await else {
			return admitted.refuse(CommandRefusal::SpawnFailed);
		};

		let registration = ServletRegistration { servlet: new_servlet, spawner: Arc::clone(spawner), servlet_type };
		let instances = HiveInstances::new(self.servlets.as_ref(), &self.hive_context);
		let (instance, addr_bytes) = match instances.insert(registration) {
			Ok(placed) => placed,
			Err(InsertRefusal::Unnameable(_)) => return admitted.refuse(CommandRefusal::UnnameableInstance),
			Err(InsertRefusal::Registry(_)) => return admitted.refuse(CommandRefusal::RegistryFault),
		};

		// The manage response owns its address bytes, so this copy is real.
		let address = addr_bytes.as_ref().to_vec();
		let response = HiveManagementResponse::spawn_ok(address, instance);

		admitted.reply(ClusterCommandResponse::manage(response))
	}

	fn manage_list(&self, admitted: &AdmittedCommand) -> Result<Option<Frame>, TightBeamError>
	where
		P: Protocol,
	{
		let list = self.servlets.slate();
		let response = HiveManagementResponse::list_ok(list);

		admitted.reply(ClusterCommandResponse::manage(response))
	}

	fn manage_stop(&self, stop: &StopServletParams, admitted: &AdmittedCommand) -> Result<Option<Frame>, TightBeamError>
	where
		P: Protocol,
	{
		let id_bytes = stop.servlet_id.canonical_bytes();
		let instances = HiveInstances::new(self.servlets.as_ref(), &self.hive_context);
		if instances.remove(&id_bytes).is_none() {
			return admitted.refuse(CommandRefusal::UnknownInstance);
		}

		let response = ClusterCommandResponse::manage(HiveManagementResponse::stop_ok());

		admitted.reply(response)
	}
}

#[cfg(test)]
mod tests {
	use core::future::{poll_fn, Future};
	use core::pin::Pin;
	use core::task::Poll;

	use super::*;
	use crate::utils::time::ManualClock;

	/// The drain timeout every wait in this module races against.
	const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

	/// A bound on a wait that the test expects to end at once. A wait that
	/// reaches it is a hang, which the test reports as a failure.
	const HANG_GUARD: Duration = Duration::from_secs(5);

	/// A clock that moves only when the test advances it.
	fn manual_clock() -> Arc<ManualClock> {
		Arc::new(ManualClock::default())
	}

	/// `clock` as the erased handle a settle reads.
	fn erased(clock: &Arc<ManualClock>) -> Arc<dyn Clock> {
		Arc::clone(clock) as Arc<dyn Clock>
	}

	/// `settle` bounded by [`HANG_GUARD`], so a wait that never ends fails
	/// the test instead of hanging it.
	async fn bounded(settle: impl Future<Output = Settled>) -> Result<Settled, TightBeamError> {
		tokio::time::timeout(HANG_GUARD, settle)
			.await
			.map_err(|_| TightBeamError::RecvTimeoutError)
	}

	/// Polls `settle` once, so the waits inside it register with the clock
	/// and the in-flight count before the test moves either.
	async fn poll_once(settle: &mut Pin<&mut impl Future<Output = Settled>>) -> Poll<Settled> {
		poll_fn(|context| Poll::Ready(settle.as_mut().poll(context))).await
	}

	/// A hive with no command in flight settles at once.
	#[tokio::test]
	async fn an_idle_hive_settles_at_once() -> Result<(), TightBeamError> {
		let in_flight = InFlight::default();
		let clock = erased(&manual_clock());

		let settled = bounded(in_flight.settle(clock.as_ref(), DRAIN_TIMEOUT)).await?;

		assert_eq!(settled, Settled::Idle);
		Ok(())
	}

	/// The wait ends the moment the last command finishes, with the hive
	/// clock never advanced, so a drain on a manual clock does not hang on
	/// a poll.
	#[tokio::test]
	async fn a_settle_ends_when_the_last_command_finishes() -> Result<(), TightBeamError> {
		let in_flight = InFlight::default();
		let clock = erased(&manual_clock());
		let guard = in_flight.enter();
		let mut settle = pin!(in_flight.settle(clock.as_ref(), DRAIN_TIMEOUT));
		assert!(poll_once(&mut settle).await.is_pending());

		drop(guard);

		let settled = bounded(settle).await?;
		assert_eq!(settled, Settled::Idle);
		Ok(())
	}

	/// The timeout fires on the hive clock while a command is still in
	/// flight, so the drain's backstop holds on a manual clock too.
	#[tokio::test]
	async fn a_settle_times_out_on_the_hive_clock() -> Result<(), TightBeamError> {
		let in_flight = InFlight::default();
		let clock = manual_clock();
		let hive_clock = erased(&clock);
		let _guard = in_flight.enter();
		let mut settle = pin!(in_flight.settle(hive_clock.as_ref(), DRAIN_TIMEOUT));
		assert!(poll_once(&mut settle).await.is_pending());

		clock.advance(DRAIN_TIMEOUT);

		let settled = bounded(settle).await?;
		assert_eq!(settled, Settled::TimedOut);
		Ok(())
	}
}
