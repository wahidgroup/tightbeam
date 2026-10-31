//! The hive control plane: its accept loop, its cluster command handlers, and
//! the in-flight count that a drain waits on.

use core::future::Future;
use core::pin::pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures::future::{select, Either};
use tokio::sync::Notify;

use crate::clock::{Clock, MonotonicInstant};
use crate::colony::hive::gates::{AdmitRefusal, AdmittedCommand, CommandAudit, CommandRefusal};
use crate::colony::hive::runtime::{DrainMode, HiveContextImpl, HiveInstances, HiveRuntime};
use crate::colony::hive::{
	BackpressureGate, ClusterSecurityGate, HiveScalingConfig, ServletRegistration, ServletRegistry, SpawnerFn,
};
use crate::colony::protocol::{
	ClusterCommand, ClusterCommandResponse, HiveManagement, HiveManagementOutcome, SpawnServletParams,
	StopServletParams,
};
use crate::macros::server::{serve_connection, AcceptedConnection, SharedHandler};
use crate::policy::{GatePolicy, SessionContext, TransitStatus};
use crate::runtime::rt;
use crate::trace::{TraceCollector, TraceHandle};
use crate::transport::accept::{AcceptPlane, ConnectionTerms};
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::multiplex::MuxCapable;
use crate::transport::policy::PolicyConfig;
use crate::transport::{AsyncListenerTrait, Protocol, TransportError, TransportFailure};
use crate::urn::Urn;
use crate::{Frame, TightBeamError};

/// The count of cluster commands that the hive holds in flight.
///
/// A drain waits on it. A control connection idles between commands, so an
/// open connection counts as work only while it holds a command. The last
/// guard to drop wakes every waiter, so a drain ends the moment the hive falls
/// idle.
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
	/// The drain deadline passed with commands in flight.
	TimedOut,
}

/// The bound on the two waits of a drain: the drain timeout from the start of
/// the drain, on the hive clock.
///
/// The wait on commands and the wait on the servlet drains both race it, so
/// both waits end within the timeout of the drain's start. The slate
/// announcement follows them.
pub struct DrainDeadline<'a> {
	clock: &'a dyn Clock,
	started: MonotonicInstant,
	timeout: Duration,
}

impl<'a> DrainDeadline<'a> {
	/// Starts the deadline of a drain that may last `timeout` on `clock`.
	pub fn start(clock: &'a dyn Clock, timeout: Duration) -> Self {
		let started = clock.monotonic();
		Self { clock, started, timeout }
	}

	/// The span of the timeout that is left on the clock.
	fn remaining(&self) -> Duration {
		let spent = self.clock.monotonic().saturating_duration_since(self.started);
		self.timeout.saturating_sub(spent)
	}

	/// Runs `work` until it ends or the deadline passes. Past the deadline,
	/// `work` drops unfinished.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::DeadlineExceeded`] -- the deadline passed first.
	pub async fn within<F: Future>(&self, work: F) -> Result<F::Output, TransportError> {
		let work = pin!(work);
		let expired = self.clock.sleep(self.remaining());

		match select(work, expired).await {
			Either::Left((output, _)) => Ok(output),
			Either::Right(_) => Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded)),
		}
	}
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
	/// It registers the notification before it reads the count, so a guard
	/// that drops between the read and the await wakes this waiter.
	pub async fn idle(&self) {
		loop {
			let notified = self.0.idle.notified();
			if self.is_idle() {
				return;
			}

			notified.await;
		}
	}

	/// Waits for the hive to fall idle, or for `deadline` to pass.
	///
	/// It races the two waits, so a hive on a clock that only a test advances
	/// settles the moment its last command finishes.
	pub async fn settle(&self, deadline: &DrainDeadline<'_>) -> Settled {
		match deadline.within(self.idle()).await {
			Ok(()) => Settled::Idle,
			// The expiry is the whole outcome of this wait, so the error adds
			// nothing to it.
			Err(_expired) => Settled::TimedOut,
		}
	}
}

/// One command's share of the [`InFlight`] count. The guard releases it on
/// drop, so an early return also settles the drain.
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
///
/// [`Self::new`] alone builds one, from the runtime that owns the handles, so
/// the drain state and the servlets of a context come from the same runtime.
pub struct HiveControlCtx<P: Protocol, R: ServletRegistry> {
	/// The registry of live servlet instances, keyed by instance URN bytes.
	servlets: Arc<R>,
	/// The spawner closures, keyed by servlet type URN, that scale-up and a
	/// manage spawn call.
	spawners: Arc<HashMap<Urn<'static>, SpawnerFn>>,
	/// The trace handle shared with spawned servlets, which files the record
	/// of each command.
	trace: Arc<TraceCollector>,
	/// The trace of the plane, and of each record that no proven peer backs.
	connections: Arc<TraceCollector>,
	/// The one decider for whether this hive takes work, and the one home
	/// for the utilization it reads.
	backpressure: BackpressureGate,
	/// The drain state. A draining hive refuses all commands but the heartbeat.
	drain: DrainMode,
	/// The instance set's admission lock, which the scaling loop shares.
	admission: Arc<Mutex<()>>,
	/// The instance bounds of each servlet type, which a spawn and a stop keep.
	scaling: HiveScalingConfig,
	/// The count of commands in flight, which a drain waits on to reach zero.
	in_flight: InFlight,
	/// The intra-hive routing context, which [`HiveInstances`] updates as it
	/// inserts or removes instances.
	hive_context: Arc<HiveContextImpl<P>>,
	/// The one admission gate for cluster commands. It is [`None`] when the
	/// hive has no trust store, and then the hive refuses every command.
	security: Option<ClusterSecurityGate>,
}

impl<P: Protocol, R: ServletRegistry> HiveControlCtx<P, R> {
	/// The context of the control plane of `runtime`, whose connections record
	/// on `connections`.
	pub(crate) fn new(runtime: &HiveRuntime<P, R>, connections: &Arc<TraceCollector>) -> Self {
		let shares = runtime.shares();
		let config = shares.config;
		let threshold = config.control.backpressure_threshold;
		let backpressure = BackpressureGate::new(Arc::clone(shares.utilization), threshold);

		Self {
			servlets: Arc::clone(shares.servlets),
			spawners: Arc::clone(shares.spawners),
			trace: Arc::clone(shares.trace),
			connections: Arc::clone(connections),
			backpressure,
			drain: shares.drain.clone(),
			admission: Arc::clone(shares.admission),
			scaling: config.scaling.clone(),
			in_flight: shares.in_flight.clone(),
			hive_context: Arc::clone(shares.hive_context),
			security: config.security_gate(),
		}
	}
}

impl<P, R> HiveControlCtx<P, R>
where
	P: Protocol + Send + Sync + 'static,
	P::Listener: AsyncListenerTrait + Sync + 'static,
	<P::Listener as Protocol>::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	P::Address: Clone + Send + Sync + 'static,
	P::Transport: Send + Sync + 'static,
	R: ServletRegistry + 'static,
{
	/// Serves the hive control plane on `listener` through `plane`.
	///
	/// - Each accepted connection dispatches through [`HiveControlCtx::handle_command`] against this context.
	/// - Each connection records on the connection trace from before its handshake.
	///
	/// # Warning
	///
	/// The connection trace records each peer, one that never authenticates
	/// included. Give the hive's trace an `EventSink` that forwards through
	/// `EventSink::sibling`, or drain the connection trace.
	pub fn serve(
		self,
		listener: P::Listener,
		plane: AcceptPlane,
		mux_offer: Option<Arc<TransportOffer>>,
	) -> rt::JoinHandle {
		let connections = TraceHandle::new(Arc::clone(&self.connections));
		let terms = ConnectionTerms::new(connections, mux_offer);
		let ctx = Arc::new(self);
		let handler = SharedHandler::from(move |frame: Frame, session| {
			let ctx = Arc::clone(&ctx);
			async move { ctx.handle_command(frame, session).await }
		});

		rt::spawn(
			plane.accept_owned(listener, terms, move |transport: <P::Listener as Protocol>::Transport| {
				let handler = handler.clone();
				async move { serve_connection(transport, handler, None, None).await }
			}),
		)
	}
}

impl<P, R> HiveControlCtx<P, R>
where
	P: Protocol + Send + Sync + 'static,
	P::Transport: Send + Sync + 'static,
	R: ServletRegistry,
{
	/// Authenticates, gates, and dispatches one cluster command frame.
	///
	/// - Each refusal reply records [`HIVE_COMMAND_REFUSED`].
	/// - Each spawn or stop that the hive carries out records
	///   [`HIVE_COMMAND_ACCEPTED`], under the name of the command and the
	///   instance it changed.
	/// - A record goes on the trace of this context for a proven peer, and on the connection trace otherwise.
	/// - Each record carries the canonical key of the peer of `session` as its
	///   payload. The gate admits a command whose signer is that peer alone.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the reply body does not encode.
	/// - [`TightBeamError::BuildError`] -- the reply metadata fails validation.
	/// - [`TightBeamError`] -- the runtime fault model injects a fault at the
	///   refusal or the acceptance event.
	///
	/// [`HIVE_COMMAND_ACCEPTED`]: crate::instrumentation::events::HIVE_COMMAND_ACCEPTED
	/// [`HIVE_COMMAND_REFUSED`]: crate::instrumentation::events::HIVE_COMMAND_REFUSED
	pub async fn handle_command(
		self: Arc<Self>,
		frame: Frame,
		session: SessionContext,
	) -> Result<Option<Frame>, TightBeamError> {
		let ctx = self;
		let _in_flight = ctx.in_flight.enter();
		let audit = CommandAudit::new(&ctx.trace, &ctx.connections, &session);

		// Security admission runs before drain, so drain state answers
		// authenticated peers only. A refusal answers in the shape the sender
		// decodes, because a mismatched shape can evict the hive.
		let admitted = match ctx.admit(frame, &session) {
			Ok(admitted) => admitted,
			Err(refusal) => return refusal.reply(&audit),
		};

		// The command decides whether it yields to load. A draining hive
		// refuses every command that yields, and the refusal answers in the
		// alternative the command names.
		let yields = admitted.body().yields_to_load();
		if ctx.drain.is_draining() && yields {
			return admitted.refuse(CommandRefusal::Draining, &audit);
		}

		// A command that survives load, the heartbeat, skips backpressure, so
		// a health check answers under load. The exemption follows admission,
		// so an unauthenticated peer gets no bypass.
		if yields && ctx.under_backpressure(&admitted, &session) {
			return admitted.refuse(CommandRefusal::Backpressure, &audit);
		}

		ctx.dispatch(admitted, &audit).await
	}

	/// Answers one admitted command in the shape its body names, and records
	/// each refusal, spawn, and stop on `audit`.
	async fn dispatch(
		&self,
		admitted: AdmittedCommand,
		audit: &CommandAudit<'_>,
	) -> Result<Option<Frame>, TightBeamError> {
		match admitted.body() {
			ClusterCommand::Heartbeat(_) => self.heartbeat_reply(&admitted, audit),
			ClusterCommand::Manage(HiveManagement::Spawn(spawn)) => self.manage_spawn(spawn, &admitted, audit).await,
			ClusterCommand::Manage(HiveManagement::List(_)) => self.manage_list(&admitted, audit),
			ClusterCommand::Manage(HiveManagement::Stop(stop)) => self.manage_stop(stop, &admitted, audit),
		}
	}
}

impl<P: Protocol, R: ServletRegistry> HiveControlCtx<P, R> {
	/// The hive's instance set, which a spawn and a stop move under its
	/// admission lock.
	fn instances(&self) -> HiveInstances<'_, R, P> {
		let servlets = self.servlets.as_ref();
		let routes = &self.hive_context;
		HiveInstances::new(servlets, routes, &self.admission, &self.drain, &self.scaling)
	}

	fn admit(&self, frame: Frame, session: &SessionContext) -> Result<AdmittedCommand, Box<AdmitRefusal>> {
		let Some(gate) = &self.security else {
			return Err(AdmitRefusal::denied(frame, TransitStatus::PermissionDenied));
		};

		gate.admit(frame, session)
	}

	/// Whether the backpressure gate refuses `admitted` at the present load.
	fn under_backpressure(&self, admitted: &AdmittedCommand, session: &SessionContext) -> bool {
		let verdict = GatePolicy::evaluate(&self.backpressure, Some(admitted.frame()), session);
		verdict == TransitStatus::ResourceExhausted
	}

	fn heartbeat_reply(
		&self,
		admitted: &AdmittedCommand,
		audit: &CommandAudit<'_>,
	) -> Result<Option<Frame>, TightBeamError>
	where
		P: Protocol,
	{
		let load = self.backpressure.report();
		let active_count = self.healthy_servlets();
		let response = ClusterCommandResponse::heartbeat(load.status, load.utilization, active_count);

		admitted.reply(response, audit)
	}

	/// The count of the servlets that report themselves healthy, read in one
	/// walk of the registry under the lock contract of
	/// [`ServletBox::is_healthy`].
	///
	/// [`ServletBox::is_healthy`]: crate::colony::hive::ServletBox::is_healthy
	fn healthy_servlets(&self) -> u32 {
		let mut healthy = 0u32;
		self.servlets.for_each(|_, registration| {
			if registration.servlet.is_healthy() {
				healthy = healthy.saturating_add(1);
			}
		});

		healthy
	}

	async fn manage_spawn(
		&self,
		spawn: &SpawnServletParams,
		admitted: &AdmittedCommand,
		audit: &CommandAudit<'_>,
	) -> Result<Option<Frame>, TightBeamError>
	where
		P: Protocol + Send + Sync + 'static,
		P::Transport: Send + Sync + 'static,
	{
		let servlet_type = spawn.servlet_type.clone();
		let Some(spawner) = self.spawners.get(&servlet_type) else {
			return admitted.refuse(CommandRefusal::UnknownServletType, audit);
		};

		let Ok(new_servlet) = spawner(Arc::clone(&self.trace)).await else {
			return admitted.refuse(CommandRefusal::SpawnFailed, audit);
		};

		let registration = ServletRegistration { servlet: new_servlet, spawner: Arc::clone(spawner), servlet_type };
		let placed = match self.instances().insert(registration) {
			Ok(placed) => placed,
			Err(refusal) => return admitted.refuse(CommandRefusal::from(refusal), audit),
		};

		// The manage response owns its address bytes, so this copy is needed.
		let address = placed.address.as_ref().to_vec();
		let response = HiveManagementOutcome::spawn_ok(address, placed.instance);

		admitted.reply(ClusterCommandResponse::Manage(response), audit)
	}

	fn manage_list(&self, admitted: &AdmittedCommand, audit: &CommandAudit<'_>) -> Result<Option<Frame>, TightBeamError>
	where
		P: Protocol,
	{
		let list = self.servlets.slate();
		let response = HiveManagementOutcome::list_ok(list);
		admitted.reply(ClusterCommandResponse::Manage(response), audit)
	}

	fn manage_stop(
		&self,
		stop: &StopServletParams,
		admitted: &AdmittedCommand,
		audit: &CommandAudit<'_>,
	) -> Result<Option<Frame>, TightBeamError>
	where
		P: Protocol,
	{
		let id_bytes = stop.servlet_id.canonical_bytes();
		if let Err(refusal) = self.instances().remove(&id_bytes) {
			return admitted.refuse(CommandRefusal::from(refusal), audit);
		}

		let response = ClusterCommandResponse::Manage(HiveManagementOutcome::stop_ok());
		admitted.reply(response, audit)
	}
}

#[cfg(test)]
mod tests {
	use core::future::{poll_fn, Future};
	use core::pin::Pin;
	use core::task::Poll;

	use super::*;
	use crate::clock::ManualClock;
	use crate::testing::fixtures::TestClock;

	/// The drain timeout every wait in this module races against.
	const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

	/// A bound on a wait that the test expects to end at once. A wait that
	/// reaches it is a hang, which the test reports as a failure.
	const HANG_GUARD: Duration = Duration::from_secs(5);

	/// The in-flight count of a hive, beside the manual clock that its drain
	/// reads.
	struct Drain {
		in_flight: InFlight,
		clock: Arc<ManualClock>,
		hive_clock: Arc<dyn Clock>,
	}

	impl Drain {
		/// A hive with no command in flight, at the start of its clock.
		fn new() -> Self {
			let clock = TestClock::manual();
			Self { in_flight: InFlight::default(), hive_clock: TestClock::erased(&clock), clock }
		}

		/// The deadline of a drain of [`DRAIN_TIMEOUT`] that starts now.
		fn deadline(&self) -> DrainDeadline<'_> {
			DrainDeadline::start(self.hive_clock.as_ref(), DRAIN_TIMEOUT)
		}
	}

	/// Bounds `settle` by [`HANG_GUARD`], so a wait that never ends fails its
	/// test.
	async fn bounded(settle: impl Future<Output = Settled>) -> Settled {
		let settled = tokio::time::timeout(HANG_GUARD, settle).await;
		settled.expect("the settle ends inside the hang guard")
	}

	/// Polls `settle` once, so the waits inside it register with the clock
	/// and the in-flight count before the test moves either.
	async fn poll_once(settle: &mut Pin<&mut impl Future<Output = Settled>>) -> Poll<Settled> {
		poll_fn(|context| Poll::Ready(settle.as_mut().poll(context))).await
	}

	/// A hive with no command in flight settles at once.
	#[tokio::test]
	async fn an_idle_hive_settles_at_once() {
		let drain = Drain::new();
		let deadline = drain.deadline();

		let settled = bounded(drain.in_flight.settle(&deadline)).await;
		assert_eq!(settled, Settled::Idle);
	}

	/// The wait ends the moment the last command finishes, while the hive
	/// clock stands still, so a drain on a manual clock settles on the drop of
	/// its last guard.
	#[tokio::test]
	async fn a_settle_ends_when_the_last_command_finishes() {
		let drain = Drain::new();
		let deadline = drain.deadline();
		let guard = drain.in_flight.enter();
		let mut settle = pin!(drain.in_flight.settle(&deadline));
		let before = poll_once(&mut settle).await;

		drop(guard);

		let settled = bounded(settle).await;
		assert_eq!((before, settled), (Poll::Pending, Settled::Idle));
	}

	/// The timeout fires on the hive clock while a command is in flight, so
	/// the drain's backstop holds on a manual clock too.
	#[tokio::test]
	async fn a_settle_times_out_on_the_hive_clock() {
		let drain = Drain::new();
		let deadline = drain.deadline();
		let _guard = drain.in_flight.enter();
		let mut settle = pin!(drain.in_flight.settle(&deadline));
		let before = poll_once(&mut settle).await;

		drain.clock.advance(DRAIN_TIMEOUT);

		let settled = bounded(settle).await;
		assert_eq!((before, settled), (Poll::Pending, Settled::TimedOut));
	}
}
