//! The hive lifecycle runtime for a protocol `P` and a servlet registry `R`.
//!
//! - [`HiveRuntime`] owns the control, scaling, and re-registration task handles.
//! - Callers reach the lifecycle through the [`Hive`] trait only.
//! - The `hive!` macro names a type alias of [`HiveRuntime`].

use core::future::Future;
use core::hash::Hash;
use core::pin::Pin;
use core::str::FromStr;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use futures::future::join_all;

use crate::colony::hive::runtime::control::{DrainDeadline, InFlight, Settled};
use crate::colony::hive::runtime::{ClusterLink, HiveContextImpl, HiveControlCtx, HiveInstances, ScalingLoop};
use crate::colony::hive::{
	HashMapRegistry, Hive, HiveConfig, HiveContext, HiveError, ServletBox, ServletRegistration, ServletRegistry,
	SpawnerFn, SpawnerTable,
};
use crate::colony::protocol::{IssueClock, RegisterHiveResponse};
use crate::colony::urn::ColonyResource;
use crate::constants::DEFAULT_MAX_SERVER_CONNECTIONS;
use crate::instrumentation::events::HIVE_ESTABLISHED;
use crate::macros::server::AcceptedConnection;
use crate::policy::TransitStatus;
use crate::runtime::{rt, TaskGroup};
use crate::trace::TraceCollector;
use crate::transport::accept::AcceptPlane;
use crate::transport::client::{ConnectionBuilder, ConnectionPool, ConnectionPoolBuilder};
use crate::transport::handshake::HandshakeProvider;
use crate::transport::multiplex::{MuxCapable, MuxConnector};
use crate::transport::policy::PolicyConfig;
use crate::transport::{
	AsyncListenerTrait, EncryptedProtocol, MessageCollector, MessageEmitter, PersistentConnection, Protocol,
};
use crate::urn::{Urn, UrnValidationError};
use crate::TightBeamError;

use crate::transport::state::EncryptedProtocolState;

/// The accept plane a cluster reaches this hive on.
///
/// The hive binds it only under the TLS identity that signs registrations. A
/// cluster refuses an unsigned hive, so an unauthenticated control listener
/// would answer only an attacker (CWE-306).
struct ControlPlane<P: Protocol> {
	/// The accept loop, which [`Hive::join`] awaits.
	handle: rt::JoinHandle,
	/// The address a cluster dials, and the hive's own identity locator.
	addr: P::Address,
	/// The trace that each connection of the plane records on, which
	/// [`Hive::connection_trace`] returns.
	connections: Arc<TraceCollector>,
}

/// Where a hive sits in its lifecycle.
///
/// Servlet registration closes when the hive establishes, so each phase
/// holds its own state.
enum Lifecycle<P: Protocol> {
	/// Servlet registration is open, and the control plane is unbound.
	Provisional,
	/// The servlets run. `control` is present for a hive that holds a
	/// TLS identity, and absent for one that can never join a cluster.
	Established { control: Option<ControlPlane<P>> },
}

impl<P: Protocol> Lifecycle<P> {
	/// Returns the control plane, for a hive that established one.
	fn control(&self) -> Option<&ControlPlane<P>> {
		match self {
			Self::Established { control } => control.as_ref(),
			Self::Provisional => None,
		}
	}

	/// Whether servlet registration is open.
	fn is_provisional(&self) -> bool {
		matches!(self, Self::Provisional)
	}
}

/// Whether a runtime has entered drain.
///
/// Every clone of the handle shares one flag, so its readers agree:
///
/// - The hive control plane refuses each command that yields to load.
/// - [`Hive::is_draining`] reports the flag.
///
/// Drain is terminal: a runtime that enters it never leaves it.
#[derive(Clone, Default)]
pub struct DrainMode(Arc<AtomicBool>);

impl DrainMode {
	/// Enters drain.
	pub fn begin(&self) {
		self.0.store(true, Ordering::Release);
	}

	/// Returns `true` once drain has begun.
	#[must_use]
	pub fn is_draining(&self) -> bool {
		self.0.load(Ordering::Acquire)
	}
}

/// A running hive for a protocol `P`, which stores its servlets in the
/// registry `R`.
///
/// [`Self::new`] builds the registry through [`Default`], and
/// [`Self::with_registry`] takes a registry that the caller built.
pub struct HiveRuntime<P: Protocol, R: ServletRegistry = HashMapRegistry> {
	servlets: Arc<R>,
	spawners: Arc<HashMap<Urn<'static>, SpawnerFn>>,
	config: HiveConfig,
	trace: Arc<TraceCollector>,
	lifecycle: Lifecycle<P>,
	/// Every background task that this runtime starts.
	tasks: TaskGroup,
	utilization: Arc<AtomicU16>,
	drain: DrainMode,
	/// The admission lock of the instance set, which the control plane and
	/// the scaling loop share.
	admission: Arc<Mutex<()>>,
	/// The count of commands in flight, which a drain waits to see at zero.
	in_flight: InFlight,
	cluster_addrs: Arc<RwLock<Vec<P::Address>>>,
	hive_context: Arc<HiveContextImpl<P>>,
	/// The issue times of this hive's control frames, which every link to
	/// the gateways shares, so the orders of the hive increase strictly.
	issue_clock: Arc<IssueClock>,
}

/// The shared handles of a [`HiveRuntime`], which the control plane and the
/// scaling loop that the runtime starts read.
///
/// Each handle is a shared borrow, so every reader holds the one drain state,
/// admission lock, and servlet registry of the runtime.
pub(super) struct RuntimeShares<'a, P: Protocol, R: ServletRegistry> {
	pub(super) servlets: &'a Arc<R>,
	pub(super) spawners: &'a Arc<HashMap<Urn<'static>, SpawnerFn>>,
	pub(super) config: &'a HiveConfig,
	pub(super) trace: &'a Arc<TraceCollector>,
	pub(super) tasks: &'a TaskGroup,
	pub(super) utilization: &'a Arc<AtomicU16>,
	pub(super) drain: &'a DrainMode,
	pub(super) admission: &'a Arc<Mutex<()>>,
	pub(super) in_flight: &'a InFlight,
	pub(super) cluster_addrs: &'a Arc<RwLock<Vec<P::Address>>>,
	pub(super) hive_context: &'a Arc<HiveContextImpl<P>>,
	pub(super) issue_clock: &'a Arc<IssueClock>,
}

impl<P: Protocol, R: ServletRegistry + Default> HiveRuntime<P, R> {
	/// Creates a provisional hive on the registry that [`Default`] builds.
	///
	/// Call [`Hive::register`] to add servlets, then [`Hive::establish`] to
	/// start the hive.
	///
	/// # Errors
	///
	/// - [`HiveError::OccupiedRegistry`] -- the default registry holds a registration.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::hive::{Hive, HiveRuntime};
	/// use tightbeam::transport::tcp::r#async::TokioListener;
	///
	/// let hive = HiveRuntime::<TokioListener>::new(None)?;
	/// assert!(hive.servlet_addresses().is_empty());
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// ```
	pub fn new(config: Option<HiveConfig>) -> Result<Self, TightBeamError> {
		let config = config.unwrap_or_default();

		Self::with_registry(config, R::default())
	}
}

impl<P: Protocol, R: ServletRegistry> HiveRuntime<P, R> {
	/// Creates a provisional hive that stores its servlets in `registry`.
	///
	/// Each servlet enters through [`Hive::register`], the one namespace check,
	/// so the registry starts empty.
	///
	/// # Errors
	///
	/// - [`HiveError::OccupiedRegistry`] -- `registry` holds a registration, and each servlet it holds stops.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::hive::{HashMapRegistry, Hive, HiveConfig, HiveRuntime};
	/// use tightbeam::transport::tcp::r#async::TokioListener;
	///
	/// let registry = HashMapRegistry::default();
	/// let hive = HiveRuntime::<TokioListener, _>::with_registry(HiveConfig::default(), registry)?;
	/// assert!(hive.servlet_addresses().is_empty());
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// ```
	pub fn with_registry(config: HiveConfig, registry: R) -> Result<Self, TightBeamError> {
		if registry.count() != 0 {
			registry.drain_all().into_iter().for_each(|(_, reg)| reg.servlet.stop_boxed());
			return Err(HiveError::OccupiedRegistry.into());
		}

		let trace = Arc::new(TraceCollector::default());
		let servlet_pool = Self::servlet_pool(&config, &trace);
		let hive_context = Arc::new(HiveContextImpl::new(servlet_pool).with_trace(Arc::clone(&trace)));
		let issue_clock = Arc::new(IssueClock::new(Arc::clone(&config.clock)));

		Ok(Self {
			servlets: Arc::new(registry),
			spawners: Arc::new(HashMap::new()),
			config,
			trace,
			lifecycle: Lifecycle::Provisional,
			tasks: TaskGroup::default(),
			utilization: Arc::new(AtomicU16::new(0)),
			drain: DrainMode::default(),
			admission: Arc::default(),
			in_flight: InFlight::default(),
			cluster_addrs: Arc::new(RwLock::new(Vec::new())),
			hive_context,
			issue_clock,
		})
	}

	/// Lends the shared handles of this runtime to the control plane and the
	/// scaling loop that it starts, which [`HiveControlCtx::new`] and
	/// [`ScalingLoop::new`] read.
	pub(super) fn shares(&self) -> RuntimeShares<'_, P, R> {
		RuntimeShares {
			servlets: &self.servlets,
			spawners: &self.spawners,
			config: &self.config,
			trace: &self.trace,
			tasks: &self.tasks,
			utilization: &self.utilization,
			drain: &self.drain,
			admission: &self.admission,
			in_flight: &self.in_flight,
			cluster_addrs: &self.cluster_addrs,
			hive_context: &self.hive_context,
			issue_clock: &self.issue_clock,
		}
	}

	/// Aborts the hive's tasks and its control plane, then drains the
	/// instance set and stops every registered servlet. Both `stop` and `Drop`
	/// run it, so a dropped hive leaks no servlet.
	fn release(&mut self) {
		self.tasks.abort_all();
		if let Lifecycle::Established { control } = &mut self.lifecycle {
			if let Some(plane) = control.take() {
				rt::abort(&plane.handle);
			}
		}

		let released = self.instances().drain_all();
		released.into_iter().for_each(|reg| reg.servlet.stop_boxed());
	}

	/// The hive's instance set, which a drain empties under its lock.
	fn instances(&self) -> HiveInstances<'_, R, P> {
		let servlets = self.servlets.as_ref();
		let routes = &self.hive_context;
		HiveInstances::new(servlets, routes, &self.admission, &self.drain, &self.config.scaling)
	}

	/// Builds the pool that the hive's servlets call their siblings on, from
	/// `config`. Each dial records its session on `trace`, a failed one too.
	///
	/// # Warning
	///
	/// The default `BoundedMemorySink` drops events past `max_events`, the
	/// hive's own among them, so a long-lived hive needs a forwarding
	/// `EventSink` or a reader that drains the trace.
	#[cfg_attr(not(feature = "instrument"), allow(unused_variables))]
	fn servlet_pool(config: &HiveConfig, trace: &TraceCollector) -> Arc<ConnectionPool<P>> {
		let builder = ConnectionPoolBuilder::new(config.pool.clone(), Arc::clone(&config.clock));
		#[cfg(feature = "instrument")]
		let builder = builder.with_trace(trace.share());
		Arc::new(config.sibling_dials(builder).build())
	}

	/// Records [`HIVE_ESTABLISHED`] on `trace` for a hive of `servlet_count`
	/// servlets that serves its control plane at `control_addr`, or serves
	/// none.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the runtime fault model injects a fault at the event.
	fn record_established(
		trace: &TraceCollector,
		servlet_count: usize,
		control_addr: Option<P::Address>,
	) -> Result<(), TightBeamError> {
		let label = match control_addr {
			Some(_) => "control-plane",
			None => "no-control-plane",
		};

		let evidence = move || -> Option<Vec<u8>> { control_addr.map(Into::into) };
		trace.emit_event_with_value_and_rendered_evidence(HIVE_ESTABLISHED, label, servlet_count, evidence)
	}
}

impl<P, R> HiveRuntime<P, R>
where
	P: Protocol + EncryptedProtocol<CryptoProvider: HandshakeProvider> + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + MuxCapable + EncryptedProtocolState + Send + 'static,
	R: ServletRegistry + 'static,
	TightBeamError: From<P::Error>,
{
	/// Binds this hive's slate, gateways, address, configuration, and trace.
	///
	/// It returns [`None`] for a hive with no control plane, which has no
	/// address to register and which no cluster can reach.
	fn cluster_link(&self) -> Option<ClusterLink<P, R>> {
		let addr = self.lifecycle.control().map(|plane| plane.addr)?;
		Some(ClusterLink::new(
			Arc::clone(&self.servlets),
			Arc::clone(&self.cluster_addrs),
			addr,
			Arc::new(self.config.clone()),
			Arc::clone(&self.trace),
			Arc::clone(&self.issue_clock),
		))
	}

	/// Binds the control plane, for a hive that has an identity to present.
	///
	/// It returns [`None`] when `hive_tls` is unset. Spawn and stop MUST NOT
	/// travel cleartext, and a hive with no identity signs no registration,
	/// so no cluster can learn this address to dial it.
	async fn bind_control_listener(config: &HiveConfig) -> Result<Option<(P::Listener, P::Address)>, TightBeamError> {
		let Some(encryption_config) = config.control_encryption() else {
			return Ok(None);
		};

		let bind_addr = P::default_bind_address()?;
		Ok(Some(P::bind_with(bind_addr, encryption_config).await?))
	}

	/// Admits a registration of a servlet as `servlet_type`: the hive is
	/// provisional, and the type is a servlet type of its namespace. The
	/// instance set derives the key of the servlet.
	///
	/// # Errors
	///
	/// - [`TightBeamError::AlreadyEstablished`] -- the hive is past its provisional state.
	/// - [`TightBeamError::UrnValidationError`] -- `servlet_type` is no servlet type of this namespace.
	fn admit_registration(&self, servlet_type: &Urn<'static>) -> Result<(), TightBeamError> {
		if !self.lifecycle.is_provisional() {
			return Err(TightBeamError::AlreadyEstablished);
		}

		// A registration names a servlet type, so its URN MUST sit in this
		// hive's namespace and carry no instance tail.
		match self.config.namespace.validate(servlet_type)? {
			ColonyResource::Servlet { instance: None, .. } => Ok(()),
			_ => Err(TightBeamError::UrnValidationError(UrnValidationError::InvalidFormat {
				field: "resource-id",
				pattern: None,
			})),
		}
	}
}

impl<P, R> Hive for HiveRuntime<P, R>
where
	P: Protocol + PersistentConnection + EncryptedProtocol<CryptoProvider: HandshakeProvider> + Send + Sync + 'static,
	P::Listener: AsyncListenerTrait + Sync + 'static,
	<P::Listener as Protocol>::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	P::Address: Hash + Eq + Clone + Copy + Send + Sync + FromStr + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ MuxConnector
		+ EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
	R: ServletRegistry + 'static,
	TightBeamError: From<P::Error>,
{
	type Protocol = P;
	type Address = P::Address;

	fn register<S, F, Fut>(&mut self, servlet_type: Urn<'static>, servlet: S, spawner: F) -> Result<(), TightBeamError>
	where
		S: ServletBox + 'static,
		F: Fn(Arc<TraceCollector>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<S, TightBeamError>> + Send + 'static,
	{
		// A refused registration stops its servlet, since `stop_boxed` is the
		// one way a servlet stops.
		if let Err(refusal) = self.admit_registration(&servlet_type) {
			Box::new(servlet).stop_boxed();
			return Err(refusal);
		}

		let spawner: SpawnerFn = Arc::new(move |trace| {
			let fut = spawner(trace);
			Box::pin(async move {
				let servlet = fut.await?;
				Ok(Box::new(servlet) as Box<dyn ServletBox>)
			}) as Pin<Box<dyn Future<Output = Result<Box<dyn ServletBox>, TightBeamError>> + Send>>
		});

		// The instance set derives the key and the route of the servlet, and
		// stops each servlet it refuses or replaces.
		let registration = ServletRegistration { servlet: Box::new(servlet), spawner, servlet_type };
		self.instances().insert(registration)?;
		Ok(())
	}

	async fn establish(&mut self, trace: Arc<TraceCollector>) -> Result<(), TightBeamError> {
		if !self.lifecycle.is_provisional() {
			return Err(TightBeamError::AlreadyEstablished);
		}

		// 1. Bind the control plane, for a hive with an identity to present.
		let bound = Self::bind_control_listener(&self.config).await?;
		let hive_addr = bound.as_ref().map(|(_, addr)| *addr);

		// 2. Record the establish ahead of every step that the hive cannot
		//    undo, so a trace that refuses the event drops the bound listener
		//    and leaves the hive provisional.
		Self::record_established(&trace, self.servlets.count(), hive_addr)?;

		// 3. The established hive dials its servlets on a plane of its own
		//    trace, which records the pool and the refused dials.
		let servlet_pool = Self::servlet_pool(&self.config, &trace);
		self.hive_context.establish_plane(servlet_pool, Arc::clone(&trace))?;

		self.trace = trace;
		self.spawners = Arc::new(self.servlets.spawners());

		// 4. Serve the control plane, and commit the lifecycle. Records that
		//    no proven peer backs go on the connection trace (CWE-778).
		let control = bound.map(|(listener, addr)| {
			let mux_offer = self.config.pool.mux_offer.as_ref().map(Arc::clone);
			let plane = AcceptPlane::new(DEFAULT_MAX_SERVER_CONNECTIONS, Arc::clone(&self.config.clock));
			let connections = Arc::new(self.trace.connections());
			let control_ctx = HiveControlCtx::new(self, &connections);
			let handle = control_ctx.serve(listener, plane, mux_offer);

			ControlPlane { handle, addr, connections }
		});
		self.lifecycle = Lifecycle::Established { control };

		self.tasks.adopt(ScalingLoop::new(self, hive_addr).spawn());

		// Gateway registries are soft state, so a hive with a control plane
		// re-announces its slate each interval.
		if let Some(link) = self.cluster_link() {
			self.tasks.adopt(link.spawn_reregister());
		}

		Ok(())
	}

	fn context(&self) -> Arc<dyn HiveContext> {
		Arc::clone(&self.hive_context) as Arc<dyn HiveContext>
	}

	fn addr(&self) -> Option<&Self::Address> {
		self.lifecycle.control().map(|plane| &plane.addr)
	}

	fn connection_trace(&self) -> Option<&TraceCollector> {
		self.lifecycle.control().map(|plane| plane.connections.as_ref())
	}

	fn servlet_addresses(&self) -> Vec<(Urn<'static>, Vec<u8>)> {
		self.servlets.addresses()
	}

	fn stop(mut self) {
		self.release();
	}

	async fn join(mut self) -> Result<(), TightBeamError> {
		let settled = core::mem::replace(&mut self.lifecycle, Lifecycle::Provisional);
		if let Lifecycle::Established { control: Some(plane) } = settled {
			rt::join(plane.handle).await.map_err(|_| TightBeamError::JoinError)?;
		}

		Ok(())
	}

	async fn register_with_cluster(
		&self,
		cluster_addr: &<Self::Protocol as Protocol>::Address,
	) -> Result<RegisterHiveResponse, TightBeamError> {
		// A hive registers the address a cluster dials it back on, so it
		// needs an established control plane. Without one there is no
		// heartbeat or manage target to install.
		let Some(link) = self.cluster_link() else {
			return Err(TightBeamError::NotEstablished);
		};

		let cluster_addr = *cluster_addr;
		let response = link.register(cluster_addr).await?;
		// The hive remembers a gateway only after the gateway accepts, so the
		// re-announce beat and the scaling fan-out skip a gateway that refused.
		if response.status == TransitStatus::Ok {
			link.remember(cluster_addr);
		}

		Ok(response)
	}

	async fn drain(&self) -> Result<(), TightBeamError> {
		self.drain.begin();

		// The beats stop before the wait on commands, because a re-announce or
		// a scale-up that outlived the wait would reinstall the routes this
		// drain withdraws (CWE-362).
		self.tasks.abort_all();

		// One deadline on the hive clock bounds the wait on commands and the
		// servlet drains, whatever each servlet does. The slate announcement
		// follows them.
		let deadline = DrainDeadline::start(self.config.clock.as_ref(), self.config.control.drain_timeout);

		// The wait counts commands in flight, because a control connection
		// idles between commands. The deadline is the backstop for work that
		// outlasts it.
		let settled = self.in_flight.settle(&deadline).await;

		// Either outcome ends drained, so the caller holds a hive with no
		// running servlets. Each servlet drains once the admission lock drops,
		// and one that still drains at the deadline drops, which aborts it.
		let (Settled::Idle | Settled::TimedOut) = settled;
		let drained = self.instances().drain_all();
		let drains = drained.into_iter().map(|registration| registration.servlet.drain_boxed());
		let all_drained = join_all(drains);
		let servlets_drained = deadline.within(all_drained).await;

		// The emptied slate goes out at once, so gateways retire this hive's
		// routes ahead of the heartbeat that would eventually miss.
		if let Some(link) = self.cluster_link() {
			link.announce_slate().await?;
		}

		servlets_drained?.into_iter().collect()
	}

	fn is_draining(&self) -> bool {
		self.drain.is_draining()
	}
}

impl<P: Protocol, R: ServletRegistry> Drop for HiveRuntime<P, R> {
	fn drop(&mut self) {
		self.release();
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::cms::signed_data::SignerIdentifier;
	use crate::colony::hive::fixtures::{echo_type, Probe};
	use crate::colony::hive::ServletScaleConfig;
	use crate::colony::protocol::ServletInfo;
	use crate::tb_cases;
	use crate::testing::TestResult;
	use crate::transport::TokioListener;

	/// A fresh runtime has begun no drain.
	#[test]
	fn a_fresh_runtime_is_not_draining() {
		assert!(!DrainMode::default().is_draining());
	}

	/// Each holder of the drain handle sees a drain that one holder began.
	#[test]
	fn every_holder_of_the_handle_sees_the_drain() {
		let mode = DrainMode::default();
		let reader = mode.clone();
		mode.begin();
		assert!(reader.is_draining());
	}

	// A sibling's dial admits a servlet's answer by its signer alone, so a
	// registration routes a servlet that names its signer and leaves out one
	// that names none.
	tb_cases! {
		fn register_routes_a_servlet_by_its_signer((signer, routed): (Option<SignerIdentifier>, bool)) -> TestResult {
			let mut hive = HiveRuntime::<TokioListener>::new(None)?;
			let probe = Probe::at(b"127.0.0.1:7005").signed(signer);

			hive.register(echo_type(), probe, |_| async { Ok(Probe::at(b"127.0.0.1:7005")) })?;

			assert_eq!(hive.hive_context.resolves(&echo_type()), routed);
			Ok(())
		}
		cases {
			a_signed_servlet_is_routed => (Some(ServletInfo::fixture_signer()), true),
			an_unsigned_servlet_is_left_out => (None, false),
		}
	}

	/// The configuration of a hive whose `echo` type holds one instance at
	/// most.
	fn single_instance_config() -> HiveConfig {
		let mut config = HiveConfig::default();
		let bounds = ServletScaleConfig::single_instance();
		config.scaling.overrides.insert(echo_type(), bounds);
		config
	}

	/// A type at its bound refuses a registration at a second address, so a
	/// registration keeps the bound that a spawn keeps (CWE-770).
	#[test]
	fn a_registration_past_the_bound_of_its_type_is_refused() -> TestResult {
		let mut hive = HiveRuntime::<TokioListener>::new(Some(single_instance_config()))?;
		let spawner = |_| async { Ok(Probe::at(b"127.0.0.1:7005")) };
		hive.register(echo_type(), Probe::at(b"127.0.0.1:7005"), spawner)?;

		let refused = hive.register(echo_type(), Probe::at(b"127.0.0.1:7006"), spawner);
		assert!(matches!(
			refused,
			Err(TightBeamError::WorkRefused(TransitStatus::ResourceExhausted))
		));
		Ok(())
	}
}
