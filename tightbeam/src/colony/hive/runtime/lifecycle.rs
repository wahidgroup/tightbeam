//! The hive lifecycle runtime for a protocol `P`.
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
use std::sync::{Arc, RwLock};

use crate::colony::hive::runtime::control::{InFlight, Settled};
use crate::colony::hive::runtime::{ClusterLink, HiveContextImpl, HiveControlCtx, ScalingLoop};
use crate::colony::hive::{
	HashMapRegistry, Hive, HiveConfig, HiveContext, ServletBox, ServletRegistration, ServletRegistry, SpawnerFn,
};
use crate::colony::protocol::RegisterHiveResponse;
use crate::colony::urn::ColonyResource;
use crate::colony::TaskGroup;
use crate::constants::DEFAULT_MAX_SERVER_CONNECTIONS;
use crate::instrumentation::events::HIVE_ESTABLISHED;
use crate::macros::server::AcceptedConnection;
use crate::policy::TransitStatus;
use crate::runtime::rt;
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

use crate::colony::hive::{BackpressureGate, ClusterSecurityGate, GateLimits};
use crate::crypto::x509::store::CertificateTrust;
use crate::transport::state::EncryptedProtocolState;

/// The accept plane a cluster reaches this hive on.
///
/// The hive binds it only under the TLS identity that signs registrations.
/// A cluster refuses an unsigned hive, so only a hive with an identity
/// publishes this address, and an unauthenticated control listener would
/// answer only an attacker (CWE-306).
struct ControlPlane<P: Protocol> {
	/// The accept loop, which [`Hive::join`] awaits.
	handle: rt::JoinHandle,
	/// The address a cluster dials, and the hive's own identity locator.
	addr: P::Address,
}

/// Where a hive sits in its lifecycle.
///
/// Servlet registration closes when the hive establishes, so each phase
/// holds its own state, in place of one nullable handle that every guard has
/// to read the same way.
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
/// The hive drain aborts the scaling loop and the re-announce loop through the
/// runtime's [`TaskGroup`] before it waits on commands in flight.
///
/// Drain is terminal. A runtime that has entered it stays in it.
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

/// A running hive for a protocol `P`.
///
/// The runtime owns the accept, scaling, and anti-entropy tasks, and callers
/// reach its state only through [`Hive`].
pub struct HiveRuntime<P: Protocol> {
	servlets: Arc<HashMapRegistry>,
	spawners: Arc<HashMap<Urn<'static>, SpawnerFn>>,
	config: HiveConfig,
	trace: Arc<TraceCollector>,
	lifecycle: Lifecycle<P>,
	/// Every background task that this runtime starts.
	tasks: TaskGroup,
	utilization: Arc<AtomicU16>,
	drain: DrainMode,
	/// The count of commands in flight, which a drain waits to see at zero.
	in_flight: InFlight,
	cluster_addrs: Arc<RwLock<Vec<P::Address>>>,
	hive_context: Arc<HiveContextImpl<P>>,
}

impl<P: Protocol> HiveRuntime<P> {
	/// Aborts the hive's tasks and its control plane, and stops every
	/// registered servlet. Both `stop` and `Drop` run it, so a dropped hive
	/// leaks no servlet.
	fn release(&mut self) {
		self.tasks.abort_all();
		if let Lifecycle::Established { control } = &mut self.lifecycle {
			if let Some(plane) = control.take() {
				rt::abort(&plane.handle);
			}
		}

		self.servlets
			.drain_all()
			.into_iter()
			.for_each(|(_, reg)| reg.servlet.stop_boxed());
	}

	fn build_control_ctx(&self) -> HiveControlCtx<P> {
		HiveControlCtx {
			servlets: Arc::clone(&self.servlets),
			spawners: Arc::clone(&self.spawners),
			trace: Arc::clone(&self.trace),
			drain: self.drain.clone(),
			in_flight: self.in_flight.clone(),
			hive_context: Arc::clone(&self.hive_context),
			backpressure: BackpressureGate::new(
				Arc::clone(&self.utilization),
				self.config.control.backpressure_threshold,
			),
			security: self.config.trust_store.as_ref().map(|store| self.security_gate(store)),
		}
	}

	/// Builds the pool the hive's servlets call their siblings on, which reads
	/// `config` and records its dials and the sessions they open into `trace`.
	///
	/// # Warning
	///
	/// The trace holds the session of each sibling dial, a session that the
	/// sibling fails included. The default `BoundedMemorySink` drops each
	/// event past `max_events`, the hive's own included, so a long-lived hive
	/// needs an `EventSink` that forwards each event, or a reader that drains
	/// the trace.
	// The `instrument` build alone attaches a trace to a pool, so that build
	// alone reads `trace`.
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
	/// - The injected error, when the runtime fault model injects a fault at the event.
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

	/// The control plane's one admission gate, which trusts `store` and reads
	/// the hive clock.
	fn security_gate(&self, store: &Arc<dyn CertificateTrust>) -> ClusterSecurityGate {
		let control = &self.config.control;
		let limits = GateLimits {
			failure_threshold: control.circuit_breaker_threshold,
			cooldown: control.circuit_breaker_cooldown,
			freshness_window: control.command_freshness_window,
		};

		ClusterSecurityGate::new(Arc::clone(store), limits, Arc::clone(&self.config.clock))
	}
}

impl<P> HiveRuntime<P>
where
	P: Protocol + EncryptedProtocol<CryptoProvider: HandshakeProvider> + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + MuxCapable + EncryptedProtocolState + Send + 'static,
	TightBeamError: From<P::Error>,
{
	/// Binds this hive's slate, gateways, address, configuration, and trace.
	///
	/// It returns [`None`] for a hive with no control plane, which has no
	/// address to register and which no cluster can reach.
	fn cluster_link(&self) -> Option<ClusterLink<P>> {
		let addr = self.lifecycle.control().map(|plane| plane.addr)?;

		Some(ClusterLink::new(
			Arc::clone(&self.servlets),
			Arc::clone(&self.cluster_addrs),
			addr,
			Arc::new(self.config.clone()),
			Arc::clone(&self.trace),
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
}

impl<P> Hive for HiveRuntime<P>
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
	TightBeamError: From<P::Error>,
{
	type Protocol = P;
	type Address = P::Address;

	fn new(config: Option<HiveConfig>) -> Result<Self, TightBeamError> {
		let config = config.unwrap_or_default();
		let trace = Arc::new(TraceCollector::default());
		let servlet_pool = Self::servlet_pool(&config, &trace);
		let hive_context = Arc::new(HiveContextImpl::new(servlet_pool).with_trace(Arc::clone(&trace)));

		Ok(Self {
			servlets: Arc::new(HashMapRegistry::default()),
			spawners: Arc::new(HashMap::new()),
			config,
			trace,
			lifecycle: Lifecycle::Provisional,
			tasks: TaskGroup::default(),
			utilization: Arc::new(AtomicU16::new(0)),
			drain: DrainMode::default(),
			in_flight: InFlight::default(),
			cluster_addrs: Arc::new(RwLock::new(Vec::new())),
			hive_context,
		})
	}

	fn register<S, F, Fut>(&mut self, servlet_type: Urn<'static>, servlet: S, spawner: F) -> Result<(), TightBeamError>
	where
		S: ServletBox + 'static,
		F: Fn(Arc<TraceCollector>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<S, TightBeamError>> + Send + 'static,
	{
		if !self.lifecycle.is_provisional() {
			return Err(TightBeamError::AlreadyEstablished);
		}

		// A registration names a servlet type, so its URN MUST sit in this
		// hive's namespace and carry no instance tail.
		match self.config.namespace.validate(&servlet_type)? {
			ColonyResource::Servlet { instance: None, .. } => {}
			_ => {
				return Err(TightBeamError::UrnValidationError(UrnValidationError::InvalidFormat {
					field: "resource-id",
					pattern: None,
				}))
			}
		}

		let spawner: SpawnerFn = Arc::new(move |trace| {
			let fut = spawner(trace);
			Box::pin(async move {
				let servlet = fut.await?;
				Ok(Box::new(servlet) as Box<dyn ServletBox>)
			}) as Pin<Box<dyn Future<Output = Result<Box<dyn ServletBox>, TightBeamError>> + Send>>
		});

		// The key is the instance URN bytes, so a manage stop and scaling
		// share one lookup.
		let key = servlet_type.instance_urn(servlet.addr_bytes())?.canonical_bytes();
		let registration = ServletRegistration { servlet: Box::new(servlet), spawner, servlet_type };

		self.servlets
			.insert(key, registration)
			.map_err(|refused| refused.stop_servlet())
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

		// 3. The pool and the refused dials record into the trace of the hive
		//    that builds the pool, so the established hive dials its servlets
		//    on a plane of its own trace.
		let servlet_pool = Self::servlet_pool(&self.config, &trace);
		self.hive_context.establish_plane(servlet_pool, Arc::clone(&trace))?;

		self.trace = trace;
		self.spawners = Arc::new(self.servlets.spawners());
		self.hive_context.seed_routes(&self.servlets);

		// 4. Serve the control plane, and commit the lifecycle.
		let control = bound.map(|(listener, addr)| {
			let mux_offer = self.config.pool.mux_offer.as_ref().map(Arc::clone);
			let plane = AcceptPlane::new(DEFAULT_MAX_SERVER_CONNECTIONS, Arc::clone(&self.config.clock));
			let handle = self.build_control_ctx().serve(listener, plane, mux_offer);

			ControlPlane { handle, addr }
		});
		self.lifecycle = Lifecycle::Established { control };

		self.tasks.adopt(
			ScalingLoop {
				servlets: Arc::clone(&self.servlets),
				spawners: Arc::clone(&self.spawners),
				trace: Arc::clone(&self.trace),
				utilization: Arc::clone(&self.utilization),
				cluster_addrs: Arc::clone(&self.cluster_addrs),
				hive_context: Arc::clone(&self.hive_context),
				hive_addr,
				config: self.config.clone(),
				tasks: self.tasks.clone(),
			}
			.spawn(),
		);

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

		// The wait counts commands in flight, because a control connection
		// idles between commands by design. The timeout is the backstop for
		// work that outlasts it.
		let drain_timeout = self.config.control.drain_timeout;
		let settled = self.in_flight.settle(self.config.clock.as_ref(), drain_timeout).await;

		// Either outcome ends drained, so a caller that awaited this call
		// holds a hive with no running servlets.
		let (Settled::Idle | Settled::TimedOut) = settled;
		self.servlets
			.drain_all()
			.into_iter()
			.for_each(|(_, reg)| reg.servlet.stop_boxed());

		// The emptied slate goes out at once, so gateways retire this hive's
		// routes ahead of the heartbeat that would eventually miss.
		if let Some(link) = self.cluster_link() {
			link.announce_slate().await;
		}

		Ok(())
	}

	fn is_draining(&self) -> bool {
		self.drain.is_draining()
	}
}

impl<P: Protocol> Drop for HiveRuntime<P> {
	fn drop(&mut self) {
		self.release();
	}
}

#[cfg(test)]
mod tests {
	use super::DrainMode;

	#[test]
	fn a_fresh_runtime_is_not_draining() {
		assert!(!DrainMode::default().is_draining());
	}

	#[test]
	fn every_holder_of_the_handle_sees_the_drain() {
		let mode = DrainMode::default();
		let reader = mode.clone();
		mode.begin();
		assert!(reader.is_draining());
	}
}
