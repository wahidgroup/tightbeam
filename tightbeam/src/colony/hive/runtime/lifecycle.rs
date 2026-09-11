//! Hive lifecycle runtime for protocol `P`.
//!
//! - Owns control, scaling, and re-registration task handles.
//! - Exposes lifecycle through [`Hive`] only.
//! - `hive!` names a type alias of [`HiveRuntime`].

use core::future::Future;
use core::hash::Hash;
use core::pin::Pin;
use core::str::FromStr;
use core::sync::atomic::AtomicU16;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::colony::common::{ColonyResource, DrainMode, TaskGroup};
use crate::colony::hive::runtime::control::InFlight;
use crate::colony::hive::runtime::{ClusterLink, HiveContextImpl, HiveControlCtx, ScalingLoop};
use crate::colony::hive::{
	HashMapRegistry, Hive, HiveConfig, HiveContext, RegisterHiveResponse, ServletBox, ServletRegistration,
	ServletRegistry, SpawnerFn,
};
use crate::colony::servlet::servlet_runtime::rt;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::macros::server::AcceptedConnection;
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::transport::client::pool::{ConnectionBuilder, ConnectionPool};
use crate::transport::multiplex::{MuxCapable, MuxConnector};
use crate::transport::policy::PolicyConfig;
use crate::transport::{
	AsyncListenerTrait, EncryptedProtocol, MessageCollector, MessageEmitter, PersistentConnection, Protocol,
	X509ClientConfig,
};
use crate::utils::urn::{Urn, UrnValidationError};
use crate::TightBeamError;

use crate::colony::hive::{ClusterCircuitBreaker, ReplayGuard};
use crate::transport::TransportEncryptionConfig;

/// The accept plane a cluster reaches this hive on.
///
/// Binding it needs the TLS identity that signs registrations. A cluster
/// refuses an unsigned hive, so a hive with no identity never publishes
/// this address, and an unauthenticated control listener would answer
/// nobody but an attacker (CWE-306).
struct ControlPlane<P: Protocol> {
	/// The accept loop, which [`Hive::join`] awaits.
	handle: rt::JoinHandle,
	/// The address a cluster dials, and the hive's own identity locator.
	addr: P::Address,
}

/// Where a hive sits in its lifecycle.
///
/// Servlet registration closes when the hive establishes, so the two
/// phases hold different things rather than one nullable handle that
/// every guard has to read the same way.
enum Lifecycle<P: Protocol> {
	/// Servlets may still be registered. Nothing is listening.
	Provisional,
	/// Servlets are running. `control` is present for a hive that holds a
	/// TLS identity, and absent for one that can never join a cluster.
	Established { control: Option<ControlPlane<P>> },
}

impl<P: Protocol> Lifecycle<P> {
	/// The control plane, for a hive that established one.
	fn control(&self) -> Option<&ControlPlane<P>> {
		match self {
			Self::Established { control } => control.as_ref(),
			Self::Provisional => None,
		}
	}

	/// Whether servlet registration is still open.
	fn is_provisional(&self) -> bool {
		matches!(self, Self::Provisional)
	}
}

/// Running hive for protocol `P`.
///
/// Owns accept, scaling, and anti-entropy tasks. Callers reach state only
/// through [`Hive`].
pub struct HiveRuntime<P: Protocol> {
	servlets: Arc<HashMapRegistry>,
	spawners: Arc<HashMap<Urn<'static>, SpawnerFn>>,
	config: HiveConfig,
	trace: Arc<TraceCollector>,
	lifecycle: Lifecycle<P>,
	/// Every background task this runtime started.
	tasks: TaskGroup,
	utilization: Arc<AtomicU16>,
	utilization_map: Arc<Mutex<HashMap<Vec<u8>, u16>>>,
	drain: DrainMode,
	/// Commands in flight, which a drain waits to reach zero.
	in_flight: InFlight,
	cluster_addrs: Arc<RwLock<Vec<P::Address>>>,
	hive_context: Arc<HiveContextImpl<P>>,
}

/// How often a drain re-checks whether its commands have finished.
const DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(10);

impl<P: Protocol> HiveRuntime<P> {
	fn abort_tasks(&mut self) {
		self.tasks.abort_all();
		if let Lifecycle::Established { control } = &mut self.lifecycle {
			if let Some(plane) = control.take() {
				rt::abort(&plane.handle);
			}
		}
	}

	fn build_control_ctx(&self) -> HiveControlCtx<P> {
		HiveControlCtx {
			servlets: Arc::clone(&self.servlets),
			spawners: Arc::clone(&self.spawners),
			trace: Arc::clone(&self.trace),
			utilization: Arc::clone(&self.utilization),
			utilization_map: Arc::clone(&self.utilization_map),
			drain: self.drain.clone(),
			in_flight: self.in_flight.clone(),
			hive_context: Arc::clone(&self.hive_context),
			bp_threshold: self.config.control.backpressure_threshold,
			circuit_breaker: Arc::new(ClusterCircuitBreaker::new(
				self.config.control.circuit_breaker_threshold,
				self.config.control.circuit_breaker_cooldown_ms,
			)),
			replay_guard: Arc::new(ReplayGuard::new(self.config.control.command_freshness_window_ms)),
			trust_store: self.config.trust_store.as_ref().map(Arc::clone),
		}
	}
}

impl<P> HiveRuntime<P>
where
	P: Protocol + EncryptedProtocol<CryptoProvider = DefaultCryptoProvider> + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + X509ClientConfig<CryptoProvider = DefaultCryptoProvider> + Send + 'static,
	TightBeamError: From<P::Error>,
{
	/// Binds this hive's slate, gateways, address, and configuration.
	///
	/// [`None`] for a hive with no control plane: it has no address to
	/// register and no cluster can reach it.
	fn cluster_link(&self) -> Option<ClusterLink<P>> {
		let addr = self.lifecycle.control().map(|plane| plane.addr)?;

		Some(ClusterLink::new(
			Arc::clone(&self.servlets),
			Arc::clone(&self.cluster_addrs),
			addr,
			Arc::new(self.config.clone()),
		))
	}

	/// Bind the control plane, for a hive that has an identity to present.
	///
	/// [`None`] where `hive_tls` is unset. Spawn and stop MUST NOT travel
	/// cleartext, and a hive with no identity signs no registration, so no
	/// cluster can learn this address to dial it.
	async fn bind_control_listener(config: &HiveConfig) -> Result<Option<(P::Listener, P::Address)>, TightBeamError> {
		let Some(hive_tls) = config.hive_tls.as_ref() else {
			return Ok(None);
		};

		let bind_addr = P::default_bind_address()?;
		let (certificate, key_manager) = hive_tls.identity().parts();
		let encryption_config = TransportEncryptionConfig::new(certificate, key_manager);
		let encryption_config = encryption_config.with_client_validators(hive_tls.validators.iter().map(Arc::clone));

		Ok(Some(P::bind_with(bind_addr, encryption_config).await?))
	}
}

impl<P> Hive for HiveRuntime<P>
where
	P: Protocol
		+ PersistentConnection
		+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static,
	P::Listener: AsyncListenerTrait + Sync + 'static,
	<P::Listener as Protocol>::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	P::Address: Hash + Eq + Clone + Copy + Send + Sync + FromStr + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ Send
		+ Sync
		+ 'static,
	TightBeamError: From<P::Error>,
{
	type Protocol = P;
	type Address = P::Address;

	fn new(config: Option<HiveConfig>) -> Result<Self, TightBeamError> {
		let config = config.unwrap_or_default();
		let pool_builder = ConnectionPool::<P>::builder().with_config(config.pool.clone());

		// Intra-hive calls validate servlet certificates against the hive trust store.
		let pool_builder = match config.trust_store.as_ref() {
			Some(store) => pool_builder.with_trust_store(Arc::clone(store)),
			None => pool_builder,
		};

		let servlet_pool = Arc::new(pool_builder.build());
		let hive_context = Arc::new(HiveContextImpl::new(servlet_pool));

		Ok(Self {
			servlets: Arc::new(HashMapRegistry::default()),
			spawners: Arc::new(HashMap::new()),
			config,
			trace: Arc::new(TraceCollector::default()),
			lifecycle: Lifecycle::Provisional,
			tasks: TaskGroup::default(),
			utilization: Arc::new(AtomicU16::new(0)),
			utilization_map: Arc::new(Mutex::new(HashMap::new())),
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

		// Refuse type URNs outside this hive namespace or carrying an instance tail.
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

		// Key by instance URN bytes so manage stop and scaling share one lookup.
		let key = servlet_type.instance_urn(servlet.addr_bytes())?.canonical_bytes();
		let registration = ServletRegistration { servlet: Box::new(servlet), spawner, servlet_type };

		self.servlets.insert(key, registration)?;
		Ok(())
	}

	async fn establish(&mut self, trace: Arc<TraceCollector>) -> Result<(), TightBeamError> {
		if !self.lifecycle.is_provisional() {
			return Err(TightBeamError::AlreadyEstablished);
		}

		self.trace = trace;
		self.spawners = Arc::new(self.servlets.spawners());

		self.hive_context.seed_routes(&self.servlets);

		let control = match Self::bind_control_listener(&self.config).await? {
			Some((listener, addr)) => {
				// Share the configured mux offer with the control accept loop.
				let mux_offer = self.config.pool.mux_offer.as_ref().map(Arc::clone);
				let handle = self.build_control_ctx().serve(listener, mux_offer);

				Some(ControlPlane { handle, addr })
			}
			None => None,
		};

		let hive_addr = control.as_ref().map(|plane| plane.addr);
		self.lifecycle = Lifecycle::Established { control };

		self.tasks.adopt(
			ScalingLoop {
				servlets: Arc::clone(&self.servlets),
				spawners: Arc::clone(&self.spawners),
				trace: Arc::clone(&self.trace),
				utilization: Arc::clone(&self.utilization),
				utilization_map: Arc::clone(&self.utilization_map),
				cluster_addrs: Arc::clone(&self.cluster_addrs),
				hive_context: Arc::clone(&self.hive_context),
				hive_addr,
				config: self.config.clone(),
				tasks: self.tasks.clone(),
			}
			.spawn(),
		);

		// Re-announce the slate each interval. Gateway registries are soft
		// state. A hive with no control plane has nothing to announce.
		if let Some(link) = self.cluster_link() {
			self.tasks.adopt(link.spawn_reregister(Arc::clone(&self.trace)));
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
		self.abort_tasks();
		self.servlets
			.drain_all()
			.into_iter()
			.for_each(|(_, reg)| reg.servlet.stop_boxed());
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
		// Remember the gateway only after acceptance so refused peers are not polled.
		if response.status == TransitStatus::Ok {
			link.remember(cluster_addr);
		}

		Ok(response)
	}

	async fn drain(&self) -> Result<(), TightBeamError> {
		self.drain.begin();

		// Stop the beats before waiting on commands. A re-announce or a
		// scale-up that outlived the wait would reinstall the very routes
		// this drain withdraws (CWE-362).
		self.tasks.abort_all();

		let drain_timeout = self.config.control.drain_timeout;
		let start = Instant::now();

		// Wait on commands, not on open connections: a control connection
		// idles between commands by design. The timeout is the backstop for
		// work that outlasts it.
		while !self.in_flight.is_idle() && start.elapsed() < drain_timeout {
			tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
		}

		// Either path ends drained, so a caller that awaited this call holds
		// a hive with no running servlets.
		self.servlets
			.drain_all()
			.into_iter()
			.for_each(|(_, reg)| reg.servlet.stop_boxed());

		// Announce the emptied slate so gateways retire this hive's routes
		// now, ahead of the heartbeat that would eventually miss.
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
		self.abort_tasks();
	}
}
