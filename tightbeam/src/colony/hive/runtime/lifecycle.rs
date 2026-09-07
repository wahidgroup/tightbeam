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

/// Running hive for protocol `P`.
///
/// Owns accept, scaling, and anti-entropy tasks. Callers reach state only
/// through [`Hive`].
pub struct HiveRuntime<P: Protocol> {
	servlets: Arc<HashMapRegistry>,
	spawners: Arc<HashMap<Urn<'static>, SpawnerFn>>,
	config: HiveConfig,
	trace: Arc<TraceCollector>,
	/// The control accept loop, which [`Hive::join`] awaits.
	control_server_handle: Option<rt::JoinHandle>,
	addr: P::Address,
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
		rt::take_and_abort(&mut self.control_server_handle);
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
	fn cluster_link(&self) -> ClusterLink<P> {
		ClusterLink::new(
			Arc::clone(&self.servlets),
			Arc::clone(&self.cluster_addrs),
			self.addr,
			Arc::new(self.config.clone()),
		)
	}

	/// Encrypt the control plane when hive_tls is set (spawn/stop must not travel cleartext).
	async fn bind_control_listener(config: &HiveConfig) -> Result<(P::Listener, P::Address), TightBeamError> {
		let bind_addr = P::default_bind_address()?;

		{
			match config.hive_tls.as_ref() {
				Some(hive_tls) => {
					let (certificate, key_manager) = hive_tls.identity()?;
					let mut encryption_config = TransportEncryptionConfig::new(certificate, key_manager);
					if !hive_tls.validators.is_empty() {
						let validators: Vec<_> = hive_tls.validators.iter().map(Arc::clone).collect();
						encryption_config = encryption_config.with_client_validators(validators);
					}

					Ok(P::bind_with(bind_addr, encryption_config).await?)
				}
				None => Ok(P::bind(bind_addr).await?),
			}
		}
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
		let addr = P::default_bind_address()?;

		Ok(Self {
			servlets: Arc::new(HashMapRegistry::default()),
			spawners: Arc::new(HashMap::new()),
			config,
			trace: Arc::new(TraceCollector::default()),
			control_server_handle: None,
			addr,
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
		if self.control_server_handle.is_some() {
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
		if self.control_server_handle.is_some() {
			return Err(TightBeamError::AlreadyEstablished);
		}

		self.trace = trace;

		let (listener, addr) = Self::bind_control_listener(&self.config).await?;

		self.addr = addr;
		self.spawners = Arc::new(self.servlets.spawners());

		self.hive_context.seed_routes(&self.servlets);

		// Share the configured mux offer with the control accept loop.
		let mux_offer = self.config.pool.mux_offer.as_ref().map(Arc::clone);
		let control_ctx = self.build_control_ctx();

		self.control_server_handle = Some(control_ctx.serve(listener, mux_offer));
		self.tasks.adopt(
			ScalingLoop {
				servlets: Arc::clone(&self.servlets),
				spawners: Arc::clone(&self.spawners),
				trace: Arc::clone(&self.trace),
				utilization: Arc::clone(&self.utilization),
				utilization_map: Arc::clone(&self.utilization_map),
				cluster_addrs: Arc::clone(&self.cluster_addrs),
				hive_context: Arc::clone(&self.hive_context),
				hive_addr: self.addr,
				config: self.config.clone(),
				tasks: self.tasks.clone(),
			}
			.spawn(),
		);

		// Re-announce the slate each interval. Gateway registries are soft state.
		self.tasks.adopt(self.cluster_link().spawn_reregister(Arc::clone(&self.trace)));

		Ok(())
	}

	fn context(&self) -> Arc<dyn HiveContext> {
		Arc::clone(&self.hive_context) as Arc<dyn HiveContext>
	}

	fn addr(&self) -> &Self::Address {
		&self.addr
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
		if let Some(handle) = self.control_server_handle.take() {
			rt::join(handle).await.map_err(|_| TightBeamError::JoinError)?;
		}

		Ok(())
	}

	async fn register_with_cluster(
		&self,
		cluster_addr: &<Self::Protocol as Protocol>::Address,
	) -> Result<RegisterHiveResponse, TightBeamError> {
		// Control addr is provisional until establish binds the listener.
		// Registering early would install a wrong heartbeat/manage target.
		if self.control_server_handle.is_none() {
			return Err(TightBeamError::NotEstablished);
		}

		let cluster_addr = *cluster_addr;
		let link = self.cluster_link();
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
		self.cluster_link().announce_slate().await;

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
