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

use crate::colony::common::{canonical_bytes, take_and_abort, ColonyResource};
use crate::colony::hive::runtime::{
	instance_urn, register_once, spawn_control_server, spawn_reregister_task, spawn_scaling_task, HiveContextImpl,
	HiveControlCtx, ScalingTaskCtx,
};
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

#[cfg(feature = "x509")]
use crate::colony::hive::{ClusterCircuitBreaker, ReplayGuard};
#[cfg(feature = "x509")]
use crate::crypto::x509::Certificate;
#[cfg(feature = "x509")]
use crate::transport::handshake::HandshakeKeyManager;
#[cfg(feature = "x509")]
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
	control_server_handle: Option<rt::JoinHandle>,
	addr: P::Address,
	scaling_handle: Option<rt::JoinHandle>,
	utilization: Arc<AtomicU16>,
	utilization_map: Arc<Mutex<HashMap<Vec<u8>, u16>>>,
	draining_since: Arc<RwLock<Option<Instant>>>,
	cluster_addrs: Arc<RwLock<Vec<P::Address>>>,
	reregister_handle: Option<rt::JoinHandle>,
	hive_context: Arc<HiveContextImpl<P>>,
}

impl<P: Protocol> HiveRuntime<P> {
	fn abort_tasks(&mut self) {
		take_and_abort(&mut self.scaling_handle);
		take_and_abort(&mut self.reregister_handle);
		take_and_abort(&mut self.control_server_handle);
	}

	fn build_control_ctx(&self) -> HiveControlCtx<P> {
		HiveControlCtx {
			servlets: Arc::clone(&self.servlets),
			spawners: Arc::clone(&self.spawners),
			trace: Arc::clone(&self.trace),
			utilization: Arc::clone(&self.utilization),
			utilization_map: Arc::clone(&self.utilization_map),
			draining_since: Arc::clone(&self.draining_since),
			hive_context: Arc::clone(&self.hive_context),
			bp_threshold: self.config.control.backpressure_threshold,
			#[cfg(feature = "x509")]
			circuit_breaker: Arc::new(ClusterCircuitBreaker::new(
				self.config.control.circuit_breaker_threshold,
				self.config.control.circuit_breaker_cooldown_ms,
			)),
			#[cfg(feature = "x509")]
			replay_guard: Arc::new(ReplayGuard::new(self.config.control.command_freshness_window_ms)),
			#[cfg(feature = "x509")]
			trust_store: self.config.trust_store.as_ref().map(Arc::clone),
		}
	}
}

impl<P> HiveRuntime<P>
where
	P: Protocol + EncryptedProtocol<CryptoProvider = DefaultCryptoProvider> + Send + Sync + 'static,
	P::Address: Clone + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	TightBeamError: From<P::Error>,
{
	/// Encrypt the control plane when hive_tls is set (spawn/stop must not travel cleartext).
	async fn bind_control_listener(config: &HiveConfig) -> Result<(P::Listener, P::Address), TightBeamError> {
		let bind_addr = P::default_bind_address()?;

		#[cfg(feature = "x509")]
		{
			match config.hive_tls.as_ref() {
				Some(hive_tls) => {
					let certificate = Certificate::try_from(hive_tls.certificate.clone())?;
					let key_manager = HandshakeKeyManager::new(Arc::clone(&hive_tls.key));
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

		#[cfg(not(feature = "x509"))]
		{
			let _ = config;
			Ok(P::bind(bind_addr).await?)
		}
	}
}

fn collect_spawners(servlets: &HashMapRegistry) -> HashMap<Urn<'static>, SpawnerFn> {
	let mut spawners = HashMap::new();
	servlets.for_each(|_key, reg| {
		spawners.insert(reg.servlet_type.clone(), Arc::clone(&reg.spawner));
	});

	spawners
}

fn seed_hive_routes<P: Protocol>(servlets: &HashMapRegistry, hive_context: &HiveContextImpl<P>) {
	servlets.for_each(|key, reg| {
		let addr_bytes = reg.servlet.addr_bytes();
		let type_key = canonical_bytes(&reg.servlet_type);
		// for_each borrows the registry key; add_route needs an owned copy.
		hive_context.add_route(key.clone(), addr_bytes, &type_key);
	});
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
		#[cfg(feature = "x509")]
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
			scaling_handle: None,
			utilization: Arc::new(AtomicU16::new(0)),
			utilization_map: Arc::new(Mutex::new(HashMap::new())),
			draining_since: Arc::new(RwLock::new(None)),
			cluster_addrs: Arc::new(RwLock::new(Vec::new())),
			reregister_handle: None,
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
		let key = canonical_bytes(&instance_urn(&servlet_type, servlet.addr_bytes())?);
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
		self.spawners = Arc::new(collect_spawners(&self.servlets));

		seed_hive_routes(&self.servlets, &self.hive_context);

		// Share the configured mux offer with the control accept loop.
		let mux_offer = self.config.pool.mux_offer.as_ref().map(Arc::clone);
		let control_ctx = self.build_control_ctx();

		self.control_server_handle = Some(spawn_control_server::<P>(listener, mux_offer, control_ctx));
		self.scaling_handle = Some(spawn_scaling_task::<P>(ScalingTaskCtx {
			servlets: Arc::clone(&self.servlets),
			spawners: Arc::clone(&self.spawners),
			trace: Arc::clone(&self.trace),
			utilization: Arc::clone(&self.utilization),
			utilization_map: Arc::clone(&self.utilization_map),
			cluster_addrs: Arc::clone(&self.cluster_addrs),
			hive_context: Arc::clone(&self.hive_context),
			hive_addr: self.addr,
			config: self.config.clone(),
		}));

		// Re-announce the slate each interval; gateway registries are soft state.
		self.reregister_handle = Some(spawn_reregister_task::<P>(
			Arc::clone(&self.servlets),
			Arc::clone(&self.trace),
			Arc::clone(&self.cluster_addrs),
			self.addr,
			self.config.clone(),
		));

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
		let cluster_addr = *cluster_addr;
		let response = register_once::<P>(&*self.servlets, self.addr, cluster_addr, &self.config).await?;

		// Remember the gateway only after acceptance so refused peers are not polled.
		if response.status == TransitStatus::Ok {
			if let Ok(mut addrs) = self.cluster_addrs.write() {
				let incoming: Vec<u8> = cluster_addr.into();
				let known = addrs.iter().any(|addr| {
					let bytes: Vec<u8> = (*addr).into();
					bytes == incoming
				});
				if !known {
					addrs.push(cluster_addr);
				}
			}
		}

		Ok(response)
	}

	async fn drain(&self) -> Result<(), TightBeamError> {
		{
			let mut guard = self.draining_since.write().map_err(|_| TightBeamError::LockPoisoned)?;
			*guard = Some(Instant::now());
		}

		let drain_timeout = self.config.control.drain_timeout;
		let start = Instant::now();

		loop {
			let timed_out = start.elapsed() >= drain_timeout;
			if self.servlets.count() == 0 || timed_out {
				if timed_out {
					self.servlets
						.drain_all()
						.into_iter()
						.for_each(|(_, reg)| reg.servlet.stop_boxed());
				}
				break;
			}

			tokio::time::sleep(Duration::from_millis(100)).await;
		}

		Ok(())
	}

	fn is_draining(&self) -> bool {
		self.draining_since.read().map(|g| g.is_some()).unwrap_or(false)
	}
}

impl<P: Protocol> Drop for HiveRuntime<P> {
	fn drop(&mut self) {
		self.abort_tasks();
	}
}
