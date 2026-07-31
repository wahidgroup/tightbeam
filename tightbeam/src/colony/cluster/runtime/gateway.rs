use core::marker::PhantomData;
use std::sync::Arc;

use crate::colony::cluster::outbound::build_cluster_pools;
use crate::colony::cluster::runtime::bounds::{ClusterDigest, ClusterPool, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::dispatch::handle_gateway_request;
use crate::colony::cluster::runtime::gossip_tasks::{build_advertise_task, peer_dial_pool};
use crate::colony::cluster::runtime::heartbeat::{send_heartbeat_async, spawn_evaporation_loop, spawn_heartbeat_loop};
use crate::colony::cluster::{Cluster, ClusterConfig, ClusterError, ClusterHeartbeat, HiveRegistry, ServletRegistry};
use crate::colony::common::take_and_abort;
use crate::colony::servlet::servlet_runtime::rt;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::macros::server::{into_shared_session_handler, serve_connection, AcceptedConnection};
use crate::trace::TraceCollector;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::{MuxCapable, MuxConnector};
use crate::transport::policy::PolicyConfig;
use crate::transport::{
	AsyncListenerTrait, EncryptedProtocol, PersistentConnection, Protocol, TransportError, X509ClientConfig,
};
use crate::Frame;
use crate::TightBeamError;

fn protocol_error<E: Into<TransportError>>(error: E) -> TightBeamError {
	TightBeamError::from(error.into())
}

#[cfg(feature = "x509")]
use crate::colony::hive::ReplayGuard;

/// Running cluster gateway for protocol `P` and digest `D`.
///
/// - Owns accept, heartbeat, evaporation, and advertise task handles.
/// - Exposes state through [`Cluster`] / [`ClusterHeartbeat`] only.
pub struct ClusterGateway<P, D = crate::crypto::hash::Sha3_256>
where
	P: Protocol,
{
	registry: Arc<HiveRegistry>,
	servlet_registry: Arc<ServletRegistry>,
	config: Arc<ClusterConfig>,
	pool: Arc<ClusterPool<P>>,
	server_handle: Option<rt::JoinHandle>,
	heartbeat_handle: Option<rt::JoinHandle>,
	evaporation_handle: Option<rt::JoinHandle>,
	advertise_handle: Option<rt::JoinHandle>,
	addr: P::Address,
	trace: Arc<TraceCollector>,
	_digest: PhantomData<D>,
}

impl<P, D> ClusterGateway<P, D>
where
	P: Protocol
		+ PersistentConnection
		+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static,
	P::Listener: AsyncListenerTrait + Sync + 'static,
	<P::Listener as Protocol>::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync + core::str::FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ crate::transport::state::EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
	D: ClusterDigest,
{
	fn abort_tasks(&mut self) {
		take_and_abort(&mut self.advertise_handle);
		take_and_abort(&mut self.evaporation_handle);
		take_and_abort(&mut self.heartbeat_handle);
		take_and_abort(&mut self.server_handle);
	}
}

impl<P, D> Cluster for ClusterGateway<P, D>
where
	P: Protocol
		+ PersistentConnection
		+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static,
	P::Listener: AsyncListenerTrait + Sync + 'static,
	<P::Listener as Protocol>::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync + core::str::FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ crate::transport::state::EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
	D: ClusterDigest,
{
	type Protocol = P;
	type Address = P::Address;

	async fn start(trace: Arc<TraceCollector>, config: ClusterConfig) -> Result<Self, TightBeamError> {
		// The admission freshness window MUST NOT outlive journal
		// retention: a rumor older than retention has no digest
		// left to deduplicate against, so a wider window would
		// re-admit a replayed rumor as new (CWE-294). Clamped
		// here, where the config becomes immutable, so mutation
		// after the builder cannot widen the window.
		#[cfg(feature = "x509")]
		let config = {
			let mut config = config;
			let retention = core::time::Duration::from_millis(config.gossip.journal.retention_ms());
			if config.gossip.seen_ttl > retention {
				config.gossip.seen_ttl = retention;
			}
			config
		};

		let config = Arc::new(config);

		// The gateway always serves TLS when x509 is enabled;
		// an empty client_validators list means server-auth only.
		let bind_addr = match config.bind_addr.as_deref() {
			Some(raw) => raw.parse().map_err(|_| TransportError::InvalidMessage)?,
			None => P::default_bind_address().map_err(protocol_error)?,
		};

		#[cfg(feature = "x509")]
		let (listener, addr) = {
			let cert_obj = crate::crypto::x509::Certificate::try_from(config.tls.certificate.clone())?;
			let key_mgr = crate::transport::handshake::HandshakeKeyManager::new(Arc::clone(&config.tls.key));
			let mut encryption_config = crate::transport::TransportEncryptionConfig::new(cert_obj, key_mgr);
			if !config.tls.client_validators.is_empty() {
				let validators: Vec<_> = config.tls.client_validators.iter().map(Arc::clone).collect();
				encryption_config = encryption_config.with_client_validators(validators);
			}

			P::bind_with(bind_addr, encryption_config).await.map_err(protocol_error)?
		};

		#[cfg(not(feature = "x509"))]
		let (listener, addr) = P::bind(bind_addr).await.map_err(protocol_error)?;

		let registry = Arc::new(HiveRegistry::new(config.heartbeat.timeout));
		let servlet_registry = Arc::new(ServletRegistry::new(config.pheromone.clone()));

		let pools = build_cluster_pools::<P>(config.pool_config.clone(), &config.tls)?;
		let pool = pools.hive;
		let peer_pool = pools.peer;

		#[cfg(feature = "x509")]
		let replay_guard_for_server = Arc::new(ReplayGuard::new(config.control_freshness_window_ms));
		#[cfg(not(feature = "x509"))]
		let replay_guard_for_server = ();

		let server_handle = spawn_gateway_server::<P, D>(
			listener,
			GatewayRuntimeCtx {
				registry: Arc::clone(&registry),
				servlet_registry: Arc::clone(&servlet_registry),
				config: Arc::clone(&config),
				pool: Arc::clone(&pool),
				peer_pool: peer_pool.as_ref().map(Arc::clone),
				trace: Arc::clone(&trace),
				replay_guard: replay_guard_for_server,
			},
		);

		let heartbeat_handle = spawn_heartbeat_loop::<P, D>(
			Arc::clone(&registry),
			Arc::clone(&servlet_registry),
			Arc::clone(&config),
			Arc::clone(&pool),
			Arc::clone(&trace),
		);

		let evaporation_handle =
			spawn_evaporation_loop(Arc::clone(&servlet_registry), config.pheromone.evaporation_interval);

		#[cfg(feature = "x509")]
		let advertise_handle = {
			let advertise_pool = peer_dial_pool(&peer_pool, &pool);
			let gateway_bytes: Vec<u8> = addr.clone().into();
			let gateway_addr: Arc<[u8]> = Arc::from(gateway_bytes);
			Some(build_advertise_task::<P, D>(
				Arc::clone(&servlet_registry),
				advertise_pool,
				Arc::clone(&pool),
				Arc::clone(&config),
				gateway_addr,
				Arc::clone(&trace),
			))
		};
		#[cfg(not(feature = "x509"))]
		let advertise_handle = None;

		Ok(Self {
			registry,
			servlet_registry,
			config,
			pool,
			server_handle: Some(server_handle),
			heartbeat_handle: Some(heartbeat_handle),
			evaporation_handle: Some(evaporation_handle),
			advertise_handle,
			addr,
			trace,
			_digest: PhantomData,
		})
	}

	fn addr(&self) -> &Self::Address {
		&self.addr
	}

	fn available_servlets(&self) -> Vec<crate::colony::cluster::SharedId> {
		self.registry.to_available_servlets().unwrap_or_default()
	}

	fn peer_servlets(&self) -> Vec<crate::colony::cluster::SharedId> {
		let mut types: Vec<crate::colony::cluster::SharedId> = self
			.servlet_registry
			.peer_entries()
			.unwrap_or_default()
			.into_iter()
			.map(|entry| Arc::clone(entry.servlet_type()))
			.collect();
		types.sort_unstable();
		types.dedup();
		types
	}

	fn peer_routes(&self) -> Vec<crate::colony::cluster::PeerRouteInfo> {
		self.servlet_registry
			.peer_entries()
			.unwrap_or_default()
			.into_iter()
			.filter_map(|entry| entry.peer_route_info())
			.collect()
	}

	fn hive_count(&self) -> usize {
		self.registry.len().unwrap_or(0)
	}

	fn trace(&self) -> Arc<TraceCollector> {
		Arc::clone(&self.trace)
	}

	fn stop(mut self) {
		self.abort_tasks();
	}

	async fn join(mut self) -> Result<(), rt::JoinError> {
		if let Some(handle) = self.server_handle.take() {
			rt::join(handle).await
		} else {
			Ok(())
		}
	}
}

impl<P, D> ClusterHeartbeat for ClusterGateway<P, D>
where
	P: Protocol
		+ PersistentConnection
		+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static,
	P::Listener: AsyncListenerTrait + Sync + 'static,
	<P::Listener as Protocol>::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync + core::str::FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ crate::transport::state::EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
	D: ClusterDigest,
{
	fn registry(&self) -> &Arc<HiveRegistry> {
		&self.registry
	}

	fn heartbeat_config(&self) -> &crate::colony::cluster::HeartbeatConfig {
		&self.config.heartbeat
	}

	async fn send_heartbeat(
		&self,
		addr: Self::Address,
	) -> Result<crate::colony::common::HeartbeatResult, ClusterError> {
		send_heartbeat_async::<P, D>(Arc::clone(&self.pool), Arc::clone(&self.config), addr).await
	}
}

impl<P, D> Drop for ClusterGateway<P, D>
where
	P: Protocol,
{
	fn drop(&mut self) {
		take_and_abort(&mut self.advertise_handle);
		take_and_abort(&mut self.evaporation_handle);
		take_and_abort(&mut self.heartbeat_handle);
		take_and_abort(&mut self.server_handle);
	}
}

/// Spawn the gateway accept loop that dispatches [`handle_gateway_request`].
pub(crate) fn spawn_gateway_server<P, D>(listener: P::Listener, ctx: GatewayRuntimeCtx<P>) -> rt::JoinHandle
where
	P: Protocol
		+ PersistentConnection
		+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static,
	P::Listener: AsyncListenerTrait + Sync + 'static,
	<P::Listener as Protocol>::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync + core::str::FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ crate::transport::state::EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
	D: ClusterDigest,
{
	let mux_offer = ctx.config.pool_config.mux_offer.to_owned();
	let handler = into_shared_session_handler(move |frame: Frame, session| {
		let ctx = ctx.clone();
		async move { handle_gateway_request::<P, D>(frame, session, ctx).await }
	});

	rt::spawn(async move {
		let permits = Arc::new(tokio::sync::Semaphore::new(crate::constants::DEFAULT_MAX_SERVER_CONNECTIONS));
		loop {
			let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
				break;
			};
			match listener.accept().await {
				Ok((mut transport, _addr)) => {
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
