//! Builders for [`ClusterConfig`] and heartbeat settings.

use core::time::Duration;
use std::sync::Arc;

use super::{
	ClusterConfig, ClusterTlsConfig, HeartbeatCallback, HeartbeatConfig, PeerConfig, PheromoneConfig,
	DEFAULT_HEARTBEAT_INTERVAL_SECS, DEFAULT_HEARTBEAT_TIMEOUT_SECS, DEFAULT_MAX_CONCURRENT, DEFAULT_MAX_FAILURES,
};
#[cfg(feature = "x509")]
use super::{MemoryPeerStore, PeerStore, PeerTable};
use crate::colony::common::{ColonyNamespace, LoadBalancer, StochasticForager};
use crate::policy::GatePolicy;
use crate::transport::client::pool::PoolConfig;

#[cfg(feature = "x509")]
use super::{cert_colony_urn, GossipAdmission, GossipConfig};
#[cfg(feature = "x509")]
use crate::crypto::x509::Certificate;
#[cfg(feature = "x509")]
use crate::utils::urn::Urn;

// ============================================================================
// HeartbeatConfigBuilder
// ============================================================================

/// Builder for HeartbeatConfig
pub struct HeartbeatConfigBuilder {
	interval: Duration,
	timeout: Duration,
	max_concurrent: usize,
	max_failures: u32,
	on_heartbeat: Option<HeartbeatCallback>,
}

impl Default for HeartbeatConfigBuilder {
	fn default() -> Self {
		Self {
			interval: Duration::from_secs(DEFAULT_HEARTBEAT_INTERVAL_SECS),
			timeout: Duration::from_secs(DEFAULT_HEARTBEAT_TIMEOUT_SECS),
			max_concurrent: DEFAULT_MAX_CONCURRENT,
			max_failures: DEFAULT_MAX_FAILURES,
			on_heartbeat: None,
		}
	}
}

impl HeartbeatConfig {
	/// Create a builder for HeartbeatConfig
	pub fn builder() -> HeartbeatConfigBuilder {
		HeartbeatConfigBuilder::default()
	}
}

impl HeartbeatConfigBuilder {
	/// Set the interval between heartbeat checks
	pub fn with_interval(mut self, interval: Duration) -> Self {
		self.interval = interval;
		self
	}

	/// Set the timeout before evicting unresponsive hives
	pub fn with_timeout(mut self, timeout: Duration) -> Self {
		self.timeout = timeout;
		self
	}

	/// Set the maximum number of failed heartbeats before eviction
	pub fn with_max_failures(mut self, max: u32) -> Self {
		self.max_failures = max;
		self
	}

	/// Set the maximum number of concurrent heartbeat requests
	pub fn with_max_concurrent(mut self, max: usize) -> Self {
		self.max_concurrent = max;
		self
	}

	/// Set the callback for heartbeat events
	pub fn with_callback(mut self, callback: HeartbeatCallback) -> Self {
		self.on_heartbeat = Some(callback);
		self
	}

	/// Build the HeartbeatConfig
	pub fn build(self) -> HeartbeatConfig {
		HeartbeatConfig {
			interval: self.interval,
			timeout: self.timeout,
			max_concurrent: self.max_concurrent,
			max_failures: self.max_failures,
			on_heartbeat: self.on_heartbeat,
		}
	}
}

// ============================================================================
// ClusterConfigBuilder
// ============================================================================

/// Builder for ClusterConfig
#[cfg(feature = "x509")]
pub struct ClusterConfigBuilder {
	namespace: ColonyNamespace,
	load_balancer: Arc<dyn LoadBalancer>,
	heartbeat: HeartbeatConfig,
	pheromone: PheromoneConfig,
	policies: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	pool_config: PoolConfig,
	control_freshness_window_ms: u64,
	bind_addr: Option<String>,
	peer: PeerConfig,
	peer_store: Arc<dyn PeerStore>,
	gossip: GossipConfig,
	tls: ClusterTlsConfig,
}

#[cfg(feature = "x509")]
impl ClusterConfig {
	/// Create a builder for ClusterConfig
	pub fn builder(tls: ClusterTlsConfig) -> ClusterConfigBuilder {
		ClusterConfigBuilder {
			namespace: ColonyNamespace::default(),
			load_balancer: Arc::new(StochasticForager::default()),
			heartbeat: HeartbeatConfig::default(),
			pheromone: PheromoneConfig::default(),
			policies: Vec::new(),
			pool_config: PoolConfig::default(),
			control_freshness_window_ms: crate::constants::DEFAULT_COMMAND_FRESHNESS_WINDOW_MS,
			bind_addr: None,
			peer: PeerConfig::default(),
			peer_store: Arc::new(MemoryPeerStore),
			gossip: GossipConfig::default(),
			tls,
		}
	}
}

#[cfg(feature = "x509")]
impl ClusterConfigBuilder {
	/// Set the heartbeat configuration
	pub fn with_heartbeat_config(mut self, config: HeartbeatConfig) -> Self {
		self.heartbeat = config;
		self
	}

	/// Set pheromone configuration for route selection and evaporation
	pub fn with_pheromone_config(mut self, config: PheromoneConfig) -> Self {
		self.pheromone = config;
		self
	}

	/// Set the naming scope inbound resource URNs are validated against
	pub fn with_namespace(mut self, namespace: ColonyNamespace) -> Self {
		self.namespace = namespace;
		self
	}

	/// Set the load balancer strategy (defaults to [`StochasticForager`])
	pub fn with_load_balancer(mut self, load_balancer: impl LoadBalancer + 'static) -> Self {
		self.load_balancer = Arc::new(load_balancer);
		self
	}

	/// Add a gate policy
	pub fn with_gate_policy(mut self, policy: Arc<dyn GatePolicy + Send + Sync>) -> Self {
		self.policies.push(policy);
		self
	}

	/// Set the connection pool configuration
	pub fn with_pool_config(mut self, config: PoolConfig) -> Self {
		self.pool_config = config;
		self
	}

	/// Set the freshness window for signed hive control frames
	pub fn with_control_freshness_window_ms(mut self, window_ms: u64) -> Self {
		self.control_freshness_window_ms = window_ms;
		self
	}

	/// Bind the gateway to a stable address instead of the protocol
	/// default, so hives can re-register through gateway restarts
	pub fn with_bind_addr(mut self, addr: impl Into<String>) -> Self {
		self.bind_addr = Some(addr.into());
		self
	}

	/// Set peer-federation configuration (dial list, beat, allowlist)
	pub fn with_peer_config(mut self, config: PeerConfig) -> Self {
		self.peer = config;
		self
	}

	/// Set the peer gateways this gateway advertises its exported types to
	pub fn with_peers(mut self, peers: impl IntoIterator<Item = String>) -> Self {
		self.peer.peers = peers.into_iter().collect();
		self
	}

	/// Set the re-advertise beat cadence (enables the advertise beat)
	pub fn with_advertise_interval(mut self, interval: Duration) -> Self {
		self.peer.advertise_interval = Some(interval);
		self
	}

	/// Restrict claimed peer dial addresses to this exact-match allowlist
	pub fn with_peer_dial_allowlist(mut self, allowlist: impl IntoIterator<Item = String>) -> Self {
		self.peer.peer_dial_allowlist = Some(allowlist.into_iter().collect());
		self
	}

	/// Cap the relay budget honored on inbound work and routed stream
	/// opens. The default honors a single forward, and `0` disables
	/// forwarding.
	///
	/// Relay-trail fallback needs `2`: the trail spends one forward at
	/// the relay and one more to reach the owner. A gateway below
	/// that cap never installs relay trails.
	pub fn with_max_hops(mut self, max_hops: u8) -> Self {
		self.peer.max_hops = max_hops;
		self
	}

	/// Set the advertisement-rumor refresh interval.
	///
	/// [`ClusterConfigBuilder::build`] clamps the interval to the
	/// gossip freshness window (`GossipConfig::seen_ttl`): a refresh
	/// slower than the window would re-publish rumors that peers
	/// refuse as stale.
	pub fn with_rumor_refresh(mut self, rumor_refresh: Duration) -> Self {
		self.peer.rumor_refresh = rumor_refresh;
		self
	}

	/// Set the persistence driver beneath the peer discovery table.
	/// Defaults to the process-local [`MemoryPeerStore`]. A durable
	/// driver preserves learned peers across restarts. The table still
	/// owns every discovery bound, so a driver cannot bypass them.
	pub fn with_peer_store(mut self, store: Arc<dyn PeerStore>) -> Self {
		self.peer_store = store;
		self
	}

	/// Set the gossip subsystem configuration: freshness, ttl,
	/// retention, and the journal. Defaults to
	/// [`GossipConfig::default`].
	pub fn with_gossip_config(mut self, config: GossipConfig) -> Self {
		self.gossip = config;
		self
	}

	/// Set the per-signer gossip rate admission.
	/// Defaults to the token bucket in [`GossipConfig::default`].
	pub fn with_gossip_admission(mut self, admission: Arc<dyn GossipAdmission>) -> Self {
		self.gossip.admission = admission;
		self
	}

	/// Deliver admitted rumors to local instances of this servlet type.
	/// Defaults to `None`: the gateway journals and refloods only.
	pub fn with_gossip_ingress(mut self, ingress: Urn<'static>) -> Self {
		self.gossip.ingress = Some(ingress);
		self
	}

	/// Build the ClusterConfig
	pub fn build(self) -> ClusterConfig {
		// Colony membership is derived from the certificate exactly once:
		// the colony URN binds to the cert's URI SAN, and every per-frame
		// membership check compares against this cached value. A cert
		// that fails to decode or carries no valid colony URN leaves the
		// gateway a non-member, fail closed.
		let colony_urn = Certificate::try_from(self.tls.certificate.clone())
			.ok()
			.and_then(|cert| cert_colony_urn(&self.namespace, &cert));

		// The discovery table derives from the dial list at build, so the
		// configured peers are always its un-evictable anchors. The
		// injected driver rehydrates learned peers through the capped
		// admission path. The anchor list is a one-time copy because
		// `peers` stays readable configuration beside the table.
		let mut peer = self.peer;
		peer.table = Arc::new(PeerTable::new(peer.peers.clone(), self.peer_store));

		// A refresh slower than the gossip freshness window would
		// re-publish advertisement rumors that peers refuse as stale,
		// so the interval clamps to the window.
		peer.rumor_refresh = peer.rumor_refresh.min(self.gossip.seen_ttl);

		ClusterConfig {
			namespace: self.namespace,
			load_balancer: self.load_balancer,
			heartbeat: self.heartbeat,
			pheromone: self.pheromone,
			policies: self.policies,
			pool_config: self.pool_config,
			control_freshness_window_ms: self.control_freshness_window_ms,
			bind_addr: self.bind_addr,
			peer,
			gossip: self.gossip,
			colony_urn,
			tls: self.tls,
		}
	}
}
