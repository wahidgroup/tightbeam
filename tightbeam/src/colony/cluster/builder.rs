//! Builder patterns for cluster configuration

use core::time::Duration;
use std::sync::Arc;

use super::{
	ClusterConf, ClusterTlsConfig, HeartbeatCallback, HeartbeatConf, PheromoneConf, DEFAULT_HEARTBEAT_INTERVAL_SECS,
	DEFAULT_HEARTBEAT_TIMEOUT_SECS, DEFAULT_MAX_CONCURRENT, DEFAULT_MAX_FAILURES,
};
use crate::colony::common::{ColonyNamespace, LoadBalancer, StochasticForager};
use crate::policy::GatePolicy;
use crate::transport::client::pool::PoolConfig;

// ============================================================================
// HeartbeatConfBuilder
// ============================================================================

/// Builder for HeartbeatConf
pub struct HeartbeatConfBuilder {
	interval: Duration,
	timeout: Duration,
	max_concurrent: usize,
	max_failures: u32,
	on_heartbeat: Option<HeartbeatCallback>,
}

impl Default for HeartbeatConfBuilder {
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

impl HeartbeatConf {
	/// Create a builder for HeartbeatConf
	pub fn builder() -> HeartbeatConfBuilder {
		HeartbeatConfBuilder::default()
	}
}

impl HeartbeatConfBuilder {
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

	/// Build the HeartbeatConf
	pub fn build(self) -> HeartbeatConf {
		HeartbeatConf {
			interval: self.interval,
			timeout: self.timeout,
			max_concurrent: self.max_concurrent,
			max_failures: self.max_failures,
			on_heartbeat: self.on_heartbeat,
		}
	}
}

// ============================================================================
// ClusterConfBuilder
// ============================================================================

/// Builder for ClusterConf
#[cfg(feature = "x509")]
pub struct ClusterConfBuilder {
	namespace: ColonyNamespace,
	load_balancer: Arc<dyn LoadBalancer>,
	heartbeat: HeartbeatConf,
	pheromone: PheromoneConf,
	policies: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	pool_config: PoolConfig,
	control_freshness_window_ms: u64,
	bind_addr: Option<String>,
	peers: Vec<String>,
	advertise_interval: Option<Duration>,
	tls: ClusterTlsConfig,
}

#[cfg(feature = "x509")]
impl ClusterConf {
	/// Create a builder for ClusterConf
	pub fn builder(tls: ClusterTlsConfig) -> ClusterConfBuilder {
		ClusterConfBuilder {
			namespace: ColonyNamespace::default(),
			load_balancer: Arc::new(StochasticForager::default()),
			heartbeat: HeartbeatConf::default(),
			pheromone: PheromoneConf::default(),
			policies: Vec::new(),
			pool_config: PoolConfig::default(),
			control_freshness_window_ms: crate::constants::DEFAULT_COMMAND_FRESHNESS_WINDOW_MS,
			bind_addr: None,
			peers: Vec::new(),
			advertise_interval: None,
			tls,
		}
	}
}

#[cfg(feature = "x509")]
impl ClusterConfBuilder {
	/// Set the heartbeat configuration
	pub fn with_heartbeat_config(mut self, config: HeartbeatConf) -> Self {
		self.heartbeat = config;
		self
	}

	/// Set the pheromone configuration for bio-inspired routing
	pub fn with_pheromone_config(mut self, config: PheromoneConf) -> Self {
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

	/// Set the peer gateways this gateway advertises its exported types to
	pub fn with_peers(mut self, peers: impl IntoIterator<Item = String>) -> Self {
		self.peers = peers.into_iter().collect();
		self
	}

	/// Set the re-advertise beat cadence (enables the advertise beat)
	pub fn with_advertise_interval(mut self, interval: Duration) -> Self {
		self.advertise_interval = Some(interval);
		self
	}

	/// Build the ClusterConf
	pub fn build(self) -> ClusterConf {
		ClusterConf {
			namespace: self.namespace,
			load_balancer: self.load_balancer,
			heartbeat: self.heartbeat,
			pheromone: self.pheromone,
			policies: self.policies,
			pool_config: self.pool_config,
			control_freshness_window_ms: self.control_freshness_window_ms,
			bind_addr: self.bind_addr,
			peers: self.peers,
			advertise_interval: self.advertise_interval,
			tls: self.tls,
		}
	}
}
