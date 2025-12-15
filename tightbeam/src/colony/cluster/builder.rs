//! Builder patterns for cluster configuration

use core::marker::PhantomData;
use core::time::Duration;
use std::sync::Arc;

use crate::crypto::hash::{Digest, Sha3_256};
use crate::policy::GatePolicy;
use crate::transport::client::pool::PoolConfig;
use crate::transport::policy::{RestartExponentialBackoff, RestartPolicy};

use super::{
	ClusterConf, ClusterTlsConfig, HeartbeatCallback, HeartbeatConf, DEFAULT_HEARTBEAT_INTERVAL_SECS,
	DEFAULT_HEARTBEAT_TIMEOUT_SECS, DEFAULT_MAX_CONCURRENT, DEFAULT_MAX_FAILURES,
};
use crate::colony::common::LeastLoaded;
use crate::colony::hive::LoadBalancer;

// =============================================================================
// HeartbeatConfBuilder
// =============================================================================

/// Builder for HeartbeatConf
pub struct HeartbeatConfBuilder {
	interval: Duration,
	timeout: Duration,
	retry_policy: Option<Arc<dyn RestartPolicy + Send + Sync>>,
	max_concurrent: usize,
	max_failures: u32,
	on_heartbeat: Option<HeartbeatCallback>,
}

impl Default for HeartbeatConfBuilder {
	fn default() -> Self {
		Self {
			interval: Duration::from_secs(DEFAULT_HEARTBEAT_INTERVAL_SECS),
			timeout: Duration::from_secs(DEFAULT_HEARTBEAT_TIMEOUT_SECS),
			retry_policy: None,
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

	/// Set the retry policy for heartbeat requests
	pub fn with_retry_policy(mut self, policy: Arc<dyn RestartPolicy + Send + Sync>) -> Self {
		self.retry_policy = Some(policy);
		self
	}

	/// Build the HeartbeatConf
	pub fn build(self) -> HeartbeatConf {
		HeartbeatConf {
			interval: self.interval,
			timeout: self.timeout,
			retry_policy: self.retry_policy,
			max_concurrent: self.max_concurrent,
			max_failures: self.max_failures,
			on_heartbeat: self.on_heartbeat,
		}
	}
}

// =============================================================================
// ClusterConfBuilder
// =============================================================================

/// Builder for ClusterConf
#[cfg(feature = "x509")]
pub struct ClusterConfBuilder<L: LoadBalancer = LeastLoaded, D: Digest = Sha3_256> {
	load_balancer: L,
	heartbeat: HeartbeatConf,
	policies: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	pool_config: PoolConfig,
	retry_policy: Arc<dyn RestartPolicy + Send + Sync>,
	tls: ClusterTlsConfig,
	_digest: PhantomData<D>,
}

#[cfg(feature = "x509")]
impl ClusterConf {
	/// Create a builder for ClusterConf
	pub fn builder(tls: ClusterTlsConfig) -> ClusterConfBuilder {
		ClusterConfBuilder {
			load_balancer: LeastLoaded,
			heartbeat: HeartbeatConf::default(),
			policies: Vec::new(),
			pool_config: PoolConfig::default(),
			retry_policy: Arc::new(RestartExponentialBackoff::default()),
			tls,
			_digest: PhantomData,
		}
	}
}

#[cfg(feature = "x509")]
impl<L: LoadBalancer, D: Digest> ClusterConfBuilder<L, D> {
	/// Set the heartbeat configuration
	pub fn with_heartbeat_config(mut self, config: HeartbeatConf) -> Self {
		self.heartbeat = config;
		self
	}

	/// Set the load balancer strategy
	pub fn with_load_balancer<L2: LoadBalancer>(self, load_balancer: L2) -> ClusterConfBuilder<L2, D> {
		ClusterConfBuilder {
			load_balancer,
			heartbeat: self.heartbeat,
			policies: self.policies,
			pool_config: self.pool_config,
			retry_policy: self.retry_policy,
			tls: self.tls,
			_digest: PhantomData,
		}
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

	/// Set the retry policy
	pub fn with_retry_policy(mut self, policy: Arc<dyn RestartPolicy + Send + Sync>) -> Self {
		self.retry_policy = policy;
		self
	}

	/// Build the ClusterConf
	pub fn build(self) -> ClusterConf<L, D> {
		ClusterConf {
			load_balancer: self.load_balancer,
			heartbeat: self.heartbeat,
			policies: self.policies,
			pool_config: self.pool_config,
			retry_policy: self.retry_policy,
			tls: self.tls,
			_digest: PhantomData,
		}
	}
}
