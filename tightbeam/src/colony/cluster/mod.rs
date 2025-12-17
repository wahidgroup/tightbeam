//! Cluster framework for servlet orchestration
//!
//! Clusters are gateways that receive work requests from external clients
//! and route them to registered hives/hives based on servlet type.
//!
//! # Architecture
//!
//! 1. **Hives/Drones register** with the cluster, announcing available servlet types
//! 2. **Cluster maintains registry** of hives and their capabilities
//! 3. **Clients send** `ClusterWorkRequest` with `servlet_type` and `payload`
//! 4. **Cluster routes** to a hive that supports the requested servlet type
//! 5. **Cluster forwards** payload and returns response to client

pub mod builder;
pub mod error;
pub mod macros;
pub mod registry;
pub mod servlet_registry;

// Re-export submodule types
pub use builder::{ClusterConfBuilder, HeartbeatConfBuilder};
pub use error::ClusterError;
pub use registry::{HiveEntry, HiveRegistry, SharedId};
pub use servlet_registry::{PheromoneConf, ServletEntry, ServletRegistry};

use core::future::Future;
use core::marker::PhantomData;
use core::time::Duration;
use std::sync::Arc;

use crate::crypto::hash::{Digest, Sha3_256};
use crate::crypto::key::SigningKeyProvider;
use crate::der::Sequence;
use crate::policy::{GatePolicy, TransitStatus};
use crate::trace::TraceCollector;
use crate::transport::client::pool::PoolConfig;
use crate::transport::policy::RestartPolicy;
use crate::transport::{Protocol, TightBeamAddress};
use crate::Beamable;

#[cfg(feature = "x509")]
use crate::crypto::x509::{policy::CertificateValidation, CertificateSpec};

use super::common::LeastLoaded;
use super::hive::LoadBalancer;

#[cfg(feature = "tokio")]
use crate::colony::servlet::servlet_runtime::rt;

// =============================================================================
// Configuration
// =============================================================================

// Heartbeat default constants (single source of truth)
pub(crate) const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 5;
pub(crate) const DEFAULT_HEARTBEAT_TIMEOUT_SECS: u64 = 15;
pub(crate) const DEFAULT_MAX_CONCURRENT: usize = 10;
pub(crate) const DEFAULT_MAX_FAILURES: u32 = 3;

/// Configuration for cluster heartbeat behavior
pub struct HeartbeatConf {
	/// Interval between heartbeat checks
	pub interval: Duration,
	/// Timeout before evicting unresponsive hives
	pub timeout: Duration,
	/// Optional retry policy override (uses ClusterConf.retry_policy if None)
	pub retry_policy: Option<Arc<dyn RestartPolicy + Send + Sync>>,
	/// Maximum concurrent heartbeat requests
	pub max_concurrent: usize,
	/// Failed heartbeats before eviction
	pub max_failures: u32,
	/// Optional callback for heartbeat events (monitoring, testing)
	pub on_heartbeat: Option<HeartbeatCallback>,
}

impl Default for HeartbeatConf {
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

impl core::fmt::Debug for HeartbeatConf {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("HeartbeatConf")
			.field("interval", &self.interval)
			.field("timeout", &self.timeout)
			.field("retry_policy", &self.retry_policy.as_ref().map(|_| "Some(...)"))
			.field("max_concurrent", &self.max_concurrent)
			.field("max_failures", &self.max_failures)
			.field("on_heartbeat", &self.on_heartbeat.as_ref().map(|_| "Some(...)"))
			.finish()
	}
}

impl HeartbeatConf {
	/// Add a callback to be invoked on each heartbeat result
	pub fn with_callback(mut self, callback: HeartbeatCallback) -> Self {
		self.on_heartbeat = Some(callback);
		self
	}
}

// =============================================================================
// Heartbeat Callback
// =============================================================================

/// Event emitted for each heartbeat result
///
/// Provides information about the heartbeat outcome for monitoring,
/// metrics collection, or testing purposes.
#[derive(Debug, Clone)]
pub struct HeartbeatEvent {
	/// Address of the hive that was checked
	pub hive_addr: Arc<[u8]>,
	/// Whether the heartbeat succeeded
	pub success: bool,
	/// Utilization reported by the hive (if successful)
	pub utilization: Option<crate::utils::BasisPoints>,
}

/// Callback type for heartbeat events
///
/// Called after each heartbeat result is processed. The callback must be
/// thread-safe (`Send + Sync`) as it may be invoked from multiple concurrent
/// heartbeat tasks.
pub type HeartbeatCallback = Arc<dyn Fn(HeartbeatEvent) + Send + Sync>;

// ============================================================================
// TLS Configuration
// ============================================================================

/// TLS configuration for cluster → hive connections
///
/// Contains certificate, key, and validators for encrypted transport.
/// Used by the connection pool for mutual TLS with hives.
#[cfg(feature = "x509")]
pub struct ClusterTlsConfig {
	/// Client certificate specification for mutual TLS
	pub certificate: CertificateSpec,
	/// Private key provider for signing operations (supports HSM/KMS)
	pub key: Arc<dyn SigningKeyProvider>,
	/// Server certificate validators for hive connections
	pub validators: Vec<Arc<dyn CertificateValidation>>,
}

#[cfg(feature = "x509")]
impl Clone for ClusterTlsConfig {
	fn clone(&self) -> Self {
		Self {
			certificate: self.certificate.clone(),
			key: Arc::clone(&self.key),
			validators: self.validators.clone(),
		}
	}
}

#[cfg(feature = "x509")]
impl core::fmt::Debug for ClusterTlsConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("ClusterTlsConfig")
			.field("certificate", &self.certificate)
			.field("key", &"<KeyProvider>")
			.field("validators", &format!("[{} validators]", self.validators.len()))
			.finish()
	}
}

/// Configuration for clusters
///
/// Contains settings for load balancing, health checks, gateway policies,
/// and cryptographic signing for cluster → hive communication.
///
/// # Type Parameters
/// - `L`: Load balancing strategy (default: `LeastLoaded`)
/// - `D`: Digest algorithm for frame integrity and signing (default: `Sha3_256`)
pub struct ClusterConf<L: LoadBalancer = LeastLoaded, D: Digest = Sha3_256> {
	/// Load balancing strategy for distributing work across hives
	pub load_balancer: L,
	/// Heartbeat configuration
	pub heartbeat: HeartbeatConf,
	/// Pheromone configuration for bio-inspired routing
	pub pheromone: PheromoneConf,
	/// Gate policies for the gateway (rate limiting, auth, etc.)
	pub policies: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	/// Connection pool configuration for hive connections
	pub pool_config: PoolConfig,
	/// Default retry policy for all cluster → hive communication
	pub retry_policy: Arc<dyn RestartPolicy + Send + Sync>,
	/// TLS configuration for cluster → hive connections
	#[cfg(feature = "x509")]
	pub tls: ClusterTlsConfig,
	/// Phantom data for digest type
	pub(crate) _digest: PhantomData<D>,
}

#[cfg(feature = "x509")]
impl ClusterConf {
	/// Create a new cluster configuration with TLS config
	pub fn new(tls: ClusterTlsConfig) -> Self {
		Self::builder(tls).build()
	}
}

#[cfg(feature = "x509")]
impl<L: LoadBalancer, D: Digest> core::fmt::Debug for ClusterConf<L, D> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("ClusterConfig")
			.field("heartbeat", &self.heartbeat)
			.field("pheromone", &self.pheromone)
			.field("policies", &format!("[{} policies]", self.policies.len()))
			.field("pool_config", &self.pool_config)
			.field("tls", &self.tls)
			.finish()
	}
}

// =============================================================================
// Work Request/Response Messages
// =============================================================================

/// Work request envelope for cluster routing
///
/// Clients send this to the cluster gateway. The cluster routes based on
/// `servlet_type` and forwards `payload` to the selected hive.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ClusterWorkRequest {
	/// Target servlet type (e.g., b"ping_servlet")
	pub servlet_type: Vec<u8>,
	/// Raw message payload (encoded inner message)
	pub payload: Vec<u8>,
}

/// Work response from cluster
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ClusterWorkResponse {
	/// Status of the routing/execution
	pub status: TransitStatus,
	/// Response payload from servlet (if successful)
	pub payload: Option<Vec<u8>>,
}

impl ClusterWorkResponse {
	/// Create a successful response with payload
	#[inline]
	pub fn ok(payload: Vec<u8>) -> Self {
		Self { status: TransitStatus::Accepted, payload: Some(payload) }
	}

	/// Create an error response with status
	#[inline]
	pub fn err(status: TransitStatus) -> Self {
		Self { status, payload: None }
	}
}

// =============================================================================
// Cluster Trait
// =============================================================================

/// Trait for cluster implementations
///
/// Clusters are gateways that route work requests to registered hives
/// based on servlet type. Hives register dynamically, and the cluster
/// learns available servlet types from their registrations.
pub trait Cluster: Sized + Send + Sync {
	/// The protocol type this cluster uses
	type Protocol: Protocol;

	/// Address type for this cluster
	type Address: TightBeamAddress;

	/// Start the cluster gateway
	fn start(
		trace: Arc<TraceCollector>,
		config: ClusterConf,
	) -> impl Future<Output = Result<Self, crate::TightBeamError>> + Send;

	/// Get the gateway address
	fn addr(&self) -> Self::Address;

	/// Get available servlet types (from registered hives)
	fn available_servlets(&self) -> Vec<Vec<u8>>;

	/// Get the number of registered hives
	fn hive_count(&self) -> usize;

	/// Get the trace collector
	fn trace(&self) -> Arc<TraceCollector>;

	/// Stop the cluster
	fn stop(self);

	/// Wait for the cluster to finish
	fn join(self) -> impl Future<Output = Result<(), crate::colony::servlet::servlet_runtime::rt::JoinError>> + Send;

	// =========================================================================
	// Heartbeat Methods
	// =========================================================================

	/// Access the hive registry
	fn registry(&self) -> &Arc<HiveRegistry>;

	/// Access heartbeat configuration
	fn heartbeat_config(&self) -> &HeartbeatConf;

	/// Send a single heartbeat to a hive
	///
	/// Builds a signed heartbeat frame and sends it via the connection pool.
	/// Returns the heartbeat result from the hive.
	fn send_heartbeat(
		&self,
		addr: Self::Address,
	) -> impl Future<Output = Result<super::common::HeartbeatResult, ClusterError>> + Send;

	/// Process a heartbeat result, updating registry accordingly
	///
	/// On success, updates the hive's utilization metric.
	/// On failure, increments the failure counter and evicts if threshold exceeded.
	fn process_heartbeat_result(&self, hive_addr: &[u8], result: Result<super::common::HeartbeatResult, ClusterError>) {
		match result {
			Ok(hb) => {
				let _ = self.registry().touch(hive_addr, hb.utilization);
			}
			Err(_) => {
				if let Ok(failures) = self.registry().increment_failure(hive_addr) {
					if failures >= self.heartbeat_config().max_failures {
						let _ = self.registry().unregister(hive_addr);
					}
				}
			}
		}
	}

	// =========================================================================
	// Heartbeat Loop - Default Trait Implementation
	// =========================================================================
	//
	// Note: The cluster! macro provides optimized implementations with proper
	// concurrency. These trait defaults are simpler fallbacks.

	/// Tier 1: Tokio - sequential async processing
	///
	/// Default implementation processes heartbeats sequentially.
	/// The macro-generated implementation uses JoinSet for concurrency.
	#[cfg(feature = "tokio")]
	fn run_heartbeat_loop(&self) -> impl Future<Output = ()> + Send
	where
		Self::Address: core::str::FromStr,
	{
		async move {
			loop {
				// Collect parsed addresses first
				let tasks: Vec<_> = self
					.registry()
					.all_hives()
					.unwrap_or_default()
					.into_iter()
					.filter_map(|hive| {
						let hive_addr = Arc::clone(&hive.address);
						core::str::from_utf8(&hive_addr)
							.ok()
							.and_then(|s| s.parse().ok())
							.map(|addr| (hive_addr, addr))
					})
					.collect();

				// Concurrent processing with futures
				#[cfg(feature = "futures")]
				{
					use futures::stream::{self, StreamExt};

					let max_concurrent = self.heartbeat_config().max_concurrent;
					stream::iter(tasks)
						.for_each_concurrent(max_concurrent, |(hive_addr, addr)| async move {
							let result = self.send_heartbeat(addr).await;
							self.process_heartbeat_result(&hive_addr, result);
						})
						.await;
				}

				// Sequential fallback without futures
				#[cfg(not(feature = "futures"))]
				for (hive_addr, addr) in tasks {
					let result = self.send_heartbeat(addr).await;
					self.process_heartbeat_result(&hive_addr, result);
				}

				rt::sleep(self.heartbeat_config().interval).await;
			}
		}
	}

	/// Tier 2: std + futures - sequential with block_on
	///
	/// For non-tokio builds with futures crate.
	#[cfg(all(not(feature = "tokio"), feature = "std", feature = "futures"))]
	fn run_heartbeat_loop(&self)
	where
		Self::Address: core::str::FromStr,
	{
		use futures::executor::block_on;

		loop {
			self.registry()
				.all_hives()
				.unwrap_or_default()
				.into_iter()
				.filter_map(|hive| {
					let hive_addr = Arc::clone(&hive.address);
					core::str::from_utf8(&hive_addr)
						.ok()
						.and_then(|s| s.parse().ok())
						.map(|addr| (hive_addr, addr))
				})
				.for_each(|(hive_addr, addr)| {
					let result = block_on(self.send_heartbeat(addr));
					self.process_heartbeat_result(&hive_addr, result);
				});

			std::thread::sleep(self.heartbeat_config().interval);
		}
	}

	/// Tier 3: std only - placeholder
	///
	/// For std builds without tokio or futures.
	/// Cannot call async send_heartbeat - placeholder only.
	#[cfg(all(not(feature = "tokio"), feature = "std", not(feature = "futures")))]
	fn run_heartbeat_loop(&self)
	where
		Self::Address: core::str::FromStr,
	{
		loop {
			self.registry()
				.all_hives()
				.unwrap_or_default()
				.into_iter()
				.filter_map(|hive| {
					let hive_addr = Arc::clone(&hive.address);
					core::str::from_utf8(&hive_addr)
						.ok()
						.and_then(|s| s.parse::<Self::Address>().ok())
						.map(|addr| (hive_addr, addr))
				})
				.for_each(|(hive_addr, _addr)| {
					// Note: Cannot call async send_heartbeat without executor
					// Increment failure as placeholder behavior
					let _ = self.registry().increment_failure(&hive_addr);
				});

			std::thread::sleep(self.heartbeat_config().interval);
		}
	}
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::common::RegisterHiveRequest;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::testing::create_test_signing_key;
	use crate::utils::BasisPoints;

	// =========================================================================
	// Test Helpers
	// =========================================================================

	fn test_tls_config() -> ClusterTlsConfig {
		let key: Secp256k1SigningKey = create_test_signing_key();
		ClusterTlsConfig {
			certificate: CertificateSpec::Der(&[]),
			key: Arc::new(Secp256k1KeyProvider::from(key)),
			validators: Vec::new(),
		}
	}

	fn test_registry() -> HiveRegistry {
		HiveRegistry::new(Duration::from_secs(15))
	}

	fn request(addr: &[u8], servlets: &[&[u8]]) -> RegisterHiveRequest {
		RegisterHiveRequest {
			hive_addr: addr.to_vec(),
			available_servlets: servlets.iter().map(|s| s.to_vec()).collect(),
			metadata: None,
		}
	}

	fn request_with_meta(addr: &[u8], servlets: &[&[u8]], meta: &[u8]) -> RegisterHiveRequest {
		RegisterHiveRequest {
			hive_addr: addr.to_vec(),
			available_servlets: servlets.iter().map(|s| s.to_vec()).collect(),
			metadata: Some(meta.to_vec()),
		}
	}

	// =========================================================================
	// ClusterConf Tests
	// =========================================================================

	#[test]
	fn cluster_conf_defaults() {
		let config = ClusterConf::new(test_tls_config());
		assert_eq!(config.heartbeat.interval, Duration::from_secs(5));
		assert_eq!(config.heartbeat.timeout, Duration::from_secs(15));
		assert!(config.policies.is_empty());
	}

	// =========================================================================
	// ClusterWorkResponse Tests
	// =========================================================================

	#[test]
	fn work_response_ok() {
		let response = ClusterWorkResponse::ok(b"test".to_vec());
		assert_eq!(response.status, TransitStatus::Accepted);
		assert_eq!(response.payload, Some(b"test".to_vec()));
	}

	#[test]
	fn work_response_err() {
		let response = ClusterWorkResponse::err(TransitStatus::Forbidden);
		assert_eq!(response.status, TransitStatus::Forbidden);
		assert!(response.payload.is_none());
	}

	// =========================================================================
	// HiveRegistry Tests
	// =========================================================================

	#[test]
	fn registry_register_and_lookup() -> Result<(), ClusterError> {
		let registry = test_registry();
		registry.register(request(b"127.0.0.1:8080", &[b"ping", b"calc"]))?;

		// Registered types found
		assert_eq!(registry.hives_for_type(b"ping")?.len(), 1);
		assert_eq!(registry.hives_for_type(b"calc")?.len(), 1);
		assert_eq!(registry.hives_for_type(b"ping")?[0].address.as_ref(), b"127.0.0.1:8080");

		// Unknown type not found
		assert!(registry.hives_for_type(b"unknown")?.is_empty());

		Ok(())
	}

	#[test]
	fn registry_unregister() -> Result<(), ClusterError> {
		let registry = test_registry();
		registry.register(request(b"127.0.0.1:8080", &[b"ping"]))?;

		assert_eq!(registry.len()?, 1);
		assert!(registry.unregister(b"127.0.0.1:8080")?.is_some());
		assert_eq!(registry.len()?, 0);
		assert!(registry.hives_for_type(b"ping")?.is_empty());

		Ok(())
	}

	#[test]
	fn registry_update_utilization() -> Result<(), ClusterError> {
		let registry = test_registry();
		registry.register(request(b"127.0.0.1:8080", &[b"ping"]))?;

		assert!(registry.update_utilization(b"127.0.0.1:8080", BasisPoints::new(5000))?);
		assert_eq!(registry.hives_for_type(b"ping")?[0].utilization.get(), 5000);

		Ok(())
	}

	#[test]
	fn registry_available_servlets_deduplicated() -> Result<(), ClusterError> {
		let registry = test_registry();
		registry.register(request(b"hive1", &[b"ping", b"calc"]))?;
		registry.register(request(b"hive2", &[b"ping", b"worker"]))?;

		// ping, calc, worker - ping deduplicated
		assert_eq!(registry.to_available_servlets()?.len(), 3);

		Ok(())
	}

	#[test]
	fn registry_multiple_hives_same_type() -> Result<(), ClusterError> {
		let registry = test_registry();
		registry.register(request(b"hive1", &[b"ping"]))?;
		registry.register(request(b"hive2", &[b"ping"]))?;

		assert_eq!(registry.hives_for_type(b"ping")?.len(), 2);

		Ok(())
	}

	#[test]
	fn registry_all_hives() -> Result<(), ClusterError> {
		let registry = test_registry();
		registry.register(request(b"hive1", &[b"ping"]))?;
		registry.register(request_with_meta(b"hive2", &[b"calc"], b"metadata"))?;

		let all = registry.all_hives()?;
		assert_eq!(all.len(), 2);

		let addrs: Vec<_> = all.iter().map(|e| e.address.as_ref()).collect();
		assert!(addrs.contains(&b"hive1".as_slice()));
		assert!(addrs.contains(&b"hive2".as_slice()));

		Ok(())
	}
}
