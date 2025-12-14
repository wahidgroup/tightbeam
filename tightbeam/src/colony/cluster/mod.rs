//! Cluster framework for servlet orchestration
//!
//! Clusters are gateways that receive work requests from external clients
//! and route them to registered hives/drones based on servlet type.
//!
//! # Architecture
//!
//! 1. **Hives/Drones register** with the cluster, announcing available servlet types
//! 2. **Cluster maintains registry** of hives and their capabilities
//! 3. **Clients send** `ClusterWorkRequest` with `servlet_type` and `payload`
//! 4. **Cluster routes** to a hive that supports the requested servlet type
//! 5. **Cluster forwards** payload and returns response to client

pub mod error;
pub mod macros;
pub mod registry;

// Re-export submodule types
pub use error::ClusterError;
pub use registry::{HiveEntry, HiveRegistry, SharedId};

use core::future::Future;
use core::time::Duration;
use std::sync::Arc;

use crate::builder::TypeBuilder;
use crate::crypto::key::SigningKeyProvider;
use crate::der::Sequence;
use crate::policy::{GatePolicy, TransitStatus};
use crate::trace::TraceCollector;
use crate::transport::client::pool::PoolConfig;
use crate::transport::policy::{RestartExponentialBackoff, RestartPolicy};
use crate::transport::{Protocol, TightBeamAddress};
use crate::Beamable;

#[cfg(feature = "x509")]
use crate::crypto::x509::{policy::CertificateValidation, CertificateSpec};

use super::common::{ClusterCommand, ClusterCommandResponse, ClusterStatus, HeartbeatParams, LeastLoaded};
use super::drone::LoadBalancer;

#[cfg(feature = "tokio")]
use crate::colony::servlet::servlet_runtime::rt;
#[cfg(feature = "tokio")]
use tokio::sync::Semaphore;

// =============================================================================
// Configuration
// =============================================================================

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
}

impl Default for HeartbeatConf {
	fn default() -> Self {
		Self {
			interval: Duration::from_secs(5),
			timeout: Duration::from_secs(15),
			retry_policy: None,
			max_concurrent: 10,
			max_failures: 3,
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
			.finish()
	}
}

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
pub struct ClusterConf<L: LoadBalancer = LeastLoaded> {
	/// Load balancing strategy for distributing work across hives
	pub load_balancer: L,
	/// Heartbeat configuration
	pub heartbeat: HeartbeatConf,
	/// Gate policies for the gateway (rate limiting, auth, etc.)
	pub policies: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	/// Connection pool configuration for hive connections
	pub pool_config: PoolConfig,
	/// Default retry policy for all cluster → hive communication
	pub retry_policy: Arc<dyn RestartPolicy + Send + Sync>,
	/// TLS configuration for cluster → hive connections
	#[cfg(feature = "x509")]
	pub tls: ClusterTlsConfig,
}

#[cfg(feature = "x509")]
impl ClusterConf {
	/// Create a new cluster configuration with TLS config
	pub fn new(tls: ClusterTlsConfig) -> Self {
		Self {
			load_balancer: LeastLoaded,
			heartbeat: HeartbeatConf::default(),
			policies: Vec::new(),
			pool_config: PoolConfig::default(),
			retry_policy: Arc::new(RestartExponentialBackoff::default()),
			tls,
		}
	}
}

#[cfg(feature = "x509")]
impl<L: LoadBalancer> core::fmt::Debug for ClusterConf<L> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("ClusterConfig")
			.field("heartbeat", &self.heartbeat)
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
pub trait Cluster: Sized {
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
}

// =============================================================================
// Heartbeat Loop
// =============================================================================

/// Process a single heartbeat result, updating registry accordingly
fn process_heartbeat_result<L: LoadBalancer>(
	result: Result<ClusterCommandResponse, ClusterError>,
	hive_addr: &[u8],
	registry: &HiveRegistry,
	config: &ClusterConf<L>,
	trace: &TraceCollector,
) {
	match result {
		Ok(response) if response.heartbeat.is_some() => {
			let hb = response.heartbeat.as_ref();
			let _ = registry.touch(hive_addr, hb.map(|h| h.utilization).unwrap_or_default());
			let _ = trace.event("heartbeat_success");
		}
		_ => {
			if let Ok(failures) = registry.increment_failure(hive_addr) {
				if failures >= config.heartbeat.max_failures {
					let _ = registry.unregister(hive_addr);
					let _ = trace.event("hive_evicted");
				}
			}
		}
	}
}

/// Simulate a heartbeat (placeholder until connection pool is wired)
fn simulate_heartbeat() -> Result<ClusterCommandResponse, ClusterError> {
	Ok(ClusterCommandResponse {
		heartbeat: Some(super::common::HeartbeatResult {
			status: TransitStatus::Accepted,
			utilization: crate::utils::BasisPoints::default(),
			active_servlets: 0,
		}),
		manage: None,
	})
}

/// Run the cluster heartbeat loop (tokio async version)
///
/// Periodically sends heartbeat requests to all registered hives, updates
/// utilization metrics, and evicts unresponsive hives.
#[cfg(feature = "tokio")]
pub async fn run_heartbeat_loop<L: LoadBalancer + Send + Sync + 'static>(
	registry: Arc<HiveRegistry>,
	config: Arc<ClusterConf<L>>,
	trace: Arc<TraceCollector>,
) {
	loop {
		let hives = match registry.all_hives() {
			Ok(h) => h,
			Err(_) => {
				rt::sleep(config.heartbeat.interval).await;
				continue;
			}
		};

		let semaphore = Arc::new(Semaphore::new(config.heartbeat.max_concurrent));
		let tasks: Vec<_> = hives
			.into_iter()
			.map(|hive| {
				let registry = Arc::clone(&registry);
				let config = Arc::clone(&config);
				let semaphore = Arc::clone(&semaphore);
				let trace = Arc::clone(&trace);
				let hive_addr = Arc::clone(&hive.address);

				rt::spawn(async move {
					let _permit = match semaphore.acquire().await {
						Ok(p) => p,
						Err(_) => return,
					};

					let cmd = ClusterCommand {
						heartbeat: Some(HeartbeatParams { cluster_status: ClusterStatus::Healthy }),
						manage: None,
					};

					// Build and sign the heartbeat frame
					let frame: crate::Frame = match crate::builder::frame::FrameBuilder::from(crate::Version::V1)
						.with_message(cmd)
						.with_priority(crate::MessagePriority::Heartbeat)
						.build()
					{
						Ok(f) => f,
						Err(_) => {
							process_heartbeat_result(
								Err(ClusterError::EncodingError),
								&hive_addr,
								&registry,
								&config,
								&trace,
							);
							return;
						}
					};

					// Sign the frame with the cluster's key provider
					let signed_frame = match frame
						.sign_with_provider::<crate::crypto::hash::Sha3_256, _>(config.tls.key.as_ref())
						.await
					{
						Ok(f) => f,
						Err(_) => {
							process_heartbeat_result(
								Err(ClusterError::SigningError),
								&hive_addr,
								&registry,
								&config,
								&trace,
							);
							return;
						}
					};

					// TODO: Send signed_frame via connection pool to hive_addr
					let _ = signed_frame;
					let result = simulate_heartbeat();
					process_heartbeat_result(result, &hive_addr, &registry, &config, &trace);
				})
			})
			.collect();

		// Await all tasks
		for task in tasks {
			let _ = rt::join(task).await;
		}

		rt::sleep(config.heartbeat.interval).await;
	}
}

/// Run the cluster heartbeat loop (std sync version)
///
/// Periodically sends heartbeat requests to all registered hives, updates
/// utilization metrics, and evicts unresponsive hives.
///
/// Note: This sync version cannot use async signing (HSM/KMS support).
/// Use the tokio async version for production with HSM/KMS key providers.
#[cfg(all(not(feature = "tokio"), feature = "std", feature = "x509"))]
pub fn run_heartbeat_loop<L: LoadBalancer + Send + Sync + 'static>(
	registry: Arc<HiveRegistry>,
	config: Arc<ClusterConf<L>>,
	trace: Arc<TraceCollector>,
) {
	use crate::colony::servlet::servlet_runtime::rt as std_rt;

	loop {
		let hives = match registry.all_hives() {
			Ok(h) => h,
			Err(_) => {
				std_rt::sleep(config.heartbeat.interval);
				continue;
			}
		};

		// Spawn heartbeat threads with concurrency limiting via chunking
		hives.chunks(config.heartbeat.max_concurrent).for_each(|chunk| {
			let handles: Vec<_> = chunk
				.iter()
				.map(|hive| {
					let registry = Arc::clone(&registry);
					let config = Arc::clone(&config);
					let trace = Arc::clone(&trace);
					let hive_addr = Arc::clone(&hive.address);

					std_rt::spawn(move || {
						// Note: Sync version cannot use async signing
						// This is a placeholder - production should use tokio version
						let result: Result<ClusterCommandResponse, ClusterError> = Ok(ClusterCommandResponse {
							heartbeat: Some(super::common::HeartbeatResult {
								status: TransitStatus::Accepted,
								utilization: crate::utils::BasisPoints::default(),
								active_servlets: 0,
							}),
							manage: None,
						});
						process_heartbeat_result(result, &hive_addr, &registry, &config, &trace);
					})
				})
				.collect();

			// Wait for this chunk to complete before spawning next
			handles.into_iter().for_each(|h| {
				let _ = std_rt::join(h);
			});
		});

		std_rt::sleep(config.heartbeat.interval);
	}
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::common::RegisterDroneRequest;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::testing::create_test_signing_key;
	use crate::utils::BasisPoints;

	/// Create a test TLS config for unit tests
	fn create_test_tls_config() -> ClusterTlsConfig {
		let signing_key = create_test_signing_key();
		let key: Secp256k1SigningKey = signing_key;
		ClusterTlsConfig {
			certificate: CertificateSpec::Der(&[]),
			key: Arc::new(Secp256k1KeyProvider::from(key)),
			validators: Vec::new(),
		}
	}

	#[test]
	fn cluster_config_new() {
		let tls = create_test_tls_config();
		let config = ClusterConf::new(tls);
		assert_eq!(config.heartbeat.interval, Duration::from_secs(5));
		assert_eq!(config.heartbeat.timeout, Duration::from_secs(15));
		assert!(config.policies.is_empty());
	}

	#[test]
	fn cluster_work_response_ok() {
		let response = ClusterWorkResponse::ok(b"test".to_vec());
		assert_eq!(response.status, TransitStatus::Accepted);
		assert_eq!(response.payload, Some(b"test".to_vec()));
	}

	#[test]
	fn cluster_work_response_err() {
		let response = ClusterWorkResponse::err(TransitStatus::Forbidden);
		assert_eq!(response.status, TransitStatus::Forbidden);
		assert!(response.payload.is_none());
	}

	#[test]
	fn hive_registry_register_and_lookup() -> Result<(), ClusterError> {
		let registry = HiveRegistry::new(Duration::from_secs(15));

		let request = RegisterDroneRequest {
			drone_addr: b"127.0.0.1:8080".to_vec(),
			available_servlets: vec![b"ping_servlet".to_vec(), b"calc_servlet".to_vec()],
			metadata: None,
		};

		registry.register(request)?;

		// Should find hives for registered types
		let hives = registry.hives_for_type(b"ping_servlet")?;
		assert_eq!(hives.len(), 1);
		assert_eq!(hives[0].address.as_ref(), b"127.0.0.1:8080");

		let hives = registry.hives_for_type(b"calc_servlet")?;
		assert_eq!(hives.len(), 1);

		// Should not find hives for unregistered types
		let hives = registry.hives_for_type(b"unknown_servlet")?;
		assert!(hives.is_empty());

		Ok(())
	}

	#[test]
	fn hive_registry_unregister() -> Result<(), ClusterError> {
		let registry = HiveRegistry::new(Duration::from_secs(15));

		let request = RegisterDroneRequest {
			drone_addr: b"127.0.0.1:8080".to_vec(),
			available_servlets: vec![b"ping_servlet".to_vec()],
			metadata: None,
		};

		registry.register(request)?;
		assert_eq!(registry.len()?, 1);

		let entry = registry.unregister(b"127.0.0.1:8080")?;
		assert!(entry.is_some());
		assert_eq!(registry.len()?, 0);

		// Servlet index should be cleaned up
		let hives = registry.hives_for_type(b"ping_servlet")?;
		assert!(hives.is_empty());

		Ok(())
	}

	#[test]
	fn hive_registry_update_utilization() -> Result<(), ClusterError> {
		let registry = HiveRegistry::new(Duration::from_secs(15));

		let request = RegisterDroneRequest {
			drone_addr: b"127.0.0.1:8080".to_vec(),
			available_servlets: vec![b"ping_servlet".to_vec()],
			metadata: None,
		};

		registry.register(request)?;

		let updated = registry.update_utilization(b"127.0.0.1:8080", BasisPoints::new(5000))?;
		assert!(updated);

		let hives = registry.hives_for_type(b"ping_servlet")?;
		assert_eq!(hives[0].utilization.get(), 5000);

		Ok(())
	}

	#[test]
	fn hive_registry_available_servlets() -> Result<(), ClusterError> {
		let registry = HiveRegistry::new(Duration::from_secs(15));

		let request1 = RegisterDroneRequest {
			drone_addr: b"hive1".to_vec(),
			available_servlets: vec![b"ping".to_vec(), b"calc".to_vec()],
			metadata: None,
		};

		let request2 = RegisterDroneRequest {
			drone_addr: b"hive2".to_vec(),
			available_servlets: vec![b"ping".to_vec(), b"worker".to_vec()],
			metadata: None,
		};

		registry.register(request1)?;
		registry.register(request2)?;

		let servlets = registry.to_available_servlets()?;
		assert_eq!(servlets.len(), 3); // ping, calc, worker (ping deduplicated)

		Ok(())
	}

	#[test]
	fn hive_registry_multiple_hives_same_type() -> Result<(), ClusterError> {
		let registry = HiveRegistry::new(Duration::from_secs(15));

		let request1 = RegisterDroneRequest {
			drone_addr: b"hive1".to_vec(),
			available_servlets: vec![b"ping".to_vec()],
			metadata: None,
		};

		let request2 = RegisterDroneRequest {
			drone_addr: b"hive2".to_vec(),
			available_servlets: vec![b"ping".to_vec()],
			metadata: None,
		};

		registry.register(request1)?;
		registry.register(request2)?;

		let hives = registry.hives_for_type(b"ping")?;
		assert_eq!(hives.len(), 2);

		Ok(())
	}

	#[test]
	fn hive_registry_all_hives() -> Result<(), ClusterError> {
		let registry = HiveRegistry::new(Duration::from_secs(15));

		let request1 = RegisterDroneRequest {
			drone_addr: b"hive1".to_vec(),
			available_servlets: vec![b"ping".to_vec()],
			metadata: None,
		};

		let request2 = RegisterDroneRequest {
			drone_addr: b"hive2".to_vec(),
			available_servlets: vec![b"calc".to_vec()],
			metadata: Some(b"metadata".to_vec()),
		};

		registry.register(request1)?;
		registry.register(request2)?;

		let all = registry.all_hives()?;
		assert_eq!(all.len(), 2);

		// Verify entries contain expected data
		let addrs: Vec<&[u8]> = all.iter().map(|e| e.address.as_ref()).collect();
		assert!(addrs.contains(&b"hive1".as_slice()));
		assert!(addrs.contains(&b"hive2".as_slice()));

		Ok(())
	}
}
