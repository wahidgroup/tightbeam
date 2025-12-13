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
//!
//! # Example
//!
//! ```ignore
//! use tightbeam::cluster;
//! use tightbeam::colony::ClusterConfig;
//!
//! cluster! {
//!     pub MyCluster,
//!     protocol: TokioListener,
//!     config: ClusterConfig::default()
//! }
//!
//! // Start the cluster
//! let cluster = MyCluster::start(trace, ClusterConfig::default()).await?;
//! println!("Cluster listening on {:?}", cluster.addr());
//!
//! // Hives will register themselves, cluster learns available servlets dynamically
//! ```

use core::future::Future;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use crate::der::Sequence;
use crate::policy::{GatePolicy, TransitStatus};
use crate::trace::TraceCollector;
use crate::transport::client::pool::PoolConfig;
use crate::transport::policy::{RestartExponentialBackoff, RestartPolicy};
use crate::transport::{Protocol, TightBeamAddress};
use crate::utils::BasisPoints;
use crate::Beamable;

use super::drone::{LeastLoaded, LoadBalancer, RegisterDroneRequest};

/// Shared byte slice for hive and servlet identifiers
pub type SharedId = Arc<[u8]>;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for cluster heartbeat behavior
pub struct HeartbeatConf {
	/// Interval between heartbeat checks
	pub interval: Duration,
	/// Timeout before evicting unresponsive hives
	pub timeout: Duration,
	/// Optional retry policy override (uses ClusterConfig.retry_policy if None)
	pub retry_policy: Option<Arc<dyn RestartPolicy + Send + Sync>>,
}

impl Default for HeartbeatConf {
	fn default() -> Self {
		Self {
			interval: Duration::from_secs(5),
			timeout: Duration::from_secs(15),
			retry_policy: None,
		}
	}
}

impl core::fmt::Debug for HeartbeatConf {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("HeartbeatConf")
			.field("interval", &self.interval)
			.field("timeout", &self.timeout)
			.field("retry_policy", &self.retry_policy.as_ref().map(|_| "Some(...)"))
			.finish()
	}
}

/// Configuration for clusters
///
/// Contains settings for load balancing, health checks, and gateway policies.
pub struct ClusterConfig<L: LoadBalancer = LeastLoaded> {
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
}

impl Default for ClusterConfig {
	fn default() -> Self {
		Self {
			load_balancer: LeastLoaded,
			heartbeat: HeartbeatConf::default(),
			policies: Vec::new(),
			pool_config: PoolConfig::default(),
			retry_policy: Arc::new(RestartExponentialBackoff::default()),
		}
	}
}

impl<L: LoadBalancer> core::fmt::Debug for ClusterConfig<L> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("ClusterConfig")
			.field("heartbeat", &self.heartbeat)
			.field("policies", &format!("[{} policies]", self.policies.len()))
			.field("pool_config", &self.pool_config)
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
// Hive Registry
// =============================================================================

/// Entry for a registered hive in the cluster
#[derive(Debug, Clone)]
pub struct HiveEntry {
	/// Hive control address
	pub address: SharedId,
	/// Available servlet types
	pub servlet_types: Arc<[SharedId]>,
	/// Last reported utilization
	pub utilization: BasisPoints,
	/// Timestamp of last successful heartbeat
	pub last_seen: Instant,
	/// Optional metadata from registration
	pub metadata: Option<Arc<[u8]>>,
}

/// Registry of hives with servlet type indexing
///
/// Maintains a mapping of hives and a reverse index from servlet types
/// to hives that support them. Thread-safe for concurrent access.
pub struct HiveRegistry {
	/// Map of hive_id -> HiveEntry
	hives: RwLock<HashMap<SharedId, HiveEntry>>,
	/// Reverse index: servlet_type -> Vec<hive_id>
	servlet_index: RwLock<HashMap<SharedId, Vec<SharedId>>>,
	/// Heartbeat timeout for eviction
	timeout: Duration,
}

impl HiveRegistry {
	/// Create a new registry with the given heartbeat timeout
	pub fn new(timeout: Duration) -> Self {
		Self {
			hives: RwLock::new(HashMap::new()),
			servlet_index: RwLock::new(HashMap::new()),
			timeout,
		}
	}

	/// Register a hive and index its servlet types
	///
	/// If the hive was already registered, updates its entry and re-indexes.
	/// Takes ownership for zero-copy conversion to `Arc<[u8]>`.
	pub fn register(&self, request: RegisterDroneRequest) -> Result<(), ClusterError> {
		let hive_id: SharedId = request.drone_addr.into();
		let servlet_types: Arc<[SharedId]> = request
			.available_servlets
			.into_iter()
			.map(Into::into)
			.collect();
		let metadata: Option<Arc<[u8]>> = request.metadata.map(Into::into);

		let entry = HiveEntry {
			address: Arc::clone(&hive_id),
			servlet_types: Arc::clone(&servlet_types),
			utilization: BasisPoints::default(),
			last_seen: Instant::now(),
			metadata,
		};

		// Remove old index entries if re-registering
		self.unregister(&hive_id)?;

		// Add to hives map
		{
			let mut hives = self.hives.write().map_err(|_| ClusterError::LockPoisoned)?;
			hives.insert(Arc::clone(&hive_id), entry);
		}

		{
			let mut index = self.servlet_index.write().map_err(|_| ClusterError::LockPoisoned)?;
			for servlet_type in servlet_types.iter() {
				index
					.entry(Arc::clone(servlet_type))
					.or_default()
					.push(Arc::clone(&hive_id));
			}
		}

		Ok(())
	}

	/// Unregister a hive and remove from indices
	pub fn unregister(&self, hive_id: &[u8]) -> Result<Option<HiveEntry>, ClusterError> {
		// Remove from hives map (O(1) lookup via Borrow<[u8]>)
		let entry = {
			let mut hives = self.hives.write().map_err(|_| ClusterError::LockPoisoned)?;
			hives.remove(hive_id)
		};

		// Remove from servlet index
		if let Some(ref entry) = entry {
			let mut index = self.servlet_index.write().map_err(|_| ClusterError::LockPoisoned)?;
			for servlet_type in entry.servlet_types.iter() {
				if let Some(hive_ids) = index.get_mut(servlet_type) {
					hive_ids.retain(|id| id.as_ref() != hive_id);
					if hive_ids.is_empty() {
						index.remove(servlet_type);
					}
				}
			}
		}

		Ok(entry)
	}

	/// Find all hives that support a servlet type
	pub fn hives_for_type(&self, servlet_type: &[u8]) -> Result<Vec<HiveEntry>, ClusterError> {
		// O(1) lookup via Borrow<[u8]>
		let index = self.servlet_index.read().map_err(|_| ClusterError::LockPoisoned)?;
		let hive_ids = match index.get(servlet_type) {
			Some(ids) => ids.clone(),
			None => return Ok(Vec::new()),
		};
		drop(index);

		let hives = self.hives.read().map_err(|_| ClusterError::LockPoisoned)?;
		let entries: Vec<HiveEntry> = hive_ids
			.iter()
			.filter_map(|id| hives.get(id.as_ref()).cloned())
			.collect();

		Ok(entries)
	}

	/// Update hive utilization from heartbeat
	pub fn update_utilization(&self, hive_id: &[u8], utilization: BasisPoints) -> Result<bool, ClusterError> {
		let mut hives = self.hives.write().map_err(|_| ClusterError::LockPoisoned)?;
		// O(1) lookup via Borrow<[u8]>
		if let Some(entry) = hives.get_mut(hive_id) {
			entry.utilization = utilization;
			entry.last_seen = Instant::now();
			Ok(true)
		} else {
			Ok(false)
		}
	}

	/// Evict stale hives that haven't sent heartbeat within timeout
	///
	/// Returns the number of hives evicted.
	pub fn evict_stale(&self) -> Result<usize, ClusterError> {
		let now = Instant::now();
		let stale_ids: Vec<SharedId> = {
			let hives = self.hives.read().map_err(|_| ClusterError::LockPoisoned)?;
			hives
				.iter()
				.filter(|(_, entry)| now.duration_since(entry.last_seen) > self.timeout)
				.map(|(id, _)| Arc::clone(id))
				.collect()
		};

		let count = stale_ids.len();
		for id in &stale_ids {
			self.unregister(id)?;
		}

		Ok(count)
	}

	/// List all available servlet types across all registered hives
	pub fn to_available_servlets(&self) -> Result<Vec<Vec<u8>>, ClusterError> {
		let index = self.servlet_index.read().map_err(|_| ClusterError::LockPoisoned)?;
		Ok(index.keys().map(|k| k.to_vec()).collect())
	}

	/// Get a snapshot of all registered hives
	pub fn all_hives(&self) -> Result<Vec<HiveEntry>, ClusterError> {
		let hives = self.hives.read().map_err(|_| ClusterError::LockPoisoned)?;
		Ok(hives.values().cloned().collect())
	}

	/// Count the number of registered hives
	pub fn len(&self) -> Result<usize, ClusterError> {
		let hives = self.hives.read().map_err(|_| ClusterError::LockPoisoned)?;
		Ok(hives.len())
	}

	/// Check if the registry is empty
	pub fn is_empty(&self) -> Result<bool, ClusterError> {
		Ok(self.len()? == 0)
	}
}

impl Default for HiveRegistry {
	fn default() -> Self {
		Self::new(Duration::from_secs(15))
	}
}

// =============================================================================
// Cluster Error
// =============================================================================

/// Errors specific to clusters
#[cfg_attr(feature = "derive", derive(crate::Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterError {
	/// Lock poisoned
	#[cfg_attr(feature = "derive", error("Lock poisoned"))]
	LockPoisoned,
	/// Unknown servlet type
	#[cfg_attr(feature = "derive", error("Unknown servlet type: {:#?}"))]
	UnknownServletType(Vec<u8>),
	/// No hives available for servlet type
	#[cfg_attr(feature = "derive", error("No hives available for servlet type: {:#?}"))]
	NoHivesAvailable(Vec<u8>),
	/// Hive communication failed
	#[cfg_attr(feature = "derive", error("Hive communication failed: {:#?}"))]
	HiveCommunicationFailed(Vec<u8>),
	/// Registration failed
	#[cfg_attr(feature = "derive", error("Registration failed"))]
	RegistrationFailed,
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for ClusterError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			ClusterError::LockPoisoned => write!(f, "Lock poisoned"),
			ClusterError::UnknownServletType(t) => {
				write!(f, "Unknown servlet type: {}", String::from_utf8_lossy(t))
			}
			ClusterError::NoHivesAvailable(t) => {
				write!(f, "No hives available for servlet type: {}", String::from_utf8_lossy(t))
			}
			ClusterError::HiveCommunicationFailed(msg) => {
				write!(f, "Hive communication failed: {}", String::from_utf8_lossy(msg))
			}
			ClusterError::RegistrationFailed => write!(f, "Registration failed"),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for ClusterError {}

impl<T> From<std::sync::PoisonError<T>> for ClusterError {
	fn from(_: std::sync::PoisonError<T>) -> Self {
		ClusterError::LockPoisoned
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
		config: ClusterConfig,
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
	fn join(self) -> impl Future<Output = Result<(), crate::colony::servlet_runtime::rt::JoinError>> + Send;
}

// =============================================================================
// Cluster Macro
// =============================================================================

/// Macro for creating clusters with pre-configured settings
///
/// # Syntax
///
/// ```ignore
/// cluster! {
///     pub MyCluster,
///     protocol: TokioListener,
///     config: ClusterConfig::default()
/// }
/// ```
#[macro_export]
macro_rules! cluster {
	(
		$(#[$meta:meta])*
		pub $cluster_name:ident,
		protocol: $protocol:path,
		config: $config:expr
	) => {
		$crate::cluster!(@impl_cluster $cluster_name, $protocol, pub, [$(#[$meta])*]);
	};

	(
		$(#[$meta:meta])*
		$cluster_name:ident,
		protocol: $protocol:path,
		config: $config:expr
	) => {
		$crate::cluster!(@impl_cluster $cluster_name, $protocol, , [$(#[$meta])*]);
	};

	// Generate cluster struct (public)
	(@impl_cluster $cluster_name:ident, $protocol:path, pub, [$(#[$meta:meta])*]) => {
		$(#[$meta])*
		pub struct $cluster_name {
			registry: ::std::sync::Arc<$crate::colony::HiveRegistry>,
			config: $crate::colony::ClusterConfig,
			server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
			heartbeat_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
			addr: <$protocol as $crate::transport::Protocol>::Address,
			trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
		}

		$crate::cluster!(@impl_cluster_trait $cluster_name, $protocol);
		$crate::cluster!(@impl_drop $cluster_name);
	};

	// Generate cluster struct (private)
	(@impl_cluster $cluster_name:ident, $protocol:path, , [$(#[$meta:meta])*]) => {
		$(#[$meta])*
		struct $cluster_name {
			registry: ::std::sync::Arc<$crate::colony::HiveRegistry>,
			config: $crate::colony::ClusterConfig,
			server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
			heartbeat_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
			addr: <$protocol as $crate::transport::Protocol>::Address,
			trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
		}

		$crate::cluster!(@impl_cluster_trait $cluster_name, $protocol);
		$crate::cluster!(@impl_drop $cluster_name);
	};

	// Implement Cluster trait
	(@impl_cluster_trait $cluster_name:ident, $protocol:path) => {
		impl $crate::colony::Cluster for $cluster_name {
			type Protocol = $protocol;
			type Address = <$protocol as $crate::transport::Protocol>::Address;

			async fn start(
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				config: $crate::colony::ClusterConfig,
			) -> Result<Self, $crate::TightBeamError> {
				use $crate::transport::Protocol;

				// Bind to a port for the gateway server
				let bind_addr = <$protocol>::default_bind_address()?;
				let (listener, addr) = <$protocol>::bind(bind_addr).await?;

				// Create registry with timeout from config
				let registry = ::std::sync::Arc::new(
					$crate::colony::HiveRegistry::new(config.heartbeat.timeout)
				);
				let registry_for_server = ::std::sync::Arc::clone(&registry);
				let trace_for_server = ::std::sync::Arc::clone(&trace);

				// Start the gateway server
				let server_handle = $crate::cluster!(
					@build_gateway_server $protocol,
					listener,
					registry_for_server,
					trace_for_server
				);

				Ok(Self {
					registry,
					config,
					server_handle: Some(server_handle),
					heartbeat_handle: None, // TODO: Start heartbeat loop
					addr,
					trace,
				})
			}

			fn addr(&self) -> Self::Address {
				self.addr
			}

			fn available_servlets(&self) -> Vec<Vec<u8>> {
				self.registry.to_available_servlets().unwrap_or_default()
			}

			fn hive_count(&self) -> usize {
				self.registry.len().unwrap_or(0)
			}

			fn trace(&self) -> ::std::sync::Arc<$crate::trace::TraceCollector> {
				::std::sync::Arc::clone(&self.trace)
			}

			fn stop(mut self) {
				if let Some(handle) = self.heartbeat_handle.take() {
					$crate::colony::servlet_runtime::rt::abort(handle);
				}
				if let Some(handle) = self.server_handle.take() {
					$crate::colony::servlet_runtime::rt::abort(handle);
				}
			}

			#[cfg(feature = "tokio")]
			async fn join(mut self) -> Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
				if let Some(handle) = self.server_handle.take() {
					$crate::colony::servlet_runtime::rt::join(handle).await
				} else {
					Ok(())
				}
			}

			#[cfg(all(not(feature = "tokio"), feature = "std"))]
			async fn join(mut self) -> Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
				if let Some(handle) = self.server_handle.take() {
					$crate::colony::servlet_runtime::rt::join(handle)
				} else {
					Ok(())
				}
			}
		}
	};

	// Build gateway server
	(@build_gateway_server $protocol:path, $listener:ident, $registry:ident, $trace:ident) => {
		$crate::server! {
			protocol $protocol: $listener,
			handle: move |frame: $crate::Frame| {
				let registry = ::std::sync::Arc::clone(&$registry);
				let _trace = ::std::sync::Arc::clone(&$trace);
				async move {
					$crate::cluster!(@handle_gateway_request frame, registry)
				}
			}
		}
	};

	// Helper: Build response frame (DRY)
	(@reply $frame:ident, $message:expr) => {{
		use $crate::builder::TypeBuilder;
		Ok(Some(
			$crate::utils::compose($crate::Version::V0)
				.with_id($frame.metadata.id.clone())
				.with_order(0)
				.with_message($message)
				.build()?
		))
	}};

	// Handle gateway requests (registration + work)
	(@handle_gateway_request $frame:ident, $registry:ident) => {{
		// Try to decode as RegisterDroneRequest (hive registration)
		if let Ok(request) = $crate::decode::<$crate::colony::RegisterDroneRequest>(&$frame.message) {
			let status = match $registry.register(request.clone()) {
				Ok(()) => $crate::policy::TransitStatus::Accepted,
				Err(_) => $crate::policy::TransitStatus::Forbidden,
			};

			let response = $crate::colony::RegisterDroneResponse {
				status,
				drone_id: Some(request.drone_addr.clone()),
			};

			return $crate::cluster!(@reply $frame, response);
		}

		// Try to decode as ClusterWorkRequest (work routing)
		if let Ok(request) = $crate::decode::<$crate::colony::ClusterWorkRequest>(&$frame.message) {
			// Check if any hives support this servlet type
			let hives = match $registry.hives_for_type(&request.servlet_type) {
				Ok(h) if !h.is_empty() => h,
				_ => {
					return $crate::cluster!(@reply $frame,
						$crate::colony::ClusterWorkResponse::err($crate::policy::TransitStatus::Forbidden)
					);
				}
			};

			// TODO: Load balance and forward to selected hive
			// For now, return accepted with the payload echoed back
			let _ = hives; // Suppress unused warning until forwarding is implemented
			return $crate::cluster!(@reply $frame,
				$crate::colony::ClusterWorkResponse::ok(request.payload)
			);
		}

		// Unknown message type
		Ok(None)
	}};

	// Implement Drop
	(@impl_drop $cluster_name:ident) => {
		impl Drop for $cluster_name {
			fn drop(&mut self) {
				if let Some(handle) = self.heartbeat_handle.take() {
					$crate::colony::servlet_runtime::rt::abort(handle);
				}
				if let Some(handle) = self.server_handle.take() {
					$crate::colony::servlet_runtime::rt::abort(handle);
				}
			}
		}
	};
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn cluster_config_default() {
		let config = ClusterConfig::default();
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
