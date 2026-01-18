//! Hive framework for servlet orchestration.
//!
//! Hives orchestrate multiple servlets, enabling intra-hive communication
//! and coordinated lifecycle management.

pub mod error;
pub mod gates;

// Re-export submodule types
pub use error::HiveError;
pub use gates::{BackpressureGate, CircuitState, ClusterCircuitBreaker, ClusterSecurityGate};

// Re-export common types used by hives
pub use crate::colony::common::{
	ActivateServletRequest, ActivateServletResponse, ClusterCommand, ClusterCommandResponse, ClusterStatus,
	HeartbeatParams, HeartbeatResult, HiveManagementRequest, HiveManagementResponse, InstanceMetrics, LeastLoaded,
	ListServletsParams, ListServletsResult, LoadBalancer, MessageRouter, MessageValidator, PowerOfTwoChoices,
	RegisterHiveRequest, RegisterHiveResponse, RoundRobin, ScalingDecision, ScalingMetrics, ServletAddressUpdate,
	ServletAddressUpdateResponse, ServletInfo, ServletScaleConf, SpawnServletParams, SpawnServletResult,
	StopServletParams, StopServletResult, TypeBasedRouter,
};

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(feature = "std")]
use std::sync::Arc;

use core::future::Future;
use core::pin::Pin;
use core::time::Duration;

use crate::constants::DEFAULT_BACKPRESSURE_THRESHOLD_BPS;
use crate::trace::TraceCollector;
use crate::transport::policy::CoreRetryPolicy;
use crate::transport::Protocol;
use crate::utils::BasisPoints;
use crate::TightBeamError;

#[cfg(feature = "x509")]
pub use crate::crypto::x509::store::CertificateTrust;

// =============================================================================
// Spawner Function Type
// =============================================================================

/// Type alias for spawner function used in auto-scaling.
///
/// A spawner function creates a new servlet instance given a trace collector.
/// This enables hives to spawn additional servlet instances when scaling up.
pub type SpawnerFn = Arc<
	dyn Fn(Arc<TraceCollector>) -> Pin<Box<dyn Future<Output = Result<Box<dyn ServletBox>, TightBeamError>> + Send>>
		+ Send
		+ Sync,
>;

// =============================================================================
// ServletBox Trait
// =============================================================================

/// Trait for type-erased servlet storage in hives.
///
/// This enables hives to store servlets of different types in a single collection.
/// Servlets implement this trait to be registerable with a hive.
pub trait ServletBox: Send + Sync {
	/// Get the servlet's bound address as bytes
	fn addr_bytes(&self) -> Vec<u8>;

	/// Stop the servlet (consumes the boxed servlet)
	fn stop_boxed(self: Box<Self>);

	/// Get the servlet's current utilization (0-10000 basis points).
	///
	/// Returns `None` if the servlet does not report utilization.
	/// Used by the scaling task to evaluate scaling decisions.
	///
	/// Default implementation returns `None`, indicating the servlet
	/// does not self-report utilization.
	fn utilization(&self) -> Option<BasisPoints> {
		None
	}
}

// =============================================================================
// Servlet Registration
// =============================================================================

/// A registered servlet with its spawner function for auto-scaling.
pub struct ServletRegistration {
	/// The running servlet instance
	pub servlet: Box<dyn ServletBox>,
	/// Function to spawn additional instances of this servlet type
	pub spawner: SpawnerFn,
	/// The servlet type name (e.g., "auth", "capture")
	pub servlet_type: &'static str,
}

// =============================================================================
// Servlet Registry
// =============================================================================

/// Abstraction for servlet storage within a hive.
///
/// Provides a consistent interface for storing and retrieving servlet
/// registrations. The default implementation uses a HashMap, but custom
/// implementations could use sharded storage for high concurrency.
pub trait ServletRegistry: Send + Sync {
	/// Insert a servlet registration.
	fn insert(&self, key: Vec<u8>, registration: ServletRegistration) -> Result<(), TightBeamError>;

	/// Remove and return a servlet registration.
	fn remove(&self, key: &[u8]) -> Option<ServletRegistration>;

	/// Get a reference to a servlet registration (requires interior mutability pattern).
	/// Returns the registration if found, via a callback to avoid lifetime issues.
	fn with_get<F, R>(&self, key: &[u8], f: F) -> Option<R>
	where
		F: FnOnce(&ServletRegistration) -> R;

	/// Iterate over all registrations via callback.
	fn for_each<F>(&self, f: F)
	where
		F: FnMut(&Vec<u8>, &ServletRegistration);

	/// Find registrations by type prefix via callback.
	fn for_each_by_type<F>(&self, prefix: &[u8], f: F)
	where
		F: FnMut(&Vec<u8>, &ServletRegistration);

	/// Count of registered servlets.
	fn count(&self) -> usize;

	/// Get all servlet addresses as (type_name, address) pairs.
	fn addresses(&self) -> Vec<(&'static str, Vec<u8>)>;

	/// Find a spawner's static type name by matching prefix.
	/// Returns the &'static str servlet_type if found.
	fn find_type_by_prefix(&self, prefix: &[u8]) -> Option<&'static str>;

	/// Drain all registrations and return them.
	/// Used during shutdown to stop all servlets.
	fn drain_all(&self) -> Vec<(Vec<u8>, ServletRegistration)>;

	/// Get all keys (for collecting keys to remove).
	fn keys(&self) -> Vec<Vec<u8>>;
}

/// Default HashMap-based implementation of ServletRegistry.
pub struct HashMapRegistry {
	inner: std::sync::Mutex<HashMap<Vec<u8>, ServletRegistration>>,
}

impl Default for HashMapRegistry {
	fn default() -> Self {
		Self { inner: std::sync::Mutex::new(HashMap::new()) }
	}
}

impl ServletRegistry for HashMapRegistry {
	fn insert(&self, key: Vec<u8>, registration: ServletRegistration) -> Result<(), TightBeamError> {
		self.inner
			.lock()
			.map_err(|_| TightBeamError::LockPoisoned)?
			.insert(key, registration);
		Ok(())
	}

	fn remove(&self, key: &[u8]) -> Option<ServletRegistration> {
		self.inner.lock().ok()?.remove(key)
	}

	fn with_get<F, R>(&self, key: &[u8], f: F) -> Option<R>
	where
		F: FnOnce(&ServletRegistration) -> R,
	{
		let guard = self.inner.lock().ok()?;
		guard.get(key).map(f)
	}

	fn for_each<F>(&self, mut f: F)
	where
		F: FnMut(&Vec<u8>, &ServletRegistration),
	{
		if let Ok(guard) = self.inner.lock() {
			guard.iter().for_each(|(k, v)| f(k, v));
		}
	}

	fn for_each_by_type<F>(&self, prefix: &[u8], mut f: F)
	where
		F: FnMut(&Vec<u8>, &ServletRegistration),
	{
		if let Ok(guard) = self.inner.lock() {
			guard.iter().filter(|(k, _)| k.starts_with(prefix)).for_each(|(k, v)| f(k, v));
		}
	}

	fn count(&self) -> usize {
		self.inner.lock().map(|g| g.len()).unwrap_or(0)
	}

	fn addresses(&self) -> Vec<(&'static str, Vec<u8>)> {
		self.inner
			.lock()
			.map(|guard| guard.values().map(|reg| (reg.servlet_type, reg.servlet.addr_bytes())).collect())
			.unwrap_or_default()
	}

	fn find_type_by_prefix(&self, prefix: &[u8]) -> Option<&'static str> {
		self.inner.lock().ok().and_then(|guard| {
			guard
				.iter()
				.find(|(k, _)| k.starts_with(prefix))
				.map(|(_, reg)| reg.servlet_type)
		})
	}

	fn drain_all(&self) -> Vec<(Vec<u8>, ServletRegistration)> {
		self.inner.lock().map(|mut guard| guard.drain().collect()).unwrap_or_default()
	}

	fn keys(&self) -> Vec<Vec<u8>> {
		self.inner
			.lock()
			.map(|guard| guard.keys().cloned().collect())
			.unwrap_or_default()
	}
}

/// Trait for hive implementations.
///
/// Hives are orchestrators that manage servlet instances. Servlets are started
/// independently with their own configs, then registered with the hive along
/// with a spawner function for auto-scaling.
///
/// # Usage
///
/// ```ignore
/// // 1. Start servlets independently with their own configs
/// let trace = Arc::new(TraceCollector::new());
/// let auth_conf = auth_conf.clone();
/// let auth = AuthServlet::start(Arc::clone(&trace), Some(auth_conf.clone())).await?;
/// let capture = CaptureServlet::start(Arc::clone(&trace), None).await?;
///
/// // 2. Create hive
/// let mut hive = PaymentHive::new(Some(hive_conf))?;
///
/// // 3. Register with spawners for auto-scaling
/// hive.register("auth", auth, |t| AuthServlet::start(t, Some(auth_conf.clone())))?;
/// hive.register("capture", capture, |t| CaptureServlet::start(t, None))?;
///
/// // 4. Establish (starts control server + scaling task)
/// hive.establish(trace).await?;
///
/// // 5. Register with cluster
/// hive.register_with_cluster(cluster_addr).await?;
/// ```
pub trait Hive: Sized + Send + Sync {
	/// The protocol type this hive uses
	type Protocol: Protocol;

	/// The address type for this hive
	type Address;

	/// Create a new hive instance.
	///
	/// The hive is created but not yet established. Call `register()` to add
	/// servlets, then `establish()` to start the hive.
	fn new(config: Option<HiveConf>) -> Result<Self, TightBeamError>;

	/// Register an already-started servlet with the hive.
	///
	/// The spawner function enables auto-scaling: when the hive needs to spawn
	/// additional instances, it calls the spawner with a trace collector.
	///
	/// # Arguments
	/// * `name` - Unique name for this servlet type (used for intra-hive routing)
	/// * `servlet` - An already-started servlet instance
	/// * `spawner` - Function to spawn additional instances of this servlet type
	///
	/// # Type Parameters
	/// * `S` - The servlet type (must implement `ServletBox`)
	/// * `F` - The spawner function type
	/// * `Fut` - The future returned by the spawner
	fn register<S, F, Fut>(&mut self, name: &'static str, servlet: S, spawner: F) -> Result<(), TightBeamError>
	where
		S: ServletBox + 'static,
		F: Fn(Arc<TraceCollector>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<S, TightBeamError>> + Send + 'static;

	/// Establish the hive.
	///
	/// Sets up intra-hive routing (HiveContext), starts the control server
	/// for cluster commands, and begins the auto-scaling task.
	/// All servlets should be registered before calling this.
	///
	/// # Arguments
	/// * `trace` - Trace collector for hive-level events
	fn establish(&mut self, trace: Arc<TraceCollector>) -> impl Future<Output = Result<(), TightBeamError>> + Send;

	/// Get the hive's control server address.
	fn addr(&self) -> Self::Address;

	/// Get addresses of all registered servlets.
	///
	/// Returns a list of (servlet_name, address_bytes) pairs.
	fn servlet_addresses(&self) -> Vec<(&'static str, Vec<u8>)>;

	/// Stop the hive, control server, scaling task, and all registered servlets.
	fn stop(self);

	/// Wait for the hive to complete (joins control server handle).
	fn join(self) -> impl Future<Output = Result<(), TightBeamError>> + Send;

	/// Register this hive with a cluster.
	///
	/// Sends `RegisterHiveRequest` with all servlet addresses to the cluster.
	/// The cluster will then route work to the servlets and send management
	/// commands (heartbeat, spawn, stop) to this hive's control server.
	///
	/// # Arguments
	/// * `cluster_addr` - The address of the cluster controller
	fn register_with_cluster(
		&self,
		cluster_addr: <Self::Protocol as Protocol>::Address,
	) -> impl Future<Output = Result<RegisterHiveResponse, TightBeamError>> + Send;

	/// Begin graceful shutdown - stop accepting new requests.
	///
	/// Sets draining state and waits for in-flight requests to complete
	/// or until the configured drain timeout is reached.
	fn drain(&self) -> impl Future<Output = Result<(), TightBeamError>> + Send;

	/// Check if the hive is currently draining.
	fn is_draining(&self) -> bool;
}

// =============================================================================
// TLS Configuration
// =============================================================================

/// TLS configuration for hive servlets
///
/// Contains certificate, key, and validators for encrypted transport.
/// Wrapped in `Arc` when stored in `HiveConf` because validators are trait objects.
#[cfg(feature = "x509")]
pub struct HiveTlsConfig {
	/// Server certificate specification
	pub certificate: crate::crypto::x509::CertificateSpec,
	/// Private key provider for signing operations
	pub key: Arc<dyn crate::crypto::key::SigningKeyProvider>,
	/// Client certificate validators (e.g., public key pinning)
	pub validators: Vec<Arc<dyn crate::crypto::x509::policy::CertificateValidation>>,
}

#[cfg(feature = "x509")]
impl core::fmt::Debug for HiveTlsConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("HiveTlsConfig")
			.field("certificate", &self.certificate)
			.field("key", &"<KeyProvider>")
			.field("validators", &format!("[{} validators]", self.validators.len()))
			.finish()
	}
}

// =============================================================================
// Intra-Hive Communication
// =============================================================================

/// Type alias for async call result
pub type CallFuture<'a> = Pin<Box<dyn core::future::Future<Output = Result<Vec<u8>, TightBeamError>> + Send + 'a>>;

/// Context for intra-hive servlet communication.
///
/// This trait enables servlets within the same hive to call each other
/// without going through the cluster. This is useful for patterns like
/// a KeyManager servlet that provides encryption/decryption services
/// to other servlets in the hive.
///
/// # Example
///
/// ```ignore
/// // In a servlet handler:
/// if let Some(ctx) = config.hive_context() {
///     let decrypted = ctx.call(b"keymanager", encrypt_request).await?;
/// }
/// ```
pub trait HiveContext: Send + Sync {
	/// Call a sibling servlet by type ID and get a response.
	///
	/// # Arguments
	/// * `servlet_type` - The type identifier of the target servlet (e.g., b"keymanager")
	/// * `request` - The serialized request message
	///
	/// # Returns
	/// * `Ok(Vec<u8>)` - The serialized response from the target servlet
	/// * `Err(TightBeamError)` - If the servlet is not found or the call fails
	fn call<'a>(&'a self, servlet_type: &'a [u8], request: Vec<u8>) -> CallFuture<'a>;
}

// =============================================================================
// Hive Configuration
// =============================================================================

/// Configuration for hives
///
/// Generic over load balancing and message routing strategies.
/// Defaults to `LeastLoaded` for load balancing and `TypeBasedRouter` for routing.
#[derive(Clone)]
pub struct HiveConf<L: LoadBalancer = LeastLoaded, R: MessageRouter = TypeBasedRouter> {
	/// Load balancing strategy for distributing work
	pub load_balancer: L,
	/// Message routing strategy for type-based dispatch
	pub router: R,
	/// Default scaling config for all servlet types
	pub default_scale: ServletScaleConf,
	/// Per-type overrides (keyed by servlet type name)
	pub servlet_overrides: HashMap<Vec<u8>, ServletScaleConf>,
	/// Cooldown between scaling decisions (default: 5 seconds)
	pub cooldown: Duration,
	/// Queue capacity per servlet for utilization calculation (default: 100)
	pub queue_capacity: u32,
	/// Backpressure threshold in basis points (default: 9000 = 90%)
	pub backpressure_threshold: BasisPoints,
	/// Circuit breaker failure threshold before tripping (default: 3)
	pub circuit_breaker_threshold: u8,
	/// Circuit breaker cooldown in milliseconds (default: 30_000)
	pub circuit_breaker_cooldown_ms: u64,
	/// Max connections per servlet for forwarding (default: 8)
	pub servlet_pool_size: usize,
	/// Idle timeout for pooled connections (default: 30s)
	pub servlet_pool_idle_timeout: Option<Duration>,
	/// Drain timeout before force-stop (default: 30s)
	pub drain_timeout: Duration,
	/// Retry policy for cluster notifications (scaling events).
	/// Default: exponential backoff with 3 attempts, 500ms base delay.
	#[cfg(feature = "std")]
	pub cluster_notify_retry: Arc<dyn CoreRetryPolicy + Send + Sync>,
	/// Trust store for certificate-based cluster command authentication.
	/// Required for receiving authenticated ClusterCommand messages.
	/// If None, all cluster commands will be rejected.
	#[cfg(feature = "x509")]
	pub trust_store: Option<Arc<dyn CertificateTrust>>,
	/// TLS configuration for spawned servlets (default: None = plain transport)
	#[cfg(feature = "x509")]
	pub hive_tls: Option<Arc<HiveTlsConfig>>,
}

impl<L: LoadBalancer + core::fmt::Debug, R: MessageRouter + core::fmt::Debug> core::fmt::Debug for HiveConf<L, R> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let mut d = f.debug_struct("HiveConf");
		d.field("load_balancer", &self.load_balancer)
			.field("router", &self.router)
			.field("default_scale", &self.default_scale)
			.field("servlet_overrides", &self.servlet_overrides)
			.field("cooldown", &self.cooldown)
			.field("queue_capacity", &self.queue_capacity)
			.field("backpressure_threshold", &self.backpressure_threshold)
			.field("circuit_breaker_threshold", &self.circuit_breaker_threshold)
			.field("circuit_breaker_cooldown_ms", &self.circuit_breaker_cooldown_ms)
			.field("servlet_pool_size", &self.servlet_pool_size)
			.field("servlet_pool_idle_timeout", &self.servlet_pool_idle_timeout)
			.field("drain_timeout", &self.drain_timeout);
		#[cfg(feature = "std")]
		d.field("cluster_notify_retry", &"<RetryPolicy>");
		#[cfg(feature = "x509")]
		d.field("trust_store", &self.trust_store.as_ref().map(|_| "<CertificateTrust>"));
		#[cfg(feature = "x509")]
		d.field("hive_tls", &self.hive_tls);
		d.finish()
	}
}

impl Default for HiveConf {
	fn default() -> Self {
		Self {
			load_balancer: LeastLoaded,
			router: TypeBasedRouter,
			default_scale: ServletScaleConf::default(),
			servlet_overrides: HashMap::new(),
			cooldown: Duration::from_secs(5),
			queue_capacity: 100,
			backpressure_threshold: BasisPoints::new(DEFAULT_BACKPRESSURE_THRESHOLD_BPS),
			circuit_breaker_threshold: 3,
			circuit_breaker_cooldown_ms: 30_000,
			servlet_pool_size: 8,
			servlet_pool_idle_timeout: Some(Duration::from_secs(30)),
			drain_timeout: Duration::from_secs(30),
			#[cfg(feature = "std")]
			cluster_notify_retry: Arc::new(crate::transport::policy::RestartExponentialBackoff {
				max_attempts: 3,
				scale_factor: 500,
				jitter: Some(Box::new(crate::transport::policy::DecorrelatedJitter)),
			}),
			#[cfg(feature = "x509")]
			trust_store: None,
			#[cfg(feature = "x509")]
			hive_tls: None,
		}
	}
}

// =============================================================================
// Macro (included from macros.rs)
// =============================================================================

// The hive! macro is defined in macros.rs and exported via #[macro_export]
#[path = "macros.rs"]
mod macros_impl;
