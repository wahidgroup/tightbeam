//! Hive framework for dynamic servlet deployment
//!
//! Hives are orchestrators that manage servlet instances. They support two modes:
//!
//! ## Single-Servlet Mode
//! A hive can morph into **one servlet at a time**.
//! - Receives `ActivateServletRequest` from cluster
//! - Stops current servlet and starts the requested one
//! - Useful for dynamic workload allocation
//!
//! ## Multi-Servlet Mode (Mycelial)
//! On mycelial protocols (like TCP), a hive can manage **multiple servlets simultaneously**.
//! - Requires a protocol that implements `Mycelial` (different port per servlet)
//! - Call `establish_hive()` to spawn all registered servlets on different ports
//! - All servlets run concurrently
//!
//! The mode is determined automatically based on the protocol's capabilities.

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
use core::time::Duration;

use crate::colony::servlet::Servlet;
use crate::constants::DEFAULT_BACKPRESSURE_THRESHOLD_BPS;
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::transport::{AsyncListenerTrait, Mycelial, Protocol};
use crate::utils::BasisPoints;

#[cfg(feature = "x509")]
pub use crate::crypto::x509::store::CertificateTrust;

// =============================================================================
// Auto-Establish Helper
// =============================================================================

/// Helper trait for automatic hive establishment
///
/// This trait enables transparent auto-establishment for Mycelial protocols.
/// The `hive!` macro generates implementations:
/// - For Mycelial protocols: calls `establish_hive()`
/// - For other protocols: no-op (returns Ok)
///
/// This is called automatically at the end of `start()`.
pub trait MaybeEstablish {
	/// Establish the hive if the protocol supports it
	fn maybe_establish(&mut self) -> impl Future<Output = Result<(), HiveError>> + Send;
}

// =============================================================================
// Hive Trait
// =============================================================================

/// Trait for hive implementations
///
/// Hives are orchestrators that manage servlet instances. They extend the `Servlet`
/// trait, inheriting standard lifecycle methods (start, addr, stop, join) and adding
/// hive-specific capabilities.
///
/// ## Capabilities
///
/// - **Morphing**: Switch between different servlet types dynamically
/// - **Cluster Registration**: Register with a cluster to receive work
/// - **Multi-Servlet Mode**: On mycelial protocols, manage multiple servlets simultaneously
///
/// ## Multi-Servlet Mode
///
/// When the protocol implements `Mycelial + AsyncListenerTrait`, additional methods
/// become available:
/// - `establish_hive()` - Spawn all registered servlets on different ports
/// - `servlet_addresses()` - Get addresses of all active servlets
/// - `drain()` - Graceful shutdown
pub trait Hive<I>: Servlet<I> {
	/// The protocol type this hive uses
	type Protocol: Protocol;

	/// Get the trace collector for this hive
	fn trace(&self) -> Arc<TraceCollector>;

	/// Activate a servlet on this hive
	///
	/// # Arguments
	/// * `msg` - The activation message containing servlet ID and configuration
	///
	/// # Returns
	/// * `Ok(TransitStatus)` indicating whether the servlet was activated
	/// * `Err(HiveError)` if activation failed
	fn morph(&mut self, msg: ActivateServletRequest) -> impl Future<Output = Result<TransitStatus, HiveError>> + Send;

	/// Check if a servlet is currently active
	fn is_active(&self) -> bool;

	/// Stop the currently active servlet
	fn deactivate(&mut self) -> impl Future<Output = Result<(), HiveError>> + Send;

	/// Register this hive with a cluster
	///
	/// Sends a `RegisterHiveRequest` to the cluster controller with this hive's
	/// address and available servlet types.
	///
	/// # Arguments
	/// * `cluster_addr` - The address of the cluster controller
	///
	/// # Returns
	/// * `Ok(RegisterHiveResponse)` if registration succeeded
	/// * `Err(HiveError)` if registration failed
	fn register_with_cluster(
		&self,
		cluster_addr: <Self::Protocol as Protocol>::Address,
	) -> impl Future<Output = Result<RegisterHiveResponse, HiveError>> + Send;

	/// Establish multi-servlet mode (mycelial protocols only)
	///
	/// This starts all registered servlets on different ports (using mycelial networking)
	/// and begins listening for management commands from the cluster.
	///
	/// # Requirements
	/// This method is only available when `Self::Protocol: Mycelial + AsyncListenerTrait`.
	fn establish_hive(&mut self) -> impl Future<Output = Result<(), HiveError>> + Send
	where
		Self::Protocol: Mycelial + AsyncListenerTrait;

	/// Get the addresses of all active servlets in the hive
	///
	/// Returns a list of (servlet_name, address) pairs.
	///
	/// # Requirements
	/// This method is only available when `Self::Protocol: Mycelial + AsyncListenerTrait`.
	fn servlet_addresses(&self) -> impl Future<Output = Vec<(Vec<u8>, <Self::Protocol as Protocol>::Address)>> + Send
	where
		Self::Protocol: Mycelial + AsyncListenerTrait;

	/// Begin graceful shutdown - stop accepting new requests and wait for in-flight to complete
	///
	/// Returns once all servlets have stopped or the drain timeout has elapsed.
	///
	/// # Requirements
	/// This method is only available when `Self::Protocol: Mycelial + AsyncListenerTrait`.
	fn drain(&self) -> impl Future<Output = Result<(), HiveError>> + Send
	where
		Self::Protocol: Mycelial + AsyncListenerTrait;

	/// Check if the hive is currently draining
	fn is_draining(&self) -> bool
	where
		Self::Protocol: Mycelial + AsyncListenerTrait;
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

use crate::TightBeamError;
use core::pin::Pin;

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
#[derive(Debug, Clone)]
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
	/// Trust store for certificate-based cluster command authentication.
	/// Required for receiving authenticated ClusterCommand messages.
	/// If None, all cluster commands will be rejected.
	#[cfg(feature = "x509")]
	pub trust_store: Option<Arc<dyn CertificateTrust>>,
	/// TLS configuration for spawned servlets (default: None = plain transport)
	#[cfg(feature = "x509")]
	pub hive_tls: Option<Arc<HiveTlsConfig>>,
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
