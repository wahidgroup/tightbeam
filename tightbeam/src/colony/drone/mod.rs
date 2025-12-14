//! Drone framework for dynamic servlet deployment
//!
//! This module provides two types of servlet orchestration:
//!
//! ## Drone
//! A **Drone** is a containerized servlet runner that can morph into **one servlet at a time**.
//! - Receives `ActivateServletRequest` from cluster
//! - Stops current servlet and starts the requested one
//! - Useful for dynamic workload allocation
//!
//! ## Hive
//! A **Hive** is an orchestrator that manages **multiple servlets simultaneously**.
//! - Requires a mycelial protocol (different port per servlet)
//! - Receives `OverlordMessage` from cluster containing `servlet_name` and `frame`
//! - Routes messages to the appropriate servlet
//! - All servlets run concurrently on different ports

pub mod error;
pub mod gates;

// Re-export submodule types
pub use error::DroneError;
pub use gates::{BackpressureGate, CircuitState, ClusterCircuitBreaker, ClusterSecurityGate};

// Re-export common types used by drones
pub use crate::colony::common::{
	ActivateServletRequest, ActivateServletResponse, ClusterCommand, ClusterCommandResponse, ClusterStatus,
	HeartbeatParams, HeartbeatResult, HiveManagementRequest, HiveManagementResponse, InstanceMetrics, LeastLoaded,
	ListServletsParams, ListServletsResult, LoadBalancer, MessageRouter, MessageValidator, PowerOfTwoChoices,
	RegisterDroneRequest, RegisterDroneResponse, RoundRobin, ScalingDecision, ScalingMetrics, ServletInfo,
	ServletScaleConf, SpawnServletParams, SpawnServletResult, StopServletParams, StopServletResult, TypeBasedRouter,
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

// =============================================================================
// Drone Trait
// =============================================================================

/// Trait for drone implementations
///
/// Drones are containerized servlet runners that can dynamically morph
/// between different servlet types based on activation messages.
///
/// Drones extend the `Servlet` trait, inheriting the standard lifecycle methods
/// (start, addr, stop, join) and adding drone-specific capabilities for morphing
/// between different servlet types.
pub trait Drone<I>: Servlet<I> {
	/// The protocol type this drone uses
	type Protocol: Protocol;

	/// Get the trace collector for this drone
	fn trace(&self) -> Arc<TraceCollector>;

	/// Activate a servlet on this drone
	///
	/// # Arguments
	/// * `msg` - The activation message containing servlet ID and configuration
	///
	/// # Returns
	/// * `Ok(TransitStatus)` indicating whether the servlet was activated
	/// * `Err(DroneError)` if activation failed
	fn morph(&mut self, msg: ActivateServletRequest) -> impl Future<Output = Result<TransitStatus, DroneError>> + Send;

	/// Check if a servlet is currently active
	fn is_active(&self) -> bool;

	/// Stop the currently active servlet
	fn deactivate(&mut self) -> impl Future<Output = Result<(), DroneError>> + Send;

	/// Register this drone with a cluster
	///
	/// Sends a `RegisterDroneRequest` to the cluster controller with this drone's
	/// address and available servlet types.
	///
	/// # Arguments
	/// * `cluster_addr` - The address of the cluster controller
	///
	/// # Returns
	/// * `Ok(RegisterDroneResponse)` if registration succeeded
	/// * `Err(DroneError)` if registration failed
	fn register_with_cluster(
		&self,
		cluster_addr: <Self::Protocol as Protocol>::Address,
	) -> impl Future<Output = Result<RegisterDroneResponse, DroneError>> + Send;
}

// =============================================================================
// Hive Trait
// =============================================================================

/// Trait for hives that manage multiple servlets simultaneously
///
/// **Design Philosophy:**
/// - **Drone**: Morphs into a single servlet at a time (one active servlet)
/// - **Hive**: Orchestrates multiple servlet instances simultaneously (many active servlets)
///
/// Hives act as orchestrators that manage servlet lifecycle based on cluster demand:
/// - Spawn new servlet instances on demand
/// - Stop/restart servlets
/// - Provide service discovery (servlet addresses)
/// - Health monitoring
///
/// Clusters connect directly to individual servlets for actual work messages.
/// The hive's control server is only used for management commands.
///
/// This trait can only be implemented by drones whose protocol implements both `Mycelial`
/// and `AsyncListenerTrait` (hives require async protocols for concurrent servlet management).
pub trait Hive<I>: Drone<I>
where
	Self::Protocol: Mycelial + AsyncListenerTrait,
{
	/// Establish a hive for this mycelial drone
	///
	/// This starts all registered servlets on different ports (using mycelial networking)
	/// and begins listening for `OverlordMessage` commands from the cluster.
	fn establish_hive(&mut self) -> impl Future<Output = Result<(), DroneError>> + Send;

	/// Get the addresses of all active servlets in the hive
	///
	/// Returns a map of servlet names to their addresses.
	fn servlet_addresses(&self) -> impl Future<Output = Vec<(Vec<u8>, <Self::Protocol as Protocol>::Address)>> + Send;

	/// Begin graceful shutdown - stop accepting new requests and wait for in-flight to complete
	///
	/// Returns once all servlets have stopped or the drain timeout has elapsed.
	fn drain(&self) -> impl Future<Output = Result<(), DroneError>> + Send;

	/// Check if the hive is currently draining
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
	/// Trusted cluster verifying keys (SEC1-encoded public keys)
	/// Required for receiving authenticated ClusterCommand messages.
	/// If empty, all cluster commands will be rejected.
	pub trusted_cluster_keys: Vec<Vec<u8>>,
	/// Max connections per servlet for forwarding (default: 8)
	pub servlet_pool_size: usize,
	/// Idle timeout for pooled connections (default: 30s)
	pub servlet_pool_idle_timeout: Option<Duration>,
	/// Drain timeout before force-stop (default: 30s)
	pub drain_timeout: Duration,
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
			trusted_cluster_keys: Vec::new(),
			servlet_pool_size: 8,
			servlet_pool_idle_timeout: Some(Duration::from_secs(30)),
			drain_timeout: Duration::from_secs(30),
			#[cfg(feature = "x509")]
			hive_tls: None,
		}
	}
}

// =============================================================================
// Macro (included from macros.rs)
// =============================================================================

// The drone! macro is defined in macros.rs and exported via #[macro_export]
#[path = "macros.rs"]
mod macros_impl;
