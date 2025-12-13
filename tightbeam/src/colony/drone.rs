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
//!
//! # Architecture
//!
//! ## Drone Flow:
//! 1. **Drone starts** and listens for control messages on its protocol
//! 2. **Drone registers** with a cluster controller, announcing its capabilities
//! 3. **Cluster sends** `ActivateServletRequest` to morph the drone into a specific servlet
//! 4. **Drone activates** the requested servlet and responds with status
//! 5. **Drone processes** messages using the active servlet
//!
//! ## Hive Flow:
//! 1. **Hive starts** and establishes all servlets on different ports (mycelial)
//! 2. **Hive registers** with cluster, providing addresses for all servlets
//! 3. **Cluster sends** `OverlordMessage` with `servlet_name` and `frame`
//! 4. **Hive routes** the frame to the specified servlet
//! 5. **Hive returns** the servlet's response to the cluster
//!
//! # Example
//!
//! ```ignore
//! use tightbeam::drone;
//! use tightbeam::trace::TraceCollector;
//!
//! // Regular drone (non-mycelial)
//! drone! {
//!     name: RegularDrone,
//!     protocol: Listener,
//!     servlets: {
//!         simple_servlet: SimpleServlet,
//!         worker_servlet: WorkerServlet
//!     }
//! }
//!
//! // Start the drone
//! let drone = RegularDrone::start(TraceCollector::new(), None).await?;
//!
//! // Register with cluster
//! let cluster_addr = "127.0.0.1:8888".parse()?;
//! let response = drone.register_with_cluster(cluster_addr).await?;
//! println!("Registered with cluster: {:?}", response);
//!
//! // Cluster can now send ActivateServletRequest to morph the drone
//! // The drone will automatically handle these requests in its control server
//!
//! // Mycelial drone with hive support
//! drone! {
//!     name: MycelialDrone,
//!     protocol: std::net::TcpListener,  // Must implement Mycelial trait
//!     hive: true,
//!     servlets: {
//!         simple_servlet: SimpleServlet,
//!         worker_servlet: WorkerServlet
//!     }
//! }
//!
//! // Only mycelial drones can call establish_hive()
//! let mut mycelial_drone = MycelialDrone::start(TraceCollector::new(), None).await?;
//! mycelial_drone.establish_hive();  // ✓ Compiles
//!
//! let mut regular_drone = RegularDrone::start(TraceCollector::new(), None).await?;
//! // regular_drone.establish_hive();  // ✗ Compile error: Hive trait not implemented
//! ```

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};

#[cfg(feature = "std")]
use std::sync::Arc;

#[cfg(feature = "std")]
use std::collections::HashMap;

use core::future::Future;
use core::sync::atomic::{AtomicU16, AtomicU64, AtomicU8, Ordering};
use core::time::Duration;

use crate::colony::Servlet;
use crate::constants::{DEFAULT_BACKPRESSURE_THRESHOLD_BPS, LCG_MULTIPLIER};
use crate::der::{Enumerated, Sequence};
use crate::policy::{GatePolicy, TransitStatus};
use crate::trace::TraceCollector;
use crate::transport::{AsyncListenerTrait, Mycelial, Protocol};
use crate::utils::BasisPoints;
use crate::Beamable;
use crate::Frame;

#[cfg(feature = "derive")]
use crate::Errorizable;

/// Errors specific to drones
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DroneError {
	/// Invalid servlet ID
	#[cfg_attr(feature = "derive", error("Invalid servlet ID: {:#?}"))]
	InvalidServletId(Vec<u8>),
	/// Transport/IO error (message stored as string since io::Error isn't Clone)
	#[cfg_attr(feature = "derive", error("IO error: {:#?}"))]
	Io(Vec<u8>),
	/// Message composition failed
	#[cfg_attr(feature = "derive", error("Message composition failed: {:#?}"))]
	ComposeFailed(Vec<u8>),
	/// Message emission failed
	#[cfg_attr(feature = "derive", error("Message emission failed"))]
	EmitFailed,
	/// No response received
	#[cfg_attr(feature = "derive", error("No response received"))]
	NoResponse,
	/// Message decoding failed
	#[cfg_attr(feature = "derive", error("Message decoding failed"))]
	DecodeFailed,
	/// Lock poisoned
	#[cfg_attr(feature = "derive", error("Lock poisoned"))]
	LockPoisoned,
	/// No trusted keys configured for ClusterSecurityGate
	#[cfg_attr(feature = "derive", error("No trusted keys configured"))]
	NoTrustedKeys,
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for DroneError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			DroneError::InvalidServletId(id) => write!(f, "Invalid servlet ID: {:#?}", id),
			DroneError::Io(msg) => write!(f, "IO error: {}", String::from_utf8_lossy(msg)),
			DroneError::ComposeFailed(msg) => write!(f, "Message composition failed: {}", String::from_utf8_lossy(msg)),
			DroneError::EmitFailed => write!(f, "Message emission failed"),
			DroneError::NoResponse => write!(f, "No response received"),
			DroneError::DecodeFailed => write!(f, "Message decoding failed"),
			DroneError::LockPoisoned => write!(f, "Lock poisoned"),
			DroneError::NoTrustedKeys => write!(f, "No trusted keys configured"),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for DroneError {}

#[cfg(feature = "std")]
impl<T> From<::std::sync::PoisonError<T>> for DroneError {
	fn from(_: ::std::sync::PoisonError<T>) -> Self {
		DroneError::LockPoisoned
	}
}

#[cfg(feature = "std")]
impl From<::std::io::Error> for DroneError {
	fn from(e: ::std::io::Error) -> Self {
		DroneError::Io(e.to_string().into_bytes())
	}
}

impl From<crate::transport::TransportError> for DroneError {
	fn from(e: crate::transport::TransportError) -> Self {
		DroneError::Io(format!("{:?}", e).into_bytes())
	}
}

#[cfg(not(feature = "derive"))]
impl From<crate::TightBeamError> for DroneError {
	fn from(e: crate::TightBeamError) -> Self {
		DroneError::ComposeFailed(e.to_string().into_bytes())
	}
}

/// Message type for registering a drone with a cluster
///
/// This message is sent from a drone to a cluster controller to announce
/// its availability and capabilities.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct RegisterDroneRequest {
	/// The address where this drone can be reached
	pub drone_addr: Vec<u8>,
	/// List of servlet IDs this drone can run
	pub available_servlets: Vec<Vec<u8>>,
	/// Optional metadata about the drone
	pub metadata: Option<Vec<u8>>,
}

/// Response message for drone registration
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct RegisterDroneResponse {
	/// The status of the registration request
	pub status: TransitStatus,
	/// Optional cluster-assigned drone ID
	pub drone_id: Option<Vec<u8>>,
}

/// Message type for activating a servlet on a drone
///
/// This message is sent from a cluster controller to a drone to instruct
/// it to morph into a specific servlet configuration.
///
/// **Drones** morph into a single servlet at a time.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ActivateServletRequest {
	/// The identifier of the servlet to activate
	pub servlet_id: Vec<u8>,
	/// Optional configuration data for the servlet
	pub config: Option<Vec<u8>>,
}

/// Response message for servlet activation
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ActivateServletResponse {
	/// The status of the activation request
	pub status: TransitStatus,
	/// The address of the activated servlet (if successful)
	pub servlet_address: Option<Vec<u8>>,
}

impl ActivateServletResponse {
	/// Create a successful activation response
	#[inline]
	pub fn ok(address: Vec<u8>) -> Self {
		Self { status: TransitStatus::Accepted, servlet_address: Some(address) }
	}

	/// Create a failed activation response
	#[inline]
	pub fn err(status: TransitStatus) -> Self {
		Self { status, servlet_address: None }
	}
}

/// Servlet information entry
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ServletInfo {
	/// The servlet instance ID
	pub servlet_id: Vec<u8>,
	/// The servlet's address
	pub address: Vec<u8>,
}

/// Hive management request message
///
/// Uses context-specific tags to distinguish between different request types.
/// Only one field should be set per request.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HiveManagementRequest {
	/// Spawn a new servlet instance [context 0]
	#[asn1(context_specific = "0", optional = "true")]
	pub spawn: Option<SpawnServletParams>,
	/// List all active servlets [context 1]
	#[asn1(context_specific = "1", optional = "true")]
	pub list: Option<ListServletsParams>,
	/// Stop a specific servlet instance [context 2]
	#[asn1(context_specific = "2", optional = "true")]
	pub stop: Option<StopServletParams>,
}

/// Parameters for spawning a new servlet
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct SpawnServletParams {
	/// The type of servlet to spawn (e.g., "worker_servlet")
	pub servlet_type: Vec<u8>,
	/// Optional configuration data for the servlet
	pub config: Option<Vec<u8>>,
}

/// Parameters for listing servlets
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ListServletsParams {
	/// Optional filter (reserved for future use)
	pub filter: Option<Vec<u8>>,
}

/// Parameters for stopping a servlet
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct StopServletParams {
	/// The ID of the servlet instance to stop
	pub servlet_id: Vec<u8>,
}

/// Hive management response message
///
/// Uses context-specific tags to distinguish between different response types.
/// Only one field should be set per response.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HiveManagementResponse {
	/// Response to spawn request [context 0]
	#[asn1(context_specific = "0", optional = "true")]
	pub spawn: Option<SpawnServletResult>,
	/// Response to list request [context 1]
	#[asn1(context_specific = "1", optional = "true")]
	pub list: Option<ListServletsResult>,
	/// Response to stop request [context 2]
	#[asn1(context_specific = "2", optional = "true")]
	pub stop: Option<StopServletResult>,
}

/// Result of spawning a servlet
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct SpawnServletResult {
	/// The status of the spawn request
	pub status: TransitStatus,
	/// The address of the newly spawned servlet (if successful)
	pub servlet_address: Option<Vec<u8>>,
	/// The identifier of the servlet instance (e.g., "worker_servlet_127.0.0.1:8080")
	pub servlet_id: Option<Vec<u8>>,
}

/// Result of listing servlets
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ListServletsResult {
	/// The status of the request
	pub status: TransitStatus,
	/// List of active servlets
	pub servlets: Vec<ServletInfo>,
}

/// Result of stopping a servlet
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct StopServletResult {
	/// The status of the stop request
	pub status: TransitStatus,
}

// =============================================================================
// Cluster Command Protocol
// =============================================================================

/// Status reported by cluster in heartbeat
///
/// Clusters report their current operational status to hives during heartbeat.
/// Hives may use this to adjust their behavior (e.g., reduce capacity during draining).
#[derive(Enumerated, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClusterStatus {
	/// Normal operation
	#[default]
	Healthy = 0,
	/// Partial degradation (some services unavailable)
	Degraded = 1,
	/// Overloaded (high utilization)
	Overloaded = 2,
	/// Draining (preparing for shutdown)
	Draining = 3,
}

/// Cluster command message - ASN.1 CHOICE
///
/// Commands from cluster to hive. Uses context-specific tags for
/// CHOICE discrimination. Only one field should be set per message.
///
/// **Security**: Requires nonrepudiation signature and frame integrity.
/// Frames without proper authentication will be rejected and may trigger
/// the circuit breaker.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
#[beam(nonrepudiable, frame_integrity)]
pub struct ClusterCommand {
	/// Heartbeat request [context 0]
	#[asn1(context_specific = "0", optional = "true")]
	pub heartbeat: Option<HeartbeatParams>,

	/// Hive management request [context 1]
	#[asn1(context_specific = "1", optional = "true")]
	pub manage: Option<HiveManagementRequest>,
}

/// Heartbeat parameters
///
/// Minimal payload - identity is established via certificate in the
/// frame's nonrepudiation signature.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HeartbeatParams {
	/// Cluster's current operational status
	pub cluster_status: ClusterStatus,
}

/// Cluster command response - ASN.1 CHOICE
///
/// Responses from hive to cluster. Uses context-specific tags for
/// CHOICE discrimination. Only one field should be set per response.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ClusterCommandResponse {
	/// Heartbeat response [context 0]
	#[asn1(context_specific = "0", optional = "true")]
	pub heartbeat: Option<HeartbeatResult>,

	/// Management response [context 1]
	#[asn1(context_specific = "1", optional = "true")]
	pub manage: Option<HiveManagementResponse>,
}

/// Heartbeat response with hive health status
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HeartbeatResult {
	/// Overall status (Accepted = healthy, Busy = at capacity)
	pub status: TransitStatus,
	/// Current aggregate utilization across all servlets
	pub utilization: BasisPoints,
	/// Number of active servlet instances
	pub active_servlets: u32,
}

// =============================================================================
// Circuit Breaker
// =============================================================================

/// Circuit breaker states
///
/// Implements the standard circuit breaker pattern for halting communication
/// with a cluster after repeated authentication failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitState {
	/// Normal operation - accepting requests
	Closed = 0,
	/// Tripped - rejecting all requests
	Open = 1,
	/// Testing - allowing single request to check recovery
	HalfOpen = 2,
}

/// Circuit breaker for cluster authentication failures
///
/// Trips after consecutive auth failures, halting all cluster communication.
/// After a cooldown period, transitions to half-open to allow a probe request.
///
/// # Thread Safety
///
/// All state is managed via atomics for lock-free concurrent access.
pub struct ClusterCircuitBreaker {
	/// Current state (CircuitState as u8)
	state: AtomicU8,
	/// Consecutive failure count
	failures: AtomicU8,
	/// Timestamp when breaker opened (ms since UNIX epoch)
	opened_at: AtomicU64,
	/// Failure threshold before tripping
	failure_threshold: u8,
	/// Cooldown duration in milliseconds
	cooldown_ms: u64,
}

impl ClusterCircuitBreaker {
	/// Create a new circuit breaker
	///
	/// # Arguments
	/// * `failure_threshold` - Number of consecutive failures before tripping
	/// * `cooldown_ms` - Time in milliseconds before transitioning to half-open
	pub fn new(failure_threshold: u8, cooldown_ms: u64) -> Self {
		Self {
			state: AtomicU8::new(CircuitState::Closed as u8),
			failures: AtomicU8::new(0),
			opened_at: AtomicU64::new(0),
			failure_threshold,
			cooldown_ms,
		}
	}

	/// Check if a request should be allowed through
	///
	/// Returns `true` if the circuit is closed or half-open (after cooldown).
	/// Returns `false` if the circuit is open and cooldown hasn't elapsed.
	pub fn allow_request(&self) -> bool {
		match self.state() {
			CircuitState::Closed => true,
			CircuitState::Open => {
				// Check if cooldown has elapsed
				let now = current_timestamp_ms();
				let opened = self.opened_at.load(Ordering::Relaxed);
				if now.saturating_sub(opened) >= self.cooldown_ms {
					// Transition to half-open for probe
					self.state.store(CircuitState::HalfOpen as u8, Ordering::Release);
					true
				} else {
					false
				}
			}
			CircuitState::HalfOpen => true, // Allow probe request
		}
	}

	/// Record a successful request
	///
	/// Resets failure count and closes the circuit.
	pub fn record_success(&self) {
		self.failures.store(0, Ordering::Relaxed);
		self.state.store(CircuitState::Closed as u8, Ordering::Release);
	}

	/// Record an authentication failure
	///
	/// Increments failure count. If threshold is reached, trips the circuit.
	pub fn record_auth_failure(&self) {
		let failures = self.failures.fetch_add(1, Ordering::AcqRel) + 1;
		if failures >= self.failure_threshold {
			self.state.store(CircuitState::Open as u8, Ordering::Release);
			self.opened_at.store(current_timestamp_ms(), Ordering::Relaxed);
		}
	}

	/// Get the current circuit state
	pub fn state(&self) -> CircuitState {
		match self.state.load(Ordering::Acquire) {
			0 => CircuitState::Closed,
			1 => CircuitState::Open,
			_ => CircuitState::HalfOpen,
		}
	}

	/// Check if the circuit is currently open (tripped)
	pub fn is_open(&self) -> bool {
		self.state() == CircuitState::Open
	}

	/// Reset the circuit breaker to closed state
	pub fn reset(&self) {
		self.failures.store(0, Ordering::Relaxed);
		self.state.store(CircuitState::Closed as u8, Ordering::Release);
	}
}

/// Get current timestamp in milliseconds since UNIX epoch
#[cfg(feature = "std")]
fn current_timestamp_ms() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_millis() as u64)
		.unwrap_or(0)
}

/// Timestamp stub for no_std environments
///
/// Embedded systems should provide their own time source.
#[cfg(not(feature = "std"))]
fn current_timestamp_ms() -> u64 {
	0 // Embedded systems need external time source
}

// =============================================================================
// Gate Policies
// =============================================================================

/// Gate policy for cluster command security
///
/// Enforces nonrepudiation and integrity requirements on cluster commands.
/// Integrates with the circuit breaker to halt communication after repeated
/// authentication failures.
///
/// # Type Parameters
///
/// * `S` - Signature encoding type (e.g., `Secp256k1Signature`)
/// * `V` - Verifying key type that implements `signature::Verifier<S>`
///
/// # Security Flow
///
/// 1. Check circuit breaker - reject if open
/// 2. Verify nonrepudiation signature present
/// 3. Verify frame integrity present
/// 4. Verify signature against at least one trusted key
/// 5. On failure: record auth failure (may trip breaker)
/// 6. On success: record success (resets breaker)
pub struct ClusterSecurityGate<S, V>
where
	S: signature::SignatureEncoding,
	V: signature::Verifier<S> + Clone,
{
	/// Circuit breaker for tracking auth failures
	circuit_breaker: Arc<ClusterCircuitBreaker>,
	/// Trusted cluster verifying keys for signature validation
	trusted_keys: Vec<V>,
	/// Phantom data for signature type
	_signature: core::marker::PhantomData<S>,
}

impl<S, V> ClusterSecurityGate<S, V>
where
	S: signature::SignatureEncoding,
	V: signature::Verifier<S> + Clone,
{
	/// Create a new security gate with the given circuit breaker and trusted keys
	///
	/// # Arguments
	/// * `circuit_breaker` - Shared circuit breaker for tracking auth failures
	/// * `trusted_keys` - Trusted verifying keys for signature verification
	///
	/// # Errors
	/// Returns `DroneError::NoTrustedKeys` if `trusted_keys` is empty.
	pub fn new(circuit_breaker: Arc<ClusterCircuitBreaker>, trusted_keys: Vec<V>) -> Result<Self, DroneError> {
		if trusted_keys.is_empty() {
			return Err(DroneError::NoTrustedKeys);
		}
		Ok(Self { circuit_breaker, trusted_keys, _signature: core::marker::PhantomData })
	}
}

impl<S, V> GatePolicy for ClusterSecurityGate<S, V>
where
	S: signature::SignatureEncoding + Send + Sync,
	V: signature::Verifier<S> + Clone + Send + Sync,
{
	fn evaluate(&self, frame: &Frame) -> TransitStatus {
		// Check circuit breaker first
		if !self.circuit_breaker.allow_request() {
			return TransitStatus::Forbidden;
		}

		// Check nonrepudiation (required by #[beam(nonrepudiable)])
		if frame.nonrepudiation.is_none() {
			self.circuit_breaker.record_auth_failure();
			return TransitStatus::Unauthorized;
		}

		// Check integrity (required by #[beam(frame_integrity)])
		if frame.integrity.is_none() {
			self.circuit_breaker.record_auth_failure();
			return TransitStatus::Unauthorized;
		}

		// Verify signature against trusted keys
		let verified = self.trusted_keys.iter().any(|key| frame.verify::<S>(key).is_ok());
		if !verified {
			self.circuit_breaker.record_auth_failure();
			return TransitStatus::Forbidden;
		}

		// All checks passed
		self.circuit_breaker.record_success();

		TransitStatus::Accepted
	}
}

/// Gate policy enforcing hive capacity limits (backpressure)
///
/// Returns `TransitStatus::Busy` when utilization exceeds threshold,
/// signaling to the cluster that it should route work elsewhere or queue.
///
/// **Exception**: Heartbeat priority frames always pass through to ensure
/// health monitoring continues even under load.
pub struct BackpressureGate {
	/// Current aggregate utilization (basis points as u16)
	utilization: Arc<AtomicU16>,
	/// Threshold above which to reject (from HiveConf)
	threshold: BasisPoints,
}

impl BackpressureGate {
	/// Create a new backpressure gate
	///
	/// # Arguments
	/// * `utilization` - Shared atomic for current utilization (updated by scaling loop)
	/// * `threshold` - Utilization threshold above which to reject requests
	pub fn new(utilization: Arc<AtomicU16>, threshold: BasisPoints) -> Self {
		Self { utilization, threshold }
	}

	/// Get the current utilization as BasisPoints
	pub fn current_utilization(&self) -> BasisPoints {
		BasisPoints::new_saturating(self.utilization.load(Ordering::Relaxed))
	}
}

impl GatePolicy for BackpressureGate {
	fn evaluate(&self, frame: &Frame) -> TransitStatus {
		// Heartbeat always passes through (pheromone signal channel)
		if frame.metadata.priority == Some(crate::MessagePriority::Heartbeat) {
			return TransitStatus::Accepted;
		}

		// Check utilization against threshold
		let current = self.utilization.load(Ordering::Relaxed);
		if current >= self.threshold.get() {
			TransitStatus::Busy
		} else {
			TransitStatus::Accepted
		}
	}
}

// ============================================================================
// Load Balancing
// ============================================================================

/// Metrics for a servlet instance used in load balancing decisions
#[derive(Debug, Clone)]
pub struct InstanceMetrics {
	/// Unique instance identifier (e.g., "worker_servlet_127.0.0.1:8080")
	pub servlet_id: Vec<u8>,
	/// Current utilization in basis points (0-10000)
	pub utilization: BasisPoints,
	/// Number of active/in-flight requests
	pub active_requests: u32,
}

/// Load balancing strategy for selecting servlet instances
///
/// Implementations determine how to distribute work across multiple
/// instances of the same servlet type.
pub trait LoadBalancer: Send + Sync + Default + Clone {
	/// Select an instance index from candidates
	///
	/// # Arguments
	/// * `candidates` - Slice of instance metrics to choose from
	///
	/// # Returns
	/// Index into `candidates` of the selected instance, or None if no suitable instance
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize>;
}

/// Select instance with lowest utilization
///
/// Simple and effective for most workloads. May cause thundering herd
/// under high concurrency as all routers converge on the same instance.
#[derive(Debug, Clone, Copy, Default)]
pub struct LeastLoaded;

impl LoadBalancer for LeastLoaded {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		if candidates.is_empty() {
			return None;
		}

		candidates
			.iter()
			.enumerate()
			.min_by_key(|(_, m)| m.utilization.get())
			.map(|(i, _)| i)
	}
}

/// Power of Two Choices (P2C) load balancer
///
/// Picks two random candidates and selects the one with lower utilization.
/// Better than pure least-loaded under high concurrency as it avoids
/// thundering herd while still achieving good balance.
///
/// Used by Envoy, gRPC, and other modern load balancers.
#[derive(Debug, Clone, Copy, Default)]
pub struct PowerOfTwoChoices;

impl LoadBalancer for PowerOfTwoChoices {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		match candidates.len() {
			0 => None,
			1 => Some(0),
			2 => {
				// Exactly 2: pick least loaded
				if candidates[0].utilization <= candidates[1].utilization {
					Some(0)
				} else {
					Some(1)
				}
			}
			n => {
				// Pick 2 random indices using simple LCG for no_std compatibility
				let seed = current_timestamp_ms();
				let i1 = (seed as usize) % n;
				let i2 = ((seed.wrapping_mul(LCG_MULTIPLIER).wrapping_add(1)) as usize) % n;
				// Ensure different indices
				let i2 = if i1 == i2 {
					(i2 + 1) % n
				} else {
					i2
				};

				// Select least loaded of the two
				if candidates[i1].utilization <= candidates[i2].utilization {
					Some(i1)
				} else {
					Some(i2)
				}
			}
		}
	}
}

/// Round-robin load balancer
///
/// Distributes requests evenly across all instances regardless of load.
/// Simple and predictable but doesn't account for varying request costs.
#[derive(Debug, Clone, Default)]
pub struct RoundRobin {
	counter: Arc<AtomicU64>,
}

impl LoadBalancer for RoundRobin {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		if candidates.is_empty() {
			return None;
		}

		let count = self.counter.fetch_add(1, Ordering::Relaxed);
		Some((count as usize) % candidates.len())
	}
}

// =============================================================================
// Message Routing
// =============================================================================

/// Type validator function signature for message routing
pub type MessageValidator = fn(&[u8]) -> bool;

/// Message routing strategy for type-based dispatch
///
/// Implementations determine how to match incoming messages to servlet types.
pub trait MessageRouter: Send + Sync + Default + Clone {
	/// Attempt to route a message to a servlet type
	///
	/// # Arguments
	/// * `message` - Raw message bytes to route
	/// * `registered_types` - Slice of (type_name, validator) pairs
	///
	/// # Returns
	/// The servlet type name if matched, None otherwise
	fn route<'a>(&self, message: &[u8], registered_types: &'a [(&'static [u8], MessageValidator)]) -> Option<&'a [u8]>;
}

/// Routes by attempting decode against each registered type's validator
///
/// Tries validators in registration order; first match wins.
#[derive(Debug, Clone, Copy, Default)]
pub struct TypeBasedRouter;

impl MessageRouter for TypeBasedRouter {
	fn route<'a>(&self, message: &[u8], registered_types: &'a [(&'static [u8], MessageValidator)]) -> Option<&'a [u8]> {
		registered_types
			.iter()
			.find(|(_, validator)| validator(message))
			.map(|(name, _)| *name)
	}
}

// =============================================================================
// Response Builder Helpers (DRY)
// =============================================================================

impl ClusterCommandResponse {
	/// Create a heartbeat response
	#[inline]
	pub fn heartbeat(status: TransitStatus, utilization: BasisPoints, active_servlets: u32) -> Self {
		Self {
			heartbeat: Some(HeartbeatResult { status, utilization, active_servlets }),
			manage: None,
		}
	}

	/// Create a management response wrapper
	#[inline]
	pub fn manage(response: HiveManagementResponse) -> Self {
		Self { heartbeat: None, manage: Some(response) }
	}
}

impl HiveManagementResponse {
	/// Create a spawn success response
	#[inline]
	pub fn spawn_ok(address: Vec<u8>, servlet_id: Vec<u8>) -> Self {
		Self {
			spawn: Some(SpawnServletResult {
				status: TransitStatus::Accepted,
				servlet_address: Some(address),
				servlet_id: Some(servlet_id),
			}),
			list: None,
			stop: None,
		}
	}

	/// Create a spawn failure response
	#[inline]
	pub fn spawn_err(status: TransitStatus) -> Self {
		Self {
			spawn: Some(SpawnServletResult { status, servlet_address: None, servlet_id: None }),
			list: None,
			stop: None,
		}
	}

	/// Create a list response
	#[inline]
	pub fn list_ok(servlets: Vec<ServletInfo>) -> Self {
		Self {
			spawn: None,
			list: Some(ListServletsResult { status: TransitStatus::Accepted, servlets }),
			stop: None,
		}
	}

	/// Create a stop success response
	#[inline]
	pub fn stop_ok() -> Self {
		Self {
			spawn: None,
			list: None,
			stop: Some(StopServletResult { status: TransitStatus::Accepted }),
		}
	}

	/// Create a stop failure response
	#[inline]
	pub fn stop_err(status: TransitStatus) -> Self {
		Self { spawn: None, list: None, stop: Some(StopServletResult { status }) }
	}
}

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

/// TLS configuration for hive servlets
///
/// Contains certificate, key, and validators for encrypted transport.
/// Wrapped in `Arc` when stored in `HiveConf` because validators are trait objects.
#[cfg(feature = "x509")]
pub struct HiveTlsConfig {
	/// Server certificate specification
	pub certificate: crate::crypto::x509::CertificateSpec,
	/// Private key specification
	pub key: crate::crypto::key::KeySpec,
	/// Client certificate validators (e.g., public key pinning)
	pub validators: Vec<Arc<dyn crate::crypto::x509::policy::CertificateValidation>>,
}

#[cfg(feature = "x509")]
impl core::fmt::Debug for HiveTlsConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("HiveTlsConfig")
			.field("certificate", &self.certificate)
			.field("key", &self.key)
			.field("validators", &format!("[{} validators]", self.validators.len()))
			.finish()
	}
}

/// Per-servlet-type scaling configuration
#[derive(Debug, Clone)]
pub struct ServletScaleConf {
	/// Minimum instances to maintain (default: 1)
	pub min_instances: usize,
	/// Maximum instances allowed (default: 10)
	pub max_instances: usize,
	/// Scale-up threshold in basis points (default: 8000 = 80%)
	pub scale_up_threshold: BasisPoints,
	/// Scale-down threshold in basis points (default: 2000 = 20%)
	pub scale_down_threshold: BasisPoints,
}

impl Default for ServletScaleConf {
	fn default() -> Self {
		Self {
			min_instances: 1,
			max_instances: 10,
			scale_up_threshold: BasisPoints::new(8000),
			scale_down_threshold: BasisPoints::new(2000),
		}
	}
}

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

/// Input message to the scaling worker
#[derive(Debug, Clone)]
pub struct ScalingMetrics {
	/// Servlet type being evaluated
	pub servlet_type: Vec<u8>,
	/// Current utilization in basis points (0-10000)
	pub utilization: BasisPoints,
	/// Current instance count
	pub current_instances: usize,
	/// Scaling configuration for this type
	pub config: ServletScaleConf,
}

/// Output decision from the scaling worker
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalingDecision {
	/// No action needed
	Hold,
	/// Spawn one additional instance
	ScaleUp,
	/// Stop one idle instance
	ScaleDown,
}

impl ScalingDecision {
	/// Evaluate scaling metrics and return a decision
	///
	/// This is the core scaling logic that determines whether to scale up,
	/// scale down, or hold steady based on current utilization and bounds.
	#[must_use]
	pub fn evaluate(metrics: &ScalingMetrics) -> Self {
		let utilization = metrics.utilization.get();
		let up_threshold = metrics.config.scale_up_threshold.get();
		let down_threshold = metrics.config.scale_down_threshold.get();
		if utilization > up_threshold && metrics.current_instances < metrics.config.max_instances {
			ScalingDecision::ScaleUp
		} else if utilization < down_threshold && metrics.current_instances > metrics.config.min_instances {
			ScalingDecision::ScaleDown
		} else {
			ScalingDecision::Hold
		}
	}
}

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

/// Macro for creating drones with pre-registered servlets
#[macro_export]
macro_rules! drone {
	(
		$(#[$meta:meta])*
		pub $drone_name:ident,
		protocol: $protocol:path,
		hive: true,
		policies: { $($policy_key:ident: $policy_val:tt),+ $(,)? },
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol, [hive],
			[$($policy_key: $policy_val),+],
			$($servlet_id: $servlet_name<$input>),*, pub, [$(#[$meta])*]
		);
	};

	(
		$(#[$meta:meta])*
		$drone_name:ident,
		protocol: $protocol:path,
		hive: true,
		policies: { $($policy_key:ident: $policy_val:tt),+ $(,)? },
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol,
			[hive],
			[$($policy_key: $policy_val),+],
			$($servlet_id: $servlet_name<$input>),*, , [$(#[$meta])*]
		);
	};

	(
		$(#[$meta:meta])*
		pub $drone_name:ident,
		protocol: $protocol:path,
		policies: { $($policy_key:ident: $policy_val:tt),+ $(,)? },
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol,
			[],
			[$($policy_key: $policy_val),+],
			$($servlet_id: $servlet_name<$input>),*, pub, [$(#[$meta])*]
		);
	};

	(
		$(#[$meta:meta])*
		$drone_name:ident,
		protocol: $protocol:path,
		policies: { $($policy_key:ident: $policy_val:tt),+ $(,)? },
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol,
			[],
			[$($policy_key: $policy_val),+],
			$($servlet_id: $servlet_name<$input>),*, , [$(#[$meta])*]
		);
	};

	(
		$(#[$meta:meta])*
		pub $drone_name:ident,
		protocol: $protocol:path,
		hive: true,
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol,
			[hive],
			[],
			$($servlet_id: $servlet_name<$input>),*, pub, [$(#[$meta])*]
		);
	};
	(
		$(#[$meta:meta])*
		$drone_name:ident,
		protocol: $protocol:path,
		hive: true,
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol,
			[hive],
			[],
			$($servlet_id: $servlet_name<$input>),*, , [$(#[$meta])*]
		);
	};

	(
		$(#[$meta:meta])*
		pub $drone_name:ident,
		protocol: $protocol:path,
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol,
			[],
			[],
			$($servlet_id: $servlet_name<$input>),*, pub, [$(#[$meta])*]
		);
	};

	// Implement hive struct without attributes and visibility
	(
		$(#[$meta:meta])*
		$drone_name:ident,
		protocol: $protocol:path,
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol,
			[],
			[],
			$($servlet_id: $servlet_name<$input>),*, , [$(#[$meta])*]
		);
	};

	// Generate with attributes and visibility (new syntax)
	(
		@generate_with_attrs $drone_name:ident,
		$protocol:path,
		[hive],
		[$($policy_key:ident: $policy_val:tt),*],
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*, pub, [$(#[$meta:meta])*]
	) => {
		drone!(@impl_hive_struct_with_attrs $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*, pub, [$(#[$meta])*]);
		drone!(@impl_servlet_trait_for_hive $drone_name, $protocol, [$($policy_key: $policy_val),*], $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drone_trait_for_hive $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_hive_trait $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drop_for_hive $drone_name);
	};

	(
		@generate_with_attrs $drone_name:ident,
		$protocol:path,
		[hive],
		[$($policy_key:ident: $policy_val:tt),*],
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*, , [$(#[$meta:meta])*]
	) => {
		drone!(@impl_hive_struct_with_attrs $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*, , [$(#[$meta])*]);
		drone!(@impl_servlet_trait_for_hive $drone_name, $protocol, [$($policy_key: $policy_val),*], $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drone_trait_for_hive $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_hive_trait $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drop_for_hive $drone_name);
	};

	(
		@generate_with_attrs $drone_name:ident,
		$protocol:path,
		[],
		[$($policy_key:ident: $policy_val:tt),*],
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*, pub, [$(#[$meta:meta])*]
	) => {
		drone!(@impl_enum $drone_name, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_struct_with_attrs $drone_name, $protocol, pub, [$(#[$meta])*]);
		drone!(@impl_servlet_trait $drone_name, $protocol, [$($policy_key: $policy_val),*], $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drone_trait $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drop $drone_name);
	};

	(
		@generate_with_attrs $drone_name:ident,
		$protocol:path,
		[],
		[$($policy_key:ident: $policy_val:tt),*],
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*, , [$(#[$meta:meta])*]
	) => {
		drone!(@impl_enum $drone_name, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_struct_with_attrs $drone_name, $protocol, , [$(#[$meta])*]);
		drone!(@impl_servlet_trait $drone_name, $protocol, [$($policy_key: $policy_val),*], $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drone_trait $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drop $drone_name);
	};

	// Start servlet
	(
		@start_servlet $servlet_name:ident<$input:ty>,
		$instance:ident,
		$drone_name:ident,
		$servlet_id:ident,
		$servlet_id_str:expr,
		$error_id:expr
	) => {
		paste::paste! {
			let servlet = <$servlet_name as $crate::colony::Servlet<$input>>::start(
				::std::sync::Arc::clone(&$instance.trace), None,
			).await.map_err(|_| $crate::colony::DroneError::InvalidServletId($error_id))?;

			let mut active = $instance.active_servlet.lock()?;
			*active = [<$drone_name ActiveServlet>]::[<$servlet_id:camel>](servlet);
			return Ok($crate::policy::TransitStatus::Accepted);
		}
	};

	// Start servlet with response (for control server)
	(
		@start_servlet_with_response $servlet_name:ident<$input:ty>,
		$drone_name:ident,
		$servlet_id:ident,
		$servlet_id_str:expr,
		$error_id:expr,
		$active_servlet:ident,
		$trace:ident,
		$stop_old:ident,
		$frame:ident
	) => {
		paste::paste! {
			// Stop old servlet if any
			let old_servlet = {
				let mut active = $active_servlet.lock()?;
				core::mem::replace(&mut *active, [<$drone_name ActiveServlet>]::None)
			};

			$stop_old(old_servlet);

			// Start new servlet
			match <$servlet_name as $crate::colony::Servlet<$input>>::start(
				::std::sync::Arc::clone(&$trace), None,
			).await {
				Ok(servlet) => {
					let servlet_addr = servlet.addr();
					let addr_bytes: Vec<u8> = servlet_addr.into();
					let mut active = $active_servlet.lock()?;
					*active = [<$drone_name ActiveServlet>]::[<$servlet_id:camel>](servlet);
					drop(active);
					return drone!(@reply $frame, $crate::colony::ActivateServletResponse::ok(addr_bytes));
				}
				Err(_) => {
					return drone!(@reply $frame,
						$crate::colony::ActivateServletResponse::err($crate::policy::TransitStatus::Forbidden)
					);
				}
			}
		}
	};

	// Generate the enum for holding different servlet types
	(@impl_enum $drone_name:ident, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			// Generate an enum to hold any of the possible servlet types
			enum [<$drone_name ActiveServlet>] {
				None,
				$(
					[<$servlet_id:camel>]($servlet_name),
				)*
			}

			impl Default for [<$drone_name ActiveServlet>] {
				fn default() -> Self {
					Self::None
				}
			}
		}
	};

	// Generate the drone struct
	(@impl_struct $drone_name:ident, $protocol:path) => {
		drone!(@impl_struct_with_attrs $drone_name, $protocol, pub, []);
	};

	// Generate the drone struct with attributes and visibility
	(@impl_struct_with_attrs $drone_name:ident, $protocol:path, pub, [$(#[$meta:meta])*]) => {
		paste::paste! {
			$(#[$meta])*
			pub struct $drone_name {
				active_servlet: ::std::sync::Arc<::std::sync::Mutex<[<$drone_name ActiveServlet>]>>,
				control_server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
			}
		}
	};
	(@impl_struct_with_attrs $drone_name:ident, $protocol:path, , [$(#[$meta:meta])*]) => {
		paste::paste! {
			$(#[$meta])*
			struct $drone_name {
				active_servlet: ::std::sync::Arc<::std::sync::Mutex<[<$drone_name ActiveServlet>]>>,
				control_server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
			}
		}
	};

	// Implement Servlet trait
	(
		@impl_servlet_trait $drone_name:ident,
		$protocol:path,
		[$($policy_key:ident: $policy_val:tt),*],
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			impl $crate::colony::Servlet<()> for $drone_name {
				type Conf = ();
				type Address = <$protocol as $crate::transport::Protocol>::Address;

				async fn start(
					trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
					_config: Option<Self::Conf>
				) -> Result<Self, $crate::TightBeamError> {
					// Bind to a port for the control server
					let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()?;
					let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await?;

					// Create shared state for the active servlet
					let active_servlet = ::std::sync::Arc::new(::std::sync::Mutex::new([<$drone_name ActiveServlet>]::None));
					let active_servlet_clone = ::std::sync::Arc::clone(&active_servlet);

					// Clone trace for control server
					let trace_clone = ::std::sync::Arc::clone(&trace);

					// Start the control server that listens for ActivateServletRequest messages
					let control_server_handle = drone!(
						@build_control_server $protocol,
						listener,
						[$($policy_key: $policy_val),*],
						active_servlet_clone,
						trace_clone,
						$drone_name,
						$($servlet_id: $servlet_name<$input>),*
					);

					Ok(Self {
						active_servlet,
						control_server_handle: Some(control_server_handle),
						addr,
						trace,
					})
				}

				fn addr(&self) -> Self::Address {
					self.addr
				}

				fn stop(mut self) {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet_runtime::rt::abort(handle);
					}
					// Stop any active servlet
					if let Ok(mut active) = self.active_servlet.lock() {
						let servlet = core::mem::replace(&mut *active, [<$drone_name ActiveServlet>]::None);
						drop(active);
						match servlet {
							[<$drone_name ActiveServlet>]::None => {},
							$(
								[<$drone_name ActiveServlet>]::[<$servlet_id:camel>](s) => {
									s.stop();
								}
							)*
						}
					}
				}

				#[cfg(feature = "tokio")]
				async fn join(mut self) -> Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet_runtime::rt::join(handle).await
					} else {
						Ok(())
					}
				}

				#[cfg(all(not(feature = "tokio"), feature = "std"))]
				async fn join(mut self) -> Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet_runtime::rt::join(handle)
					} else {
						Ok(())
					}
				}
			}
		}
	};

	// Start servlet for hive establishment (no response needed)
	(
		@start_servlet_for_hive_establish_impl $protocol:path,
		$servlet_name:ident<$input:ty>,
		$instance:ident,
		$drone_name:ident,
		$servlet_id:ident
	) => {
		paste::paste! {
			// Build servlet config (with TLS if configured)
			#[cfg(feature = "x509")]
			let servlet_conf = if let Some(ref tls) = $instance.config.hive_tls {
				use $crate::colony::ServletConf;
				ServletConf::<$protocol, $input>::builder()
					.with_certificate(tls.certificate.clone(), tls.key.clone(), tls.validators.clone())
					.ok()
					.map(|builder| builder.with_config(::std::sync::Arc::new(())).build())
			} else {
				None
			};
			#[cfg(not(feature = "x509"))]
			let servlet_conf: Option<<$servlet_name as $crate::colony::Servlet<$input>>::Conf> = None;

			match <$servlet_name as $crate::colony::Servlet<$input>>::start(
				::std::sync::Arc::clone(&$instance.trace),
				servlet_conf,
			).await {
				Ok(servlet) => {
					let servlet_addr = servlet.addr();
					let addr_bytes: Vec<u8> = servlet_addr.into();

					// Pre-allocate with exact capacity
					let type_prefix = stringify!($servlet_id).as_bytes();
					let mut servlet_id = Vec::with_capacity(type_prefix.len() + 1 + addr_bytes.len());

					servlet_id.extend_from_slice(type_prefix);
					servlet_id.push(b'_');
					servlet_id.extend_from_slice(&addr_bytes);

					// Initialize utilization_map entry for this instance
					if let Ok(mut util_map) = $instance.utilization_map.lock() {
						util_map.insert(servlet_id.clone(), 0);
					}

					if let Ok(mut servlets) = $instance.servlets.lock() {
						servlets.insert(servlet_id, [<$drone_name Servlet>]::[<$servlet_id:camel>](servlet));
					}
				}
				Err(_e) => {
					// Servlet start failed - continue with other servlets
					#[cfg(feature = "std")]
					eprintln!("Warning: Failed to start servlet {}: {:?}", stringify!($servlet_id), _e);
				}
			}
		}
	};

	// Start servlet for hive (with response) - legacy version
	(
		@start_servlet_for_hive $servlet_name:ident<$input:ty>,
		$drone_name:ident,
		$servlet_id:ident,
		$servlet_id_str:expr,
		$error_id:expr,
		$servlets:ident,
		$trace:ident,
		$frame:ident
	) => {
		paste::paste! {
			match <$servlet_name as $crate::colony::Servlet<$input>>::start(
				::std::sync::Arc::clone(&$trace),
				None,
			).await {
				Ok(servlet) => {
					let servlet_addr = servlet.addr();
					let addr_bytes: Vec<u8> = servlet_addr.into();

					// Pre-allocate with exact capacity
					let type_prefix = stringify!($servlet_id).as_bytes();
					let mut servlet_id = Vec::with_capacity(type_prefix.len() + 1 + addr_bytes.len());

					servlet_id.extend_from_slice(type_prefix);
					servlet_id.push(b'_');
					servlet_id.extend_from_slice(&addr_bytes);

					let mut servlets = $servlets.lock()?;
					servlets.insert(servlet_id.clone(), [<$drone_name Servlet>]::[<$servlet_id:camel>](servlet));

					drop(servlets);

					return drone!(@reply $frame,
						$crate::colony::HiveManagementResponse::spawn_ok(addr_bytes, servlet_id)
					);
				}
				Err(_) => {
					return drone!(@reply $frame,
						$crate::colony::HiveManagementResponse::spawn_err($crate::policy::TransitStatus::Forbidden)
					);
				}
			}
		}
	};

	// Start servlet for hive (with ClusterCommandResponse wrapper)
	(
		@start_servlet_for_hive_cmd $servlet_name:ident<$input:ty>,
		$drone_name:ident,
		$servlet_id:ident,
		$servlet_id_str:expr,
		$error_id:expr,
		$servlets:ident,
		$trace:ident,
		$frame:ident
	) => {
		paste::paste! {
			match <$servlet_name as $crate::colony::Servlet<$input>>::start(
				::std::sync::Arc::clone(&$trace),
				None,
			).await {
				Ok(servlet) => {
					let servlet_addr = servlet.addr();
					let addr_bytes: Vec<u8> = servlet_addr.into();
					let type_prefix = stringify!($servlet_id).as_bytes();
					let mut servlet_id = Vec::with_capacity(type_prefix.len() + 1 + addr_bytes.len());

					servlet_id.extend_from_slice(type_prefix);
					servlet_id.push(b'_');
					servlet_id.extend_from_slice(&addr_bytes);

					let mut servlets = $servlets.lock()?;
					servlets.insert(servlet_id.clone(), [<$drone_name Servlet>]::[<$servlet_id:camel>](servlet));

					drop(servlets);

					return drone!(@reply $frame, $crate::colony::ClusterCommandResponse::manage(
						$crate::colony::HiveManagementResponse::spawn_ok(addr_bytes, servlet_id)
					));
				}
				Err(_) => {
					return drone!(@reply $frame, $crate::colony::ClusterCommandResponse::manage(
						$crate::colony::HiveManagementResponse::spawn_err($crate::policy::TransitStatus::Forbidden)
					));
				}
			}
		}
	};

	// Implement Drone trait
	(@impl_drone_trait $drone_name:ident, $protocol:path, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			impl $crate::colony::Drone<()> for $drone_name {
				type Protocol = $protocol;

				fn trace(&self) -> ::std::sync::Arc<$crate::trace::TraceCollector> {
					::std::sync::Arc::clone(&self.trace)
				}

				async fn morph(
					&mut self,
					msg: $crate::colony::ActivateServletRequest,
				) -> Result<$crate::policy::TransitStatus, $crate::colony::DroneError> {
					// Deactivate current servlet if any
					if self.is_active() {
						self.deactivate().await?;
					}

					// Match servlet_id and activate the corresponding servlet
					$(
						if msg.servlet_id == stringify!($servlet_id).as_bytes() {
							drone!(
								@start_servlet $servlet_name<$input>,
								self,
								$drone_name,
								$servlet_id,
								stringify!($servlet_id),
								msg.servlet_id.clone()
							);
						}
					)*

					// Unknown servlet ID
					Err($crate::colony::DroneError::InvalidServletId(msg.servlet_id))
				}

				fn is_active(&self) -> bool {
					self.active_servlet.lock()
						.map(|active| !matches!(*active, [<$drone_name ActiveServlet>]::None))
						.unwrap_or(false)
				}

				async fn deactivate(&mut self) -> Result<(), $crate::colony::DroneError> {
					// Take the active servlet and stop it
					let mut active = self.active_servlet.lock()?;
					let servlet = core::mem::replace(&mut *active, [<$drone_name ActiveServlet>]::None);

					drop(active);

					match servlet {
						[<$drone_name ActiveServlet>]::None => {},
						$(
							[<$drone_name ActiveServlet>]::[<$servlet_id:camel>](s) => {
								s.stop();
							}
						)*
					}

					Ok(())
				}

				async fn register_with_cluster(
					&self,
					cluster_addr: <$protocol as $crate::transport::Protocol>::Address,
				) -> Result<$crate::colony::RegisterDroneResponse, $crate::colony::DroneError> {
					use $crate::transport::MessageEmitter;

					// Get this drone's address
					let drone_addr = self.addr();
					// Convert address to bytes
					let drone_addr_bytes: Vec<u8> = drone_addr.into();

					// Build list of available servlet IDs
					let available_servlets = vec![
						$(
							stringify!($servlet_id).as_bytes().to_vec(),
						)*
					];

					// Create registration request
					let request = $crate::colony::RegisterDroneRequest {
						drone_addr: drone_addr_bytes,
						available_servlets,
						metadata: None,
					};

					// Connect to cluster and send registration
					let stream = <$protocol as $crate::transport::Protocol>::connect(cluster_addr).await?;
					let mut transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);
					let frame = {
						use $crate::builder::TypeBuilder;
						$crate::utils::compose($crate::Version::V0)
							.with_id(b"drone-registration")
							.with_order(0)
							.with_message(request)
							.build()?
					};

					// Send and wait for response
					let response_frame = transport.emit(frame, None).await
						.map_err(|_| $crate::colony::DroneError::EmitFailed)?
						.ok_or_else(|| $crate::colony::DroneError::NoResponse)?;

					// Decode response
					let response = $crate::decode::<$crate::colony::RegisterDroneResponse>(&response_frame.message)
						.map_err(|_| $crate::colony::DroneError::DecodeFailed)?;

					Ok(response)
				}
			}
		}
	};

	// Generate hive struct (stores multiple servlet instances)
	(@impl_hive_struct $drone_name:ident, $protocol:path, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		drone!(@impl_hive_struct_with_attrs $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*, pub, []);
	};

	// Generate hive struct with attributes and visibility
	(
		@impl_hive_struct_with_attrs $drone_name:ident,
		$protocol:path,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*, pub, [$(#[$meta:meta])*]
	) => {
		paste::paste! {
			$(#[$meta])*
			pub struct $drone_name {
				servlets: ::std::sync::Arc<::std::sync::Mutex<::std::collections::HashMap<Vec<u8>, [<$drone_name Servlet>]>>>,
				config: $crate::colony::HiveConf,
				control_server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				scaling_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				utilization: ::std::sync::Arc<::core::sync::atomic::AtomicU16>,
				utilization_map: ::std::sync::Arc<::std::sync::Mutex<::std::collections::HashMap<Vec<u8>, u16>>>,
				#[allow(dead_code)]
				servlet_pool: ::std::sync::Arc<$crate::transport::client::pool::ConnectionPool<$protocol>>,
				/// Draining state: None = running, Some(Instant) = draining since
				draining_since: ::std::sync::Arc<::std::sync::RwLock<Option<::std::time::Instant>>>,
			}

			enum [<$drone_name Servlet>] {
				$(
					[<$servlet_id:camel>]($servlet_name),
				)*
			}
		}
	};

	// Implement hive struct with attributes and visibility
	(
		@impl_hive_struct_with_attrs $drone_name:ident,
		$protocol:path,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*, , [$(#[$meta:meta])*]
	) => {
		paste::paste! {
			$(#[$meta])*
			struct $drone_name {
				servlets: ::std::sync::Arc<::std::sync::Mutex<::std::collections::HashMap<Vec<u8>, [<$drone_name Servlet>]>>>,
				config: $crate::colony::HiveConf,
				control_server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				scaling_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				utilization: ::std::sync::Arc<::core::sync::atomic::AtomicU16>,
				utilization_map: ::std::sync::Arc<::std::sync::Mutex<::std::collections::HashMap<Vec<u8>, u16>>>,
				#[allow(dead_code)]
				servlet_pool: ::std::sync::Arc<$crate::transport::client::pool::ConnectionPool<$protocol>>,
				/// Draining state: None = running, Some(Instant) = draining since
				draining_since: ::std::sync::Arc<::std::sync::RwLock<Option<::std::time::Instant>>>,
			}

			enum [<$drone_name Servlet>] {
				$(
					[<$servlet_id:camel>]($servlet_name),
				)*
			}
		}
	};

	// Implement Servlet trait for hive
	(
		@impl_servlet_trait_for_hive $drone_name:ident,
		$protocol:path,
		[$($policy_key:ident: $policy_val:tt),*],
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			impl $crate::colony::Servlet<()> for $drone_name {
				type Conf = $crate::colony::HiveConf;
				type Address = <$protocol as $crate::transport::Protocol>::Address;

				async fn start(
					trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
					config: Option<Self::Conf>
				) -> Result<Self, $crate::TightBeamError> {
					// Bind to a port for the control server
					let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()?;
					let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await?;

					// Use provided config or default
					let config = config.unwrap_or_default();

					// Create shared state for servlets
					let servlets = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::collections::HashMap::new()));
					let servlets_clone = ::std::sync::Arc::clone(&servlets);
					let trace_clone = ::std::sync::Arc::clone(&trace);

					// Create utilization atomic for backpressure
					let utilization = ::std::sync::Arc::new(::core::sync::atomic::AtomicU16::new(0));
					let utilization_for_server = ::std::sync::Arc::clone(&utilization);

					// Create per-instance utilization map for load balancing
					let utilization_map = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::collections::HashMap::new()));
					let utilization_map_for_server = ::std::sync::Arc::clone(&utilization_map);

					// Circuit breaker and security settings from config
					let cb_threshold = config.circuit_breaker_threshold;
					let cb_cooldown_ms = config.circuit_breaker_cooldown_ms;
					let trusted_keys = config.trusted_cluster_keys.clone();

					// Create connection pool for servlet forwarding
					let pool_config = $crate::transport::client::pool::PoolConfig {
						idle_timeout: config.servlet_pool_idle_timeout,
						max_connections: config.servlet_pool_size,
					};
					let servlet_pool = {
						use $crate::transport::client::pool::ConnectionBuilder;
						::std::sync::Arc::new(
							$crate::transport::client::pool::ConnectionPool::<$protocol>::builder()
								.with_config(pool_config)
								.build()
						)
					};
					let servlet_pool_for_server = ::std::sync::Arc::clone(&servlet_pool);

					// Create draining state for graceful shutdown
					let draining_since = ::std::sync::Arc::new(::std::sync::RwLock::new(None));
					let draining_since_for_server = ::std::sync::Arc::clone(&draining_since);

					// Start the control server that listens for management commands
					let control_server_handle = drone!(
						@build_hive_control_server $protocol,
						listener,
						[$($policy_key: $policy_val),*],
						servlets_clone,
						trace_clone,
						utilization_for_server,
						utilization_map_for_server,
						cb_threshold,
						cb_cooldown_ms,
						trusted_keys,
						servlet_pool_for_server,
						draining_since_for_server,
						$drone_name,
						$($servlet_id: $servlet_name<$input>),*
					);

					Ok(Self {
						servlets,
						config,
						control_server_handle: Some(control_server_handle),
						scaling_handle: None,
						addr,
						trace,
						utilization,
						utilization_map,
						servlet_pool,
						draining_since,
					})
				}

				fn addr(&self) -> Self::Address {
					self.addr
				}

				fn stop(mut self) {
					// Stop the scaling task
					if let Some(handle) = self.scaling_handle.take() {
						$crate::colony::servlet_runtime::rt::abort(handle);
					}
					// Stop the control server
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet_runtime::rt::abort(handle);
					}
					// Stop all servlets
					if let Ok(mut servlets) = self.servlets.lock() {
						for (_name, servlet) in servlets.drain() {
							match servlet {
								$(
									[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => {
										s.stop();
									}
								)*
							}
						}
					}
				}

				#[cfg(feature = "tokio")]
				async fn join(mut self) -> Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet_runtime::rt::join(handle).await
					} else {
						Ok(())
					}
				}

				#[cfg(all(not(feature = "tokio"), feature = "std"))]
				async fn join(mut self) -> Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet_runtime::rt::join(handle)
					} else {
						Ok(())
					}
				}
			}
		}
	};

	// Implement Drone trait for hive (minimal implementation)
	(
		@impl_drone_trait_for_hive $drone_name:ident,
		$protocol:path,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			impl $crate::colony::Drone<()> for $drone_name {
				type Protocol = $protocol;

				fn trace(&self) -> ::std::sync::Arc<$crate::trace::TraceCollector> {
					::std::sync::Arc::clone(&self.trace)
				}

				async fn morph(
					&mut self,
					_msg: $crate::colony::ActivateServletRequest,
				) -> Result<$crate::policy::TransitStatus, $crate::colony::DroneError> {
					// Hives don't morph - they manage multiple servlets
					Err($crate::colony::DroneError::InvalidServletId(b"hive_does_not_morph".to_vec()))
				}

				fn is_active(&self) -> bool {
					self.servlets.lock()
						.map(|servlets| !servlets.is_empty())
						.unwrap_or(false)
				}

				async fn deactivate(&mut self) -> Result<(), $crate::colony::DroneError> {
					// Stop all servlets
					let mut servlets = self.servlets.lock()?;
					for (_name, servlet) in servlets.drain() {
						match servlet {
							$(
								[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => {
									s.stop();
								}
							)*
						}
					}

					Ok(())
				}

				async fn register_with_cluster(
					&self,
					cluster_addr: <$protocol as $crate::transport::Protocol>::Address,
				) -> Result<$crate::colony::RegisterDroneResponse, $crate::colony::DroneError> {
					use $crate::transport::MessageEmitter;

					// Get this hive's address
					let drone_addr = self.addr();
					let drone_addr_bytes: Vec<u8> = drone_addr.into();

					// Build list of available servlet IDs
					let available_servlets = vec![
						$(
							stringify!($servlet_id).as_bytes().to_vec(),
						)*
					];

					// Create registration request
					let request = $crate::colony::RegisterDroneRequest {
						drone_addr: drone_addr_bytes,
						available_servlets,
						metadata: Some(b"hive".to_vec()),
					};

					// Connect to cluster and send registration
					let stream = <$protocol as $crate::transport::Protocol>::connect(cluster_addr).await?;
					let mut transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);
					let frame = {
						use $crate::builder::TypeBuilder;
						$crate::utils::compose($crate::Version::V0)
							.with_id(b"hive-registration")
							.with_order(0)
							.with_message(request)
							.build()?
					};

					// Send and wait for response
					let response_frame = transport.emit(frame, None).await?
						.ok_or($crate::colony::DroneError::NoResponse)?;

					// Decode response
					Ok($crate::decode::<$crate::colony::RegisterDroneResponse>(&response_frame.message)?)
				}
			}
		}
	};

	// Implement Hive trait for mycelial async protocols
	(@impl_hive_trait $drone_name:ident, $protocol:path, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			impl $crate::colony::Hive<()> for $drone_name
			where
				$protocol: $crate::transport::Mycelial + $crate::transport::AsyncListenerTrait,
			{
				async fn establish_hive(&mut self) -> Result<(), $crate::colony::DroneError> {
					// Start min_instances of each servlet type
					// Each servlet will call Protocol::bind() with default_bind_address()
					// which returns "0.0.0.0:0" (or equivalent), causing the OS to allocate
					// a unique port for each servlet. This is the mycelial networking model.
					$(
						{
							let min_instances = self.config.servlet_overrides
								.get(stringify!($servlet_id).as_bytes())
								.map(|c| c.min_instances)
								.unwrap_or(self.config.default_scale.min_instances);

							for _ in 0..min_instances {
								drone!(
									@start_servlet_for_hive_establish_impl $protocol,
									$servlet_name<$input>,
									self,
									$drone_name,
									$servlet_id
								);
							}
						}
					)*

					// Spawn the auto-scaling background task
					let servlets = ::std::sync::Arc::clone(&self.servlets);
					let config = self.config.clone();
					let trace = ::std::sync::Arc::clone(&self.trace);
					let utilization_for_scaling = ::std::sync::Arc::clone(&self.utilization);
					let utilization_map_for_scaling = ::std::sync::Arc::clone(&self.utilization_map);

					// Define helper closure to stop any servlet variant (avoids nested macro repetition)
					let stop_servlet = |servlet: [<$drone_name Servlet>]| {
						match servlet {
							$(
								[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.stop(),
							)*
						}
					};

					// Define servlet type names for iteration
					let servlet_types: Vec<&'static [u8]> = vec![
						$(stringify!($servlet_id).as_bytes(),)*
					];

					// Type alias for spawn function closures
					type SpawnFn = ::std::sync::Arc<
						dyn Fn() -> ::core::pin::Pin<::std::boxed::Box<dyn ::core::future::Future<Output = ()> + Send>>
						+ Send + Sync
					>;

					// Build spawn function map - each closure captures its own Arc clones
					let spawn_fns: ::std::collections::HashMap<&'static [u8], SpawnFn> = {
						let mut map: ::std::collections::HashMap<&'static [u8], SpawnFn> = ::std::collections::HashMap::new();
						let util_map_for_spawn = ::std::sync::Arc::clone(&self.utilization_map);

						$(
							{
								let trace_for_spawn = ::std::sync::Arc::clone(&trace);
								let servlets_for_spawn = ::std::sync::Arc::clone(&servlets);
								let util_map_inner = ::std::sync::Arc::clone(&util_map_for_spawn);
								map.insert(
									stringify!($servlet_id).as_bytes(),
									::std::sync::Arc::new(move || -> ::core::pin::Pin<::std::boxed::Box<dyn ::core::future::Future<Output = ()> + Send>> {
										let trace_inner = ::std::sync::Arc::clone(&trace_for_spawn);
										let servlets_inner = ::std::sync::Arc::clone(&servlets_for_spawn);
										let util_map_spawn = ::std::sync::Arc::clone(&util_map_inner);
										::std::boxed::Box::pin(async move {
											if let Ok(servlet) = <$servlet_name as $crate::colony::Servlet<$input>>::start(
												trace_inner,
												None,
											).await {
												let servlet_addr = servlet.addr();
												let addr_str: Vec<u8> = servlet_addr.into();
												let mut key: Vec<u8> = Vec::new();

												key.extend_from_slice(stringify!($servlet_id).as_bytes());
												key.push(b'_');
												key.extend_from_slice(&addr_str);

												// Initialize utilization_map entry for new servlet
												if let Ok(mut util_guard) = util_map_spawn.lock() {
													util_guard.insert(key.clone(), 0);
												}

												if let Ok(mut guard) = servlets_inner.lock() {
													guard.insert(key, [<$drone_name Servlet>]::[<$servlet_id:camel>](servlet));
												}
											}
										})
									})
								);
							}
						)*
						map
					};

					let scaling_handle = $crate::colony::servlet_runtime::rt::spawn(async move {
						loop {
							// Sleep for cooldown period
							#[cfg(feature = "tokio")]
							tokio::time::sleep(config.cooldown).await;
							#[cfg(all(not(feature = "tokio"), feature = "std"))]
							std::thread::sleep(config.cooldown);

							// Evaluate scaling for each servlet type
							for servlet_type in &servlet_types {
								let scale_conf = config.servlet_overrides
									.get(*servlet_type)
									.cloned()
									.unwrap_or_else(|| config.default_scale.clone());

								// Count instances and collect utilization from each servlet
								let (current_instances, type_utilization_sum) = {
									let servlets_guard = match servlets.lock() {
										Ok(g) => g,
										Err(_) => continue,
									};

									let mut count = 0usize;
									let mut util_sum = 0u32;

									for (key, servlet) in servlets_guard.iter() {
										if !key.starts_with(*servlet_type) {
											continue;
										}
										count += 1;

										// Get utilization from servlet (if it reports one)
										let util_bps: u16 = match servlet {
											$(
												[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => {
													s.utilization()
														.map(|bp| bp.get())
														.unwrap_or(5000) // Default 50% if not reported
												}
											)*
										};

										util_sum += util_bps as u32;

										// Update per-instance utilization map
										if let Ok(mut util_map) = utilization_map_for_scaling.lock() {
											util_map.insert(key.clone(), util_bps);
										}
									}

									(count, util_sum)
								};

								// Calculate average utilization for this servlet type
								let utilization_bps = if current_instances == 0 {
									$crate::utils::BasisPoints::MAX
								} else {
									let avg = (type_utilization_sum / current_instances as u32) as u16;
									$crate::utils::BasisPoints::new_saturating(avg)
								};

								// Update the shared aggregate utilization atomic for backpressure signaling
								utilization_for_scaling.store(
									utilization_bps.get(),
									::core::sync::atomic::Ordering::Relaxed
								);

								let metrics = $crate::colony::ScalingMetrics {
									servlet_type: servlet_type.to_vec(),
									utilization: utilization_bps,
									current_instances,
									config: scale_conf,
								};

								let decision = $crate::colony::ScalingDecision::evaluate(&metrics);
								match decision {
									$crate::colony::ScalingDecision::ScaleUp => {
										// Look up and call the spawn function for this servlet type
										if let Some(spawn_fn) = spawn_fns.get(*servlet_type) {
											spawn_fn().await;
										}
									}
									$crate::colony::ScalingDecision::ScaleDown => {
										// Stop the most recently added servlet of this type
										if let Ok(mut guard) = servlets.lock() {
											let key_to_remove: Option<Vec<u8>> = guard.keys()
												.filter(|k| k.starts_with(*servlet_type))
												.last()
												.cloned();
											if let Some(key) = key_to_remove {
												if let Some(servlet) = guard.remove(&key) {
													// Remove from utilization_map
													if let Ok(mut util_guard) = utilization_map_for_scaling.lock() {
														util_guard.remove(&key);
													}
													stop_servlet(servlet);
												}
											}
										}
									}

									$crate::colony::ScalingDecision::Hold => {}
								}
							}
						}
					});

					self.scaling_handle = Some(scaling_handle);
					Ok(())
				}

				async fn servlet_addresses(&self) -> Vec<(Vec<u8>, <$protocol as $crate::transport::Protocol>::Address)> {
					self.servlets.lock()
						.map(|servlets| {
							// Collect addresses of all active servlets
							let mut addresses = Vec::new();
							for (name, servlet) in servlets.iter() {
								let addr = match servlet {
									$(
										[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.addr(),
									)*
								};

								addresses.push((name.clone(), addr));
							}

							addresses
						})
						.unwrap_or_else(|_| Vec::new())
				}

				async fn drain(&self) -> Result<(), $crate::colony::DroneError> {
					// Set draining state
					{
						let mut guard = self.draining_since.write()
							.map_err(|_| $crate::TightBeamError::LockPoisoned)?;
						*guard = Some(::std::time::Instant::now());
					}

					let drain_timeout = self.config.drain_timeout;
					let start = ::std::time::Instant::now();

					// Poll until all servlets stopped or timeout
					loop {
						let active_count = self.servlets.lock()
							.map(|s| s.len())
							.unwrap_or(0);

						if active_count == 0 {
							break;
						}

						if start.elapsed() >= drain_timeout {
							// Force stop remaining servlets
							if let Ok(mut guard) = self.servlets.lock() {
								let keys: Vec<_> = guard.keys().cloned().collect();
								for key in keys {
									if let Some(servlet) = guard.remove(&key) {
										match servlet {
											$(
												[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.stop(),
											)*
										}
									}
								}
							}
							break;
						}

						#[cfg(feature = "tokio")]
						tokio::time::sleep(::std::time::Duration::from_millis(100)).await;
						#[cfg(all(not(feature = "tokio"), feature = "std"))]
						std::thread::sleep(::std::time::Duration::from_millis(100));
					}

					Ok(())
				}

				fn is_draining(&self) -> bool {
					self.draining_since.read()
						.map(|g| g.is_some())
						.unwrap_or(false)
				}
			}
		}
	};

	// Implement Drop for hive
	(@impl_drop_for_hive $drone_name:ident) => {
		impl Drop for $drone_name {
			fn drop(&mut self) {
				// Stop the scaling task
				if let Some(handle) = self.scaling_handle.take() {
					$crate::colony::servlet_runtime::rt::abort(handle);
				}
				// Stop the control server
				if let Some(handle) = self.control_server_handle.take() {
					$crate::colony::servlet_runtime::rt::abort(handle);
				}
			}
		}
	};

	// Implement Drop trait
	(@impl_drop $drone_name:ident) => {
		impl Drop for $drone_name {
			fn drop(&mut self) {
				if let Some(handle) = self.control_server_handle.take() {
					$crate::colony::servlet_runtime::rt::abort(handle);
				}
			}
		}
	};

	// Helper to build control server with policies
	(
		@build_control_server $protocol:path,
		$listener:ident,
		[$($policy_key:ident: $policy_val:tt),+],
		$active_servlet:ident,
		$trace:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			$crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),+ },
				handle: move |frame: $crate::Frame| {
					let active_servlet = std::sync::Arc::clone(&$active_servlet);
					let trace = ::std::sync::Arc::clone(&$trace);
					async move {
						drone!(
							@handle_activation_request frame,
							active_servlet,
							trace,
							$drone_name, $($servlet_id: $servlet_name<$input>),*
						)
					}
				}
			}
		}
	};

	// Helper to build control server without policies
	(
		@build_control_server $protocol:path,
		$listener:ident,
		[],
		$active_servlet:ident,
		$trace:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			$crate::server! {
				protocol $protocol: $listener,
				handle: move |frame: $crate::Frame| {
					let active_servlet = ::std::sync::Arc::clone(&$active_servlet);
					let trace = ::std::sync::Arc::clone(&$trace);
					async move {
						drone!(
							@handle_activation_request frame,
							$active_servlet,
							trace,
							$drone_name,
							$($servlet_id: $servlet_name<$input>),*
						)
					}
				}
			}
		}
	};

	// Helper to build hive control server with policies
	(
		@build_hive_control_server $protocol:path,
		$listener:ident,
		[$($policy_key:ident: $policy_val:tt),+],
		$servlets:ident,
		$trace:ident,
		$utilization:ident,
		$utilization_map:ident,
		$cb_threshold:ident,
		$cb_cooldown_ms:ident,
		$trusted_keys:ident,
		$servlet_pool:ident,
		$draining_since:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {{
		let circuit_breaker = ::std::sync::Arc::new(
			$crate::colony::ClusterCircuitBreaker::new($cb_threshold, $cb_cooldown_ms)
		);
		let trusted_keys = ::std::sync::Arc::new($trusted_keys);

		paste::paste! {
			$crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),+ },
				handle: move |frame: $crate::Frame| {
					let servlets = ::std::sync::Arc::clone(&$servlets);
					let trace = ::std::sync::Arc::clone(&$trace);
					let utilization = ::std::sync::Arc::clone(&$utilization);
					let utilization_map = ::std::sync::Arc::clone(&$utilization_map);
					let circuit_breaker = ::std::sync::Arc::clone(&circuit_breaker);
					let trusted_keys = ::std::sync::Arc::clone(&trusted_keys);
					let servlet_pool = ::std::sync::Arc::clone(&$servlet_pool);
					let draining_since = ::std::sync::Arc::clone(&$draining_since);
					async move {
						drone!(
							@handle_cluster_command $protocol,
							frame,
							servlets,
							trace,
							utilization,
							utilization_map,
							circuit_breaker,
							trusted_keys,
							servlet_pool,
							draining_since,
							$drone_name,
							$($servlet_id: $servlet_name<$input>),*
						)
					}
				}
			}
		}
	}};

	// Helper to build hive control server without policies
	(
		@build_hive_control_server $protocol:path,
		$listener:ident,
		[],
		$servlets:ident,
		$trace:ident,
		$utilization:ident,
		$utilization_map:ident,
		$cb_threshold:ident,
		$cb_cooldown_ms:ident,
		$trusted_keys:ident,
		$servlet_pool:ident,
		$draining_since:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {{
		let circuit_breaker = ::std::sync::Arc::new(
			$crate::colony::ClusterCircuitBreaker::new($cb_threshold, $cb_cooldown_ms)
		);
		let trusted_keys = ::std::sync::Arc::new($trusted_keys);

		paste::paste! {
			$crate::server! {
				protocol $protocol: $listener,
				handle: move |frame: $crate::Frame| {
					let servlets = ::std::sync::Arc::clone(&$servlets);
					let trace = ::std::sync::Arc::clone(&$trace);
					let utilization = ::std::sync::Arc::clone(&$utilization);
					let utilization_map = ::std::sync::Arc::clone(&$utilization_map);
					let circuit_breaker = ::std::sync::Arc::clone(&circuit_breaker);
					let trusted_keys = ::std::sync::Arc::clone(&trusted_keys);
					let servlet_pool = ::std::sync::Arc::clone(&$servlet_pool);
					let draining_since = ::std::sync::Arc::clone(&$draining_since);
					async move {
						drone!(
							@handle_cluster_command $protocol,
							frame,
							servlets,
							trace,
							utilization,
							utilization_map,
							circuit_breaker,
							trusted_keys,
							servlet_pool,
							draining_since,
							$drone_name,
							$($servlet_id: $servlet_name<$input>),*
						)
					}
				}
			}
		}
	}};

	// ==========================================================================
	// Response Composition Helpers
	// ==========================================================================

	// Helper: compose a response frame with message
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

	// Helper: compose a response frame with message and priority
	(@reply_priority $frame:ident, $priority:expr, $message:expr) => {{
		use $crate::builder::TypeBuilder;
		Ok(Some(
			$crate::utils::compose($crate::Version::V0)
				.with_id($frame.metadata.id.clone())
				.with_order(0)
				.with_priority($priority)
				.with_message($message)
				.build()?
		))
	}};

	// Helper to handle activation requests and route messages to active servlet
	(
		@handle_activation_request $frame:ident,
		$active_servlet:ident,
		$trace:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			{
				// Define a helper function to stop old servlets
				// This must be defined outside the repetition so we can
				// generate all match arms
				let stop_old_servlet = |old: [<$drone_name ActiveServlet>]| {
					match old {
						[<$drone_name ActiveServlet>]::None => {},
						$(
							[<$drone_name ActiveServlet>]::[<$servlet_id:camel>](s) => {
								s.stop();
							}
						)*
					}
				};

				// First, try to decode as an activation request
				if let Ok(request) = $crate::decode::<$crate::colony::ActivateServletRequest>(&$frame.message) {
					// Match servlet_id and activate the corresponding servlet
					$(
						if request.servlet_id == stringify!($servlet_id).as_bytes() {
							// Start the servlet with correct generic parameter
							paste::paste! {
								drone!(
									@start_servlet_with_response $servlet_name<$input>,
									$drone_name,
									$servlet_id,
									stringify!($servlet_id),
									request.servlet_id.clone(),
									$active_servlet,
									$trace,
									stop_old_servlet,
									$frame
								);
							}
						}
					)*

					// Unknown servlet ID - return error
					return drone!(@reply $frame,
						$crate::colony::ActivateServletResponse::err($crate::policy::TransitStatus::Forbidden)
					);
				}

				Ok(None)
			}
		}
	};

	// Helper to handle cluster commands for hives (with gate checks)
	(
		@handle_cluster_command $protocol:path,
		$frame:ident,
		$servlets:ident,
		$trace:ident,
		$utilization:ident,
		$utilization_map:ident,
		$circuit_breaker:ident,
		$trusted_keys:ident,
		$servlet_pool:ident,
		$draining_since:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			{
				use ::core::sync::atomic::Ordering;
				use $crate::transport::Protocol;

				let active_count = || -> u32 {
					$servlets.lock().map(|s| s.len() as u32).unwrap_or(0)
				};

				let current_util = || -> $crate::utils::BasisPoints {
					$crate::utils::BasisPoints::new_saturating($utilization.load(Ordering::Relaxed))
				};

				// 0. Check drain state - reject non-heartbeat requests when draining
				let is_draining = $draining_since.read().map(|g| g.is_some()).unwrap_or(false);
				let is_heartbeat = $crate::decode::<$crate::colony::ClusterCommand>(&$frame.message)
					.map(|cmd| cmd.heartbeat.is_some())
					.unwrap_or(false);

				if is_draining && !is_heartbeat {
					return drone!(@reply $frame, $crate::colony::ClusterCommandResponse::heartbeat(
						$crate::policy::TransitStatus::Busy, current_util(), active_count()
					));
				}

				// 1. Apply ClusterSecurityGate with trusted keys from HiveConf
				let parsed_keys: Vec<$crate::crypto::sign::ecdsa::Secp256k1VerifyingKey> = $trusted_keys
					.iter()
					.filter_map(|der_bytes| {
						$crate::crypto::sign::ecdsa::Secp256k1VerifyingKey::from_sec1_bytes(der_bytes).ok()
					})
					.collect();
				let security_gate = match $crate::colony::ClusterSecurityGate::<
					$crate::crypto::sign::ecdsa::Secp256k1Signature,
					$crate::crypto::sign::ecdsa::Secp256k1VerifyingKey,
				>::new(
					::std::sync::Arc::clone(&$circuit_breaker),
					parsed_keys,
				) {
					Ok(gate) => gate,
					Err(_) => {
						// No trusted keys configured - reject all cluster commands
						return drone!(@reply $frame, $crate::colony::ClusterCommandResponse::manage(
							$crate::colony::HiveManagementResponse::stop_err($crate::policy::TransitStatus::Forbidden)
						));
					}
				};
				let security_status = $crate::policy::GatePolicy::evaluate(&security_gate, &$frame);
				if security_status != $crate::policy::TransitStatus::Accepted {
					return drone!(@reply $frame, $crate::colony::ClusterCommandResponse::manage(
						$crate::colony::HiveManagementResponse::stop_err(security_status)
					));
				}

				// 2. Apply BackpressureGate (heartbeat priority frames exempt)
				let backpressure_gate = $crate::colony::BackpressureGate::new(
					::std::sync::Arc::clone(&$utilization),
					$crate::utils::BasisPoints::new(9000)
				);
				let bp_status = $crate::policy::GatePolicy::evaluate(&backpressure_gate, &$frame);
				if bp_status == $crate::policy::TransitStatus::Busy {
					return drone!(@reply $frame, $crate::colony::ClusterCommandResponse::heartbeat(
						$crate::policy::TransitStatus::Busy,
						current_util(),
						active_count(),
					));
				}

				// 3. Try ClusterCommand (the protocol envelope)
				if let Ok(cmd) = $crate::decode::<$crate::colony::ClusterCommand>(&$frame.message) {
					if cmd.heartbeat.is_some() {
						let util_bps = current_util();
						let status = if util_bps.get() >= 9000 {
							$crate::policy::TransitStatus::Busy
						} else {
							$crate::policy::TransitStatus::Accepted
						};

						return drone!(@reply_priority $frame, $crate::MessagePriority::Heartbeat,
							$crate::colony::ClusterCommandResponse::heartbeat(status, util_bps, active_count())
						);
					}

					if let Some(manage_request) = cmd.manage {
						return drone!(
							@handle_management_request $frame,
							manage_request,
							$servlets,
							$trace,
							$drone_name,
							$($servlet_id: $servlet_name<$input>),*
						);
					}
				}

				// 4. Work routing: match message to servlet type and forward via pooled connection
				let mut matched_type: Option<&'static [u8]> = None;
				$(
					if matched_type.is_none() && $crate::decode::<$input>(&$frame.message).is_ok() {
						matched_type = Some(stringify!($servlet_id).as_bytes());
					}
				)*

				if let Some(type_prefix) = matched_type {
					let instances: Vec<$crate::colony::InstanceMetrics> = {
						let servlets_guard = $servlets.lock()?;
						let util_guard = $utilization_map.lock()?;

						servlets_guard.keys()
							.filter(|k| k.starts_with(type_prefix))
							.map(|k| {
								let utilization_bps = util_guard.get(k).copied().unwrap_or(0);
								$crate::colony::InstanceMetrics {
									servlet_id: k.clone(),
									utilization: $crate::utils::BasisPoints::new_saturating(utilization_bps),
									active_requests: 0,
								}
							})
							.collect()
					};

					let load_balancer = $crate::colony::LeastLoaded;
					if let Some(idx) = $crate::colony::LoadBalancer::select(&load_balancer, &instances) {
						let target = &instances[idx];

						let addr_bytes = &target.servlet_id[type_prefix.len() + 1..];
						let addr_str = ::std::string::String::from_utf8(addr_bytes.to_vec())?;
						let addr: <$protocol as Protocol>::Address = addr_str.parse()?;

						let mut pooled_client = $servlet_pool.connect(addr).await?;
						return Ok(pooled_client.conn()?.emit($frame.clone(), None).await?);
					}
				}

				Ok(None)
			}
		}
	};

	// Helper to handle management request (extracted for reuse)
	// Now wraps responses in ClusterCommandResponse
	(
		@handle_management_request $frame:ident,
		$request:ident,
		$servlets:ident,
		$trace:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			{
				// Handle spawn request
				if let Some(spawn_params) = $request.spawn {
					let servlet_type_name = spawn_params.servlet_type;

					// Try to spawn the requested servlet type
					$(
						if servlet_type_name == stringify!($servlet_id).as_bytes() {
							drone!(
								@start_servlet_for_hive_cmd $servlet_name<$input>,
								$drone_name,
								$servlet_id,
								stringify!($servlet_id),
								servlet_type_name,
								$servlets,
								$trace,
								$frame
							);
						}
					)*

					// Unknown servlet type
					return drone!(@reply $frame, $crate::colony::ClusterCommandResponse::manage(
						$crate::colony::HiveManagementResponse::spawn_err($crate::policy::TransitStatus::Forbidden)
					));
				}

				// Handle list request
				if $request.list.is_some() {
					let servlets = $servlets.lock()?;
					let servlet_list: Vec<_> = servlets.iter().map(|(id, servlet)| {
						let addr = match servlet {
							$(
								[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.addr(),
							)*
						};
						$crate::colony::ServletInfo {
							servlet_id: id.clone(),
							address: addr.into(),
						}
					}).collect();
					drop(servlets);

					return drone!(@reply $frame, $crate::colony::ClusterCommandResponse::manage(
						$crate::colony::HiveManagementResponse::list_ok(servlet_list)
					));
				}

				// Handle stop request
				if let Some(stop_params) = $request.stop {
					let mut servlets = $servlets.lock()?;
					if let Some(servlet) = servlets.remove(&stop_params.servlet_id) {
						drop(servlets);
						// Stop the servlet
						match servlet {
							$(
								[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.stop(),
							)*
						}
						return drone!(@reply $frame, $crate::colony::ClusterCommandResponse::manage(
							$crate::colony::HiveManagementResponse::stop_ok()
						));
					} else {
						drop(servlets);
						return drone!(@reply $frame, $crate::colony::ClusterCommandResponse::manage(
							$crate::colony::HiveManagementResponse::stop_err($crate::policy::TransitStatus::Forbidden)
						));
					}
				}

				// No recognized request type
				Ok(None)
			}
		}
	};

	// Legacy helper to handle management commands for hives (kept for reference)
	(
		@handle_hive_management $frame:ident,
		$servlets:ident,
		$trace:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			{
				// Decode the management request
				if let Ok(request) = $crate::decode::<$crate::colony::HiveManagementRequest>(&$frame.message) {
					// Handle spawn request
					if let Some(spawn_params) = request.spawn {
						let servlet_type_name = spawn_params.servlet_type;

						// Try to spawn the requested servlet type
						$(
							if servlet_type_name == stringify!($servlet_id).as_bytes() {
								drone!(
									@start_servlet_for_hive $servlet_name<$input>,
									$drone_name,
									$servlet_id,
									stringify!($servlet_id),
									servlet_type_name,
									$servlets,
									$trace,
									$frame
								);
							}
						)*

						// Unknown servlet type
						return drone!(@reply $frame,
							$crate::colony::HiveManagementResponse::spawn_err($crate::policy::TransitStatus::Forbidden)
						);
					}

					// Handle list request
					if request.list.is_some() {
						let servlets = $servlets.lock()?;
						let servlet_list: Vec<_> = servlets.iter().map(|(id, servlet)| {
							let addr = match servlet {
								$(
									[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.addr(),
								)*
							};
							$crate::colony::ServletInfo {
								servlet_id: id.clone(),
								address: addr.into(),
							}
						}).collect();
						drop(servlets);

						return drone!(@reply $frame, $crate::colony::HiveManagementResponse::list_ok(servlet_list));
					}

					// Handle stop request
					if let Some(stop_params) = request.stop {
						let mut servlets = $servlets.lock()?;
						if let Some(servlet) = servlets.remove(&stop_params.servlet_id) {
							drop(servlets);
							// Stop the servlet
							match servlet {
								$(
									[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.stop(),
								)*
							}
							return drone!(@reply $frame, $crate::colony::HiveManagementResponse::stop_ok());
						} else {
							drop(servlets);
							return drone!(@reply $frame,
								$crate::colony::HiveManagementResponse::stop_err($crate::policy::TransitStatus::Forbidden)
							);
						}
					}
				}

				// Unknown message type
				Ok(None)
			}
		}
	};
}

#[cfg(test)]
mod tests {
	use super::*;

	use core::sync::atomic::AtomicU16;
	use std::sync::Arc;

	use crate::asn1::Metadata;
	use crate::colony::drone::Hive;
	use crate::colony::servlet::{LatencyTracker, Servlet};
	use crate::crypto::profiles::{DefaultCryptoProvider, DigestProvider, SigningProvider};
	use crate::der::Sequence;
	use crate::policy::{GatePolicy, TransitStatus};
	use crate::trace::TraceCollector;
	use crate::transport::policy::PolicyConf;
	use crate::transport::tcp::r#async::TokioListener;
	use crate::transport::{MessageEmitter, Protocol};
	use crate::{compose, job, mutex, policy, servlet, worker};
	use crate::{Beamable, Frame};

	// Type aliases from DefaultCryptoProvider - allows algorithm agility
	type TestProvider = DefaultCryptoProvider;
	type TestSignature = <TestProvider as SigningProvider>::Signature;
	type TestSigningKey = <TestProvider as SigningProvider>::SigningKey;
	type TestVerifyingKey = <TestProvider as SigningProvider>::VerifyingKey;
	type TestDigest = <TestProvider as DigestProvider>::Digest;

	#[cfg(feature = "tokio")]
	type Listener = crate::transport::tcp::r#async::TokioListener;
	#[cfg(all(not(feature = "tokio"), feature = "std"))]
	type Listener = crate::transport::tcp::sync::TcpListener<std::net::TcpListener>;

	// Jobs for hive management operations - all implement Job trait
	// ClusterCommand requires nonrepudiation and frame integrity
	// Types pulled from TestProvider for algorithm agility

	job! {
		name: ListServletsJob,
		fn run((id, signing_key): (Vec<u8>, TestSigningKey)) -> crate::error::Result<Frame> {
			compose! {
				V1: id: id,
					order: 0u64,
					message: ClusterCommand {
						heartbeat: None,
						manage: Some(HiveManagementRequest {
							spawn: None,
							list: Some(ListServletsParams { filter: None }),
							stop: None,
						}),
					},
					nonrepudiation<TestSignature, _>: signing_key,
					frame_integrity: type TestDigest
			}
		}
	}

	job! {
		name: SpawnServletJob,
		fn run((id, servlet_type, config, signing_key): (Vec<u8>, Vec<u8>, Option<Vec<u8>>, TestSigningKey)) -> crate::error::Result<Frame> {
			compose! {
				V1: id: id,
					order: 0u64,
					message: ClusterCommand {
						heartbeat: None,
						manage: Some(HiveManagementRequest {
							spawn: Some(SpawnServletParams { servlet_type, config }),
							list: None,
							stop: None,
						}),
					},
					nonrepudiation<TestSignature, _>: signing_key,
					frame_integrity: type TestDigest
			}
		}
	}

	job! {
		name: StopServletJob,
		fn run((id, servlet_id, signing_key): (Vec<u8>, Vec<u8>, TestSigningKey)) -> crate::error::Result<Frame> {
			compose! {
				V1: id: id,
					order: 0u64,
					message: ClusterCommand {
						heartbeat: None,
						manage: Some(HiveManagementRequest {
							spawn: None,
							list: None,
							stop: Some(StopServletParams { servlet_id }),
						}),
					},
					nonrepudiation<TestSignature, _>: signing_key,
					frame_integrity: type TestDigest
			}
		}
	}

	job! {
		name: HeartbeatJob,
		fn run((id, cluster_status, signing_key): (Vec<u8>, ClusterStatus, TestSigningKey)) -> crate::error::Result<Frame> {
			compose! {
				V1: id: id,
					order: 0u64,
					priority: crate::MessagePriority::Heartbeat,
					message: ClusterCommand {
						heartbeat: Some(HeartbeatParams { cluster_status }),
						manage: None,
					},
					nonrepudiation<TestSignature, _>: signing_key,
					frame_integrity: type TestDigest
			}
		}
	}

	job! {
		name: ActivateServletJob,
		fn run((id, servlet_id, config, signing_key): (Vec<u8>, Vec<u8>, Option<Vec<u8>>, TestSigningKey)) -> crate::error::Result<Frame> {
			compose! {
				V0: id: id,
					message: ActivateServletRequest { servlet_id, config },
					nonrepudiation<TestSignature, _>: signing_key
			}
		}
	}

	// Jobs for servlet responses
	job! {
		name: DroneResponseJob,
		fn run((id, result): (Vec<u8>, String)) -> crate::error::Result<Frame> {
			compose! {
				V0: id: id,
					message: DroneResponseMessage { result }
			}
		}
	}

	job! {
		name: DroneResponseWithOrderJob,
		fn run((id, order, message): (Vec<u8>, u64, DroneResponseMessage)) -> crate::error::Result<Frame> {
			compose! {
				V0: id: id,
					order: order,
					message: message
			}
		}
	}

	mutex! { SIGNING_KEY: TestSigningKey = crate::testing::create_test_signing_key() }

	// Helper to safely get signing key for gate policy initialization
	fn get_signing_key_for_gate() -> TestVerifyingKey {
		SIGNING_KEY()
			.lock()
			.map(|guard| *guard.verifying_key())
			.unwrap_or_else(|_| *crate::testing::create_test_signing_key().verifying_key())
	}

	// Test message types
	#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
	pub struct DroneTestMessage {
		content: String,
		value: u32,
	}

	#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
	pub struct DroneResponseMessage {
		result: String,
	}

	// Firewall signature gate that verifies cryptographic signatures on activation requests
	// Uses provider-based types for algorithm agility
	struct SignatureGate {
		verifying_key: TestVerifyingKey,
	}

	impl SignatureGate {
		fn new(verifying_key: TestVerifyingKey) -> Self {
			Self { verifying_key }
		}
	}

	impl GatePolicy for SignatureGate {
		fn evaluate(&self, frame: &Frame) -> TransitStatus {
			// Check if the frame has a nonrepudiation signature
			if frame.nonrepudiation.is_some() {
				// Verify the signature using the built-in verify method
				// Uses TestSignature from provider for algorithm agility
				if frame.verify::<TestSignature>(&self.verifying_key).is_ok() {
					TransitStatus::Accepted
				} else {
					TransitStatus::Forbidden
				}
			} else {
				TransitStatus::Unauthorized
			}
		}
	}

	policy! {
		ReceptorPolicy<DroneTestMessage>: TestGate |msg| {
			if msg.value > 0 {
				TransitStatus::Accepted
			} else {
				TransitStatus::Forbidden
			}
		}
	}

	// Create test workers
	worker! {
		name: ValueCheckerWorker<DroneTestMessage, bool>,
		config: {
			threshold: u32,
		},
		handle: |message, _trace, config| async move {
			message.value >= config.threshold
		}
	}

	worker! {
		name: EchoWorker<DroneTestMessage, DroneResponseMessage>,
		policies: {
			with_receptor_gate: [TestGate]
		},
		handle: |message, _trace| async move {
			DroneResponseMessage {
				result: message.content.clone(),
			}
		}
	}

	// Config structs for servlets
	#[derive(Clone)]
	pub struct ConfigurableServletConf {
		pub threshold: u32,
	}

	// Create test servlets
	servlet! {
		pub SimpleServlet<DroneTestMessage, EnvConfig = ()>,
		protocol: Listener,
		handle: |message, _trace, _config, _workers| async move {
			let decoded: DroneTestMessage = crate::decode(&message.message)?;
			if decoded.content == "PING" {
				Ok(Some(DroneResponseJob::run((message.metadata.id.clone(), "PONG".to_string()))?))
			} else {
				Ok(None)
			}
		}
	}

	servlet! {
		pub ConfigurableServlet<DroneTestMessage, EnvConfig = ConfigurableServletConf>,
		protocol: Listener,
		handle: |message, _trace, config, _workers| async move {
			let decoded: DroneTestMessage = crate::decode(&message.message)?;
			if decoded.value >= config.threshold {
				Ok(Some(DroneResponseJob::run((message.metadata.id.clone(), "ACCEPTED".to_string()))?))
			} else {
				Ok(None)
			}
		}
	}

	servlet! {
		pub WorkerServlet<DroneTestMessage, EnvConfig = ()>,
		protocol: Listener,
		handle: |message, _trace, _config, workers| async move {
			let decoded: DroneTestMessage = crate::decode(&message.message)?;
			let decoded_arc = ::std::sync::Arc::new(decoded);
			let (echo_result, check_result) = tokio::join!(
				workers.relay::<EchoWorker>(::std::sync::Arc::clone(&decoded_arc)),
				workers.relay::<ValueCheckerWorker>(::std::sync::Arc::clone(&decoded_arc))
			);

			let echo_msg = match echo_result {
				Ok(msg) => msg,
				Err(_) => return Ok(None),
			};

			let is_valid = match check_result {
				Ok(valid) => valid,
				Err(_) => return Ok(None),
			};

			Ok(if is_valid {
				DroneResponseWithOrderJob::run((
					message.metadata.id.clone(),
					1_700_000_000u64,
					echo_msg
				)).ok()
			} else {
				None
			})
		}
	}

	// Regular drone with multiple servlets
	drone! {
		RegularDrone,
		protocol: Listener,
		policies: {
			with_collector_gate: [SignatureGate::new(get_signing_key_for_gate())]
		},
		servlets: {
			simple_servlet: SimpleServlet<DroneTestMessage>,
			configurable_servlet: ConfigurableServlet<DroneTestMessage>,
			worker_servlet: WorkerServlet<DroneTestMessage>
		}
	}

	crate::test_drone! {
		name: test_mycelial_drone_with_collector_gate,
		protocol: Listener,
		drone: RegularDrone,
		config: None,
		setup: |drone| async {
			// No additional setup needed
			drone
		},
		assertions: |client, _channels| async move {

			// Step 1: Send a signed activation request to morph the drone into simple_servlet
			let signing_key = SIGNING_KEY().lock().map_err(|_| "Lock error")?.clone();
			let signed_frame = ActivateServletJob::run((
				b"cluster-activation-001".to_vec(),
				b"simple_servlet".to_vec(),
				None,
				signing_key.clone()
			))?;

			// Send activation request to drone's control server
			let response = client.emit(signed_frame, None).await?
				.ok_or("No response received from drone")?;

			// Decode the activation response
			let activation_response: ActivateServletResponse = crate::decode(&response.message)?;
			assert_eq!(activation_response.status, TransitStatus::Accepted, "Servlet activation should succeed");

			// Step 2: Test morphing back to simple_servlet (verify we can morph multiple times)
			let signed_simple_again_frame = ActivateServletJob::run((
				b"cluster-activation-002".to_vec(),
				b"simple_servlet".to_vec(),
				None,
				signing_key.clone()
			))?;

			let simple_again_response = client.emit(signed_simple_again_frame, None).await?
				.ok_or("No response from drone for second simple activation")?;

			let simple_again_activation: ActivateServletResponse = crate::decode(&simple_again_response.message)?;
			assert_eq!(simple_again_activation.status, TransitStatus::Accepted, "Second simple servlet activation should succeed");

			// Step 3: Test invalid servlet ID
			let signed_invalid_frame = ActivateServletJob::run((
				b"cluster-activation-003".to_vec(),
				b"nonexistent_servlet".to_vec(),
				None,
				signing_key
			))?;

			let invalid_response = client.emit(signed_invalid_frame, None).await?
				.ok_or("No response from drone for invalid activation")?;

			let invalid_activation: ActivateServletResponse = crate::decode(&invalid_response.message)?;
			assert_eq!(invalid_activation.status, TransitStatus::Forbidden, "Invalid servlet activation should be rejected");

			Ok(())
		}
	}

	// Test hive with mycelial port allocation using TokioListener
	#[cfg(feature = "tokio")]
	drone! {
		TestHive,
		protocol: crate::transport::tcp::r#async::TokioListener,
		hive: true,
		servlets: {
			simple_servlet: SimpleServlet<DroneTestMessage>,
			echo_servlet: EchoServlet<DroneTestMessage>
		}
	}

	#[cfg(feature = "tokio")]
	servlet! {
		EchoServlet<DroneTestMessage, EnvConfig = ()>,
		protocol: crate::transport::tcp::r#async::TokioListener,
		handle: |message, _trace, _config, _workers| async move {
			let decoded: DroneTestMessage = crate::decode(&message.message)?;
			Ok(Some(DroneResponseJob::run((
				message.metadata.id.clone(),
				format!("ECHO: {}", decoded.content)
			))?))
		}
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_hive_mycelial_port_allocation() -> Result<(), Box<dyn std::error::Error>> {
		let mut hive = TestHive::start(Arc::new(TraceCollector::new()), None).await?;
		let control_addr = hive.addr();

		hive.establish_hive().await?;

		let servlet_addrs: Vec<(Vec<u8>, crate::prelude::TightBeamSocketAddr)> = hive.servlet_addresses().await;

		assert_eq!(servlet_addrs.len(), 2, "Should have 2 servlets");

		let (_, servlet1_addr) = &servlet_addrs[0];
		let (_, servlet2_addr) = &servlet_addrs[1];

		// Verify addresses are all different (mycelial networking)
		assert_ne!(
			format!("{control_addr:?}"),
			format!("{:?}", servlet1_addr),
			"Servlet 1 should have a different address than control server"
		);
		assert_ne!(
			format!("{control_addr:?}"),
			format!("{:?}", servlet2_addr),
			"Servlet 2 should have a different address than control server"
		);
		assert_ne!(
			format!("{servlet1_addr:?}"),
			format!("{:?}", servlet2_addr),
			"Servlets should have different addresses from each other"
		);

		hive.stop();
		Ok(())
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_hive_management_commands() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key = SIGNING_KEY().lock().map_err(|_| "Lock error")?.clone();
		let verifying_key_bytes = signing_key.verifying_key().to_sec1_bytes().to_vec();

		// Configure hive with trusted cluster key
		let config = HiveConf {
			trusted_cluster_keys: vec![verifying_key_bytes],
			..Default::default()
		};

		let mut hive = TestHive::start(Arc::new(TraceCollector::new()), Some(config)).await?;
		let control_addr = hive.addr();

		hive.establish_hive().await?;

		let stream = TokioListener::<DefaultCryptoProvider>::connect(control_addr).await?;
		let mut transport = TokioListener::<DefaultCryptoProvider>::create_transport(stream);

		// List servlets (should have 2 default servlets)
		let list_frame = ListServletsJob::run((b"list-1".to_vec(), signing_key.clone()))?;
		let response = transport.emit(list_frame, None).await?.ok_or("No response")?;
		let cmd_response: ClusterCommandResponse = crate::decode(&response.message)?;
		let management_response = cmd_response.manage.ok_or("No manage response")?;
		let list_response = management_response.list.ok_or("No list response")?;
		assert_eq!(list_response.status, TransitStatus::Accepted);
		assert_eq!(list_response.servlets.len(), 2, "Should have 2 default servlets");

		// Spawn a new servlet instance
		let spawn_frame =
			SpawnServletJob::run((b"spawn-1".to_vec(), b"simple_servlet".to_vec(), None, signing_key.clone()))?;
		let response = transport.emit(spawn_frame, None).await?.ok_or("No response")?;
		let cmd_response: ClusterCommandResponse = crate::decode(&response.message)?;
		let management_response = cmd_response.manage.ok_or("No manage response")?;
		let spawn_response = management_response.spawn.ok_or("No spawn response")?;
		assert_eq!(spawn_response.status, TransitStatus::Accepted);
		assert!(spawn_response.servlet_address.is_some());
		assert!(spawn_response.servlet_id.is_some());

		let new_servlet_id = spawn_response.servlet_id.ok_or("No servlet_id")?;

		// List servlets again (should have 3 now)
		let list_frame = ListServletsJob::run((b"list-2".to_vec(), signing_key.clone()))?;
		let response = transport.emit(list_frame, None).await?.ok_or("No response")?;
		let cmd_response: ClusterCommandResponse = crate::decode(&response.message)?;
		let management_response = cmd_response.manage.ok_or("No manage response")?;
		let list_response = management_response.list.ok_or("No list response")?;
		assert_eq!(list_response.status, TransitStatus::Accepted);
		assert_eq!(list_response.servlets.len(), 3, "Should have 3 servlets after spawn");

		// Stop the newly spawned servlet
		let stop_frame = StopServletJob::run((b"stop-1".to_vec(), new_servlet_id.clone(), signing_key.clone()))?;
		let response = transport.emit(stop_frame, None).await?.ok_or("No response")?;
		let cmd_response: ClusterCommandResponse = crate::decode(&response.message)?;
		let management_response = cmd_response.manage.ok_or("No manage response")?;
		let stop_response = management_response.stop.ok_or("No stop response")?;
		assert_eq!(stop_response.status, TransitStatus::Accepted);

		// List servlets again (should be back to 2)
		let list_frame = ListServletsJob::run((b"list-3".to_vec(), signing_key.clone()))?;
		let response = transport.emit(list_frame, None).await?.ok_or("No response")?;
		let cmd_response: ClusterCommandResponse = crate::decode(&response.message)?;
		let management_response = cmd_response.manage.ok_or("No manage response")?;
		let list_response = management_response.list.ok_or("No list response")?;
		assert_eq!(list_response.status, TransitStatus::Accepted);
		assert_eq!(list_response.servlets.len(), 2, "Should be back to 2 servlets after stop");

		// Try to spawn unknown servlet type
		let spawn_frame =
			SpawnServletJob::run((b"spawn-2".to_vec(), b"unknown_servlet".to_vec(), None, signing_key.clone()))?;
		let response = transport.emit(spawn_frame, None).await?.ok_or("No response")?;
		let cmd_response: ClusterCommandResponse = crate::decode(&response.message)?;
		let management_response = cmd_response.manage.ok_or("No manage response")?;
		let spawn_response = management_response.spawn.ok_or("No spawn response")?;
		assert_eq!(spawn_response.status, TransitStatus::Forbidden);
		assert!(spawn_response.servlet_address.is_none());

		// Send heartbeat and verify response
		let heartbeat_frame =
			HeartbeatJob::run((b"heartbeat-1".to_vec(), ClusterStatus::Healthy, signing_key.clone()))?;
		let response = transport.emit(heartbeat_frame, None).await?.ok_or("No response")?;
		let cmd_response: ClusterCommandResponse = crate::decode(&response.message)?;
		let heartbeat_response = cmd_response.heartbeat.ok_or("No heartbeat response")?;
		assert_eq!(heartbeat_response.status, TransitStatus::Accepted);

		hive.stop();
		Ok(())
	}

	// ==========================================================================
	// Test Helpers
	// ==========================================================================

	/// Options for building test frames with configurable security attributes
	struct FrameOpts {
		with_signature: bool,
		with_integrity: bool,
		priority: Option<crate::MessagePriority>,
	}

	impl Default for FrameOpts {
		fn default() -> Self {
			Self { with_signature: true, with_integrity: true, priority: None }
		}
	}

	impl FrameOpts {
		fn unsigned() -> Self {
			Self { with_signature: false, with_integrity: false, priority: None }
		}

		fn signed_no_integrity() -> Self {
			Self { with_signature: true, with_integrity: false, priority: None }
		}

		fn with_priority(mut self, priority: crate::MessagePriority) -> Self {
			self.priority = Some(priority);
			self
		}
	}

	/// Build a test frame with configurable security options
	/// For unsigned/partial frames, constructs Frame directly to avoid compose! validation
	fn build_test_frame(opts: FrameOpts) -> crate::error::Result<Frame> {
		let message_bytes = crate::encode(&ClusterCommand {
			heartbeat: Some(HeartbeatParams { cluster_status: ClusterStatus::Healthy }),
			manage: None,
		})?;

		match (opts.with_signature, opts.with_integrity) {
			// Fully secured - use compose! for proper signature/integrity
			(true, true) => {
				let signing_key = SIGNING_KEY().lock().map_err(|_| DroneError::LockPoisoned)?.clone();
				match opts.priority {
					// Priority requires V2+ (use V2 when priority is set)
					Some(priority) => compose! {
						V2: id: b"test-frame".to_vec(),
							order: 0u64,
							priority: priority,
							message: ClusterCommand {
								heartbeat: Some(HeartbeatParams { cluster_status: ClusterStatus::Healthy }),
								manage: None,
							},
							nonrepudiation<TestSignature, _>: signing_key,
							frame_integrity: type TestDigest
					},
					None => compose! {
						V1: id: b"test-frame".to_vec(),
							order: 0u64,
							message: ClusterCommand {
								heartbeat: Some(HeartbeatParams { cluster_status: ClusterStatus::Healthy }),
								manage: None,
							},
							nonrepudiation<TestSignature, _>: signing_key,
							frame_integrity: type TestDigest
					},
				}
			}
			// Signed but no integrity - construct directly with dummy signature
			(true, false) => {
				use crate::cms::cert::IssuerAndSerialNumber;
				use crate::cms::content_info::CmsVersion;
				use crate::cms::signed_data::{SignerIdentifier, SignerInfo};
				use crate::der::asn1::OctetString;
				use crate::der::oid::db::rfc5912::ID_SHA_256;
				use crate::oids::SIGNER_ECDSA_WITH_SHA3_256;
				use crate::spki::AlgorithmIdentifier;
				use crate::x509::name::Name;
				use crate::x509::serial_number::SerialNumber;

				Ok(Frame {
					version: crate::Version::V1,
					metadata: Metadata {
						id: b"test-frame".to_vec(),
						order: 0,
						compactness: None,
						integrity: None,
						confidentiality: None,
						priority: opts.priority,
						lifetime: None,
						previous_frame: None,
						matrix: None,
					},
					message: message_bytes,
					integrity: None, // No frame integrity
					nonrepudiation: Some(SignerInfo {
						version: CmsVersion::V1,
						sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
							issuer: Name::default(),
							serial_number: SerialNumber::new(&[0; 8])?,
						}),
						digest_alg: AlgorithmIdentifier { oid: ID_SHA_256, parameters: None },
						signed_attrs: None,
						signature_algorithm: AlgorithmIdentifier { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None },
						signature: OctetString::new(vec![0; 64])?,
						unsigned_attrs: None,
					}),
				})
			}
			// Unsigned - construct directly without signature/integrity
			// Use V2 if priority is set (V2+ feature)
			(false, _) => Ok(Frame {
				version: if opts.priority.is_some() {
					crate::Version::V2
				} else {
					crate::Version::V1
				},
				metadata: Metadata {
					id: b"test-frame".to_vec(),
					order: 0,
					compactness: None,
					integrity: None,
					confidentiality: None,
					priority: opts.priority,
					lifetime: None,
					previous_frame: None,
					matrix: None,
				},
				message: message_bytes,
				integrity: None,
				nonrepudiation: None,
			}),
		}
	}

	/// Build ScalingMetrics with configurable values
	fn build_metrics(utilization_bps: u16, instances: usize, config: Option<ServletScaleConf>) -> ScalingMetrics {
		ScalingMetrics {
			servlet_type: b"test_servlet".to_vec(),
			utilization: BasisPoints::new_saturating(utilization_bps),
			current_instances: instances,
			config: config.unwrap_or_default(),
		}
	}

	// ==========================================================================
	// ClusterCircuitBreaker Unit Tests
	// ==========================================================================

	#[test]
	fn circuit_breaker_initializes_closed() {
		let breaker = ClusterCircuitBreaker::new(3, 1000);
		assert_eq!(breaker.state(), CircuitState::Closed);
		assert!(!breaker.is_open());
		assert!(breaker.allow_request());
	}

	#[test]
	fn circuit_breaker_trips_at_threshold() {
		let breaker = ClusterCircuitBreaker::new(3, 1000);

		// First two failures don't trip
		breaker.record_auth_failure();
		assert_eq!(breaker.state(), CircuitState::Closed);

		breaker.record_auth_failure();
		assert_eq!(breaker.state(), CircuitState::Closed);

		// Third failure trips the circuit
		breaker.record_auth_failure();
		assert_eq!(breaker.state(), CircuitState::Open);
		assert!(breaker.is_open());
		assert!(!breaker.allow_request());
	}

	#[test]
	fn circuit_breaker_success_resets() {
		let breaker = ClusterCircuitBreaker::new(3, 1000);

		// Accumulate some failures
		breaker.record_auth_failure();
		breaker.record_auth_failure();

		// Success resets
		breaker.record_success();
		assert_eq!(breaker.state(), CircuitState::Closed);

		// Now need 3 more failures to trip
		breaker.record_auth_failure();
		breaker.record_auth_failure();
		assert_eq!(breaker.state(), CircuitState::Closed);
	}

	#[test]
	fn circuit_breaker_reset_closes() {
		let breaker = ClusterCircuitBreaker::new(3, 1000);

		// Trip the circuit
		breaker.record_auth_failure();
		breaker.record_auth_failure();
		breaker.record_auth_failure();
		assert!(breaker.is_open());

		// Reset closes it
		breaker.reset();
		assert_eq!(breaker.state(), CircuitState::Closed);
		assert!(breaker.allow_request());
	}

	// ==========================================================================
	// ClusterSecurityGate Unit Tests
	// ==========================================================================

	/// Helper to get the test verifying key
	fn test_verifying_key() -> TestVerifyingKey {
		get_signing_key_for_gate()
	}

	/// Helper to create a security gate with the test signing key
	fn make_test_gate(
		breaker: Arc<ClusterCircuitBreaker>,
	) -> Result<ClusterSecurityGate<TestSignature, TestVerifyingKey>, DroneError> {
		ClusterSecurityGate::new(breaker, vec![test_verifying_key()])
	}

	/// Helper to create a gate with specific trusted keys for signature verification
	fn make_verifying_gate(
		breaker: Arc<ClusterCircuitBreaker>,
		keys: Vec<TestVerifyingKey>,
	) -> Result<ClusterSecurityGate<TestSignature, TestVerifyingKey>, DroneError> {
		ClusterSecurityGate::new(breaker, keys)
	}

	#[test]
	fn security_gate_rejects_when_circuit_open() -> crate::error::Result<()> {
		let breaker = Arc::new(ClusterCircuitBreaker::new(1, 1000));
		breaker.record_auth_failure(); // Trip immediately
		assert!(breaker.is_open());

		let gate = make_test_gate(Arc::clone(&breaker))?;
		let frame = build_test_frame(FrameOpts::default())?;
		assert_eq!(gate.evaluate(&frame), TransitStatus::Forbidden);
		Ok(())
	}

	#[test]
	fn security_gate_rejects_missing_signature() -> crate::error::Result<()> {
		let frame = build_test_frame(FrameOpts::unsigned())?;
		assert!(frame.nonrepudiation.is_none());

		let breaker = Arc::new(ClusterCircuitBreaker::new(3, 1000));
		let gate = make_test_gate(Arc::clone(&breaker))?;
		assert_eq!(gate.evaluate(&frame), TransitStatus::Unauthorized);
		Ok(())
	}

	#[test]
	fn security_gate_rejects_missing_integrity() -> crate::error::Result<()> {
		let frame = build_test_frame(FrameOpts::signed_no_integrity())?;
		assert!(frame.nonrepudiation.is_some());
		assert!(frame.integrity.is_none());

		let breaker = Arc::new(ClusterCircuitBreaker::new(3, 1000));
		let gate = make_test_gate(Arc::clone(&breaker))?;
		assert_eq!(gate.evaluate(&frame), TransitStatus::Unauthorized);
		Ok(())
	}

	#[test]
	fn security_gate_accepts_valid_frame() -> crate::error::Result<()> {
		let frame = build_test_frame(FrameOpts::default())?;
		assert!(frame.nonrepudiation.is_some());
		assert!(frame.integrity.is_some());

		let breaker = Arc::new(ClusterCircuitBreaker::new(3, 1000));
		let gate = make_test_gate(Arc::clone(&breaker))?;
		assert_eq!(gate.evaluate(&frame), TransitStatus::Accepted);
		Ok(())
	}

	#[test]
	fn security_gate_records_failures_on_breaker() -> crate::error::Result<()> {
		let breaker = Arc::new(ClusterCircuitBreaker::new(3, 1000));
		let gate = make_test_gate(Arc::clone(&breaker))?;

		// Send 3 unsigned frames - should trip breaker
		for _ in 0..3 {
			let frame = build_test_frame(FrameOpts::unsigned())?;
			gate.evaluate(&frame);
		}

		assert!(breaker.is_open());
		Ok(())
	}

	#[test]
	fn security_gate_verifies_signature_with_trusted_key() -> crate::error::Result<()> {
		let signing_key = SIGNING_KEY().lock().map_err(|_| DroneError::LockPoisoned)?.clone();
		let verifying_key = *signing_key.verifying_key();

		let frame = build_test_frame(FrameOpts::default())?;
		let breaker = Arc::new(ClusterCircuitBreaker::new(3, 1000));
		let gate = make_verifying_gate(Arc::clone(&breaker), vec![verifying_key])
			.map_err(|_| DroneError::LockPoisoned)?;
		assert_eq!(gate.evaluate(&frame), TransitStatus::Accepted);
		Ok(())
	}

	#[test]
	fn security_gate_rejects_invalid_signature() -> crate::error::Result<()> {
		// Create a frame signed with SIGNING_KEY
		let frame = build_test_frame(FrameOpts::default())?;

		// Create a truly different key for verification (using different seed)
		let different_secret = [42u8; 32]; // Different from testing::create_test_signing_key which uses [1u8; 32]
		let different_key = crate::crypto::sign::ecdsa::SigningKey::from_bytes(&different_secret.into())
			.map_err(|_| DroneError::LockPoisoned)?;
		let wrong_verifying_key = *different_key.verifying_key();

		let breaker = Arc::new(ClusterCircuitBreaker::new(3, 1000));
		let gate = make_verifying_gate(Arc::clone(&breaker), vec![wrong_verifying_key])
			.map_err(|_| DroneError::LockPoisoned)?;
		assert_eq!(gate.evaluate(&frame), TransitStatus::Forbidden);
		Ok(())
	}

	#[test]
	fn security_gate_rejects_empty_trusted_keys() {
		let breaker = Arc::new(ClusterCircuitBreaker::new(3, 1000));
		let result = ClusterSecurityGate::<TestSignature, TestVerifyingKey>::new(breaker, vec![]);
		assert!(matches!(result, Err(DroneError::NoTrustedKeys)));
	}

	// ==========================================================================
	// BackpressureGate Unit Tests
	// ==========================================================================

	#[test]
	fn backpressure_gate_allows_heartbeat_when_overloaded() -> crate::error::Result<()> {
		let utilization = Arc::new(AtomicU16::new(10000)); // 100%
		let gate = BackpressureGate::new(Arc::clone(&utilization), BasisPoints::new(9000));

		let frame = build_test_frame(FrameOpts::default().with_priority(crate::MessagePriority::Heartbeat))?;
		assert_eq!(gate.evaluate(&frame), TransitStatus::Accepted);
		Ok(())
	}

	#[test]
	fn backpressure_gate_returns_busy_over_threshold() -> crate::error::Result<()> {
		let utilization = Arc::new(AtomicU16::new(9500)); // 95%
		let gate = BackpressureGate::new(Arc::clone(&utilization), BasisPoints::new(9000)); // 90% threshold

		let frame = build_test_frame(FrameOpts::default())?;
		assert_eq!(gate.evaluate(&frame), TransitStatus::Busy);
		Ok(())
	}

	#[test]
	fn backpressure_gate_accepts_under_threshold() -> crate::error::Result<()> {
		let utilization = Arc::new(AtomicU16::new(5000)); // 50%
		let gate = BackpressureGate::new(Arc::clone(&utilization), BasisPoints::new(9000)); // 90% threshold

		let frame = build_test_frame(FrameOpts::default())?;
		assert_eq!(gate.evaluate(&frame), TransitStatus::Accepted);
		Ok(())
	}

	#[test]
	fn backpressure_gate_current_utilization() {
		let utilization = Arc::new(AtomicU16::new(7500));
		let gate = BackpressureGate::new(Arc::clone(&utilization), BasisPoints::new(9000));
		assert_eq!(gate.current_utilization().get(), 7500);
	}

	// ==========================================================================
	// ScalingDecision Unit Tests (Data-Driven)
	// ==========================================================================

	/// Test case for scaling decision evaluation
	struct ScalingTestCase {
		utilization_bps: u16,
		instances: usize,
		min: usize,
		max: usize,
		up_threshold: u16,
		down_threshold: u16,
		expected: ScalingDecision,
	}

	#[test]
	fn scaling_decision_evaluates_correctly() {
		let cases = [
			// Scale up: high utilization, room to grow
			ScalingTestCase {
				utilization_bps: 9000,
				instances: 5,
				min: 1,
				max: 10,
				up_threshold: 8000,
				down_threshold: 2000,
				expected: ScalingDecision::ScaleUp,
			},
			// Scale down: low utilization, above minimum
			ScalingTestCase {
				utilization_bps: 1000,
				instances: 5,
				min: 1,
				max: 10,
				up_threshold: 8000,
				down_threshold: 2000,
				expected: ScalingDecision::ScaleDown,
			},
			// Hold: utilization in normal range
			ScalingTestCase {
				utilization_bps: 5000,
				instances: 5,
				min: 1,
				max: 10,
				up_threshold: 8000,
				down_threshold: 2000,
				expected: ScalingDecision::Hold,
			},
			// Hold: at max instances (can't scale up even if over threshold)
			ScalingTestCase {
				utilization_bps: 9500,
				instances: 10,
				min: 1,
				max: 10,
				up_threshold: 8000,
				down_threshold: 2000,
				expected: ScalingDecision::Hold,
			},
			// Hold: at min instances (can't scale down even if under threshold)
			ScalingTestCase {
				utilization_bps: 500,
				instances: 1,
				min: 1,
				max: 10,
				up_threshold: 8000,
				down_threshold: 2000,
				expected: ScalingDecision::Hold,
			},
			// Hold: exactly at up threshold (not above)
			ScalingTestCase {
				utilization_bps: 8000,
				instances: 5,
				min: 1,
				max: 10,
				up_threshold: 8000,
				down_threshold: 2000,
				expected: ScalingDecision::Hold,
			},
			// Hold: exactly at down threshold (not below)
			ScalingTestCase {
				utilization_bps: 2000,
				instances: 5,
				min: 1,
				max: 10,
				up_threshold: 8000,
				down_threshold: 2000,
				expected: ScalingDecision::Hold,
			},
		];

		for case in &cases {
			let config = ServletScaleConf {
				min_instances: case.min,
				max_instances: case.max,
				scale_up_threshold: BasisPoints::new(case.up_threshold),
				scale_down_threshold: BasisPoints::new(case.down_threshold),
			};

			let metrics = build_metrics(case.utilization_bps, case.instances, Some(config));
			let decision = ScalingDecision::evaluate(&metrics);
			assert_eq!(decision, case.expected);
		}
	}

	// ==========================================================================
	// Response Helper Unit Tests
	// ==========================================================================

	#[test]
	fn response_helper_heartbeat() {
		let resp = ClusterCommandResponse::heartbeat(TransitStatus::Accepted, BasisPoints::new(7500), 5);
		assert!(resp.manage.is_none());
		assert!(matches!(
			resp.heartbeat,
			Some(HeartbeatResult { status: TransitStatus::Accepted, utilization, active_servlets: 5 })
			if utilization.get() == 7500
		));
	}

	#[test]
	fn response_helper_manage() {
		let inner = HiveManagementResponse::stop_ok();
		let resp = ClusterCommandResponse::manage(inner.clone());
		assert!(resp.heartbeat.is_none());
		assert_eq!(resp.manage, Some(inner));
	}

	#[test]
	fn response_helper_spawn_ok() {
		let resp = HiveManagementResponse::spawn_ok(b"127.0.0.1:8080".to_vec(), b"servlet_1".to_vec());
		assert!(resp.list.is_none());
		assert!(resp.stop.is_none());
		assert!(matches!(
			&resp.spawn,
			Some(SpawnServletResult {
				status: TransitStatus::Accepted,
				servlet_address: Some(addr),
				servlet_id: Some(id),
			}) if addr == b"127.0.0.1:8080" && id == b"servlet_1"
		));
	}

	#[test]
	fn response_helper_spawn_err() {
		let resp = HiveManagementResponse::spawn_err(TransitStatus::Forbidden);
		assert!(matches!(
			resp.spawn,
			Some(SpawnServletResult { status: TransitStatus::Forbidden, servlet_address: None, servlet_id: None })
		));
	}

	#[test]
	fn response_helper_list_ok() {
		let servlets = vec![
			ServletInfo { servlet_id: b"s1".to_vec(), address: b"addr1".to_vec() },
			ServletInfo { servlet_id: b"s2".to_vec(), address: b"addr2".to_vec() },
		];

		let resp = HiveManagementResponse::list_ok(servlets);
		assert!(matches!(
			&resp.list,
			Some(ListServletsResult { status: TransitStatus::Accepted, servlets })
			if servlets.len() == 2
		));
	}

	#[test]
	fn response_helper_stop_ok() {
		let resp = HiveManagementResponse::stop_ok();
		assert!(matches!(resp.stop, Some(StopServletResult { status: TransitStatus::Accepted })));
	}

	#[test]
	fn response_helper_stop_err() {
		let resp = HiveManagementResponse::stop_err(TransitStatus::Forbidden);
		assert!(matches!(
			resp.stop,
			Some(StopServletResult { status: TransitStatus::Forbidden })
		));
	}

	#[test]
	fn response_helper_activate_ok() {
		let resp = ActivateServletResponse::ok(b"127.0.0.1:9000".to_vec());
		assert_eq!(resp.status, TransitStatus::Accepted);
		assert_eq!(resp.servlet_address, Some(b"127.0.0.1:9000".to_vec()));
	}

	#[test]
	fn response_helper_activate_err() {
		let resp = ActivateServletResponse::err(TransitStatus::Forbidden);
		assert_eq!(resp.status, TransitStatus::Forbidden);
		assert!(resp.servlet_address.is_none());
	}

	// ==========================================================================
	// Default Implementation Unit Tests
	// ==========================================================================

	#[test]
	fn defaults_servlet_scale_conf() {
		let conf = ServletScaleConf::default();
		assert_eq!(conf.min_instances, 1);
		assert_eq!(conf.max_instances, 10);
		assert_eq!(conf.scale_up_threshold.get(), 8000);
		assert_eq!(conf.scale_down_threshold.get(), 2000);
	}

	#[test]
	fn defaults_hive_conf() {
		let conf = HiveConf::default();
		assert_eq!(conf.default_scale.min_instances, 1);
		assert_eq!(conf.default_scale.max_instances, 10);
		assert!(conf.servlet_overrides.is_empty());
		assert_eq!(conf.cooldown, Duration::from_secs(5));
		assert_eq!(conf.queue_capacity, 100);
		assert_eq!(conf.circuit_breaker_threshold, 3);
		assert_eq!(conf.circuit_breaker_cooldown_ms, 30_000);
		assert!(conf.trusted_cluster_keys.is_empty());
	}

	#[test]
	fn defaults_cluster_status() {
		let status = ClusterStatus::default();
		assert_eq!(status, ClusterStatus::Healthy);
	}

	// ==========================================================================
	// LoadBalancer Unit Tests
	// ==========================================================================

	fn make_instance(id: &str, util_bps: u16) -> InstanceMetrics {
		InstanceMetrics {
			servlet_id: id.as_bytes().to_vec(),
			utilization: BasisPoints::new_saturating(util_bps),
			active_requests: 0,
		}
	}

	#[test]
	fn least_loaded_selects_minimum() {
		let lb = LeastLoaded;
		let instances = vec![make_instance("a", 5000), make_instance("b", 2000), make_instance("c", 8000)];
		assert_eq!(LoadBalancer::select(&lb, &instances), Some(1));
	}

	#[test]
	fn least_loaded_empty_returns_none() {
		let lb = LeastLoaded;
		assert_eq!(LoadBalancer::select(&lb, &[]), None);
	}

	#[test]
	fn least_loaded_single_returns_zero() {
		let lb = LeastLoaded;
		let instances = vec![make_instance("a", 5000)];
		assert_eq!(LoadBalancer::select(&lb, &instances), Some(0));
	}

	#[test]
	fn p2c_empty_returns_none() {
		let lb = PowerOfTwoChoices;
		assert_eq!(LoadBalancer::select(&lb, &[]), None);
	}

	#[test]
	fn p2c_single_returns_zero() {
		let lb = PowerOfTwoChoices;
		let instances = vec![make_instance("a", 5000)];
		assert_eq!(LoadBalancer::select(&lb, &instances), Some(0));
	}

	#[test]
	fn p2c_two_picks_least_loaded() {
		let lb = PowerOfTwoChoices;
		let instances = vec![make_instance("a", 8000), make_instance("b", 2000)];
		assert_eq!(LoadBalancer::select(&lb, &instances), Some(1));
	}

	#[test]
	fn round_robin_cycles() {
		let lb = RoundRobin::default();
		let instances = vec![make_instance("a", 5000), make_instance("b", 5000), make_instance("c", 5000)];
		assert_eq!(LoadBalancer::select(&lb, &instances), Some(0));
		assert_eq!(LoadBalancer::select(&lb, &instances), Some(1));
		assert_eq!(LoadBalancer::select(&lb, &instances), Some(2));
		assert_eq!(LoadBalancer::select(&lb, &instances), Some(0));
	}

	#[test]
	fn round_robin_empty_returns_none() {
		let lb = RoundRobin::default();
		assert_eq!(LoadBalancer::select(&lb, &[]), None);
	}

	// ==========================================================================
	// MessageRouter Unit Tests
	// ==========================================================================

	#[test]
	fn type_based_router_finds_match() {
		let router = TypeBasedRouter;
		let types: &[(&'static [u8], MessageValidator)] =
			&[(b"type_a", |_| false), (b"type_b", |_| true), (b"type_c", |_| false)];
		assert_eq!(MessageRouter::route(&router, b"test", types), Some(b"type_b".as_slice()));
	}

	#[test]
	fn type_based_router_no_match() {
		let router = TypeBasedRouter;
		let types: &[(&'static [u8], MessageValidator)] = &[(b"type_a", |_| false), (b"type_b", |_| false)];
		assert_eq!(MessageRouter::route(&router, b"test", types), None);
	}

	#[test]
	fn type_based_router_empty_types() {
		let router = TypeBasedRouter;
		let types: &[(&'static [u8], MessageValidator)] = &[];
		assert_eq!(MessageRouter::route(&router, b"test", types), None);
	}

	#[test]
	fn type_based_router_first_match_wins() {
		let router = TypeBasedRouter;
		let types: &[(&'static [u8], MessageValidator)] = &[(b"first", |_| true), (b"second", |_| true)];
		assert_eq!(MessageRouter::route(&router, b"test", types), Some(b"first".as_slice()));
	}

	// ==========================================================================
	// LatencyTracker Unit Tests
	// ==========================================================================

	#[test]
	fn latency_tracker_initial_zero() {
		let tracker = LatencyTracker::default();
		assert_eq!(tracker.ema_microseconds(), 0);
		assert_eq!(tracker.utilization().get(), 0);
	}

	#[test]
	fn latency_tracker_records_latency() {
		let tracker = LatencyTracker::new(10000, 100_000); // 100% weight, 100ms target
		tracker.record(50_000); // 50ms
		assert_eq!(tracker.ema_microseconds(), 50_000);
		assert_eq!(tracker.utilization().get(), 5000); // 50%
	}

	#[test]
	fn latency_tracker_ema_smoothing() {
		let tracker = LatencyTracker::new(5000, 100_000); // 50% weight
		tracker.record(100_000);
		assert_eq!(tracker.ema_microseconds(), 50_000); // 0.5 * 100k + 0.5 * 0 = 50k

		tracker.record(100_000);
		assert_eq!(tracker.ema_microseconds(), 75_000); // 0.5 * 100k + 0.5 * 50k = 75k
	}

	#[test]
	fn latency_tracker_saturates_at_max() {
		let tracker = LatencyTracker::new(10000, 100_000); // 100% weight, 100ms target
		tracker.record(200_000); // 200ms
		assert_eq!(tracker.utilization().get(), 10000); // Capped at 100%
	}

	#[test]
	fn latency_tracker_reset() {
		let tracker = LatencyTracker::new(10000, 100_000);
		tracker.record(50_000);
		assert_eq!(tracker.ema_microseconds(), 50_000);

		tracker.reset();
		assert_eq!(tracker.ema_microseconds(), 0);
	}

	#[test]
	fn latency_tracker_zero_target_returns_max() {
		let tracker = LatencyTracker::new(10000, 0); // Zero target
		tracker.record(50_000);
		assert_eq!(tracker.utilization().get(), 10000); // MAX when target is 0
	}

	// ==========================================================================
	// Hive Drain (Graceful Shutdown) Unit Tests
	// ==========================================================================

	/// Helper to create a TestHive with custom drain timeout
	async fn make_hive_with_drain_timeout(timeout_ms: u64) -> Result<TestHive, Box<dyn std::error::Error>> {
		let config = HiveConf { drain_timeout: Duration::from_millis(timeout_ms), ..Default::default() };
		let mut hive = TestHive::start(Arc::new(TraceCollector::new()), Some(config)).await?;

		hive.establish_hive().await?;
		Ok(hive)
	}

	#[tokio::test]
	async fn hive_drain_sets_draining_state() -> Result<(), Box<dyn std::error::Error>> {
		let hive = make_hive_with_drain_timeout(500).await?;
		assert!(!hive.is_draining());

		hive.drain().await?;
		assert!(hive.is_draining());

		hive.stop();
		Ok(())
	}

	#[tokio::test]
	async fn hive_drain_stops_all_servlets() -> Result<(), Box<dyn std::error::Error>> {
		let hive = make_hive_with_drain_timeout(500).await?;
		assert!(!hive.servlet_addresses().await.is_empty());

		hive.drain().await?;
		assert!(hive.servlet_addresses().await.is_empty());

		hive.stop();
		Ok(())
	}

	#[tokio::test]
	async fn hive_drain_completes_within_timeout() -> Result<(), Box<dyn std::error::Error>> {
		let hive = make_hive_with_drain_timeout(100).await?;
		let start = std::time::Instant::now();

		// Should complete within ~200ms (100ms timeout + polling overhead)
		hive.drain().await?;
		assert!(start.elapsed() < Duration::from_millis(500));

		hive.stop();
		Ok(())
	}
}
