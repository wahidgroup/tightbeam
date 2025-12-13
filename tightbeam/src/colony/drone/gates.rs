//! Gate policies for drone/hive security and backpressure
//!
//! Contains circuit breaker and security gate implementations for
//! cluster command authentication and capacity management.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::sync::Arc;

use core::sync::atomic::{AtomicU16, AtomicU64, AtomicU8, Ordering};

use crate::policy::{GatePolicy, TransitStatus};
use crate::utils::BasisPoints;
use crate::Frame;

use super::error::DroneError;
use crate::colony::common::current_timestamp_ms;

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
