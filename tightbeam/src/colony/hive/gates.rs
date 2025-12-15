//! Gate policies for hive security and backpressure
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

use crate::colony::common::current_timestamp_ms;
use crate::policy::{GatePolicy, TransitStatus};
use crate::utils::BasisPoints;
use crate::Frame;

#[cfg(feature = "x509")]
use crate::crypto::x509::store::CertificateTrust;
#[cfg(feature = "x509")]
use crate::der::Encode;

// ============================================================================
// Circuit Breaker
// ============================================================================

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

/// Gate policy for certificate-based cluster command security
///
/// Enforces nonrepudiation and integrity requirements on cluster commands
/// using certificate-based trust verification.
///
/// # Security Flow
///
/// 1. Check circuit breaker - reject if open
/// 2. Verify nonrepudiation signature present
/// 3. Verify frame integrity present
/// 4. Look up signer certificate in trust store
/// 5. Verify signature using certificate's public key
/// 6. On failure: record auth failure (may trip breaker)
/// 7. On success: record success (resets breaker)
#[cfg(feature = "x509")]
pub struct ClusterSecurityGate {
	/// Circuit breaker for tracking auth failures
	circuit_breaker: Arc<ClusterCircuitBreaker>,
	/// Trust store for certificate lookup and signature verification
	trust_store: Arc<dyn CertificateTrust>,
}

#[cfg(feature = "x509")]
impl ClusterSecurityGate {
	/// Create a new security gate with certificate-based trust
	///
	/// # Arguments
	/// * `circuit_breaker` - Shared circuit breaker for tracking auth failures
	/// * `trust_store` - Trust store containing trusted certificates
	pub fn new(circuit_breaker: Arc<ClusterCircuitBreaker>, trust_store: Arc<dyn CertificateTrust>) -> Self {
		Self { circuit_breaker, trust_store }
	}
}

#[cfg(feature = "x509")]
impl GatePolicy for ClusterSecurityGate {
	fn evaluate(&self, frame: &Frame) -> TransitStatus {
		// Check circuit breaker first
		if !self.circuit_breaker.allow_request() {
			return TransitStatus::Forbidden;
		}

		// Check nonrepudiation (required by #[beam(nonrepudiable)])
		let signer_info = match frame.nonrepudiation.as_ref() {
			Some(info) => info,
			None => {
				self.circuit_breaker.record_auth_failure();
				return TransitStatus::Unauthorized;
			}
		};

		// Check integrity
		if frame.integrity.is_none() {
			self.circuit_breaker.record_auth_failure();
			return TransitStatus::Unauthorized;
		}

		// Look up signer certificate - if found, signer is trusted
		let cert = match self.trust_store.find_by_signer_info(signer_info) {
			Some(c) => c,
			None => {
				self.circuit_breaker.record_auth_failure();
				return TransitStatus::Forbidden;
			}
		};

		// Verify signature using certificate's public key
		let algorithm_oid = signer_info.signature_algorithm.oid;
		let signature = signer_info.signature.as_bytes();
		let public_key_der = match cert.tbs_certificate.subject_public_key_info.to_der() {
			Ok(der) => der,
			Err(_) => {
				self.circuit_breaker.record_auth_failure();
				return TransitStatus::Forbidden;
			}
		};

		let message = match frame.to_tbs() {
			Ok(tbs) => tbs,
			Err(_) => {
				self.circuit_breaker.record_auth_failure();
				return TransitStatus::Forbidden;
			}
		};

		match self
			.trust_store
			.to_policy_ref()
			.verify_signature(&algorithm_oid, &public_key_der, &message, signature)
		{
			Ok(()) => {
				self.circuit_breaker.record_success();
				TransitStatus::Accepted
			}
			Err(_) => {
				self.circuit_breaker.record_auth_failure();
				TransitStatus::Forbidden
			}
		}
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
	/// * `utilization` - Shared atomic for current utilization
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
