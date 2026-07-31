//! Gate policies for hive security and backpressure
//!
//! Contains circuit breaker, replay guard, and security gate implementations
//! for cluster command authentication and capacity management.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::sync::Arc;

use core::sync::atomic::{AtomicU16, AtomicU64, AtomicU8, Ordering};

use crate::colony::common::current_timestamp_ms;
use crate::policy::{GatePolicy, SessionContext, TransitStatus};
use crate::utils::BasisPoints;
use crate::Frame;

#[cfg(feature = "x509")]
mod x509 {
	pub use std::collections::{HashMap, HashSet};
	pub use std::sync::Mutex;

	pub use crate::colony::common::ClusterCommand;
	pub use crate::crypto::x509::store::CertificateTrust;
	pub use crate::der::Encode;
}

#[cfg(feature = "x509")]
use x509::*;

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
	/// Testing - allowing probe requests to check recovery
	HalfOpen = 2,
}

/// Circuit breaker for cluster authentication failures
///
/// Trips after consecutive auth failures, halting all cluster communication.
/// After a cooldown period, transitions to half-open to allow probe requests.
///
/// Only failures attributable to a *known* signer count toward the
/// threshold (see [`ClusterSecurityGate`]): unauthenticated garbage must
/// not be able to sever the control plane between hive and legitimate
/// cluster (CWE-645).
///
/// # Thread Safety
///
/// All state is managed via atomics for lock-free concurrent access. The
/// `Open -> HalfOpen` transition is a compare-and-swap, so exactly one
/// caller performs it per cooldown expiry.
pub struct ClusterCircuitBreaker {
	/// Current state (CircuitState as u8)
	state: AtomicU8,
	/// Consecutive failure count (saturating)
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
				let now = current_timestamp_ms();
				let opened = self.opened_at.load(Ordering::Relaxed);
				if now.saturating_sub(opened) < self.cooldown_ms {
					return false;
				}

				// Compare-and-swap so concurrent callers racing the same
				// cooldown expiry produce a single state transition.
				self.state
					.compare_exchange(
						CircuitState::Open as u8,
						CircuitState::HalfOpen as u8,
						Ordering::AcqRel,
						Ordering::Acquire,
					)
					.is_ok()
			}
			// Probes stay allowed until one resolves via record_success or
			// record_auth_failure. Rejecting here instead would deadlock the
			// breaker when a probe slot is consumed by a frame that resolves
			// neither way.
			CircuitState::HalfOpen => true,
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
	/// Increments failure count (saturating). If the threshold is reached,
	/// trips the circuit. A failure while half-open re-opens immediately
	/// and restarts the cooldown.
	pub fn record_auth_failure(&self) {
		if self.state() == CircuitState::HalfOpen {
			self.trip();
			return;
		}

		let previous = self
			.failures
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| Some(count.saturating_add(1)))
			.unwrap_or(u8::MAX);
		if previous.saturating_add(1) >= self.failure_threshold {
			self.trip();
		}
	}

	fn trip(&self) {
		self.opened_at.store(current_timestamp_ms(), Ordering::Relaxed);
		self.state.store(CircuitState::Open as u8, Ordering::Release);
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

// ============================================================================
// Trust Verification
// ============================================================================

/// Outcome of verifying a frame signature against a trust store
///
/// Distinguishes "no identity claimed" and "unknown identity claimed"
/// from "trusted identity claimed with a bad signature" so callers can
/// apply different consequences (the circuit breaker only counts the
/// last one).
#[cfg(feature = "x509")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustVerification {
	/// Frame carries no nonrepudiation signature
	MissingSignature,
	/// Signer is not present in the trust store
	UnknownSigner,
	/// Signer is trusted but the signature does not verify
	Invalid,
	/// Signature verified against a trusted certificate
	Verified,
}

/// Verify a frame's nonrepudiation signature against a trust store
///
/// Looks up the signer certificate via the frame's `SignerInfo` and
/// verifies the signature over the frame's to-be-signed bytes. Shared by
/// [`ClusterSecurityGate`] (hive side) and the cluster gateway's
/// registration authentication.
#[cfg(feature = "x509")]
pub fn verify_frame_signature(trust_store: &dyn CertificateTrust, frame: &Frame) -> TrustVerification {
	let Some(signer_info) = frame.nonrepudiation.as_ref() else {
		return TrustVerification::MissingSignature;
	};

	let Some(cert) = trust_store.find_by_signer_info(signer_info) else {
		return TrustVerification::UnknownSigner;
	};

	let algorithm_oid = signer_info.signature_algorithm.oid;
	let signature = signer_info.signature.as_bytes();
	let Ok(public_key_der) = cert.tbs_certificate.subject_public_key_info.to_der() else {
		return TrustVerification::Invalid;
	};

	let Ok(message) = frame.to_tbs() else {
		return TrustVerification::Invalid;
	};

	match trust_store
		.to_policy_ref()
		.verify_signature(&algorithm_oid, &public_key_der, &message, signature)
	{
		Ok(()) => TrustVerification::Verified,
		Err(_) => TrustVerification::Invalid,
	}
}

// ============================================================================
// Replay Guard
// ============================================================================

/// Maximum distinct signatures remembered per signer per freshness window
///
/// Legitimate traffic is bounded by a signer's command rate inside one
/// window. Each signer's partition fails closed at capacity rather than
/// evicting, because an unauthenticated attacker cannot create the fresh
/// valid signatures needed to fill it.
#[cfg(feature = "x509")]
pub const REPLAY_GUARD_CAPACITY: usize = 1024;

/// Bounded freshness and replay window for signed cluster commands
///
/// A command is accepted when its `Frame.metadata.order` lies within
/// `window_ms` of the hive clock (either direction, tolerating skew)
/// AND its signature has not already been seen inside the window.
/// Signatures are tracked per signer so one signer saturating its
/// partition cannot block the others. Entries more than the window away
/// from the current clock are pruned on each check, so memory is bounded by
/// [`REPLAY_GUARD_CAPACITY`] per trusted signer.
#[cfg(feature = "x509")]
type SignerPartitions = HashMap<Vec<u8>, HashMap<Vec<u8>, u64>>;

#[cfg(feature = "x509")]
pub struct ReplayGuard {
	seen: Mutex<SignerPartitions>,
	window_ms: u64,
}

#[cfg(feature = "x509")]
impl ReplayGuard {
	/// Create a guard with the given freshness window in milliseconds
	pub fn new(window_ms: u64) -> Self {
		Self { seen: Mutex::new(HashMap::new()), window_ms }
	}

	/// Whether `order_ms` (`Frame.metadata.order`) is within the freshness window of `now_ms`
	pub fn is_fresh(&self, order_ms: u64, now_ms: u64) -> bool {
		now_ms.abs_diff(order_ms) <= self.window_ms
	}

	/// Record `signature` for `signer` if unseen within the window
	///
	/// Returns `true` when the signature is new (and now recorded).
	/// Returns `false` for replays, and fails closed when the signer's
	/// partition is at capacity or the lock is poisoned.
	pub fn check_and_insert(&self, signer: &[u8], signature: &[u8], now_ms: u64) -> bool {
		let Ok(mut seen) = self.seen.lock() else {
			return false;
		};

		// After a backward clock step the recorded timestamps sit in the
		// future, and a past-only check would retain them until the clock
		// re-passes them, pinning partitions at capacity the duration.
		seen.retain(|_, sigs| {
			sigs.retain(|_, ts| now_ms.abs_diff(*ts) <= self.window_ms);
			!sigs.is_empty()
		});

		// Replay detection spans all partitions: the same certificate can be
		// named by either SignerIdentifier CHOICE arm, so a partition-local
		// check would grant one extra replay per alternate encoding.
		if seen.values().any(|sigs| sigs.contains_key(signature)) {
			return false;
		}

		let sigs = seen.entry(signer.to_vec()).or_default();
		if sigs.len() >= REPLAY_GUARD_CAPACITY {
			return false;
		}

		sigs.insert(signature.to_vec(), now_ms);

		true
	}

	/// Remove a recorded signature so the frame may be retried
	///
	/// The signature is recorded before the guarded operation runs. When
	/// that operation fails, the record must be released or a legitimate
	/// retry of the same signed frame is rejected as a replay until the
	/// window expires.
	pub fn forget(&self, signature: &[u8]) {
		let Ok(mut seen) = self.seen.lock() else {
			return;
		};

		seen.retain(|_, sigs| {
			sigs.remove(signature);
			!sigs.is_empty()
		});
	}
}

// =============================================================================
// Gate Policies
// =============================================================================

/// Gate policy for certificate-based cluster command security
///
/// Enforces nonrepudiation, integrity, freshness, and replay requirements
/// on cluster commands using certificate-based trust verification.
///
/// # Security Flow
///
/// 1. Check circuit breaker - reject if open
/// 2. Verify nonrepudiation signature present (else `Unauthenticated`, not counted)
/// 3. Verify frame integrity present (else `Unauthenticated`, not counted)
/// 4. Look up signer certificate in trust store (unknown signer: `PermissionDenied`, not counted)
/// 5. Verify signature using certificate's public key (invalid: `PermissionDenied`, **counted**)
/// 6. Check `Frame.metadata.order` freshness (stale: `PermissionDenied`, not counted)
/// 7. Reject signatures already seen inside the window (replay: `PermissionDenied`, not counted)
/// 8. On success: record success (resets breaker)
///
/// Only step 5 counts toward the circuit breaker.
/// Counting unauthenticated failures would let garbage sever the control plane (CWE-645).
/// Steps 6-7 are not counted: a replayed capture still carries a valid signature.
#[cfg(feature = "x509")]
pub struct ClusterSecurityGate {
	/// Circuit breaker for tracking auth failures
	circuit_breaker: Arc<ClusterCircuitBreaker>,
	/// Trust store for certificate lookup and signature verification
	trust_store: Arc<dyn CertificateTrust>,
	/// Freshness window and replay set for signed commands
	replay_guard: Arc<ReplayGuard>,
}

#[cfg(feature = "x509")]
impl ClusterSecurityGate {
	/// Create a new security gate with certificate-based trust
	///
	/// # Arguments
	/// * `circuit_breaker` - Shared circuit breaker for tracking auth failures
	/// * `trust_store` - Trust store containing trusted certificates
	/// * `replay_guard` - Freshness window and replay set for commands
	pub fn new(
		circuit_breaker: Arc<ClusterCircuitBreaker>,
		trust_store: Arc<dyn CertificateTrust>,
		replay_guard: Arc<ReplayGuard>,
	) -> Self {
		Self { circuit_breaker, trust_store, replay_guard }
	}
}

#[cfg(feature = "x509")]
impl GatePolicy for ClusterSecurityGate {
	fn evaluate(&self, frame: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		if !self.circuit_breaker.allow_request() {
			return TransitStatus::PermissionDenied;
		}

		let Some(frame) = frame else {
			return TransitStatus::Unauthenticated;
		};

		let Some(signer_info) = frame.nonrepudiation.as_ref() else {
			return TransitStatus::Unauthenticated;
		};

		if frame.integrity.is_none() {
			return TransitStatus::Unauthenticated;
		}

		match verify_frame_signature(self.trust_store.as_ref(), frame) {
			TrustVerification::MissingSignature => return TransitStatus::Unauthenticated,
			TrustVerification::UnknownSigner => return TransitStatus::PermissionDenied,
			TrustVerification::Invalid => {
				self.circuit_breaker.record_auth_failure();
				return TransitStatus::PermissionDenied;
			}
			TrustVerification::Verified => {}
		}

		// Decode before freshness so malformed frames never consume replay capacity (CWE-770).
		let Ok(_command) = crate::decode::<ClusterCommand>(&frame.message) else {
			return TransitStatus::PermissionDenied;
		};

		let now = current_timestamp_ms();
		if !self.replay_guard.is_fresh(frame.metadata.order, now) {
			return TransitStatus::PermissionDenied;
		}

		// Signer identifier keys the replay partition; an unencodable
		// identifier cannot be attributed, so it fails closed.
		let Ok(signer_id) = signer_info.sid.to_der() else {
			return TransitStatus::PermissionDenied;
		};
		if !self
			.replay_guard
			.check_and_insert(&signer_id, signer_info.signature.as_bytes(), now)
		{
			return TransitStatus::PermissionDenied;
		}

		self.circuit_breaker.record_success();

		TransitStatus::Ok
	}
}

/// Gate policy enforcing hive capacity limits (backpressure).
///
/// Returns `TransitStatus::ResourceExhausted` when utilization exceeds threshold,
/// signaling to the cluster that it should route work elsewhere or queue.
///
/// The gate itself grants no exemptions: any bypass keyed on frame-controlled
/// data (e.g. message priority) is attacker-selectable. Callers that must keep
/// specific traffic flowing under load (heartbeats) exempt it explicitly
/// *after* authentication.
pub struct BackpressureGate {
	/// Current aggregate utilization (basis points as u16)
	utilization: Arc<AtomicU16>,
	/// Threshold above which to reject (from HiveConfig)
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
	fn evaluate(&self, _frame: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		let current = self.utilization.load(Ordering::Relaxed);
		if current >= self.threshold.get() {
			TransitStatus::ResourceExhausted
		} else {
			TransitStatus::Ok
		}
	}
}

// ============================================================================
// Peer List Gate
// ============================================================================

/// Membership mode of a [`PeerListGate`].
#[cfg(feature = "x509")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerListMode {
	/// White list: only listed peer keys are admitted.
	Allow,
	/// Black list: listed peer keys are refused.
	Deny,
}

/// Session-identity black/white list.
///
/// Keys on the DER-encoded `SubjectPublicKeyInfo` of the connection's
/// mutually-authenticated peer certificate, not the frame signer which is an
/// application-level concern. An empty session context answers as an absent
/// peer, so allow lists fail closed (`Unauthenticated`) and deny lists admit.
#[cfg(feature = "x509")]
#[derive(Clone)]
pub struct PeerListGate {
	keys: HashSet<Vec<u8>>,
	mode: PeerListMode,
}

#[cfg(feature = "x509")]
impl PeerListGate {
	/// White list admitting only these peer public keys (SPKI DER).
	pub fn allow<I, K>(keys: I) -> Self
	where
		I: IntoIterator<Item = K>,
		K: Into<Vec<u8>>,
	{
		Self { keys: keys.into_iter().map(Into::into).collect(), mode: PeerListMode::Allow }
	}

	/// Black list refusing these peer public keys (SPKI DER).
	pub fn deny<I, K>(keys: I) -> Self
	where
		I: IntoIterator<Item = K>,
		K: Into<Vec<u8>>,
	{
		Self { keys: keys.into_iter().map(Into::into).collect(), mode: PeerListMode::Deny }
	}

	/// The verdict for one peer identity.
	///
	/// A certified peer with an absent key means the SPKI failed to
	/// encode locally; refused as [`TransitStatus::Internal`] in both
	/// modes so the fault cannot slip past a deny list.
	fn admit(&self, has_certificate: bool, peer_key: Option<&[u8]>) -> TransitStatus {
		match (self.mode, peer_key) {
			(_, None) if has_certificate => TransitStatus::Internal,
			(PeerListMode::Allow, Some(key)) if self.keys.contains(key) => TransitStatus::Ok,
			(PeerListMode::Allow, Some(_)) => TransitStatus::PermissionDenied,
			(PeerListMode::Allow, None) => TransitStatus::Unauthenticated,
			(PeerListMode::Deny, Some(key)) if self.keys.contains(key) => TransitStatus::PermissionDenied,
			(PeerListMode::Deny, _) => TransitStatus::Ok,
		}
	}
}

#[cfg(feature = "x509")]
impl GatePolicy for PeerListGate {
	fn evaluate(&self, _message: Option<&Frame>, session: &SessionContext) -> TransitStatus {
		self.admit(session.peer_certificate().is_some(), session.peer_public_key())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn breaker_trips_after_threshold() {
		let breaker = ClusterCircuitBreaker::new(3, 60_000);

		breaker.record_auth_failure();
		breaker.record_auth_failure();
		assert_eq!(breaker.state(), CircuitState::Closed);

		breaker.record_auth_failure();
		assert_eq!(breaker.state(), CircuitState::Open);
		assert!(!breaker.allow_request());
	}

	#[test]
	fn breaker_probe_success_closes() {
		let breaker = ClusterCircuitBreaker::new(1, 0);

		breaker.record_auth_failure();
		assert!(breaker.allow_request());
		assert_eq!(breaker.state(), CircuitState::HalfOpen);

		breaker.record_success();
		assert_eq!(breaker.state(), CircuitState::Closed);
	}

	#[test]
	fn breaker_probe_failure_reopens() {
		let breaker = ClusterCircuitBreaker::new(1, 0);

		breaker.record_auth_failure();
		assert!(breaker.allow_request());
		assert_eq!(breaker.state(), CircuitState::HalfOpen);

		breaker.record_auth_failure();
		assert_eq!(breaker.state(), CircuitState::Open);
	}

	#[test]
	fn breaker_reset_clears_state() {
		let breaker = ClusterCircuitBreaker::new(1, 60_000);

		breaker.record_auth_failure();
		assert!(breaker.is_open());

		breaker.reset();
		assert_eq!(breaker.state(), CircuitState::Closed);
		assert!(breaker.allow_request());
	}

	#[cfg(feature = "x509")]
	#[test]
	fn replay_guard_accepts_first_rejects_second() {
		let guard = ReplayGuard::new(30_000);
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 1_000));
		assert!(!guard.check_and_insert(b"signer-1", b"sig-a", 2_000));
		assert!(guard.check_and_insert(b"signer-1", b"sig-b", 2_000));
	}

	#[cfg(feature = "x509")]
	#[test]
	fn replay_guard_prunes_expired_entries() {
		let guard = ReplayGuard::new(1_000);
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 1_000));
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 3_000));
	}

	#[cfg(feature = "x509")]
	#[test]
	fn replay_guard_prunes_future_dated_entries_after_clock_regression() {
		let guard = ReplayGuard::new(1_000);
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 10_000));
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 5_000));
	}

	#[cfg(feature = "x509")]
	#[test]
	fn replay_guard_saturated_signer_does_not_block_others() {
		let guard = ReplayGuard::new(30_000);
		let seeded = (0..REPLAY_GUARD_CAPACITY).all(|i| guard.check_and_insert(b"signer-1", &i.to_be_bytes(), 1_000));
		assert!(seeded);
		assert!(!guard.check_and_insert(b"signer-1", b"sig-overflow", 1_000));
		assert!(guard.check_and_insert(b"signer-2", b"sig-a", 1_000));
	}

	#[cfg(feature = "x509")]
	#[test]
	fn replay_guard_rejects_replay_across_signer_partitions() {
		let guard = ReplayGuard::new(30_000);
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 1_000));
		assert!(!guard.check_and_insert(b"signer-2", b"sig-a", 1_000));
	}

	#[cfg(feature = "x509")]
	#[test]
	fn replay_guard_forget_permits_retry() {
		let guard = ReplayGuard::new(30_000);
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 1_000));
		guard.forget(b"sig-a");
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 2_000));
	}

	#[cfg(feature = "x509")]
	#[test]
	fn replay_guard_freshness_window_is_bidirectional() {
		let guard = ReplayGuard::new(1_000);
		assert!(guard.is_fresh(9_500, 10_000));
		assert!(guard.is_fresh(10_500, 10_000));
		assert!(!guard.is_fresh(8_999, 10_000));
		assert!(!guard.is_fresh(11_001, 10_000));
	}

	fn work_frame(priority: Option<crate::MessagePriority>) -> Result<Frame, crate::TightBeamError> {
		use crate::builder::TypeBuilder;

		// V2: priority is a V2+ metadata field
		let mut builder = crate::utils::compose(crate::Version::V2)
			.with_id(b"work")
			.with_order(0)
			.with_message(crate::testing::TestMessage { content: "payload".into() });
		if let Some(priority) = priority {
			builder = builder.with_priority(priority);
		}

		builder.build()
	}

	#[test]
	fn backpressure_gate_ignores_priority() -> Result<(), crate::TightBeamError> {
		let utilization = Arc::new(AtomicU16::new(9_500));
		let gate = BackpressureGate::new(utilization, BasisPoints::new_saturating(9_000));

		let frame = work_frame(Some(crate::MessagePriority::NetworkControl))?;
		assert_eq!(
			GatePolicy::evaluate(&gate, Some(&frame), &SessionContext::default()),
			TransitStatus::ResourceExhausted
		);

		Ok(())
	}

	#[test]
	fn backpressure_gate_accepts_below_threshold() -> Result<(), crate::TightBeamError> {
		let utilization = Arc::new(AtomicU16::new(1_000));
		let gate = BackpressureGate::new(utilization, BasisPoints::new_saturating(9_000));

		let frame = work_frame(None)?;
		assert_eq!(
			GatePolicy::evaluate(&gate, Some(&frame), &SessionContext::default()),
			TransitStatus::Ok
		);

		Ok(())
	}

	#[cfg(feature = "x509")]
	#[test]
	fn peer_allow_list_admits_listed_key_only() {
		let gate = PeerListGate::allow([b"key-a".to_vec()]);
		assert_eq!(gate.admit(true, Some(b"key-a")), TransitStatus::Ok);
		assert_eq!(gate.admit(true, Some(b"key-b")), TransitStatus::PermissionDenied);
	}

	#[cfg(feature = "x509")]
	#[test]
	fn peer_allow_list_fails_closed_without_identity() {
		let gate = PeerListGate::allow([b"key-a".to_vec()]);
		assert_eq!(gate.admit(false, None), TransitStatus::Unauthenticated);
	}

	#[cfg(feature = "x509")]
	#[test]
	fn peer_deny_list_refuses_listed_key_only() {
		let gate = PeerListGate::deny([b"key-a".to_vec()]);
		assert_eq!(gate.admit(true, Some(b"key-a")), TransitStatus::PermissionDenied);
		assert_eq!(gate.admit(true, Some(b"key-b")), TransitStatus::Ok);
	}

	#[cfg(feature = "x509")]
	#[test]
	fn peer_deny_list_admits_absent_identity() {
		let gate = PeerListGate::deny([b"key-a".to_vec()]);
		assert_eq!(gate.admit(false, None), TransitStatus::Ok);
	}

	#[cfg(feature = "x509")]
	#[test]
	fn peer_list_refuses_certified_peer_without_spki() {
		let allow = PeerListGate::allow([b"key-a".to_vec()]);
		let deny = PeerListGate::deny([b"key-a".to_vec()]);
		assert_eq!(allow.admit(true, None), TransitStatus::Internal);
		assert_eq!(deny.admit(true, None), TransitStatus::Internal);
	}

	#[cfg(feature = "x509")]
	#[test]
	fn peer_list_empty_context_answers_as_absent_peer() -> Result<(), crate::TightBeamError> {
		let frame = work_frame(None)?;
		let empty = SessionContext::default();
		let allow = PeerListGate::allow([b"key-a".to_vec()]);
		let deny = PeerListGate::deny([b"key-a".to_vec()]);
		assert_eq!(
			GatePolicy::evaluate(&allow, Some(&frame), &empty),
			TransitStatus::Unauthenticated
		);
		assert_eq!(GatePolicy::evaluate(&deny, Some(&frame), &empty), TransitStatus::Ok);

		Ok(())
	}
}
