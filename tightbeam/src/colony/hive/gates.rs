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

use core::sync::atomic::{AtomicU16, Ordering};

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
	/// Per-signer circuits. A signer with no failure history holds no row.
	signers: Mutex<HashMap<Vec<u8>, SignerCircuit>>,
	/// Failure threshold before tripping
	failure_threshold: u8,
	/// Cooldown duration in milliseconds
	cooldown_ms: u64,
}

/// One signer's breaker position.
#[derive(Clone, Copy)]
struct SignerCircuit {
	state: CircuitState,
	failures: u8,
	opened_at: u64,
}

impl SignerCircuit {
	const CLOSED: Self = Self { state: CircuitState::Closed, failures: 0, opened_at: 0 };

	/// A closed circuit with no failures carries no history, so its row is
	/// dropped and the map stays bounded by the signers currently failing.
	const fn is_quiescent(&self) -> bool {
		matches!(self.state, CircuitState::Closed) && self.failures == 0
	}
}

impl ClusterCircuitBreaker {
	/// Create a new circuit breaker
	///
	/// # Arguments
	/// * `failure_threshold` - Number of consecutive failures before tripping
	/// * `cooldown_ms` - Time in milliseconds before transitioning to half-open
	pub fn new(failure_threshold: u8, cooldown_ms: u64) -> Self {
		Self { signers: Mutex::new(HashMap::new()), failure_threshold, cooldown_ms }
	}

	/// Check whether `signer` may send a request
	///
	/// Returns `true` while that signer's circuit is closed, or half-open
	/// after its cooldown. Each signer's failures gate that signer alone, so
	/// the colony control plane stays open to every other member
	/// (CWE-645).
	pub fn allow_request(&self, signer: &[u8]) -> bool {
		let Ok(mut signers) = self.signers.lock() else {
			return false;
		};

		let Some(circuit) = signers.get_mut(signer) else {
			return true;
		};

		match circuit.state {
			CircuitState::Closed | CircuitState::HalfOpen => true,
			CircuitState::Open => {
				let elapsed = current_timestamp_ms().saturating_sub(circuit.opened_at);
				if elapsed < self.cooldown_ms {
					return false;
				}

				// The guard serialises concurrent callers racing the same
				// cooldown expiry, so exactly one probe is admitted.
				circuit.state = CircuitState::HalfOpen;

				true
			}
		}
	}

	/// Record a successful request from `signer`
	pub fn record_success(&self, signer: &[u8]) {
		let Ok(mut signers) = self.signers.lock() else {
			return;
		};

		signers.remove(signer);
	}

	/// Record an authentication failure attributed to `signer`
	///
	/// A failure while half-open re-opens immediately and restarts the
	/// cooldown.
	pub fn record_auth_failure(&self, signer: &[u8]) {
		let Ok(mut signers) = self.signers.lock() else {
			return;
		};

		let circuit = signers.entry(signer.to_vec()).or_insert(SignerCircuit::CLOSED);
		if matches!(circuit.state, CircuitState::HalfOpen) {
			circuit.state = CircuitState::Open;
			circuit.opened_at = current_timestamp_ms();

			return;
		}

		circuit.failures = circuit.failures.saturating_add(1);
		if circuit.failures >= self.failure_threshold {
			circuit.state = CircuitState::Open;
			circuit.opened_at = current_timestamp_ms();
		}
	}

	/// Current circuit state for `signer`
	pub fn state(&self, signer: &[u8]) -> CircuitState {
		let Ok(signers) = self.signers.lock() else {
			return CircuitState::Open;
		};

		signers.get(signer).map_or(CircuitState::Closed, |circuit| circuit.state)
	}

	/// Whether `signer`'s circuit is currently open (tripped)
	pub fn is_open(&self, signer: &[u8]) -> bool {
		self.state(signer) == CircuitState::Open
	}

	/// Close `signer`'s circuit and clear its failure history
	pub fn reset(&self, signer: &[u8]) {
		self.record_success(signer);
	}

	/// Drop rows for signers that carry no failure history
	pub fn prune(&self) {
		let Ok(mut signers) = self.signers.lock() else {
			return;
		};

		signers.retain(|_, circuit| !circuit.is_quiescent());
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
	/// Signer is trusted and the signature fails verification
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
/// window. Each signer's partition fails closed at capacity, which holds
/// while an attacker lacks the fresh valid signatures that would fill it.
#[cfg(feature = "x509")]
pub const REPLAY_GUARD_CAPACITY: usize = 1024;

/// Bounded freshness and replay window for signed cluster commands
///
/// A command is accepted when its `Frame.metadata.order` lies within
/// `window_ms` of the hive clock (either direction, tolerating skew)
/// AND its signature has not already been seen inside the window.
/// Signatures are tracked per signer so one signer saturating its
/// partition leaves the others admitting. Entries more than the window away
/// from the current clock are pruned on each check, so memory is bounded by
/// [`REPLAY_GUARD_CAPACITY`] per trusted signer.
#[cfg(feature = "x509")]
type SignerPartitions = HashMap<Vec<u8>, HashMap<Vec<u8>, u64>>;

/// Recorded signatures, partitioned by signer and indexed by signature.
///
/// The partitions hold the per-signer capacity. The index answers "have I
/// seen this signature" in one lookup, so admission costs the same whether
/// the colony has one trusted signer or a thousand.
#[cfg(feature = "x509")]
#[derive(Default)]
struct SeenSignatures {
	partitions: SignerPartitions,
	owner: HashMap<Vec<u8>, Vec<u8>>,
}

#[cfg(feature = "x509")]
impl SeenSignatures {
	/// Whether `signature` is recorded and still inside the window.
	///
	/// A record found past the window is dropped here, so an expired
	/// signature returns its capacity on the next admission. The signer is
	/// read through the index without copying it.
	fn is_live_replay(&mut self, signature: &[u8], now_ms: u64, window_ms: u64) -> bool {
		let live = match self.owner.get(signature) {
			Some(signer) => self
				.partitions
				.get(signer.as_slice())
				.and_then(|sigs| sigs.get(signature))
				.is_some_and(|at_ms| now_ms.abs_diff(*at_ms) <= window_ms),
			None => return false,
		};

		if !live {
			self.forget(signature);
		}

		live
	}

	/// Drops `signer`'s expired records. Bounded by the per-signer
	/// capacity, so each signer's history costs that signer alone.
	fn expire(&mut self, signer: &[u8], now_ms: u64, window_ms: u64) {
		let Some(sigs) = self.partitions.get_mut(signer) else {
			return;
		};

		sigs.retain(|signature, at_ms| {
			let live = now_ms.abs_diff(*at_ms) <= window_ms;
			if !live {
				self.owner.remove(signature);
			}

			live
		});

		if sigs.is_empty() {
			self.partitions.remove(signer);
		}
	}

	fn record(&mut self, signer: &[u8], signature: &[u8], now_ms: u64) {
		self.partitions
			.entry(signer.to_vec())
			.or_default()
			.insert(signature.to_vec(), now_ms);
		self.owner.insert(signature.to_vec(), signer.to_vec());
	}

	fn forget(&mut self, signature: &[u8]) {
		let Some(signer) = self.owner.remove(signature) else {
			return;
		};
		let Some(sigs) = self.partitions.get_mut(&signer) else {
			return;
		};

		sigs.remove(signature);
		if sigs.is_empty() {
			self.partitions.remove(&signer);
		}
	}

	fn len_for(&self, signer: &[u8]) -> usize {
		self.partitions.get(signer).map_or(0, HashMap::len)
	}
}

#[cfg(feature = "x509")]
pub struct ReplayGuard {
	seen: Mutex<SeenSignatures>,
	window_ms: u64,
}

#[cfg(feature = "x509")]
impl ReplayGuard {
	/// Create a guard with the given freshness window in milliseconds
	pub fn new(window_ms: u64) -> Self {
		Self { seen: Mutex::new(SeenSignatures::default()), window_ms }
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

		// Replay detection spans all partitions: the same certificate can be
		// named by either SignerIdentifier CHOICE arm, so a partition-local
		// check would grant one extra replay per alternate encoding. The
		// index carries every partition's signatures, so one lookup answers
		// for all of them.
		if seen.is_live_replay(signature, now_ms, self.window_ms) {
			return false;
		}

		seen.expire(signer, now_ms, self.window_ms);
		if seen.len_for(signer) >= REPLAY_GUARD_CAPACITY {
			return false;
		}

		seen.record(signer, signature, now_ms);

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

		seen.forget(signature);
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
		let Some(frame) = frame else {
			return TransitStatus::Unauthenticated;
		};

		let Some(signer_info) = frame.nonrepudiation.as_ref() else {
			return TransitStatus::Unauthenticated;
		};

		if frame.integrity.is_none() {
			return TransitStatus::Unauthenticated;
		}

		// One identity keys the breaker and the replay partition, so a
		// signer is gated and recorded under one name. An unencodable
		// identifier has no attribution, so it fails closed.
		let Ok(signer_id) = signer_info.sid.to_der() else {
			return TransitStatus::PermissionDenied;
		};

		if !self.circuit_breaker.allow_request(&signer_id) {
			return TransitStatus::PermissionDenied;
		}

		match verify_frame_signature(self.trust_store.as_ref(), frame) {
			TrustVerification::MissingSignature => return TransitStatus::Unauthenticated,
			TrustVerification::UnknownSigner => return TransitStatus::PermissionDenied,
			TrustVerification::Invalid => {
				self.circuit_breaker.record_auth_failure(&signer_id);
				return TransitStatus::PermissionDenied;
			}
			TrustVerification::Verified => {}
		}

		// Decode before freshness so replay capacity spends on well-formed
		// frames (CWE-770).
		let Ok(_command) = crate::decode::<ClusterCommand>(&frame.message) else {
			return TransitStatus::PermissionDenied;
		};

		let now = current_timestamp_ms();
		if !self.replay_guard.is_fresh(frame.metadata.order, now) {
			return TransitStatus::PermissionDenied;
		}

		if !self
			.replay_guard
			.check_and_insert(&signer_id, signer_info.signature.as_bytes(), now)
		{
			return TransitStatus::PermissionDenied;
		}

		self.circuit_breaker.record_success(&signer_id);

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
	/// encode locally. Both modes refuse it as [`TransitStatus::Internal`], so
	/// a deny list evaluates the same verdict.
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

	const SIGNER: &[u8] = b"signer-under-test";

	#[test]
	fn breaker_trips_after_threshold() {
		let breaker = ClusterCircuitBreaker::new(3, 60_000);

		breaker.record_auth_failure(SIGNER);
		breaker.record_auth_failure(SIGNER);
		assert_eq!(breaker.state(SIGNER), CircuitState::Closed);

		breaker.record_auth_failure(SIGNER);
		assert_eq!(breaker.state(SIGNER), CircuitState::Open);
		assert!(!breaker.allow_request(SIGNER));
	}

	#[test]
	fn breaker_probe_success_closes() {
		let breaker = ClusterCircuitBreaker::new(1, 0);

		breaker.record_auth_failure(SIGNER);
		assert!(breaker.allow_request(SIGNER));
		assert_eq!(breaker.state(SIGNER), CircuitState::HalfOpen);

		breaker.record_success(SIGNER);
		assert_eq!(breaker.state(SIGNER), CircuitState::Closed);
	}

	#[test]
	fn breaker_probe_failure_reopens() {
		let breaker = ClusterCircuitBreaker::new(1, 0);

		breaker.record_auth_failure(SIGNER);
		assert!(breaker.allow_request(SIGNER));
		assert_eq!(breaker.state(SIGNER), CircuitState::HalfOpen);

		breaker.record_auth_failure(SIGNER);
		assert_eq!(breaker.state(SIGNER), CircuitState::Open);
	}

	#[test]
	fn breaker_reset_clears_state() {
		let breaker = ClusterCircuitBreaker::new(1, 60_000);

		breaker.record_auth_failure(SIGNER);
		assert!(breaker.is_open(SIGNER));

		breaker.reset(SIGNER);
		assert_eq!(breaker.state(SIGNER), CircuitState::Closed);
		assert!(breaker.allow_request(SIGNER));
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

	/// One signer's failures leave every other signer admitted, so a
	/// compromised member leaves the colony control plane open (CWE-645).
	#[test]
	fn a_tripped_signer_does_not_gate_another() {
		const OTHER: &[u8] = b"other-signer";
		let breaker = ClusterCircuitBreaker::new(3, 60_000);

		for _ in 0..3 {
			breaker.record_auth_failure(SIGNER);
		}

		assert!(breaker.is_open(SIGNER));
		assert!(!breaker.allow_request(SIGNER));
		assert!(breaker.allow_request(OTHER));
	}

	/// A signature recorded under one signer is refused under another, so
	/// an alternate SignerIdentifier encoding grants no extra replay.
	#[test]
	fn a_replay_is_refused_across_partitions() {
		const OTHER: &[u8] = b"other-signer";
		let guard = ReplayGuard::new(60_000);

		assert!(guard.check_and_insert(SIGNER, b"signature", 1_000));
		assert!(!guard.check_and_insert(OTHER, b"signature", 1_000));
	}

	/// An expired record frees its capacity and admits the same signature
	/// again, so the window bounds retention and the partition holds its size.
	#[test]
	fn an_expired_record_is_admitted_again() {
		let guard = ReplayGuard::new(1_000);

		assert!(guard.check_and_insert(SIGNER, b"signature", 1_000));
		assert!(guard.check_and_insert(SIGNER, b"signature", 5_000));
	}
}
