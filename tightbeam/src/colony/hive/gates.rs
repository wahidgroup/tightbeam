//! Gate policies for hive security and backpressure
//!
//! Contains circuit breaker, replay guard, and security gate implementations
//! for cluster command authentication and capacity management.

use core::sync::atomic::{AtomicU16, Ordering};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;

use crate::colony::common::current_timestamp_ms;
use crate::colony::common::{ClusterCommand, ClusterCommandKind, ReplyShape};
use crate::crypto::x509::store::{CertificateTrust, TrustVerification};
use crate::der::Encode;
use crate::policy::{GatePolicy, ProvenPeer, SessionContext, TransitStatus};
use crate::utils::BasisPoints;
use crate::Frame;
use crate::SignerInfo;

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
	pub fn admit_request(&self, signer: ProvenPeer<'_>) -> bool {
		let Ok(mut signers) = self.signers.lock() else {
			return false;
		};

		let Some(circuit) = signers.get_mut(signer.as_key()) else {
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

	/// Whether a request from `signer` would be admitted right now.
	///
	/// Read-only. A cooldown that has expired reports `true` without
	/// taking the one probe [`ClusterCircuitBreaker::admit_request`]
	/// spends, so asking the question never answers it: a verdict that
	/// consumed the probe would leave the circuit half-open with no
	/// outcome recorded, and half-open admits every later request.
	#[must_use]
	pub fn would_allow(&self, signer: ProvenPeer<'_>) -> bool {
		let Ok(signers) = self.signers.lock() else {
			return false;
		};

		let Some(circuit) = signers.get(signer.as_key()) else {
			return true;
		};

		match circuit.state {
			CircuitState::Closed | CircuitState::HalfOpen => true,
			CircuitState::Open => current_timestamp_ms().saturating_sub(circuit.opened_at) >= self.cooldown_ms,
		}
	}

	/// Record a successful request from `signer`
	pub fn record_success(&self, signer: ProvenPeer<'_>) {
		let Ok(mut signers) = self.signers.lock() else {
			return;
		};

		signers.remove(signer.as_key());
	}

	/// Record an authentication failure attributed to `signer`
	///
	/// A failure while half-open re-opens immediately and restarts the
	/// cooldown.
	pub fn record_auth_failure(&self, signer: ProvenPeer<'_>) {
		let Ok(mut signers) = self.signers.lock() else {
			return;
		};

		let circuit = signers.entry(signer.as_key().to_vec()).or_insert(SignerCircuit::CLOSED);
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
	pub fn state(&self, signer: ProvenPeer<'_>) -> CircuitState {
		let Ok(signers) = self.signers.lock() else {
			return CircuitState::Open;
		};

		signers
			.get(signer.as_key())
			.map_or(CircuitState::Closed, |circuit| circuit.state)
	}

	/// Whether `signer`'s circuit is currently open (tripped)
	pub fn is_open(&self, signer: ProvenPeer<'_>) -> bool {
		self.state(signer) == CircuitState::Open
	}

	/// Close `signer`'s circuit and clear its failure history
	pub fn reset(&self, signer: ProvenPeer<'_>) {
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
// Replay Guard
// ============================================================================

/// Maximum distinct signatures remembered per signer per freshness window
///
/// Legitimate traffic is bounded by a signer's command rate inside one
/// window. Each signer's partition fails closed at capacity, which holds
/// while an attacker lacks the fresh valid signatures that would fill it.
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
type SignerPartitions = HashMap<Vec<u8>, HashMap<Vec<u8>, u64>>;

/// Recorded signatures, partitioned by signer and indexed by signature.
///
/// The partitions hold the per-signer capacity. The index answers "have I
/// seen this signature" in one lookup, so admission costs the same whether
/// the colony has one trusted signer or a thousand.
#[derive(Default)]
struct SeenSignatures {
	partitions: SignerPartitions,
	owner: HashMap<Vec<u8>, Vec<u8>>,
}

impl SeenSignatures {
	/// Whether `signature` is recorded and still inside the window.
	/// Whether `signature` is recorded and still inside the window.
	///
	/// Read-only, so a verdict can ask without changing what a later
	/// admission sees. The signer is read through the index without
	/// copying it.
	fn is_live(&self, signature: impl AsRef<[u8]>, now_ms: u64, window_ms: u64) -> bool {
		let signature = signature.as_ref();
		self.owner
			.get(signature)
			.and_then(|signer| self.partitions.get(signer.as_slice()))
			.and_then(|sigs| sigs.get(signature))
			.is_some_and(|at_ms| now_ms.abs_diff(*at_ms) <= window_ms)
	}

	///
	/// A record found past the window is dropped here, so an expired
	/// signature returns its capacity on the next admission. The signer is
	/// read through the index without copying it.
	fn is_live_replay(&mut self, signature: impl AsRef<[u8]>, now_ms: u64, window_ms: u64) -> bool {
		let signature = signature.as_ref();
		if !self.owner.contains_key(signature) {
			return false;
		}

		let live = self.is_live(signature, now_ms, window_ms);
		if !live {
			self.forget(signature);
		}

		live
	}

	/// Drops `signer`'s expired records. Bounded by the per-signer
	/// capacity, so each signer's history costs that signer alone.
	fn expire(&mut self, signer: impl AsRef<[u8]>, now_ms: u64, window_ms: u64) {
		let signer = signer.as_ref();
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

	fn record(&mut self, signer: impl AsRef<[u8]>, signature: impl AsRef<[u8]>, now_ms: u64) {
		let signer = signer.as_ref();
		let signature = signature.as_ref();
		self.partitions
			.entry(signer.to_vec())
			.or_default()
			.insert(signature.to_vec(), now_ms);
		self.owner.insert(signature.to_vec(), signer.to_vec());
	}

	fn forget(&mut self, signature: impl AsRef<[u8]>) {
		let signature = signature.as_ref();
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

	fn len_for(&self, signer: impl AsRef<[u8]>) -> usize {
		let signer = signer.as_ref();
		self.partitions.get(signer).map_or(0, HashMap::len)
	}
}

pub struct ReplayGuard {
	seen: Mutex<SeenSignatures>,
	window_ms: u64,
}

impl ReplayGuard {
	/// Create a guard with the given freshness window in milliseconds
	pub fn new(window_ms: u64) -> Self {
		Self { seen: Mutex::new(SeenSignatures::default()), window_ms }
	}

	/// Whether `order_ms` (`Frame.metadata.order`) is within the freshness window of `now_ms`
	pub fn is_fresh(&self, order_ms: u64, now_ms: u64) -> bool {
		now_ms.abs_diff(order_ms) <= self.window_ms
	}

	/// Whether `signature` was already recorded within the window.
	///
	/// Read-only. A verdict asks this; the admission that follows spends
	/// the slot with [`ReplayGuard::check_and_insert`]. A poisoned lock
	/// answers `true`, so a verdict fails closed the way an admission does.
	#[must_use]
	pub fn is_replay(&self, signature: impl AsRef<[u8]>, now_ms: u64) -> bool {
		let signature = signature.as_ref();
		let Ok(seen) = self.seen.lock() else {
			return true;
		};

		seen.is_live(signature, now_ms, self.window_ms)
	}

	/// Record `signature` for `signer` if unseen within the window
	///
	/// Returns `true` when the signature is new (and now recorded).
	/// Returns `false` for replays, and fails closed when the signer's
	/// partition is at capacity or the lock is poisoned.
	pub fn check_and_insert(&self, signer: impl AsRef<[u8]>, signature: impl AsRef<[u8]>, now_ms: u64) -> bool {
		let signer = signer.as_ref();
		let signature = signature.as_ref();
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
	pub fn forget(&self, signature: impl AsRef<[u8]>) {
		let signature = signature.as_ref();
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
/// Only step 5 counts toward the circuit breaker, and it counts against
/// the [`ProvenPeer`] the transport handshake established, so one member's
/// failures gate that member alone (CWE-645). Steps 6-7 stay uncounted,
/// because a replayed capture still carries a valid signature.
pub struct ClusterSecurityGate {
	/// Circuit breaker for tracking auth failures
	circuit_breaker: Arc<ClusterCircuitBreaker>,
	/// Trust store for certificate lookup and signature verification
	trust_store: Arc<dyn CertificateTrust>,
	/// Freshness window and replay set for signed commands
	replay_guard: Arc<ReplayGuard>,
}

/// A cluster command this gate has authenticated and decoded.
///
/// The body is the alternative the CHOICE proved during admission, so a
/// dispatcher matches it rather than reading the optional fields again.
/// `signer` is the nonrepudiation signer the signature check accepted.
#[derive(Debug)]
pub(crate) struct AdmittedCommand {
	body: ClusterCommandKind,
	frame: Frame,
	signer: SignerInfo,
}

impl AdmittedCommand {
	/// Whether the admitted command is a heartbeat.
	pub(crate) fn is_heartbeat(&self) -> bool {
		matches!(self.body, ClusterCommandKind::Heartbeat(_))
	}

	/// The alternative admission proved.
	pub(crate) fn body(&self) -> &ClusterCommandKind {
		&self.body
	}

	/// The frame the command arrived on.
	pub(crate) fn frame(&self) -> &Frame {
		&self.frame
	}

	/// The signer the signature check accepted.
	pub(crate) fn signer(&self) -> &SignerInfo {
		&self.signer
	}
}

/// A frame this gate refused, with the reply shape of its command body.
#[derive(Debug)]
pub(crate) struct AdmitRefusal {
	frame: Frame,
	status: TransitStatus,
	shape: ReplyShape,
}

impl AdmitRefusal {
	/// Refuse `frame` with `status`, reading its reply shape from one
	/// decode of the command body.
	///
	/// A body that names no single alternative has no heartbeat shape, so
	/// the refusal answers in the management shape.
	pub(crate) fn denied(frame: Frame, status: TransitStatus) -> Box<Self> {
		let body = crate::decode::<ClusterCommand>(frame.message())
			.ok()
			.and_then(|command| command.into_choice().ok());
		let shape = ReplyShape::of(body.as_ref());

		Self::boxed(frame, status, shape)
	}

	fn boxed(frame: Frame, status: TransitStatus, shape: ReplyShape) -> Box<Self> {
		Box::new(Self { frame, status, shape })
	}

	/// The status the control plane answers with.
	pub(crate) fn status(&self) -> TransitStatus {
		self.status
	}

	/// The shape the refusal answers in.
	pub(crate) fn shape(&self) -> ReplyShape {
		self.shape
	}

	/// The frame the refusal answers.
	pub(crate) fn frame(&self) -> &Frame {
		&self.frame
	}
}

/// What the non-spending checks proved about one frame.
///
/// Held between [`ClusterSecurityGate::inspect`] and the steps that spend,
/// so the spending steps do not re-derive any of it.
struct Authenticated<'a> {
	signer: SignerInfo,
	signer_id: Vec<u8>,
	breaker_key: ProvenPeer<'a>,
}

/// Why [`ClusterSecurityGate::inspect`] refused a frame.
///
/// A bad signature is the one refusal an admission counts against the
/// breaker, so it is a variant rather than a status: the verdict reports
/// it without recording anything, and the admission records it once.
enum InspectRefusal {
	/// Refused before, or independently of, judging the signature.
	Plain(TransitStatus),
	/// The signature did not verify against the trust store.
	BadSignature,
}

impl InspectRefusal {
	/// The status a caller answers the sender with.
	fn status(&self) -> TransitStatus {
		match self {
			Self::Plain(status) => *status,
			Self::BadSignature => TransitStatus::PermissionDenied,
		}
	}
}

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

	/// Judge `frame` without spending anything it judges.
	///
	/// Every refusal [`ClusterSecurityGate::admit`] can give is given here,
	/// replay included: a captured frame is refused because the signature
	/// is already recorded, not because asking recorded it. What this does
	/// not do is take the breaker's cooldown probe, record an auth failure,
	/// insert the signature, or record a success. Those belong to the one
	/// admission.
	fn inspect<'a>(
		&self,
		frame: &Frame,
		session: &'a SessionContext,
		now: u64,
	) -> Result<Authenticated<'a>, InspectRefusal> {
		let Some(signer) = frame.nonrepudiation().cloned() else {
			return Err(InspectRefusal::Plain(TransitStatus::Unauthenticated));
		};

		if frame.integrity().is_none() {
			return Err(InspectRefusal::Plain(TransitStatus::Unauthenticated));
		}

		// The replay partition keys on the signer, which the verification
		// below proves. An unencodable identifier has no attribution, so
		// it fails closed.
		let Ok(signer_id) = signer.sid.to_der() else {
			return Err(InspectRefusal::Plain(TransitStatus::PermissionDenied));
		};

		// The breaker keys on the handshake-proven peer, because a failure
		// reached here before the signature was checked. [`ProvenPeer`] is
		// the only key the breaker accepts, so a caller who copies a
		// trusted `SignerIdentifier` spends its own budget (CWE-345).
		//
		// An unauthenticated transport offers no such key. Sharing one row
		// across every anonymous caller would let a single bad signature
		// deny the rest, so this plane requires a proven peer (CWE-645).
		let Some(breaker_key) = session.proven_peer() else {
			return Err(InspectRefusal::Plain(TransitStatus::Unauthenticated));
		};

		if !self.circuit_breaker.would_allow(breaker_key) {
			return Err(InspectRefusal::Plain(TransitStatus::PermissionDenied));
		}

		match self.trust_store.verify_frame(frame) {
			TrustVerification::MissingSignature => {
				return Err(InspectRefusal::Plain(TransitStatus::Unauthenticated));
			}
			TrustVerification::UnknownSigner => {
				return Err(InspectRefusal::Plain(TransitStatus::PermissionDenied));
			}
			TrustVerification::Invalid => return Err(InspectRefusal::BadSignature),
			TrustVerification::Verified(_) => {}
		}

		// Freshness and replay are checked here so a verdict refuses a
		// captured frame (CWE-294). The slot itself is spent in `admit`.
		if !self.replay_guard.is_fresh(frame.metadata().order(), now) {
			return Err(InspectRefusal::Plain(TransitStatus::PermissionDenied));
		}
		if self.replay_guard.is_replay(signer.signature.as_bytes(), now) {
			return Err(InspectRefusal::Plain(TransitStatus::PermissionDenied));
		}

		Ok(Authenticated { signer, signer_id, breaker_key })
	}

	/// Authenticate `frame`, decode its cluster command once, and spend the
	/// admission.
	///
	/// This is the consuming step: it takes the breaker's cooldown probe,
	/// records an auth failure or a success against it, and spends the
	/// replay slot for the signature. The control plane calls it exactly
	/// once per frame.
	pub(crate) fn admit(&self, frame: Frame, session: &SessionContext) -> Result<AdmittedCommand, Box<AdmitRefusal>> {
		// One decode, and one proof of the CHOICE the body spells as tagged
		// optional fields. A body that names none or several is not a
		// command, so nothing downstream sees the ambiguous form.
		let body = crate::decode::<ClusterCommand>(frame.message())
			.ok()
			.and_then(|command| command.into_choice().ok());

		let shape = ReplyShape::of(body.as_ref());
		let now = current_timestamp_ms();
		let authenticated = match self.inspect(&frame, session, now) {
			Ok(authenticated) => authenticated,
			Err(refusal) => {
				// A bad signature counts once, here, where the frame was
				// actually submitted for admission.
				if let (InspectRefusal::BadSignature, Some(breaker_key)) = (&refusal, session.proven_peer()) {
					self.circuit_breaker.record_auth_failure(breaker_key);
				}

				return Err(AdmitRefusal::boxed(frame, refusal.status(), shape));
			}
		};

		// Replay capacity spends on well-formed frames (CWE-770). A body
		// that does not decode, or that names no single alternative, is
		// malformed rather than unauthorized: the sender's own request is
		// wrong whatever this hive's state is.
		let Some(body) = body else {
			return Err(AdmitRefusal::boxed(frame, TransitStatus::InvalidArgument, shape));
		};

		let Authenticated { signer, signer_id, breaker_key } = authenticated;
		if !self.circuit_breaker.admit_request(breaker_key) {
			return Err(AdmitRefusal::boxed(frame, TransitStatus::PermissionDenied, shape));
		}
		if !self.replay_guard.check_and_insert(&signer_id, signer.signature.as_bytes(), now) {
			return Err(AdmitRefusal::boxed(frame, TransitStatus::PermissionDenied, shape));
		}

		self.circuit_breaker.record_success(breaker_key);

		Ok(AdmittedCommand { body, frame, signer })
	}
}

impl GatePolicy for ClusterSecurityGate {
	/// Whether this frame would be admitted, without spending the
	/// admission.
	///
	/// A verdict must not consume what it judges: a transport that gates
	/// on this and then hands the frame to the control plane would
	/// otherwise see its own admission refused as a replay, and would burn
	/// the breaker's cooldown probe on a question rather than an answer.
	/// A captured frame is still refused here, because the signature it
	/// carries is already recorded (CWE-294).
	fn evaluate(&self, frame: Option<&Frame>, session: &SessionContext) -> TransitStatus {
		let Some(frame) = frame else {
			return TransitStatus::Unauthenticated;
		};

		match self.inspect(frame, session, current_timestamp_ms()) {
			Ok(_) => TransitStatus::Ok,
			Err(refusal) => refusal.status(),
		}
	}
}

/// One reading of a hive's load, and the verdict that describes it.
///
/// The pair comes from one atomic load, so a caller reporting both cannot
/// name a utilization that disagrees with the status beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackpressureReport {
	/// Hive-wide utilization at the moment of the read.
	pub utilization: BasisPoints,
	/// Whether the hive is taking work at that utilization.
	pub status: TransitStatus,
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

	/// Whether the hive is taking work at the current utilization.
	///
	/// This is the one comparison of utilization against the threshold. The
	/// gate answers requests with it, and the heartbeat reports the same
	/// verdict, so a hive can never refuse work while reporting capacity.
	#[must_use]
	pub fn status(&self) -> TransitStatus {
		self.report().status
	}

	/// The utilization and the verdict that describes it.
	///
	/// Both come from one load, so a heartbeat cannot report capacity that
	/// disagrees with the status beside it.
	#[must_use]
	pub fn report(&self) -> BackpressureReport {
		let utilization = self.current_utilization();
		let status = if utilization.get() >= self.threshold.get() {
			TransitStatus::ResourceExhausted
		} else {
			TransitStatus::Ok
		};

		BackpressureReport { utilization, status }
	}
}

impl GatePolicy for BackpressureGate {
	fn evaluate(&self, _frame: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		self.status()
	}
}

// ============================================================================
// Peer List Gate
// ============================================================================

/// Membership mode of a [`PeerListGate`].
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
#[derive(Clone)]
pub struct PeerListGate {
	keys: HashSet<Vec<u8>>,
	mode: PeerListMode,
}

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

impl GatePolicy for PeerListGate {
	fn evaluate(&self, _message: Option<&Frame>, session: &SessionContext) -> TransitStatus {
		self.admit(session.peer_certificate().is_some(), session.peer_public_key())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const SIGNER: &[u8] = b"signer-under-test";

	/// The identity under test, as a handshake would prove it.
	fn signer() -> ProvenPeer<'static> {
		ProvenPeer::for_test(SIGNER)
	}

	/// A second proven identity, for isolation assertions.
	fn other() -> ProvenPeer<'static> {
		ProvenPeer::for_test(b"other-signer")
	}

	#[test]
	fn breaker_trips_after_threshold() {
		let breaker = ClusterCircuitBreaker::new(3, 60_000);
		breaker.record_auth_failure(signer());
		breaker.record_auth_failure(signer());

		assert_eq!(breaker.state(signer()), CircuitState::Closed);

		breaker.record_auth_failure(signer());

		assert_eq!(breaker.state(signer()), CircuitState::Open);
		assert!(!breaker.admit_request(signer()));
	}

	#[test]
	fn breaker_probe_success_closes() {
		let breaker = ClusterCircuitBreaker::new(1, 0);
		breaker.record_auth_failure(signer());

		assert!(breaker.admit_request(signer()));
		assert_eq!(breaker.state(signer()), CircuitState::HalfOpen);

		breaker.record_success(signer());

		assert_eq!(breaker.state(signer()), CircuitState::Closed);
	}

	#[test]
	fn breaker_probe_failure_reopens() {
		let breaker = ClusterCircuitBreaker::new(1, 0);
		breaker.record_auth_failure(signer());

		assert!(breaker.admit_request(signer()));
		assert_eq!(breaker.state(signer()), CircuitState::HalfOpen);

		breaker.record_auth_failure(signer());

		assert_eq!(breaker.state(signer()), CircuitState::Open);
	}

	#[test]
	fn breaker_reset_clears_state() {
		let breaker = ClusterCircuitBreaker::new(1, 60_000);
		breaker.record_auth_failure(signer());

		assert!(breaker.is_open(signer()));

		breaker.reset(signer());

		assert_eq!(breaker.state(signer()), CircuitState::Closed);
		assert!(breaker.admit_request(signer()));
	}

	#[test]
	fn replay_guard_accepts_first_rejects_second() {
		let guard = ReplayGuard::new(30_000);
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 1_000));
		assert!(!guard.check_and_insert(b"signer-1", b"sig-a", 2_000));
		assert!(guard.check_and_insert(b"signer-1", b"sig-b", 2_000));
	}

	#[test]
	fn replay_guard_prunes_expired_entries() {
		let guard = ReplayGuard::new(1_000);
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 1_000));
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 3_000));
	}

	#[test]
	fn replay_guard_prunes_future_dated_entries_after_clock_regression() {
		let guard = ReplayGuard::new(1_000);
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 10_000));
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 5_000));
	}

	#[test]
	fn replay_guard_saturated_signer_does_not_block_others() {
		let guard = ReplayGuard::new(30_000);
		let seeded = (0..REPLAY_GUARD_CAPACITY).all(|i| guard.check_and_insert(b"signer-1", i.to_be_bytes(), 1_000));
		assert!(seeded);
		assert!(!guard.check_and_insert(b"signer-1", b"sig-overflow", 1_000));
		assert!(guard.check_and_insert(b"signer-2", b"sig-a", 1_000));
	}

	#[test]
	fn replay_guard_rejects_replay_across_signer_partitions() {
		let guard = ReplayGuard::new(30_000);
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 1_000));
		assert!(!guard.check_and_insert(b"signer-2", b"sig-a", 1_000));
	}

	#[test]
	fn replay_guard_forget_permits_retry() {
		let guard = ReplayGuard::new(30_000);
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 1_000));
		guard.forget(b"sig-a");
		assert!(guard.check_and_insert(b"signer-1", b"sig-a", 2_000));
	}

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
		let mut builder = crate::Version::V2
			.compose()
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

	#[test]
	fn peer_allow_list_admits_listed_key_only() {
		let gate = PeerListGate::allow([b"key-a".to_vec()]);
		assert_eq!(gate.admit(true, Some(b"key-a")), TransitStatus::Ok);
		assert_eq!(gate.admit(true, Some(b"key-b")), TransitStatus::PermissionDenied);
	}

	#[test]
	fn peer_allow_list_fails_closed_without_identity() {
		let gate = PeerListGate::allow([b"key-a".to_vec()]);
		assert_eq!(gate.admit(false, None), TransitStatus::Unauthenticated);
	}

	#[test]
	fn peer_deny_list_refuses_listed_key_only() {
		let gate = PeerListGate::deny([b"key-a".to_vec()]);
		assert_eq!(gate.admit(true, Some(b"key-a")), TransitStatus::PermissionDenied);
		assert_eq!(gate.admit(true, Some(b"key-b")), TransitStatus::Ok);
	}

	#[test]
	fn peer_deny_list_admits_absent_identity() {
		let gate = PeerListGate::deny([b"key-a".to_vec()]);
		assert_eq!(gate.admit(false, None), TransitStatus::Ok);
	}

	#[test]
	fn peer_list_refuses_certified_peer_without_spki() {
		let allow = PeerListGate::allow([b"key-a".to_vec()]);
		let deny = PeerListGate::deny([b"key-a".to_vec()]);
		assert_eq!(allow.admit(true, None), TransitStatus::Internal);
		assert_eq!(deny.admit(true, None), TransitStatus::Internal);
	}

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

	/// Trust store that resolves every signer and fails every signature,
	/// which drives [`crate::crypto::x509::store::TrustVerification::Invalid`]
	/// deterministically.
	#[derive(Debug)]
	struct AlwaysInvalid {
		certificate: crate::crypto::x509::Certificate,
	}

	impl crate::crypto::x509::policy::CertificateValidation for AlwaysInvalid {
		fn evaluate(
			&self,
			_cert: &crate::crypto::x509::Certificate,
		) -> Result<(), crate::crypto::x509::error::CertificateValidationError> {
			Ok(())
		}
	}

	impl crate::crypto::policy::VerificationPolicy for AlwaysInvalid {
		fn verify_signature(
			&self,
			_algorithm: &crate::der::asn1::ObjectIdentifier,
			_public_key_der: &[u8],
			_message: &[u8],
			_signature: &[u8],
		) -> Result<(), crate::crypto::x509::error::CertificateValidationError> {
			Err(
				crate::crypto::x509::error::CertificateValidationError::SignatureVerificationFailed(
					signature::Error::new(),
				),
			)
		}
	}

	impl CertificateTrust for AlwaysInvalid {
		fn is_trusted(&self, _cert: &crate::crypto::x509::Certificate) -> bool {
			true
		}

		fn verify_chain(
			&self,
			_chain: &[crate::crypto::x509::Certificate],
		) -> Result<(), crate::crypto::x509::error::CertificateValidationError> {
			Ok(())
		}

		fn find_by_signer_identifier(
			&self,
			_sid: &crate::cms::signed_data::SignerIdentifier,
		) -> Option<&crate::crypto::x509::Certificate> {
			Some(&self.certificate)
		}

		fn to_policy_ref(&self) -> &dyn crate::crypto::policy::VerificationPolicy {
			self
		}
	}

	/// Trust store that resolves every signer and accepts every signature,
	/// which drives
	/// [`crate::crypto::x509::store::TrustVerification::Verified`]
	/// deterministically.
	#[derive(Debug)]
	struct AlwaysVerified {
		certificate: crate::crypto::x509::Certificate,
	}

	impl crate::crypto::x509::policy::CertificateValidation for AlwaysVerified {
		fn evaluate(
			&self,
			_cert: &crate::crypto::x509::Certificate,
		) -> Result<(), crate::crypto::x509::error::CertificateValidationError> {
			Ok(())
		}
	}

	impl crate::crypto::policy::VerificationPolicy for AlwaysVerified {
		fn verify_signature(
			&self,
			_algorithm: &crate::der::asn1::ObjectIdentifier,
			_public_key_der: &[u8],
			_message: &[u8],
			_signature: &[u8],
		) -> Result<(), crate::crypto::x509::error::CertificateValidationError> {
			Ok(())
		}
	}

	impl CertificateTrust for AlwaysVerified {
		fn is_trusted(&self, _cert: &crate::crypto::x509::Certificate) -> bool {
			true
		}

		fn verify_chain(
			&self,
			_chain: &[crate::crypto::x509::Certificate],
		) -> Result<(), crate::crypto::x509::error::CertificateValidationError> {
			Ok(())
		}

		fn find_by_signer_identifier(
			&self,
			_sid: &crate::cms::signed_data::SignerIdentifier,
		) -> Option<&crate::crypto::x509::Certificate> {
			Some(&self.certificate)
		}

		fn to_policy_ref(&self) -> &dyn crate::crypto::policy::VerificationPolicy {
			self
		}
	}

	/// A gate that verifies a frame and a session that proves its peer,
	/// which is the arrangement every admission question is asked under.
	async fn verified_gate() -> Result<(ClusterSecurityGate, SessionContext, Frame), crate::TightBeamError> {
		verified_gate_with_breaker(ClusterCircuitBreaker::new(3, 60_000)).await
	}

	/// [`verified_gate`] with a breaker the caller has tuned.
	async fn verified_gate_with_breaker(
		breaker: ClusterCircuitBreaker,
	) -> Result<(ClusterSecurityGate, SessionContext, Frame), crate::TightBeamError> {
		use crate::builder::TypeBuilder;

		let signing_key = crate::testing::fixtures::TestKey::signing();
		let certificate = crate::testing::fixtures::TestCertificate::self_signed(&signing_key);
		let provider = crate::crypto::key::Secp256k1KeyProvider::from(signing_key);

		let probe = ClusterCommandKind::Heartbeat(crate::colony::common::HeartbeatParams {
			cluster_status: crate::colony::common::ClusterStatus::Healthy,
		});

		let mut signed = crate::Version::V2
			.compose()
			.with_id(b"command")
			.with_order(current_timestamp_ms())
			.with_message(ClusterCommand::from(probe))
			.with_witness_hasher::<crate::crypto::hash::Sha3_256>()
			.build()?;
		signed.sign_with_provider::<crate::crypto::hash::Sha3_256, _>(&provider).await?;

		let gate = ClusterSecurityGate::new(
			Arc::new(breaker),
			Arc::new(AlwaysVerified { certificate: certificate.clone() }),
			Arc::new(ReplayGuard::new(60_000)),
		);

		Ok((gate, SessionContext::for_peer(Arc::new(certificate)), signed))
	}

	/// A verdict judges a frame without spending it, so the control plane
	/// that gated on the verdict can still admit the same frame.
	#[tokio::test]
	async fn a_gate_verdict_leaves_the_admission_unspent() -> Result<(), crate::TightBeamError> {
		let (gate, sender, signed) = verified_gate().await?;
		assert_eq!(gate.evaluate(Some(&signed), &sender), TransitStatus::Ok);
		assert_eq!(gate.evaluate(Some(&signed), &sender), TransitStatus::Ok);
		assert!(gate.admit(signed, &sender).is_ok());
		Ok(())
	}

	/// A verdict still refuses a captured frame, because the signature the
	/// frame carries is already recorded (CWE-294).
	#[tokio::test]
	async fn a_gate_verdict_refuses_a_frame_already_admitted() -> Result<(), crate::TightBeamError> {
		let (gate, sender, signed) = verified_gate().await?;
		assert!(gate.admit(signed.to_owned(), &sender).is_ok());
		assert_eq!(gate.evaluate(Some(&signed), &sender), TransitStatus::PermissionDenied);
		Ok(())
	}

	/// A verdict leaves a tripped breaker's one cooldown probe for the
	/// admission to take. Spending it on a question parks the circuit
	/// half-open with no outcome recorded, and half-open admits every
	/// request that follows.
	#[tokio::test]
	async fn a_gate_verdict_does_not_take_the_breakers_cooldown_probe() -> Result<(), crate::TightBeamError> {
		let (gate, sender, signed) = verified_gate_with_breaker(ClusterCircuitBreaker::new(1, 0)).await?;
		let peer_key = sender.peer_public_key().expect("the session carries a peer key").to_vec();
		let breaker_key = || ProvenPeer::for_test(&peer_key);

		gate.circuit_breaker.record_auth_failure(breaker_key());
		assert!(gate.circuit_breaker.is_open(breaker_key()));

		// The cooldown has expired, so the verdict admits. It must not be
		// the one that spends the probe.
		assert_eq!(gate.evaluate(Some(&signed), &sender), TransitStatus::Ok);
		assert!(gate.circuit_breaker.is_open(breaker_key()));

		assert!(gate.admit(signed, &sender).is_ok());
		assert!(!gate.circuit_breaker.is_open(breaker_key()));

		Ok(())
	}

	/// A caller who copies a trusted `SignerIdentifier` and attaches a bad
	/// signature is counted against its own transport peer, so the copied
	/// signer keeps its budget (CWE-345).
	///
	/// The count runs through `admit`, because that is where a frame is
	/// submitted. A verdict judges the same frame without counting it.
	#[tokio::test]
	async fn a_forged_signer_id_gates_the_sender_not_the_signer() -> Result<(), crate::TightBeamError> {
		use crate::builder::TypeBuilder;

		let signing_key = crate::testing::fixtures::TestKey::signing();
		let certificate = crate::testing::fixtures::TestCertificate::self_signed(&signing_key);
		let provider = crate::crypto::key::EcdsaKeyProvider::from(signing_key.clone());

		let mut signed = crate::Version::V2
			.compose()
			.with_id(b"control")
			.with_order(current_timestamp_ms())
			.with_message(crate::testing::TestMessage { content: "payload".into() })
			.with_witness_hasher::<crate::crypto::hash::Sha3_256>()
			.build()?;
		signed.sign_with_provider::<crate::crypto::hash::Sha3_256, _>(&provider).await?;

		let signer_id = signed.signer_id().expect("the signed frame carries a signer id");
		let breaker = Arc::new(ClusterCircuitBreaker::new(3, 60_000));
		let gate = ClusterSecurityGate::new(
			Arc::clone(&breaker),
			Arc::new(AlwaysInvalid { certificate: certificate.clone() }),
			Arc::new(ReplayGuard::new(60_000)),
		);

		let sender = SessionContext::for_peer(Arc::new(certificate));
		let sender_key = sender.peer_public_key().expect("the session carries a peer key").to_vec();
		let refusals = [
			gate.admit(signed.to_owned(), &sender).err().map(|refusal| refusal.status()),
			gate.admit(signed.to_owned(), &sender).err().map(|refusal| refusal.status()),
			gate.admit(signed.to_owned(), &sender).err().map(|refusal| refusal.status()),
		];

		assert_eq!(refusals, [Some(TransitStatus::PermissionDenied); 3]);
		assert!(breaker.is_open(ProvenPeer::for_test(&sender_key)));
		assert!(!breaker.is_open(ProvenPeer::for_test(&signer_id)));

		Ok(())
	}

	/// One signer's failures leave every other signer admitted, so a
	/// compromised member leaves the colony control plane open (CWE-645).
	#[test]
	fn a_tripped_signer_does_not_gate_another() {
		let breaker = ClusterCircuitBreaker::new(3, 60_000);
		for _ in 0..3 {
			breaker.record_auth_failure(signer());
		}

		assert!(breaker.is_open(signer()));
		assert!(!breaker.admit_request(signer()));
		assert!(breaker.admit_request(other()));
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
