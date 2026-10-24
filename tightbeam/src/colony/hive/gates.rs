//! The gate policies for hive security and backpressure.
//!
//! - [`ClusterSecurityGate`] authenticates cluster commands. It builds its
//!   [`ClusterCircuitBreaker`] and its [`ReplayGuard`] on one clock.
//! - [`BackpressureGate`] refuses work while the hive runs at its capacity threshold.
//! - [`PeerListGate`] admits or refuses a session by its peer certificate key.

use core::sync::atomic::{AtomicU16, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::colony::common::{ClusterCommand, ClusterCommandKind, ClusterCommandResponse, IssuedAt, ReplyShape};
use crate::crypto::sign::VerifiedSignature;
use crate::crypto::x509::store::{CertificateTrust, TrustVerification};
use crate::crypto::x509::{CanonicalKey, KeyCurves, KeyList, KeyListError};
use crate::der::Encode;
use crate::policy::{GatePolicy, ProvenPeer, SessionContext, TransitStatus};
use crate::utils::time::{Clock, MonotonicInstant, UnixMillis};
use crate::utils::BasisPoints;
use crate::{Frame, TightBeamError};

/// The states of one signer's circuit in a [`ClusterCircuitBreaker`].
///
/// The breaker follows the standard circuit breaker pattern, which halts
/// communication with a signer after repeated authentication failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitState {
	/// The circuit admits requests in normal operation.
	Closed = 0,
	/// The circuit has tripped and rejects every request.
	Open = 1,
	/// The circuit admits probe requests to test recovery, and the next
	/// outcome closes or reopens it.
	HalfOpen = 2,
}

/// Circuit breaker for cluster authentication failures.
///
/// It trips after consecutive auth failures, which halts cluster communication
/// with that signer, and after a cooldown it moves to half-open to let one
/// probe through. The breaker measures the cooldown on the monotonic reading of
/// the clock it is given, so a step of the system time neither shortens nor
/// stretches it.
///
/// # Failures that count
///
/// Only failures attributable to a *known* signer count toward the threshold
/// (see [`ClusterSecurityGate`]), so unauthenticated garbage cannot sever the
/// control plane between a hive and its legitimate cluster (CWE-645).
///
/// # Thread Safety
///
/// Per-signer circuits live under one mutex, so the transition from open to
/// half-open happens under the lock and exactly one caller performs it per
/// cooldown expiry.
pub struct ClusterCircuitBreaker {
	/// Per-signer circuits, one row for each signer that has a failure history.
	///
	/// A poisoned lock answers every signer as open, so the breaker fails
	/// closed the way the replay guard does.
	signers: Mutex<HashMap<CanonicalKey, SignerCircuit>>,
	/// The count of consecutive failures that trips a signer's circuit.
	failure_threshold: u8,
	/// Time an open circuit waits before it lets one probe through.
	cooldown: Duration,
	/// The clock the cooldown is measured on.
	clock: Arc<dyn Clock>,
}

/// Where one signer's circuit stands.
///
/// An open circuit carries the instant it opened, so every open circuit has
/// a start for its cooldown.
#[derive(Clone, Copy)]
enum Position {
	Closed,
	Open(MonotonicInstant),
	HalfOpen,
}

impl Position {
	fn state(self) -> CircuitState {
		match self {
			Self::Closed => CircuitState::Closed,
			Self::Open(_) => CircuitState::Open,
			Self::HalfOpen => CircuitState::HalfOpen,
		}
	}
}

/// One signer's breaker position.
#[derive(Clone, Copy)]
struct SignerCircuit {
	position: Position,
	failures: u8,
}

impl SignerCircuit {
	const CLOSED: Self = Self { position: Position::Closed, failures: 0 };

	/// Whether this circuit is closed with no failures. Such a circuit carries
	/// no history, so [`ClusterCircuitBreaker::prune`] drops its row and the
	/// map stays bounded by the signers currently failing.
	const fn is_quiescent(&self) -> bool {
		matches!(self.position, Position::Closed) && self.failures == 0
	}
}

impl ClusterCircuitBreaker {
	/// A breaker that opens after `failure_threshold` consecutive failures from
	/// one signer and lets one probe through once `cooldown` has passed on
	/// `clock`.
	pub fn new(failure_threshold: u8, cooldown: Duration, clock: Arc<dyn Clock>) -> Self {
		Self { signers: Mutex::new(HashMap::new()), failure_threshold, cooldown, clock }
	}

	/// Whether a circuit that opened at `opened_at` has cooled down.
	fn cooled(&self, opened_at: MonotonicInstant) -> bool {
		self.clock.monotonic().saturating_duration_since(opened_at) >= self.cooldown
	}

	/// Admits or refuses one request from `signer`.
	///
	/// It returns `true` while that signer's circuit is closed or half-open.
	/// An open circuit whose cooldown has passed moves to half-open and admits
	/// this request as its probe. Each signer's failures gate that signer
	/// alone, so the colony control plane stays open to every other member
	/// (CWE-645). A poisoned lock refuses every request.
	pub fn admit_request(&self, signer: ProvenPeer<'_>) -> bool {
		let Ok(mut signers) = self.signers.lock() else {
			return false;
		};

		let Some(circuit) = signers.get_mut(signer.as_key()) else {
			return true;
		};

		match circuit.position {
			Position::Closed | Position::HalfOpen => true,
			Position::Open(opened_at) => {
				if !self.cooled(opened_at) {
					return false;
				}

				// The guard serialises concurrent callers racing the same
				// cooldown expiry, so exactly one probe is admitted.
				circuit.position = Position::HalfOpen;

				true
			}
		}
	}

	/// Whether a request from `signer` would be admitted right now.
	///
	/// The check is read-only. A cooldown that has expired reports `true` and
	/// leaves the one probe for [`ClusterCircuitBreaker::admit_request`] to
	/// spend. A verdict that consumed the probe would leave the circuit
	/// half-open with no outcome recorded, and half-open admits every later
	/// request.
	#[must_use]
	pub fn would_allow(&self, signer: ProvenPeer<'_>) -> bool {
		let Ok(signers) = self.signers.lock() else {
			return false;
		};
		let Some(circuit) = signers.get(signer.as_key()) else {
			return true;
		};

		match circuit.position {
			Position::Closed | Position::HalfOpen => true,
			Position::Open(opened_at) => self.cooled(opened_at),
		}
	}

	/// Records a successful request from `signer`, which closes its circuit
	/// and clears its failure history.
	pub fn record_success(&self, signer: ProvenPeer<'_>) {
		let Ok(mut signers) = self.signers.lock() else {
			return;
		};

		signers.remove(signer.as_key());
	}

	/// Records an authentication failure attributed to `signer`.
	///
	/// A failure while half-open re-opens immediately and restarts the
	/// cooldown.
	pub fn record_auth_failure(&self, signer: ProvenPeer<'_>) {
		let Ok(mut signers) = self.signers.lock() else {
			return;
		};

		let circuit = signers.entry(signer.as_key().clone()).or_insert(SignerCircuit::CLOSED);
		if matches!(circuit.position, Position::HalfOpen) {
			circuit.position = Position::Open(self.clock.monotonic());
			return;
		}

		circuit.failures = circuit.failures.saturating_add(1);
		if circuit.failures >= self.failure_threshold {
			circuit.position = Position::Open(self.clock.monotonic());
		}
	}

	/// The current circuit state for `signer`. A poisoned lock reports
	/// [`CircuitState::Open`].
	pub fn state(&self, signer: ProvenPeer<'_>) -> CircuitState {
		let Ok(signers) = self.signers.lock() else {
			return CircuitState::Open;
		};

		signers
			.get(signer.as_key())
			.map_or(CircuitState::Closed, |circuit| circuit.position.state())
	}

	/// Whether `signer`'s circuit is open (tripped).
	pub fn is_open(&self, signer: ProvenPeer<'_>) -> bool {
		self.state(signer) == CircuitState::Open
	}

	/// Closes `signer`'s circuit and clears its failure history.
	pub fn reset(&self, signer: ProvenPeer<'_>) {
		self.record_success(signer);
	}

	/// Drops the rows of signers that carry no failure history.
	pub fn prune(&self) {
		let Ok(mut signers) = self.signers.lock() else {
			return;
		};

		signers.retain(|_, circuit| !circuit.is_quiescent());
	}
}

/// The maximum number of distinct signatures remembered per signer in one
/// freshness window.
///
/// Legitimate traffic is bounded by a signer's command rate inside one
/// window. Each signer's partition fails closed at capacity, which holds
/// while an attacker lacks the fresh valid signatures that would fill it.
pub const REPLAY_GUARD_CAPACITY: usize = 1024;

/// Recorded signatures per signer, each with the instant it was recorded.
type SignerPartitions = HashMap<Arc<[u8]>, HashMap<VerifiedSignature, UnixMillis>>;

/// Recorded signatures, partitioned by signer and indexed by signature.
///
/// The partitions hold the per-signer capacity. The index answers "have I
/// seen this signature" in one lookup, so admission costs the same whether
/// the colony has one trusted signer or a thousand. Each key is a
/// [`VerifiedSignature`], so a signature and its `(r, n - s)` twin are one
/// key.
#[derive(Default)]
struct SeenSignatures {
	partitions: SignerPartitions,
	owner: HashMap<VerifiedSignature, Arc<[u8]>>,
}

impl SeenSignatures {
	/// Whether `signature` is recorded and still inside the window.
	///
	/// The check is read-only, so a verdict can ask without changing what a
	/// later admission sees. The signer is read through the index without
	/// copying it.
	fn is_live(&self, signature: &VerifiedSignature, now: UnixMillis, window: Duration) -> bool {
		self.owner
			.get(signature)
			.and_then(|signer| self.partitions.get(signer.as_ref()))
			.and_then(|sigs| sigs.get(signature))
			.is_some_and(|at| now.abs_diff(*at) <= window)
	}

	/// Whether `signature` is recorded and still inside the window, for an
	/// admission that is about to record it.
	///
	/// A record found past the window is dropped here, so an expired
	/// signature returns its capacity on the next admission. The signer is
	/// read through the index without copying it.
	fn is_live_replay(&mut self, signature: &VerifiedSignature, now: UnixMillis, window: Duration) -> bool {
		if !self.owner.contains_key(signature) {
			return false;
		}

		let live = self.is_live(signature, now, window);
		if !live {
			self.forget(signature);
		}

		live
	}

	/// Drops `signer`'s expired records. The work is bounded by the
	/// per-signer capacity, so each signer's history costs that signer alone.
	fn expire(&mut self, signer: impl AsRef<[u8]>, now: UnixMillis, window: Duration) {
		let signer = signer.as_ref();
		let Some(sigs) = self.partitions.get_mut(signer) else {
			return;
		};

		sigs.retain(|signature, at| {
			let live = now.abs_diff(*at) <= window;
			if !live {
				self.owner.remove(signature);
			}

			live
		});

		if sigs.is_empty() {
			self.partitions.remove(signer);
		}
	}

	/// Record `signature` of `signer` at `now`. The partition and the owner
	/// index share one allocation of the signer, which is the key of its
	/// partition once the signer holds one.
	fn record(&mut self, signer: impl AsRef<[u8]>, signature: &VerifiedSignature, now: UnixMillis) {
		let signer = signer.as_ref();
		let held = self.partitions.get_key_value(signer).map(|(held, _)| Arc::clone(held));
		let shared = held.unwrap_or_else(|| Arc::from(signer));
		let partition = self.partitions.entry(Arc::clone(&shared)).or_default();
		partition.insert(signature.clone(), now);
		self.owner.insert(signature.clone(), shared);
	}

	fn forget(&mut self, signature: &VerifiedSignature) {
		let Some(signer) = self.owner.remove(signature) else {
			return;
		};
		let Some(sigs) = self.partitions.get_mut(signer.as_ref()) else {
			return;
		};

		sigs.remove(signature);
		if sigs.is_empty() {
			self.partitions.remove(signer.as_ref());
		}
	}

	fn len_for(&self, signer: impl AsRef<[u8]>) -> usize {
		let signer = signer.as_ref();
		self.partitions.get(signer).map_or(0, HashMap::len)
	}
}

/// Bounded freshness and replay window for signed cluster commands.
///
/// A command is accepted when its `Frame.metadata.order` lies within the
/// window of the hive clock, in either direction to tolerate skew, and its
/// signature has not already been seen inside the window.
///
/// - Signatures are tracked per signer, so one signer that saturates its
///   partition leaves the others admitting.
/// - A signer's entries more than the window away from the clock are pruned
///   on each of its inserts, so memory is bounded by [`REPLAY_GUARD_CAPACITY`]
///   per trusted signer.
pub struct ReplayGuard {
	seen: Mutex<SeenSignatures>,
	window: Duration,
}

impl ReplayGuard {
	/// Creates a guard with a freshness `window` around the hive clock.
	pub fn new(window: Duration) -> Self {
		Self { seen: Mutex::new(SeenSignatures::default()), window }
	}

	/// Whether `order` (`Frame.metadata.order`) is within the freshness window
	/// of `now`.
	///
	/// Both are instants, and the comparison is on the magnitude of their
	/// difference, so the two read the same in either position. That is
	/// why they stay separate parameters rather than moving into a
	/// carrier: an exchange here changes no verdict.
	pub fn is_fresh(&self, order: UnixMillis, now: UnixMillis) -> bool {
		now.abs_diff(order) <= self.window
	}

	/// Whether `signature` was already recorded within the window.
	///
	/// The check is read-only. A verdict asks it, and the admission that
	/// follows spends the slot with [`ReplayGuard::check_and_insert`]. A
	/// poisoned lock answers `true`, so a verdict fails closed the way an
	/// admission does.
	#[must_use]
	pub fn is_replay(&self, signature: &VerifiedSignature, now: UnixMillis) -> bool {
		let Ok(seen) = self.seen.lock() else {
			return true;
		};

		seen.is_live(signature, now, self.window)
	}

	/// Records `signature` for `signer` when it is unseen within the window.
	///
	/// It returns `true` for a new signature, which it records. It returns
	/// `false` for a replay, and it fails closed when the signer's partition
	/// is at capacity or the lock is poisoned.
	pub fn check_and_insert(&self, signer: impl AsRef<[u8]>, signature: &VerifiedSignature, now: UnixMillis) -> bool {
		let signer = signer.as_ref();
		let Ok(mut seen) = self.seen.lock() else {
			return false;
		};

		// Replay detection spans all partitions: either `SignerIdentifier`
		// CHOICE arm can name one certificate, so a partition-local check would
		// grant one extra replay per alternate encoding.
		if seen.is_live_replay(signature, now, self.window) {
			return false;
		}

		seen.expire(signer, now, self.window);
		if seen.len_for(signer) >= REPLAY_GUARD_CAPACITY {
			return false;
		}

		seen.record(signer, signature, now);

		true
	}

	/// Removes a recorded signature, so the frame may be retried.
	///
	/// The signature is recorded before the guarded operation runs. When
	/// that operation fails, the record must be released or a legitimate
	/// retry of the same signed frame is rejected as a replay until the
	/// window expires. A poisoned guard admits nothing, so it holds no slot
	/// to release.
	pub fn forget(&self, signature: &VerifiedSignature) {
		let Ok(mut seen) = self.seen.lock() else {
			return;
		};

		seen.forget(signature);
	}
}

/// The gate policy for certificate-based cluster command security.
///
/// The gate enforces nonrepudiation, integrity, freshness, and replay rules
/// on cluster commands through certificate-based trust verification.
///
/// # Security Flow
///
/// 1. Require a nonrepudiation signature (missing: `Unauthenticated`, not counted).
/// 2. Require frame integrity (missing: `Unauthenticated`, not counted).
/// 3. Require a handshake-proven peer (missing: `Unauthenticated`), and refuse
///    while its circuit is open (`PermissionDenied`). Neither is counted.
/// 4. Look up the signer certificate in the trust store (unknown signer: `PermissionDenied`, not counted).
/// 5. Verify the signature with the certificate's public key (invalid: `PermissionDenied`, **counted**).
/// 6. Check `Frame.metadata.order` freshness (stale: `PermissionDenied`, not counted).
/// 7. Refuse a signature already seen inside the window (replay: `PermissionDenied`, not counted).
/// 8. On success, take the breaker's cooldown probe and record the success, which resets the breaker.
///
/// Only step 5 counts toward the circuit breaker, and it counts against
/// the [`ProvenPeer`] the transport handshake established, so one member's
/// failures gate that member alone (CWE-645). Steps 6-7 stay uncounted,
/// because a replayed capture still carries a valid signature.
///
/// # Breaker key
///
/// - The signature is still unchecked where the breaker is first read, so the
///   breaker keys on the handshake-proven peer.
/// - [`ProvenPeer`] is the only key the breaker accepts, so a caller who copies
///   a trusted `SignerIdentifier` spends its own budget (CWE-345).
/// - An unauthenticated transport offers no such key. Sharing one row across
///   every anonymous caller would let a single bad signature deny the rest,
///   so this plane requires a proven peer (CWE-645).
pub struct ClusterSecurityGate {
	/// The breaker that counts authentication failures, on this gate's clock.
	circuit_breaker: ClusterCircuitBreaker,
	/// The trust store for certificate lookup and signature verification.
	trust_store: Arc<dyn CertificateTrust>,
	/// Freshness window and replay set for signed commands.
	///
	/// The guard is shared with every [`AdmittedCommand`] this gate admits, so
	/// a refusal the command meets later can release the slot it spent.
	replay_guard: Arc<ReplayGuard>,
	/// The clock a command's freshness is judged against, and the one the
	/// breaker's cooldown runs on.
	clock: Arc<dyn Clock>,
}

/// The thresholds one [`ClusterSecurityGate`] enforces.
///
/// The fields are named so the two durations cannot change places at a
/// call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateLimits {
	/// The count of consecutive bad signatures from one peer that opens its
	/// circuit.
	pub failure_threshold: u8,
	/// Time an open circuit waits before it lets one probe through.
	pub cooldown: Duration,
	/// How far a command's stated issue time may sit from the gate clock.
	pub freshness_window: Duration,
}

/// A cluster command this gate has authenticated and decoded.
///
/// The body is the alternative the CHOICE proved during admission, so a
/// dispatcher matches it rather than reading the optional fields again.
/// `signer` is the nonrepudiation signer the signature check accepted, and
/// `replay_guard` holds the slot its signature spent.
pub(crate) struct AdmittedCommand {
	body: ClusterCommandKind,
	frame: Frame,
	signature: VerifiedSignature,
	replay_guard: Arc<ReplayGuard>,
}

impl AdmittedCommand {
	/// Whether the admitted command is a heartbeat.
	pub(crate) fn is_heartbeat(&self) -> bool {
		matches!(self.body, ClusterCommandKind::Heartbeat(_))
	}

	/// The alternative that admission proved.
	pub(crate) fn body(&self) -> &ClusterCommandKind {
		&self.body
	}

	/// The frame the command arrived on.
	pub(crate) fn frame(&self) -> &Frame {
		&self.frame
	}

	/// Answers this command with `response` in the shape its body names.
	///
	/// # Errors
	///
	/// - [`TightBeamError::BuildError`] -- the reply frame did not build.
	pub(crate) fn reply(&self, response: ClusterCommandResponse) -> Result<Option<Frame>, TightBeamError> {
		self.body.reply_shape().reply(self.frame.metadata().id(), response)
	}

	/// Refuses this command in the shape its body names.
	///
	/// The refusal decides whether the replay slot is released. A refusal
	/// that a retry of the same signed frame can change gives the slot
	/// back, so the cluster may resubmit the frame. A refusal that holds
	/// for every resubmission keeps the slot spent, so a captured frame
	/// buys its holder nothing.
	///
	/// # Errors
	///
	/// - [`TightBeamError::BuildError`] -- the reply frame did not build.
	pub(crate) fn refuse(&self, refusal: CommandRefusal) -> Result<Option<Frame>, TightBeamError> {
		if refusal.releases_replay() {
			self.forget_replay();
		}

		self.body.reply_shape().refuse(self.frame.metadata().id(), refusal.status())
	}

	/// Releases the replay slot this command's signature spent, so a signed
	/// retry of the same frame is admitted again.
	fn forget_replay(&self) {
		self.replay_guard.forget(&self.signature);
	}
}

/// Why the control plane refused a command the gate had admitted.
///
/// Each variant knows whether a retry of the same signed frame could be
/// answered differently, which is the one fact
/// [`AdmittedCommand::refuse`] needs to decide the replay slot. The
/// mapping lives here, so a handler names its refusal and this type
/// decides the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandRefusal {
	/// The hive is draining, which ends with the hive gone.
	Draining,
	/// The hive is at capacity, which clears as work completes.
	Backpressure,
	/// No spawner is registered for the requested servlet type.
	UnknownServletType,
	/// The spawner ran and produced no servlet.
	SpawnFailed,
	/// The spawned servlet's address is not a valid instance locator.
	UnnameableInstance,
	/// The servlet registry refused the insert.
	RegistryFault,
	/// The stop named no running instance.
	UnknownInstance,
}

impl CommandRefusal {
	/// The status the sender reads.
	pub(crate) fn status(self) -> TransitStatus {
		match self {
			Self::Draining | Self::SpawnFailed | Self::RegistryFault => TransitStatus::Unavailable,
			Self::Backpressure => TransitStatus::ResourceExhausted,
			Self::UnknownServletType | Self::UnnameableInstance | Self::UnknownInstance => {
				TransitStatus::PermissionDenied
			}
		}
	}

	/// Whether a retry of the same signed frame could be answered
	/// differently.
	///
	/// A drain is terminal, a servlet type or instance the hive does not
	/// have stays absent, and a servlet that names itself badly does so on
	/// every spawn, so those refusals keep the slot spent.
	pub(crate) fn releases_replay(self) -> bool {
		match self {
			Self::Backpressure | Self::SpawnFailed | Self::RegistryFault => true,
			Self::Draining | Self::UnknownServletType | Self::UnnameableInstance | Self::UnknownInstance => false,
		}
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
	/// Refuses `frame` with `status`, reading its reply shape from one
	/// decode of the command body.
	///
	/// A body that names no single alternative has no heartbeat shape, so
	/// the refusal answers in the management shape.
	pub(crate) fn denied(frame: Frame, status: TransitStatus) -> Box<Self> {
		let body = ClusterCommand::choice_of(&frame);
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

	/// Answers the refused frame in the shape its body named.
	///
	/// # Errors
	///
	/// - [`TightBeamError::BuildError`] -- the reply frame did not build.
	pub(crate) fn reply(&self) -> Result<Option<Frame>, TightBeamError> {
		self.shape.refuse(self.frame.metadata().id(), self.status())
	}
}

/// What the non-spending checks proved about one frame.
///
/// The gate holds it between [`ClusterSecurityGate::inspect`] and the steps
/// that spend, so the spending steps read what the checks already derived.
struct Authenticated<'a> {
	signature: VerifiedSignature,
	signer_id: Vec<u8>,
	breaker_key: ProvenPeer<'a>,
}

/// Why [`ClusterSecurityGate::inspect`] refused a frame.
///
/// A bad signature is the one refusal an admission counts against the
/// breaker, so it is a variant rather than a status: the verdict reports
/// it without recording anything, and the admission records it once.
enum InspectRefusal {
	/// The frame was refused before, or independently of, the signature
	/// check.
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
	/// A security gate that trusts the certificates in `trust_store` and
	/// enforces `limits` on `clock`.
	///
	/// The gate builds its own circuit breaker and replay guard from that
	/// one clock, so the cooldown and the freshness window always read the
	/// same time.
	pub fn new(trust_store: Arc<dyn CertificateTrust>, limits: GateLimits, clock: Arc<dyn Clock>) -> Self {
		let GateLimits { failure_threshold, cooldown, freshness_window } = limits;
		let circuit_breaker = ClusterCircuitBreaker::new(failure_threshold, cooldown, Arc::clone(&clock));
		let replay_guard = Arc::new(ReplayGuard::new(freshness_window));

		Self { circuit_breaker, trust_store, replay_guard, clock }
	}

	/// Judges `frame` without spending anything it judges.
	///
	/// The verdict covers the signer, the peer's circuit, freshness, and
	/// replay. A captured frame is therefore refused here, because its
	/// signature is already recorded, and the question itself records nothing.
	///
	/// # Left to the admission
	///
	/// - Taking the breaker's cooldown probe.
	/// - Recording an auth failure.
	/// - Refusing a body that names no single command.
	/// - Inserting the signature, which refuses a full partition.
	/// - Recording a success.
	fn inspect<'a>(
		&self,
		frame: &Frame,
		session: &'a SessionContext,
		now: UnixMillis,
	) -> Result<Authenticated<'a>, InspectRefusal> {
		let Some(signer) = frame.nonrepudiation() else {
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

		// The breaker keys on the handshake-proven peer, so a transport that
		// proves none is refused here (CWE-345, CWE-645).
		let Some(breaker_key) = session.proven_peer() else {
			return Err(InspectRefusal::Plain(TransitStatus::Unauthenticated));
		};

		if !self.circuit_breaker.would_allow(breaker_key) {
			return Err(InspectRefusal::Plain(TransitStatus::PermissionDenied));
		}

		// The verified signature is the replay key, in its canonical form, so
		// a capture with `s` flipped to `n - s` keys the slot it already spent.
		let signature = match self.trust_store.verify_frame(frame) {
			TrustVerification::MissingSignature => {
				return Err(InspectRefusal::Plain(TransitStatus::Unauthenticated));
			}
			TrustVerification::UnknownSigner => {
				return Err(InspectRefusal::Plain(TransitStatus::PermissionDenied));
			}
			TrustVerification::Invalid => return Err(InspectRefusal::BadSignature),
			TrustVerification::Verified(_, signature) => signature,
		};

		// Freshness and replay are checked here so a verdict refuses a
		// captured frame (CWE-294). The slot itself is spent in `admit`.
		if !self.replay_guard.is_fresh(frame.issued_at(), now) {
			return Err(InspectRefusal::Plain(TransitStatus::PermissionDenied));
		}
		if self.replay_guard.is_replay(&signature, now) {
			return Err(InspectRefusal::Plain(TransitStatus::PermissionDenied));
		}

		Ok(Authenticated { signature, signer_id, breaker_key })
	}

	/// Authenticates `frame`, decodes its cluster command once, and spends
	/// the admission.
	///
	/// This is the consuming step: it takes the breaker's cooldown probe,
	/// records an auth failure or a success against it, and spends the
	/// replay slot for the signature. The control plane calls it exactly
	/// once per frame.
	pub(crate) fn admit(&self, frame: Frame, session: &SessionContext) -> Result<AdmittedCommand, Box<AdmitRefusal>> {
		// The body decodes once, and that decode proves the CHOICE that the
		// body spells as tagged optional fields. A body that names none or
		// more than one is not a command, so the ambiguous form stops here.
		let body = ClusterCommand::choice_of(&frame);

		let shape = ReplyShape::of(body.as_ref());
		let now = self.clock.unix();
		let authenticated = match self.inspect(&frame, session, now) {
			Ok(authenticated) => authenticated,
			Err(refusal) => {
				// A bad signature counts once, here, where the frame was
				// submitted for admission.
				if let (InspectRefusal::BadSignature, Some(breaker_key)) = (&refusal, session.proven_peer()) {
					self.circuit_breaker.record_auth_failure(breaker_key);
				}

				return Err(AdmitRefusal::boxed(frame, refusal.status(), shape));
			}
		};

		// Replay capacity spends on well-formed frames (CWE-770). A body that
		// does not decode or names no single alternative is malformed rather
		// than unauthorized, and stays wrong whatever this hive's state is.
		let Some(body) = body else {
			return Err(AdmitRefusal::boxed(frame, TransitStatus::InvalidArgument, shape));
		};

		let Authenticated { signature, signer_id, breaker_key } = authenticated;
		if !self.replay_guard.check_and_insert(&signer_id, &signature, now) {
			return Err(AdmitRefusal::boxed(frame, TransitStatus::PermissionDenied, shape));
		}

		// The cooldown probe is taken last, immediately before the outcome it
		// waits for, so no refusing path leaves the circuit half-open with
		// nothing recorded.
		if !self.circuit_breaker.admit_request(breaker_key) {
			// This frame is not admitted, so its signature must not count
			// as seen: a legitimate retry would be refused as a replay.
			self.replay_guard.forget(&signature);
			return Err(AdmitRefusal::boxed(frame, TransitStatus::PermissionDenied, shape));
		}

		self.circuit_breaker.record_success(breaker_key);

		let replay_guard = Arc::clone(&self.replay_guard);
		Ok(AdmittedCommand { body, frame, signature, replay_guard })
	}
}

impl GatePolicy for ClusterSecurityGate {
	/// Whether this frame would be admitted, without spending the
	/// admission.
	///
	/// A captured frame is still refused here, because the signature it
	/// carries is already recorded (CWE-294).
	///
	/// # Command-query separation
	///
	/// A verdict must not consume what it judges. A transport that gates on
	/// this and then hands the frame to the control plane would otherwise see
	/// its own admission refused as a replay, and would burn the breaker's
	/// cooldown probe on a question rather than an answer.
	fn evaluate(&self, frame: Option<&Frame>, session: &SessionContext) -> TransitStatus {
		let Some(frame) = frame else {
			return TransitStatus::Unauthenticated;
		};

		match self.inspect(frame, session, self.clock.unix()) {
			Ok(_) => TransitStatus::Ok,
			Err(refusal) => refusal.status(),
		}
	}
}

/// One reading of a hive's load, and the verdict that describes it.
///
/// The pair comes from one atomic load, so a caller that reports both names
/// a utilization that agrees with the status beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackpressureReport {
	/// The hive-wide utilization at the moment of the read.
	pub utilization: BasisPoints,
	/// Whether the hive is taking work at that utilization.
	pub status: TransitStatus,
}

/// The gate policy that enforces hive capacity limits (backpressure).
///
/// It answers [`TransitStatus::ResourceExhausted`] when utilization reaches the
/// threshold, and the cluster then routes the work elsewhere or queues it.
///
/// # Exemptions
///
/// The gate grants none, because any bypass keyed on frame-controlled data,
/// such as message priority, is attacker-selectable. Callers that must keep
/// specific traffic flowing under load, such as heartbeats, exempt it
/// explicitly *after* authentication.
pub struct BackpressureGate {
	/// The current aggregate utilization in basis points.
	utilization: Arc<AtomicU16>,
	/// The utilization at or above which the gate refuses, from the hive's
	/// `backpressure_threshold`.
	threshold: BasisPoints,
}

impl BackpressureGate {
	/// A gate that refuses requests while `utilization` is at or above
	/// `threshold`.
	pub fn new(utilization: Arc<AtomicU16>, threshold: BasisPoints) -> Self {
		Self { utilization, threshold }
	}

	/// The current utilization, saturated into [`BasisPoints`].
	pub fn current_utilization(&self) -> BasisPoints {
		BasisPoints::new_saturating(self.utilization.load(Ordering::Relaxed))
	}

	/// Whether the hive is taking work at the current utilization.
	///
	/// This is the one comparison of utilization against the threshold. The
	/// gate answers requests with it, and the heartbeat reports the same
	/// verdict, so the capacity a hive reports matches the work it admits.
	#[must_use]
	pub fn status(&self) -> TransitStatus {
		self.report().status
	}

	/// The utilization and the verdict that describes it.
	///
	/// Both come from one load, so the capacity a heartbeat reports agrees
	/// with the status beside it.
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

/// Membership mode of a [`PeerListGate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerListMode {
	/// An allow list, which admits only the listed peer keys.
	Allow,
	/// A deny list, which refuses the listed peer keys.
	Deny,
}

/// An allow list or a deny list of session identities.
///
/// - The gate keys on the [`CanonicalKey`] of the mutually authenticated peer certificate.
/// - The gate reads its entries through the key list that [`PublicKeyPinning`] reads its pins through.
/// - The frame signer stays an application concern.
/// - An empty session context answers as an absent peer, so an allow list
///   fails closed (`Unauthenticated`) and a deny list admits.
///
/// [`PublicKeyPinning`]: crate::crypto::x509::policy::PublicKeyPinning
#[derive(Clone)]
pub struct PeerListGate {
	keys: KeyList,
	mode: PeerListMode,
}

impl PeerListGate {
	/// A list in `mode` of these peer public keys (SPKI DER), each read under
	/// `curves`, so the decoder of a curve refuses its off-curve encodings.
	///
	/// # Errors
	///
	/// - [`KeyListError::Unreadable`] -- an entry is no SubjectPublicKeyInfo
	///   DER, or its canonical form exceeds the DER length cap.
	/// - [`KeyListError::NoPoint`] -- an entry names an elliptic-curve key that reads as no point.
	/// - [`KeyListError::NoDecoder`] -- an entry names a point on a curve that `curves` holds no decoder for.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::hive::{PeerListGate, PeerListMode};
	/// use tightbeam::crypto::x509::{KeyCurves, KeyListError};
	///
	/// // An entry that is no SubjectPublicKeyInfo refuses the whole list.
	/// let refused = PeerListGate::new(PeerListMode::Deny, KeyCurves::HOUSE, [b"not a key"]);
	/// assert_eq!(refused.err(), Some(KeyListError::Unreadable { index: 0 }));
	/// ```
	pub fn new<I, K>(mode: PeerListMode, curves: KeyCurves, keys: I) -> Result<Self, KeyListError>
	where
		I: IntoIterator<Item = K>,
		K: AsRef<[u8]>,
	{
		let keys = KeyList::read(curves, keys)?;
		Ok(Self { keys, mode })
	}

	/// An allow list that admits only these peer public keys (SPKI DER), read
	/// under [`KeyCurves::HOUSE`].
	///
	/// # Errors
	///
	/// - The [`Self::new`] set.
	pub fn allow<I, K>(keys: I) -> Result<Self, KeyListError>
	where
		I: IntoIterator<Item = K>,
		K: AsRef<[u8]>,
	{
		Self::new(PeerListMode::Allow, KeyCurves::HOUSE, keys)
	}

	/// A deny list that refuses these peer public keys (SPKI DER), read under
	/// [`KeyCurves::HOUSE`].
	///
	/// # Errors
	///
	/// - The [`Self::new`] set.
	pub fn deny<I, K>(keys: I) -> Result<Self, KeyListError>
	where
		I: IntoIterator<Item = K>,
		K: AsRef<[u8]>,
	{
		Self::new(PeerListMode::Deny, KeyCurves::HOUSE, keys)
	}

	/// The verdict for one peer identity.
	fn admit(&self, peer_key: Option<&CanonicalKey>) -> TransitStatus {
		match (self.mode, peer_key) {
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
		self.admit(session.peer_key())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::builder::TypeBuilder;
	use crate::cms::signed_data::SignerIdentifier;
	use crate::colony::common::{ClusterStatus, HeartbeatParams};
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::policy::{Secp256k1Policy, VerificationPolicy};
	use crate::crypto::sign::ecdsa::{Secp256k1, Secp256k1Signature, Signature};
	use crate::crypto::sign::{PrehashVerifier, SigningIdentity};
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::crypto::x509::policy::CertificateValidation;
	use crate::crypto::x509::store::{CertificateTrustBuilder, TrustBuilder};
	use crate::crypto::x509::{Certificate, ErasedSigning, PeerCertificate};
	use crate::der::asn1::ObjectIdentifier;
	use crate::der::oid::db::rfc5912::ID_EC_DH;
	use crate::der::oid::db::rfc8410::ID_ED_25519;
	use crate::oids::CURVE_NIST_P256;
	use crate::spki::SubjectPublicKeyInfoOwned;
	use crate::tb_cases;
	use crate::testing::fixtures::{TestCertificate, TestIdentity, TestKey, TestP256Points};
	use crate::testing::TestFrame;
	use crate::testing::TestMessage;
	use crate::utils::time::ManualClock;
	use crate::{MessagePriority, Version};
	use std::sync::LazyLock;

	const SIGNER: &[u8] = b"signer-under-test";

	/// The key identity of [`listed_peer`], the signer under test.
	static SIGNER_KEY: LazyLock<CanonicalKey> = LazyLock::new(|| key_of(&listed_peer()));

	/// The key identity of [`unlisted_peer`], a second signer.
	static OTHER_KEY: LazyLock<CanonicalKey> = LazyLock::new(|| key_of(&unlisted_peer()));

	/// The cooldown every breaker fixture waits out.
	const COOLDOWN: Duration = Duration::from_millis(60_000);

	/// The freshness window every gate fixture judges against.
	const FRESHNESS_WINDOW: Duration = Duration::from_millis(60_000);

	/// A clock that moves only when the test advances it.
	fn manual_clock() -> Arc<ManualClock> {
		Arc::new(ManualClock::default())
	}

	/// `clock` as the erased handle a breaker or gate is built on.
	fn erased(clock: &Arc<ManualClock>) -> Arc<dyn Clock> {
		Arc::clone(clock) as Arc<dyn Clock>
	}

	/// A breaker that opens after `failure_threshold` failures and waits out
	/// [`COOLDOWN`] on `clock`.
	fn breaker_on(clock: &Arc<ManualClock>, failure_threshold: u8) -> ClusterCircuitBreaker {
		ClusterCircuitBreaker::new(failure_threshold, COOLDOWN, erased(clock))
	}

	/// A breaker that opens after three failures, on a clock nothing advances.
	fn breaker() -> ClusterCircuitBreaker {
		breaker_on(&manual_clock(), 3)
	}

	/// [`breaker`] with the circuit of [`signer`] already open.
	fn tripped_breaker() -> ClusterCircuitBreaker {
		let breaker = breaker();
		breaker.record_auth_failure(signer());
		breaker.record_auth_failure(signer());
		breaker.record_auth_failure(signer());

		breaker
	}

	/// Gate limits that open after three failures and wait out
	/// [`COOLDOWN`].
	fn limits() -> GateLimits {
		GateLimits { failure_threshold: 3, cooldown: COOLDOWN, freshness_window: FRESHNESS_WINDOW }
	}

	/// Gate limits whose one failure opens a circuit that has already
	/// cooled, so the next admission is the probe.
	fn instant_cooldown() -> GateLimits {
		GateLimits {
			failure_threshold: 1,
			cooldown: Duration::ZERO,
			freshness_window: FRESHNESS_WINDOW,
		}
	}

	/// The identity under test, as a handshake would prove it.
	fn signer() -> ProvenPeer<'static> {
		ProvenPeer::for_test(&SIGNER_KEY)
	}

	/// A second proven identity, for isolation assertions.
	fn other() -> ProvenPeer<'static> {
		ProvenPeer::for_test(&OTHER_KEY)
	}

	/// The identity the handshake proved for `session`.
	fn proven(session: &SessionContext) -> ProvenPeer<'_> {
		session.proven_peer().expect("the session proved a peer")
	}

	/// The key the handshake proved for `session`.
	fn peer_key(session: &SessionContext) -> CanonicalKey {
		proven(session).as_key().clone()
	}

	/// The certificate of the fixed test key, whose point is uncompressed.
	fn listed_peer() -> Certificate {
		TestCertificate::self_signed(&TestKey::insecure_fixed_signing())
	}

	/// [`listed_peer`] with the P-256 key of RFC 6979 §A.2.5 in the SEC 1 form
	/// `point` holds.
	fn with_p256_point(point: &[u8]) -> Certificate {
		TestCertificate::with_curve_point(listed_peer(), CURVE_NIST_P256, point)
	}

	/// The certificate of the negation of the fixed test key, another key.
	fn unlisted_peer() -> Certificate {
		TestCertificate::self_signed(&TestKey::negation_of(&TestKey::insecure_fixed_signing()))
	}

	/// `sect233k1`, a SEC 2 curve over a binary field.
	const SECT233K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.26");

	/// The set that holds the decoder of P-256 alone.
	const P256: KeyCurves = KeyCurves::new(&[&TestP256Points]);

	/// [`listed_peer`] with its key under `algorithm` and no parameters, a key
	/// of another algorithm than `id-ecPublicKey`.
	fn under_algorithm(algorithm: ObjectIdentifier) -> Certificate {
		let mut certificate = listed_peer();
		let spki = &mut certificate.tbs_certificate.subject_public_key_info;
		spki.algorithm.oid = algorithm;
		spki.algorithm.parameters = None;
		certificate
	}

	/// The refusal of a deny list whose second entry is the key of `entry`.
	fn refusal_of(entry: &Certificate) -> Option<KeyListError> {
		PeerListGate::deny([listed(&listed_peer()), listed(entry)]).err()
	}

	/// The SubjectPublicKeyInfo DER of `certificate`, as an operator lists it.
	fn listed(certificate: &Certificate) -> Vec<u8> {
		let spki = &certificate.tbs_certificate.subject_public_key_info;
		spki.to_der().expect("a test key encodes")
	}

	/// The key identity a session of `certificate` proves.
	fn key_of(certificate: &Certificate) -> CanonicalKey {
		let spki = &certificate.tbs_certificate.subject_public_key_info;
		CanonicalKey::of(spki).expect("a test key has a canonical form")
	}

	/// A session whose peer holds the key of [`listed_peer`] in the
	/// compressed form.
	fn compressed_session() -> SessionContext {
		let compressed = TestCertificate::with_compressed_key(listed_peer());
		SessionContext::for_peer(Arc::new(compressed))
	}

	/// The signer identifier `frame`'s signature names.
	fn signer_id(frame: &Frame) -> Vec<u8> {
		frame.signer_id().expect("the signed frame carries a signer id")
	}

	/// A verifier that accepts every signature, so a test reaches a
	/// [`VerifiedSignature`] of any canonical value through the one producer.
	struct AcceptAll;

	impl PrehashVerifier<Secp256k1Signature> for AcceptAll {
		fn verify_prehash(&self, _prehash: &[u8], _signature: &Secp256k1Signature) -> Result<(), signature::Error> {
			Ok(())
		}
	}

	/// A low-s signature value distinct for each `index`, as [`AcceptAll`]
	/// verifies it.
	fn accepted(index: usize) -> VerifiedSignature {
		let mut r = [0u8; 32];
		r[24..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
		let mut s = [0u8; 32];
		s[31] = 1;

		let scalars = Signature::<Secp256k1>::from_scalars(r, s).expect("small scalars are in range");
		let encoded = scalars.to_der();
		let verifying = VerifiedSignature::verify::<Secp256k1Signature, _>(&AcceptAll, [0u8; 32], encoded.as_bytes());
		verifying.expect("the test verifier accepts every canonical value")
	}

	/// Fills `signer`'s replay partition to capacity at `now`.
	fn fill_replay_partition(gate: &ClusterSecurityGate, signer: impl AsRef<[u8]>, now: UnixMillis) {
		let signer = signer.as_ref();
		let filled =
			(0..REPLAY_GUARD_CAPACITY).all(|index| gate.replay_guard.check_and_insert(signer, &accepted(index), now));

		assert!(filled, "the partition takes every filler up to capacity");
	}

	#[test]
	fn breaker_trips_after_threshold() {
		let breaker = breaker();
		breaker.record_auth_failure(signer());
		breaker.record_auth_failure(signer());

		assert_eq!(breaker.state(signer()), CircuitState::Closed);

		breaker.record_auth_failure(signer());

		assert_eq!(breaker.state(signer()), CircuitState::Open);
		assert!(!breaker.admit_request(signer()));
	}

	// The cooldown runs on the breaker's clock, so an open circuit lets its
	// probe through once that clock reaches the cooldown and not before.
	tb_cases! {
		fn breaker_cooldown_runs_on_its_clock((advance, admitted): (Duration, bool)) {
			let clock = manual_clock();
			let breaker = breaker_on(&clock, 1);
			breaker.record_auth_failure(signer());

			clock.advance(advance);

			assert_eq!(breaker.admit_request(signer()), admitted);
		}
		cases {
			one_millisecond_short => (COOLDOWN.saturating_sub(Duration::from_millis(1)), false),
			at_the_cooldown => (COOLDOWN, true),
		}
	}

	/// The admitted probe leaves the circuit half-open, waiting on its
	/// outcome.
	#[test]
	fn breaker_probe_leaves_the_circuit_half_open() {
		let clock = manual_clock();
		let breaker = breaker_on(&clock, 1);
		breaker.record_auth_failure(signer());
		clock.advance(COOLDOWN);

		assert!(breaker.admit_request(signer()));
		assert_eq!(breaker.state(signer()), CircuitState::HalfOpen);
	}

	#[test]
	fn breaker_probe_success_closes() {
		let breaker = ClusterCircuitBreaker::new(1, Duration::ZERO, erased(&manual_clock()));
		breaker.record_auth_failure(signer());

		assert!(breaker.admit_request(signer()));
		assert_eq!(breaker.state(signer()), CircuitState::HalfOpen);

		breaker.record_success(signer());

		assert_eq!(breaker.state(signer()), CircuitState::Closed);
	}

	#[test]
	fn breaker_probe_failure_reopens() {
		let breaker = ClusterCircuitBreaker::new(1, Duration::ZERO, erased(&manual_clock()));
		breaker.record_auth_failure(signer());

		assert!(breaker.admit_request(signer()));
		assert_eq!(breaker.state(signer()), CircuitState::HalfOpen);

		breaker.record_auth_failure(signer());

		assert_eq!(breaker.state(signer()), CircuitState::Open);
	}

	#[test]
	fn breaker_reset_clears_state() {
		let breaker = breaker_on(&manual_clock(), 1);
		breaker.record_auth_failure(signer());

		assert!(breaker.is_open(signer()));

		breaker.reset(signer());

		assert_eq!(breaker.state(signer()), CircuitState::Closed);
		assert!(breaker.admit_request(signer()));
	}

	#[test]
	fn replay_guard_accepts_first_rejects_second() {
		let guard = ReplayGuard::new(Duration::from_millis(30_000));
		assert!(guard.check_and_insert(b"signer-1", &accepted(1), UnixMillis::new(1_000)));
		assert!(!guard.check_and_insert(b"signer-1", &accepted(1), UnixMillis::new(2_000)));
		assert!(guard.check_and_insert(b"signer-1", &accepted(2), UnixMillis::new(2_000)));
	}

	#[test]
	fn replay_guard_prunes_expired_entries() {
		let guard = ReplayGuard::new(Duration::from_millis(1_000));
		assert!(guard.check_and_insert(b"signer-1", &accepted(1), UnixMillis::new(1_000)));
		assert!(guard.check_and_insert(b"signer-1", &accepted(1), UnixMillis::new(3_000)));
	}

	#[test]
	fn replay_guard_prunes_future_dated_entries_after_clock_regression() {
		let guard = ReplayGuard::new(Duration::from_millis(1_000));
		assert!(guard.check_and_insert(b"signer-1", &accepted(1), UnixMillis::new(10_000)));
		assert!(guard.check_and_insert(b"signer-1", &accepted(1), UnixMillis::new(5_000)));
	}

	#[test]
	fn replay_guard_saturated_signer_does_not_block_others() {
		let guard = ReplayGuard::new(Duration::from_millis(30_000));
		let seeded = (0..REPLAY_GUARD_CAPACITY)
			.all(|i| guard.check_and_insert(b"signer-1", &accepted(i + 10), UnixMillis::new(1_000)));
		assert!(seeded);
		assert!(!guard.check_and_insert(b"signer-1", &accepted(REPLAY_GUARD_CAPACITY + 1), UnixMillis::new(1_000)));
		assert!(guard.check_and_insert(b"signer-2", &accepted(1), UnixMillis::new(1_000)));
	}

	#[test]
	fn replay_guard_rejects_replay_across_signer_partitions() {
		let guard = ReplayGuard::new(Duration::from_millis(30_000));
		assert!(guard.check_and_insert(b"signer-1", &accepted(1), UnixMillis::new(1_000)));
		assert!(!guard.check_and_insert(b"signer-2", &accepted(1), UnixMillis::new(1_000)));
	}

	#[test]
	fn replay_guard_forget_permits_retry() {
		let guard = ReplayGuard::new(Duration::from_millis(30_000));
		assert!(guard.check_and_insert(b"signer-1", &accepted(1), UnixMillis::new(1_000)));
		guard.forget(&accepted(1));
		assert!(guard.check_and_insert(b"signer-1", &accepted(1), UnixMillis::new(2_000)));
	}

	#[test]
	fn replay_guard_freshness_window_is_bidirectional() {
		let guard = ReplayGuard::new(Duration::from_millis(1_000));
		assert!(guard.is_fresh(UnixMillis::new(9_500), UnixMillis::new(10_000)));
		assert!(guard.is_fresh(UnixMillis::new(10_500), UnixMillis::new(10_000)));
		assert!(!guard.is_fresh(UnixMillis::new(8_999), UnixMillis::new(10_000)));
		assert!(!guard.is_fresh(UnixMillis::new(11_001), UnixMillis::new(10_000)));
	}

	fn work_frame(priority: Option<MessagePriority>) -> Result<Frame, TightBeamError> {
		// Priority is a V2+ metadata field, so the frame is V2.
		let mut builder = Version::V2
			.compose()
			.with_id(b"work")
			.with_order(0)
			.with_message(TestMessage { content: "payload".into() });
		if let Some(priority) = priority {
			builder = builder.with_priority(priority);
		}

		builder.build()
	}

	#[test]
	fn backpressure_gate_ignores_priority() -> Result<(), TightBeamError> {
		let utilization = Arc::new(AtomicU16::new(9_500));
		let gate = BackpressureGate::new(utilization, BasisPoints::new_saturating(9_000));
		let frame = work_frame(Some(MessagePriority::NetworkControl))?;
		assert_eq!(
			GatePolicy::evaluate(&gate, Some(&frame), &SessionContext::default()),
			TransitStatus::ResourceExhausted
		);

		Ok(())
	}

	#[test]
	fn backpressure_gate_accepts_below_threshold() -> Result<(), TightBeamError> {
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
	fn peer_allow_list_admits_listed_key_only() -> Result<(), KeyListError> {
		let gate = PeerListGate::allow([listed(&listed_peer())])?;
		assert_eq!(gate.admit(Some(&key_of(&listed_peer()))), TransitStatus::Ok);
		assert_eq!(gate.admit(Some(&key_of(&unlisted_peer()))), TransitStatus::PermissionDenied);
		Ok(())
	}

	#[test]
	fn peer_allow_list_fails_closed_without_identity() -> Result<(), KeyListError> {
		let gate = PeerListGate::allow([listed(&listed_peer())])?;
		assert_eq!(gate.admit(None), TransitStatus::Unauthenticated);
		Ok(())
	}

	#[test]
	fn peer_deny_list_refuses_listed_key_only() -> Result<(), KeyListError> {
		let gate = PeerListGate::deny([listed(&listed_peer())])?;
		assert_eq!(gate.admit(Some(&key_of(&listed_peer()))), TransitStatus::PermissionDenied);
		assert_eq!(gate.admit(Some(&key_of(&unlisted_peer()))), TransitStatus::Ok);
		Ok(())
	}

	#[test]
	fn peer_deny_list_admits_absent_identity() -> Result<(), KeyListError> {
		let gate = PeerListGate::deny([listed(&listed_peer())])?;
		assert_eq!(gate.admit(None), TransitStatus::Ok);
		Ok(())
	}

	#[test]
	fn peer_list_empty_context_answers_as_absent_peer() -> Result<(), Box<dyn std::error::Error>> {
		let frame = work_frame(None)?;
		let empty = SessionContext::default();
		let allow = PeerListGate::allow([listed(&listed_peer())])?;
		let deny = PeerListGate::deny([listed(&listed_peer())])?;
		assert_eq!(
			GatePolicy::evaluate(&allow, Some(&frame), &empty),
			TransitStatus::Unauthenticated
		);
		assert_eq!(GatePolicy::evaluate(&deny, Some(&frame), &empty), TransitStatus::Ok);

		Ok(())
	}

	/// One secp256k1 point in either SEC 1 form is one key, so a deny list of
	/// the uncompressed key refuses a session of its compressed form.
	#[test]
	fn a_deny_list_refuses_its_key_in_the_compressed_form() -> Result<(), KeyListError> {
		let gate = PeerListGate::deny([listed(&listed_peer())])?;
		let refused = GatePolicy::evaluate(&gate, None, &compressed_session());
		assert_eq!(refused, TransitStatus::PermissionDenied);
		Ok(())
	}

	/// An allow list of the uncompressed key admits a session of its
	/// compressed form, as the store admits a certificate re-issued in it.
	#[test]
	fn an_allow_list_admits_its_key_in_the_compressed_form() -> Result<(), KeyListError> {
		let gate = PeerListGate::allow([listed(&listed_peer())])?;
		let admitted = GatePolicy::evaluate(&gate, None, &compressed_session());
		assert_eq!(admitted, TransitStatus::Ok);
		Ok(())
	}

	/// A deny list of the P-256 key of RFC 6979 §A.2.5 in the uncompressed
	/// form, read under a decoder of P-256, refuses a session of its
	/// compressed form.
	#[test]
	fn a_deny_list_refuses_a_p256_key_in_the_compressed_form() -> Result<(), KeyListError> {
		let uncompressed = with_p256_point(&TestKey::RFC6979_P256_UNCOMPRESSED);
		let compressed = with_p256_point(&TestKey::RFC6979_P256_COMPRESSED);
		let gate = PeerListGate::new(PeerListMode::Deny, P256, [listed(&uncompressed)])?;

		let session = SessionContext::for_peer(Arc::new(compressed));
		let refused = GatePolicy::evaluate(&gate, None, &session);
		assert_eq!(refused, TransitStatus::PermissionDenied);
		Ok(())
	}

	/// A list under the house set holds no decoder of P-256, so an entry of
	/// the P-256 key of RFC 6979 §A.2.5 refuses the list.
	#[test]
	fn a_list_entry_on_a_curve_without_a_decoder_refuses_the_list() {
		let p256 = with_p256_point(&TestKey::RFC6979_P256_UNCOMPRESSED);
		assert_eq!(refusal_of(&p256), Some(KeyListError::NoDecoder { index: 1 }));
	}

	/// A key of another algorithm names no point of a curve, so a deny list
	/// holds it and refuses its session.
	#[test]
	fn a_deny_list_of_a_key_of_another_algorithm_refuses_its_session() -> Result<(), KeyListError> {
		let ed25519 = under_algorithm(ID_ED_25519);
		let gate = PeerListGate::deny([listed(&ed25519)])?;
		let session = SessionContext::for_peer(Arc::new(ed25519));

		let refused = GatePolicy::evaluate(&gate, None, &session);
		assert_eq!(refused, TransitStatus::PermissionDenied);
		Ok(())
	}

	/// An entry that is no SubjectPublicKeyInfo refuses the list, so a deny
	/// list never lets the peer it meant to name pass.
	#[test]
	fn a_list_entry_that_is_no_key_refuses_the_list() {
		let refused = PeerListGate::deny([b"key-a"]);
		assert_eq!(refused.err(), Some(KeyListError::Unreadable { index: 0 }));
	}

	/// An entry that names an off-curve encoding of a secp256k1 key refuses
	/// the list, because no session holds that key.
	#[test]
	fn a_list_entry_off_its_curve_refuses_the_list() {
		let alias = TestCertificate::with_off_curve_key(listed_peer());
		assert_eq!(refusal_of(&alias), Some(KeyListError::NoPoint { index: 1 }));
	}

	/// RFC 5480 §2.2 refuses the compact form, so an entry in it names no
	/// point and refuses the list.
	#[test]
	fn a_list_entry_in_the_compact_form_refuses_the_list() {
		let compact = TestCertificate::with_compact_key(listed_peer());
		assert_eq!(refusal_of(&compact), Some(KeyListError::NoPoint { index: 1 }));
	}

	/// RFC 5480 §2.2 refuses the hybrid form, so an entry in it names no
	/// point and refuses the list.
	#[test]
	fn a_list_entry_in_the_hybrid_form_refuses_the_list() {
		let hybrid = TestCertificate::with_key_form(listed_peer(), 0x06);
		assert_eq!(refusal_of(&hybrid), Some(KeyListError::NoPoint { index: 1 }));
	}

	/// A key on a binary-field curve reads as its bits, so an entry of one
	/// names no point and refuses the list.
	#[test]
	fn a_list_entry_on_a_binary_field_curve_refuses_the_list() {
		let binary = TestCertificate::with_named_curve(listed_peer(), SECT233K1);
		assert_eq!(refusal_of(&binary), Some(KeyListError::NoPoint { index: 1 }));
	}

	/// No use reads a key under `id-ecDH` (RFC 5480 §2.1.2), so an entry of
	/// one refuses the list.
	#[test]
	fn a_list_entry_under_ec_dh_refuses_the_list() {
		let restricted = under_algorithm(ID_EC_DH);
		assert_eq!(refusal_of(&restricted), Some(KeyListError::NoPoint { index: 1 }));
	}

	/// The breaker keys on the identity of the peer's key, so the failures of
	/// a session of one form open the circuit of a session of the other.
	#[test]
	fn the_breaker_counts_one_point_in_either_form_as_one_peer() {
		let uncompressed = SessionContext::for_peer(Arc::new(listed_peer()));
		let compressed = compressed_session();
		let breaker = breaker();
		breaker.record_auth_failure(proven(&uncompressed));
		breaker.record_auth_failure(proven(&uncompressed));
		breaker.record_auth_failure(proven(&uncompressed));

		assert!(breaker.is_open(proven(&compressed)));
	}

	/// A trust store that resolves every signer and fails every signature,
	/// which drives [`TrustVerification::Invalid`] deterministically.
	#[derive(Debug)]
	struct AlwaysInvalid {
		signer: PeerCertificate<ErasedSigning>,
	}

	impl CertificateValidation for AlwaysInvalid {
		fn evaluate(&self, _cert: &Certificate) -> Result<(), CertificateValidationError> {
			Ok(())
		}
	}

	impl VerificationPolicy for AlwaysInvalid {
		fn verify_signature(
			&self,
			_algorithm: &ObjectIdentifier,
			_public_key_der: &[u8],
			_message: &[u8],
			_signature: &[u8],
		) -> Result<VerifiedSignature, CertificateValidationError> {
			Err(CertificateValidationError::SignatureVerificationFailed(signature::Error::new()))
		}

		fn digest(
			&self,
			signature: &ObjectIdentifier,
			digest: &ObjectIdentifier,
			content: &[u8],
		) -> Result<Vec<u8>, CertificateValidationError> {
			Secp256k1Policy::default().digest(signature, digest, content)
		}
	}

	impl CertificateTrust for AlwaysInvalid {
		fn is_trusted(&self, _cert: &Certificate) -> bool {
			true
		}

		fn verify_chain(&self, _chain: &[Certificate]) -> Result<Arc<Certificate>, CertificateValidationError> {
			Ok(Arc::clone(self.signer.certificate()))
		}

		fn trust_anchor(&self, _cert: &Certificate) -> Result<Arc<Certificate>, CertificateValidationError> {
			Ok(Arc::clone(self.signer.certificate()))
		}

		fn find_by_signer_identifier(&self, _sid: &SignerIdentifier) -> Option<&PeerCertificate<ErasedSigning>> {
			Some(&self.signer)
		}

		fn find_by_public_key(&self, _spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate> {
			Some(self.signer.certificate())
		}

		fn to_policy_ref(&self) -> &dyn VerificationPolicy {
			self
		}
	}

	/// A trust store that resolves every signer and accepts every signature,
	/// which drives [`TrustVerification::Verified`] deterministically.
	#[derive(Debug)]
	struct AlwaysVerified {
		signer: PeerCertificate<ErasedSigning>,
	}

	impl CertificateValidation for AlwaysVerified {
		fn evaluate(&self, _cert: &Certificate) -> Result<(), CertificateValidationError> {
			Ok(())
		}
	}

	impl VerificationPolicy for AlwaysVerified {
		fn verify_signature(
			&self,
			_algorithm: &ObjectIdentifier,
			_public_key_der: &[u8],
			_message: &[u8],
			signature: &[u8],
		) -> Result<VerifiedSignature, CertificateValidationError> {
			Ok(VerifiedSignature::verify::<Secp256k1Signature, _>(
				&AcceptAll, [0u8; 32], signature,
			)?)
		}

		fn digest(
			&self,
			signature: &ObjectIdentifier,
			digest: &ObjectIdentifier,
			content: &[u8],
		) -> Result<Vec<u8>, CertificateValidationError> {
			Secp256k1Policy::default().digest(signature, digest, content)
		}
	}

	impl CertificateTrust for AlwaysVerified {
		fn is_trusted(&self, _cert: &Certificate) -> bool {
			true
		}

		fn verify_chain(&self, _chain: &[Certificate]) -> Result<Arc<Certificate>, CertificateValidationError> {
			Ok(Arc::clone(self.signer.certificate()))
		}

		fn trust_anchor(&self, _cert: &Certificate) -> Result<Arc<Certificate>, CertificateValidationError> {
			Ok(Arc::clone(self.signer.certificate()))
		}

		fn find_by_signer_identifier(&self, _sid: &SignerIdentifier) -> Option<&PeerCertificate<ErasedSigning>> {
			Some(&self.signer)
		}

		fn find_by_public_key(&self, _spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate> {
			Some(self.signer.certificate())
		}

		fn to_policy_ref(&self) -> &dyn VerificationPolicy {
			self
		}
	}

	/// A signed heartbeat issued at `clock`'s current instant.
	async fn signed_heartbeat(clock: &ManualClock, identity: &SigningIdentity) -> Result<Frame, TightBeamError> {
		let probe = ClusterCommandKind::Heartbeat(HeartbeatParams { cluster_status: ClusterStatus::Healthy });
		let mut signed = Version::V2
			.compose()
			.with_id(b"command")
			.with_order(clock.unix().get())
			.with_message(ClusterCommand::from(probe))
			.with_witness_hasher::<Sha3_256>()
			.build()?;
		signed.sign_with_provider(identity).await?;
		Ok(signed)
	}

	/// A gate that verifies a frame and a session that proves its peer,
	/// which is the arrangement every admission question is asked under.
	///
	/// The gate and the frame's issue time read one clock, so the frame is
	/// fresh until the test moves that clock.
	struct VerifiedGate {
		gate: ClusterSecurityGate,
		sender: SessionContext,
		signed: Frame,
		clock: Arc<ManualClock>,
	}

	/// [`VerifiedGate`] under `limits`.
	async fn verified_gate_with(limits: GateLimits) -> Result<VerifiedGate, TightBeamError> {
		let clock = manual_clock();
		let identity = TestIdentity::insecure_fixed();
		let certificate = identity.certificate().clone();
		let signed = signed_heartbeat(&clock, &identity).await?;
		let signer = identity.signing_certificate().clone();
		let trust_store = Arc::new(AlwaysVerified { signer });
		let gate = ClusterSecurityGate::new(trust_store, limits, erased(&clock));
		let sender = SessionContext::for_peer(Arc::new(certificate));

		Ok(VerifiedGate { gate, sender, signed, clock })
	}

	/// [`VerifiedGate`] under [`limits`].
	async fn verified_gate() -> Result<VerifiedGate, TightBeamError> {
		verified_gate_with(limits()).await
	}

	/// A verdict judges a frame without spending it, so the control plane
	/// that gated on the verdict can still admit the same frame.
	#[tokio::test]
	async fn a_gate_verdict_leaves_the_admission_unspent() -> Result<(), TightBeamError> {
		let VerifiedGate { gate, sender, signed, .. } = verified_gate().await?;
		assert_eq!(gate.evaluate(Some(&signed), &sender), TransitStatus::Ok);
		assert_eq!(gate.evaluate(Some(&signed), &sender), TransitStatus::Ok);
		assert!(gate.admit(signed, &sender).is_ok());
		Ok(())
	}

	/// A verdict still refuses a captured frame, because the signature the
	/// frame carries is already recorded (CWE-294).
	#[tokio::test]
	async fn a_gate_verdict_refuses_a_frame_already_admitted() -> Result<(), TightBeamError> {
		let VerifiedGate { gate, sender, signed, .. } = verified_gate().await?;
		assert!(gate.admit(signed.to_owned(), &sender).is_ok());
		assert_eq!(gate.evaluate(Some(&signed), &sender), TransitStatus::PermissionDenied);
		Ok(())
	}

	/// A captured command replayed with its signature's `s` flipped to
	/// `n - s` verifies under a real trust store (SEC 1 v2.0 §4.1.4), to the
	/// value its original verifies to. The gate refuses it as a replay, not as
	/// a forgery, because both forms key one replay slot.
	#[tokio::test]
	async fn a_command_replayed_with_its_s_flipped_is_refused() -> Result<(), TightBeamError> {
		let clock = manual_clock();
		let identity = TestIdentity::insecure_fixed();
		let certificate = identity.certificate().clone();
		let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(certificate.clone())?
			.build();

		let store = Arc::new(store);
		let gate = ClusterSecurityGate::new(Arc::clone(&store) as Arc<dyn CertificateTrust>, limits(), erased(&clock));
		let sender = SessionContext::for_peer(Arc::new(certificate));
		let signed = signed_heartbeat(&clock, &identity).await?;
		let flipped = TestFrame::with_flipped_s(&signed);
		let original = store.verify_frame(&signed);
		let twin = store.verify_frame(&flipped);
		let admitted = gate.admit(signed, &sender).is_ok();
		let inspected = gate.inspect(&flipped, &sender, clock.unix()).err();
		let replayed = gate.admit(flipped, &sender).err().map(|refusal| refusal.status());

		let verified = (original, twin);
		assert!(matches!(verified, (TrustVerification::Verified(_, a), TrustVerification::Verified(_, b)) if a == b));
		assert!(admitted);
		assert!(matches!(
			inspected,
			Some(InspectRefusal::Plain(TransitStatus::PermissionDenied))
		));
		assert_eq!(replayed, Some(TransitStatus::PermissionDenied));
		Ok(())
	}

	/// A verdict leaves a tripped breaker's one cooldown probe for the
	/// admission to take. Spending it on a question parks the circuit
	/// half-open with no outcome recorded, and half-open admits every
	/// request that follows.
	#[tokio::test]
	async fn a_gate_verdict_does_not_take_the_breakers_cooldown_probe() -> Result<(), TightBeamError> {
		let VerifiedGate { gate, sender, signed, .. } = verified_gate_with(instant_cooldown()).await?;
		let peer_key = peer_key(&sender);
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

	/// A refused admission leaves the breaker as it found it.
	///
	/// The cooldown probe admits exactly one request. Spending it on a
	/// path that then refuses parks the circuit half-open with no outcome
	/// recorded, and half-open admits everything that follows.
	#[tokio::test]
	async fn a_refused_admission_does_not_strand_the_breaker_half_open() -> Result<(), TightBeamError> {
		let VerifiedGate { gate, sender, signed, clock } = verified_gate_with(instant_cooldown()).await?;
		let peer_key = peer_key(&sender);
		let breaker_key = || ProvenPeer::for_test(&peer_key);

		gate.circuit_breaker.record_auth_failure(breaker_key());

		assert!(gate.circuit_breaker.is_open(breaker_key()));

		// Fill this signer's replay partition, so the admission refuses
		// after the checks that spend have started.
		fill_replay_partition(&gate, signer_id(&signed), clock.unix());

		let refusal = gate.admit(signed, &sender).err().map(|refusal| refusal.status());
		assert_eq!(refusal, Some(TransitStatus::PermissionDenied));
		assert!(gate.circuit_breaker.is_open(breaker_key()));
		Ok(())
	}

	/// The breaker a gate builds cools on the gate's clock, so a circuit
	/// the gate opened admits its probe once that one clock reaches the
	/// cooldown.
	#[tokio::test]
	async fn a_gates_breaker_cools_on_the_gates_clock() -> Result<(), TightBeamError> {
		let VerifiedGate { gate, sender, clock, .. } = verified_gate().await?;
		let peer_key = peer_key(&sender);
		let breaker_key = || ProvenPeer::for_test(&peer_key);
		gate.circuit_breaker.record_auth_failure(breaker_key());
		gate.circuit_breaker.record_auth_failure(breaker_key());
		gate.circuit_breaker.record_auth_failure(breaker_key());
		assert!(!gate.circuit_breaker.would_allow(breaker_key()));

		clock.advance(COOLDOWN);

		assert!(gate.circuit_breaker.would_allow(breaker_key()));
		Ok(())
	}

	/// A caller who copies a trusted `SignerIdentifier` and attaches a bad
	/// signature is counted against its own transport peer, so the copied
	/// signer keeps its budget (CWE-345).
	///
	/// The count runs through `admit`, because that is where a frame is
	/// submitted. A verdict judges the same frame without counting it.
	#[tokio::test]
	async fn a_forged_signer_id_gates_the_sender_not_the_signer() -> Result<(), TightBeamError> {
		let clock = manual_clock();
		let identity = TestIdentity::insecure_fixed();

		let mut signed = Version::V2
			.compose()
			.with_id(b"control")
			.with_order(clock.unix().get())
			.with_message(TestMessage { content: "payload".into() })
			.with_witness_hasher::<Sha3_256>()
			.build()?;
		signed.sign_with_provider(&identity).await?;

		let signer_key = key_of(identity.certificate());
		let signer = identity.signing_certificate().clone();
		let trust_store = Arc::new(AlwaysInvalid { signer });
		let gate = ClusterSecurityGate::new(trust_store, limits(), erased(&clock));

		let sender = SessionContext::for_peer(Arc::new(unlisted_peer()));
		let sender_key = peer_key(&sender);
		let refusals = [
			gate.admit(signed.to_owned(), &sender).err().map(|refusal| refusal.status()),
			gate.admit(signed.to_owned(), &sender).err().map(|refusal| refusal.status()),
			gate.admit(signed.to_owned(), &sender).err().map(|refusal| refusal.status()),
		];

		assert_eq!(refusals, [Some(TransitStatus::PermissionDenied); 3]);
		assert!(gate.circuit_breaker.is_open(ProvenPeer::for_test(&sender_key)));
		assert!(!gate.circuit_breaker.is_open(ProvenPeer::for_test(&signer_key)));

		Ok(())
	}

	/// One signer's failures leave every other signer admitted, so a
	/// compromised member leaves the colony control plane open (CWE-645).
	#[test]
	fn a_tripped_signer_does_not_gate_another() {
		let breaker = tripped_breaker();
		assert!(breaker.is_open(signer()));
		assert!(!breaker.admit_request(signer()));
		assert!(breaker.admit_request(other()));
	}

	/// A signature recorded under one signer is refused under another, so
	/// an alternate `SignerIdentifier` encoding grants no extra replay.
	#[test]
	fn a_replay_is_refused_across_partitions() {
		const OTHER: &[u8] = b"other-signer";

		let guard = ReplayGuard::new(Duration::from_millis(60_000));
		assert!(guard.check_and_insert(SIGNER, &accepted(1), UnixMillis::new(1_000)));
		assert!(!guard.check_and_insert(OTHER, &accepted(1), UnixMillis::new(1_000)));
	}

	/// An expired record frees its capacity and admits the same signature
	/// again, so the window bounds retention and the partition holds its size.
	#[test]
	fn an_expired_record_is_admitted_again() {
		let guard = ReplayGuard::new(Duration::from_millis(1_000));
		assert!(guard.check_and_insert(SIGNER, &accepted(1), UnixMillis::new(1_000)));
		assert!(guard.check_and_insert(SIGNER, &accepted(1), UnixMillis::new(5_000)));
	}

	// A refusal releases the replay slot only where a retry of the same
	// signed frame could be answered differently, so a captured frame
	// buys its holder nothing on a refusal that holds for every retry.
	tb_cases! {
		fn a_refusal_releases_the_slot_only_where_a_retry_can_change_it(
			(refusal, releases): (CommandRefusal, bool)
		) {
			assert_eq!(refusal.releases_replay(), releases);
		}
		cases {
			draining => (CommandRefusal::Draining, false),
			backpressure => (CommandRefusal::Backpressure, true),
			unknown_servlet_type => (CommandRefusal::UnknownServletType, false),
			spawn_failed => (CommandRefusal::SpawnFailed, true),
			unnameable_instance => (CommandRefusal::UnnameableInstance, false),
			registry_fault => (CommandRefusal::RegistryFault, true),
			unknown_instance => (CommandRefusal::UnknownInstance, false),
		}
	}

	/// A transient refusal releases the slot, so the same signed frame is
	/// admitted again.
	#[tokio::test]
	async fn a_transient_refusal_admits_the_same_frame_again() -> Result<(), TightBeamError> {
		let VerifiedGate { gate, sender, signed, .. } = verified_gate().await?;
		let admitted = gate
			.admit(signed.to_owned(), &sender)
			.ok()
			.ok_or(TightBeamError::MissingResponse)?;

		admitted.refuse(CommandRefusal::Backpressure)?;

		assert!(gate.admit(signed, &sender).is_ok());
		Ok(())
	}

	/// A permanent refusal keeps the slot spent, so the same signed frame
	/// is refused as a replay.
	#[tokio::test]
	async fn a_permanent_refusal_refuses_the_same_frame_as_a_replay() -> Result<(), TightBeamError> {
		let VerifiedGate { gate, sender, signed, .. } = verified_gate().await?;
		let admitted = gate
			.admit(signed.to_owned(), &sender)
			.ok()
			.ok_or(TightBeamError::MissingResponse)?;

		admitted.refuse(CommandRefusal::Draining)?;

		let replay = gate.admit(signed, &sender).err().map(|refusal| refusal.status());
		assert_eq!(replay, Some(TransitStatus::PermissionDenied));
		Ok(())
	}
}
