//! The gate policies for hive security and backpressure.
//!
//! - [`ClusterSecurityGate`] authenticates cluster commands. It runs its
//!   [`ClusterCircuitBreaker`] and its [`ReplayGuard`] on one clock.
//! - [`BackpressureGate`] refuses work while the hive runs at its capacity threshold.
//! - [`PeerListGate`] admits or refuses a session by its peer certificate key.

use core::sync::atomic::{AtomicU16, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::basis_points::BasisPoints;
use crate::clock::{Clock, MonotonicInstant, UnixMillis};
use crate::colony::cluster::FreshnessWindow;
use crate::colony::hive::runtime::{InsertRefusal, RemoveRefusal};
use crate::colony::protocol::{AcceptedRecord, ClusterCommand, ClusterCommandResponse, IssuedAt, ReplyShape};
use crate::crypto::sign::VerifiedSignature;
use crate::crypto::x509::store::{CertificateTrust, TrustVerification};
use crate::crypto::x509::{CanonicalKey, KeyCurves, KeyList, KeyListError};
use crate::der::Encode;
use crate::instrumentation::events::{HIVE_COMMAND_ACCEPTED, HIVE_COMMAND_REFUSED};
use crate::policy::{GatePolicy, ProvenPeer, SessionContext, TransitStatus};
use crate::trace::TraceCollector;
use crate::{Frame, TightBeamError};

/// The states of one signer's circuit in a [`ClusterCircuitBreaker`].
///
/// A tripped circuit refuses every request of its signer until its cooldown
/// passes, and then admits requests again. A request whose signature verifies
/// closes it and clears its count, and a failure that comes first opens it
/// for another cooldown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitState {
	/// The circuit admits requests in normal operation.
	Closed = 0,
	/// The circuit has tripped and rejects every request until its cooldown
	/// passes.
	Open = 1,
}

/// A circuit breaker for cluster authentication failures.
///
/// Consecutive failures of one signer trip its circuit, which halts cluster
/// traffic with it.
///
/// # Cooldown
///
/// After a cooldown, the circuit admits requests again. A request whose
/// signature verifies closes it and clears its count, and a failure that comes
/// first opens it for another cooldown. The cooldown runs on the monotonic
/// clock, so a step of the system time neither shortens nor stretches it.
///
/// # Failures that count
///
/// Only failures of a *known* signer count ([`ClusterSecurityGate`]), so
/// unauthenticated frames cannot cut a hive off from its cluster (CWE-645).
/// Each signer's failures gate that signer alone, so the colony control plane
/// stays open to every other member.
///
/// # Thread Safety
///
/// One mutex holds every circuit, so the verdict and the close of
/// [`Self::admit_verified`] are one step (CWE-367).
pub struct ClusterCircuitBreaker {
	/// The per-signer circuits, one row for each signer with a failure history.
	/// A poisoned lock answers every signer as open, so the breaker fails
	/// closed as the replay guard does.
	signers: Mutex<HashMap<CanonicalKey, SignerCircuit>>,
	/// The count of consecutive failures that trips a signer's circuit.
	failure_threshold: u8,
	/// The time an open circuit refuses requests before it admits them again.
	cooldown: Duration,
	/// The clock the breaker measures the cooldown on.
	clock: Arc<dyn Clock>,
}

/// Where one signer's circuit stands.
///
/// An open circuit carries the instant it opened, the start of its cooldown.
#[derive(Clone, Copy)]
enum Position {
	Closed,
	Open(MonotonicInstant),
}

impl Position {
	fn state(self) -> CircuitState {
		match self {
			Self::Closed => CircuitState::Closed,
			Self::Open(_) => CircuitState::Open,
		}
	}
}

/// One signer's breaker position and its count of consecutive failures.
#[derive(Clone, Copy)]
struct SignerCircuit {
	position: Position,
	failures: u8,
}

impl SignerCircuit {
	const CLOSED: Self = Self { position: Position::Closed, failures: 0 };

	/// Returns whether this circuit is closed with no failures. It then carries
	/// no history, so [`ClusterCircuitBreaker::prune`] drops its row.
	const fn is_quiescent(&self) -> bool {
		matches!(self.position, Position::Closed) && self.failures == 0
	}
}

impl ClusterCircuitBreaker {
	/// Creates a breaker that opens after `failure_threshold` consecutive
	/// failures from one signer and admits that signer again once `cooldown`
	/// has passed on `clock`.
	pub fn new(failure_threshold: u8, cooldown: Duration, clock: Arc<dyn Clock>) -> Self {
		Self { signers: Mutex::new(HashMap::new()), failure_threshold, cooldown, clock }
	}

	/// Returns whether a cooldown that started at `since` has passed.
	fn cooled(&self, since: MonotonicInstant) -> bool {
		self.clock.monotonic().saturating_duration_since(since) >= self.cooldown
	}

	/// The verdict on one request through `circuit`: a closed circuit admits
	/// it, and an open one admits it once its cooldown has passed.
	fn admits(&self, circuit: &SignerCircuit) -> bool {
		match circuit.position {
			Position::Closed => true,
			Position::Open(since) => self.cooled(since),
		}
	}

	/// Returns whether the breaker would admit the next request from `signer`.
	///
	/// The check is read-only, and it reads the verdict that
	/// [`Self::admit_verified`] takes, so a request that passes it passes the
	/// admission unless a failure lands between the two. A poisoned lock
	/// refuses every request.
	#[must_use]
	pub fn would_allow(&self, signer: ProvenPeer<'_>) -> bool {
		let Ok(signers) = self.signers.lock() else {
			return false;
		};

		signers.get(signer.as_key()).is_none_or(|circuit| self.admits(circuit))
	}

	/// Admits one request whose signature the caller verified, from `signer`,
	/// and closes its circuit, in one critical section.
	///
	/// - A closed circuit, or an open one whose cooldown has passed, admits the
	///   request and clears its history.
	/// - An open circuit within its cooldown refuses the request.
	/// - A poisoned lock refuses every request.
	///
	/// The verdict and the close take one lock, so a failure that another
	/// request records for the signer lands before or after both (CWE-367).
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	/// use std::sync::Arc;
	///
	/// use tightbeam::clock::SystemClock;
	/// use tightbeam::colony::hive::ClusterCircuitBreaker;
	/// use tightbeam::policy::SessionContext;
	///
	/// /// Whether `breaker` admits the verified request of the peer that
	/// /// `session` proved, which closes the circuit of that peer.
	/// fn admits(breaker: &ClusterCircuitBreaker, session: &SessionContext) -> bool {
	///     session.proven_peer().is_some_and(|peer| breaker.admit_verified(peer))
	/// }
	///
	/// // A session that proved no peer has no circuit to admit through.
	/// let breaker = ClusterCircuitBreaker::new(3, Duration::from_secs(30), Arc::new(SystemClock));
	/// assert!(!admits(&breaker, &SessionContext::default()));
	/// ```
	pub fn admit_verified(&self, signer: ProvenPeer<'_>) -> bool {
		let Ok(mut signers) = self.signers.lock() else {
			return false;
		};

		let admitted = signers.get(signer.as_key()).is_none_or(|circuit| self.admits(circuit));
		if admitted {
			signers.remove(signer.as_key());
		}

		admitted
	}

	/// Records an authentication failure attributed to `signer`.
	///
	/// A failure on an open circuit restarts its cooldown.
	pub fn record_auth_failure(&self, signer: ProvenPeer<'_>) {
		let Ok(mut signers) = self.signers.lock() else {
			return;
		};

		let circuit = signers.entry(signer.as_key().clone()).or_insert(SignerCircuit::CLOSED);
		circuit.failures = circuit.failures.saturating_add(1);
		if circuit.failures >= self.failure_threshold {
			circuit.position = Position::Open(self.clock.monotonic());
		}
	}

	/// Returns the current circuit state for `signer`. A poisoned lock reports
	/// [`CircuitState::Open`].
	pub fn state(&self, signer: ProvenPeer<'_>) -> CircuitState {
		let Ok(signers) = self.signers.lock() else {
			return CircuitState::Open;
		};

		signers
			.get(signer.as_key())
			.map_or(CircuitState::Closed, |circuit| circuit.position.state())
	}

	/// Returns whether `signer`'s circuit is open (tripped).
	pub fn is_open(&self, signer: ProvenPeer<'_>) -> bool {
		self.state(signer) == CircuitState::Open
	}

	/// Closes `signer`'s circuit and clears its failure history.
	pub fn reset(&self, signer: ProvenPeer<'_>) {
		let Ok(mut signers) = self.signers.lock() else {
			return;
		};

		signers.remove(signer.as_key());
	}

	/// Drops the rows of signers that carry no failure history.
	pub fn prune(&self) {
		let Ok(mut signers) = self.signers.lock() else {
			return;
		};

		signers.retain(|_, circuit| !circuit.is_quiescent());
	}
}

/// The maximum number of distinct signatures the replay guard remembers per
/// signer in one freshness window.
///
/// A signer's command rate inside one window bounds its legitimate traffic.
/// Each signer's partition fails closed at capacity, which holds while an
/// attacker lacks the fresh valid signatures that would fill it.
pub const REPLAY_GUARD_CAPACITY: usize = 1024;

/// The recorded signatures of each signer, each with the instant its frame
/// states.
type SignerPartitions = HashMap<Arc<[u8]>, HashMap<VerifiedSignature, UnixMillis>>;

/// The recorded signatures, partitioned by signer and indexed by signature.
///
/// The partitions hold the per-signer capacity. The index finds a signature
/// in one lookup, so admission costs the same for one trusted signer or a
/// thousand. Each key is a [`VerifiedSignature`], so a signature and its
/// `(r, n - s)` twin are one key.
#[derive(Default)]
struct SeenSignatures {
	partitions: SignerPartitions,
	owner: HashMap<VerifiedSignature, Arc<[u8]>>,
}

impl SeenSignatures {
	/// Returns whether `signature` is recorded and the instant its frame states
	/// lies inside the window.
	///
	/// It is read-only, so a verdict can ask it and a later admission sees the
	/// same records. It borrows the signer from the index.
	fn is_live(&self, signature: &VerifiedSignature, now: UnixMillis, window: FreshnessWindow) -> bool {
		self.owner
			.get(signature)
			.and_then(|signer| self.partitions.get(signer.as_ref()))
			.and_then(|sigs| sigs.get(signature))
			.is_some_and(|at| window.admits(*at, now))
	}

	/// Drops the expired records that an admission of `signature` for
	/// `signer` meets: the record of `signature`, in whichever partition holds
	/// it, and each expired record of `signer`.
	///
	/// An expired signature so returns its capacity on the next admission.
	fn prune(&mut self, signer: &[u8], signature: &VerifiedSignature, now: UnixMillis, window: FreshnessWindow) {
		let expired = self.owner.contains_key(signature) && !self.is_live(signature, now, window);
		if expired {
			self.forget(signature);
		}

		self.expire(signer, now, window);
	}

	/// Returns whether the guard admits a frame of `signer` that states
	/// `order` and carries `signature`, at `now`.
	///
	/// It is the one rule of the guard. It reads live records alone, so a
	/// verdict and an admission that pruned the expired records answer alike:
	///
	/// 1. `order` lies inside the window.
	/// 2. No live record holds `signature`, in any partition. Either
	///    `SignerIdentifier` CHOICE arm can name one certificate, so a check of
	///    one partition would grant one replay per encoding.
	/// 3. `signer` holds no live record at `order`.
	/// 4. `signer` holds fewer than [`REPLAY_GUARD_CAPACITY`] live records.
	fn admits(
		&self,
		signer: &[u8],
		signature: &VerifiedSignature,
		order: UnixMillis,
		now: UnixMillis,
		window: FreshnessWindow,
	) -> bool {
		if !window.admits(order, now) {
			return false;
		}
		if self.is_live(signature, now, window) {
			return false;
		}
		if self.holds_order(signer, order, now, window) {
			return false;
		}

		self.live_len_for(signer, now, window) < REPLAY_GUARD_CAPACITY
	}

	/// Drops `signer`'s expired records. The work is bounded by the
	/// per-signer capacity, so each signer's history costs that signer alone.
	fn expire(&mut self, signer: impl AsRef<[u8]>, now: UnixMillis, window: FreshnessWindow) {
		let signer = signer.as_ref();
		let Some(sigs) = self.partitions.get_mut(signer) else {
			return;
		};

		sigs.retain(|signature, at| {
			let live = window.admits(*at, now);
			if !live {
				self.owner.remove(signature);
			}

			live
		});

		if sigs.is_empty() {
			self.partitions.remove(signer);
		}
	}

	/// Records `signature` of `signer`, whose frame states `order`. The
	/// partition and the owner index share one allocation of the signer,
	/// which is the key of its partition once the signer holds one.
	fn record(&mut self, signer: impl AsRef<[u8]>, signature: &VerifiedSignature, order: UnixMillis) {
		let signer = signer.as_ref();
		let held = self.partitions.get_key_value(signer).map(|(held, _)| Arc::clone(held));
		let shared = held.unwrap_or_else(|| Arc::from(signer));
		let partition = self.partitions.entry(Arc::clone(&shared)).or_default();
		partition.insert(signature.clone(), order);

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

	/// Returns how many records of `signer` state an order inside the window.
	///
	/// The scan reads one partition, which [`REPLAY_GUARD_CAPACITY`] bounds.
	fn live_len_for(&self, signer: impl AsRef<[u8]>, now: UnixMillis, window: FreshnessWindow) -> usize {
		let partition = self.partitions.get(signer.as_ref());
		let orders = partition.into_iter().flat_map(HashMap::values);
		orders.filter(|at| window.admits(**at, now)).count()
	}

	/// Returns whether `signer` holds a record whose frame states `order`,
	/// while that order lies inside the window.
	///
	/// The scan reads one partition, which [`REPLAY_GUARD_CAPACITY`] bounds,
	/// as [`Self::expire`] does.
	fn holds_order(
		&self,
		signer: impl AsRef<[u8]>,
		order: UnixMillis,
		now: UnixMillis,
		window: FreshnessWindow,
	) -> bool {
		let partition = self.partitions.get(signer.as_ref());
		let held = partition.is_some_and(|sigs| sigs.values().any(|at| *at == order));

		held && window.admits(order, now)
	}
}

/// A bounded freshness and replay window for signed cluster commands.
///
/// It accepts a command when its `Frame.metadata.order` lies within the
/// window of the hive clock, in either direction to tolerate skew, it holds
/// no live record of the signature, and the signer holds no live record of
/// another frame at that order. [`ReplayGuard::admits`] is that rule, and
/// [`ReplayGuard::check_and_insert`] applies it before it records.
///
/// - The guard tracks signatures per signer, so a signer that saturates its partition blocks only itself.
/// - Each record keeps its frame's order, so it lives exactly as long as its frame is fresh (CWE-294).
/// - The orders of each signer are one message namespace, so a second frame
///   of one signer at one order is a duplicate whatever its signature (README
///   §5.7.1).
/// - Each insert prunes that signer's entries more than the window from the
///   clock, so [`REPLAY_GUARD_CAPACITY`] per trusted signer bounds the memory.
pub struct ReplayGuard {
	seen: Mutex<SeenSignatures>,
	window: FreshnessWindow,
}

impl ReplayGuard {
	/// Creates a guard with a freshness `window` around the hive clock.
	pub fn new(window: Duration) -> Self {
		let window = FreshnessWindow::new(window);
		Self { seen: Mutex::new(SeenSignatures::default()), window }
	}

	/// Returns whether `order` (`Frame.metadata.order`) is within the freshness
	/// window of `now`, by the rule of [`FreshnessWindow::admits`].
	pub fn is_fresh(&self, order: UnixMillis, now: UnixMillis) -> bool {
		self.window.admits(order, now)
	}

	/// Returns whether the guard admits a frame of `signer` that states
	/// `order` (`Frame.metadata.order`) and carries `signature`, at `now`.
	///
	/// It is the one rule of the guard, which
	/// [`ReplayGuard::check_and_insert`] applies before it records:
	///
	/// - `order` lies inside the window, as [`ReplayGuard::is_fresh`] answers.
	/// - No live record holds `signature`, as [`ReplayGuard::is_replay`] answers.
	/// - `signer` holds no live record at `order`, as [`ReplayGuard::holds_order`] answers (README §5.7.1).
	/// - `signer` holds fewer than [`REPLAY_GUARD_CAPACITY`] live records.
	///
	/// It is read-only, so a verdict asks it and the admission spends the
	/// slot. A poisoned lock answers `false`, so a verdict fails closed.
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::clock::UnixMillis;
	/// use tightbeam::colony::hive::ReplayGuard;
	/// use tightbeam::crypto::sign::ecdsa::Secp256k1Signature;
	/// use tightbeam::crypto::sign::{PrehashSigner, VerifiedSignature};
	/// use tightbeam::testing::fixtures::TestKey;
	///
	/// let key = TestKey::insecure_fixed_signing();
	/// let prehash = [7u8; 32];
	/// let signed: Secp256k1Signature = key.sign_prehash(&prehash)?;
	/// let signature = VerifiedSignature::verify::<Secp256k1Signature, _>(key.verifying_key(), prehash, signed)?;
	///
	/// let guard = ReplayGuard::new(Duration::from_secs(30));
	/// let order = UnixMillis::new(100_000);
	///
	/// // A verdict spends nothing, so the admission records the frame.
	/// assert!(guard.admits(b"signer", &signature, order, order));
	/// assert!(guard.check_and_insert(b"signer", &signature, order, order));
	/// assert!(!guard.admits(b"signer", &signature, order, order));
	///
	/// // An order 40 s from the clock lies outside the 30 s window.
	/// assert!(!guard.admits(b"other", &signature, order, UnixMillis::new(140_000)));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[must_use]
	pub fn admits(
		&self,
		signer: impl AsRef<[u8]>,
		signature: &VerifiedSignature,
		order: UnixMillis,
		now: UnixMillis,
	) -> bool {
		let Ok(seen) = self.seen.lock() else {
			return false;
		};

		seen.admits(signer.as_ref(), signature, order, now, self.window)
	}

	/// Returns whether the guard holds a record of `signature` within the
	/// window.
	///
	/// It is read-only, as [`ReplayGuard::admits`] is. A poisoned lock answers
	/// `true`, so a caller fails closed as an admission does.
	#[must_use]
	pub fn is_replay(&self, signature: &VerifiedSignature, now: UnixMillis) -> bool {
		let Ok(seen) = self.seen.lock() else {
			return true;
		};

		seen.is_live(signature, now, self.window)
	}

	/// Returns whether the guard holds a live record of a frame of `signer`
	/// that states `order` (`Frame.metadata.order`).
	///
	/// The orders of each signer are one message namespace, so a second frame
	/// of `signer` at `order` is a duplicate whatever its signature (README
	/// §5.7.1). It is read-only, as [`ReplayGuard::is_replay`] is, and a
	/// poisoned lock answers `true`.
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::clock::UnixMillis;
	/// use tightbeam::colony::hive::ReplayGuard;
	/// use tightbeam::crypto::sign::ecdsa::Secp256k1Signature;
	/// use tightbeam::crypto::sign::{PrehashSigner, VerifiedSignature};
	/// use tightbeam::testing::fixtures::TestKey;
	///
	/// let key = TestKey::insecure_fixed_signing();
	/// let prehash = [7u8; 32];
	/// let signed: Secp256k1Signature = key.sign_prehash(&prehash)?;
	/// let signature = VerifiedSignature::verify::<Secp256k1Signature, _>(key.verifying_key(), prehash, signed)?;
	///
	/// let guard = ReplayGuard::new(Duration::from_secs(30));
	/// let order = UnixMillis::new(100_000);
	/// assert!(guard.check_and_insert(b"signer", &signature, order, order));
	///
	/// // Another frame of the signer at that order is a duplicate, and another
	/// // signer's order is its own.
	/// assert!(guard.holds_order(b"signer", order, order));
	/// assert!(!guard.holds_order(b"other", order, order));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[must_use]
	pub fn holds_order(&self, signer: impl AsRef<[u8]>, order: UnixMillis, now: UnixMillis) -> bool {
		let Ok(seen) = self.seen.lock() else {
			return true;
		};

		seen.holds_order(signer, order, now, self.window)
	}

	/// Records `signature` for `signer`, whose frame states `order`, when
	/// [`ReplayGuard::admits`] admits the frame.
	///
	/// - It drops the expired records it meets, then applies the rule of
	///   [`ReplayGuard::admits`] and records under the same lock, so of two
	///   frames that race for one slot, one spends it (CWE-367).
	/// - The record keeps `order` (`Frame.metadata.order`), so it lives exactly
	///   as long as the frame is fresh, even when `order` leads the clock
	///   (CWE-294).
	/// - It returns `true` for a fresh frame with a new signature at a new order, which it records.
	/// - It returns `false` for a stale order, a replay, and a second frame of
	///   `signer` at `order` (README §5.7.1), and fails closed on a full
	///   partition or a poisoned lock.
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::clock::UnixMillis;
	/// use tightbeam::colony::hive::ReplayGuard;
	/// use tightbeam::crypto::sign::ecdsa::Secp256k1Signature;
	/// use tightbeam::crypto::sign::{PrehashSigner, VerifiedSignature};
	/// use tightbeam::testing::fixtures::TestKey;
	///
	/// let key = TestKey::insecure_fixed_signing();
	/// let prehash = [7u8; 32];
	/// let signed: Secp256k1Signature = key.sign_prehash(&prehash)?;
	/// let signature = VerifiedSignature::verify::<Secp256k1Signature, _>(key.verifying_key(), prehash, signed)?;
	///
	/// // The signer's clock leads this one by 20 s, inside the 30 s window.
	/// let guard = ReplayGuard::new(Duration::from_secs(30));
	/// let order = UnixMillis::new(120_000);
	/// assert!(guard.check_and_insert(b"signer", &signature, order, UnixMillis::new(100_000)));
	///
	/// // 40 s on, the order is still fresh, so its record refuses the replay.
	/// assert!(!guard.check_and_insert(b"signer", &signature, order, UnixMillis::new(140_000)));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn check_and_insert(
		&self,
		signer: impl AsRef<[u8]>,
		signature: &VerifiedSignature,
		order: UnixMillis,
		now: UnixMillis,
	) -> bool {
		let signer = signer.as_ref();
		let Ok(mut seen) = self.seen.lock() else {
			return false;
		};

		seen.prune(signer, signature, now, self.window);
		if !seen.admits(signer, signature, order, now, self.window) {
			return false;
		}

		seen.record(signer, signature, order);

		true
	}

	/// Removes a recorded signature, so the sender may retry the frame.
	///
	/// The guard records the signature before the guarded operation runs. When
	/// that operation fails, the caller must release the record, or the guard
	/// refuses a legitimate retry as a replay until the window expires. A
	/// poisoned guard admits nothing, so it holds no slot to release.
	pub fn forget(&self, signature: &VerifiedSignature) {
		let Ok(mut seen) = self.seen.lock() else {
			return;
		};

		seen.forget(signature);
	}
}

/// The gate that admits a signed cluster command: nonrepudiation, integrity,
/// freshness, and replay.
///
/// # Security Flow
///
/// | Step | Check | Refusal |
/// | --- | --- | --- |
/// | 1 | The frame carries a nonrepudiation signature | `Unauthenticated` |
/// | 2 | The frame carries its integrity | `Unauthenticated` |
/// | 3 | The handshake proved a peer, whose circuit is closed | `Unauthenticated`, or `PermissionDenied` while open |
/// | 4 | The trust store holds the signer certificate | `PermissionDenied` |
/// | 5 | The signature verifies under that certificate | `PermissionDenied`, **counted** |
/// | 6 | The verified signer is the handshake-proven peer | `PermissionDenied` |
/// | 7 | `Frame.metadata.order` is fresh | `PermissionDenied` |
/// | 8 | The signature and the order are new, and the partition has room (README §5.7.1) | `PermissionDenied` |
///
/// On success the breaker admits the command and closes the circuit of its
/// peer in one step.
///
/// - Only step 5 counts, against the [`ProvenPeer`], so one member's failures gate it alone (CWE-645).
/// - Steps 6 to 8 stay uncounted, because a relayed or replayed capture carries a valid signature.
/// - Step 6 makes the peer of each admitted command its signer, so its record names that party (CWE-778).
///
/// # Breaker key
///
/// - The gate reads the breaker before the signature, so the breaker keys on the handshake-proven peer.
/// - [`ProvenPeer`] is its only key, so a caller who copies a trusted
///   `SignerIdentifier` spends its own budget (CWE-345).
/// - An unauthenticated transport offers no key. One row for every anonymous
///   caller would let one bad signature deny the rest, so this plane requires
///   a proven peer (CWE-645).
pub struct ClusterSecurityGate {
	/// The breaker that counts authentication failures, on this gate's clock.
	circuit_breaker: ClusterCircuitBreaker,
	/// The trust store for certificate lookup and signature verification.
	trust_store: Arc<dyn CertificateTrust>,
	/// The freshness window and the replay set for signed commands.
	///
	/// The gate shares the guard with every [`AdmittedCommand`] it admits, so
	/// a refusal the command meets later can release the slot it spent.
	replay_guard: Arc<ReplayGuard>,
	/// The clock the gate judges a command's freshness against, and the one
	/// the breaker's cooldown runs on.
	clock: Arc<dyn Clock>,
}

/// The thresholds one [`ClusterSecurityGate`] enforces.
///
/// The named fields keep a call site from swapping the two durations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateLimits {
	/// The count of consecutive bad signatures from one peer that opens its
	/// circuit.
	pub failure_threshold: u8,
	/// The time an open circuit refuses commands before it admits them again.
	pub cooldown: Duration,
	/// How far a command's stated issue time may sit from the gate clock.
	pub freshness_window: Duration,
}

/// A cluster command this gate has authenticated and decoded.
///
/// The body is the command the admission decoded, so a dispatcher matches
/// its alternative on that one decode. `signature` is the one the trust store
/// verified, and `replay_guard` holds the slot it spent.
pub(crate) struct AdmittedCommand {
	body: ClusterCommand,
	frame: Frame,
	signature: VerifiedSignature,
	replay_guard: Arc<ReplayGuard>,
}

impl AdmittedCommand {
	/// Returns the command that admission decoded.
	pub(crate) fn body(&self) -> &ClusterCommand {
		&self.body
	}

	/// Returns the frame the command arrived on.
	pub(crate) fn frame(&self) -> &Frame {
		&self.frame
	}

	/// Answers this command, which the hive carried out, with `response` in
	/// the shape its body names.
	///
	/// A spawn or a stop changes a servlet, so its record goes on `audit`
	/// ahead of the reply, as [`ClusterCommand::accepted`] names it.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the reply body does not encode.
	/// - [`TightBeamError::BuildError`] -- the reply metadata fails validation.
	/// - [`TightBeamError`] -- the runtime fault model injects a fault at the acceptance event.
	pub(crate) fn reply(
		&self,
		response: ClusterCommandResponse,
		audit: &CommandAudit<'_>,
	) -> Result<Option<Frame>, TightBeamError> {
		if let Some(record) = self.body.accepted(&response) {
			audit.accepted(&record)?;
		}

		self.body.reply_shape().reply(self.frame.metadata().id(), response)
	}

	/// Refuses this command in the shape its body names, and records the
	/// refusal on `audit`.
	///
	/// The refusal decides whether the command releases its replay slot:
	///
	/// - A refusal that a retry of the same signed frame can change gives the
	///   slot back, so the cluster may resubmit the frame.
	/// - A refusal that holds for every resubmission keeps the slot spent, so a
	///   captured frame buys its holder nothing.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the reply body does not encode.
	/// - [`TightBeamError::BuildError`] -- the reply metadata fails validation.
	/// - [`TightBeamError`] -- the runtime fault model injects a fault at the refusal event.
	pub(crate) fn refuse(
		&self,
		refusal: CommandRefusal,
		audit: &CommandAudit<'_>,
	) -> Result<Option<Frame>, TightBeamError> {
		if refusal.releases_replay() {
			self.forget_replay();
		}

		let status = refusal.status();
		let reply = self.body.reply_shape().refuse(self.frame.metadata().id(), status)?;
		audit.refused(refusal.name(), status)?;

		Ok(reply)
	}

	/// Releases the replay slot this command's signature spent, so the gate
	/// admits a signed retry of the same frame again.
	fn forget_replay(&self) {
		self.replay_guard.forget(&self.signature);
	}
}

/// Why the control plane refused a command the gate had admitted.
///
/// Each variant knows whether the hive could answer a retry of the same
/// signed frame differently, so a handler names its refusal and this type
/// decides the replay slot for [`AdmittedCommand::refuse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandRefusal {
	/// The hive is draining, which ends with the hive gone.
	Draining,
	/// The hive is at capacity, which clears as work completes.
	Backpressure,
	/// The servlet type holds the most instances its bounds admit, which
	/// clears as an instance stops.
	AtCapacity,
	/// The servlet type holds the fewest instances its bounds admit.
	BelowFloor,
	/// The hive holds no spawner for the requested servlet type.
	UnknownServletType,
	/// The spawner ran and produced no servlet.
	SpawnFailed,
	/// The spawned servlet's address is not a valid instance locator.
	UnnameableInstance,
	/// The servlet registry refused the insert.
	RegistryFault,
	/// The stop named no live instance.
	UnknownInstance,
}

impl CommandRefusal {
	/// Returns the name of this refusal, the label of the refusal event.
	pub(crate) fn name(self) -> &'static str {
		match self {
			Self::Draining => "Draining",
			Self::Backpressure => "Backpressure",
			Self::AtCapacity => "AtCapacity",
			Self::BelowFloor => "BelowFloor",
			Self::UnknownServletType => "UnknownServletType",
			Self::SpawnFailed => "SpawnFailed",
			Self::UnnameableInstance => "UnnameableInstance",
			Self::RegistryFault => "RegistryFault",
			Self::UnknownInstance => "UnknownInstance",
		}
	}

	/// Returns the status the sender reads.
	pub(crate) fn status(self) -> TransitStatus {
		match self {
			Self::Draining | Self::SpawnFailed | Self::RegistryFault => TransitStatus::Unavailable,
			Self::Backpressure | Self::AtCapacity => TransitStatus::ResourceExhausted,
			Self::BelowFloor => TransitStatus::FailedPrecondition,
			Self::UnknownServletType | Self::UnnameableInstance | Self::UnknownInstance => {
				TransitStatus::PermissionDenied
			}
		}
	}

	/// Returns whether the hive could answer a retry of the same signed frame
	/// differently.
	///
	/// A refusal that a retry meets again keeps the slot spent:
	///
	/// - A drain is terminal.
	/// - A servlet type or instance the hive does not have stays absent.
	/// - A servlet that names itself badly does so on every spawn.
	/// - A stop at the floor stops nothing however often it repeats.
	pub(crate) fn releases_replay(self) -> bool {
		match self {
			Self::Backpressure | Self::AtCapacity | Self::SpawnFailed | Self::RegistryFault => true,
			Self::Draining
			| Self::BelowFloor
			| Self::UnknownServletType
			| Self::UnnameableInstance
			| Self::UnknownInstance => false,
		}
	}
}

impl From<InsertRefusal> for CommandRefusal {
	/// The refusal that answers a spawn the instance set turned away.
	fn from(refusal: InsertRefusal) -> Self {
		match refusal {
			InsertRefusal::Draining => Self::Draining,
			InsertRefusal::AtCapacity => Self::AtCapacity,
			InsertRefusal::Unnameable(_) => Self::UnnameableInstance,
			InsertRefusal::Registry(_) => Self::RegistryFault,
		}
	}
}

impl From<RemoveRefusal> for CommandRefusal {
	/// The refusal that answers a stop the instance set turned away.
	fn from(refusal: RemoveRefusal) -> Self {
		match refusal {
			RemoveRefusal::Absent => Self::UnknownInstance,
			RemoveRefusal::AtFloor => Self::BelowFloor,
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
	/// Refuses `frame` with `status`, and reads its reply shape from one
	/// decode of the command body.
	///
	/// A body that does not decode as a command has no heartbeat shape, so
	/// the refusal answers in the management stop shape that
	/// [`ReplyShape::of`] names.
	pub(crate) fn denied(frame: Frame, status: TransitStatus) -> Box<Self> {
		let body = ClusterCommand::choice_of(&frame);
		let shape = ReplyShape::of(body.as_ref());

		Self::boxed(frame, status, shape)
	}

	fn boxed(frame: Frame, status: TransitStatus, shape: ReplyShape) -> Box<Self> {
		Box::new(Self { frame, status, shape })
	}

	/// Returns the status the control plane answers with.
	pub(crate) fn status(&self) -> TransitStatus {
		self.status
	}

	/// Answers the refused frame in the shape its body named, and records the
	/// refusal on `audit` under the name of its status.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the reply body does not encode.
	/// - [`TightBeamError::BuildError`] -- the reply metadata fails validation.
	/// - [`TightBeamError`] -- the runtime fault model injects a fault at the refusal event.
	pub(crate) fn reply(&self, audit: &CommandAudit<'_>) -> Result<Option<Frame>, TightBeamError> {
		let status = self.status();
		let reply = self.shape.refuse(self.frame.metadata().id(), status)?;
		audit.refused(status.as_str(), status)?;

		Ok(reply)
	}
}

/// The trail that one cluster command leaves: the trace its records go on,
/// and the session of the peer that sent the command.
///
/// - [`AdmittedCommand::refuse`] and [`AdmitRefusal::reply`] take it, so a
///   refusal reply leaves the hive with its [`HIVE_COMMAND_REFUSED`] event.
/// - [`AdmittedCommand::reply`] takes it, so a spawn or a stop that the hive
///   carries out leaves its [`HIVE_COMMAND_ACCEPTED`] event.
pub(crate) struct CommandAudit<'a> {
	trace: &'a TraceCollector,
	session: &'a SessionContext,
}

impl<'a> CommandAudit<'a> {
	/// Binds the records of one command to `trace` for a proven peer, and to
	/// `connections` otherwise (CWE-778). Each record names the session's peer.
	pub(crate) fn new(trace: &'a TraceCollector, connections: &'a TraceCollector, session: &'a SessionContext) -> Self {
		let proven = session.proven_peer().is_some();
		let trace = if proven {
			trace
		} else {
			connections
		};

		Self { trace, session }
	}

	/// Records [`HIVE_COMMAND_REFUSED`] for a refusal that `label` names and
	/// whose sender reads `status`, with the canonical key of the peer as its
	/// payload.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the runtime fault model injects a fault at the event.
	fn refused(&self, label: &'static str, status: TransitStatus) -> Result<(), TightBeamError> {
		let peer = self.peer();
		self.trace
			.emit_event_with_value_and_evidence(HIVE_COMMAND_REFUSED, label, status, peer)
	}

	/// Records [`HIVE_COMMAND_ACCEPTED`] for a command that the hive carried
	/// out, under the label of `record`, with the canonical key of the peer
	/// as its payload. The gate bound that peer to the verified signer of the
	/// command at admission.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the runtime fault model injects a fault at the event.
	fn accepted(&self, record: &AcceptedRecord<'_>) -> Result<(), TightBeamError> {
		let peer = self.peer();
		self.trace
			.emit_rendered_event(HIVE_COMMAND_ACCEPTED, || record.to_string(), (), || peer)
	}

	/// Returns the canonical key of the peer, in DER, as the payload of each
	/// record.
	fn peer(&self) -> Option<&[u8]> {
		self.session.peer_key().map(CanonicalKey::as_der)
	}
}

/// What the read-only checks proved about one frame.
///
/// The gate holds it between [`ClusterSecurityGate::inspect`] and the steps
/// that spend, so those steps read what the checks already derived.
struct Authenticated<'a> {
	signature: VerifiedSignature,
	signer_id: Vec<u8>,
	breaker_key: ProvenPeer<'a>,
}

/// Why [`ClusterSecurityGate::inspect`] refused a frame.
///
/// A bad signature is the one refusal an admission counts against the
/// breaker, so it has its own variant. The verdict reports it and records
/// nothing, and the admission records it once.
enum InspectRefusal {
	/// The gate refused the frame before, or independently of, the signature
	/// check.
	Plain(TransitStatus),
	/// The signature fails verification against the trust store.
	BadSignature,
}

impl InspectRefusal {
	/// Returns the status a caller answers the sender with.
	fn status(&self) -> TransitStatus {
		match self {
			Self::Plain(status) => *status,
			Self::BadSignature => TransitStatus::PermissionDenied,
		}
	}
}

impl ClusterSecurityGate {
	/// Creates a security gate that trusts the certificates in `trust_store`
	/// and enforces `limits` on `clock`. The breaker's cooldown and the
	/// freshness window both read `clock`.
	pub fn new(trust_store: Arc<dyn CertificateTrust>, limits: GateLimits, clock: Arc<dyn Clock>) -> Self {
		let GateLimits { failure_threshold, cooldown, freshness_window } = limits;
		let circuit_breaker = ClusterCircuitBreaker::new(failure_threshold, cooldown, Arc::clone(&clock));
		let replay_guard = Arc::new(ReplayGuard::new(freshness_window));

		Self { circuit_breaker, trust_store, replay_guard, clock }
	}

	/// Judges `frame` with read-only checks.
	///
	/// The verdict covers the signer and its binding to the peer, the peer's
	/// circuit, and the rule of [`ReplayGuard::admits`]: freshness, replay, a
	/// duplicate order, and a full partition. It refuses a captured frame,
	/// whose signature is already recorded, and a second frame of the signer
	/// at a recorded order, and it changes no record.
	///
	/// # Left to the admission
	///
	/// - The admission records an auth failure.
	/// - It refuses a body that names no single command.
	/// - It records the signature under the lock that applies the guard's rule again.
	/// - It closes the circuit of the peer.
	fn inspect<'a>(
		&self,
		frame: &Frame,
		session: &'a SessionContext,
		now: UnixMillis,
	) -> Result<Authenticated<'a>, InspectRefusal> {
		let Some(signer) = frame.nonrepudiation() else {
			return Err(InspectRefusal::Plain(TransitStatus::Unauthenticated));
		};

		// A command declares the protections it requires, such as frame
		// integrity, so a frame that lacks one carries no command.
		if frame.validate_for::<ClusterCommand>().is_err() {
			return Err(InspectRefusal::Plain(TransitStatus::Unauthenticated));
		}

		// The replay partition keys on the signer, which the verification
		// below proves. An unencodable identifier has no attribution, so
		// it fails closed.
		let Ok(signer_id) = signer.sid.to_der() else {
			return Err(InspectRefusal::Plain(TransitStatus::PermissionDenied));
		};

		// The breaker keys on the handshake-proven peer, so the gate refuses a
		// transport that proves none here (CWE-345, CWE-645).
		let Some(breaker_key) = session.proven_peer() else {
			return Err(InspectRefusal::Plain(TransitStatus::Unauthenticated));
		};

		if !self.circuit_breaker.would_allow(breaker_key) {
			return Err(InspectRefusal::Plain(TransitStatus::PermissionDenied));
		}

		// The verified signature is the replay key, in its canonical form, so
		// a capture with `s` flipped to `n - s` keys the slot it already spent.
		let (signer, signature) = match self.trust_store.verify_frame(frame) {
			TrustVerification::MissingSignature => {
				return Err(InspectRefusal::Plain(TransitStatus::Unauthenticated));
			}
			TrustVerification::UnknownSigner => {
				return Err(InspectRefusal::Plain(TransitStatus::PermissionDenied));
			}
			TrustVerification::Invalid => return Err(InspectRefusal::BadSignature),
			TrustVerification::Verified(signer, signature) => (signer, signature),
		};

		// The gate binds the signer it verified to the peer the handshake
		// proved, so the record of an admitted command names the party that
		// signed it (CWE-778).
		let signer_key = &signer.certificate().tbs_certificate.subject_public_key_info;
		if !breaker_key.as_key().is_key_of(signer_key) {
			return Err(InspectRefusal::Plain(TransitStatus::PermissionDenied));
		}

		// The guard's rule runs here, so a verdict refuses a captured frame
		// (CWE-294). `admit` spends the slot itself.
		if !self.replay_guard.admits(&signer_id, &signature, frame.issued_at(), now) {
			return Err(InspectRefusal::Plain(TransitStatus::PermissionDenied));
		}

		Ok(Authenticated { signature, signer_id, breaker_key })
	}

	/// Authenticates `frame`, decodes its cluster command once, and spends
	/// the admission.
	///
	/// It records an auth failure, or closes the circuit of the peer, and
	/// spends the signature's replay slot. The control plane calls it exactly
	/// once per frame.
	pub(crate) fn admit(&self, frame: Frame, session: &SessionContext) -> Result<AdmittedCommand, Box<AdmitRefusal>> {
		// The body decodes once. A CHOICE names exactly one alternative, so a
		// body that names none or more than one decodes to `None`, which the
		// admission refuses once the frame authenticates.
		let body = ClusterCommand::choice_of(&frame);

		let shape = ReplyShape::of(body.as_ref());
		let now = self.clock.unix();
		let authenticated = match self.inspect(&frame, session, now) {
			Ok(authenticated) => authenticated,
			Err(refusal) => {
				// A bad signature counts once, here, where the caller submits
				// the frame for admission.
				if let (InspectRefusal::BadSignature, Some(breaker_key)) = (&refusal, session.proven_peer()) {
					self.circuit_breaker.record_auth_failure(breaker_key);
				}

				return Err(AdmitRefusal::boxed(frame, refusal.status(), shape));
			}
		};

		// Only a well-formed frame spends replay capacity (CWE-770). A body
		// that does not decode is malformed rather than unauthorized, and stays
		// wrong whatever this hive's state is.
		let Some(body) = body else {
			return Err(AdmitRefusal::boxed(frame, TransitStatus::InvalidArgument, shape));
		};

		let Authenticated { signature, signer_id, breaker_key } = authenticated;
		let order = frame.issued_at();
		if !self.replay_guard.check_and_insert(&signer_id, &signature, order, now) {
			return Err(AdmitRefusal::boxed(frame, TransitStatus::PermissionDenied, shape));
		}

		// The signature verified, so the breaker admits the command and closes
		// the circuit in one step (CWE-367).
		if !self.circuit_breaker.admit_verified(breaker_key) {
			// The gate refuses this frame, so it releases the signature: a
			// kept record would refuse a legitimate retry as a replay.
			self.replay_guard.forget(&signature);
			return Err(AdmitRefusal::boxed(frame, TransitStatus::PermissionDenied, shape));
		}

		let replay_guard = Arc::clone(&self.replay_guard);
		Ok(AdmittedCommand { body, frame, signature, replay_guard })
	}
}

impl GatePolicy for ClusterSecurityGate {
	/// Returns whether the gate would admit this frame, by a check that leaves
	/// the admission unspent.
	///
	/// Even so, it refuses a captured frame, because the guard already recorded
	/// its signature (CWE-294).
	///
	/// # Command-query separation
	///
	/// A verdict must not consume what it judges. Otherwise a transport that
	/// gates on this and then hands the frame to the control plane would see
	/// its own admission refused as a replay.
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
	/// The verdict on whether the hive takes work at that utilization.
	pub status: TransitStatus,
}

/// The gate policy that enforces hive capacity limits (backpressure).
///
/// It answers [`TransitStatus::ResourceExhausted`] when utilization reaches the
/// threshold, and the cluster then routes the work elsewhere or queues it.
///
/// # Exemptions
///
/// The gate applies to every frame, because any bypass keyed on
/// frame-controlled data, such as message priority, is attacker-selectable.
/// Callers that must admit specific traffic under load, such as heartbeats,
/// exempt it explicitly *after* authentication.
pub struct BackpressureGate {
	/// The current aggregate utilization in basis points.
	utilization: Arc<AtomicU16>,
	/// The utilization at or above which the gate refuses, from the hive's
	/// `backpressure_threshold`.
	threshold: BasisPoints,
}

impl BackpressureGate {
	/// Creates a gate that refuses requests while `utilization` is at or above
	/// `threshold`.
	pub fn new(utilization: Arc<AtomicU16>, threshold: BasisPoints) -> Self {
		Self { utilization, threshold }
	}

	/// Returns the current utilization, saturated into [`BasisPoints`].
	pub fn current_utilization(&self) -> BasisPoints {
		BasisPoints::new_saturating(self.utilization.load(Ordering::Relaxed))
	}

	/// Returns the verdict on whether the hive takes work at the current
	/// utilization.
	///
	/// It reads [`Self::report`], the one comparison of utilization against
	/// the threshold. The gate and the heartbeat both answer with it, so the
	/// capacity a hive reports matches the work it admits.
	#[must_use]
	pub fn status(&self) -> TransitStatus {
		self.report().status
	}

	/// Returns the utilization and the verdict that describes it, from one
	/// load.
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

/// The membership mode of a [`PeerListGate`].
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
	/// Creates a list in `mode` of these peer public keys (SPKI DER), each
	/// read under `curves`, so the decoder of a curve refuses its off-curve
	/// encodings.
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

	/// Creates an allow list that admits only these peer public keys (SPKI
	/// DER), read under [`KeyCurves::HOUSE`].
	///
	/// # Errors
	///
	/// - [`KeyListError`] -- an entry fails the read that [`Self::new`] runs, under [`KeyCurves::HOUSE`].
	pub fn allow<I, K>(keys: I) -> Result<Self, KeyListError>
	where
		I: IntoIterator<Item = K>,
		K: AsRef<[u8]>,
	{
		Self::new(PeerListMode::Allow, KeyCurves::HOUSE, keys)
	}

	/// Creates a deny list that refuses these peer public keys (SPKI DER),
	/// read under [`KeyCurves::HOUSE`].
	///
	/// # Errors
	///
	/// - [`KeyListError`] -- an entry fails the read that [`Self::new`] runs, under [`KeyCurves::HOUSE`].
	pub fn deny<I, K>(keys: I) -> Result<Self, KeyListError>
	where
		I: IntoIterator<Item = K>,
		K: AsRef<[u8]>,
	{
		Self::new(PeerListMode::Deny, KeyCurves::HOUSE, keys)
	}

	/// Returns the verdict for one peer identity.
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
	use std::sync::LazyLock;

	use super::*;
	use crate::builder::TypeBuilder;
	use crate::clock::ManualClock;
	use crate::colony::protocol::{ClusterStatus, HeartbeatParams};
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::sign::ecdsa::Secp256k1Signature;
	use crate::crypto::sign::PrehashSigner;
	use crate::crypto::x509::store::CertificateTrustStore;
	use crate::crypto::x509::Certificate;
	use crate::der::asn1::ObjectIdentifier;
	use crate::der::oid::db::rfc5912::ID_EC_DH;
	use crate::der::oid::db::rfc8410::ID_ED_25519;
	use crate::oids::CURVE_NIST_P256;
	use crate::tb_cases;
	use crate::testing::fixtures::{
		flip_last, TestCertificate, TestClock, TestIdentity, TestKey, TestP256Points, TestStore,
	};
	use crate::testing::{TestFrame, TestMessage, TestResult};
	use crate::{MessagePriority, Version};

	const SIGNER: &[u8] = b"signer-under-test";

	/// The first signer of the replay tests.
	const S1: &[u8] = b"signer-1";

	/// The second signer of the replay tests.
	const S2: &[u8] = b"signer-2";

	/// The key identity of [`listed_peer`], the signer under test.
	static SIGNER_KEY: LazyLock<CanonicalKey> = LazyLock::new(|| key_of(&listed_peer()));

	/// The key identity of [`unlisted_peer`], a second signer.
	static OTHER_KEY: LazyLock<CanonicalKey> = LazyLock::new(|| key_of(&unlisted_peer()));

	/// The cooldown every breaker fixture waits out.
	const COOLDOWN: Duration = Duration::from_millis(60_000);

	/// The freshness window every gate fixture judges against.
	const FRESHNESS_WINDOW: Duration = Duration::from_millis(60_000);

	/// Builds a breaker that opens after `failure_threshold` failures and
	/// waits out [`COOLDOWN`] on `clock`.
	fn breaker_on(clock: &Arc<ManualClock>, failure_threshold: u8) -> ClusterCircuitBreaker {
		ClusterCircuitBreaker::new(failure_threshold, COOLDOWN, TestClock::erased(clock))
	}

	/// Builds a breaker that opens after three failures, on a clock that
	/// stays still.
	fn breaker() -> ClusterCircuitBreaker {
		breaker_on(&TestClock::manual(), 3)
	}

	/// Records three authentication failures of `peer` on `breaker`, which
	/// open the circuit of `peer` on a breaker of three.
	fn trip(breaker: &ClusterCircuitBreaker, peer: ProvenPeer<'_>) {
		breaker.record_auth_failure(peer);
		breaker.record_auth_failure(peer);
		breaker.record_auth_failure(peer);
	}

	/// Returns gate limits that open after three failures and wait out
	/// [`COOLDOWN`].
	fn limits() -> GateLimits {
		GateLimits { failure_threshold: 3, cooldown: COOLDOWN, freshness_window: FRESHNESS_WINDOW }
	}

	/// Returns gate limits whose one failure opens a circuit that has already
	/// cooled, so the next admission closes it.
	fn instant_cooldown() -> GateLimits {
		GateLimits {
			failure_threshold: 1,
			cooldown: Duration::ZERO,
			freshness_window: FRESHNESS_WINDOW,
		}
	}

	/// Returns the identity under test, as a handshake would prove it.
	fn signer() -> ProvenPeer<'static> {
		ProvenPeer::for_test(&SIGNER_KEY)
	}

	/// Returns a second proven identity, for isolation assertions.
	fn other() -> ProvenPeer<'static> {
		ProvenPeer::for_test(&OTHER_KEY)
	}

	/// Returns the identity the handshake proved for `session`.
	fn proven(session: &SessionContext) -> ProvenPeer<'_> {
		session.proven_peer().expect("the session proved a peer")
	}

	/// Builds the certificate of the fixed test key, whose point is
	/// uncompressed.
	fn listed_peer() -> Certificate {
		TestCertificate::insecure_fixed()
	}

	/// Builds [`listed_peer`] with the P-256 key of RFC 6979 §A.2.5 in the
	/// SEC 1 form `point` holds.
	fn with_p256_point(point: &[u8]) -> Certificate {
		TestCertificate::with_curve_point(listed_peer(), CURVE_NIST_P256, point)
	}

	/// Builds the certificate of the negation of the fixed test key, another
	/// key.
	fn unlisted_peer() -> Certificate {
		TestCertificate::insecure_fixed_negation()
	}

	/// A session whose handshake proved the holder of `certificate`.
	fn session_of(certificate: Certificate) -> SessionContext {
		SessionContext::for_peer(Arc::new(certificate))
	}

	/// `sect233k1`, a SEC 2 curve over a binary field.
	const SECT233K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.26");

	/// The set that holds the decoder of P-256 alone.
	const P256: KeyCurves = KeyCurves::new(&[&TestP256Points]);

	/// Builds [`listed_peer`] with its key under `algorithm` and no parameters,
	/// a key of an algorithm other than `id-ecPublicKey`.
	fn under_algorithm(algorithm: ObjectIdentifier) -> Certificate {
		let mut certificate = listed_peer();
		let spki = &mut certificate.tbs_certificate.subject_public_key_info;
		spki.algorithm.oid = algorithm;
		spki.algorithm.parameters = None;
		certificate
	}

	/// Returns the SubjectPublicKeyInfo DER of `certificate`, as an operator
	/// lists it.
	fn listed(certificate: &Certificate) -> Vec<u8> {
		let spki = &certificate.tbs_certificate.subject_public_key_info;
		spki.to_der().expect("a test key encodes")
	}

	/// Returns the key identity a session of `certificate` proves.
	fn key_of(certificate: &Certificate) -> CanonicalKey {
		let spki = &certificate.tbs_certificate.subject_public_key_info;
		CanonicalKey::of(spki).expect("a test key has a canonical form")
	}

	/// Builds a session whose peer holds the key of [`listed_peer`] in the
	/// compressed form.
	fn compressed_session() -> SessionContext {
		session_of(TestCertificate::with_compressed_key(listed_peer()))
	}

	/// Returns the signer identifier `frame`'s signature names.
	fn signer_id(frame: &Frame) -> Vec<u8> {
		frame.signer_id().expect("the signed frame carries a signer id")
	}

	/// The verified signatures of the fixed test key over the prehashes `1`
	/// to one past the replay capacity, each distinct from the rest.
	static SIGNATURES: LazyLock<Vec<VerifiedSignature>> = LazyLock::new(|| {
		let key = TestKey::insecure_fixed_signing();
		let sign = |index: u64| {
			let mut prehash = [0u8; 32];
			prehash[24..].copy_from_slice(&index.to_be_bytes());

			let signed: Secp256k1Signature = key.sign_prehash(&prehash).expect("the fixed key signs a prehash");
			let verified = VerifiedSignature::verify::<Secp256k1Signature, _>(key.verifying_key(), prehash, signed);
			verified.expect("a signature of the fixed key verifies under its key")
		};

		(1..=REPLAY_GUARD_CAPACITY as u64 + 2).map(sign).collect()
	});

	/// Returns the verified signature `index` of [`SIGNATURES`].
	fn accepted(index: usize) -> VerifiedSignature {
		SIGNATURES[index].clone()
	}

	/// Fills `signer`'s replay partition of `guard` to capacity with frames
	/// issued one millisecond apart after `now`, so no filler states the order
	/// `now`.
	fn fill_replay_partition(guard: &ReplayGuard, signer: impl AsRef<[u8]>, now: UnixMillis) {
		let signer = signer.as_ref();
		let issued = |index: usize| now.saturating_add(Duration::from_millis(index as u64 + 1));
		let spend = |index: usize| guard.check_and_insert(signer, &accepted(index), issued(index), now);

		let filled = (0..REPLAY_GUARD_CAPACITY).all(spend);
		assert!(filled);
	}

	/// Spends the slot of `signature` under `signer` for a frame issued at
	/// `at`, as the clock reads `at`.
	fn spend_at(guard: &ReplayGuard, signer: &[u8], signature: &VerifiedSignature, at: u64) -> bool {
		let at = UnixMillis::new(at);
		guard.check_and_insert(signer, signature, at, at)
	}

	/// A breaker of three opens on its third failure.
	#[test]
	fn breaker_trips_after_threshold() {
		let breaker = breaker();
		breaker.record_auth_failure(signer());
		breaker.record_auth_failure(signer());

		let below = breaker.state(signer());

		breaker.record_auth_failure(signer());

		let verdict = (below, breaker.state(signer()), breaker.admit_verified(signer()));
		assert_eq!(verdict, (CircuitState::Closed, CircuitState::Open, false));
	}

	// The cooldown runs on the breaker's clock, so an open circuit admits a
	// request again once that clock reaches the cooldown and not before.
	tb_cases! {
		fn breaker_cooldown_runs_on_its_clock((advance, admitted): (Duration, bool)) {
			let clock = TestClock::manual();
			let breaker = breaker_on(&clock, 1);
			breaker.record_auth_failure(signer());
			clock.advance(advance);
			assert_eq!(breaker.admit_verified(signer()), admitted);
		}
		cases {
			one_millisecond_short => (COOLDOWN.saturating_sub(Duration::from_millis(1)), false),
			at_the_cooldown => (COOLDOWN, true),
		}
	}

	/// A failure on a circuit whose cooldown has passed opens it again, so its
	/// cooldown starts over.
	#[test]
	fn a_failure_after_the_cooldown_restarts_it() {
		let clock = TestClock::manual();
		let breaker = breaker_on(&clock, 1);
		breaker.record_auth_failure(signer());
		clock.advance(COOLDOWN);
		breaker.record_auth_failure(signer());
		assert!(!breaker.would_allow(signer()));
	}

	/// A reset closes an open circuit, so its peer is admitted again.
	#[test]
	fn breaker_reset_clears_state() {
		let breaker = breaker_on(&TestClock::manual(), 1);
		breaker.record_auth_failure(signer());
		breaker.reset(signer());

		let verdict = (breaker.state(signer()), breaker.admit_verified(signer()));
		assert_eq!(verdict, (CircuitState::Closed, true));
	}

	/// A step that puts the circuit of [`signer`] in the state a case names.
	type Prepare = fn(&ClusterCircuitBreaker, &ManualClock);

	/// Whether the gate admits the request, and the circuit state after it.
	type Verdict = (bool, CircuitState);

	/// Leaves the circuit of [`signer`] closed.
	fn leave_closed(_breaker: &ClusterCircuitBreaker, _clock: &ManualClock) {}

	/// Opens the circuit of [`signer`].
	fn open_circuit(breaker: &ClusterCircuitBreaker, _clock: &ManualClock) {
		breaker.record_auth_failure(signer());
	}

	/// Opens the circuit of [`signer`] and lets its cooldown pass.
	fn cool_circuit(breaker: &ClusterCircuitBreaker, clock: &ManualClock) {
		breaker.record_auth_failure(signer());
		clock.advance(COOLDOWN);
	}

	// A verified request passes a closed or a cooled circuit and closes it in
	// the same step, and an open circuit refuses it.
	tb_cases! {
		fn admit_verified_admits_a_closed_and_a_cooled_circuit_and_refuses_an_open_one(
			(prepare, verdict): (Prepare, Verdict)
		) {
			let clock = TestClock::manual();
			let breaker = breaker_on(&clock, 1);
			prepare(&breaker, &clock);

			let admitted = breaker.admit_verified(signer());
			assert_eq!((admitted, breaker.state(signer())), verdict);
		}
		cases {
			a_closed_circuit => (leave_closed, (true, CircuitState::Closed)),
			a_cooled_circuit => (cool_circuit, (true, CircuitState::Closed)),
			an_open_circuit => (open_circuit, (false, CircuitState::Open)),
		}
	}

	/// One spend of a replay slot: the signer, the index of the signature in
	/// [`SIGNATURES`], the order the frame states, and the clock reading.
	type Spend = (&'static [u8], usize, u64, u64);

	/// Spends `spend` on `guard`.
	fn spend(guard: &ReplayGuard, (signer, signature, order, now): Spend) -> bool {
		guard.check_and_insert(signer, &accepted(signature), UnixMillis::new(order), UnixMillis::new(now))
	}

	// The guard records the first spend, and judges a second spend by its
	// signature, its signer, its order, and the window. A signature the guard
	// recorded is a replay under any signer, and a second signature of one
	// signer at a recorded order is a duplicate (README §5.7.1). A record
	// leaves the guard once its order leaves the window, whichever way the
	// clock moved, and a record whose order leads the clock stays while that
	// order is fresh.
	tb_cases! {
		fn replay_guard_judges_a_second_spend((window_ms, first, second, admitted): (u64, Spend, Spend, bool)) {
			let guard = ReplayGuard::new(Duration::from_millis(window_ms));
			let first = spend(&guard, first);

			let second = spend(&guard, second);
			assert_eq!((first, second), (true, admitted));
		}
		cases {
			the_same_signature_later => (30_000, (S1, 1, 1_000, 1_000), (S1, 1, 2_000, 2_000), false),
			a_new_signature_later => (30_000, (S1, 1, 1_000, 1_000), (S1, 2, 2_000, 2_000), true),
			the_same_signature_past_the_window => (1_000, (S1, 1, 1_000, 1_000), (S1, 1, 3_000, 3_000), true),
			the_same_signature_after_a_clock_regression => (
				1_000,
				(S1, 1, 10_000, 10_000),
				(S1, 1, 5_000, 5_000),
				true,
			),
			a_future_dated_order_while_it_is_fresh => (1_000, (S1, 1, 1_900, 1_000), (S1, 1, 1_900, 2_100), false),
			the_same_signature_under_another_signer => (30_000, (S1, 1, 1_000, 1_000), (S2, 1, 1_000, 1_000), false),
			a_new_signature_at_the_same_order => (30_000, (S1, 1, 1_000, 1_000), (S1, 2, 1_000, 1_000), false),
			another_signer_at_the_same_order => (30_000, (S1, 1, 1_000, 1_000), (S2, 2, 1_000, 1_000), true),
			/// An alternate `SignerIdentifier` encoding grants no extra replay.
			the_same_signature_under_another_encoding_of_the_signer => (
				60_000,
				(SIGNER, 1, 1_000, 1_000),
				(b"other-signer", 1, 1_000, 1_000),
				false,
			),
			/// The window bounds retention, so the partition holds its size.
			an_expired_record => (1_000, (SIGNER, 1, 1_000, 1_000), (SIGNER, 1, 5_000, 5_000), true),
		}
	}

	/// A signer whose partition is full refuses its next frame, and leaves
	/// every other signer its own partition.
	#[test]
	fn replay_guard_saturated_signer_does_not_block_others() {
		let guard = ReplayGuard::new(Duration::from_millis(30_000));
		let now = UnixMillis::new(1_000);
		fill_replay_partition(&guard, b"signer-1", now);

		let full = guard.check_and_insert(b"signer-1", &accepted(REPLAY_GUARD_CAPACITY), now, now);
		let other = guard.check_and_insert(b"signer-2", &accepted(REPLAY_GUARD_CAPACITY + 1), now, now);
		assert_eq!((full, other), (false, true));
	}

	// A released record frees its slot and its order, so the signer's retry
	// passes, under the same signature later or under a new signature at the
	// same order.
	tb_cases! {
		fn replay_guard_forget_frees_the_slot(retry: Spend) {
			let guard = ReplayGuard::new(Duration::from_millis(30_000));
			let first = spend_at(&guard, S1, &accepted(1), 1_000);
			guard.forget(&accepted(1));

			let retried = spend(&guard, retry);
			assert_eq!((first, retried), (true, true));
		}
		cases {
			the_same_signature_later => (S1, 1, 2_000, 2_000),
			a_new_signature_at_the_same_order => (S1, 2, 1_000, 1_000),
		}
	}

	// The window of one second reaches half a second each way from the clock
	// at 10 s, and an order past it either way is stale.
	tb_cases! {
		fn replay_guard_freshness_window_is_bidirectional((order, fresh): (u64, bool)) {
			let guard = ReplayGuard::new(Duration::from_millis(1_000));
			assert_eq!(guard.is_fresh(UnixMillis::new(order), UnixMillis::new(10_000)), fresh);
		}
		cases {
			half_a_window_behind => (9_500, true),
			half_a_window_ahead => (10_500, true),
			past_the_window_behind => (8_999, false),
			past_the_window_ahead => (11_001, false),
		}
	}

	/// A verdict of the guard spends no slot, so the admission after it
	/// records the frame.
	#[test]
	fn a_replay_guard_verdict_leaves_the_slot_to_the_admission() {
		let guard = ReplayGuard::new(Duration::from_millis(30_000));
		let at = UnixMillis::new(1_000);
		let verdict = || guard.admits(b"signer-1", &accepted(1), at, at);
		let verdicts = [verdict(), verdict()];
		let spent = guard.check_and_insert(b"signer-1", &accepted(1), at, at);
		assert_eq!((verdicts, spent), ([true, true], true));
	}

	/// The guard records a frame only while its order lies inside the window,
	/// so an admission refuses a stale order as a verdict does.
	#[test]
	fn replay_guard_refuses_an_order_outside_its_window() {
		let guard = ReplayGuard::new(Duration::from_millis(30_000));
		let stale = UnixMillis::new(1_000);
		let spent = guard.check_and_insert(b"signer-1", &accepted(1), stale, UnixMillis::new(10_000_000));
		assert!(!spent);
	}

	/// A V2 work frame that states `priority`, or no priority for `None`.
	fn work_frame(priority: Option<MessagePriority>) -> Frame {
		// Priority is a metadata field of V2 or later, so the frame is V2.
		let builder = Version::V2.compose().with_id(b"work").with_order(0);
		let builder = builder.with_message(TestMessage { content: "payload".into() });
		let builder = match priority {
			Some(priority) => builder.with_priority(priority),
			None => builder,
		};

		builder.build().expect("a work frame builds")
	}

	// The backpressure gate judges by the utilization of the hive alone, so a
	// network-control frame meets a hive past its threshold, and any frame
	// passes below it.
	tb_cases! {
		fn a_backpressure_gate_judges_utilization_alone(
			(utilization, priority, status): (u16, Option<MessagePriority>, TransitStatus)
		) {
			let utilization = Arc::new(AtomicU16::new(utilization));
			let gate = BackpressureGate::new(utilization, BasisPoints::new_saturating(9_000));

			let verdict = GatePolicy::evaluate(&gate, Some(&work_frame(priority)), &SessionContext::default());
			assert_eq!(verdict, status);
		}
		cases {
			ignores_priority => (9_500, Some(MessagePriority::NetworkControl), TransitStatus::ResourceExhausted),
			accepts_below_threshold => (1_000, None, TransitStatus::Ok),
		}
	}

	/// A constructor of a peer list of one SubjectPublicKeyInfo entry, read
	/// under [`KeyCurves::HOUSE`].
	type ListOf = fn([Vec<u8>; 1]) -> Result<PeerListGate, KeyListError>;

	// An allow list admits the key it names alone and fails closed without a
	// proven key. A deny list refuses the key it names alone and admits a
	// session with no proven key.
	tb_cases! {
		fn a_peer_list_admits_by_key(
			(list_of, peer, status): (ListOf, Option<CanonicalKey>, TransitStatus)
		) -> TestResult {
			let gate = list_of([listed(&listed_peer())])?;
			assert_eq!(gate.admit(peer.as_ref()), status);
			Ok(())
		}
		cases {
			allow_listed => (PeerListGate::allow, Some(key_of(&listed_peer())), TransitStatus::Ok),
			allow_unlisted => (PeerListGate::allow, Some(key_of(&unlisted_peer())), TransitStatus::PermissionDenied),
			allow_absent => (PeerListGate::allow, None, TransitStatus::Unauthenticated),
			deny_listed => (PeerListGate::deny, Some(key_of(&listed_peer())), TransitStatus::PermissionDenied),
			deny_unlisted => (PeerListGate::deny, Some(key_of(&unlisted_peer())), TransitStatus::Ok),
			deny_absent => (PeerListGate::deny, None, TransitStatus::Ok),
		}
	}

	/// A peer list of one entry under a decoder set, the session it judges,
	/// and its verdict.
	type ListedSession = (PeerListMode, KeyCurves, Certificate, SessionContext, TransitStatus);

	// A session with no proven peer answers as an absent peer. One point in
	// either SEC 1 form is one key, so a list of the uncompressed key judges
	// a session of its compressed form as that key, on secp256k1 and on
	// P-256 (RFC 6979 §A.2.5) alike. A key of another algorithm names no
	// point of a curve, so a deny list holds it and refuses its session.
	tb_cases! {
		fn a_peer_list_evaluates_a_session((mode, curves, entry, session, status): ListedSession) -> TestResult {
			let gate = PeerListGate::new(mode, curves, [listed(&entry)])?;

			let verdict = GatePolicy::evaluate(&gate, None, &session);
			assert_eq!(verdict, status);
			Ok(())
		}
		cases {
			an_empty_session_under_an_allow_list => (
				PeerListMode::Allow,
				KeyCurves::HOUSE,
				listed_peer(),
				SessionContext::default(),
				TransitStatus::Unauthenticated,
			),
			an_empty_session_under_a_deny_list => (
				PeerListMode::Deny,
				KeyCurves::HOUSE,
				listed_peer(),
				SessionContext::default(),
				TransitStatus::Ok,
			),
			a_compressed_key_under_a_deny_list => (
				PeerListMode::Deny,
				KeyCurves::HOUSE,
				listed_peer(),
				compressed_session(),
				TransitStatus::PermissionDenied,
			),
			/// The store admits a certificate re-issued in the compressed form
			/// too.
			a_compressed_key_under_an_allow_list => (
				PeerListMode::Allow,
				KeyCurves::HOUSE,
				listed_peer(),
				compressed_session(),
				TransitStatus::Ok,
			),
			a_compressed_p256_key_under_a_deny_list => (
				PeerListMode::Deny,
				P256,
				with_p256_point(&TestKey::RFC6979_P256_UNCOMPRESSED),
				session_of(with_p256_point(&TestKey::RFC6979_P256_COMPRESSED)),
				TransitStatus::PermissionDenied,
			),
			a_key_of_another_algorithm_under_a_deny_list => (
				PeerListMode::Deny,
				KeyCurves::HOUSE,
				under_algorithm(ID_ED_25519),
				session_of(under_algorithm(ID_ED_25519)),
				TransitStatus::PermissionDenied,
			),
		}
	}

	// An entry the house decoders cannot read as a point refuses the deny
	// list that holds it, at its index, so a deny list never lets the peer
	// it meant to name pass. The house set holds no decoder of P-256. An
	// off-curve encoding names a key no session holds. RFC 5480 §2.2 refuses
	// the compact and the hybrid form, a key on a binary-field curve reads
	// as its bits, and no key use reads a key under `id-ecDH`
	// (RFC 5480 §2.1.2).
	tb_cases! {
		fn a_list_entry_refuses_the_list((entry, refusal): (Certificate, KeyListError)) {
			let refused = PeerListGate::deny([listed(&listed_peer()), listed(&entry)]);
			assert_eq!(refused.err(), Some(refusal));
		}
		cases {
			on_a_curve_without_a_decoder => (
				with_p256_point(&TestKey::RFC6979_P256_UNCOMPRESSED),
				KeyListError::NoDecoder { index: 1 },
			),
			off_its_curve => (TestCertificate::with_off_curve_key(listed_peer()), KeyListError::NoPoint { index: 1 }),
			in_the_compact_form => (
				TestCertificate::with_compact_key(listed_peer()),
				KeyListError::NoPoint { index: 1 },
			),
			in_the_hybrid_form => (
				TestCertificate::with_key_form(listed_peer(), 0x06),
				KeyListError::NoPoint { index: 1 },
			),
			on_a_binary_field_curve => (
				TestCertificate::with_named_curve(listed_peer(), SECT233K1),
				KeyListError::NoPoint { index: 1 },
			),
			under_ec_dh => (under_algorithm(ID_EC_DH), KeyListError::NoPoint { index: 1 }),
		}
	}

	/// An entry that is no SubjectPublicKeyInfo refuses the list, so a deny
	/// list never lets the peer it meant to name pass.
	#[test]
	fn a_list_entry_that_is_no_key_refuses_the_list() {
		let refused = PeerListGate::deny([b"key-a"]);
		assert_eq!(refused.err(), Some(KeyListError::Unreadable { index: 0 }));
	}

	/// The breaker keys on the identity of the peer's key, so the failures of
	/// a session of one form open the circuit of a session of the other.
	#[test]
	fn the_breaker_counts_one_point_in_either_form_as_one_peer() {
		let uncompressed = session_of(listed_peer());
		let breaker = breaker();

		trip(&breaker, proven(&uncompressed));

		assert!(breaker.is_open(proven(&compressed_session())));
	}

	/// A heartbeat of message id `id` that states `order` as its issue time,
	/// signed by the fixed test identity. Two ids give two signatures at one
	/// order.
	fn heartbeat_named(id: &[u8], order: UnixMillis) -> Frame {
		let probe = ClusterCommand::Heartbeat(HeartbeatParams { cluster_status: ClusterStatus::Healthy });
		let built = Version::V2
			.compose()
			.with_id(id)
			.with_order(order.get())
			.with_message(probe)
			.with_witness_hasher::<Sha3_256>()
			.build();

		TestFrame::signed_by(built.expect("a witnessed heartbeat builds"), &TestIdentity::insecure_fixed())
	}

	/// A heartbeat that states `order` as its issue time, signed by the fixed
	/// test identity.
	fn heartbeat_at(order: UnixMillis) -> Frame {
		heartbeat_named(b"command", order)
	}

	/// A session whose handshake proved the fixed test identity, the signer of
	/// each fixture command.
	fn member() -> SessionContext {
		session_of(TestCertificate::insecure_fixed())
	}

	/// The admission of `frame` from `sender`, which the gate takes.
	fn admit_ok(gate: &ClusterSecurityGate, frame: Frame, sender: &SessionContext) -> AdmittedCommand {
		gate.admit(frame, sender).expect("the gate admits a fresh signed command")
	}

	/// The status of the refusal of `frame` from `sender`, or `None` for an
	/// admission.
	fn refusal_status(gate: &ClusterSecurityGate, frame: Frame, sender: &SessionContext) -> Option<TransitStatus> {
		gate.admit(frame, sender).err().map(|refusal| refusal.status())
	}

	/// A gate that verifies a frame and a session that proves its peer, the
	/// setup of every admission test.
	///
	/// The gate and the frame's issue time read one clock, so the frame is
	/// fresh until the test moves that clock.
	struct VerifiedGate {
		gate: ClusterSecurityGate,
		sender: SessionContext,
		signed: Frame,
		clock: Arc<ManualClock>,
	}

	/// Builds a [`VerifiedGate`] under `limits`, whose house store enrolls
	/// the certificate of the fixed test identity.
	fn verified_gate_with(limits: GateLimits) -> VerifiedGate {
		let clock = TestClock::manual();
		let trust: Arc<dyn CertificateTrust> = Arc::new(TestStore::holding([TestCertificate::insecure_fixed()]));
		let gate = ClusterSecurityGate::new(trust, limits, TestClock::erased(&clock));

		VerifiedGate { gate, sender: member(), signed: heartbeat_at(clock.unix()), clock }
	}

	/// Builds a [`VerifiedGate`] under [`limits`].
	fn verified_gate() -> VerifiedGate {
		verified_gate_with(limits())
	}

	/// A gate whose house store enrolls the certificate of the fixed test
	/// identity, beside that store and the clock the gate reads.
	struct EnrolledGate {
		gate: ClusterSecurityGate,
		store: Arc<CertificateTrustStore>,
		clock: Arc<ManualClock>,
	}

	/// Builds an [`EnrolledGate`] under [`limits`].
	fn enrolled_gate() -> EnrolledGate {
		let clock = TestClock::manual();
		let store = Arc::new(TestStore::holding([TestCertificate::insecure_fixed()]));
		let trust: Arc<dyn CertificateTrust> = Arc::clone(&store) as Arc<dyn CertificateTrust>;
		let gate = ClusterSecurityGate::new(trust, limits(), TestClock::erased(&clock));

		EnrolledGate { gate, store, clock }
	}

	/// A verdict judges a frame and leaves it unspent, so the control plane
	/// that gated on the verdict can admit the same frame afterward.
	#[test]
	fn a_gate_verdict_leaves_the_admission_unspent() {
		let VerifiedGate { gate, sender, signed, .. } = verified_gate();

		let verdicts = [gate.evaluate(Some(&signed), &sender), gate.evaluate(Some(&signed), &sender)];
		let admitted = gate.admit(signed, &sender);
		assert!(matches!((verdicts, admitted), ([TransitStatus::Ok, TransitStatus::Ok], Ok(_))));
	}

	/// A verdict refuses a signed frame that lacks the frame integrity that a
	/// cluster command requires.
	#[test]
	fn a_gate_verdict_refuses_a_frame_without_frame_integrity() -> TestResult {
		let VerifiedGate { gate, sender, clock, .. } = verified_gate();
		let builder = Version::V2.compose().with_id(b"unwitnessed").with_order(clock.unix().get());
		let built = builder.with_message(TestMessage::sample(None)).build()?;
		let unwitnessed = TestFrame::signed_by(built, &TestIdentity::insecure_fixed());

		let verdict = gate.evaluate(Some(&unwitnessed), &sender);
		assert_eq!(verdict, TransitStatus::Unauthenticated);
		Ok(())
	}

	/// The frame of `verified`, once an admission spends it.
	fn admitted_frame(verified: &VerifiedGate) -> Frame {
		drop(admit_ok(&verified.gate, verified.signed.clone(), &verified.sender));
		verified.signed.clone()
	}

	/// A second command of the signer of `verified`, at the order of its frame
	/// once an admission spends that frame.
	fn sibling_of_an_admitted_frame(verified: &VerifiedGate) -> Frame {
		drop(admit_ok(&verified.gate, verified.signed.clone(), &verified.sender));
		heartbeat_named(b"sibling", verified.clock.unix())
	}

	/// The frame of `verified`, once the replay partition of its signer is
	/// full.
	fn frame_of_a_full_partition(verified: &VerifiedGate) -> Frame {
		let signer = signer_id(&verified.signed);
		fill_replay_partition(verified.gate.replay_guard.as_ref(), signer, verified.clock.unix());
		verified.signed.clone()
	}

	/// A step that spends the replay slot of a command, and returns the frame
	/// a verdict then judges.
	type Spent = fn(&VerifiedGate) -> Frame;

	// A verdict refuses a command the replay guard already holds as an
	// admission does: a captured frame, whose signature the guard recorded
	// (CWE-294), a second command of one signer at an admitted order, and a
	// command of a signer whose replay partition is full.
	tb_cases! {
		fn a_gate_verdict_refuses_a_spent_command(spent: Spent) {
			let verified = verified_gate();
			let frame = spent(&verified);

			let verdict = verified.gate.evaluate(Some(&frame), &verified.sender);
			assert_eq!(verdict, TransitStatus::PermissionDenied);
		}
		cases {
			already_admitted => admitted_frame,
			at_an_admitted_order => sibling_of_an_admitted_frame,
			of_a_full_partition => frame_of_a_full_partition,
		}
	}

	/// The gate refuses a second command of one signer at the order of an
	/// admitted one (README §5.7.1), though its signature is new.
	#[test]
	fn a_second_command_at_an_admitted_order_is_refused() {
		let VerifiedGate { gate, sender, signed, clock } = verified_gate();
		let sibling = heartbeat_named(b"sibling", clock.unix());
		let admitted = refusal_status(&gate, signed, &sender);

		let duplicate = refusal_status(&gate, sibling, &sender);
		assert_eq!((admitted, duplicate), (None, Some(TransitStatus::PermissionDenied)));
	}

	/// The gate refuses a command that a trusted member signs and another
	/// peer delivers. It binds the signer it verifies to the peer the
	/// handshake proved, so the record of each command it admits names the
	/// party that signed it (CWE-778).
	#[test]
	fn a_command_that_another_peer_delivers_is_refused() {
		let EnrolledGate { gate, clock, .. } = enrolled_gate();
		let courier = session_of(unlisted_peer());

		let refused = refusal_status(&gate, heartbeat_at(clock.unix()), &courier);
		assert_eq!(refused, Some(TransitStatus::PermissionDenied));
	}

	/// A captured command replayed with its signature's `s` flipped to
	/// `n - s` verifies under a real trust store (SEC 1 v2.0 §4.1.4), to the
	/// value its original verifies to. The gate refuses it as a replay, not as
	/// a forgery, because both forms key one replay slot.
	#[test]
	fn a_command_replayed_with_its_s_flipped_is_refused() {
		let EnrolledGate { gate, store, clock } = enrolled_gate();
		let sender = member();
		let signed = heartbeat_at(clock.unix());
		let flipped = TestFrame::with_flipped_s(&signed);
		let verified = (store.verify_frame(&signed), store.verify_frame(&flipped));
		let admitted = refusal_status(&gate, signed, &sender);

		let inspected = gate.inspect(&flipped, &sender, clock.unix()).err();
		let replayed = refusal_status(&gate, flipped, &sender);
		assert!(matches!(verified, (TrustVerification::Verified(_, a), TrustVerification::Verified(_, b)) if a == b));
		assert!(matches!(
			inspected,
			Some(InspectRefusal::Plain(TransitStatus::PermissionDenied))
		));
		assert_eq!((admitted, replayed), (None, Some(TransitStatus::PermissionDenied)));
	}

	/// A command whose signer's clock leads the hive's by 59 s, inside the
	/// 60 s window, stays fresh until its stated order leaves the window. A
	/// capture replayed 61 s after its admission stays fresh, so the gate
	/// refuses it as a replay (CWE-294).
	#[test]
	fn a_future_dated_command_is_refused_as_a_replay_while_it_is_fresh() {
		let EnrolledGate { gate, clock, .. } = enrolled_gate();
		let sender = member();
		let order = clock.unix().saturating_add(Duration::from_millis(59_000));
		let signed = heartbeat_at(order);
		let admitted = refusal_status(&gate, signed.clone(), &sender);
		clock.advance(Duration::from_millis(61_000));

		let replayed = refusal_status(&gate, signed, &sender);

		let fresh = gate.replay_guard.is_fresh(order, clock.unix());
		assert_eq!((admitted, fresh, replayed), (None, true, Some(TransitStatus::PermissionDenied)));
	}

	/// A verdict leaves a tripped breaker as it found it, so the admission
	/// alone closes the circuit.
	#[test]
	fn a_gate_verdict_leaves_the_breaker_to_the_admission() {
		let VerifiedGate { gate, sender, signed, .. } = verified_gate_with(instant_cooldown());
		gate.circuit_breaker.record_auth_failure(proven(&sender));

		let verdict = gate.evaluate(Some(&signed), &sender);
		let open_after_the_verdict = gate.circuit_breaker.is_open(proven(&sender));
		let admitted = gate.admit(signed, &sender);

		// The cooldown has passed, so the verdict admits and leaves the
		// circuit open, and the admission closes it.
		let open_after_the_admission = gate.circuit_breaker.is_open(proven(&sender));
		assert!(matches!(
			(verdict, open_after_the_verdict, admitted, open_after_the_admission),
			(TransitStatus::Ok, true, Ok(_), false)
		));
	}

	/// A refused admission leaves the breaker as it found it.
	#[test]
	fn a_refused_admission_leaves_the_breaker_open() {
		let VerifiedGate { gate, sender, signed, clock } = verified_gate_with(instant_cooldown());
		gate.circuit_breaker.record_auth_failure(proven(&sender));

		// Fill this signer's replay partition, so the admission refuses the
		// command at the guard's rule.
		fill_replay_partition(gate.replay_guard.as_ref(), signer_id(&signed), clock.unix());

		let refusal = refusal_status(&gate, signed, &sender);
		assert_eq!(refusal, Some(TransitStatus::PermissionDenied));
		assert!(gate.circuit_breaker.is_open(proven(&sender)));
	}

	/// The breaker a gate builds cools on the gate's clock, so a circuit
	/// the gate opened admits a command again once that one clock reaches the
	/// cooldown.
	#[test]
	fn a_gates_breaker_cools_on_the_gates_clock() {
		let VerifiedGate { gate, sender, clock, .. } = verified_gate();
		trip(&gate.circuit_breaker, proven(&sender));

		let before = gate.circuit_breaker.would_allow(proven(&sender));

		clock.advance(COOLDOWN);

		let after = gate.circuit_breaker.would_allow(proven(&sender));
		assert_eq!((before, after), (false, true));
	}

	/// `frame` with the last octet of its signature flipped, so its signer
	/// identifier still names its signer, and its signature verifies under
	/// no key.
	fn forged(frame: &Frame) -> Frame {
		let signer = frame.nonrepudiation().expect("the frame carries a signature");
		let signature = signer.signature.as_bytes();
		TestFrame::tamper(frame, signature, flip_last(signature))
	}

	/// The gate counts a caller who copies a trusted `SignerIdentifier` and
	/// attaches a bad signature against its own transport peer, so the copied
	/// signer keeps its budget (CWE-345).
	///
	/// The count runs through `admit`, because a caller submits a frame
	/// there. A verdict judges the same frame and counts nothing.
	#[test]
	fn a_forged_signer_id_gates_the_sender_not_the_signer() {
		let EnrolledGate { gate, clock, .. } = enrolled_gate();
		let forged = forged(&heartbeat_at(clock.unix()));
		let courier = session_of(unlisted_peer());
		let refusals = [
			refusal_status(&gate, forged.clone(), &courier),
			refusal_status(&gate, forged.clone(), &courier),
			refusal_status(&gate, forged, &courier),
		];

		let circuits = (gate.circuit_breaker.is_open(other()), gate.circuit_breaker.is_open(signer()));
		assert_eq!(refusals, [Some(TransitStatus::PermissionDenied); 3]);
		assert_eq!(circuits, (true, false));
	}

	/// One signer's failures leave every other signer admitted, so a
	/// compromised member leaves the colony control plane open (CWE-645).
	#[test]
	fn a_tripped_signer_does_not_gate_another() {
		let breaker = breaker();
		trip(&breaker, signer());

		let verdicts = (breaker.admit_verified(signer()), breaker.admit_verified(other()));
		assert_eq!(verdicts, (false, true));
	}

	// A refusal releases the replay slot only where the hive could answer a
	// retry of the same signed frame differently, so a captured frame buys
	// its holder nothing on a refusal that holds for every retry.
	tb_cases! {
		fn a_refusal_releases_the_slot_only_where_a_retry_can_change_it(
			(refusal, releases): (CommandRefusal, bool)
		) {
			assert_eq!(refusal.releases_replay(), releases);
		}
		cases {
			draining => (CommandRefusal::Draining, false),
			backpressure => (CommandRefusal::Backpressure, true),
			at_capacity => (CommandRefusal::AtCapacity, true),
			below_floor => (CommandRefusal::BelowFloor, false),
			unknown_servlet_type => (CommandRefusal::UnknownServletType, false),
			spawn_failed => (CommandRefusal::SpawnFailed, true),
			unnameable_instance => (CommandRefusal::UnnameableInstance, false),
			registry_fault => (CommandRefusal::RegistryFault, true),
			unknown_instance => (CommandRefusal::UnknownInstance, false),
		}
	}

	// A transient refusal releases the slot, so the gate admits the same
	// signed frame again. A permanent refusal keeps the slot spent, so the
	// gate refuses the same signed frame as a replay.
	tb_cases! {
		fn a_refusal_decides_whether_the_same_frame_passes_again(
			(refusal, replay): (CommandRefusal, Option<TransitStatus>)
		) -> TestResult {
			let trace = TraceCollector::default();
			let VerifiedGate { gate, sender, signed, .. } = verified_gate();
			let admitted = admit_ok(&gate, signed.clone(), &sender);

			admitted.refuse(refusal, &CommandAudit::new(&trace, &trace, &sender))?;

			assert_eq!(refusal_status(&gate, signed, &sender), replay);
			Ok(())
		}
		cases {
			transient => (CommandRefusal::Backpressure, None),
			permanent => (CommandRefusal::Draining, Some(TransitStatus::PermissionDenied)),
		}
	}

	/// A refusal of an admitted command records on the trace of the hive alone.
	#[cfg(feature = "testing")]
	#[test]
	fn a_refusal_records_its_event_on_the_trace_of_its_audit() -> TestResult {
		let VerifiedGate { gate, sender, signed, .. } = verified_gate();
		let admitted = admit_ok(&gate, signed, &sender);
		let (trace, connections) = (TraceCollector::default(), TraceCollector::default());

		admitted.refuse(CommandRefusal::Draining, &CommandAudit::new(&trace, &connections, &sender))?;

		let recorded = (trace.recorded(HIVE_COMMAND_REFUSED), connections.recorded(HIVE_COMMAND_REFUSED));
		assert_eq!(recorded, (1, 0));
		Ok(())
	}

	/// A refusal of an unproven peer records on the connection trace alone.
	#[cfg(feature = "testing")]
	#[test]
	fn a_refusal_of_an_unproven_peer_records_on_the_connection_trace() -> TestResult {
		let (trace, connections) = (TraceCollector::default(), TraceCollector::default());
		let session = SessionContext::default();
		let frame = TestFrame::v0(None, Some("command"));

		let audit = CommandAudit::new(&trace, &connections, &session);
		AdmitRefusal::denied(frame, TransitStatus::PermissionDenied).reply(&audit)?;

		let recorded = (trace.recorded(HIVE_COMMAND_REFUSED), connections.recorded(HIVE_COMMAND_REFUSED));
		assert_eq!(recorded, (0, 1));
		Ok(())
	}
}
