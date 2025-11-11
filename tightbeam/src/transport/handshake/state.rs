//! State machine infrastructure for TightBeam handshake protocol.
//!
//! This redesigned module provides role-specific handshake state machines
//! with explicit terminal states, granular failure classification, replay
//! (nonce) tracking, and invariant enforcement hooks.
//!
//! Breaking changes: the previous `HandshakeState` enum is replaced by
//! `ClientHandshakeState` and `ServerHandshakeState`. Transition APIs are
//! now role-specific (`ClientStateMachine` / `ServerStateMachine`).

use crate::transport::handshake::error::HandshakeError;

// ---------------------------------------------------------------------------
// Failure and Abort Classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
	Hello,
	KeyExchange,
	Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
	LocalPolicy,
	Timeout(Phase),
	PeerAbort,
	Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
	ProtocolViolation,
	ReplayDetected,
	DowngradeAttempt,
	CertificateInvalid,
	SignatureInvalid,
	IntegrityMismatch,
	DerDecodeError,
	KeyDerivationError,
	UnsupportedAlgorithm,
	InternalError,
}

// ---------------------------------------------------------------------------
// Role-Specific States
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ClientHandshakeState {
	#[default]
	Init,
	HelloSent,
	ServerHelloReceived,
	KeyExchangeSent,
	ServerFinishedReceived,
	ClientFinishedSent,
	Completed,
	Aborted(AbortReason),
	Failed(FailureKind),
}

impl ClientHandshakeState {
	pub fn is_completed(&self) -> bool {
		matches!(self, Self::Completed)
	}
	pub fn is_failed(&self) -> bool {
		matches!(self, Self::Failed(_))
	}
	pub fn is_aborted(&self) -> bool {
		matches!(self, Self::Aborted(_))
	}
	pub fn is_terminal(&self) -> bool {
		self.is_completed() || self.is_failed() || self.is_aborted()
	}
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ServerHandshakeState {
	#[default]
	Init,
	ClientHelloReceived,
	ServerHelloSent,
	KeyExchangeReceived,
	ServerFinishedSent,
	ClientFinishedReceived,
	Completed,
	Aborted(AbortReason),
	Failed(FailureKind),
}

impl ServerHandshakeState {
	pub fn is_completed(&self) -> bool {
		matches!(self, Self::Completed)
	}
	pub fn is_failed(&self) -> bool {
		matches!(self, Self::Failed(_))
	}
	pub fn is_aborted(&self) -> bool {
		matches!(self, Self::Aborted(_))
	}
	pub fn is_terminal(&self) -> bool {
		self.is_completed() || self.is_failed() || self.is_aborted()
	}
}

// ---------------------------------------------------------------------------
// Replay / Nonce Tracking
// ---------------------------------------------------------------------------

use std::collections::{HashMap, VecDeque};

/// Nonce replay detection with LRU eviction.
///
/// Maintains a bounded set of recently seen nonces to prevent replay attacks.
/// When capacity is reached, the oldest nonce is evicted (FIFO/LRU).
///
/// # Type Parameters
/// - `N`: Nonce size in bytes (e.g., 32 for ECIES client_random, 64 for CMS UKM)
///
/// # Security Properties
/// - Constant-time lookup via HashMap
/// - Bounded memory usage (cap * N bytes + overhead)
/// - LRU eviction ensures recent nonces are always tracked
/// - No silent failures: all nonces are either tracked or evict oldest
#[derive(Debug)]
pub struct NonceReplaySet<const N: usize> {
	/// Maps nonce -> insertion order for O(1) lookup
	seen: HashMap<[u8; N], usize>,
	/// Queue of nonces in insertion order for LRU eviction
	order: VecDeque<[u8; N]>,
	/// Maximum number of nonces to track
	cap: usize,
	/// Monotonic counter for insertion order
	counter: usize,
}

impl<const N: usize> NonceReplaySet<N> {
	pub fn new(cap: usize) -> Self {
		Self {
			seen: HashMap::with_capacity(cap),
			order: VecDeque::with_capacity(cap),
			cap,
			counter: 0,
		}
	}

	/// Check if nonce is a replay and insert if new.
	///
	/// Returns `true` if the nonce was already seen (replay attack).
	/// Returns `false` if the nonce is new (inserted successfully).
	///
	/// When at capacity, evicts the oldest nonce (LRU).
	pub fn insert_or_replay(&mut self, n: [u8; N]) -> bool {
		// Check for replay
		if self.seen.contains_key(&n) {
			return true; // Replay detected
		}

		// Evict oldest if at capacity
		if self.seen.len() >= self.cap {
			if let Some(oldest) = self.order.pop_front() {
				self.seen.remove(&oldest);
			}
		}

		// Insert new nonce
		self.seen.insert(n, self.counter);
		self.order.push_back(n);
		self.counter = self.counter.wrapping_add(1);

		false // Not a replay
	}

	pub fn clear(&mut self) {
		self.seen.clear();
		self.order.clear();
		self.counter = 0;
	}

	/// Get the number of nonces currently tracked.
	pub fn len(&self) -> usize {
		self.seen.len()
	}

	/// Check if the replay set is empty.
	pub fn is_empty(&self) -> bool {
		self.seen.is_empty()
	}
}

// ---------------------------------------------------------------------------
// Invariant Tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct HandshakeInvariant {
	pub transcript_locked: bool,
	pub aead_key_derived: bool,
	pub finished_sent: bool,
}

impl HandshakeInvariant {
	/// Lock the transcript. Returns Ok(true) if newly locked, Ok(false) if it
	/// was already locked.
	pub fn lock_transcript(&mut self) -> Result<bool, HandshakeError> {
		if self.transcript_locked {
			return Err(HandshakeError::TranscriptAlreadyLocked);
		}

		self.transcript_locked = true;
		Ok(true)
	}

	/// Derive AEAD key exactly once. Ordering: transcript must be locked first.
	/// Returns Ok(true) if freshly derived, Ok(false) if already derived.
	/// Errors on ordering violation.
	pub fn derive_aead_once(&mut self) -> Result<bool, HandshakeError> {
		if !self.transcript_locked {
			return Err(HandshakeError::TranscriptNotLocked);
		}
		if self.aead_key_derived {
			return Err(HandshakeError::AeadAlreadyDerived);
		}

		self.aead_key_derived = true;
		Ok(true)
	}

	/// Mark Finished message as sent. Requires transcript lock. Returns Ok(true) if newly marked,
	/// Err if ordering violated or already sent.
	pub fn mark_finished_sent(&mut self) -> Result<bool, HandshakeError> {
		if !self.transcript_locked {
			return Err(HandshakeError::FinishedBeforeTranscriptLock);
		}
		if self.finished_sent {
			return Err(HandshakeError::FinishedAlreadySent);
		}

		self.finished_sent = true;
		Ok(true)
	}
}

// ---------------------------------------------------------------------------
// Client State Machine
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ClientStateMachine {
	state: ClientHandshakeState,
}

impl ClientStateMachine {
	pub fn state(&self) -> ClientHandshakeState {
		self.state
	}

	fn can_transition(&self, to: ClientHandshakeState) -> bool {
		use ClientHandshakeState::*;
		match (self.state, to) {
			// Linear progression
			(Init, HelloSent)
			// CMS direct path (no explicit hello messages)
			| (Init, KeyExchangeSent)
			| (HelloSent, ServerHelloReceived)
			| (ServerHelloReceived, KeyExchangeSent)
			| (KeyExchangeSent, ServerFinishedReceived)
			| (ServerFinishedReceived, ClientFinishedSent)
			| (ClientFinishedSent, Completed)
			// ECIES short-circuit (no Finished messages)
			| (KeyExchangeSent, Completed)
			// Terminal classification
			| (_, Aborted(_))
			| (_, Failed(_)) => true,
			_ => false,
		}
	}

	pub fn transition(&mut self, to: ClientHandshakeState) -> Result<(), HandshakeError> {
		if self.state.is_terminal() {
			return Err(HandshakeError::InvalidState);
		}
		if self.can_transition(to) {
			self.state = to;
			Ok(())
		} else {
			Err(HandshakeError::InvalidState)
		}
	}
}

// ---------------------------------------------------------------------------
// Server State Machine
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ServerStateMachine {
	state: ServerHandshakeState,
}

impl ServerStateMachine {
	pub fn state(&self) -> ServerHandshakeState {
		self.state
	}

	fn can_transition(&self, to: ServerHandshakeState) -> bool {
		use ServerHandshakeState::*;
		match (self.state, to) {
			// Two entry paths: ECIES (ClientHelloReceived) or CMS (KeyExchangeReceived)
			(Init, ClientHelloReceived)
			| (Init, KeyExchangeReceived)
			| (ClientHelloReceived, ServerHelloSent)
			| (ServerHelloSent, KeyExchangeReceived)
			| (KeyExchangeReceived, ServerFinishedSent)
			| (ServerFinishedSent, ClientFinishedReceived)
			| (ClientFinishedReceived, Completed)
			// ECIES short-circuit (no Finished messages)
			| (KeyExchangeReceived, Completed)
			// Terminal classification
			| (_, Aborted(_))
			| (_, Failed(_)) => true,
			_ => false,
		}
	}

	pub fn transition(&mut self, to: ServerHandshakeState) -> Result<(), HandshakeError> {
		if self.state.is_terminal() {
			return Err(HandshakeError::InvalidState);
		}
		if self.can_transition(to) {
			self.state = to;
			Ok(())
		} else {
			Err(HandshakeError::InvalidState)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn client_linear_flow_ecies_short() {
		let mut sm = ClientStateMachine::default();
		assert_eq!(sm.state(), ClientHandshakeState::Init);
		assert!(sm.transition(ClientHandshakeState::HelloSent).is_ok());
		assert!(sm.transition(ClientHandshakeState::ServerHelloReceived).is_ok());
		assert!(sm.transition(ClientHandshakeState::KeyExchangeSent).is_ok());
		// ECIES path allows direct complete
		assert!(sm.transition(ClientHandshakeState::Completed).is_ok());
		assert!(sm.state().is_completed());
	}

	#[test]
	fn client_full_flow_cms() {
		let mut sm = ClientStateMachine::default();
		assert!(sm.transition(ClientHandshakeState::HelloSent).is_ok());
		assert!(sm.transition(ClientHandshakeState::ServerHelloReceived).is_ok());
		assert!(sm.transition(ClientHandshakeState::KeyExchangeSent).is_ok());
		assert!(sm.transition(ClientHandshakeState::ServerFinishedReceived).is_ok());
		assert!(sm.transition(ClientHandshakeState::ClientFinishedSent).is_ok());
		assert!(sm.transition(ClientHandshakeState::Completed).is_ok());
	}

	#[test]
	fn server_linear_flow_ecies_short() {
		let mut sm = ServerStateMachine::default();
		assert_eq!(sm.state(), ServerHandshakeState::Init);
		assert!(sm.transition(ServerHandshakeState::ClientHelloReceived).is_ok());
		assert!(sm.transition(ServerHandshakeState::ServerHelloSent).is_ok());
		assert!(sm.transition(ServerHandshakeState::KeyExchangeReceived).is_ok());
		assert!(sm.transition(ServerHandshakeState::Completed).is_ok());
		assert!(sm.state().is_completed());
	}

	#[test]
	fn server_full_flow_cms() {
		let mut sm = ServerStateMachine::default();
		assert!(sm.transition(ServerHandshakeState::KeyExchangeReceived).is_ok());
		assert!(sm.transition(ServerHandshakeState::ServerFinishedSent).is_ok());
		assert!(sm.transition(ServerHandshakeState::ClientFinishedReceived).is_ok());
		assert!(sm.transition(ServerHandshakeState::Completed).is_ok());
	}

	#[test]
	fn abort_and_failure_are_terminal() {
		let mut sm = ClientStateMachine::default();
		assert!(sm.transition(ClientHandshakeState::HelloSent).is_ok());
		assert!(sm.transition(ClientHandshakeState::Aborted(AbortReason::PeerAbort)).is_ok());
		assert!(sm.state().is_aborted());
		assert!(sm.transition(ClientHandshakeState::ServerHelloReceived).is_err());
		let mut sm2 = ServerStateMachine::default();
		assert!(sm2
			.transition(ServerHandshakeState::Failed(FailureKind::ProtocolViolation))
			.is_ok());
		assert!(sm2.state().is_failed());
	}

	// ---------------------------------------------------------------------------
	// Nonce Replay Set Tests
	// ---------------------------------------------------------------------------

	#[test]
	fn test_nonce_replay_detection() {
		let mut set = NonceReplaySet::<32>::new(3);
		let nonce1 = [1u8; 32];
		let nonce2 = [2u8; 32];

		// First insertion should succeed
		assert!(!set.insert_or_replay(nonce1));
		assert_eq!(set.len(), 1);

		// Replay should be detected
		assert!(set.insert_or_replay(nonce1));
		assert_eq!(set.len(), 1);

		// Different nonce should succeed
		assert!(!set.insert_or_replay(nonce2));
		assert_eq!(set.len(), 2);
	}

	#[test]
	fn test_nonce_lru_eviction() {
		let mut set = NonceReplaySet::<32>::new(3);
		let nonce1 = [1u8; 32];
		let nonce2 = [2u8; 32];
		let nonce3 = [3u8; 32];
		let nonce4 = [4u8; 32];

		// Fill to capacity: [nonce1, nonce2, nonce3]
		assert!(!set.insert_or_replay(nonce1));
		assert!(!set.insert_or_replay(nonce2));
		assert!(!set.insert_or_replay(nonce3));
		assert_eq!(set.len(), 3);

		// Insert 4th nonce - should evict nonce1 (oldest)
		// Now: [nonce2, nonce3, nonce4]
		assert!(!set.insert_or_replay(nonce4));
		assert_eq!(set.len(), 3);

		// nonce1 should no longer be tracked (evicted)
		assert!(!set.insert_or_replay(nonce1)); // Not a replay!
		assert_eq!(set.len(), 3);

		// But nonce3, nonce4, nonce1 should still be in the set
		// (nonce2 was evicted when we inserted nonce1)
		// Current state: [nonce3, nonce4, nonce1]
		assert!(set.insert_or_replay(nonce3)); // Replay!
		assert!(set.insert_or_replay(nonce4)); // Replay!
		assert!(set.insert_or_replay(nonce1)); // Replay!
	}

	#[test]
	fn test_nonce_clear() {
		let mut set = NonceReplaySet::<32>::new(10);
		let nonce = [42u8; 32];

		set.insert_or_replay(nonce);
		assert_eq!(set.len(), 1);

		set.clear();
		assert_eq!(set.len(), 0);
		assert!(set.is_empty());

		// After clear, same nonce should not be detected as replay
		assert!(!set.insert_or_replay(nonce));
	}

	#[test]
	fn test_nonce_capacity_boundary() {
		let mut set = NonceReplaySet::<32>::new(1);
		let nonce1 = [1u8; 32];
		let nonce2 = [2u8; 32];

		// Insert first nonce
		assert!(!set.insert_or_replay(nonce1));
		assert_eq!(set.len(), 1);

		// Insert second nonce - should evict first
		assert!(!set.insert_or_replay(nonce2));
		assert_eq!(set.len(), 1);

		// First nonce should be evicted
		assert!(!set.insert_or_replay(nonce1));
		assert_eq!(set.len(), 1);
	}

	#[test]
	fn test_nonce_64byte_ukm() {
		let mut set = NonceReplaySet::<64>::new(3);
		let ukm1 = [1u8; 64];
		let ukm2 = [2u8; 64];

		// First insertion should succeed
		assert!(!set.insert_or_replay(ukm1));
		assert_eq!(set.len(), 1);

		// Replay should be detected
		assert!(set.insert_or_replay(ukm1));
		assert_eq!(set.len(), 1);

		// Different UKM should succeed
		assert!(!set.insert_or_replay(ukm2));
		assert_eq!(set.len(), 2);
	}
}
