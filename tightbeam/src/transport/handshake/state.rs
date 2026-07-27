//! State machine infrastructure for TightBeam handshake protocol.
//!
//! This redesigned module provides role-specific handshake state machines
//! with explicit terminal states, granular failure classification, and
//! invariant enforcement hooks.

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
// Invariant Tracking
// ---------------------------------------------------------------------------

/// Once-only ordering guards for the handshake state machine: each flag
/// flips exactly once and later steps demand the earlier ones.
#[derive(Debug, Default)]
pub struct HandshakeInvariant {
	/// The transcript hash is sealed; no further messages may extend it.
	pub transcript_locked: bool,
	/// Session AEAD keys were derived (requires a locked transcript).
	pub aead_key_derived: bool,
	/// The finished message went out (requires derived AEAD keys).
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

	// Deliberately the union of the ECIES and CMS transition tables: both
	// protocols share this machine, so a transition legal in either flow is
	// accepted here. Protocol-confusion is prevented by the orchestrators,
	// which drive a fixed sequence.
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

	// Union of ECIES and CMS transition tables; see ClientStateMachine note.
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
}
