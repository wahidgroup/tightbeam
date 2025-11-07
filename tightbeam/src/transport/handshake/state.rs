//! State machine infrastructure for TightBeam handshake protocol.
//!
//! Defines states, transitions, and orchestration logic for the handshake.

use crate::transport::handshake::error::HandshakeError;

/// Handshake protocol states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
	/// Initial state - no handshake started
	Init,
	/// Client: Sent ClientHello, waiting for ServerHello
	ClientHelloSent,
	/// Server: Received ClientHello, ready to send ServerHello
	ServerHelloReceived,
	/// Server: Sent ServerHello, waiting for KeyExchange
	ServerHelloSent,
	/// Client: Sent KeyExchange, waiting for Finished
	KeyExchangeSent,
	/// Server: Received KeyExchange, ready to send Finished
	KeyExchangeReceived,
	/// Server: Sent Finished, waiting for client Finished
	ServerFinishedSent,
	/// Client: Received server Finished, ready to send client Finished
	ServerFinishedReceived,
	/// Client: Sent client Finished, handshake complete
	ClientFinishedSent,
	/// Server: Received client Finished, handshake complete
	ClientFinishedReceived,
	/// Handshake successfully completed
	Complete,
	/// Handshake failed
	Failed,
}

impl HandshakeState {
	/// Check if the handshake is complete.
	pub fn is_complete(&self) -> bool {
		matches!(self, HandshakeState::Complete)
	}

	/// Check if the handshake has failed.
	pub fn is_failed(&self) -> bool {
		matches!(self, HandshakeState::Failed)
	}

	/// Check if the handshake is still in progress.
	pub fn is_in_progress(&self) -> bool {
		!self.is_complete() && !self.is_failed()
	}
}

/// Handshake message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeMessageType {
	/// Client Hello - initiates handshake
	ClientHello,
	/// Server Hello - server responds with key material
	ServerHello,
	/// Key Exchange - client sends encrypted session key
	KeyExchange,
	/// Finished - authentication message (mutual)
	Finished,
}

/// State transition validation.
pub trait StateTransition {
	/// Validate a state transition is allowed.
	fn can_transition(&self, from: HandshakeState, to: HandshakeState) -> bool;

	/// Perform a state transition.
	fn transition(&mut self, to: HandshakeState) -> Result<(), HandshakeError>;

	/// Get current state.
	fn state(&self) -> HandshakeState;
}

/// Client-side state transitions.
pub struct ClientStateTransition {
	state: HandshakeState,
}

impl ClientStateTransition {
	/// Create a new client state machine.
	pub fn new() -> Self {
		Self { state: HandshakeState::Init }
	}
}

impl Default for ClientStateTransition {
	fn default() -> Self {
		Self::new()
	}
}

impl StateTransition for ClientStateTransition {
	fn can_transition(&self, from: HandshakeState, to: HandshakeState) -> bool {
		use HandshakeState::*;
		matches!(
			(from, to),
			(Init, ClientHelloSent)
				| (Init, KeyExchangeSent) // Direct transition for simplified handshake
				| (ClientHelloSent, ServerHelloReceived)
				| (ServerHelloReceived, KeyExchangeSent)
				| (KeyExchangeSent, ServerFinishedReceived)
				| (KeyExchangeSent, Complete) // Direct completion for ECIES-style handshake
				| (ServerFinishedReceived, ClientFinishedSent)
				| (ClientFinishedSent, Complete)
				| (_, Failed)
		)
	}

	fn transition(&mut self, to: HandshakeState) -> Result<(), HandshakeError> {
		if self.can_transition(self.state, to) {
			self.state = to;
			Ok(())
		} else {
			Err(HandshakeError::InvalidState)
		}
	}

	fn state(&self) -> HandshakeState {
		self.state
	}
}

/// Server-side state transitions.
pub struct ServerStateTransition {
	state: HandshakeState,
}

impl ServerStateTransition {
	/// Create a new server state machine.
	pub fn new() -> Self {
		Self { state: HandshakeState::Init }
	}
}

impl Default for ServerStateTransition {
	fn default() -> Self {
		Self::new()
	}
}

impl StateTransition for ServerStateTransition {
	fn can_transition(&self, from: HandshakeState, to: HandshakeState) -> bool {
		use HandshakeState::*;
		matches!(
			(from, to),
			(Init, ServerHelloReceived)
				| (Init, KeyExchangeReceived) // Direct transition for simplified handshake
				| (ServerHelloReceived, ServerHelloSent)
				| (ServerHelloSent, KeyExchangeReceived)
				| (KeyExchangeReceived, ServerFinishedSent)
				| (KeyExchangeReceived, Complete) // Direct completion for ECIES-style handshake
				| (ServerFinishedSent, ClientFinishedReceived)
				| (ClientFinishedReceived, Complete)
				| (_, Failed)
		)
	}

	fn transition(&mut self, to: HandshakeState) -> Result<(), HandshakeError> {
		if self.can_transition(self.state, to) {
			self.state = to;
			Ok(())
		} else {
			Err(HandshakeError::InvalidState)
		}
	}

	fn state(&self) -> HandshakeState {
		self.state
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_client_state_transitions() {
		let mut client = ClientStateTransition::new();

		// Valid transitions
		assert_eq!(client.state(), HandshakeState::Init);
		assert!(client.transition(HandshakeState::ClientHelloSent).is_ok());
		assert_eq!(client.state(), HandshakeState::ClientHelloSent);

		assert!(client.transition(HandshakeState::ServerHelloReceived).is_ok());
		assert!(client.transition(HandshakeState::KeyExchangeSent).is_ok());
		assert!(client.transition(HandshakeState::ServerFinishedReceived).is_ok());
		assert!(client.transition(HandshakeState::ClientFinishedSent).is_ok());
		assert!(client.transition(HandshakeState::Complete).is_ok());

		assert!(client.state().is_complete());
	}

	#[test]
	fn test_server_state_transitions() {
		let mut server = ServerStateTransition::new();

		// Valid transitions
		assert_eq!(server.state(), HandshakeState::Init);
		assert!(server.transition(HandshakeState::ServerHelloReceived).is_ok());
		assert!(server.transition(HandshakeState::ServerHelloSent).is_ok());
		assert!(server.transition(HandshakeState::KeyExchangeReceived).is_ok());
		assert!(server.transition(HandshakeState::ServerFinishedSent).is_ok());
		assert!(server.transition(HandshakeState::ClientFinishedReceived).is_ok());
		assert!(server.transition(HandshakeState::Complete).is_ok());

		assert!(server.state().is_complete());
	}

	#[test]
	fn test_invalid_client_transition() {
		let mut client = ClientStateTransition::new();

		// Try to skip to an invalid state (Init can go to ClientHelloSent or KeyExchangeSent, but not ServerFinishedReceived)
		assert!(client.transition(HandshakeState::ServerFinishedReceived).is_err());
		assert_eq!(client.state(), HandshakeState::Init); // State unchanged
	}

	#[test]
	fn test_invalid_server_transition() {
		let mut server = ServerStateTransition::new();

		// Try to skip states
		assert!(server.transition(HandshakeState::ServerFinishedSent).is_err());
		assert_eq!(server.state(), HandshakeState::Init); // State unchanged
	}

	#[test]
	fn test_transition_to_failed() {
		let mut client = ClientStateTransition::new();

		// Can transition to Failed from any state
		assert!(client.transition(HandshakeState::ClientHelloSent).is_ok());
		assert!(client.transition(HandshakeState::Failed).is_ok());
		assert!(client.state().is_failed());
	}

	#[test]
	fn test_state_checks() {
		assert!(HandshakeState::Complete.is_complete());
		assert!(!HandshakeState::Complete.is_failed());
		assert!(!HandshakeState::Complete.is_in_progress());

		assert!(HandshakeState::Failed.is_failed());
		assert!(!HandshakeState::Failed.is_complete());
		assert!(!HandshakeState::Failed.is_in_progress());

		assert!(HandshakeState::ClientHelloSent.is_in_progress());
		assert!(!HandshakeState::ClientHelloSent.is_complete());
		assert!(!HandshakeState::ClientHelloSent.is_failed());
	}
}
