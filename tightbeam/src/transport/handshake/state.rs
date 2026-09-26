//! State machine infrastructure for TightBeam handshake protocol.
//!
//! Each role has its own states, and each protocol its own transition table.
//! `Completed` is the one terminal state. A failed handshake is the error the
//! orchestrator returns, and the transport's session reset discards it.

use crate::transport::handshake::error::HandshakeError;

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
}

impl ClientHandshakeState {
	/// Whether the handshake reached its one terminal state.
	pub fn is_completed(&self) -> bool {
		matches!(self, Self::Completed)
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
}

impl ServerHandshakeState {
	/// Whether the handshake reached its one terminal state.
	pub fn is_completed(&self) -> bool {
		matches!(self, Self::Completed)
	}
}

#[derive(Debug)]
pub struct ClientStateMachine<F: HandshakeFlow> {
	state: ClientHandshakeState,
	flow: core::marker::PhantomData<F>,
}

impl<F: HandshakeFlow> Default for ClientStateMachine<F> {
	fn default() -> Self {
		Self { state: ClientHandshakeState::default(), flow: core::marker::PhantomData }
	}
}

mod sealed {
	pub trait Sealed {}
}

/// The handshake flow whose transition table a state machine enforces.
///
/// Each protocol has its own table. An ECIES machine cannot take a CMS-only
/// transition and a CMS machine cannot take an ECIES-only one, so the type
/// refuses protocol confusion before the orchestrator has to avoid it by
/// driving a fixed sequence.
///
/// The trait is sealed, because the flows are the two this crate implements.
pub trait HandshakeFlow: sealed::Sealed {
	/// Whether this flow permits a client to move `from` to `to`.
	fn client_permits(from: ClientHandshakeState, to: ClientHandshakeState) -> bool;

	/// Whether this flow permits a server to move `from` to `to`.
	fn server_permits(from: ServerHandshakeState, to: ServerHandshakeState) -> bool;
}

/// The CMS handshake flow: no explicit hello, and a Finished exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cms;

/// The ECIES handshake flow: an explicit hello, and no Finished exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ecies;

impl sealed::Sealed for Cms {}
impl sealed::Sealed for Ecies {}

impl HandshakeFlow for Cms {
	fn client_permits(from: ClientHandshakeState, to: ClientHandshakeState) -> bool {
		use ClientHandshakeState::*;
		matches!(
			(from, to),
			(Init, KeyExchangeSent)
				| (KeyExchangeSent, ServerFinishedReceived)
				| (ServerFinishedReceived, ClientFinishedSent)
				| (ClientFinishedSent, Completed)
		)
	}

	fn server_permits(from: ServerHandshakeState, to: ServerHandshakeState) -> bool {
		use ServerHandshakeState::*;
		matches!(
			(from, to),
			(Init, KeyExchangeReceived)
				| (KeyExchangeReceived, ServerFinishedSent)
				| (ServerFinishedSent, ClientFinishedReceived)
				| (ClientFinishedReceived, Completed)
		)
	}
}

impl HandshakeFlow for Ecies {
	fn client_permits(from: ClientHandshakeState, to: ClientHandshakeState) -> bool {
		use ClientHandshakeState::*;
		matches!(
			(from, to),
			(Init, HelloSent)
				| (HelloSent, ServerHelloReceived)
				| (ServerHelloReceived, KeyExchangeSent)
				| (KeyExchangeSent, Completed)
		)
	}

	fn server_permits(from: ServerHandshakeState, to: ServerHandshakeState) -> bool {
		use ServerHandshakeState::*;
		matches!(
			(from, to),
			(Init, ClientHelloReceived)
				| (ClientHelloReceived, ServerHelloSent)
				| (ServerHelloSent, KeyExchangeReceived)
				| (KeyExchangeReceived, Completed)
		)
	}
}

impl<F: HandshakeFlow> ClientStateMachine<F> {
	pub fn state(&self) -> ClientHandshakeState {
		self.state
	}

	/// Enforce a single expected handshake state. A mismatch yields
	/// `InvalidState`.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(crate) fn expect_state(&self, expected: ClientHandshakeState) -> Result<(), HandshakeError> {
		if self.state != expected {
			Err(HandshakeError::InvalidState)
		} else {
			Ok(())
		}
	}

	pub fn transition(&mut self, to: ClientHandshakeState) -> Result<(), HandshakeError> {
		if self.state.is_completed() {
			return Err(HandshakeError::InvalidState);
		}
		if F::client_permits(self.state, to) {
			self.state = to;
			Ok(())
		} else {
			Err(HandshakeError::InvalidState)
		}
	}
}

#[derive(Debug)]
pub struct ServerStateMachine<F: HandshakeFlow> {
	state: ServerHandshakeState,
	flow: core::marker::PhantomData<F>,
}

impl<F: HandshakeFlow> Default for ServerStateMachine<F> {
	fn default() -> Self {
		Self { state: ServerHandshakeState::default(), flow: core::marker::PhantomData }
	}
}

impl<F: HandshakeFlow> ServerStateMachine<F> {
	pub fn state(&self) -> ServerHandshakeState {
		self.state
	}

	/// Enforce a single expected handshake state. A mismatch yields
	/// `InvalidState`.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(crate) fn expect_state(&self, expected: ServerHandshakeState) -> Result<(), HandshakeError> {
		if self.state != expected {
			Err(HandshakeError::InvalidState)
		} else {
			Ok(())
		}
	}

	pub fn transition(&mut self, to: ServerHandshakeState) -> Result<(), HandshakeError> {
		if self.state.is_completed() {
			return Err(HandshakeError::InvalidState);
		}
		if F::server_permits(self.state, to) {
			self.state = to;
			Ok(())
		} else {
			Err(HandshakeError::InvalidState)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// ECIES: an explicit hello, and completion straight from key exchange.
	#[test]
	fn ecies_client_runs_its_own_flow() {
		let mut sm = ClientStateMachine::<Ecies>::default();
		assert_eq!(sm.state(), ClientHandshakeState::Init);
		assert!(sm.transition(ClientHandshakeState::HelloSent).is_ok());
		assert!(sm.transition(ClientHandshakeState::ServerHelloReceived).is_ok());
		assert!(sm.transition(ClientHandshakeState::KeyExchangeSent).is_ok());
		assert!(sm.transition(ClientHandshakeState::Completed).is_ok());
		assert!(sm.state().is_completed());
	}

	/// CMS: no hello, and a Finished exchange before completion.
	#[test]
	fn cms_client_runs_its_own_flow() {
		let mut sm = ClientStateMachine::<Cms>::default();
		assert!(sm.transition(ClientHandshakeState::KeyExchangeSent).is_ok());
		assert!(sm.transition(ClientHandshakeState::ServerFinishedReceived).is_ok());
		assert!(sm.transition(ClientHandshakeState::ClientFinishedSent).is_ok());
		assert!(sm.transition(ClientHandshakeState::Completed).is_ok());
	}

	#[test]
	fn ecies_server_runs_its_own_flow() {
		let mut sm = ServerStateMachine::<Ecies>::default();
		assert_eq!(sm.state(), ServerHandshakeState::Init);
		assert!(sm.transition(ServerHandshakeState::ClientHelloReceived).is_ok());
		assert!(sm.transition(ServerHandshakeState::ServerHelloSent).is_ok());
		assert!(sm.transition(ServerHandshakeState::KeyExchangeReceived).is_ok());
		assert!(sm.transition(ServerHandshakeState::Completed).is_ok());
		assert!(sm.state().is_completed());
	}

	#[test]
	fn cms_server_runs_its_own_flow() {
		let mut sm = ServerStateMachine::<Cms>::default();
		assert!(sm.transition(ServerHandshakeState::KeyExchangeReceived).is_ok());
		assert!(sm.transition(ServerHandshakeState::ServerFinishedSent).is_ok());
		assert!(sm.transition(ServerHandshakeState::ClientFinishedReceived).is_ok());
		assert!(sm.transition(ServerHandshakeState::Completed).is_ok());
	}

	/// A CMS client that skips its Finished exchange, or an ECIES client that
	/// sends a Finished it has no message for, is refused by the table itself.
	#[test]
	fn a_flow_refuses_the_other_protocols_transitions() {
		let mut cms = ClientStateMachine::<Cms>::default();
		assert!(cms.transition(ClientHandshakeState::HelloSent).is_err());
		assert!(cms.transition(ClientHandshakeState::KeyExchangeSent).is_ok());
		assert!(cms.transition(ClientHandshakeState::Completed).is_err());

		let mut ecies = ClientStateMachine::<Ecies>::default();
		assert!(ecies.transition(ClientHandshakeState::KeyExchangeSent).is_err());
		assert!(ecies.transition(ClientHandshakeState::HelloSent).is_ok());
		assert!(ecies.transition(ClientHandshakeState::ServerHelloReceived).is_ok());
		assert!(ecies.transition(ClientHandshakeState::KeyExchangeSent).is_ok());
		assert!(ecies.transition(ClientHandshakeState::ServerFinishedReceived).is_err());
	}

	/// The same split on the server side.
	#[test]
	fn a_server_flow_refuses_the_other_protocols_entry() {
		let mut cms = ServerStateMachine::<Cms>::default();
		assert!(cms.transition(ServerHandshakeState::ClientHelloReceived).is_err());

		let mut ecies = ServerStateMachine::<Ecies>::default();
		assert!(ecies.transition(ServerHandshakeState::KeyExchangeReceived).is_err());
	}

	/// A completed handshake admits no further move, so a replayed message
	/// cannot restart it.
	#[test]
	fn a_completed_handshake_is_terminal() {
		let mut sm = ClientStateMachine::<Cms>::default();
		assert!(sm.transition(ClientHandshakeState::KeyExchangeSent).is_ok());
		assert!(sm.transition(ClientHandshakeState::ServerFinishedReceived).is_ok());
		assert!(sm.transition(ClientHandshakeState::ClientFinishedSent).is_ok());
		assert!(sm.transition(ClientHandshakeState::Completed).is_ok());
		assert!(sm.transition(ClientHandshakeState::KeyExchangeSent).is_err());
	}
}
