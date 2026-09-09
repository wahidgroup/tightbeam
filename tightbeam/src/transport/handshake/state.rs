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
// Client State Machine
// ---------------------------------------------------------------------------

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
/// One table per protocol, rather than their union. An ECIES machine cannot
/// take a CMS-only transition and a CMS machine cannot take an ECIES-only one,
/// so protocol confusion is refused by the type rather than avoided by the
/// orchestrator driving a fixed sequence.
///
/// Sealed: the flows are the two this crate implements.
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
				| (_, Aborted(_))
				| (_, Failed(_))
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
				| (_, Aborted(_))
				| (_, Failed(_))
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
				| (_, Aborted(_))
				| (_, Failed(_))
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
				| (_, Aborted(_))
				| (_, Failed(_))
		)
	}
}

impl<F: HandshakeFlow> ClientStateMachine<F> {
	pub fn state(&self) -> ClientHandshakeState {
		self.state
	}

	pub fn transition(&mut self, to: ClientHandshakeState) -> Result<(), HandshakeError> {
		if self.state.is_terminal() {
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

// ---------------------------------------------------------------------------
// Server State Machine
// ---------------------------------------------------------------------------

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

	pub fn transition(&mut self, to: ServerHandshakeState) -> Result<(), HandshakeError> {
		if self.state.is_terminal() {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

	/// The union table accepted either protocol's moves from either machine.
	/// A CMS client skipping its Finished exchange, or an ECIES client sending
	/// a Finished it has no message for, is now refused by the table itself.
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

	#[test]
	fn abort_and_failure_are_terminal() {
		let mut sm = ClientStateMachine::<Ecies>::default();
		assert!(sm.transition(ClientHandshakeState::HelloSent).is_ok());
		assert!(sm.transition(ClientHandshakeState::Aborted(AbortReason::PeerAbort)).is_ok());
		assert!(sm.state().is_aborted());
		assert!(sm.transition(ClientHandshakeState::ServerHelloReceived).is_err());

		let mut sm2 = ServerStateMachine::<Cms>::default();
		assert!(sm2
			.transition(ServerHandshakeState::Failed(FailureKind::ProtocolViolation))
			.is_ok());
		assert!(sm2.state().is_failed());
	}
}
