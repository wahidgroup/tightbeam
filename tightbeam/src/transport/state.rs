//! Protocol state management traits
//!
//! This module separates protocol state accessors from I/O operations,
//! following the Single Responsibility Principle.

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::sync::Arc;

use core::time::Duration;

use crate::crypto::aead::RuntimeAead;
use crate::crypto::x509::policy::CertificateValidation;
use crate::transport::handshake::{
	HandshakeError, HandshakeKeyManager, HandshakeProtocolKind, ServerHandshakeProtocol, TcpHandshakeState,
};
use crate::transport::TransportResult;
use crate::x509::Certificate;

/// Protocol state management for encrypted transports
///
/// This trait provides access to the state fields needed for encrypted transport operations,
/// separating state management from I/O operations.
#[cfg(feature = "x509")]
pub trait EncryptedProtocolState {
	/// Get the encryptor instance (RuntimeAead)
	fn to_encryptor_ref(&self) -> TransportResult<&RuntimeAead>;

	/// Get the decryptor instance (RuntimeAead)
	fn to_decryptor_ref(&self) -> TransportResult<&RuntimeAead>;

	/// Get current handshake state (pure accessor)
	fn to_handshake_state(&self) -> TcpHandshakeState;

	/// Set handshake state (pure mutator)
	fn set_handshake_state(&mut self, state: TcpHandshakeState);

	/// Get server certificate if present (pure accessor)
	fn to_server_certificate_ref(&self) -> Option<&Certificate>;

	/// Set symmetric encryption key (pure mutator)
	fn set_symmetric_key(&mut self, key: RuntimeAead);

	/// Helper to clear symmetric key (for circuit breaker)
	fn unset_symmetric_key(&mut self);

	/// Set peer certificate after mutual auth
	fn set_peer_certificate(&mut self, _cert: Certificate);

	/// Maximum allowed size for cleartext envelopes (bytes)
	fn to_max_cleartext_envelope(&self) -> Option<usize> {
		None
	}

	/// Maximum allowed size for encrypted envelopes (bytes)
	fn to_max_encrypted_envelope(&self) -> Option<usize> {
		None
	}

	/// Helper to check if client validators are present
	fn is_client_validators_present(&self) -> bool {
		false
	}

	/// Get handshake protocol kind
	fn to_handshake_protocol_kind(&self) -> HandshakeProtocolKind {
		HandshakeProtocolKind::default()
	}

	/// Get key manager reference
	fn to_key_manager_ref(&self) -> Option<&Arc<HandshakeKeyManager>> {
		None
	}

	/// Get client certificate reference
	fn to_client_certificate_ref(&self) -> Option<&Arc<Certificate>> {
		None
	}

	/// Get server certificates reference
	fn to_server_certificates_ref(&self) -> &[Arc<Certificate>] {
		&[]
	}

	/// Get mutable reference to server handshake orchestrator
	fn to_server_handshake_mut(
		&mut self,
	) -> &mut Option<Box<dyn ServerHandshakeProtocol<Error = HandshakeError> + Send>> {
		panic!("server_handshake_mut not implemented")
	}

	/// Get handshake timeout
	fn to_handshake_timeout(&self) -> Duration {
		Duration::from_secs(1)
	}

	/// Get client validators
	fn to_client_validators_ref(&self) -> Option<&Arc<Vec<Arc<dyn CertificateValidation>>>> {
		None
	}
}
