//! Protocol state management traits
//!
//! This module separates protocol state accessors from I/O operations,
//! following the Single Responsibility Principle.

use core::time::Duration;

#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::crypto::aead::{RecvCipher, SendCipher, SessionKeys};
use crate::crypto::profiles::CryptoProvider;
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::store::CertificateTrust;
use crate::transport::handshake::negotiation::{MuxSettings, TransportAuthorizer, TransportOffer};
use crate::transport::handshake::receipt::{ReceiptApprover, SessionObserver, StoredReceipt};
use crate::transport::handshake::{
	BoxedServerHandshake, HandshakeKeyManager, HandshakeProtocolKind, TcpHandshakeState,
};
use crate::transport::TransportResult;
use crate::x509::Certificate;

/// Protocol state management for encrypted transports
///
/// This trait provides access to the state fields needed for encrypted transport operations,
/// separating state management from I/O operations.
#[cfg(feature = "x509")]
pub trait EncryptedProtocolState {
	/// The crypto provider used by this transport
	type CryptoProvider: CryptoProvider + Send + Sync + 'static;

	/// Get the send-direction cipher (counter-nonce encryptor)
	fn to_encryptor_ref(&self) -> TransportResult<&SendCipher>;

	/// Get the receive-direction cipher (replay-rejecting decryptor)
	fn to_decryptor_ref(&self) -> TransportResult<&RecvCipher>;

	/// Get current handshake state (pure accessor)
	fn to_handshake_state(&self) -> TcpHandshakeState;

	/// Set handshake state (pure mutator)
	fn set_handshake_state(&mut self, state: TcpHandshakeState);

	/// Get server certificate if present (pure accessor)
	fn to_server_certificate_ref(&self) -> Option<&Certificate>;

	/// Set the directional session keys (pure mutator)
	fn set_session_keys(&mut self, keys: SessionKeys);

	/// Helper to clear session keys (for circuit breaker)
	fn unset_session_keys(&mut self);

	/// Get the local transport capability advertisement (multiplexing)
	fn to_mux_config(&self) -> Option<TransportOffer>;

	/// Get the budget-grant policy consulted between the client's
	/// transport offer and the server's accept. `None` grants the local
	/// configuration ceiling.
	fn to_transport_authorizer(&self) -> Option<Arc<dyn TransportAuthorizer>> {
		None
	}

	/// Get the client-side receipt approver consulted before
	/// countersigning a session receipt. `None` fails closed on
	/// challenge-bearing receipts.
	fn to_receipt_approver(&self) -> Option<Arc<dyn ReceiptApprover>> {
		None
	}

	/// Get the server-side observer that records the session outcome of
	/// every budget-bearing handshake. `None` discards the record.
	fn to_session_observer(&self) -> Option<Arc<dyn SessionObserver>> {
		None
	}

	/// Store the negotiated multiplexing settings (pure mutator)
	fn set_mux_settings(&mut self, settings: Option<MuxSettings>);

	/// Store the dual-signed session receipt (pure mutator)
	fn set_session_receipt(&mut self, _receipt: Option<StoredReceipt>) {}

	/// Set peer certificate after mutual auth
	fn set_peer_certificate(&mut self, _cert: Certificate);

	/// Get server certificate Arc if present (zero-copy accessor)
	fn to_server_certificate_arc(&self) -> Option<Arc<Certificate>> {
		None
	}

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
	fn to_key_manager_ref(&self) -> Option<&Arc<HandshakeKeyManager<Self::CryptoProvider>>> {
		None
	}

	/// Get client certificate reference
	fn to_client_certificate_ref(&self) -> Option<&Arc<Certificate>> {
		None
	}

	/// Get trust store reference (for server certificate validation)
	fn to_trust_store_ref(&self) -> Option<&Arc<dyn CertificateTrust>> {
		None
	}

	/// Get the provisioned server certificate chain, ordered root to leaf
	fn to_server_certificate_chain_ref(&self) -> Option<&Arc<[Certificate]>> {
		None
	}

	/// Get mutable reference to server handshake orchestrator
	fn to_server_handshake_mut(&mut self) -> &mut Option<BoxedServerHandshake>;

	/// Get handshake timeout
	fn to_handshake_timeout(&self) -> Duration {
		Duration::from_secs(1)
	}

	/// Get client validators
	fn to_client_validators_ref(&self) -> Option<&Arc<Vec<Arc<dyn CertificateValidation>>>> {
		None
	}
}
