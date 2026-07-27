//! Protocol state management traits
//!
//! Separates encrypted-transport state accessors from I/O.

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

#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(feature = "aead")]
use crate::transport::handshake::EpochMaterials;

/// State accessors for encrypted transports, separate from I/O.
#[cfg(feature = "x509")]
pub trait EncryptedProtocolState {
	/// Crypto provider bound to this transport.
	type CryptoProvider: CryptoProvider + Send + Sync + 'static;

	/// Send-direction cipher (counter-nonce encryptor).
	fn to_encryptor_ref(&self) -> TransportResult<&SendCipher>;

	/// Receive-direction cipher (exact-next counter decryptor).
	fn to_decryptor_ref(&self) -> TransportResult<&RecvCipher>;

	/// Current handshake state machine position.
	fn to_handshake_state(&self) -> TcpHandshakeState;

	/// Advance or reset the handshake state machine.
	fn set_handshake_state(&mut self, state: TcpHandshakeState);

	/// Local server certificate, when this endpoint presents one.
	fn to_server_certificate_ref(&self) -> Option<&Certificate>;

	/// Install directional session keys after handshake completion.
	fn set_session_keys(&mut self, keys: SessionKeys);

	/// Drop session keys (circuit-breaker / teardown).
	fn unset_session_keys(&mut self);

	/// Local mux capability advertisement offered in the handshake.
	fn to_mux_config(&self) -> Option<TransportOffer>;

	/// Persist negotiated multiplexing settings after the handshake.
	fn set_mux_settings(&mut self, settings: Option<MuxSettings>);

	/// Persist the dual-signed session receipt.
	fn set_session_receipt(&mut self, _receipt: Option<StoredReceipt>) {}

	/// Store the peer certificate after mutual authentication.
	fn set_peer_certificate(&mut self, _cert: Certificate);

	/// Budget-grant policy between the client's transport offer and the
	/// server's accept. `None` grants the local configuration ceiling.
	fn to_transport_authorizer(&self) -> Option<Arc<dyn TransportAuthorizer>> {
		None
	}

	/// Client receipt approver for challenge-bearing session receipts.
	/// `None` fails closed when a challenge is present.
	fn to_receipt_approver(&self) -> Option<Arc<dyn ReceiptApprover>> {
		None
	}

	/// Server observer for budget-bearing handshake outcomes.
	/// `None` discards the record.
	fn to_session_observer(&self) -> Option<Arc<dyn SessionObserver>> {
		None
	}

	/// Dual-signed session receipt, if stored (zero-copy).
	fn to_session_receipt_ref(&self) -> Option<&StoredReceipt> {
		None
	}

	/// Shared handle to the dual-signed session receipt (zero-copy).
	fn to_session_receipt_arc(&self) -> Option<Arc<StoredReceipt>> {
		None
	}

	/// Validated peer certificate: client identity on a mutual-auth
	/// server, trust-store-validated server identity on a client.
	fn to_peer_certificate_ref(&self) -> Option<&Certificate> {
		None
	}

	/// Shared handle to the validated peer certificate (zero-copy).
	fn to_peer_certificate_arc(&self) -> Option<Arc<Certificate>> {
		None
	}

	/// Shared handle to the local server certificate (zero-copy).
	fn to_server_certificate_arc(&self) -> Option<Arc<Certificate>> {
		None
	}

	/// Cleartext envelope size cap in bytes.
	fn to_max_cleartext_envelope(&self) -> Option<usize> {
		None
	}

	/// Encrypted envelope size cap in bytes.
	fn to_max_encrypted_envelope(&self) -> Option<usize> {
		None
	}

	/// Whether client certificate validators are configured (mutual auth).
	fn is_client_validators_present(&self) -> bool {
		false
	}

	/// Selected handshake protocol for encrypted sessions.
	fn to_handshake_protocol_kind(&self) -> HandshakeProtocolKind {
		HandshakeProtocolKind::default()
	}

	/// Signing key manager for client identity / countersignatures.
	fn to_key_manager_ref(&self) -> Option<&Arc<HandshakeKeyManager<Self::CryptoProvider>>> {
		None
	}

	/// Client certificate presented for mutual authentication.
	fn to_client_certificate_ref(&self) -> Option<&Arc<Certificate>> {
		None
	}

	/// Trust store used to validate the peer server certificate.
	fn to_trust_store_ref(&self) -> Option<&Arc<dyn CertificateTrust>> {
		None
	}

	/// Provisioned server certificate chain, ordered root to leaf
	/// (required for CMS key-transport before the server speaks).
	fn to_server_certificate_chain_ref(&self) -> Option<&Arc<[Certificate]>> {
		None
	}

	/// Mutable server handshake orchestrator slot.
	fn to_server_handshake_mut(&mut self) -> &mut Option<BoxedServerHandshake>;

	/// Absolute deadline applied to handshake-phase reads.
	fn to_handshake_timeout(&self) -> Duration {
		Duration::from_secs(1)
	}

	/// Client certificate validators for mutual authentication.
	fn to_client_validators_ref(&self) -> Option<&Arc<Vec<Arc<dyn CertificateValidation>>>> {
		None
	}

	/// Persist epoch-0 rekey materials. Transports without rekey support
	/// discard them.
	#[cfg(feature = "aead")]
	fn set_epoch_materials(&mut self, _materials: Option<EpochMaterials>) {}

	/// Detach epoch rekey materials for in-band renewal wiring (one-shot).
	#[cfg(feature = "aead")]
	fn take_epoch_materials(&mut self) -> Option<EpochMaterials> {
		None
	}

	/// Production instrumentation collector attached to this transport.
	#[cfg(feature = "instrument")]
	fn to_trace_ref(&self) -> Option<&TraceCollector> {
		None
	}
}
