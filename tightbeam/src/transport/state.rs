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
use crate::transport::builders::EnvelopeBuilder;
use crate::transport::envelopes::WireMode;
use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::handshake::negotiation::{MuxSettings, TransportAuthorizer, TransportOffer};
use crate::transport::handshake::receipt::{ReceiptApprover, SessionObserver, StoredReceipt};
use crate::transport::handshake::{
	BoxedServerHandshake, HandshakeKeyManager, HandshakeProtocolKind, TcpHandshakeState,
};
use crate::transport::TransportLimits;
use crate::transport::TransportResult;
use crate::x509::Certificate;

#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(feature = "aead")]
use crate::transport::handshake::EpochMaterials;

/// Which wire mode a session is entitled to write.
///
/// The phase derives from the handshake position together with the endpoint's
/// encryption provisioning, read in one place so every write site receives
/// the same answer. Callers match every arm, so a new phase surfaces at each
/// of them as a compile error.
///
/// # Sources
///
/// - CWE-311, missing encryption of sensitive data:
///   <https://cwe.mitre.org/data/definitions/311.html>
#[cfg(feature = "x509")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionPhase {
	/// The endpoint carries no encryption provisioning, so frames travel in
	/// the clear as a configured choice.
	Cleartext,
	/// Encryption is provisioned and the handshake is outstanding. A write
	/// in this phase fails with
	/// [`TransportFailure::EncryptorUnavailable`].
	Pending,
	/// The handshake completed and directional session keys are installed.
	Encrypted,
}

#[cfg(feature = "x509")]
impl SessionPhase {
	/// A pooled connection is leased only in a writable phase, so a peer that
	/// stalls its handshake keeps that connection out of the pool. A phase
	/// added later stays unwritable until it is named here.
	pub const fn is_writable(self) -> bool {
		matches!(self, Self::Cleartext | Self::Encrypted)
	}
}

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

	/// A server certificate, a trust store, or client validators each imply a
	/// handshake, so the dispatcher and the wire-mode decision agree on what
	/// counts as provisioned.
	fn expects_encryption(&self) -> bool {
		self.to_server_certificate_ref().is_some()
			|| self.to_trust_store_ref().is_some()
			|| self.is_client_validators_present()
	}

	/// [`SessionPhase::Encrypted`] requires a completed handshake. A
	/// provisioned endpoint at any earlier handshake position holds
	/// [`SessionPhase::Pending`], so a stalled or failed attempt keeps the
	/// session at a phase whose writes stay encrypted.
	fn session_phase(&self) -> SessionPhase {
		if self.to_handshake_state() == TcpHandshakeState::Complete {
			SessionPhase::Encrypted
		} else if self.expects_encryption() {
			SessionPhase::Pending
		} else {
			SessionPhase::Cleartext
		}
	}

	/// Every envelope this endpoint writes passes through here, so the wire
	/// mode is decided once per session rather than once per call site.
	///
	/// # Errors
	///
	/// - [`TransportFailure::EncryptorUnavailable`] -- the session is
	///   [`SessionPhase::Pending`], so the frame waits for the handshake to
	///   install keys.
	fn apply_wire_mode<'a>(&'a self, builder: EnvelopeBuilder<'a>) -> TransportResult<EnvelopeBuilder<'a>> {
		match self.session_phase() {
			SessionPhase::Encrypted => {
				let encryptor = self.to_encryptor_ref()?;

				Ok(builder.with_wire_mode(WireMode::Encrypted).with_encryptor(encryptor))
			}
			SessionPhase::Cleartext => Ok(builder.with_wire_mode(WireMode::Cleartext)),
			SessionPhase::Pending => Err(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable)),
		}
	}

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

	/// Every ceiling this endpoint enforces.
	fn limits(&self) -> &TransportLimits;

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
		self.limits().handshake_timeout
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

#[cfg(all(test, feature = "x509", feature = "aead"))]
mod tests {
	use super::*;
	use crate::asn1::{Frame, Metadata};
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::Version;

	/// Carries the two inputs [`EncryptedProtocolState::session_phase`] reads.
	struct PhaseProbe {
		handshake: TcpHandshakeState,
		validators: bool,
		limits: TransportLimits,
	}

	impl PhaseProbe {
		fn provisioned(handshake: TcpHandshakeState) -> Self {
			Self { handshake, validators: true, limits: TransportLimits::default() }
		}
	}

	impl EncryptedProtocolState for PhaseProbe {
		type CryptoProvider = DefaultCryptoProvider;

		fn limits(&self) -> &TransportLimits {
			&self.limits
		}

		fn to_handshake_state(&self) -> TcpHandshakeState {
			self.handshake
		}

		fn is_client_validators_present(&self) -> bool {
			self.validators
		}

		fn to_server_certificate_ref(&self) -> Option<&Certificate> {
			None
		}

		fn to_encryptor_ref(&self) -> TransportResult<&SendCipher> {
			Err(TransportError::ConnectionClosed)
		}

		fn to_decryptor_ref(&self) -> TransportResult<&RecvCipher> {
			Err(TransportError::ConnectionClosed)
		}

		fn set_handshake_state(&mut self, state: TcpHandshakeState) {
			self.handshake = state;
		}

		fn set_session_keys(&mut self, _keys: SessionKeys) {}

		fn unset_session_keys(&mut self) {}

		fn to_mux_config(&self) -> Option<TransportOffer> {
			None
		}

		fn set_mux_settings(&mut self, _settings: Option<MuxSettings>) {}

		fn set_peer_certificate(&mut self, _cert: Certificate) {}

		fn to_server_handshake_mut(&mut self) -> &mut Option<BoxedServerHandshake> {
			unreachable!()
		}
	}

	#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
	fn awaiting_server_response() -> TcpHandshakeState {
		TcpHandshakeState::AwaitingServerResponse { initiated_at: std::time::Instant::now() }
	}

	#[cfg(not(all(feature = "std", not(target_arch = "wasm32"))))]
	fn awaiting_server_response() -> TcpHandshakeState {
		TcpHandshakeState::AwaitingServerResponse { initiated_at: 0 }
	}

	#[test]
	fn unprovisioned_session_is_cleartext() {
		let probe = PhaseProbe {
			handshake: TcpHandshakeState::None,
			validators: false,
			limits: TransportLimits::default(),
		};
		assert_eq!(probe.session_phase(), SessionPhase::Cleartext);
	}

	#[test]
	fn completed_handshake_is_encrypted() {
		let probe = PhaseProbe::provisioned(TcpHandshakeState::Complete);
		assert_eq!(probe.session_phase(), SessionPhase::Encrypted);
	}

	#[test]
	fn provisioned_session_before_the_handshake_is_pending() {
		let probe = PhaseProbe::provisioned(TcpHandshakeState::None);
		assert_eq!(probe.session_phase(), SessionPhase::Pending);
	}

	/// A stalled attempt holds [`SessionPhase::Pending`], which is what keeps
	/// the payload encrypted when the handshake never completes (CWE-311).
	#[test]
	fn provisioned_session_awaiting_the_handshake_is_pending() {
		let probe = PhaseProbe::provisioned(awaiting_server_response());
		assert_eq!(probe.session_phase(), SessionPhase::Pending);
	}

	#[test]
	fn cleartext_and_encrypted_phases_are_writable() {
		assert!(SessionPhase::Cleartext.is_writable());
		assert!(SessionPhase::Encrypted.is_writable());
	}

	/// The connection pool leases on this predicate, so a stalled handshake
	/// keeps its connection out of the available set.
	#[test]
	fn pending_phase_is_unwritable() {
		assert!(!SessionPhase::Pending.is_writable());
	}

	/// Every envelope path applies the wire mode here, so this refusal is the
	/// one that keeps a stalled session from writing in the clear (CWE-311).
	#[test]
	fn pending_session_refuses_to_apply_a_wire_mode() {
		let probe = PhaseProbe::provisioned(awaiting_server_response());
		let frame = Frame {
			version: Version::V0,
			metadata: Metadata::default(),
			message: Vec::new(),
			integrity: None,
			nonrepudiation: None,
		};

		let builder = EnvelopeBuilder::request(frame);
		let refusal = probe.apply_wire_mode(builder);
		assert!(matches!(
			refusal,
			Err(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))
		));
	}
}
