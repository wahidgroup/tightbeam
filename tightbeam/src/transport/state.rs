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
use crate::transport::handshake::{BoxedServerHandshake, HandshakeInstant, HandshakeKeyManager, HandshakeProtocolKind};
use crate::transport::TransportLimits;
use crate::transport::TransportResult;
use crate::x509::Certificate;

#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(feature = "aead")]
use crate::transport::handshake::EpochMaterials;

/// Which wire mode a session is entitled to write, and the state backing it.
///
/// The phase is stored rather than derived, and each arm carries what that
/// phase needs. Session keys live in [`SessionPhase::Encrypted`], so a
/// completed handshake without keys, or keys without a completed handshake,
/// cannot be built.
///
/// # Sources
///
/// - CWE-311, missing encryption of sensitive data:
///   <https://cwe.mitre.org/data/definitions/311.html>
#[cfg(feature = "x509")]
#[derive(Default)]
pub enum SessionPhase {
	/// The endpoint carries no encryption provisioning, so frames travel in
	/// the clear as a configured choice.
	#[default]
	Cleartext,
	/// Encryption is provisioned and no handshake has started. A write in
	/// this phase fails with [`TransportFailure::EncryptorUnavailable`].
	Provisioned,
	/// A handshake is in flight, measured against `initiated_at`.
	Handshaking { initiated_at: HandshakeInstant },
	/// The handshake completed and these are its directional keys.
	Encrypted(SessionKeys),
}

#[cfg(feature = "x509")]
impl SessionPhase {
	/// A pooled connection is leased only in a writable phase, so a peer that
	/// stalls its handshake keeps that connection out of the pool. A phase
	/// added later stays unwritable until it is named here.
	pub const fn is_writable(&self) -> bool {
		matches!(self, Self::Cleartext | Self::Encrypted(_))
	}

	/// Whether a handshake is provisioned but not yet complete.
	pub const fn is_handshake_pending(&self) -> bool {
		matches!(self, Self::Provisioned | Self::Handshaking { .. })
	}

	/// When the in-flight handshake began, if one is in flight.
	pub const fn initiated_at(&self) -> Option<HandshakeInstant> {
		match self {
			Self::Handshaking { initiated_at } => Some(*initiated_at),
			_ => None,
		}
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

	/// The session's stored phase.
	fn session_phase(&self) -> &SessionPhase;

	/// Replace the session's phase.
	///
	/// The one writer. Installing keys and marking the handshake complete are
	/// the same transition here, so they cannot be done separately.
	fn set_session_phase(&mut self, phase: SessionPhase);

	/// A server certificate, a trust store, or client validators each imply a
	/// handshake, so the dispatcher and the wire-mode decision agree on what
	/// counts as provisioned.
	fn expects_encryption(&self) -> bool {
		self.to_server_certificate_ref().is_some()
			|| self.to_trust_store_ref().is_some()
			|| self.is_client_validators_present()
	}

	/// Move a cleartext session to [`SessionPhase::Provisioned`] once
	/// encryption material is installed.
	///
	/// Provisioning and the phase it implies travel together: a transport
	/// holding a certificate but still claiming `Cleartext` would write
	/// application data in the clear (CWE-311). The decision reads
	/// [`Self::expects_encryption`], the one definition of what counts as
	/// provisioned.
	fn provision(&mut self) {
		if self.expects_encryption() && matches!(self.session_phase(), SessionPhase::Cleartext) {
			self.set_session_phase(SessionPhase::Provisioned);
		}
	}

	/// Record that a handshake has started.
	fn begin_handshake(&mut self) {
		self.set_session_phase(SessionPhase::Handshaking { initiated_at: HandshakeInstant::now() });
	}

	/// Install the handshake's keys and mark the session encrypted.
	fn complete_handshake(&mut self, keys: SessionKeys) {
		self.set_session_phase(SessionPhase::Encrypted(keys));
	}

	/// Drop any session keys and return to the phase this endpoint starts in.
	///
	/// The circuit breaker. Resetting the position and dropping the keys is
	/// one transition, so a caller cannot do one and forget the other.
	fn reset_session(&mut self) {
		let phase = if self.expects_encryption() {
			SessionPhase::Provisioned
		} else {
			SessionPhase::Cleartext
		};
		self.set_session_phase(phase);
	}

	/// Every envelope this endpoint writes passes through here, so the wire
	/// mode is decided once per session rather than once per call site.
	///
	/// # Errors
	///
	/// - [`TransportFailure::EncryptorUnavailable`] -- the session is
	///   [`SessionPhase::Provisioned`] or [`SessionPhase::Handshaking`], so the
	///   frame waits for the handshake to install keys.
	fn apply_wire_mode<'a>(&'a self, builder: EnvelopeBuilder<'a>) -> TransportResult<EnvelopeBuilder<'a>> {
		match self.session_phase() {
			SessionPhase::Encrypted(keys) => {
				Ok(builder.with_wire_mode(WireMode::Encrypted).with_encryptor(keys.send()))
			}
			SessionPhase::Cleartext => Ok(builder.with_wire_mode(WireMode::Cleartext)),
			SessionPhase::Provisioned | SessionPhase::Handshaking { .. } => {
				Err(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))
			}
		}
	}

	/// Local server certificate, when this endpoint presents one.
	fn to_server_certificate_ref(&self) -> Option<&Certificate>;

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

	/// Holds the phase the trait reads back.
	struct PhaseProbe {
		phase: SessionPhase,
		validators: bool,
		limits: TransportLimits,
	}

	impl PhaseProbe {
		fn provisioned(phase: SessionPhase) -> Self {
			Self { phase, validators: true, limits: TransportLimits::default() }
		}
	}

	impl EncryptedProtocolState for PhaseProbe {
		type CryptoProvider = DefaultCryptoProvider;

		fn limits(&self) -> &TransportLimits {
			&self.limits
		}

		fn session_phase(&self) -> &SessionPhase {
			&self.phase
		}

		fn set_session_phase(&mut self, phase: SessionPhase) {
			self.phase = phase;
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

		fn to_mux_config(&self) -> Option<TransportOffer> {
			None
		}

		fn set_mux_settings(&mut self, _settings: Option<MuxSettings>) {}

		fn set_peer_certificate(&mut self, _cert: Certificate) {}

		fn to_server_handshake_mut(&mut self) -> &mut Option<BoxedServerHandshake> {
			unreachable!()
		}
	}

	fn handshaking() -> SessionPhase {
		SessionPhase::Handshaking { initiated_at: HandshakeInstant::now() }
	}

	#[test]
	fn an_unprovisioned_session_is_cleartext() {
		let probe = PhaseProbe {
			phase: SessionPhase::Cleartext,
			validators: false,
			limits: TransportLimits::default(),
		};
		assert!(matches!(probe.session_phase(), SessionPhase::Cleartext));
	}

	/// Completing the handshake and installing keys is one transition, so a
	/// phase that claims encryption always has the keys to honour it.
	#[test]
	fn completing_a_handshake_installs_its_keys() {
		let mut probe = PhaseProbe::provisioned(handshaking());
		use crate::crypto::aead::{Aes256Gcm, Aes256GcmOid, KeyInit};
		use crate::der::oid::AssociatedOid;

		probe.complete_handshake(SessionKeys::for_client(
			Aes256Gcm::new(&[0u8; 32].into()),
			Aes256Gcm::new(&[1u8; 32].into()),
			Aes256GcmOid::OID,
		));

		let SessionPhase::Encrypted(keys) = probe.session_phase() else {
			panic!("completing a handshake must leave the session encrypted");
		};
		assert!(core::ptr::eq(keys.send(), keys.send()));
	}

	/// The circuit breaker returns a provisioned endpoint to a phase whose
	/// writes stay encrypted, in one transition (CWE-311).
	#[test]
	fn resetting_a_provisioned_session_returns_it_to_provisioned() {
		let mut probe = PhaseProbe::provisioned(handshaking());
		probe.reset_session();
		assert!(matches!(probe.session_phase(), SessionPhase::Provisioned));
	}

	#[test]
	fn resetting_an_unprovisioned_session_returns_it_to_cleartext() {
		let mut probe = PhaseProbe { phase: handshaking(), validators: false, limits: TransportLimits::default() };
		probe.reset_session();
		assert!(matches!(probe.session_phase(), SessionPhase::Cleartext));
	}

	#[test]
	fn only_cleartext_and_encrypted_phases_are_writable() {
		assert!(SessionPhase::Cleartext.is_writable());
		assert!(!SessionPhase::Provisioned.is_writable());
		assert!(!handshaking().is_writable());
	}

	/// Every envelope path applies the wire mode here, so this refusal is the
	/// one that keeps a stalled session from writing in the clear (CWE-311).
	#[test]
	fn pending_session_refuses_to_apply_a_wire_mode() {
		let probe = PhaseProbe::provisioned(handshaking());
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
