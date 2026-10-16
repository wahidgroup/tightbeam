#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;

use crate::Errorizable;

#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
use crate::instrumentation::events;
#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
use crate::urn::Urn;

/// Result type for handshake operations.
pub type Result<T> = core::result::Result<T, HandshakeError>;

/// Errors that a handshake operation returns.
///
/// The handshake reports an invariant violation through one of these variants
/// instead of a panic.
#[derive(Debug, Errorizable)]
#[non_exhaustive]
pub enum HandshakeError {
	/// The client key exchange message is invalid.
	#[error("Invalid client key exchange message")]
	InvalidClientKeyExchange,

	/// The server key exchange message is invalid.
	#[error("Invalid server key exchange message")]
	InvalidServerKeyExchange,

	/// A public key in the handshake is invalid.
	#[error("Invalid public key in handshake: {0}")]
	#[from]
	InvalidPublicKey(crate::crypto::sign::ecdsa::k256::elliptic_curve::Error),

	/// The server sent its static key, or the negation of it, as its
	/// ephemeral. The agreement would then collapse into the static one, which
	/// the server's key recovers, so the client refuses it.
	#[error("Server ephemeral equals the server static key")]
	ServerEphemeralIsStatic,

	/// The client sent its static key, or the negation of it, as an ephemeral
	/// of the handshake or of a rekey. The agreement would then collapse into
	/// the static one, which the client's key recovers, so the server refuses
	/// it.
	#[error("Client ephemeral equals the client static key")]
	ClientEphemeralIsStatic,

	/// The peer certificate failed validation.
	#[error("Invalid certificate: {0}")]
	#[from]
	CertificateValidationError(crate::crypto::x509::error::CertificateValidationError),

	/// The handshake signature failed verification.
	#[error("Handshake signature verification failed")]
	SignatureVerificationFailed,

	/// A signature failed to parse or to verify.
	#[error("Signature error: {0}")]
	#[from]
	SignatureError(crate::crypto::sign::Error),

	/// The underlying DER encoding or decoding failed.
	#[error("DER error: {0}")]
	#[from]
	DerError(crate::der::Error),

	/// A SubjectPublicKeyInfo (SPKI) value is invalid.
	#[error("SPKI error: {0}")]
	#[from]
	SpkiError(crate::spki::Error),

	/// The key provider failed.
	#[error("Key provider error: {0}")]
	#[from]
	KeyError(crate::crypto::key::KeyError),

	/// The CMS builder failed.
	#[error("CMS builder error: {0}")]
	CmsBuilderError(crate::cms::builder::Error),

	/// The handshake state is invalid for this operation.
	#[error("Invalid handshake state")]
	InvalidState,

	/// The peer sent the other CMS container for this handshake step.
	#[error("Unexpected handshake container for this step")]
	UnexpectedContainer,

	/// No trust store or certificate validator is configured, so the handshake
	/// refuses expiry-only peer certificate validation.
	#[error("Trust store required: refusing expiry-only peer certificate validation")]
	MissingTrustStore,

	/// The server certificate is missing.
	#[error("Missing server certificate")]
	MissingServerCertificate,

	/// The client certificate is missing.
	#[error("Missing client certificate")]
	MissingClientCertificate,

	/// The digest output width differs from the required transcript hash
	/// width. `expected` is the required width and `received` is the digest
	/// output width, both in bytes.
	#[error("Transcript digest length invalid: expected {expected} bytes, got {received}")]
	TranscriptDigestLength { expected: usize, received: usize },

	/// The server requires mutual authentication, and the client has no
	/// identity configured.
	#[error("Server requires mutual authentication but client has no identity")]
	MutualAuthRequired,

	/// A budget-bearing session requires a session receipt, and none arrived.
	#[error("Session receipt required for budget-bearing session but missing")]
	ReceiptMissing,

	/// The session receipt disagrees with the negotiated session parameters.
	#[error("Session receipt does not match the negotiated session")]
	ReceiptMismatch,

	/// A budget-bearing session requires the client countersignature, and it
	/// is missing.
	#[error("Receipt countersignature required for budget-bearing session but missing")]
	CountersignatureMissing,

	/// The client's receipt approver refused the session receipt. `code` is
	/// the refusal code the approver returned.
	#[error("Session receipt refused by approver: code {code}")]
	ApprovalRefused { code: u32 },

	/// The server's authorizer rejected the settlement answer. `code` is the
	/// rejection code the authorizer returned.
	#[error("Settlement rejected: code {code}")]
	SettlementRejected { code: u32 },

	/// The AEAD refused to seal or open the receipt acknowledgement under the
	/// key the handshake secret derives. On the opening side the
	/// acknowledgement was sealed under another handshake secret or altered
	/// in flight.
	#[error("Receipt acknowledgement AEAD failure: {0}")]
	ReceiptAckCipher(crate::crypto::aead::Error),

	/// The sealed client identity of the closing fails to open under the key
	/// the handshake secret derives, or its frame is malformed. It was sealed
	/// under another handshake secret or another transcript, or altered in
	/// flight. A sealed CMS Finished is refused the same way when it names
	/// another content type or algorithm, or carries no content.
	#[error("Sealed client identity failed to open")]
	SealedIdentity,

	/// The key-confirmation tag of the closing differs from the tag the server
	/// derived. The client holds another handshake secret, or it confirmed
	/// another transcript.
	#[error("Key confirmation failed")]
	KeyConfirmationFailed,

	/// The KDF salt of a traffic-key derivation is below the minimum entropy
	/// requirement. `actual` is the salt length and `minimum` is the required
	/// length, both in bytes.
	#[error("KDF salt too short: {actual} bytes (minimum {minimum} required)")]
	InsufficientSaltEntropy { actual: usize, minimum: usize },

	/// The peer sent an abort alert during the handshake.
	#[error("Handshake aborted by peer: {0:?}")]
	AbortReceived(crate::transport::handshake::HandshakeAlert),

	/// The server selected no profile, or one that the client did not offer.
	#[error("Server selected no profile, or one outside the client's offer")]
	InvalidProfileSelection,

	/// Profile negotiation failed.
	#[error("Profile negotiation failed: {0}")]
	#[from]
	NegotiationError(crate::transport::handshake::negotiation::NegotiationError),

	/// The server has no supported profile configured, so it can select none.
	#[error("No supported profiles configured on server")]
	NoSupportedProfiles,

	/// An attribute holds more or fewer than one value.
	#[error("Attribute must contain exactly one value")]
	InvalidAttributeArity,
	/// An attribute appears more than once.
	#[error("Duplicate attribute present")]
	DuplicateAttribute,
	/// A required attribute is missing.
	#[error("Required attribute missing")]
	MissingAttribute,
	/// An OCTET STRING has the wrong length.
	#[error("OCTET STRING length mismatch: {0}")]
	OctetStringLengthError(crate::error::ReceivedExpectedError<usize, usize>),
	/// A version or alert value is not a valid INTEGER.
	#[error("Version/alert value not valid INTEGER")]
	InvalidIntegerEncoding,
	/// An INTEGER is out of range.
	#[error("INTEGER out of range")]
	IntegerOutOfRange,
	/// The alert code is unknown.
	#[error("Unknown alert code: {0:?}")]
	UnknownAlertCode(u8),

	/// An HPKE operation failed.
	#[cfg(feature = "hpke")]
	#[error("HPKE operation failed: {0}")]
	#[from]
	HpkeError(crate::crypto::hpke::HpkeError),
	/// The decrypted HPKE payload has an invalid size.
	#[error("Invalid decrypted payload size")]
	InvalidDecryptedPayloadSize,
	/// The client random differs from the expected value, which indicates a
	/// possible replay attack.
	#[error("client_random mismatch - possible replay attack")]
	ClientRandomMismatchReplay,

	/// A KDF operation failed.
	#[error("KDF operation failed: {0}")]
	#[from]
	KdfError(crate::crypto::kdf::KdfError),
	/// A key has an invalid size. `expected` and `received` are the required
	/// and the actual key length in bytes.
	#[error("Invalid key size: expected {expected}, got {received}")]
	InvalidKeySize { expected: usize, received: usize },
	/// The recipient index is invalid.
	#[error("Invalid recipient index")]
	InvalidRecipientIndex,
	/// The KeyAgreeRecipientInfo carries no user keying material (UKM).
	#[error("Missing UKM in KeyAgreeRecipientInfo")]
	MissingUkm,
	/// The originator identifier type is unsupported.
	#[error("Unsupported originator identifier type")]
	UnsupportedOriginatorIdentifier,
	/// The KARI builder was already consumed.
	#[error("KARI builder already consumed")]
	KariBuilderConsumed,
	/// The security profile configures no key wrap algorithm.
	#[error("Key wrap algorithm not configured in security profile")]
	MissingKeyWrapAlgorithm,
	/// The negotiated key wrap algorithm is not AES-128, AES-192, or AES-256
	/// key wrap.
	#[error("Negotiated key wrap algorithm unsupported (expected AES-128/192/256 key wrap)")]
	UnsupportedKeyWrapAlgorithm,

	/// Random generation failed.
	#[error("Random generation failed")]
	RandomGenerationFailed,

	/// Cryptographic key or nonce material has the wrong length.
	#[error("Invalid key material length: {0}")]
	#[from]
	InvalidKeyMaterialLength(crypto_common::InvalidLength),
}

#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
impl HandshakeError {
	/// Returns the audit event a failed handshake records for this error, when
	/// the error names one.
	///
	/// - A receipt approval or settlement refusal records
	///   [`SESSION_RECEIPT_REFUSED`](events::SESSION_RECEIPT_REFUSED).
	/// - A refused peer certificate or proof of possession, including a
	///   certificate the peer did not present and a sealed identity that fails
	///   to open, records
	///   [`SESSION_CERT_REJECTED`](events::SESSION_CERT_REJECTED).
	pub(crate) fn audit_event(&self) -> Option<Urn<'static>> {
		match self {
			Self::ApprovalRefused { .. } | Self::SettlementRejected { .. } => Some(events::SESSION_RECEIPT_REFUSED),
			Self::CertificateValidationError(_)
			| Self::SignatureVerificationFailed
			| Self::MissingClientCertificate
			| Self::SealedIdentity
			| Self::MutualAuthRequired => Some(events::SESSION_CERT_REJECTED),
			_ => None,
		}
	}
}

/// Narrows [`TightBeamError`](crate::error::TightBeamError) into
/// [`HandshakeError`].
///
/// A variant without a handshake counterpart collapses to
/// [`HandshakeError::InvalidState`].
impl From<crate::error::TightBeamError> for HandshakeError {
	fn from(err: crate::error::TightBeamError) -> Self {
		use crate::error::TightBeamError;
		match err {
			TightBeamError::HandshakeError(h) => h,
			TightBeamError::SerializationError(e) => HandshakeError::DerError(e),
			TightBeamError::SpkiError(e) => HandshakeError::SpkiError(e),
			TightBeamError::CertificateValidationError(e) => HandshakeError::CertificateValidationError(e),
			TightBeamError::KeyError(e) => HandshakeError::KeyError(e),
			TightBeamError::SignatureError(e) => HandshakeError::SignatureError(e),
			#[cfg(feature = "hpke")]
			TightBeamError::HpkeError(e) => HandshakeError::HpkeError(e),
			TightBeamError::OsRngError(_) => HandshakeError::RandomGenerationFailed,
			_ => HandshakeError::InvalidState,
		}
	}
}

/// Narrows [`HandshakeError`] into the foreign [`crate::cms::builder::Error`].
///
/// A variant without a counterpart collapses into
/// [`Builder`](crate::cms::builder::Error::Builder) through its `Display`.
impl From<HandshakeError> for crate::cms::builder::Error {
	fn from(err: HandshakeError) -> Self {
		match err {
			HandshakeError::CmsBuilderError(e) => e,
			HandshakeError::DerError(e) => crate::cms::builder::Error::Asn1(e),
			HandshakeError::SpkiError(e) => crate::cms::builder::Error::PublicKey(e),
			other => crate::cms::builder::Error::Builder(other.to_string()),
		}
	}
}

#[cfg(all(
	test,
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
mod tests {
	use super::*;

	#[test]
	fn a_missing_client_certificate_is_a_certificate_rejection() {
		let event = HandshakeError::MissingClientCertificate.audit_event();
		assert_eq!(event, Some(events::SESSION_CERT_REJECTED));
	}

	/// A sealed identity that fails to open names no certificate the server
	/// could check, so it records the refusal of an unproven identity.
	#[test]
	fn a_sealed_identity_that_fails_to_open_is_a_certificate_rejection() {
		let event = HandshakeError::SealedIdentity.audit_event();
		assert_eq!(event, Some(events::SESSION_CERT_REJECTED));
	}

	#[test]
	fn a_refused_approval_is_a_receipt_refusal() {
		let event = HandshakeError::ApprovalRefused { code: 7 }.audit_event();
		assert_eq!(event, Some(events::SESSION_RECEIPT_REFUSED));
	}

	#[test]
	fn a_state_error_records_no_audit_event() {
		assert_eq!(HandshakeError::InvalidState.audit_event(), None);
	}
}
