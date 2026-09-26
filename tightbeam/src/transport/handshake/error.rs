#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;

use crate::Errorizable;

#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use crate::instrumentation::events;
#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use crate::utils::urn::Urn;

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

	/// The server key is missing.
	#[error("Missing server key")]
	MissingServerKey,

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

	/// The transcript hash has an invalid length or format.
	#[error("Invalid transcript hash")]
	InvalidTranscriptHash,

	/// The digest output width differs from the required transcript hash
	/// width.
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

	/// The client's receipt approver refused the session receipt.
	#[error("Session receipt refused by approver: code {code}")]
	ApprovalRefused { code: u32 },

	/// The server's authorizer rejected the settlement answer.
	#[error("Settlement rejected: code {code}")]
	SettlementRejected { code: u32 },

	/// The approver's settlement answer exceeds the length prefix of its
	/// encoding.
	#[error("Settlement answer too large for the wire encoding")]
	AnswerTooLarge,

	/// The leaf of the provisioned certificate chain differs from the pinned
	/// server certificate.
	#[error("Provisioned certificate chain leaf does not match pinned server certificate")]
	PinnedCertificateMismatch,

	/// The client random is missing from the ClientHello.
	#[error("Missing client random from ClientHello")]
	MissingClientRandom,

	/// The base session key is missing.
	#[error("Missing base session key")]
	MissingBaseSessionKey,

	/// The client random is missing from the handshake state.
	#[error("Missing client random")]
	MissingClientRandomState,

	/// The server random is missing.
	#[error("Missing server random")]
	MissingServerRandom,

	/// The CMS salt (the transcript hash) is below the minimum entropy
	/// requirement.
	#[error("CMS salt too short: {actual} bytes (minimum {minimum} required)")]
	InsufficientSaltEntropy { actual: usize, minimum: usize },

	/// The peer sent an abort alert during the handshake.
	#[error("Handshake aborted by peer: {0:?}")]
	AbortReceived(crate::transport::handshake::HandshakeAlert),

	/// The handshake timed out.
	#[error("Handshake timeout")]
	Timeout,

	/// The server selected a profile that the client did not offer.
	#[error("Server selected profile not in client's offer")]
	InvalidProfileSelection,

	/// Profile negotiation failed.
	#[error("Profile negotiation failed: {0}")]
	#[from]
	NegotiationError(crate::transport::handshake::negotiation::NegotiationError),

	/// Negotiation found no mutually supported profiles.
	#[error("No mutually supported cryptographic profiles found")]
	NoMutualProfiles,

	/// Dealer's choice failed because no supported profiles are configured.
	#[error("Dealer's choice failed: no supported profiles configured")]
	NoSupportedProfiles,

	/// Profile negotiation is required, and the server has no profiles
	/// configured.
	#[error("Profile negotiation required but no profiles configured on server")]
	NegotiationRequired,

	/// An attribute holds more or fewer than one value.
	#[error("Attribute must contain exactly one value")]
	InvalidAttributeArity,
	/// An attribute appears more than once.
	#[error("Duplicate attribute present")]
	DuplicateAttribute,
	/// A required attribute is missing.
	#[error("Required attribute missing")]
	MissingAttribute,
	/// The supported-curves list exceeds its cap.
	#[error("Too many supported curves: {count} exceeds cap of {max}")]
	TooManySupportedCurves { count: usize, max: usize },
	/// The nonce value is not a valid OCTET STRING.
	#[error("Nonce value not valid OCTET STRING")]
	InvalidNonceEncoding,
	/// The nonce has the wrong length.
	#[error("Nonce length mismatch: {0}")]
	NonceLengthError(crate::error::ReceivedExpectedError<usize, usize>),
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

	/// The certificate is not yet valid.
	#[error("Certificate not yet valid")]
	CertificateNotYetValid,
	/// The certificate has expired.
	#[error("Certificate expired")]
	CertificateExpired,
	/// A certificate timestamp is invalid.
	#[error("Invalid timestamp")]
	InvalidTimestamp,

	/// An ECIES operation failed.
	#[cfg(feature = "ecies")]
	#[error("ECIES operation failed: {0}")]
	#[from]
	EciesError(crate::crypto::ecies::EciesError),
	/// The ECIES message carries no encrypted content.
	#[error("Missing encrypted content in ECIES message")]
	MissingEncryptedContent,
	/// The decrypted ECIES payload has an invalid size.
	#[error("Invalid decrypted payload size")]
	InvalidDecryptedPayloadSize,
	/// The client random differs from the expected value, which indicates a
	/// possible replay attack.
	#[error("client_random mismatch - possible replay attack")]
	ClientRandomMismatchReplay,

	/// An ECDH operation failed during key agreement.
	#[error("ECDH operation failed")]
	EcdhFailed,
	/// A KDF operation failed.
	#[error("KDF operation failed: {0}")]
	#[from]
	KdfError(crate::crypto::kdf::KdfError),
	/// A key has an invalid size.
	#[error("Invalid key size: expected {expected}, got {received}")]
	InvalidKeySize { expected: usize, received: usize },
	/// A ciphertext is shorter than the minimum length.
	#[error("Ciphertext too short: {received} bytes (minimum {minimum} required)")]
	CiphertextTooShort { minimum: usize, received: usize },
	/// ASN.1 encoding failed during CMS key agreement (KARI).
	#[error("ASN.1 encoding error: {0}")]
	Asn1Error(der::Error),
	/// The recipient index is invalid.
	#[error("Invalid recipient index")]
	InvalidRecipientIndex,
	/// The KeyAgreeRecipientInfo carries no user keying material (UKM).
	#[error("Missing UKM in KeyAgreeRecipientInfo")]
	MissingUkm,
	/// The originator public key failed to parse.
	#[error("Failed to parse originator public key")]
	InvalidOriginatorPublicKey,
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
	/// An AES key wrap operation failed.
	#[cfg(all(feature = "builder", feature = "aead"))]
	#[error("AES key wrap operation failed: {0}")]
	#[from]
	AesKeyWrap(crate::crypto::aead::aes_kw::Error),

	/// Random generation failed.
	#[error("Random generation failed")]
	RandomGenerationFailed,

	/// Cryptographic key or nonce material had the wrong length.
	#[error("Invalid key material length: {0}")]
	#[from]
	InvalidKeyMaterialLength(crypto_common::InvalidLength),
}

#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
impl HandshakeError {
	/// Returns the audit event a failed handshake records for this error, when
	/// the error names one.
	///
	/// - A receipt approval or settlement refusal records
	///   [`SESSION_RECEIPT_REFUSED`](events::SESSION_RECEIPT_REFUSED).
	/// - A refused peer certificate or proof of possession, including a
	///   certificate the peer did not present, records
	///   [`SESSION_CERT_REJECTED`](events::SESSION_CERT_REJECTED).
	pub(crate) fn audit_event(&self) -> Option<Urn<'static>> {
		match self {
			Self::ApprovalRefused { .. } | Self::SettlementRejected { .. } => Some(events::SESSION_RECEIPT_REFUSED),
			Self::CertificateValidationError(_)
			| Self::SignatureVerificationFailed
			| Self::MissingClientCertificate
			| Self::PinnedCertificateMismatch
			| Self::CertificateNotYetValid
			| Self::CertificateExpired
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
			#[cfg(feature = "x509")]
			TightBeamError::SpkiError(e) => HandshakeError::SpkiError(e),
			#[cfg(feature = "x509")]
			TightBeamError::CertificateValidationError(e) => HandshakeError::CertificateValidationError(e),
			#[cfg(feature = "crypto")]
			TightBeamError::KeyError(e) => HandshakeError::KeyError(e),
			#[cfg(feature = "signature")]
			TightBeamError::SignatureError(e) => HandshakeError::SignatureError(e),
			#[cfg(feature = "ecies")]
			TightBeamError::EciesError(e) => HandshakeError::EciesError(e),
			#[cfg(feature = "random")]
			TightBeamError::OsRngError(_) => HandshakeError::RandomGenerationFailed,
			_ => HandshakeError::InvalidState,
		}
	}
}

/// Narrows [`HandshakeError`] into the foreign [`crate::cms::builder::Error`].
///
/// A variant without a counterpart collapses into
/// [`Builder`](crate::cms::builder::Error::Builder) through its `Display`.
#[cfg(all(feature = "builder", feature = "aead"))]
impl From<HandshakeError> for crate::cms::builder::Error {
	fn from(err: HandshakeError) -> Self {
		match err {
			HandshakeError::CmsBuilderError(e) => e,
			HandshakeError::DerError(e) => crate::cms::builder::Error::Asn1(e),
			HandshakeError::Asn1Error(e) => crate::cms::builder::Error::Asn1(e),
			HandshakeError::SpkiError(e) => crate::cms::builder::Error::PublicKey(e),
			other => crate::cms::builder::Error::Builder(other.to_string()),
		}
	}
}

#[cfg(all(
	test,
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
mod tests {
	use super::*;

	#[test]
	fn a_missing_client_certificate_is_a_certificate_rejection() {
		let event = HandshakeError::MissingClientCertificate.audit_event();
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
