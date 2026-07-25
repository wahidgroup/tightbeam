#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;

#[cfg(feature = "derive")]
use crate::Errorizable;

pub type Result<T> = core::result::Result<T, HandshakeError>;

/// Errors specific to handshake operations
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum HandshakeError {
	// ---------------- Protocol & structure specific ----------------
	// Invariant violations (non-panicking)
	#[cfg_attr(
		feature = "derive",
		error("Handshake invariant violation: transcript already locked")
	)]
	TranscriptAlreadyLocked,
	#[cfg_attr(
		feature = "derive",
		error("Handshake invariant violation: transcript not locked")
	)]
	TranscriptNotLocked,
	#[cfg_attr(
		feature = "derive",
		error("Handshake invariant violation: AEAD key already derived")
	)]
	AeadAlreadyDerived,
	#[cfg_attr(
		feature = "derive",
		error("Handshake invariant violation: Finished already sent")
	)]
	FinishedAlreadySent,
	#[cfg_attr(
		feature = "derive",
		error("Handshake invariant violation: Finished before transcript lock")
	)]
	FinishedBeforeTranscriptLock,
	/// Invalid client key exchange message
	#[cfg_attr(feature = "derive", error("Invalid client key exchange message"))]
	InvalidClientKeyExchange,

	/// Invalid server key exchange message
	#[cfg_attr(feature = "derive", error("Invalid server key exchange message"))]
	InvalidServerKeyExchange,

	/// Invalid public key in handshake
	#[cfg_attr(feature = "derive", error("Invalid public key in handshake: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	InvalidPublicKey(crate::crypto::sign::ecdsa::k256::elliptic_curve::Error),

	/// Invalid certificate
	#[cfg_attr(feature = "derive", error("Invalid certificate: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	CertificateValidationError(crate::crypto::x509::error::CertificateValidationError),

	/// Signature verification failed
	#[cfg_attr(feature = "derive", error("Handshake signature verification failed"))]
	SignatureVerificationFailed,

	/// Signature error (parsing or verification)
	#[cfg_attr(feature = "derive", error("Signature error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	SignatureError(crate::crypto::sign::Error),

	/// Key derivation failed
	#[cfg_attr(feature = "derive", error("Handshake key derivation failed: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	KeyDerivationFailed(crate::crypto::aead::Error),

	/// Underlying DER encode/decode error
	#[cfg_attr(feature = "derive", error("DER error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	DerError(crate::der::Error),

	/// SPKI (SubjectPublicKeyInfo) error
	#[cfg_attr(feature = "derive", error("SPKI error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	SpkiError(crate::spki::Error),

	/// Key provider error
	#[cfg_attr(feature = "derive", error("Key provider error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	KeyError(crate::crypto::key::KeyError),

	/// CMS builder error
	#[cfg_attr(feature = "derive", error("CMS builder error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	CmsBuilderError(crate::cms::builder::Error),

	/// Invalid handshake state
	#[cfg_attr(feature = "derive", error("Invalid handshake state"))]
	InvalidState,

	/// Missing server key
	#[cfg_attr(feature = "derive", error("Missing server key"))]
	MissingServerKey,

	/// No trust store / certificate validator configured
	#[cfg_attr(
		feature = "derive",
		error("Trust store required: refusing expiry-only peer certificate validation")
	)]
	MissingTrustStore,

	/// Missing server certificate
	#[cfg_attr(feature = "derive", error("Missing server certificate"))]
	MissingServerCertificate,

	/// Missing client certificate
	#[cfg_attr(feature = "derive", error("Missing client certificate"))]
	MissingClientCertificate,

	/// Invalid transcript hash length or format
	#[cfg_attr(feature = "derive", error("Invalid transcript hash"))]
	InvalidTranscriptHash,

	/// Digest output width does not match the required transcript hash width
	#[cfg_attr(
		feature = "derive",
		error("Transcript digest length invalid: expected {expected} bytes, got {received}")
	)]
	TranscriptDigestLength { expected: usize, received: usize },

	/// Server requires mutual authentication but client has no identity configured
	#[cfg_attr(
		feature = "derive",
		error("Server requires mutual authentication but client has no identity")
	)]
	MutualAuthRequired,

	/// Budget-bearing session requires a session receipt but none arrived
	#[cfg_attr(
		feature = "derive",
		error("Session receipt required for budget-bearing session but missing")
	)]
	ReceiptMissing,

	/// Session receipt disagrees with the negotiated session parameters
	#[cfg_attr(
		feature = "derive",
		error("Session receipt does not match the negotiated session")
	)]
	ReceiptMismatch,

	/// Client countersignature required for budget-bearing session but missing
	#[cfg_attr(
		feature = "derive",
		error("Receipt countersignature required for budget-bearing session but missing")
	)]
	CountersignatureMissing,

	/// Client's receipt approver refused the session receipt
	#[cfg_attr(feature = "derive", error("Session receipt refused by approver: code {code}"))]
	ApprovalRefused { code: u32 },

	/// Server's authorizer rejected the settlement answer
	#[cfg_attr(feature = "derive", error("Settlement rejected: code {code}"))]
	SettlementRejected { code: u32 },

	/// The approver's settlement answer exceeds the wire length prefix
	#[cfg_attr(feature = "derive", error("Settlement answer too large for the wire encoding"))]
	AnswerTooLarge,

	/// Peer identity mismatch during re-handshake (immutable identity violation)
	#[cfg_attr(
		feature = "derive",
		error("Peer identity changed during re-handshake - connection identity is immutable")
	)]
	PeerIdentityMismatch,

	/// Provisioned certificate chain leaf does not match the pinned server certificate
	#[cfg_attr(
		feature = "derive",
		error("Provisioned certificate chain leaf does not match pinned server certificate")
	)]
	PinnedCertificateMismatch,

	/// Missing client random
	#[cfg_attr(feature = "derive", error("Missing client random from ClientHello"))]
	MissingClientRandom,

	/// Missing base session key
	#[cfg_attr(feature = "derive", error("Missing base session key"))]
	MissingBaseSessionKey,

	/// Missing client random
	#[cfg_attr(feature = "derive", error("Missing client random"))]
	MissingClientRandomState,

	/// Missing server random
	#[cfg_attr(feature = "derive", error("Missing server random"))]
	MissingServerRandom,

	/// CMS salt (transcript hash) below minimum entropy requirement
	#[cfg_attr(
		feature = "derive",
		error("CMS salt too short: {actual} bytes (minimum {minimum} required)")
	)]
	InsufficientSaltEntropy { actual: usize, minimum: usize },

	/// Peer sent abort alert during handshake
	#[cfg_attr(feature = "derive", error("Handshake aborted by peer: {0:?}"))]
	AbortReceived(crate::transport::handshake::HandshakeAlert),

	/// Handshake timeout
	#[cfg_attr(feature = "derive", error("Handshake timeout"))]
	Timeout,

	/// Invalid profile selection - server selected profile not in client's offer
	#[cfg_attr(feature = "derive", error("Server selected profile not in client's offer"))]
	InvalidProfileSelection,

	/// Negotiation error
	#[cfg_attr(feature = "derive", error("Profile negotiation failed: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	NegotiationError(crate::transport::handshake::negotiation::NegotiationError),

	/// No mutually supported profiles found during negotiation
	#[cfg_attr(feature = "derive", error("No mutually supported cryptographic profiles found"))]
	NoMutualProfiles,

	/// Dealer's choice failed - no supported profiles configured
	#[cfg_attr(
		feature = "derive",
		error("Dealer's choice failed: no supported profiles configured")
	)]
	NoSupportedProfiles,

	/// Profile negotiation required but no profiles configured
	#[cfg_attr(
		feature = "derive",
		error("Profile negotiation required but no profiles configured on server")
	)]
	NegotiationRequired,

	/// Certificate policy rejection
	#[cfg_attr(feature = "derive", error("Certificate rejected by policy: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	CertificatePolicyError(crate::crypto::policy::CryptoPolicyError),

	// ---------------- Attribute / ASN.1 profile errors ----------------
	#[cfg_attr(feature = "derive", error("Attribute must contain exactly one value"))]
	InvalidAttributeArity,
	#[cfg_attr(feature = "derive", error("Duplicate attribute present"))]
	DuplicateAttribute,
	#[cfg_attr(feature = "derive", error("Required attribute missing"))]
	MissingAttribute,
	#[cfg_attr(
		feature = "derive",
		error("Too many supported curves: {count} exceeds cap of {max}")
	)]
	TooManySupportedCurves { count: usize, max: usize },
	#[cfg_attr(feature = "derive", error("Nonce value not valid OCTET STRING"))]
	InvalidNonceEncoding,
	#[cfg_attr(feature = "derive", error("Nonce length mismatch: {0}"))]
	NonceLengthError(crate::error::ReceivedExpectedError<usize, usize>),
	#[cfg_attr(feature = "derive", error("OCTET STRING length mismatch: {0}"))]
	OctetStringLengthError(crate::error::ReceivedExpectedError<usize, usize>),
	#[cfg_attr(feature = "derive", error("Version/alert value not valid INTEGER"))]
	InvalidIntegerEncoding,
	#[cfg_attr(feature = "derive", error("INTEGER out of range"))]
	IntegerOutOfRange,
	#[cfg_attr(feature = "derive", error("Unknown alert code: {0:?}"))]
	UnknownAlertCode(u8),

	// ---------------- Certificate time validation ----------------
	#[cfg_attr(feature = "derive", error("Certificate not yet valid"))]
	CertificateNotYetValid,
	#[cfg_attr(feature = "derive", error("Certificate expired"))]
	CertificateExpired,
	#[cfg_attr(feature = "derive", error("Invalid timestamp"))]
	InvalidTimestamp,

	// ---------------- ECIES / encryption path ----------------
	#[cfg(feature = "ecies")]
	#[cfg_attr(feature = "derive", error("ECIES operation failed: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	EciesError(crate::crypto::ecies::EciesError),
	#[cfg_attr(feature = "derive", error("Missing encrypted content in ECIES message"))]
	MissingEncryptedContent,
	#[cfg_attr(feature = "derive", error("Invalid decrypted payload size"))]
	InvalidDecryptedPayloadSize,
	#[cfg_attr(feature = "derive", error("client_random mismatch - possible replay attack"))]
	ClientRandomMismatchReplay,

	// ---------------- Key agreement / CMS KARI ----------------
	#[cfg_attr(feature = "derive", error("ECDH operation failed"))]
	EcdhFailed,
	#[cfg_attr(feature = "derive", error("KDF operation failed"))]
	KdfError,
	#[cfg_attr(
		feature = "derive",
		error("Invalid key size: expected {expected}, got {received}")
	)]
	InvalidKeySize { expected: usize, received: usize },
	#[cfg_attr(
		feature = "derive",
		error("Ciphertext too short: {received} bytes (minimum {minimum} required)")
	)]
	CiphertextTooShort { minimum: usize, received: usize },
	#[cfg_attr(feature = "derive", error("ASN.1 encoding error: {0}"))]
	Asn1Error(der::Error),
	#[cfg_attr(feature = "derive", error("Invalid recipient index"))]
	InvalidRecipientIndex,
	#[cfg_attr(feature = "derive", error("Missing UKM in KeyAgreeRecipientInfo"))]
	MissingUkm,
	#[cfg_attr(feature = "derive", error("Failed to parse originator public key"))]
	InvalidOriginatorPublicKey,
	#[cfg_attr(feature = "derive", error("Unsupported originator identifier type"))]
	UnsupportedOriginatorIdentifier,
	#[cfg_attr(feature = "derive", error("KARI builder already consumed"))]
	KariBuilderConsumed,
	#[cfg_attr(feature = "derive", error("Content encryption algorithm not set"))]
	MissingContentEncryptionAlgorithm,
	#[cfg_attr(
		feature = "derive",
		error("Key wrap algorithm not configured in security profile")
	)]
	MissingKeyWrapAlgorithm,
	#[cfg_attr(
		feature = "derive",
		error("Negotiated key wrap algorithm unsupported (expected AES-128/192/256 key wrap)")
	)]
	UnsupportedKeyWrapAlgorithm,
	#[cfg_attr(
		feature = "derive",
		error("Negotiated AEAD algorithm unsupported (expected AES-128/256 GCM)")
	)]
	UnsupportedAeadAlgorithm,
	#[cfg_attr(
		feature = "derive",
		error("Peer aead_key_size {declared} does not match negotiated AEAD key size {expected}")
	)]
	AeadKeySizeMismatch { declared: usize, expected: usize },
	#[cfg(all(feature = "builder", feature = "aead"))]
	#[cfg_attr(feature = "derive", error("AES key wrap operation failed: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	AesKeyWrap(crate::crypto::aead::aes_kw::Error),

	#[cfg(feature = "kem")]
	#[cfg_attr(
		feature = "derive",
		error("Hybrid key agreement integrity check failed: combined ECDH+KEM key validation error")
	)]
	HybridKariIntegrityCheckFailed,

	// ---------------- Random generation ----------------
	#[cfg_attr(feature = "derive", error("Random generation failed"))]
	RandomGenerationFailed,

	/// Secret material was unavailable
	#[cfg_attr(feature = "derive", error("Secret unavailable: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	SecretUnavailable(crate::crypto::secret::SecretError),

	// ---------------- Generic octet string length (server_random/client_random etc.) ----------------
	#[cfg_attr(feature = "derive", error("Invalid OCTET STRING length: {0}"))]
	InvalidOctetStringLength(&'static str),
}

// Mirrors the `#[error(...)]` strings above. Compiled only without `derive`.
crate::impl_error_display!(HandshakeError {
	TranscriptAlreadyLocked => "Handshake invariant violation: transcript already locked",
	TranscriptNotLocked => "Handshake invariant violation: transcript not locked",
	AeadAlreadyDerived => "Handshake invariant violation: AEAD key already derived",
	FinishedAlreadySent => "Handshake invariant violation: Finished already sent",
	FinishedBeforeTranscriptLock => "Handshake invariant violation: Finished before transcript lock",
	InvalidClientKeyExchange => "Invalid client key exchange message",
	InvalidServerKeyExchange => "Invalid server key exchange message",
	InvalidPublicKey(e) => "Invalid public key in handshake: {e}",
	CertificateValidationError(e) => "Invalid certificate: {e}",
	SignatureVerificationFailed => "Handshake signature verification failed",
	SignatureError(e) => "Signature error: {e}",
	KeyDerivationFailed(e) => "Handshake key derivation failed: {e}",
	DerError(e) => "DER error: {e}",
	SpkiError(e) => "SPKI error: {e}",
	KeyError(e) => "Key provider error: {e}",
	CmsBuilderError(e) => "CMS builder error: {e}",
	InvalidState => "Invalid handshake state",
	MissingServerKey => "Missing server key",
	MissingTrustStore => "Trust store required: refusing expiry-only peer certificate validation",
	MissingServerCertificate => "Missing server certificate",
	MissingClientCertificate => "Missing client certificate",
	InvalidTranscriptHash => "Invalid transcript hash",
	TranscriptDigestLength { expected, received } => "Transcript digest length invalid: expected {expected} bytes, got {received}",
	MutualAuthRequired => "Server requires mutual authentication but client has no identity",
	ReceiptMissing => "Session receipt required for budget-bearing session but missing",
	ReceiptMismatch => "Session receipt does not match the negotiated session",
	CountersignatureMissing => "Receipt countersignature required for budget-bearing session but missing",
	ApprovalRefused { code } => "Session receipt refused by approver: code {code}",
	SettlementRejected { code } => "Settlement rejected: code {code}",
	AnswerTooLarge => "Settlement answer too large for the wire encoding",
	PeerIdentityMismatch => "Peer identity changed during re-handshake - connection identity is immutable",
	PinnedCertificateMismatch => "Provisioned certificate chain leaf does not match pinned server certificate",
	MissingClientRandom => "Missing client random from ClientHello",
	MissingBaseSessionKey => "Missing base session key",
	MissingClientRandomState => "Missing client random",
	MissingServerRandom => "Missing server random",
	InsufficientSaltEntropy { actual, minimum } => "CMS salt too short: {actual} bytes (minimum {minimum} required)",
	AbortReceived(alert) => "Handshake aborted by peer: {alert:?}",
	Timeout => "Handshake timeout",
	InvalidProfileSelection => "Server selected profile not in client's offer",
	NegotiationError(e) => "Profile negotiation failed: {e}",
	NoMutualProfiles => "No mutually supported cryptographic profiles found",
	NoSupportedProfiles => "Dealer's choice failed: no supported profiles configured",
	NegotiationRequired => "Profile negotiation required but no profiles configured on server",
	CertificatePolicyError(e) => "Certificate rejected by policy: {e}",
	InvalidAttributeArity => "Attribute must contain exactly one value",
	DuplicateAttribute => "Duplicate attribute present",
	MissingAttribute => "Required attribute missing",
	TooManySupportedCurves { count, max } => "Too many supported curves: {count} exceeds cap of {max}",
	InvalidNonceEncoding => "Nonce value not valid OCTET STRING",
	NonceLengthError(e) => "Nonce length mismatch: {e}",
	OctetStringLengthError(e) => "OCTET STRING length mismatch: {e}",
	InvalidIntegerEncoding => "Version/alert value not valid INTEGER",
	IntegerOutOfRange => "INTEGER out of range",
	UnknownAlertCode(code) => "Unknown alert code: {code:?}",
	CertificateNotYetValid => "Certificate not yet valid",
	CertificateExpired => "Certificate expired",
	InvalidTimestamp => "Invalid timestamp",
	MissingEncryptedContent => "Missing encrypted content in ECIES message",
	InvalidDecryptedPayloadSize => "Invalid decrypted payload size",
	ClientRandomMismatchReplay => "client_random mismatch - possible replay attack",
	EcdhFailed => "ECDH operation failed",
	KdfError => "KDF operation failed",
	InvalidKeySize { expected, received } => "Invalid key size: expected {expected}, got {received}",
	CiphertextTooShort { minimum, received } => "Ciphertext too short: {received} bytes (minimum {minimum} required)",
	Asn1Error(e) => "ASN.1 encoding error: {e}",
	InvalidRecipientIndex => "Invalid recipient index",
	MissingUkm => "Missing UKM in KeyAgreeRecipientInfo",
	InvalidOriginatorPublicKey => "Failed to parse originator public key",
	UnsupportedOriginatorIdentifier => "Unsupported originator identifier type",
	KariBuilderConsumed => "KARI builder already consumed",
	MissingContentEncryptionAlgorithm => "Content encryption algorithm not set",
	MissingKeyWrapAlgorithm => "Key wrap algorithm not configured in security profile",
	UnsupportedKeyWrapAlgorithm => "Negotiated key wrap algorithm unsupported (expected AES-128/192/256 key wrap)",
	UnsupportedAeadAlgorithm => "Negotiated AEAD algorithm unsupported (expected AES-128/256 GCM)",
	AeadKeySizeMismatch { declared, expected } => "Peer aead_key_size {declared} does not match negotiated AEAD key size {expected}",
	RandomGenerationFailed => "Random generation failed",
	SecretUnavailable(e) => "Secret unavailable: {e}",
	InvalidOctetStringLength(m) => "Invalid OCTET STRING length: {m}",

	#[cfg(feature = "ecies")]
	EciesError(e) => "ECIES operation failed: {e}",
	#[cfg(all(feature = "builder", feature = "aead"))]
	AesKeyWrap(e) => "AES key wrap operation failed: {e}",
	#[cfg(feature = "kem")]
	HybridKariIntegrityCheckFailed => "Hybrid key agreement integrity check failed: combined ECDH+KEM key validation error",
});

impl From<crate::crypto::kdf::KdfError> for HandshakeError {
	fn from(_: crate::crypto::kdf::KdfError) -> Self {
		HandshakeError::KeyDerivationFailed(crate::crypto::aead::Error)
	}
}

/// Narrows [`TightBeamError`](crate::error::TightBeamError) into [`HandshakeError`];
/// variants without a handshake counterpart collapse to [`HandshakeError::InvalidState`].
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
			TightBeamError::CryptoPolicyError(e) => HandshakeError::CertificatePolicyError(e),
			#[cfg(feature = "crypto")]
			TightBeamError::KeyError(e) => HandshakeError::KeyError(e),
			#[cfg(feature = "signature")]
			TightBeamError::SignatureError(e) => HandshakeError::SignatureError(e),
			#[cfg(feature = "ecies")]
			TightBeamError::EciesError(e) => HandshakeError::EciesError(e),
			#[cfg(feature = "crypto")]
			TightBeamError::SecretUnavailable(e) => HandshakeError::SecretUnavailable(e),
			#[cfg(feature = "random")]
			TightBeamError::OsRngError(_) => HandshakeError::RandomGenerationFailed,
			_ => HandshakeError::InvalidState,
		}
	}
}

#[cfg(all(feature = "crypto", not(feature = "derive")))]
impl From<crate::crypto::secret::SecretError> for HandshakeError {
	fn from(err: crate::crypto::secret::SecretError) -> Self {
		HandshakeError::SecretUnavailable(err)
	}
}

/// Narrows [`HandshakeError`] into the foreign [`crate::cms::builder::Error`];
/// variants without a counterpart collapse into
/// [`Builder`](crate::cms::builder::Error::Builder) via their `Display`.
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

impl From<crypto_common::InvalidLength> for HandshakeError {
	fn from(_: crypto_common::InvalidLength) -> Self {
		HandshakeError::KeyDerivationFailed(crate::crypto::aead::Error)
	}
}

#[cfg(not(feature = "derive"))]
impl From<crate::crypto::key::KeyError> for HandshakeError {
	fn from(e: crate::crypto::key::KeyError) -> Self {
		HandshakeError::KeyError(e)
	}
}
