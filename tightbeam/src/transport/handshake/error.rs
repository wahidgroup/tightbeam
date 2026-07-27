#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;

use crate::Errorizable;

pub type Result<T> = core::result::Result<T, HandshakeError>;

/// Errors specific to handshake operations
#[derive(Debug, Errorizable)]
pub enum HandshakeError {
	// ---------------- Protocol & structure specific ----------------
	// Invariant violations (non-panicking)
	#[error("Handshake invariant violation: transcript already locked")]
	TranscriptAlreadyLocked,
	#[error("Handshake invariant violation: transcript not locked")]
	TranscriptNotLocked,
	#[error("Handshake invariant violation: AEAD key already derived")]
	AeadAlreadyDerived,
	#[error("Handshake invariant violation: Finished already sent")]
	FinishedAlreadySent,
	#[error("Handshake invariant violation: Finished before transcript lock")]
	FinishedBeforeTranscriptLock,
	/// Invalid client key exchange message
	#[error("Invalid client key exchange message")]
	InvalidClientKeyExchange,

	/// Invalid server key exchange message
	#[error("Invalid server key exchange message")]
	InvalidServerKeyExchange,

	/// Invalid public key in handshake
	#[error("Invalid public key in handshake: {0}")]
	#[from]
	InvalidPublicKey(crate::crypto::sign::ecdsa::k256::elliptic_curve::Error),

	/// Invalid certificate
	#[error("Invalid certificate: {0}")]
	#[from]
	CertificateValidationError(crate::crypto::x509::error::CertificateValidationError),

	/// Signature verification failed
	#[error("Handshake signature verification failed")]
	SignatureVerificationFailed,

	/// Signature error (parsing or verification)
	#[error("Signature error: {0}")]
	#[from]
	SignatureError(crate::crypto::sign::Error),

	/// Key derivation failed
	#[error("Handshake key derivation failed: {0}")]
	#[from]
	KeyDerivationFailed(crate::crypto::aead::Error),

	/// Underlying DER encode/decode error
	#[error("DER error: {0}")]
	#[from]
	DerError(crate::der::Error),

	/// SPKI (SubjectPublicKeyInfo) error
	#[error("SPKI error: {0}")]
	#[from]
	SpkiError(crate::spki::Error),

	/// Key provider error
	#[error("Key provider error: {0}")]
	#[from]
	KeyError(crate::crypto::key::KeyError),

	/// CMS builder error
	#[error("CMS builder error: {0}")]
	#[from]
	CmsBuilderError(crate::cms::builder::Error),

	/// Invalid handshake state
	#[error("Invalid handshake state")]
	InvalidState,

	/// Missing server key
	#[error("Missing server key")]
	MissingServerKey,

	/// No trust store / certificate validator configured
	#[error("Trust store required: refusing expiry-only peer certificate validation")]
	MissingTrustStore,

	/// Missing server certificate
	#[error("Missing server certificate")]
	MissingServerCertificate,

	/// Missing client certificate
	#[error("Missing client certificate")]
	MissingClientCertificate,

	/// Invalid transcript hash length or format
	#[error("Invalid transcript hash")]
	InvalidTranscriptHash,

	/// Digest output width does not match the required transcript hash width
	#[error("Transcript digest length invalid: expected {expected} bytes, got {received}")]
	TranscriptDigestLength { expected: usize, received: usize },

	/// Server requires mutual authentication but client has no identity configured
	#[error("Server requires mutual authentication but client has no identity")]
	MutualAuthRequired,

	/// Budget-bearing session requires a session receipt but none arrived
	#[error("Session receipt required for budget-bearing session but missing")]
	ReceiptMissing,

	/// Session receipt disagrees with the negotiated session parameters
	#[error("Session receipt does not match the negotiated session")]
	ReceiptMismatch,

	/// Client countersignature required for budget-bearing session but missing
	#[error("Receipt countersignature required for budget-bearing session but missing")]
	CountersignatureMissing,

	/// Client's receipt approver refused the session receipt
	#[error("Session receipt refused by approver: code {code}")]
	ApprovalRefused { code: u32 },

	/// Server's authorizer rejected the settlement answer
	#[error("Settlement rejected: code {code}")]
	SettlementRejected { code: u32 },

	/// The approver's settlement answer exceeds the wire length prefix
	#[error("Settlement answer too large for the wire encoding")]
	AnswerTooLarge,

	/// Peer identity mismatch during re-handshake (immutable identity violation)
	#[error("Peer identity changed during re-handshake - connection identity is immutable")]
	PeerIdentityMismatch,

	/// Provisioned certificate chain leaf does not match the pinned server certificate
	#[error("Provisioned certificate chain leaf does not match pinned server certificate")]
	PinnedCertificateMismatch,

	/// Missing client random
	#[error("Missing client random from ClientHello")]
	MissingClientRandom,

	/// Missing base session key
	#[error("Missing base session key")]
	MissingBaseSessionKey,

	/// Missing client random
	#[error("Missing client random")]
	MissingClientRandomState,

	/// Missing server random
	#[error("Missing server random")]
	MissingServerRandom,

	/// CMS salt (transcript hash) below minimum entropy requirement
	#[error("CMS salt too short: {actual} bytes (minimum {minimum} required)")]
	InsufficientSaltEntropy { actual: usize, minimum: usize },

	/// Peer sent abort alert during handshake
	#[error("Handshake aborted by peer: {0:?}")]
	AbortReceived(crate::transport::handshake::HandshakeAlert),

	/// Handshake timeout
	#[error("Handshake timeout")]
	Timeout,

	/// Invalid profile selection - server selected profile not in client's offer
	#[error("Server selected profile not in client's offer")]
	InvalidProfileSelection,

	/// Negotiation error
	#[error("Profile negotiation failed: {0}")]
	#[from]
	NegotiationError(crate::transport::handshake::negotiation::NegotiationError),

	/// No mutually supported profiles found during negotiation
	#[error("No mutually supported cryptographic profiles found")]
	NoMutualProfiles,

	/// Dealer's choice failed - no supported profiles configured
	#[error("Dealer's choice failed: no supported profiles configured")]
	NoSupportedProfiles,

	/// Profile negotiation required but no profiles configured
	#[error("Profile negotiation required but no profiles configured on server")]
	NegotiationRequired,

	/// Certificate policy rejection
	#[error("Certificate rejected by policy: {0}")]
	#[from]
	CertificatePolicyError(crate::crypto::policy::CryptoPolicyError),

	// ---------------- Attribute / ASN.1 profile errors ----------------
	#[error("Attribute must contain exactly one value")]
	InvalidAttributeArity,
	#[error("Duplicate attribute present")]
	DuplicateAttribute,
	#[error("Required attribute missing")]
	MissingAttribute,
	#[error("Too many supported curves: {count} exceeds cap of {max}")]
	TooManySupportedCurves { count: usize, max: usize },
	#[error("Nonce value not valid OCTET STRING")]
	InvalidNonceEncoding,
	#[error("Nonce length mismatch: {0}")]
	NonceLengthError(crate::error::ReceivedExpectedError<usize, usize>),
	#[error("OCTET STRING length mismatch: {0}")]
	OctetStringLengthError(crate::error::ReceivedExpectedError<usize, usize>),
	#[error("Version/alert value not valid INTEGER")]
	InvalidIntegerEncoding,
	#[error("INTEGER out of range")]
	IntegerOutOfRange,
	#[error("Unknown alert code: {0:?}")]
	UnknownAlertCode(u8),

	// ---------------- Certificate time validation ----------------
	#[error("Certificate not yet valid")]
	CertificateNotYetValid,
	#[error("Certificate expired")]
	CertificateExpired,
	#[error("Invalid timestamp")]
	InvalidTimestamp,

	// ---------------- ECIES / encryption path ----------------
	#[cfg(feature = "ecies")]
	#[error("ECIES operation failed: {0}")]
	#[from]
	EciesError(crate::crypto::ecies::EciesError),
	#[error("Missing encrypted content in ECIES message")]
	MissingEncryptedContent,
	#[error("Invalid decrypted payload size")]
	InvalidDecryptedPayloadSize,
	#[error("client_random mismatch - possible replay attack")]
	ClientRandomMismatchReplay,

	// ---------------- Key agreement / CMS KARI ----------------
	#[error("ECDH operation failed")]
	EcdhFailed,
	#[error("KDF operation failed: {0}")]
	#[from]
	KdfError(crate::crypto::kdf::KdfError),
	#[error("Invalid key size: expected {expected}, got {received}")]
	InvalidKeySize { expected: usize, received: usize },
	#[error("Ciphertext too short: {received} bytes (minimum {minimum} required)")]
	CiphertextTooShort { minimum: usize, received: usize },
	#[error("ASN.1 encoding error: {0}")]
	Asn1Error(der::Error),
	#[error("Invalid recipient index")]
	InvalidRecipientIndex,
	#[error("Missing UKM in KeyAgreeRecipientInfo")]
	MissingUkm,
	#[error("Failed to parse originator public key")]
	InvalidOriginatorPublicKey,
	#[error("Unsupported originator identifier type")]
	UnsupportedOriginatorIdentifier,
	#[error("KARI builder already consumed")]
	KariBuilderConsumed,
	#[error("Content encryption algorithm not set")]
	MissingContentEncryptionAlgorithm,
	#[error("Key wrap algorithm not configured in security profile")]
	MissingKeyWrapAlgorithm,
	#[error("Negotiated key wrap algorithm unsupported (expected AES-128/192/256 key wrap)")]
	UnsupportedKeyWrapAlgorithm,
	#[error("Negotiated AEAD algorithm unsupported (expected AES-128/256 GCM)")]
	UnsupportedAeadAlgorithm,
	#[error("Peer aead_key_size {declared} does not match negotiated AEAD key size {expected}")]
	AeadKeySizeMismatch { declared: usize, expected: usize },
	#[cfg(all(feature = "builder", feature = "aead"))]
	#[error("AES key wrap operation failed: {0}")]
	#[from]
	AesKeyWrap(crate::crypto::aead::aes_kw::Error),

	#[cfg(feature = "kem")]
	#[error("Hybrid key agreement integrity check failed: combined ECDH+KEM key validation error")]
	HybridKariIntegrityCheckFailed,

	// ---------------- Random generation ----------------
	#[error("Random generation failed")]
	RandomGenerationFailed,

	/// Secret material was unavailable
	#[error("Secret unavailable: {0}")]
	#[from]
	SecretUnavailable(crate::crypto::secret::SecretError),

	/// Cryptographic key or nonce material had the wrong length
	#[error("Invalid key material length: {0}")]
	#[from]
	InvalidKeyMaterialLength(crypto_common::InvalidLength),
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
