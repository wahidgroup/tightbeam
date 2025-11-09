#[cfg(feature = "derive")]
use crate::Errorizable;

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

	/// Key derivation failed
	#[cfg_attr(feature = "derive", error("Handshake key derivation failed: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	KeyDerivationFailed(crate::crypto::aead::Error),

	/// Underlying DER encode/decode error
	#[cfg_attr(feature = "derive", error("DER error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	DerError(crate::der::Error),

	/// ECDSA error
	#[cfg_attr(feature = "derive", error("ECDSA error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	EcdsaError(crate::crypto::sign::ecdsa::Error),

	/// SPKI (SubjectPublicKeyInfo) error
	#[cfg_attr(feature = "derive", error("SPKI error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	SpkiError(crate::spki::Error),

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

	/// Missing server certificate
	#[cfg_attr(feature = "derive", error("Missing server certificate"))]
	MissingServerCertificate,

	/// Missing client certificate
	#[cfg_attr(feature = "derive", error("Missing client certificate"))]
	MissingClientCertificate,

	/// Server requires mutual authentication but client has no identity configured
	#[cfg_attr(
		feature = "derive",
		error("Server requires mutual authentication but client has no identity")
	)]
	MutualAuthRequired,

	/// Peer identity mismatch during re-handshake (immutable identity violation)
	#[cfg_attr(
		feature = "derive",
		error("Peer identity changed during re-handshake - connection identity is immutable")
	)]
	PeerIdentityMismatch,

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
	NegotiationError(crate::crypto::negotiation::NegotiationError),

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
	#[cfg_attr(feature = "derive", error("Nonce value not valid OCTET STRING"))]
	InvalidNonceEncoding,
	#[cfg_attr(feature = "derive", error("Nonce length mismatch: {0}"))]
	NonceLengthError(crate::error::ExpectError<usize, usize>),
	#[cfg_attr(feature = "derive", error("OCTET STRING length mismatch: {0}"))]
	OctetStringLengthError(crate::error::ExpectError<usize, usize>),
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
	#[cfg(all(feature = "builder", feature = "aead"))]
	#[cfg_attr(feature = "derive", error("AES key wrap operation failed: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	AesKeyWrap(crate::crypto::aead::aes_kw::Error),

	// ---------------- Random generation ----------------
	#[cfg_attr(feature = "derive", error("Random generation failed"))]
	RandomGenerationFailed,

	// ---------------- Generic octet string length (server_random/client_random etc.) ----------------
	#[cfg_attr(feature = "derive", error("Invalid OCTET STRING length: {0}"))]
	InvalidOctetStringLength(&'static str),
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for HandshakeError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			HandshakeError::InvalidClientKeyExchange => write!(f, "Invalid client key exchange message"),
			HandshakeError::InvalidServerKeyExchange => write!(f, "Invalid server key exchange message"),
			HandshakeError::InvalidPublicKey(e) => write!(f, "Invalid public key in handshake: {}", e),
			HandshakeError::CertificateValidationError(e) => write!(f, "Invalid certificate: {}", e),
			HandshakeError::EcdsaError(e) => write!(f, "ECDSA error: {}", e),
			HandshakeError::SpkiError(e) => write!(f, "SPKI error: {}", e),
			HandshakeError::CmsBuilderError(e) => write!(f, "CMS builder error: {}", e),
			HandshakeError::SignatureVerificationFailed => write!(f, "Handshake signature verification failed"),
			HandshakeError::KeyDerivationFailed(e) => write!(f, "Handshake key derivation failed: {}", e),
			HandshakeError::InvalidState => write!(f, "Invalid handshake state"),
			HandshakeError::MissingServerKey => write!(f, "Missing server key"),
			HandshakeError::MissingServerCertificate => write!(f, "Missing server certificate"),
			HandshakeError::MissingClientRandom => write!(f, "Missing client random from ClientHello"),
			HandshakeError::MissingBaseSessionKey => write!(f, "Missing base session key"),
			HandshakeError::MissingClientRandomState => write!(f, "Missing client random"),
			HandshakeError::MissingServerRandom => write!(f, "Missing server random"),
			HandshakeError::InsufficientSaltEntropy { actual, minimum } => {
				write!(f, "CMS salt too short: {} bytes (minimum {} required)", actual, minimum)
			}
			HandshakeError::AbortReceived(alert) => write!(f, "Handshake aborted by peer: {:?}", alert),
			HandshakeError::Timeout => write!(f, "Handshake timeout"),
			HandshakeError::InvalidProfileSelection => write!(f, "Server selected profile not in client's offer"),
			HandshakeError::NegotiationError(e) => write!(f, "Profile negotiation failed: {}", e),
			HandshakeError::NoMutualProfiles => write!(f, "No mutually supported cryptographic profiles found"),
			HandshakeError::NoSupportedProfiles => {
				write!(f, "Dealer's choice failed: no supported profiles configured")
			}
			HandshakeError::NegotiationRequired => {
				write!(f, "Profile negotiation required but no profiles configured on server")
			}
			HandshakeError::CertificatePolicyError(e) => write!(f, "Certificate rejected by policy: {}", e),
			HandshakeError::DerError(e) => write!(f, "DER error: {}", e),
			HandshakeError::InvalidAttributeArity => write!(f, "Attribute must contain exactly one value"),
			HandshakeError::DuplicateAttribute => write!(f, "Duplicate attribute present"),
			HandshakeError::MissingAttribute => write!(f, "Required attribute missing"),
			HandshakeError::InvalidNonceEncoding => write!(f, "Nonce value not valid OCTET STRING"),
			HandshakeError::NonceLengthError(e) => write!(f, "Nonce length mismatch: {}", e),
			HandshakeError::OctetStringLengthError(e) => write!(f, "OCTET STRING length mismatch: {}", e),
			HandshakeError::InvalidIntegerEncoding => write!(f, "Version/alert value not valid INTEGER"),
			HandshakeError::IntegerOutOfRange => write!(f, "INTEGER out of range"),
			HandshakeError::UnknownAlertCode(code) => write!(f, "Unknown alert code: {code}"),
			HandshakeError::CertificateNotYetValid => write!(f, "Certificate not yet valid"),
			HandshakeError::CertificateExpired => write!(f, "Certificate expired"),
			HandshakeError::InvalidTimestamp => write!(f, "Invalid timestamp"),
			HandshakeError::EciesError(e) => write!(f, "ECIES operation failed: {}", e),
			HandshakeError::MissingEncryptedContent => write!(f, "Missing encrypted content in ECIES message"),
			HandshakeError::InvalidDecryptedPayloadSize => write!(f, "Invalid decrypted payload size"),
			HandshakeError::ClientRandomMismatchReplay => write!(f, "client_random mismatch - possible replay attack"),
			HandshakeError::EcdhFailed => write!(f, "ECDH operation failed"),
			HandshakeError::KdfError => write!(f, "KDF operation failed"),
			HandshakeError::InvalidKeySize { expected, received } => {
				write!(f, "Invalid key size: expected {}, got {}", expected, received)
			}
			HandshakeError::Asn1Error(e) => write!(f, "ASN.1 encoding error: {}", e),
			HandshakeError::InvalidRecipientIndex => write!(f, "Invalid recipient index"),
			HandshakeError::MissingUkm => write!(f, "Missing UKM in KeyAgreeRecipientInfo"),
			HandshakeError::InvalidOriginatorPublicKey => write!(f, "Failed to parse originator public key"),
			HandshakeError::UnsupportedOriginatorIdentifier => write!(f, "Unsupported originator identifier type"),
			HandshakeError::KariBuilderConsumed => write!(f, "KARI builder already consumed"),
			HandshakeError::MissingContentEncryptionAlgorithm => write!(f, "Content encryption algorithm not set"),
			#[cfg(all(feature = "builder", feature = "aead"))]
			HandshakeError::AesKeyWrap(e) => write!(f, "AES key wrap operation failed: {}", e),
			HandshakeError::RandomGenerationFailed => write!(f, "Random generation failed"),
			HandshakeError::InvalidOctetStringLength(m) => write!(f, "Invalid OCTET STRING length: {}", m),
			HandshakeError::NonceLengthError(e) => write!(f, "Nonce length mismatch: {}", e),
			HandshakeError::OctetStringLengthError(e) => write!(f, "OCTET STRING length mismatch: {}", e),
			HandshakeError::UnknownAlertCode(code) => write!(f, "Unknown alert code: {code}"),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for HandshakeError {}

// From implementations for common underlying errors
impl From<crate::TightBeamError> for HandshakeError {
	fn from(e: crate::TightBeamError) -> Self {
		match e {
			crate::TightBeamError::InvalidOverflowValue => HandshakeError::RandomGenerationFailed,
			_ => HandshakeError::RandomGenerationFailed,
		}
	}
}

impl From<crate::crypto::kdf::KdfError> for HandshakeError {
	fn from(_: crate::crypto::kdf::KdfError) -> Self {
		HandshakeError::KeyDerivationFailed(crate::crypto::aead::Error)
	}
}

impl From<crypto_common::InvalidLength> for HandshakeError {
	fn from(_: crypto_common::InvalidLength) -> Self {
		HandshakeError::KeyDerivationFailed(crate::crypto::aead::Error)
	}
}
