#[cfg(feature = "derive")]
use crate::Errorizable;

/// Errors specific to handshake operations
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum HandshakeError {
	/// Invalid client key exchange message
	#[cfg_attr(feature = "derive", error("Invalid client key exchange message"))]
	InvalidClientKeyExchange,

	/// Invalid server key exchange message
	#[cfg_attr(feature = "derive", error("Invalid server key exchange message"))]
	InvalidServerKeyExchange,

	/// Invalid public key in handshake
	#[cfg_attr(feature = "derive", error("Invalid public key in handshake: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	InvalidPublicKey(k256::elliptic_curve::Error),

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

	/// ECDSA error
	#[cfg_attr(feature = "derive", error("ECDSA error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	EcdsaError(crate::crypto::sign::ecdsa::Error),

	/// Invalid handshake state
	#[cfg_attr(feature = "derive", error("Invalid handshake state"))]
	InvalidState,

	/// Missing server key
	#[cfg_attr(feature = "derive", error("Missing server key"))]
	MissingServerKey,

	/// Missing server certificate
	#[cfg_attr(feature = "derive", error("Missing server certificate"))]
	MissingServerCertificate,

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

	/// Handshake timeout
	#[cfg_attr(feature = "derive", error("Handshake timeout"))]
	Timeout,

	/// Handshake protocol error
	#[cfg_attr(feature = "derive", error("Handshake protocol error: {0}"))]
	ProtocolError(String),
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
			HandshakeError::SignatureVerificationFailed => write!(f, "Handshake signature verification failed"),
			HandshakeError::KeyDerivationFailed(e) => write!(f, "Handshake key derivation failed: {}", e),
			HandshakeError::InvalidState => write!(f, "Invalid handshake state"),
			HandshakeError::MissingServerKey => write!(f, "Missing server key"),
			HandshakeError::MissingServerCertificate => write!(f, "Missing server certificate"),
			HandshakeError::MissingClientRandom => write!(f, "Missing client random from ClientHello"),
			HandshakeError::MissingBaseSessionKey => write!(f, "Missing base session key"),
			HandshakeError::MissingClientRandomState => write!(f, "Missing client random"),
			HandshakeError::MissingServerRandom => write!(f, "Missing server random"),
			HandshakeError::Timeout => write!(f, "Handshake timeout"),
			HandshakeError::ProtocolError(msg) => write!(f, "Handshake protocol error: {}", msg),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for HandshakeError {}

// From implementations for common underlying errors
impl From<crate::TightBeamError> for HandshakeError {
	fn from(e: crate::TightBeamError) -> Self {
		match e {
			crate::TightBeamError::InvalidOverflowValue => {
				HandshakeError::ProtocolError("Invalid random generation".into())
			}
			_ => HandshakeError::ProtocolError("Random generation failed".into()),
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
