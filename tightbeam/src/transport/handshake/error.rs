#[cfg(feature = "derive")]
use crate::Errorizable;

/// Errors specific to handshake operations
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone)]
pub enum HandshakeError {
	/// Invalid client key exchange message
	#[cfg_attr(feature = "derive", error("Invalid client key exchange message"))]
	InvalidClientKeyExchange,

	/// Invalid server key exchange message
	#[cfg_attr(feature = "derive", error("Invalid server key exchange message"))]
	InvalidServerKeyExchange,

	/// Invalid public key in handshake
	#[cfg_attr(feature = "derive", error("Invalid public key in handshake"))]
	InvalidPublicKey,

	/// Invalid certificate
	#[cfg_attr(feature = "derive", error("Invalid certificate"))]
	InvalidCertificate,

	/// Signature verification failed
	#[cfg_attr(feature = "derive", error("Handshake signature verification failed"))]
	SignatureVerificationFailed,

	/// Key derivation failed
	#[cfg_attr(feature = "derive", error("Handshake key derivation failed"))]
	KeyDerivationFailed,

	/// Invalid handshake state
	#[cfg_attr(feature = "derive", error("Invalid handshake state"))]
	InvalidState,

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
			HandshakeError::InvalidPublicKey => write!(f, "Invalid public key in handshake"),
			HandshakeError::InvalidCertificate => write!(f, "Invalid certificate"),
			HandshakeError::SignatureVerificationFailed => write!(f, "Handshake signature verification failed"),
			HandshakeError::KeyDerivationFailed => write!(f, "Handshake key derivation failed"),
			HandshakeError::InvalidState => write!(f, "Invalid handshake state"),
			HandshakeError::Timeout => write!(f, "Handshake timeout"),
			HandshakeError::ProtocolError(msg) => write!(f, "Handshake protocol error: {}", msg),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for HandshakeError {}
