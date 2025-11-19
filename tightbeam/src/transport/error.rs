use crate::asn1::Frame;
use crate::policy::TransitStatus;
#[cfg(feature = "derive")]
use crate::Errorizable;

pub type Result<T> = core::result::Result<T, TransportError>;

/// Reasons why a message failed to be sent before network I/O
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransportFailure {
	/// DER encoding failed
	EncodingFailed,
	/// AEAD encryption failed
	EncryptionFailed,
	/// Message size exceeds configured limits
	SizeExceeded,
	/// Encryptor not available
	EncryptorUnavailable,
	/// Random nonce generation failed
	NonceGenerationFailed,
}

/// Transport error types
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum TransportError {
	#[cfg_attr(feature = "derive", error("Connection failed"))]
	ConnectionFailed,
	#[cfg_attr(feature = "derive", error("Send failed"))]
	SendFailed,
	#[cfg_attr(feature = "derive", error("Receive failed"))]
	ReceiveFailed,
	#[cfg_attr(feature = "derive", error("Timeout"))]
	Timeout,
	#[cfg_attr(feature = "derive", error("Busy"))]
	Busy,
	#[cfg_attr(feature = "derive", error("Unauthorized"))]
	Unauthorized,
	#[cfg_attr(feature = "derive", error("Forbidden"))]
	Forbidden,
	#[cfg_attr(feature = "derive", error("Encryption required but not provided"))]
	MissingEncryption,
	#[cfg_attr(feature = "derive", error("Invalid message"))]
	InvalidMessage,
	#[cfg_attr(feature = "derive", error("Invalid reply"))]
	InvalidReply,
	#[cfg_attr(feature = "derive", error("Missing request"))]
	MissingRequest,
	#[cfg_attr(feature = "derive", error("Max retries exceeded"))]
	MaxRetriesExceeded,
	#[cfg_attr(feature = "derive", error("Invalid address"))]
	InvalidAddress,
	#[cfg_attr(feature = "derive", error("Invalid state"))]
	InvalidState,
	#[cfg_attr(feature = "derive", error("Message not sent: {1:?} - {0:?}"))]
	MessageNotSent(Box<crate::asn1::Frame>, TransportFailure),
	#[cfg(feature = "x509")]
	#[cfg_attr(feature = "derive", error("Handshake error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	HandshakeError(crate::transport::handshake::HandshakeError),
	#[cfg_attr(feature = "derive", error("DER error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	DerError(der::Error),
	#[cfg(feature = "std")]
	#[cfg_attr(feature = "derive", error("I/O error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	IoError(std::io::Error),
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for TransportError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{self:?}")
	}
}

impl From<TransitStatus> for TransportError {
	fn from(status: TransitStatus) -> Self {
		match status {
			TransitStatus::Request => TransportError::InvalidMessage,
			TransitStatus::Accepted => TransportError::InvalidMessage,
			TransitStatus::Busy => TransportError::Busy,
			TransitStatus::Unauthorized => TransportError::Unauthorized,
			TransitStatus::Forbidden => TransportError::Forbidden,
			TransitStatus::Timeout => TransportError::Timeout,
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for TransportError {}

#[cfg(all(feature = "std", not(feature = "derive")))]
crate::impl_from!(std::io::Error => TransportError::IoError);
#[cfg(not(feature = "derive"))]
crate::impl_from!(der::Error => TransportError::DerError);
#[cfg(all(feature = "x509", not(feature = "derive")))]
crate::impl_from!(crate::transport::handshake::HandshakeError => TransportError::HandshakeError);

crate::impl_from!(
	spki::Error => TransportError::DerError extract spki::Error::Asn1(der_err) =>
		der_err else der::Error::from(der::ErrorKind::Failed)
);
#[cfg(feature = "x509")]
crate::impl_from!(
	x509_cert::builder::Error => TransportError::DerError extract x509_cert::builder::Error::Asn1(der_err) =>
		der_err else der::Error::from(der::ErrorKind::Failed)
);

// Wrap AddrParseError in IoError
#[cfg(all(feature = "std", feature = "tcp"))]
impl From<std::net::AddrParseError> for TransportError {
	fn from(err: std::net::AddrParseError) -> Self {
		TransportError::IoError(std::io::Error::new(std::io::ErrorKind::InvalidInput, err))
	}
}

// Wrap JoinError in IoError
#[cfg(feature = "tokio")]
impl From<tokio::task::JoinError> for TransportError {
	fn from(err: tokio::task::JoinError) -> Self {
		TransportError::IoError(std::io::Error::other(err))
	}
}

// Convert timeout errors
#[cfg(feature = "tokio")]
impl From<tokio::time::error::Elapsed> for TransportError {
	fn from(_: tokio::time::error::Elapsed) -> Self {
		TransportError::Timeout
	}
}

// Convert ecdsa::Error through HandshakeError
#[cfg(all(feature = "x509", feature = "secp256k1"))]
impl From<k256::ecdsa::Error> for TransportError {
	fn from(err: k256::ecdsa::Error) -> Self {
		TransportError::HandshakeError(crate::transport::handshake::HandshakeError::from(err))
	}
}

impl TransportError {
	pub fn from_failure(frame: Frame, failure: TransportFailure) -> Self {
		TransportError::MessageNotSent(Box::new(frame), failure)
	}

	/// Extract Frame from error if present, otherwise returns None
	pub fn take_frame(self) -> Option<crate::asn1::Frame> {
		match self {
			TransportError::MessageNotSent(frame, _) => Some(*frame),
			_ => None,
		}
	}

	/// Extract Frame from error if present without consuming the error
	pub fn frame(&self) -> Option<&crate::asn1::Frame> {
		match self {
			TransportError::MessageNotSent(frame, _) => Some(frame),
			_ => None,
		}
	}

	/// Extract TransportFailure from error if present, otherwise returns None
	pub fn failure_reason(&self) -> Option<&TransportFailure> {
		match self {
			TransportError::MessageNotSent(_, reason) => Some(reason),
			_ => None,
		}
	}
}

impl From<TransportFailure> for TransportError {
	fn from(failure: TransportFailure) -> Self {
		match failure {
			TransportFailure::EncodingFailed => TransportError::InvalidMessage,
			TransportFailure::EncryptionFailed => TransportError::Forbidden,
			TransportFailure::SizeExceeded => TransportError::InvalidMessage,
			TransportFailure::EncryptorUnavailable => TransportError::Forbidden,
			TransportFailure::NonceGenerationFailed => TransportError::SendFailed,
		}
	}
}

impl TransportFailure {
	pub fn with_frame(self, frame: Frame) -> TransportError {
		TransportError::from_failure(frame, self)
	}

	pub fn with_optional_frame(self, frame: Option<Frame>) -> TransportError {
		if let Some(frame) = frame {
			self.with_frame(frame)
		} else {
			self.into()
		}
	}
}
