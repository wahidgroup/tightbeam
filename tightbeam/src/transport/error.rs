use crate::asn1::Frame;
use crate::crypto::x509::error::CertificateValidationError;
use crate::error::TightBeamError;
use crate::policy::TransitStatus;
use crate::transport::handshake::{HandshakeError, HandshakeProtocolKind};

#[cfg(feature = "std")]
use std::io::Error as IoError;
#[cfg(all(feature = "std", feature = "tcp"))]
use std::io::ErrorKind;
#[cfg(all(feature = "std", feature = "tcp"))]
use std::net::AddrParseError;

#[cfg(feature = "derive")]
use crate::Errorizable;
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

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
	/// AEAD record limit reached: send cipher halted or peer overran the
	/// volume bound. Reestablish the session to rekey
	RekeyRequired,
	/// Inbound AEAD sequence violation: replay, reorder, or deletion of an
	/// envelope on the connection (CWE-345)
	TamperDetected,
	/// Gate policy rejected (busy)
	Busy,
	/// Local stream cap exhausted on a multiplexed connection: every
	/// concurrent stream slot is in flight. Retry after a response frees
	/// a slot, or open another connection
	StreamsExhausted,
	/// Gate policy rejected (forbidden)
	Forbidden,
	/// Gate policy rejected (unauthorized)
	Unauthorized,
	/// Gate policy rejected (timeout)
	Timeout,
	/// Gate policy rejected (general)
	PolicyRejection,
}

/// Transport error types
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum TransportError {
	#[cfg_attr(feature = "derive", error("Connection closed gracefully"))]
	ConnectionClosed,
	#[cfg_attr(feature = "derive", error("Connection failed"))]
	ConnectionFailed,
	#[cfg_attr(feature = "derive", error("Send failed"))]
	SendFailed,
	#[cfg_attr(feature = "derive", error("Encryption required but not provided"))]
	MissingEncryption,
	#[cfg_attr(
		feature = "derive",
		error("Handshake protocol not supported by this transport: {0:?}")
	)]
	UnsupportedHandshakeProtocol(HandshakeProtocolKind),
	#[cfg_attr(
		feature = "derive",
		error("Server certificate chain required but not provisioned")
	)]
	MissingServerCertificateChain,
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
	#[cfg(feature = "transport-multiplex")]
	#[cfg_attr(feature = "derive", error("Connection draining after GoAway. No new streams"))]
	Draining,
	#[cfg(feature = "x509")]
	#[cfg_attr(feature = "derive", error("Invalid certificate: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	InvalidCertificate(CertificateValidationError),
	#[cfg_attr(feature = "derive", error("Message not sent: {1:?} - {0:?}"))]
	MessageNotSent(Box<Frame>, TransportFailure),
	#[cfg_attr(feature = "derive", error("Operation failed: {0:?}"))]
	OperationFailed(TransportFailure),
	#[cfg(feature = "x509")]
	#[cfg_attr(feature = "derive", error("Handshake error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	HandshakeError(HandshakeError),
	#[cfg_attr(feature = "derive", error("DER error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	DerError(der::Error),
	#[cfg(feature = "std")]
	#[cfg_attr(feature = "derive", error("I/O error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	IoError(IoError),
}

crate::impl_error_display!(TransportError {
	ConnectionClosed => "Connection closed gracefully",
	ConnectionFailed => "Connection failed",
	SendFailed => "Send failed",
	MissingEncryption => "Encryption required but not provided",
	UnsupportedHandshakeProtocol(kind) => "Handshake protocol not supported by this transport: {kind:?}",
	MissingServerCertificateChain => "Server certificate chain required but not provisioned",
	InvalidMessage => "Invalid message",
	InvalidReply => "Invalid reply",
	MissingRequest => "Missing request",
	MaxRetriesExceeded => "Max retries exceeded",
	InvalidAddress => "Invalid address",
	InvalidState => "Invalid state",
	MessageNotSent(frame, failure) => "Message not sent: {failure:?} - {frame:?}",
	OperationFailed(failure) => "Operation failed: {failure:?}",
	DerError(err) => "DER error: {err}",

	#[cfg(feature = "transport-multiplex")]
	Draining => "Connection draining after GoAway. No new streams",
	#[cfg(feature = "x509")]
	InvalidCertificate(err) => "Invalid certificate: {err}",
	#[cfg(feature = "x509")]
	HandshakeError(err) => "Handshake error: {err}",
	#[cfg(feature = "std")]
	IoError(err) => "I/O error: {err}",
});

/// Narrows [`TightBeamError`](crate::error::TightBeamError) into [`TransportError`];
/// variants without a transport counterpart collapse to [`TransportError::InvalidMessage`].
impl From<TightBeamError> for TransportError {
	fn from(err: TightBeamError) -> Self {
		use crate::error::TightBeamError;
		match err {
			TightBeamError::TransportError(t) => t,
			TightBeamError::SerializationError(e) => TransportError::DerError(e),

			#[cfg(feature = "x509")]
			TightBeamError::HandshakeError(h) => TransportError::HandshakeError(h),
			#[cfg(feature = "x509")]
			TightBeamError::CertificateValidationError(e) => TransportError::InvalidCertificate(e),
			#[cfg(feature = "std")]
			TightBeamError::IoError(e) => TransportError::IoError(e),
			// Exact-next counter nonces make replay, reorder, and deletion
			// indistinguishable from tampering. Surface them as such.
			#[cfg(feature = "aead")]
			TightBeamError::NonceReplayed(_) => TransportError::OperationFailed(TransportFailure::TamperDetected),
			// Receive side hits this only when the peer overran the per-key
			// volume bound. Session unusable either way.
			#[cfg(feature = "aead")]
			TightBeamError::RekeyRequired => TransportError::OperationFailed(TransportFailure::RekeyRequired),
			_ => TransportError::InvalidMessage,
		}
	}
}

impl From<TransitStatus> for TransportError {
	fn from(status: TransitStatus) -> Self {
		match status {
			TransitStatus::Request => TransportError::InvalidMessage,
			TransitStatus::Accepted => TransportError::InvalidMessage,
			TransitStatus::Busy => TransportError::OperationFailed(TransportFailure::Busy),
			TransitStatus::Unauthorized => TransportError::OperationFailed(TransportFailure::Unauthorized),
			TransitStatus::Forbidden => TransportError::OperationFailed(TransportFailure::Forbidden),
			TransitStatus::Timeout => TransportError::OperationFailed(TransportFailure::Timeout),
		}
	}
}

#[cfg(all(feature = "std", not(feature = "derive")))]
crate::impl_from!(IoError => TransportError::IoError);
#[cfg(not(feature = "derive"))]
crate::impl_from!(der::Error => TransportError::DerError);
#[cfg(all(feature = "x509", not(feature = "derive")))]
crate::impl_from!(HandshakeError => TransportError::HandshakeError);
#[cfg(all(feature = "x509", not(feature = "derive")))]
crate::impl_from!(CertificateValidationError => TransportError::InvalidCertificate);

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
impl From<AddrParseError> for TransportError {
	fn from(err: AddrParseError) -> Self {
		TransportError::IoError(IoError::new(ErrorKind::InvalidInput, err))
	}
}

#[cfg(feature = "tokio")]
mod tokio_rt {
	pub use tokio::task::JoinError;
	pub use tokio::time::error::Elapsed;
}

// Wrap JoinError in IoError
#[cfg(feature = "tokio")]
impl From<tokio_rt::JoinError> for TransportError {
	fn from(err: tokio_rt::JoinError) -> Self {
		TransportError::IoError(IoError::other(err))
	}
}

// Convert timeout errors
#[cfg(feature = "tokio")]
impl From<tokio_rt::Elapsed> for TransportError {
	fn from(_: tokio_rt::Elapsed) -> Self {
		TransportError::OperationFailed(TransportFailure::Timeout)
	}
}

// Convert ecdsa::Error through HandshakeError
#[cfg(all(feature = "x509", feature = "secp256k1"))]
impl From<k256::ecdsa::Error> for TransportError {
	fn from(err: k256::ecdsa::Error) -> Self {
		TransportError::HandshakeError(HandshakeError::from(err))
	}
}

impl TransportError {
	pub fn from_failure(frame: Frame, failure: TransportFailure) -> Self {
		TransportError::MessageNotSent(Box::new(frame), failure)
	}

	/// Extract Frame from error if present, otherwise returns None
	pub fn take_frame(self) -> Option<Frame> {
		match self {
			TransportError::MessageNotSent(frame, _) => Some(*frame),
			_ => None,
		}
	}

	/// Extract Frame from error if present without consuming the error
	pub fn frame(&self) -> Option<&Frame> {
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

	/// Check if error indicates connection is dead (for auto-reconnect)
	///
	/// Returns true for errors that suggest the underlying connection
	/// should be discarded and a new connection established.
	pub fn is_connection_error(&self) -> bool {
		matches!(
			self,
			TransportError::ConnectionClosed
				| TransportError::ConnectionFailed
				| TransportError::OperationFailed(TransportFailure::Timeout)
		) || {
			#[cfg(feature = "std")]
			{
				matches!(self, TransportError::IoError(_))
			}
			#[cfg(not(feature = "std"))]
			{
				false
			}
		}
	}
}

impl From<TransportFailure> for TransportError {
	fn from(failure: TransportFailure) -> Self {
		match failure {
			TransportFailure::EncodingFailed => TransportError::InvalidMessage,
			TransportFailure::SizeExceeded => TransportError::InvalidMessage,
			TransportFailure::PolicyRejection => TransportError::InvalidReply,
			TransportFailure::NonceGenerationFailed => TransportError::SendFailed,
			// All other failures map to OperationFailed
			other => TransportError::OperationFailed(other),
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
