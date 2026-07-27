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
	/// Local stream cap exhausted on a multiplexed connection: every
	/// concurrent stream slot is in flight. Retry after a response frees
	/// a slot, or open another connection
	StreamsExhausted,
	/// Outbound session budget exhausted on a multiplexed connection:
	/// the epoch's remaining spendable credits cannot cover the frame.
	BudgetExhausted,
	/// Gate policy rejected (general)
	PolicyRejection,
	/// Peer refusal: the caller cancelled the operation
	Cancelled,
	/// Peer refusal: unclassified server failure
	Unknown,
	/// Peer refusal: the request is malformed regardless of system state
	InvalidArgument,
	/// Peer refusal: the peer gave up waiting
	DeadlineExceeded,
	/// Peer refusal: the requested entity does not exist
	NotFound,
	/// Peer refusal: the entity already exists
	AlreadyExists,
	/// Peer refusal: the caller is identified but refused authorization
	PermissionDenied,
	/// Peer refusal: capacity exhausted, retry with backoff may succeed
	ResourceExhausted,
	/// Peer refusal: system state must change before a retry can succeed
	FailedPrecondition,
	/// Peer refusal: concurrency conflict, retry at a higher level
	Aborted,
	/// Peer refusal: the operation ran past a valid range
	OutOfRange,
	/// Peer refusal: no handler answers the requested operation
	Unimplemented,
	/// Peer refusal: the peer broke an internal invariant
	Internal,
	/// Peer refusal: transient unavailability such as a draining peer
	Unavailable,
	/// Peer refusal: unrecoverable data loss or corruption
	DataLoss,
	/// Peer refusal: the caller lacks valid authentication credentials
	Unauthenticated,
}

/// Transport error types
#[derive(Debug, Errorizable)]
pub enum TransportError {
	#[error("Connection closed gracefully")]
	ConnectionClosed,
	#[error("Connection failed")]
	ConnectionFailed,
	#[error("Send failed")]
	SendFailed,
	#[error("Encryption required but not provided")]
	MissingEncryption,
	#[error("Handshake protocol not supported by this transport: {0:?}")]
	UnsupportedHandshakeProtocol(HandshakeProtocolKind),
	#[error("Server certificate chain required but not provisioned")]
	MissingServerCertificateChain,
	#[error("Invalid message")]
	InvalidMessage,
	#[error("Invalid reply")]
	InvalidReply,
	#[error("Missing request")]
	MissingRequest,
	#[error("Max retries exceeded")]
	MaxRetriesExceeded,
	#[error("Invalid address")]
	InvalidAddress,
	#[error("Invalid state")]
	InvalidState,
	#[cfg(feature = "transport-multiplex")]
	#[error("Connection draining after GoAway. No new streams")]
	Draining,
	#[cfg(feature = "x509")]
	#[error("Invalid certificate: {0}")]
	#[from]
	InvalidCertificate(CertificateValidationError),
	#[error("Message not sent: {1:?} - {0:?}")]
	MessageNotSent(Box<Frame>, TransportFailure),
	#[error("Operation failed: {0:?}")]
	OperationFailed(TransportFailure),
	#[cfg(feature = "x509")]
	#[error("Handshake error: {0}")]
	#[from]
	HandshakeError(HandshakeError),
	#[error("DER error: {0}")]
	#[from]
	DerError(der::Error),
	#[cfg(feature = "std")]
	#[error("I/O error: {0}")]
	#[from]
	IoError(IoError),
}

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

impl TryFrom<TransitStatus> for TransportFailure {
	type Error = TransportError;

	fn try_from(status: TransitStatus) -> core::result::Result<Self, Self::Error> {
		let failure = match status {
			// A success status is not convertible to a failure
			TransitStatus::Ok => return Err(TransportError::InvalidMessage),
			TransitStatus::Cancelled => TransportFailure::Cancelled,
			TransitStatus::Unknown => TransportFailure::Unknown,
			TransitStatus::InvalidArgument => TransportFailure::InvalidArgument,
			TransitStatus::DeadlineExceeded => TransportFailure::DeadlineExceeded,
			TransitStatus::NotFound => TransportFailure::NotFound,
			TransitStatus::AlreadyExists => TransportFailure::AlreadyExists,
			TransitStatus::PermissionDenied => TransportFailure::PermissionDenied,
			TransitStatus::ResourceExhausted => TransportFailure::ResourceExhausted,
			TransitStatus::FailedPrecondition => TransportFailure::FailedPrecondition,
			TransitStatus::Aborted => TransportFailure::Aborted,
			TransitStatus::OutOfRange => TransportFailure::OutOfRange,
			TransitStatus::Unimplemented => TransportFailure::Unimplemented,
			TransitStatus::Internal => TransportFailure::Internal,
			TransitStatus::Unavailable => TransportFailure::Unavailable,
			TransitStatus::DataLoss => TransportFailure::DataLoss,
			TransitStatus::Unauthenticated => TransportFailure::Unauthenticated,
		};

		Ok(failure)
	}
}

impl From<TransitStatus> for TransportError {
	fn from(status: TransitStatus) -> Self {
		match TransportFailure::try_from(status) {
			Ok(failure) => TransportError::OperationFailed(failure),
			Err(error) => error,
		}
	}
}

impl TryFrom<TransportFailure> for TransitStatus {
	type Error = TransportError;

	fn try_from(failure: TransportFailure) -> core::result::Result<Self, Self::Error> {
		let status = match failure {
			TransportFailure::Cancelled => TransitStatus::Cancelled,
			TransportFailure::Unknown => TransitStatus::Unknown,
			TransportFailure::InvalidArgument => TransitStatus::InvalidArgument,
			TransportFailure::DeadlineExceeded => TransitStatus::DeadlineExceeded,
			TransportFailure::NotFound => TransitStatus::NotFound,
			TransportFailure::AlreadyExists => TransitStatus::AlreadyExists,
			TransportFailure::PermissionDenied => TransitStatus::PermissionDenied,
			TransportFailure::ResourceExhausted => TransitStatus::ResourceExhausted,
			TransportFailure::FailedPrecondition => TransitStatus::FailedPrecondition,
			TransportFailure::Aborted => TransitStatus::Aborted,
			TransportFailure::OutOfRange => TransitStatus::OutOfRange,
			TransportFailure::Unimplemented => TransitStatus::Unimplemented,
			TransportFailure::Internal => TransitStatus::Internal,
			TransportFailure::Unavailable => TransitStatus::Unavailable,
			TransportFailure::DataLoss => TransitStatus::DataLoss,
			TransportFailure::Unauthenticated => TransitStatus::Unauthenticated,
			// Local-only failures carry no wire status
			local => return Err(TransportError::OperationFailed(local)),
		};

		Ok(status)
	}
}

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
		TransportError::OperationFailed(TransportFailure::DeadlineExceeded)
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
				| TransportError::OperationFailed(TransportFailure::DeadlineExceeded)
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

#[cfg(test)]
mod tests {
	use super::*;

	struct StatusMappingCase {
		status: TransitStatus,
		expected: TransportFailure,
	}

	fn refusal_cases() -> Vec<StatusMappingCase> {
		vec![
			StatusMappingCase { status: TransitStatus::Cancelled, expected: TransportFailure::Cancelled },
			StatusMappingCase { status: TransitStatus::Unknown, expected: TransportFailure::Unknown },
			StatusMappingCase {
				status: TransitStatus::InvalidArgument,
				expected: TransportFailure::InvalidArgument,
			},
			StatusMappingCase {
				status: TransitStatus::DeadlineExceeded,
				expected: TransportFailure::DeadlineExceeded,
			},
			StatusMappingCase { status: TransitStatus::NotFound, expected: TransportFailure::NotFound },
			StatusMappingCase { status: TransitStatus::AlreadyExists, expected: TransportFailure::AlreadyExists },
			StatusMappingCase {
				status: TransitStatus::PermissionDenied,
				expected: TransportFailure::PermissionDenied,
			},
			StatusMappingCase {
				status: TransitStatus::ResourceExhausted,
				expected: TransportFailure::ResourceExhausted,
			},
			StatusMappingCase {
				status: TransitStatus::FailedPrecondition,
				expected: TransportFailure::FailedPrecondition,
			},
			StatusMappingCase { status: TransitStatus::Aborted, expected: TransportFailure::Aborted },
			StatusMappingCase { status: TransitStatus::OutOfRange, expected: TransportFailure::OutOfRange },
			StatusMappingCase { status: TransitStatus::Unimplemented, expected: TransportFailure::Unimplemented },
			StatusMappingCase { status: TransitStatus::Internal, expected: TransportFailure::Internal },
			StatusMappingCase { status: TransitStatus::Unavailable, expected: TransportFailure::Unavailable },
			StatusMappingCase { status: TransitStatus::DataLoss, expected: TransportFailure::DataLoss },
			StatusMappingCase {
				status: TransitStatus::Unauthenticated,
				expected: TransportFailure::Unauthenticated,
			},
		]
	}

	#[test]
	fn refusal_statuses_surface_their_failure() {
		for case in refusal_cases() {
			let error = TransportError::from(case.status);
			assert!(matches!(error, TransportError::OperationFailed(failure) if failure == case.expected));
		}
	}

	#[test]
	fn refusal_codes_survive_the_round_trip() {
		for case in refusal_cases() {
			let relayed = TransitStatus::try_from(case.expected);
			assert!(matches!(relayed, Ok(status) if status == case.status));
		}
	}

	#[test]
	fn local_failures_have_no_wire_status() {
		let relayed = TransitStatus::try_from(TransportFailure::EncodingFailed);
		assert!(matches!(
			relayed,
			Err(TransportError::OperationFailed(TransportFailure::EncodingFailed))
		));
	}
}
