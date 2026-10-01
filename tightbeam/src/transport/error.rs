//! Transport error types and their conversions.
//!
//! [`TransportError`] is the error every transport operation returns.
//! [`TransportFailure`] names why an operation failed, and its peer-refusal
//! variants map to and from the wire [`TransitStatus`].
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

/// Result type of transport operations.
pub type Result<T> = core::result::Result<T, TransportError>;

/// Reason an operation failed, either locally or as a peer refusal.
///
/// Each peer-refusal variant maps one to one onto a non-Ok [`TransitStatus`],
/// and the local-only variants carry no wire status.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransportFailure {
	/// DER encoding failed.
	EncodingFailed,
	/// AEAD encryption failed, or an encrypted envelope did not decrypt.
	EncryptionFailed,
	/// The message size exceeds the configured limits.
	SizeExceeded,
	/// No encryptor is available.
	EncryptorUnavailable,
	/// Random nonce generation failed.
	NonceGenerationFailed,
	/// The AEAD record limit was reached, because the send cipher halted or
	/// the peer overran the volume bound. Reestablish the session to rekey.
	RekeyRequired,
	/// An inbound AEAD sequence violation, which is a replay, reorder, or
	/// deletion of an envelope on the connection (CWE-345).
	TamperDetected,
	/// The local stream cap is exhausted on a multiplexed connection, because
	/// every concurrent stream slot is in flight. Retry after a response frees
	/// a slot, or open another connection.
	StreamsExhausted,
	/// The outbound session budget is exhausted on a multiplexed connection,
	/// because the epoch's remaining spendable credits cannot cover the frame.
	BudgetExhausted,
	/// A gate policy rejected the operation, as a general refusal.
	PolicyRejection,
	/// The peer refused the call because the caller cancelled the operation.
	Cancelled,
	/// The peer refused the call with an unclassified server failure.
	Unknown,
	/// The peer refused the call because the request is malformed regardless
	/// of system state.
	InvalidArgument,
	/// The peer refused the call because it gave up waiting. A local deadline
	/// that elapses also reports this variant.
	DeadlineExceeded,
	/// The peer refused the call because the requested entity does not exist.
	NotFound,
	/// The peer refused the call because the entity already exists.
	AlreadyExists,
	/// The peer refused the call because the caller is identified but was
	/// refused authorization.
	PermissionDenied,
	/// The peer refused the call because its capacity is exhausted. A retry
	/// with backoff may succeed.
	ResourceExhausted,
	/// The peer refused the call because system state must change before a
	/// retry can succeed.
	FailedPrecondition,
	/// The peer refused the call on a concurrency conflict. Retry at a higher
	/// level.
	Aborted,
	/// The peer refused the call because the operation ran past a valid range.
	OutOfRange,
	/// The peer refused the call because no handler answers the requested
	/// operation.
	Unimplemented,
	/// The peer refused the call because it broke an internal invariant.
	Internal,
	/// The peer refused the call on a transient unavailability, such as a
	/// draining peer.
	Unavailable,
	/// The peer refused the call on unrecoverable data loss or corruption.
	DataLoss,
	/// The peer refused the call because the caller lacks valid
	/// authentication credentials.
	Unauthenticated,
}

/// Error returned by every transport operation.
#[derive(Debug, Errorizable)]
#[non_exhaustive]
pub enum TransportError {
	/// The connection closed gracefully.
	#[error("Connection closed gracefully")]
	ConnectionClosed,
	/// The peer closed the connection before the handshake completed.
	#[error("Peer closed the connection before the handshake completed")]
	PeerClosedBeforeHandshake,
	/// The connection failed.
	#[error("Connection failed")]
	ConnectionFailed,
	/// A send failed. A [`TransportFailure::NonceGenerationFailed`] without a
	/// frame converts to this variant.
	#[error("Send failed")]
	SendFailed,
	/// The operation requires encryption, and none was provided.
	#[error("Encryption required but not provided")]
	MissingEncryption,
	/// This transport does not support the configured handshake protocol.
	#[error("Handshake protocol not supported by this transport: {0:?}")]
	UnsupportedHandshakeProtocol(HandshakeProtocolKind),
	/// The operation requires a server certificate chain, and none is
	/// provisioned.
	#[error("Server certificate chain required but not provisioned")]
	MissingServerCertificateChain,
	/// The client has no trust store. Install one, or call `allow_cleartext`
	/// to choose cleartext.
	#[error("Client has no trust store: install one or call allow_cleartext to choose cleartext")]
	PeerAuthenticationUnconfigured,
	/// A message broke the protocol or failed to decode, such as a mux
	/// protocol violation or an oversized handshake message.
	#[error("Invalid message")]
	InvalidMessage,
	/// A reply was invalid. A [`TransportFailure::PolicyRejection`] without a
	/// frame converts to this variant.
	#[error("Invalid reply")]
	InvalidReply,
	/// No request frame is present to send or retry.
	#[error("Missing request")]
	MissingRequest,
	/// The retry loop ran out of attempts.
	#[error("Max retries exceeded")]
	MaxRetriesExceeded,
	/// The configured address is invalid.
	#[error("Invalid address")]
	InvalidAddress,
	/// The operation does not fit the current state of the transport or its
	/// session.
	#[error("Invalid state")]
	InvalidState,
	/// The connection is draining after a GoAway and admits no new streams.
	#[cfg(feature = "transport-multiplex")]
	#[error("Connection draining after GoAway. No new streams")]
	Draining,
	/// A certificate failed validation.
	#[cfg(feature = "x509")]
	#[error("Invalid certificate: {0}")]
	#[from]
	InvalidCertificate(CertificateValidationError),
	/// The message was not sent, and the frame travels with the error so a
	/// restart policy can retry it.
	///
	/// The display names only the failure and the frame's identity, through
	/// the frame's own `Display`, because the body is application plaintext
	/// and an error string reaches logs (CWE-532).
	#[error("Message not sent: {1:?} for {0}")]
	MessageNotSent(Box<Frame>, TransportFailure),
	/// An operation failed for the carried [`TransportFailure`] reason.
	#[error("Operation failed: {0:?}")]
	OperationFailed(TransportFailure),
	/// The handshake failed.
	#[cfg(feature = "x509")]
	#[error("Handshake error: {0}")]
	#[from]
	HandshakeError(HandshakeError),
	/// DER encoding or decoding failed.
	#[error("DER error: {0}")]
	#[from]
	DerError(der::Error),
	/// An I/O operation on the underlying stream failed.
	#[cfg(feature = "std")]
	#[error("I/O error: {0}")]
	#[from]
	IoError(IoError),
}

/// Narrow a [`TightBeamError`] into a [`TransportError`].
///
/// A variant without a transport counterpart collapses to
/// [`TransportError::InvalidMessage`].
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
			// The receive side hits this only when the peer overran the
			// per-key volume bound. The session is unusable either way.
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
			// A success status is not convertible to a failure.
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
			// Local-only failures carry no wire status.
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

/// Report an unparsable address as an `InvalidInput` I/O error.
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

/// Report a failed task join as an I/O error.
#[cfg(feature = "tokio")]
impl From<tokio_rt::JoinError> for TransportError {
	fn from(err: tokio_rt::JoinError) -> Self {
		TransportError::IoError(IoError::other(err))
	}
}

/// Report an elapsed timeout as [`TransportFailure::DeadlineExceeded`].
#[cfg(feature = "tokio")]
impl From<tokio_rt::Elapsed> for TransportError {
	fn from(_: tokio_rt::Elapsed) -> Self {
		TransportError::OperationFailed(TransportFailure::DeadlineExceeded)
	}
}

/// Report an ECDSA failure as a handshake error.
#[cfg(all(feature = "x509", feature = "secp256k1"))]
impl From<k256::ecdsa::Error> for TransportError {
	fn from(err: k256::ecdsa::Error) -> Self {
		TransportError::HandshakeError(HandshakeError::from(err))
	}
}

impl TransportError {
	/// Wrap `frame` with the `failure` that kept it from sending.
	pub fn from_failure(frame: Frame, failure: TransportFailure) -> Self {
		TransportError::MessageNotSent(Box::new(frame), failure)
	}

	/// Take the unsent frame out of a [`TransportError::MessageNotSent`], or
	/// return `None` for any other variant.
	pub fn take_frame(self) -> Option<Frame> {
		match self {
			TransportError::MessageNotSent(frame, _) => Some(*frame),
			_ => None,
		}
	}

	/// Borrow the unsent frame of a [`TransportError::MessageNotSent`] without
	/// consuming the error.
	pub fn frame(&self) -> Option<&Frame> {
		match self {
			TransportError::MessageNotSent(frame, _) => Some(frame),
			_ => None,
		}
	}

	/// The failure that kept a [`TransportError::MessageNotSent`] frame from
	/// sending, or `None` for any other variant.
	pub fn failure_reason(&self) -> Option<&TransportFailure> {
		match self {
			TransportError::MessageNotSent(_, reason) => Some(reason),
			_ => None,
		}
	}

	/// Whether the error means the connection is dead, which drives
	/// auto-reconnect.
	///
	/// Returns `true` for errors that suggest the underlying connection should
	/// be discarded and a new connection established.
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

/// Lift a failure that carries no frame into its error.
///
/// Encoding, size, policy, and nonce failures map to dedicated variants, and
/// every other failure maps to [`TransportError::OperationFailed`].
impl From<TransportFailure> for TransportError {
	fn from(failure: TransportFailure) -> Self {
		match failure {
			TransportFailure::EncodingFailed => TransportError::InvalidMessage,
			TransportFailure::SizeExceeded => TransportError::InvalidMessage,
			TransportFailure::PolicyRejection => TransportError::InvalidReply,
			TransportFailure::NonceGenerationFailed => TransportError::SendFailed,
			other => TransportError::OperationFailed(other),
		}
	}
}

impl TransportFailure {
	/// Attach the unsent `frame` to this failure, as a
	/// [`TransportError::MessageNotSent`].
	pub fn with_frame(self, frame: Frame) -> TransportError {
		TransportError::from_failure(frame, self)
	}

	/// Attach `frame` when one is present, or convert the bare failure into
	/// its error.
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

	// An error reaches consumer logs through `Display` or `Debug`, so the
	// frame body, which is application plaintext, stays out of both, as text
	// and as the byte list a derived `Debug` would print (CWE-532).
	#[test]
	fn message_not_sent_names_the_frame_without_its_body() {
		use crate::testing::TestFrame;

		let body = "plaintext-that-must-not-reach-a-log";
		let body_bytes = format!("{:?}", body.as_bytes());
		let body_bytes = body_bytes.trim_matches(['[', ']']);
		let frame = TestFrame::v0(Some(body), None);
		let frame_id = format!("{:02x?}", frame.metadata().id());
		let error = TransportError::MessageNotSent(Box::new(frame), TransportFailure::SizeExceeded);

		let displayed = error.to_string();
		let debugged = format!("{error:?}");
		assert!(displayed.contains("SizeExceeded"));
		assert!(displayed.contains(&frame_id));
		assert!(!displayed.contains(body));
		assert!(!displayed.contains(body_bytes));
		assert!(!debugged.contains(body));
		assert!(!debugged.contains(body_bytes));
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
