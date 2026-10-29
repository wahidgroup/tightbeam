//! The error types of the transport layer and their conversions.
//!
//! [`TransportError`] is the error every transport operation returns.
//! [`TransportFailure`] names why an operation failed, and its peer-refusal
//! variants map to and from the wire [`TransitStatus`].
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::io::Error as IoError;
#[cfg(all(feature = "std", feature = "tcp"))]
use std::io::ErrorKind;
#[cfg(all(feature = "std", feature = "tcp"))]
use std::net::AddrParseError;
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::Frame;
use crate::crypto::x509::error::CertificateValidationError;
use crate::error::TightBeamError;
use crate::policy::TransitStatus;
use crate::transport::handshake::SessionPeer;
use crate::transport::handshake::{HandshakeError, HandshakeProtocolKind};
use crate::Errorizable;

#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
use crate::transport::handshake::HandshakeAudit;

/// The result type of transport operations.
pub type Result<T> = core::result::Result<T, TransportError>;

/// The reason an operation failed, either locally or as a peer refusal.
///
/// Each peer-refusal variant maps one to one onto a non-Ok [`TransitStatus`],
/// and a local-only variant fails that conversion.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransportFailure {
	/// DER encoding failed.
	EncodingFailed,
	/// AEAD encryption failed, or an encrypted envelope did not decrypt.
	EncryptionFailed,
	/// The message size exceeds the configured limits. A reply header past the
	/// read cap raises it after the request's write completed.
	SizeExceeded,
	/// No encryptor is available. The read side raises it for a session with
	/// no keys, whose write fails first on the same missing keys.
	EncryptorUnavailable,
	/// Random nonce generation failed.
	NonceGenerationFailed,
	/// The send cipher of the session is at its record limit (RFC 9846 § 5.5),
	/// so every later seal fails. Reestablish the session to rekey.
	RekeyRequired,
	/// An inbound record passed a renewal bound of the receive key, by its
	/// sequence number or by the bytes the key has opened. An honest sender
	/// renews before either bound, so the record is a fault of the peer or of
	/// the path, and the read that met it ends the session.
	RenewalBoundExceeded,
	/// An inbound envelope broke the AEAD sequence by a replay, reorder, or
	/// deletion on the connection (CWE-345).
	TamperDetected,
	/// The local stream cap is exhausted on a multiplexed connection, because
	/// every concurrent stream slot is in flight. Retry after a response frees
	/// a slot, or open another connection.
	StreamsExhausted,
	/// The outbound session budget is exhausted on a multiplexed connection,
	/// because the spendable credits left in the epoch cannot cover the frame.
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
	/// The peer refused the call because the call's deadline elapsed. A local
	/// deadline that elapses also reports this variant.
	DeadlineExceeded,
	/// The peer refused the call because the requested entity does not exist.
	NotFound,
	/// The peer refused the call because the entity already exists.
	AlreadyExists,
	/// The peer refused the call because it identified the caller but denied
	/// it authorization.
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
	/// draining peer. A peer answers it before its handler runs, so a retry
	/// on another peer runs the call at most once.
	Unavailable,
	/// The peer refused the call on unrecoverable data loss or corruption.
	DataLoss,
	/// The peer refused the call because the caller lacks valid
	/// authentication credentials.
	Unauthenticated,
}

/// The rule of [`TransportLimits::checked`] that a set of limits breaks.
///
/// [`TransportLimits::checked`]: crate::transport::TransportLimits::checked
#[derive(Clone, Copy, Debug, PartialEq, Eq, Errorizable)]
pub enum LimitsRefusal {
	/// A ceiling is zero, so it refuses every envelope or every operation it
	/// bounds.
	#[error("every ceiling must be above zero")]
	ZeroCeiling,
	/// A handshake message of [`TransportLimits::handshake_wire`] octets, in
	/// its cleartext wire form, passes [`TransportLimits::cleartext_envelope`]
	/// or the largest length DER encodes. A reader then refuses a handshake
	/// message that the writer admits.
	///
	/// [`TransportLimits::handshake_wire`]: crate::transport::TransportLimits::handshake_wire
	/// [`TransportLimits::cleartext_envelope`]: crate::transport::TransportLimits::cleartext_envelope
	#[error("a handshake message at handshake_wire must fit cleartext_envelope on the wire")]
	HandshakePastCleartext,
}

/// The error every transport operation returns.
#[derive(Debug, Errorizable)]
#[non_exhaustive]
pub enum TransportError {
	/// The connection closed. The reader reports it when the peer ends the
	/// stream between two frames, and a mux handle reports it when its
	/// connection fails or a driver ends.
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
	/// The operation requires encryption that the link, its configuration, or
	/// the envelope that arrived lacks.
	#[error("Encryption required but not provided")]
	MissingEncryption,
	/// This transport does not support the configured handshake protocol.
	#[error("Handshake protocol not supported by this transport: {0:?}")]
	UnsupportedHandshakeProtocol(HandshakeProtocolKind),
	/// The CMS handshake requires the server's pinned key-agreement
	/// certificate, and the client configuration holds none.
	#[error("Server certificate chain required but not provisioned")]
	MissingServerCertificateChain,
	/// A server of the CMS flow requires a key-agreement identity beside its
	/// signing identity, and its configuration holds only the signing identity.
	#[error("Key-agreement identity required but not provisioned")]
	MissingKeyAgreementIdentity,
	/// The client holds no server trust, which is a trust store or a CMS
	/// server trust. Install one, or remove any server policy and call
	/// `allow_cleartext` to choose cleartext.
	#[error("Client holds no server trust: install one, or remove any server policy and call allow_cleartext")]
	PeerAuthenticationUnconfigured,
	/// A message broke the protocol or failed to decode, such as a mux
	/// protocol violation or an oversized handshake message.
	#[error("Invalid message")]
	InvalidMessage,
	/// A reply is invalid. A [`TransportFailure::PolicyRejection`] without a
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
	/// The endpoint serves no call of the kind, or no operation, that the
	/// call names. The default methods of a multiplexed service return it for
	/// each kind the service leaves out, and a peer reads it as
	/// [`TransitStatus::Unimplemented`].
	#[error("Not served by this endpoint")]
	NotServed,
	/// The connection is draining after a GoAway and admits no new streams.
	#[cfg(feature = "transport-multiplex")]
	#[error("Connection draining after GoAway. No new streams")]
	Draining,
	/// A certificate failed validation.
	#[error("Invalid certificate: {0}")]
	#[from]
	InvalidCertificate(CertificateValidationError),
	/// A set of [`TransportLimits`] breaks a rule of
	/// [`TransportLimits::checked`], at the configuration that takes it.
	///
	/// [`TransportLimits`]: crate::transport::TransportLimits
	/// [`TransportLimits::checked`]: crate::transport::TransportLimits::checked
	#[error("Invalid transport limits: {0}")]
	InvalidLimits(LimitsRefusal),
	/// The transport did not send the message, and the frame travels with the
	/// error so a restart policy can retry it.
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
/// A poisoned lock is a local fault, and it becomes the
/// [`TransportFailure::Internal`] failure, as a poisoned pool map does. A
/// variant without a transport counterpart collapses to
/// [`TransportError::InvalidMessage`].
impl From<TightBeamError> for TransportError {
	fn from(err: TightBeamError) -> Self {
		use crate::error::TightBeamError;
		match err {
			TightBeamError::TransportError(t) => t,
			TightBeamError::SerializationError(e) => TransportError::DerError(e),

			TightBeamError::HandshakeError(h) => TransportError::HandshakeError(h),
			TightBeamError::CertificateValidationError(e) => TransportError::InvalidCertificate(e),
			#[cfg(feature = "std")]
			TightBeamError::IoError(e) => TransportError::IoError(e),
			// An exact-next record sequence makes replay, reorder, and deletion
			// indistinguishable from tampering, so each surfaces as tampering.
			TightBeamError::NonceReplayed(_) => TransportError::OperationFailed(TransportFailure::TamperDetected),
			// A spent send cipher and a record past a renewal bound of the
			// receive key keep their own failures, so a routine end of keys
			// reads apart from a fault of the inbound stream.
			TightBeamError::RekeyRequired => TransportError::OperationFailed(TransportFailure::RekeyRequired),
			TightBeamError::RenewalBoundExceeded => {
				TransportError::OperationFailed(TransportFailure::RenewalBoundExceeded)
			}
			#[cfg(feature = "std")]
			TightBeamError::LockPoisoned => TransportError::OperationFailed(TransportFailure::Internal),
			_ => TransportError::InvalidMessage,
		}
	}
}

// `NotServed` is the transport's variant, so the transport answers whether a
// crate error carries it.
#[cfg(feature = "std")]
impl TightBeamError {
	/// Whether this error is [`TransportError::NotServed`], the refusal of a
	/// kind or an operation that its endpoint leaves out.
	pub(crate) fn is_not_served(&self) -> bool {
		matches!(self, TightBeamError::TransportError(TransportError::NotServed))
	}
}

/// Why a reader refused an envelope at its arrival, or why its read ended.
///
/// A forged record reads as [`TransportError::InvalidMessage`] or as the error
/// of its open, which names no cause. The cause keeps it, so the audit record
/// of the read step names it (CWE-778).
#[derive(Debug)]
pub(crate) enum ArrivalCause {
	/// A refusal, or an end of the read, that its transport error names.
	Failed(TransportError),
	/// A record that names another epoch than the receive key, with the error
	/// of the key.
	WrongEpoch(TightBeamError),
	/// A record that the receive key does not open, with the error of the key:
	/// the record is no envelope of this key, its position does not decode or
	/// passes a renewal bound, or its tag fails.
	OpenFailed(TightBeamError),
}

impl ArrivalCause {
	/// The cause of a record that the receive key refused to open with
	/// `error`.
	///
	/// - A record of another epoch is [`Self::WrongEpoch`].
	/// - A record out of sequence reads as [`TransportFailure::TamperDetected`], so it is [`Self::Failed`].
	/// - Every other refusal of the key is [`Self::OpenFailed`]. The key refuses
	///   a position that does not decode or passes a renewal bound before its
	///   tag check, so a party with no key chooses that form at no cost.
	pub(crate) fn of_open(error: TightBeamError) -> Self {
		match error {
			TightBeamError::RecordEpoch(_) => Self::WrongEpoch(error),
			TightBeamError::NonceReplayed(_) => Self::Failed(error.into()),
			error => Self::OpenFailed(error),
		}
	}

	/// The name of the refusal that this cause makes of an envelope, which
	/// labels its audit record, or `None` for a read that ended for another
	/// reason, such as a closed connection.
	#[cfg(feature = "instrument")]
	pub(crate) fn refusal(&self) -> Option<&'static str> {
		match self {
			Self::WrongEpoch(_) => Some("WrongEpoch"),
			Self::OpenFailed(_) => Some("OpenFailed"),
			Self::Failed(error) => error.peer_refusal(),
		}
	}
}

impl From<TransportError> for ArrivalCause {
	fn from(error: TransportError) -> Self {
		Self::Failed(error)
	}
}

/// The failed read of one envelope, with the peer of the session that the
/// envelope arrived on.
///
/// The reader builds the refusal where it holds the peer, so the audit record
/// of every read path names that peer. A session that resets on the refusal
/// moves the peer of the session it drops into the refusal.
#[derive(Debug)]
pub(crate) struct ArrivalRefusal {
	cause: ArrivalCause,
	/// The peer that the audit record of the refusal names.
	#[cfg(feature = "instrument")]
	peer: Option<Arc<SessionPeer>>,
}

impl ArrivalRefusal {
	/// The refusal of an arrival for `cause`, on a session whose peer is
	/// `peer`.
	pub(crate) fn new(cause: impl Into<ArrivalCause>, peer: Option<&Arc<SessionPeer>>) -> Self {
		#[cfg(not(feature = "instrument"))]
		let _ = peer;

		Self {
			cause: cause.into(),
			#[cfg(feature = "instrument")]
			peer: peer.cloned(),
		}
	}

	/// The refusal of an arrival for `cause`, which took `peer` from the
	/// session that the refusal reset.
	pub(crate) fn of_dropped(cause: impl Into<ArrivalCause>, peer: Option<Arc<SessionPeer>>) -> Self {
		#[cfg(not(feature = "instrument"))]
		let _ = peer;

		Self {
			cause: cause.into(),
			#[cfg(feature = "instrument")]
			peer,
		}
	}

	/// The name of the refusal that this read makes of its envelope, or `None`
	/// for a read that ended for another reason. See [`ArrivalCause::refusal`].
	#[cfg(feature = "instrument")]
	pub(crate) fn refusal(&self) -> Option<&'static str> {
		self.cause.refusal()
	}

	/// The peer of the session that the envelope arrived on.
	#[cfg(feature = "instrument")]
	pub(crate) fn peer(&self) -> Option<&SessionPeer> {
		self.peer.as_deref()
	}
}

/// The error that the read step returns for a refused arrival. The error of a
/// record that does not open narrows as every [`TightBeamError`] does.
impl From<ArrivalRefusal> for TransportError {
	fn from(refusal: ArrivalRefusal) -> Self {
		match refusal.cause {
			ArrivalCause::Failed(error) => error,
			ArrivalCause::WrongEpoch(error) | ArrivalCause::OpenFailed(error) => error.into(),
		}
	}
}

impl TransportError {
	/// The transit status this error carries: the status of the peer refusal
	/// that [`TransportError::OperationFailed`] names, or `None` for a local
	/// failure, which carries no wire status.
	///
	/// ```
	/// use tightbeam::policy::TransitStatus;
	/// use tightbeam::transport::TransportError;
	///
	/// let refusal = TransportError::from(TransitStatus::PermissionDenied);
	/// assert_eq!(refusal.transit_status(), Some(TransitStatus::PermissionDenied));
	/// assert_eq!(TransportError::InvalidMessage.transit_status(), None);
	/// ```
	#[must_use]
	pub fn transit_status(&self) -> Option<TransitStatus> {
		let Self::OperationFailed(failure) = self else {
			return None;
		};

		TransitStatus::try_from(*failure).ok()
	}
}

#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "tokio", feature = "async-transport")
))]
impl TransportError {
	/// Returns the terminal status that a peer stream reads when its handler
	/// fails with this error.
	///
	/// - A failure that carries a transit status keeps it, apart from [`TransitStatus::Unavailable`].
	/// - A carried `Unavailable` answers [`TransitStatus::Unknown`], because
	///   the handler ran up to its failure. A peer reads `Unavailable` as a
	///   refusal before any handler ran, which a gate answers, and a gateway
	///   retries such a frame on another instance.
	/// - [`TransportError::NotServed`] answers [`TransitStatus::Unimplemented`].
	/// - Any other failure answers [`TransitStatus::Internal`], so a peer
	///   tells a failure apart from an accepted empty reply and the failure
	///   stays attributable.
	#[must_use]
	pub(crate) fn failure_status(&self) -> TransitStatus {
		if let Self::NotServed = self {
			return TransitStatus::Unimplemented;
		}

		match self.transit_status() {
			Some(TransitStatus::Unavailable) => TransitStatus::Unknown,
			Some(status) => status,
			None => TransitStatus::Internal,
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
impl From<k256::ecdsa::Error> for TransportError {
	fn from(err: k256::ecdsa::Error) -> Self {
		TransportError::HandshakeError(HandshakeError::from(err))
	}
}

impl TransportError {
	/// Wrap the unsent `frame` with the `failure` that stopped its send.
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

	/// Borrow the unsent frame of a [`TransportError::MessageNotSent`], and
	/// keep the error whole.
	pub fn frame(&self) -> Option<&Frame> {
		match self {
			TransportError::MessageNotSent(frame, _) => Some(frame),
			_ => None,
		}
	}

	/// Return the failure that stopped the send of a
	/// [`TransportError::MessageNotSent`] frame, or `None` for any other
	/// variant.
	pub fn failure_reason(&self) -> Option<&TransportFailure> {
		match self {
			TransportError::MessageNotSent(_, reason) => Some(reason),
			_ => None,
		}
	}

	/// Report whether this fault proves that the frame never reached a handler
	/// of the peer, so a retry on another route runs it at most once. Three
	/// kinds of fault prove it:
	///
	/// - A send the transport reports as not sent, or a failed write.
	/// - A local refusal before the write: a full stream table, a spent
	///   budget, an unencodable frame, a missing encryptor, or a failed nonce
	///   generation.
	/// - A peer's [`TransportFailure::Unavailable`], which a peer answers before its handler runs.
	#[must_use]
	pub(crate) fn proves_unsent(&self) -> bool {
		matches!(
			self,
			TransportError::MessageNotSent(..)
				| TransportError::SendFailed
				| TransportError::OperationFailed(
					TransportFailure::Unavailable
						| TransportFailure::StreamsExhausted
						| TransportFailure::BudgetExhausted
						| TransportFailure::EncodingFailed
						| TransportFailure::EncryptorUnavailable
						| TransportFailure::NonceGenerationFailed
				)
		)
	}

	/// The name of the refusal that this error makes of what the peer sent,
	/// which labels the audit record of a refused envelope, or `None` for an
	/// error that ends an exchange for another reason.
	///
	/// - The refusal of an arrival names its failure: an envelope past its
	///   ceiling, out of sequence, past a renewal bound, or of a mode the
	///   session refuses.
	/// - A message that breaks the protocol, ends early, or does not decode is a refusal.
	/// - A close, a stall past a deadline, an I/O failure, a local fault, and a
	///   peer status answer `None`. A handshake or certificate failure answers
	///   `None` too, because a record of its own names it.
	#[cfg(feature = "instrument")]
	#[must_use]
	pub(crate) fn peer_refusal(&self) -> Option<&'static str> {
		match self {
			TransportError::OperationFailed(failure) => failure.refuses_arrival().then_some(failure.as_str()),
			TransportError::MissingEncryption => Some("MissingEncryption"),
			TransportError::InvalidMessage => Some("InvalidMessage"),
			TransportError::DerError(_) => Some("DerError"),
			TransportError::ConnectionClosed
			| TransportError::PeerClosedBeforeHandshake
			| TransportError::ConnectionFailed
			| TransportError::SendFailed
			| TransportError::UnsupportedHandshakeProtocol(_)
			| TransportError::MissingServerCertificateChain
			| TransportError::MissingKeyAgreementIdentity
			| TransportError::PeerAuthenticationUnconfigured
			| TransportError::InvalidReply
			| TransportError::MissingRequest
			| TransportError::MaxRetriesExceeded
			| TransportError::InvalidAddress
			| TransportError::InvalidState
			| TransportError::NotServed
			| TransportError::InvalidCertificate(_)
			| TransportError::InvalidLimits(_)
			| TransportError::MessageNotSent(..)
			| TransportError::HandshakeError(_) => None,
			#[cfg(feature = "transport-multiplex")]
			TransportError::Draining => None,
			#[cfg(feature = "std")]
			TransportError::IoError(_) => None,
		}
	}

	/// Whether this error is the refusal of a send cipher at its record
	/// limit, with the frame or without it.
	#[cfg(feature = "instrument")]
	#[must_use]
	pub(crate) fn at_record_limit(&self) -> bool {
		match self {
			TransportError::MessageNotSent(_, failure) | TransportError::OperationFailed(failure) => {
				*failure == TransportFailure::RekeyRequired
			}
			TransportError::ConnectionClosed
			| TransportError::PeerClosedBeforeHandshake
			| TransportError::ConnectionFailed
			| TransportError::SendFailed
			| TransportError::MissingEncryption
			| TransportError::UnsupportedHandshakeProtocol(_)
			| TransportError::MissingServerCertificateChain
			| TransportError::MissingKeyAgreementIdentity
			| TransportError::PeerAuthenticationUnconfigured
			| TransportError::InvalidMessage
			| TransportError::InvalidReply
			| TransportError::MissingRequest
			| TransportError::MaxRetriesExceeded
			| TransportError::InvalidAddress
			| TransportError::InvalidState
			| TransportError::NotServed
			| TransportError::InvalidCertificate(_)
			| TransportError::InvalidLimits(_)
			| TransportError::HandshakeError(_)
			| TransportError::DerError(_) => false,
			#[cfg(feature = "transport-multiplex")]
			TransportError::Draining => false,
			#[cfg(feature = "std")]
			TransportError::IoError(_) => false,
		}
	}

	/// Report whether this error leaves the stream of an exchange unsound, so
	/// the caller discards the connection and establishes a new one.
	///
	/// It is the complement of the faults that prove the frame never left, so
	/// every other error ends the stream: a close, a deadline, an I/O failure,
	/// a handshake failure, and a decode or size refusal of an answer.
	///
	/// # Domain
	///
	/// The predicate reads the error that one exchange of a transport returns,
	/// as [`MessageEmitter::perform_send_receive`] hands it back, before any
	/// status the peer answered becomes an error. An error that a
	/// [`TransitStatus`] builds after a whole exchange, such as the peer's
	/// `Unavailable`, is outside it.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::transport::{TransportError, TransportFailure};
	///
	/// // A deadline after the write leaves an answer on its way.
	/// let expired = TransportError::OperationFailed(TransportFailure::DeadlineExceeded);
	/// assert!(expired.is_connection_error());
	///
	/// // A missing encryptor refuses before the write.
	/// let unsent = TransportError::OperationFailed(TransportFailure::EncryptorUnavailable);
	/// assert!(!unsent.is_connection_error());
	/// ```
	///
	/// [`MessageEmitter::perform_send_receive`]: crate::transport::MessageEmitter::perform_send_receive
	#[must_use]
	pub fn is_connection_error(&self) -> bool {
		!self.proves_unsent()
	}
}

/// Lift a failure that carries no frame into its error.
///
/// Encoding and size failures map to [`TransportError::InvalidMessage`], a
/// policy failure to [`TransportError::InvalidReply`], and a nonce failure to
/// [`TransportError::SendFailed`]. Every other failure maps to
/// [`TransportError::OperationFailed`].
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

	/// Whether this failure leaves its session unable to send again, so a
	/// resend on that session can never succeed: the send cipher is at its
	/// record limit ([RFC 9846 § 5.5][rfc9846-5.5]).
	///
	/// [rfc9846-5.5]: https://datatracker.ietf.org/doc/html/rfc9846#section-5.5
	pub(crate) const fn spends_the_session(&self) -> bool {
		matches!(self, Self::RekeyRequired)
	}
}

// The audit records of the transport alone name a failure, so the names take
// the gate of those records.
#[cfg(feature = "instrument")]
impl TransportFailure {
	/// The canonical name of the variant, which an audit event uses as a label.
	pub(crate) const fn as_str(&self) -> &'static str {
		match self {
			Self::EncodingFailed => "EncodingFailed",
			Self::EncryptionFailed => "EncryptionFailed",
			Self::SizeExceeded => "SizeExceeded",
			Self::EncryptorUnavailable => "EncryptorUnavailable",
			Self::NonceGenerationFailed => "NonceGenerationFailed",
			Self::RekeyRequired => "RekeyRequired",
			Self::RenewalBoundExceeded => "RenewalBoundExceeded",
			Self::TamperDetected => "TamperDetected",
			Self::StreamsExhausted => "StreamsExhausted",
			Self::BudgetExhausted => "BudgetExhausted",
			Self::PolicyRejection => "PolicyRejection",
			Self::Cancelled => "Cancelled",
			Self::Unknown => "Unknown",
			Self::InvalidArgument => "InvalidArgument",
			Self::DeadlineExceeded => "DeadlineExceeded",
			Self::NotFound => "NotFound",
			Self::AlreadyExists => "AlreadyExists",
			Self::PermissionDenied => "PermissionDenied",
			Self::ResourceExhausted => "ResourceExhausted",
			Self::FailedPrecondition => "FailedPrecondition",
			Self::Aborted => "Aborted",
			Self::OutOfRange => "OutOfRange",
			Self::Unimplemented => "Unimplemented",
			Self::Internal => "Internal",
			Self::Unavailable => "Unavailable",
			Self::DataLoss => "DataLoss",
			Self::Unauthenticated => "Unauthenticated",
		}
	}

	/// Whether a read that fails with this failure refuses the envelope that
	/// arrived: one past its ceiling, out of sequence, past a renewal bound of
	/// the receive key, or a record on a session with no keys.
	const fn refuses_arrival(&self) -> bool {
		match self {
			Self::SizeExceeded | Self::TamperDetected | Self::RenewalBoundExceeded | Self::EncryptionFailed => true,
			Self::EncodingFailed
			| Self::RekeyRequired
			| Self::EncryptorUnavailable
			| Self::NonceGenerationFailed
			| Self::StreamsExhausted
			| Self::BudgetExhausted
			| Self::PolicyRejection
			| Self::Cancelled
			| Self::Unknown
			| Self::InvalidArgument
			| Self::DeadlineExceeded
			| Self::NotFound
			| Self::AlreadyExists
			| Self::PermissionDenied
			| Self::ResourceExhausted
			| Self::FailedPrecondition
			| Self::Aborted
			| Self::OutOfRange
			| Self::Unimplemented
			| Self::Internal
			| Self::Unavailable
			| Self::DataLoss
			| Self::Unauthenticated => false,
		}
	}
}

#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
impl TransportError {
	/// The audit record of a handshake whose outcome is this error, or `None`
	/// for an error that names no record, such as a state error.
	///
	/// - A handshake error files the record that [`HandshakeError::audit`] names.
	/// - A refused certificate files its cause, as the handshake error of a refused certificate does.
	/// - A deadline that ends the handshake files its expiry.
	/// - A close, an I/O failure, a local fault, and every other failure answer `None`.
	pub(crate) fn handshake_audit(&self) -> Option<HandshakeAudit> {
		match self {
			TransportError::HandshakeError(error) => error.audit(),
			TransportError::InvalidCertificate(cause) => Some(HandshakeAudit::IdentityRefused(cause.refusal_label())),
			TransportError::OperationFailed(TransportFailure::DeadlineExceeded) => Some(HandshakeAudit::Expired),
			TransportError::OperationFailed(_)
			| TransportError::ConnectionClosed
			| TransportError::PeerClosedBeforeHandshake
			| TransportError::ConnectionFailed
			| TransportError::SendFailed
			| TransportError::MissingEncryption
			| TransportError::UnsupportedHandshakeProtocol(_)
			| TransportError::MissingServerCertificateChain
			| TransportError::MissingKeyAgreementIdentity
			| TransportError::PeerAuthenticationUnconfigured
			| TransportError::InvalidMessage
			| TransportError::InvalidReply
			| TransportError::MissingRequest
			| TransportError::MaxRetriesExceeded
			| TransportError::InvalidAddress
			| TransportError::InvalidState
			| TransportError::NotServed
			| TransportError::InvalidLimits(_)
			| TransportError::MessageNotSent(..)
			| TransportError::DerError(_) => None,
			#[cfg(feature = "transport-multiplex")]
			TransportError::Draining => None,
			#[cfg(feature = "std")]
			TransportError::IoError(_) => None,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A refusal status and the failure it surfaces as.
	type StatusMappingCase = (TransitStatus, TransportFailure);

	// Each refusal status surfaces as its failure.
	crate::tb_cases! {
		fn a_refusal_status_surfaces_as_its_failure((status, expected): StatusMappingCase) {
			let error = TransportError::from(status);
			assert!(matches!(error, TransportError::OperationFailed(failure) if failure == expected));
		}
		cases {
			cancelled => (TransitStatus::Cancelled, TransportFailure::Cancelled),
			unknown => (TransitStatus::Unknown, TransportFailure::Unknown),
			invalid_argument => (TransitStatus::InvalidArgument, TransportFailure::InvalidArgument),
			deadline_exceeded => (TransitStatus::DeadlineExceeded, TransportFailure::DeadlineExceeded),
			not_found => (TransitStatus::NotFound, TransportFailure::NotFound),
			already_exists => (TransitStatus::AlreadyExists, TransportFailure::AlreadyExists),
			permission_denied => (TransitStatus::PermissionDenied, TransportFailure::PermissionDenied),
			resource_exhausted => (TransitStatus::ResourceExhausted, TransportFailure::ResourceExhausted),
			failed_precondition => (TransitStatus::FailedPrecondition, TransportFailure::FailedPrecondition),
			aborted => (TransitStatus::Aborted, TransportFailure::Aborted),
			out_of_range => (TransitStatus::OutOfRange, TransportFailure::OutOfRange),
			unimplemented => (TransitStatus::Unimplemented, TransportFailure::Unimplemented),
			internal => (TransitStatus::Internal, TransportFailure::Internal),
			unavailable => (TransitStatus::Unavailable, TransportFailure::Unavailable),
			data_loss => (TransitStatus::DataLoss, TransportFailure::DataLoss),
			unauthenticated => (TransitStatus::Unauthenticated, TransportFailure::Unauthenticated),
		}
	}

	// Each failure of a refusal status relays as that status.
	crate::tb_cases! {
		fn a_refusal_failure_relays_as_its_status((status, failure): StatusMappingCase) {
			let relayed = TransitStatus::try_from(failure);
			assert!(matches!(relayed, Ok(relayed) if relayed == status));
		}
		cases {
			cancelled => (TransitStatus::Cancelled, TransportFailure::Cancelled),
			unknown => (TransitStatus::Unknown, TransportFailure::Unknown),
			invalid_argument => (TransitStatus::InvalidArgument, TransportFailure::InvalidArgument),
			deadline_exceeded => (TransitStatus::DeadlineExceeded, TransportFailure::DeadlineExceeded),
			not_found => (TransitStatus::NotFound, TransportFailure::NotFound),
			already_exists => (TransitStatus::AlreadyExists, TransportFailure::AlreadyExists),
			permission_denied => (TransitStatus::PermissionDenied, TransportFailure::PermissionDenied),
			resource_exhausted => (TransitStatus::ResourceExhausted, TransportFailure::ResourceExhausted),
			failed_precondition => (TransitStatus::FailedPrecondition, TransportFailure::FailedPrecondition),
			aborted => (TransitStatus::Aborted, TransportFailure::Aborted),
			out_of_range => (TransitStatus::OutOfRange, TransportFailure::OutOfRange),
			unimplemented => (TransitStatus::Unimplemented, TransportFailure::Unimplemented),
			internal => (TransitStatus::Internal, TransportFailure::Internal),
			unavailable => (TransitStatus::Unavailable, TransportFailure::Unavailable),
			data_loss => (TransitStatus::DataLoss, TransportFailure::DataLoss),
			unauthenticated => (TransitStatus::Unauthenticated, TransportFailure::Unauthenticated),
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

	// An error of one exchange ends the stream unless it proves the frame never
	// left, so a decode or size refusal of an answer ends it too.
	crate::tb_cases! {
		fn is_connection_error_of((error, expected): (TransportError, bool)) -> Result<()> {
			assert_eq!(error.is_connection_error(), expected);
			Ok(())
		}
		cases {
			a_close_ends_the_stream => (TransportError::ConnectionClosed, true),
			a_deadline_ends_the_stream => (TransportError::OperationFailed(TransportFailure::DeadlineExceeded), true),
			an_undecodable_answer_ends_the_stream => (TransportError::InvalidMessage, true),
			an_answer_past_its_ceiling_ends_the_stream => (
				TransportError::OperationFailed(TransportFailure::SizeExceeded),
				true
			),
			a_malformed_answer_ends_the_stream => (TransportError::DerError(der::Error::from(der::ErrorKind::Failed)), true),
			a_failed_nonce_keeps_the_stream => (TransportError::SendFailed, false),
			a_missing_encryptor_keeps_the_stream => (
				TransportError::OperationFailed(TransportFailure::EncryptorUnavailable),
				false
			),
			a_spent_budget_keeps_the_stream => (TransportError::OperationFailed(TransportFailure::BudgetExhausted), false),
			a_send_past_the_record_limit_keeps_the_stream => (
				TransportFailure::RekeyRequired.with_frame(crate::testing::TestFrame::prioritized()),
				false
			),
			an_answer_past_the_record_limit_ends_the_stream => (
				TransportError::OperationFailed(TransportFailure::RenewalBoundExceeded),
				true
			),
			a_collect_on_a_spent_send_cipher_ends_the_stream => (
				TransportError::OperationFailed(TransportFailure::RekeyRequired),
				true
			),
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

	/// A poisoned lock is a local fault, so it converts to the `Internal`
	/// failure that a poisoned pool map also fails with.
	#[cfg(feature = "std")]
	#[test]
	fn a_poisoned_lock_converts_to_the_internal_failure() {
		let converted = TransportError::from(TightBeamError::LockPoisoned);
		assert!(matches!(converted, TransportError::OperationFailed(TransportFailure::Internal)));
	}

	// A handler's failure keeps the status it carries, apart from
	// `Unavailable`, which a peer reads as a refusal before any handler ran.
	// A failure that carries no status answers `Internal`.
	#[cfg(all(
		feature = "transport-multiplex",
		any(feature = "tokio", feature = "async-transport")
	))]
	crate::tb_cases! {
		fn failure_status_of((failure, expected): (TransportError, TransitStatus)) {
			let status = failure.failure_status();

			assert_eq!(status, expected);
		}

		cases {
			a_carried_unavailable_is_unknown => (TransitStatus::Unavailable.into(), TransitStatus::Unknown),
			a_carried_refusal_keeps_its_status => (TransitStatus::PermissionDenied.into(), TransitStatus::PermissionDenied),
			a_local_failure_is_internal => (
				TransportError::OperationFailed(TransportFailure::SizeExceeded),
				TransitStatus::Internal
			),
			a_failure_with_no_status_is_internal => (TransportError::ConnectionClosed, TransitStatus::Internal),
			a_kind_not_served_is_unimplemented => (TransportError::NotServed, TransitStatus::Unimplemented),
		}
	}

	// The open of a record names its refusal by the cause of the open: a
	// record of another epoch, a record out of sequence, or any other refusal
	// of the key, which an on-path party chooses before the tag check.
	#[cfg(feature = "instrument")]
	crate::tb_cases! {
		fn a_refused_open_names_its_cause((error, refusal): (TightBeamError, &str)) {
			assert_eq!(ArrivalCause::of_open(error).refusal(), Some(refusal));
		}

		cases {
			of_another_epoch => (TightBeamError::RecordEpoch((1, 0).into()), "WrongEpoch"),
			out_of_sequence => (TightBeamError::NonceReplayed((2, 0).into()), "TamperDetected"),
			past_the_record_limit => (TightBeamError::RenewalBoundExceeded, "OpenFailed"),
			whose_position_does_not_decode => (
				TightBeamError::SerializationError(der::Error::from(der::ErrorKind::Failed)),
				"OpenFailed"
			),
			whose_tag_fails => (crate::crypto::cms::EnvelopeError::Authentication.into(), "OpenFailed"),
		}
	}
}
