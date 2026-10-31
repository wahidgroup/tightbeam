#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::spki::ObjectIdentifier;
use crate::Errorizable;
use crate::Version;

/// A specialized Result type for TightBeam operations.
pub type Result<T> = core::result::Result<T, TightBeamError>;

/// A specialized Result type for compression operations.
#[cfg(feature = "compress")]
pub type CompressionResult<T> = core::result::Result<T, CompressionError>;

/// An error that reports a mismatch between a received and an expected value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReceivedExpectedError<Received, Expected> {
	/// The value that arrived.
	pub received: Received,
	/// The value that the check expected.
	pub expected: Expected,
}

impl<Received, Expected> From<(Received, Expected)> for ReceivedExpectedError<Received, Expected> {
	fn from((received, expected): (Received, Expected)) -> Self {
		Self { received, expected }
	}
}

impl<Received: core::fmt::Debug, Expected: core::fmt::Debug> core::fmt::Display
	for ReceivedExpectedError<Received, Expected>
{
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "expected {:?}, got {:?}", self.expected, self.received)
	}
}

/// Errors that compression and decompression return.
#[cfg(feature = "compress")]
#[derive(Errorizable, Debug)]
pub enum CompressionError {
	#[cfg(feature = "zstd")]
	/// The zstd codec refused the frame, reported as its numeric code.
	///
	/// `zstd_safe::get_error_name` gives zstd's own name for the code.
	#[error("ZSTD compression/decompression error: code {0}")]
	ZSTD(usize),

	/// Bytes remain after the single zstd frame.
	///
	/// A compressed body is exactly one plain frame. Skippable frames and a
	/// seekable-format seek table arrive as trailing input, which the parse
	/// boundary refuses.
	#[cfg(feature = "zstd")]
	#[error("{0} trailing octets after the zstd frame")]
	TrailingBytes(usize),

	/// The input ended before the frame completed.
	#[cfg(feature = "zstd")]
	#[error("zstd frame is truncated")]
	Truncated,

	/// The decoder consumed no input and produced no output.
	///
	/// The decompression loop advances one of its two cursors on every
	/// iteration, and this refusal holds that guarantee (CWE-835).
	#[cfg(feature = "zstd")]
	#[error("zstd decoder stalled without consuming input")]
	Stalled,

	/// An I/O operation failed during compression or decompression.
	#[cfg(feature = "std")]
	#[error("I/O error during compression/decompression: {0}")]
	#[source]
	IO(std::io::Error),

	/// The decompressed output exceeds the byte limit that the variant carries.
	#[cfg(feature = "zstd")]
	#[error("decompressed output exceeds the {0}-byte limit")]
	OutputLimitExceeded(usize),
}

/// An error that a test injects as a fault.
#[cfg(feature = "testing-fault")]
pub trait InjectedError: core::fmt::Debug + core::fmt::Display + Send + Sync {}

#[cfg(feature = "testing-fault")]
impl<T> InjectedError for T where T: core::fmt::Debug + core::fmt::Display + Send + Sync {}

/// The errors collected from one operation.
///
/// The chain owns the rendering of the list through its `Display` impl, so
/// every [`TightBeamError`] message stays a single format string.
#[derive(Debug)]
pub struct ErrorChain(Vec<TightBeamError>);

impl ErrorChain {
	/// Returns the collected errors, in the order they were reported.
	#[must_use]
	pub fn as_slice(&self) -> &[TightBeamError] {
		&self.0
	}

	/// Returns the number of errors the chain holds.
	#[must_use]
	pub fn len(&self) -> usize {
		self.0.len()
	}

	/// Returns whether the chain holds no error.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
}

impl From<Vec<TightBeamError>> for ErrorChain {
	fn from(errors: Vec<TightBeamError>) -> Self {
		Self(errors)
	}
}

impl core::fmt::Display for ErrorChain {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		for (position, error) in self.0.iter().enumerate() {
			if position > 0 {
				write!(f, "; ")?;
			}
			write!(f, "{error}")?;
		}

		Ok(())
	}
}

/// The top-level error type of the crate.
#[derive(Errorizable, Debug)]
#[non_exhaustive]
pub enum TightBeamError {
	/// The matrix implementation reported an error.
	#[error("Matrix error: {0}")]
	#[source]
	MatrixError(crate::matrix::MatrixError),

	/// The router reported an error.
	#[cfg(feature = "router")]
	#[error("Route error: {0}")]
	#[source]
	RouterError(crate::router::RouterError),

	/// The message builder reported an error.
	#[cfg(feature = "builder")]
	#[error("Build error: {0}")]
	#[source]
	BuildError(crate::builder::error::BuildError),

	/// The standards module reported an error.
	#[cfg(feature = "standards")]
	#[error("Standard error: {0}")]
	#[source]
	StandardError(crate::standards::error::StandardError),

	/// A hive reported an error.
	#[cfg(feature = "colony")]
	#[error("Hive error: {0}")]
	#[source]
	HiveError(crate::colony::hive::HiveError),

	/// A cluster gateway reported an error.
	///
	/// `From<ClusterError>` boxes a cluster error into this variant, because a
	/// cluster error can carry a frame error in turn.
	#[cfg(feature = "colony")]
	#[error("Cluster error: {0}")]
	#[source]
	ClusterError(Box<crate::colony::cluster::ClusterError>),

	/// A worker relay reported an error.
	#[cfg(feature = "colony")]
	#[error("Worker relay error: {0}")]
	#[source]
	WorkerRelay(crate::colony::worker::WorkerRelayError),

	#[cfg(feature = "std")]
	/// An I/O operation failed.
	#[error("I/O error: {0}")]
	#[source]
	IoError(std::io::Error),

	#[cfg(feature = "std")]
	/// A lock is poisoned.
	#[error("Lock poisoned")]
	LockPoisoned,

	/// The algorithm identifier is invalid or unsupported.
	#[error("Invalid or unsupported object identifier: {0}")]
	InvalidOID(crate::der::oid::Error),

	/// Signature verification or generation failed.
	#[cfg(feature = "signature")]
	#[error("Signature verification or generation error: {0}")]
	#[source]
	SignatureError(crate::crypto::sign::Error),

	/// An elliptic curve operation failed.
	#[cfg(feature = "signature")]
	#[error("Elliptic curve error: {0}")]
	#[source]
	EllipticCurveError(crate::crypto::sign::elliptic_curve::Error),

	/// Serialization failed.
	#[error("Serialization error: {0}")]
	#[source]
	SerializationError(crate::der::Error),

	/// Compression or decompression failed.
	#[cfg(feature = "compress")]
	#[error("Compression error: {0}")]
	#[source]
	CompressionError(CompressionError),

	/// A handshake operation failed.
	#[cfg(feature = "transport")]
	#[error("Handshake error: {0}")]
	#[source]
	HandshakeError(crate::transport::handshake::HandshakeError),

	/// The transport reported an error.
	#[cfg(feature = "transport")]
	#[error("Transport error: {0}")]
	#[source]
	TransportError(crate::transport::error::TransportError),

	/// The protocol version is not supported.
	#[error("Unsupported protocol version: {0}")]
	UnsupportedVersion(ReceivedExpectedError<Version, Version>),

	/// A frame carries a field that its version forbids (README §5.6).
	///
	/// `field` names the field, and `version` names the frame version, which
	/// is below [`GatedField::since`](crate::asn1::GatedField::since) of the
	/// field. The frame build and every change to a frame in place refuse
	/// with it.
	///
	/// # Examples
	///
	/// ```
	/// # #[cfg(feature = "builder")]
	/// # {
	/// use tightbeam::asn1::GatedField;
	/// use tightbeam::prelude::MatrixDyn;
	/// use tightbeam::testing::TestMessage;
	/// use tightbeam::{compose, TightBeamError, Version};
	///
	/// let refused = compose! {
	///     V2: id: "grid", order: 1u64, message: TestMessage::sample(None), matrix: MatrixDyn::default()
	/// };
	///
	/// assert!(matches!(
	///     refused,
	///     Err(TightBeamError::UnsupportedField { field: GatedField::Matrix, version: Version::V2 })
	/// ));
	/// # }
	/// ```
	#[error("Field {field} is not supported in protocol version {version:?}")]
	UnsupportedField { field: crate::asn1::GatedField, version: Version },

	/// A testing operation failed.
	#[cfg(feature = "testing")]
	#[error("Testing error: {0}")]
	#[source]
	TestingError(crate::testing::error::TestingError),

	/// URN validation failed.
	#[error("URN validation error: {0}")]
	#[source]
	UrnValidationError(crate::urn::UrnValidationError),

	/// Encryption or decryption failed.
	#[cfg(feature = "aead")]
	#[error("Encryption or decryption error: {0}")]
	#[source]
	EncryptionError(crate::crypto::aead::Error),

	/// The key length is invalid for the cryptographic operation.
	#[cfg(feature = "aead")]
	#[error("Invalid key length: {0}")]
	#[source]
	InvalidKeyLength(crypto_common::InvalidLength),

	/// An HPKE operation failed.
	#[cfg(feature = "hpke")]
	#[error("HPKE error: {0}")]
	#[source]
	HpkeError(crate::crypto::hpke::HpkeError),

	/// An authenticated envelope failed to seal, or refused to open.
	#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	#[error("Authenticated envelope error: {0}")]
	#[source]
	EnvelopeError(crate::crypto::cms::EnvelopeError),

	/// Certificate validation failed.
	#[cfg(feature = "x509")]
	#[error("Certificate validation error: {0}")]
	#[source]
	CertificateValidationError(crate::crypto::x509::error::CertificateValidationError),

	/// A key list, such as a pin list or a peer list, refused an entry it
	/// was built from.
	#[cfg(feature = "x509")]
	#[error("Key list error: {0}")]
	#[source]
	KeyListError(crate::crypto::x509::KeyListError),

	/// Key derivation failed.
	#[cfg(feature = "kdf")]
	#[error("Key derivation error: {0}")]
	#[source]
	KeyDerivationError(crate::crypto::kdf::KdfError),

	/// A key provider operation failed.
	#[cfg(feature = "crypto")]
	#[error("Key provider error: {0}")]
	#[source]
	KeyError(crate::crypto::key::KeyError),

	/// The OS failed to provide random bytes.
	#[cfg(feature = "random")]
	#[error("OS random number generator error: {0}")]
	#[source]
	OsRngError(rand_core::Error),

	/// An SPKI operation failed.
	#[cfg(feature = "x509")]
	#[error("SPKI error: {0}")]
	#[source]
	SpkiError(crate::spki::Error),

	/// The X.509 certificate builder failed.
	#[cfg(feature = "builder")]
	#[error("X.509 builder error: {0}")]
	#[source]
	X509BuilderError(x509_cert::builder::Error),

	/// A channel receive with a timeout failed.
	#[cfg(feature = "std")]
	#[error("Channel receive timeout error")]
	RecvTimeoutError,

	/// The signature bytes failed to decode.
	#[cfg(feature = "signature")]
	#[error("Signature encoding error")]
	SignatureEncodingError,

	/// A CMS signature or `SignedData` breaks a rule of the CMS signer: its
	/// signer, version, signed attributes, `digestAlgorithms`, or content, or
	/// a key that differs from its certificate or has no supported algorithm.
	#[cfg(feature = "signature")]
	#[error("CMS signer error: {0}")]
	#[source]
	Signer(crate::crypto::sign::SignerError),

	/// The metadata is invalid.
	#[error("Invalid metadata")]
	InvalidMetadata,

	/// The message body is invalid.
	#[error("Invalid message body")]
	InvalidBody,

	/// The overflow value is invalid.
	#[error("Invalid overflow value")]
	InvalidOverflowValue,

	/// The order is invalid.
	#[error("Invalid order")]
	InvalidOrder,

	/// The order is missing.
	#[error("Missing order")]
	MissingOrder,

	/// The inflator is missing.
	#[error("Missing inflator")]
	MissingInflator,

	/// A required feature is missing.
	#[error("Missing feature: {0}")]
	MissingFeature(&'static str),

	/// A message type's marker requires a protection that the builder lacks.
	///
	/// `marker` names the [`Message`](crate::core::Message) constant, and
	/// `call` names the builder method that satisfies it.
	#[error("{marker} requires {call} before build")]
	MissingProtection { marker: &'static str, call: &'static str },

	/// A Frame fails a requirement of the message type it carries.
	#[error("Requirement error: {0}")]
	#[source]
	Requirement(crate::core::RequirementError),

	/// A typed decode reads a Frame body that still needs the named transform:
	/// a decrypt for an encrypted body, or an inflate for a compressed one.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::asn1::BodyTransform;
	/// use tightbeam::TightBeamError;
	///
	/// let refused = TightBeamError::OpaqueBody(BodyTransform::Decrypt);
	/// assert_eq!(refused.to_string(), "Frame body needs a decrypt before a decode");
	/// ```
	#[error("Frame body needs a {0} before a decode")]
	OpaqueBody(crate::frame::BodyTransform),

	/// The response is missing.
	#[error("Missing response")]
	MissingResponse,

	/// The cluster refused the work. The gateway reported a non-`Ok` transit
	/// status in place of a servlet response frame.
	#[cfg(feature = "policy")]
	#[error("Work refused: {0:?}")]
	WorkRefused(crate::policy::TransitStatus),

	/// The other end of a channel is gone: the receiving end dropped before a
	/// send, or the sending end dropped before it sent.
	#[error("Channel closed")]
	ChannelClosed,

	/// The signature is missing.
	#[cfg(feature = "signature")]
	#[error("Missing signature")]
	MissingSignature,

	/// The signature info is missing.
	#[cfg(feature = "signature")]
	#[error("Missing signature info")]
	MissingSignatureInfo,

	/// The encryption info is missing.
	#[cfg(feature = "aead")]
	#[error("Missing encryption info")]
	MissingEncryptionInfo,

	/// The frame carries an FI digest or a signature, which cover the frame
	/// as it is before a seal rewrites its metadata and its body.
	#[cfg(feature = "aead")]
	#[error("Frame is digested or signed before the seal")]
	CoveredBeforeSeal,

	/// The commitment salt is shorter than the hiding floor.
	#[cfg(feature = "digest")]
	#[error("Invalid commitment salt length: {0}")]
	InvalidSaltLength(ReceivedExpectedError<usize, usize>),

	/// The send-direction record sequence space is exhausted.
	#[cfg(feature = "aead")]
	#[error("Record sequence space exhausted")]
	NonceExhausted,

	/// The send cipher is at the record limit of its key (RFC 9846 § 5.5).
	#[cfg(feature = "aead")]
	#[error("Record limit reached: reestablish the session to rekey")]
	RekeyRequired,

	/// A received record passes a renewal bound of its receive key: its
	/// sequence number reaches the record limit, or its bytes take the key
	/// past the renewal volume. An honest sender renews before either bound.
	#[cfg(feature = "aead")]
	#[error("Record past a renewal bound of the receive key")]
	RenewalBoundExceeded,

	/// A received record carries another sequence number than the exact
	/// next, which signals a replay, a reorder, or a deletion.
	#[cfg(feature = "aead")]
	#[error("Out-of-sequence record: {0}")]
	NonceReplayed(ReceivedExpectedError<u64, u64>),

	/// A received record carries another epoch than the key that opens it.
	#[cfg(feature = "aead")]
	#[error("Record of another epoch: {0}")]
	RecordEpoch(ReceivedExpectedError<u32, u32>),

	/// The integrity info is missing.
	#[cfg(feature = "digest")]
	#[error("Missing integrity info")]
	MissingDigestInfo,

	/// The algorithm is invalid for the message profile.
	#[error("Invalid algorithm for message profile")]
	InvalidAlgorithm,

	/// The algorithm is unexpected for the message profile.
	#[error("Unexpected algorithm for message profile: {0}")]
	UnexpectedAlgorithm(ReceivedExpectedError<ObjectIdentifier, ObjectIdentifier>),

	/// The configuration is missing or invalid.
	#[error("Missing configuration")]
	MissingConfiguration,

	/// The hive is already established.
	#[cfg(feature = "colony")]
	#[error("Hive already established")]
	AlreadyEstablished,

	/// The hive is not established yet.
	///
	/// Cluster registration and other control-plane operations require a bound
	/// control listener. Call
	/// [`Hive::establish`](crate::colony::hive::Hive::establish) first so the
	/// registered address matches the live accept socket.
	#[cfg(feature = "colony")]
	#[error("Hive not established")]
	NotEstablished,

	/// A task join failed.
	#[cfg(feature = "colony")]
	#[error("Task join failed")]
	JoinError,

	/// One operation collected the errors that the chain holds.
	#[error("Multiple errors occurred: {0}")]
	Sequence(ErrorChain),

	/// A fault injected for testing, which can wrap any error type.
	#[cfg(feature = "testing-fault")]
	#[error("Injected fault: {0}")]
	InjectedFault(Box<dyn InjectedError>),
}

crate::impl_from!(der::Error => TightBeamError::SerializationError);
crate::impl_from!(crate::matrix::MatrixError => TightBeamError::MatrixError);
crate::impl_from!(crate::urn::UrnValidationError => TightBeamError::UrnValidationError);

#[cfg(feature = "std")]
crate::impl_from!(std::string::FromUtf8Error => TightBeamError::IoError via |err| std::io::Error::new(std::io::ErrorKind::InvalidData, err));
#[cfg(feature = "std")]
crate::impl_from!(std::net::AddrParseError => TightBeamError::IoError via |err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err));
#[cfg(feature = "kdf")]
crate::impl_from!(crate::crypto::kdf::KdfError => TightBeamError::KeyDerivationError);
#[cfg(feature = "crypto")]
crate::impl_from!(crate::crypto::key::KeyError => TightBeamError::KeyError);
#[cfg(feature = "std")]
crate::impl_from!(std::io::Error => TightBeamError::IoError);
crate::impl_from!(crate::core::RequirementError => TightBeamError::Requirement);
#[cfg(feature = "router")]
crate::impl_from!(crate::router::RouterError => TightBeamError::RouterError);
#[cfg(feature = "builder")]
crate::impl_from!(crate::builder::error::BuildError => TightBeamError::BuildError);
#[cfg(feature = "standards")]
crate::impl_from!(crate::standards::error::StandardError => TightBeamError::StandardError);
#[cfg(feature = "colony")]
crate::impl_from!(crate::colony::hive::HiveError => TightBeamError::HiveError);
#[cfg(feature = "colony")]
crate::impl_from!(crate::colony::worker::WorkerRelayError => TightBeamError::WorkerRelay);

#[cfg(feature = "colony")]
impl From<crate::colony::cluster::ClusterError> for TightBeamError {
	fn from(error: crate::colony::cluster::ClusterError) -> Self {
		Self::ClusterError(Box::new(error))
	}
}
#[cfg(feature = "transport")]
crate::impl_from!(crate::transport::handshake::HandshakeError => TightBeamError::HandshakeError);
#[cfg(feature = "transport")]
crate::impl_from!(crate::transport::error::TransportError => TightBeamError::TransportError);
#[cfg(feature = "random")]
crate::impl_from!(rand_core::Error => TightBeamError::OsRngError);
#[cfg(feature = "x509")]
crate::impl_from!(crate::crypto::x509::error::CertificateValidationError => TightBeamError::CertificateValidationError);
#[cfg(feature = "x509")]
crate::impl_from!(crate::crypto::x509::KeyListError => TightBeamError::KeyListError);
#[cfg(feature = "x509")]
crate::impl_from!(spki::Error => TightBeamError::SpkiError);
#[cfg(feature = "builder")]
crate::impl_from!(x509_cert::builder::Error => TightBeamError::X509BuilderError);
#[cfg(feature = "compress")]
crate::impl_from!(CompressionError => TightBeamError::CompressionError);
#[cfg(all(feature = "std", feature = "compress"))]
crate::impl_from!(std::io::Error => CompressionError::IO);
#[cfg(feature = "aead")]
crate::impl_from!(aead::Error => TightBeamError::EncryptionError);
#[cfg(feature = "aead")]
crate::impl_from!(crypto_common::InvalidLength => TightBeamError::InvalidKeyLength);
#[cfg(feature = "hpke")]
crate::impl_from!(crate::crypto::hpke::HpkeError => TightBeamError::HpkeError);
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
crate::impl_from!(crate::crypto::cms::EnvelopeError => TightBeamError::EnvelopeError);
#[cfg(feature = "signature")]
crate::impl_from!(signature::Error => TightBeamError::SignatureError);
#[cfg(feature = "signature")]
crate::impl_from!(crate::crypto::sign::elliptic_curve::Error => TightBeamError::EllipticCurveError);
#[cfg(feature = "testing")]
crate::impl_from!(crate::testing::error::TestingError => TightBeamError::TestingError);
#[cfg(feature = "std")]
crate::impl_from!(std::sync::mpsc::RecvTimeoutError => TightBeamError::RecvTimeoutError discard);
#[cfg(feature = "std")]
crate::impl_from!(crate::runtime::ChannelClosed => TightBeamError::ChannelClosed discard);

#[cfg(feature = "transport")]
impl TightBeamError {
	/// Wraps a protocol error as this crate's transport error.
	///
	/// A protocol reports its own error type, bound to convert into
	/// [`TransportError`], so the cluster and servlet bind sites map through
	/// this one constructor.
	///
	/// [`TransportError`]: crate::transport::error::TransportError
	#[must_use]
	pub fn transport(error: impl Into<crate::transport::error::TransportError>) -> Self {
		let transport = error.into();
		Self::TransportError(transport)
	}

	/// Returns whether this error is a fuzz iteration running out of input.
	///
	/// AFL feeds short inputs constantly. An iteration whose oracle runs out of
	/// bytes before a terminal state exercises only a prefix, so its trace is
	/// incomplete and its assertions describe events its input never reached.
	#[must_use]
	pub fn is_fuzz_input_exhausted(&self) -> bool {
		#[cfg(feature = "testing")]
		{
			matches!(
				self,
				TightBeamError::TestingError(crate::testing::error::TestingError::FuzzInputExhausted)
			)
		}

		#[cfg(not(feature = "testing"))]
		{
			false
		}
	}

	/// Returns the terminal status that a service failure answers a peer with.
	///
	/// - A failure that carries a transit status keeps it, apart from [`TransitStatus::Unavailable`].
	/// - A carried `Unavailable` answers [`TransitStatus::Unknown`], because
	///   the handler ran until it failed. A peer reads `Unavailable` as a
	///   gate's refusal before any handler ran, and a gateway retries that
	///   frame on another instance.
	/// - A kind or an operation that the endpoint leaves out answers [`TransitStatus::Unimplemented`].
	/// - Any other failure answers [`TransitStatus::Internal`], so a peer
	///   tells a failure apart from an accepted empty reply and the failure
	///   stays attributable.
	///
	/// [`TransitStatus::Internal`]: crate::policy::TransitStatus::Internal
	/// [`TransitStatus::Unavailable`]: crate::policy::TransitStatus::Unavailable
	/// [`TransitStatus::Unimplemented`]: crate::policy::TransitStatus::Unimplemented
	/// [`TransitStatus::Unknown`]: crate::policy::TransitStatus::Unknown
	#[cfg(pooled_mux)]
	#[must_use]
	pub(crate) fn failure_status(&self) -> crate::policy::TransitStatus {
		use crate::policy::TransitStatus;

		let TightBeamError::TransportError(error) = self else {
			return TransitStatus::Internal;
		};

		error.failure_status()
	}

	/// Returns the refusal behind every [`MuxService`] default: the kind or
	/// the operation that a call names is not served, which a peer reads as
	/// `Unimplemented`.
	///
	/// [`MuxService`]: crate::transport::multiplex::MuxService
	#[cfg(pooled_mux)]
	#[must_use]
	pub(crate) fn unimplemented() -> Self {
		crate::transport::TransportError::NotServed.into()
	}
}

/// The signer's encoding, key, certificate, signature, and algorithm failures
/// map to the variants this enum names for them, so a caller matches one
/// variant per cause whichever path it took.
#[cfg(feature = "signature")]
impl From<crate::crypto::sign::SignerError> for TightBeamError {
	fn from(err: crate::crypto::sign::SignerError) -> Self {
		use crate::crypto::sign::SignerError;

		match err {
			SignerError::Encoding(err) => TightBeamError::SerializationError(err),
			SignerError::PublicKey(err) => TightBeamError::SpkiError(err),
			SignerError::Key(err) => TightBeamError::KeyError(err),
			SignerError::Certificate(err) => TightBeamError::CertificateValidationError(err),
			SignerError::Signature(err) => TightBeamError::SignatureError(err),
			SignerError::UnexpectedAlgorithm(algorithms) => TightBeamError::UnexpectedAlgorithm(algorithms),
			other => TightBeamError::Signer(other),
		}
	}
}

// A generic source type cannot go through `impl_from!`, so this impl writes
// the unit-variant conversion out.
#[cfg(feature = "std")]
impl<T> From<std::sync::PoisonError<T>> for TightBeamError {
	fn from(_: std::sync::PoisonError<T>) -> Self {
		TightBeamError::LockPoisoned
	}
}

#[cfg(all(test, feature = "std"))]
mod tests {
	use super::*;
	#[cfg(feature = "x509")]
	use crate::crypto::x509::{policy::PublicKeyPinning, KeyListError};
	use crate::matrix::MatrixError;
	#[cfg(pooled_mux)]
	use crate::policy::TransitStatus;

	/// A matrix error converts into the wrapper variant that carries it.
	#[test]
	fn a_matrix_error_converts_into_its_wrapper() {
		let err = TightBeamError::from(crate::matrix::MatrixError::InvalidN(0));
		assert!(matches!(
			err,
			TightBeamError::MatrixError(crate::matrix::MatrixError::InvalidN(0))
		));
	}

	// A wrapper annotated with its source exposes the error it wraps as the
	// source, and a unit variant exposes none.
	crate::tb_cases! {
		fn a_source_annotation_exposes_the_cause((err, cause): (TightBeamError, Option<MatrixError>)) {
			let source = core::error::Error::source(&err);
			let exposed = source.and_then(|source| source.downcast_ref::<MatrixError>());
			assert_eq!(exposed, cause.as_ref());
		}
		cases {
			annotated_wrapper => (TightBeamError::from(MatrixError::InvalidN(0)), Some(MatrixError::InvalidN(0))),
			unit_variant => (TightBeamError::InvalidBody, None),
		}
	}

	// A chain of errors renders each error once, joined by a separator, and a
	// lone error renders with no separator.
	crate::tb_cases! {
		fn error_chain_renders((errors, rendered): (Vec<TightBeamError>, &str)) {
			let wrapped = TightBeamError::Sequence(ErrorChain::from(errors));
			assert_eq!(wrapped.to_string(), rendered);
		}
		cases {
			a_readable_join => (
				vec![TightBeamError::InvalidBody, TightBeamError::MissingOrder],
				"Multiple errors occurred: Invalid message body; Missing order"
			),
			a_lone_error_without_a_separator => (
				vec![TightBeamError::InvalidBody],
				"Multiple errors occurred: Invalid message body"
			),
		}
	}

	// A chain counts the errors it collected, and reads as empty when it
	// collected none.
	crate::tb_cases! {
		fn an_error_chain_counts_its_errors((errors, counted): (Vec<TightBeamError>, (usize, bool))) {
			let chain = ErrorChain::from(errors);
			assert_eq!((chain.len(), chain.is_empty()), counted);
		}
		cases {
			two_errors => (vec![TightBeamError::InvalidBody, TightBeamError::MissingOrder], (2, false)),
			no_error => (Vec::new(), (0, true)),
		}
	}

	/// A runtime channel whose other end is gone converts into the channel
	/// error of the crate, so `?` carries the fact under one name.
	#[test]
	fn a_closed_runtime_channel_converts_into_the_channel_error() {
		let converted = TightBeamError::from(crate::runtime::ChannelClosed);
		assert!(matches!(converted, TightBeamError::ChannelClosed));
	}

	/// A protocol error converts into the transport error it names, and the
	/// crate error carries the converted error.
	#[cfg(all(feature = "transport", feature = "policy"))]
	#[test]
	fn transport_wraps_the_converted_protocol_error() {
		use crate::policy::TransitStatus;
		use crate::transport::error::TransportError::OperationFailed;
		use crate::transport::error::TransportFailure;

		let err = TightBeamError::transport(TransitStatus::Unimplemented);
		assert!(matches!(
			err,
			TightBeamError::TransportError(OperationFailed(TransportFailure::Unimplemented))
		));
	}

	/// The pin list that `pins` builds, through the `?` that carries a refusal
	/// into the crate error.
	#[cfg(feature = "x509")]
	fn pinned(pins: &[&[u8]]) -> Result<PublicKeyPinning> {
		Ok(PublicKeyPinning::new(pins)?)
	}

	/// A pin list's refusal reaches the crate error under its own name, so a
	/// caller propagates it with `?` wherever `x509` builds.
	#[cfg(feature = "x509")]
	#[test]
	fn a_key_list_refusal_propagates_under_its_own_name() {
		let refused = pinned(&[b"no SubjectPublicKeyInfo"]);

		let expected = KeyListError::Unreadable { index: 0 };
		let unreadable = matches!(refused, Err(TightBeamError::KeyListError(found)) if found == expected);
		assert!(unreadable);
	}

	// A handler's failure keeps the status it carries, apart from
	// `Unavailable`, which a peer reads as a refusal before any handler ran.
	// A failure that carries no status answers `Internal`.
	#[cfg(pooled_mux)]
	crate::tb_cases! {
		fn failure_status_of((failure, expected): (TightBeamError, TransitStatus)) {
			let status = failure.failure_status();
			assert_eq!(status, expected);
		}

		cases {
			a_carried_unavailable_is_unknown => (TransitStatus::Unavailable.refusal(), TransitStatus::Unknown),
			a_carried_refusal_keeps_its_status => (
				TransitStatus::PermissionDenied.refusal(),
				TransitStatus::PermissionDenied
			),
			a_failure_with_no_status_is_internal => (TightBeamError::InvalidBody, TransitStatus::Internal),
		}
	}
}
