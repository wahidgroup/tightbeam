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

/// Error indicating a mismatch between received and expected values.
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
	/// `zstd_safe::get_error_name` renders the code as zstd's own name for
	/// the condition.
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

/// Trait for injected faults in testing.
#[cfg(feature = "testing-fault")]
pub trait InjectedError: core::fmt::Debug + core::fmt::Display + Send + Sync {}

#[cfg(feature = "testing-fault")]
impl<T> InjectedError for T where T: core::fmt::Debug + core::fmt::Display + Send + Sync {}

/// Several errors collected from one operation.
///
/// Rendering the list is behavior of the collection, so the chain owns it.
/// That keeps every [`TightBeamError`] message a single format string, and
/// the one Display block below stays the only home for all of them.
#[derive(Debug)]
pub struct ErrorChain(Vec<TightBeamError>);

impl ErrorChain {
	/// The collected errors, in the order they were reported.
	#[must_use]
	pub fn as_slice(&self) -> &[TightBeamError] {
		&self.0
	}

	/// How many errors the chain holds.
	#[must_use]
	pub fn len(&self) -> usize {
		self.0.len()
	}

	/// Whether the chain holds no error.
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

	/// A testing operation failed.
	#[cfg(feature = "testing")]
	#[error("Testing error: {0}")]
	#[source]
	TestingError(crate::testing::error::TestingError),

	/// URN validation failed.
	#[error("URN validation error: {0}")]
	#[source]
	UrnValidationError(crate::utils::urn::UrnValidationError),

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

	/// An ECIES operation failed.
	#[cfg(feature = "ecies")]
	#[error("ECIES error: {0}")]
	#[source]
	EciesError(crate::crypto::ecies::EciesError),

	/// Certificate validation failed.
	#[cfg(feature = "x509")]
	#[error("Certificate validation error: {0}")]
	#[source]
	CertificateValidationError(crate::crypto::x509::error::CertificateValidationError),

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

	/// Building an X.509 certificate failed.
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

	/// A message type's marker requires a protection the builder was not
	/// given.
	///
	/// `marker` names the [`Message`](crate::core::Message) constant and
	/// `call` the builder method that satisfies it.
	#[error("{marker} requires {call} before build")]
	MissingProtection { marker: &'static str, call: &'static str },

	/// The response is missing.
	#[error("Missing response")]
	MissingResponse,

	/// The cluster refused the work. The gateway reported a non-`Ok` transit
	/// status in place of a servlet response frame.
	#[cfg(feature = "policy")]
	#[error("Work refused: {0:?}")]
	WorkRefused(crate::policy::TransitStatus),

	/// Channel closed because the receiving end was dropped before the send.
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

	/// The AEAD nonce length does not match the nonce size of the cipher.
	#[cfg(feature = "aead")]
	#[error("Invalid AEAD nonce length: {0}")]
	InvalidNonceLength(ReceivedExpectedError<usize, usize>),

	/// The commitment salt is shorter than the hiding floor.
	#[cfg(feature = "digest")]
	#[error("Invalid commitment salt length: {0}")]
	InvalidSaltLength(ReceivedExpectedError<usize, usize>),

	/// The send-direction AEAD counter nonce space is exhausted.
	#[cfg(feature = "aead")]
	#[error("AEAD counter nonce space exhausted")]
	NonceExhausted,

	/// The send-direction AEAD record limit is reached (RFC 9846 § 5.5).
	#[cfg(feature = "aead")]
	#[error("AEAD record limit reached: reestablish the session to rekey")]
	RekeyRequired,

	/// The received AEAD counter nonce is not the exact next in sequence, which
	/// signals a replay, a reorder, or a deletion.
	#[cfg(feature = "aead")]
	#[error("Out-of-sequence AEAD nonce: {0}")]
	NonceReplayed(ReceivedExpectedError<u64, u64>),

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

	/// Several errors were collected together.
	#[error("Multiple errors occurred: {0}")]
	Sequence(ErrorChain),

	/// A fault injected for testing, which can wrap any error type.
	#[cfg(feature = "testing-fault")]
	#[error("Injected fault: {0}")]
	InjectedFault(Box<dyn InjectedError>),
}

crate::impl_from!(der::Error => TightBeamError::SerializationError);
crate::impl_from!(crate::matrix::MatrixError => TightBeamError::MatrixError);
crate::impl_from!(crate::utils::urn::UrnValidationError => TightBeamError::UrnValidationError);

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
#[cfg(feature = "transport")]
crate::impl_from!(crate::transport::handshake::HandshakeError => TightBeamError::HandshakeError);
#[cfg(feature = "transport")]
crate::impl_from!(crate::transport::error::TransportError => TightBeamError::TransportError);
#[cfg(feature = "random")]
crate::impl_from!(rand_core::Error => TightBeamError::OsRngError);
#[cfg(feature = "x509")]
crate::impl_from!(crate::crypto::x509::error::CertificateValidationError => TightBeamError::CertificateValidationError);
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
#[cfg(feature = "ecies")]
crate::impl_from!(crate::crypto::ecies::EciesError => TightBeamError::EciesError);
#[cfg(feature = "signature")]
crate::impl_from!(signature::Error => TightBeamError::SignatureError);
#[cfg(feature = "signature")]
crate::impl_from!(crate::crypto::sign::elliptic_curve::Error => TightBeamError::EllipticCurveError);
#[cfg(feature = "testing")]
crate::impl_from!(crate::testing::error::TestingError => TightBeamError::TestingError);
#[cfg(feature = "std")]
crate::impl_from!(std::sync::mpsc::RecvTimeoutError => TightBeamError::RecvTimeoutError discard);

#[cfg(feature = "transport")]
impl TightBeamError {
	/// Whether this error is a fuzz iteration running out of input.
	///
	/// AFL feeds short inputs constantly. An iteration whose oracle ran out of
	/// bytes before the process reached a terminal state exercised a prefix of
	/// a run, so its trace is incomplete and its assertions describe events
	/// the target was never given the input to reach.
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

	/// Terminal status a service failure answers a peer with.
	///
	/// A failure already carrying a transit status keeps it. Anything else
	/// answers
	/// [`TransitStatus::Internal`](crate::policy::TransitStatus::Internal), so
	/// a peer tells a failure apart from an accepted empty reply and the
	/// failure stays attributable.
	#[cfg(pooled_mux)]
	#[must_use]
	pub(crate) fn failure_status(&self) -> crate::policy::TransitStatus {
		use crate::policy::TransitStatus;

		if let TightBeamError::TransportError(crate::transport::TransportError::OperationFailed(failure)) = self {
			return TransitStatus::try_from(*failure).unwrap_or(TransitStatus::Internal);
		}

		TransitStatus::Internal
	}
}

// A generic source type cannot go through impl_from!, so the unit-variant
// conversion is written out.
#[cfg(feature = "std")]
impl<T> From<std::sync::PoisonError<T>> for TightBeamError {
	fn from(_: std::sync::PoisonError<T>) -> Self {
		TightBeamError::LockPoisoned
	}
}

#[cfg(all(test, feature = "std"))]
mod tests {
	use super::*;

	#[test]
	fn source_annotated_wrappers_expose_their_cause() {
		let err = TightBeamError::from(crate::matrix::MatrixError::InvalidN(0));
		let source = core::error::Error::source(&err);
		assert!(matches!(err, TightBeamError::MatrixError(_)));
		assert!(source.is_some());
	}

	#[test]
	fn error_chain_renders_a_readable_join() {
		let chain = ErrorChain::from(vec![TightBeamError::InvalidBody, TightBeamError::MissingOrder]);
		let wrapped = TightBeamError::Sequence(chain);
		assert_eq!(
			wrapped.to_string(),
			"Multiple errors occurred: Invalid message body; Missing order"
		);
	}

	#[test]
	fn error_chain_renders_a_lone_error_without_a_separator() {
		let wrapped = TightBeamError::Sequence(ErrorChain::from(vec![TightBeamError::InvalidBody]));
		assert_eq!(wrapped.to_string(), "Multiple errors occurred: Invalid message body");
	}

	#[test]
	fn unit_variants_have_no_source() {
		let err = TightBeamError::InvalidBody;
		assert!(core::error::Error::source(&err).is_none());
	}
}
