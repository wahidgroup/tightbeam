#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::spki::ObjectIdentifier;
use crate::Version;

#[cfg(feature = "derive")]
use crate::Errorizable;

/// A specialized Result type for TightBeam operations
pub type Result<T> = core::result::Result<T, TightBeamError>;

/// A specialized Result type for compression operations
pub type CompressionResult<T> = core::result::Result<T, CompressionError>;

/// Error indicating a mismatch between received and expected values
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReceivedExpectedError<Received, Expected> {
	pub received: Received,
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

#[cfg(feature = "compress")]
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum CompressionError {
	#[cfg(feature = "zstd")]
	#[cfg_attr(feature = "derive", error("ZSTD compression/decompression error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	ZSTD(zeekstd::Error),

	#[cfg_attr(feature = "derive", error("I/O error during compression/decompression: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	IO(std::io::Error),
}

#[cfg(all(feature = "compress", not(feature = "derive")))]
impl core::fmt::Display for CompressionError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			#[cfg(feature = "zstd")]
			CompressionError::ZSTD(e) => write!(f, "ZSTD compression/decompression error: {e}"),
			CompressionError::IO(e) => write!(f, "I/O error during compression/decompression: {e}"),
		}
	}
}

/// Trait for injected faults in testing
#[cfg(feature = "testing-fault")]
pub trait InjectedError: core::fmt::Debug + core::fmt::Display + Send + Sync {}

// Blanket implementation for any type meeting the requirements
#[cfg(feature = "testing-fault")]
impl<T> InjectedError for T where T: core::fmt::Debug + core::fmt::Display + Send + Sync {}

#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum TightBeamError {
	/// Error from the matrix implementation
	#[cfg_attr(feature = "derive", error("Matrix error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	MatrixError(crate::matrix::MatrixError),

	#[cfg(feature = "router")]
	#[cfg_attr(feature = "derive", error("Route error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	RouterError(crate::router::RouterError),

	/// Error from the message builder
	#[cfg(feature = "builder")]
	#[cfg_attr(feature = "derive", error("Build error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	BuildError(crate::builder::error::BuildError),

	/// StandardError
	#[cfg(feature = "standards")]
	#[cfg_attr(feature = "derive", error("Standard error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	StandardError(crate::standards::error::StandardError),

	#[cfg(feature = "colony")]
	#[cfg_attr(feature = "derive", error("Drone error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	DroneError(crate::colony::drone::DroneError),

	#[cfg(feature = "colony")]
	#[cfg_attr(feature = "derive", error("Worker relay error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	WorkerRelay(crate::colony::worker::WorkerRelayError),

	#[cfg(feature = "std")]
	/// I/O error
	#[cfg_attr(feature = "derive", error("I/O error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	IoError(std::io::Error),

	#[cfg(feature = "std")]
	/// Lock poisoned
	#[cfg_attr(feature = "derive", error("Lock poisoned"))]
	LockPoisoned,

	/// Invalid or unsupported algorithm identifier
	#[cfg_attr(feature = "derive", error("Invalid or unsupported object identifier: {0}"))]
	InvalidOID(crate::der::oid::Error),

	/// Error during signature verification or generation
	#[cfg(feature = "signature")]
	#[cfg_attr(feature = "derive", error("Signature verification or generation error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	SignatureError(crate::crypto::sign::Error),

	/// Error from elliptic curve operations
	#[cfg(feature = "signature")]
	#[cfg_attr(feature = "derive", error("Elliptic curve error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	EllipticCurveError(crate::crypto::sign::elliptic_curve::Error),

	/// Error during serialization
	#[cfg_attr(feature = "derive", error("Serialization error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	SerializationError(crate::der::Error),

	/// Error during compression or decompression
	#[cfg(feature = "compress")]
	#[cfg_attr(feature = "derive", error("Compression error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	CompressionError(CompressionError),

	/// Error during handshake operations
	#[cfg(feature = "transport")]
	#[cfg_attr(feature = "derive", error("Handshake error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	HandshakeError(crate::transport::handshake::HandshakeError),

	#[cfg(feature = "transport")]
	#[cfg_attr(feature = "derive", error("Transport error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	TransportError(crate::transport::error::TransportError),

	/// Unsupported protocol version
	#[cfg_attr(
		feature = "derive",
		error("Unsupported protocol version: expected {expected:?}, got {received:?}")
	)]
	UnsupportedVersion(ReceivedExpectedError<Version, Version>),

	/// Error during testing operations
	#[cfg(feature = "testing")]
	#[cfg_attr(feature = "derive", error("Testing error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	TestingError(crate::testing::error::TestingError),

	/// Error during URN validation
	#[cfg_attr(feature = "derive", error("URN validation error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	UrnValidationError(crate::utils::urn::UrnValidationError),

	/// Error during encryption or decryption
	#[cfg(feature = "aead")]
	#[cfg_attr(feature = "derive", error("Encryption or decryption error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	EncryptionError(crate::crypto::aead::Error),

	/// Error during ECIES operations
	#[cfg(feature = "ecies")]
	#[cfg_attr(feature = "derive", error("ECIES error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	EciesError(crate::crypto::ecies::EciesError),

	#[cfg_attr(feature = "derive", error("Crypto policy error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	CryptoPolicyError(crate::crypto::policy::CryptoPolicyError),

	#[cfg_attr(feature = "derive", error("Key derivation error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	KeyDerivationError(crate::crypto::kdf::KdfError),

	/// Error from key provider operations
	#[cfg_attr(feature = "derive", error("Key provider error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	KeyError(crate::crypto::key::KeyError),

	/// Error obtaining random bytes from the OS
	#[cfg(feature = "random")]
	#[cfg_attr(feature = "derive", error("OS random number generator error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	OsRngError(rand_core::Error),

	/// Error during SPKI operations
	#[cfg(feature = "x509")]
	#[cfg_attr(feature = "derive", error("SPKI error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	SpkiError(crate::spki::Error),

	/// Error during X.509 certificate building
	#[cfg(feature = "x509")]
	#[cfg_attr(feature = "derive", error("X.509 builder error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	X509BuilderError(x509_cert::builder::Error),

	/// Error receiving from channel with timeout
	#[cfg(feature = "std")]
	#[cfg_attr(feature = "derive", error("Channel receive timeout error"))]
	RecvTimeoutError,

	/// Error decoding signature from bytes
	#[cfg(feature = "signature")]
	#[cfg_attr(feature = "derive", error("Signature encoding error"))]
	SignatureEncodingError,

	/// Invalid metadata
	#[cfg_attr(feature = "derive", error("Invalid metadata"))]
	InvalidMetadata,

	/// Invalid message body
	#[cfg_attr(feature = "derive", error("Invalid message body"))]
	InvalidBody,

	/// Invalid overflow value
	#[cfg_attr(feature = "derive", error("Invalid overflow value"))]
	InvalidOverflowValue,

	/// Invalid order
	#[cfg_attr(feature = "derive", error("Invalid order"))]
	InvalidOrder,

	// Missing order
	#[cfg_attr(feature = "derive", error("Missing order"))]
	MissingOrder,

	/// Missing inflator
	#[cfg_attr(feature = "derive", error("Missing inflator"))]
	MissingInflator,

	/// Missing feature
	#[cfg_attr(feature = "derive", error("Missing feature: {0}"))]
	MissingFeature(&'static str),

	/// Missing priority
	#[cfg_attr(feature = "derive", error("Missing priority"))]
	MissingPriority,

	/// Missing response
	#[cfg_attr(feature = "derive", error("Missing response"))]
	MissingResponse,

	/// Signature is missing
	#[cfg(feature = "signature")]
	#[cfg_attr(feature = "derive", error("Missing signature"))]
	MissingSignature,

	/// Signature info is missing
	#[cfg(feature = "signature")]
	#[cfg_attr(feature = "derive", error("Missing signature info"))]
	MissingSignatureInfo,

	/// Missing Encryption Info
	#[cfg(feature = "aead")]
	#[cfg_attr(feature = "derive", error("Missing encryption info"))]
	MissingEncryptionInfo,

	/// Missing Integrity Info
	#[cfg(feature = "digest")]
	#[cfg_attr(feature = "derive", error("Missing integrity info"))]
	MissingDigestInfo,

	/// Missing Compression Info
	#[cfg(feature = "compress")]
	#[cfg_attr(feature = "derive", error("Missing compression info"))]
	MissingCompressedData,

	/// Invalid algorithm for the message profile
	#[cfg_attr(feature = "derive", error("Invalid algorithm for message profile"))]
	InvalidAlgorithm,

	/// Unexpected algorithm for the message profile
	#[cfg_attr(
		feature = "derive",
		error("Unexpected algorithm for message profile: expected {expected:?}, got {received:?}")
	)]
	UnexpectedAlgorithm(ReceivedExpectedError<ObjectIdentifier, ObjectIdentifier>),

	/// Missing or invalid configuration
	#[cfg_attr(feature = "derive", error("Missing configuration"))]
	MissingConfiguration,

	/// Operation not supported by this implementation
	#[cfg_attr(feature = "derive", error("Unsupported operation"))]
	UnsupportedOperation,

	/// Multiple errors collected together
	#[cfg_attr(feature = "derive", error("Multiple errors occurred: {0:?}"))]
	Sequence(Vec<TightBeamError>),

	/// Injected fault for testing (any error type)
	#[cfg(feature = "testing-fault")]
	#[cfg_attr(feature = "derive", error("Injected fault: {0}"))]
	InjectedFault(Box<dyn InjectedError>),
}

#[cfg(all(feature = "colony", not(feature = "derive")))]
impl From<crate::colony::WorkerRelayError> for TightBeamError {
	fn from(err: crate::colony::WorkerRelayError) -> Self {
		TightBeamError::WorkerRelay(err)
	}
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for TightBeamError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			TightBeamError::SerializationError(err) => write!(f, "Serialization error: {err}"),
			#[cfg(feature = "router")]
			TightBeamError::RouterError(err) => write!(f, "Route error: {err}"),
			TightBeamError::InvalidMetadata => write!(f, "Invalid metadata"),
			TightBeamError::InvalidBody => write!(f, "Invalid message body"),
			TightBeamError::InvalidOID(err) => {
				write!(f, "Invalid or unsupported object identifier: {err}")
			}
			TightBeamError::InvalidOverflowValue => write!(f, "Invalid overflow value"),
			TightBeamError::InvalidOrder => write!(f, "Invalid order"),
			TightBeamError::MissingInflator => write!(f, "Missing inflator"),
			TightBeamError::MissingOrder => write!(f, "Missing order"),
			TightBeamError::MissingPriority => write!(f, "Missing priority"),
			TightBeamError::MissingResponse => write!(f, "Missing response"),
			TightBeamError::MissingFeature(feature) => write!(f, "Missing feature: {feature}"),
			TightBeamError::MissingConfiguration => write!(f, "Missing configuration"),
			TightBeamError::UnsupportedOperation => write!(f, "Unsupported operation"),
			#[cfg(feature = "transport")]
			TightBeamError::HandshakeError(err) => write!(f, "Handshake error: {err}"),
			#[cfg(feature = "colony")]
			TightBeamError::DroneError(err) => write!(f, "Drone error: {err}"),
			#[cfg(feature = "std")]
			TightBeamError::LockPoisoned => write!(f, "Lock poisoned"),
			#[cfg(feature = "standards")]
			TightBeamError::StandardError(err) => write!(f, "Standard error: {err}"),
			#[cfg(feature = "random")]
			TightBeamError::OsRngError(err) => write!(f, "OS random number generator error: {err}"),
			#[cfg(feature = "x509")]
			TightBeamError::SpkiError(err) => write!(f, "SPKI error: {err}"),
			#[cfg(feature = "x509")]
			TightBeamError::X509BuilderError(err) => write!(f, "X.509 builder error: {err}"),
			#[cfg(feature = "std")]
			TightBeamError::RecvTimeoutError => write!(f, "Channel receive timeout error"),
			#[cfg(feature = "aead")]
			TightBeamError::EncryptionError(err) => {
				write!(f, "Encryption or decryption error: {err}")
			}
			#[cfg(feature = "ecies")]
			TightBeamError::EciesError(err) => write!(f, "ECIES error: {err}"),
			#[cfg(feature = "signature")]
			TightBeamError::SignatureError(err) => {
				write!(f, "Signature verification or generation error: {err}")
			}
			#[cfg(feature = "signature")]
			TightBeamError::EllipticCurveError(_) => write!(f, "Elliptic curve error"),
			#[cfg(feature = "signature")]
			TightBeamError::SignatureEncodingError => write!(f, "Signature encoding error"),
			TightBeamError::KeyError(err) => write!(f, "Key provider error: {err}"),
			#[cfg(feature = "digest")]
			TightBeamError::MissingDigestInfo => write!(f, "Missing integrity info"),
			#[cfg(feature = "aead")]
			TightBeamError::MissingEncryptionInfo => write!(f, "Missing encryption info"),
			#[cfg(feature = "signature")]
			TightBeamError::MissingSignatureInfo => write!(f, "Missing signature info"),
			#[cfg(feature = "signature")]
			TightBeamError::MissingSignature => write!(f, "Missing signature"),
			#[cfg(feature = "compress")]
			TightBeamError::MissingCompressedData => write!(f, "Missing compression info"),
			TightBeamError::InvalidAlgorithm => write!(f, "Invalid algorithm for message profile"),
			TightBeamError::UnexpectedAlgorithm(err) => {
				write!(
					f,
					"Unexpected algorithm for message profile: expected {:?}, got {:?}",
					err.expected, err.received
				)
			}
			#[cfg(feature = "compress")]
			TightBeamError::CompressionError(err) => match err {
				#[cfg(feature = "zstd")]
				CompressionError::ZSTD(e) => write!(f, "ZSTD compression/decompression error: {e}"),
				CompressionError::IO(e) => {
					write!(f, "I/O error during compression/decompression: {e}")
				}
			},
			TightBeamError::Sequence(errors) => {
				write!(f, "Multiple errors: ")?;
				for (i, error) in errors.iter().enumerate() {
					if i > 0 {
						write!(f, "; ")?;
					}
					write!(f, "{error}")?;
				}
				Ok(())
			}
			TightBeamError::UnsupportedVersion(err) => {
				write!(
					f,
					"Unsupported protocol version: expected {:?}, got {:?}",
					err.expected, err.received
				)
			}
			#[cfg(feature = "testing")]
			TightBeamError::TestingError(err) => write!(f, "Testing error: {err}"),
			TightBeamError::UrnValidationError(err) => write!(f, "URN validation error: {err}"),
			#[cfg(feature = "testing-fault")]
			TightBeamError::InjectedFault(err) => write!(f, "Injected fault: {err}"),
		}
	}
}

#[cfg(not(feature = "derive"))]
crate::impl_from!(der::Error => TightBeamError::SerializationError);
#[cfg(all(feature = "router", not(feature = "derive")))]
crate::impl_from!(crate::router::RouterError => TightBeamError::RouterError);
#[cfg(all(feature = "random", not(feature = "derive")))]
crate::impl_from!(getrandom::Error => TightBeamError::OsRngError);
#[cfg(all(feature = "x509", not(feature = "derive")))]
crate::impl_from!(spki::Error => TightBeamError::SpkiError);
#[cfg(all(feature = "x509", not(feature = "derive")))]
crate::impl_from!(x509_cert::builder::Error => TightBeamError::X509BuilderError);
#[cfg(feature = "std")]
impl From<std::sync::mpsc::RecvTimeoutError> for TightBeamError {
	fn from(_: std::sync::mpsc::RecvTimeoutError) -> Self {
		TightBeamError::RecvTimeoutError
	}
}
#[cfg(all(feature = "std", feature = "compress", not(feature = "derive")))]
crate::impl_from!(std::io::Error => CompressionError::IO);
#[cfg(all(feature = "std", feature = "compress", not(feature = "derive")))]
crate::impl_from!(CompressionError => TightBeamError::CompressionError);
#[cfg(all(feature = "aead", not(feature = "derive")))]
crate::impl_from!(aead::Error => TightBeamError::EncryptionError);
#[cfg(all(feature = "ecies", not(feature = "derive")))]
crate::impl_from!(EciesError => TightBeamError::EciesError);
#[cfg(all(feature = "signature", not(feature = "derive")))]
crate::impl_from!(signature::Error => TightBeamError::SignatureError);
#[cfg(all(feature = "signature", not(feature = "derive")))]
crate::impl_from!(crate::crypto::sign::elliptic_curve::Error => TightBeamError::EllipticCurveError);
#[cfg(all(feature = "zstd", not(feature = "derive")))]
crate::impl_from!(zeekstd::Error => TightBeamError::CompressionError via CompressionError::ZSTD);
#[cfg(all(feature = "zstd", not(feature = "derive")))]
crate::impl_from!(zeekstd::Error => CompressionError::ZSTD);
#[cfg(all(feature = "testing", not(feature = "derive")))]
crate::impl_from!(crate::testing::error::TestingError => TightBeamError::TestingError);
#[cfg(not(feature = "derive"))]
crate::impl_from!(crate::utils::urn::UrnValidationError => TightBeamError::UrnValidationError);

#[cfg(not(feature = "derive"))]
impl core::error::Error for TightBeamError {}

#[cfg(feature = "std")]
impl<T> From<std::sync::PoisonError<T>> for TightBeamError {
	fn from(_: std::sync::PoisonError<T>) -> Self {
		TightBeamError::LockPoisoned
	}
}

#[cfg(feature = "std")]
impl From<std::string::FromUtf8Error> for TightBeamError {
	fn from(err: std::string::FromUtf8Error) -> Self {
		TightBeamError::IoError(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
	}
}

#[cfg(feature = "std")]
impl From<std::net::AddrParseError> for TightBeamError {
	fn from(err: std::net::AddrParseError) -> Self {
		TightBeamError::IoError(std::io::Error::new(std::io::ErrorKind::InvalidInput, err))
	}
}

#[cfg(all(feature = "compress", not(feature = "derive")))]
impl core::error::Error for CompressionError {}
