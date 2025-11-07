#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::Version;

#[cfg(feature = "derive")]
use crate::Errorizable;

/// A specialized Result type for TightBeam operations
pub type Result<T> = core::result::Result<T, TightBeamError>;

/// A specialized Result type for compression operations
pub type CompressionResult<T> = core::result::Result<T, CompressionError>;

/// Error indicating a mismatch between received and expected values
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExpectError<Received, Expected> {
	pub received: Received,
	pub expected: Expected,
}

impl<Received, Expected> From<(Received, Expected)> for ExpectError<Received, Expected> {
	fn from((received, expected): (Received, Expected)) -> Self {
		Self { received, expected }
	}
}

impl<Received: core::fmt::Debug, Expected: core::fmt::Debug> core::fmt::Display for ExpectError<Received, Expected> {
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
	DroneError(crate::colony::DroneError),

	#[cfg(feature = "std")]
	/// I/O error
	#[cfg_attr(feature = "derive", error("I/O error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	IoError(std::io::Error),

	/// Invalid or unsupported algorithm identifier
	#[cfg_attr(feature = "derive", error("Invalid or unsupported object identifier: {0}"))]
	InvalidOID(crate::der::oid::Error),

	/// Error during signature verification or generation
	#[cfg(feature = "signature")]
	#[cfg_attr(feature = "derive", error("Signature verification or generation error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	SignatureError(crate::crypto::sign::Error),

	/// Error during serialization
	#[cfg_attr(feature = "derive", error("Serialization error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	SerializationError(crate::der::Error),

	/// Error during compression or decompression
	#[cfg(feature = "compress")]
	#[cfg_attr(feature = "derive", error("Compression error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	CompressionError(CompressionError),

	#[cfg(feature = "transport")]
	#[cfg_attr(feature = "derive", error("Transport error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	TransportError(crate::transport::error::TransportError),

	/// Unsupported protocol version
	#[cfg_attr(
		feature = "derive",
		error("Unsupported protocol version: expected {expected:?}, got {received:?}")
	)]
	UnsupportedVersion(ExpectError<Version, Version>),

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

	/// Error obtaining random bytes from the OS
	#[cfg(feature = "random")]
	#[cfg_attr(feature = "derive", error("OS random number generator error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	OsRngError(rand_core::Error),

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

	/// Missing or invalid configuration
	#[cfg_attr(feature = "derive", error("Missing configuration"))]
	MissingConfiguration,

	/// Multiple errors collected together
	#[cfg_attr(feature = "derive", error("Multiple errors occurred: {0:?}"))]
	Sequence(Vec<TightBeamError>),
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
			TightBeamError::InvalidOID(err) => write!(f, "Invalid or unsupported object identifier: {err}"),
			TightBeamError::InvalidOverflowValue => write!(f, "Invalid overflow value"),
			TightBeamError::InvalidOrder => write!(f, "Invalid order"),
			TightBeamError::MissingInflator => write!(f, "Missing inflator"),
			TightBeamError::MissingOrder => write!(f, "Missing order"),
			TightBeamError::MissingPriority => write!(f, "Missing priority"),
			TightBeamError::MissingFeature(feature) => write!(f, "Missing feature: {feature}"),
			TightBeamError::MissingConfiguration => write!(f, "Missing configuration"),
			#[cfg(feature = "colony")]
			TightBeamError::DroneError(err) => write!(f, "Drone error: {err}"),
			#[cfg(feature = "standards")]
			TightBeamError::StandardError(err) => write!(f, "Standard error: {err}"),
			#[cfg(feature = "random")]
			TightBeamError::OsRngError(err) => write!(f, "OS random number generator error: {err}"),
			#[cfg(feature = "aead")]
			TightBeamError::EncryptionError(err) => write!(f, "Encryption or decryption error: {err}"),
			#[cfg(feature = "ecies")]
			TightBeamError::EciesError(err) => write!(f, "ECIES error: {err}"),
			#[cfg(feature = "signature")]
			TightBeamError::SignatureError(err) => write!(f, "Signature verification or generation error: {err}"),
			#[cfg(feature = "signature")]
			TightBeamError::SignatureEncodingError => write!(f, "Signature encoding error"),
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
			#[cfg(feature = "compress")]
			TightBeamError::CompressionError(err) => match err {
				#[cfg(feature = "zstd")]
				CompressionError::ZSTD(e) => write!(f, "ZSTD compression/decompression error: {e}"),
				CompressionError::IO(e) => write!(f, "I/O error during compression/decompression: {e}"),
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
		}
	}
}

#[cfg(not(feature = "derive"))]
crate::impl_from!(der::Error => TightBeamError::SerializationError);
#[cfg(all(feature = "router", not(feature = "derive")))]
crate::impl_from!(crate::router::RouterError => TightBeamError::RouterError);
#[cfg(all(feature = "random", not(feature = "derive")))]
crate::impl_from!(getrandom::Error => TightBeamError::OsRngError);
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
#[cfg(all(feature = "zstd", not(feature = "derive")))]
crate::impl_from!(zeekstd::Error => TightBeamError::CompressionError via CompressionError::ZSTD);
#[cfg(all(feature = "zstd", not(feature = "derive")))]
crate::impl_from!(zeekstd::Error => CompressionError::ZSTD);

#[cfg(not(feature = "derive"))]
impl core::error::Error for TightBeamError {}

#[cfg(all(feature = "compress", not(feature = "derive")))]
impl core::error::Error for CompressionError {}
