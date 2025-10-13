#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::Version;

#[cfg(feature = "derive")]
use crate::Errorizable;

/// Errors specific to metadata validation
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataError {
	/// Missing required ID field
	#[cfg_attr(feature = "derive", error("Missing required field: id"))]
	MissingId,

	/// Missing required order field
	#[cfg_attr(feature = "derive", error("Missing required field: order"))]
	MissingTimestamp,

	/// Missing required hash field (V2+)
	#[cfg_attr(feature = "derive", error("Missing required field: hash (required for V2)"))]
	MissingHash,

	/// Missing required encryption info (V1+)
	#[cfg_attr(
		feature = "derive",
		error("Missing required field: encryption (required for V1+)")
	)]
	MissingEncryption,

	/// Field not supported in this protocol version
	#[cfg_attr(
		feature = "derive",
		error("Field '{field}' is not supported in protocol version {version:?}")
	)]
	UnsupportedField { field: &'static str, version: Version },
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for MetadataError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::MissingId => write!(f, "Missing required field: id"),
			Self::MissingTimestamp => write!(f, "Missing required field: order"),
			Self::MissingHash => write!(f, "Missing required field: hash (required for V2)"),
			Self::MissingEncryption => write!(f, "Missing required field: encryption (required for V1+)"),
			Self::UnsupportedField { field, version } => {
				write!(f, "Field '{field}' is not supported in protocol version {version:?}")
			}
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for MetadataError {}

/// Errors that can occur during builder operations
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum BuildError {
	/// Invalid metadata configuration
	#[cfg_attr(feature = "derive", error("Invalid metadata: {0}"))]
	InvalidMetadata(MetadataError),

	/// Glitch in the Matrix
	#[cfg_attr(feature = "derive", error("Matrix error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	MatrixError(crate::matrix::MatrixError),

	/// Error during serialization
	#[cfg_attr(feature = "derive", error("Serialization error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	Serialization(der::Error),

	/// Error during encryption
	#[cfg(feature = "aead")]
	#[cfg_attr(feature = "derive", error("Encryption error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	Encryption(aead::Error),

	/// Error during signing
	#[cfg(feature = "signature")]
	#[cfg_attr(feature = "derive", error("Signature error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	Signature(signature::Error),

	/// Error during compression
	#[cfg(feature = "compress")]
	#[cfg_attr(feature = "derive", error("Compression error: {0}"))]
	Compression(crate::error::CompressionError),

	/// Error obtaining random bytes
	#[cfg(feature = "random")]
	#[cfg_attr(feature = "derive", error("Random number generation error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	Random(rand_core::Error),

	/// Missing message body
	#[cfg_attr(feature = "derive", error("Missing message body"))]
	MissingMessage,
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for BuildError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::InvalidMetadata(err) => write!(f, "Invalid metadata: {err}"),
			Self::Serialization(err) => write!(f, "Serialization error: {err}"),
			Self::MissingMessage => write!(f, "Missing message body"),
			#[cfg(feature = "aead")]
			Self::Encryption(err) => write!(f, "Encryption error: {err}"),
			#[cfg(feature = "signature")]
			Self::Signature(err) => write!(f, "Signature error: {err}"),
			#[cfg(feature = "compress")]
			Self::Compression(err) => write!(f, "Compression error: {err}"),
			#[cfg(feature = "random")]
			Self::Random(err) => write!(f, "Random number generation error: {err}"),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for BuildError {}

#[cfg(not(feature = "derive"))]
crate::impl_from!(MetadataError => BuildError::InvalidMetadata);
#[cfg(not(feature = "derive"))]
crate::impl_from!(der::Error => BuildError::Serialization);
#[cfg(all(feature = "aead", not(feature = "derive")))]
crate::impl_from!(aead::Error => BuildError::Encryption);
#[cfg(all(feature = "signature", not(feature = "derive")))]
crate::impl_from!(signature::Error => BuildError::Signature);
#[cfg(all(feature = "random", not(feature = "derive")))]
crate::impl_from!(rand_core::Error => BuildError::Random);
#[cfg(all(feature = "compress", not(feature = "derive")))]
crate::impl_from!(crate::error::CompressionError => BuildError::Compression);
