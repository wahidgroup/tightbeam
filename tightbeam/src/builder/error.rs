#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::asn1::GatedField;
use crate::{Errorizable, Version};

/// Errors specific to metadata validation
#[derive(Errorizable, Debug, Clone, PartialEq, Eq)]
pub enum MetadataError {
	/// Missing required ID field
	#[error("Missing required field: id")]
	MissingId,

	/// Missing required order field
	#[error("Missing required field: order")]
	MissingOrder,

	/// Field not supported in this protocol version
	#[error("Field {field} is not supported in protocol version {version:?}")]
	UnsupportedField { field: GatedField, version: Version },
}

/// Errors that can occur during builder operations
#[derive(Errorizable, Debug)]
pub enum BuildError {
	/// Invalid metadata configuration
	#[error("Invalid metadata: {0}")]
	#[from]
	InvalidMetadata(MetadataError),

	/// Invalid matrix dimensions or contents
	#[error("Matrix error: {0}")]
	#[from]
	MatrixError(crate::matrix::MatrixError),

	/// Error during serialization
	#[error("Serialization error: {0}")]
	#[from]
	Serialization(der::Error),

	/// Error during encryption
	#[cfg(feature = "aead")]
	#[error("Encryption error: {0}")]
	#[from]
	Encryption(aead::Error),

	/// Error during signing
	#[cfg(feature = "signature")]
	#[error("Signature error: {0}")]
	#[from]
	Signature(signature::Error),

	/// Error during compression
	#[cfg(feature = "compress")]
	#[error("Compression error: {0}")]
	Compression(crate::error::CompressionError),

	/// Error obtaining random bytes
	#[cfg(feature = "random")]
	#[error("Random number generation error: {0}")]
	#[from]
	Random(rand_core::Error),

	/// Missing message body
	#[error("Missing message body")]
	MissingMessage,
}
