//! Utility modules and functions

use crate::error::TightBeamError;
use crate::{Message, Version};

#[cfg(feature = "builder")]
use crate::builder::FrameBuilder;
#[cfg(feature = "compress")]
use crate::{
	compress::{Compressor, Inflator},
	error::CompressionError,
	CompressedData,
};

// Submodules
pub mod basis_points;
pub mod jitter;
pub mod math;
pub mod statistics;
pub mod task;
pub mod urn;

pub use basis_points::BasisPoints;

// Re-exports
#[cfg(feature = "hex")]
pub use ::hex_literal::hex;

/// Macro to implement From trait for both reference and owned types
///
/// This generates:
/// - `impl From<&TightBeam> for TargetType` that clones or copies the field
/// - `impl From<TightBeam> for TargetType` that delegates to the reference impl
#[macro_export]
macro_rules! impl_from {
	// Pattern for field extraction from structs
	($source:ty, $param:ident => $target:ty: $($field:tt)*) => {
		impl From<&$source> for $target {
			fn from($param: &$source) -> Self {
				$($field)*
			}
		}

		impl From<$source> for $target {
			fn from($param: $source) -> Self {
				(&$param).into()
			}
		}
	};

	// Pattern for error conversions (unconditional)
	($from_type:ty => $target:ident::$variant:ident) => {
		impl From<$from_type> for $target {
			fn from(err: $from_type) -> Self {
				$target::$variant(err)
			}
		}
	};

	// Pattern for conditional error conversions (with cfg)
	(#[cfg($feature:meta)] $from_type:ty => $target:ident::$variant:ident) => {
		#[cfg($feature)]
		impl From<$from_type> for $target {
			fn from(err: $from_type) -> Self {
				$target::$variant(err)
			}
		}
	};

	// Pattern for conditional error conversions via enum wrapper (with cfg)
	(#[cfg($feature:meta)] $from_type:ty => $target:ident::$variant:ident via $wrapper:path) => {
		#[cfg($feature)]
		impl From<$from_type> for $target {
			fn from(err: $from_type) -> Self {
				$target::$variant($wrapper(err))
			}
		}
	};

	// Pattern for unconditional error conversions via enum wrapper
	($from_type:ty => $target:ident::$variant:ident via $wrapper:path) => {
		impl From<$from_type> for $target {
			fn from(err: $from_type) -> Self {
				$target::$variant($wrapper(err))
			}
		}
	};

	// Pattern for extracting inner value from enum variant with fallback
	($from_type:ty => $target:ident::$variant:ident extract $enum_variant:pat => $inner:ident else $fallback:expr) => {
		impl From<$from_type> for $target {
			fn from(err: $from_type) -> Self {
				match err {
					$enum_variant => $target::$variant($inner),
					_ => $target::$variant($fallback),
				}
			}
		}
	};

	// Pattern for extracting inner value from enum variant with fallback (conditional)
	(#[cfg($feature:meta)] $from_type:ty => $target:ident::$variant:ident extract $enum_variant:pat => $inner:ident else $fallback:expr) => {
		#[cfg($feature)]
		impl From<$from_type> for $target {
			fn from(err: $from_type) -> Self {
				match err {
					$enum_variant => $target::$variant($inner),
					_ => $target::$variant($fallback),
				}
			}
		}
	};

	// Pattern for unit variants (discard the error value)
	($from_type:ty => $target:ident::$variant:ident discard) => {
		impl From<$from_type> for $target {
			fn from(_: $from_type) -> Self {
				$target::$variant
			}
		}
	};

	// Pattern for unit variants with cfg (discard the error value)
	(#[cfg($feature:meta)] $from_type:ty => $target:ident::$variant:ident discard) => {
		#[cfg($feature)]
		impl From<$from_type> for $target {
			fn from(_: $from_type) -> Self {
				$target::$variant
			}
		}
	};

	// Pattern for generic types to unit variants (e.g., PoisonError<T>)
	(<$($gen:ident),+> $from_type:ty => $target:ident::$variant:ident discard) => {
		impl<$($gen),+> From<$from_type> for $target {
			fn from(_: $from_type) -> Self {
				$target::$variant
			}
		}
	};

	// Pattern for generic types to unit variants with cfg
	(#[cfg($feature:meta)] <$($gen:ident),+> $from_type:ty => $target:ident::$variant:ident discard) => {
		#[cfg($feature)]
		impl<$($gen),+> From<$from_type> for $target {
			fn from(_: $from_type) -> Self {
				$target::$variant
			}
		}
	};

	// Pattern for transformative conversions (wrap error via expression)
	($from_type:ty => $target:ident::$variant:ident via |$err:ident| $transform:expr) => {
		impl From<$from_type> for $target {
			fn from($err: $from_type) -> Self {
				$target::$variant($transform)
			}
		}
	};

	// Pattern for transformative conversions with cfg
	(#[cfg($feature:meta)] $from_type:ty => $target:ident::$variant:ident via |$err:ident| $transform:expr) => {
		#[cfg($feature)]
		impl From<$from_type> for $target {
			fn from($err: $from_type) -> Self {
				$target::$variant($transform)
			}
		}
	};
}

/// Macro to implement TryFrom trait for extracting optional fields
///
/// This generates:
/// - `impl TryFrom<TightBeam> for TargetType` that consumes the source
/// - Uses `take()` for zero-copy extraction when consuming the source
#[macro_export]
macro_rules! impl_try_from {
	// For fields directly on TightBeam
	($source:ty, $param:ident => $target:ty: $field:ident) => {
		impl TryFrom<$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from(mut $param: $source) -> Result<Self, Self::Error> {
				$param.$field.take().ok_or($crate::error::TightBeamError::InvalidMetadata)
			}
		}
	};

	($source:ty, $param:ident => $target:ty: $field:ident, $error:expr) => {
		impl TryFrom<$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from(mut $param: $source) -> core::result::Result<Self, Self::Error> {
				$param.$field.take().ok_or($error)
			}
		}
	};

	// For fields in metadata
	($source:ty, $param:ident => $target:ty: metadata.$field:ident) => {
		impl TryFrom<$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from(mut $param: $source) -> Result<Self, Self::Error> {
				$param
					.metadata
					.$field
					.take()
					.ok_or($crate::error::TightBeamError::InvalidMetadata)
			}
		}
	};

	($source:ty, $param:ident => $target:ty: metadata.$field:ident, $error:expr) => {
		impl TryFrom<$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from(mut $param: $source) -> core::result::Result<Self, Self::Error> {
				$param.metadata.$field.take().ok_or($error)
			}
		}
	};
}

/// Encode a value to DER format
#[inline]
pub fn encode<T: der::Encode>(value: &T) -> Result<Vec<u8>, TightBeamError> {
	Ok(der::Encode::to_der(value)?)
}

/// Decode a value from MessageContent
/// This is used for decoding messages from frame content
#[inline]
pub fn decode<'a, T: der::Decode<'a>>(content: &'a impl AsRef<[u8]>) -> Result<T, TightBeamError> {
	Ok(der::Decode::from_der(content.as_ref())?)
}

/// Create a new FrameBuilder for the given message type and version
///
/// This is a convenience function for creating frames without using the
/// `compose!` macro. Useful in contexts where macros cannot be used
/// (e.g., within other macro definitions).
pub fn compose<T: Message>(version: Version) -> FrameBuilder<T> {
	FrameBuilder::from(version)
}

/// Compress data using the specified algorithm.
#[cfg(feature = "compress")]
#[inline]
pub fn compress(
	data: impl AsRef<[u8]>,
	compressor: &impl Compressor,
	content_info: Option<crate::cms::signed_data::EncapsulatedContentInfo>,
) -> Result<(Vec<u8>, CompressedData), CompressionError> {
	let data = data.as_ref();
	compressor.compress(data, content_info)
}

/// Decompress data using the specified algorithm.
#[cfg(feature = "compress")]
#[inline]
pub fn decompress(data: impl AsRef<[u8]>, inflator: &impl Inflator) -> Result<Vec<u8>, CompressionError> {
	let data = data.as_ref();
	inflator.decompress(data)
}

/// Compute a digest of the provided data using the specified algorithm.
#[cfg(feature = "digest")]
#[inline]
pub fn digest<D: digest::Digest + crate::der::oid::AssociatedOid>(
	data: impl AsRef<[u8]>,
) -> Result<crate::asn1::DigestInfo, TightBeamError> {
	let data = data.as_ref();

	let mut hasher = D::new();
	hasher.update(data);

	let algorithm = crate::asn1::AlgorithmIdentifier { oid: D::OID, parameters: None };
	let digest = hasher.finalize();
	let digest_octet_string = crate::asn1::OctetString::new(&digest[..])?;
	Ok(crate::asn1::DigestInfo { algorithm, digest: digest_octet_string })
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::der::asn1::OctetStringRef;
	use crate::der::oid::ObjectIdentifier;

	#[test]
	fn data_driven_der_round_trip() -> Result<(), TightBeamError> {
		// OID cases
		let oid_cases = [
			ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
			ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1"),
			ObjectIdentifier::new_unwrap("2.5.4.3"),
		];

		// Octet string cases (varied sizes/patterns)
		let octet_cases: &[&[u8]] = &[
			b"",
			b"a",
			b"hello",
			b"The quick brown fox jumps over the lazy dog",
			&(0u16..64).map(|v| (v % 251) as u8).collect::<Vec<u8>>(),
		];

		for oid in oid_cases {
			let enc = encode(&oid)?;
			assert!(!enc.is_empty());
			assert_eq!(enc[0], 0x06);

			let dec: ObjectIdentifier = decode(&enc)?;
			assert_eq!(dec, oid);
		}

		for data in octet_cases {
			let oct = OctetStringRef::new(data)?;
			let enc = encode(&oct)?;
			assert_eq!(enc[0], 0x04);

			let dec: OctetStringRef<'_> = decode(&enc)?;
			assert_eq!(dec.as_bytes(), *data);
		}

		Ok(())
	}

	#[test]
	#[cfg(feature = "compress")]
	fn test_compress_decompress() -> Result<(), CompressionError> {
		use crate::compress::ZstdCompression;

		// Data-driven cases
		let patterned = (0u32..2048).map(|i| (i % 251) as u8).collect::<Vec<u8>>();
		let big_repeat = vec![b'a'; 16 * 1024];
		let cases: Vec<&[u8]> = vec![
			b"",
			b"a",
			b"hello world",
			b"The quick brown fox jumps over the lazy dog",
			&patterned,
			&big_repeat,
		];

		let compressor = ZstdCompression;
		for &data in &cases {
			let (compressed, _info) = compress(data, &compressor, None)?;
			let decompressed = decompress(&compressed, &compressor)?;
			assert_eq!(decompressed, data);
		}

		Ok(())
	}
}
