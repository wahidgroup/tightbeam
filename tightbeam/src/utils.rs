use crate::error::TightBeamError;

#[cfg(feature = "compress")]
use crate::error::CompressionError;
#[cfg(feature = "compress")]
use crate::{CompressionAlgorithm, CompressionInfo};

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
}

/// Macro to implement TryFrom trait for extracting optional fields
///
/// This generates:
/// - `impl TryFrom<&TightBeam> for TargetType` that extracts optional fields
/// - `impl TryFrom<TightBeam> for TargetType` that delegates to the reference
///   impl
#[macro_export]
macro_rules! impl_try_from {
	// For fields directly on TightBeam
	($source:ty, $param:ident => $target:ty: $field:ident) => {
		impl TryFrom<&$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from($param: &$source) -> Result<Self, Self::Error> {
				$param.$field.clone().ok_or($crate::error::TightBeamError::InvalidMetadata)
			}
		}

		impl TryFrom<$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from($param: $source) -> Result<Self, Self::Error> {
				(&$param).try_into()
			}
		}
	};

	($source:ty, $param:ident => $target:ty: $field:ident, $error:expr) => {
		impl TryFrom<&$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from($param: &$source) -> core::result::Result<Self, Self::Error> {
				$param.$field.clone().ok_or($error)
			}
		}

		impl TryFrom<$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from($param: $source) -> core::result::Result<Self, Self::Error> {
				(&$param).try_into()
			}
		}
	};

	// For fields in metadata
	($source:ty, $param:ident => $target:ty: metadata.$field:ident) => {
		impl TryFrom<&$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from($param: &$source) -> Result<Self, Self::Error> {
				$param
					.metadata
					.$field
					.clone()
					.ok_or($crate::error::TightBeamError::InvalidMetadata)
			}
		}

		impl TryFrom<$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from($param: $source) -> Result<Self, Self::Error> {
				(&$param).try_into()
			}
		}
	};

	($source:ty, $param:ident => $target:ty: metadata.$field:ident, $error:expr) => {
		impl TryFrom<&$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from($param: &$source) -> core::result::Result<Self, Self::Error> {
				$param.metadata.$field.clone().ok_or($error)
			}
		}

		impl TryFrom<$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from($param: $source) -> core::result::Result<Self, Self::Error> {
				(&$param).try_into()
			}
		}
	};
}

/// Encode a value to DER format
#[inline]
pub fn encode<T: der::Encode>(value: &T) -> Result<Vec<u8>, TightBeamError> {
	Ok(der::Encode::to_der(value)?)
}

/// Decode a value from DER format
#[inline]
pub fn decode<'a, T: der::Decode<'a>, B: AsRef<[u8]>>(bytes: &'a B) -> Result<T, TightBeamError> {
	Ok(der::Decode::from_der(bytes.as_ref())?)
}

/// Compress data using the specified algorithm.
#[cfg(feature = "compress")]
#[inline]
pub fn compress(
	data: impl AsRef<[u8]>,
	algorithm: CompressionAlgorithm,
) -> Result<(Vec<u8>, CompressionInfo), CompressionError> {
	let data = data.as_ref();
	match algorithm {
		CompressionAlgorithm::NONE => Ok((data.to_vec(), CompressionInfo::NONE(der::asn1::Null))),
		CompressionAlgorithm::ZSTD => {
			use std::io::Cursor;

			let mut output: Vec<u8> = vec![];
			let mut encoder = zeekstd::Encoder::new(&mut output)?;
			std::io::copy(&mut Cursor::new(data), &mut encoder)?;
			encoder.finish()?;

			let level = 0;
			let original_size = data.len() as u64;
			let info = CompressionInfo::ZSTD(crate::asn1::ZstdInfo { level, original_size });

			Ok((output, info))
		}
	}
}
/// Compress data using the specified algorithm.
#[cfg(feature = "compress")]
#[inline]
pub fn decompress(data: impl AsRef<[u8]>, info: &CompressionInfo) -> Result<Vec<u8>, CompressionError> {
	let data = data.as_ref();
	match info {
		crate::asn1::CompressionInfo::NONE(_) => Ok(data.to_vec()),
		#[cfg(feature = "zstd")]
		crate::asn1::CompressionInfo::ZSTD(_) => {
			use std::io::Cursor;

			let cursor = Cursor::new(data);
			let mut decoder = zeekstd::Decoder::new(cursor)?;
			let mut out: Vec<u8> = Vec::new();

			std::io::copy(&mut decoder, &mut out)?;
			Ok(out)
		}
		#[cfg(feature = "gzip")]
		crate::asn1::CompressionInfo::GZIP(_) => {
			todo!("gzip decompression not implemented yet");
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use der::asn1::OctetStringRef;
	use der::oid::ObjectIdentifier;

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
		let algorithms = [CompressionAlgorithm::NONE, CompressionAlgorithm::ZSTD];

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

		for &alg in &algorithms {
			for &data in &cases {
				let (compressed, info) = compress(data, alg)?;
				let decompressed = decompress(&compressed, &info)?;
				assert_eq!(decompressed, data);

				// Assert CompressionInfo metadata
				match &info {
					crate::asn1::CompressionInfo::NONE(_) => {
						// NONE should be identical
						assert_eq!(compressed, data);
					}
					#[cfg(feature = "zstd")]
					crate::asn1::CompressionInfo::ZSTD(z) => {
						assert_eq!(z.original_size as usize, data.len());
						assert_eq!(z.level, 0);
					}
					#[cfg(feature = "gzip")]
					crate::asn1::CompressionInfo::GZIP(_) => {
						unreachable!("GZIP not in algorithms set");
					}
				}
			}
		}

		Ok(())
	}
}
