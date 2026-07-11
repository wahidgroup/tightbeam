#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::{cms::signed_data::EncapsulatedContentInfo, error::CompressionResult, CompressedData};

#[cfg(feature = "zstd")]
use crate::{
	cms::content_info::CmsVersion, constants::DEFAULT_MAX_DECOMPRESSED_LEN, error::CompressionError,
	spki::AlgorithmIdentifierOwned,
};

pub use crate::core::Inflator;

/// Trait for compressing data
pub trait Compressor {
	/// Compress data and return the compressed bytes along with compression metadata
	fn compress(
		&self,
		data: &[u8],
		content_info: Option<EncapsulatedContentInfo>,
	) -> CompressionResult<(Vec<u8>, CompressedData)>;
}

/// zstd-backed compressor; requires `std` I/O, hence lives behind `zstd`.
///
/// Decompression is bounded: output larger than `max_output` bytes is
/// rejected with [`CompressionError::OutputLimitExceeded`] instead of
/// inflating a wire-supplied bomb into memory (CWE-409).
///
/// The default ceiling is [`DEFAULT_MAX_DECOMPRESSED_LEN`].
/// Raise or lower it with [`with_max_output`](Self::with_max_output).
#[cfg(feature = "zstd")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZstdCompression {
	max_output: usize,
}

#[cfg(feature = "zstd")]
impl Default for ZstdCompression {
	fn default() -> Self {
		Self { max_output: DEFAULT_MAX_DECOMPRESSED_LEN }
	}
}

#[cfg(feature = "zstd")]
impl ZstdCompression {
	/// Create a compressor whose decompression output is capped at
	/// `max_output` bytes
	pub const fn with_max_output(max_output: usize) -> Self {
		Self { max_output }
	}
}

#[cfg(feature = "zstd")]
impl Compressor for ZstdCompression {
	fn compress(
		&self,
		data: &[u8],
		content_info: Option<EncapsulatedContentInfo>,
	) -> CompressionResult<(Vec<u8>, CompressedData)> {
		use std::io::Cursor;

		let mut output: Vec<u8> = vec![];
		let mut encoder = zeekstd::Encoder::new(&mut output)?;
		std::io::copy(&mut Cursor::new(data), &mut encoder)?;
		encoder.finish()?;

		let compression_alg = AlgorithmIdentifierOwned::from(self);
		let encap_content_info = content_info
			.unwrap_or(EncapsulatedContentInfo { econtent_type: crate::oids::COMPRESSION_CONTENT, econtent: None });
		let compressed_data = CompressedData { version: CmsVersion::V0, compression_alg, encap_content_info };

		Ok((output, compressed_data))
	}
}

#[cfg(feature = "zstd")]
impl Inflator for ZstdCompression {
	fn decompress(&self, data: &[u8]) -> crate::error::Result<Vec<u8>> {
		use std::io::{Cursor, Read};

		let cursor = Cursor::new(data);
		let decoder = zeekstd::Decoder::new(cursor).map_err(CompressionError::from)?;
		let mut out: Vec<u8> = Vec::new();

		// Read one byte past the cap so an over-limit stream is
		// distinguishable from one that is exactly at the limit.
		let limit = self.max_output as u64;
		let copied =
			std::io::copy(&mut decoder.take(limit.saturating_add(1)), &mut out).map_err(CompressionError::from)?;
		if copied > limit {
			return Err(CompressionError::OutputLimitExceeded(self.max_output).into());
		}

		Ok(out)
	}
}

#[cfg(feature = "zstd")]
impl From<&ZstdCompression> for AlgorithmIdentifierOwned {
	fn from(_: &ZstdCompression) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: crate::oids::COMPRESSION_ZSTD, parameters: None }
	}
}

#[cfg(feature = "zstd")]
impl From<ZstdCompression> for AlgorithmIdentifierOwned {
	fn from(compression: ZstdCompression) -> AlgorithmIdentifierOwned {
		(&compression).into()
	}
}

#[cfg(all(test, feature = "zstd"))]
mod tests {
	use super::*;
	use crate::error::Result;

	fn compress_zeros(len: usize) -> Result<Vec<u8>> {
		let data = vec![0u8; len];
		let (compressed, _) = ZstdCompression::default().compress(&data, None)?;
		Ok(compressed)
	}

	#[test]
	fn decompress_within_limit_round_trips() -> Result<()> {
		let compressed = compress_zeros(4096)?;

		let out = ZstdCompression::with_max_output(4096).decompress(&compressed)?;
		assert_eq!(out, vec![0u8; 4096]);

		Ok(())
	}

	#[test]
	fn decompress_over_limit_rejected() -> Result<()> {
		let compressed = compress_zeros(4096)?;

		let result = ZstdCompression::with_max_output(4095).decompress(&compressed);
		assert!(matches!(
			result,
			Err(crate::TightBeamError::CompressionError(CompressionError::OutputLimitExceeded(
				4095
			)))
		));

		Ok(())
	}

	#[test]
	fn decompression_bomb_rejected_by_default_cap() -> Result<()> {
		let compressed = compress_zeros(DEFAULT_MAX_DECOMPRESSED_LEN + 1)?;

		let result = ZstdCompression::default().decompress(&compressed);
		assert!(matches!(
			result,
			Err(crate::TightBeamError::CompressionError(CompressionError::OutputLimitExceeded(
				_
			)))
		));

		Ok(())
	}
}
