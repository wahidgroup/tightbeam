//! Frame body compression.
//!
//! - [`Compressor`] compresses a message body and describes the result as CMS [`CompressedData`].
//! - [`Inflator`] reverses a compressor and returns the original body.
//! - [`ZstdCompression`] implements both with zstd and bounds the output of decompression (CWE-409).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::{cms::signed_data::EncapsulatedContentInfo, error::CompressionResult, CompressedData};

#[cfg(feature = "zstd")]
use crate::{
	cms::content_info::CmsVersion, constants::DEFAULT_MAX_DECOMPRESSED_LEN, error::CompressionError,
	oids::COMPRESSION_CONTENT, spki::AlgorithmIdentifierOwned,
};

pub use crate::core::Inflator;

/// zstd's own default level, named here so the compressor has one home for it.
#[cfg(feature = "zstd")]
const ZSTD_LEVEL: i32 = 3;

/// Growth step for the decompression buffer.
///
/// Decompression starts small and grows toward the ceiling, so a frame that
/// declares a large content size cannot make the first allocation the attack.
#[cfg(feature = "zstd")]
const RESERVE_HINT: usize = 64 * 1024;

/// The smallest window log zstd accepts, `ZSTD_WINDOWLOG_ABSOLUTEMIN` in
/// `zstd.h`.
///
/// `zstd-safe` exports the window bounds only under its `experimental`
/// feature, so this module names them.
#[cfg(feature = "zstd")]
const ZSTD_WINDOW_LOG_MIN: u32 = 10;

/// The largest window log zstd accepts on a 32-bit target,
/// `ZSTD_WINDOWLOG_MAX_32` in `zstd.h`.
#[cfg(all(feature = "zstd", target_pointer_width = "32"))]
const ZSTD_WINDOW_LOG_MAX: u32 = 30;

/// The largest window log zstd accepts on a 64-bit target,
/// `ZSTD_WINDOWLOG_MAX_64` in `zstd.h`.
#[cfg(all(feature = "zstd", not(target_pointer_width = "32")))]
const ZSTD_WINDOW_LOG_MAX: u32 = 31;

/// Compresses a frame body into bytes and the CMS [`CompressedData`] that
/// describes them.
///
/// [`Inflator`] is the reverse direction.
pub trait Compressor {
	/// Compresses `data` and returns the compressed bytes with their
	/// [`CompressedData`] metadata.
	///
	/// `content_info` names the encapsulated content. When it is `None`, the
	/// implementation picks its own default, which is [`COMPRESSION_CONTENT`]
	/// for [`ZstdCompression`].
	///
	/// # Errors
	///
	/// - [`CompressionError`] when the backend fails to compress `data`.
	fn compress(
		&self,
		data: &[u8],
		content_info: Option<EncapsulatedContentInfo>,
	) -> CompressionResult<(Vec<u8>, CompressedData)>;
}

/// zstd-backed compressor. It requires `std` I/O, so it lives behind the
/// `zstd` feature.
///
/// The default ceiling is [`DEFAULT_MAX_DECOMPRESSED_LEN`].
/// Raise or lower it with [`with_max_output`](Self::with_max_output).
///
/// # Decompression bounds
///
/// - Output larger than `max_output` bytes is rejected with
///   [`CompressionError::OutputLimitExceeded`] instead of inflating a
///   peer-supplied bomb into memory (CWE-409).
/// - The window a frame header declares is bounded by the same ceiling,
///   rounded up to a power of two, so a short header cannot make the decoder
///   reserve more memory than the output may fill (CWE-770).
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
	/// Creates a compressor whose decompression output is capped at
	/// `max_output` bytes.
	pub const fn with_max_output(max_output: usize) -> Self {
		Self { max_output }
	}

	/// The largest window log a frame may declare, the smallest power of two
	/// at or above `max_output` within the range zstd accepts.
	///
	/// libzstd sizes its stream buffers from the declared window before it
	/// produces any output, and admits up to 128 MiB by default.
	fn window_log_max(&self) -> u32 {
		let ceil_log2 = usize::BITS - self.max_output.saturating_sub(1).leading_zeros();
		ceil_log2.clamp(ZSTD_WINDOW_LOG_MIN, ZSTD_WINDOW_LOG_MAX)
	}
}

#[cfg(feature = "zstd")]
impl Compressor for ZstdCompression {
	fn compress(
		&self,
		data: &[u8],
		content_info: Option<EncapsulatedContentInfo>,
	) -> CompressionResult<(Vec<u8>, CompressedData)> {
		let mut output: Vec<u8> = Vec::with_capacity(zstd_safe::compress_bound(data.len()));
		zstd_safe::compress(&mut output, data, ZSTD_LEVEL).map_err(CompressionError::ZSTD)?;

		let compression_alg = AlgorithmIdentifierOwned::from(self);
		let encap_content_info =
			content_info.unwrap_or(EncapsulatedContentInfo { econtent_type: COMPRESSION_CONTENT, econtent: None });
		let compressed_data = CompressedData { version: CmsVersion::V0, compression_alg, encap_content_info };

		Ok((output, compressed_data))
	}
}

#[cfg(feature = "zstd")]
impl Inflator for ZstdCompression {
	fn decompress(&self, data: &[u8]) -> crate::error::Result<Vec<u8>> {
		let mut ctx = zstd_safe::DCtx::create();
		let window_log_max = zstd_safe::DParameter::WindowLogMax(self.window_log_max());
		ctx.set_parameter(window_log_max).map_err(CompressionError::ZSTD)?;

		let mut input = zstd_safe::InBuffer { src: data, pos: 0 };

		// One octet past the cap distinguishes an over-limit stream from one
		// that lands exactly on it, and caps the allocation at the same time.
		let ceiling = self.max_output.saturating_add(1);
		let mut out: Vec<u8> = Vec::with_capacity(ceiling.min(RESERVE_HINT));

		loop {
			let consumed = input.pos;
			let produced = out.len();
			if produced >= ceiling {
				return Err(CompressionError::OutputLimitExceeded(self.max_output).into());
			}
			if out.capacity() == produced {
				out.reserve(RESERVE_HINT.min(ceiling - produced));
			}

			let remaining = {
				let mut buffer = zstd_safe::OutBuffer::around_pos(&mut out, produced);
				ctx.decompress_stream(&mut buffer, &mut input).map_err(CompressionError::ZSTD)?
			};

			// A frame boundary is the only successful exit.
			if remaining == 0 {
				break;
			}

			if input.pos == data.len() {
				return Err(CompressionError::Truncated.into());
			}

			// Neither cursor moved, so a further iteration repeats this one.
			// Refusing here bounds the work an input can demand.
			if input.pos == consumed && out.len() == produced {
				return Err(CompressionError::Stalled.into());
			}
		}

		if out.len() > self.max_output {
			return Err(CompressionError::OutputLimitExceeded(self.max_output).into());
		}

		// Octets past the frame belong to a second container, such as a
		// skippable frame or a seekable-format seek table.
		if input.pos != data.len() {
			return Err(CompressionError::TrailingBytes(data.len() - input.pos).into());
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
	use crate::tb_cases;

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

	/// One zstd frame followed by a skippable frame whose payload ends in
	/// the seekable-format magic number.
	///
	/// The protocol emits a single plain frame, so this octet stream reaches
	/// the decoder only from a hostile peer.
	const TRAILING_SEEK_TABLE: &[u8] = &[
		0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x54, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0xfb, 0xff, 0x39, 0xc0, 0x02,
		0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x02, 0x00, 0x10, 0x00,
		0x02, 0x00, 0x10, 0x00, 0x03, 0x12, 0x0a, 0x00, 0x5e, 0x2a, 0x4d, 0x18, 0x11, 0x00, 0x00, 0x00, 0x2f, 0x00,
		0x00, 0x00, 0x40, 0x42, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xb1, 0xea, 0x92, 0x8f,
	];

	/// The skippable frame alone, taken from the octet stream above.
	const SKIPPABLE_TAIL: &[u8] = TRAILING_SEEK_TABLE.split_at(44).1;

	#[test]
	fn seekable_footer_input_terminates() -> Result<()> {
		let result = ZstdCompression::with_max_output(65536).decompress(TRAILING_SEEK_TABLE);
		assert!(matches!(result, Err(crate::TightBeamError::CompressionError(_))));
		Ok(())
	}

	#[test]
	fn octets_after_the_frame_are_rejected() -> Result<()> {
		let mut framed = compress_zeros(4096)?;
		framed.extend_from_slice(SKIPPABLE_TAIL);

		let result = ZstdCompression::with_max_output(65536).decompress(&framed);
		assert!(matches!(
			result,
			Err(crate::TightBeamError::CompressionError(CompressionError::TrailingBytes(_)))
		));

		Ok(())
	}

	/// A frame whose header declares a window of `2^window_log` octets and
	/// whose one RLE block emits a single octet.
	///
	/// The protocol's compressor sizes the window to the content, so a
	/// window past the payload reaches the decoder only from a hostile peer.
	fn frame_declaring_window(window_log: u8) -> Vec<u8> {
		// The window descriptor holds the window log less 10 in its top five
		// bits (RFC 8878, section 3.1.1.1.2).
		let window_descriptor = (window_log - 10) << 3;
		vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, window_descriptor, 0x0b, 0x00, 0x00, 0x41]
	}

	// A frame may declare a window up to the output ceiling rounded up to a
	// power of two, which a cap between two powers exercises.
	tb_cases! {
		fn a_window_within_the_rounded_output_ceiling_decodes((max_output, window_log): (usize, u8)) -> Result<()> {
			let frame = frame_declaring_window(window_log);
			let out = ZstdCompression::with_max_output(max_output).decompress(&frame)?;
			assert_eq!(out, vec![0x41]);

			Ok(())
		}
		cases {
			at_a_power_of_two_ceiling => (65536, 16),
			below_the_next_power_of_two => (49152, 16),
			below_the_smallest_window => (512, 10),
			at_an_unbounded_ceiling => (usize::MAX, 16),
		}
	}

	// A wider window is refused before the decoder reserves memory for it.
	tb_cases! {
		fn a_window_past_the_rounded_output_ceiling_is_refused((max_output, window_log): (usize, u8)) {
			let frame = frame_declaring_window(window_log);
			let result = ZstdCompression::with_max_output(max_output).decompress(&frame);
			assert!(matches!(
				result,
				Err(crate::TightBeamError::CompressionError(CompressionError::ZSTD(_)))
			));
		}
		cases {
			past_a_power_of_two_ceiling => (65536, 17),
			past_the_next_power_of_two => (49152, 17),
			past_the_default_ceiling => (DEFAULT_MAX_DECOMPRESSED_LEN, 27),
		}
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
