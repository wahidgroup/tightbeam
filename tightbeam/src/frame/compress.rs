use crate::core::Inflator;
use crate::error::Result;
use crate::Frame;

impl Frame {
	/// Decompress the message body in place for a cleartext-but-compressed
	/// frame, clearing `compactness` on success.
	///
	/// A frame without `compactness` is returned unchanged. On decompression
	/// failure the frame is restored unchanged.
	///
	/// # Errors
	///
	/// Returns the underlying codec error when the inflator rejects the body.
	pub fn inflate_in_place(&mut self, inflator: &dyn Inflator) -> Result<()> {
		let Some(compactness) = self.metadata.compactness.take() else {
			return Ok(());
		};

		let compressed = core::mem::take(&mut self.message);
		match inflator.decompress(&compressed) {
			Ok(plaintext) => {
				self.message = plaintext;
				Ok(())
			}
			Err(err) => {
				self.message = compressed;
				self.metadata.compactness = Some(compactness);
				Err(err)
			}
		}
	}
}

#[cfg(all(test, feature = "compress"))]
mod tests {
	#[cfg(not(feature = "std"))]
	use alloc::vec;

	use crate::compress::{Compressor, ZstdCompression};
	use crate::error::Result;
	use crate::testing::TestMessage;
	use crate::{Frame, Metadata, Version};

	fn compressed_frame(body: &[u8]) -> Result<Frame> {
		let zstd = ZstdCompression::default();
		let (compressed, compression_info) = zstd.compress(body, None)?;

		let mut metadata = Metadata::empty();
		metadata.id = b"inf-001".to_vec();
		metadata.compactness = Some(compression_info);

		Ok(Frame {
			version: Version::V0,
			metadata,
			message: compressed,
			integrity: None,
			nonrepudiation: None,
		})
	}

	#[test]
	fn restores_original_body_and_clears_compactness() -> Result<()> {
		let body = b"inflate me".repeat(64);
		let mut frame = compressed_frame(&body)?;
		frame.inflate_in_place(&ZstdCompression::default())?;

		assert!(frame.metadata.compactness.is_none());
		assert_eq!(frame.message, body);
		Ok(())
	}

	#[test]
	fn corrupt_body_restores_frame() -> Result<()> {
		let mut frame = compressed_frame(b"inflate me")?;
		frame.message = vec![0xFF; 8];

		let original = frame.clone();
		let result = frame.inflate_in_place(&ZstdCompression::default());
		assert!(result.is_err());
		assert_eq!(frame, original);
		Ok(())
	}

	#[test]
	fn uncompressed_frame_untouched() -> Result<()> {
		let message = TestMessage::sample(None);
		let mut frame = compose! { V0: id: "inf-002", order: 1u64, message: message }?;
		let original = frame.clone();

		frame.inflate_in_place(&ZstdCompression::default())?;

		assert_eq!(frame, original);
		Ok(())
	}
}
