use crate::core::Inflator;
use crate::error::Result;
use crate::frame::Opened;
use crate::Frame;

impl Frame {
	/// Decompress the message body in place for a frame that is cleartext but
	/// compressed, and clear `compactness` on success.
	///
	/// - A successful inflate moves the FI digest and the signature into the [`Opened`] it returns.
	/// - A frame with no `compactness` stays as it is, and its [`Opened`] holds neither.
	/// - A failed decompression restores the frame to its state before the call.
	///
	/// # Errors
	///
	/// - The error of [`Inflator::decompress`], when the codec rejects the body.
	///
	/// # Examples
	///
	/// ```
	/// # #[cfg(feature = "zstd")]
	/// # {
	/// use tightbeam::compose;
	/// use tightbeam::compress::ZstdCompression;
	/// use tightbeam::testing::TestMessage;
	///
	/// let message = TestMessage::sample(None);
	/// let mut frame = compose! {
	///     V1: id: "packed", order: 1u64, message: message.clone(), compactness: ZstdCompression::default()
	/// }?;
	///
	/// let _opened = frame.inflate_in_place(&ZstdCompression::default())?;
	/// assert_eq!(tightbeam::decode::<TestMessage>(frame.message())?, message);
	/// # }
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// ```
	pub fn inflate_in_place(&mut self, inflator: &dyn Inflator) -> Result<Opened> {
		let Some(compactness) = self.metadata.compactness.take() else {
			return Ok(Opened { integrity: None, nonrepudiation: None });
		};

		let compressed = core::mem::take(&mut self.message);
		match inflator.decompress(&compressed) {
			Ok(plaintext) => {
				self.message = plaintext;
				Ok(self.take_opened())
			}
			Err(err) => {
				self.message = compressed;
				self.metadata.compactness = Some(compactness);
				Err(err)
			}
		}
	}
}

#[cfg(all(test, feature = "zstd"))]
mod tests {
	use crate::compress::{Compressor, ZstdCompression};
	use crate::error::Result;
	use crate::testing::TestMessage;
	use crate::{Frame, Metadata, Version};

	fn compressed_frame(body: impl AsRef<[u8]>) -> Result<Frame> {
		let body = body.as_ref();
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
		let _opened = frame.inflate_in_place(&ZstdCompression::default())?;
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
		let _opened = frame.inflate_in_place(&ZstdCompression::default())?;
		assert_eq!(frame, original);
		Ok(())
	}

	#[cfg(all(feature = "secp256k1", feature = "signature"))]
	mod opened {
		use super::*;
		use crate::crypto::sign::ecdsa::Secp256k1Signature;
		use crate::testing::{TestIdentity, TestKey};
		use crate::TightBeamError;

		/// The signature covers the compressed body, so the inflate moves it
		/// out of the frame and into the product it returns.
		#[test]
		fn an_inflate_moves_the_signature_out_of_the_frame() -> Result<()> {
			let message = TestMessage::sample(None);
			let signer = TestIdentity::certified(TestKey::insecure_fixed_signing());
			let mut frame = compose! {
				V1: id: "inf-003",
					order: 1u64,
					message: message,
					compactness: ZstdCompression::default(),
					nonrepudiation<Secp256k1Signature, _>: signer
			}?;
			let signature = frame.nonrepudiation().cloned().ok_or(TightBeamError::MissingSignatureInfo)?;

			let opened = frame.inflate_in_place(&ZstdCompression::default())?;
			assert_eq!((frame.nonrepudiation(), opened.nonrepudiation()), (None, Some(&signature)));
			Ok(())
		}
	}
}
