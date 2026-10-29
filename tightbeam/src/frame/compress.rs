#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::cms::content_info::CmsVersion;
use crate::core::Inflator;
use crate::error::Result;
use crate::frame::{Metadata, Opened};
use crate::{Frame, TightBeamError};

impl Metadata {
	/// Refuse a `compactness` that `inflator` does not reverse, before any
	/// work on the body (README §5.7.2).
	///
	/// Metadata with no `compactness` passes. A `CompressedData` passes when
	/// each of these holds:
	///
	/// - Its version is 0 (RFC 3274 §1.1).
	/// - Its `encapContentInfo` carries no `eContent`, because the compressed
	///   bytes travel in `Frame.message`.
	/// - Its `compressionAlgorithm` names [`Inflator::algorithm_oid`].
	/// - [`Inflator::admits_parameters`] admits the parameters of that algorithm.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnexpectedAlgorithm`] -- the algorithm differs from the inflator's.
	/// - [`TightBeamError::InvalidMetadata`] -- the version, the `eContent`, or
	///   the parameters break a rule above.
	pub(super) fn admit_compactness(&self, inflator: &dyn Inflator) -> Result<()> {
		let Some(compactness) = self.compactness.as_ref() else {
			return Ok(());
		};

		let received = compactness.compression_alg.oid;
		let expected = inflator.algorithm_oid();
		if received != expected {
			return Err(TightBeamError::UnexpectedAlgorithm((received, expected).into()));
		}

		let first_version = compactness.version == CmsVersion::V0;
		let detached = compactness.encap_content_info.econtent.is_none();
		let parameters = inflator.admits_parameters(compactness.compression_alg.parameters.as_ref());
		if !(first_version && detached && parameters) {
			return Err(TightBeamError::InvalidMetadata);
		}

		Ok(())
	}

	/// Inflate `body`, the body that the `compactness` of this metadata
	/// describes, once [`Self::admit_compactness`] admits `inflator`. Every
	/// inflate of a received body runs through it, so the description refuses
	/// before the codec allocates (CWE-409).
	///
	/// # Errors
	///
	/// - [`TightBeamError::InvalidMetadata`] -- this metadata carries no
	///   `compactness`, or one that breaks a rule of [`Self::admit_compactness`].
	/// - [`TightBeamError::UnexpectedAlgorithm`] -- the algorithm differs from the inflator's.
	/// - The error of [`Inflator::decompress`], when the codec rejects the body.
	pub(super) fn inflate(&self, inflator: &dyn Inflator, body: &[u8]) -> Result<Vec<u8>> {
		if self.compactness.is_none() {
			return Err(TightBeamError::InvalidMetadata);
		}

		self.admit_compactness(inflator)?;
		inflator.decompress(body)
	}
}

impl Frame {
	/// Decompress the message body in place for a frame that is cleartext but
	/// compressed, and clear `compactness` on success.
	///
	/// - A successful inflate moves the FI digest and the signature into the [`Opened`] it returns.
	/// - A frame with no `compactness` stays as it is, and its [`Opened`] holds neither.
	/// - A refused description or a failed decompression leaves the frame in its state before the call.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnexpectedAlgorithm`] -- the `CompressedData` names
	///   another algorithm than [`Inflator::algorithm_oid`].
	/// - [`TightBeamError::InvalidMetadata`] -- the `CompressedData` is not
	///   version 0, carries an `eContent`, or names parameters that
	///   [`Inflator::admits_parameters`] refuses.
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
		if self.metadata.compactness.is_none() {
			return Ok(Opened { integrity: None, nonrepudiation: None });
		}

		// The inflate reads the body in place, so a refused description or a
		// failed decompression leaves the frame as it was.
		self.message = self.metadata.inflate(inflator, &self.message)?;
		self.metadata.compactness = None;
		Ok(self.take_opened())
	}
}

#[cfg(all(test, feature = "zstd"))]
mod tests {
	use crate::cms::content_info::CmsVersion;
	use crate::cms::signed_data::EncapsulatedContentInfo;
	use crate::compress::{Compressor, ZstdCompression};
	use crate::der::asn1::{Null, OctetString};
	use crate::der::{Any, Decode};
	use crate::error::{ReceivedExpectedError, Result};
	use crate::oids::{COMPRESSION_ZLIB, COMPRESSION_ZSTD, DATA};
	use crate::spki::AlgorithmIdentifierOwned;
	use crate::testing::TestMessage;
	use crate::{hex, tb_cases};
	use crate::{CompressedData, Frame, Metadata, TightBeamError, Version};

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

	/// The DER of the zlib algorithm identifier that RFC 3274 §1.1 prints in
	/// its SMIMECapability: `id-alg-zlibCompress`, its parameters omitted.
	const RFC_3274_ZLIB: [u8; 15] = hex!("300D060B2A864886F70D0109100308");

	/// The `CompressedData` of a zstd body whose algorithm carries
	/// `parameters`.
	fn zstd_description(parameters: Option<Any>) -> CompressedData {
		let compression_alg = AlgorithmIdentifierOwned { oid: COMPRESSION_ZSTD, parameters };
		let encap_content_info = EncapsulatedContentInfo { econtent_type: DATA, econtent: None };
		CompressedData { version: CmsVersion::V0, compression_alg, encap_content_info }
	}

	/// The `CompressedData` of a zstd body whose parameters name `level`.
	fn zstd_at_level(level: i32) -> Result<CompressedData> {
		let level = Any::encode_from(&level)?;
		Ok(zstd_description(Some(level)))
	}

	/// The compressed frame of [`compressed_frame`], described by
	/// `description` in place of the description its compressor gave.
	fn described(description: CompressedData) -> Result<Frame> {
		let mut frame = compressed_frame(b"inflate me")?;
		frame.metadata.compactness = Some(description);
		Ok(frame)
	}

	#[test]
	fn the_rfc_3274_zlib_identifier_decodes_to_its_oid() -> Result<()> {
		let algorithm = AlgorithmIdentifierOwned::from_der(&RFC_3274_ZLIB)?;
		assert_eq!(algorithm, AlgorithmIdentifierOwned { oid: COMPRESSION_ZLIB, parameters: None });
		Ok(())
	}

	/// A body that names zlib by the identifier of RFC 3274 is refused at
	/// the algorithm before the zstd codec reads it, and the frame keeps its
	/// state.
	#[test]
	fn a_body_under_the_rfc_3274_zlib_identifier_is_refused_at_its_oid() -> Result<()> {
		let compression_alg = AlgorithmIdentifierOwned::from_der(&RFC_3274_ZLIB)?;
		let mut frame = described(CompressedData { compression_alg, ..zstd_description(None) })?;
		let original = frame.clone();

		let refused = frame.inflate_in_place(&ZstdCompression::default());
		let algorithms = ReceivedExpectedError::from((COMPRESSION_ZLIB, COMPRESSION_ZSTD));
		assert!(matches!(refused, Err(TightBeamError::UnexpectedAlgorithm(found)) if found == algorithms));
		assert_eq!(frame, original);
		Ok(())
	}

	// A receiver refuses a description outside RFC 3274 (a version other than
	// 0, an attached `eContent`) and zstd parameters that name no level in its
	// range.
	tb_cases! {
		fn a_description_a_receiver_refuses_leaves_the_body_compressed(description: CompressedData) -> Result<()> {
			let mut frame = described(description)?;
			let refused = frame.inflate_in_place(&ZstdCompression::default());
			assert!(matches!(refused, Err(TightBeamError::InvalidMetadata)));
			Ok(())
		}
		cases {
			at_version_one => CompressedData { version: CmsVersion::V1, ..zstd_description(None) },
			with_attached_content => CompressedData {
				encap_content_info: EncapsulatedContentInfo {
					econtent_type: DATA,
					econtent: Some(Any::encode_from(&OctetString::new(*b"attached")?)?),
				},
				..zstd_description(None)
			},
			past_the_largest_level => zstd_at_level(zstd_safe::max_c_level().saturating_add(1))?,
			below_the_smallest_level => zstd_at_level(zstd_safe::min_c_level().saturating_sub(1))?,
			under_null_parameters => zstd_description(Some(Any::encode_from(&Null)?)),
		}
	}

	// A level inside the range zstd accepts passes, though the decoder never
	// reads it.
	tb_cases! {
		fn a_level_inside_the_zstd_range_inflates(level: i32) -> Result<()> {
			let mut frame = described(zstd_at_level(level)?)?;
			let _opened = frame.inflate_in_place(&ZstdCompression::default())?;
			assert_eq!(frame.message, b"inflate me");
			Ok(())
		}
		cases {
			at_the_smallest_level => zstd_safe::min_c_level(),
			at_the_house_level => 3,
			at_the_largest_level => zstd_safe::max_c_level(),
		}
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
