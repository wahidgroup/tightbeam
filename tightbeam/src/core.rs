#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::der::{EncodeValue, Tagged};
use crate::error::Result;
use crate::{Frame, Metadata, TightBeamError, Version};

#[cfg(feature = "aead")]
use crate::asn1::OctetString;
#[cfg(feature = "signature")]
use crate::crypto::hash::Digest;
#[cfg(feature = "crypto")]
use crate::crypto::profiles::SecurityProfile;
#[cfg(feature = "signature")]
use crate::crypto::sign::{verify_canonical, PrehashVerifier, SignatureEncoding};
#[cfg(feature = "signature")]
use crate::der::oid::AssociatedOid;
#[cfg(feature = "signature")]
use crate::der::Encode;
#[cfg(feature = "signature")]
use crate::error::ReceivedExpectedError;
#[cfg(feature = "aead")]
use crate::EncryptedContentInfo;
#[cfg(feature = "signature")]
use crate::SignerInfo;

/// Decompresses message bodies.
///
/// A single always-present trait so downstream code compiles identically
/// under every feature combination.
pub trait Inflator {
	/// Decompress `data`, returning the decompressed bytes.
	///
	/// # Errors
	///
	/// Returns an error when the underlying codec rejects the input.
	fn decompress(&self, data: &[u8]) -> Result<Vec<u8>>;
}

/// A marker trait for types that can be used as the body of a TightBeam
/// message.
pub trait Message:
	EncodeValue + Tagged + for<'a> crate::der::Decode<'a> + Clone + PartialEq + core::fmt::Debug + Sized + Send + Sync
{
	/// Minimum version required to send this message type.
	const MIN_VERSION: Version = Version::V0;
	/// Whether this message type requires non-repudiation (signing).
	const MUST_BE_NON_REPUDIABLE: bool = false;
	/// Whether this message type requires confidentiality (encryption).
	const MUST_BE_CONFIDENTIAL: bool = false;
	/// Whether this message type requires compression.
	const MUST_BE_COMPRESSED: bool = false;
	/// Whether this message type requires prioritization.
	const MUST_BE_PRIORITIZED: bool = false;
	/// Whether this message type requires message integrity (hashing).
	const MUST_HAVE_MESSAGE_INTEGRITY: bool = false;
	/// Whether this message type requires frame integrity (hashing).
	const MUST_HAVE_FRAME_INTEGRITY: bool = false;

	/// Whether this message type has a custom security profile that
	/// constrains algorithms.
	const HAS_PROFILE: bool = false;

	/// The security profile that constrains which cryptographic algorithms
	/// can be used with this message type. Defaults to TightbeamProfile.
	#[cfg(feature = "crypto")]
	type Profile: SecurityProfile;
}

/// A trait for types that represent a TightBeam message with associated data.
pub trait TightBeamLike:
	crate::der::Encode
	+ for<'a> crate::der::Decode<'a>
	+ Clone
	+ core::fmt::Debug
	+ PartialEq
	+ Into<Metadata>
	+ Into<Version>
{
}

impl Frame {
	/// Get a reference to the metadata.
	///
	/// For owned, use `From<Frame> for Metadata` which consumes the frame.
	pub fn as_metadata(&self) -> &Metadata {
		&self.metadata
	}
}

#[cfg(feature = "signature")]
impl Frame {
	/// Get a reference to the signature info if present.
	pub fn signature_info(&self) -> Option<&SignerInfo> {
		self.nonrepudiation.as_ref()
	}

	/// Encode the Frame for signature verification (TBS - to-be-signed).
	///
	/// Excludes `nonrepudiation` without cloning the frame. The borrowing
	/// `TbsScaffold` reuses the derived field encoders, so these bytes
	/// are bit-identical to the DER encoding of the frame with
	/// `nonrepudiation` set to `None`.
	pub fn to_tbs(&self) -> Result<Vec<u8>> {
		let scaffold = crate::frame::TbsScaffold {
			version: &self.version,
			metadata: &self.metadata,
			message: &self.message,
			integrity: self.integrity.as_ref(),
		};

		Ok(scaffold.to_der()?)
	}

	/// Verify the signature of the TightBeam message.
	///
	/// This verifies the signature against the entire TightBeam structure
	/// under the canonical convention. The TBS encoding is hashed once with
	/// `D` and the signature is checked against that prehash.
	///
	/// # Arguments
	/// * `verifier` - The verifier to use for signature verification
	///
	/// # Returns
	/// Ok(()) if the signature is valid
	///
	/// # Errors
	/// Returns an error if:
	/// - The TightBeam doesn't contain a signature
	/// - The SignerInfo advertises a digest other than `D`
	/// - Signature verification fails
	///
	/// # See also
	/// - [`Frame::sign_with_provider`]: the signing counterpart under the
	///   same canonical convention
	/// - [`Frame::to_tbs`]: the exact bytes the signature covers
	pub fn verify<S, D>(&self, verifier: &impl PrehashVerifier<S>) -> Result<()>
	where
		S: SignatureEncoding,
		D: Digest + AssociatedOid,
	{
		let signature_info = self.nonrepudiation.as_ref().ok_or(TightBeamError::MissingSignature)?;

		// The canonical convention binds the signature to the digest declared
		// in the SignerInfo. A mismatch is algorithm confusion, not merely a
		// bad signature.
		if signature_info.digest_alg.oid != D::OID {
			return Err(TightBeamError::UnexpectedAlgorithm(ReceivedExpectedError::from((
				signature_info.digest_alg.oid,
				D::OID,
			))));
		}

		let signature_bytes: &[u8] = signature_info.signature.as_bytes();
		let signature = S::try_from(signature_bytes).map_err(|_| TightBeamError::SignatureEncodingError)?;
		let tbs_der = self.to_tbs()?;

		verify_canonical::<D, S>(verifier, &tbs_der, &signature)?;

		Ok(())
	}
}

#[cfg(feature = "aead")]
impl Frame {
	/// Get a reference to the encrypted content info if present.
	pub fn encrypted_content_info(&self) -> Option<&EncryptedContentInfo> {
		self.metadata.confidentiality.as_ref()
	}

	/// Decrypt the message body and return the plaintext bytes.
	/// This will consume the frame.
	///
	/// # Arguments
	/// * `decryptor` - The AEAD decryptor to use for decryption
	///
	/// # Returns
	/// The decrypted plaintext as a [`SecretSlice`](crate::crypto::secret::SecretSlice)
	/// that zeroizes on drop. If the frame was compressed, these bytes are
	/// still compressed and need to be decompressed separately. Callers that
	/// need a raw copy opt out explicitly via
	/// [`ToInsecure`](crate::crypto::secret::ToInsecure).
	///
	/// # Errors
	/// Returns an error if:
	/// - The metadata doesn't contain encryption info (V0 metadata)
	/// - Decryption fails
	pub fn decrypt_bytes(
		mut self,
		decryptor: &impl crate::crypto::aead::Decryptor,
	) -> Result<crate::crypto::secret::SecretSlice<u8>> {
		let mut encrypted_content_info = self
			.metadata
			.confidentiality
			.take()
			.ok_or(TightBeamError::MissingEncryptionInfo)?;

		// The encrypted content lives in the message field, so it moves
		// into the info before decryption.
		let message = OctetString::new(core::mem::take(&mut self.message))?;
		encrypted_content_info.encrypted_content = Some(message);

		decryptor.decrypt_content(&encrypted_content_info)
	}

	/// Decrypt, decompress (if needed), and decode the message body into a typed message T.
	/// This is a convenience method that combines `decrypt_bytes`, `decompress`, and `decode`.
	///
	/// # Arguments
	/// * `decryptor` - The AEAD decryptor to use for decryption
	/// * `inflator` - Optional inflator for decompressing the data (required if compressed)
	///
	/// # Returns
	/// The decrypted, decompressed, and decoded message of type T
	///
	/// # Errors
	/// Returns an error if:
	/// - The metadata doesn't contain encryption info (V0 metadata)
	/// - Decryption fails
	/// - Decompression fails (if compressed)
	/// - Deserialization of the decrypted data fails
	pub fn decrypt<T>(
		self,
		decryptor: &impl crate::crypto::aead::Decryptor,
		inflator: Option<&dyn Inflator>,
	) -> Result<T>
	where
		T: Message,
	{
		use crate::crypto::secret::ToInsecure;

		let was_compressed = self.metadata.compactness.is_some();
		let plaintext = self.decrypt_bytes(decryptor)?.to_insecure()?;
		let decompressed = Self::decompress(plaintext.into_vec(), was_compressed, inflator)?;

		crate::decode::<T>(&decompressed)
	}

	/// Decrypt the message body in place, turning an encrypted frame into
	/// its cleartext equivalent.
	///
	/// Frame-level `integrity` and `nonrepudiation` cover the encrypted
	/// body and are left untouched. Verify them *before* calling
	/// ([`Frame::verify_frame_integrity`], [`Frame::verify`]), because
	/// they will no longer match afterwards. The message commitment in
	/// `metadata.integrity` is the check that survives decryption
	/// ([`Frame::verify_commitment_of`]).
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingEncryptionInfo`] when the frame is not encrypted.
	/// - [`TightBeamError::MissingInflator`] when the body is compressed with no inflator.
	/// - Decryption or decompression errors from the underlying implementations.
	pub fn decrypt_in_place(
		&mut self,
		decryptor: &dyn crate::crypto::aead::Decryptor,
		inflator: Option<&dyn Inflator>,
	) -> Result<()> {
		use crate::crypto::secret::ToInsecure;

		let Some(mut encrypted) = self.metadata.confidentiality.take() else {
			return Err(TightBeamError::MissingEncryptionInfo);
		};

		if self.metadata.compactness.is_some() && inflator.is_none() {
			self.metadata.confidentiality = Some(encrypted);
			return Err(TightBeamError::MissingInflator);
		}

		encrypted.encrypted_content = Some(OctetString::new(core::mem::take(&mut self.message))?);

		match decryptor.decrypt_content(&encrypted) {
			Ok(plaintext) => {
				let was_compressed = self.metadata.compactness.take().is_some();
				let plaintext = plaintext.to_insecure()?;

				self.message = Self::decompress(plaintext.into_vec(), was_compressed, inflator)?;

				Ok(())
			}
			Err(err) => {
				if let Some(content) = encrypted.encrypted_content.take() {
					self.message = content.into_bytes();
				}
				self.metadata.confidentiality = Some(encrypted);
				Err(err)
			}
		}
	}
}

impl Frame {
	/// Decompress the message body in place for a cleartext-but-compressed
	/// frame, clearing `compactness` on success.
	///
	/// A frame without `compactness` is returned unchanged. On
	/// decompression failure the frame is restored unchanged.
	///
	/// # Errors
	///
	/// Returns the underlying codec error when the inflator rejects the
	/// body.
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

impl TightBeamLike for Frame {}

impl From<Frame> for Metadata {
	fn from(mut frame: Frame) -> Self {
		core::mem::take(&mut frame.metadata)
	}
}

crate::impl_from!(Frame, tb => Version: tb.version);

#[cfg(feature = "signature")]
crate::impl_try_from!(Frame, tb => SignerInfo: nonrepudiation, TightBeamError::MissingSignature);

/// Outcome of an integrity verification check.
#[cfg(feature = "digest")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityVerdict {
	/// Recomputed digest matches the stored value.
	Verified,
	/// The frame carries no integrity value to check.
	Absent,
	/// The stored digest was produced by a different algorithm than `D`.
	AlgorithmMismatch,
	/// Recomputed digest differs because the covered bytes changed after
	/// digesting.
	Mismatch,
}

#[cfg(feature = "digest")]
impl IntegrityVerdict {
	/// `true` only for [`IntegrityVerdict::Verified`].
	pub fn is_verified(self) -> bool {
		matches!(self, IntegrityVerdict::Verified)
	}
}

#[cfg(feature = "digest")]
impl Frame {
	/// Get a reference to the frame integrity info if present.
	pub fn integrity_info(&self) -> Option<&crate::DigestInfo> {
		self.integrity.as_ref()
	}

	/// Get a reference to the message integrity info if present.
	pub fn message_integrity(&self) -> Option<&crate::DigestInfo> {
		self.metadata.integrity.as_ref()
	}

	/// Check a disclosed [`Opening`](crate::crypto::commitment::Opening)
	/// against this frame's message commitment, reporting which condition
	/// held.
	pub fn message_commitment_verdict<D>(
		&self,
		opening: &crate::crypto::commitment::Opening,
	) -> Result<IntegrityVerdict>
	where
		D: crate::crypto::hash::Digest + crate::der::oid::AssociatedOid,
	{
		let Some(commitment) = self.metadata.integrity.as_ref() else {
			return Ok(IntegrityVerdict::Absent);
		};
		if commitment.algorithm.oid != D::OID {
			return Ok(IntegrityVerdict::AlgorithmMismatch);
		}

		if opening.verify::<D>(commitment)? {
			Ok(IntegrityVerdict::Verified)
		} else {
			Ok(IntegrityVerdict::Mismatch)
		}
	}

	/// Verify a disclosed [`Opening`](crate::crypto::commitment::Opening)
	/// against this frame's message commitment.
	///
	/// Convenience over [`Frame::message_commitment_verdict`]. Returns
	/// `Ok(false)` for absence, algorithm mismatch, and digest mismatch alike.
	/// Callers that must distinguish a stripped commitment from a tampered one
	/// use the verdict method.
	pub fn verify_message_commitment<D>(&self, opening: &crate::crypto::commitment::Opening) -> Result<bool>
	where
		D: crate::crypto::hash::Digest + crate::der::oid::AssociatedOid,
	{
		Ok(self.message_commitment_verdict::<D>(opening)?.is_verified())
	}

	/// Verify this frame's message commitment against a message the
	/// caller holds, re-proving the opening in place.
	///
	/// Convenience over [`Opening`](crate::crypto::commitment::Opening)
	/// plus [`Frame::verify_message_commitment`] for receivers that
	/// already decoded the typed message.
	///
	/// # Contract
	///
	/// - After [`Frame::decrypt_in_place`] unwraps the body, the
	///   commitment in `metadata.integrity` is the surviving
	///   cryptographic bind between the frame and that cleartext.
	/// - `salt` must match the value the sender committed with.
	///
	/// # Returns
	///
	/// `Ok(false)` for absence, algorithm mismatch, and digest mismatch
	/// alike. Callers that must distinguish those conditions use
	/// [`Frame::message_commitment_verdict`].
	pub fn verify_commitment_of<D, M>(&self, message: &M, salt: impl AsRef<[u8]>) -> Result<bool>
	where
		D: crate::crypto::hash::Digest + crate::der::oid::AssociatedOid,
		M: Message,
	{
		let (_, opening) = crate::crypto::commitment::Opening::prove::<D, M>(message, salt)?;

		self.verify_message_commitment::<D>(&opening)
	}

	/// Check this frame's frame-integrity (FI) digest, reporting which
	/// condition held.
	///
	/// Recomputes `H(SEQUENCE { version, metadata })` with `D` and compares it
	/// against the stored digest.
	///
	/// # Ordering
	///
	/// The FI digest covers the wire envelope, including any
	/// `confidentiality` info. Verify it *before*
	/// [`Frame::decrypt_in_place`], because decryption rewrites the
	/// envelope and the digest no longer recomputes afterwards.
	///
	/// # See also
	///
	/// [`Frame::verify_commitment_of`]: the message commitment is the
	/// integrity check that survives decryption.
	pub fn frame_integrity_verdict<D>(&self) -> Result<IntegrityVerdict>
	where
		D: crate::crypto::hash::Digest + crate::der::oid::AssociatedOid,
	{
		let Some(info) = self.integrity.as_ref() else {
			return Ok(IntegrityVerdict::Absent);
		};
		if info.algorithm.oid != D::OID {
			return Ok(IntegrityVerdict::AlgorithmMismatch);
		}

		let scaffold = crate::frame::FrameIntegrityScaffold { version: &self.version, metadata: &self.metadata };
		let recomputed = crate::utils::digest::<D>(&crate::encode(&scaffold)?)?;
		if recomputed.digest.as_bytes() == info.digest.as_bytes() {
			Ok(IntegrityVerdict::Verified)
		} else {
			Ok(IntegrityVerdict::Mismatch)
		}
	}

	/// Verify this frame's frame-integrity (FI) digest.
	///
	/// Convenience over [`Frame::frame_integrity_verdict`]. Returns
	/// `Ok(false)` for absence, algorithm mismatch, and digest mismatch alike.
	/// Callers that must distinguish a stripped FI field from a tampered
	/// envelope use the verdict method.
	pub fn verify_frame_integrity<D>(&self) -> Result<bool>
	where
		D: crate::crypto::hash::Digest + crate::der::oid::AssociatedOid,
	{
		Ok(self.frame_integrity_verdict::<D>()?.is_verified())
	}
}

#[cfg(feature = "compress")]
impl Frame {
	/// Get a reference to the compressed data info if present.
	pub fn compressed_data(&self) -> Option<&crate::CompressedData> {
		self.metadata.compactness.as_ref()
	}

	/// Decompress the plaintext bytes if compression was used.
	///
	/// # Arguments
	/// * `plaintext` - The plaintext bytes (may be compressed)
	/// * `was_compressed` - Whether the data was compressed
	/// * `inflator` - The inflator to use for decompression (required if compressed)
	///
	/// # Returns
	/// The decompressed bytes, or the original bytes if not compressed.
	///
	/// # Errors
	/// Returns an error if:
	/// - Compression was used but no inflator was provided
	/// - Decompression fails
	pub fn decompress(plaintext: Vec<u8>, was_compressed: bool, inflator: Option<&dyn Inflator>) -> Result<Vec<u8>> {
		if was_compressed {
			let inflator = inflator.ok_or(TightBeamError::MissingInflator)?;
			inflator.decompress(&plaintext)
		} else {
			Ok(plaintext)
		}
	}
}

#[cfg(not(feature = "compress"))]
impl Frame {
	/// Decompress the plaintext bytes if compression was used.
	///
	/// Without the `compress` feature this only rejects compressed input.
	pub fn decompress(plaintext: Vec<u8>, was_compressed: bool, _inflator: Option<&dyn Inflator>) -> Result<Vec<u8>> {
		if was_compressed {
			Err(TightBeamError::MissingFeature("compress"))
		} else {
			Ok(plaintext)
		}
	}
}

#[cfg(feature = "aead")]
impl TryFrom<Frame> for EncryptedContentInfo {
	type Error = TightBeamError;

	fn try_from(mut frame: Frame) -> core::result::Result<Self, Self::Error> {
		frame
			.metadata
			.confidentiality
			.take()
			.ok_or(TightBeamError::MissingEncryptionInfo)
	}
}

#[cfg(test)]
mod tests {
	#[cfg(not(feature = "std"))]
	use alloc::{
		string::{String, ToString},
		vec,
		vec::Vec,
	};

	use crate::testing::create_test_cipher_key;
	use crate::testing::{create_test_message, create_test_signing_key};
	use crate::Beamable;
	use crate::MessagePriority;

	use super::*;

	#[derive(Clone, Debug, PartialEq, der::Sequence)]
	struct SimpleMessage {
		id: u64,
		name: String,
	}

	#[derive(Clone, Debug, PartialEq, der::Sequence)]
	struct NestedMessage {
		value: u32,
		data: Vec<u8>,
		flag: bool,
	}

	/// Pin `decoded` to the type of `original`. With reduced feature sets the
	/// `serde_json` dev-dependency's `PartialEq<Value>` impls for integers make
	/// a bare `assert_eq!` on `decode`'s inferred output ambiguous.
	fn assert_round_trip<T: PartialEq + core::fmt::Debug>(original: &T, decoded: &T) {
		assert_eq!(original, decoded);
	}

	/// Macro to generate encode/decode round-trip tests.
	macro_rules! test_encode_decode {
		($($name:ident: $value:expr,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let original = $value;

					let encoded = crate::encode(&original)?;
					assert!(!encoded.is_empty());

					let decoded = crate::decode(&encoded)?;
					assert_round_trip(&original, &decoded);

					// A second encode proves the decoded value is valid DER.
					let re_encoded = crate::encode(&decoded)?;
					assert_eq!(encoded, re_encoded);

					Ok(())
				}
			)*
		};
	}

	test_encode_decode! {
		encode_decode_simple_message: SimpleMessage {
			id: 42,
			name: "test".to_string(),
		},
		encode_decode_simple_message_zero: SimpleMessage {
			id: 0,
			name: String::new(),
		},
		encode_decode_simple_message_large: SimpleMessage {
			id: u64::MAX,
			name: "a very long name with many characters".to_string(),
		},
		encode_decode_nested_message: NestedMessage {
			value: 12345,
			data: vec![1, 2, 3, 4, 5],
			flag: true,
		},
		encode_decode_nested_message_false: NestedMessage {
			value: 0,
			data: Vec::new(),
			flag: false,
		},
		encode_decode_u32: 42u32,
		encode_decode_u64: 9876543210u64,
		encode_decode_bool_true: true,
		encode_decode_bool_false: false,
	}

	/// Macro to generate decode failure tests.
	macro_rules! test_decode_failure {
		($($name:ident: $data:expr => $type:ty,)*) => {
			$(
				#[test]
				fn $name() {
					let result: Result<$type> = crate::decode($data);
					assert!(result.is_err());
				}
			)*
		};
	}

	test_decode_failure! {
		decode_invalid_der_should_fail: &vec![0xFF, 0xFF, 0xFF] => u32,
		decode_empty_should_fail: &vec![] => u32,
		decode_invalid_sequence: &vec![0x30, 0xFF] => SimpleMessage,
		decode_wrong_type: &vec![0x02, 0x01, 0x2A] => SimpleMessage, // INTEGER instead of SEQUENCE
	}

	#[test]
	fn decode_truncated_should_fail() -> Result<()> {
		let original = SimpleMessage { id: 100, name: "test".to_string() };
		let mut encoded = crate::encode(&original)?;
		encoded.truncate(5);

		let result: Result<SimpleMessage> = crate::decode(&encoded);
		assert!(result.is_err());

		Ok(())
	}

	/// Macro to generate TightBeam encode/decode round-trip tests.
	macro_rules! test_tightbeam_roundtrip {
		($($name:ident: $tightbeam:expr,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let original = $tightbeam;

					let encoded = crate::encode(&original)?;
					assert!(!encoded.is_empty());

					let decoded: Frame = crate::decode(&encoded)?;
					assert_eq!(original, decoded);

					// A second encode proves the decoded value is valid DER.
					let re_encoded = crate::encode(&decoded)?;
					assert_eq!(encoded, re_encoded);

					Ok(())
				}
			)*
		};
	}

	test_tightbeam_roundtrip! {
		tightbeam_v0_minimal: {
			let message = create_test_message(None);
			compose! {
				V0:
					id: "test-001",
					order: 1696521600,
					message: message,
			}?
		},
		tightbeam_v0_large_value: {
			let message = create_test_message(Some(&("A".repeat(1000))));
			compose! {
				V0:
					id: "test-002",
					order: 1696521700,
					message: message
			}?
		},
		tightbeam_v1_encrypted: {
			use crate::crypto::aead::Aes256GcmOid;
			use crate::crypto::sign::ecdsa::Secp256k1Signature;

			let message = create_test_message(None);
			let (_, cipher) = create_test_cipher_key();
			let signing_key = create_test_signing_key();

			compose! {
				V1: id: "test-003",
					order: 1696521800,
					message: message,
					confidentiality<Aes256GcmOid, _>: cipher,
					nonrepudiation<Secp256k1Signature, _>: signing_key
			}?
		},
		tightbeam_v2_full: {
			use crate::crypto::aead::Aes256GcmOid;
			use crate::crypto::sign::ecdsa::Secp256k1Signature;
			use crate::crypto::hash::Sha3_256;

			let message = create_test_message(None);
			let (_, cipher) = create_test_cipher_key();
			let signing_key = create_test_signing_key();

			compose! {
				V2: id: "test-004",
					order: 1696521900,
					message: message,
					confidentiality<Aes256GcmOid, _>: cipher,
					nonrepudiation<Secp256k1Signature, _>: signing_key,
					message_integrity<Sha3_256>: [],
					priority: MessagePriority::HighThroughput,
					lifetime: 3600
			}?
		},
	}

	/// Macro to test TightBeam conversions.
	macro_rules! test_tightbeam_conversions {
		($($name:ident: $tightbeam:expr => $target:ty,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let tightbeam = $tightbeam;
					let _converted: $target = tightbeam.clone().into();

					Ok(())
				}
			)*
		};
	}

	test_tightbeam_conversions! {
		tightbeam_to_metadata_v0: {
			let message = create_test_message(None);
			compose! {
				V0:
					id: "meta-001",
					order: 1000,
					message: message
			}?
		} => Metadata,
		tightbeam_to_protocol_version: {
			use crate::crypto::aead::Aes256GcmOid;
			use crate::crypto::sign::ecdsa::Secp256k1Signature;
			use crate::crypto::hash::Sha3_256;

			let message = create_test_message(None);
			let (_, cipher) = create_test_cipher_key();
			let signing_key = create_test_signing_key();

			compose! {
				V2:
					id: "ver-001",
					order: 2000,
					message: message,
					confidentiality<Aes256GcmOid, _>: cipher,
					nonrepudiation<Secp256k1Signature, _>: signing_key,
					message_integrity<Sha3_256>: [],
					priority: MessagePriority::Expedited,
					lifetime: 60
			}?
		} => Version,
	}

	/// Macro to test TightBeam TryFrom conversions (owned only).
	macro_rules! test_tightbeam_try_conversions {
		(success: $($name:ident: $tightbeam:expr => $target:ty,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let tightbeam = $tightbeam;
					let result: Result<$target> = tightbeam.try_into();
					assert!(result.is_ok());

					Ok(())
				}
			)*
		};
		(failure: $($name:ident: $tightbeam:expr => $target:ty,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let tightbeam = $tightbeam;
					let result: Result<$target> = tightbeam.try_into();
					assert!(result.is_err());

					Ok(())
				}
			)*
		};
	}

	test_tightbeam_try_conversions! {
		success:
		tightbeam_v1_to_signature_info: {
			use crate::crypto::aead::Aes256GcmOid;
			use crate::crypto::sign::ecdsa::Secp256k1Signature;

			let message = create_test_message(None);
			let (_, cipher) = create_test_cipher_key();
			let signing_key = create_test_signing_key();

			compose! {
				V1: id: "sig-001",
					order: 3000,
					message: message,
					confidentiality<Aes256GcmOid, _>: cipher,
					nonrepudiation<Secp256k1Signature, _>: signing_key
			}?
		} => SignerInfo,
		tightbeam_v2_to_encryption_info: {
			use crate::crypto::aead::Aes256GcmOid;
			use crate::crypto::sign::ecdsa::Secp256k1Signature;
			use crate::crypto::hash::Sha3_256;

			let message = create_test_message(None);
			let (_, cipher) = create_test_cipher_key();
			let signing_key = create_test_signing_key();

			compose! {
				V2:
					id: "enc-001",
					order: 4000,
					message: message,
					confidentiality<Aes256GcmOid, _>: cipher,
					nonrepudiation<Secp256k1Signature, _>: signing_key,
					message_integrity<Sha3_256>: [],
					priority: MessagePriority::LowLatency,
					lifetime: 120
			}?
		} => EncryptedContentInfo,
	}

	test_tightbeam_try_conversions! {
		failure: // These conversions should fail due to missing fields.
		tightbeam_v0_to_signature_info_fails: {
			let message = create_test_message(None);
			compose! {
				V0:
					id: "fail-001",
					order: 5000,
					message: message
			}?
		} => SignerInfo,
		tightbeam_v0_to_encryption_info_fails: {
			let message = create_test_message(None);
			compose! {
				V0:
					id: "fail-002",
					order: 6000,
					message: message
			}?
		} => EncryptedContentInfo,
	}

	#[cfg(feature = "derive")]
	#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
	#[beam(profile = 1)]
	struct NumericProfileMessage {
		id: u64,
		data: String,
	}

	#[cfg(feature = "derive")]
	#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
	#[beam(profile(crate::crypto::profiles::TightbeamProfile))]
	struct TypeProfileMessage {
		id: u64,
		data: String,
	}

	#[cfg(feature = "derive")]
	#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
	struct NoProfileMessage {
		id: u64,
		data: String,
	}

	#[cfg(feature = "derive")]
	#[test]
	#[allow(clippy::assertions_on_constants)]
	fn test_profile_types() {
		// Every message type must expose a Profile type that implements
		// SecurityProfile.
		fn assert_security_profile<P: crate::crypto::profiles::SecurityProfile>() {}

		assert_security_profile::<<NumericProfileMessage as crate::Message>::Profile>();
		assert_security_profile::<<TypeProfileMessage as crate::Message>::Profile>();
		assert_security_profile::<<NoProfileMessage as crate::Message>::Profile>();

		// A type-based profile resolves to the named profile type.
		assert_eq!(
			core::any::TypeId::of::<<TypeProfileMessage as crate::Message>::Profile>(),
			core::any::TypeId::of::<crate::crypto::profiles::TightbeamProfile>()
		);

		assert!(!NumericProfileMessage::HAS_PROFILE);
		assert!(TypeProfileMessage::HAS_PROFILE);
		assert!(!NoProfileMessage::HAS_PROFILE);
	}

	#[cfg(all(feature = "signature", feature = "builder", feature = "sha3"))]
	mod tbs_encoding {
		use super::*;
		use crate::testing::create_frame_with_frame_integrity;

		/// Signature validity depends on `to_tbs` staying bit-identical to the
		/// derived DER encoding of a frame with `nonrepudiation` stripped.
		#[test]
		fn tbs_matches_derived_encoding_with_integrity() -> Result<()> {
			let frame = create_frame_with_frame_integrity();

			let mut unsigned = frame.clone();
			unsigned.nonrepudiation = None;

			assert_eq!(frame.to_tbs()?, crate::encode(&unsigned)?);

			Ok(())
		}

		#[test]
		fn tbs_matches_derived_encoding_without_integrity() -> Result<()> {
			let message = create_test_message(None);
			let frame = compose! { V0: id: "tbs-basic", order: 1u64, message: message }?;

			let mut unsigned = frame.clone();
			unsigned.nonrepudiation = None;

			assert_eq!(frame.to_tbs()?, crate::encode(&unsigned)?);

			Ok(())
		}
	}

	#[cfg(all(feature = "digest", feature = "sha3", feature = "builder"))]
	mod message_commitment {
		use super::*;
		use crate::crypto::commitment::Opening;
		use crate::crypto::hash::Sha3_256;

		#[test]
		fn verify_commitment_of_recomputes_over_message() -> Result<()> {
			let message = create_test_message(None);
			let (commitment, _) = Opening::prove::<Sha3_256, _>(&message, [])?;

			let mut frame = compose! { V1: id: "commit-1", order: 1u64, message: message.clone() }?;
			frame.metadata.integrity = Some(commitment);

			assert!(frame.verify_commitment_of::<Sha3_256, _>(&message, [])?);

			Ok(())
		}

		#[test]
		fn verify_commitment_of_rejects_other_message() -> Result<()> {
			let committed = create_test_message(None);
			let (commitment, _) = Opening::prove::<Sha3_256, _>(&committed, [])?;

			let mut frame = compose! { V1: id: "commit-2", order: 2u64, message: committed }?;
			frame.metadata.integrity = Some(commitment);

			let other = create_test_message(Some("a different body"));

			assert!(!frame.verify_commitment_of::<Sha3_256, _>(&other, [])?);

			Ok(())
		}

		#[test]
		fn verify_commitment_of_is_false_without_commitment() -> Result<()> {
			let message = create_test_message(None);
			let frame = compose! { V1: id: "commit-3", order: 3u64, message: message.clone() }?;

			assert!(!frame.verify_commitment_of::<Sha3_256, _>(&message, [])?);

			Ok(())
		}
	}

	#[cfg(all(feature = "builder", feature = "sha3"))]
	mod frame_integrity {
		use super::*;
		use crate::crypto::hash::{Sha3_256, Sha3_512};
		use crate::testing::create_frame_with_frame_integrity;

		#[test]
		fn verifies_intact_envelope() {
			let frame = create_frame_with_frame_integrity();
			assert!(matches!(frame.verify_frame_integrity::<Sha3_256>(), Ok(true)));
		}

		#[test]
		fn rejects_tampered_envelope() {
			let mut frame = create_frame_with_frame_integrity();
			frame.metadata.id = b"tampered".to_vec();
			assert!(matches!(frame.verify_frame_integrity::<Sha3_256>(), Ok(false)));
		}

		#[test]
		fn rejects_algorithm_mismatch() {
			let frame = create_frame_with_frame_integrity();
			assert!(matches!(frame.verify_frame_integrity::<Sha3_512>(), Ok(false)));
		}

		#[test]
		fn absent_integrity_is_false() -> Result<()> {
			let message = create_test_message(None);
			let frame = compose! { V0: id: "no-fi", order: 1u64, message: message }?;
			assert!(matches!(frame.verify_frame_integrity::<Sha3_256>(), Ok(false)));
			Ok(())
		}

		#[test]
		fn verdict_reports_verified() {
			let frame = create_frame_with_frame_integrity();
			assert!(matches!(
				frame.frame_integrity_verdict::<Sha3_256>(),
				Ok(IntegrityVerdict::Verified)
			));
		}

		#[test]
		fn verdict_reports_mismatch_on_tamper() {
			let mut frame = create_frame_with_frame_integrity();
			frame.metadata.id = b"tampered".to_vec();
			assert!(matches!(
				frame.frame_integrity_verdict::<Sha3_256>(),
				Ok(IntegrityVerdict::Mismatch)
			));
		}

		#[test]
		fn verdict_reports_algorithm_mismatch() {
			let frame = create_frame_with_frame_integrity();
			assert!(matches!(
				frame.frame_integrity_verdict::<Sha3_512>(),
				Ok(IntegrityVerdict::AlgorithmMismatch)
			));
		}

		#[test]
		fn verdict_reports_absent() -> Result<()> {
			let message = create_test_message(None);
			let frame = compose! { V0: id: "no-fi-verdict", order: 1u64, message: message }?;
			assert!(matches!(
				frame.frame_integrity_verdict::<Sha3_256>(),
				Ok(IntegrityVerdict::Absent)
			));

			Ok(())
		}
	}

	#[cfg(feature = "aead")]
	mod decrypt_in_place {
		use super::*;
		use crate::crypto::aead::Aes256GcmOid;
		use crate::error::Result;
		use crate::testing::TestMessage;

		fn encrypted_frame() -> Result<Frame> {
			let message = create_test_message(Some("in-place"));
			let (_, cipher) = create_test_cipher_key();
			compose! {
				V1: id: "dip-001",
					order: 1u64,
					message: message,
					confidentiality<Aes256GcmOid, _>: cipher
			}
		}

		#[test]
		fn yields_cleartext_frame_with_decodable_body() -> Result<()> {
			let (_, cipher) = create_test_cipher_key();
			let mut frame = encrypted_frame()?;

			frame.decrypt_in_place(&cipher, None)?;

			assert!(frame.metadata.confidentiality.is_none());

			let decoded: TestMessage = crate::decode(&frame.message)?;
			assert_eq!(decoded, create_test_message(Some("in-place")));
			Ok(())
		}

		#[test]
		fn wrong_key_restores_frame() -> Result<()> {
			use crate::crypto::aead::{Aes256Gcm, KeyInit};
			use crate::crypto::common::Key;

			let mut frame = encrypted_frame()?;
			let original = frame.clone();
			let wrong_cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from([0x44; 32]));

			let result = frame.decrypt_in_place(&wrong_cipher, None);
			assert!(result.is_err());
			assert_eq!(frame, original);
			Ok(())
		}

		#[test]
		fn cleartext_frame_rejected() -> Result<()> {
			let message = create_test_message(None);
			let (_, cipher) = create_test_cipher_key();
			let mut frame = compose! { V0: id: "dip-002", order: 1u64, message: message }?;

			let result = frame.decrypt_in_place(&cipher, None);
			assert!(matches!(result, Err(TightBeamError::MissingEncryptionInfo)));
			Ok(())
		}

		#[test]
		fn compressed_without_inflator_fails_before_mutation() -> Result<()> {
			use crate::cms::compressed_data::CompressedData;
			use crate::cms::content_info::CmsVersion;
			use crate::cms::signed_data::EncapsulatedContentInfo;
			use crate::oids::{COMPRESSION_ZSTD, DATA};
			use crate::spki::AlgorithmIdentifier;

			let (_, cipher) = create_test_cipher_key();
			let mut frame = encrypted_frame()?;
			frame.metadata.compactness = Some(CompressedData {
				version: CmsVersion::V0,
				compression_alg: AlgorithmIdentifier { oid: COMPRESSION_ZSTD, parameters: None },
				encap_content_info: EncapsulatedContentInfo { econtent_type: DATA, econtent: None },
			});

			let original = frame.clone();
			let result = frame.decrypt_in_place(&cipher, None);
			assert!(matches!(result, Err(TightBeamError::MissingInflator)));
			assert_eq!(frame, original);
			Ok(())
		}
	}

	#[cfg(feature = "compress")]
	mod inflate_in_place {
		use super::*;
		use crate::compress::{Compressor, ZstdCompression};
		use crate::error::Result;

		fn compressed_frame(body: &[u8]) -> Result<Frame> {
			let zstd = ZstdCompression::default();
			let (compressed, compression_info) = zstd.compress(body, None)?;

			let mut metadata = Metadata::default();
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
			let message = create_test_message(None);
			let mut frame = compose! { V0: id: "inf-002", order: 1u64, message: message }?;
			let original = frame.clone();

			frame.inflate_in_place(&ZstdCompression::default())?;

			assert_eq!(frame, original);
			Ok(())
		}
	}
}
