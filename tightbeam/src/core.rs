#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::der::{EncodeValue, Tagged};
use crate::error::Result;
use crate::{Frame, Metadata, TightBeamError, Version};

#[cfg(feature = "aead")]
use crate::asn1::OctetString;
#[cfg(feature = "crypto")]
use crate::crypto::profiles::SecurityProfile;
#[cfg(feature = "signature")]
use crate::crypto::sign::{SignatureEncoding, Verifier};
#[cfg(feature = "signature")]
use crate::der::Encode;
#[cfg(feature = "aead")]
use crate::EncryptedContentInfo;
#[cfg(feature = "signature")]
use crate::SignerInfo;

/// Decompresses message bodies.
///
/// A single always-present trait so downstream code compiles identically
/// under every feature combination; only the implementations are
/// feature-gated (e.g. `ZstdCompression` behind `compress`).
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
	/// Minimum version required to send this message type
	const MIN_VERSION: Version = Version::V0;
	/// Whether this message type requires non-repudiation (signing)
	const MUST_BE_NON_REPUDIABLE: bool = false;
	/// Whether this message type requires confidentiality (encryption)
	const MUST_BE_CONFIDENTIAL: bool = false;
	/// Whether this message type requires compression
	const MUST_BE_COMPRESSED: bool = false;
	/// Whether this message type requires prioritization
	const MUST_BE_PRIORITIZED: bool = false;
	/// Whether this message type requires message integrity (hashing)
	const MUST_HAVE_MESSAGE_INTEGRITY: bool = false;
	/// Whether this message type requires frame integrity (hashing)
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
	/// Excludes `nonrepudiation` without cloning the frame: the borrowing
	/// [`TbsScaffold`](crate::frame::TbsScaffold) reuses the derived field
	/// encoders, so these bytes are bit-identical to the DER encoding of the
	/// frame with `nonrepudiation` set to `None`.
	pub fn to_tbs(&self) -> Result<Vec<u8>> {
		let scaffold = crate::frame::TbsScaffold {
			version: &self.version,
			metadata: &self.metadata,
			message: &self.message,
			integrity: self.integrity.as_ref(),
		};

		Ok(scaffold.to_der()?)
	}

	/// Verify the signature of the TightBeam message
	///
	/// This verifies the signature against the entire TightBeam structure.
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
	/// - Signature verification fails
	pub fn verify<S>(&self, verifier: &impl Verifier<S>) -> Result<()>
	where
		S: SignatureEncoding,
	{
		// Extract signature info from the Frame
		let signature_info = self.nonrepudiation.as_ref().ok_or(TightBeamError::MissingSignature)?;
		let signature_bytes: &[u8] = signature_info.signature.as_bytes();

		// Decode the signature
		let signature = S::try_from(signature_bytes).map_err(|_| TightBeamError::SignatureEncodingError)?;

		// Encode TBS (to-be-signed) structure without cloning - skip the signature field
		let tbs_der = self.to_tbs()?;

		// Verify signature
		verifier.verify(&tbs_der, &signature)?;

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
	/// The decrypted plaintext bytes. If the frame was compressed, these bytes
	/// are still compressed and need to be decompressed separately.
	///
	/// # Errors
	/// Returns an error if:
	/// - The metadata doesn't contain encryption info (V0 metadata)
	/// - Decryption fails
	pub fn decrypt_bytes(mut self, decryptor: &impl crate::crypto::aead::Decryptor) -> Result<Vec<u8>> {
		let mut encrypted_content_info = self
			.metadata
			.confidentiality
			.take()
			.ok_or(TightBeamError::MissingEncryptionInfo)?;

		// The encrypted content is stored in the message field - move it into the info
		let message = OctetString::new(core::mem::take(&mut self.message))?;
		encrypted_content_info.encrypted_content = Some(message);

		// Decrypt using the Decryptor trait
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
		let was_compressed = self.metadata.compactness.is_some();
		let plaintext = self.decrypt_bytes(decryptor)?;
		let decompressed = Self::decompress(plaintext, was_compressed, inflator)?;
		crate::decode::<T>(&decompressed)
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
///
/// Distinguishes the three conditions a boolean collapses: "nothing to
/// verify", "wrong algorithm", and "covered bytes changed". Absence is a
/// protocol-level policy decision, not a verification success or failure --
/// callers enforcing integrity MUST decide how to treat
/// [`IntegrityVerdict::Absent`] instead of folding it into a boolean, since a
/// stripped integrity field is otherwise indistinguishable from a frame that
/// never carried one.
#[cfg(feature = "digest")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityVerdict {
	/// Recomputed digest matches the stored value.
	Verified,
	/// The frame carries no integrity value to check.
	Absent,
	/// The stored digest was produced by a different algorithm than `D`.
	AlgorithmMismatch,
	/// Recomputed digest differs: the covered bytes changed after digesting.
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
	/// Convenience over [`Frame::message_commitment_verdict`]: returns
	/// `Ok(false)` for absence, algorithm mismatch, and digest mismatch alike.
	/// Callers that must distinguish a stripped commitment from a tampered one
	/// use the verdict method.
	pub fn verify_message_commitment<D>(&self, opening: &crate::crypto::commitment::Opening) -> Result<bool>
	where
		D: crate::crypto::hash::Digest + crate::der::oid::AssociatedOid,
	{
		Ok(self.message_commitment_verdict::<D>(opening)?.is_verified())
	}

	/// Check this frame's frame-integrity (FI) digest, reporting which
	/// condition held.
	///
	/// Recomputes `H(SEQUENCE { version, metadata })` with `D` and compares it
	/// against the stored digest.
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
	/// Convenience over [`Frame::frame_integrity_verdict`]: returns
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
	/// This is a no-op when the `compress` feature is disabled.
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

	// Test data structures
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

	/// Macro to generate encode/decode round-trip tests
	macro_rules! test_encode_decode {
		($($name:ident: $value:expr,)*) => {
			$(
				#[test]
				fn $name() {
					let original = $value;

					// Encode
					let encoded = crate::encode(&original).unwrap();
					assert!(!encoded.is_empty());

					// Decode
					let decoded = crate::decode(&encoded).unwrap();
					assert_eq!(original, decoded);

					// Verify it's valid DER (encode again and compare)
					let re_encoded = crate::encode(&decoded).unwrap();
					assert_eq!(encoded, re_encoded);
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

	/// Macro to generate decode failure tests
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
		// Create a valid encoding then truncate it
		let original = SimpleMessage { id: 100, name: "test".to_string() };
		let mut encoded = crate::encode(&original)?;
		encoded.truncate(5);

		let result: Result<SimpleMessage> = crate::decode(&encoded);
		assert!(result.is_err());

		Ok(())
	}

	/// Macro to generate TightBeam encode/decode round-trip tests
	macro_rules! test_tightbeam_roundtrip {
		($($name:ident: $tightbeam:expr,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let original = $tightbeam;

					// Encode
					let encoded = crate::encode(&original).unwrap();
					assert!(!encoded.is_empty());

					// Decode
					let decoded: Frame = crate::decode(&encoded).unwrap();
					// Verify round-trip
					assert_eq!(original, decoded);

					// Verify it's valid DER (encode again and compare)
					let re_encoded = crate::encode(&decoded).unwrap();
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
			}.unwrap()
		},
		tightbeam_v0_large_value: {
			let message = create_test_message(Some(&("A".repeat(1000))));
			compose! {
				V0:
					id: "test-002",
					order: 1696521700,
					message: message
			}.unwrap()
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
			}.unwrap()
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
			}.unwrap()
		},
	}

	/// Macro to test TightBeam conversions
	macro_rules! test_tightbeam_conversions {
		($($name:ident: $tightbeam:expr => $target:ty,)*) => {
			$(
				#[test]
				fn $name() {
					let tightbeam = $tightbeam;
					let _converted: $target = tightbeam.clone().into();
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
			}.unwrap()
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
			}.unwrap()
		} => Version,
	}

	/// Macro to test TightBeam TryFrom conversions (owned only)
	macro_rules! test_tightbeam_try_conversions {
		(success: $($name:ident: $tightbeam:expr => $target:ty,)*) => {
			$(
				#[test]
				fn $name() {
					let tightbeam = $tightbeam;
					let result: Result<$target> = tightbeam.try_into();
					assert!(result.is_ok());
				}
			)*
		};
		(failure: $($name:ident: $tightbeam:expr => $target:ty,)*) => {
			$(
				#[test]
				fn $name() {
					let tightbeam = $tightbeam;
					let result: Result<$target> = tightbeam.try_into();
					assert!(result.is_err());
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
			}.unwrap()
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
			}.unwrap()
		} => EncryptedContentInfo,
	}

	test_tightbeam_try_conversions! {
		failure: // Do nothing: should fail due to missing fields
		tightbeam_v0_to_signature_info_fails: {
			let message = create_test_message(None);
			compose! {
				V0:
					id: "fail-001",
					order: 5000,
					message: message
			}.unwrap()
		} => SignerInfo,
		tightbeam_v0_to_encryption_info_fails: {
			let message = create_test_message(None);
			compose! {
				V0:
					id: "fail-002",
					order: 6000,
					message: message
			}.unwrap()
		} => EncryptedContentInfo,
	}

	// Test data structures for Profile type testing
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
		// All message types should have a Profile type that implements SecurityProfile
		fn assert_security_profile<P: crate::crypto::profiles::SecurityProfile>() {}

		assert_security_profile::<<NumericProfileMessage as crate::Message>::Profile>();
		assert_security_profile::<<TypeProfileMessage as crate::Message>::Profile>();
		assert_security_profile::<<NoProfileMessage as crate::Message>::Profile>();

		// Type-based profile should be StandardProfile
		assert_eq!(
			core::any::TypeId::of::<<TypeProfileMessage as crate::Message>::Profile>(),
			core::any::TypeId::of::<crate::crypto::profiles::TightbeamProfile>()
		);

		// Test HAS_PROFILE values
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
		fn absent_integrity_is_false() {
			let message = create_test_message(None);
			let frame = compose! { V0: id: "no-fi", order: 1u64, message: message }.unwrap();
			assert!(matches!(frame.verify_frame_integrity::<Sha3_256>(), Ok(false)));
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
		fn verdict_reports_absent() {
			let message = create_test_message(None);
			let frame = compose! { V0: id: "no-fi-verdict", order: 1u64, message: message }.unwrap();
			assert!(matches!(
				frame.frame_integrity_verdict::<Sha3_256>(),
				Ok(IntegrityVerdict::Absent)
			));
		}
	}
}
