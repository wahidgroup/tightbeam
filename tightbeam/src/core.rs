use crate::asn1::OctetString;
use crate::error::Result;
use crate::{Frame, Metadata, TightBeamError, Version};

#[cfg(feature = "compress")]
use crate::compress::Inflator;
#[cfg(feature = "signature")]
use crate::crypto::sign::{SignatureEncoding, Verifier};
#[cfg(feature = "aead")]
use crate::EncryptedContentInfo;
#[cfg(feature = "signature")]
use crate::SignerInfo;

/// A marker trait for types that can be used as the body of a TightBeam
/// message.
pub trait Message:
	der::EncodeValue + der::Tagged + for<'a> der::Decode<'a> + Clone + PartialEq + core::fmt::Debug + Sized + Send + Sync
{
	const MUST_BE_NON_REPUDIABLE: bool = false;
	const MUST_BE_CONFIDENTIAL: bool = false;
	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MUST_HAVE_MESSAGE_INTEGRITY: bool = false;
	const MUST_HAVE_FRAME_INTEGRITY: bool = false;
	// TODO MUST_BE_ORDERED: bool = - with_genesis<hash>
	const MIN_VERSION: Version = Version::V0;
}

/// A trait for types that represent a TightBeam message with metadata and
/// version
pub trait TightBeamLike:
	der::Encode
	+ for<'a> der::Decode<'a>
	+ Clone
	+ core::fmt::Debug
	+ PartialEq
	+ core::fmt::Debug
	+ Into<Metadata>
	+ Into<Version>
{
}

impl Frame {
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
	#[cfg(feature = "signature")]
	pub fn verify<S>(&self, verifier: &impl Verifier<S>) -> Result<()>
	where
		S: SignatureEncoding,
	{
		// Extract signature info from the Frame
		let signature_info = self.nonrepudiation.as_ref().ok_or(TightBeamError::MissingSignature)?;
		let signature_bytes: &[u8] = signature_info.signature.as_bytes();

		// Decode the signature
		let signature = S::try_from(signature_bytes).map_err(|_| TightBeamError::SignatureEncodingError)?;

		// Recreate TBS (to-be-signed) structure
		let mut tbs = self.clone();
		tbs.nonrepudiation = None;

		// Encode TBS to DER
		let tbs_der = crate::encode(&tbs)?;

		// Verify signature
		verifier.verify(&tbs_der, &signature)?;

		Ok(())
	}

	/// Decrypt and decode the message body into a typed message T
	///
	/// # Arguments
	/// * `cipher` - The AEAD cipher to use for decryption
	/// * `inflator` - Optional inflator for decompressing the data
	///
	/// # Returns
	/// The decrypted and decoded message of type T
	///
	/// # Errors
	/// Returns an error if:
	/// - The metadata doesn't contain encryption info (V0 metadata)
	/// - Decryption fails
	/// - Deserialization of the decrypted data fails
	#[cfg(feature = "aead")]
	pub fn decrypt<T>(
		&self,
		decryptor: &impl crate::crypto::aead::Decryptor,
		inflator: Option<&dyn Inflator>,
	) -> Result<T>
	where
		T: Message,
	{
		// Extract encrypted content info from metadata and reconstruct with message bytes
		let message = OctetString::new(self.message.clone())?;
		let mut encrypted_content_info = self
			.metadata
			.confidentiality
			.clone()
			.ok_or(TightBeamError::MissingEncryptionInfo)?;

		// The encrypted content is stored in the message field
		encrypted_content_info.encrypted_content = Some(message);

		// Decrypt using the Decryptor trait
		let plaintext = decryptor.decrypt_content(&encrypted_content_info)?;
		// When compressed, decompress before decoding
		let decompressed = if self.metadata.compactness.is_some() {
			#[cfg(not(feature = "compress"))]
			return Err(TightBeamError::MissingFeature("compress"));

			#[cfg(feature = "compress")]
			{
				let inflator = inflator.ok_or(TightBeamError::MissingInflator)?;
				inflator.decompress(&plaintext)?
			}
		} else {
			plaintext
		};

		// Decode the plaintext into type T
		let message_content = decompressed;
		crate::decode::<T>(&message_content)
	}
}

impl TightBeamLike for Frame {}

crate::impl_from!(Frame, tb => Metadata: tb.metadata.clone());
crate::impl_from!(Frame, tb => Version: tb.version);

#[cfg(feature = "signature")]
crate::impl_try_from!(Frame, tb => SignerInfo: nonrepudiation, TightBeamError::MissingSignature);

#[cfg(feature = "aead")]
impl TryFrom<&Frame> for EncryptedContentInfo {
	type Error = TightBeamError;

	fn try_from(frame: &Frame) -> core::result::Result<Self, Self::Error> {
		frame
			.metadata
			.confidentiality
			.clone()
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

	use crate::compose;
	use crate::testing::create_test_cipher_key;
	use crate::testing::{create_test_message, create_test_signing_key};
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
		let mut encoded = crate::encode(&original).unwrap();
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
					confidentiality<Aes256GcmOid, _>: &cipher,
					nonrepudiation<Secp256k1Signature, _>: &signing_key
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
					confidentiality<Aes256GcmOid, _>: &cipher,
					nonrepudiation<Secp256k1Signature, _>: &signing_key,
					message_integrity: type Sha3_256,
					priority: MessagePriority::Bulk,
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

					// Test reference conversion
					let converted_ref: $target = (&tightbeam).into();

					// Test owned conversion
					let converted_owned: $target = tightbeam.clone().into();

					// Both should be equal
					assert_eq!(converted_ref, converted_owned);
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
					confidentiality<Aes256GcmOid, _>: &cipher,
					nonrepudiation<Secp256k1Signature, _>: &signing_key,
					message_integrity: type Sha3_256,
					priority: MessagePriority::Top,
					lifetime: 60
			}.unwrap()
		} => Version,
	}

	/// Macro to test TightBeam TryFrom conversions
	macro_rules! test_tightbeam_try_conversions {
		(success: $($name:ident: $tightbeam:expr => $target:ty,)*) => {
			$(
				#[test]
				fn $name() {
					let tightbeam = $tightbeam;
					let result: Result<$target> = (&tightbeam).try_into();
					assert!(result.is_ok());
				}
			)*
		};
		(failure: $($name:ident: $tightbeam:expr => $target:ty,)*) => {
			$(
				#[test]
				fn $name() {
					let tightbeam = $tightbeam;
					let result: Result<$target> = (&tightbeam).try_into();
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
					confidentiality<Aes256GcmOid, _>: &cipher,
					nonrepudiation<Secp256k1Signature, _>: &signing_key
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
					confidentiality<Aes256GcmOid, _>: &cipher,
					nonrepudiation<Secp256k1Signature, _>: &signing_key,
					message_integrity: type Sha3_256,
					priority: MessagePriority::High,
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
}
