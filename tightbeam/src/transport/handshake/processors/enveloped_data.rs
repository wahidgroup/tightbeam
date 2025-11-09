//! EnvelopedData processor for TightBeam CMS handshake.
//!
//! Processes received EnvelopedData structures to decrypt content.
//! Algorithm-agnostic design allows different content encryption algorithms.

use crate::cms::enveloped_data::{EnvelopedData, RecipientInfo};
use crate::transport::handshake::error::HandshakeError;

/// Trait for processing RecipientInfo to extract the Content Encryption Key (CEK).
///
/// Implementations should handle specific recipient types (KARI, KTRI, etc.)
/// and extract the CEK from the RecipientInfo structure.
pub trait RecipientProcessor {
	/// Process a RecipientInfo to extract the CEK.
	///
	/// # Parameters
	/// - `info`: The RecipientInfo structure
	/// - `recipient_index`: Index of this recipient in the RecipientInfos set
	///
	/// # Returns
	/// The extracted CEK (Content Encryption Key)
	fn process_recipient(&self, info: &RecipientInfo, recipient_index: usize) -> Result<Vec<u8>, HandshakeError>;
}

/// Trait for decrypting content from an EncryptedContentInfo structure.
///
/// Note: This is defined in `crate::crypto::aead` as `Decryptor` but we need
/// a version that works with raw bytes and algorithm OIDs for the processor.
pub trait ContentDecryptor {
	/// Decrypt encrypted content using the provided CEK.
	///
	/// # Parameters
	/// - `encrypted_content`: The ciphertext to decrypt
	/// - `cek`: The Content Encryption Key
	/// - `algorithm_oid`: The content encryption algorithm OID
	///
	/// # Returns
	/// The decrypted plaintext
	fn decrypt_content(
		&self,
		encrypted_content: &[u8],
		cek: &[u8],
		algorithm_oid: &der::asn1::ObjectIdentifier,
	) -> Result<Vec<u8>, HandshakeError>;
}

/// Simple AES-GCM content decryptor.
///
/// Decrypts content using AES-256-GCM. The nonce is embedded in the ciphertext
/// by the `aes_gcm_decrypt` helper function.
pub struct AesGcmContentDecryptor;

impl ContentDecryptor for AesGcmContentDecryptor {
	fn decrypt_content(
		&self,
		encrypted_content: &[u8],
		cek: &[u8],
		algorithm_oid: &der::asn1::ObjectIdentifier,
	) -> Result<Vec<u8>, HandshakeError> {
		// Verify it's AES-256-GCM
		use crate::asn1::AES_256_GCM_OID;
		if algorithm_oid != &AES_256_GCM_OID {
			return Err(HandshakeError::MissingContentEncryptionAlgorithm);
		}

		// Decrypt using the utils function
		use crate::transport::handshake::utils::aes_gcm_decrypt;
		aes_gcm_decrypt(cek, encrypted_content, None)
	}
}

/// Processor for CMS `EnvelopedData` structures.
///
/// This is algorithm-agnostic - it delegates:
/// - Recipient info processing to a `RecipientProcessor` implementation
/// - Content decryption to a `ContentDecryptor` implementation
///
/// This allows flexibility to support different key agreement mechanisms
/// and content encryption algorithms without hardcoding specific choices.
pub struct TightBeamEnvelopedDataProcessor {
	/// Processor to extract CEK from RecipientInfo
	recipient_processor: Box<dyn RecipientProcessor>,

	/// Decryptor for content
	content_decryptor: Box<dyn ContentDecryptor>,

	/// Recipient index to use (default: 0)
	recipient_index: usize,
}

impl TightBeamEnvelopedDataProcessor {
	/// Create a new EnvelopedData processor.
	///
	/// Note: You must set the recipient processor and content decryptor
	/// before calling `process()`.
	pub fn new<R, D>(recipient_processor: R, content_decryptor: D) -> Self
	where
		R: RecipientProcessor + 'static,
		D: ContentDecryptor + 'static,
	{
		Self {
			recipient_processor: Box::new(recipient_processor),
			content_decryptor: Box::new(content_decryptor),
			recipient_index: 0,
		}
	}

	/// Set which recipient index to use (default: 0).
	pub fn with_recipient_index(mut self, index: usize) -> Self {
		self.recipient_index = index;
		self
	}

	/// Process an EnvelopedData structure to extract and decrypt content.
	///
	/// # Steps
	/// 1. Validate RecipientInfos contains the specified index
	/// 2. Extract CEK using recipient processor
	/// 3. Extract encrypted content from EncryptedContentInfo
	/// 4. Decrypt content using content decryptor
	///
	/// # Parameters
	/// - `enveloped_data`: The EnvelopedData structure to process
	///
	/// # Returns
	/// The decrypted plaintext content
	pub fn process(&self, enveloped_data: &EnvelopedData) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validate recipient index
		let recip_vec = enveloped_data.recip_infos.0.as_ref();
		if self.recipient_index >= recip_vec.len() {
			return Err(HandshakeError::InvalidRecipientIndex);
		}

		// 2. Extract CEK using recipient processor
		let recipient_info = &recip_vec[self.recipient_index];
		let cek = self
			.recipient_processor
			.process_recipient(recipient_info, self.recipient_index)?;

		// 3. Get encrypted content
		let encrypted_content_info = &enveloped_data.encrypted_content;

		// The encrypted content should be present for EnvelopedData
		let encrypted_content = encrypted_content_info
			.encrypted_content
			.as_ref()
			.ok_or(HandshakeError::MissingContentEncryptionAlgorithm)?; // Better error needed

		// 4. Decrypt content using the algorithm specified
		let content_enc_alg = &encrypted_content_info.content_enc_alg;
		let plaintext =
			self.content_decryptor
				.decrypt_content(encrypted_content.as_bytes(), &cek, &content_enc_alg.oid)?;

		Ok(plaintext)
	}

	/// Extract unprotected attributes from the EnvelopedData.
	///
	/// Returns the unprotected attributes if present.
	pub fn extract_unprotected_attributes<'a>(
		&self,
		enveloped_data: &'a EnvelopedData,
	) -> Option<&'a [x509_cert::attr::Attribute]> {
		enveloped_data.unprotected_attrs.as_ref().map(|attrs| attrs.as_slice())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	mod processor {
		use super::*;
		use crate::crypto::sign::ecdsa::k256::SecretKey as K256SecretKey;
		use crate::der::asn1::{ObjectIdentifier, OctetStringRef};
		use crate::spki::SubjectPublicKeyInfoOwned;
		use crate::transport::handshake::attributes::HandshakeAttribute;
		use crate::transport::handshake::builders::enveloped_data::TightBeamEnvelopedDataBuilder;
		use crate::transport::handshake::builders::kari::TightBeamKariBuilder;
		use crate::transport::handshake::processors::kari::TightBeamKariRecipient;
		use crate::transport::handshake::tests::{
			create_test_key_enc_alg, create_test_keypair, create_test_recipient_id, create_test_ukm,
		};

		/// Helper function to create a test KARI builder with all required fields
		fn create_test_kari_builder(
			sender_key: K256SecretKey,
			sender_spki: SubjectPublicKeyInfoOwned,
			recipient_pubkey: elliptic_curve::PublicKey<k256::Secp256k1>,
		) -> TightBeamKariBuilder<crate::crypto::profiles::DefaultCryptoProvider> {
			let ukm = create_test_ukm();
			let rid = create_test_recipient_id();
			let key_enc_alg = create_test_key_enc_alg();

			TightBeamKariBuilder::default()
				.with_sender_priv(sender_key)
				.with_sender_pub_spki(sender_spki)
				.with_recipient_pub(recipient_pubkey)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg)
		}

		/// Dummy recipient processor for testing
		struct DummyRecipientProcessor;
		impl RecipientProcessor for DummyRecipientProcessor {
			fn process_recipient(
				&self,
				_info: &RecipientInfo,
				_recipient_index: usize,
			) -> Result<Vec<u8>, HandshakeError> {
				Ok(vec![0u8; 32])
			}
		}

		/// Dummy content decryptor for testing
		struct DummyContentDecryptor;
		impl ContentDecryptor for DummyContentDecryptor {
			fn decrypt_content(
				&self,
				_encrypted_content: &[u8],
				_cek: &[u8],
				_algorithm_oid: &der::asn1::ObjectIdentifier,
			) -> Result<Vec<u8>, HandshakeError> {
				Ok(vec![])
			}
		}

		#[test]
		fn test_roundtrip_with_kari_aes_gcm() -> Result<(), Box<dyn std::error::Error>> {
			// 1. Create test key pairs
			let (sender_key, sender_spki, recipient_key, recipient_pubkey) = create_test_keypair();

			// 2. Create KARI builder with all required fields
			let kari_builder = create_test_kari_builder(sender_key, sender_spki, recipient_pubkey);

			// 3. Original plaintext to encrypt
			let plaintext = b"Secret handshake message";

			// 4. Build EnvelopedData (sender side)
			let builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let enveloped_data = builder.build(plaintext, None)?;

			// 5. Create recipient processor and content decryptor
			let kari_recipient = TightBeamKariRecipient::with_defaults(recipient_key);
			let content_decryptor = AesGcmContentDecryptor;

			// 6. Create processor and decrypt (recipient side)
			let processor = TightBeamEnvelopedDataProcessor::new(kari_recipient, content_decryptor);
			let decrypted = processor.process(&enveloped_data)?;

			// 7. Verify roundtrip success
			assert_eq!(decrypted, plaintext);

			Ok(())
		}

		#[test]
		fn test_invalid_recipient_index() -> Result<(), Box<dyn std::error::Error>> {
			// 1. Create test key pairs
			let (sender_key, sender_spki, _recipient_key, recipient_pubkey) = create_test_keypair();

			// 2. Create KARI builder and build EnvelopedData
			let kari_builder = create_test_kari_builder(sender_key, sender_spki, recipient_pubkey);
			let builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let enveloped_data = builder.build(b"Test message", None)?;

			// 3. Create processor with invalid recipient index
			let processor = TightBeamEnvelopedDataProcessor::new(DummyRecipientProcessor, DummyContentDecryptor)
				.with_recipient_index(99); // Invalid index

			// 4. Attempt to process with invalid index
			let result = processor.process(&enveloped_data);
			assert!(result.is_err());

			// Verify specific error type (should be InvalidRecipientIndex)
			match result.unwrap_err() {
				HandshakeError::InvalidRecipientIndex => {}
				_ => unreachable!("Expected InvalidRecipientIndex error"),
			}

			Ok(())
		}

		#[test]
		fn test_unprotected_attributes() -> Result<(), Box<dyn std::error::Error>> {
			// 1. Create test key pairs
			let (sender_key, sender_spki, _recipient_key, recipient_pubkey) = create_test_keypair();

			// 2. Create test attribute
			let test_oid = ObjectIdentifier::new_unwrap("1.2.3.4.5");
			let test_value = OctetStringRef::new(b"test-value")?;
			let test_attr = HandshakeAttribute::new_single(test_oid, der::Any::encode_from(&test_value)?)?;

			// 3. Create KARI builder and build EnvelopedData with unprotected attributes
			let kari_builder = create_test_kari_builder(sender_key, sender_spki, recipient_pubkey);
			let builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let builder = builder.with_unprotected_attr(test_attr.clone());
			let enveloped_data = builder.build(b"Test with attributes", None)?;

			// 4. Extract attributes using processor
			let processor = TightBeamEnvelopedDataProcessor::new(DummyRecipientProcessor, AesGcmContentDecryptor);
			let attrs = processor.extract_unprotected_attributes(&enveloped_data);

			// 5. Verify attributes were extracted correctly
			assert!(attrs.is_some());
			let attrs = attrs.unwrap();
			assert_eq!(attrs.len(), 1);
			assert_eq!(attrs[0].oid, test_oid);

			Ok(())
		}
	}
}
