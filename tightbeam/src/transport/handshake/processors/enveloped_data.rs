//! EnvelopedData processor for TightBeam CMS handshake.
//!
//! Processes received EnvelopedData structures to decrypt content.
//! Algorithm-agnostic design allows different content encryption algorithms.

use crate::transport::handshake::error::HandshakeError;
use cms::enveloped_data::{EnvelopedData, RecipientInfo};

/// Trait for processing RecipientInfo to extract the Content Encryption Key (CEK).
///
/// Implementations should handle specific recipient types (KARI, KTRI, etc.)
/// and extract the CEK from the RecipientInfo structure.
#[cfg(all(feature = "builder", feature = "aead"))]
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
#[cfg(all(feature = "builder", feature = "aead"))]
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
#[cfg(all(feature = "builder", feature = "aead"))]
pub struct AesGcmContentDecryptor;

#[cfg(all(feature = "builder", feature = "aead"))]
impl ContentDecryptor for AesGcmContentDecryptor {
	fn decrypt_content(
		&self,
		encrypted_content: &[u8],
		cek: &[u8],
		algorithm_oid: &der::asn1::ObjectIdentifier,
	) -> Result<Vec<u8>, HandshakeError> {
		// Verify it's AES-256-GCM
		let expected_oid = der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.46");
		if algorithm_oid != &expected_oid {
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
#[cfg(all(feature = "builder", feature = "aead"))]
pub struct TightBeamEnvelopedDataProcessor {
	/// Processor to extract CEK from RecipientInfo
	recipient_processor: Box<dyn RecipientProcessor>,

	/// Decryptor for content
	content_decryptor: Box<dyn ContentDecryptor>,

	/// Recipient index to use (default: 0)
	recipient_index: usize,
}

#[cfg(all(feature = "builder", feature = "aead"))]
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

	#[cfg(all(
		feature = "builder",
		feature = "aead",
		feature = "secp256k1",
		feature = "kdf",
		feature = "sha3"
	))]
	mod processor {
		use super::*;
		use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, UserKeyingMaterial};
		use crate::random::OsRng;
		use crate::spki::SubjectPublicKeyInfoOwned;
		use crate::transport::handshake::builders::enveloped_data::TightBeamEnvelopedDataBuilder;
		use crate::transport::handshake::builders::kari::TightBeamKariBuilder;
		use crate::transport::handshake::processors::kari::TightBeamKariRecipient;
		use k256::SecretKey as K256SecretKey;
		use spki::AlgorithmIdentifierOwned;

		#[test]
		fn test_roundtrip_with_kari_aes_gcm() -> Result<(), Box<dyn std::error::Error>> {
			// Generate sender and recipient keys
			let sender_key = K256SecretKey::random(&mut OsRng);
			let sender_pubkey = sender_key.public_key();
			let sender_spki = SubjectPublicKeyInfoOwned::from_key(sender_pubkey)?;

			let recipient_key = K256SecretKey::random(&mut OsRng);
			let recipient_pubkey = recipient_key.public_key();

			// Original plaintext
			let plaintext = b"Secret handshake message";

			// Create UKM
			let ukm = UserKeyingMaterial::new(vec![0x42u8; 64])?;

			// Recipient identifier
			let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
				issuer: x509_cert::name::Name::default(),
				serial_number: x509_cert::serial_number::SerialNumber::new(&[0x01])?,
			});

			// Key encryption algorithm (AES-256 key wrap)
			let key_enc_alg = AlgorithmIdentifierOwned {
				oid: der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45"),
				parameters: None,
			};

			// SENDER SIDE: Build EnvelopedData with KARI
			let kari_builder = TightBeamKariBuilder::<k256::Secp256k1>::default()
				.with_sender_priv(sender_key)
				.with_sender_pub_spki(sender_spki)
				.with_recipient_pub(recipient_pubkey)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg);

			let builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let enveloped_data = builder.build(plaintext, None)?;

			// RECIPIENT SIDE: Process EnvelopedData
			let kari_recipient = TightBeamKariRecipient::with_defaults(recipient_key);
			let content_decryptor = AesGcmContentDecryptor;

			let processor = TightBeamEnvelopedDataProcessor::new(kari_recipient, content_decryptor);

			let decrypted = processor.process(&enveloped_data)?;

			// Verify roundtrip
			assert_eq!(decrypted, plaintext);
			Ok(())
		}

		#[test]
		fn test_invalid_recipient_index() -> Result<(), Box<dyn std::error::Error>> {
			// Generate keys
			let sender_key = K256SecretKey::random(&mut OsRng);
			let sender_pubkey = sender_key.public_key();
			let sender_spki = SubjectPublicKeyInfoOwned::from_key(sender_pubkey)?;

			let recipient_key = K256SecretKey::random(&mut OsRng);
			let recipient_pubkey = recipient_key.public_key();

			let plaintext = b"Test message";

			// Create UKM
			let ukm = UserKeyingMaterial::new(vec![0x42u8; 64])?;

			// Recipient identifier
			let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
				issuer: x509_cert::name::Name::default(),
				serial_number: x509_cert::serial_number::SerialNumber::new(&[0x01])?,
			});

			// Key encryption algorithm
			let key_enc_alg = AlgorithmIdentifierOwned {
				oid: der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45"),
				parameters: None,
			};

			// Build EnvelopedData
			let kari_builder = TightBeamKariBuilder::<k256::Secp256k1>::default()
				.with_sender_priv(sender_key)
				.with_sender_pub_spki(sender_spki)
				.with_recipient_pub(recipient_pubkey)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg);

			let builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let enveloped_data = builder.build(plaintext, None)?;

			// Try to process with invalid index - use dummy processors
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

			let processor = TightBeamEnvelopedDataProcessor::new(DummyRecipientProcessor, DummyContentDecryptor)
				.with_recipient_index(99); // Invalid index

			let result = processor.process(&enveloped_data);
			assert!(result.is_err());
			assert!(matches!(result.unwrap_err(), HandshakeError::InvalidRecipientIndex));
			Ok(())
		}

		#[test]
		fn test_unprotected_attributes() -> Result<(), Box<dyn std::error::Error>> {
			// Generate keys
			let sender_key = K256SecretKey::random(&mut OsRng);
			let sender_pubkey = sender_key.public_key();
			let sender_spki = SubjectPublicKeyInfoOwned::from_key(sender_pubkey)?;

			let recipient_key = K256SecretKey::random(&mut OsRng);
			let recipient_pubkey = recipient_key.public_key();

			let plaintext = b"Test with attributes";

			// Create UKM
			let ukm = UserKeyingMaterial::new(vec![0x42u8; 64])?;

			// Recipient identifier
			let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
				issuer: x509_cert::name::Name::default(),
				serial_number: x509_cert::serial_number::SerialNumber::new(&[0x01])?,
			});

			// Key encryption algorithm
			let key_enc_alg = AlgorithmIdentifierOwned {
				oid: der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45"),
				parameters: None,
			};

			// Create a test attribute
			use crate::transport::handshake::attributes::HandshakeAttribute;
			use der::asn1::{ObjectIdentifier, OctetStringRef};
			let test_oid = ObjectIdentifier::new_unwrap("1.2.3.4.5");
			let test_value = OctetStringRef::new(b"test-value")?;
			let test_attr = HandshakeAttribute::new_single(test_oid, der::Any::encode_from(&test_value)?)?;

			// Build KARI
			let kari_builder = TightBeamKariBuilder::<k256::Secp256k1>::default()
				.with_sender_priv(sender_key)
				.with_sender_pub_spki(sender_spki)
				.with_recipient_pub(recipient_pubkey)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg);

			// Build EnvelopedData with unprotected attributes
			let builder =
				TightBeamEnvelopedDataBuilder::with_defaults(kari_builder).with_unprotected_attr(test_attr.clone());

			let enveloped_data = builder.build(plaintext, None)?;

			// Extract attributes - use dummy processors since we're just testing attribute extraction
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

			let processor = TightBeamEnvelopedDataProcessor::new(DummyRecipientProcessor, AesGcmContentDecryptor);
			let attrs = processor.extract_unprotected_attributes(&enveloped_data);

			assert!(attrs.is_some());
			let attrs = attrs.unwrap();
			assert_eq!(attrs.len(), 1);
			assert_eq!(attrs[0].oid, test_oid);
			Ok(())
		}
	}
}
