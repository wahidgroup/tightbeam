//! EnvelopedData processor for the TightBeam CMS handshake.
//!
//! The processor decrypts the content of a received EnvelopedData structure.

use core::marker::PhantomData;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

use crate::cms::enveloped_data::{EncryptedContentInfo, EnvelopedData, RecipientInfo};
use crate::crypto::aead::{DecryptContent, Decryptor, KeyInit};
use crate::crypto::common::{typenum::Unsigned, KeySizeUser};
use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use crate::crypto::secret::SecretSlice;
use crate::transport::handshake::error::HandshakeError;

/// Trait for processing a RecipientInfo to extract the Content Encryption
/// Key (CEK).
///
/// An implementation handles one recipient type, such as KARI or KTRI, and
/// extracts the CEK from the RecipientInfo structure.
pub trait RecipientProcessor {
	/// Process a RecipientInfo to extract the CEK.
	///
	/// # Parameters
	///
	/// - `info`: the RecipientInfo structure.
	/// - `recipient_index`: the index of this recipient in the RecipientInfos set.
	///
	/// # Returns
	///
	/// The extracted CEK (Content Encryption Key), wrapped so it zeroizes on
	/// drop.
	fn process_recipient(
		&self,
		info: &RecipientInfo,
		recipient_index: usize,
	) -> Result<SecretSlice<u8>, HandshakeError>;
}

/// Processor for CMS `EnvelopedData` structures.
///
/// The processor delegates recipient info processing to a
/// [`RecipientProcessor`] implementation and uses the standard `Decryptor`
/// trait from `crypto::aead` for content decryption.
pub struct TightBeamEnvelopedDataProcessor<P = DefaultCryptoProvider>
where
	P: CryptoProvider,
{
	/// Processor that extracts the CEK from a RecipientInfo.
	recipient_processor: Box<dyn RecipientProcessor>,

	/// Index of the recipient to use, which defaults to 0.
	recipient_index: usize,

	/// Marker for the crypto provider type.
	_phantom: PhantomData<P>,
}

impl<P> TightBeamEnvelopedDataProcessor<P>
where
	P: CryptoProvider,
	P::AeadCipher: KeyInit,
{
	/// Create a new EnvelopedData processor.
	pub fn new<R>(recipient_processor: R) -> Self
	where
		R: RecipientProcessor + 'static,
	{
		Self {
			recipient_processor: Box::new(recipient_processor),
			recipient_index: 0,
			_phantom: PhantomData,
		}
	}

	/// Set which recipient index to use (default: 0).
	pub fn with_recipient_index(mut self, index: usize) -> Self {
		self.recipient_index = index;
		self
	}

	fn validate_recipient_index(&self, enveloped_data: &EnvelopedData) -> Result<(), HandshakeError> {
		if self.recipient_index >= enveloped_data.recip_infos.0.len() {
			Err(HandshakeError::InvalidRecipientIndex)
		} else {
			Ok(())
		}
	}

	fn extract_cek(&self, recipient_info: &RecipientInfo) -> Result<SecretSlice<u8>, HandshakeError> {
		self.recipient_processor.process_recipient(recipient_info, self.recipient_index)
	}

	fn create_cipher_from_cek(cek: &[u8]) -> Result<P::AeadCipher, HandshakeError> {
		P::AeadCipher::new_from_slice(cek).map_err(|_| HandshakeError::InvalidKeySize {
			expected: <P::AeadCipher as KeySizeUser>::KeySize::USIZE,
			received: cek.len(),
		})
	}

	fn decrypt_content(
		cipher: &P::AeadCipher,
		encrypted_content_info: &EncryptedContentInfo,
	) -> Result<SecretSlice<u8>, HandshakeError>
	where
		P::AeadCipher: Decryptor,
	{
		Ok(cipher.decrypt_content(encrypted_content_info)?)
	}

	/// Process an EnvelopedData structure to extract and decrypt its content.
	///
	/// # Steps
	///
	/// 1. Validate the recipient index.
	/// 2. Extract the CEK through the recipient processor.
	/// 3. Decrypt the content, which refuses an algorithm other than the cipher's.
	///
	/// # Returns
	///
	/// The decrypted plaintext content, wrapped so it zeroizes on drop.
	pub fn process(&self, enveloped_data: &EnvelopedData) -> Result<SecretSlice<u8>, HandshakeError> {
		// 1. Validate the recipient index.
		self.validate_recipient_index(enveloped_data)?;

		// 2. Extract the CEK.
		let recipient_info = &enveloped_data.recip_infos.0.as_ref()[self.recipient_index];
		let cek = self.extract_cek(recipient_info)?;

		// 3. Decrypt the content.
		let encrypted_content_info = &enveloped_data.encrypted_content;
		let cipher = cek.with(|cek| Self::create_cipher_from_cek(cek))?;
		Self::decrypt_content(&cipher, encrypted_content_info)
	}

	/// Return the unprotected attributes of the EnvelopedData, if present.
	pub fn extract_unprotected_attributes<'a>(
		&self,
		enveloped_data: &'a EnvelopedData,
	) -> Option<&'a [x509_cert::attr::Attribute]> {
		enveloped_data.unprotected_attrs.as_ref().map(|attrs| attrs.as_slice())
	}
}

/// Default implementation for DefaultCryptoProvider.
impl TightBeamEnvelopedDataProcessor<DefaultCryptoProvider> {
	/// Create a processor with default TightBeam settings.
	pub fn with_defaults<R>(recipient_processor: R) -> Self
	where
		R: RecipientProcessor + 'static,
	{
		Self::new(recipient_processor)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	mod processor {
		use super::*;
		use crate::crypto::secret::ToInsecure;
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

		/// Create a test KARI builder with every required field.
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

		/// Stub recipient processor for testing.
		struct DummyRecipientProcessor;
		impl RecipientProcessor for DummyRecipientProcessor {
			fn process_recipient(
				&self,
				_info: &RecipientInfo,
				_recipient_index: usize,
			) -> Result<SecretSlice<u8>, HandshakeError> {
				Ok(SecretSlice::from(vec![0u8; 32]))
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
			let enveloped_data = builder.build(plaintext, None, None)?;

			// 5. Create recipient processor
			let kari_recipient = TightBeamKariRecipient::with_defaults(recipient_key);

			// 6. Create processor and decrypt (recipient side)
			let processor = TightBeamEnvelopedDataProcessor::with_defaults(kari_recipient);

			// 7. Verify roundtrip success
			let decrypted = processor.process(&enveloped_data)?;
			let decrypted = decrypted.to_insecure();
			assert_eq!(&decrypted[..], &plaintext[..]);

			Ok(())
		}

		#[test]
		fn test_invalid_recipient_index() -> Result<(), Box<dyn std::error::Error>> {
			// 1. Create test key pairs
			let (sender_key, sender_spki, _recipient_key, recipient_pubkey) = create_test_keypair();

			// 2. Create KARI builder and build EnvelopedData
			let kari_builder = create_test_kari_builder(sender_key, sender_spki, recipient_pubkey);
			let builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let enveloped_data = builder.build(b"Test message", None, None)?;

			// 3. Create processor with invalid recipient index
			let processor =
				TightBeamEnvelopedDataProcessor::with_defaults(DummyRecipientProcessor).with_recipient_index(99);

			// 4. Process with the invalid index. The error MUST be
			// InvalidRecipientIndex specifically.
			let result = processor.process(&enveloped_data);
			assert!(matches!(result, Err(HandshakeError::InvalidRecipientIndex)));

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
			let attr = test_attr.clone();
			let builder = builder.with_unprotected_attr(attr);
			let enveloped_data = builder.build(b"Test with attributes", None, None)?;

			// 4. Extract attributes using processor
			let processor = TightBeamEnvelopedDataProcessor::with_defaults(DummyRecipientProcessor);

			// 5. Verify attributes were extracted correctly
			let attrs = processor.extract_unprotected_attributes(&enveloped_data);
			let Some(attrs) = attrs else {
				return Err(crate::testing::error::TestingError::InvariantViolated.into());
			};
			assert_eq!(attrs.len(), 1);
			assert_eq!(attrs[0].oid, test_oid);

			Ok(())
		}
	}
}
