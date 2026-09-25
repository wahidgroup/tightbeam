#[cfg(not(feature = "std"))]
use alloc::vec;

use crate::asn1::OctetString;
use crate::core::{Inflator, Message};
use crate::crypto::aead::{CheckedContent, DecryptContent, Decryptor};
use crate::crypto::key::EncryptingKeyProvider;
use crate::crypto::secret::SecretSlice;
use crate::der::Any;
use crate::error::Result;
use crate::spki::AlgorithmIdentifierOwned;
use crate::version::GatedField;
use crate::{EncryptedContentInfo, Frame, TightBeamError};

impl Frame {
	/// Decrypt the message body with `decryptor` and return the plaintext
	/// bytes, consuming the frame.
	///
	/// # Plaintext
	///
	/// The plaintext comes back as a [`SecretSlice`] that zeroizes on drop.
	/// When the frame was compressed, these bytes are still compressed, and the
	/// caller decompresses them separately. A caller who must own the bytes
	/// takes them through [`ToInsecure::to_insecure`], a buffer that still
	/// wipes.
	///
	/// [`ToInsecure::to_insecure`]: crate::crypto::secret::ToInsecure::to_insecure
	///
	/// # Errors
	///
	/// The method returns an error when:
	///
	/// - the metadata holds no encryption info (V0 metadata), or
	/// - decryption fails.
	pub fn decrypt_bytes(mut self, decryptor: &(impl Decryptor + ?Sized)) -> Result<SecretSlice<u8>> {
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

	/// Decrypt, decompress when needed, and decode the message body into a
	/// typed message `T`.
	///
	/// The method combines [`Frame::decrypt_bytes`], `decompress`, and
	/// `decode`. A compressed body requires an `inflator`.
	///
	/// # Errors
	///
	/// The method returns an error when:
	///
	/// - the metadata holds no encryption info (V0 metadata),
	/// - decryption fails,
	/// - decompression of a compressed body fails, or
	/// - the decrypted data fails to deserialize.
	pub fn decrypt<T>(mut self, decryptor: &(impl Decryptor + ?Sized), inflator: Option<&dyn Inflator>) -> Result<T>
	where
		T: Message,
	{
		self.decrypt_in_place(decryptor, inflator)?;
		crate::decode::<T>(&self.message)
	}

	/// Decrypt the message body in place, turning an encrypted frame into
	/// its cleartext equivalent. On any error the frame is unchanged.
	///
	/// # Verify first
	///
	/// Frame-level `integrity` and `nonrepudiation` cover the encrypted body,
	/// and this method leaves them untouched. Verify them *before* the call
	/// ([`Frame::verify_frame_integrity`], [`Frame::verify`]), because they
	/// stop matching afterwards. The message commitment in `metadata.integrity`
	/// is the check that survives decryption ([`Frame::verify_commitment_of`]).
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingEncryptionInfo`] when the frame is not encrypted.
	/// - [`TightBeamError::MissingInflator`] when the body is compressed with no inflator.
	/// - Decryption or decompression errors from the underlying implementations.
	pub fn decrypt_in_place(
		&mut self,
		decryptor: &(impl Decryptor + ?Sized),
		inflator: Option<&dyn Inflator>,
	) -> Result<()> {
		if self.metadata.confidentiality.is_none() {
			return Err(TightBeamError::MissingEncryptionInfo);
		}

		// A compressed body needs an inflator, so its absence refuses before
		// any work.
		let inflator = match (self.metadata.compactness.is_some(), inflator) {
			(false, _) => None,
			(true, Some(inflator)) => Some(inflator),
			(true, None) => return Err(TightBeamError::MissingInflator),
		};

		let mut encrypted = self
			.metadata
			.confidentiality
			.take()
			.ok_or(TightBeamError::MissingEncryptionInfo)?;
		encrypted.encrypted_content = Some(OctetString::new(core::mem::take(&mut self.message))?);

		let body = decryptor.decrypt_content(&encrypted).and_then(|plaintext| match inflator {
			// A compressed plaintext is inflated in place, so its buffer stays
			// in the wrapper that wipes it.
			Some(inflator) => plaintext.with(|compressed| inflator.decompress(compressed)),
			// The frame owns its cleartext body once it is decrypted, so the
			// buffer moves here and the frame wipes it when it drops.
			None => Ok(plaintext.release()),
		});

		match body {
			Ok(body) => {
				self.message = body;
				self.metadata.compactness = None;
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

	/// Encrypt the frame message with the provided encryption key provider.
	///
	/// Use it when an async `EncryptingKeyProvider`, such as an HSM or a KMS,
	/// cannot encrypt the frame synchronously. On any error the frame is
	/// unchanged. On success the method stores:
	///
	/// - the encrypted content info in the `confidentiality` field, and
	/// - the encrypted bytes in the `message` field.
	///
	/// # Parameters
	///
	/// - `provider`: an encryption key provider that implements the `EncryptingKeyProvider` trait.
	/// - `nonce_size`: the size of the nonce in bytes, such as 12 for AES-GCM.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedVersion`] when the frame version predates confidentiality.
	/// - Nonce generation or encryption errors from the provider.
	pub async fn encrypt_with_provider<P>(&mut self, provider: &P, nonce_size: usize) -> Result<()>
	where
		P: EncryptingKeyProvider,
	{
		self.ensure_allows(GatedField::Confidentiality)?;

		let mut nonce = vec![0u8; nonce_size];
		crate::random::generate_random_bytes(&mut nonce, None)?;

		let ciphertext = provider.encrypt(&nonce, &self.message).await?;
		let content_enc_alg = provider.algorithm();

		// The nonce travels in the algorithm parameters so the receiver
		// can decrypt without out-of-band state.
		let nonce_octets = OctetString::new(nonce.as_slice())?;
		let parameters = Some(Any::encode_from(&nonce_octets)?);
		let content_enc_alg = AlgorithmIdentifierOwned { oid: content_enc_alg.oid, parameters };

		let content_type = crate::oids::DATA;
		let encrypted_content = Some(OctetString::new(ciphertext.as_slice())?);
		let encrypted_content_info = EncryptedContentInfo { content_type, content_enc_alg, encrypted_content };

		self.metadata.confidentiality = Some(encrypted_content_info);
		self.message = ciphertext;

		Ok(())
	}

	/// Decrypt the frame message with the provided encryption key provider.
	///
	/// Use it when an async `EncryptingKeyProvider`, such as an HSM or a KMS,
	/// cannot decrypt the frame synchronously. On any error the frame is
	/// unchanged. On success the method:
	///
	/// 1. reads the nonce from the algorithm parameters of the `confidentiality` field,
	/// 2. decrypts the message bytes with the provider,
	/// 3. stores the plaintext back in the `message` field, and
	/// 4. clears the `confidentiality` field.
	///
	/// # Parameters
	///
	/// - `provider`: an encryption key provider that implements the `EncryptingKeyProvider` trait.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingEncryptionInfo`] when the frame is not
	///   encrypted or names no nonce.
	/// - [`TightBeamError::UnexpectedAlgorithm`] when the frame names an
	///   algorithm other than the provider's.
	/// - Decryption errors from the provider.
	pub async fn decrypt_with_provider<P>(&mut self, provider: &P) -> Result<()>
	where
		P: EncryptingKeyProvider,
	{
		let confidentiality = self
			.metadata
			.confidentiality
			.as_ref()
			.ok_or(TightBeamError::MissingEncryptionInfo)?;

		let content = CheckedContent::check(confidentiality, provider.algorithm().oid)?;
		let nonce_any = content
			.info()
			.content_enc_alg
			.parameters
			.as_ref()
			.ok_or(TightBeamError::MissingEncryptionInfo)?;

		let nonce_octet_string: OctetString = nonce_any.decode_as()?;
		let nonce = nonce_octet_string.as_bytes();
		// The frame owns its cleartext body once it is decrypted, so the
		// buffer moves in without a copy out of a wiping wrapper.
		let plaintext = provider.decrypt(nonce, &self.message).await?;

		self.message = plaintext.release();
		self.metadata.confidentiality = None;

		Ok(())
	}
}

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
	use crate::error::Result;
	use crate::testing::{TestKey, TestMessage};
	use crate::{Frame, TightBeamError};

	mod decrypt_in_place {
		use super::*;
		use crate::cms::compressed_data::CompressedData;
		use crate::cms::content_info::CmsVersion;
		use crate::cms::signed_data::EncapsulatedContentInfo;
		use crate::oids::{COMPRESSION_ZSTD, DATA};
		use crate::spki::AlgorithmIdentifier;

		fn encrypted_frame() -> Result<Frame> {
			let message = TestMessage::sample(Some("in-place"));
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			compose! {
				V1: id: "dip-001",
					order: 1u64,
					message: message,
					confidentiality: cipher
			}
		}

		/// Compression parameters that mark a body as zstd-compressed.
		fn zstd_compactness() -> CompressedData {
			let compression_alg = AlgorithmIdentifier { oid: COMPRESSION_ZSTD, parameters: None };
			let encap_content_info = EncapsulatedContentInfo { econtent_type: DATA, econtent: None };
			CompressedData { version: CmsVersion::V0, compression_alg, encap_content_info }
		}

		#[test]
		fn yields_cleartext_frame_with_decodable_body() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = encrypted_frame()?;

			frame.decrypt_in_place(&cipher, None)?;

			assert!(frame.metadata.confidentiality.is_none());

			let decoded: TestMessage = crate::decode(&frame.message)?;
			assert_eq!(decoded, TestMessage::sample(Some("in-place")));
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
			let message = TestMessage::sample(None);
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = compose! { V0: id: "dip-002", order: 1u64, message: message }?;

			let result = frame.decrypt_in_place(&cipher, None);
			assert!(matches!(result, Err(TightBeamError::MissingEncryptionInfo)));
			Ok(())
		}

		#[test]
		fn compressed_without_inflator_fails_before_mutation() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = encrypted_frame()?;
			frame.metadata.compactness = Some(zstd_compactness());

			let original = frame.clone();
			let result = frame.decrypt_in_place(&cipher, None);
			assert!(matches!(result, Err(TightBeamError::MissingInflator)));
			assert_eq!(frame, original);
			Ok(())
		}

		/// An inflator that refuses every body.
		struct RefusingInflator;

		impl crate::core::Inflator for RefusingInflator {
			fn decompress(&self, _data: &[u8]) -> Result<Vec<u8>> {
				Err(TightBeamError::MissingInflator)
			}
		}

		#[test]
		fn failed_inflate_after_decrypt_restores_frame() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = encrypted_frame()?;
			frame.metadata.compactness = Some(zstd_compactness());

			let original = frame.clone();
			let result = frame.decrypt_in_place(&cipher, Some(&RefusingInflator));
			assert!(result.is_err());
			assert_eq!(frame, original);
			Ok(())
		}
	}

	#[cfg(all(feature = "aes-gcm", feature = "tokio"))]
	mod encrypt {
		use super::*;
		use crate::crypto::aead::{Aes256Gcm, KeyInit};
		use crate::crypto::key::Aes256GcmKeyProvider;

		fn provider() -> Result<Aes256GcmKeyProvider> {
			let key_bytes = [42u8; 32];
			let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;
			Ok(Aes256GcmKeyProvider::from(cipher))
		}

		#[tokio::test]
		async fn test_frame_encrypt_decrypt_roundtrip() -> Result<()> {
			let message = TestMessage::sample(None);
			let original_message_bytes = crate::encode(&message)?;

			let mut frame = compose! { V1: id: "test-encrypt", order: 1696521600u64, message: message }?;
			assert!(frame.metadata.confidentiality.is_none());
			assert_eq!(frame.message, original_message_bytes);

			let provider = provider()?;
			frame.encrypt_with_provider(&provider, 12).await?;
			assert!(frame.metadata.confidentiality.is_some());
			assert_ne!(frame.message, original_message_bytes);

			frame.decrypt_with_provider(&provider).await?;
			assert!(frame.metadata.confidentiality.is_none());
			assert_eq!(frame.message, original_message_bytes);
			Ok(())
		}

		#[tokio::test]
		async fn encrypting_below_v1_is_refused() -> Result<()> {
			let message = TestMessage::sample(None);
			let mut frame = compose! { V0: id: "test-encrypt-v0", order: 1u64, message: message }?;
			let original = frame.clone();

			let result = frame.encrypt_with_provider(&provider()?, 12).await;
			assert!(matches!(result, Err(TightBeamError::UnsupportedVersion(_))));
			assert_eq!(frame, original);
			Ok(())
		}

		// A frame that names another algorithm is refused before the provider
		// decrypts it.
		#[tokio::test]
		async fn a_provider_refuses_a_frame_that_names_another_algorithm() -> Result<()> {
			let message = TestMessage::sample(None);
			let mut frame = compose! { V1: id: "test-relabel", order: 1u64, message: message }?;
			let provider = provider()?;

			frame.encrypt_with_provider(&provider, 12).await?;

			let info = frame
				.metadata
				.confidentiality
				.as_mut()
				.ok_or(TightBeamError::MissingEncryptionInfo)?;
			info.content_enc_alg.oid = crate::oids::AES_128_GCM;

			let original = frame.clone();
			let result = frame.decrypt_with_provider(&provider).await;
			assert!(matches!(result, Err(TightBeamError::UnexpectedAlgorithm(_))));
			assert_eq!(frame, original);
			Ok(())
		}
	}
}
