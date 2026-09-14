#[cfg(not(feature = "std"))]
use alloc::vec;

use crate::asn1::OctetString;
use crate::core::{Inflator, Message};
use crate::crypto::aead::Decryptor;
use crate::crypto::key::EncryptingKeyProvider;
use crate::crypto::secret::{SecretSlice, ToInsecure};
use crate::der::Any;
use crate::error::Result;
use crate::spki::AlgorithmIdentifierOwned;
use crate::version::GatedField;
use crate::{EncryptedContentInfo, Frame, TightBeamError};

impl Frame {
	/// Decrypt the message body and return the plaintext bytes.
	/// This will consume the frame.
	///
	/// # Arguments
	/// * `decryptor` - The AEAD decryptor to use for decryption
	///
	/// # Returns
	/// The decrypted plaintext as a [`SecretSlice`] that zeroizes on drop. If
	/// the frame was compressed, these bytes are still compressed and need to
	/// be decompressed separately. Callers that need a raw copy opt out
	/// explicitly via [`ToInsecure`].
	///
	/// # Errors
	/// Returns an error if:
	/// - The metadata doesn't contain encryption info (V0 metadata)
	/// - Decryption fails
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

	/// Decrypt, decompress (if needed), and decode the message body into a
	/// typed message T. This is a convenience method that combines
	/// `decrypt_bytes`, `decompress`, and `decode`.
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
	pub fn decrypt<T>(mut self, decryptor: &(impl Decryptor + ?Sized), inflator: Option<&dyn Inflator>) -> Result<T>
	where
		T: Message,
	{
		self.decrypt_in_place(decryptor, inflator)?;
		crate::decode::<T>(&self.message)
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
	/// On any error the frame is unchanged.
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

		let body = decryptor.decrypt_content(&encrypted).and_then(|plaintext| {
			let plaintext = plaintext.to_insecure()?.into_vec();
			match inflator {
				Some(inflator) => inflator.decompress(&plaintext),
				None => Ok(plaintext),
			}
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
	/// This method encrypts the message bytes using the provided encryption key
	/// provider and stores the encrypted content info in the `confidentiality`
	/// field. The encrypted bytes are stored in the `message` field. It is
	/// useful if you require an async `EncryptingKeyProvider` and cannot
	/// encrypt the frame synchronously (HSM, KMS, etc.).
	///
	/// On any error the frame is unchanged.
	///
	/// # Parameters
	/// - `provider`: An encryption key provider implementing the `EncryptingKeyProvider` trait
	/// - `nonce_size`: The size of the nonce in bytes (e.g., 12 for AES-GCM)
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
	/// This method extracts the nonce from the `confidentiality` field's
	/// algorithm parameters and decrypts the message bytes using the provided
	/// encryption key provider. The decrypted bytes are stored back in the
	/// `message` field, and the `confidentiality` field is cleared. It is
	/// useful if you require an async `EncryptingKeyProvider` and cannot
	/// decrypt the frame synchronously (HSM, KMS, etc.).
	///
	/// On any error the frame is unchanged.
	///
	/// # Parameters
	/// - `provider`: An encryption key provider implementing the `EncryptingKeyProvider` trait
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingEncryptionInfo`] when the frame is not encrypted or names no nonce.
	/// - Decryption errors from the provider.
	pub async fn decrypt_with_provider<P>(&mut self, provider: &P) -> Result<()>
	where
		P: EncryptingKeyProvider,
	{
		let encrypted_content_info = self
			.metadata
			.confidentiality
			.as_ref()
			.ok_or(TightBeamError::MissingEncryptionInfo)?;
		let nonce_any = encrypted_content_info
			.content_enc_alg
			.parameters
			.as_ref()
			.ok_or(TightBeamError::MissingEncryptionInfo)?;

		let nonce_octet_string: OctetString = nonce_any.decode_as()?;
		let nonce = nonce_octet_string.as_bytes();
		let plaintext = provider.decrypt(nonce, &self.message).await?;
		self.message = plaintext;
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
	use crate::crypto::aead::Aes256GcmOid;
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
			let (_, cipher) = TestKey::cipher();
			compose! {
				V1: id: "dip-001",
					order: 1u64,
					message: message,
					confidentiality<Aes256GcmOid, _>: cipher
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
			let (_, cipher) = TestKey::cipher();
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
			let (_, cipher) = TestKey::cipher();
			let mut frame = compose! { V0: id: "dip-002", order: 1u64, message: message }?;

			let result = frame.decrypt_in_place(&cipher, None);
			assert!(matches!(result, Err(TightBeamError::MissingEncryptionInfo)));
			Ok(())
		}

		#[test]
		fn compressed_without_inflator_fails_before_mutation() -> Result<()> {
			let (_, cipher) = TestKey::cipher();
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
			let (_, cipher) = TestKey::cipher();
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
	}
}
