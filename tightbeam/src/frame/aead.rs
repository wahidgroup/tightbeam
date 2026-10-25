use core::mem;

use crate::asn1::AuthEnvelopedData;
use crate::core::{Inflator, Message};
use crate::crypto::aead::{DecryptContent, Decryptor};
use crate::crypto::secret::SecretSlice;
use crate::error::Result;
use crate::zeroize::Zeroizing;
use crate::{Frame, TightBeamError};

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::asn1::WireDer;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::crypto::cms::ContentEncryption;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::crypto::key::EncryptingKeyProvider;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::crypto::profiles::CryptoProvider;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::oids::DATA;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::version::GatedField;

impl Frame {
	/// Consume the frame, decrypt its message body with `decryptor`, and return
	/// the plaintext bytes.
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
	/// - [`TightBeamError::MissingEncryptionInfo`] -- the metadata holds no
	///   encryption info, as V0 metadata does.
	/// - The errors of [`DecryptContent::decrypt_content`].
	pub async fn decrypt_bytes(mut self, decryptor: &(impl Decryptor + ?Sized)) -> Result<SecretSlice<u8>> {
		let sealed = self
			.metadata
			.confidentiality
			.take()
			.ok_or(TightBeamError::MissingEncryptionInfo)?;

		let (arrived, envelope) = sealed.into_parts();
		// The encrypted content lives in the message field, so it moves out
		// with no copy and decrypts in place.
		let mut content = Zeroizing::new(mem::take(&mut self.message));
		decryptor.decrypt_content(&envelope, &arrived, &mut content).await?;
		Ok(SecretSlice::from(mem::take(&mut *content)))
	}

	/// Decrypt, decompress when needed, and decode the message body into a
	/// typed message `T`.
	///
	/// The method combines [`Frame::decrypt_in_place`] and [`crate::decode`].
	/// A compressed body requires an `inflator`.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingEncryptionInfo`] -- the metadata holds no
	///   encryption info, as V0 metadata does.
	/// - [`TightBeamError::MissingInflator`] -- the body is compressed and `inflator` is `None`.
	/// - The errors of [`DecryptContent::decrypt_content`] and [`Inflator::decompress`].
	/// - [`TightBeamError::SerializationError`] -- the cleartext fails to decode as `T`.
	pub async fn decrypt<T>(
		mut self,
		decryptor: &(impl Decryptor + ?Sized),
		inflator: Option<&(dyn Inflator + Sync)>,
	) -> Result<T>
	where
		T: Message,
	{
		self.decrypt_in_place(decryptor, inflator).await?;
		crate::decode::<T>(&self.message)
	}

	/// Decrypt the message body in place, so an encrypted frame becomes its
	/// cleartext equivalent. On any error the frame is unchanged.
	///
	/// # Verify first
	///
	/// Frame-level `integrity` and `nonrepudiation` cover the encrypted body,
	/// and this method leaves them untouched. Verify them *before* the call
	/// ([`Frame::verify_frame_integrity`], [`Frame::verify`]), because they
	/// fail on the cleartext. The message commitment in `metadata.integrity`
	/// is the check that survives decryption ([`Frame::verify_commitment_of`]).
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingEncryptionInfo`] -- the frame is not encrypted.
	/// - [`TightBeamError::MissingInflator`] -- the body is compressed and `inflator` is `None`.
	/// - The errors of [`DecryptContent::decrypt_content`] and [`Inflator::decompress`].
	pub async fn decrypt_in_place(
		&mut self,
		decryptor: &(impl Decryptor + ?Sized),
		inflator: Option<&(dyn Inflator + Sync)>,
	) -> Result<()> {
		let Some(sealed) = self.metadata.confidentiality.as_ref() else {
			return Err(TightBeamError::MissingEncryptionInfo);
		};

		// A compressed body needs an inflator, so its absence refuses before
		// any work.
		let inflator = match (self.metadata.compactness.is_some(), inflator) {
			(false, _) => None,
			(true, Some(inflator)) => Some(inflator),
			(true, None) => return Err(TightBeamError::MissingInflator),
		};

		match inflator {
			// The inflate runs after the open and can refuse, so the body
			// opens in a copy that wipes, and a refused inflate leaves the
			// ciphertext in the frame.
			Some(inflator) => {
				let mut compressed = Zeroizing::new(self.message.clone());
				decryptor.decrypt_content(sealed.value(), sealed.der(), &mut compressed).await?;
				self.message = inflator.decompress(&compressed)?;
			}
			// The body opens in the buffer it arrived in, and a refused open
			// leaves that buffer as it was (`Decryptor::open`).
			None => {
				let opened = decryptor.decrypt_content(sealed.value(), sealed.der(), &mut self.message);
				opened.await?;
			}
		}

		self.metadata.confidentiality = None;
		self.metadata.compactness = None;
		Ok(())
	}

	/// Encrypt the message body under the AEAD of `P`, with the content key
	/// encrypted by the key-encryption key an async key provider holds.
	///
	/// Use it when an [`EncryptingKeyProvider`], such as an HSM or a KMS, holds
	/// the key-encryption key. A refusal of the version or of the seal leaves
	/// the frame unchanged. On success the method stores:
	///
	/// - The envelope in the `confidentiality` field, its recipient named by the provider's key identifier.
	/// - The encrypted bytes in the `message` field, detached from the envelope (RFC 5652 §6.1).
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedVersion`] -- the frame version predates confidentiality.
	/// - [`TightBeamError::EnvelopeError`] -- the provider or the envelope refuses to seal.
	/// - [`TightBeamError::SerializationError`] -- the sealed envelope fails to encode.
	#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	pub async fn encrypt_with_provider<P>(&mut self, provider: &(impl EncryptingKeyProvider + ?Sized)) -> Result<()>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption>,
	{
		self.ensure_allows(GatedField::Confidentiality)?;

		// The body seals in place, and every step of the seal that can fail
		// runs before the body encrypts, so a refused seal leaves the frame
		// unchanged. The envelope carries the body detached, so its encoding
		// is its fields alone, far inside a DER length.
		let envelope = AuthEnvelopedData::seal_to_holder::<P>(provider, DATA, &mut self.message).await?;
		self.metadata.confidentiality = Some(WireDer::new(envelope)?);

		Ok(())
	}

	/// Decrypt the message body under the AEAD of `P`, with the content key
	/// decrypted by the key-encryption key an async key provider holds.
	///
	/// Use it when an [`EncryptingKeyProvider`], such as an HSM or a KMS, holds
	/// the key-encryption key. On any error the frame is unchanged. On success
	/// the method:
	///
	/// 1. holds the envelope of the `confidentiality` field to the provider's key and the AEAD of `P`,
	/// 2. decrypts the message bytes in place with the content key the provider decrypts, and
	/// 3. clears the `confidentiality` field.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingEncryptionInfo`] -- the frame is not encrypted.
	/// - [`TightBeamError::EnvelopeError`] -- the envelope names another key or
	///   another algorithm than the provider's and `P`'s, or fails to open.
	#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	pub async fn decrypt_with_provider<P>(&mut self, provider: &(impl EncryptingKeyProvider + ?Sized)) -> Result<()>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption>,
	{
		let sealed = self
			.metadata
			.confidentiality
			.as_ref()
			.ok_or(TightBeamError::MissingEncryptionInfo)?;

		let envelope = sealed.value();
		let content_type = envelope.auth_encrypted_content_info.content_type;

		// The body opens in the buffer it arrived in, and a refused open
		// leaves that buffer as it was, so the frame is unchanged.
		let opened = envelope.open_with_holder::<P>(sealed.der(), &mut self.message, provider, content_type);
		opened.await?;
		self.metadata.confidentiality = None;

		Ok(())
	}
}

impl TryFrom<Frame> for AuthEnvelopedData {
	type Error = TightBeamError;

	fn try_from(mut frame: Frame) -> core::result::Result<Self, Self::Error> {
		let sealed = frame
			.metadata
			.confidentiality
			.take()
			.ok_or(TightBeamError::MissingEncryptionInfo)?;
		Ok(sealed.into_value())
	}
}

#[cfg(test)]
mod tests {
	use crate::error::Result;
	use crate::testing::{TestKey, TestMessage};
	use crate::{Frame, TightBeamError};

	/// `frame` with the first octet of its encrypted body flipped, so the body
	/// fails its tag.
	fn tampered(mut frame: Frame) -> Frame {
		let octet = frame.message.first_mut().expect("the frame carries an encrypted body");
		*octet ^= 0x01;
		frame
	}

	mod decrypt_in_place {
		use super::*;
		use crate::cms::compressed_data::CompressedData;
		use crate::cms::content_info::CmsVersion;
		use crate::cms::signed_data::EncapsulatedContentInfo;
		use crate::crypto::cms::EnvelopeError;
		use crate::crypto::key::{Aes256GcmKeyProvider, KeyError};
		use crate::crypto::secret::ToInsecure;
		use crate::error::ReceivedExpectedError;
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

		#[tokio::test]
		async fn yields_cleartext_frame_with_decodable_body() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = encrypted_frame()?;
			frame.decrypt_in_place(&cipher, None).await?;

			assert!(frame.metadata.confidentiality.is_none());

			let decoded: TestMessage = crate::decode(&frame.message)?;
			assert_eq!(decoded, TestMessage::sample(Some("in-place")));
			Ok(())
		}

		/// The frame moves its ciphertext out, and the decryptor returns the
		/// encoded body.
		#[tokio::test]
		async fn decrypt_bytes_returns_the_encoded_body() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let frame = encrypted_frame()?;

			let plaintext = frame.decrypt_bytes(&cipher).await?;
			let expected = crate::encode(&TestMessage::sample(Some("in-place")))?;
			assert_eq!(&plaintext.to_insecure()[..], expected.as_slice());
			Ok(())
		}

		/// An in-memory key holds a key-encryption key of its wrap's size
		/// alone: 32 octets for AES-256 key wrap (RFC 3394).
		#[test]
		fn an_in_memory_kek_of_another_size_is_refused() {
			let refused = Aes256GcmKeyProvider::new(vec![0x33; 16], b"tb/test/kek/v1".to_vec());
			let expected = ReceivedExpectedError { received: 16, expected: 32 };
			assert!(matches!(refused, Err(KeyError::KekLength(found)) if found == expected));
		}

		/// The ciphertext travels in the message, so the envelope in the
		/// metadata carries no encrypted content (RFC 5652 §6.1).
		#[test]
		fn the_envelope_of_a_frame_carries_no_content() -> Result<()> {
			let frame = encrypted_frame()?;

			let metadata = frame.metadata();
			let envelope = metadata.confidentiality().ok_or(TightBeamError::MissingEncryptionInfo)?;
			assert!(envelope.auth_encrypted_content_info.encrypted_content.is_none());
			Ok(())
		}

		/// A frame with no compression opens in the buffer its body arrived
		/// in.
		#[tokio::test]
		async fn a_frame_opens_in_the_buffer_it_arrived_in() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = encrypted_frame()?;
			let arrived = frame.message().as_ptr();

			frame.decrypt_in_place(&cipher, None).await?;
			assert_eq!(frame.message().as_ptr(), arrived);
			Ok(())
		}

		/// A body that fails its tag is refused, and the open, which ran in the
		/// body's own buffer, leaves the frame as it arrived.
		#[tokio::test]
		async fn a_body_that_fails_its_tag_leaves_the_frame() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = tampered(encrypted_frame()?);
			let original = frame.clone();

			let result = frame.decrypt_in_place(&cipher, None).await;
			assert!(matches!(
				result,
				Err(TightBeamError::EnvelopeError(EnvelopeError::Authentication))
			));
			assert_eq!(frame, original);
			Ok(())
		}

		#[tokio::test]
		async fn wrong_key_restores_frame() -> Result<()> {
			let mut frame = encrypted_frame()?;
			let original = frame.clone();
			let wrong_cipher = Aes256GcmKeyProvider::new(vec![0x44; 32], b"tb/test/kek/v1".to_vec())?;

			let result = frame.decrypt_in_place(&wrong_cipher, None).await;
			assert!(matches!(result, Err(TightBeamError::EnvelopeError(EnvelopeError::KeyUnwrap))));
			assert_eq!(frame, original);
			Ok(())
		}

		#[tokio::test]
		async fn a_key_of_another_identifier_is_refused() -> Result<()> {
			let mut frame = encrypted_frame()?;
			let other = Aes256GcmKeyProvider::new(vec![0x33; 32], b"tb/test/other/kek/v1".to_vec())?;

			let result = frame.decrypt_in_place(&other, None).await;
			assert!(matches!(
				result,
				Err(TightBeamError::EnvelopeError(EnvelopeError::KeyIdentifier))
			));
			Ok(())
		}

		#[tokio::test]
		async fn cleartext_frame_rejected() -> Result<()> {
			let message = TestMessage::sample(None);
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = compose! { V0: id: "dip-002", order: 1u64, message: message }?;

			let result = frame.decrypt_in_place(&cipher, None).await;
			assert!(matches!(result, Err(TightBeamError::MissingEncryptionInfo)));
			Ok(())
		}

		#[tokio::test]
		async fn compressed_without_inflator_fails_before_mutation() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = encrypted_frame()?;
			frame.metadata.compactness = Some(zstd_compactness());

			let original = frame.clone();
			let result = frame.decrypt_in_place(&cipher, None).await;
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

		#[tokio::test]
		async fn failed_inflate_after_decrypt_restores_frame() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = encrypted_frame()?;
			frame.metadata.compactness = Some(zstd_compactness());

			let original = frame.clone();
			let result = frame.decrypt_in_place(&cipher, Some(&RefusingInflator)).await;
			assert!(result.is_err());
			assert_eq!(frame, original);
			Ok(())
		}
	}

	#[cfg(all(feature = "aes-gcm", feature = "tokio"))]
	mod encrypt {
		use core::future::{ready, Future};
		use core::pin::Pin;

		use super::*;
		use crate::asn1::WireDer;
		use crate::crypto::cms::EnvelopeError;
		use crate::crypto::key::{Aes256GcmKeyProvider, EncryptingKeyProvider, KeyError};
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::crypto::secret::SecretSlice;
		use crate::oids::AES_256_WRAP;
		use crate::spki::AlgorithmIdentifierOwned;

		/// The key identifier of [`provider`].
		const KEY_IDENTIFIER: &[u8] = b"tb/test/frame/kek/v1";

		fn provider() -> Result<Aes256GcmKeyProvider> {
			Ok(Aes256GcmKeyProvider::new(vec![42u8; 32], KEY_IDENTIFIER.to_vec())?)
		}

		#[tokio::test]
		async fn test_frame_encrypt_decrypt_roundtrip() -> Result<()> {
			let message = TestMessage::sample(None);
			let original_message_bytes = crate::encode(&message)?;

			let mut frame = compose! { V1: id: "test-encrypt", order: 1696521600u64, message: message }?;
			assert!(frame.metadata.confidentiality.is_none());
			assert_eq!(frame.message, original_message_bytes);

			let provider = provider()?;
			frame.encrypt_with_provider::<DefaultCryptoProvider>(&provider).await?;
			assert!(frame.metadata.confidentiality.is_some());
			assert_ne!(frame.message, original_message_bytes);

			frame.decrypt_with_provider::<DefaultCryptoProvider>(&provider).await?;
			assert!(frame.metadata.confidentiality.is_none());
			assert_eq!(frame.message, original_message_bytes);
			Ok(())
		}

		/// A frame sealed through the async provider opens under the same
		/// in-memory key as a frame decryptor, because both write one
		/// `KEKRecipientInfo` under the provider's key and wrap.
		#[tokio::test]
		async fn a_frame_sealed_through_the_provider_opens_as_a_frame_decryptor() -> Result<()> {
			let message = TestMessage::sample(None);
			let mut frame = compose! { V1: id: "test-provider-seal", order: 1u64, message: message.clone() }?;
			let provider = provider()?;

			frame.encrypt_with_provider::<DefaultCryptoProvider>(&provider).await?;

			let opened: TestMessage = frame.decrypt(&provider, None).await?;
			assert_eq!(opened, message);
			Ok(())
		}

		/// The `kekid.keyIdentifier` of the one `KEKRecipientInfo` of `frame`.
		fn key_identifier_of(frame: &Frame) -> Vec<u8> {
			use crate::cms::enveloped_data::RecipientInfo;

			let envelope = frame.metadata().confidentiality().expect("the frame is encrypted");
			let recipient = match envelope.recipient_infos.0.as_slice().first() {
				Some(RecipientInfo::Kekri(recipient)) => Some(recipient),
				_ => None,
			};
			let recipient = recipient.expect("the frame carries one KEKRecipientInfo");
			recipient.kek_id.kek_identifier.as_bytes().to_vec()
		}

		/// The provider's key identifier names the key-encryption key of the
		/// frame's one `KEKRecipientInfo`.
		#[tokio::test]
		async fn a_provider_seal_names_the_providers_key() -> Result<()> {
			let message = TestMessage::sample(None);
			let mut frame = compose! { V1: id: "test-kekid", order: 1u64, message: message }?;
			frame.encrypt_with_provider::<DefaultCryptoProvider>(&provider()?).await?;

			assert_eq!(key_identifier_of(&frame), KEY_IDENTIFIER);
			Ok(())
		}

		/// A key holder that refuses every key it receives.
		#[derive(Debug)]
		struct RefusingHolder;

		impl EncryptingKeyProvider for RefusingHolder {
			fn algorithm(&self) -> AlgorithmIdentifierOwned {
				AlgorithmIdentifierOwned { oid: AES_256_WRAP, parameters: None }
			}

			fn key_identifier(&self) -> &[u8] {
				KEY_IDENTIFIER
			}

			fn encrypt(
				&self,
				content_key: &[u8],
			) -> Pin<Box<dyn Future<Output = core::result::Result<Vec<u8>, KeyError>> + Send + '_>> {
				Box::pin(ready(Err(KeyError::WrapLength((content_key.len(), 0).into()))))
			}

			fn decrypt(
				&self,
				encrypted_key: &[u8],
			) -> Pin<Box<dyn Future<Output = core::result::Result<SecretSlice<u8>, KeyError>> + Send + '_>> {
				Box::pin(ready(Err(KeyError::WrapLength((encrypted_key.len(), 0).into()))))
			}
		}

		/// A holder that refuses the content key refuses the seal, which runs
		/// before the body encrypts, so the frame keeps its body.
		#[tokio::test]
		async fn a_seal_its_holder_refuses_leaves_the_frame() -> Result<()> {
			let message = TestMessage::sample(None);
			let mut frame = compose! { V1: id: "test-refused-seal", order: 1u64, message: message }?;
			let original = frame.clone();

			let result = frame.encrypt_with_provider::<DefaultCryptoProvider>(&RefusingHolder).await;
			assert!(matches!(result, Err(TightBeamError::EnvelopeError(EnvelopeError::Key(_)))));
			assert_eq!(frame, original);
			Ok(())
		}

		/// The provider's open refuses a body that fails its tag, and the open
		/// runs in the body's own buffer, so it leaves the frame as it arrived.
		#[tokio::test]
		async fn a_provider_open_of_a_body_that_fails_its_tag_leaves_the_frame() -> Result<()> {
			let message = TestMessage::sample(None);
			let mut frame = compose! { V1: id: "test-refused-open", order: 1u64, message: message }?;
			let provider = provider()?;

			frame.encrypt_with_provider::<DefaultCryptoProvider>(&provider).await?;

			let mut frame = tampered(frame);
			let original = frame.clone();

			let result = frame.decrypt_with_provider::<DefaultCryptoProvider>(&provider).await;
			assert!(matches!(
				result,
				Err(TightBeamError::EnvelopeError(EnvelopeError::Authentication))
			));
			assert_eq!(frame, original);
			Ok(())
		}

		#[tokio::test]
		async fn encrypting_below_v1_is_refused() -> Result<()> {
			let message = TestMessage::sample(None);
			let mut frame = compose! { V0: id: "test-encrypt-v0", order: 1u64, message: message }?;
			let original = frame.clone();

			let result = frame.encrypt_with_provider::<DefaultCryptoProvider>(&provider()?).await;
			assert!(matches!(result, Err(TightBeamError::UnsupportedVersion(_))));
			assert_eq!(frame, original);
			Ok(())
		}

		// `decrypt_with_provider` refuses a frame that names another algorithm
		// before the provider decrypts it.
		#[tokio::test]
		async fn a_provider_refuses_a_frame_that_names_another_algorithm() -> Result<()> {
			let message = TestMessage::sample(None);
			let mut frame = compose! { V1: id: "test-relabel", order: 1u64, message: message }?;
			let provider = provider()?;

			frame.encrypt_with_provider::<DefaultCryptoProvider>(&provider).await?;

			let metadata = frame.metadata();
			let envelope = metadata.confidentiality().ok_or(TightBeamError::MissingEncryptionInfo)?;
			let mut relabelled = envelope.clone();

			relabelled.auth_encrypted_content_info.content_enc_alg.oid = crate::oids::AES_128_GCM;
			frame.metadata.confidentiality = Some(WireDer::new(relabelled)?);

			let original = frame.clone();
			let result = frame.decrypt_with_provider::<DefaultCryptoProvider>(&provider).await;
			assert!(matches!(
				result,
				Err(TightBeamError::EnvelopeError(EnvelopeError::ContentEncryptionAlgorithm))
			));
			assert_eq!(frame, original);
			Ok(())
		}
	}
}
