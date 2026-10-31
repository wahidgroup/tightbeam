use core::mem;

use crate::asn1::AuthEnvelopedData;
use crate::core::{Inflator, Message};
use crate::crypto::aead::{DecryptContent, Decryptor};
use crate::crypto::secret::SecretSlice;
use crate::error::Result;
use crate::frame::Opened;
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
	/// The plaintext is a [`SecretSlice`] that zeroizes on drop. The bytes of a
	/// compressed frame stay compressed, so the caller decompresses them. A
	/// caller who must own the bytes takes them through
	/// [`ToInsecure::to_insecure`], a buffer that also wipes on drop.
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

		// The encrypted content lives in the message field, so it moves out
		// with no copy and decrypts in place.
		let mut content = Zeroizing::new(mem::take(&mut self.message));
		decryptor.decrypt_content(&sealed, &mut content).await?;
		Ok(SecretSlice::from(mem::take(&mut *content)))
	}

	/// Decrypt, decompress when needed, and decode the message body into a
	/// typed message `T`.
	///
	/// The steps run in this order:
	///
	/// 1. The frame, as it arrived, meets the requirements of `T` ([`Frame::validate_for`]).
	/// 2. [`Frame::decrypt_in_place`] opens the body, and an `inflator` inflates a compressed one.
	/// 3. The cleartext decodes as `T`.
	///
	/// The [`Opened`] drops with the frame, so a caller that names the signer
	/// after the open calls [`Frame::decrypt_in_place`].
	///
	/// # Errors
	///
	/// - [`TightBeamError::Requirement`] -- the frame, as it arrived, fails a requirement of `T`.
	/// - [`TightBeamError::MissingEncryptionInfo`] -- the metadata holds no
	///   encryption info, as V0 metadata does.
	/// - [`TightBeamError::MissingInflator`] -- the body is compressed and `inflator` is `None`.
	/// - The errors of [`DecryptContent::decrypt_content`] and [`Inflator::decompress`].
	/// - [`TightBeamError::SerializationError`] -- the cleartext fails to decode as
	///   `T`, or a SET in it holds its elements out of DER order.
	pub async fn decrypt<T>(
		mut self,
		decryptor: &(impl Decryptor + ?Sized),
		inflator: Option<&(dyn Inflator + Sync)>,
	) -> Result<T>
	where
		T: Message,
	{
		// The typed message is the one product, so the digest and the
		// signature that the open takes out drop with the frame.
		let open = async |frame: &mut Self| frame.decrypt_in_place(decryptor, inflator).await.map(drop);
		self.open_message::<T>(open).await
	}

	/// Decrypt the message body in place, so an encrypted frame becomes its
	/// cleartext equivalent. On any error the frame is unchanged.
	///
	/// # Verify first
	///
	/// Frame-level `integrity` and `nonrepudiation` fail on the cleartext, so
	/// verify them *before* the call ([`Frame::verify_frame_integrity`],
	/// [`Frame::verify`]). The decrypt moves both into the [`Opened`] it
	/// returns. The message commitment in `metadata.integrity` is the check
	/// that survives decryption ([`Frame::verify_commitment_of`]).
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingEncryptionInfo`] -- the frame is not encrypted.
	/// - [`TightBeamError::MissingInflator`] -- the body is compressed and `inflator` is `None`.
	/// - The errors of [`Frame::inflate_in_place`] for the `CompressedData`,
	///   when it names an algorithm or a form that `inflator` refuses.
	/// - The errors of [`DecryptContent::decrypt_content`] and [`Inflator::decompress`].
	pub async fn decrypt_in_place(
		&mut self,
		decryptor: &(impl Decryptor + ?Sized),
		inflator: Option<&(dyn Inflator + Sync)>,
	) -> Result<Opened> {
		let Some(sealed) = self.metadata.confidentiality.as_ref() else {
			return Err(TightBeamError::MissingEncryptionInfo);
		};

		// A compressed body needs an inflator that reverses the algorithm its
		// `CompressedData` names, so a missing or a refusing inflator refuses
		// before any work.
		let inflator = match (self.metadata.compactness.is_some(), inflator) {
			(false, _) => None,
			(true, Some(inflator)) => {
				self.metadata.admit_compactness(inflator)?;
				Some(inflator)
			}
			(true, None) => return Err(TightBeamError::MissingInflator),
		};

		match inflator {
			// The inflate runs after the open and can refuse, so the body
			// opens in a copy that wipes, and a refused inflate leaves the
			// ciphertext in the frame.
			Some(inflator) => {
				let mut compressed = Zeroizing::new(self.message.clone());
				decryptor.decrypt_content(sealed, &mut compressed).await?;
				self.message = self.metadata.inflate(inflator, &compressed)?;
			}
			// The body opens in the buffer it arrived in, and a refused open
			// leaves that buffer unchanged (`Decryptor::open`).
			None => {
				decryptor.decrypt_content(sealed, &mut self.message).await?;
			}
		}

		self.metadata.confidentiality = None;
		self.metadata.compactness = None;
		Ok(self.take_opened())
	}

	/// Encrypt the message body under the AEAD of `P`, and the content key
	/// under the key-encryption key that an async key provider holds.
	///
	/// Use it when an [`EncryptingKeyProvider`], such as an HSM or a KMS, holds
	/// the key-encryption key. On any error the frame is unchanged. On success
	/// it stores:
	///
	/// - The envelope in the `confidentiality` field, its recipient named by the provider's key identifier.
	/// - The encrypted bytes in the `message` field, detached from the envelope (RFC 5652 §6.1).
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedField`] -- the frame version predates confidentiality.
	/// - [`TightBeamError::CoveredBeforeSeal`] -- the frame carries an FI digest or a signature.
	/// - [`TightBeamError::EnvelopeError`] -- the provider or the envelope refuses to seal.
	#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	pub async fn encrypt_with_provider<P>(&mut self, provider: &(impl EncryptingKeyProvider + ?Sized)) -> Result<()>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption>,
	{
		self.ensure_allows(GatedField::Confidentiality)?;
		self.ensure_uncovered()?;

		// Each step of the seal that can fail runs before the body encrypts in
		// place, so a refused seal leaves the frame unchanged. The DER length
		// check is one, so the envelope that the seal returns encodes.
		let envelope = AuthEnvelopedData::seal_to_holder::<P>(provider, DATA, &mut self.message).await?;
		self.metadata.confidentiality = Some(WireDer::new(envelope)?);

		Ok(())
	}

	/// Decrypt the message body under the AEAD of `P`, with the content key
	/// that an async key provider decrypts under the key-encryption key it
	/// holds.
	///
	/// Use it when an [`EncryptingKeyProvider`], such as an HSM or a KMS, holds
	/// the key-encryption key. On any error the frame is unchanged. On success
	/// it:
	///
	/// 1. holds the envelope of the `confidentiality` field to the provider's key and the AEAD of `P`,
	/// 2. decrypts the message bytes in place with the content key the provider decrypts,
	/// 3. clears the `confidentiality` field, and
	/// 4. takes the FI digest and the signature out of the frame, into the [`Opened`] it returns.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingEncryptionInfo`] -- the frame is not encrypted.
	/// - [`TightBeamError::EnvelopeError`] -- the envelope names another key or
	///   another algorithm than the provider's and `P`'s, or fails to open.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::compose;
	/// use tightbeam::crypto::key::Aes256GcmKeyProvider;
	/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
	/// use tightbeam::testing::TestMessage;
	///
	/// # let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
	/// # runtime.block_on(async {
	/// let holder = Aes256GcmKeyProvider::new(vec![0x42; 32], b"example-kek".to_vec())?;
	/// let message = TestMessage::sample(None);
	/// let mut frame = compose! { V1: id: "held", order: 1u64, message: message.clone() }?;
	/// frame.encrypt_with_provider::<DefaultCryptoProvider>(&holder).await?;
	///
	/// let _opened = frame.decrypt_with_provider::<DefaultCryptoProvider>(&holder).await?;
	/// assert_eq!(tightbeam::decode::<TestMessage>(frame.message())?, message);
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// # })?;
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	pub async fn decrypt_with_provider<P>(&mut self, provider: &(impl EncryptingKeyProvider + ?Sized)) -> Result<Opened>
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
		// leaves that buffer, and so the frame, unchanged.
		let opened = envelope.open_with_holder::<P>(sealed.der(), &mut self.message, provider, content_type);
		opened.await?;
		self.metadata.confidentiality = None;

		Ok(self.take_opened())
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
	use crate::testing::{TestFrame, TestKey, TestMessage, TestResult};
	use crate::{Frame, TightBeamError};

	/// Returns `frame` with the first octet of its encrypted body flipped, so
	/// the body fails its tag.
	fn tampered(mut frame: Frame) -> Frame {
		let octet = frame.message.first_mut().expect("the frame carries an encrypted body");
		*octet ^= 0x01;
		frame
	}

	mod decrypt_in_place {
		use super::*;
		use crate::asn1::admission::fixtures::tlv;
		use crate::asn1::{AuthEnvelopedData, WireDer};
		use crate::cms::compressed_data::CompressedData;
		use crate::cms::content_info::CmsVersion;
		use crate::cms::enveloped_data::OriginatorInfo;
		use crate::cms::signed_data::EncapsulatedContentInfo;
		use crate::core::Inflator;
		use crate::crypto::cms::EnvelopeError;
		use crate::crypto::key::{Aes256GcmKeyProvider, KeyError};
		use crate::crypto::secret::ToInsecure;
		use crate::der::asn1::{Null, ObjectIdentifier, SetOfVec};
		use crate::der::{Any, AnyRef, Decode, ErrorKind, Tag, TagNumber};
		use crate::error::ReceivedExpectedError;
		use crate::frame::Opened;
		use crate::oids::{COMPRESSION_ZSTD, DATA};
		use crate::runtime::rt;
		use crate::spki::AlgorithmIdentifier;
		use crate::x509::attr::Attribute;

		#[cfg(feature = "zstd")]
		use crate::compress::ZstdCompression;
		#[cfg(feature = "zstd")]
		use crate::oids::COMPRESSION_ZLIB;

		/// Returns the compression parameters that mark a body as
		/// zstd-compressed.
		fn zstd_compactness() -> CompressedData {
			let compression_alg = AlgorithmIdentifier { oid: COMPRESSION_ZSTD, parameters: None };
			let encap_content_info = EncapsulatedContentInfo { econtent_type: DATA, econtent: None };
			CompressedData { version: CmsVersion::V0, compression_alg, encap_content_info }
		}

		/// Returns the frame of [`TestFrame::sealed`] with its metadata marking
		/// the body compressed as `compactness` describes.
		fn sealed_compressed(compactness: CompressedData) -> Frame {
			let mut frame = TestFrame::sealed("dip-001");
			frame.metadata.compactness = Some(compactness);
			frame
		}

		/// Returns an in-memory key of thirty-two `fill` octets under
		/// `identifier`.
		fn key_of(fill: u8, identifier: &[u8]) -> Aes256GcmKeyProvider {
			let key = Aes256GcmKeyProvider::new(vec![fill; 32], identifier.to_vec());
			key.expect("32 octets is the key of AES-256 key wrap")
		}

		/// Returns `frame` with `edit` applied to the envelope of its
		/// `confidentiality` field, which the frame then carries in its DER.
		fn with_envelope(mut frame: Frame, edit: impl FnOnce(&mut AuthEnvelopedData)) -> Frame {
			let sealed = frame.metadata.confidentiality.take().expect("the frame is encrypted");
			let mut envelope = sealed.into_value();
			edit(&mut envelope);
			frame.metadata.confidentiality = Some(WireDer::new(envelope).expect("the envelope encodes"));
			frame
		}

		/// Returns an `unauthAttrs` of one attribute of one `NULL` value.
		fn unauthenticated_attributes() -> SetOfVec<Attribute> {
			let oid = ObjectIdentifier::new_unwrap("1.2.3.4");
			let value = Any::encode_from(&Null).expect("a NULL encodes");
			let values = SetOfVec::try_from(vec![value]).expect("a set of one value forms");
			SetOfVec::try_from(vec![Attribute { oid, values }]).expect("a set of one attribute forms")
		}

		/// Returns the kind of the DER error that refused an open, or `None`
		/// for another outcome.
		fn encoding_refusal<T>(outcome: Result<T>) -> Option<ErrorKind> {
			match outcome {
				Err(TightBeamError::EnvelopeError(EnvelopeError::Encoding(error))) => Some(error.kind()),
				_ => None,
			}
		}

		/// An open yields the cleartext frame, whose body decodes.
		#[tokio::test]
		async fn yields_cleartext_frame_with_decodable_body() -> TestResult {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = TestFrame::sealed("dip-001");
			let _opened = frame.decrypt_in_place(&cipher, None).await?;

			assert!(frame.metadata.confidentiality.is_none());

			let decoded: TestMessage = crate::decode(&frame.message)?;
			assert_eq!(decoded, TestMessage::sample(None));
			Ok(())
		}

		/// The frame moves its ciphertext out, and the decryptor returns the
		/// encoded body.
		#[tokio::test]
		async fn decrypt_bytes_returns_the_encoded_body() -> TestResult {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let frame = TestFrame::sealed("dip-001");

			let plaintext = frame.decrypt_bytes(&cipher).await?;
			let expected = crate::encode(&TestMessage::sample(None))?;
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
		fn the_envelope_of_a_frame_carries_no_content() -> TestResult {
			let frame = TestFrame::sealed("dip-001");

			let metadata = frame.metadata();
			let envelope = metadata.confidentiality().ok_or(TightBeamError::MissingEncryptionInfo)?;
			assert!(envelope.auth_encrypted_content_info.encrypted_content.is_none());
			Ok(())
		}

		/// The metadata of a frame reads its envelope through the `WireDer`
		/// decode, which holds the envelope to its arrival, so it refuses a
		/// stray `[1]` after `mac`, which `der` skips (X.690 § 8.9.2).
		#[test]
		fn a_frame_envelope_with_a_stray_context_tag_is_refused() -> TestResult {
			let frame = TestFrame::sealed("dip-001");
			let sealed = frame.metadata.confidentiality.as_ref();
			let sealed = sealed.ok_or(TightBeamError::MissingEncryptionInfo)?;
			let fields = AnyRef::from_der(sealed.der())?.value();
			let stray = tlv(Tag::Sequence, &[fields, &[0xa1, 0x02, 0x05, 0x00]].concat());

			let refused = WireDer::<AuthEnvelopedData>::from_der(&stray).map_err(|error| error.kind());
			assert_eq!(refused, Err(ErrorKind::Noncanonical { tag: Tag::Sequence }));
			Ok(())
		}

		// The tag of a frame covers no `originatorInfo` and no `unauthAttrs`,
		// so the open refuses a frame whose envelope carries either, as a
		// record refuses them (RFC 5083 § 2.1). The refusal names the context
		// tag of the field.
		crate::tb_cases! {
			fn the_open_refuses_an_envelope_that_carries(
				(edit, number): (fn(&mut AuthEnvelopedData), TagNumber)
			) {
				let (_, cipher) = TestKey::insecure_fixed_cipher();
				let mut frame = with_envelope(TestFrame::sealed("dip-001"), edit);

				let refused = rt::block_on(frame.decrypt_in_place(&cipher, None));
				let tag = Tag::ContextSpecific { constructed: true, number };
				assert_eq!(encoding_refusal(refused), Some(ErrorKind::Value { tag }));
			}
			cases {
				an_originator => (
					|envelope| envelope.originator_info = Some(OriginatorInfo { certs: None, crls: None }),
					TagNumber::N0,
				),
				unauthenticated_attributes => (
					|envelope| envelope.unauth_attrs = Some(unauthenticated_attributes()),
					TagNumber::N2,
				),
			}
		}

		/// A frame with no compression opens in the buffer its body arrived
		/// in.
		#[tokio::test]
		async fn a_frame_opens_in_the_buffer_it_arrived_in() -> TestResult {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = TestFrame::sealed("dip-001");
			let arrived = frame.message().as_ptr();

			let _opened = frame.decrypt_in_place(&cipher, None).await?;
			assert_eq!(frame.message().as_ptr(), arrived);
			Ok(())
		}

		/// A sealed frame, the key and the inflator an open meets it with, and
		/// the test of the refusal.
		type RefusedOpen = (
			Frame,
			Aes256GcmKeyProvider,
			Option<Box<dyn Inflator + Sync>>,
			fn(&Result<Opened>) -> bool,
		);

		// `decrypt_in_place` leaves the frame as it arrived when it refuses the
		// open, whether the refusal falls before the decrypt or after it.
		crate::tb_cases! {
			fn a_refused_open_leaves_the_frame((arrived, key, inflator, refused): RefusedOpen) {
				let mut frame = arrived.clone();
				let opened = rt::block_on(frame.decrypt_in_place(&key, inflator.as_deref()));
				assert!(refused(&opened));
				assert_eq!(frame, arrived);
			}
			cases {
				/// The open runs in the body's own buffer.
				of_a_body_that_fails_its_tag => (
					tampered(TestFrame::sealed("dip-001")),
					TestKey::insecure_fixed_cipher().1,
					None,
					|opened| matches!(opened, Err(TightBeamError::EnvelopeError(EnvelopeError::Authentication))),
				),
				/// The content key unwraps under the key of the seal alone.
				under_the_wrong_key => (
					TestFrame::sealed("dip-001"),
					key_of(0x44, b"tb/test/kek/v1"),
					None,
					|opened| matches!(opened, Err(TightBeamError::EnvelopeError(EnvelopeError::KeyUnwrap))),
				),
				/// A compressed body with no inflator fails before the open
				/// changes the frame.
				of_a_compressed_body_with_no_inflator => (
					sealed_compressed(zstd_compactness()),
					TestKey::insecure_fixed_cipher().1,
					None,
					|opened| matches!(opened, Err(TightBeamError::MissingInflator)),
				),
				/// The inflate fails after the decrypt, and the open restores
				/// the frame.
				of_a_body_its_inflator_refuses => (
					sealed_compressed(zstd_compactness()),
					TestKey::insecure_fixed_cipher().1,
					Some(Box::new(RefusingInflator)),
					|opened| matches!(opened, Err(TightBeamError::MissingInflator)),
				),
				/// A body that names another compression algorithm than the
				/// inflator's is refused before the decrypt.
				#[cfg(feature = "zstd")]
				of_a_body_under_another_compression_algorithm => (
					sealed_compressed(CompressedData {
						compression_alg: AlgorithmIdentifier { oid: COMPRESSION_ZLIB, parameters: None },
						..zstd_compactness()
					}),
					TestKey::insecure_fixed_cipher().1,
					Some(Box::new(ZstdCompression::default())),
					|opened| matches!(
						opened,
						Err(TightBeamError::UnexpectedAlgorithm(found))
							if *found == ReceivedExpectedError::from((COMPRESSION_ZLIB, COMPRESSION_ZSTD))
					),
				),
			}
		}

		/// A key whose identifier names another recipient is refused.
		#[tokio::test]
		async fn a_key_of_another_identifier_is_refused() {
			let mut frame = TestFrame::sealed("dip-001");
			let other = key_of(0x33, b"tb/test/other/kek/v1");

			let result = frame.decrypt_in_place(&other, None).await;
			assert!(matches!(
				result,
				Err(TightBeamError::EnvelopeError(EnvelopeError::KeyIdentifier))
			));
		}

		/// A frame that carries no confidentiality is refused at the open.
		#[tokio::test]
		async fn cleartext_frame_rejected() {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = TestFrame::v1(None, Some("dip-002"));

			let result = frame.decrypt_in_place(&cipher, None).await;
			assert!(matches!(result, Err(TightBeamError::MissingEncryptionInfo)));
		}

		/// An inflator that refuses every body.
		///
		/// The house inflators inflate every body they can parse, and the case
		/// needs a refusal after the decrypt.
		struct RefusingInflator;

		impl Inflator for RefusingInflator {
			fn algorithm_oid(&self) -> ObjectIdentifier {
				COMPRESSION_ZSTD
			}

			fn decompress(&self, _data: &[u8]) -> Result<Vec<u8>> {
				Err(TightBeamError::MissingInflator)
			}
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
		use crate::der::Length;
		use crate::oids::AES_256_WRAP;
		use crate::runtime::rt;
		use crate::spki::AlgorithmIdentifierOwned;
		use crate::version::GatedField;
		use crate::Version;

		/// The key identifier of [`provider`].
		const KEY_IDENTIFIER: &[u8] = b"tb/test/frame/kek/v1";

		/// Returns an in-memory key of thirty-two `42` octets under
		/// [`KEY_IDENTIFIER`].
		fn provider() -> Aes256GcmKeyProvider {
			let provider = Aes256GcmKeyProvider::new(vec![42u8; 32], KEY_IDENTIFIER.to_vec());
			provider.expect("32 octets is the key of AES-256 key wrap")
		}

		/// The V1 frame of [`TestFrame::v1`] under `id`, sealed through
		/// [`provider`].
		fn provider_sealed(id: &str) -> Frame {
			let mut frame = TestFrame::v1(None, Some(id));
			let sealed = rt::block_on(frame.encrypt_with_provider::<DefaultCryptoProvider>(&provider()));
			sealed.expect("the in-memory key seals a V1 frame");
			frame
		}

		/// A seal through the provider records the confidentiality of the frame
		/// and replaces its body.
		#[tokio::test]
		async fn a_seal_records_confidentiality_and_replaces_the_body() -> TestResult {
			let mut frame = TestFrame::v1(None, Some("test-encrypt"));
			let cleartext = frame.message.clone();

			frame.encrypt_with_provider::<DefaultCryptoProvider>(&provider()).await?;

			assert!(frame.metadata.confidentiality.is_some());
			assert_ne!(frame.message, cleartext);
			Ok(())
		}

		/// An open through the provider restores the body that its seal
		/// replaced, and clears the confidentiality of the frame.
		#[tokio::test]
		async fn an_open_restores_the_body_its_seal_replaced() -> TestResult {
			let cleartext = TestFrame::v1(None, Some("test-encrypt")).message().to_vec();
			let mut frame = provider_sealed("test-encrypt");

			let _opened = frame.decrypt_with_provider::<DefaultCryptoProvider>(&provider()).await?;
			assert!(frame.metadata.confidentiality.is_none());
			assert_eq!(frame.message, cleartext);
			Ok(())
		}

		/// A frame sealed through the async provider opens under the same
		/// in-memory key as a frame decryptor, because both write one
		/// `KEKRecipientInfo` under the provider's key and wrap.
		#[tokio::test]
		async fn a_frame_sealed_through_the_provider_opens_as_a_frame_decryptor() -> TestResult {
			let frame = provider_sealed("test-provider-seal");
			let opened: TestMessage = frame.decrypt(&provider(), None).await?;
			assert_eq!(opened, TestMessage::sample(None));
			Ok(())
		}

		/// Returns the `kekid.keyIdentifier` of the one `KEKRecipientInfo` of
		/// `frame`.
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
		#[test]
		fn a_provider_seal_names_the_providers_key() {
			let frame = provider_sealed("test-kekid");
			assert_eq!(key_identifier_of(&frame), KEY_IDENTIFIER);
		}

		/// A key holder whose wrap answers with the function it holds, and
		/// whose unwrap refuses every key.
		///
		/// The house holders wrap each content key they receive, and the cases
		/// need a wrap that refuses the key or one past a DER length.
		#[derive(Debug)]
		struct StubHolder(fn(&[u8]) -> core::result::Result<Vec<u8>, KeyError>);

		impl StubHolder {
			/// A holder that refuses every content key it receives.
			const REFUSING: Self = Self(|content_key| Err(KeyError::WrapLength((content_key.len(), 0).into())));

			/// A holder whose encrypted key fills a DER length, so the
			/// `KEKRecipientInfo` that carries the key runs past one. An
			/// outside holder returns a key of any length, and this one stands
			/// for it.
			const OVERSIZED: Self = Self(|_content_key| {
				let longest = usize::try_from(Length::MAX).expect("a DER length fits a usize");
				Ok(vec![0u8; longest])
			});
		}

		impl EncryptingKeyProvider for StubHolder {
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
				Box::pin(ready((self.0)(content_key)))
			}

			fn decrypt(
				&self,
				encrypted_key: &[u8],
			) -> Pin<Box<dyn Future<Output = core::result::Result<SecretSlice<u8>, KeyError>> + Send + '_>> {
				Box::pin(ready(Err(KeyError::WrapLength((encrypted_key.len(), 0).into()))))
			}
		}

		// The holder wraps the content key before the body encrypts, so a seal
		// that the wrap refuses leaves the frame its body. A refused key fails
		// the seal at the holder, and a key past a DER length fails it at the
		// encoding of its envelope.
		crate::tb_cases! {
			fn a_refused_seal_leaves_the_frame((holder, refused): (StubHolder, fn(&Result<()>) -> bool)) {
				let arrived = TestFrame::v1(None, Some("test-refused-seal"));
				let mut frame = arrived.clone();

				let sealed = rt::block_on(frame.encrypt_with_provider::<DefaultCryptoProvider>(&holder));
				assert!(refused(&sealed));
				assert_eq!(frame, arrived);
			}
			cases {
				when_its_holder_refuses_the_key => (
					StubHolder::REFUSING,
					|sealed| {
						matches!(
							sealed,
							Err(TightBeamError::EnvelopeError(EnvelopeError::Key(KeyError::WrapLength(_))))
						)
					},
				),
				when_its_envelope_is_past_a_der_length => (
					StubHolder::OVERSIZED,
					|sealed| matches!(sealed, Err(TightBeamError::EnvelopeError(EnvelopeError::Encoding(_)))),
				),
			}
		}

		/// The provider's open refuses a body that fails its tag, and the open
		/// runs in the body's own buffer, so it leaves the frame as it arrived.
		#[tokio::test]
		async fn a_provider_open_of_a_body_that_fails_its_tag_leaves_the_frame() {
			let mut frame = tampered(provider_sealed("test-refused-open"));
			let original = frame.clone();

			let result = frame.decrypt_with_provider::<DefaultCryptoProvider>(&provider()).await;
			assert!(matches!(
				result,
				Err(TightBeamError::EnvelopeError(EnvelopeError::Authentication))
			));
			assert_eq!(frame, original);
		}

		/// A seal of a frame below V1 is refused.
		#[tokio::test]
		async fn encrypting_below_v1_is_refused() {
			let mut frame = TestFrame::v0(None, Some("test-encrypt-v0"));
			let original = frame.clone();

			let result = frame.encrypt_with_provider::<DefaultCryptoProvider>(&provider()).await;
			assert!(matches!(
				result,
				Err(TightBeamError::UnsupportedField { field: GatedField::Confidentiality, version: Version::V0 })
			));
			assert_eq!(frame, original);
		}

		/// `decrypt_with_provider` refuses a frame that names another algorithm
		/// before the provider decrypts it.
		#[tokio::test]
		async fn a_provider_refuses_a_frame_that_names_another_algorithm() -> TestResult {
			let mut frame = provider_sealed("test-relabel");
			let metadata = frame.metadata();
			let envelope = metadata.confidentiality().ok_or(TightBeamError::MissingEncryptionInfo)?;
			let mut relabelled = envelope.clone();

			relabelled.auth_encrypted_content_info.content_enc_alg.oid = crate::oids::AES_128_GCM;
			frame.metadata.confidentiality = Some(WireDer::new(relabelled)?);

			let original = frame.clone();
			let result = frame.decrypt_with_provider::<DefaultCryptoProvider>(&provider()).await;
			assert!(matches!(
				result,
				Err(TightBeamError::EnvelopeError(EnvelopeError::ContentEncryptionAlgorithm))
			));
			assert_eq!(frame, original);
			Ok(())
		}
	}

	#[cfg(all(
		feature = "aes-gcm",
		feature = "secp256k1",
		feature = "signature",
		feature = "tokio"
	))]
	mod opened {
		use super::*;
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::crypto::sign::ecdsa::Secp256k1Signature;
		use crate::runtime::rt;
		use crate::testing::TestIdentity;
		use crate::Version;

		/// Returns a sealed frame that carries an FI digest and a signature,
		/// both over the frame as it was sealed. The frame of
		/// [`TestFrame::sealed_signed`] carries no digest.
		fn sealed_signed_digested() -> Frame {
			let message = TestMessage::sample(None);
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let signer = TestIdentity::certified(TestKey::insecure_fixed_signing());
			let built = compose! {
				V1: id: "opened-001",
					order: TestFrame::ORDER,
					message: message,
					confidentiality: cipher,
					nonrepudiation<Secp256k1Signature, _>: signer,
					frame_integrity: type Sha3_256
			};
			built.expect("a V1 frame carries a seal, a signature, and a digest")
		}

		/// The digest and the signature cover the frame as it arrived, so the
		/// open takes both out of the frame.
		#[tokio::test]
		async fn an_opened_frame_carries_no_integrity_or_signature() -> TestResult {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = sealed_signed_digested();

			let _opened = frame.decrypt_in_place(&cipher, None).await?;
			assert_eq!((frame.integrity(), frame.nonrepudiation()), (None, None));
			Ok(())
		}

		/// The open returns the signature it took out, for a caller that names
		/// the signer after the open.
		#[tokio::test]
		async fn decrypt_in_place_returns_the_signature_it_took_out() -> TestResult {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = TestFrame::sealed_signed(Version::V1, "opened-001");
			let signature = frame.nonrepudiation().cloned().ok_or(TightBeamError::MissingSignatureInfo)?;

			let opened = frame.decrypt_in_place(&cipher, None).await?;
			assert_eq!(opened.nonrepudiation(), Some(&signature));
			Ok(())
		}

		// A signature covers the frame, and an FI digest its metadata, as each
		// is before the seal, so the seal refuses a frame that carries either
		// and leaves it unchanged.
		crate::tb_cases! {
			fn the_seal_refuses_a_frame_that_carries(arrived: Frame) {
				let (_, cipher) = TestKey::insecure_fixed_cipher();
				let mut frame = arrived.clone();

				let sealed = rt::block_on(frame.encrypt_with_provider::<DefaultCryptoProvider>(&cipher));
				assert!(matches!(sealed, Err(TightBeamError::CoveredBeforeSeal)));
				assert_eq!(frame, arrived);
			}
			cases {
				a_signature => {
					TestFrame::signed_by(TestFrame::v1(None, Some("seal-signed")), &TestIdentity::insecure_fixed())
				},
				a_digest => TestFrame::with_integrity(),
			}
		}

		/// The open returns the FI digest it took out.
		#[tokio::test]
		async fn decrypt_in_place_returns_the_digest_it_took_out() -> TestResult {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = sealed_signed_digested();
			let digest = frame.integrity().cloned().ok_or(TightBeamError::MissingDigestInfo)?;

			let opened = frame.decrypt_in_place(&cipher, None).await?;
			assert_eq!(opened.integrity(), Some(&digest));
			Ok(())
		}

		/// The open through a key provider moves the signature out of the
		/// frame and into the product it returns.
		#[tokio::test]
		async fn a_provider_open_moves_the_signature_out_of_the_frame() -> TestResult {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let mut frame = TestFrame::sealed_signed(Version::V1, "opened-001");
			let signature = frame.nonrepudiation().cloned().ok_or(TightBeamError::MissingSignatureInfo)?;

			let opened = frame.decrypt_with_provider::<DefaultCryptoProvider>(&cipher).await?;
			assert_eq!((frame.nonrepudiation(), opened.nonrepudiation()), (None, Some(&signature)));
			Ok(())
		}
	}
}
