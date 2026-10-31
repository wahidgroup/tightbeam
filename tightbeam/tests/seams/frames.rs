//! The frame and record seals under the outside provider, each built as an
//! outside crate must build it:
//!
//! - a frame sealed to the bare recipient of the outside KEM, which an outside
//!   backend opens through a [`BareKemKey`],
//! - a frame and a record under the outside AEAD and key wrap, and a refused frame that keeps its ciphertext,
//! - a key-encryption key an outside crate holds, as an
//!   [`EncryptingKeyProvider`] that keeps the provided `decrypt_into`,
//! - a frame cipher an outside crate writes, as an [`Encryptor`] and a [`Decryptor`],
//! - a frame decryptor an outside crate writes, which opens the parts of a
//!   [`CheckedContent`] itself and refuses a frame whose envelope carries
//!   `unauthAttrs`,
//! - a codec an outside crate writes, as a [`Compressor`] and an [`Inflator`]
//!   that names its own algorithm and refuses a body under another, and
//! - the single-shot HPKE API under a suite whose KDF the outside crate defines.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tightbeam::asn1::GcmParameters;
use tightbeam::cms::compressed_data::CompressedData;
use tightbeam::cms::content_info::CmsVersion;
use tightbeam::cms::enveloped_data::{KekRecipientInfo, RecipientInfo};
use tightbeam::cms::signed_data::EncapsulatedContentInfo;
use tightbeam::compress::{Compressor, Inflator};
use tightbeam::crypto::aead::aes_kw::{KekAes128, KekAes256};
use tightbeam::crypto::aead::{
	AeadInPlace, Aes128Gcm, Aes128GcmOid, CheckedContent, Decryptor, Encryptor, Key, KeyInit, Nonce, RecordDirection,
	RecvCipher, RuntimeAead, SendCipher, Tag,
};
use tightbeam::crypto::cms::{
	AuthEnvelopedData, BareKemKey, EnvelopeError, KemRecipient, KemRecipientInfo, Opener, Recipient,
};
use tightbeam::crypto::common::generic_array::GenericArray;
use tightbeam::crypto::common::typenum::U16;
use tightbeam::crypto::hkdf::InvalidLength;
use tightbeam::crypto::hpke::{
	HkdfSha256, HpkeDecryptor, HpkeEncryptor, HpkeKdf, HpkeMessage, HpkePublicKeyOps, HpkeSecretKeyOps, HpkeSuite,
	KEM_DHKEM_SECP256K1_HKDF_SHA256,
};
use tightbeam::crypto::k256::sha2::Sha512;
use tightbeam::crypto::k256::SecretKey;
use tightbeam::crypto::kdf::{Hkdf, KdfError};
use tightbeam::crypto::key::{EncryptingKeyProvider, InMemoryEncryptingKeyProvider, KeyError};
use tightbeam::crypto::profiles::Kek;
use tightbeam::crypto::secret::{SecretSlice, ToInsecure};
use tightbeam::der::asn1::{Null, ObjectIdentifier, SetOfVec};
use tightbeam::der::{Any, Decode, Encode, ErrorKind, Tag as DerTag, TagNumber};
use tightbeam::error::{CompressionResult, ReceivedExpectedError};
use tightbeam::marker::MaybeSendFuture;
use tightbeam::oids::{AES_128_GCM, AES_128_WRAP, AES_256_WRAP, DATA, ORI_KEM};
use tightbeam::random::CryptoRngCore;
use tightbeam::testing::{unhex, SeededStream, TestMessage};
use tightbeam::x509::attr::Attribute;
use tightbeam::zeroize::Zeroizing;
use tightbeam::{compose, Frame, TightBeamError, ZeroizingBytes};

#[cfg(feature = "zstd")]
use tightbeam::compress::ZstdCompression;
#[cfg(feature = "zstd")]
use tightbeam::oids::COMPRESSION_ZSTD;

use super::{
	AlgorithmIdentifierOwned, DiffieHellman, KeyBackend, OutsideAgreementBackend, OutsideKem, OutsideProvider,
	PublicKey, Secp256k1, CLIENT_SEED, KNOWN_RECIPIENT_KEY, OUTSIDE_KDF, OUTSIDE_KEM, SERVER_SEED,
};
use crate::common::result::TestResult;
use crate::common::security::fixed_signing_key;

/// The key identifier of the outside key-encryption keys.
const OUTSIDE_KEY_IDENTIFIER: &[u8] = b"tb/test/outside/kek/v1";

/// The content of the sample message that each sealed frame carries.
const FRAME_CONTENT: &str = "outside frame";

/// The outside key-agreement backend of the key whose scalar is thirty-two
/// `seed` octets, beside its public key.
fn outside_backend(seed: u8) -> (PublicKey, Arc<dyn DiffieHellman<Secp256k1>>) {
	let backend = OutsideAgreementBackend::of(&fixed_signing_key(seed));
	(backend.public_key(), Arc::new(backend))
}

/// The bare recipient under the outside KEM of the key `backend` holds, from
/// the SubjectPublicKeyInfo it publishes.
fn bare_outside_recipient(backend: &Arc<dyn DiffieHellman<Secp256k1>>) -> KemRecipient<OutsideKem> {
	let spki = backend.to_public_key_bytes().expect("the outside backend encodes its key");
	KemRecipient::bare(spki).expect("the key is a secp256k1 key")
}

/// The sample message that each sealed frame carries.
fn outside_message() -> TestMessage {
	TestMessage::sample(Some(FRAME_CONTENT))
}

/// A V1 frame of [`outside_message`], sealed by `encryptor`.
fn sealed_frame(encryptor: impl Encryptor<Aes128GcmOid> + 'static) -> Frame {
	let message = outside_message();
	let frame = compose! { V1: id: "outside-frame", order: 1u64, message: message, confidentiality: encryptor };
	frame.expect("the frame seals under the outside encryptor")
}

/// The envelope that `frame` carries.
fn envelope_of(frame: &Frame) -> &AuthEnvelopedData {
	let envelope = frame.metadata().confidentiality();
	envelope.expect("the frame is encrypted")
}

/// The one `KEKRecipientInfo` of `envelope`.
pub(super) fn kek_recipient_of(envelope: &AuthEnvelopedData) -> KekRecipientInfo {
	let recipient = match envelope.recipient_infos.0.as_slice().first() {
		Some(RecipientInfo::Kekri(kek)) => Some(kek.to_owned()),
		_ => None,
	};
	recipient.expect("the envelope carries one KEKRecipientInfo")
}

/// The `KEMRecipientInfo` of the envelope `frame` carries.
fn kem_recipient_of(frame: &Frame) -> KemRecipientInfo {
	let recipient = match envelope_of(frame).recipient_infos.0.as_slice().first() {
		Some(RecipientInfo::Ori(other)) if other.ori_type == ORI_KEM => Some(other),
		_ => None,
	};

	let recipient = recipient.expect("the frame carries one id-ori-kem recipient");
	recipient.ori_value.decode_as().expect("the value is a KEMRecipientInfo")
}

/// A frame sealed to the bare recipient of the outside KEM opens through a
/// bare key over the outside backend, whose own scalar product decapsulates.
#[tokio::test]
async fn a_frame_sealed_to_a_bare_outside_recipient_opens_through_its_bare_kem_key() -> TestResult {
	let (public, backend) = outside_backend(SERVER_SEED);
	let frame = sealed_frame(HpkeEncryptor::<OutsideProvider>::new(bare_outside_recipient(&backend)));

	let decryptor = HpkeDecryptor::<OutsideProvider>::new(BareKemKey::new(public, backend)?);
	let opened: TestMessage = frame.decrypt(&decryptor, None).await?;
	assert_eq!(opened, outside_message());
	Ok(())
}

/// The frame seal runs every algorithm of the outside provider: its KEM, its
/// KDF, its key wrap, and its AEAD.
#[test]
fn a_frame_sealed_to_the_outside_kem_names_the_outside_algorithms() {
	let (_, backend) = outside_backend(SERVER_SEED);
	let frame = sealed_frame(HpkeEncryptor::<OutsideProvider>::new(bare_outside_recipient(&backend)));

	let kem = kem_recipient_of(&frame);
	let cipher = envelope_of(&frame).auth_encrypted_content_info.content_enc_alg.oid;
	let named = (kem.kem.oid, kem.kdf.oid, kem.wrap.oid, cipher);
	assert_eq!(named, (OUTSIDE_KEM, OUTSIDE_KDF, AES_128_WRAP, AES_128_GCM));
}

/// `BareKemKey::new` refuses an outside backend that holds another key.
#[test]
fn a_bare_kem_key_refuses_an_outside_backend_of_another_key() {
	let (public, _) = outside_backend(SERVER_SEED);
	let (_, other) = outside_backend(CLIENT_SEED);

	let refused = BareKemKey::<OutsideKem>::new(public, other);
	assert!(matches!(refused, Err(EnvelopeError::KeyMismatch)));
}

/// The in-memory key-encryption key of the outside provider, 16 octets for
/// AES-128 key wrap.
fn outside_kek() -> InMemoryEncryptingKeyProvider<OutsideProvider> {
	let kek = InMemoryEncryptingKeyProvider::new(vec![0x37; 16], OUTSIDE_KEY_IDENTIFIER.to_vec());
	kek.expect("16 octets is the key of AES-128 key wrap")
}

/// `frame` with the last octet of its encrypted body flipped, read back from
/// its DER as a receiver reads it.
fn with_body_tampered(frame: &Frame) -> Frame {
	let body = frame.message();
	let mut der = frame.to_der().expect("the frame encodes");
	let at = der.windows(body.len()).position(|window| window == body);
	let last = at.expect("the frame carries its body") + body.len() - 1;
	let octet = der.get_mut(last).expect("the body lies inside the frame");
	*octet ^= 0x01;

	Frame::from_der(&der).expect("the tampered frame decodes")
}

/// `Frame::decrypt_in_place` refuses a frame under the outside cipher whose
/// body fails its tag, and the outside cipher, which opened the body in its own
/// buffer, leaves it as it arrived.
#[tokio::test]
async fn a_refused_frame_under_the_outside_cipher_keeps_its_ciphertext() {
	let mut frame = with_body_tampered(&sealed_frame(outside_kek()));
	let arrived = frame.message().to_vec();

	let refused = frame.decrypt_in_place(&outside_kek(), None).await;
	assert!(matches!(
		refused,
		Err(TightBeamError::EnvelopeError(EnvelopeError::Authentication))
	));
	assert_eq!(frame.message(), arrived.as_slice());
}

/// The outside record key of 16 `fill` octets, under the outside AEAD and
/// key wrap.
fn outside_record_key(fill: u8) -> RuntimeAead {
	RuntimeAead::new::<OutsideProvider>(vec![fill; 16]).expect("16 octets is the key of AES-128 key wrap")
}

/// A record sealed under the outside provider opens on the outside receive
/// cipher of the same key, in the buffer it arrived in.
#[test]
fn a_record_under_the_outside_provider_opens() -> TestResult {
	let sender = SendCipher::new(outside_record_key(0x21), 0, RecordDirection::ClientToServer);
	let mut record = sender.encrypt_next(b"outside record".to_vec())?.to_der()?;

	let mut receiver = RecvCipher::new(outside_record_key(0x21), 0, RecordDirection::ClientToServer);
	let opened = receiver.open(&mut record)?;
	assert_eq!(opened, b"outside record");
	Ok(())
}

/// A record under the outside provider names the outside AEAD and wraps its
/// content key under the outside key wrap.
#[test]
fn a_record_under_the_outside_provider_names_its_algorithms() -> TestResult {
	let sender = SendCipher::new(outside_record_key(0x21), 0, RecordDirection::ClientToServer);
	let record = sender.encrypt_next(b"outside record".to_vec())?;

	let wrap = kek_recipient_of(&record).key_enc_alg.oid;
	let cipher = record.auth_encrypted_content_info.content_enc_alg.oid;
	assert_eq!((cipher, wrap), (AES_128_GCM, AES_128_WRAP));
	Ok(())
}

/// A key-encryption key an outside crate holds behind an async boundary, as
/// an HSM holds it: AES-256 key wrap under its own key, through the `aes-kw`
/// crate.
#[derive(Debug)]
struct OutsideKekHolder {
	kek: [u8; 32],
}

impl OutsideKekHolder {
	/// The holder of the key of thirty-two `0x48` octets.
	fn fixed() -> Self {
		Self { kek: [0x48; 32] }
	}
}

impl EncryptingKeyProvider for OutsideKekHolder {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: AES_256_WRAP, parameters: None }
	}

	fn key_identifier(&self) -> &[u8] {
		OUTSIDE_KEY_IDENTIFIER
	}

	fn encrypt(&self, content_key: &[u8]) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		let wrapped = KekAes256::from(self.kek).wrap_vec(content_key).map_err(KeyError::WrapFailed);
		Box::pin(async move { wrapped })
	}

	fn decrypt(
		&self,
		encrypted_key: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<SecretSlice<u8>, KeyError>> + Send + '_>> {
		let unwrapped = KekAes256::from(self.kek).unwrap_vec(encrypted_key);
		let unwrapped = unwrapped.map_err(KeyError::WrapFailed);
		let content_key = unwrapped.map(SecretSlice::from);
		Box::pin(async move { content_key })
	}
}

/// A frame sealed through the outside key holder opens through it, under the
/// AEAD of the outside provider.
#[tokio::test]
async fn a_frame_sealed_through_an_outside_kek_holder_opens_through_it() -> TestResult {
	let holder = OutsideKekHolder::fixed();
	let message = TestMessage::sample(Some("outside holder"));
	let mut frame = compose! { V1: id: "outside-holder", order: 1u64, message: message.clone() }?;

	frame.encrypt_with_provider::<OutsideProvider>(&holder).await?;
	// The open leaves the message in the frame, which the test reads, so its
	// record drops here.
	let _opened = frame.decrypt_with_provider::<OutsideProvider>(&holder).await?;
	let opened: TestMessage = tightbeam::decode(frame.message())?;
	assert_eq!(opened, message);
	Ok(())
}

/// The content key the outside holder wraps in the tests of its open.
const OUTSIDE_CONTENT_KEY: [u8; 32] = [0x6Bu8; 32];

/// The outside holder keeps the provided `decrypt_into`, which decrypts
/// through its `decrypt` and copies the content key into the caller's buffer.
#[tokio::test]
async fn an_outside_kek_holder_decrypts_into_the_callers_buffer() -> TestResult {
	let holder = OutsideKekHolder::fixed();
	let wrapped = holder.encrypt(&OUTSIDE_CONTENT_KEY).await?;
	let mut content_key = [0u8; 32];

	holder.decrypt_into(&wrapped, &mut content_key).await?;
	assert_eq!(content_key, OUTSIDE_CONTENT_KEY);
	Ok(())
}

/// The provided `decrypt_into` refuses a buffer of another size than the key
/// the holder decrypts, and names both sizes.
#[tokio::test]
async fn the_provided_decrypt_into_refuses_a_buffer_of_another_size() -> TestResult {
	let holder = OutsideKekHolder::fixed();
	let wrapped = holder.encrypt(&OUTSIDE_CONTENT_KEY).await?;
	let mut short = [0u8; 16];

	let refused = holder.decrypt_into(&wrapped, &mut short).await;
	assert!(matches!(refused, Err(KeyError::WrapLength(sizes)) if (sizes.received, sizes.expected) == (16, 32)));
	Ok(())
}

/// The frame names the outside holder's key and key-encryption algorithm in
/// its one `KEKRecipientInfo`.
#[tokio::test]
async fn an_outside_kek_holder_names_its_key_and_algorithm() -> TestResult {
	let holder = OutsideKekHolder::fixed();
	let message = TestMessage::sample(Some("outside holder"));
	let mut frame = compose! { V1: id: "outside-holder", order: 1u64, message: message }?;
	frame.encrypt_with_provider::<OutsideProvider>(&holder).await?;

	let recipient = kek_recipient_of(envelope_of(&frame));
	let named = (recipient.kek_id.kek_identifier.as_bytes(), recipient.key_enc_alg.oid);
	assert_eq!(named, (OUTSIDE_KEY_IDENTIFIER, AES_256_WRAP));
	Ok(())
}

/// The key-encryption key of the outside frame ciphers, 16 octets for
/// AES-128 key wrap.
const FRAME_KEK: [u8; 16] = [0x52; 16];

/// A frame cipher an outside crate writes against the public envelope API:
/// it seals a frame to its own key-encryption key under the outside
/// provider, and opens it under the same key. The array type of the key holds
/// the key size of the wrap, so the cipher lends a [`Kek`] with no length
/// check.
struct OutsideFrameCipher {
	kek: GenericArray<u8, U16>,
}

impl OutsideFrameCipher {
	/// The cipher of [`FRAME_KEK`].
	fn fixed() -> Self {
		Self { kek: FRAME_KEK.into() }
	}
}

impl Encryptor<Aes128GcmOid> for OutsideFrameCipher {
	fn encrypt_content(
		&self,
		content: impl Into<Vec<u8>>,
		content_type: Option<ObjectIdentifier>,
		rng: Option<&mut dyn CryptoRngCore>,
	) -> Result<AuthEnvelopedData, TightBeamError> {
		let kek = Kek::from(&self.kek);
		let recipient = Recipient::Kek { kek, key_identifier: OUTSIDE_KEY_IDENTIFIER };
		let content_type = content_type.unwrap_or(DATA);

		let sealed = AuthEnvelopedData::seal::<OutsideProvider>(recipient, content_type, content, [], rng);
		Ok(sealed?)
	}
}

impl Decryptor for OutsideFrameCipher {
	fn algorithm_oid(&self) -> ObjectIdentifier {
		AES_128_GCM
	}

	fn open<'a>(&'a self, content: CheckedContent<'a>) -> MaybeSendFuture<'a, Result<(), TightBeamError>> {
		Box::pin(async move {
			let kek = Kek::from(&self.kek);
			let opener = Opener::Kek { kek, key_identifier: OUTSIDE_KEY_IDENTIFIER };
			content.open::<OutsideProvider>(&opener).await
		})
	}
}

/// A frame decryptor an outside crate writes with an open of its own: it
/// takes the envelope and the content through `into_parts`, unwraps the
/// content key onto its stack under its own key, and decrypts in place under
/// AES-128-GCM, which checks the tag before it decrypts.
struct OutsidePartsDecryptor {
	kek: [u8; 16],
}

impl OutsidePartsDecryptor {
	/// Decrypt `content`, the encrypted content of `envelope`, in place.
	fn opened(&self, envelope: &AuthEnvelopedData, content: &mut [u8]) -> Result<(), TightBeamError> {
		let wrapped = kek_recipient_of(envelope).encrypted_key;
		let mut content_key = Zeroizing::new(Key::<Aes128Gcm>::default());
		let unwrapped = KekAes128::from(self.kek).unwrap(wrapped.as_bytes(), &mut content_key);
		unwrapped.map_err(KeyError::WrapFailed)?;
		let algorithm = &envelope.auth_encrypted_content_info.content_enc_alg;
		let parameters = algorithm.parameters.as_ref().ok_or(EnvelopeError::ContentEncryptionAlgorithm)?;
		let parameters: GcmParameters = parameters.decode_as()?;
		let nonce = Nonce::<Aes128Gcm>::from_exact_iter(parameters.aes_nonce.as_bytes().iter().copied());
		let nonce = nonce.ok_or(EnvelopeError::ContentEncryptionAlgorithm)?;
		let mac = envelope.mac.as_bytes();
		let tag = Tag::<Aes128Gcm>::from_exact_iter(mac.iter().copied());
		let tag = tag.ok_or(EnvelopeError::TagLength((mac.len(), 16).into()))?;
		let attributes = envelope.auth_attrs.as_ref().ok_or(EnvelopeError::ContentTypeAttribute)?;

		let cipher = Aes128Gcm::new(&content_key);
		let opened = cipher.decrypt_in_place_detached(&nonce, &attributes.to_der()?, content, &tag);
		Ok(opened.map_err(|_| EnvelopeError::Authentication)?)
	}
}

impl Decryptor for OutsidePartsDecryptor {
	fn algorithm_oid(&self) -> ObjectIdentifier {
		AES_128_GCM
	}

	fn open<'a>(&'a self, content: CheckedContent<'a>) -> MaybeSendFuture<'a, Result<(), TightBeamError>> {
		let (envelope, _arrived, encrypted) = content.into_parts();
		Box::pin(std::future::ready(self.opened(envelope, encrypted)))
	}
}

/// A function that builds the decryptor of an outside part, which holds the
/// key of a sealed frame.
type OutsideDecryptor = fn() -> Box<dyn Decryptor>;

// A frame that an outside part seals opens through the outside part that
// holds its key.
tightbeam::tb_cases! {
	async fn a_frame_sealed_under_an_outside_part_opens(
		(sealed, decryptor): (fn() -> Frame, OutsideDecryptor)
	) -> TestResult {
		let frame = sealed();
		let decryptor = decryptor();

		let opened: TestMessage = frame.decrypt(&*decryptor, None).await?;
		assert_eq!(opened, outside_message());
		Ok(())
	}
	cases {
		/// A frame sealed to an in-memory key under the outside AEAD and key
		/// wrap opens under the same key.
		under_the_outside_aead_and_key_wrap => (|| sealed_frame(outside_kek()), || Box::new(outside_kek())),
		/// A frame the outside cipher seals opens through the outside cipher.
		through_an_outside_frame_cipher => (
			|| sealed_frame(OutsideFrameCipher::fixed()),
			|| Box::new(OutsideFrameCipher::fixed())
		),
		/// A frame the outside cipher seals opens through an outside
		/// decryptor that reads its parts and runs its own open.
		through_an_outside_parts_decryptor => (
			|| sealed_frame(OutsideFrameCipher::fixed()),
			|| Box::new(OutsidePartsDecryptor { kek: FRAME_KEK })
		),
	}
}

/// The attribute that [`UnauthenticatedAttributeCipher`] attaches, under an
/// arc of the outside crate.
const OUTSIDE_UNAUTHENTICATED_ATTRIBUTE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.14");

/// A frame cipher an outside crate writes that seals as
/// [`OutsideFrameCipher`] seals, then attaches one `unauthAttrs` attribute,
/// which the tag does not cover, as a party outside the seal would.
struct UnauthenticatedAttributeCipher(OutsideFrameCipher);

impl Encryptor<Aes128GcmOid> for UnauthenticatedAttributeCipher {
	fn encrypt_content(
		&self,
		content: impl Into<Vec<u8>>,
		content_type: Option<ObjectIdentifier>,
		rng: Option<&mut dyn CryptoRngCore>,
	) -> Result<AuthEnvelopedData, TightBeamError> {
		let mut sealed = self.0.encrypt_content(content, content_type, rng)?;
		let values = SetOfVec::try_from(vec![Any::encode_from(&Null)?])?;
		let attribute = Attribute { oid: OUTSIDE_UNAUTHENTICATED_ATTRIBUTE, values };
		sealed.unauth_attrs = Some(SetOfVec::try_from(vec![attribute])?);
		Ok(sealed)
	}
}

/// The outside decryptor that opens from the parts of a [`CheckedContent`]
/// refuses a frame whose envelope carries `unauthAttrs`, because the check
/// reads the envelope as it arrived before any decryptor sees its parts
/// (RFC 5083 §2.1).
#[tokio::test]
async fn an_outside_parts_decryptor_refuses_an_envelope_that_carries_unauthenticated_attributes() {
	let mut frame = sealed_frame(UnauthenticatedAttributeCipher(OutsideFrameCipher::fixed()));

	let refused = frame.decrypt_in_place(&OutsidePartsDecryptor { kek: FRAME_KEK }, None).await;
	let unauthenticated = DerTag::ContextSpecific { constructed: true, number: TagNumber::N2 };
	assert!(matches!(
		refused,
		Err(TightBeamError::EnvelopeError(EnvelopeError::Encoding(error)))
			if error.kind() == ErrorKind::Value { tag: unauthenticated }
	));
}

/// The compression algorithm of the outside codec, under an arc of its own.
const OUTSIDE_CODEC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.9");

/// A codec an outside crate writes under its own algorithm identifier. It
/// reverses the body, a transform its inflator alone undoes, so a frame
/// decodes only after the outside inflator ran.
struct OutsideCodec;

impl Compressor for OutsideCodec {
	fn compress(
		&self,
		data: &[u8],
		content_info: Option<EncapsulatedContentInfo>,
	) -> CompressionResult<(Vec<u8>, CompressedData)> {
		let compression_alg = AlgorithmIdentifierOwned { oid: OUTSIDE_CODEC, parameters: None };
		let data_content = EncapsulatedContentInfo { econtent_type: DATA, econtent: None };
		let encap_content_info = content_info.unwrap_or(data_content);
		let compressed = CompressedData { version: CmsVersion::V0, compression_alg, encap_content_info };
		Ok((data.iter().rev().copied().collect(), compressed))
	}
}

impl Inflator for OutsideCodec {
	fn algorithm_oid(&self) -> ObjectIdentifier {
		OUTSIDE_CODEC
	}

	fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, TightBeamError> {
		Ok(data.iter().rev().copied().collect())
	}
}

/// The outside codec under parameters of the test's choice, which the frame
/// names in its `CompressedData`.
struct OutsideCodecUnder(Option<Any>);

impl Compressor for OutsideCodecUnder {
	fn compress(
		&self,
		data: &[u8],
		content_info: Option<EncapsulatedContentInfo>,
	) -> CompressionResult<(Vec<u8>, CompressedData)> {
		let (reversed, mut compressed) = OutsideCodec.compress(data, content_info)?;
		compressed.compression_alg.parameters = self.0.clone();
		Ok((reversed, compressed))
	}
}

/// A cleartext frame under the outside codec, whose `CompressedData` names
/// `parameters`.
fn outside_codec_frame(parameters: Option<Any>) -> Frame {
	let message = TestMessage::sample(Some("outside codec"));
	let compressor = OutsideCodecUnder(parameters);
	let frame = compose! { V0: id: "outside-codec", order: 1u64, message: message, compactness: compressor };
	frame.expect("the frame compresses under the outside codec")
}

/// The provided parameter rule of an outside inflator admits the `NULL` of
/// an algorithm that defines no parameters (RFC 3274 §2).
#[test]
fn an_outside_inflator_admits_the_null_parameters_of_its_algorithm() -> TestResult {
	let mut frame = outside_codec_frame(Some(Any::encode_from(&Null)?));
	// The inflate leaves the message in the frame, which the test reads, so
	// its record drops here.
	let _opened = frame.inflate_in_place(&OutsideCodec)?;

	let inflated: TestMessage = tightbeam::decode(frame.message())?;
	assert_eq!(inflated, TestMessage::sample(Some("outside codec")));
	Ok(())
}

/// The provided parameter rule refuses a level, which an algorithm with no
/// parameters does not define.
#[test]
fn an_outside_inflator_refuses_parameters_its_algorithm_lacks() -> TestResult {
	let mut frame = outside_codec_frame(Some(Any::encode_from(&3i32)?));
	let refused = frame.inflate_in_place(&OutsideCodec);
	assert!(matches!(refused, Err(TightBeamError::InvalidMetadata)));
	Ok(())
}

/// An outside inflator refuses a body that names the house zstd algorithm
/// at its OID, before its own transform runs.
#[cfg(feature = "zstd")]
#[test]
fn an_outside_inflator_refuses_a_body_under_another_algorithm() -> TestResult {
	let message = TestMessage::sample(None);
	let zstd = ZstdCompression::default();
	let mut frame = compose! { V0: id: "house-zstd", order: 1u64, message: message, compactness: zstd }?;

	let refused = frame.inflate_in_place(&OutsideCodec);
	let algorithms = ReceivedExpectedError::from((COMPRESSION_ZSTD, OUTSIDE_CODEC));
	assert!(matches!(refused, Err(TightBeamError::UnexpectedAlgorithm(found)) if found == algorithms));
	Ok(())
}

/// A frame compressed by the outside codec and sealed under the outside
/// provider opens through the outside inflator.
#[tokio::test]
async fn an_outside_inflator_opens_a_compressed_frame() -> TestResult {
	let message = TestMessage::sample(Some("outside codec"));
	let kek = outside_kek();
	let frame = compose! {
		V1: id: "outside-codec", order: 1u64, message: message.clone(), compactness: OutsideCodec, confidentiality: kek
	}?;

	let opened: TestMessage = frame.decrypt(&outside_kek(), Some(&OutsideCodec)).await?;
	assert_eq!(opened, message);
	Ok(())
}

/// HKDF over SHA-512, the KDF `0x0003` of RFC 9180 §7.2, as an outside crate
/// brings it to the single-shot API.
struct OutsideHkdfSha512;

impl HpkeKdf for OutsideHkdfSha512 {
	const KDF_ID: u16 = 0x0003;
	const EXTRACT_SIZE: usize = 64;

	fn extract(salt: &[u8], ikm: &[u8]) -> ZeroizingBytes {
		let (prk, _) = Hkdf::<Sha512>::extract(Some(salt), ikm);
		Zeroizing::new(prk.to_vec())
	}

	fn expand(prk: &[u8], info: &[u8], len: usize) -> Result<ZeroizingBytes, KdfError> {
		let keyed = Hkdf::<Sha512>::from_prk(prk).map_err(|_| KdfError::DerivationFailed(InvalidLength))?;
		let mut okm = Zeroizing::new(vec![0u8; len]);
		keyed.expand(info, &mut okm).map_err(KdfError::DerivationFailed)?;
		Ok(okm)
	}
}

/// A suite an outside crate defines: the registered DHKEM over secp256k1,
/// HKDF-SHA512 for its key schedule, and AES-128-GCM.
struct OutsideSuite;

impl HpkeSuite for OutsideSuite {
	type Curve = Secp256k1;
	type KemKdf = HkdfSha256;
	type Kdf = OutsideHkdfSha512;
	type Aead = Aes128Gcm;

	const KEM_ID: u16 = KEM_DHKEM_SECP256K1_HKDF_SHA256;
}

/// The `info` of the single-shot seals under the outside suite.
const OUTSIDE_INFO: &[u8] = b"tb/test/outside/hpke";

/// The `enc` of the plaintext `outside suite`, sealed under the AAD `aad` and
/// [`OUTSIDE_INFO`] to [`KNOWN_RECIPIENT_KEY`], `0x2a` repeated 32 times, with
/// the ephemeral key `0x01` repeated 32 times that `SeededStream(0)` draws. An
/// independent RFC 9180 implementation in Python, which reproduces
/// draft-wahby B.2.1, computed it.
const OUTSIDE_ENC: &str = "041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1";

/// The ciphertext of the seal of [`OUTSIDE_ENC`], which the same
/// implementation computed under HKDF-SHA512.
const OUTSIDE_CIPHERTEXT: &str = "c877c909e89dcfa44855991934eaf36cf0056a14980eeee9a8041cc01e";

/// The message of the known answer of the outside suite: [`OUTSIDE_ENC`],
/// then [`OUTSIDE_CIPHERTEXT`].
fn outside_known_answer() -> Vec<u8> {
	[unhex(OUTSIDE_ENC), unhex(OUTSIDE_CIPHERTEXT)].concat()
}

/// The single-shot API seals under the outside suite's own KDF, so its seal
/// is the known answer of HKDF-SHA512.
#[test]
fn the_single_shot_api_seals_under_the_outside_kdf() -> TestResult {
	let secret = SecretKey::from_slice(&KNOWN_RECIPIENT_KEY)?;
	let public = secret.public_key();
	let mut stream = SeededStream(0);

	let sealed = public.seal::<OutsideSuite>(OUTSIDE_INFO, b"aad", b"outside suite", Some(&mut stream))?;
	assert_eq!(sealed.to_bytes(), outside_known_answer());
	Ok(())
}

/// The single-shot API opens the known answer of HKDF-SHA512 under the
/// outside suite's own KDF.
#[test]
fn the_single_shot_api_opens_under_the_outside_kdf() -> TestResult {
	let secret = SecretKey::from_slice(&KNOWN_RECIPIENT_KEY)?;
	let sealed = HpkeMessage::<OutsideSuite>::from_bytes(outside_known_answer())?;

	let opened = secret.open(&sealed, OUTSIDE_INFO, b"aad")?;
	assert_eq!(opened.to_insecure().as_slice(), b"outside suite");
	Ok(())
}
