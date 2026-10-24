//! The seal and the open of an [`AuthEnvelopedData`] under the AEAD of a
//! [`CryptoProvider`].

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use core::ops::Range;

use aead::{AeadCore, AeadInPlace, Key, KeyInit, Nonce, Tag};

use crate::asn1::admission::DerAdmission;
use crate::asn1::GcmParametersRef;
use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{EncryptedContentInfo, RecipientInfo, RecipientInfos};
use crate::crypto::aead::{AeadAlgorithm, Aes128Gcm, Aes256Gcm};
use crate::crypto::cms::kek::{self, ContentKey};
use crate::crypto::cms::{AttributesExt, AuthEnvelopedData, EnvelopeError};
use crate::crypto::common::generic_array::GenericArray;
use crate::crypto::common::typenum::Unsigned;
use crate::crypto::key::EncryptingKeyProvider;
use crate::crypto::profiles::CryptoProvider;
use crate::der::asn1::{ObjectIdentifier, OctetString, OctetStringRef, SetOfVec};
use crate::der::oid::AssociatedOid;
use crate::der::{
	Any, AnyRef, Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, SliceReader,
	Tag as DerTag, Tagged, Writer,
};
use crate::oids::ATTR_CONTENT_TYPE;
use crate::random::{CryptoRngCore, OsRng};
use crate::spki::AlgorithmIdentifierOwned;
use crate::x509::attr::{Attribute, Attributes};
use crate::zeroize::Zeroizing;
use crate::ZeroizingBytes;

#[cfg(all(feature = "hpke", feature = "signature"))]
use crate::crypto::cms::{Opener, Recipient};
#[cfg(all(feature = "hpke", feature = "signature"))]
use crate::crypto::secret::SecretSlice;

/// The content-encryption algorithm of an envelope: an AEAD cipher with its
/// identifier, from [`AeadAlgorithm`], and its parameters (RFC 5083 §2.1).
///
/// A provider names its cipher, so an implementor brings another one, such
/// as ChaCha20-Poly1305 (RFC 8103), with an implementation of this trait on
/// its cipher type. AES-GCM under `GCMParameters` (RFC 5084) is the house one.
///
/// # Buffers
///
/// A refused seal or open MUST leave its buffer as it was, so a frame that
/// lends its body to either keeps it on a refusal. The house AES-128-GCM and
/// AES-256-GCM keep this: `aes-gcm` 0.10.3 checks the lengths before it
/// applies the keystream (`lib.rs:273`, `lib.rs:294`), and the tag before it
/// decrypts (`lib.rs:305-306`).
pub trait ContentEncryption: AeadAlgorithm + AeadInPlace + KeyInit {
	/// The algorithm parameters of a seal under `nonce`.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Encoding`] -- the parameters fail to encode.
	fn parameters(nonce: &Nonce<Self>) -> Result<Any, EnvelopeError>;

	/// The nonce `parameters` carry, once they are this cipher's parameters.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::ContentEncryptionAlgorithm`] -- the parameters are not this cipher's.
	/// - [`EnvelopeError::TagLength`] -- the parameters name another tag length.
	fn nonce(parameters: Option<&Any>) -> Result<Nonce<Self>, EnvelopeError>;
}

/// AES-256-GCM under `GCMParameters`, the house cipher (RFC 5084 §3.2).
impl ContentEncryption for Aes256Gcm {
	fn parameters(nonce: &Nonce<Self>) -> Result<Any, EnvelopeError> {
		gcm_parameters::<Self>(nonce)
	}

	fn nonce(parameters: Option<&Any>) -> Result<Nonce<Self>, EnvelopeError> {
		gcm_nonce::<Self>(parameters)
	}
}

/// AES-128-GCM under `GCMParameters` (RFC 5084 §3.2).
impl ContentEncryption for Aes128Gcm {
	fn parameters(nonce: &Nonce<Self>) -> Result<Any, EnvelopeError> {
		gcm_parameters::<Self>(nonce)
	}

	fn nonce(parameters: Option<&Any>) -> Result<Nonce<Self>, EnvelopeError> {
		gcm_nonce::<Self>(parameters)
	}
}

/// The `GCMParameters` of a seal of `A` under `nonce`, which name the tag
/// length of `A` in `aes-ICVlen`.
///
/// # Errors
///
/// - [`EnvelopeError::Encoding`] -- the parameters fail to encode.
fn gcm_parameters<A: AeadCore>(nonce: &Nonce<A>) -> Result<Any, EnvelopeError> {
	let aes_icv_len =
		u8::try_from(A::TagSize::USIZE).map_err(|_| EnvelopeError::TagLength((A::TagSize::USIZE, 16).into()))?;
	let parameters = GcmParametersRef { aes_nonce: OctetStringRef::new(nonce.as_slice())?, aes_icv_len };
	Ok(Any::encode_from(&parameters)?)
}

/// The nonce of `GCMParameters` for `A`, once their tag length and their
/// nonce are the sizes of `A`.
///
/// # Errors
///
/// - [`EnvelopeError::ContentEncryptionAlgorithm`] -- no parameters, no
///   `GCMParameters`, or a nonce of another size.
/// - [`EnvelopeError::TagLength`] -- `aes-ICVlen` is another length.
fn gcm_nonce<A: AeadCore>(parameters: Option<&Any>) -> Result<Nonce<A>, EnvelopeError> {
	let parameters = parameters.ok_or(EnvelopeError::ContentEncryptionAlgorithm)?;
	let parameters = parameters.decode_as::<GcmParametersRef<'_>>();
	let parameters = parameters.map_err(|_| EnvelopeError::ContentEncryptionAlgorithm)?;
	let tag_length = usize::from(parameters.aes_icv_len);
	if tag_length != A::TagSize::USIZE {
		return Err(EnvelopeError::TagLength((tag_length, A::TagSize::USIZE).into()));
	}

	let nonce = parameters.aes_nonce.as_bytes().iter().copied();
	GenericArray::from_exact_iter(nonce).ok_or(EnvelopeError::ContentEncryptionAlgorithm)
}

impl AuthEnvelopedData {
	/// Seal `content`, of type `content_type`, to `recipient` under the
	/// algorithms of `P`: its AEAD, its KDF, its key wrap, and its KEM.
	///
	/// - Each seal draws a fresh content key and nonce from `rng`, or from the OS source without one.
	/// - The authenticated attributes, the content type and `auth_attrs`, are the associated data in DER.
	/// - The cipher encrypts `content` in place, so a `Vec` that moves in becomes the `encryptedContent`.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::ContentTypeAttribute`] -- `auth_attrs` carries a content-type attribute.
	/// - [`EnvelopeError::Random`] -- the random source failed.
	/// - The errors of `Recipient::wrap`: the recipient key, its name, the wrap, or a derivation failed.
	/// - [`EnvelopeError::Encryption`] -- the cipher refused the content.
	/// - [`EnvelopeError::Encoding`] -- an attribute or a parameter fails to encode.
	#[cfg(all(feature = "hpke", feature = "signature"))]
	pub fn seal<P>(
		recipient: Recipient<'_, P::Kem>,
		content_type: ObjectIdentifier,
		content: impl Into<Vec<u8>>,
		auth_attrs: impl IntoIterator<Item = Attribute>,
		rng: Option<&mut dyn CryptoRngCore>,
	) -> Result<Self, EnvelopeError>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption>,
	{
		let wrap = |content_key: &[u8], rng: &mut dyn CryptoRngCore| recipient.wrap::<P>(content_key, rng);
		Self::sealed::<P::AeadCipher>(content_type, content, auth_attrs, rng, wrap)
	}

	/// Seal `content`, of type `content_type`, under the AEAD of `P` to `kek`,
	/// through a `KEKRecipientInfo` that `key_identifier` names, under the
	/// key wrap of `P`.
	///
	/// # Errors
	///
	/// - The errors of [`Self::seal`], with the wrap of `P` as the recipient.
	pub(crate) fn seal_kek<P>(
		kek: &[u8],
		key_identifier: &[u8],
		content_type: ObjectIdentifier,
		content: impl Into<Vec<u8>>,
		auth_attrs: impl IntoIterator<Item = Attribute>,
		rng: Option<&mut dyn CryptoRngCore>,
	) -> Result<Self, EnvelopeError>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption>,
	{
		let wrap = |content_key: &[u8], _: &mut dyn CryptoRngCore| {
			kek::wrap_kek::<P::KeyWrap>(kek, key_identifier, content_key)
		};
		Self::sealed::<P::AeadCipher>(content_type, content, auth_attrs, rng, wrap)
	}

	/// Seal `content` under the cipher `A`, with the content key that `wrap`
	/// wraps for the one recipient.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Random`] -- the random source failed.
	/// - The errors of `wrap`.
	/// - The errors of [`Draw::seal`].
	fn sealed<A: ContentEncryption>(
		content_type: ObjectIdentifier,
		content: impl Into<Vec<u8>>,
		auth_attrs: impl IntoIterator<Item = Attribute>,
		rng: Option<&mut dyn CryptoRngCore>,
		wrap: impl FnOnce(&[u8], &mut dyn CryptoRngCore) -> Result<RecipientInfo, EnvelopeError>,
	) -> Result<Self, EnvelopeError> {
		let mut os_rng = OsRng;
		let rng = rng.unwrap_or(&mut os_rng);

		// 1. Draw the content key and the nonce of this one seal.
		let draw = Draw::<A>::new(rng)?;

		// 2. Wrap the content key for the recipient.
		let recipient_info = wrap(draw.content_key.as_slice(), rng)?;

		// 3. Encrypt in place under the authenticated attributes.
		draw.seal(recipient_info, content_type, content, auth_attrs)
	}

	/// Seal `content` in place, of type `content_type`, under the AEAD of `P`
	/// to the KEK `holder` holds, through a `KEKRecipientInfo` that names the
	/// holder's `kekid` and algorithm (RFC 5652 §6.2.3). The envelope carries
	/// the content detached, and the content key and nonce come from `OsRng`.
	///
	/// Every step that can fail runs before the content encrypts, so a refused
	/// seal leaves `content` as it was.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Random`] -- the random source failed.
	/// - [`EnvelopeError::Key`] -- the holder refused to encrypt the content key.
	/// - The errors of [`Draw::seal_in_place`].
	pub(crate) async fn seal_to_holder<P>(
		holder: &(impl EncryptingKeyProvider + ?Sized),
		content_type: ObjectIdentifier,
		content: &mut [u8],
	) -> Result<Self, EnvelopeError>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption>,
	{
		// 1. Draw the content key and the nonce of this one seal.
		let draw = Draw::<P::AeadCipher>::new(&mut OsRng)?;

		// 2. The holder encrypts the content key under its key.
		let encrypted_key = holder.encrypt(draw.content_key.as_slice()).await?;
		let recipient_info = kek::kek_info(holder.key_identifier(), holder.algorithm(), encrypted_key)?;

		// 3. Encrypt in place under the authenticated attributes.
		draw.seal_in_place(recipient_info, content_type, content, [])
	}

	/// Open the content, which must be of type `content_type`, with `opener`
	/// under the algorithms of `P`, in the buffer the ciphertext arrived in.
	///
	/// `arrived` is the encoding `self` decoded from. This checks every field
	/// before the content key unwraps, so a refused envelope costs the
	/// opener's key no operation. A content that returns has passed its tag,
	/// so the authenticated attributes it arrived with passed it too.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::MissingContent`] -- the envelope carries no encrypted content.
	/// - [`EnvelopeError::Encoding`] -- `arrived` is no DER `AuthEnvelopedData`.
	/// - [`EnvelopeError::ContentTypeAttribute`] -- the authenticated
	///   attributes carry no single content type.
	/// - [`EnvelopeError::ContentType`] -- a content type other than `content_type`.
	/// - [`EnvelopeError::AuthAttributesNotDer`] -- the attributes in `arrived` are not their DER.
	/// - [`EnvelopeError::Version`] -- the version is not 0.
	/// - [`EnvelopeError::ContentEncryptionAlgorithm`] -- the algorithm or its
	///   parameters are not the provider's cipher's.
	/// - [`EnvelopeError::TagLength`] -- the parameters or `mac` name another tag length than the cipher's.
	/// - The errors of [`Opener`]: the recipient differs from the opener, or its key fails to unwrap.
	/// - [`EnvelopeError::KeyUnwrap`] -- the content key is no key of the cipher.
	/// - [`EnvelopeError::Authentication`] -- the tag fails.
	#[cfg(all(feature = "hpke", feature = "signature"))]
	pub async fn open<P>(
		mut self,
		arrived: impl AsRef<[u8]>,
		opener: &Opener<'_, P::Kem>,
		content_type: ObjectIdentifier,
	) -> Result<SecretSlice<u8>, EnvelopeError>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption>,
	{
		let mut content = self.take_content()?;
		let opened = self.open_detached::<P>(arrived.as_ref(), &mut content, opener, content_type);
		opened.await?;
		Ok(SecretSlice::from(core::mem::take(&mut *content)))
	}

	/// Open `content` in place, the encrypted content of this envelope, which
	/// carries it detached, with `opener` under the algorithms of `P`.
	/// `arrived` is the encoding `self` decoded from. A refused open leaves
	/// `content` as it was.
	///
	/// # Errors
	///
	/// - The errors of [`Self::open`], for the content outside the envelope.
	#[cfg(all(feature = "hpke", feature = "signature"))]
	pub(crate) async fn open_detached<P>(
		&self,
		arrived: &[u8],
		content: &mut [u8],
		opener: &Opener<'_, P::Kem>,
		content_type: ObjectIdentifier,
	) -> Result<(), EnvelopeError>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption>,
	{
		// 1. Hold the envelope to the provider's cipher before any key runs,
		//    and its authenticated attributes to DER.
		let opening = self.check::<P::AeadCipher>(arrived, content_type)?;

		// 2. Unwrap the content key onto the stack, then decrypt the content in place under it.
		let mut content_key = ContentKey::<P::AeadCipher>::default();
		opener.unwrap::<P>(&self.recipient_infos, &mut content_key).await?;
		opening.decrypt(&<P::AeadCipher as KeyInit>::new(&content_key), content)
	}

	/// Open `content` in place, the encrypted content of this envelope, which
	/// carries it detached, under the AEAD of `P` and `kek`, which
	/// `key_identifier` names. `arrived` is the encoding `self` decoded from.
	/// A refused open leaves `content` as it was.
	///
	/// # Errors
	///
	/// - The errors of [`Self::check`]: a field, the cipher, or the attributes differ.
	/// - The errors of the `KEKRecipientInfo`: the recipient names another key or another wrap than `P`'s.
	/// - [`EnvelopeError::KeyUnwrap`] -- the wrapped content key fails its integrity check.
	/// - [`EnvelopeError::Authentication`] -- the tag fails.
	pub(crate) fn open_detached_kek<P>(
		&self,
		arrived: &[u8],
		content: &mut [u8],
		kek: &[u8],
		key_identifier: &[u8],
		content_type: ObjectIdentifier,
	) -> Result<(), EnvelopeError>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption>,
	{
		// 1. Hold the envelope to the provider's cipher before the key runs,
		//    and its authenticated attributes to DER.
		let opening = self.check::<P::AeadCipher>(arrived, content_type)?;

		// 2. Unwrap the content key onto the stack, then decrypt the content in place under it.
		let mut content_key = ContentKey::<P::AeadCipher>::default();
		kek::unwrap_kek::<P::KeyWrap>(kek, key_identifier, &self.recipient_infos, &mut content_key)?;
		opening.decrypt(&<P::AeadCipher as KeyInit>::new(&content_key), content)
	}

	/// Open `content` in place, the encrypted content of this envelope, which
	/// carries it detached, under the AEAD of `P` and the key-encryption key
	/// `holder` holds. `arrived` is the encoding `self` decoded from. A
	/// refused open leaves `content` as it was.
	///
	/// # Errors
	///
	/// - The errors of [`Self::check`]: a field, the cipher, or the attributes differ.
	/// - The errors of the holder's `KEKRecipientInfo`: the recipient names
	///   another key or another key-encryption algorithm than the holder's.
	/// - [`EnvelopeError::Key`] -- the holder refused to decrypt the content
	///   key, or decrypted a key of another size than the cipher's.
	/// - [`EnvelopeError::Authentication`] -- the tag fails.
	pub(crate) async fn open_with_holder<P>(
		&self,
		arrived: &[u8],
		content: &mut [u8],
		holder: &(impl EncryptingKeyProvider + ?Sized),
		content_type: ObjectIdentifier,
	) -> Result<(), EnvelopeError>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption>,
	{
		// 1. Hold the envelope to the provider's cipher, and its recipient to
		//    the holder's key, before the holder runs.
		let opening = self.check::<P::AeadCipher>(arrived, content_type)?;
		let algorithm = holder.algorithm();
		let encrypted_key = kek::named_kek(&self.recipient_infos, holder.key_identifier(), &algorithm)?;

		// 2. The holder decrypts the content key onto the stack, and the content decrypts in place under it.
		let mut content_key = ContentKey::<P::AeadCipher>::default();
		holder.decrypt_into(encrypted_key, &mut content_key).await?;
		opening.decrypt(&<P::AeadCipher as KeyInit>::new(&content_key), content)
	}

	/// The encrypted content of this envelope, taken out into a buffer that
	/// wipes, so it decrypts in place beside the envelope, as a frame carries
	/// it (RFC 5652 §6.1).
	///
	/// # Errors
	///
	/// - [`EnvelopeError::MissingContent`] -- the envelope carries no encrypted content.
	pub fn take_content(&mut self) -> Result<ZeroizingBytes, EnvelopeError> {
		let content = self.auth_encrypted_content_info.encrypted_content.take();
		let content = content.ok_or(EnvelopeError::MissingContent)?;
		Ok(Zeroizing::new(content.into_bytes()))
	}

	/// Hold this envelope, whose encoding is `arrived`, to the cipher `A`, to
	/// DER attributes, and to the content type `content_type`.
	///
	/// # Errors
	///
	/// - The errors of [`Self::associated_data`].
	/// - The errors of [`Self::opening`].
	fn check<A: ContentEncryption>(
		&self,
		arrived: &[u8],
		content_type: ObjectIdentifier,
	) -> Result<Opening<A>, EnvelopeError> {
		let associated_data = self.associated_data(arrived, content_type)?;
		self.opening::<A>(associated_data)
	}

	/// The one recipient of `arrived`, the `recipientInfos` of a record as it
	/// arrived, as the set the envelope holds.
	///
	/// A record names one recipient, the key of its direction and epoch, so
	/// this refuses a set of another count before `der` sorts it, and the set
	/// of one that this builds sorts nothing.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::RecipientKind`] -- the set holds another number of recipients than one.
	/// - [`EnvelopeError::Encoding`] -- `arrived` is no SET, or its element is no `RecipientInfo`.
	fn sole_recipient(arrived: AnyRef<'_>) -> Result<RecipientInfos, EnvelopeError> {
		if arrived.tag() != DerTag::Set {
			return Err(EnvelopeError::Encoding(arrived.tag().unexpected_error(Some(DerTag::Set))));
		}

		let mut recipients = SliceReader::new(arrived.value())?;
		let mut sole = None;
		while !recipients.is_finished() {
			let recipient = recipients.tlv_bytes()?;
			if sole.replace(recipient).is_some() {
				return Err(EnvelopeError::RecipientKind);
			}
		}

		let sole = sole.ok_or(EnvelopeError::RecipientKind)?;
		let recipient = RecipientInfo::from_der(sole)?;
		Ok(RecipientInfos(SetOfVec::try_from(vec![recipient])?))
	}

	/// The associated data of an open of this envelope, whose encoding is
	/// `arrived`, of type `expected`, as [`Self::aad_as_arrived`] admits it.
	/// It reads the attributes from `arrived` in place.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Encoding`] -- `arrived` is no DER `AuthEnvelopedData`.
	/// - The errors of [`Self::aad_as_arrived`].
	pub(super) fn associated_data(&self, arrived: &[u8], expected: ObjectIdentifier) -> Result<Vec<u8>, EnvelopeError> {
		let arrived = ArrivedEnvelopeRef::from_der(arrived)?;
		self.aad_as_arrived(expected, arrived.auth_attrs)
	}

	/// What an open of this envelope under the cipher `A` reads, once its
	/// version, its algorithm and parameters, and its tag hold, under
	/// `associated_data`, the attributes [`Self::aad_as_arrived`] admitted.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Version`] -- the version is not 0.
	/// - [`EnvelopeError::ContentEncryptionAlgorithm`] -- the algorithm or its parameters differ from `A`.
	/// - [`EnvelopeError::TagLength`] -- the parameters or `mac` name another tag length than the cipher's.
	fn opening<A: ContentEncryption>(&self, associated_data: Vec<u8>) -> Result<Opening<A>, EnvelopeError> {
		if self.version != CmsVersion::V0 {
			return Err(EnvelopeError::Version((self.version, CmsVersion::V0).into()));
		}

		let info = &self.auth_encrypted_content_info;
		let nonce = Self::nonce::<A>(&info.content_enc_alg)?;
		let tag = self.tag::<A>()?;
		Ok(Opening { nonce, tag, associated_data })
	}

	/// Decode the envelope `record` holds, of type `content_type`, with its
	/// encrypted content left in place, so the content opens in the buffer it
	/// arrived in. Every other field decodes as [`Decode`] decodes it, and the
	/// encrypted content stays in `record` alone.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Encoding`] -- `record` is no DER `AuthEnvelopedData`
	///   that the admission walk admits, or it carries `originatorInfo` or
	///   `unauthAttrs`.
	/// - [`EnvelopeError::RecipientKind`] -- `record` carries another number of recipients than one.
	/// - [`EnvelopeError::MissingContent`] -- the envelope carries no encrypted content.
	/// - The errors of [`Self::aad_as_arrived`].
	pub(in crate::crypto) fn detach(
		record: &mut [u8],
		content_type: ObjectIdentifier,
	) -> Result<Detached<'_>, EnvelopeError> {
		let (envelope, associated_data, content) = Self::decode_detached(record, content_type)?;
		let content = record.get_mut(content).ok_or(EnvelopeError::MissingContent)?;
		Ok(Detached { envelope, associated_data, content })
	}

	/// The envelope `arrived` encodes, its encrypted content left in place,
	/// beside its associated data and the range of `arrived` that content
	/// spans.
	///
	/// # Errors
	///
	/// - The errors of [`Self::detach`].
	fn decode_detached(
		arrived: &[u8],
		content_type: ObjectIdentifier,
	) -> Result<(Self, Vec<u8>, Range<usize>), EnvelopeError> {
		DerAdmission::Cms.admit(arrived)?;
		let decoded = ArrivedEnvelope::from_der(arrived)?;
		// The sender of a record leaves both fields out, and the tag covers
		// neither, so this refuses an envelope that carries one before any key
		// runs.
		if let Some(unauthenticated) = decoded.originator_info.or(decoded.unauth_attrs) {
			return Err(EnvelopeError::Encoding(unauthenticated.tag().value_error()));
		}

		let ArrivedContentInfo { content_type: encrypted_type, content_enc_alg, encrypted_content } =
			decoded.auth_encrypted_content_info;

		let encrypted_content = encrypted_content.ok_or(EnvelopeError::MissingContent)?;
		let content = Self::span(arrived, encrypted_content.as_bytes())?;
		let auth_encrypted_content_info =
			EncryptedContentInfo { content_type: encrypted_type, content_enc_alg, encrypted_content: None };

		let envelope = Self {
			version: decoded.version,
			originator_info: None,
			recipient_infos: Self::sole_recipient(decoded.recipient_infos)?,
			auth_encrypted_content_info,
			auth_attrs: decoded.auth_attrs.map(ArrivedAttributes::attributes).transpose()?,
			mac: decoded.mac,
			unauth_attrs: None,
		};

		let associated_data = envelope.aad_as_arrived(content_type, decoded.auth_attrs)?;
		Ok((envelope, associated_data, content))
	}

	/// The range of `whole` that `part`, a slice the decoder borrowed from
	/// it, spans.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::MissingContent`] -- `part` lies outside `whole`.
	fn span(whole: &[u8], part: &[u8]) -> Result<Range<usize>, EnvelopeError> {
		let whole_start = whole.as_ptr() as usize;
		let start = (part.as_ptr() as usize).checked_sub(whole_start);
		let start = start.ok_or(EnvelopeError::MissingContent)?;
		let end = start.checked_add(part.len()).ok_or(EnvelopeError::MissingContent)?;

		let slice = whole.get(start..end);
		let spanned = slice.is_some_and(|slice| core::ptr::eq(slice.as_ptr(), part.as_ptr()));
		spanned.then_some(start..end).ok_or(EnvelopeError::MissingContent)
	}

	/// The nonce of `algorithm`, which must name the cipher `A`.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::ContentEncryptionAlgorithm`] -- another algorithm, or parameters not of `A`.
	/// - [`EnvelopeError::TagLength`] -- the parameters name another tag length.
	fn nonce<A: ContentEncryption>(algorithm: &AlgorithmIdentifierOwned) -> Result<Nonce<A>, EnvelopeError> {
		if algorithm.oid != <A::Oid as AssociatedOid>::OID {
			return Err(EnvelopeError::ContentEncryptionAlgorithm);
		}

		A::nonce(algorithm.parameters.as_ref())
	}

	/// The tag `mac` carries, which must be the tag length of `A`.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::TagLength`] -- `mac` is another length.
	fn tag<A: AeadCore>(&self) -> Result<Tag<A>, EnvelopeError> {
		let mac = self.mac.as_bytes();
		let tag = GenericArray::from_exact_iter(mac.iter().copied());
		tag.ok_or(EnvelopeError::TagLength((mac.len(), A::TagSize::USIZE).into()))
	}

	/// The associated data of an open: the DER of the authenticated
	/// attributes under the universal `SET OF` tag (RFC 5083 §2.2). It is the
	/// one encode of the attributes on an open, and it returns the DER when
	/// both conditions hold:
	///
	/// - The content-type attribute and the encrypted content name `expected`.
	/// - `arrived`, the attributes as they arrived, are that DER (RFC 5083 §2.1).
	///
	/// # Errors
	///
	/// - [`EnvelopeError::ContentTypeAttribute`] -- the attributes carry no single content type.
	/// - [`EnvelopeError::ContentType`] -- the attribute or the content names another type.
	/// - [`EnvelopeError::AuthAttributesNotDer`] -- the attributes did not arrive as their DER.
	/// - [`EnvelopeError::Encoding`] -- the content type fails to decode, or the attributes to encode.
	fn aad_as_arrived(
		&self,
		expected: ObjectIdentifier,
		arrived: Option<ArrivedAttributes<'_>>,
	) -> Result<Vec<u8>, EnvelopeError> {
		let auth_attrs = self.auth_attrs.as_ref().ok_or(EnvelopeError::ContentTypeAttribute)?;
		let named = content_type_of(auth_attrs)?;
		if named != expected {
			return Err(EnvelopeError::ContentType((named, expected).into()));
		}

		let encrypted = self.auth_encrypted_content_info.content_type;
		if encrypted != expected {
			return Err(EnvelopeError::ContentType((encrypted, expected).into()));
		}

		// The contents of the SET OF are the contents of the `[1]` element.
		let associated_data = auth_attrs.to_der()?;
		let mut reader = SliceReader::new(&associated_data)?;
		let header = Header::decode(&mut reader)?;
		let contents = reader.read_slice(header.length)?;
		if arrived.map(|attributes| attributes.contents) != Some(contents) {
			return Err(EnvelopeError::AuthAttributesNotDer);
		}

		Ok(associated_data)
	}
}

/// The content key and the nonce of one seal, drawn before the recipient
/// wraps the key. Both sit on the stack, and the key wipes where it drops.
struct Draw<A: AeadCore + KeyInit> {
	content_key: ContentKey<A>,
	nonce: Nonce<A>,
}

impl<A: ContentEncryption> Draw<A> {
	/// Draw a content key of the size of `A` and a nonce from `rng`.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Random`] -- the random source failed.
	fn new(rng: &mut dyn CryptoRngCore) -> Result<Self, EnvelopeError> {
		let mut content_key = Zeroizing::new(Key::<A>::default());
		let mut nonce = Nonce::<A>::default();
		let key_drawn = rng.try_fill_bytes(content_key.as_mut_slice());
		let drawn = key_drawn.and_then(|()| rng.try_fill_bytes(&mut nonce));
		drawn.map_err(|_| EnvelopeError::Random)?;

		Ok(Self { content_key, nonce })
	}

	/// Seal `content`, of type `content_type`, under this content key for
	/// `recipient_info`, the recipient that holds it wrapped. A `Vec` that
	/// moves in becomes the `encryptedContent`.
	///
	/// # Errors
	///
	/// - The errors of [`Self::seal_in_place`].
	fn seal(
		self,
		recipient_info: RecipientInfo,
		content_type: ObjectIdentifier,
		content: impl Into<Vec<u8>>,
		auth_attrs: impl IntoIterator<Item = Attribute>,
	) -> Result<AuthEnvelopedData, EnvelopeError> {
		let mut ciphertext = Zeroizing::new(content.into());
		let mut sealed = self.seal_in_place(recipient_info, content_type, &mut ciphertext, auth_attrs)?;
		let encrypted_content = OctetString::new(core::mem::take(&mut *ciphertext))?;
		sealed.auth_encrypted_content_info.encrypted_content = Some(encrypted_content);
		Ok(sealed)
	}

	/// Seal `content` in place, of type `content_type`, under this content
	/// key for `recipient_info`, the recipient that holds it wrapped. The
	/// envelope carries the content detached.
	///
	/// Every step that can fail runs before the content encrypts, and the
	/// cipher leaves a refused buffer as it was ([`ContentEncryption`]), so a
	/// refused seal leaves `content` as it was.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::ContentTypeAttribute`] -- `auth_attrs` carries a content-type attribute.
	/// - [`EnvelopeError::Encoding`] -- a field fails to encode, or `content` is past a DER length.
	/// - [`EnvelopeError::Encryption`] -- the cipher refused the content.
	fn seal_in_place(
		self,
		recipient_info: RecipientInfo,
		content_type: ObjectIdentifier,
		content: &mut [u8],
		auth_attrs: impl IntoIterator<Item = Attribute>,
	) -> Result<AuthEnvelopedData, EnvelopeError> {
		// 1. Build every field the content leaves as it is: the recipient, the
		//    attributes with the content type ahead of the caller's, their DER
		//    as the associated data, and the parameters.
		let recipient_infos = RecipientInfos(SetOfVec::try_from(vec![recipient_info])?);
		let auth_attrs = authenticated_attributes(content_type, auth_attrs)?;
		let associated_data = auth_attrs.to_der()?;
		let parameters = Some(A::parameters(&self.nonce)?);

		// 2. Hold the content and the tag to DER lengths, so each octet string
		//    forms once the content has encrypted.
		Length::try_from(content.len())?;
		Length::try_from(A::TagSize::USIZE)?;

		// 3. Encrypt in place, with the tag detached into `mac`.
		let cipher = A::new(&self.content_key);
		let tag = cipher.encrypt_in_place_detached(&self.nonce, &associated_data, content);
		let tag = tag.map_err(|_| EnvelopeError::Encryption)?;

		let oid = <A::Oid as AssociatedOid>::OID;
		let content_enc_alg = AlgorithmIdentifierOwned { oid, parameters };
		let auth_encrypted_content_info =
			EncryptedContentInfo { content_type, content_enc_alg, encrypted_content: None };
		Ok(AuthEnvelopedData {
			version: CmsVersion::V0,
			originator_info: None,
			recipient_infos,
			auth_encrypted_content_info,
			auth_attrs: Some(auth_attrs),
			mac: OctetString::new(tag.as_slice())?,
			unauth_attrs: None,
		})
	}
}

/// The nonce, the tag, and the associated data an open reads, each held to
/// the cipher `A` before any key runs.
struct Opening<A: AeadCore> {
	nonce: Nonce<A>,
	tag: Tag<A>,
	associated_data: Vec<u8>,
}

impl<A: ContentEncryption> Opening<A> {
	/// Decrypt `content` in place under `cipher`, keyed with the content key.
	/// A content that returns has passed its tag, and a refused one is as it
	/// arrived ([`ContentEncryption`]).
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Authentication`] -- the tag fails.
	fn decrypt(self, cipher: &A, content: &mut [u8]) -> Result<(), EnvelopeError> {
		let opened = cipher.decrypt_in_place_detached(&self.nonce, &self.associated_data, content, &self.tag);
		opened.map_err(|_| EnvelopeError::Authentication)
	}
}

/// An envelope whose encrypted content stayed in the buffer it arrived in,
/// from [`AuthEnvelopedData::detach`], with the associated data its
/// attributes were admitted as.
pub(in crate::crypto) struct Detached<'a> {
	envelope: AuthEnvelopedData,
	associated_data: Vec<u8>,
	content: &'a mut [u8],
}

impl<'a> Detached<'a> {
	/// The envelope, its encrypted content left in the record.
	pub(in crate::crypto) fn envelope(&self) -> &AuthEnvelopedData {
		&self.envelope
	}

	/// The length in octets of the encrypted content.
	pub(in crate::crypto) fn content_len(&self) -> usize {
		self.content.len()
	}

	/// Open the content in the buffer it arrived in, under the AEAD of `P` and
	/// `kek`, which `key_identifier` names, and return it decrypted.
	///
	/// # Errors
	///
	/// - The errors of [`AuthEnvelopedData::open_detached_kek`] that follow the attributes.
	pub(in crate::crypto) fn open_kek<P>(self, kek: &[u8], key_identifier: &[u8]) -> Result<&'a [u8], EnvelopeError>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption>,
	{
		let Self { envelope, associated_data, content } = self;
		let opening = envelope.opening::<P::AeadCipher>(associated_data)?;
		let mut content_key = ContentKey::<P::AeadCipher>::default();
		kek::unwrap_kek::<P::KeyWrap>(kek, key_identifier, &envelope.recipient_infos, &mut content_key)?;
		opening.decrypt(&<P::AeadCipher as KeyInit>::new(&content_key), &mut *content)?;
		Ok(content)
	}
}

/// The syntax of [`AuthEnvelopedData`] with the encrypted content and the
/// authenticated attributes borrowed from the buffer they arrived in. The
/// `originatorInfo` and the `unauthAttrs` stay as they arrived, and each other
/// field decodes as the field of the owned type does.
#[derive(Sequence)]
struct ArrivedEnvelope<'a> {
	version: CmsVersion,
	#[asn1(
		context_specific = "0",
		tag_mode = "IMPLICIT",
		constructed = "true",
		optional = "true"
	)]
	originator_info: Option<AnyRef<'a>>,
	recipient_infos: AnyRef<'a>,
	auth_encrypted_content_info: ArrivedContentInfo<'a>,
	#[asn1(
		context_specific = "1",
		tag_mode = "IMPLICIT",
		constructed = "true",
		optional = "true"
	)]
	auth_attrs: Option<ArrivedAttributes<'a>>,
	mac: OctetString,
	#[asn1(
		context_specific = "2",
		tag_mode = "IMPLICIT",
		constructed = "true",
		optional = "true"
	)]
	unauth_attrs: Option<AnyRef<'a>>,
}

/// The syntax of [`AuthEnvelopedData`] borrowed whole from the buffer it
/// arrived in, so an envelope decoded once reads its arrived attributes with
/// no allocation. Each other field is its element as it arrived.
#[derive(Sequence)]
struct ArrivedEnvelopeRef<'a> {
	version: AnyRef<'a>,
	#[asn1(
		context_specific = "0",
		tag_mode = "IMPLICIT",
		constructed = "true",
		optional = "true"
	)]
	originator_info: Option<AnyRef<'a>>,
	recipient_infos: AnyRef<'a>,
	auth_encrypted_content_info: AnyRef<'a>,
	#[asn1(
		context_specific = "1",
		tag_mode = "IMPLICIT",
		constructed = "true",
		optional = "true"
	)]
	auth_attrs: Option<ArrivedAttributes<'a>>,
	mac: AnyRef<'a>,
	#[asn1(
		context_specific = "2",
		tag_mode = "IMPLICIT",
		constructed = "true",
		optional = "true"
	)]
	unauth_attrs: Option<AnyRef<'a>>,
}

/// `EncryptedContentInfo` (RFC 5652 §6.1) with the encrypted content
/// borrowed from the buffer it arrived in.
#[derive(Sequence)]
struct ArrivedContentInfo<'a> {
	content_type: ObjectIdentifier,
	content_enc_alg: AlgorithmIdentifierOwned,
	#[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
	encrypted_content: Option<OctetStringRef<'a>>,
}

/// The `authAttrs` of an envelope as they arrived: the contents of their
/// `[1]` element, borrowed from the buffer they arrived in.
#[derive(Clone, Copy)]
struct ArrivedAttributes<'a> {
	contents: &'a [u8],
}

impl ArrivedAttributes<'_> {
	/// The attributes these contents encode, decoded as an [`Attributes`]
	/// decodes.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Encoding`] -- the contents are no SET OF `Attribute`.
	fn attributes(self) -> Result<Attributes, EnvelopeError> {
		let header = Header::new(DerTag::Set, Length::try_from(self.contents.len())?)?;
		let mut reader = SliceReader::new(self.contents)?;
		let attributes = Attributes::decode_value(&mut reader, header)?;
		Ok(reader.finish(attributes)?)
	}
}

impl<'a> DecodeValue<'a> for ArrivedAttributes<'a> {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> crate::der::Result<Self> {
		let contents = reader.read_slice(header.length)?;
		Ok(Self { contents })
	}
}

/// The contents encode as they arrived, so the borrowed syntax round-trips.
impl EncodeValue for ArrivedAttributes<'_> {
	fn value_len(&self) -> crate::der::Result<Length> {
		Length::try_from(self.contents.len())
	}

	fn encode_value(&self, writer: &mut impl Writer) -> crate::der::Result<()> {
		writer.write(self.contents)
	}
}

/// The `[1] IMPLICIT` element of `authAttrs` replaces the universal `SET OF`
/// tag, so the contents carry that tag's form.
impl FixedTag for ArrivedAttributes<'_> {
	const TAG: DerTag = DerTag::Set;
}

/// The authenticated attributes of a seal: the content-type attribute that
/// names `content_type`, and `attributes`.
///
/// # Errors
///
/// - [`EnvelopeError::ContentTypeAttribute`] -- `attributes` carries a content-type attribute.
/// - [`EnvelopeError::Encoding`] -- the set fails to build.
fn authenticated_attributes(
	content_type: ObjectIdentifier,
	attributes: impl IntoIterator<Item = Attribute>,
) -> Result<Attributes, EnvelopeError> {
	let values = SetOfVec::try_from(vec![Any::encode_from(&content_type)?])?;
	let attributes = attributes.into_iter();
	let mut set = Vec::with_capacity(attributes.size_hint().0.saturating_add(1));
	set.push(Attribute { oid: ATTR_CONTENT_TYPE, values });
	for attribute in attributes {
		if attribute.oid == ATTR_CONTENT_TYPE {
			return Err(EnvelopeError::ContentTypeAttribute);
		}

		set.push(attribute);
	}

	Ok(Attributes::try_from(set)?)
}

/// The content type the one content-type attribute of `attributes` names.
///
/// # Errors
///
/// - [`EnvelopeError::ContentTypeAttribute`] -- no such attribute, two, or one of another number of values.
/// - [`EnvelopeError::Encoding`] -- its value is no OBJECT IDENTIFIER.
fn content_type_of(attributes: &Attributes) -> Result<ObjectIdentifier, EnvelopeError> {
	let named = attributes.single(ATTR_CONTENT_TYPE, EnvelopeError::ContentTypeAttribute)?;
	let attribute = named.ok_or(EnvelopeError::ContentTypeAttribute)?;
	let [value] = attribute.values.as_slice() else {
		return Err(EnvelopeError::ContentTypeAttribute);
	};

	Ok(value.decode_as::<ObjectIdentifier>()?)
}
