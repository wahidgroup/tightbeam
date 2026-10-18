//! The seal and the open of an [`AuthEnvelopedData`] under the AEAD of a
//! [`CryptoProvider`].

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use aead::{AeadCore, AeadInPlace, KeyInit, Nonce, Tag};

use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{EncryptedContentInfo, RecipientInfos};
use crate::crypto::aead::{AeadAlgorithm, Aes128Gcm, Aes256Gcm};
use crate::crypto::cms::recipient::ContentKey;
use crate::crypto::cms::{AttributesExt, AuthEnvelopedData, EnvelopeError, GcmParameters, Opener, Recipient};
use crate::crypto::common::generic_array::GenericArray;
use crate::crypto::common::typenum::Unsigned;
use crate::crypto::common::KeySizeUser;
use crate::crypto::profiles::CryptoProvider;
use crate::crypto::secret::SecretSlice;
use crate::der::asn1::{ContextSpecificRef, ObjectIdentifier, OctetString, SetOfVec};
use crate::der::oid::AssociatedOid;
use crate::der::{Any, AnyRef, Decode, Encode, Header, Reader, SliceReader, Tag as DerTag, TagMode, TagNumber, Tagged};
use crate::oids::ATTR_CONTENT_TYPE;
use crate::random::{CryptoRngCore, OsRng};
use crate::spki::AlgorithmIdentifierOwned;
use crate::x509::attr::{Attribute, Attributes};
use crate::zeroize::Zeroizing;

/// The `[1]` tag of `authAttrs` (RFC 5083 §2.1).
const AUTH_ATTRS_TAG: DerTag = DerTag::ContextSpecific { constructed: true, number: TagNumber::N1 };

/// The content-encryption algorithm of an envelope: an AEAD cipher with its
/// identifier, from [`AeadAlgorithm`], and its parameters (RFC 5083 §2.1).
///
/// A provider names its cipher, so an implementor brings another one, such
/// as ChaCha20-Poly1305 (RFC 8103), with an implementation of this trait on
/// its cipher type. AES-GCM under `GCMParameters` (RFC 5084) is the house one.
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
	let parameters = GcmParameters { aes_nonce: OctetString::new(nonce.as_slice())?, aes_icv_len };
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
	let parameters = parameters.decode_as::<GcmParameters>();
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
	/// - The `Recipient::wrap` set: the recipient key, its name, the wrap, or a derivation failed.
	/// - [`EnvelopeError::Encryption`] -- the cipher refused the content.
	/// - [`EnvelopeError::Encoding`] -- an attribute or a parameter fails to encode.
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
		let mut os_rng = OsRng;
		let rng = rng.unwrap_or(&mut os_rng);

		// 1. Draw the content key and the nonce of this one seal.
		let mut content_key = ContentKey::new(vec![0u8; <P::AeadCipher as KeySizeUser>::key_size()]);
		let mut nonce = Nonce::<P::AeadCipher>::default();
		let key_drawn = rng.try_fill_bytes(content_key.as_mut_slice());
		let drawn = key_drawn.and_then(|()| rng.try_fill_bytes(&mut nonce));
		drawn.map_err(|_| EnvelopeError::Random)?;

		// 2. Wrap the content key for the recipient.
		let recipient_info = recipient.wrap::<P>(&content_key, rng)?;
		let recipient_infos = RecipientInfos(SetOfVec::try_from(vec![recipient_info])?);

		// 3. Authenticate the content type ahead of the caller's attributes.
		let auth_attrs = authenticated_attributes(content_type, auth_attrs)?;
		let associated_data = auth_attrs.to_der()?;

		// 4. Encrypt, with the tag detached into `mac`.
		let mut ciphertext = Zeroizing::new(content.into());
		let cipher = P::AeadCipher::new_from_slice(&content_key).map_err(|_| EnvelopeError::Encryption)?;
		let tag = cipher.encrypt_in_place_detached(&nonce, &associated_data, &mut ciphertext);
		let tag = tag.map_err(|_| EnvelopeError::Encryption)?;

		let parameters = Some(P::AeadCipher::parameters(&nonce)?);
		let oid = <<P::AeadCipher as AeadAlgorithm>::Oid as AssociatedOid>::OID;
		let content_enc_alg = AlgorithmIdentifierOwned { oid, parameters };
		let encrypted_content = Some(OctetString::new(core::mem::take(&mut *ciphertext))?);
		let auth_encrypted_content_info = EncryptedContentInfo { content_type, content_enc_alg, encrypted_content };
		Ok(Self {
			version: CmsVersion::V0,
			originator_info: None,
			recipient_infos,
			auth_encrypted_content_info,
			auth_attrs: Some(auth_attrs),
			mac: OctetString::new(tag.as_slice())?,
			unauth_attrs: None,
		})
	}

	/// Open the content, which must be of type `content_type`, with `opener`
	/// under the algorithms of `P`, in the buffer the ciphertext arrived in.
	///
	/// `arrived` is the encoding `self` decoded from. Every field is checked
	/// before the content key unwraps, so a refused envelope costs the
	/// opener's key no operation. A content that returns has passed its tag,
	/// so the authenticated attributes it arrived with passed it too.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::AuthAttributesNotDer`] -- the attributes in `arrived` are not their DER.
	/// - [`EnvelopeError::Version`] -- the version is not 0.
	/// - [`EnvelopeError::ContentEncryptionAlgorithm`] -- the algorithm or its
	///   parameters are not the provider's cipher's.
	/// - [`EnvelopeError::TagLength`] -- the parameters or `mac` name another tag length than the cipher's.
	/// - [`EnvelopeError::ContentTypeAttribute`] -- the authenticated
	///   attributes carry no single content type.
	/// - [`EnvelopeError::ContentType`] -- a content type other than `content_type`.
	/// - [`EnvelopeError::MissingContent`] -- the envelope carries no encrypted content.
	/// - The [`Opener`] set: the recipient differs from the opener, or its key fails to unwrap.
	/// - [`EnvelopeError::KeyUnwrap`] -- the content key is no key of the cipher.
	/// - [`EnvelopeError::Authentication`] -- the tag fails.
	/// - [`EnvelopeError::Encoding`] -- a structure fails to decode or encode.
	pub async fn open<P>(
		mut self,
		arrived: impl AsRef<[u8]>,
		opener: &Opener<'_, P::Kem>,
		content_type: ObjectIdentifier,
	) -> Result<SecretSlice<u8>, EnvelopeError>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption>,
	{
		// 1. Hold the envelope to the provider's cipher before any key runs,
		//    and its authenticated attributes to DER.
		if Self::arrived_auth_attrs(arrived.as_ref())? != self.auth_attrs_der()? {
			return Err(EnvelopeError::AuthAttributesNotDer);
		}
		if self.version != CmsVersion::V0 {
			return Err(EnvelopeError::Version((self.version, CmsVersion::V0).into()));
		}

		let info = &self.auth_encrypted_content_info;
		let nonce = Self::nonce::<P::AeadCipher>(&info.content_enc_alg)?;
		let tag = self.tag::<P::AeadCipher>()?;
		let associated_data = self.associated_data(content_type)?;
		let ciphertext = self.auth_encrypted_content_info.encrypted_content.take();
		let ciphertext = ciphertext.ok_or(EnvelopeError::MissingContent)?;

		// 2. Unwrap the content key, then decrypt the ciphertext in place under it.
		let content_key = opener.unwrap::<P>(&self.recipient_infos).await?;
		let mut plaintext = Zeroizing::new(ciphertext.into_bytes());
		let cipher = P::AeadCipher::new_from_slice(&content_key).map_err(|_| EnvelopeError::KeyUnwrap)?;
		let opened = cipher.decrypt_in_place_detached(&nonce, &associated_data, &mut plaintext, &tag);
		opened.map_err(|_| EnvelopeError::Authentication)?;

		// The plaintext moves into its wiping wrapper without a copy.
		Ok(SecretSlice::from(core::mem::take(&mut *plaintext)))
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

	/// The `authAttrs` element of `arrived`, the encoding of an envelope, as
	/// its bytes arrived, or `None` when it carries none.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Encoding`] -- `arrived` is no SEQUENCE of elements.
	fn arrived_auth_attrs(arrived: &[u8]) -> Result<Option<Vec<u8>>, EnvelopeError> {
		let mut reader = SliceReader::new(arrived)?;
		let header = Header::decode(&mut reader)?;
		let found = reader.read_nested(header.length, |fields| {
			let mut found = None;
			while !fields.is_finished() {
				let field = AnyRef::decode(fields)?;
				if field.tag() == AUTH_ATTRS_TAG {
					found = Some(field.to_der()?);
				}
			}
			Ok(found)
		});

		Ok(found?)
	}

	/// The DER of `authAttrs` under its `[1]` tag, or `None` when the envelope
	/// carries none.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Encoding`] -- the attributes fail to encode.
	fn auth_attrs_der(&self) -> Result<Option<Vec<u8>>, EnvelopeError> {
		let tagged = self.auth_attrs.as_ref().map(|value| ContextSpecificRef {
			tag_number: TagNumber::N1,
			tag_mode: TagMode::Implicit,
			value,
		});
		Ok(tagged.map(|tagged| tagged.to_der()).transpose()?)
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

	/// The associated data, the DER of the authenticated attributes, once
	/// their content-type attribute and the encrypted content both name
	/// `expected`.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::ContentTypeAttribute`] -- the attributes carry no single content type.
	/// - [`EnvelopeError::ContentType`] -- the attribute or the content names another type.
	/// - [`EnvelopeError::Encoding`] -- the content type fails to decode, or the attributes to encode.
	pub(super) fn associated_data(&self, expected: ObjectIdentifier) -> Result<Vec<u8>, EnvelopeError> {
		let auth_attrs = self.auth_attrs.as_ref().ok_or(EnvelopeError::ContentTypeAttribute)?;
		let named = content_type_of(auth_attrs)?;
		if named != expected {
			return Err(EnvelopeError::ContentType((named, expected).into()));
		}

		let encrypted = self.auth_encrypted_content_info.content_type;
		if encrypted != expected {
			return Err(EnvelopeError::ContentType((encrypted, expected).into()));
		}

		Ok(auth_attrs.to_der()?)
	}
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
	let mut set = vec![Attribute { oid: ATTR_CONTENT_TYPE, values }];
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
