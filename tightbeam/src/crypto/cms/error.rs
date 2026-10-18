//! Errors of the authenticated envelope and its recipients.

use crate::cms::content_info::CmsVersion;
use crate::der::asn1::ObjectIdentifier;
use crate::error::ReceivedExpectedError;
use crate::Errorizable;

/// Errors from sealing or opening an
/// [`AuthEnvelopedData`](super::AuthEnvelopedData).
///
/// An opener refuses with one of these before any byte of the content is
/// released, and every refusal of the tag, the wrapped key, or a field of the
/// recipient leaves the content closed.
#[derive(Errorizable, Debug)]
#[non_exhaustive]
pub enum EnvelopeError {
	/// The `AuthEnvelopedData` version is not 0 (RFC 5083 §2.1).
	#[error("AuthEnvelopedData version differs from RFC 5083 §2.1: {0:?}")]
	Version(ReceivedExpectedError<CmsVersion, CmsVersion>),

	/// The content-encryption algorithm is not the provider's cipher, or its
	/// parameters are not the cipher's, such as `GCMParameters` with a nonce
	/// of the cipher's size (RFC 5084 §3.2).
	#[error("The content-encryption algorithm is not the provider's cipher")]
	ContentEncryptionAlgorithm,

	/// The tag length the parameters name, such as `aes-ICVlen`, or the
	/// length of `mac`, is another than the cipher's (RFC 5084 §3.2).
	#[error("Tag length differs: {0:?}")]
	TagLength(ReceivedExpectedError<usize, usize>),

	/// The authenticated attributes carry no content-type attribute, carry
	/// it twice, or carry another number of values in it (RFC 5083 §2.1).
	#[error("The authenticated attributes carry no single content-type attribute")]
	ContentTypeAttribute,

	/// The content type differs from the one the opener expects, or the
	/// content-type attribute differs from the encrypted content's type.
	#[error("Content type differs: {0:?}")]
	ContentType(ReceivedExpectedError<ObjectIdentifier, ObjectIdentifier>),

	/// An authenticated attribute the reader requires is absent, carried
	/// twice, or holds another value.
	#[error("A required authenticated attribute is absent or differs")]
	AuthenticatedAttribute,

	/// The authenticated attributes arrived in another encoding than their
	/// DER, such as a SET OF out of DER order. RFC 5083 §2.1 requires them in
	/// DER, because their DER is the associated data.
	#[error("The authenticated attributes did not arrive in DER")]
	AuthAttributesNotDer,

	/// The envelope carries no encrypted content.
	#[error("The envelope carries no encrypted content")]
	MissingContent,

	/// The envelope carries another number of recipients than one, or a
	/// recipient of another kind than the opener's.
	#[error("The recipient differs in kind from the opener")]
	RecipientKind,

	/// The `RecipientInfo` version differs from its kind's: 0 for a
	/// `KEMRecipientInfo` (RFC 9629 §3), 4 for a `KEKRecipientInfo` (RFC 5652
	/// §6.2.3).
	#[error("RecipientInfo version differs: {0:?}")]
	RecipientVersion(ReceivedExpectedError<CmsVersion, CmsVersion>),

	/// The `rid` of a `KEMRecipientInfo` names another certificate than the
	/// opener's.
	#[error("The recipient identifier names another certificate")]
	RecipientIdentifier,

	/// The KEM, the KDF, or the key wrap differs from the provider's, or
	/// carries parameters, or the provider's profile names no key wrap of AES.
	#[error("The recipient names an algorithm other than the provider's")]
	RecipientAlgorithm,

	/// `kekLength`, or a key-encryption key, is another length than the key
	/// size of the provider's wrap (RFC 9629 §3).
	#[error("kekLength differs from the key wrap: {0:?}")]
	KekLength(ReceivedExpectedError<usize, usize>),

	/// The `ukm` is absent, or it is not the opener's purpose label followed
	/// by 32 octets.
	#[error("The user keying material differs from the opener's purpose")]
	Ukm,

	/// The `kekid` names another key than the opener's.
	#[error("The key identifier names another key")]
	KeyIdentifier,

	/// The `kemct` is not an uncompressed point on secp256k1.
	#[error("The KEM ciphertext is no uncompressed point on the curve")]
	KemPoint,

	/// The wrapped content key fails the integrity check of AES key wrap
	/// (RFC 3394 §2.2.3), or it unwraps to no key of the cipher.
	#[error("The wrapped content key fails to unwrap")]
	KeyUnwrap,

	/// The tag in `mac` fails, so the ciphertext, the nonce, or the
	/// authenticated attributes changed, or the content key is another.
	#[error("The content fails to authenticate")]
	Authentication,

	/// The cipher refused to encrypt the content.
	#[error("The content fails to encrypt")]
	Encryption,

	/// The random source failed.
	#[error("The random source failed")]
	Random,

	/// The key provider failed the agreement of the recipient.
	#[error("Key provider error: {0}")]
	Key(crate::crypto::key::KeyError),

	/// The KEM failed a derivation.
	#[error("KEM error: {0}")]
	Kem(crate::crypto::hpke::HpkeError),

	/// The KDF refused a derivation, or the provider's agreement is not 32
	/// octets.
	#[error("KDF error: {0}")]
	Kdf(crate::crypto::kdf::KdfError),

	/// The certificate failed to name its recipient, or holds no point on
	/// secp256k1.
	#[error("Certificate error: {0}")]
	Certificate(crate::crypto::x509::error::CertificateValidationError),

	/// A structure or an attribute failed to encode or decode.
	#[error("CMS encoding error: {0}")]
	Encoding(crate::der::Error),
}

crate::impl_from!(crate::crypto::key::KeyError => EnvelopeError::Key);
crate::impl_from!(crate::crypto::hpke::HpkeError => EnvelopeError::Kem);
crate::impl_from!(crate::crypto::kdf::KdfError => EnvelopeError::Kdf);
crate::impl_from!(crate::crypto::x509::error::CertificateValidationError => EnvelopeError::Certificate);
crate::impl_from!(crate::der::Error => EnvelopeError::Encoding);
