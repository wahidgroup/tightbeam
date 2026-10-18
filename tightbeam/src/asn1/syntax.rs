//! The ASN.1 syntax of the four CMS types the `cms` crate lacks, each checked
//! field by field against the ASN.1 module of its RFC. A frame carries an
//! [`AuthEnvelopedData`] in every build, so the syntax compiles in every
//! build.

use crate::cms::cert::x509::attr::Attributes;
use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{
	EncryptedContentInfo, EncryptedKey, OriginatorInfo, RecipientIdentifier, RecipientInfos, UserKeyingMaterial,
};
use crate::der::asn1::OctetString;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::der::asn1::OctetStringRef;
use crate::der::Sequence;
use crate::spki::AlgorithmIdentifierOwned;

/// `AuthEnvelopedData` ([RFC 5083 §2.1][rfc5083-2.1]): a content encrypted
/// under an authenticated cipher for one or more recipients.
///
/// ```text
/// AuthEnvelopedData ::= SEQUENCE {
///   version CMSVersion,
///   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
///   recipientInfos RecipientInfos,
///   authEncryptedContentInfo EncryptedContentInfo,
///   authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
///   mac MessageAuthenticationCode,
///   unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
/// ```
///
/// [rfc5083-2.1]: https://datatracker.ietf.org/doc/html/rfc5083#section-2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AuthEnvelopedData {
	/// The syntax version, which RFC 5083 §2.1 sets to 0.
	pub version: CmsVersion,
	/// The originator's certificates and revocation lists.
	#[asn1(
		context_specific = "0",
		tag_mode = "IMPLICIT",
		constructed = "true",
		optional = "true"
	)]
	pub originator_info: Option<OriginatorInfo>,
	/// One `RecipientInfo` for each recipient of the content key.
	pub recipient_infos: RecipientInfos,
	/// The content type, the cipher with its parameters, and the ciphertext.
	pub auth_encrypted_content_info: EncryptedContentInfo,
	/// The attributes the cipher authenticates as associated data.
	#[asn1(
		context_specific = "1",
		tag_mode = "IMPLICIT",
		constructed = "true",
		optional = "true"
	)]
	pub auth_attrs: Option<Attributes>,
	/// The authentication tag of the cipher.
	pub mac: OctetString,
	/// The attributes outside the authentication tag (RFC 5083 §2.1).
	#[asn1(
		context_specific = "2",
		tag_mode = "IMPLICIT",
		constructed = "true",
		optional = "true"
	)]
	pub unauth_attrs: Option<Attributes>,
}

/// `KEMRecipientInfo` ([RFC 9629 §3][rfc9629-3]): a content key wrapped under
/// a key that a KEM shared secret derives, carried as the value of an
/// `OtherRecipientInfo` of type `id-ori-kem`.
///
/// ```text
/// KEMRecipientInfo ::= SEQUENCE {
///   version CMSVersion,  -- always set to 0
///   rid RecipientIdentifier,
///   kem KEMAlgorithmIdentifier,
///   kemct OCTET STRING,
///   kdf KeyDerivationAlgorithmIdentifier,
///   kekLength INTEGER (1..65535),
///   ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL,
///   wrap KeyEncryptionAlgorithmIdentifier,
///   encryptedKey EncryptedKey }
/// ```
///
/// [rfc9629-3]: https://datatracker.ietf.org/doc/html/rfc9629#section-3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct KemRecipientInfo {
	/// The syntax version, which RFC 9629 §3 sets to 0.
	pub version: CmsVersion,
	/// The certificate or key the sender encapsulated to.
	pub rid: RecipientIdentifier,
	/// The KEM and its parameters.
	pub kem: AlgorithmIdentifierOwned,
	/// The ciphertext the KEM's `Encapsulate` produced.
	pub kemct: OctetString,
	/// The KDF that derives the key-encryption key from the KEM shared secret.
	pub kdf: AlgorithmIdentifierOwned,
	/// The length in octets of the key-encryption key.
	pub kek_length: u16,
	/// The user keying material the KDF binds, when the sender gives one.
	#[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
	pub ukm: Option<UserKeyingMaterial>,
	/// The key-encryption algorithm that wraps the content key.
	pub wrap: AlgorithmIdentifierOwned,
	/// The wrapped content key.
	pub encrypted_key: EncryptedKey,
}

/// `CMSORIforKEMOtherInfo` ([RFC 9629 §5][rfc9629-5]): the `info` the KDF of
/// a `KEMRecipientInfo` derives the key-encryption key under.
///
/// ```text
/// CMSORIforKEMOtherInfo ::= SEQUENCE {
///   wrap KeyEncryptionAlgorithmIdentifier,
///   kekLength INTEGER (1..65535),
///   ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL }
/// ```
///
/// [rfc9629-5]: https://datatracker.ietf.org/doc/html/rfc9629#section-5
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CmsOriForKemOtherInfo {
	/// The `wrap` of the `KEMRecipientInfo`.
	pub wrap: AlgorithmIdentifierOwned,
	/// The `kekLength` of the `KEMRecipientInfo`.
	pub kek_length: u16,
	/// The `ukm` of the `KEMRecipientInfo`, when it carries one.
	#[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
	pub ukm: Option<UserKeyingMaterial>,
}

/// `GCMParameters` ([RFC 5084 §3.2][rfc5084-3.2]): the nonce and the tag
/// length of an AES-GCM content-encryption algorithm.
///
/// ```text
/// GCMParameters ::= SEQUENCE {
///   aes-nonce        OCTET STRING, -- recommended size is 12 octets
///   aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
///
/// AES-GCM-ICVlen ::= INTEGER (12 | 13 | 14 | 15 | 16)
/// ```
///
/// DER omits a value equal to its default, so `aes-ICVlen` encodes when it is
/// 16 and is absent when it is 12.
///
/// [rfc5084-3.2]: https://datatracker.ietf.org/doc/html/rfc5084#section-3.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct GcmParameters {
	/// The nonce of the one encryption.
	pub aes_nonce: OctetString,
	/// The length of the authentication tag in octets.
	#[asn1(default = "default_icv_len")]
	pub aes_icv_len: u8,
}

/// [`GcmParameters`] with the nonce borrowed, which a seal encodes from the
/// nonce it drew and an open reads in place, with no copy of the nonce.
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct GcmParametersRef<'a> {
	/// The nonce of the one encryption.
	pub(crate) aes_nonce: OctetStringRef<'a>,
	/// The length of the authentication tag in octets.
	#[asn1(default = "default_icv_len")]
	pub(crate) aes_icv_len: u8,
}

/// The default `aes-ICVlen` of RFC 5084 §3.2.
fn default_icv_len() -> u8 {
	12
}
