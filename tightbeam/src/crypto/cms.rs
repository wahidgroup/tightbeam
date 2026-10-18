//! The CMS types the crate defines itself, and the authenticated envelope
//! that seals a content to one recipient.
//!
//! The `cms` crate holds every other CMS type. It lacks `AuthEnvelopedData`
//! (RFC 5083), `KEMRecipientInfo` and `CMSORIforKEMOtherInfo` (RFC 9629), and
//! `GCMParameters` (RFC 5084), so the crate defines each once with `der`
//! derives, field by field against the ASN.1 module of its RFC.
//!
//! ## The envelope
//!
//! [`AuthEnvelopedData::seal`] seals a content, and [`AuthEnvelopedData::open`]
//! opens it, each under the algorithms of a `CryptoProvider`. The house
//! provider runs AES-256-GCM, HKDF-SHA3-256, AES-256 key wrap, and
//! DHKEM(secp256k1, HKDF-SHA256), and an implementor brings its own of each:
//!
//! - Each seal draws a random content key of the cipher's size and a random nonce.
//! - The cipher's [`ContentEncryption`] parameters name the nonce, such as
//!   `GCMParameters` (RFC 5084 §3.2), and the tag travels in `mac`.
//! - The authenticated attributes carry the content type. Their DER under the
//!   universal `SET OF` tag is the associated data (RFC 5083 §2.2).
//! - An opener refuses authenticated attributes that did not arrive in DER (RFC 5083 §2.1).
//!
//! ## Recipients
//!
//! A [`Recipient`] wraps the content key, and an [`Opener`] unwraps it. Both
//! wrap with the provider's key wrap under a key-encryption key (KEK) of its
//! size, and each has two kinds:
//!
//! - `Kem` writes a `KEMRecipientInfo` (RFC 9629 §3) in an `ori` of type `id-ori-kem`.
//! - `Kek` writes a `KEKRecipientInfo` (RFC 5652 §6.2.3) under a key both ends hold.
//!
//! A `Kem` recipient runs the provider's [`RecipientKem`]. Its shared secret
//! derives the KEK alone, under the provider's KDF (RFC 9629 §7):
//!
//! ```text
//! KEK = KDF(IKM = shared secret, salt = "", info = DER(CMSORIforKEMOtherInfo), L = kekLength)
//! ```
//!
//! The `ukm` is a purpose label followed by 32 random octets that the seal
//! draws for itself, and an opener admits the label of its own purpose alone.
//!
//! ## Sources
//!
//! - [RFC 5083][rfc5083]: CMS Authenticated-Enveloped-Data Content Type.
//! - [RFC 5084][rfc5084]: AES-CCM and AES-GCM in CMS.
//! - [RFC 5652 §6.2.3][rfc5652-6.2.3]: `KEKRecipientInfo`.
//! - [RFC 9629][rfc9629]: Using KEM Algorithms in CMS.
//! - [RFC 9688 §5.1][rfc9688-5.1]: HKDF with SHA3-256.
//! - [RFC 3394][rfc3394] and [RFC 3565][rfc3565]: AES key wrap and its CMS identifiers.
//!
//! [rfc5083]: https://datatracker.ietf.org/doc/html/rfc5083
//! [rfc5084]: https://datatracker.ietf.org/doc/html/rfc5084
//! [rfc5652-6.2.3]: https://datatracker.ietf.org/doc/html/rfc5652#section-6.2.3
//! [rfc9629]: https://datatracker.ietf.org/doc/html/rfc9629
//! [rfc9688-5.1]: https://datatracker.ietf.org/doc/html/rfc9688#section-5.1
//! [rfc3394]: https://datatracker.ietf.org/doc/html/rfc3394
//! [rfc3565]: https://datatracker.ietf.org/doc/html/rfc3565

mod attributes;
mod syntax;

#[cfg(all(feature = "hpke", feature = "signature", feature = "ecdh"))]
mod envelope;
#[cfg(all(feature = "hpke", feature = "signature"))]
mod error;
#[cfg(all(feature = "hpke", feature = "signature", feature = "ecdh"))]
mod recipient;
#[cfg(all(test, feature = "hpke", feature = "signature", feature = "ecdh"))]
mod tests;

pub use attributes::AttributesExt;
pub use syntax::{AuthEnvelopedData, CmsOriForKemOtherInfo, GcmParameters, KemRecipientInfo};

#[cfg(all(feature = "hpke", feature = "signature", feature = "ecdh"))]
pub use envelope::ContentEncryption;
#[cfg(all(feature = "hpke", feature = "signature"))]
pub use error::EnvelopeError;
#[cfg(all(feature = "hpke", feature = "signature", feature = "ecdh"))]
pub use recipient::{Encapsulation, Opener, Recipient, RecipientKem};
