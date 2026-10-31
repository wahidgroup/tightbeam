//! A certificate admitted for one use and one role, with the key of that
//! use.
//!
//! ## Uses
//!
//! [`PeerCertificate::parse`] is the one parse that decides what a
//! certificate may do. [`CertificateUse`] names each use, and a certificate
//! whose `keyUsage` carries the bits of two uses is admitted for each:
//!
//! | Use | Key | `keyUsage` bit | Reader |
//! | --- | --- | --- | --- |
//! | [`Signing<P>`] | the verifying key of the signing provider `P` | `digitalSignature` | the CMS signer |
//! | [`KeyAgreement<K>`] | the recipient key of the KEM `K` | `K::USAGE` of the KEM | the KEM recipient |
//! | [`ErasedSigning`] | none: the verifier reads the SPKI | `digitalSignature` | the trust store |
//!
//! ## Roles
//!
//! The role is the key purpose of `extendedKeyUsage` that [`KeyPurposes`]
//! names for it.
//!
//! ## Keys
//!
//! The key stays inside the certificate it came from, and the `crypto` layer
//! alone reads it, through the signer and the KEM recipient. One key, one use
//! rests on distinct keys, which each pair of server identities refuses to
//! share (NIST SP 800-57 Part 1 Rev. 5 §5.2).

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::sync::Arc;

use core::fmt;
#[cfg(feature = "signature")]
use core::marker::PhantomData;

use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::ext::pkix::KeyUsages;
use crate::crypto::x509::utils::CertificateExt;
use crate::der::asn1::ObjectIdentifier;
use crate::der::oid::db::rfc5280::{ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH};
use crate::oids::KEY_PURPOSE_SIGNER;
use crate::x509::Certificate;

#[cfg(feature = "signature")]
use crate::crypto::profiles::SigningProvider;
#[cfg(feature = "signature")]
use crate::crypto::x509::key::Sec1Point;
#[cfg(feature = "signature")]
use crate::der::referenced::OwnedToRef;
#[cfg(feature = "signature")]
use crate::spki::SubjectPublicKeyInfoRef;

#[cfg(all(feature = "hpke", feature = "signature"))]
use crate::crypto::cms::RecipientKem;
#[cfg(feature = "signature")]
use crate::der::oid::db::rfc5912::ID_EC_PUBLIC_KEY;
#[cfg(feature = "transport-cms")]
use crate::spki::SubjectPublicKeyInfoOwned;

mod sealed {
	pub trait Sealed {}
}

/// A use a certificate is admitted for: the key it carries, the `keyUsage`
/// bit it requires, and the one parse of both.
///
/// The trait is sealed, so [`Signing`], [`KeyAgreement`], and
/// [`ErasedSigning`] are the uses, and each parse runs the checks of
/// [`CertificateExt::require_use`] before it reads the key.
pub trait CertificateUse: sealed::Sealed {
	/// The key a certificate admitted for this use carries.
	type Key;

	/// The `keyUsage` bit this use requires (RFC 5280 §4.2.1.3).
	const USAGE: KeyUsages;

	/// Refuse `certificate` for this use through
	/// [`CertificateExt::require_use`], then parse its SPKI as [`Self::Key`].
	///
	/// # Errors
	///
	/// - The [`CertificateExt::require_use`] set.
	/// - [`CertificateValidationError::SpkiError`] -- the SPKI is no key of this use.
	fn parse_key(certificate: &Certificate) -> Result<Self::Key, CertificateValidationError>;
}

/// The signing use under the signature of `P`: the certificate's key
/// verifies a CMS `SignerInfo` of `P` (RFC 5652 §5.4).
///
/// The parse of `P::VerifyingKey` MUST refuse two kinds of key, so each key
/// this use admits is a point of the curve it names:
///
/// - A key whose parameters name a curve other than the curve of `P`.
/// - A point off the curve of `P` (SEC 1 v2.0 §2.3.4).
///
/// The house providers refuse both.
#[cfg(feature = "signature")]
pub struct Signing<P>(PhantomData<fn() -> P>);

#[cfg(feature = "signature")]
impl<P> sealed::Sealed for Signing<P> {}

#[cfg(feature = "signature")]
impl<P> CertificateUse for Signing<P>
where
	P: SigningProvider,
	P::VerifyingKey: for<'a> TryFrom<SubjectPublicKeyInfoRef<'a>, Error = crate::spki::Error>,
{
	type Key = P::VerifyingKey;
	const USAGE: KeyUsages = KeyUsages::DigitalSignature;

	fn parse_key(certificate: &Certificate) -> Result<P::VerifyingKey, CertificateValidationError> {
		certificate.require_use(Self::USAGE)?;
		let spki = certificate.tbs_certificate.subject_public_key_info.owned_to_ref();
		spki.require_point_form()?;
		Ok(P::VerifyingKey::try_from(spki)?)
	}
}

/// The key-agreement use under the KEM `K`: a sender encapsulates to the
/// certificate's key (RFC 9629 §3).
///
/// - The certificate asserts the bit of the KEM's certificate profile,
///   [`RecipientKem::USAGE`]: `keyAgreement` for a DHKEM (RFC 5480 §3), and
///   `keyEncipherment` for ML-KEM (RFC 9935 §5).
/// - The parse refuses an `id-ecPublicKey` point in a form that RFC 5480 §2.2
///   refuses before the KEM reads the key, so the rule holds for every KEM.
#[cfg(all(feature = "hpke", feature = "signature"))]
pub struct KeyAgreement<K>(PhantomData<fn() -> K>);

#[cfg(all(feature = "hpke", feature = "signature"))]
impl<K> sealed::Sealed for KeyAgreement<K> {}

#[cfg(all(feature = "hpke", feature = "signature"))]
impl<K: RecipientKem> CertificateUse for KeyAgreement<K> {
	type Key = K::PublicKey;
	const USAGE: KeyUsages = K::USAGE;

	fn parse_key(certificate: &Certificate) -> Result<K::PublicKey, CertificateValidationError> {
		certificate.require_use(Self::USAGE)?;
		let spki = certificate.tbs_certificate.subject_public_key_info.owned_to_ref();
		spki.require_point_form()?;
		K::public_key(spki)
	}
}

/// The signing use with the provider erased, for a verifier that holds a
/// policy in place of a provider type, as a trust store does.
///
/// The parse runs the use's checks alone, and the verifier reads the SPKI
/// from the certificate under its policy at each verify.
#[derive(Debug)]
pub enum ErasedSigning {}

impl sealed::Sealed for ErasedSigning {}

impl CertificateUse for ErasedSigning {
	type Key = ();
	const USAGE: KeyUsages = KeyUsages::DigitalSignature;

	fn parse_key(certificate: &Certificate) -> Result<(), CertificateValidationError> {
		certificate.require_use(Self::USAGE)
	}
}

/// A certificate admitted for the use `U`, with the key of that use parsed
/// once.
///
/// [`Self::parse`] admits a peer's certificate for a role, and an own
/// identity's certificate is admitted for its use where the identity is
/// built. The type that performs the use reads the key: the signer a signing
/// key, and the KEM recipient a recipient key.
pub struct PeerCertificate<U: CertificateUse> {
	certificate: Arc<Certificate>,
	/// The key of the use, which the type that performs the use reads.
	pub(in crate::crypto) key: U::Key,
}

impl<U: CertificateUse> PeerCertificate<U> {
	/// Admit `certificate` for the use `U` in the role whose key purpose is
	/// `purpose`, and parse its key. [`KeyPurposes`] names the purpose of each
	/// role.
	///
	/// `certificate` accepts an owned certificate or a handle to a shared one.
	///
	/// # Errors
	///
	/// - The [`CertificateUse::parse_key`] set of `U`.
	/// - The [`CertificateExt::require_purpose`] set.
	pub fn parse(
		certificate: impl Into<Arc<Certificate>>,
		purpose: ObjectIdentifier,
	) -> Result<Self, CertificateValidationError> {
		let admitted = Self::own(certificate)?;
		admitted.certificate.require_purpose(purpose)?;
		Ok(admitted)
	}

	/// Admit the certificate of an own identity for the use `U`, and parse
	/// its key. The configuration that installs the identity checks the
	/// purpose of its role.
	///
	/// # Errors
	///
	/// - The [`CertificateUse::parse_key`] set of `U`.
	pub(in crate::crypto) fn own(certificate: impl Into<Arc<Certificate>>) -> Result<Self, CertificateValidationError> {
		let certificate = certificate.into();
		let key = U::parse_key(&certificate)?;
		Ok(Self { certificate, key })
	}

	/// The certificate the use admitted.
	pub fn certificate(&self) -> &Arc<Certificate> {
		&self.certificate
	}
}

impl<U: CertificateUse<Key: Clone>> Clone for PeerCertificate<U> {
	fn clone(&self) -> Self {
		Self { certificate: Arc::clone(&self.certificate), key: self.key.clone() }
	}
}

/// Two admissions are equal when they admitted one certificate, whose key
/// they parsed alike.
impl<U: CertificateUse<Key: PartialEq>> PartialEq for PeerCertificate<U> {
	fn eq(&self, other: &Self) -> bool {
		self.certificate == other.certificate && self.key == other.key
	}
}

impl<U: CertificateUse<Key: Eq>> Eq for PeerCertificate<U> {}

/// The subject names the certificate, and the key stays out of the output.
impl<U: CertificateUse> fmt::Debug for PeerCertificate<U> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("PeerCertificate")
			.field("subject", &self.certificate.tbs_certificate.subject)
			.finish_non_exhaustive()
	}
}

/// The key purpose of `extendedKeyUsage` each role of a tightbeam
/// certificate admits (RFC 5280 §4.2.1.12), the one home of that mapping.
///
/// A role also admits `anyExtendedKeyUsage`, and a certificate with no
/// `extendedKeyUsage` serves every role. [`Default`] is [`Self::HOUSE`], and
/// an implementor sets its own through the trust and the server
/// configuration that admit each role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPurposes {
	/// The purpose of a server's signing and key-agreement certificates.
	pub server: ObjectIdentifier,
	/// The purpose of a client's certificate.
	pub client: ObjectIdentifier,
	/// The purpose of a frame and colony signer's certificate.
	pub signer: ObjectIdentifier,
}

impl KeyPurposes {
	/// The house purposes: `id-kp-serverAuth` for a server, `id-kp-clientAuth`
	/// for a client, and [`KEY_PURPOSE_SIGNER`] for a frame signer.
	pub const HOUSE: Self = Self { server: ID_KP_SERVER_AUTH, client: ID_KP_CLIENT_AUTH, signer: KEY_PURPOSE_SIGNER };
}

impl Default for KeyPurposes {
	fn default() -> Self {
		Self::HOUSE
	}
}

/// The SEC 1 point of an `id-ecPublicKey` SubjectPublicKeyInfo, whose first
/// octet names its form (RFC 5480 §2.2, SEC 1 v2.0 §2.3.3).
#[cfg(feature = "signature")]
pub(crate) trait EllipticCurvePoint {
	/// The x-coordinate of an `id-ecPublicKey` key, read from its compressed
	/// or uncompressed point, or `None` for a key of another algorithm. It is
	/// the coordinate an ECDH agreement keeps (SEC 1 v2.0 §3.3.1), read here
	/// where no curve type is named.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::SpkiError`] -- the first octet of the
	///   point is not `0x02`, `0x03`, or `0x04`, which RFC 5480 §2.2 refuses,
	///   or an uncompressed point holds no two coordinates of one length.
	fn elliptic_curve_x(&self) -> Result<Option<&[u8]>, CertificateValidationError>;

	/// Refuse an `id-ecPublicKey` key whose point is in a form RFC 5480 §2.2
	/// refuses.
	///
	/// # Errors
	///
	/// - The [`Self::elliptic_curve_x`] set.
	fn require_point_form(&self) -> Result<(), CertificateValidationError> {
		self.elliptic_curve_x().map(drop)
	}
}

#[cfg(feature = "signature")]
impl EllipticCurvePoint for SubjectPublicKeyInfoRef<'_> {
	fn elliptic_curve_x(&self) -> Result<Option<&[u8]>, CertificateValidationError> {
		if self.algorithm.oid != ID_EC_PUBLIC_KEY {
			return Ok(None);
		}

		let point = self.subject_public_key.as_bytes().ok_or(crate::spki::Error::KeyMalformed)?;
		let point = Sec1Point::read(point).ok_or(crate::spki::Error::KeyMalformed)?;
		Ok(Some(point.x()))
	}
}

/// The key a SubjectPublicKeyInfo holds, compared as an agreement compares
/// it, for a refusal of one key in two certificates.
#[cfg(feature = "transport-cms")]
pub(crate) trait SubjectKey {
	/// Whether this key and `other` are one key: for two elliptic-curve keys,
	/// one curve and one x-coordinate in either SEC 1 encoding, as an ECDH
	/// agreement reads a point, and for any other key, one
	/// SubjectPublicKeyInfo.
	fn same_key(&self, other: &Self) -> bool;
}

#[cfg(feature = "transport-cms")]
impl SubjectKey for SubjectPublicKeyInfoOwned {
	fn same_key(&self, other: &Self) -> bool {
		let own = self.owned_to_ref();
		let theirs = other.owned_to_ref();
		match (own.elliptic_curve_x(), theirs.elliptic_curve_x()) {
			(Ok(Some(own_x)), Ok(Some(their_x))) => self.algorithm == other.algorithm && own_x == their_x,
			_ => self == other,
		}
	}
}

#[cfg(all(test, feature = "transport-cms"))]
mod tests {
	use crate::crypto::hpke::DhKemSecp256k1;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::x509::error::CertificateValidationError::{DuplicateExtension, UnprocessedCriticalExtension};
	use crate::crypto::x509::fixtures::{parse, Parse, Refusal};
	use crate::der::flagset::FlagSet;
	use crate::der::oid::db::rfc5280::{
		ANY_EXTENDED_KEY_USAGE, ID_CE_NAME_CONSTRAINTS, ID_KP_EMAIL_PROTECTION, ID_KP_TIME_STAMPING,
	};
	use crate::oids::{CURVE_NIST_P256, CURVE_SECP256K1};
	use crate::testing::{TestCertificate, TestKey, TestResult};
	use crate::x509::ext::pkix::KeyUsage;

	use super::*;

	/// The signing use under the house provider.
	type HouseSigning = Signing<DefaultCryptoProvider>;

	/// The key-agreement use under the house KEM.
	type HouseAgreement = KeyAgreement<DhKemSecp256k1>;

	/// The house purpose of a server.
	const SERVER: ObjectIdentifier = KeyPurposes::HOUSE.server;

	/// The house purpose of a client.
	const CLIENT: ObjectIdentifier = KeyPurposes::HOUSE.client;

	/// The house purpose of a frame signer.
	const SIGNER: ObjectIdentifier = KeyPurposes::HOUSE.signer;

	/// The tightbeam signer purpose, named by its number under the crate's
	/// arc.
	const TIGHTBEAM_SIGNER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.3.1");

	/// A purpose that an implementor names under its own arc.
	const OWN_PURPOSE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.1");

	/// The fixed test certificate with `usages` as the bits of its `keyUsage`.
	fn with_usages(usages: impl Into<FlagSet<KeyUsages>>) -> Certificate {
		TestCertificate::with_key_usage(TestCertificate::insecure_fixed(), KeyUsage(usages.into()))
	}

	/// The fixed test certificate with an `extendedKeyUsage` that names
	/// `purposes` alone.
	fn with_purposes(purposes: impl IntoIterator<Item = ObjectIdentifier>) -> Certificate {
		TestCertificate::with_key_purposes(TestCertificate::insecure_fixed(), purposes)
	}

	// The parse admits a certificate for a use whose `keyUsage` bit it
	// carries, in a role whose purpose its `extendedKeyUsage` names. A
	// certificate with no `extendedKeyUsage` serves every role.
	crate::tb_cases! {
		fn the_parse_admits((parse, certificate, role): (Parse, Certificate, ObjectIdentifier)) -> TestResult {
			parse(certificate, role)?;
			Ok(())
		}
		cases {
			a_certificate_with_both_bits_for_signing => (
				parse::<HouseSigning>,
				TestCertificate::insecure_fixed(),
				SERVER,
			),
			a_certificate_with_both_bits_for_key_agreement => (
				parse::<HouseAgreement>,
				TestCertificate::insecure_fixed(),
				SERVER,
			),
			a_certificate_with_both_bits_for_erased_signing => (
				parse::<ErasedSigning>,
				TestCertificate::insecure_fixed(),
				SIGNER,
			),
			/// `encipherOnly` beside `keyAgreement` leaves the key for
			/// enciphering, which a sender does (RFC 5480 §3).
			an_encipher_only_certificate_for_key_agreement => (
				parse::<HouseAgreement>,
				with_usages(KeyUsages::KeyAgreement | KeyUsages::EncipherOnly),
				SERVER,
			),
			/// `decipherOnly` restricts the key-agreement use alone, so a
			/// certificate of both bits that asserts it serves the signing use
			/// (RFC 5280 §4.2.1.3).
			a_decipher_only_certificate_for_signing => (
				parse::<HouseSigning>,
				with_usages(KeyUsages::DigitalSignature | KeyUsages::KeyAgreement | KeyUsages::DecipherOnly),
				SERVER,
			),
			a_server_certificate_for_the_server_role => (parse::<HouseSigning>, with_purposes([SERVER]), SERVER),
			a_server_certificate_for_the_server_key_agreement => (
				parse::<HouseAgreement>,
				with_purposes([SERVER]),
				SERVER,
			),
			a_client_certificate_for_the_client_role => (parse::<HouseSigning>, with_purposes([CLIENT]), CLIENT),
			a_signer_certificate_for_the_signer_role => (parse::<ErasedSigning>, with_purposes([SIGNER]), SIGNER),
			/// The house server role admits `id-kp-serverAuth`, named here by
			/// the OID database of RFC 5280.
			a_server_auth_certificate_for_the_house_server_role => (
				parse::<HouseSigning>,
				with_purposes([ID_KP_SERVER_AUTH]),
				KeyPurposes::HOUSE.server,
			),
			/// The house client role admits `id-kp-clientAuth`, named here by
			/// the OID database of RFC 5280.
			a_client_auth_certificate_for_the_house_client_role => (
				parse::<HouseSigning>,
				with_purposes([ID_KP_CLIENT_AUTH]),
				KeyPurposes::HOUSE.client,
			),
			/// The house signer role admits the tightbeam signer purpose, named
			/// here by its number under the crate's arc.
			a_tightbeam_signer_certificate_for_the_house_signer_role => (
				parse::<ErasedSigning>,
				with_purposes([TIGHTBEAM_SIGNER]),
				KeyPurposes::HOUSE.signer,
			),
			/// `anyExtendedKeyUsage` admits every role (RFC 5280 §4.2.1.12).
			any_extended_key_usage_for_the_client_role => (
				parse::<HouseSigning>,
				with_purposes([ANY_EXTENDED_KEY_USAGE]),
				CLIENT,
			),
			/// A certificate that names two roles serves each of them.
			a_certificate_of_two_roles_for_the_second => (
				parse::<HouseSigning>,
				with_purposes([SERVER, CLIENT]),
				CLIENT,
			),
			/// A certificate of an implementor's own purpose is admitted for
			/// the role read under that purpose.
			an_own_purpose_for_its_role => (parse::<HouseSigning>, with_purposes([OWN_PURPOSE]), OWN_PURPOSE),
		}
	}

	// The parse refuses a certificate for a use whose `keyUsage` bit it lacks,
	// for a role its `extendedKeyUsage` omits, for an extension that breaks
	// RFC 5280 §4.2, and for a key that is no point of the use's curve. Each
	// row names the refusal with its payload.
	crate::tb_cases! {
		fn the_parse_refuses((parse, certificate, role, refusal): (Parse, Certificate, ObjectIdentifier, Refusal)) {
			let refused = parse(certificate, role);
			assert!(matches!(refused, Err(ref error) if refusal(error)));
		}
		cases {
			a_key_agreement_certificate_for_signing => (
				parse::<HouseSigning>,
				with_usages(KeyUsages::KeyAgreement),
				SERVER,
				|e| matches!(e, CertificateValidationError::MissingKeyUsage(KeyUsages::DigitalSignature)),
			),
			a_key_agreement_certificate_for_erased_signing => (
				parse::<ErasedSigning>,
				with_usages(KeyUsages::KeyAgreement),
				SIGNER,
				|e| matches!(e, CertificateValidationError::MissingKeyUsage(KeyUsages::DigitalSignature)),
			),
			a_signing_certificate_for_key_agreement => (
				parse::<HouseAgreement>,
				with_usages(KeyUsages::DigitalSignature),
				SERVER,
				|e| matches!(e, CertificateValidationError::MissingKeyUsage(KeyUsages::KeyAgreement)),
			),
			/// `decipherOnly` beside `keyAgreement` restricts the key to
			/// deciphering, so the key a sender enciphers to is refused
			/// (RFC 5280 §4.2.1.3).
			a_decipher_only_certificate_for_key_agreement => (
				parse::<HouseAgreement>,
				with_usages(KeyUsages::KeyAgreement | KeyUsages::DecipherOnly),
				SERVER,
				|e| matches!(e, CertificateValidationError::ExcludedKeyUsage(KeyUsages::DecipherOnly)),
			),
			/// A client's certificate names a purpose of the client role alone,
			/// so the server role refuses it (RFC 5280 §4.2.1.12).
			a_client_certificate_for_the_server_role => (
				parse::<HouseSigning>,
				with_purposes([CLIENT]),
				SERVER,
				|e| matches!(e, CertificateValidationError::ExcludedKeyPurpose),
			),
			a_client_certificate_for_the_server_key_agreement => (
				parse::<HouseAgreement>,
				with_purposes([CLIENT]),
				SERVER,
				|e| matches!(e, CertificateValidationError::ExcludedKeyPurpose),
			),
			a_server_certificate_for_the_client_role => (
				parse::<HouseSigning>,
				with_purposes([SERVER]),
				CLIENT,
				|e| matches!(e, CertificateValidationError::ExcludedKeyPurpose),
			),
			a_server_certificate_for_the_signer_role => (
				parse::<ErasedSigning>,
				with_purposes([SERVER]),
				SIGNER,
				|e| matches!(e, CertificateValidationError::ExcludedKeyPurpose),
			),
			a_signer_certificate_for_the_server_role => (
				parse::<HouseSigning>,
				with_purposes([SIGNER]),
				SERVER,
				|e| matches!(e, CertificateValidationError::ExcludedKeyPurpose),
			),
			/// `id-kp-emailProtection` names S/MIME, so the client role refuses
			/// it.
			an_email_protection_certificate_for_the_client_role => (
				parse::<HouseSigning>,
				with_purposes([ID_KP_EMAIL_PROTECTION]),
				CLIENT,
				|e| matches!(e, CertificateValidationError::ExcludedKeyPurpose),
			),
			/// A certificate whose `extendedKeyUsage` names
			/// `id-kp-timeStamping` alone serves time stamping alone, so the
			/// server's key agreement refuses it.
			a_certificate_of_another_purpose_for_key_agreement => (
				parse::<HouseAgreement>,
				with_purposes([ID_KP_TIME_STAMPING]),
				SERVER,
				|e| matches!(e, CertificateValidationError::ExcludedKeyPurpose),
			),
			/// A certificate that repeats an extension is refused for every use
			/// (RFC 5280 §4.2).
			a_certificate_that_repeats_an_extension_for_signing => (
				parse::<HouseSigning>,
				TestCertificate::with_repeated_extension(TestCertificate::insecure_fixed(), "2.5.29.30"),
				SERVER,
				|e| matches!(e, DuplicateExtension(oid) if *oid == ID_CE_NAME_CONSTRAINTS),
			),
			/// A certificate with a critical extension the crate does not
			/// process is refused for every use (RFC 5280 §4.2).
			a_certificate_with_an_unknown_critical_extension_for_erased_signing => (
				parse::<ErasedSigning>,
				TestCertificate::with_unknown_critical_extension(TestCertificate::insecure_fixed()),
				SIGNER,
				|e| matches!(e, UnprocessedCriticalExtension(oid) if *oid == ID_CE_NAME_CONSTRAINTS),
			),
			/// The signing use parses the SPKI as the provider's verifying key,
			/// which names its curve, so a key under another curve's OID is
			/// refused.
			a_key_on_another_curve_for_signing => (
				parse::<HouseSigning>,
				TestCertificate::with_named_curve(TestCertificate::insecure_fixed(), CURVE_NIST_P256),
				SERVER,
				|e| matches!(e, CertificateValidationError::SpkiError(_)),
			),
			/// The key-agreement use parses the SPKI as the KEM's recipient
			/// key, which names its curve, so a key under another curve's OID
			/// is refused.
			a_key_on_another_curve_for_key_agreement => (
				parse::<HouseAgreement>,
				TestCertificate::with_named_curve(TestCertificate::insecure_fixed(), CURVE_NIST_P256),
				SERVER,
				|e| matches!(e, CertificateValidationError::SpkiError(_)),
			),
			/// Bits that are no point of the curve the SPKI names are refused
			/// for signing.
			a_key_off_the_curve_for_signing => (
				parse::<HouseSigning>,
				TestCertificate::with_curve_point(TestCertificate::insecure_fixed(), CURVE_SECP256K1, &[0x04; 65]),
				SERVER,
				|e| matches!(e, CertificateValidationError::SpkiError(_)),
			),
			a_key_off_the_curve_for_key_agreement => (
				parse::<HouseAgreement>,
				TestCertificate::with_curve_point(TestCertificate::insecure_fixed(), CURVE_SECP256K1, &[0x04; 65]),
				SERVER,
				|e| matches!(e, CertificateValidationError::SpkiError(_)),
			),
			/// The compact twin of the signing key would decompact to a point
			/// that agrees as the signing key does, so the key-agreement use
			/// refuses its form (RFC 5480 §2.2).
			a_compact_twin_of_the_signing_key_for_key_agreement => (
				parse::<HouseAgreement>,
				TestCertificate::with_compact_key(TestCertificate::insecure_fixed()),
				SERVER,
				|e| matches!(e, CertificateValidationError::SpkiError(_)),
			),
			a_compact_signing_key_for_signing => (
				parse::<HouseSigning>,
				TestCertificate::with_compact_key(TestCertificate::insecure_fixed()),
				SERVER,
				|e| matches!(e, CertificateValidationError::SpkiError(_)),
			),
		}
	}

	/// The house KEM's certificate profile asserts `keyAgreement`, the bit
	/// the key-agreement use reads.
	#[test]
	fn the_key_agreement_use_reads_the_bit_of_its_kem() {
		assert_eq!(HouseAgreement::USAGE, KeyUsages::KeyAgreement);
	}

	/// An uncompressed point whose two halves differ in length holds no x and
	/// y of one field, so its form is refused.
	#[test]
	fn an_uncompressed_point_of_uneven_halves_fails_the_point_form() {
		let fixed = TestCertificate::insecure_fixed();
		let point = fixed.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
		let uneven = [point, &[0][..]].concat();
		let certificate = TestCertificate::with_curve_point(fixed, CURVE_SECP256K1, &uneven);
		let spki = certificate.tbs_certificate.subject_public_key_info;

		let refused = spki.owned_to_ref().require_point_form();
		assert!(matches!(refused, Err(CertificateValidationError::SpkiError(_))));
	}

	// An agreement reads a point by its curve and its x-coordinate, so the
	// fixed key is one key with each SEC 1 form of its point and with its
	// negation, and another key on another curve or at another point.
	crate::tb_cases! {
		fn the_fixed_key((other, same): (Certificate, bool)) {
			let own = TestCertificate::insecure_fixed().tbs_certificate.subject_public_key_info;

			let compared = own.same_key(&other.tbs_certificate.subject_public_key_info);
			assert_eq!(compared, same);
		}
		cases {
			/// One point in its compressed and its uncompressed SEC 1 encoding
			/// is one key.
			is_one_key_with_its_compressed_twin => (
				TestCertificate::with_compressed_key(TestCertificate::insecure_fixed()),
				true,
			),
			/// A point and its negation agree alike, so they are one key.
			is_one_key_with_its_negation => (TestCertificate::insecure_fixed_negation(), true),
			/// One x-coordinate on two curves names two points.
			is_another_key_on_another_curve => (
				TestCertificate::with_named_curve(TestCertificate::insecure_fixed(), CURVE_NIST_P256),
				false,
			),
			/// A seeded key other than the fixed one holds another point.
			is_another_key_than_another_point => (TestCertificate::self_signed(&TestKey::fixed(0x0b)), false),
		}
	}
}
