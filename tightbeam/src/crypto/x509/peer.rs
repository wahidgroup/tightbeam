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

#[cfg(all(feature = "signature", feature = "ecdh"))]
mod agreement {
	pub use crate::crypto::profiles::CurveProvider;
	pub use crate::crypto::sign::elliptic_curve::point::AffineCoordinates;
	pub use crate::crypto::sign::elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytes, PublicKey};
}

#[cfg(all(feature = "signature", feature = "ecdh"))]
use agreement::*;

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

#[cfg(all(feature = "signature", feature = "ecdh"))]
impl<P> PeerCertificate<Signing<P>>
where
	P: SigningProvider + CurveProvider,
	P::VerifyingKey: for<'a> TryFrom<SubjectPublicKeyInfoRef<'a>, Error = crate::spki::Error>,
	P::VerifyingKey: AsRef<AffinePoint<P::Curve>>,
{
	/// Whether an ECDH agreement with `point` differs from one with this
	/// certificate's key, as a point on the curve of `P`.
	///
	/// A peer's agreement ephemeral MUST be distinct from its static key, so
	/// the agreement keeps the forward secrecy of two ephemerals.
	pub fn distinct(&self, point: &PublicKey<P::Curve>) -> bool {
		!self.shares_x(&point.as_affine().x())
	}

	/// Whether an agreement with this certificate's key equals one with a
	/// point whose x-coordinate is `x`, so a check of one point against
	/// more than one key reads its x-coordinate once.
	pub(crate) fn shares_x(&self, x: &FieldBytes<P::Curve>) -> bool {
		AgreementPoint::<P::Curve>::shares_x(&self.key, x)
	}
}

/// The rule of an ECDH agreement over a point: the agreement keeps the
/// x-coordinate of the product alone (SEC 1 v2.0 §3.3.1), so a point and its
/// negation agree alike.
#[cfg(all(feature = "signature", feature = "ecdh"))]
pub(crate) trait AgreementPoint<C: CurveArithmetic> {
	/// Whether an agreement with this point equals one with a point whose
	/// x-coordinate is `x`.
	fn shares_x(&self, x: &FieldBytes<C>) -> bool;
}

/// A key is a point by reference. The comparison reads the key's
/// x-coordinate as a field element on the stack.
#[cfg(all(feature = "signature", feature = "ecdh"))]
impl<C, T> AgreementPoint<C> for T
where
	C: CurveArithmetic,
	T: AsRef<AffinePoint<C>> + ?Sized,
{
	fn shares_x(&self, x: &FieldBytes<C>) -> bool {
		self.as_ref().x() == *x
	}
}

/// The SEC 1 point of an `id-ecPublicKey` SubjectPublicKeyInfo, whose first
/// octet names its form (RFC 5480 §2.2, SEC 1 v2.0 §2.3.3).
#[cfg(feature = "signature")]
pub(crate) trait EllipticCurvePoint {
	/// The x-coordinate of an `id-ecPublicKey` key, read from its compressed
	/// or uncompressed point, or `None` for a key of another algorithm. It is
	/// the coordinate `AgreementPoint::shares_x` reads from a parsed point,
	/// read here where no curve type is named.
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
	/// one curve and one x-coordinate in either SEC 1 encoding, as
	/// [`AgreementPoint`] reads a point, and for any other key, one
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
	use super::*;
	use crate::crypto::hpke::DhKemSecp256k1;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::ecdsa::k256::{Secp256k1, SecretKey};
	use crate::crypto::sign::elliptic_curve::sec1::ToEncodedPoint;
	use crate::crypto::sign::elliptic_curve::ALGORITHM_OID as EC_PUBLIC_KEY;
	use crate::der::asn1::{BitString, ObjectIdentifier};
	use crate::der::oid::db::rfc5280::{ANY_EXTENDED_KEY_USAGE, ID_KP_EMAIL_PROTECTION, ID_KP_TIME_STAMPING};
	use crate::der::Any;
	use crate::oids::{CURVE_NIST_P256, CURVE_SECP256K1};
	use crate::random::OsRng;
	use crate::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
	use crate::testing::{TestCertificate, TestKey};
	use crate::x509::ext::pkix::KeyUsage;

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

	/// A placeholder-signed certificate of the fixed test key, whose
	/// `keyUsage` carries `digitalSignature` and `keyAgreement`.
	fn both_uses() -> Certificate {
		TestCertificate::self_signed(&TestKey::insecure_fixed_signing())
	}

	/// [`both_uses`] with `usage` as the one bit of its `keyUsage`.
	fn only(usage: KeyUsages) -> Certificate {
		TestCertificate::with_key_usage(both_uses(), KeyUsage(usage.into()))
	}

	/// [`both_uses`] with `extendedKeyUsage` naming `purposes` alone.
	fn with_purposes(purposes: Vec<ObjectIdentifier>) -> Certificate {
		TestCertificate::with_key_purposes(both_uses(), purposes)
	}

	/// [`both_uses`] with an `id-ecPublicKey` SPKI on the curve `curve` whose
	/// bits are `point`.
	fn with_key(curve: ObjectIdentifier, point: &[u8]) -> Certificate {
		let named_curve = Any::encode_from(&curve).expect("a curve OID encodes");
		let algorithm = AlgorithmIdentifierOwned { oid: EC_PUBLIC_KEY, parameters: Some(named_curve) };
		let subject_public_key = BitString::from_bytes(point).expect("a point is a BIT STRING");

		let mut certificate = both_uses();
		let spki = SubjectPublicKeyInfoOwned { algorithm, subject_public_key };
		certificate.tbs_certificate.subject_public_key_info = spki;
		certificate
	}

	/// The SubjectPublicKeyInfo of [`with_key`].
	fn key_info(curve: ObjectIdentifier, point: &[u8]) -> SubjectPublicKeyInfoOwned {
		with_key(curve, point).tbs_certificate.subject_public_key_info
	}

	/// [`both_uses`] under the P-256 OID over the bits of its own secp256k1
	/// point, so the curve OID alone is foreign.
	fn on_another_curve() -> Certificate {
		let point = fixed_point().to_encoded_point(false);
		with_key(CURVE_NIST_P256, point.as_bytes())
	}

	/// [`both_uses`] under the secp256k1 OID over bits that are no point of
	/// the curve.
	fn off_the_curve() -> Certificate {
		with_key(CURVE_SECP256K1, &[0x04; 65])
	}

	/// [`both_uses`] over the SEC 1 compact form of [`fixed_point`]: `0x05`
	/// and its x-coordinate, a form RFC 5480 §2.2 refuses.
	fn compact_twin() -> Certificate {
		let point = fixed_point().to_encoded_point(false);
		let x = point.x().expect("an uncompressed point has an x-coordinate");
		let compact = [&[0x05][..], x.as_slice()].concat();
		with_key(CURVE_SECP256K1, &compact)
	}

	/// The fixed test key as a point of secp256k1.
	fn fixed_point() -> PublicKey<Secp256k1> {
		PublicKey::from(TestKey::insecure_fixed_signing().verifying_key())
	}

	/// The negation of [`fixed_point`], which shares its x-coordinate.
	fn negated_fixed_point() -> PublicKey<Secp256k1> {
		let negation = PublicKey::<Secp256k1>::from_affine(-*fixed_point().as_affine());
		negation.expect("the negation of a public key is a public key")
	}

	#[test]
	fn a_certificate_with_both_bits_is_admitted_for_signing() {
		assert!(PeerCertificate::<HouseSigning>::parse(both_uses(), SERVER).is_ok());
	}

	#[test]
	fn a_certificate_with_both_bits_is_admitted_for_key_agreement() {
		assert!(PeerCertificate::<HouseAgreement>::parse(both_uses(), SERVER).is_ok());
	}

	#[test]
	fn a_certificate_with_both_bits_is_admitted_for_erased_signing() {
		assert!(PeerCertificate::<ErasedSigning>::parse(both_uses(), SIGNER).is_ok());
	}

	#[test]
	fn a_key_agreement_certificate_is_refused_for_signing() {
		let refused = PeerCertificate::<HouseSigning>::parse(only(KeyUsages::KeyAgreement), SERVER);
		assert!(matches!(
			refused,
			Err(CertificateValidationError::MissingKeyUsage(KeyUsages::DigitalSignature))
		));
	}

	#[test]
	fn a_key_agreement_certificate_is_refused_for_erased_signing() {
		let refused = PeerCertificate::<ErasedSigning>::parse(only(KeyUsages::KeyAgreement), SIGNER);
		assert!(matches!(
			refused,
			Err(CertificateValidationError::MissingKeyUsage(KeyUsages::DigitalSignature))
		));
	}

	#[test]
	fn a_signing_certificate_is_refused_for_key_agreement() {
		let refused = PeerCertificate::<HouseAgreement>::parse(only(KeyUsages::DigitalSignature), SERVER);
		assert!(matches!(
			refused,
			Err(CertificateValidationError::MissingKeyUsage(KeyUsages::KeyAgreement))
		));
	}

	/// `decipherOnly` beside `keyAgreement` restricts the key to deciphering,
	/// so the key a sender enciphers to is refused (RFC 5280 §4.2.1.3).
	#[test]
	fn a_decipher_only_certificate_is_refused_for_key_agreement() {
		let usage = KeyUsage(KeyUsages::KeyAgreement | KeyUsages::DecipherOnly);
		let certificate = TestCertificate::with_key_usage(both_uses(), usage);
		let refused = PeerCertificate::<HouseAgreement>::parse(certificate, SERVER);
		assert!(matches!(
			refused,
			Err(CertificateValidationError::ExcludedKeyUsage(KeyUsages::DecipherOnly))
		));
	}

	/// `encipherOnly` beside `keyAgreement` leaves the key for enciphering,
	/// which a sender does (RFC 5480 §3).
	#[test]
	fn an_encipher_only_certificate_is_admitted_for_key_agreement() {
		let usage = KeyUsage(KeyUsages::KeyAgreement | KeyUsages::EncipherOnly);
		let certificate = TestCertificate::with_key_usage(both_uses(), usage);
		assert!(PeerCertificate::<HouseAgreement>::parse(certificate, SERVER).is_ok());
	}

	/// `decipherOnly` restricts the key-agreement use alone, so a certificate
	/// of both bits that asserts it serves the signing use (RFC 5280
	/// §4.2.1.3).
	#[test]
	fn a_decipher_only_certificate_is_admitted_for_signing() {
		let usage = KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyAgreement | KeyUsages::DecipherOnly);
		let certificate = TestCertificate::with_key_usage(both_uses(), usage);
		assert!(PeerCertificate::<HouseSigning>::parse(certificate, SERVER).is_ok());
	}

	/// The house KEM's certificate profile asserts `keyAgreement`, the bit
	/// the key-agreement use reads.
	#[test]
	fn the_key_agreement_use_reads_the_bit_of_its_kem() {
		assert_eq!(HouseAgreement::USAGE, KeyUsages::KeyAgreement);
	}

	/// A client's certificate names a purpose of the client role alone, so
	/// the server role refuses it (RFC 5280 §4.2.1.12).
	#[test]
	fn a_client_certificate_is_refused_for_the_server_role() {
		let refused = PeerCertificate::<HouseSigning>::parse(with_purposes(vec![CLIENT]), SERVER);
		assert!(matches!(refused, Err(CertificateValidationError::ExcludedKeyPurpose)));
	}

	#[test]
	fn a_client_certificate_is_refused_for_the_server_key_agreement() {
		let refused = PeerCertificate::<HouseAgreement>::parse(with_purposes(vec![CLIENT]), SERVER);
		assert!(matches!(refused, Err(CertificateValidationError::ExcludedKeyPurpose)));
	}

	#[test]
	fn a_server_certificate_is_refused_for_the_client_role() {
		let refused = PeerCertificate::<HouseSigning>::parse(with_purposes(vec![SERVER]), CLIENT);
		assert!(matches!(refused, Err(CertificateValidationError::ExcludedKeyPurpose)));
	}

	#[test]
	fn a_server_certificate_is_refused_for_the_signer_role() {
		let refused = PeerCertificate::<ErasedSigning>::parse(with_purposes(vec![SERVER]), SIGNER);
		assert!(matches!(refused, Err(CertificateValidationError::ExcludedKeyPurpose)));
	}

	#[test]
	fn a_signer_certificate_is_refused_for_the_server_role() {
		let refused = PeerCertificate::<HouseSigning>::parse(with_purposes(vec![SIGNER]), SERVER);
		assert!(matches!(refused, Err(CertificateValidationError::ExcludedKeyPurpose)));
	}

	/// `id-kp-emailProtection` names S/MIME, so the client role refuses it.
	#[test]
	fn an_email_protection_certificate_is_refused_for_the_client_role() {
		let refused = PeerCertificate::<HouseSigning>::parse(with_purposes(vec![ID_KP_EMAIL_PROTECTION]), CLIENT);
		assert!(matches!(refused, Err(CertificateValidationError::ExcludedKeyPurpose)));
	}

	/// A certificate whose `extendedKeyUsage` names `id-kp-timeStamping` alone
	/// serves time stamping alone, so the server's key agreement refuses it.
	#[test]
	fn a_certificate_of_another_purpose_is_refused_for_key_agreement() {
		let refused = PeerCertificate::<HouseAgreement>::parse(with_purposes(vec![ID_KP_TIME_STAMPING]), SERVER);
		assert!(matches!(refused, Err(CertificateValidationError::ExcludedKeyPurpose)));
	}

	#[test]
	fn a_server_certificate_is_admitted_for_the_server_role() {
		assert!(PeerCertificate::<HouseSigning>::parse(with_purposes(vec![SERVER]), SERVER).is_ok());
	}

	#[test]
	fn a_server_certificate_is_admitted_for_the_server_key_agreement() {
		assert!(PeerCertificate::<HouseAgreement>::parse(with_purposes(vec![SERVER]), SERVER).is_ok());
	}

	#[test]
	fn a_client_certificate_is_admitted_for_the_client_role() {
		assert!(PeerCertificate::<HouseSigning>::parse(with_purposes(vec![CLIENT]), CLIENT).is_ok());
	}

	#[test]
	fn a_signer_certificate_is_admitted_for_the_signer_role() {
		assert!(PeerCertificate::<ErasedSigning>::parse(with_purposes(vec![SIGNER]), SIGNER).is_ok());
	}

	/// The house server role admits `id-kp-serverAuth`, named here by the
	/// OID database of RFC 5280.
	#[test]
	fn a_server_auth_certificate_is_admitted_for_the_house_server_role() {
		let certificate = with_purposes(vec![ID_KP_SERVER_AUTH]);
		assert!(PeerCertificate::<HouseSigning>::parse(certificate, KeyPurposes::HOUSE.server).is_ok());
	}

	/// The house client role admits `id-kp-clientAuth`, named here by the
	/// OID database of RFC 5280.
	#[test]
	fn a_client_auth_certificate_is_admitted_for_the_house_client_role() {
		let certificate = with_purposes(vec![ID_KP_CLIENT_AUTH]);
		assert!(PeerCertificate::<HouseSigning>::parse(certificate, KeyPurposes::HOUSE.client).is_ok());
	}

	/// The house signer role admits the tightbeam signer purpose, named here
	/// by its number under the crate's arc.
	#[test]
	fn a_tightbeam_signer_certificate_is_admitted_for_the_house_signer_role() {
		let signer = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.3.1");
		let certificate = with_purposes(vec![signer]);
		assert!(PeerCertificate::<ErasedSigning>::parse(certificate, KeyPurposes::HOUSE.signer).is_ok());
	}

	/// `anyExtendedKeyUsage` admits every role (RFC 5280 §4.2.1.12).
	#[test]
	fn any_extended_key_usage_is_admitted_for_the_client_role() {
		let certificate = with_purposes(vec![ANY_EXTENDED_KEY_USAGE]);
		assert!(PeerCertificate::<HouseSigning>::parse(certificate, CLIENT).is_ok());
	}

	/// A certificate that names two roles serves each of them.
	#[test]
	fn a_certificate_of_two_roles_is_admitted_for_the_second() {
		let certificate = with_purposes(vec![SERVER, CLIENT]);
		assert!(PeerCertificate::<HouseSigning>::parse(certificate, CLIENT).is_ok());
	}

	/// A certificate of an implementor's own purpose is admitted for the role
	/// read under that purpose.
	#[test]
	fn an_own_purpose_is_admitted_for_its_role() {
		let own = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.1");
		let certificate = with_purposes(vec![own]);
		assert!(PeerCertificate::<HouseSigning>::parse(certificate, own).is_ok());
	}

	/// A certificate that repeats an extension is refused for every use
	/// (RFC 5280 §4.2).
	#[test]
	fn a_certificate_that_repeats_an_extension_is_refused_for_signing() {
		let extension = TestCertificate::opaque_extension("2.5.29.30", false);
		let certificate = TestCertificate::with_extension(both_uses(), extension.clone());
		let certificate = TestCertificate::with_extension(certificate, extension);

		let refused = PeerCertificate::<HouseSigning>::parse(certificate, SERVER);
		assert!(matches!(refused, Err(CertificateValidationError::DuplicateExtension(_))));
	}

	/// A certificate with a critical extension the crate does not process is
	/// refused for every use (RFC 5280 §4.2).
	#[test]
	fn a_certificate_with_an_unknown_critical_extension_is_refused_for_erased_signing() {
		let extension = TestCertificate::opaque_extension("2.5.29.30", true);
		let certificate = TestCertificate::with_extension(both_uses(), extension);

		let refused = PeerCertificate::<ErasedSigning>::parse(certificate, SIGNER);
		assert!(matches!(
			refused,
			Err(CertificateValidationError::UnprocessedCriticalExtension(_))
		));
	}

	/// The signing use parses the SPKI as the provider's verifying key, which
	/// names its curve, so a key under another curve's OID is refused.
	#[test]
	fn a_key_on_another_curve_is_refused_for_signing() {
		let refused = PeerCertificate::<HouseSigning>::parse(on_another_curve(), SERVER);
		assert!(matches!(refused, Err(CertificateValidationError::SpkiError(_))));
	}

	/// The key-agreement use parses the SPKI as the KEM's recipient key,
	/// which names its curve, so a key under another curve's OID is refused.
	#[test]
	fn a_key_on_another_curve_is_refused_for_key_agreement() {
		let refused = PeerCertificate::<HouseAgreement>::parse(on_another_curve(), SERVER);
		assert!(matches!(refused, Err(CertificateValidationError::SpkiError(_))));
	}

	/// Bits that are no point of the curve the SPKI names are refused for
	/// signing.
	#[test]
	fn a_key_off_the_curve_is_refused_for_signing() {
		let refused = PeerCertificate::<HouseSigning>::parse(off_the_curve(), SERVER);
		assert!(matches!(refused, Err(CertificateValidationError::SpkiError(_))));
	}

	#[test]
	fn a_key_off_the_curve_is_refused_for_key_agreement() {
		let refused = PeerCertificate::<HouseAgreement>::parse(off_the_curve(), SERVER);
		assert!(matches!(refused, Err(CertificateValidationError::SpkiError(_))));
	}

	/// The compact twin of the signing key would decompact to a point that
	/// agrees as the signing key does, so the key-agreement use refuses its
	/// form (RFC 5480 §2.2).
	#[test]
	fn a_compact_twin_of_the_signing_key_is_refused_for_key_agreement() {
		let refused = PeerCertificate::<HouseAgreement>::parse(compact_twin(), SERVER);
		assert!(matches!(refused, Err(CertificateValidationError::SpkiError(_))));
	}

	#[test]
	fn a_compact_signing_key_is_refused_for_signing() {
		let refused = PeerCertificate::<HouseSigning>::parse(compact_twin(), SERVER);
		assert!(matches!(refused, Err(CertificateValidationError::SpkiError(_))));
	}

	/// An uncompressed point whose two halves differ in length holds no x and
	/// y of one field, so its form is refused.
	#[test]
	fn an_uncompressed_point_of_uneven_halves_fails_the_point_form() {
		let point = fixed_point().to_encoded_point(false);
		let uneven = [point.as_bytes(), &[0][..]].concat();
		let spki = key_info(CURVE_SECP256K1, &uneven);

		let refused = spki.owned_to_ref().require_point_form();
		assert!(matches!(refused, Err(CertificateValidationError::SpkiError(_))));
	}

	#[test]
	fn a_point_is_distinct_from_another_key() -> Result<(), CertificateValidationError> {
		let signing = PeerCertificate::<HouseSigning>::parse(both_uses(), SERVER)?;
		let other = SecretKey::random(&mut OsRng).public_key();
		assert!(signing.distinct(&other));
		Ok(())
	}

	#[test]
	fn the_certificate_key_is_not_distinct_from_itself() -> Result<(), CertificateValidationError> {
		let signing = PeerCertificate::<HouseSigning>::parse(both_uses(), SERVER)?;
		assert!(!signing.distinct(&fixed_point()));
		Ok(())
	}

	/// ECDH keeps the x-coordinate alone, so the negation of the key collapses
	/// an agreement as the key does.
	#[test]
	fn the_negation_of_the_certificate_key_is_not_distinct() -> Result<(), CertificateValidationError> {
		let signing = PeerCertificate::<HouseSigning>::parse(both_uses(), SERVER)?;
		assert!(!signing.distinct(&negated_fixed_point()));
		Ok(())
	}

	/// One point in its compressed and its uncompressed SEC 1 encoding is one
	/// key.
	#[test]
	fn a_compressed_twin_is_the_same_key() {
		let uncompressed = fixed_point().to_encoded_point(false);
		let compressed = fixed_point().to_encoded_point(true);
		let own = key_info(CURVE_SECP256K1, uncompressed.as_bytes());
		let twin = key_info(CURVE_SECP256K1, compressed.as_bytes());
		assert!(own.same_key(&twin));
	}

	/// A point and its negation agree alike, so they are one key.
	#[test]
	fn a_negated_point_is_the_same_key() {
		let point = fixed_point().to_encoded_point(false);
		let negation = negated_fixed_point().to_encoded_point(false);
		let own = key_info(CURVE_SECP256K1, point.as_bytes());
		let negated = key_info(CURVE_SECP256K1, negation.as_bytes());
		assert!(own.same_key(&negated));
	}

	/// One x-coordinate on two curves names two points.
	#[test]
	fn one_x_coordinate_on_two_curves_is_two_keys() {
		let point = fixed_point().to_encoded_point(false);
		let own = key_info(CURVE_SECP256K1, point.as_bytes());
		let other = on_another_curve().tbs_certificate.subject_public_key_info;
		assert!(!own.same_key(&other));
	}

	#[test]
	fn two_points_are_two_keys() {
		let other = SecretKey::random(&mut OsRng).public_key().to_encoded_point(false);
		let own = both_uses().tbs_certificate.subject_public_key_info;
		let other = key_info(CURVE_SECP256K1, other.as_bytes());
		assert!(!own.same_key(&other));
	}
}
