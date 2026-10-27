//! The CMS signer, the signing identity, and the key identifier.

use core::iter;
use core::str::FromStr;
use std::sync::Arc;

use super::*;
use crate::asn1::admission::fixtures::tlv;
use crate::asn1::admission::DerAdmission;
use crate::cms::cert::{CertificateChoices, IssuerAndSerialNumber, OtherCertificateFormat};
use crate::cms::content_info::CmsVersion;
use crate::cms::revocation::{OtherRevocationInfoFormat, RevocationInfoChoice, RevocationInfoChoices};
use crate::cms::signed_data::{CertificateSet, SignedAttributes, SignedData, SignerIdentifier, SignerInfo};
use crate::crypto::hash::Sha3_256;
use crate::crypto::key::{KeyBackend, KeyError, Secp256k1KeyProvider, SigningKeyProvider};
use crate::crypto::policy::Secp256k1Policy;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::crypto::sign::ecdsa::{Secp256k1, Secp256k1Signature, Secp256k1SigningKey};
use crate::crypto::sign::elliptic_curve::ALGORITHM_OID as EC_PUBLIC_KEY;
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::error::CertificateValidationError::{AmbiguousIssuer, InvalidChain, PathLenExceeded};
use crate::crypto::x509::utils::{CertificateExt, Skid};
use crate::crypto::x509::KeyPurposes;
use crate::crypto::x509::{ErasedSigning, PeerCertificate, Signing};
use crate::der::asn1::{BitString, OctetString, SetOfVec};
use crate::der::oid::AssociatedOid;
use crate::der::{Any, AnyRef, Decode, Encode, ErrorKind, Header, Reader, SliceReader, Tag, TagNumber};
use crate::error::ReceivedExpectedError;
use crate::oids::{
	ATTR_CMS_ALGORITHM_PROTECTION, ATTR_CONTENT_TYPE, ATTR_MESSAGE_DIGEST, DATA, HASH_SHA3_256, HASH_SHA3_512,
	RECEIPT_ROLE, SESSION_RECEIPT_CONTENT, SIGNER_ECDSA_WITH_SHA256,
};
use crate::random::OsRng;
use crate::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use crate::testing::fixtures::{TestAttributes, TestCertificate, TestIdentity, TestKey};
use crate::utils::marker::MaybeSendFuture;
use crate::x509::attr::Attribute;
use crate::x509::ext::pkix::{KeyUsage, KeyUsages, SubjectKeyIdentifier};
use crate::x509::name::RdnSequence;
use crate::x509::serial_number::SerialNumber;
use crate::x509::Certificate;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::asn1::admission::Canonical;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::asn1::WireDer;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::frame::{ArrivedCertificates, CERTIFICATES_TAG};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The content every test signs.
const CONTENT: &[u8] = b"cms signer content";

/// The fixed test key beside a certificate with no key identifier, which
/// names it by issuer and serial number.
fn issuer_and_serial_key() -> CertifiedKey<Secp256k1SigningKey> {
	let key = TestKey::insecure_fixed_signing();
	let certificate = TestCertificate::self_signed(&key);
	let certificate = TestCertificate::without_extension(certificate, SubjectKeyIdentifier::OID);
	CertifiedKey::new(&certificate, key).expect("the test key matches its certificate")
}

/// The `SignerInfo` that `key` signs over `content`.
fn signed_by(key: &CertifiedKey<Secp256k1SigningKey>, content: SignedContent<'_>) -> Signed<SignerInfo> {
	CmsSigner::sign_with::<Secp256k1Signature, _>(key, content).expect("the test key signs")
}

/// The `SignerInfo` the fixed test key signs over [`CONTENT`], under its
/// self-signed certificate.
fn signed() -> Signed<SignerInfo> {
	let key = TestIdentity::certified(TestKey::insecure_fixed_signing());
	signed_by(&key, SignedContent::data(CONTENT))
}

/// [`signed`] beside the certificate its `sid` names, the self-signed
/// certificate of the fixed test key.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn certified() -> CertifiedSigner {
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let certified = CertifiedSigner::new(signed(), Arc::new(certificate));
	certified.expect("the sid names the certificate of its key")
}

/// The `SignedData` that carries [`CONTENT`] and [`signed`].
fn signed_data() -> SignedData {
	let content = SignedContent::data(CONTENT);
	let signed_data = CmsSigner::signed_data(content, signed(), None).expect("the SignedData assembles");
	signed_data.into_inner()
}

/// A key provider that returns its key's signature in another form than the
/// DER low-s one, as some external backends do.
#[derive(Debug)]
struct ExternalProvider {
	inner: Secp256k1KeyProvider,
	algorithm: ObjectIdentifier,
	reshape: fn(ecdsa::Signature<Secp256k1>) -> Vec<u8>,
}

impl KeyBackend for ExternalProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: self.algorithm, parameters: None }
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		self.inner.to_public_key_bytes()
	}
}

impl SigningKeyProvider for ExternalProvider {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let signing = self.inner.sign_prehash(prehash);
		let reshape = self.reshape;
		Box::pin(async move {
			let der = signing.await?;
			let parsed = Secp256k1Signature::from_bytes(&der)?;
			let scalars = ecdsa::Signature::<Secp256k1>::try_from(parsed)?;
			Ok(reshape(scalars))
		})
	}
}

/// The raw `r || s` form of `scalars`.
fn raw_form(scalars: ecdsa::Signature<Secp256k1>) -> Vec<u8> {
	scalars.to_bytes().to_vec()
}

/// The DER of the `(r, n - s)` twin of `scalars`.
fn high_form(scalars: ecdsa::Signature<Secp256k1>) -> Vec<u8> {
	let (r, s) = scalars.split_scalars();
	let high = ecdsa::Signature::<Secp256k1>::from_scalars(r, -s).expect("n - s is a scalar");
	high.to_der().as_bytes().to_vec()
}

/// The fixed test key behind an [`ExternalProvider`] of `algorithm` that
/// reshapes each signature with `reshape`.
fn external_provider(
	algorithm: ObjectIdentifier,
	reshape: fn(ecdsa::Signature<Secp256k1>) -> Vec<u8>,
) -> Arc<ExternalProvider> {
	let inner = Secp256k1KeyProvider::from(TestKey::insecure_fixed_signing());
	Arc::new(ExternalProvider { inner, algorithm, reshape })
}

/// An identity of the fixed test key whose provider reshapes each signature
/// with `reshape`.
fn external_identity(reshape: fn(ecdsa::Signature<Secp256k1>) -> Vec<u8>) -> SigningIdentity {
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let provider = external_provider(SIGNER_ECDSA_WITH_SHA3_256, reshape);
	SigningIdentity::new(certificate, provider).expect("the test key matches its certificate")
}

/// Verify `signer_info` over [`CONTENT`] under the fixed test key.
fn verify(signer_info: &SignerInfo) -> Result<VerifiedSignature, SignerError> {
	let key = TestKey::insecure_fixed_signing();
	let content = SignedContent::data(CONTENT);
	CmsSigner::verify::<Secp256k1Signature, _>(signer_info, key.verifying_key(), content)
}

/// `signer_info` with its signed attributes replaced by `attributes`, which
/// the fixed test key signs again, so only the attribute check can refuse
/// it.
fn resigned(signer_info: &SignerInfo, attributes: Vec<Attribute>) -> SignerInfo {
	let key = TestKey::insecure_fixed_signing();
	let signed_attrs = SignedAttributes::try_from(attributes).expect("the attributes form a SET");
	let attrs_der = signed_attrs.to_der().expect("the attributes encode");
	let signature: Secp256k1Signature = key.sign_canonical::<Sha3_256>(attrs_der).expect("the key signs");
	let signature = OctetString::new(signature.to_bytes().as_ref()).expect("a signature wraps");

	SignerInfo { signed_attrs: Some(signed_attrs), signature, ..signer_info.clone() }
}

/// The signed attributes of `signer_info`.
fn attributes_of(signer_info: &SignerInfo) -> Vec<Attribute> {
	let attributes = signer_info.signed_attrs.as_ref().expect("the signer writes signed attributes");
	attributes.iter().cloned().collect()
}

/// The signed attributes of `signer_info` without the one under `oid`.
fn attributes_without(signer_info: &SignerInfo, oid: ObjectIdentifier) -> Vec<Attribute> {
	let attributes = attributes_of(signer_info);
	attributes.into_iter().filter(|attribute| attribute.oid != oid).collect()
}

/// The algorithm protection attribute of `digest` beside `signature`.
fn protection(digest: ObjectIdentifier, signature: ObjectIdentifier) -> Attribute {
	let protection = CmsAlgorithmProtection {
		digest_algorithm: AlgorithmIdentifierOwned { oid: digest, parameters: None },
		signature_algorithm: Some(AlgorithmIdentifierOwned { oid: signature, parameters: None }),
		mac_algorithm: None,
	};

	let value = Any::encode_from(&protection).expect("the attribute encodes");
	let values = SetOfVec::try_from(vec![value]).expect("one value forms a SET");
	Attribute { oid: ATTR_CMS_ALGORITHM_PROTECTION, values }
}

/// `signer_info` with its signature replaced by `signature`.
fn with_signature(signer_info: &SignerInfo, signature: impl AsRef<[u8]>) -> SignerInfo {
	let signature = OctetString::new(signature.as_ref()).expect("a signature wraps");
	SignerInfo { signature, ..signer_info.clone() }
}

/// The scalar pair of `signer_info`'s DER signature.
fn scalars(signer_info: &SignerInfo) -> ecdsa::Signature<ecdsa::Secp256k1> {
	let der = Secp256k1Signature::from_bytes(signer_info.signature.as_bytes()).expect("the signer writes DER");
	ecdsa::Signature::try_from(der).expect("a DER signature holds two scalars")
}

/// The RFC 7093 §2 method 1 identifier of a public key matches the value
/// an independent computation of the point and of SHA-256 gives.
#[test]
fn the_key_identifier_matches_its_known_answer() -> TestResult {
	let key = TestKey::insecure_fixed_signing();
	let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key())?;

	let identifier = Skid::of_public_key(&spki);
	assert_eq!(identifier.as_bytes(), &TestKey::INSECURE_FIXED_KEY_IDENTIFIER);
	Ok(())
}

/// A certificate the crate creates carries its key identifier, so it names
/// its signer by the `subjectKeyIdentifier` (RFC 5652 §5.3).
#[test]
fn a_minted_certificate_names_its_signer_by_its_key_identifier() -> TestResult {
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let expected = SubjectKeyIdentifier::from(OctetString::new(TestKey::INSECURE_FIXED_KEY_IDENTIFIER)?);

	let sid = certificate.signer_identifier()?;
	assert_eq!(sid, SignerIdentifier::SubjectKeyIdentifier(expected));
	Ok(())
}

/// A certificate with no key identifier is named by its issuer and serial
/// number.
#[test]
fn a_certificate_with_no_key_identifier_is_named_by_issuer_and_serial() -> TestResult {
	let mut certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	certificate.tbs_certificate.extensions = None;

	let issuer = certificate.tbs_certificate.issuer.clone();
	let serial_number = certificate.tbs_certificate.serial_number.clone();
	let sid = certificate.signer_identifier()?;

	let expected = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber { issuer, serial_number });
	assert_eq!(sid, expected);
	Ok(())
}

/// A key paired with its certificate names the certificate by the value its
/// extension holds, which another method than the crate's wrote, so a `sid`
/// computed from the key would differ.
#[test]
fn a_certified_key_names_its_certificate() -> TestResult {
	let key = TestKey::insecure_fixed_signing();
	let written = SubjectKeyIdentifier::from(OctetString::new([0x42u8; 20])?);
	let certificate = TestCertificate::with_key_identifier(TestCertificate::self_signed(&key), written.clone());

	let certified = CertifiedKey::new(&certificate, key)?;
	assert_eq!(certified.signer_identifier(), &SignerIdentifier::SubjectKeyIdentifier(written));
	Ok(())
}

/// A key whose public half differs from the certificate's
/// SubjectPublicKeyInfo pairs with no certificate.
#[test]
fn a_certified_key_refuses_a_key_other_than_its_certificate_names() -> TestResult {
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let other = Secp256k1SigningKey::from_bytes(&[2u8; 32].into())?;

	let refused = CertifiedKey::new(&certificate, other);
	assert!(matches!(refused, Err(SignerError::KeyMismatch)));
	Ok(())
}

/// A key that signs in place pairs with a certificate that holds its point
/// in the compressed SEC 1 form, since both forms name one key (RFC 5480
/// §2.2).
#[test]
fn a_certified_key_admits_its_key_in_the_compressed_form() -> TestResult {
	let key = TestKey::insecure_fixed_signing();
	let certificate = TestCertificate::with_compressed_key(TestCertificate::self_signed(&key));
	CertifiedKey::new(&certificate, key)?;
	Ok(())
}

/// A key whose point is the negation of the certificate's pairs with no
/// certificate, though the two points share an x-coordinate.
#[test]
fn a_certified_key_refuses_the_negation_of_its_key() {
	let key = TestKey::insecure_fixed_signing();
	let certificate = TestCertificate::self_signed(&key);

	let refused = CertifiedKey::new(&certificate, TestKey::negation_of(&key));
	assert!(matches!(refused, Err(SignerError::KeyMismatch)));
}

/// Every `SignerInfo` carries the content type, the message digest, and the
/// algorithm protection as signed attributes.
#[test]
fn a_signer_info_carries_the_three_signed_attributes() {
	let signer_info = signed();
	let oids = TestAttributes::oids(&signer_info);
	assert_eq!(
		oids,
		vec![ATTR_CONTENT_TYPE, ATTR_CMS_ALGORITHM_PROTECTION, ATTR_MESSAGE_DIGEST]
	);
}

/// A `SignerInfo` named by a key identifier is version 3 (RFC 5652 §5.3).
#[test]
fn a_key_identifier_signer_is_version_3() {
	let signer_info = signed();
	assert_eq!(signer_info.version, CmsVersion::V3);
}

/// A `SignerInfo` named by issuer and serial number is version 1 (RFC 5652
/// §5.3).
#[test]
fn an_issuer_and_serial_signer_is_version_1() {
	let key = issuer_and_serial_key();
	let signer_info = signed_by(&key, SignedContent::data(CONTENT));
	assert_eq!(signer_info.version, CmsVersion::V1);
}

/// The signature value is a DER `ECDSA-Sig-Value` (RFC 5753 §2.1.1).
#[test]
fn the_signer_writes_a_der_signature_value() {
	let signer_info = signed();
	let parsed = Secp256k1Signature::from_bytes(signer_info.signature.as_bytes());
	assert!(parsed.is_ok());
}

/// The crate signs with `s` in the low half of the curve order.
#[test]
fn the_signer_writes_a_low_s_signature() {
	let signer_info = signed();
	let pair = scalars(&signer_info);
	assert!(pair.normalize_s().is_none());
}

#[test]
fn a_signer_info_verifies_over_its_content() -> TestResult {
	let signer_info = signed();
	verify(&signer_info)?;
	Ok(())
}

/// `der` skips a context-specific element whose number is below the one it
/// looks for, so the `Signed` decode holds a `SignerInfo` to its arrival and
/// refuses a stray `[0]` after `signature`, the slot of `unsignedAttrs`
/// (X.690 § 8.9.2).
#[test]
fn a_signer_info_with_a_stray_context_tag_is_refused() -> TestResult {
	let sent = signed().to_der()?;
	let fields = AnyRef::from_der(&sent)?.value();
	let stray = tlv(Tag::Sequence, &[fields, &[0xa0, 0x02, 0x05, 0x00]].concat());

	let refused = Signed::<SignerInfo>::from_der(&stray).map_err(|error| error.kind());
	assert_eq!(refused, Err(ErrorKind::Noncanonical { tag: Tag::Sequence }));
	Ok(())
}

/// A `SignerInfo` with no signed attributes is refused (RFC 5652 §5.4).
#[test]
fn a_signer_info_with_no_signed_attributes_is_refused() {
	let signer_info = SignerInfo { signed_attrs: None, ..signed().into_inner() };
	let refused = verify(&signer_info);
	assert!(matches!(refused, Err(SignerError::SignedAttributes)));
}

/// A `SignerInfo` whose signed attributes lack the message digest is
/// refused, even when its signature covers what remains.
#[test]
fn a_signer_info_missing_the_message_digest_is_refused() {
	let signer_info = signed();
	let attributes = attributes_without(&signer_info, ATTR_MESSAGE_DIGEST);
	let tampered = resigned(&signer_info, attributes);

	let refused = verify(&tampered);
	assert!(matches!(refused, Err(SignerError::SignedAttributes)));
}

/// A `SignerInfo` whose signed attributes lack the algorithm protection is
/// refused.
#[test]
fn a_signer_info_missing_the_algorithm_protection_is_refused() {
	let signer_info = signed();
	let attributes = attributes_without(&signer_info, ATTR_CMS_ALGORITHM_PROTECTION);
	let tampered = resigned(&signer_info, attributes);

	let refused = verify(&tampered);
	assert!(matches!(refused, Err(SignerError::SignedAttributes)));
}

/// An algorithm protection attribute that names another digest than the
/// `SignerInfo` does is refused (RFC 6211 §3).
#[test]
fn a_mismatched_algorithm_protection_is_refused() {
	let signer_info = signed();
	let mut attributes = attributes_without(&signer_info, ATTR_CMS_ALGORITHM_PROTECTION);
	attributes.push(protection(HASH_SHA3_512, SIGNER_ECDSA_WITH_SHA3_256));

	let tampered = resigned(&signer_info, attributes);
	let refused = verify(&tampered);
	assert!(matches!(refused, Err(SignerError::SignedAttributes)));
}

/// A `SignerInfo` whose version differs from the one its `sid` demands is
/// refused (RFC 5652 §5.3).
#[test]
fn a_signer_info_of_the_wrong_version_is_refused() {
	let signer_info = SignerInfo { version: CmsVersion::V1, ..signed().into_inner() };
	let refused = verify(&signer_info);

	let versions = ReceivedExpectedError::from((CmsVersion::V1, CmsVersion::V3));
	assert!(matches!(refused, Err(SignerError::SignerInfoVersion(received)) if received == versions));
}

/// A signature made for one content type verifies as no other, because the
/// content type is a signed attribute.
#[test]
fn a_signer_info_read_as_another_content_type_is_refused() {
	let signer_info = signed();
	let key = TestKey::insecure_fixed_signing();
	let content = SignedContent::new(SESSION_RECEIPT_CONTENT, CONTENT);

	let refused = CmsSigner::verify::<Secp256k1Signature, _>(&signer_info, key.verifying_key(), content);
	assert!(matches!(refused, Err(SignerError::SignedAttributes)));
}

/// A `SignerInfo` whose digest algorithm is not the one its signature
/// algorithm names is refused, even when its algorithm protection and its
/// signature agree with it (RFC 5753 §2.1.1).
#[test]
fn a_signer_info_whose_digest_its_signature_algorithm_does_not_name_is_refused() {
	let signer_info = signed();
	let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_512, parameters: None };
	let mismatched = SignerInfo { digest_alg, ..signer_info.clone().into_inner() };
	let mut attributes = attributes_without(&signer_info, ATTR_CMS_ALGORITHM_PROTECTION);
	attributes.push(protection(HASH_SHA3_512, SIGNER_ECDSA_WITH_SHA3_256));

	let tampered = resigned(&mismatched, attributes);
	let refused = verify(&tampered);

	let algorithms = ReceivedExpectedError::from((HASH_SHA3_512, HASH_SHA3_256));
	assert!(matches!(refused, Err(SignerError::UnexpectedAlgorithm(received)) if received == algorithms));
}

/// A `SignerInfo` of another signature algorithm than `S`'s is refused,
/// even when its algorithm protection and its signature agree with it.
#[test]
fn a_signer_info_of_another_signature_algorithm_is_refused() {
	let signer_info = signed();
	let signature_algorithm = AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA256, parameters: None };
	let mismatched = SignerInfo { signature_algorithm, ..signer_info.clone().into_inner() };
	let mut attributes = attributes_without(&signer_info, ATTR_CMS_ALGORITHM_PROTECTION);
	attributes.push(protection(HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA256));

	let tampered = resigned(&mismatched, attributes);
	let refused = verify(&tampered);

	let algorithms = ReceivedExpectedError::from((SIGNER_ECDSA_WITH_SHA256, SIGNER_ECDSA_WITH_SHA3_256));
	assert!(matches!(refused, Err(SignerError::UnexpectedAlgorithm(received)) if received == algorithms));
}

/// A `SignerInfo` with one signed attribute beyond the required set is
/// refused, even when its signature covers it.
#[test]
fn a_signer_info_with_an_extra_signed_attribute_is_refused() -> TestResult {
	let signer_info = signed();
	let extra = Attribute { oid: RECEIPT_ROLE, values: SetOfVec::try_from(vec![Any::encode_from(&1u8)?])? };
	let mut attributes = attributes_of(&signer_info);
	attributes.push(extra);

	let tampered = resigned(&signer_info, attributes);
	let refused = verify(&tampered);
	assert!(matches!(refused, Err(SignerError::SignedAttributes)));
	Ok(())
}

/// A profile attribute under the OID of a required attribute is refused when
/// the signer drafts the set (RFC 5652 §11.1).
#[test]
fn a_profile_attribute_that_repeats_a_required_oid_is_refused() -> TestResult {
	let key = TestIdentity::certified(TestKey::insecure_fixed_signing());
	let content = SignedContent::data(CONTENT).with_single_valued(ATTR_CONTENT_TYPE, Any::encode_from(&DATA)?)?;
	let refused = CmsSigner::draft::<Secp256k1Signature>(key.signer_identifier().clone(), content);
	assert!(matches!(refused, Err(SignerError::DuplicateAttribute(oid)) if oid == ATTR_CONTENT_TYPE));
	Ok(())
}

/// Two profile attributes under one OID are refused when the signer drafts
/// the set, which holds each OID once.
#[test]
fn two_profile_attributes_under_one_oid_are_refused() -> TestResult {
	let key = TestIdentity::certified(TestKey::insecure_fixed_signing());
	let content = SignedContent::data(CONTENT).with_single_valued(RECEIPT_ROLE, Any::encode_from(&1u8)?)?;
	let content = content.with_single_valued(RECEIPT_ROLE, Any::encode_from(&2u8)?)?;

	let refused = CmsSigner::draft::<Secp256k1Signature>(key.signer_identifier().clone(), content);
	assert!(matches!(refused, Err(SignerError::DuplicateAttribute(oid)) if oid == RECEIPT_ROLE));
	Ok(())
}

/// The signer takes the content by value, so a profile attribute moves into
/// the signed set of the `SignerInfo` that signs it.
#[test]
fn a_profile_attribute_moves_into_the_signed_set() -> TestResult {
	let key = TestIdentity::certified(TestKey::insecure_fixed_signing());
	let role = Attribute { oid: RECEIPT_ROLE, values: SetOfVec::try_from(vec![Any::encode_from(&1u8)?])? };
	let expected = Attribute { oid: RECEIPT_ROLE, values: SetOfVec::try_from(vec![Any::encode_from(&1u8)?])? };

	let signer_info = signed_by(&key, SignedContent::data(CONTENT).with_attribute(role));
	assert!(attributes_of(&signer_info).contains(&expected));
	Ok(())
}

/// A raw `r || s` value is no `ECDSA-Sig-Value`, so it is refused.
#[test]
fn a_raw_r_s_signature_value_is_refused() {
	let signer_info = signed();
	let raw = scalars(&signer_info).to_bytes();
	let tampered = with_signature(&signer_info, raw);

	let refused = verify(&tampered);
	assert!(matches!(refused, Err(SignerError::Signature(_))));
}

/// A high-s value from another signer verifies (SEC 1 v2.0 §4.1.4).
#[test]
fn a_high_s_signer_info_verifies() -> TestResult {
	let signer_info = signed();
	let pair = scalars(&signer_info);
	let (r, s) = pair.split_scalars();
	let high = ecdsa::Signature::<ecdsa::Secp256k1>::from_scalars(r, -s)?;

	let tampered = with_signature(&signer_info, high.to_der().as_bytes());
	verify(&tampered)?;
	Ok(())
}

/// A signature and its `(r, n - s)` twin verify to one value, the key every
/// replay guard and ledger holds.
#[test]
fn a_high_s_twin_verifies_to_the_value_of_its_original() -> TestResult {
	let signer_info = signed();
	let pair = scalars(&signer_info);
	let (r, s) = pair.split_scalars();
	let high = ecdsa::Signature::<ecdsa::Secp256k1>::from_scalars(r, -s)?;
	let tampered = with_signature(&signer_info, high.to_der().as_bytes());

	let original = verify(&signer_info)?;
	let twin = verify(&tampered)?;
	assert_eq!(original, twin);
	Ok(())
}

/// The algorithm protection attribute encodes as RFC 6211 §2 writes it: the
/// `[1]` tag replaces the AlgorithmIdentifier's SEQUENCE tag, so an explicit
/// tag fails the comparison.
#[test]
fn the_algorithm_protection_encodes_as_rfc_6211_writes_it() -> TestResult {
	let signer_info = signed();
	let value = TestAttributes::value(&signer_info, ATTR_CMS_ALGORITHM_PROTECTION);
	assert_eq!(value.to_der()?, TestAttributes::ALGORITHM_PROTECTION);
	Ok(())
}

/// A draft refuses a signature value that is not DER, so a provider's raw
/// `r || s` never reaches a `SignerInfo` (RFC 5753 §2.1.1).
#[test]
fn a_draft_refuses_a_raw_r_s_signature() -> TestResult {
	let key = TestKey::insecure_fixed_signing();
	let sid = TestIdentity::certified(key.clone()).signer_identifier().clone();
	let draft = CmsSigner::draft::<Secp256k1Signature>(sid, SignedContent::data(CONTENT))?;
	let signature: ecdsa::Signature<Secp256k1> = key.sign_prehash(draft.prehash())?;

	let refused = draft.complete(signature.to_bytes(), None);
	assert!(matches!(refused, Err(SignerError::Signature(_))));
	Ok(())
}

/// A draft attaches a high-s signature value in its low-s form.
#[test]
fn a_draft_attaches_a_high_s_signature_in_low_s() -> TestResult {
	let key = TestKey::insecure_fixed_signing();
	let sid = TestIdentity::certified(key.clone()).signer_identifier().clone();
	let draft = CmsSigner::draft::<Secp256k1Signature>(sid, SignedContent::data(CONTENT))?;
	let signature: ecdsa::Signature<Secp256k1> = key.sign_prehash(draft.prehash())?;

	let signer_info = draft.complete(high_form(signature), None)?;
	assert!(scalars(&signer_info).normalize_s().is_none());
	Ok(())
}

/// An identity whose provider returns raw `r || s` refuses to sign, so the
/// provider's bytes reach no `SignerInfo`.
#[tokio::test]
async fn an_identity_refuses_a_provider_that_returns_raw_r_s() {
	let identity = external_identity(raw_form);
	let refused = identity.sign(SignedContent::data(CONTENT)).await;
	assert!(matches!(refused, Err(SignerError::Signature(_))));
}

/// An identity whose provider returns a high-s value emits its low-s form,
/// which verifies.
#[tokio::test]
async fn an_identity_emits_a_high_s_provider_signature_in_low_s() -> TestResult {
	let identity = external_identity(high_form);
	let signer_info = identity.sign(SignedContent::data(CONTENT)).await?;
	assert!(scalars(&signer_info).normalize_s().is_none());
	verify(&signer_info)?;
	Ok(())
}

/// A provider of an algorithm the crate has no canonical form for pairs with
/// no identity.
#[test]
fn a_signing_identity_refuses_an_algorithm_it_has_no_form_for() {
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let provider = external_provider(SIGNER_ECDSA_WITH_SHA256, high_form);

	let refused = SigningIdentity::new(certificate, provider);
	assert!(matches!(refused, Err(SignerError::UnsupportedAlgorithm(oid)) if oid == SIGNER_ECDSA_WITH_SHA256));
}

/// A certificate whose `keyUsage` carries `keyAgreement` alone pairs with
/// no signing identity, so its key signs nothing the identity emits.
#[test]
fn a_signing_identity_refuses_a_certificate_without_digital_signature() {
	let key = TestKey::insecure_fixed_signing();
	let certificate = TestCertificate::self_signed(&key);
	let certificate = TestCertificate::with_key_usage(certificate, KeyUsage(KeyUsages::KeyAgreement.into()));
	let provider = Arc::new(Secp256k1KeyProvider::from(key));

	let refused = SigningIdentity::with_provider::<DefaultCryptoProvider>(certificate, provider);
	assert!(matches!(
		refused,
		Err(SignerError::Certificate(CertificateValidationError::MissingKeyUsage(
			KeyUsages::DigitalSignature
		)))
	));
}

/// A key that signs in place pairs with no certificate whose `keyUsage`
/// lacks `digitalSignature`.
#[test]
fn a_certified_key_refuses_a_certificate_without_digital_signature() {
	let key = TestKey::insecure_fixed_signing();
	let certificate = TestCertificate::self_signed(&key);
	let certificate = TestCertificate::with_key_usage(certificate, KeyUsage(KeyUsages::KeyAgreement.into()));

	let refused = CertifiedKey::new(&certificate, key);
	assert!(matches!(
		refused,
		Err(SignerError::Certificate(CertificateValidationError::MissingKeyUsage(
			KeyUsages::DigitalSignature
		)))
	));
}

/// A provider that declares `ecdsa-with-SHA3-256` and returns `public_key`
/// as its SubjectPublicKeyInfo. Its `sign_prehash` refuses every prehash.
#[derive(Debug)]
struct DeclaringProvider {
	public_key: Vec<u8>,
}

impl KeyBackend for DeclaringProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None }
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		Ok(self.public_key.clone())
	}
}

impl SigningKeyProvider for DeclaringProvider {
	fn sign_prehash(&self, _prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		Box::pin(async { Err(KeyError::SignatureError(crate::crypto::sign::Error::new())) })
	}
}

/// `ecdsa-with-SHA3-256` on a key of another curve is no key of the
/// built-in scheme, so the identity refuses the pair where it is built.
#[test]
fn the_scheme_refuses_ecdsa_with_sha3_256_on_another_curve() -> TestResult {
	let named_curve = Any::encode_from(&ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"))?;
	let algorithm = AlgorithmIdentifierOwned { oid: EC_PUBLIC_KEY, parameters: Some(named_curve) };
	let subject_public_key = BitString::from_bytes(&[0x04; 65])?;
	let p256_key = SubjectPublicKeyInfoOwned { algorithm, subject_public_key };
	let provider = Arc::new(DeclaringProvider { public_key: p256_key.to_der()? });
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());

	let refused = SigningIdentity::with_provider::<DefaultCryptoProvider>(certificate, provider);
	assert!(matches!(refused, Err(SignerError::UnsupportedAlgorithm(oid)) if oid == SIGNER_ECDSA_WITH_SHA3_256));
	Ok(())
}

/// An identity's prehash signature from a provider that returns raw
/// `r || s` is refused, so the bare HPKE signatures carry no such value.
#[tokio::test]
async fn an_identity_refuses_a_raw_r_s_prehash_signature() {
	let identity = external_identity(raw_form);
	let refused = identity.sign_prehash(&[0x5a; 32]).await;
	assert!(matches!(refused, Err(SignerError::Signature(_))));
}

/// An identity returns a provider's high-s prehash signature as the DER of
/// its low-s twin.
#[tokio::test]
async fn an_identity_returns_a_high_s_prehash_signature_in_low_s() -> TestResult {
	let identity = external_identity(high_form);
	let signature = identity.sign_prehash(&[0x5a; 32]).await?;
	let parsed = Secp256k1Signature::from_bytes(&signature)?;

	let scalars = ecdsa::Signature::<Secp256k1>::try_from(parsed)?;
	assert!(scalars.normalize_s().is_none());
	Ok(())
}

/// A `SignedData` of a version 3 signer is version 3 (RFC 5652 §5.1).
#[test]
fn a_signed_data_of_a_version_3_signer_is_version_3() -> TestResult {
	let content = SignedContent::data(CONTENT);
	let signed_data = CmsSigner::signed_data(content, signed(), None)?;
	assert_eq!(signed_data.version, CmsVersion::V3);
	Ok(())
}

/// A `SignedData` of a version 1 signer over `id-data` is version 1
/// (RFC 5652 §5.1).
#[test]
fn a_signed_data_of_a_version_1_signer_over_data_is_version_1() -> TestResult {
	let content = SignedContent::data(CONTENT);
	let signer = signed_by(&issuer_and_serial_key(), SignedContent::data(CONTENT));

	let signed_data = CmsSigner::signed_data(content, signer, None)?;
	assert_eq!(signed_data.version, CmsVersion::V1);
	Ok(())
}

/// A `SignedData` of a version 1 signer over a content other than `id-data`
/// is version 3 (RFC 5652 §5.1).
#[test]
fn a_signed_data_over_another_content_type_is_version_3() -> TestResult {
	let content = SignedContent::new(SESSION_RECEIPT_CONTENT, CONTENT);
	let signer = signed_by(&issuer_and_serial_key(), SignedContent::new(SESSION_RECEIPT_CONTENT, CONTENT));

	let signed_data = CmsSigner::signed_data(content, signer, None)?;
	assert_eq!(signed_data.version, CmsVersion::V3);
	Ok(())
}

/// A `SignedData` that holds a certificate of type `other` is version 5
/// (RFC 5652 §5.1).
#[test]
fn a_signed_data_with_another_certificate_format_is_version_5() -> TestResult {
	let content = SignedContent::data(CONTENT);
	let other_cert = Any::encode_from(&OctetString::new(CONTENT)?)?;
	let other = OtherCertificateFormat { other_cert_format: DATA, other_cert };
	let certificates = CertificateSet(SetOfVec::try_from(vec![CertificateChoices::Other(other)])?);

	let signed_data = CmsSigner::signed_data(content, signed(), Some(certificates))?;
	assert_eq!(signed_data.version, CmsVersion::V5);
	Ok(())
}

/// A conforming `SignedData` whose revocation entries hold one of type
/// `other` is version 5, and its content reads (RFC 5652 §5.1).
#[test]
fn a_signed_data_with_another_revocation_format_reads_at_version_5() -> TestResult {
	let other_format = AlgorithmIdentifierOwned { oid: DATA, parameters: None };
	let other = OtherRevocationInfoFormat { other_format, other: Any::encode_from(&OctetString::new(CONTENT)?)? };
	let crls = RevocationInfoChoices(SetOfVec::try_from(vec![RevocationInfoChoice::Other(other)])?);
	let foreign = SignedData { version: CmsVersion::V5, crls: Some(crls), ..signed_data() };

	let read = CmsSigner::content(&foreign, DATA)?;
	assert_eq!(read, CONTENT);
	Ok(())
}

/// A version 3 countersignature lifts a version 1 `SignedData` to version 3
/// (RFC 5652 §5.1).
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn a_version_3_countersignature_lifts_the_signed_data_to_version_3() -> TestResult {
	let content = SignedContent::data(CONTENT);
	let signer = signed_by(&issuer_and_serial_key(), SignedContent::data(CONTENT));
	let signed_data = CmsSigner::signed_data(content, signer, None)?;

	let joined = signed_data.with_certified_signer(certified())?;
	assert_eq!(joined.version, CmsVersion::V3);
	Ok(())
}

/// A joining signer's digest algorithm enters `digestAlgorithms` (RFC 5652
/// §5.1).
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn a_joining_signer_declares_its_digest_algorithm() -> TestResult {
	let content = SignedContent::data(CONTENT);
	let signed_data = CmsSigner::signed_data(content, signed(), None)?;
	let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_512, parameters: None };
	let foreign = SignerInfo { digest_alg: digest_alg.clone(), ..signed().into_inner() };
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());

	let joiner = Signed::<SignerInfo>::from_der(&foreign.to_der()?)?;
	let joiner = CertifiedSigner::new(joiner, Arc::new(certificate))?;
	let joined = signed_data.with_certified_signer(joiner)?;
	assert!(joined.digest_algorithms.as_ref().contains(&digest_alg));
	Ok(())
}

/// A joining signer brings the certificate its `sid` names into
/// `certificates`, so the `SignedData` carries the certificate of each of its
/// signers (RFC 5652 §5.1).
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn a_joining_signer_brings_its_certificate() -> TestResult {
	let content = SignedContent::data(CONTENT);
	let signer = signed_by(&issuer_and_serial_key(), SignedContent::data(CONTENT));
	let signed_data = CmsSigner::signed_data(content, signer, None)?;
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());

	let joined = signed_data.with_certified_signer(certified())?;
	let carried = joined.certificates.as_ref().map(|set| set.0.as_slice().to_vec());
	assert_eq!(carried, Some(vec![CertificateChoices::Certificate(certificate)]));
	Ok(())
}

/// A joining signer whose certificate the `SignedData` carries already joins
/// beside that one copy (RFC 5652 §5.1).
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn a_joining_signer_whose_certificate_the_set_holds_keeps_one_copy() -> TestResult {
	let content = SignedContent::data(CONTENT);
	let signer = signed_by(&issuer_and_serial_key(), SignedContent::data(CONTENT));
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let held = CertificateChoices::Certificate(certificate.to_owned());
	let certificates = CertificateSet(SetOfVec::try_from(vec![held])?);
	let signed_data = CmsSigner::signed_data(content, signer, Some(certificates))?;

	let joined = signed_data.with_certified_signer(certified())?;
	let carried = joined.certificates.as_ref().map(|set| set.0.as_slice().to_vec());
	assert_eq!(carried, Some(vec![CertificateChoices::Certificate(certificate)]));
	Ok(())
}

/// A certificate the `sid` of a signer does not name is refused beside it
/// (RFC 5652 §5.3).
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn a_signer_beside_a_certificate_its_sid_does_not_name_is_refused() {
	let other = TestCertificate::self_signed(&Secp256k1SigningKey::random(&mut OsRng));
	let refused = CertifiedSigner::new(signed(), Arc::new(other));
	assert!(matches!(refused, Err(SignerError::SignerIdentifier)));
}

/// A `SignedData` whose version differs from the RFC 5652 §5.1 rule is
/// refused when its content is read.
#[test]
fn a_signed_data_of_the_wrong_version_is_refused() -> TestResult {
	let content = SignedContent::data(CONTENT);
	let signed_data = CmsSigner::signed_data(content, signed(), None)?;
	let tampered = SignedData { version: CmsVersion::V1, ..signed_data.into_inner() };

	let refused = CmsSigner::content(&tampered, DATA);
	let versions = ReceivedExpectedError::from((CmsVersion::V1, CmsVersion::V3));
	assert!(matches!(refused, Err(SignerError::SignedDataVersion(received)) if received == versions));
	Ok(())
}

/// A `SignedData` whose `digestAlgorithms` omits a signer's digest is
/// refused when its content is read (RFC 5652 §5.1).
#[test]
fn a_signed_data_that_omits_a_signer_digest_is_refused() -> TestResult {
	let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_512, parameters: None };
	let digest_algorithms = SetOfVec::try_from(vec![digest_alg])?;
	let tampered = SignedData { digest_algorithms, ..signed_data() };
	let refused = CmsSigner::content(&tampered, DATA);
	assert!(matches!(refused, Err(SignerError::DigestAlgorithms)));
	Ok(())
}

/// A `SignedData` whose content is not an OCTET STRING is refused when its
/// content is read (RFC 5652 §5.2).
#[test]
fn a_signed_data_whose_content_is_no_octet_string_is_refused() -> TestResult {
	let mut tampered = signed_data();
	tampered.encap_content_info.econtent = Some(Any::new(Tag::Utf8String, CONTENT)?);

	let refused = CmsSigner::content(&tampered, DATA);
	assert!(matches!(refused, Err(SignerError::Content)));
	Ok(())
}

/// A `SignedData` read as another content type is refused (RFC 5652 §5.2).
#[test]
fn a_signed_data_read_as_another_content_type_is_refused() {
	let signed_data = signed_data();
	let refused = CmsSigner::content(&signed_data, SESSION_RECEIPT_CONTENT);
	assert!(matches!(refused, Err(SignerError::Content)));
}

/// A `SignedData` the signer assembled decodes as the newtype the wire slots
/// hold, byte for byte.
#[test]
fn a_signed_data_round_trips_through_der() -> TestResult {
	let content = SignedContent::data(CONTENT);
	let signed_data = CmsSigner::signed_data(content, signed(), None)?;
	let encoded = signed_data.to_der()?;

	let decoded = Signed::<SignedData>::from_der(&encoded)?;
	assert_eq!(decoded, signed_data);
	Ok(())
}

#[test]
fn a_signing_identity_accepts_the_key_of_its_certificate() -> TestResult {
	let key = TestKey::insecure_fixed_signing();
	let certificate = TestCertificate::self_signed(&key);
	let provider = Arc::new(Secp256k1KeyProvider::from(key));

	let identity = SigningIdentity::new(certificate.clone(), provider)?;
	assert_eq!(identity.signer_identifier(), &certificate.signer_identifier()?);
	Ok(())
}

/// A signing identity with no chain presents its certificate alone in the
/// `certificates` set a handshake carries.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn a_signing_identity_presents_its_certificate_alone() -> TestResult {
	let key = TestKey::insecure_fixed_signing();
	let certificate = TestCertificate::self_signed(&key);
	let provider = Arc::new(Secp256k1KeyProvider::from(key));

	let identity = SigningIdentity::new(certificate.to_owned(), provider)?;
	assert_eq!(identity.presented().set(), TestCertificate::set_of([certificate]));
	Ok(())
}

/// A key whose public half differs from the certificate's
/// SubjectPublicKeyInfo pairs with no identity.
#[test]
fn a_signing_identity_refuses_a_key_other_than_its_certificate_names() -> TestResult {
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let other = Secp256k1SigningKey::from_bytes(&[2u8; 32].into())?;
	let provider = Arc::new(Secp256k1KeyProvider::from(other));

	let refused = SigningIdentity::new(certificate, provider);
	assert!(matches!(refused, Err(SignerError::KeyMismatch)));
	Ok(())
}

/// A signing identity pairs a key with a certificate that holds the key's
/// point in the compressed SEC 1 form, since both forms name one key
/// (RFC 5480 §2.2).
#[test]
fn a_signing_identity_admits_its_key_in_the_compressed_form() -> TestResult {
	let key = TestKey::insecure_fixed_signing();
	let certificate = TestCertificate::with_compressed_key(TestCertificate::self_signed(&key));
	let provider = Arc::new(Secp256k1KeyProvider::from(key));

	SigningIdentity::new(certificate, provider)?;
	Ok(())
}

/// A key whose point is the negation of the certificate's pairs with no
/// identity, though the two points share an x-coordinate.
#[test]
fn a_signing_identity_refuses_the_negation_of_its_key() {
	let key = TestKey::insecure_fixed_signing();
	let certificate = TestCertificate::self_signed(&key);
	let provider = Arc::new(Secp256k1KeyProvider::from(TestKey::negation_of(&key)));

	let refused = SigningIdentity::new(certificate, provider);
	assert!(matches!(refused, Err(SignerError::KeyMismatch)));
}

/// A `SignerInfo` an identity signs names the identity's certificate.
#[tokio::test]
async fn an_identity_signs_under_its_certificate_name() -> TestResult {
	let identity = TestIdentity::insecure_fixed();
	let signer_info = identity.sign(SignedContent::data(CONTENT)).await?;
	assert_eq!(&signer_info.sid, identity.signer_identifier());
	Ok(())
}

/// The signer verifies a `SignerInfo` that names the certificate it is
/// checked against.
#[tokio::test]
async fn a_signer_info_verifies_under_the_certificate_it_names() -> TestResult {
	let identity = TestIdentity::insecure_fixed();
	let content = SignedContent::data(CONTENT);
	let signer_info = identity.sign(SignedContent::data(CONTENT)).await?;
	let certificate = identity.certificate_arc();
	let signer = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(certificate, KeyPurposes::HOUSE.signer)?;

	CmsSigner::verify_signer::<DefaultCryptoProvider>(&signer_info, &signer, content)?;
	Ok(())
}

/// A `SignerInfo` checked against another certificate is refused by its
/// `sid` before its signature is read.
#[tokio::test]
async fn a_signer_info_checked_against_another_certificate_is_refused() -> TestResult {
	let identity = TestIdentity::insecure_fixed();
	let other_key = Secp256k1SigningKey::from_bytes(&[2u8; 32].into())?;
	let other = TestCertificate::self_signed(&other_key);
	let other = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(other, KeyPurposes::HOUSE.signer)?;
	let content = SignedContent::data(CONTENT);
	let signer_info = identity.sign(SignedContent::data(CONTENT)).await?;

	let refused = CmsSigner::verify_signer::<DefaultCryptoProvider>(&signer_info, &other, content);
	assert!(matches!(refused, Err(SignerError::SignerIdentifier)));
	Ok(())
}

/// A `SignerInfo` checked under a policy against another certificate of the
/// same key is refused by its `sid` (RFC 5652 §5.3).
#[tokio::test]
async fn a_signer_info_checked_by_policy_against_another_certificate_is_refused() -> TestResult {
	let identity = TestIdentity::insecure_fixed();
	let content = SignedContent::data(CONTENT);
	let signer_info = identity.sign(SignedContent::data(CONTENT)).await?;
	let other = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let other = TestCertificate::without_extension(other, SubjectKeyIdentifier::OID);
	let other = PeerCertificate::<ErasedSigning>::parse(other, KeyPurposes::HOUSE.signer)?;

	let refused = CmsSigner::verify_with_policy(&signer_info, &other, &Secp256k1Policy::default(), content);
	assert!(matches!(refused, Err(SignerError::SignerIdentifier)));
	Ok(())
}

/// A `SignerInfo` whose digest its signature algorithm does not name is
/// refused by the policy (RFC 5753 §2.1.1).
#[tokio::test]
async fn a_policy_refuses_a_digest_the_signature_algorithm_does_not_name() -> TestResult {
	let identity = TestIdentity::insecure_fixed();
	let content = SignedContent::data(CONTENT);
	let signer_info = identity.sign(SignedContent::data(CONTENT)).await?;
	let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_512, parameters: None };
	let mismatched = SignerInfo { digest_alg, ..signer_info.into_inner() };
	let policy = Secp256k1Policy::default();
	let refused = CmsSigner::verify_with_policy(&mismatched, identity.signing_certificate(), &policy, content);

	let unsupported = matches!(
		refused,
		Err(SignerError::Certificate(CertificateValidationError::UnsupportedAlgorithm(oid))) if oid == HASH_SHA3_512
	);
	assert!(unsupported);
	Ok(())
}

/// The `SignedData` of [`signed`] carrying `certificates`, which DER sorts.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn signed_data_carrying(certificates: impl IntoIterator<Item = Certificate>) -> SignedData {
	let set = TestCertificate::set_of(certificates);
	let signed_data = CmsSigner::signed_data(SignedContent::data(CONTENT), signed(), Some(set));
	signed_data.expect("the SignedData assembles").into_inner()
}

/// The `SignedData` of [`signed`] whose set holds the certificate its signer
/// names beside eight choices of another format, nine choices in all.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn signed_data_of_nine_choices() -> SignedData {
	let named = CertificateChoices::Certificate(TestCertificate::self_signed(&TestKey::insecure_fixed_signing()));
	let choices = iter::once(named).chain((0..8).map(other_format));
	let set = SetOfVec::try_from(choices.collect::<Vec<_>>()).expect("distinct choices are a SET");

	let signed_data = CmsSigner::signed_data(SignedContent::data(CONTENT), signed(), Some(CertificateSet(set)));
	signed_data.expect("the SignedData assembles").into_inner()
}

/// The path the one signer presents moves out of `certificates`, which the
/// call leaves empty, as a server takes it from a client Finished (RFC 5652
/// §5.3).
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[tokio::test]
async fn taking_the_signer_path_moves_the_set_out() -> TestResult {
	let identity = chained_identity();
	let signer = identity.sign(SignedContent::data(CONTENT)).await?;
	let presented = Some(identity.presented().set());
	let signed = CmsSigner::signed_data(SignedContent::data(CONTENT), signer, presented)?;
	let (signed_data, path) = CmsSigner::take_signer_path(signed)?;
	let path = path.ok_or("the set holds the named certificate")?;
	let (leaf, issuers) = path.into_parts();

	let [chained_leaf, intermediate] = chained_certificates();
	let taken = (leaf, issuers.as_slice(), signed_data.certificates);
	assert_eq!(taken, (chained_leaf, [intermediate].as_slice(), None));
	Ok(())
}

/// A set that holds no certificate the signer names gives no path, and the
/// call still leaves the set empty.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn taking_from_a_set_without_the_signer_certificate_takes_no_path() -> TestResult {
	let other = TestCertificate::self_signed(&Secp256k1SigningKey::random(&mut OsRng));
	let finished = received_as_signed(&signed_data_carrying([other]));

	let (signed_data, path) = CmsSigner::take_signer_path(finished)?;
	assert_eq!((path.is_none(), signed_data.certificates), (true, None));
	Ok(())
}

/// The cap of the path a server takes out of a client Finished counts each
/// choice of the set, so a choice of another format counts toward it.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn taking_a_path_counts_a_choice_of_another_format_toward_the_cap() -> TestResult {
	let finished = received_as_signed(&signed_data_of_nine_choices());

	let refused = CmsSigner::take_signer_path(finished);
	let capped = matches!(refused, Err(SignerError::Certificate(PathLenExceeded)));
	assert!(capped);
	Ok(())
}

/// A server holds the presented set of a client Finished to its cap as it
/// arrived, before the typed decode sorts the set.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn a_presented_set_past_the_cap_is_refused_before_its_decode() -> TestResult {
	let received = signed_data_of_nine_choices().to_der()?;

	let refused = CmsSigner::bound_presented(&received);
	let capped = matches!(refused, Err(SignerError::Certificate(PathLenExceeded)));
	assert!(capped);
	Ok(())
}

/// `signed_data` as a peer's `Signed` decode reads it from its DER.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn received_as_signed(signed_data: &SignedData) -> Signed<SignedData> {
	let received = signed_data.to_der().expect("a test SignedData encodes");
	Signed::<SignedData>::from_der(&received).expect("a test SignedData decodes")
}

/// `signed_data` as a peer's [`WireDer`] decode reads it from the DER its
/// signer writes, every SET in DER order.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn received_wire(signed_data: &SignedData) -> WireDer<SignedData> {
	let mut contents = Vec::new();

	signed_data.encode_canonical(&mut contents).expect("a test SignedData encodes");

	let received = tlv(Tag::Sequence, &contents);
	WireDer::try_from(received.as_slice()).expect("a test SignedData decodes from its DER")
}

/// The scan of the received set builds the path of the certificate the one
/// signer names. Under the fixed key `0x0f` × 32, the other certificate sorts
/// first in the SET, in DER and in the order `der` decodes, so the named
/// certificate is the second element, and the other one issues no
/// certificate of the path.
#[cfg(feature = "transport-cms")]
#[test]
fn the_received_path_starts_at_the_certificate_its_sid_names() -> TestResult {
	let named = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let other = TestCertificate::self_signed(&Secp256k1SigningKey::from_bytes(&[0x0fu8; 32].into())?);
	let signed_data = signed_data_carrying([other.to_owned(), named.to_owned()]);
	let received = received_wire(&signed_data);

	let (path, _) = CmsSigner::signer_path(&received)?.ok_or("the set holds the named certificate")?;
	let (leaf, issuers) = path.into_parts();
	assert_eq!((leaf, issuers.as_slice()), (named, [].as_slice()));
	Ok(())
}

/// The `certificates` field an identity encodes once is the field a
/// `SignedData` of its set carries, as a reader finds it on arrival, so both
/// ends of a handshake bind one encoding.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[tokio::test]
async fn an_identity_binds_the_field_a_reader_finds() -> TestResult {
	let identity = chained_identity();
	let signer = identity.sign(SignedContent::data(CONTENT)).await?;
	let presented = Some(identity.presented().set());
	let signed_data = CmsSigner::signed_data(SignedContent::data(CONTENT), signer, presented)?;
	let received = WireDer::<SignedData>::try_from(signed_data.to_der()?.as_slice())?;

	let (_, field) = CmsSigner::signer_path(&received)?.ok_or("the set holds the named certificate")?;
	assert_eq!(field, identity.presented().field());
	Ok(())
}

/// A set of nine certificates, one past
/// [`MAX_PRESENTED_PATH`](crate::constants::MAX_PRESENTED_PATH), is refused.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn a_set_of_nine_certificates_is_refused() -> TestResult {
	let named = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let signed_data = signed_data_carrying(iter::once(named).chain(TestCertificate::strangers(8)));
	let received = received_wire(&signed_data);

	let refused = CmsSigner::signer_path(&received);
	let capped = matches!(refused, Err(SignerError::Certificate(PathLenExceeded)));
	assert!(capped);
	Ok(())
}

/// The DER of the `SignedData` of [`signed`] with two `certificates` fields
/// beside each other, one carrying `first`, then one carrying `second`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn twice_certified(first: Certificate, second: Certificate) -> Vec<u8> {
	let first = elements_of(&signed_data_carrying([first]).to_der().expect("a SignedData encodes"));
	let second = elements_of(&signed_data_carrying([second]).to_der().expect("a SignedData encodes"));
	let second_field = second.get(3).expect("a SignedData of a set carries its certificates fourth");
	let (head, signers) = first.split_at(4);

	let fields = [head.concat(), second_field.to_owned(), signers.concat()];
	tlv(Tag::Sequence, &fields.concat())
}

/// The DER of the `SignedData` of [`signed`] whose `certificates` field
/// carries `certificate`, the DER of one certificate as it arrives.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn carrying_encoding(certificate: &[u8]) -> Vec<u8> {
	let placeholder = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let fields = elements_of(&signed_data_carrying([placeholder]).to_der().expect("a SignedData encodes"));
	let (head, rest) = fields.split_at(3);
	let signers = rest.get(1..).expect("a SignedData of a set carries its signers after it");
	let certificates = tlv(CERTIFICATES_TAG, certificate);

	tlv(Tag::Sequence, &[head.concat(), certificates, signers.concat()].concat())
}

/// The DER of `certificate` with an explicit `critical FALSE` in its first
/// extension that states no criticality, the default that DER omits
/// (X.690 § 11.5).
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn with_explicit_default(certificate: &Certificate) -> Vec<u8> {
	let mut parts = elements_of(&certificate.to_der().expect("a certificate encodes"));
	let tbs = parts.first_mut().expect("a certificate starts with its TBS");
	let mut fields = elements_of(tbs);
	let tagged = fields.pop().expect("a test certificate carries extensions last");
	let mut extensions = elements_of(AnyRef::from_der(&tagged).expect("an element decodes").value());
	let unstated = extensions.iter_mut().find(|extension| elements_of(extension).len() == 2);
	let unstated = unstated.expect("a test certificate carries an extension that states no criticality");
	let mut extension = elements_of(unstated);

	extension.insert(1, Vec::from([0x01, 0x01, 0x00]));
	*unstated = tlv(Tag::Sequence, &extension.concat());

	let extensions_tag = Tag::ContextSpecific { constructed: true, number: TagNumber::N3 };
	fields.push(tlv(extensions_tag, &tlv(Tag::Sequence, &extensions.concat())));
	*tbs = tlv(Tag::Sequence, &fields.concat());
	tlv(Tag::Sequence, &parts.concat())
}

/// The elements of the SEQUENCE that `der` encodes, each as it arrived.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn elements_of(der: &[u8]) -> Vec<Vec<u8>> {
	let mut reader = SliceReader::new(der).expect("a test encoding fits a DER length");
	let header = Header::decode(&mut reader).expect("a test encoding starts with a header");
	let elements = reader.read_nested(header.length, |elements| {
		let mut read = Vec::new();
		while !elements.is_finished() {
			read.push(elements.tlv_bytes()?.to_vec());
		}
		Ok(read)
	});
	elements.expect("a test encoding is a SEQUENCE of elements")
}

/// The typed decode keeps the first of two `certificates` fields, and the
/// scan that bounds the received bytes before their decode refuses the
/// second, so the two reads name one set.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn a_signed_data_with_two_certificates_fields_is_refused() -> TestResult {
	let named = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let stranger_key = Secp256k1SigningKey::from_bytes(&[2; 32].into())?;
	let stranger = TestCertificate::self_signed(&stranger_key);
	let received = twice_certified(stranger, named);

	let refused = CmsSigner::bound_presented(&received);
	let second_field = ErrorKind::TagUnexpected { expected: None, actual: CERTIFICATES_TAG };
	assert!(matches!(refused, Err(SignerError::Encoding(error)) if error.kind() == second_field));
	Ok(())
}

/// A certificate whose bytes differ from its DER decodes to the certificate
/// its CA signed, and the store would verify that DER. A presented path reads
/// its certificates from a [`WireDer`] alone, whose decode refuses them.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn a_certificate_in_another_encoding_than_its_der_is_refused() -> TestResult {
	let named = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let received = carrying_encoding(&with_explicit_default(&named));

	let reply = WireDer::<SignedData>::try_from(received.as_slice()).map_err(SignerError::Encoding);
	let refused = reply.and_then(|reply| Ok(CmsSigner::signer_path(&reply)?.is_some()));
	let noncanonical = ErrorKind::Noncanonical { tag: Tag::Sequence };
	assert!(matches!(refused, Err(SignerError::Encoding(error)) if error.kind() == noncanonical));
	Ok(())
}

/// The `Signed` decode of a client Finished, or of a receipt, compares the
/// DER of each certificate with the bytes it arrived as, as the client does,
/// and refuses a certificate in another encoding.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn a_signed_decode_refuses_a_certificate_in_another_encoding_than_its_der() -> TestResult {
	let named = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let received = carrying_encoding(&with_explicit_default(&named));

	let refused = Signed::<SignedData>::from_der(&received).map_err(|error| error.kind());
	assert_eq!(refused, Err(ErrorKind::Noncanonical { tag: Tag::Sequence }));
	Ok(())
}

/// The `Signed` decode holds the decoded value to the octets it arrived as,
/// so it refuses a second `certificates` field that the typed decode
/// skipped.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn a_signed_decode_refuses_two_certificates_fields() -> TestResult {
	let named = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let stranger_key = Secp256k1SigningKey::from_bytes(&[2; 32].into())?;
	let stranger = TestCertificate::self_signed(&stranger_key);
	let received = twice_certified(stranger, named);

	let refused = Signed::<SignedData>::from_der(&received).map_err(|error| error.kind());
	assert_eq!(refused, Err(ErrorKind::Noncanonical { tag: Tag::Sequence }));
	Ok(())
}

/// The cap counts each choice of the set as it arrived, before any
/// certificate parses, so a choice of another format counts toward it.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn a_choice_of_another_format_counts_toward_the_cap() -> TestResult {
	let received = received_wire(&signed_data_of_nine_choices());

	let refused = CmsSigner::signer_path(&received);
	let capped = matches!(refused, Err(SignerError::Certificate(PathLenExceeded)));
	assert!(capped);
	Ok(())
}

/// The walk takes the issuer of each certificate by name, so a set that holds
/// the root and the intermediate of the fixed chain yields both above the
/// leaf, the top first.
#[cfg(feature = "transport-cms")]
#[test]
fn the_walk_takes_each_issuer_by_name_the_top_first() -> TestResult {
	let chain = TestCertificate::insecure_fixed_chain()?;
	let stranger = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let held = vec![chain.intermediate.to_owned(), stranger, chain.root.to_owned()];

	let path = PresentedPath::walk(chain.leaf.to_owned(), held)?;
	let (leaf, issuers) = path.into_parts();
	let top_first = [chain.root, chain.intermediate];
	assert_eq!((leaf, issuers.as_slice()), (chain.leaf, top_first.as_slice()));
	Ok(())
}

/// Two certificates whose subject is the name of one issuer leave the walk
/// no single issuer, so the walk refuses the set.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn the_walk_refuses_two_issuers_of_one_subject() -> TestResult {
	let chain = TestCertificate::insecure_fixed_chain()?;
	let mut twin = chain.intermediate.to_owned();
	twin.tbs_certificate.serial_number = SerialNumber::new(&[9])?;

	let held = vec![chain.intermediate.to_owned(), twin];
	let refused = PresentedPath::walk(chain.leaf, held);
	assert!(matches!(refused, Err(CertificateValidationError::AmbiguousIssuer { .. })));
	Ok(())
}

/// A set whose issuers name each other leads the walk back into its path, so
/// the walk refuses it.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn the_walk_refuses_a_path_that_returns_to_itself() -> TestResult {
	let chain = TestCertificate::insecure_fixed_chain()?;
	let held = Vec::from(TestCertificate::looping_issuers(&chain.intermediate));

	let refused = PresentedPath::walk(chain.leaf, held);
	assert!(matches!(refused, Err(CertificateValidationError::PathCycle { .. })));
	Ok(())
}

/// An identity presents the intermediate it is given beside its own
/// certificate.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn an_identity_presents_its_chain_in_its_certificates_field() {
	let identity = chained_identity();
	let expected = TestCertificate::set_of(chained_certificates());
	assert_eq!(identity.presented().set(), expected);
}

/// A chain in which a certificate does not name the next one as its issuer
/// is refused where it is set.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn an_identity_refuses_a_chain_that_names_another_issuer() -> TestResult {
	let chain = TestCertificate::insecure_fixed_chain()?;
	let identity = TestIdentity::presenting(chain.leaf, &chain.leaf_key);

	let refused = identity.with_chain([chain.root]);
	let unchained = matches!(refused, Err(SignerError::Certificate(InvalidChain { .. })));
	assert!(unchained);
	Ok(())
}

/// A self-issued certificate is its own issuer, so a chain that sets a
/// certificate of its name above it holds two issuers of one name, which the
/// identity refuses where the chain is set.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn an_identity_refuses_a_chain_above_its_self_issued_certificate() {
	let identity = TestIdentity::of(&TestKey::insecure_fixed_signing());
	let stranger = TestCertificate::strangers(1);

	let refused = identity.with_chain(stranger);
	let ambiguous = matches!(refused, Err(SignerError::Certificate(AmbiguousIssuer { .. })));
	assert!(ambiguous);
}

/// A chain past the cap is refused where it is set, so an identity presents
/// no path its peers refuse.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn an_identity_refuses_a_chain_past_the_cap() -> TestResult {
	let chain = TestCertificate::insecure_fixed_chain()?;
	let identity = TestIdentity::presenting(chain.leaf.to_owned(), &chain.leaf_key);

	let refused = identity.with_chain(long_chain_above(&chain.leaf));
	let capped = matches!(refused, Err(SignerError::Certificate(PathLenExceeded)));
	assert!(capped);
	Ok(())
}

/// The identity of the leaf of the fixed chain, which presents the
/// intermediate.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn chained_identity() -> SigningIdentity {
	let chain = TestCertificate::insecure_fixed_chain().expect("the fixed test chain issues");
	let identity = TestIdentity::presenting(chain.leaf, &chain.leaf_key);
	let chained = identity.with_chain([chain.intermediate]);
	chained.expect("the intermediate issued the leaf")
}

/// The leaf and the intermediate of the fixed chain, as a set holds them.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn chained_certificates() -> [Certificate; 2] {
	let chain = TestCertificate::insecure_fixed_chain().expect("the fixed test chain issues");
	[chain.leaf, chain.intermediate]
}

/// A choice of another certificate format that holds `octet`, from which no
/// certificate parses.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn other_format(octet: u8) -> CertificateChoices {
	let content = OctetString::new([octet]).expect("one octet is an OCTET STRING");
	let other_cert = Any::encode_from(&content).expect("an OCTET STRING encodes");
	CertificateChoices::Other(OtherCertificateFormat { other_cert_format: DATA, other_cert })
}

/// Eight certificates above `leaf`, each named the issuer of the one below,
/// a chain one past the cap with `leaf`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn long_chain_above(leaf: &Certificate) -> Vec<Certificate> {
	let mut below = leaf.tbs_certificate.issuer.to_owned();
	let mut chain = TestCertificate::strangers(8);
	for (level, issuer) in (1u8..).zip(chain.iter_mut()) {
		issuer.tbs_certificate.subject = below;
		below = RdnSequence::from_str(&format!("CN=level {level}")).expect("a level name parses");
		issuer.tbs_certificate.issuer = below.to_owned();
	}

	chain
}

/// An unsigned attribute joins the one signer of a `SignedData`, and the
/// signature still verifies, since it covers the signed attributes alone.
#[cfg(feature = "transport-hpke")]
#[test]
fn an_unsigned_attribute_joins_the_one_signer() -> TestResult {
	let content = SignedContent::data(CONTENT);
	let signed_data = CmsSigner::signed_data(content, signed(), None)?;
	let attribute = Attribute { oid: RECEIPT_ROLE, values: SetOfVec::try_from(vec![Any::encode_from(&1u8)?])? };

	let joined = signed_data.with_unsigned_attribute(attribute.to_owned())?;
	let signer = joined.signer_infos.0.iter().next().ok_or("the SignedData has a signer")?;
	let carried = signer.unsigned_attrs.as_ref().map(|attrs| attrs.as_slice().to_vec());
	assert_eq!(carried, Some(vec![attribute]));
	verify(signer)?;
	Ok(())
}

/// The scalar of the key, 32 octets of it, whose countersignature `der`
/// sorts ahead of the signer of [`signed`], against the octet order of DER.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const DIVERGENT_SCALAR: u8 = 5;

/// The countersignature over [`CONTENT`] of the key whose scalar is 32
/// octets of `scalar`, beside its self-signed certificate.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn certified_stranger(scalar: u8) -> CertifiedSigner {
	let key = Secp256k1SigningKey::from_bytes(&[scalar; 32].into()).expect("a small scalar is a key");
	let certificate = Arc::new(TestCertificate::self_signed(&key));
	let signer = signed_by(&TestIdentity::certified(key), SignedContent::data(CONTENT));
	CertifiedSigner::new(signer, certificate).expect("the sid names the certificate of its key")
}

/// The `SignedData` of [`signed`] that the key of [`DIVERGENT_SCALAR`]
/// countersigned, whose signers `der` holds in another order than DER's.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn countersigned() -> Signed<SignedData> {
	let first = CmsSigner::signed_data(SignedContent::data(CONTENT), signed(), None).expect("the test key signs");
	let both = first.with_certified_signer(certified_stranger(DIVERGENT_SCALAR));
	both.expect("a second signer joins")
}

/// A countersigned `SignedData` whose signers `der` holds in another order
/// than DER's encodes them in DER's order (X.690 § 11.6), so the admission
/// of its own encoding passes.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn a_countersigned_signed_data_encodes_its_signers_in_der_order() -> TestResult {
	let both = countersigned();
	let in_der_sort = both.as_ref().to_der()?;
	let encoded = both.to_der()?;

	let admission = DerAdmission::SetOrder;
	let refused = admission.admit(in_der_sort).map_err(|error| error.kind());
	assert_eq!(refused, Err(ErrorKind::SetOrdering));
	admission.admit(encoded)?;
	Ok(())
}

/// `der` orders each universal SET of a `SignerInfo` by its octets: the RDN
/// of an `IssuerAndSerialNumber` `sid`, the signed attributes, and their
/// values. A `SignerInfo` that holds two-valued sets of each kind, of unequal
/// lengths, encodes in DER order with no arrangement, which the in-place
/// encode of a `Signed` `SignerInfo` rests on.
#[test]
fn a_signer_info_of_two_valued_sets_encodes_in_der_order() -> TestResult {
	let mut signer_info = signed().into_inner();
	let issuer = RdnSequence::from_str("CN=a common name of some length+O=b")?;
	let serial_number = SerialNumber::new(&[0x01])?;
	signer_info.sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber { issuer, serial_number });
	let long = Any::encode_from(&OctetString::new(*b"a value of some length")?)?;
	let short = Any::encode_from(&OctetString::new(*b"b")?)?;
	let values = SetOfVec::try_from([long, short])?;
	let attribute = Attribute { oid: ObjectIdentifier::new_unwrap("1.2.3.4"), values };
	let signed_attrs = signer_info.signed_attrs.get_or_insert_with(SignedAttributes::new);
	signed_attrs.insert(attribute)?;

	DerAdmission::SetOrder.admit(signer_info.to_der()?)?;
	Ok(())
}

/// Two self-signed certificates under fixed keys, of one length, that a SET
/// OF `der` sorts in the reverse of their DER order. `der` 0.7 compares two
/// certificate choices of one length by their encodings read as a SEQUENCE
/// OF INTEGER, which counts the octets past `0x7f` first.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn certificates_der_sorts_out_of_order() -> [Certificate; 2] {
	let first = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let second_of = |octet: u8| {
		let key = Secp256k1SigningKey::from_bytes(&[octet; 32].into()).expect("a fixed octet is a test key");
		TestCertificate::self_signed(&key)
	};
	let out_of_order = |second: &Certificate| {
		let set = TestCertificate::set_of([first.to_owned(), second.to_owned()]);
		let encodings: Vec<Vec<u8>> = set.0.iter().map(|choice| choice.to_der().expect("a choice encodes")).collect();
		encodings.windows(2).any(|pair| pair.first() > pair.get(1))
	};

	let second = (2..=u8::MAX).map(second_of).find(out_of_order);
	let second = second.expect("one fixed key gives a pair that `der` sorts out of DER order");
	[first, second]
}

/// A `SignedData` sends its `certificates` in DER order (X.690 § 11.6), as
/// the client Finished, the reply, and a receipt do through their `Signed`
/// encode, though `der` sorts the set in another order.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn a_signed_data_sends_its_certificates_in_der_order() -> TestResult {
	let set = TestCertificate::set_of(certificates_der_sorts_out_of_order());
	let signed = CmsSigner::signed_data(SignedContent::data(CONTENT), signed(), Some(set))?;
	let sent = signed.to_der()?;

	let arrived = ArrivedCertificates::read(&sent)?.ok_or("the SignedData carries its certificates")?;
	let choices = AnyRef::from_der(arrived.field())?;
	DerAdmission::SetOrder.admit(tlv(Tag::Set, choices.value()))?;
	Ok(())
}

/// The DER encoder of the crate gives the signers of a countersigned
/// `SignedData` their DER order, even outside its `Signed` wrapper.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn the_der_encoder_gives_the_signers_their_der_order() -> TestResult {
	let both = countersigned();
	let encoded = crate::encode(both.as_ref())?;
	DerAdmission::SetOrder.admit(encoded)?;
	Ok(())
}

/// A `SignedData` of two signers takes no unsigned attribute, since it names
/// no one signer.
#[cfg(feature = "transport-hpke")]
#[test]
fn an_unsigned_attribute_refuses_two_signers() -> TestResult {
	let content = SignedContent::data(CONTENT);
	let first = CmsSigner::signed_data(content, signed(), None)?;
	let other_key = Secp256k1SigningKey::random(&mut OsRng);
	let other_certificate = Arc::new(TestCertificate::self_signed(&other_key));
	let other = signed_by(&TestIdentity::certified(other_key), SignedContent::data(CONTENT));
	let other = CertifiedSigner::new(other, other_certificate)?;
	let both = first.with_certified_signer(other)?;
	let attribute = Attribute { oid: RECEIPT_ROLE, values: SetOfVec::try_from(vec![Any::encode_from(&1u8)?])? };

	let refused = both.with_unsigned_attribute(attribute);
	assert!(matches!(refused, Err(SignerError::SignerIdentifier)));
	Ok(())
}
