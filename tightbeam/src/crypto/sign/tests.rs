//! The CMS signer, the signing identity, and the key identifier.

use std::sync::Arc;

use super::*;
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
use crate::crypto::x509::utils::{CertificateExt, Skid};
use crate::crypto::x509::KeyPurposes;
use crate::crypto::x509::{ErasedSigning, PeerCertificate, Signing};
use crate::der::asn1::{BitString, OctetString, SetOfVec};
use crate::der::oid::AssociatedOid;
use crate::der::{Any, Decode, Encode, Tag};
use crate::error::ReceivedExpectedError;
use crate::oids::{
	ATTR_CMS_ALGORITHM_PROTECTION, ATTR_CONTENT_TYPE, ATTR_MESSAGE_DIGEST, DATA, HASH_SHA3_256, HASH_SHA3_512,
	RECEIPT_ROLE, SESSION_RECEIPT_CONTENT, SIGNER_ECDSA_WITH_SHA256,
};
use crate::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use crate::testing::fixtures::{TestAttributes, TestCertificate, TestIdentity, TestKey};
use crate::utils::marker::MaybeSendFuture;
use crate::x509::attr::Attribute;
use crate::x509::ext::pkix::{KeyUsage, KeyUsages, SubjectKeyIdentifier};

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

/// A certificate the crate mints carries its key identifier, so it names
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

/// A `SignedData` of a version 1 signer over `id-data` is version 1 (RFC
/// 5652 §5.1).
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

/// A `SignedData` that holds a certificate of type `other` is version 5 (RFC
/// 5652 §5.1).
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
#[test]
fn a_version_3_countersignature_lifts_the_signed_data_to_version_3() -> TestResult {
	let content = SignedContent::data(CONTENT);
	let signer = signed_by(&issuer_and_serial_key(), SignedContent::data(CONTENT));
	let signed_data = CmsSigner::signed_data(content, signer, None)?;

	let joined = signed_data.with_signer(signed())?;
	assert_eq!(joined.version, CmsVersion::V3);
	Ok(())
}

/// A joining signer's digest algorithm enters `digestAlgorithms` (RFC 5652
/// §5.1).
#[test]
fn a_joining_signer_declares_its_digest_algorithm() -> TestResult {
	let content = SignedContent::data(CONTENT);
	let signed_data = CmsSigner::signed_data(content, signed(), None)?;
	let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_512, parameters: None };
	let foreign = SignerInfo { digest_alg: digest_alg.clone(), ..signed().into_inner() };

	let joiner = Signed::<SignerInfo>::from_der(&foreign.to_der()?)?;
	let joined = signed_data.with_signer(joiner)?;
	assert!(joined.digest_algorithms.as_ref().contains(&digest_alg));
	Ok(())
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
fn signed_data_carrying(certificates: impl IntoIterator<Item = crate::x509::Certificate>) -> SignedData {
	let choices: Vec<CertificateChoices> = certificates.into_iter().map(CertificateChoices::Certificate).collect();
	let set = CertificateSet(choices.try_into().expect("distinct certificates are a SET"));
	let signed_data = CmsSigner::signed_data(SignedContent::data(CONTENT), signed(), Some(set));
	signed_data.expect("the SignedData assembles").into_inner()
}

/// The certificate the one signer names moves out of `certificates`, and
/// the rest of the set stays (RFC 5652 §5.3).
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn taking_the_signer_certificate_leaves_the_rest_of_the_set() -> TestResult {
	let named = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let other = TestCertificate::self_signed(&Secp256k1SigningKey::random(&mut crate::random::OsRng));
	let mut signed_data = signed_data_carrying([other.to_owned(), named.to_owned()]);

	let taken = CmsSigner::take_signer_certificate(&mut signed_data)?;
	let rest = signed_data.certificates.map(|set| set.0.into_vec());
	assert_eq!(taken, Some(named));
	assert_eq!(rest, Some(vec![CertificateChoices::Certificate(other)]));
	Ok(())
}

/// A set that holds no certificate the signer names gives none, and keeps
/// what it holds.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[test]
fn taking_from_a_set_without_the_signer_certificate_takes_nothing() -> TestResult {
	let other = TestCertificate::self_signed(&Secp256k1SigningKey::random(&mut crate::random::OsRng));
	let mut signed_data = signed_data_carrying([other.to_owned()]);

	let taken = CmsSigner::take_signer_certificate(&mut signed_data)?;
	let kept = signed_data.certificates.map(|set| set.0.into_vec());
	assert_eq!(taken, None);
	assert_eq!(kept, Some(vec![CertificateChoices::Certificate(other)]));
	Ok(())
}

/// The scan of the received set returns the certificate the one signer
/// names, parsed from the element it arrived as, beside those bytes. Under
/// the fixed key `0x02` × 32, the other certificate sorts first in the SET,
/// so the named certificate is the second element.
#[cfg(feature = "transport-hpke")]
#[test]
fn the_received_signer_certificate_is_the_one_its_sid_names() -> TestResult {
	let named = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let other = TestCertificate::self_signed(&Secp256k1SigningKey::from_bytes(&[0x02u8; 32].into())?);
	let signed_data = signed_data_carrying([other.to_owned(), named.to_owned()]);
	let first = signed_data.certificates.iter().flat_map(|set| set.0.iter()).next();
	let received = signed_data.to_der()?;
	let expected = named.to_der()?;

	let arrived = CmsSigner::signer_certificate_der(&signed_data, &received)?;
	assert_eq!(first, Some(&CertificateChoices::Certificate(other)));
	assert_eq!(arrived, Some((named, expected.as_slice())));
	Ok(())
}

/// An unsigned attribute joins the one signer of a `SignedData`, and the
/// signature still verifies, since it covers no unsigned attribute.
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

/// A `SignedData` of two signers takes no unsigned attribute, since it names
/// no one signer.
#[cfg(feature = "transport-hpke")]
#[test]
fn an_unsigned_attribute_refuses_two_signers() -> TestResult {
	let content = SignedContent::data(CONTENT);
	let first = CmsSigner::signed_data(content, signed(), None)?;
	let other = TestIdentity::certified(Secp256k1SigningKey::random(&mut crate::random::OsRng));
	let both = first.with_signer(signed_by(&other, SignedContent::data(CONTENT)))?;
	let attribute = Attribute { oid: RECEIPT_ROLE, values: SetOfVec::try_from(vec![Any::encode_from(&1u8)?])? };

	let refused = both.with_unsigned_attribute(attribute);
	assert!(matches!(refused, Err(SignerError::SignerIdentifier)));
	Ok(())
}
