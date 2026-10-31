//! The CMS signer, the signing identity, and the key identifier.

use core::str::FromStr;
use std::sync::Arc;

use super::*;
use crate::asn1::admission::fixtures::{der_refusal, tlv};
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
use crate::crypto::x509::utils::{CertificateExt, Skid};
use crate::crypto::x509::KeyPurposes;
use crate::crypto::x509::{ErasedSigning, PeerCertificate, Signing};
use crate::der::asn1::{BitString, OctetString, SetOfVec};
use crate::der::oid::AssociatedOid;
use crate::der::{Any, AnyRef, Decode, Encode, ErrorKind, Tag};
use crate::error::ReceivedExpectedError;
use crate::marker::MaybeSendFuture;
use crate::oids::{
	ATTR_CMS_ALGORITHM_PROTECTION, ATTR_CONTENT_TYPE, ATTR_MESSAGE_DIGEST, DATA, HASH_SHA3_256, HASH_SHA3_512,
	RECEIPT_ROLE, SESSION_RECEIPT_CONTENT, SIGNER_ECDSA_WITH_SHA256,
};
use crate::runtime::rt;
use crate::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use crate::testing::fixtures::{TestAlgorithm, TestAttributes, TestCertificate, TestIdentity, TestKey};
use crate::testing::TestResult;
use crate::x509::attr::Attribute;
use crate::x509::ext::pkix::{KeyUsage, KeyUsages, SubjectKeyIdentifier};
use crate::x509::name::RdnSequence;
use crate::x509::serial_number::SerialNumber;
use crate::x509::Certificate;

/// The content every test signs, whose raw `s` under the fixed test key lies
/// in the high half.
const CONTENT: &[u8] = TestKey::HIGH_S_CONTENT;

/// The fixed test key beside a certificate with no key identifier, which
/// names it by issuer and serial number.
fn issuer_and_serial_key() -> CertifiedKey<Secp256k1SigningKey> {
	let key = TestKey::insecure_fixed_signing();
	let certificate = TestCertificate::without_extension(TestCertificate::insecure_fixed(), SubjectKeyIdentifier::OID);
	CertifiedKey::new(&certificate, key).expect("the test key matches its certificate")
}

/// The `SignerInfo` that `key` signs over `content`.
fn signed_by(key: &CertifiedKey<Secp256k1SigningKey>, content: SignedContent<'_>) -> Signed<SignerInfo> {
	CmsSigner::sign_with::<Secp256k1Signature, _>(key, content).expect("the test key signs")
}

/// The fixed test key beside its self-signed certificate.
fn certified_fixed_key() -> CertifiedKey<Secp256k1SigningKey> {
	TestIdentity::certified(TestKey::insecure_fixed_signing())
}

/// The `SignerInfo` the fixed test key signs over [`CONTENT`], under its
/// self-signed certificate.
fn signed() -> Signed<SignerInfo> {
	signed_by(&certified_fixed_key(), SignedContent::data(CONTENT))
}

/// The `SignerInfo` the fixed test key signs over [`CONTENT`] as
/// `content_type`, under a certificate that names it by issuer and serial
/// number.
fn issuer_and_serial_signed(content_type: ObjectIdentifier) -> Signed<SignerInfo> {
	signed_by(&issuer_and_serial_key(), SignedContent::new(content_type, CONTENT))
}

/// The `SignedData` that carries [`CONTENT`] as `id-data`, `signer`, and
/// `certificates`.
fn signed_data_of(signer: Signed<SignerInfo>, certificates: Option<CertificateSet>) -> Signed<SignedData> {
	let signed_data = CmsSigner::signed_data(SignedContent::data(CONTENT), signer, certificates);
	signed_data.expect("the SignedData assembles")
}

/// The `SignedData` that carries [`CONTENT`] and [`signed`].
fn signed_data() -> SignedData {
	signed_data_of(signed(), None).into_inner()
}

/// The `SignerInfo` that `identity` signs over [`CONTENT`]. The provider
/// signs with no timer and no socket, so the signature blocks in place.
fn signed_by_identity(identity: &SigningIdentity) -> Signed<SignerInfo> {
	let signed = rt::block_on(identity.sign(SignedContent::data(CONTENT)));
	signed.expect("the identity signs")
}

/// A `receiptRole` attribute of one value, `role`.
fn receipt_role(role: u8) -> Attribute {
	let value = Any::encode_from(&role).expect("a small integer encodes");
	let values = SetOfVec::try_from(vec![value]).expect("one value forms a SET");
	Attribute { oid: RECEIPT_ROLE, values }
}

/// A choice of another certificate format that holds `octet`, from which no
/// certificate parses.
fn other_format(octet: u8) -> CertificateChoices {
	let content = OctetString::new([octet]).expect("one octet is an OCTET STRING");
	let other_cert = Any::encode_from(&content).expect("an OCTET STRING encodes");
	CertificateChoices::Other(OtherCertificateFormat { other_cert_format: DATA, other_cert })
}

/// A key provider that returns its key's signature in another form than the
/// DER low-s one, as some external backends do.
///
/// The backends that return those forms, such as an HSM or a cloud KMS, run
/// outside `cargo test`, so their forms run only as this double over the
/// house provider.
#[derive(Debug)]
struct ExternalProvider {
	inner: Secp256k1KeyProvider,
	algorithm: ObjectIdentifier,
	reshape: fn(ecdsa::Signature<Secp256k1>) -> Vec<u8>,
}

impl KeyBackend for ExternalProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		TestAlgorithm::of(self.algorithm)
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
	TestKey::high_s_twin(scalars).to_der().as_bytes().to_vec()
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
	let provider = external_provider(SIGNER_ECDSA_WITH_SHA3_256, reshape);
	SigningIdentity::new(TestCertificate::insecure_fixed(), provider).expect("the test key matches its certificate")
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
		digest_algorithm: TestAlgorithm::of(digest),
		signature_algorithm: Some(TestAlgorithm::of(signature)),
		mac_algorithm: None,
	};

	let value = Any::encode_from(&protection).expect("the attribute encodes");
	let values = SetOfVec::try_from(vec![value]).expect("one value forms a SET");
	Attribute { oid: ATTR_CMS_ALGORITHM_PROTECTION, values }
}

/// [`signed`] under the digest algorithm `digest` and the signature
/// algorithm `signature`, with an algorithm protection of the two that the
/// fixed test key signs again.
fn signed_under(digest: ObjectIdentifier, signature: ObjectIdentifier) -> SignerInfo {
	let signer_info = signed();
	let digest_alg = TestAlgorithm::of(digest);
	let signature_algorithm = TestAlgorithm::of(signature);
	let mismatched = SignerInfo { digest_alg, signature_algorithm, ..signer_info.clone().into_inner() };
	let mut attributes = attributes_without(&signer_info, ATTR_CMS_ALGORITHM_PROTECTION);
	attributes.push(protection(digest, signature));
	resigned(&mismatched, attributes)
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

/// [`signed`] with its signature replaced by the `(r, n - s)` twin of its
/// own.
fn high_s_signed() -> SignerInfo {
	let signer_info = signed();
	let twin = TestKey::high_s_twin(scalars(&signer_info));
	with_signature(&signer_info, twin.to_der().as_bytes())
}

/// A draft of the fixed test key over [`CONTENT`], beside the raw signature
/// that key makes over its prehash.
fn drafted() -> (SignerInfoDraft, ecdsa::Signature<Secp256k1>) {
	let key = TestKey::insecure_fixed_signing();
	let sid = certified_fixed_key().signer_identifier().clone();
	let draft = CmsSigner::draft::<Secp256k1Signature>(sid, SignedContent::data(CONTENT));
	let draft = draft.expect("the fixed test key drafts");
	let signature = key.sign_prehash(draft.prehash()).expect("the fixed test key signs");
	(draft, signature)
}

/// A pairing of a key with a certificate: a key that signs in place, or a
/// signing identity of the house provider.
type Pairing = fn(Certificate, Secp256k1SigningKey) -> Result<(), SignerError>;

/// Pairs `key` with `certificate` as a key that signs in place.
fn as_certified_key(certificate: Certificate, key: Secp256k1SigningKey) -> Result<(), SignerError> {
	CertifiedKey::new(&certificate, key).map(drop)
}

/// Pairs `key` with `certificate` as a signing identity of the house
/// provider.
fn as_signing_identity(certificate: Certificate, key: Secp256k1SigningKey) -> Result<(), SignerError> {
	SigningIdentity::new(certificate, TestKey::provider(key)).map(drop)
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
	let certificate = TestCertificate::insecure_fixed();
	let expected = SubjectKeyIdentifier::from(OctetString::new(TestKey::INSECURE_FIXED_KEY_IDENTIFIER)?);

	let sid = certificate.signer_identifier()?;
	assert_eq!(sid, SignerIdentifier::SubjectKeyIdentifier(expected));
	Ok(())
}

/// A certificate with no key identifier is named by its issuer and serial
/// number.
#[test]
fn a_certificate_with_no_key_identifier_is_named_by_issuer_and_serial() -> TestResult {
	let certificate = TestCertificate::without_extensions(TestCertificate::insecure_fixed());

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
	let certificate = TestCertificate::with_key_identifier(TestCertificate::insecure_fixed(), written.clone());

	let certified = CertifiedKey::new(&certificate, key)?;
	assert_eq!(certified.signer_identifier(), &SignerIdentifier::SubjectKeyIdentifier(written));
	Ok(())
}

// A key whose public half differs from the certificate's
// SubjectPublicKeyInfo pairs with no certificate, as a key that signs in
// place or as a signing identity, the negation of its key among them, though
// the two points share an x-coordinate.
crate::tb_cases! {
	fn the_pairing_refuses_a_mismatched_key((pairing, other): (Pairing, Secp256k1SigningKey)) {
		let refused = pairing(TestCertificate::insecure_fixed(), other);
		assert!(matches!(refused, Err(SignerError::KeyMismatch)));
	}
	cases {
		certified_key_of_another_key => (as_certified_key, TestKey::fixed(0x02)),
		certified_key_of_the_negation => (as_certified_key, TestKey::negation_of(&TestKey::insecure_fixed_signing())),
		signing_identity_of_another_key => (as_signing_identity, TestKey::fixed(0x02)),
		signing_identity_of_the_negation => (
			as_signing_identity,
			TestKey::negation_of(&TestKey::insecure_fixed_signing()),
		),
	}
}

// A key pairs with a certificate that holds its point in the compressed SEC
// 1 form, as a key that signs in place or as a signing identity, since both
// forms name one key (RFC 5480 §2.2).
crate::tb_cases! {
	fn the_pairing_admits_a_key_in_the_compressed_form(pairing: Pairing) -> TestResult {
		let certificate = TestCertificate::with_compressed_key(TestCertificate::insecure_fixed());
		pairing(certificate, TestKey::insecure_fixed_signing())?;
		Ok(())
	}
	cases {
		certified_key => as_certified_key,
		signing_identity => as_signing_identity,
	}
}

// A certificate whose `keyUsage` carries `keyAgreement` alone pairs with no
// key, as a key that signs in place or as a signing identity, so its key
// signs nothing either emits.
crate::tb_cases! {
	fn the_pairing_refuses_a_certificate_without_digital_signature(pairing: Pairing) {
		let usage = KeyUsage(KeyUsages::KeyAgreement.into());
		let certificate = TestCertificate::with_key_usage(TestCertificate::insecure_fixed(), usage);

		let refused = pairing(certificate, TestKey::insecure_fixed_signing());
		assert!(matches!(
			refused,
			Err(SignerError::Certificate(CertificateValidationError::MissingKeyUsage(KeyUsages::DigitalSignature)))
		));
	}
	cases {
		certified_key => as_certified_key,
		signing_identity => as_signing_identity,
	}
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

// A `SignerInfo` takes the version its `sid` demands: 3 when a key
// identifier names its signer, and 1 when an issuer and serial number do
// (RFC 5652 §5.3).
crate::tb_cases! {
	fn a_signer_info_takes_the_version_of_its_sid((signer_info, version): (Signed<SignerInfo>, CmsVersion)) {
		assert_eq!(signer_info.version, version);
	}
	cases {
		key_identifier => (signed(), CmsVersion::V3),
		issuer_and_serial => (issuer_and_serial_signed(DATA), CmsVersion::V1),
	}
}

/// The signature value is a DER `ECDSA-Sig-Value` (RFC 5753 §2.1.1).
#[test]
fn the_signer_writes_a_der_signature_value() -> TestResult {
	let signer_info = signed();
	let parsed = Secp256k1Signature::from_bytes(signer_info.signature.as_bytes())?;
	assert_eq!(parsed.as_bytes(), signer_info.signature.as_bytes());
	Ok(())
}

/// The crate signs with `s` in the low half of the curve order.
#[test]
fn the_signer_writes_a_low_s_signature() {
	let signer_info = signed();
	let pair = scalars(&signer_info);
	assert!(pair.normalize_s().is_none());
}

/// A `SignerInfo` verifies over the content it signs.
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

	let refused = der_refusal(Signed::<SignerInfo>::from_der(&stray));
	assert_eq!(refused, Some(ErrorKind::Noncanonical { tag: Tag::Sequence }));
	Ok(())
}

/// A `SignerInfo` with no signed attributes is refused (RFC 5652 §5.4).
#[test]
fn a_signer_info_with_no_signed_attributes_is_refused() {
	let signer_info = SignerInfo { signed_attrs: None, ..signed().into_inner() };
	let refused = verify(&signer_info);
	assert!(matches!(refused, Err(SignerError::SignedAttributes)));
}

// A `SignerInfo` whose signed attributes lack the message digest or the
// algorithm protection, hold an algorithm protection that names another
// digest than the `SignerInfo` does (RFC 6211 §3), or hold one attribute
// beyond the required set is refused, even when its signature covers them.
crate::tb_cases! {
	fn a_signer_info_with_tampered_signed_attributes_is_refused(attributes: Vec<Attribute>) {
		let tampered = resigned(&signed(), attributes);

		let refused = verify(&tampered);
		assert!(matches!(refused, Err(SignerError::SignedAttributes)));
	}
	cases {
		no_message_digest => attributes_without(&signed(), ATTR_MESSAGE_DIGEST),
		no_algorithm_protection => attributes_without(&signed(), ATTR_CMS_ALGORITHM_PROTECTION),
		mismatched_protection => [
			attributes_without(&signed(), ATTR_CMS_ALGORITHM_PROTECTION),
			vec![protection(HASH_SHA3_512, SIGNER_ECDSA_WITH_SHA3_256)],
		]
		.concat(),
		extra_attribute => [attributes_of(&signed()), vec![receipt_role(1)]].concat(),
	}
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

// A `SignerInfo` whose digest algorithm is not the one its signature
// algorithm names (RFC 5753 §2.1.1), or whose signature algorithm is
// another than `S`'s, is refused, even when its algorithm protection and
// its signature agree with it. The refusal names the algorithm received and
// the one expected.
crate::tb_cases! {
	fn a_signer_info_of_a_mismatched_algorithm_is_refused(
		(tampered, algorithms): (SignerInfo, ReceivedExpectedError<ObjectIdentifier, ObjectIdentifier>)
	) {
		let refused = verify(&tampered);
		assert!(matches!(refused, Err(SignerError::UnexpectedAlgorithm(received)) if received == algorithms));
	}
	cases {
		digest => (
			signed_under(HASH_SHA3_512, SIGNER_ECDSA_WITH_SHA3_256),
			ReceivedExpectedError::from((HASH_SHA3_512, HASH_SHA3_256)),
		),
		signature_algorithm => (
			signed_under(HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA256),
			ReceivedExpectedError::from((SIGNER_ECDSA_WITH_SHA256, SIGNER_ECDSA_WITH_SHA3_256)),
		),
	}
}

// The signer drafts a set that holds each OID once (RFC 5652 §11.1), so it
// refuses a profile attribute under the OID of a required attribute, and a
// second profile attribute under the OID of the first.
crate::tb_cases! {
	fn a_profile_attribute_is_refused_under((content, oid): (SignedContent<'static>, ObjectIdentifier)) -> TestResult {
		let sid = certified_fixed_key().signer_identifier().clone();

		let refused = CmsSigner::draft::<Secp256k1Signature>(sid, content);
		assert!(matches!(refused, Err(SignerError::DuplicateAttribute(found)) if found == oid));
		Ok(())
	}
	cases {
		a_required_oid => (
			SignedContent::data(CONTENT).with_single_valued(ATTR_CONTENT_TYPE, Any::encode_from(&DATA)?)?,
			ATTR_CONTENT_TYPE,
		),
		the_oid_of_another => (
			SignedContent::data(CONTENT).with_attribute(receipt_role(1)).with_attribute(receipt_role(2)),
			RECEIPT_ROLE,
		),
	}
}

/// The signer takes the content by value, so a profile attribute moves into
/// the signed set of the `SignerInfo` that signs it.
#[test]
fn a_profile_attribute_moves_into_the_signed_set() {
	let key = certified_fixed_key();
	let signer_info = signed_by(&key, SignedContent::data(CONTENT).with_attribute(receipt_role(1)));
	assert!(attributes_of(&signer_info).contains(&receipt_role(1)));
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
	let tampered = high_s_signed();
	verify(&tampered)?;
	Ok(())
}

/// A signature and its `(r, n - s)` twin verify to one value, the key every
/// replay guard and ledger holds.
#[test]
fn a_high_s_twin_verifies_to_the_value_of_its_original() -> TestResult {
	let tampered = high_s_signed();

	let original = verify(&signed())?;
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
fn a_draft_refuses_a_raw_r_s_signature() {
	let (draft, signature) = drafted();
	let refused = draft.complete(signature.to_bytes(), None);
	assert!(matches!(refused, Err(SignerError::Signature(_))));
}

/// A draft attaches a high-s signature value in its low-s form.
#[test]
fn a_draft_attaches_a_high_s_signature_in_low_s() -> TestResult {
	let (draft, signature) = drafted();
	let signer_info = draft.complete(high_form(signature), None)?;
	assert!(scalars(&signer_info).normalize_s().is_none());
	Ok(())
}

/// An identity whose provider returns raw `r || s` refuses to sign, so the
/// provider's bytes reach no `SignerInfo`.
#[test]
fn an_identity_refuses_a_provider_that_returns_raw_r_s() {
	let identity = external_identity(raw_form);
	let refused = rt::block_on(identity.sign(SignedContent::data(CONTENT)));
	assert!(matches!(refused, Err(SignerError::Signature(_))));
}

/// An identity whose provider returns a high-s value emits its low-s form.
#[test]
fn an_identity_emits_a_high_s_provider_signature_in_low_s() {
	let identity = external_identity(high_form);
	let signer_info = signed_by_identity(&identity);
	assert!(scalars(&signer_info).normalize_s().is_none());
}

/// The low-s form an identity emits for a high-s provider signature
/// verifies.
#[test]
fn an_identity_signature_from_a_high_s_provider_verifies() -> TestResult {
	let identity = external_identity(high_form);
	let signer_info = signed_by_identity(&identity);
	verify(&signer_info)?;
	Ok(())
}

/// A provider of an algorithm the crate has no canonical form for pairs with
/// no identity.
#[test]
fn a_signing_identity_refuses_an_algorithm_it_has_no_form_for() {
	let provider = external_provider(SIGNER_ECDSA_WITH_SHA256, high_form);
	let refused = SigningIdentity::new(TestCertificate::insecure_fixed(), provider);
	assert!(matches!(refused, Err(SignerError::UnsupportedAlgorithm(oid)) if oid == SIGNER_ECDSA_WITH_SHA256));
}

/// A provider that declares `ecdsa-with-SHA3-256` and returns `public_key`
/// as its SubjectPublicKeyInfo. Its `sign_prehash` refuses every prehash.
///
/// Every house provider declares the algorithm of the key it holds, so a
/// declaration that names another curve's key runs only as this double.
#[derive(Debug)]
struct DeclaringProvider {
	public_key: Vec<u8>,
}

impl KeyBackend for DeclaringProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		TestAlgorithm::of(SIGNER_ECDSA_WITH_SHA3_256)
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
	let certificate = TestCertificate::insecure_fixed();

	let refused = SigningIdentity::with_provider::<DefaultCryptoProvider>(certificate, provider);
	assert!(matches!(refused, Err(SignerError::UnsupportedAlgorithm(oid)) if oid == SIGNER_ECDSA_WITH_SHA3_256));
	Ok(())
}

/// An identity's prehash signature from a provider that returns raw
/// `r || s` is refused, so the bare HPKE signatures carry no such value.
#[test]
fn an_identity_refuses_a_raw_r_s_prehash_signature() {
	let identity = external_identity(raw_form);
	let refused = rt::block_on(identity.sign_prehash(&[0x5a; 32]));
	assert!(matches!(refused, Err(SignerError::Signature(_))));
}

/// An identity returns a provider's high-s prehash signature as the DER of
/// its low-s twin.
#[test]
fn an_identity_returns_a_high_s_prehash_signature_in_low_s() -> TestResult {
	let identity = external_identity(high_form);
	let signature = rt::block_on(identity.sign_prehash(&[0x5a; 32]))?;

	let parsed = Secp256k1Signature::from_bytes(&signature)?;
	let scalars = ecdsa::Signature::<Secp256k1>::try_from(parsed)?;
	assert!(scalars.normalize_s().is_none());
	Ok(())
}

// A `SignedData` takes the version RFC 5652 §5.1 gives it: 3 for a version 3
// signer, 1 for a version 1 signer over `id-data`, 3 for a version 1 signer
// over a content other than `id-data`, and 5 when it holds a certificate of
// type `other`.
crate::tb_cases! {
	fn a_signed_data_takes_its_version(
		(content_type, signer, certificates, version): (
			ObjectIdentifier,
			Signed<SignerInfo>,
			Option<CertificateSet>,
			CmsVersion,
		)
	) -> TestResult {
		let content = SignedContent::new(content_type, CONTENT);

		let signed_data = CmsSigner::signed_data(content, signer, certificates)?;
		assert_eq!(signed_data.version, version);
		Ok(())
	}
	cases {
		of_a_version_3_signer => (DATA, signed(), None, CmsVersion::V3),
		of_a_version_1_signer_over_data => (DATA, issuer_and_serial_signed(DATA), None, CmsVersion::V1),
		over_another_content_type => (
			SESSION_RECEIPT_CONTENT,
			issuer_and_serial_signed(SESSION_RECEIPT_CONTENT),
			None,
			CmsVersion::V3,
		),
		with_another_certificate_format => (
			DATA,
			signed(),
			Some(CertificateSet(SetOfVec::try_from(vec![other_format(0x00)])?)),
			CmsVersion::V5,
		),
	}
}

/// A conforming `SignedData` whose revocation entries hold one of type
/// `other` is version 5, and its content reads (RFC 5652 §5.1).
#[test]
fn a_signed_data_with_another_revocation_format_reads_at_version_5() -> TestResult {
	let other_format = TestAlgorithm::of(DATA);
	let other = OtherRevocationInfoFormat { other_format, other: Any::encode_from(&OctetString::new(CONTENT)?)? };
	let crls = RevocationInfoChoices(SetOfVec::try_from(vec![RevocationInfoChoice::Other(other)])?);
	let foreign = SignedData { version: CmsVersion::V5, crls: Some(crls), ..signed_data() };

	let read = foreign.content(DATA)?;
	assert_eq!(read, CONTENT);
	Ok(())
}

/// A `SignedData` whose version differs from the RFC 5652 §5.1 rule is
/// refused when its content is read.
#[test]
fn a_signed_data_of_the_wrong_version_is_refused() {
	let tampered = SignedData { version: CmsVersion::V1, ..signed_data() };

	let refused = tampered.content(DATA);
	let versions = ReceivedExpectedError::from((CmsVersion::V1, CmsVersion::V3));
	assert!(matches!(refused, Err(SignerError::SignedDataVersion(received)) if received == versions));
}

/// A `SignedData` whose `digestAlgorithms` omits a signer's digest is
/// refused when its content is read (RFC 5652 §5.1).
#[test]
fn a_signed_data_that_omits_a_signer_digest_is_refused() -> TestResult {
	let digest_alg = TestAlgorithm::of(HASH_SHA3_512);
	let digest_algorithms = SetOfVec::try_from(vec![digest_alg])?;
	let tampered = SignedData { digest_algorithms, ..signed_data() };
	let refused = tampered.content(DATA);
	assert!(matches!(refused, Err(SignerError::DigestAlgorithms)));
	Ok(())
}

/// A `SignedData` whose content is not an OCTET STRING is refused when its
/// content is read (RFC 5652 §5.2).
#[test]
fn a_signed_data_whose_content_is_no_octet_string_is_refused() -> TestResult {
	let mut tampered = signed_data();
	tampered.encap_content_info.econtent = Some(Any::new(Tag::Utf8String, CONTENT)?);

	let refused = tampered.content(DATA);
	assert!(matches!(refused, Err(SignerError::Content)));
	Ok(())
}

/// A `SignedData` read as another content type is refused (RFC 5652 §5.2).
#[test]
fn a_signed_data_read_as_another_content_type_is_refused() {
	let signed_data = signed_data();
	let refused = signed_data.content(SESSION_RECEIPT_CONTENT);
	assert!(matches!(refused, Err(SignerError::Content)));
}

/// A `SignedData` the signer assembled decodes as the newtype the wire slots
/// hold, byte for byte.
#[test]
fn a_signed_data_round_trips_through_der() -> TestResult {
	let signed_data = signed_data_of(signed(), None);
	let encoded = signed_data.to_der()?;

	let decoded = Signed::<SignedData>::from_der(&encoded)?;
	assert_eq!(decoded, signed_data);
	Ok(())
}

/// A signing identity accepts the key its certificate names, and names
/// its signer as the certificate does.
#[test]
fn a_signing_identity_accepts_the_key_of_its_certificate() -> TestResult {
	let certificate = TestCertificate::insecure_fixed();
	let provider = TestKey::provider(TestKey::insecure_fixed_signing());

	let identity = SigningIdentity::new(certificate.clone(), provider)?;
	assert_eq!(identity.signer_identifier(), &certificate.signer_identifier()?);
	Ok(())
}

/// A `SignerInfo` an identity signs names the identity's certificate.
#[test]
fn an_identity_signs_under_its_certificate_name() {
	let identity = TestIdentity::insecure_fixed();
	let signer_info = signed_by_identity(&identity);
	assert_eq!(&signer_info.sid, identity.signer_identifier());
}

/// The signer verifies a `SignerInfo` that names the certificate it is
/// checked against.
#[test]
fn a_signer_info_verifies_under_the_certificate_it_names() -> TestResult {
	let identity = TestIdentity::insecure_fixed();
	let content = SignedContent::data(CONTENT);
	let signer_info = signed_by_identity(&identity);
	let certificate = identity.certificate_arc();
	let signer = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(certificate, KeyPurposes::HOUSE.signer)?;

	CmsSigner::verify_signer::<DefaultCryptoProvider>(&signer_info, &signer, content)?;
	Ok(())
}

/// A `SignerInfo` checked against another certificate is refused by its
/// `sid` before its signature is read.
#[test]
fn a_signer_info_checked_against_another_certificate_is_refused() -> TestResult {
	let identity = TestIdentity::insecure_fixed();
	let other = TestCertificate::self_signed(&TestKey::fixed(0x02));
	let other = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(other, KeyPurposes::HOUSE.signer)?;
	let content = SignedContent::data(CONTENT);
	let signer_info = signed_by_identity(&identity);

	let refused = CmsSigner::verify_signer::<DefaultCryptoProvider>(&signer_info, &other, content);
	assert!(matches!(refused, Err(SignerError::SignerIdentifier)));
	Ok(())
}

/// A `SignerInfo` checked under a policy against another certificate of the
/// same key is refused by its `sid` (RFC 5652 §5.3).
#[test]
fn a_signer_info_checked_by_policy_against_another_certificate_is_refused() -> TestResult {
	let identity = TestIdentity::insecure_fixed();
	let content = SignedContent::data(CONTENT);
	let signer_info = signed_by_identity(&identity);
	let other = TestCertificate::without_extension(TestCertificate::insecure_fixed(), SubjectKeyIdentifier::OID);
	let other = PeerCertificate::<ErasedSigning>::parse(other, KeyPurposes::HOUSE.signer)?;

	let refused = CmsSigner::verify_with_policy(&signer_info, &other, &Secp256k1Policy::default(), content);
	assert!(matches!(refused, Err(SignerError::SignerIdentifier)));
	Ok(())
}

/// A `SignerInfo` whose digest its signature algorithm does not name is
/// refused by the policy (RFC 5753 §2.1.1).
#[test]
fn a_policy_refuses_a_digest_the_signature_algorithm_does_not_name() {
	let identity = TestIdentity::insecure_fixed();
	let content = SignedContent::data(CONTENT);
	let signer_info = signed_by_identity(&identity);
	let digest_alg = TestAlgorithm::of(HASH_SHA3_512);
	let mismatched = SignerInfo { digest_alg, ..signer_info.into_inner() };
	let policy = Secp256k1Policy::default();
	let refused = CmsSigner::verify_with_policy(&mismatched, identity.signing_certificate(), &policy, content);

	let unsupported = matches!(
		refused,
		Err(SignerError::Certificate(CertificateValidationError::UnsupportedAlgorithm(oid))) if oid == HASH_SHA3_512
	);
	assert!(unsupported);
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

/// The signer, the `SignedData`, and the paths a handshake presents, which
/// the CMS and HPKE handshakes carry.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod presented {
	use core::iter;

	use super::*;
	use crate::asn1::admission::fixtures::elements_of;
	use crate::asn1::admission::Canonical;
	use crate::asn1::WireDer;
	use crate::crypto::x509::error::CertificateValidationError::{
		InvalidChain, PathLenExceeded, SelfIssuedBelowIssuer,
	};
	use crate::der::TagNumber;
	use crate::frame::{ArrivedCertificates, CERTIFICATES_TAG};

	/// The scalar of the key, 32 octets of it, whose countersignature `der`
	/// sorts ahead of the signer of [`signed`], against the octet order of
	/// DER.
	const DIVERGENT_SCALAR: u8 = 5;

	/// The scalar of the key, 32 octets of it, whose self-signed certificate
	/// a SET OF `der` sorts ahead of [`TestCertificate::insecure_fixed`],
	/// against their DER order.
	const OUT_OF_ORDER_SCALAR: u8 = 3;

	/// [`signed`] beside the certificate its `sid` names, the self-signed
	/// certificate of the fixed test key.
	fn certified() -> CertifiedSigner {
		let certified = CertifiedSigner::new(signed(), Arc::new(TestCertificate::insecure_fixed()));
		certified.expect("the sid names the certificate of its key")
	}

	/// The `SignedData` of [`signed`] carrying `certificates`, which DER
	/// sorts.
	fn signed_data_carrying(certificates: impl IntoIterator<Item = Certificate>) -> SignedData {
		signed_data_of(signed(), Some(TestCertificate::set_of(certificates))).into_inner()
	}

	/// The `SignedData` of [`signed`] whose set holds the certificate its
	/// signer names beside eight choices of another format, nine choices in
	/// all.
	fn signed_data_of_nine_choices() -> SignedData {
		let named = CertificateChoices::Certificate(TestCertificate::insecure_fixed());
		let choices = iter::once(named).chain((0..8).map(other_format));
		let set = SetOfVec::try_from(choices.collect::<Vec<_>>()).expect("distinct choices are a SET");
		signed_data_of(signed(), Some(CertificateSet(set))).into_inner()
	}

	/// The `SignedData` of the version 1 signer of [`issuer_and_serial_signed`]
	/// over `id-data`, carrying `certificates`.
	fn issuer_and_serial_signed_data(certificates: Option<CertificateSet>) -> Signed<SignedData> {
		signed_data_of(issuer_and_serial_signed(DATA), certificates)
	}

	/// A version 3 countersignature lifts a version 1 `SignedData` to version
	/// 3 (RFC 5652 §5.1).
	#[test]
	fn a_version_3_countersignature_lifts_the_signed_data_to_version_3() -> TestResult {
		let signed_data = issuer_and_serial_signed_data(None);
		let joined = signed_data.with_certified_signer(certified())?;
		assert_eq!(joined.version, CmsVersion::V3);
		Ok(())
	}

	/// A joining signer's digest algorithm enters `digestAlgorithms` (RFC
	/// 5652 §5.1).
	#[test]
	fn a_joining_signer_declares_its_digest_algorithm() -> TestResult {
		let signed_data = signed_data_of(signed(), None);
		let digest_alg = TestAlgorithm::of(HASH_SHA3_512);
		let foreign = SignerInfo { digest_alg: digest_alg.clone(), ..signed().into_inner() };

		let joiner = Signed::<SignerInfo>::from_der(&foreign.to_der()?)?;
		let joiner = CertifiedSigner::new(joiner, Arc::new(TestCertificate::insecure_fixed()))?;
		let joined = signed_data.with_certified_signer(joiner)?;
		assert!(joined.digest_algorithms.as_ref().contains(&digest_alg));
		Ok(())
	}

	// A joining signer brings the certificate its `sid` names into
	// `certificates`, or joins beside the one copy the `SignedData` carries
	// already, so the `SignedData` carries the certificate of each of its
	// signers once (RFC 5652 §5.1).
	crate::tb_cases! {
		fn a_joining_signer_leaves_one_copy_of_its_certificate(held: Option<CertificateSet>) -> TestResult {
			let signed_data = issuer_and_serial_signed_data(held);
			let joined = signed_data.with_certified_signer(certified())?;
			assert_eq!(joined.certificates, Some(TestCertificate::set_of([TestCertificate::insecure_fixed()])));
			Ok(())
		}
		cases {
			when_none_is_held => None,
			when_the_set_holds_it => Some(TestCertificate::set_of([TestCertificate::insecure_fixed()])),
		}
	}

	/// A certificate the `sid` of a signer does not name is refused beside it
	/// (RFC 5652 §5.3).
	#[test]
	fn a_signer_beside_a_certificate_its_sid_does_not_name_is_refused() {
		let other = TestCertificate::self_signed(&TestKey::fixed(0x04));
		let refused = CertifiedSigner::new(signed(), Arc::new(other));
		assert!(matches!(refused, Err(SignerError::SignerIdentifier)));
	}

	/// A signing identity with no chain presents its certificate alone in the
	/// `certificates` set a handshake carries.
	#[test]
	fn a_signing_identity_presents_its_certificate_alone() -> TestResult {
		let certificate = TestCertificate::insecure_fixed();
		let provider = TestKey::provider(TestKey::insecure_fixed_signing());

		let identity = SigningIdentity::new(certificate.to_owned(), provider)?;
		assert_eq!(identity.presented().set(), TestCertificate::set_of([certificate]));
		Ok(())
	}

	/// The path the one signer presents moves out of `certificates`, which the
	/// call leaves empty, as a server takes it from a client Finished (RFC
	/// 5652 §5.3).
	#[test]
	fn taking_the_signer_path_moves_the_set_out() -> TestResult {
		let identity = chained_identity();
		let signer = signed_by_identity(&identity);
		let presented = Some(identity.presented().set());
		let signed = signed_data_of(signer, presented);
		let (signed_data, path) = signed.take_signer_path()?;
		let path = path.ok_or("the set holds the named certificate")?;
		let (leaf, issuers) = path.into_parts();

		let [chained_leaf, intermediate] = chained_certificates();
		let taken = (leaf, issuers.as_slice(), signed_data.certificates);
		assert_eq!(taken, (chained_leaf, [intermediate].as_slice(), None));
		Ok(())
	}

	/// A set that holds no certificate the signer names gives no path, and the
	/// call still leaves the set empty.
	#[test]
	fn taking_from_a_set_without_the_signer_certificate_takes_no_path() -> TestResult {
		let other = TestCertificate::self_signed(&TestKey::fixed(0x04));
		let finished = received_as_signed(&signed_data_carrying([other]));

		let (signed_data, path) = finished.take_signer_path()?;
		assert_eq!((path.is_none(), signed_data.certificates), (true, None));
		Ok(())
	}

	/// The cap of the path a server takes out of a client Finished counts each
	/// choice of the set, so a choice of another format counts toward it.
	#[test]
	fn taking_a_path_counts_a_choice_of_another_format_toward_the_cap() {
		let finished = received_as_signed(&signed_data_of_nine_choices());

		let refused = finished.take_signer_path();
		let capped = matches!(refused, Err(SignerError::Certificate(PathLenExceeded)));
		assert!(capped);
	}

	/// A server holds the presented set of a client Finished to its cap as it
	/// arrived, before the typed decode sorts the set.
	#[test]
	fn a_presented_set_past_the_cap_is_refused_before_its_decode() -> TestResult {
		let received = signed_data_of_nine_choices().to_der()?;

		let refused = ArrivedCertificates::bound_presented(&received);
		let capped = matches!(refused, Err(SignerError::Certificate(PathLenExceeded)));
		assert!(capped);
		Ok(())
	}

	/// `signed_data` as a peer's `Signed` decode reads it from its DER.
	fn received_as_signed(signed_data: &SignedData) -> Signed<SignedData> {
		let received = signed_data.to_der().expect("a test SignedData encodes");
		Signed::<SignedData>::from_der(&received).expect("a test SignedData decodes")
	}

	/// `signed_data` as a peer's [`WireDer`] decode reads it from the DER its
	/// signer writes, every SET in DER order.
	fn received_wire(signed_data: &SignedData) -> WireDer<SignedData> {
		let mut contents = Vec::new();

		signed_data.encode_canonical(&mut contents).expect("a test SignedData encodes");

		let received = tlv(Tag::Sequence, &contents);
		WireDer::try_from(received.as_slice()).expect("a test SignedData decodes from its DER")
	}

	/// The scan of the received set builds the path of the certificate the one
	/// signer names. Under the fixed key `0x0f` × 32, the other certificate
	/// sorts first in the SET, in DER and in the order `der` decodes, so the
	/// named certificate is the second element, and the other one issues no
	/// certificate of the path.
	#[cfg(feature = "transport-cms")]
	#[test]
	fn the_received_path_starts_at_the_certificate_its_sid_names() -> TestResult {
		let named = TestCertificate::insecure_fixed();
		let other = TestCertificate::self_signed(&TestKey::fixed(0x0f));
		let signed_data = signed_data_carrying([other.to_owned(), named.to_owned()]);
		let received = received_wire(&signed_data);

		let (path, _) = received.signer_path()?.ok_or("the set holds the named certificate")?;
		let (leaf, issuers) = path.into_parts();
		assert_eq!((leaf, issuers.as_slice()), (named, [].as_slice()));
		Ok(())
	}

	/// The `certificates` field an identity encodes once is the field a
	/// `SignedData` of its set carries, as a reader finds it on arrival, so
	/// both ends of a handshake bind one encoding.
	#[test]
	fn an_identity_binds_the_field_a_reader_finds() -> TestResult {
		let identity = chained_identity();
		let signer = signed_by_identity(&identity);
		let presented = Some(identity.presented().set());
		let signed_data = signed_data_of(signer, presented);
		let received = WireDer::<SignedData>::try_from(signed_data.to_der()?.as_slice())?;

		let (_, field) = received.signer_path()?.ok_or("the set holds the named certificate")?;
		assert_eq!(field, identity.presented().field());
		Ok(())
	}

	// The cap counts each choice of the set as it arrived, before any
	// certificate parses, so a set of nine certificates, one past
	// `MAX_PRESENTED_PATH`, is refused, and a choice of another format counts
	// toward it.
	crate::tb_cases! {
		fn a_received_set_past_the_cap_is_refused(signed_data: SignedData) {
			let received = received_wire(&signed_data);

			let refused = received.signer_path();
			let capped = matches!(refused, Err(SignerError::Certificate(PathLenExceeded)));
			assert!(capped);
		}
		cases {
			of_nine_certificates => {
				let named = TestCertificate::insecure_fixed();
				signed_data_carrying(iter::once(named).chain(TestCertificate::strangers(8)))
			},
			with_a_choice_of_another_format => signed_data_of_nine_choices(),
		}
	}

	/// The DER of the `SignedData` of [`signed`] with two `certificates`
	/// fields beside each other, one carrying `first`, then one carrying
	/// `second`.
	fn twice_certified(first: Certificate, second: Certificate) -> Vec<u8> {
		let first = elements_of(signed_data_carrying([first]).to_der().expect("a SignedData encodes"));
		let second = elements_of(signed_data_carrying([second]).to_der().expect("a SignedData encodes"));
		let second_field = second.get(3).expect("a SignedData of a set carries its certificates fourth");
		let (head, signers) = first.split_at(4);

		let fields = [head.concat(), second_field.to_owned(), signers.concat()];
		tlv(Tag::Sequence, &fields.concat())
	}

	/// The DER of the `SignedData` of [`signed`] whose `certificates` field
	/// carries `certificate`, the DER of one certificate as it arrives.
	fn carrying_encoding(certificate: &[u8]) -> Vec<u8> {
		let placeholder = TestCertificate::insecure_fixed();
		let fields = elements_of(signed_data_carrying([placeholder]).to_der().expect("a SignedData encodes"));

		let (head, rest) = fields.split_at(3);
		let signers = rest.get(1..).expect("a SignedData of a set carries its signers after it");
		let certificates = tlv(CERTIFICATES_TAG, certificate);
		tlv(Tag::Sequence, &[head.concat(), certificates, signers.concat()].concat())
	}

	/// The DER of `certificate` with an explicit `critical FALSE` in its first
	/// extension that states no criticality, the default that DER omits
	/// (X.690 § 11.5).
	fn with_explicit_default(certificate: &Certificate) -> Vec<u8> {
		let mut parts = elements_of(certificate.to_der().expect("a certificate encodes"));
		let tbs = parts.first_mut().expect("a certificate starts with its TBS");
		let mut fields = elements_of(&tbs);
		let tagged = fields.pop().expect("a test certificate carries extensions last");
		let mut extensions = elements_of(AnyRef::from_der(&tagged).expect("an element decodes").value());
		let unstated = extensions.iter_mut().find(|extension| elements_of(extension).len() == 2);
		let unstated = unstated.expect("a test certificate carries an extension that states no criticality");
		let mut extension = elements_of(&unstated);

		extension.insert(1, Vec::from([0x01, 0x01, 0x00]));
		*unstated = tlv(Tag::Sequence, &extension.concat());

		let extensions_tag = Tag::ContextSpecific { constructed: true, number: TagNumber::N3 };
		fields.push(tlv(extensions_tag, &tlv(Tag::Sequence, &extensions.concat())));
		*tbs = tlv(Tag::Sequence, &fields.concat());
		tlv(Tag::Sequence, &parts.concat())
	}

	/// The DER of the `SignedData` of [`signed`] whose `certificates` field
	/// carries [`TestCertificate::insecure_fixed`] in the encoding of
	/// [`with_explicit_default`].
	fn carrying_an_explicit_default() -> Vec<u8> {
		carrying_encoding(&with_explicit_default(&TestCertificate::insecure_fixed()))
	}

	/// The self-signed certificate of a key other than the fixed test key.
	fn stranger() -> Certificate {
		TestCertificate::self_signed(&TestKey::fixed(0x02))
	}

	/// The typed decode keeps the first of two `certificates` fields, and the
	/// scan that bounds the received bytes before their decode refuses the
	/// second, so the two reads name one set.
	#[test]
	fn a_signed_data_with_two_certificates_fields_is_refused() {
		let received = twice_certified(stranger(), TestCertificate::insecure_fixed());

		let refused = ArrivedCertificates::bound_presented(&received);
		let second_field = ErrorKind::TagUnexpected { expected: None, actual: CERTIFICATES_TAG };
		assert!(matches!(refused, Err(SignerError::Encoding(error)) if error.kind() == second_field));
	}

	/// A certificate whose bytes differ from its DER decodes to the
	/// certificate its CA signed, and the store would verify that DER. A
	/// presented path reads its certificates from a [`WireDer`] alone, whose
	/// decode refuses them.
	#[test]
	fn a_certificate_in_another_encoding_than_its_der_is_refused() {
		let received = carrying_an_explicit_default();
		let refused = der_refusal(WireDer::<SignedData>::try_from(received.as_slice()));
		assert_eq!(refused, Some(ErrorKind::Noncanonical { tag: Tag::Sequence }));
	}

	// The `Signed` decode of a client Finished, or of a receipt, holds the
	// decoded value to the octets it arrived as, as the client does. So it
	// refuses a certificate in another encoding than its DER, and a second
	// `certificates` field that the typed decode skipped.
	crate::tb_cases! {
		fn a_signed_decode_refuses(received: Vec<u8>) {
			let refused = der_refusal(Signed::<SignedData>::from_der(&received));
			assert_eq!(refused, Some(ErrorKind::Noncanonical { tag: Tag::Sequence }));
		}
		cases {
			a_certificate_in_another_encoding_than_its_der => carrying_an_explicit_default(),
			two_certificates_fields => twice_certified(stranger(), TestCertificate::insecure_fixed()),
		}
	}

	/// The walk takes the issuer of each certificate by name, so a set that
	/// holds the root and the intermediate of the fixed chain yields both
	/// above the leaf, the top first.
	#[cfg(feature = "transport-cms")]
	#[test]
	fn the_walk_takes_each_issuer_by_name_the_top_first() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let stranger = TestCertificate::insecure_fixed();
		let held = vec![chain.intermediate.to_owned(), stranger, chain.root.to_owned()];

		let path = PresentedPath::walk(chain.leaf.to_owned(), held)?;
		let (leaf, issuers) = path.into_parts();
		let top_first = [chain.root, chain.intermediate];
		assert_eq!((leaf, issuers.as_slice()), (chain.leaf, top_first.as_slice()));
		Ok(())
	}

	/// Two certificates whose subject is the name of one issuer leave the walk
	/// no single issuer, so the walk refuses the set.
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

	/// A set whose issuers name each other leads the walk back into its path,
	/// so the walk refuses it.
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
	#[test]
	fn an_identity_presents_its_chain_in_its_certificates_field() {
		let identity = chained_identity();
		let expected = TestCertificate::set_of(chained_certificates());
		assert_eq!(identity.presented().set(), expected);
	}

	/// A chain in which a certificate does not name the next one as its issuer
	/// is refused where it is set.
	#[test]
	fn an_identity_refuses_a_chain_that_names_another_issuer() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let identity = TestIdentity::presenting(chain.leaf, &chain.leaf_key);

		let refused = identity.with_chain([chain.root]);
		let unchained = matches!(refused, Err(SignerError::Certificate(InvalidChain { .. })));
		assert!(unchained);
		Ok(())
	}

	/// The subject that the refusal of a self-issued certificate below another
	/// names, or `None` for another outcome.
	fn self_issued_subject(outcome: Result<SigningIdentity, SignerError>) -> Option<String> {
		match outcome {
			Err(SignerError::Certificate(SelfIssuedBelowIssuer { subject })) => Some(subject),
			_ => None,
		}
	}

	/// A self-issued certificate is its own issuer, so the identity refuses a
	/// chain that sets a certificate of its name above it, and the refusal
	/// names that shape and the subject of the self-issued certificate.
	#[test]
	fn a_self_issued_certificate_below_another_is_refused_by_name() -> TestResult {
		let key = TestKey::insecure_fixed_signing();
		let usage = KeyUsage(KeyUsages::DigitalSignature.into());
		let certificate = TestCertificate::issued(&key, "Rollover CA", &key, "Rollover CA", 1, usage)?;
		let identity = TestIdentity::presenting(certificate, &key);
		let subject = identity.certificate().tbs_certificate.subject.to_string();
		let above = TestCertificate::authority(&TestKey::fixed(0x04), "Rollover CA")?;

		let refused = identity.with_chain([above]);
		assert_eq!(self_issued_subject(refused), Some(subject));
		Ok(())
	}

	/// A chain past the cap is refused where it is set, so an identity
	/// presents no path its peers refuse.
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
	fn chained_identity() -> SigningIdentity {
		let chain = TestCertificate::insecure_fixed_chain().expect("the fixed test chain issues");
		let identity = TestIdentity::presenting(chain.leaf, &chain.leaf_key);
		let chained = identity.with_chain([chain.intermediate]);
		chained.expect("the intermediate issued the leaf")
	}

	/// The leaf and the intermediate of the fixed chain, as a set holds them.
	fn chained_certificates() -> [Certificate; 2] {
		let chain = TestCertificate::insecure_fixed_chain().expect("the fixed test chain issues");
		[chain.leaf, chain.intermediate]
	}

	/// Eight certificates above `leaf`, each named the issuer of the one below,
	/// a chain one past the cap with `leaf`.
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
		let signed_data = signed_data_of(signed(), None);

		let joined = signed_data.with_unsigned_attribute(receipt_role(1))?;
		let signer = joined.signer_infos.0.iter().next().ok_or("the SignedData has a signer")?;
		let carried = signer.unsigned_attrs.as_ref().map(|attrs| attrs.as_slice().to_vec());
		assert_eq!(carried, Some(vec![receipt_role(1)]));
		verify(signer)?;
		Ok(())
	}

	/// The countersignature over [`CONTENT`] of [`TestKey::fixed`] `scalar`,
	/// beside its self-signed certificate.
	fn certified_stranger(scalar: u8) -> CertifiedSigner {
		let key = TestKey::fixed(scalar);
		let certificate = Arc::new(TestCertificate::self_signed(&key));
		let signer = signed_by(&TestIdentity::certified(key), SignedContent::data(CONTENT));
		CertifiedSigner::new(signer, certificate).expect("the sid names the certificate of its key")
	}

	/// The `SignedData` of [`signed`] that the key of [`DIVERGENT_SCALAR`]
	/// countersigned, whose signers `der` holds in another order than DER's.
	fn countersigned() -> Signed<SignedData> {
		let both = signed_data_of(signed(), None).with_certified_signer(certified_stranger(DIVERGENT_SCALAR));
		both.expect("a second signer joins")
	}

	/// A countersigned `SignedData` whose signers `der` holds in another order
	/// than DER's encodes them in DER's order (X.690 § 11.6), so the
	/// admission of its own encoding passes.
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

	/// Two self-signed certificates under fixed keys, of one length, that a
	/// SET OF `der` sorts in the reverse of their DER order. `der` 0.7
	/// compares two certificate choices of one length by their encodings read
	/// as a SEQUENCE OF INTEGER, which counts the octets past `0x7f` first.
	fn certificates_der_sorts_out_of_order() -> [Certificate; 2] {
		[
			TestCertificate::insecure_fixed(),
			TestCertificate::self_signed(&TestKey::fixed(OUT_OF_ORDER_SCALAR)),
		]
	}

	/// A `SignedData` sends its `certificates` in DER order (X.690 § 11.6), as
	/// the client Finished, the reply, and a receipt do through their `Signed`
	/// encode, though `der` sorts the set in another order.
	#[test]
	fn a_signed_data_sends_its_certificates_in_der_order() -> TestResult {
		let set = TestCertificate::set_of(certificates_der_sorts_out_of_order());
		let in_der_sort = set.0.to_der()?;
		let sent = signed_data_of(signed(), Some(set)).to_der()?;

		let arrived = ArrivedCertificates::read(&sent)?.ok_or("the SignedData carries its certificates")?;
		let choices = AnyRef::from_der(arrived.field())?;
		let refused = DerAdmission::SetOrder.admit(in_der_sort).map_err(|error| error.kind());
		assert_eq!(refused, Err(ErrorKind::SetOrdering));
		DerAdmission::SetOrder.admit(tlv(Tag::Set, choices.value()))?;
		Ok(())
	}

	/// The DER encoder of the crate gives the signers of a countersigned
	/// `SignedData` their DER order, even outside its `Signed` wrapper.
	#[test]
	fn the_der_encoder_gives_the_signers_their_der_order() -> TestResult {
		let both = countersigned();
		let encoded = crate::encode(both.as_ref())?;
		DerAdmission::SetOrder.admit(encoded)?;
		Ok(())
	}

	/// A `SignedData` of two signers takes no unsigned attribute, since it
	/// names no one signer.
	#[cfg(feature = "transport-hpke")]
	#[test]
	fn an_unsigned_attribute_refuses_two_signers() -> TestResult {
		let first = signed_data_of(signed(), None);
		let both = first.with_certified_signer(certified_stranger(0x06))?;

		let refused = both.with_unsigned_attribute(receipt_role(1));
		assert!(matches!(refused, Err(SignerError::SignerIdentifier)));
		Ok(())
	}
}
