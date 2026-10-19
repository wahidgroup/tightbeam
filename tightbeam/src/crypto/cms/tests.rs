use std::sync::{Arc, Mutex};

use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{
	KekIdentifier, KekRecipientInfo, OtherRecipientInfo, RecipientIdentifier, RecipientInfo,
};
use crate::crypto::cms::{
	AuthEnvelopedData, BareKemKey, CmsOriForKemOtherInfo, EnvelopeError, GcmParameters, KemKeyHolder, KemRecipient,
	KemRecipientInfo, KeyAgreementIdentity, Opener, Recipient,
};
use crate::crypto::hpke::DhKemSecp256k1;
use crate::crypto::k256::elliptic_curve::sec1::ToEncodedPoint;
use crate::crypto::k256::{PublicKey, Secp256k1};
use crate::crypto::kdf::HkdfSha3_256;
use crate::crypto::key::{DiffieHellman, KeyBackend, KeyError, Secp256k1KeyProvider};
use crate::crypto::profiles::{Aes128Wrap, Aes192Wrap, Aes256Wrap, DefaultCryptoProvider, KeyWrapAlgorithm};
use crate::crypto::secret::{SecretSlice, ToInsecure};
use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::utils::CertificateExt;
use crate::crypto::x509::{KeyAgreement, KeyPurposes, PeerCertificate};
use crate::der::asn1::{GeneralizedTime, Null, ObjectIdentifier, OctetString, SetOfVec};
use crate::der::oid::AssociatedOid;
use crate::der::{Any, Decode, Encode, EncodeValue, Tagged};
use crate::oids::{
	AES_128_GCM, AES_128_WRAP, AES_192_WRAP, AES_256_GCM, AES_256_WRAP, ATTR_CONTENT_TYPE, DATA, DHKEM_SECP256K1,
	HKDF_SHA3_256, SIGNED_DATA,
};
use crate::random::OsRng;
use crate::spki::AlgorithmIdentifierOwned;
use crate::testing::{unhex, EnvelopeRecipient, SeededStream, TestCertificate, TestKey};
use crate::utils::marker::MaybeSendFuture;
use crate::x509::attr::{Attribute, Attributes};
use crate::x509::ext::pkix::{KeyUsage, KeyUsages, SubjectKeyIdentifier};
use crate::x509::ext::Extension;
use crate::x509::Certificate;
use crate::zeroize::Zeroizing;
use crate::ZeroizingBytes;

/// The house provider, whose algorithms every seal here runs: AES-256-GCM,
/// HKDF-SHA3-256, AES-256 key wrap, and DHKEM(secp256k1, HKDF-SHA256).
type House = DefaultCryptoProvider;

/// The KEM of the house provider.
type HouseKem = DhKemSecp256k1;

/// A key-agreement identity under the house KEM.
type HouseIdentity = KeyAgreementIdentity<HouseKem>;

/// The content every test seals.
const CONTENT: &[u8] = b"authenticated envelope content";

/// The key-encryption key of the `Kek` tests.
static KEK: [u8; 32] = [0x11; 32];

/// The identifier that names [`KEK`].
const KEY_IDENTIFIER: &[u8] = b"tb/test/kek/v1";

/// The purpose label of the `Kem` tests.
const UKM_LABEL: &[u8] = b"tb/test/ukm/v1";

/// The secret key of the recipient of draft-wahby-cfrg-hpke-kem-secp256k1-01
/// B.1.1, which the KEM known answer seals to.
const PUBLISHED_RECIPIENT_SECRET: &str = "a795c287c132154a8b96dc81dc8b4e2f02bbbad78dab0567b59db1d1540751f6";

/// The holder of [`KEK`], as the recipient of a seal.
fn kek_recipient_of() -> Recipient<'static, HouseKem> {
	Recipient::Kek { kek: &KEK, key_identifier: KEY_IDENTIFIER }
}

/// [`CONTENT`] sealed as `id-data` to the holder of [`KEK`].
fn kek_sealed() -> AuthEnvelopedData {
	let sealed = AuthEnvelopedData::seal::<House>(kek_recipient_of(), DATA, CONTENT, [], None);
	sealed.expect("the content seals")
}

/// [`CONTENT`] sealed as `id-data` to the holder of [`KEK`], under the draws
/// of `SeededStream(0)`: a content key of `0x01` and a nonce of `0x02`.
fn kek_sealed_from_seed() -> AuthEnvelopedData {
	let mut stream = SeededStream(0);
	let sealed = AuthEnvelopedData::seal::<House>(kek_recipient_of(), DATA, CONTENT, [], Some(&mut stream));
	sealed.expect("the content seals")
}

/// The opener of the holder of [`KEK`].
fn kek_opener() -> Opener<'static, HouseKem> {
	Opener::Kek { kek: &KEK, key_identifier: KEY_IDENTIFIER }
}

/// The house backend of `key`, as the trait object the house KEM decapsulates
/// through.
fn backend_of(key: &Secp256k1SigningKey) -> Arc<dyn DiffieHellman<Secp256k1>> {
	Arc::new(Secp256k1KeyProvider::from(key.to_owned()))
}

/// The key-agreement identity of `key` under `certificate`.
fn agreement_identity(certificate: Certificate, key: &Secp256k1SigningKey) -> HouseIdentity {
	let identity = KeyAgreementIdentity::new(certificate, backend_of(key));
	identity.expect("the test key matches its certificate")
}

/// The key-agreement identity of a fresh secp256k1 key under a certificate
/// that carries its key identifier.
fn kem_identity() -> HouseIdentity {
	let key = Secp256k1SigningKey::random(&mut OsRng);
	agreement_identity(TestCertificate::self_signed(&key), &key)
}

/// The key-agreement identity of the published recipient key.
fn published_identity() -> HouseIdentity {
	let secret = unhex(PUBLISHED_RECIPIENT_SECRET);
	let key = Secp256k1SigningKey::from_slice(&secret).expect("the vector holds a scalar");
	agreement_identity(TestCertificate::self_signed(&key), &key)
}

/// [`CONTENT`] sealed as `id-data` to the recipient of `identity`, with a
/// `ukm` led by `ukm_label`.
fn kem_sealed(identity: &HouseIdentity, ukm_label: &[u8]) -> AuthEnvelopedData {
	let recipient = Recipient::Kem { recipient: identity.recipient(), ukm_label };
	let sealed = AuthEnvelopedData::seal::<House>(recipient, DATA, CONTENT, [], None);
	sealed.expect("the content seals")
}

/// [`CONTENT`] sealed as `id-data` to the published recipient key under the
/// draws of `SeededStream(0)`: a content key of `0x01`, a nonce of `0x02`, an
/// ephemeral scalar of `0x03`, and `ukm` random octets of `0x04`.
fn kem_sealed_from_seed() -> AuthEnvelopedData {
	let identity = published_identity();
	let recipient = Recipient::Kem { recipient: identity.recipient(), ukm_label: UKM_LABEL };
	let mut stream = SeededStream(0);

	let sealed = AuthEnvelopedData::seal::<House>(recipient, DATA, CONTENT, [], Some(&mut stream));
	sealed.expect("the content seals")
}

/// The opener of `identity` under [`UKM_LABEL`].
fn kem_opener(identity: &HouseIdentity) -> Opener<'_, HouseKem> {
	Opener::Kem { identity, ukm_label: UKM_LABEL }
}

/// Open `envelope` as it encodes, as a reader that received its DER does.
async fn opened(
	envelope: AuthEnvelopedData,
	opener: &Opener<'_, HouseKem>,
	content_type: ObjectIdentifier,
) -> Result<SecretSlice<u8>, EnvelopeError> {
	let arrived = envelope.to_der()?;
	envelope.open::<House>(&arrived, opener, content_type).await
}

/// The `GCMParameters` of `envelope`.
fn gcm_parameters(envelope: &AuthEnvelopedData) -> GcmParameters {
	let algorithm = &envelope.auth_encrypted_content_info.content_enc_alg;
	let parameters = algorithm.parameters.as_ref().expect("the algorithm carries parameters");
	let parameters = parameters.decode_as::<GcmParameters>();
	parameters.expect("the parameters are GCMParameters")
}

/// `envelope` with its algorithm parameters replaced by `parameters`.
fn with_parameters(mut envelope: AuthEnvelopedData, parameters: &(impl EncodeValue + Tagged)) -> AuthEnvelopedData {
	let encoded = Any::encode_from(parameters).expect("the parameters encode");
	envelope.auth_encrypted_content_info.content_enc_alg.parameters = Some(encoded);
	envelope
}

/// The encrypted content of `envelope`.
fn ciphertext(envelope: &AuthEnvelopedData) -> Vec<u8> {
	let content = envelope.auth_encrypted_content_info.encrypted_content.as_ref();
	let content = content.expect("the envelope carries encrypted content");
	content.as_bytes().to_vec()
}

/// The values of the one content-type attribute of `envelope`.
fn content_type_values(envelope: &AuthEnvelopedData) -> Vec<ObjectIdentifier> {
	let attrs = envelope.auth_attrs.as_ref();
	let attrs = attrs.expect("the envelope carries authenticated attributes");
	let named = attrs.iter().filter(|attribute| attribute.oid == ATTR_CONTENT_TYPE);
	let values = named.flat_map(|attribute| attribute.values.iter());

	let decoded = values.map(|value| value.decode_as::<ObjectIdentifier>().expect("a content type decodes"));
	decoded.collect()
}

/// An attribute of a type no test reads.
fn marker_attribute() -> Attribute {
	let value = Any::encode_from(&OctetString::new([0x42u8; 4]).expect("four bytes fit")).expect("it encodes");
	let values = SetOfVec::try_from(vec![value]).expect("one value is a SET");
	Attribute { oid: ObjectIdentifier::new_unwrap("1.2.3.4.5"), values }
}

/// A content-type attribute that names each of `content_types`.
fn content_type_attribute(content_types: &[ObjectIdentifier]) -> Attribute {
	let encode = |content_type: &ObjectIdentifier| Any::encode_from(content_type).expect("an OID encodes");
	let values = content_types.iter().map(encode).collect::<Vec<_>>();
	let values = SetOfVec::try_from(values).expect("distinct values are a SET");
	Attribute { oid: ATTR_CONTENT_TYPE, values }
}

/// `envelope` with `attributes` as its authenticated attributes.
fn with_auth_attrs(mut envelope: AuthEnvelopedData, attributes: Vec<Attribute>) -> AuthEnvelopedData {
	let attributes = Attributes::try_from(attributes).expect("distinct attributes are a SET");
	envelope.auth_attrs = Some(attributes);
	envelope
}

/// The DER of `envelope`, whose two authenticated attributes travel in the
/// reverse of DER order.
fn with_misordered_auth_attrs(envelope: &AuthEnvelopedData) -> Vec<u8> {
	let der = envelope.to_der().expect("the envelope encodes");
	let attrs = envelope.auth_attrs.as_ref();
	let attrs = attrs.expect("the envelope carries authenticated attributes");
	let encoded: Vec<Vec<u8>> = attrs.iter().map(|attribute| attribute.to_der().expect("it encodes")).collect();
	let ordered = encoded.concat();
	let reversed: Vec<u8> = encoded.iter().rev().flatten().copied().collect();
	let at = der.windows(ordered.len()).position(|window| window == ordered.as_slice());
	let at = at.expect("the attributes sit in the envelope");

	let mut misordered = der;
	misordered[at..at + ordered.len()].copy_from_slice(&reversed);
	misordered
}

/// `kem` with the last octet of its `ukm` flipped.
fn with_flipped_ukm(kem: KemRecipientInfo) -> KemRecipientInfo {
	let ukm = kem.ukm.as_ref().expect("the recipient carries a ukm");
	let mut flipped = ukm.as_bytes().to_vec();
	let last = flipped.last_mut().expect("the ukm carries octets");
	*last ^= 0x01;
	KemRecipientInfo { ukm: Some(OctetString::new(flipped).expect("it fits")), ..kem }
}

/// `kem` with one more octet after its `ukm`.
fn with_longer_ukm(kem: KemRecipientInfo) -> KemRecipientInfo {
	let ukm = kem.ukm.as_ref().expect("the recipient carries a ukm");
	let longer = [ukm.as_bytes(), &[0x00]].concat();
	KemRecipientInfo { ukm: Some(OctetString::new(longer).expect("it fits")), ..kem }
}

/// The test certificate of `key` with its `keyUsage` replaced by
/// `key_usage`, or removed when it is `None`.
fn certificate_with_key_usage(key: &Secp256k1SigningKey, key_usage: Option<KeyUsage>) -> Certificate {
	let mut certificate = TestCertificate::self_signed(key);
	let extensions = certificate.tbs_certificate.extensions.get_or_insert_with(Vec::new);
	extensions.retain(|extension| extension.extn_id != KeyUsage::OID);

	let value = key_usage.map(|key_usage| key_usage.to_der().expect("a key usage encodes"));
	let value = value.map(|value| OctetString::new(value).expect("an encoded key usage fits"));
	extensions.extend(value.map(|extn_value| Extension { extn_id: KeyUsage::OID, critical: true, extn_value }));
	certificate
}

/// The `keyUsage` of a CMS server: it signs, and a KEM encapsulates to it.
fn server_key_usage() -> Option<KeyUsage> {
	Some(KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyAgreement))
}

/// `kem` with its `kemct` in the compressed SEC1 form of the same point.
fn with_compressed_kemct(kem: KemRecipientInfo) -> KemRecipientInfo {
	let point = PublicKey::from_sec1_bytes(kem.kemct.as_bytes()).expect("a seal writes a point");
	let compressed = point.to_encoded_point(true);
	let kemct = OctetString::new(compressed.as_bytes()).expect("a compressed point fits");
	KemRecipientInfo { kemct, ..kem }
}

/// A key-agreement backend that records the peer key of each agreement it is
/// asked for, and agrees as [`Secp256k1KeyProvider`] does.
#[derive(Debug)]
struct RecordingAgreement {
	inner: Secp256k1KeyProvider,
	agreements: Mutex<Vec<Vec<u8>>>,
}

impl RecordingAgreement {
	/// The provider of `key`, with no agreement recorded.
	fn new(key: Secp256k1SigningKey) -> Self {
		Self { inner: Secp256k1KeyProvider::from(key), agreements: Mutex::new(Vec::new()) }
	}

	/// The peer keys of the agreements this provider was asked for, in order.
	fn agreements(&self) -> Vec<Vec<u8>> {
		let agreements = self.agreements.lock().expect("no agreement panicked while holding the record");
		agreements.to_owned()
	}
}

impl KeyBackend for RecordingAgreement {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.inner.algorithm()
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		self.inner.to_public_key_bytes()
	}
}

impl DiffieHellman<Secp256k1> for RecordingAgreement {
	fn agree<'a>(&'a self, peer: &'a PublicKey) -> MaybeSendFuture<'a, Result<SecretSlice<u8>, KeyError>> {
		let mut agreements = self.agreements.lock().expect("no agreement panicked while holding the record");
		agreements.push(peer.to_encoded_point(false).as_bytes().to_vec());
		self.inner.agree(peer)
	}
}

/// The fields a KEM seal derives from its draws, as the test compares them.
#[derive(Debug, PartialEq)]
struct KemSealFields {
	kemct: Vec<u8>,
	ukm: Vec<u8>,
	encrypted_key: Vec<u8>,
	ciphertext: Vec<u8>,
	mac: Vec<u8>,
}

impl KemSealFields {
	/// The fields `envelope` carries.
	fn of(envelope: &AuthEnvelopedData) -> Self {
		let kem = envelope.kem_recipient();
		let ukm = kem.ukm.as_ref().expect("the recipient carries a ukm");
		Self {
			kemct: kem.kemct.as_bytes().to_vec(),
			ukm: ukm.as_bytes().to_vec(),
			encrypted_key: kem.encrypted_key.as_bytes().to_vec(),
			ciphertext: ciphertext(envelope),
			mac: envelope.mac.as_bytes().to_vec(),
		}
	}
}

#[test]
fn an_envelope_is_version_0() {
	assert_eq!(kek_sealed().version, CmsVersion::V0);
}

#[test]
fn the_content_encryption_algorithm_is_aes_256_gcm() {
	let envelope = kek_sealed();
	assert_eq!(envelope.auth_encrypted_content_info.content_enc_alg.oid, AES_256_GCM);
}

/// The `GCMParameters` hold a 12-octet nonce and `aes-ICVlen` 16 (RFC 5084
/// §3.2).
#[test]
fn the_gcm_parameters_hold_a_12_octet_nonce_and_a_16_octet_tag_length() {
	let parameters = gcm_parameters(&kek_sealed());
	assert_eq!(parameters.aes_nonce.as_bytes().len(), 12);
	assert_eq!(parameters.aes_icv_len, 16);
}

/// DER writes `aes-ICVlen` 16, because 16 is not the default 12.
#[test]
fn the_gcm_parameters_encode_a_16_octet_tag_length() -> Result<(), crate::der::Error> {
	let parameters = GcmParameters { aes_nonce: OctetString::new([0x07u8; 12])?, aes_icv_len: 16 };
	assert_eq!(parameters.to_der()?, unhex("3011040c070707070707070707070707020110"));
	Ok(())
}

/// DER omits `aes-ICVlen` 12, the default.
#[test]
fn the_gcm_parameters_omit_the_default_tag_length() -> Result<(), crate::der::Error> {
	let parameters = GcmParameters { aes_nonce: OctetString::new([0x07u8; 12])?, aes_icv_len: 12 };
	assert_eq!(parameters.to_der()?, unhex("300e040c070707070707070707070707"));
	Ok(())
}

/// The 16-octet tag sits in `mac`, so the encrypted content is as long as
/// the content.
#[test]
fn the_tag_sits_in_mac() {
	let envelope = kek_sealed();
	assert_eq!(envelope.mac.as_bytes().len(), 16);
	assert_eq!(ciphertext(&envelope).len(), CONTENT.len());
}

#[test]
fn the_content_type_sits_in_the_authenticated_attributes() {
	assert_eq!(content_type_values(&kek_sealed()), vec![DATA]);
}

/// Two seals of one content under one KEK draw two content keys. AES key
/// wrap is deterministic, so two equal content keys would wrap to two equal
/// `encryptedKey` values.
#[test]
fn two_seals_draw_two_content_keys() {
	let first = kek_sealed();
	let second = kek_sealed();
	assert_ne!(first.kek_recipient().encrypted_key, second.kek_recipient().encrypted_key);
	assert_ne!(ciphertext(&first), ciphertext(&second));
}

#[test]
fn two_seals_draw_two_nonces() {
	let first = gcm_parameters(&kek_sealed());
	let second = gcm_parameters(&kek_sealed());
	assert_ne!(first.aes_nonce, second.aes_nonce);
}

/// The associated data is the DER of the authenticated attributes under the
/// universal `SET OF` tag `0x31`, not their `[1]` tag (RFC 5083 §2.2).
///
/// The expected bytes come from an independent DER encoder in Python.
#[test]
fn the_associated_data_is_the_attributes_under_the_set_of_tag() -> Result<(), EnvelopeError> {
	let sealed = kek_sealed();
	let arrived = sealed.to_der()?;
	let associated_data = sealed.associated_data(&arrived, DATA)?;
	let expected = unhex("311a301806092a864886f70d010903310b06092a864886f70d010701");
	assert_eq!(associated_data, expected);
	Ok(())
}

/// The whole KEK seal under the draws of `SeededStream(0)`.
///
/// The expected bytes come from Python: `cryptography`'s AES key wrap and
/// AES-GCM over the RFC 5083 §2.2 associated data, in DER built by hand from
/// the RFC 5083, RFC 5084, and RFC 5652 modules.
#[test]
fn a_kek_seal_matches_its_known_answer() -> Result<(), crate::der::Error> {
	let expected = unhex(
		"3081ce020100314ea24c0201043010040e74622f746573742f6b656b2f7631300b060960864801650304012d0428\
		f6bcf11278268faaa844769bad995d29a3c5eefb22885f985df1e88a6896ed498f2526df9b3c500c304b06092a86\
		4886f70d010701301e060960864801650304012e3011040c020202020202020202020202020110801e66a3bd212f\
		39b594b0adc8ad3887a7dcd4d0bd809bd4ad12b2e9949e168fa11a301806092a864886f70d010903310b06092a86\
		4886f70d01070104104c242f80e64991259a11c735cf9f6b1d",
	);
	assert_eq!(kek_sealed_from_seed().to_der()?, expected);
	Ok(())
}

/// The fields of a KEM seal to the published recipient key under the draws
/// of `SeededStream(0)`.
///
/// The expected bytes come from Python: `cryptography`'s secp256k1 ECDH, a
/// DHKEM over HKDF-SHA256 from `hmac` and `hashlib`, HKDF-SHA3-256 over the
/// other info, AES key wrap, and AES-GCM.
#[test]
fn a_kem_seal_matches_its_known_answer() {
	let expected = KemSealFields {
		kemct: unhex(
			"04531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe3379e92c265e71e481ba82a84675a47ac\
			705a200fcd524e92d93b0e7386f26a5458",
		),
		ukm: unhex("74622f746573742f756b6d2f76310404040404040404040404040404040404040404040404040404040404040404"),
		encrypted_key: unhex("38b1e6b9f07c4ae0226623316211d4cc06445edbc3f7519f47dbca776b53479587e5c9bdd54ce6bd"),
		ciphertext: unhex("66a3bd212f39b594b0adc8ad3887a7dcd4d0bd809bd4ad12b2e9949e168f"),
		mac: unhex("4c242f80e64991259a11c735cf9f6b1d"),
	};
	assert_eq!(KemSealFields::of(&kem_sealed_from_seed()), expected);
}

#[tokio::test]
async fn a_kek_seal_opens_under_its_key() -> Result<(), EnvelopeError> {
	let content = opened(kek_sealed(), &kek_opener(), DATA).await?;
	assert_eq!(content.to_insecure().as_slice(), CONTENT);
	Ok(())
}

#[tokio::test]
async fn a_kem_seal_opens_under_the_identity_of_its_certificate() -> Result<(), EnvelopeError> {
	let identity = kem_identity();
	let content = opened(kem_sealed(&identity, UKM_LABEL), &kem_opener(&identity), DATA).await?;
	assert_eq!(content.to_insecure().as_slice(), CONTENT);
	Ok(())
}

/// The `KEMRecipientInfo` names the profile: version 0, DHKEM over
/// secp256k1, HKDF-SHA3-256, a 32-octet KEK, and AES-256 key wrap, each
/// algorithm with parameters absent.
#[test]
fn a_kem_recipient_names_the_profile() {
	let kem = kem_sealed(&kem_identity(), UKM_LABEL).kem_recipient();
	let expected = KemRecipientInfo {
		version: CmsVersion::V0,
		kem: AlgorithmIdentifierOwned { oid: DHKEM_SECP256K1, parameters: None },
		kdf: AlgorithmIdentifierOwned { oid: HKDF_SHA3_256, parameters: None },
		kek_length: 32,
		wrap: AlgorithmIdentifierOwned { oid: AES_256_WRAP, parameters: None },
		..kem.clone()
	};
	assert_eq!(kem, expected);
}

/// The `rid` is the recipient certificate's `subjectKeyIdentifier`.
#[test]
fn a_kem_recipient_names_its_certificate_by_its_key_identifier() -> Result<(), Box<dyn core::error::Error>> {
	let identity = kem_identity();
	let kem = kem_sealed(&identity, UKM_LABEL).kem_recipient();
	let key_identifier = identity.certificate().extension::<SubjectKeyIdentifier>()?;
	let key_identifier = key_identifier.ok_or("the certificate carries a key identifier")?;
	assert_eq!(kem.rid, RecipientIdentifier::SubjectKeyIdentifier(key_identifier));
	Ok(())
}

/// The `kemct` is DHKEM's `enc`, the 65-octet uncompressed point.
#[test]
fn the_kem_ciphertext_is_the_uncompressed_encapsulated_key() {
	let kem = kem_sealed(&kem_identity(), UKM_LABEL).kem_recipient();
	let kemct = kem.kemct.as_bytes();
	assert_eq!(kemct.len(), 65);
	assert_eq!(kemct.first(), Some(&0x04));
}

#[test]
fn the_ukm_is_the_purpose_label_and_32_random_octets() {
	let kem = kem_sealed(&kem_identity(), UKM_LABEL).kem_recipient();
	let ukm = kem.ukm.as_ref().map(OctetString::as_bytes);
	assert_eq!(ukm.map(<[u8]>::len), Some(UKM_LABEL.len() + 32));
	assert_eq!(ukm.map(|ukm| ukm.starts_with(UKM_LABEL)), Some(true));
}

/// The `KEKRecipientInfo` is version 4 (RFC 5652 §6.2.3).
#[test]
fn a_kek_recipient_is_version_4() {
	assert_eq!(kek_sealed().kek_recipient().version, CmsVersion::V4);
}

#[test]
fn a_kek_recipient_names_its_key_by_its_identifier() {
	let kek = kek_sealed().kek_recipient();
	assert_eq!(kek.kek_id.kek_identifier.as_bytes(), KEY_IDENTIFIER);
}

/// The `KEKRecipientInfo` wraps under AES-256 key wrap with parameters
/// absent (RFC 3565 §2.3.2).
#[test]
fn a_kek_recipient_wraps_under_aes_256_key_wrap() {
	let wrap = AlgorithmIdentifierOwned { oid: AES_256_WRAP, parameters: None };
	assert_eq!(kek_sealed().kek_recipient().key_enc_alg, wrap);
}

/// The `CMSORIforKEMOtherInfo` of the known answer below.
fn known_other_info() -> CmsOriForKemOtherInfo {
	let ukm = [b"tb/handshake/opening/ukm/v1".as_slice(), &[0x07u8; 32]].concat();
	let ukm = OctetString::new(ukm).expect("the ukm is an OCTET STRING");
	let wrap = AlgorithmIdentifierOwned { oid: AES_256_WRAP, parameters: None };
	CmsOriForKemOtherInfo { wrap, kek_length: 32, ukm: Some(ukm) }
}

/// The info encodes as RFC 9629 §5 writes it, with the `ukm` under an
/// explicit `[0]`.
///
/// The expected bytes come from an independent DER encoder in Python.
#[test]
fn the_kem_other_info_encodes_as_rfc_9629_writes_it() -> Result<(), crate::der::Error> {
	let expected = unhex(
		"304f300b060960864801650304012d020120a03d043b74622f68616e647368616b652f6f70656e696e672f756b6d2f7631\
		0707070707070707070707070707070707070707070707070707070707070707",
	);
	assert_eq!(known_other_info().to_der()?, expected);
	Ok(())
}

/// The KEK is HKDF-SHA3-256 of the shared secret `0x5a` × 32, with an empty
/// salt and the DER of the info as `info`, for 32 octets.
///
/// The expected bytes come from an independent HKDF (Python's `hmac` and
/// `hashlib`), so no code of the crate computes them.
#[test]
fn the_kem_kek_matches_its_known_answer() -> Result<(), EnvelopeError> {
	let kek = known_other_info().derive_kek::<HkdfSha3_256>(&[0x5au8; 32])?;
	let expected = unhex("4a68f649a3e6c8d69006489c7f8feb66d581355fd186255227f3826d9639cc1c");
	assert_eq!(kek.to_vec(), expected);
	Ok(())
}

/// The first `size` octets of the RFC 3394 §4 KEK, `000102...1f`.
fn rfc_3394_kek(size: usize) -> Vec<u8> {
	let mut kek = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	kek.truncate(size);
	kek
}

/// The first `size` octets of the RFC 3394 §4 key data, `00112233...0f`.
fn rfc_3394_key_data(size: usize) -> ZeroizingBytes {
	let mut key_data = unhex("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
	key_data.truncate(size);
	Zeroizing::new(key_data)
}

/// The RFC 3394 §4.1 ciphertext: 128 bits of key data under a 128-bit KEK.
const RFC_3394_4_1: &str = "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5";

/// The RFC 3394 §4.2 ciphertext: 128 bits of key data under a 192-bit KEK.
const RFC_3394_4_2: &str = "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d";

/// The RFC 3394 §4.3 ciphertext: 128 bits of key data under a 256-bit KEK.
const RFC_3394_4_3: &str = "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7";

/// The RFC 3394 §4.4 ciphertext: 192 bits of key data under a 192-bit KEK.
const RFC_3394_4_4: &str = "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2";

/// The RFC 3394 §4.5 ciphertext: 192 bits of key data under a 256-bit KEK.
const RFC_3394_4_5: &str = "a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1";

/// The RFC 3394 §4.6 ciphertext: 256 bits of key data under a 256-bit KEK.
const RFC_3394_4_6: &str = "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21";

#[test]
fn aes_128_key_wrap_matches_rfc_3394_4_1() -> Result<(), KeyError> {
	let wrapped = Aes128Wrap::wrap(&rfc_3394_kek(16), &rfc_3394_key_data(16))?;
	assert_eq!(wrapped, unhex(RFC_3394_4_1));
	Ok(())
}

#[test]
fn aes_128_key_unwrap_matches_rfc_3394_4_1() -> Result<(), KeyError> {
	let unwrapped = Aes128Wrap::unwrap(&rfc_3394_kek(16), &unhex(RFC_3394_4_1))?;
	assert_eq!(unwrapped, rfc_3394_key_data(16));
	Ok(())
}

#[test]
fn aes_192_key_wrap_matches_rfc_3394_4_2() -> Result<(), KeyError> {
	let wrapped = Aes192Wrap::wrap(&rfc_3394_kek(24), &rfc_3394_key_data(16))?;
	assert_eq!(wrapped, unhex(RFC_3394_4_2));
	Ok(())
}

#[test]
fn aes_192_key_unwrap_matches_rfc_3394_4_2() -> Result<(), KeyError> {
	let unwrapped = Aes192Wrap::unwrap(&rfc_3394_kek(24), &unhex(RFC_3394_4_2))?;
	assert_eq!(unwrapped, rfc_3394_key_data(16));
	Ok(())
}

#[test]
fn aes_256_key_wrap_matches_rfc_3394_4_3() -> Result<(), KeyError> {
	let wrapped = Aes256Wrap::wrap(&rfc_3394_kek(32), &rfc_3394_key_data(16))?;
	assert_eq!(wrapped, unhex(RFC_3394_4_3));
	Ok(())
}

#[test]
fn aes_256_key_unwrap_matches_rfc_3394_4_3() -> Result<(), KeyError> {
	let unwrapped = Aes256Wrap::unwrap(&rfc_3394_kek(32), &unhex(RFC_3394_4_3))?;
	assert_eq!(unwrapped, rfc_3394_key_data(16));
	Ok(())
}

/// The house wrap unwraps onto a caller's buffer of the key's size: RFC 3394
/// §4.3, 128 bits of key data under a 256-bit KEK.
#[test]
fn aes_256_key_unwrap_into_matches_rfc_3394_4_3() -> Result<(), KeyError> {
	let mut key = Zeroizing::new([0u8; 16]);
	Aes256Wrap::unwrap_into(&rfc_3394_kek(32), &unhex(RFC_3394_4_3), &mut *key)?;
	assert_eq!(key.as_slice(), rfc_3394_key_data(16).as_slice());
	Ok(())
}

/// The house wrap refuses a buffer of another size than the wrapped key, and
/// names the 16 octets the key takes.
#[test]
fn the_house_unwrap_into_refuses_a_buffer_of_another_size() {
	let mut key = [0u8; 32];
	let refused = Aes256Wrap::unwrap_into(&rfc_3394_kek(32), &unhex(RFC_3394_4_3), &mut key);
	assert!(matches!(refused, Err(KeyError::WrapLength(sizes)) if (sizes.received, sizes.expected) == (32, 16)));
}

#[test]
fn aes_192_key_wrap_matches_rfc_3394_4_4() -> Result<(), KeyError> {
	let wrapped = Aes192Wrap::wrap(&rfc_3394_kek(24), &rfc_3394_key_data(24))?;
	assert_eq!(wrapped, unhex(RFC_3394_4_4));
	Ok(())
}

#[test]
fn aes_192_key_unwrap_matches_rfc_3394_4_4() -> Result<(), KeyError> {
	let unwrapped = Aes192Wrap::unwrap(&rfc_3394_kek(24), &unhex(RFC_3394_4_4))?;
	assert_eq!(unwrapped, rfc_3394_key_data(24));
	Ok(())
}

#[test]
fn aes_256_key_wrap_matches_rfc_3394_4_5() -> Result<(), KeyError> {
	let wrapped = Aes256Wrap::wrap(&rfc_3394_kek(32), &rfc_3394_key_data(24))?;
	assert_eq!(wrapped, unhex(RFC_3394_4_5));
	Ok(())
}

#[test]
fn aes_256_key_unwrap_matches_rfc_3394_4_5() -> Result<(), KeyError> {
	let unwrapped = Aes256Wrap::unwrap(&rfc_3394_kek(32), &unhex(RFC_3394_4_5))?;
	assert_eq!(unwrapped, rfc_3394_key_data(24));
	Ok(())
}

#[test]
fn aes_256_key_wrap_matches_rfc_3394_4_6() -> Result<(), KeyError> {
	let wrapped = Aes256Wrap::wrap(&rfc_3394_kek(32), &rfc_3394_key_data(32))?;
	assert_eq!(wrapped, unhex(RFC_3394_4_6));
	Ok(())
}

#[test]
fn aes_256_key_unwrap_matches_rfc_3394_4_6() -> Result<(), KeyError> {
	let unwrapped = Aes256Wrap::unwrap(&rfc_3394_kek(32), &unhex(RFC_3394_4_6))?;
	assert_eq!(unwrapped, rfc_3394_key_data(32));
	Ok(())
}

/// AES-128 key wrap names `id-aes128-wrap` (RFC 3565 §2.3.2).
#[test]
fn aes_128_key_wrap_names_its_identifier() {
	assert_eq!(<Aes128Wrap as AssociatedOid>::OID, AES_128_WRAP);
}

/// AES-192 key wrap names `id-aes192-wrap` (RFC 3565 §2.3.2).
#[test]
fn aes_192_key_wrap_names_its_identifier() {
	assert_eq!(<Aes192Wrap as AssociatedOid>::OID, AES_192_WRAP);
}

/// AES-256 key wrap names `id-aes256-wrap` (RFC 3565 §2.3.2).
#[test]
fn aes_256_key_wrap_names_its_identifier() {
	assert_eq!(<Aes256Wrap as AssociatedOid>::OID, AES_256_WRAP);
}

/// RFC 3394 §2 wraps two or more 64-bit blocks, so a key of one block is
/// refused.
#[test]
fn a_wrap_of_one_block_is_refused() {
	let refused = Aes256Wrap::wrap(&rfc_3394_kek(32), &[0x00; 8]);
	assert!(matches!(refused, Err(KeyError::WrapLength(_))));
}

/// An input of two 64-bit blocks would unwrap to a key of one block, under
/// the floor of RFC 3394 §2, so it is refused.
#[test]
fn an_unwrap_of_two_blocks_is_refused() {
	let refused = Aes256Wrap::unwrap(&rfc_3394_kek(32), &[0x00; 16]);
	assert!(matches!(refused, Err(KeyError::WrapLength(_))));
}

#[test]
fn a_seal_that_carries_its_own_content_type_attribute_is_refused() {
	let content_type = content_type_attribute(&[SIGNED_DATA]);
	let refused = AuthEnvelopedData::seal::<House>(kek_recipient_of(), DATA, CONTENT, [content_type], None);
	assert!(matches!(refused, Err(EnvelopeError::ContentTypeAttribute)));
}

/// An envelope whose authenticated attributes arrive out of DER order is
/// refused, though it decodes and its tag would pass over the sorted set
/// (RFC 5083 §2.1).
#[tokio::test]
async fn authenticated_attributes_out_of_der_order_are_refused() -> Result<(), EnvelopeError> {
	let sealed = AuthEnvelopedData::seal::<House>(kek_recipient_of(), DATA, CONTENT, [marker_attribute()], None)?;
	let arrived = with_misordered_auth_attrs(&sealed);
	let envelope = AuthEnvelopedData::from_der(&arrived)?;

	let refused = envelope.open::<House>(&arrived, &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::AuthAttributesNotDer)));
	Ok(())
}

#[tokio::test]
async fn an_envelope_of_another_version_is_refused() {
	let envelope = AuthEnvelopedData { version: CmsVersion::V2, ..kek_sealed() };
	let refused = opened(envelope, &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::Version(_))));
}

#[tokio::test]
async fn a_content_encryption_algorithm_other_than_aes_256_gcm_is_refused() {
	let mut envelope = kek_sealed();
	envelope.auth_encrypted_content_info.content_enc_alg.oid = AES_128_GCM;

	let refused = opened(envelope, &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::ContentEncryptionAlgorithm)));
}

/// A bare OCTET STRING nonce in place of `GCMParameters` is refused.
#[tokio::test]
async fn a_bare_nonce_in_place_of_gcm_parameters_is_refused() {
	let nonce = gcm_parameters(&kek_sealed()).aes_nonce;
	let envelope = with_parameters(kek_sealed(), &nonce);

	let refused = opened(envelope, &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::ContentEncryptionAlgorithm)));
}

#[tokio::test]
async fn an_aes_icv_length_other_than_16_is_refused() {
	let envelope = kek_sealed();
	let parameters = GcmParameters { aes_icv_len: 12, ..gcm_parameters(&envelope) };
	let envelope = with_parameters(envelope, &parameters);

	let refused = opened(envelope, &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::TagLength(_))));
}

#[tokio::test]
async fn a_mac_of_another_length_than_16_is_refused() -> Result<(), crate::der::Error> {
	let envelope = AuthEnvelopedData { mac: OctetString::new([0x00u8; 12])?, ..kek_sealed() };

	let refused = opened(envelope, &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::TagLength(_))));
	Ok(())
}

#[tokio::test]
async fn an_envelope_without_a_content_type_attribute_is_refused() {
	let envelope = with_auth_attrs(kek_sealed(), vec![marker_attribute()]);

	let refused = opened(envelope, &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::ContentTypeAttribute)));
}

#[tokio::test]
async fn an_envelope_with_two_content_type_attributes_is_refused() {
	let attributes = vec![content_type_attribute(&[DATA]), content_type_attribute(&[SIGNED_DATA])];
	let envelope = with_auth_attrs(kek_sealed(), attributes);

	let refused = opened(envelope, &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::ContentTypeAttribute)));
}

#[tokio::test]
async fn a_content_type_attribute_of_two_values_is_refused() {
	let envelope = with_auth_attrs(kek_sealed(), vec![content_type_attribute(&[DATA, SIGNED_DATA])]);

	let refused = opened(envelope, &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::ContentTypeAttribute)));
}

#[tokio::test]
async fn a_content_type_other_than_the_expected_one_is_refused() {
	let refused = opened(kek_sealed(), &kek_opener(), SIGNED_DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::ContentType(_))));
}

/// The tag covers the content-type attribute and not `eContentType`, so a
/// seal of `SignedData` whose `eContentType` is rewritten to `id-data`,
/// opened as `id-data`, is refused on its content-type attribute (RFC 5083
/// §2.1).
#[tokio::test]
async fn a_rewritten_encrypted_content_type_is_refused() -> Result<(), EnvelopeError> {
	let mut envelope = AuthEnvelopedData::seal::<House>(kek_recipient_of(), SIGNED_DATA, CONTENT, [], None)?;
	envelope.auth_encrypted_content_info.content_type = DATA;

	let refused = opened(envelope, &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::ContentType(_))));
	Ok(())
}

#[tokio::test]
async fn an_envelope_with_two_recipients_is_refused() -> Result<(), crate::der::Error> {
	let envelope = kek_sealed();
	let first = envelope.kek_recipient();
	let kek_id = KekIdentifier { kek_identifier: OctetString::new(b"tb/test/other/v1")?, ..first.kek_id.clone() };
	let second = KekRecipientInfo { kek_id, ..first.clone() };
	let envelope = envelope.with_recipients([RecipientInfo::Kekri(first), RecipientInfo::Kekri(second)]);

	let refused = opened(envelope, &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::RecipientKind)));
	Ok(())
}

/// A KEM seal under another purpose's `ukm` label is refused, though the
/// key it encapsulated to is the opener's.
#[tokio::test]
async fn a_kem_seal_under_another_ukm_is_refused() {
	let identity = kem_identity();
	let envelope = kem_sealed(&identity, b"tb/test/other/v1");

	let refused = opened(envelope, &kem_opener(&identity), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::Ukm)));
}

/// A `ukm` of the opener's label and one octet more than 32 after it is
/// refused before the agreement runs.
#[tokio::test]
async fn a_ukm_of_another_length_is_refused() {
	let identity = kem_identity();
	let envelope = kem_sealed(&identity, UKM_LABEL);
	let kem = with_longer_ukm(envelope.kem_recipient());
	let envelope = envelope.with_kem_recipient(&kem);

	let refused = opened(envelope, &kem_opener(&identity), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::Ukm)));
}

/// The `ukm` enters the KDF input of the KEK, so a changed random octet,
/// under the opener's label, derives another KEK, and the content key fails
/// to unwrap (RFC 9629 §5).
#[tokio::test]
async fn a_ukm_with_another_random_fails_the_key_unwrap() {
	let identity = kem_identity();
	let envelope = kem_sealed(&identity, UKM_LABEL);
	let kem = with_flipped_ukm(envelope.kem_recipient());
	let envelope = envelope.with_kem_recipient(&kem);

	let refused = opened(envelope, &kem_opener(&identity), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::KeyUnwrap)));
}

/// A KEK seal of another purpose names another key, and is refused.
#[tokio::test]
async fn a_kek_seal_of_another_purpose_is_refused() {
	let opener = Opener::Kek { kek: &KEK, key_identifier: b"tb/test/other/v1" };
	let refused = opened(kek_sealed(), &opener, DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::KeyIdentifier)));
}

#[tokio::test]
async fn a_kek_identifier_with_a_date_is_refused() -> Result<(), crate::der::Error> {
	let envelope = kek_sealed();
	let kek = envelope.kek_recipient();
	let date = Some(GeneralizedTime::from_unix_duration(core::time::Duration::from_secs(0))?);
	let kek = KekRecipientInfo { kek_id: KekIdentifier { date, ..kek.kek_id.clone() }, ..kek };
	let envelope = envelope.with_kek_recipient(&kek);

	let refused = opened(envelope, &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::KeyIdentifier)));
	Ok(())
}

#[tokio::test]
async fn a_kek_identifier_with_another_key_attribute_is_refused() {
	let envelope = kek_sealed();
	let kek = envelope.kek_recipient();
	let other = Some(marker_attribute());
	let kek = KekRecipientInfo { kek_id: KekIdentifier { other, ..kek.kek_id.clone() }, ..kek };
	let envelope = envelope.with_kek_recipient(&kek);

	let refused = opened(envelope, &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::KeyIdentifier)));
}

/// A `KEKRecipientInfo` must be version 4 (RFC 5652 §6.2.3).
#[tokio::test]
async fn a_kek_recipient_of_another_version_is_refused() {
	let envelope = kek_sealed();
	let kek = KekRecipientInfo { version: CmsVersion::V2, ..envelope.kek_recipient() };
	let envelope = envelope.with_kek_recipient(&kek);

	let refused = opened(envelope, &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::RecipientVersion(_))));
}

#[tokio::test]
async fn a_kek_recipient_under_another_wrap_is_refused() {
	let envelope = kek_sealed();
	let key_enc_alg = AlgorithmIdentifierOwned { oid: AES_128_WRAP, parameters: None };
	let kek = KekRecipientInfo { key_enc_alg, ..envelope.kek_recipient() };
	let envelope = envelope.with_kek_recipient(&kek);

	let refused = opened(envelope, &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::RecipientAlgorithm)));
}

#[tokio::test]
async fn a_kem_seal_opened_as_a_kek_seal_is_refused() {
	let refused = opened(kem_sealed(&kem_identity(), UKM_LABEL), &kek_opener(), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::RecipientKind)));
}

#[tokio::test]
async fn a_kek_seal_opened_as_a_kem_seal_is_refused() {
	let identity = kem_identity();
	let refused = opened(kek_sealed(), &kem_opener(&identity), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::RecipientKind)));
}

/// A valid `KEMRecipientInfo` under `id-data` as its `oriType` in place of
/// `id-ori-kem` is refused (RFC 9629 §3).
#[tokio::test]
async fn an_other_recipient_of_another_type_is_refused() -> Result<(), crate::der::Error> {
	let identity = kem_identity();
	let envelope = kem_sealed(&identity, UKM_LABEL);
	let ori_value = Any::encode_from(&envelope.kem_recipient())?;
	let other = OtherRecipientInfo { ori_type: DATA, ori_value };
	let envelope = envelope.with_recipients([RecipientInfo::Ori(other)]);

	let refused = opened(envelope, &kem_opener(&identity), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::RecipientKind)));
	Ok(())
}

#[tokio::test]
async fn a_kek_length_other_than_32_is_refused() {
	let identity = kem_identity();
	let envelope = kem_sealed(&identity, UKM_LABEL);
	let kem = KemRecipientInfo { kek_length: 16, ..envelope.kem_recipient() };
	let envelope = envelope.with_kem_recipient(&kem);

	let refused = opened(envelope, &kem_opener(&identity), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::KekLength(_))));
}

#[tokio::test]
async fn a_kem_recipient_of_another_version_is_refused() {
	let identity = kem_identity();
	let envelope = kem_sealed(&identity, UKM_LABEL);
	let kem = KemRecipientInfo { version: CmsVersion::V2, ..envelope.kem_recipient() };
	let envelope = envelope.with_kem_recipient(&kem);

	let refused = opened(envelope, &kem_opener(&identity), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::RecipientVersion(_))));
}

/// A seal to one certificate is refused by the holder of another.
#[tokio::test]
async fn a_kem_recipient_that_names_another_certificate_is_refused() {
	let other = kem_identity();
	let refused = opened(kem_sealed(&kem_identity(), UKM_LABEL), &kem_opener(&other), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::RecipientIdentifier)));
}

#[tokio::test]
async fn a_kem_recipient_under_another_wrap_is_refused() {
	let identity = kem_identity();
	let envelope = kem_sealed(&identity, UKM_LABEL);
	let wrap = AlgorithmIdentifierOwned { oid: AES_128_WRAP, parameters: None };
	let kem = KemRecipientInfo { wrap, ..envelope.kem_recipient() };
	let envelope = envelope.with_kem_recipient(&kem);

	let refused = opened(envelope, &kem_opener(&identity), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::RecipientAlgorithm)));
}

#[tokio::test]
async fn a_kem_recipient_under_another_kem_is_refused() {
	let identity = kem_identity();
	let envelope = kem_sealed(&identity, UKM_LABEL);
	let kem_algorithm = AlgorithmIdentifierOwned { oid: ObjectIdentifier::new_unwrap("1.2.3.4.5"), parameters: None };
	let kem = KemRecipientInfo { kem: kem_algorithm, ..envelope.kem_recipient() };
	let envelope = envelope.with_kem_recipient(&kem);

	let refused = opened(envelope, &kem_opener(&identity), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::RecipientAlgorithm)));
}

/// A KDF of HKDF-SHA256 (`id-alg-hkdf-with-sha256`, RFC 8619) in place of
/// HKDF-SHA3-256 is refused.
#[tokio::test]
async fn a_kem_recipient_under_another_kdf_is_refused() {
	let identity = kem_identity();
	let envelope = kem_sealed(&identity, UKM_LABEL);
	let hkdf_sha256 = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.28");
	let kdf = AlgorithmIdentifierOwned { oid: hkdf_sha256, parameters: None };
	let kem = KemRecipientInfo { kdf, ..envelope.kem_recipient() };
	let envelope = envelope.with_kem_recipient(&kem);

	let refused = opened(envelope, &kem_opener(&identity), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::RecipientAlgorithm)));
}

/// The KEM's parameters must be absent, so a NULL there is refused.
#[tokio::test]
async fn a_kem_algorithm_with_parameters_is_refused() -> Result<(), crate::der::Error> {
	let identity = kem_identity();
	let envelope = kem_sealed(&identity, UKM_LABEL);
	let kem_algorithm = AlgorithmIdentifierOwned { oid: DHKEM_SECP256K1, parameters: Some(Any::encode_from(&Null)?) };
	let kem = KemRecipientInfo { kem: kem_algorithm, ..envelope.kem_recipient() };
	let envelope = envelope.with_kem_recipient(&kem);

	let refused = opened(envelope, &kem_opener(&identity), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::RecipientAlgorithm)));
	Ok(())
}

/// The KEM ciphertext in its compressed form is refused, because DHKEM over
/// secp256k1 writes `enc` uncompressed.
#[tokio::test]
async fn a_compressed_kem_ciphertext_is_refused() {
	let identity = kem_identity();
	let envelope = kem_sealed(&identity, UKM_LABEL);
	let kem = with_compressed_kemct(envelope.kem_recipient());
	let envelope = envelope.with_kem_recipient(&kem);

	let refused = opened(envelope, &kem_opener(&identity), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::KemPoint)));
}

/// The opener parses the `kemct` before the key provider runs, so a
/// compressed `kemct` is refused with no agreement asked of the provider.
#[tokio::test]
async fn a_compressed_kem_ciphertext_is_refused_before_the_agreement() -> Result<(), EnvelopeError> {
	let key = Secp256k1SigningKey::random(&mut OsRng);
	let certificate = TestCertificate::self_signed(&key);
	let provider = Arc::new(RecordingAgreement::new(key));
	let identity = KeyAgreementIdentity::<HouseKem>::new(certificate, provider.to_owned())?;
	let envelope = kem_sealed(&identity, UKM_LABEL);
	let kem = with_compressed_kemct(envelope.kem_recipient());
	let envelope = envelope.with_kem_recipient(&kem);

	let refused = opened(envelope, &kem_opener(&identity), DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::KemPoint)));
	assert!(provider.agreements().is_empty());
	Ok(())
}

/// A clone of a key-agreement identity shares the one checked value, so it
/// copies no recipient and no `rid`.
#[test]
fn a_cloned_key_agreement_identity_shares_its_recipient() {
	let identity = kem_identity();
	let clone = identity.clone();
	assert!(core::ptr::eq(identity.recipient(), clone.recipient()));
}

/// A KEM sender seals only to a `KemRecipient`, which the key-agreement use
/// builds, so a certificate that carries no `keyUsage` names no recipient
/// (RFC 9629 §3, RFC 5280 §4.2.1.3).
#[test]
fn a_recipient_certificate_without_key_usage_names_no_kem_recipient() {
	let certificate = certificate_with_key_usage(&Secp256k1SigningKey::random(&mut OsRng), None);
	let refused = PeerCertificate::<KeyAgreement<HouseKem>>::parse(certificate, KeyPurposes::HOUSE.server);
	assert!(matches!(
		refused,
		Err(CertificateValidationError::MissingKeyUsage(KeyUsages::KeyAgreement))
	));
}

/// A certificate whose `keyUsage` lacks `keyAgreement` names no recipient
/// a KEM sender seals to.
#[test]
fn a_recipient_certificate_without_key_agreement_names_no_kem_recipient() {
	let key_usage = Some(KeyUsage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation));
	let certificate = certificate_with_key_usage(&Secp256k1SigningKey::random(&mut OsRng), key_usage);

	let refused = PeerCertificate::<KeyAgreement<HouseKem>>::parse(certificate, KeyPurposes::HOUSE.server);
	assert!(matches!(
		refused,
		Err(CertificateValidationError::MissingKeyUsage(KeyUsages::KeyAgreement))
	));
}

/// A KEM seal to a certificate whose `keyUsage` asserts `digitalSignature`
/// and `keyAgreement` (RFC 5480 §3) names the certificate as its `rid`.
#[test]
fn a_kem_seal_to_a_key_agreement_certificate_names_it() -> Result<(), Box<dyn core::error::Error>> {
	let certificate = certificate_with_key_usage(&Secp256k1SigningKey::random(&mut OsRng), server_key_usage());
	let admitted = PeerCertificate::<KeyAgreement<HouseKem>>::parse(certificate.to_owned(), KeyPurposes::HOUSE.server)?;
	let recipient = KemRecipient::from_certificate(admitted)?;

	let recipient = Recipient::Kem { recipient: &recipient, ukm_label: UKM_LABEL };
	let sealed = AuthEnvelopedData::seal::<House>(recipient, DATA, CONTENT, [], None)?;
	assert_eq!(sealed.kem_recipient().rid, certificate.recipient_identifier()?);
	Ok(())
}

/// A KEM opener pairs its backend only with a certificate admitted for key
/// agreement, so one that carries no `keyUsage` is refused.
#[test]
fn a_kem_opener_refuses_a_certificate_without_key_usage() {
	let key = Secp256k1SigningKey::random(&mut OsRng);
	let refused = HouseIdentity::new(certificate_with_key_usage(&key, None), backend_of(&key));
	assert!(matches!(
		refused,
		Err(EnvelopeError::Certificate(CertificateValidationError::MissingKeyUsage(
			KeyUsages::KeyAgreement
		)))
	));
}

/// A KEM opener refuses a certificate whose `keyUsage` lacks `keyAgreement`.
#[test]
fn a_kem_opener_refuses_a_certificate_without_key_agreement() {
	let key = Secp256k1SigningKey::random(&mut OsRng);
	let key_usage = Some(KeyUsage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation));

	let refused = HouseIdentity::new(certificate_with_key_usage(&key, key_usage), backend_of(&key));
	assert!(matches!(
		refused,
		Err(EnvelopeError::Certificate(CertificateValidationError::MissingKeyUsage(
			KeyUsages::KeyAgreement
		)))
	));
}

/// A key-agreement identity refuses a backend whose public half differs
/// from the certificate's key, so the key that decapsulates is the key the
/// `rid` names.
#[test]
fn a_key_agreement_identity_refuses_a_backend_of_another_key() {
	let key = Secp256k1SigningKey::random(&mut OsRng);
	let other = Secp256k1SigningKey::random(&mut OsRng);

	let refused = HouseIdentity::new(TestCertificate::self_signed(&key), backend_of(&other));
	assert!(matches!(refused, Err(EnvelopeError::KeyMismatch)));
}

/// A key-agreement identity pairs a backend with a certificate that holds
/// the backend's point in the compressed SEC 1 form, since both forms name
/// one key (RFC 5480 §2.2).
#[test]
fn a_key_agreement_identity_admits_its_key_in_the_compressed_form() -> Result<(), EnvelopeError> {
	let key = Secp256k1SigningKey::random(&mut OsRng);
	let certificate = TestCertificate::with_compressed_key(TestCertificate::self_signed(&key));
	HouseIdentity::new(certificate, backend_of(&key))?;
	Ok(())
}

/// A key-agreement identity refuses a backend whose point is the negation of
/// the certificate's, though the two points share an x-coordinate.
#[test]
fn a_key_agreement_identity_refuses_the_negation_of_its_key() {
	let key = Secp256k1SigningKey::random(&mut OsRng);
	let negation = TestKey::negation_of(&key);

	let refused = HouseIdentity::new(TestCertificate::self_signed(&key), backend_of(&negation));
	assert!(matches!(refused, Err(EnvelopeError::KeyMismatch)));
}

/// An opener whose certificate asserts `digitalSignature` and
/// `keyAgreement` opens a KEM seal to its key.
#[tokio::test]
async fn an_opener_whose_certificate_permits_key_agreement_opens() -> Result<(), EnvelopeError> {
	let key = Secp256k1SigningKey::random(&mut OsRng);
	let identity = agreement_identity(certificate_with_key_usage(&key, server_key_usage()), &key);
	let envelope = kem_sealed(&identity, UKM_LABEL);

	let opened = opened(envelope, &kem_opener(&identity), DATA).await?;
	assert_eq!(opened.to_insecure().as_slice(), CONTENT);
	Ok(())
}

/// The DER SubjectPublicKeyInfo of the published recipient key of
/// draft-wahby-cfrg-hpke-kem-secp256k1-01 B.1.1: `id-ecPublicKey` on
/// secp256k1 (RFC 5480 §2.1.1) over its uncompressed point.
const PUBLISHED_RECIPIENT_SPKI: &str = "3056301006072a8648ce3d020106052b8104000a034200\
	043ee7314407753d1ba296de29f07b2cd5505ca94b614f127e71f3c19fc7845d\
	af49c9bb4bf4d00d3b5411c8eb86d59a2dcadc5a13115fa9fef44d1e0b7ef11cab";

/// The RFC 7093 §2 method 1 identifier of the published recipient key: the
/// leftmost 160 bits of the SHA-256 of its uncompressed point, from Python's
/// `hashlib`.
const PUBLISHED_RECIPIENT_KEY_IDENTIFIER: &str = "ec9cf0de6fadd0acb971ccd7332d7e310cb91b9d";

/// The bare key of a fresh secp256k1 key, beside the DER of its public key.
fn bare_key() -> (BareKemKey<HouseKem>, Vec<u8>) {
	let key = Secp256k1SigningKey::random(&mut OsRng);
	let backend = backend_of(&key);
	let spki = backend.to_public_key_bytes().expect("the house backend encodes its key");
	let bare = BareKemKey::new(PublicKey::from(key.verifying_key()), backend);
	(bare.expect("the backend holds the key"), spki)
}

/// [`CONTENT`] sealed as `id-data` to `recipient`, with a `ukm` led by
/// [`UKM_LABEL`].
fn sealed_to(recipient: &KemRecipient<HouseKem>) -> AuthEnvelopedData {
	let recipient = Recipient::Kem { recipient, ukm_label: UKM_LABEL };
	let sealed = AuthEnvelopedData::seal::<House>(recipient, DATA, CONTENT, [], None);
	sealed.expect("the content seals")
}

/// A bare recipient is named by the RFC 7093 §2 method 1 identifier of its
/// key, in the `subjectKeyIdentifier` form of the `rid`.
#[test]
fn a_bare_recipient_is_named_by_the_rfc_7093_identifier_of_its_key() -> Result<(), Box<dyn core::error::Error>> {
	let recipient = KemRecipient::<HouseKem>::bare(unhex(PUBLISHED_RECIPIENT_SPKI))?;
	let sealed = sealed_to(&recipient);

	let expected = SubjectKeyIdentifier(OctetString::new(unhex(PUBLISHED_RECIPIENT_KEY_IDENTIFIER))?);
	assert_eq!(sealed.kem_recipient().rid, RecipientIdentifier::SubjectKeyIdentifier(expected));
	Ok(())
}

/// A bare recipient of a key that is no secp256k1 point is refused: the
/// SubjectPublicKeyInfo names P-256 (`1.2.840.10045.3.1.7`, RFC 5480
/// §2.1.1.1).
#[test]
fn a_bare_recipient_of_another_curve_is_refused() {
	let p256 = "3059301306072a8648ce3d020106082a8648ce3d030107034200\
		043ee7314407753d1ba296de29f07b2cd5505ca94b614f127e71f3c19fc7845d\
		af49c9bb4bf4d00d3b5411c8eb86d59a2dcadc5a13115fa9fef44d1e0b7ef11cab";

	let refused = KemRecipient::<HouseKem>::bare(unhex(p256));
	assert!(matches!(refused, Err(EnvelopeError::Certificate(_))));
}

/// A bare key whose backend holds another key than its public key is
/// refused at construction, so the key that decapsulates is the key the
/// `rid` names.
#[test]
fn a_bare_kem_key_refuses_a_backend_of_another_key() {
	let key = Secp256k1SigningKey::random(&mut OsRng);
	let other = Secp256k1SigningKey::random(&mut OsRng);

	let refused = BareKemKey::<HouseKem>::new(PublicKey::from(key.verifying_key()), backend_of(&other));
	assert!(matches!(refused, Err(EnvelopeError::KeyMismatch)));
}

/// A bare key lends the recipient of its own key, so it names the `rid` the
/// bare recipient of its public key names.
#[test]
fn a_bare_kem_key_lends_the_recipient_of_its_key() -> Result<(), EnvelopeError> {
	let (bare, spki) = bare_key();
	let recipient = KemRecipient::<HouseKem>::bare(&spki)?;

	let lent = sealed_to(bare.recipient()).kem_recipient();
	let named = sealed_to(&recipient).kem_recipient();
	assert_eq!(lent.rid, named.rid);
	Ok(())
}

/// A seal to the bare recipient of a key opens through the bare key that
/// holds it.
#[tokio::test]
async fn a_seal_to_a_bare_recipient_opens_through_its_bare_kem_key() -> Result<(), EnvelopeError> {
	let (bare, spki) = bare_key();
	let sealed = sealed_to(&KemRecipient::<HouseKem>::bare(&spki)?);

	let opener = Opener::Kem { identity: &bare, ukm_label: UKM_LABEL };
	let opened = opened(sealed, &opener, DATA).await?;
	assert_eq!(opened.to_insecure().as_slice(), CONTENT);
	Ok(())
}

/// A seal to another bare recipient is refused by its `rid` before the
/// backend runs.
#[tokio::test]
async fn a_seal_to_another_bare_recipient_is_refused() -> Result<(), EnvelopeError> {
	let (_, other_spki) = bare_key();
	let (bare, _) = bare_key();
	let sealed = sealed_to(&KemRecipient::<HouseKem>::bare(&other_spki)?);

	let opener = Opener::Kem { identity: &bare, ukm_label: UKM_LABEL };
	let refused = opened(sealed, &opener, DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::RecipientIdentifier)));
	Ok(())
}
