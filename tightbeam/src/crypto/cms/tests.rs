use std::sync::{Arc, Mutex};

use crate::asn1::admission::DerAdmission;
use crate::asn1::WireDer;
use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{
	KekIdentifier, KekRecipientInfo, OtherRecipientInfo, RecipientIdentifier, RecipientInfo, RecipientInfos,
};
use crate::crypto::cms::kek;
use crate::crypto::cms::{
	ArrivedEnvelope, AuthEnvelopedData, BareKemKey, CmsOriForKemOtherInfo, EnvelopeError, GcmParameters, KemKeyHolder,
	KemRecipient, KemRecipientInfo, KeyAgreementIdentity, Opener, Recipient,
};
use crate::crypto::hpke::DhKemSecp256k1;
use crate::crypto::k256::elliptic_curve::sec1::ToEncodedPoint;
use crate::crypto::k256::{PublicKey, Secp256k1};
use crate::crypto::kdf::HkdfSha3_256;
use crate::crypto::key::{DiffieHellman, KeyBackend, KeyError, Secp256k1KeyProvider};
use crate::crypto::profiles::{Aes128Wrap, Aes192Wrap, Aes256Wrap, DefaultCryptoProvider, Kek, KeyWrapAlgorithm};
use crate::crypto::secret::{SecretSlice, ToInsecure};
use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::utils::CertificateExt;
use crate::crypto::x509::{KeyAgreement, KeyPurposes, PeerCertificate};
use crate::der::asn1::{GeneralizedTime, Null, ObjectIdentifier, OctetString, SetOfVec};
use crate::der::oid::AssociatedOid;
use crate::der::{Any, Decode, Encode, EncodeValue, Tagged};
use crate::marker::MaybeSendFuture;
use crate::oids::{
	AES_128_GCM, AES_128_WRAP, AES_192_WRAP, AES_256_GCM, AES_256_WRAP, ATTR_CONTENT_TYPE, CURVE_SECP256K1, DATA,
	DHKEM_SECP256K1, HKDF_SHA3_256, SIGNED_DATA,
};
use crate::runtime::rt;
use crate::spki::AlgorithmIdentifierOwned;
use crate::testing::fixtures::{flip_last, TestAgreement, TestAlgorithm};
use crate::testing::vectors::rfc3394::{
	KeyWrapVector, RFC_3394_4_1, RFC_3394_4_2, RFC_3394_4_3, RFC_3394_4_4, RFC_3394_4_5, RFC_3394_4_6,
};
use crate::testing::{unhex, EnvelopeRecipient, SeededStream, TestCertificate, TestKey, TestResult};
use crate::x509::attr::{Attribute, Attributes};
use crate::x509::ext::pkix::{KeyUsage, KeyUsages, SubjectKeyIdentifier};
use crate::x509::Certificate;
use crate::zeroize::Zeroizing;

/// The house provider, whose algorithms every seal here runs: AES-256-GCM,
/// HKDF-SHA3-256, AES-256 key wrap, and DHKEM(secp256k1, HKDF-SHA256).
type House = DefaultCryptoProvider;

/// The KEM of the house provider.
type HouseKem = DhKemSecp256k1;

/// A key-agreement identity under the house KEM.
type HouseIdentity = KeyAgreementIdentity<HouseKem>;

/// The function under test of an RFC 3394 row: a wrap or an unwrap of the
/// vector under its KEK.
type KeyWrapOf = fn(&KeyWrapVector) -> Result<Vec<u8>, KeyError>;

/// The content every test seals.
const CONTENT: &[u8] = b"authenticated envelope content";

/// The key-encryption key of the `Kek` tests.
static KEK: [u8; 32] = [0x11; 32];

/// The identifier that names [`KEK`].
const KEY_IDENTIFIER: &[u8] = b"tb/test/kek/v1";

/// The purpose label of the `Kem` tests.
const UKM_LABEL: &[u8] = b"tb/test/ukm/v1";

/// The seed of the key of the recipient that the `Kem` tests seal to.
const RECIPIENT: u8 = 0x21;

/// The seed of the key of a recipient other than [`RECIPIENT`].
const OTHER_RECIPIENT: u8 = 0x22;

/// `id-alg-hkdf-with-sha256` (RFC 8619), a KDF of another profile.
const HKDF_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.28");

/// The secret key of the recipient of draft-wahby-cfrg-hpke-kem-secp256k1-01
/// B.1.1, which the KEM known answer seals to.
const PUBLISHED_RECIPIENT_SECRET: &str = "a795c287c132154a8b96dc81dc8b4e2f02bbbad78dab0567b59db1d1540751f6";

/// [`KEK`] as the key-encryption key of the house wrap.
fn house_kek() -> Kek<'static, Aes256Wrap> {
	let kek = Kek::try_from(KEK.as_slice());
	kek.expect("the test KEK is the key size of AES-256 key wrap")
}

/// The holder of [`KEK`], as the recipient of a seal.
fn kek_recipient_of() -> Recipient<'static, House> {
	Recipient::Kek { kek: house_kek(), key_identifier: KEY_IDENTIFIER }
}

/// [`CONTENT`] sealed as `id-data` to `recipient`.
fn sealed(recipient: Recipient<'_, House>) -> AuthEnvelopedData {
	let sealed = AuthEnvelopedData::seal::<House>(recipient, DATA, CONTENT, [], None);
	sealed.expect("the content seals")
}

/// [`CONTENT`] sealed as `id-data` to the holder of [`KEK`].
fn kek_sealed() -> AuthEnvelopedData {
	sealed(kek_recipient_of())
}

/// [`CONTENT`] sealed as `id-data` to the holder of [`KEK`], under the draws
/// of `SeededStream(0)`: a content key of `0x01` and a nonce of `0x02`.
fn kek_sealed_from_seed() -> AuthEnvelopedData {
	let mut stream = SeededStream(0);
	let sealed = AuthEnvelopedData::seal::<House>(kek_recipient_of(), DATA, CONTENT, [], Some(&mut stream));
	sealed.expect("the content seals")
}

/// The opener of the holder of [`KEK`].
fn kek_opener() -> Opener<'static, House> {
	Opener::Kek { kek: house_kek(), key_identifier: KEY_IDENTIFIER }
}

/// The key-agreement identity of `key` under `certificate`.
fn agreement_identity(certificate: Certificate, key: &Secp256k1SigningKey) -> HouseIdentity {
	let identity = HouseIdentity::new(certificate, TestKey::provider(key.to_owned()));
	identity.expect("the test key matches its certificate")
}

/// The key-agreement identity of [`TestKey::fixed`] `seed` under a
/// certificate that carries its key identifier.
fn kem_identity(seed: u8) -> HouseIdentity {
	TestAgreement::identity(&TestKey::fixed(seed))
}

/// The key-agreement identity of the published recipient key.
fn published_identity() -> HouseIdentity {
	let secret = unhex(PUBLISHED_RECIPIENT_SECRET);
	let key = Secp256k1SigningKey::from_slice(&secret).expect("the vector holds a scalar");
	TestAgreement::identity(&key)
}

/// [`CONTENT`] sealed as `id-data` to `recipient`, with a `ukm` led by
/// [`UKM_LABEL`].
fn kem_sealed_to(recipient: &KemRecipient<HouseKem>) -> AuthEnvelopedData {
	sealed(Recipient::Kem { recipient, ukm_label: UKM_LABEL })
}

/// [`CONTENT`] sealed as `id-data` to the identity of [`RECIPIENT`], with a
/// `ukm` led by [`UKM_LABEL`].
fn kem_sealed() -> AuthEnvelopedData {
	kem_sealed_to(kem_identity(RECIPIENT).recipient())
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
fn kem_opener(identity: &dyn KemKeyHolder<HouseKem>) -> Opener<'_, House> {
	Opener::Kem { identity, ukm_label: UKM_LABEL }
}

/// Open `envelope` as it encodes, as a reader that received its DER does.
/// The open runs no timer and no socket, so it blocks in place.
fn opened(
	envelope: AuthEnvelopedData,
	opener: &Opener<'_, House>,
	content_type: ObjectIdentifier,
) -> Result<SecretSlice<u8>, EnvelopeError> {
	let arrived = envelope.to_der()?;
	rt::block_on(envelope.open::<House>(&arrived, opener, content_type))
}

/// The refusal of `envelope`, opened as `id-data` by the holder of [`KEK`].
fn kek_refusal(envelope: AuthEnvelopedData) -> Option<EnvelopeError> {
	opened(envelope, &kek_opener(), DATA).err()
}

/// The refusal of a KEK seal whose `KEKRecipientInfo` `mutate` changed, by
/// the holder of [`KEK`].
fn kek_recipient_refusal(mutate: fn(KekRecipientInfo) -> KekRecipientInfo) -> Option<EnvelopeError> {
	let envelope = kek_sealed();
	let kek = mutate(envelope.kek_recipient());
	kek_refusal(envelope.with_kek_recipient(&kek))
}

/// The refusal of a KEM seal under `ukm_label` to the identity of
/// [`RECIPIENT`], whose `KEMRecipientInfo` `mutate` changed, by the opener of
/// that identity.
fn kem_refusal_under(ukm_label: &[u8], mutate: fn(KemRecipientInfo) -> KemRecipientInfo) -> Option<EnvelopeError> {
	let identity = kem_identity(RECIPIENT);
	let envelope = sealed(Recipient::Kem { recipient: identity.recipient(), ukm_label });
	let kem = mutate(envelope.kem_recipient());
	opened(envelope.with_kem_recipient(&kem), &kem_opener(&identity), DATA).err()
}

/// [`kem_refusal_under`] the label of the opener, [`UKM_LABEL`].
fn kem_refusal(mutate: fn(KemRecipientInfo) -> KemRecipientInfo) -> Option<EnvelopeError> {
	kem_refusal_under(UKM_LABEL, mutate)
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

/// `envelope` with its content-encryption algorithm renamed `oid`.
fn with_content_algorithm(mut envelope: AuthEnvelopedData, oid: ObjectIdentifier) -> AuthEnvelopedData {
	envelope.auth_encrypted_content_info.content_enc_alg.oid = oid;
	envelope
}

/// `envelope` with `aes-ICVlen` `icv_len` in its `GCMParameters`.
fn with_icv_len(envelope: AuthEnvelopedData, icv_len: u8) -> AuthEnvelopedData {
	let parameters = GcmParameters { aes_icv_len: icv_len, ..gcm_parameters(&envelope) };
	with_parameters(envelope, &parameters)
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

/// A seal of `SignedData` whose `eContentType` is rewritten to `id-data`.
fn signed_data_relabelled_as_data() -> AuthEnvelopedData {
	let sealed = AuthEnvelopedData::seal::<House>(kek_recipient_of(), SIGNED_DATA, CONTENT, [], None);
	let mut envelope = sealed.expect("the content seals");
	envelope.auth_encrypted_content_info.content_type = DATA;
	envelope
}

/// [`kek_sealed`] with a second KEK recipient beside its first, which names
/// another key.
fn with_two_kek_recipients() -> AuthEnvelopedData {
	let envelope = kek_sealed();
	let first = envelope.kek_recipient();
	let other = OctetString::new(b"tb/test/other/v1").expect("an identifier fits");
	let kek_id = KekIdentifier { kek_identifier: other, ..first.kek_id.clone() };
	let second = KekRecipientInfo { kek_id, ..first.clone() };

	envelope.with_recipients([RecipientInfo::Kekri(first), RecipientInfo::Kekri(second)])
}

/// The refusal of a KEM seal to [`RECIPIENT`] whose `KEMRecipientInfo`
/// travels under `id-data` as its `oriType` in place of `id-ori-kem`.
fn ori_of_another_type_refusal() -> Option<EnvelopeError> {
	let identity = kem_identity(RECIPIENT);
	let envelope = kem_sealed_to(identity.recipient());
	let ori_value = Any::encode_from(&envelope.kem_recipient()).expect("a KEMRecipientInfo encodes");
	let other = OtherRecipientInfo { ori_type: DATA, ori_value };
	let envelope = envelope.with_recipients([RecipientInfo::Ori(other)]);

	opened(envelope, &kem_opener(&identity), DATA).err()
}

/// `kek` with a date in its `KEKIdentifier`.
fn dated(kek: KekRecipientInfo) -> KekRecipientInfo {
	let date = GeneralizedTime::from_unix_duration(core::time::Duration::from_secs(0));
	let date = Some(date.expect("the epoch is a GeneralizedTime"));
	KekRecipientInfo { kek_id: KekIdentifier { date, ..kek.kek_id.clone() }, ..kek }
}

/// The `ukm` octets of `kem`.
fn ukm_of(kem: &KemRecipientInfo) -> &[u8] {
	let ukm = kem.ukm.as_ref().expect("the recipient carries a ukm");
	ukm.as_bytes()
}

/// `kem` with the last octet of its `ukm` flipped.
fn with_flipped_ukm(kem: KemRecipientInfo) -> KemRecipientInfo {
	let flipped = flip_last(ukm_of(&kem));
	KemRecipientInfo { ukm: Some(OctetString::new(flipped).expect("it fits")), ..kem }
}

/// `kem` with one more octet after its `ukm`.
fn with_longer_ukm(kem: KemRecipientInfo) -> KemRecipientInfo {
	let longer = [ukm_of(&kem), &[0x00]].concat();
	KemRecipientInfo { ukm: Some(OctetString::new(longer).expect("it fits")), ..kem }
}

/// `kem` with a NULL as the parameters of its KEM.
fn with_kem_parameters(kem: KemRecipientInfo) -> KemRecipientInfo {
	let null = Any::encode_from(&Null).expect("NULL encodes");
	let kem_algorithm = AlgorithmIdentifierOwned { oid: DHKEM_SECP256K1, parameters: Some(null) };
	KemRecipientInfo { kem: kem_algorithm, ..kem }
}

/// The test certificate of `key` with its `keyUsage` replaced by
/// `key_usage`, or removed when it is `None`.
fn certificate_with_key_usage(key: &Secp256k1SigningKey, key_usage: Option<KeyUsage>) -> Certificate {
	let certificate = TestCertificate::without_extension(TestCertificate::self_signed(key), KeyUsage::OID);
	match key_usage {
		Some(key_usage) => TestCertificate::with_key_usage(certificate, key_usage),
		None => certificate,
	}
}

/// The `keyUsage` of a CMS server: it signs, and a KEM encapsulates to it.
fn server_key_usage() -> Option<KeyUsage> {
	Some(KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyAgreement))
}

/// A `keyUsage` that signs and lacks `keyAgreement`.
fn signing_key_usage() -> Option<KeyUsage> {
	Some(KeyUsage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation))
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
///
/// The house provider runs inside it for every agreement. It exists because
/// no real provider reports the peer keys that crossed its boundary, and a
/// test asserts on those keys.
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
		Self {
			kemct: kem.kemct.as_bytes().to_vec(),
			ukm: ukm_of(&kem).to_vec(),
			encrypted_key: kem.encrypted_key.as_bytes().to_vec(),
			ciphertext: ciphertext(envelope),
			mac: envelope.mac.as_bytes().to_vec(),
		}
	}
}

/// An `AuthEnvelopedData` is version 0 (RFC 5083 §2.1).
#[test]
fn an_envelope_is_version_0() {
	assert_eq!(kek_sealed().version, CmsVersion::V0);
}

/// The content encrypts under AES-256-GCM.
#[test]
fn the_content_encryption_algorithm_is_aes_256_gcm() {
	let envelope = kek_sealed();
	assert_eq!(envelope.auth_encrypted_content_info.content_enc_alg.oid, AES_256_GCM);
}

// A KEK seal holds the lengths RFC 5084 §3.2 gives AES-GCM: a 12-octet nonce
// and `aes-ICVlen` 16 in its `GCMParameters`, and a 16-octet tag in `mac`.
// The tag sits in `mac`, so the encrypted content is as long as the content.
crate::tb_cases! {
	fn a_kek_seal_takes_its_lengths((length, expected): (usize, usize)) {
		assert_eq!(length, expected);
	}
	cases {
		nonce_of_12_octets => (gcm_parameters(&kek_sealed()).aes_nonce.as_bytes().len(), 12),
		tag_length_of_16_octets => (usize::from(gcm_parameters(&kek_sealed()).aes_icv_len), 16),
		mac_of_16_octets => (kek_sealed().mac.as_bytes().len(), 16),
		encrypted_content_as_long_as_the_content => (ciphertext(&kek_sealed()).len(), CONTENT.len()),
	}
}

// DER writes `aes-ICVlen` 16, because 16 is not the default 12, and omits
// `aes-ICVlen` 12, the default.
crate::tb_cases! {
	fn the_gcm_parameters_encode((icv_len, der): (u8, &str)) -> TestResult {
		let parameters = GcmParameters { aes_nonce: OctetString::new([0x07u8; 12])?, aes_icv_len: icv_len };
		let encoded = parameters.to_der()?;
		assert_eq!(encoded, unhex(der));
		Ok(())
	}
	cases {
		a_16_octet_tag_length => (16, "3011040c070707070707070707070707020110"),
		without_the_default_tag_length => (12, "300e040c070707070707070707070707"),
	}
}

/// The content type sits in the authenticated attributes.
#[test]
fn the_content_type_sits_in_the_authenticated_attributes() {
	assert_eq!(content_type_values(&kek_sealed()), vec![DATA]);
}

/// A reader of one field of a seal, as octets.
type FieldOf = fn(&AuthEnvelopedData) -> Vec<u8>;

// Two seals of one content under one KEK draw two content keys and two
// nonces, so they differ in their `encryptedKey`, their ciphertext, and their
// nonce. AES key wrap is deterministic, so two equal content keys would wrap
// to two equal `encryptedKey` values.
crate::tb_cases! {
	fn two_seals_of_one_content_differ_in(field: FieldOf) {
		let first = kek_sealed();
		let second = kek_sealed();
		assert_ne!(field(&first), field(&second));
	}
	cases {
		encrypted_key => |envelope| envelope.kek_recipient().encrypted_key.as_bytes().to_vec(),
		ciphertext => ciphertext,
		nonce => |envelope| gcm_parameters(envelope).aes_nonce.as_bytes().to_vec(),
	}
}

/// The associated data is the DER of the authenticated attributes under the
/// universal `SET OF` tag `0x31`, not their `[1]` tag (RFC 5083 §2.2).
///
/// The expected bytes come from an independent DER encoder in Python.
#[test]
fn the_associated_data_is_the_attributes_under_the_set_of_tag() -> TestResult {
	let sealed = kek_sealed();
	let encoded = sealed.to_der()?;
	let arrived = ArrivedEnvelope::read(&encoded)?;

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
fn a_kek_seal_matches_its_known_answer() -> TestResult {
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

/// A KEK seal opens under its key to its content.
#[test]
fn a_kek_seal_opens_under_its_key() -> TestResult {
	let content = opened(kek_sealed(), &kek_opener(), DATA)?;
	assert_eq!(content.to_insecure().as_slice(), CONTENT);
	Ok(())
}

/// A KEM seal opens under the identity of its certificate to its content.
#[test]
fn a_kem_seal_opens_under_the_identity_of_its_certificate() -> TestResult {
	let identity = kem_identity(RECIPIENT);
	let content = opened(kem_sealed_to(identity.recipient()), &kem_opener(&identity), DATA)?;
	assert_eq!(content.to_insecure().as_slice(), CONTENT);
	Ok(())
}

/// The `KEMRecipientInfo` names the profile: version 0, DHKEM over
/// secp256k1, HKDF-SHA3-256, a 32-octet KEK, and AES-256 key wrap, each
/// algorithm with parameters absent.
#[test]
fn a_kem_recipient_names_the_profile() {
	let kem = kem_sealed().kem_recipient();
	let expected = KemRecipientInfo {
		version: CmsVersion::V0,
		kem: TestAlgorithm::of(DHKEM_SECP256K1),
		kdf: TestAlgorithm::of(HKDF_SHA3_256),
		kek_length: 32,
		wrap: TestAlgorithm::of(AES_256_WRAP),
		..kem.clone()
	};
	assert_eq!(kem, expected);
}

/// The `rid` is the recipient certificate's `subjectKeyIdentifier`.
#[test]
fn a_kem_recipient_names_its_certificate_by_its_key_identifier() -> TestResult {
	let identity = kem_identity(RECIPIENT);
	let kem = kem_sealed_to(identity.recipient()).kem_recipient();
	let key_identifier = identity.certificate().extension::<SubjectKeyIdentifier>()?;
	let key_identifier = key_identifier.ok_or("the certificate carries a key identifier")?;
	assert_eq!(kem.rid, RecipientIdentifier::SubjectKeyIdentifier(key_identifier));
	Ok(())
}

/// The `kemct` is DHKEM's `enc`, the 65-octet uncompressed point.
#[test]
fn the_kem_ciphertext_is_the_uncompressed_encapsulated_key() {
	let kem = kem_sealed().kem_recipient();
	let kemct = kem.kemct.as_bytes();
	assert_eq!(kemct.len(), 65);
	assert_eq!(kemct.first(), Some(&0x04));
}

/// The `ukm` is the purpose label, then 32 random octets.
#[test]
fn the_ukm_is_the_purpose_label_and_32_random_octets() {
	let kem = kem_sealed().kem_recipient();
	let (label, random) = ukm_of(&kem).split_at(UKM_LABEL.len());
	assert_eq!((label, random.len()), (UKM_LABEL, 32));
}

/// The `KEKRecipientInfo` is version 4 (RFC 5652 §6.2.3).
#[test]
fn a_kek_recipient_is_version_4() {
	assert_eq!(kek_sealed().kek_recipient().version, CmsVersion::V4);
}

/// The `KEKRecipientInfo` names its key by the identifier of the holder.
#[test]
fn a_kek_recipient_names_its_key_by_its_identifier() {
	let kek = kek_sealed().kek_recipient();
	assert_eq!(kek.kek_id.kek_identifier.as_bytes(), KEY_IDENTIFIER);
}

/// The `KEKRecipientInfo` wraps under AES-256 key wrap with parameters
/// absent (RFC 3565 §2.3.2).
#[test]
fn a_kek_recipient_wraps_under_aes_256_key_wrap() {
	assert_eq!(kek_sealed().kek_recipient().key_enc_alg, TestAlgorithm::of(AES_256_WRAP));
}

/// The `CMSORIforKEMOtherInfo` of the known answer below.
fn known_other_info() -> CmsOriForKemOtherInfo {
	let ukm = [b"tb/handshake/opening/ukm/v1".as_slice(), &[0x07u8; 32]].concat();
	let ukm = OctetString::new(ukm).expect("the ukm is an OCTET STRING");
	CmsOriForKemOtherInfo { wrap: TestAlgorithm::of(AES_256_WRAP), kek_length: 32, ukm: Some(ukm) }
}

/// The info encodes as RFC 9629 §5 writes it, with the `ukm` under an
/// explicit `[0]`.
///
/// The expected bytes come from an independent DER encoder in Python.
#[test]
fn the_kem_other_info_encodes_as_rfc_9629_writes_it() -> TestResult {
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
fn the_kem_kek_matches_its_known_answer() -> TestResult {
	let kek = known_other_info().derive_kek::<HkdfSha3_256>(&[0x5au8; 32])?;
	let expected = unhex("4a68f649a3e6c8d69006489c7f8feb66d581355fd186255227f3826d9639cc1c");
	assert_eq!(kek.to_vec(), expected);
	Ok(())
}

/// The wrap under `W` of the key data of `vector`, under the KEK of
/// `vector`.
fn wrapped<W: KeyWrapAlgorithm>(vector: &KeyWrapVector) -> Result<Vec<u8>, KeyError> {
	let kek = unhex(vector.kek);
	let kek = Kek::<W>::try_from(kek.as_slice()).expect("a vector KEK is the key size of its wrap");
	W::wrap(&kek, &unhex(vector.key_data))
}

/// The unwrap under `W` of the ciphertext of `vector`, under the KEK of
/// `vector`.
fn unwrapped<W: KeyWrapAlgorithm>(vector: &KeyWrapVector) -> Result<Vec<u8>, KeyError> {
	let kek = unhex(vector.kek);
	let kek = Kek::<W>::try_from(kek.as_slice()).expect("a vector KEK is the key size of its wrap");
	let unwrapped = W::unwrap(&kek, &unhex(vector.ciphertext))?;
	Ok(unwrapped.to_vec())
}

/// The unwrap under AES-256 key wrap of the ciphertext of `vector` onto a
/// buffer of `len` octets.
fn unwrapped_into(vector: &KeyWrapVector, len: usize) -> Result<Vec<u8>, KeyError> {
	let kek = unhex(vector.kek);
	let kek = Kek::<Aes256Wrap>::try_from(kek.as_slice()).expect("a vector KEK is the key size of its wrap");
	let mut key = Zeroizing::new(vec![0u8; len]);
	Aes256Wrap::unwrap_into(&kek, &unhex(vector.ciphertext), &mut key)?;
	Ok(key.to_vec())
}

// Each AES key wrap of RFC 3394 §4 wraps its key data to the published
// ciphertext under its KEK.
crate::tb_cases! {
	fn a_key_wrap_matches_rfc_3394((wrap, vector): (KeyWrapOf, KeyWrapVector)) -> TestResult {
		let wrapped = wrap(&vector)?;
		assert_eq!(wrapped, unhex(vector.ciphertext));
		Ok(())
	}
	cases {
		aes_128_4_1 => (wrapped::<Aes128Wrap>, RFC_3394_4_1),
		aes_192_4_2 => (wrapped::<Aes192Wrap>, RFC_3394_4_2),
		aes_256_4_3 => (wrapped::<Aes256Wrap>, RFC_3394_4_3),
		aes_192_4_4 => (wrapped::<Aes192Wrap>, RFC_3394_4_4),
		aes_256_4_5 => (wrapped::<Aes256Wrap>, RFC_3394_4_5),
		aes_256_4_6 => (wrapped::<Aes256Wrap>, RFC_3394_4_6),
	}
}

// Each AES key unwrap of RFC 3394 §4 unwraps the published ciphertext to its
// key data under its KEK.
crate::tb_cases! {
	fn a_key_unwrap_matches_rfc_3394((unwrap, vector): (KeyWrapOf, KeyWrapVector)) -> TestResult {
		let unwrapped = unwrap(&vector)?;
		assert_eq!(unwrapped, unhex(vector.key_data));
		Ok(())
	}
	cases {
		aes_128_4_1 => (unwrapped::<Aes128Wrap>, RFC_3394_4_1),
		aes_192_4_2 => (unwrapped::<Aes192Wrap>, RFC_3394_4_2),
		aes_256_4_3 => (unwrapped::<Aes256Wrap>, RFC_3394_4_3),
		aes_192_4_4 => (unwrapped::<Aes192Wrap>, RFC_3394_4_4),
		aes_256_4_5 => (unwrapped::<Aes256Wrap>, RFC_3394_4_5),
		aes_256_4_6 => (unwrapped::<Aes256Wrap>, RFC_3394_4_6),
	}
}

/// The house wrap unwraps onto a caller's buffer of the key's size: RFC 3394
/// §4.3, 128 bits of key data under a 256-bit KEK.
#[test]
fn aes_256_key_unwrap_into_matches_rfc_3394_4_3() -> TestResult {
	let key = unwrapped_into(&RFC_3394_4_3, 16)?;
	assert_eq!(key, unhex(RFC_3394_4_3.key_data));
	Ok(())
}

/// The house wrap refuses a buffer of another size than the wrapped key, and
/// names the 16 octets the key takes.
#[test]
fn the_house_unwrap_into_refuses_a_buffer_of_another_size() {
	let refused = unwrapped_into(&RFC_3394_4_3, 32);
	assert!(matches!(refused, Err(KeyError::WrapLength(sizes)) if (sizes.received, sizes.expected) == (32, 16)));
}

// Each AES key wrap names its `id-aes*-wrap` identifier (RFC 3565 §2.3.2).
crate::tb_cases! {
	fn a_key_wrap_names_its_identifier((oid, expected): (ObjectIdentifier, ObjectIdentifier)) {
		assert_eq!(oid, expected);
	}
	cases {
		aes_128 => (<Aes128Wrap as AssociatedOid>::OID, AES_128_WRAP),
		aes_192 => (<Aes192Wrap as AssociatedOid>::OID, AES_192_WRAP),
		aes_256 => (<Aes256Wrap as AssociatedOid>::OID, AES_256_WRAP),
	}
}

// RFC 3394 §2 wraps two or more 64-bit blocks, so a key of one block is
// refused, and an input of two blocks, which would unwrap to a key of one
// block, is refused too.
crate::tb_cases! {
	fn a_wrap_below_two_blocks_is_refused(refused: Option<KeyError>) {
		assert!(matches!(refused, Some(KeyError::WrapLength(_))));
	}
	cases {
		wrap_of_one_block => Aes256Wrap::wrap(&house_kek(), &[0x00; 8]).err(),
		unwrap_of_two_blocks => Aes256Wrap::unwrap(&house_kek(), &[0x00; 16]).err(),
	}
}

// A key one octet short of, or one octet past, the 32 octets of AES-256 key
// wrap is no KEK of that wrap, and the refusal names both sizes.
crate::tb_cases! {
	fn a_kek_of_another_length_is_refused(len: usize) {
		let key = vec![0x11u8; len];

		let refused = Kek::<Aes256Wrap>::try_from(key.as_slice());
		assert!(matches!(refused, Err(KeyError::KekLength(sizes)) if (sizes.received, sizes.expected) == (len, 32)));
	}
	cases {
		one_octet_short => 31,
		one_octet_long => 33,
	}
}

/// A `Kek` recipient wraps the content key under the key it holds, as RFC
/// 3394 §4.6 wraps 256 bits of key data under a 256-bit KEK.
#[test]
fn a_kek_recipient_wraps_as_rfc_3394_4_6() -> TestResult {
	let kek = unhex(RFC_3394_4_6.kek);
	let recipient: Recipient<'_, House> =
		Recipient::Kek { kek: Kek::try_from(kek.as_slice())?, key_identifier: KEY_IDENTIFIER };

	let info = recipient.wrap(&unhex(RFC_3394_4_6.key_data), &mut SeededStream(0))?;
	let expected = unhex(RFC_3394_4_6.ciphertext);
	assert!(matches!(info, RecipientInfo::Kekri(kek) if kek.encrypted_key.as_bytes() == expected.as_slice()));
	Ok(())
}

/// A `Kek` opener unwraps the content key under the key it holds, as RFC
/// 3394 §4.6 unwraps 256 bits of key data under a 256-bit KEK.
#[test]
fn a_kek_opener_unwraps_rfc_3394_4_6() -> TestResult {
	let wrap = kek::wrap_algorithm::<Aes256Wrap>();
	let info = kek::kek_info(KEY_IDENTIFIER, wrap, unhex(RFC_3394_4_6.ciphertext))?;
	let infos = RecipientInfos(SetOfVec::try_from(vec![info])?);
	let kek = unhex(RFC_3394_4_6.kek);

	let opener: Opener<'_, House> = Opener::Kek { kek: Kek::try_from(kek.as_slice())?, key_identifier: KEY_IDENTIFIER };
	let mut key = Zeroizing::new([0u8; 32]);
	rt::block_on(opener.unwrap(&infos, &mut *key))?;
	assert_eq!(key.as_slice(), unhex(RFC_3394_4_6.key_data).as_slice());
	Ok(())
}

/// A seal refuses a caller attribute that names a content type, because the
/// seal writes its own.
#[test]
fn a_seal_that_carries_its_own_content_type_attribute_is_refused() {
	let content_type = content_type_attribute(&[SIGNED_DATA]);
	let refused = AuthEnvelopedData::seal::<House>(kek_recipient_of(), DATA, CONTENT, [content_type], None);
	assert!(matches!(refused, Err(EnvelopeError::ContentTypeAttribute)));
}

/// An envelope whose authenticated attributes arrive out of DER order is
/// refused, though it decodes and its tag would pass over the sorted set
/// (RFC 5083 §2.1).
#[test]
fn authenticated_attributes_out_of_der_order_are_refused() -> TestResult {
	let sealed = AuthEnvelopedData::seal::<House>(kek_recipient_of(), DATA, CONTENT, [marker_attribute()], None)?;
	let arrived = with_misordered_auth_attrs(&sealed);
	let envelope = AuthEnvelopedData::from_der(&arrived)?;

	let refused = rt::block_on(envelope.open::<House>(&arrived, &kek_opener(), DATA));
	assert!(matches!(refused, Err(EnvelopeError::AuthAttributesNotDer)));
	Ok(())
}

/// An envelope of another version than 0 is refused.
#[test]
fn an_envelope_of_another_version_is_refused() {
	let refused = kek_refusal(AuthEnvelopedData { version: CmsVersion::V2, ..kek_sealed() });
	assert!(matches!(refused, Some(EnvelopeError::Version(_))));
}

// An envelope is refused for a content-encryption algorithm other than
// AES-256-GCM, or for a bare OCTET STRING nonce in place of
// `GCMParameters`.
crate::tb_cases! {
	fn an_envelope_is_refused_for_its_content_encryption_algorithm(refused: Option<EnvelopeError>) {
		assert!(matches!(refused, Some(EnvelopeError::ContentEncryptionAlgorithm)));
	}
	cases {
		aes_128_gcm => kek_refusal(with_content_algorithm(kek_sealed(), AES_128_GCM)),
		bare_nonce => kek_refusal(with_parameters(kek_sealed(), &gcm_parameters(&kek_sealed()).aes_nonce)),
	}
}

// An envelope is refused for an `aes-ICVlen` other than 16, or for a `mac`
// of another length than 16.
crate::tb_cases! {
	fn an_envelope_is_refused_for_its_tag_length(refused: Option<EnvelopeError>) -> TestResult {
		assert!(matches!(refused, Some(EnvelopeError::TagLength(_))));
		Ok(())
	}
	cases {
		icv_length_12 => kek_refusal(with_icv_len(kek_sealed(), 12)),
		mac_of_12_octets => kek_refusal(AuthEnvelopedData { mac: OctetString::new([0x00u8; 12])?, ..kek_sealed() }),
	}
}

// An envelope carries one content-type attribute of one value, so it is
// refused with no such attribute, with two, or with one of two values.
crate::tb_cases! {
	fn an_envelope_is_refused_for_its_content_type_attribute(refused: Option<EnvelopeError>) {
		assert!(matches!(refused, Some(EnvelopeError::ContentTypeAttribute)));
	}
	cases {
		absent => kek_refusal(with_auth_attrs(kek_sealed(), vec![marker_attribute()])),
		two_attributes => kek_refusal(with_auth_attrs(
			kek_sealed(),
			vec![content_type_attribute(&[DATA]), content_type_attribute(&[SIGNED_DATA])],
		)),
		two_values => kek_refusal(with_auth_attrs(kek_sealed(), vec![content_type_attribute(&[DATA, SIGNED_DATA])])),
	}
}

// An envelope is refused for a content type other than the expected one.
// The tag covers the content-type attribute and not `eContentType`, so a
// seal of `SignedData` whose `eContentType` is rewritten to `id-data`,
// opened as `id-data`, is refused on its content-type attribute (RFC 5083
// §2.1).
crate::tb_cases! {
	fn an_envelope_is_refused_for_its_content_type(refused: Option<EnvelopeError>) {
		assert!(matches!(refused, Some(EnvelopeError::ContentType(_))));
	}
	cases {
		another_expected_type => opened(kek_sealed(), &kek_opener(), SIGNED_DATA).err(),
		rewritten_econtent_type => kek_refusal(signed_data_relabelled_as_data()),
	}
}

// An envelope names one recipient of the opener's kind, so it is refused
// for two recipients, for a KEM seal opened as a KEK seal and the reverse,
// and for a valid `KEMRecipientInfo` under `id-data` as its `oriType` in
// place of `id-ori-kem` (RFC 9629 §3).
crate::tb_cases! {
	fn an_envelope_is_refused_for_its_recipient_kind(refused: Option<EnvelopeError>) {
		assert!(matches!(refused, Some(EnvelopeError::RecipientKind)));
	}
	cases {
		two_recipients => kek_refusal(with_two_kek_recipients()),
		kem_seal_as_kek => kek_refusal(kem_sealed()),
		kek_seal_as_kem => opened(kek_sealed(), &kem_opener(&kem_identity(RECIPIENT)), DATA).err(),
		ori_of_another_type => ori_of_another_type_refusal(),
	}
}

// A `KEKRecipientInfo` is version 4 (RFC 5652 §6.2.3), and a
// `KEMRecipientInfo` is version 0 (RFC 9629 §3), so another version of
// either is refused.
crate::tb_cases! {
	fn an_envelope_is_refused_for_its_recipient_version(refused: Option<EnvelopeError>) {
		assert!(matches!(refused, Some(EnvelopeError::RecipientVersion(_))));
	}
	cases {
		kek_recipient => kek_recipient_refusal(|kek| KekRecipientInfo { version: CmsVersion::V2, ..kek }),
		kem_recipient => kem_refusal(|kem| KemRecipientInfo { version: CmsVersion::V2, ..kem }),
	}
}

// A recipient is refused for an algorithm of another profile: a KEK wrap
// or a KEM wrap other than AES-256 key wrap, another KEM, a KDF of
// HKDF-SHA256 (RFC 8619) in place of HKDF-SHA3-256, or a KEM with
// parameters, which must be absent.
crate::tb_cases! {
	fn an_envelope_is_refused_for_its_recipient_algorithm(refused: Option<EnvelopeError>) {
		assert!(matches!(refused, Some(EnvelopeError::RecipientAlgorithm)));
	}
	cases {
		kek_wrap => kek_recipient_refusal(|kek| {
			KekRecipientInfo { key_enc_alg: TestAlgorithm::of(AES_128_WRAP), ..kek }
		}),
		kem_wrap => kem_refusal(|kem| KemRecipientInfo { wrap: TestAlgorithm::of(AES_128_WRAP), ..kem }),
		kem => kem_refusal(|kem| {
			let unknown = TestAlgorithm::of(ObjectIdentifier::new_unwrap("1.2.3.4.5"));
			KemRecipientInfo { kem: unknown, ..kem }
		}),
		kdf => kem_refusal(|kem| KemRecipientInfo { kdf: TestAlgorithm::of(HKDF_SHA256), ..kem }),
		kem_parameters => kem_refusal(with_kem_parameters),
	}
}

// A KEK recipient is refused for a `KEKIdentifier` other than the opener's:
// a KEK seal of another purpose names another key, and an identifier with a
// date or with another key attribute names no key the opener holds.
crate::tb_cases! {
	fn an_envelope_is_refused_for_its_key_identifier(refused: Option<EnvelopeError>) {
		assert!(matches!(refused, Some(EnvelopeError::KeyIdentifier)));
	}
	cases {
		another_purpose => {
			opened(kek_sealed(), &Opener::Kek { kek: house_kek(), key_identifier: b"tb/test/other/v1" }, DATA).err()
		},
		dated => kek_recipient_refusal(dated),
		other_key_attribute => kek_recipient_refusal(|kek| KekRecipientInfo {
			kek_id: KekIdentifier { other: Some(marker_attribute()), ..kek.kek_id.clone() },
			..kek
		}),
	}
}

// A KEM seal under another purpose's `ukm` label is refused, though the key
// it encapsulated to is the opener's, and a `ukm` of the opener's label and
// one octet more than 32 after it is refused before the agreement runs.
crate::tb_cases! {
	fn an_envelope_is_refused_for_its_ukm(refused: Option<EnvelopeError>) {
		assert!(matches!(refused, Some(EnvelopeError::Ukm)));
	}
	cases {
		another_label => kem_refusal_under(b"tb/test/other/v1", core::convert::identity),
		one_octet_longer => kem_refusal(with_longer_ukm),
	}
}

/// The `ukm` enters the KDF input of the KEK, so a changed random octet,
/// under the opener's label, derives another KEK, and the content key fails
/// to unwrap (RFC 9629 §5).
#[test]
fn a_ukm_with_another_random_fails_the_key_unwrap() {
	let refused = kem_refusal(with_flipped_ukm);
	assert!(matches!(refused, Some(EnvelopeError::KeyUnwrap)));
}

/// Two KEK recipients of one length, built from the recipient of
/// [`kek_sealed_from_seed`], which two orders sort apart:
///
/// - In the order of X.690 § 11.6, the first comes first, at its identifier.
/// - In the order of `der` 0.7, the first comes second. It reads each
///   encoding as a SEQUENCE OF INTEGER (`ValueOrd for RecipientInfo`, `cms`
///   0.2.3), whose length grows with each octet of `0x80` or above, and the
///   wrapped key of the first holds more of them.
fn recipients_of_two_orders() -> [RecipientInfo; 2] {
	let sealed = kek_sealed_from_seed().kek_recipient();
	let wrapped_len = sealed.encrypted_key.as_bytes().len();
	let named = |identifier: &[u8]| {
		let kek_identifier = OctetString::new(identifier).expect("a test identifier fits");
		KekIdentifier { kek_identifier, ..sealed.kek_id.clone() }
	};

	let encrypted_key = OctetString::new(vec![0xff; wrapped_len]).expect("a wrapped key fits");
	let first = KekRecipientInfo { kek_id: named(b"tb/test/kek/v1"), encrypted_key, ..sealed.clone() };
	let encrypted_key = OctetString::new(vec![0x00; wrapped_len]).expect("a wrapped key fits");
	let second = KekRecipientInfo { kek_id: named(b"tb/test/kek/v2"), encrypted_key, ..sealed };
	[RecipientInfo::Kekri(first), RecipientInfo::Kekri(second)]
}

/// [`kek_sealed_from_seed`] with the recipients of
/// [`recipients_of_two_orders`], as `der` 0.7 writes it.
fn envelope_of_two_recipients() -> AuthEnvelopedData {
	kek_sealed_from_seed().with_recipients(recipients_of_two_orders())
}

/// The DER of [`envelope_of_two_recipients`], its recipients in the order of
/// their octets (X.690 § 11.6), as a sender of another implementation writes
/// it.
fn two_recipients_in_der() -> Vec<u8> {
	let mut der = envelope_of_two_recipients().to_der().expect("the envelope encodes");
	DerAdmission::arrange(&mut der).expect("the envelope is DER apart from the order of its sets");
	der
}

/// `der` 0.7 writes the two recipients in another order than their DER, so
/// the decode of their DER reaches the arranged hold.
#[test]
fn der_writes_the_two_recipients_in_another_order_than_their_der() -> TestResult {
	let written = envelope_of_two_recipients().to_der()?;
	assert_ne!(written, two_recipients_in_der());
	Ok(())
}

/// The decode of an envelope of two recipients in DER admits it, though
/// `der` 0.7 sorts its recipients in another order.
#[test]
fn an_envelope_of_two_recipients_in_der_is_admitted_at_its_decode() -> TestResult {
	let arrived = two_recipients_in_der();
	let admitted = WireDer::<AuthEnvelopedData>::try_from(arrived.as_slice())?;
	assert_eq!(admitted.der(), arrived);
	Ok(())
}

/// A KEM recipient takes a 32-octet KEK, so another length is refused.
#[test]
fn a_kek_length_other_than_32_is_refused() {
	let refused = kem_refusal(|kem| KemRecipientInfo { kek_length: 16, ..kem });
	assert!(matches!(refused, Some(EnvelopeError::KekLength(_))));
}

/// A seal to one certificate is refused by the holder of another.
#[test]
fn a_kem_recipient_that_names_another_certificate_is_refused() {
	let other = kem_identity(OTHER_RECIPIENT);
	let refused = opened(kem_sealed(), &kem_opener(&other), DATA);
	assert!(matches!(refused, Err(EnvelopeError::RecipientIdentifier)));
}

/// The KEM ciphertext in its compressed form is refused, because DHKEM over
/// secp256k1 writes `enc` uncompressed.
#[test]
fn a_compressed_kem_ciphertext_is_refused() {
	let refused = kem_refusal(with_compressed_kemct);
	assert!(matches!(refused, Some(EnvelopeError::KemPoint)));
}

/// The opener parses the `kemct` before the key provider runs, so a
/// compressed `kemct` is refused with no agreement asked of the provider.
#[test]
fn a_compressed_kem_ciphertext_is_refused_before_the_agreement() -> TestResult {
	let key = TestKey::fixed(RECIPIENT);
	let certificate = TestCertificate::self_signed(&key);
	let provider = Arc::new(RecordingAgreement::new(key));
	let identity = KeyAgreementIdentity::<HouseKem>::new(certificate, provider.to_owned())?;
	let envelope = kem_sealed_to(identity.recipient());
	let kem = with_compressed_kemct(envelope.kem_recipient());
	let envelope = envelope.with_kem_recipient(&kem);

	let refused = opened(envelope, &kem_opener(&identity), DATA);
	assert!(matches!(refused, Err(EnvelopeError::KemPoint)));
	assert_eq!(provider.agreements(), Vec::<Vec<u8>>::new());
	Ok(())
}

/// A clone of a key-agreement identity shares the one checked value, so it
/// copies no recipient and no `rid`.
#[test]
fn a_cloned_key_agreement_identity_shares_its_recipient() {
	let identity = kem_identity(RECIPIENT);
	let clone = identity.clone();
	assert!(core::ptr::eq(identity.recipient(), clone.recipient()));
}

// A KEM sender seals only to a `KemRecipient`, which the key-agreement use
// builds, so a certificate that carries no `keyUsage`, or whose `keyUsage`
// lacks `keyAgreement`, names no recipient (RFC 9629 §3, RFC 5280
// §4.2.1.3).
crate::tb_cases! {
	fn a_recipient_certificate_names_no_kem_recipient(key_usage: Option<KeyUsage>) {
		let certificate = certificate_with_key_usage(&TestKey::fixed(RECIPIENT), key_usage);
		let refused = PeerCertificate::<KeyAgreement<HouseKem>>::parse(certificate, KeyPurposes::HOUSE.server);
		assert!(matches!(
			refused,
			Err(CertificateValidationError::MissingKeyUsage(KeyUsages::KeyAgreement))
		));
	}
	cases {
		without_key_usage => None,
		without_key_agreement => signing_key_usage(),
	}
}

/// A KEM seal to a certificate whose `keyUsage` asserts `digitalSignature`
/// and `keyAgreement` (RFC 5480 §3) names the certificate as its `rid`.
#[test]
fn a_kem_seal_to_a_key_agreement_certificate_names_it() -> TestResult {
	let certificate = certificate_with_key_usage(&TestKey::fixed(RECIPIENT), server_key_usage());
	let admitted = PeerCertificate::<KeyAgreement<HouseKem>>::parse(certificate.to_owned(), KeyPurposes::HOUSE.server)?;
	let recipient = KemRecipient::from_certificate(admitted)?;

	let sealed = kem_sealed_to(&recipient);
	assert_eq!(sealed.kem_recipient().rid, certificate.recipient_identifier()?);
	Ok(())
}

// A KEM opener pairs its backend only with a certificate admitted for key
// agreement, so one that carries no `keyUsage`, or whose `keyUsage` lacks
// `keyAgreement`, is refused.
crate::tb_cases! {
	fn a_kem_opener_refuses_the_certificate(key_usage: Option<KeyUsage>) {
		let key = TestKey::fixed(RECIPIENT);

		let refused = HouseIdentity::new(certificate_with_key_usage(&key, key_usage), TestKey::provider(key));
		assert!(matches!(
			refused,
			Err(EnvelopeError::Certificate(CertificateValidationError::MissingKeyUsage(
				KeyUsages::KeyAgreement
			)))
		));
	}
	cases {
		without_key_usage => None,
		without_key_agreement => signing_key_usage(),
	}
}

// A key-agreement identity refuses a backend whose public half differs from
// the certificate's key, so the key that decapsulates is the key the `rid`
// names. The negation of the key shares its x-coordinate and is refused
// too.
crate::tb_cases! {
	fn a_key_agreement_identity_refuses_a_mismatched_backend(other: Secp256k1SigningKey) {
		let certificate = TestCertificate::self_signed(&TestKey::fixed(RECIPIENT));
		let refused = HouseIdentity::new(certificate, TestKey::provider(other));
		assert!(matches!(refused, Err(EnvelopeError::KeyMismatch)));
	}
	cases {
		another_key => TestKey::fixed(OTHER_RECIPIENT),
		negation => TestKey::negation_of(&TestKey::fixed(RECIPIENT)),
	}
}

/// A key-agreement identity pairs a backend with a certificate that holds
/// the backend's point in the compressed SEC 1 form, because both forms
/// name one key (RFC 5480 §2.2).
#[test]
fn a_key_agreement_identity_admits_its_key_in_the_compressed_form() -> TestResult {
	let key = TestKey::fixed(RECIPIENT);
	let certificate = TestCertificate::with_compressed_key(TestCertificate::self_signed(&key));
	HouseIdentity::new(certificate, TestKey::provider(key))?;
	Ok(())
}

/// An opener whose certificate asserts `digitalSignature` and
/// `keyAgreement` opens a KEM seal to its key.
#[test]
fn an_opener_whose_certificate_permits_key_agreement_opens() -> TestResult {
	let key = TestKey::fixed(RECIPIENT);
	let identity = agreement_identity(certificate_with_key_usage(&key, server_key_usage()), &key);
	let envelope = kem_sealed_to(identity.recipient());

	let opened = opened(envelope, &kem_opener(&identity), DATA)?;
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

/// A bare recipient is named by the RFC 7093 §2 method 1 identifier of its
/// key, in the `subjectKeyIdentifier` form of the `rid`.
#[test]
fn a_bare_recipient_is_named_by_the_rfc_7093_identifier_of_its_key() -> TestResult {
	let recipient = KemRecipient::<HouseKem>::bare(unhex(PUBLISHED_RECIPIENT_SPKI))?;
	let sealed = kem_sealed_to(&recipient);

	let expected = SubjectKeyIdentifier(OctetString::new(unhex(PUBLISHED_RECIPIENT_KEY_IDENTIFIER))?);
	assert_eq!(sealed.kem_recipient().rid, RecipientIdentifier::SubjectKeyIdentifier(expected));
	Ok(())
}

/// A bare recipient of a key that is no secp256k1 point is refused: the
/// SubjectPublicKeyInfo names P-256 (`1.2.840.10045.3.1.7`, RFC 5480
/// §2.1.1.1). The curve check refuses it and names secp256k1, the curve the
/// KEM takes.
#[test]
fn a_bare_recipient_of_another_curve_is_refused() {
	let p256 = "3059301306072a8648ce3d020106082a8648ce3d030107034200\
		043ee7314407753d1ba296de29f07b2cd5505ca94b614f127e71f3c19fc7845d\
		af49c9bb4bf4d00d3b5411c8eb86d59a2dcadc5a13115fa9fef44d1e0b7ef11cab";

	let refused = KemRecipient::<HouseKem>::bare(unhex(p256));
	let curve_check = crate::spki::Error::OidUnknown { oid: CURVE_SECP256K1 };
	assert!(matches!(
		refused,
		Err(EnvelopeError::Certificate(CertificateValidationError::SpkiError(error))) if error == curve_check
	));
}

/// A bare key whose backend holds another key than its public key is
/// refused at construction, so the key that decapsulates is the key the
/// `rid` names.
#[test]
fn a_bare_kem_key_refuses_a_backend_of_another_key() {
	let public = PublicKey::from(TestKey::fixed(RECIPIENT).verifying_key());

	let refused = BareKemKey::<HouseKem>::new(public, TestKey::provider(TestKey::fixed(OTHER_RECIPIENT)));
	assert!(matches!(refused, Err(EnvelopeError::KeyMismatch)));
}

/// A bare key lends the recipient of its own key, so it names the `rid` the
/// bare recipient of its public key names.
#[test]
fn a_bare_kem_key_lends_the_recipient_of_its_key() {
	let key = TestKey::fixed(RECIPIENT);
	let bare = TestAgreement::bare(&key);

	let lent = kem_sealed_to(bare.recipient()).kem_recipient();
	let named = kem_sealed_to(&TestAgreement::recipient(&key)).kem_recipient();
	assert_eq!(lent.rid, named.rid);
}

/// A seal to the bare recipient of a key opens through the bare key that
/// holds it.
#[test]
fn a_seal_to_a_bare_recipient_opens_through_its_bare_kem_key() -> TestResult {
	let key = TestKey::fixed(RECIPIENT);
	let bare = TestAgreement::bare(&key);
	let sealed = kem_sealed_to(&TestAgreement::recipient(&key));

	let opened = opened(sealed, &kem_opener(&bare), DATA)?;
	assert_eq!(opened.to_insecure().as_slice(), CONTENT);
	Ok(())
}

/// A seal to another bare recipient is refused by its `rid` before the
/// backend runs.
#[test]
fn a_seal_to_another_bare_recipient_is_refused() {
	let bare = TestAgreement::bare(&TestKey::fixed(RECIPIENT));
	let sealed = kem_sealed_to(&TestAgreement::recipient(&TestKey::fixed(OTHER_RECIPIENT)));

	let refused = opened(sealed, &kem_opener(&bare), DATA);
	assert!(matches!(refused, Err(EnvelopeError::RecipientIdentifier)));
}
