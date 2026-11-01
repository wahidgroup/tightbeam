//! The integration tests of the public CMS toolkit.
//!
//! The tests exercise the toolkit end to end through public interfaces
//! only, with the failure paths a consumer relies on:
//!
//! - the content key wrapped to a `KEMRecipientInfo` and unwrapped by its holder,
//! - the seal and the open of an `AuthEnvelopedData` under a `KEKRecipientInfo`, and
//! - the signature and the verification of a `SignedData`.

#![cfg(all(feature = "transport-cms", feature = "tokio", feature = "testing"))]

use tightbeam::asn1::Any;
use tightbeam::cms::signed_data::SignedData;
use tightbeam::crypto::cms::{AuthEnvelopedData, EnvelopeError, KemRecipientInfo, Opener, Recipient};
use tightbeam::crypto::profiles::{DefaultCryptoProvider, Kek};
use tightbeam::crypto::secret::{SecretSlice, ToInsecure};
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
use tightbeam::crypto::sign::{CmsSigner, Signed, SignedContent, SignedDataExt, SignerError, VerifiedSignature};
use tightbeam::der::asn1::{ObjectIdentifier, OctetString, OctetStringRef};
use tightbeam::der::{Decode, Encode};
use tightbeam::oids::{ATTR_CONTENT_TYPE, DATA};
use tightbeam::tb_cases;
use tightbeam::testing::{EnvelopeRecipient, TestCmsServer, TestIdentity, TestKey};
use tightbeam::transport::handshake::HandshakeAttribute;
use tightbeam::x509::attr::Attribute;

use crate::common::result::TestResult;
use crate::common::security::fixed_signing_key;

/// The house provider, whose algorithms the envelope scenarios run.
type House = DefaultCryptoProvider;

/// The match of the refusal that a row of an envelope table expects.
type Refusal = fn(&EnvelopeError) -> bool;

/// The match of the verdict that a row of a signature table expects.
type Verdict = fn(&Result<VerifiedSignature, SignerError>) -> bool;

/// The OID of the test-only authenticated attribute that the envelope carries.
const TOOLKIT_ATTR: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1");

/// The purpose label that leads the `ukm` of the KEM scenario.
const TOOLKIT_UKM: &[u8] = b"tb/test/cms-toolkit/ukm/v1";

/// The key-encryption key of the envelope scenario.
static TOOLKIT_KEK: [u8; 32] = [0x42u8; 32];

/// The identifier that names [`TOOLKIT_KEK`].
const TOOLKIT_KEK_ID: &[u8] = b"tb/test/cms-toolkit/kek/v1";

/// Returns `sealed` with one bit flipped in the wrapped content key of its
/// `KEMRecipientInfo`.
fn with_tampered_key(sealed: &AuthEnvelopedData) -> AuthEnvelopedData {
	let kem = sealed.kem_recipient();
	let mut tampered_bytes = kem.encrypted_key.as_bytes().to_vec();
	tampered_bytes[0] ^= 0x01;

	let encrypted_key = OctetString::new(tampered_bytes).expect("bytes are an OCTET STRING");
	let kem = KemRecipientInfo { encrypted_key, ..kem };
	sealed.to_owned().with_kem_recipient(&kem)
}

/// The content that the envelope scenarios seal.
const SEALED_CONTENT: &[u8] = b"cms toolkit sealed payload";

/// The CMS server whose key-agreement identity the KEM scenarios seal to.
fn recipient() -> TestCmsServer {
	TestCmsServer::generate("toolkit recipient")
}

/// An envelope that the house seals around [`SEALED_CONTENT`] to the
/// key-agreement identity of `server`.
fn sealed_to(server: &TestCmsServer) -> AuthEnvelopedData {
	let recipient = server.key_agreement_identity();
	let sealed_to = Recipient::Kem { recipient: recipient.recipient(), ukm_label: TOOLKIT_UKM };
	let sealed = AuthEnvelopedData::seal::<House>(sealed_to, DATA, SEALED_CONTENT, [], None);
	sealed.expect("the house seals to a test recipient")
}

/// The content that `server` opens from the DER of `envelope` as the KEM
/// recipient, or the refusal of the open.
async fn opened_by(envelope: AuthEnvelopedData, server: &TestCmsServer) -> Result<SecretSlice<u8>, EnvelopeError> {
	let identity = server.key_agreement_identity();
	let arrived = envelope.to_der().expect("an envelope encodes");
	let received = AuthEnvelopedData::from_der(&arrived).expect("an encoded envelope decodes");

	let opener = Opener::Kem { identity: &identity, ukm_label: TOOLKIT_UKM };
	received.open::<House>(&arrived, &opener, DATA).await
}

/// The KEM recipient wraps the 32-octet content key under AES-256 key wrap,
/// which adds one 8-octet block.
#[test]
fn a_kem_recipient_wraps_the_content_key_in_one_block() {
	let sealed = sealed_to(&recipient());
	let wrapped = sealed.kem_recipient().encrypted_key;
	assert_eq!(wrapped.as_bytes().len(), 40);
}

/// The holder of the KEM recipient recovers the exact content from the DER of
/// the envelope.
#[tokio::test]
async fn a_kem_recipient_recovers_the_content() -> TestResult {
	let server = recipient();
	let sealed = sealed_to(&server);

	let opened = opened_by(sealed, &server).await?.to_insecure();
	assert_eq!(opened.as_slice(), SEALED_CONTENT);
	Ok(())
}

// The open of a KEM envelope refuses a key-agreement identity that is no
// recipient of it, and a wrapped content key that an intermediary altered.
tb_cases! {
	async fn a_kem_envelope_is_refused((envelope, server, refused): (AuthEnvelopedData, TestCmsServer, Refusal)) {
		let opened = opened_by(envelope, &server).await;
		assert!(matches!(&opened, Err(error) if refused(error)));
	}
	cases {
		/// The recipient identifier names the certificate of another server.
		for_a_foreign_recipient => (
			sealed_to(&recipient()),
			TestCmsServer::generate("toolkit intruder"),
			|error| matches!(error, EnvelopeError::RecipientIdentifier),
		),
		/// The altered wrapped key fails the integrity check of the key unwrap.
		with_a_tampered_wrapped_key => (
			with_tampered_key(&sealed_to(&recipient())),
			recipient(),
			|error| matches!(error, EnvelopeError::KeyUnwrap),
		),
	}
}

/// The DER of an envelope that the house seals around [`SEALED_CONTENT`]
/// under [`TOOLKIT_KEK`], with the authenticated attribute [`TOOLKIT_ATTR`].
fn kek_envelope_der() -> Vec<u8> {
	let attr_value = OctetStringRef::new(b"toolkit-attr").expect("the attribute value is an OCTET STRING");
	let attr_value = Any::encode_from(&attr_value).expect("an OCTET STRING encodes");
	let attr = Attribute::try_from(HandshakeAttribute::new(TOOLKIT_ATTR, attr_value));
	let attr = attr.expect("the attribute holds one value");

	let kek = Kek::try_from(TOOLKIT_KEK.as_slice()).expect("the key is of the size of the wrap");
	let recipient = Recipient::Kek { kek, key_identifier: TOOLKIT_KEK_ID };
	let envelope = AuthEnvelopedData::seal::<House>(recipient, DATA, SEALED_CONTENT, [attr], None);
	let envelope = envelope.expect("the house seals under a key-encryption key");
	envelope.to_der().expect("an envelope encodes")
}

/// The OIDs of the authenticated attributes of `envelope`, in the order the
/// envelope carries them.
fn auth_attr_oids(envelope: &AuthEnvelopedData) -> Vec<ObjectIdentifier> {
	let attrs = envelope.auth_attrs.iter().flat_map(|attrs| attrs.iter());
	attrs.map(|attr| attr.oid).collect()
}

/// An envelope sealed under a key-encryption key opens to its content from
/// its DER alone.
#[tokio::test]
async fn a_kek_envelope_opens_to_its_content_from_its_der() -> TestResult {
	let arrived = kek_envelope_der();

	let kek = Kek::try_from(TOOLKIT_KEK.as_slice())?;
	let opener = Opener::Kek { kek, key_identifier: TOOLKIT_KEK_ID };
	let received = AuthEnvelopedData::from_der(&arrived)?;
	let opened = received.open::<House>(&arrived, &opener, DATA).await?.to_insecure();
	assert_eq!(opened.as_slice(), SEALED_CONTENT);
	Ok(())
}

/// An envelope read back from its DER keeps its authenticated attribute
/// beside the content type that every seal adds.
#[test]
fn a_kek_envelope_keeps_its_authenticated_attribute() -> TestResult {
	let arrived = kek_envelope_der();
	let received = AuthEnvelopedData::from_der(&arrived)?;
	assert_eq!(auth_attr_oids(&received), [ATTR_CONTENT_TYPE, TOOLKIT_ATTR]);
	Ok(())
}

/// The content that the `SignedData` scenarios sign.
const SIGNED_CONTENT: &[u8] = b"cms toolkit transcript commitment";

/// A `SignedData` over [`SIGNED_CONTENT`] that the fixed test key signs, read
/// back from its DER.
fn signed_data() -> Signed<SignedData> {
	let certified = TestIdentity::certified(TestKey::insecure_fixed_signing());
	let signer = CmsSigner::sign_with::<Secp256k1Signature, _>(&certified, SignedContent::data(SIGNED_CONTENT));
	let signer = signer.expect("the fixed key signs");
	let signed = CmsSigner::signed_data(SignedContent::data(SIGNED_CONTENT), signer, None);
	let wire = signed.expect("a SignedData builds").to_der().expect("a SignedData encodes");
	Signed::<SignedData>::from_der(&wire).expect("an encoded SignedData decodes")
}

/// The verdict of `key` on the one signature of [`signed_data`], over the
/// content that it carries.
fn verdict_under(key: &Secp256k1SigningKey) -> Result<VerifiedSignature, SignerError> {
	let received = signed_data();
	let recovered = received.content(DATA).expect("the SignedData carries its content");
	let signer_infos = received.signer_infos.0.as_slice();
	let signer_info = signer_infos.first().expect("the SignedData carries one signer");

	let content = SignedContent::data(recovered);
	CmsSigner::verify::<Secp256k1Signature, _>(signer_info, key.verifying_key(), content)
}

/// A `SignedData` read back from its DER carries the exact content that it
/// signed.
#[test]
fn a_signed_data_carries_its_content() -> TestResult {
	let received = signed_data();
	let recovered = received.content(DATA)?;
	assert_eq!(recovered, SIGNED_CONTENT);
	Ok(())
}

// The signature of a `SignedData` read back from its DER verifies under the
// key of its signer and under no other key.
tb_cases! {
	fn a_signed_data_verifies_under_its_signer_alone((key, verified): (Secp256k1SigningKey, Verdict)) {
		let verdict = verdict_under(&key);
		assert!(verified(&verdict));
	}
	cases {
		the_signer => (TestKey::insecure_fixed_signing(), |verdict| verdict.is_ok()),
		a_foreign_key => (fixed_signing_key(0x02), |verdict| matches!(verdict, Err(SignerError::Signature(_)))),
	}
}
