//! The integration tests of the public CMS toolkit.
//!
//! The tests exercise the toolkit end to end through public interfaces
//! only, with the failure paths a consumer relies on:
//!
//! - the content key wrapped to a `KEMRecipientInfo` and unwrapped by its holder,
//! - the seal and the open of an `AuthEnvelopedData` under a `KEKRecipientInfo`, and
//! - the signature and the verification of a `SignedData`.

#![cfg(all(
	feature = "transport-cms",
	feature = "builder",
	feature = "aead",
	feature = "secp256k1",
	feature = "signature",
	feature = "tokio"
))]

use tightbeam::asn1::Any;
use tightbeam::cms::signed_data::SignedData;
use tightbeam::crypto::cms::{AuthEnvelopedData, KemRecipientInfo, Opener, Recipient};
use tightbeam::crypto::profiles::{DefaultCryptoProvider, Kek};
use tightbeam::crypto::secret::ToInsecure;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
use tightbeam::crypto::sign::{CmsSigner, Signed, SignedContent};
use tightbeam::der::asn1::{ObjectIdentifier, OctetString, OctetStringRef};
use tightbeam::der::{Decode, Encode};
use tightbeam::oids::DATA;
use tightbeam::random::OsRng;
use tightbeam::testing::{EnvelopeRecipient, TestCmsServer, TestIdentity};
use tightbeam::transport::handshake::{HandshakeAttribute, HandshakeError};
use tightbeam::x509::attr::Attribute;
use tightbeam::TightBeamError;

/// The house provider, whose algorithms the envelope scenarios run.
type House = DefaultCryptoProvider;

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

/// The content that the KEM scenarios seal.
const KEM_PLAINTEXT: &[u8] = b"cms toolkit sealed payload";

/// An envelope that the house seals around [`KEM_PLAINTEXT`] to the
/// key-agreement identity of `server`.
fn sealed_to(server: &TestCmsServer) -> Result<AuthEnvelopedData, TightBeamError> {
	let recipient = server.key_agreement_identity();
	let sealed_to = Recipient::Kem { recipient: recipient.recipient(), ukm_label: TOOLKIT_UKM };
	Ok(AuthEnvelopedData::seal::<House>(sealed_to, DATA, KEM_PLAINTEXT, [], None)?)
}

/// The KEM recipient wraps the 32-octet content key under AES-256 key wrap,
/// which adds one 8-octet block.
#[test]
fn a_kem_recipient_wraps_the_content_key_in_one_block() -> Result<(), TightBeamError> {
	let sealed = sealed_to(&TestCmsServer::generate("toolkit recipient"))?;

	let wrapped = sealed.kem_recipient().encrypted_key;
	assert_eq!(wrapped.as_bytes().len(), 40);
	Ok(())
}

/// The holder of the KEM recipient recovers the exact content from the DER of
/// the envelope.
#[tokio::test]
async fn a_kem_recipient_recovers_the_content() -> Result<(), TightBeamError> {
	let server = TestCmsServer::generate("toolkit recipient");
	let recipient = server.key_agreement_identity();
	let arrived = sealed_to(&server)?.to_der()?;

	let opener = Opener::Kem { identity: &recipient, ukm_label: TOOLKIT_UKM };
	let received = AuthEnvelopedData::from_der(&arrived)?;
	let opened = received.open::<House>(&arrived, &opener, DATA).await?.to_insecure();
	assert_eq!(opened.as_slice(), KEM_PLAINTEXT);
	Ok(())
}

/// A key-agreement identity that is not a recipient of the envelope fails to
/// open it.
#[tokio::test]
async fn a_foreign_kem_recipient_is_refused() -> Result<(), TightBeamError> {
	let arrived = sealed_to(&TestCmsServer::generate("toolkit recipient"))?.to_der()?;
	let intruder = TestCmsServer::generate("toolkit intruder").key_agreement_identity();

	let opener = Opener::Kem { identity: &intruder, ukm_label: TOOLKIT_UKM };
	let received = AuthEnvelopedData::from_der(&arrived)?;
	let refused = received.open::<House>(&arrived, &opener, DATA).await;
	assert!(refused.is_err());
	Ok(())
}

/// A wrapped content key that an intermediary altered fails the integrity
/// check of the key unwrap.
#[tokio::test]
async fn a_tampered_wrapped_key_is_refused() -> Result<(), TightBeamError> {
	let server = TestCmsServer::generate("toolkit recipient");
	let recipient = server.key_agreement_identity();
	let forged = with_tampered_key(&sealed_to(&server)?);
	let forged_der = forged.to_der()?;

	let opener = Opener::Kem { identity: &recipient, ukm_label: TOOLKIT_UKM };
	let refused = forged.open::<House>(forged_der, &opener, DATA).await;
	assert!(refused.is_err());
	Ok(())
}

/// An envelope sealed under a key-encryption key opens from its DER alone,
/// with its content and its authenticated attribute intact.
#[tokio::test]
async fn auth_enveloped_data_roundtrip() -> Result<(), TightBeamError> {
	let attr_value = Any::encode_from(&OctetStringRef::new(b"toolkit-attr")?)?;
	let attr = Attribute::try_from(HandshakeAttribute::new_single(TOOLKIT_ATTR, attr_value)?)?;

	let plaintext = b"cms toolkit sealed payload";
	let kek = Kek::try_from(TOOLKIT_KEK.as_slice())?;
	let recipient = Recipient::Kek { kek, key_identifier: TOOLKIT_KEK_ID };
	let envelope = AuthEnvelopedData::seal::<House>(recipient, DATA, plaintext, [attr], None)?;

	// Transport fidelity: the recipient works from the re-decoded DER alone.
	let arrived = envelope.to_der()?;
	let envelope = AuthEnvelopedData::from_der(&arrived)?;

	let opener = Opener::Kek { kek, key_identifier: TOOLKIT_KEK_ID };
	let received = AuthEnvelopedData::from_der(&arrived)?;
	let recovered = received.open::<House>(&arrived, &opener, DATA).await?.to_insecure();
	assert_eq!(
		&recovered[..],
		plaintext.as_slice(),
		"recipient must recover the sealed plaintext"
	);

	let attrs = envelope.auth_attrs.as_ref().ok_or(HandshakeError::MissingAttribute)?;
	assert!(
		attrs.iter().any(|attr| attr.oid == TOOLKIT_ATTR),
		"the authenticated attribute must survive the wire roundtrip"
	);

	Ok(())
}

/// The content that the `SignedData` scenarios sign.
const SIGNED_CONTENT: &[u8] = b"cms toolkit transcript commitment";

/// A key, beside the DER of a `SignedData` that the key signs over
/// [`SIGNED_CONTENT`].
fn signed_wire() -> Result<(Secp256k1SigningKey, Vec<u8>), TightBeamError> {
	let signing_key = Secp256k1SigningKey::random(&mut OsRng);
	let certified = TestIdentity::certified(signing_key.clone());
	let signer = CmsSigner::sign_with::<Secp256k1Signature, _>(&certified, SignedContent::data(SIGNED_CONTENT))?;
	let signed = CmsSigner::signed_data(SignedContent::data(SIGNED_CONTENT), signer, None)?;

	Ok((signing_key, signed.to_der()?))
}

/// The signer's key verifies a `SignedData` read back from its DER, over the
/// exact content that it signed.
#[test]
fn the_signer_key_verifies_the_signed_content() -> Result<(), TightBeamError> {
	let (signing_key, wire) = signed_wire()?;
	let received = Signed::<SignedData>::from_der(&wire)?;
	let recovered = CmsSigner::content(&received, DATA)?;
	let signer_info = received
		.signer_infos
		.0
		.get(0)
		.ok_or(HandshakeError::SignatureVerificationFailed)?;

	let content = SignedContent::data(recovered);
	let verified = CmsSigner::verify::<Secp256k1Signature, _>(signer_info, signing_key.verifying_key(), content);
	assert!(verified.is_ok());
	assert_eq!(recovered, SIGNED_CONTENT);
	Ok(())
}

/// A key other than the signer's rejects the signature of a `SignedData`.
#[test]
fn a_foreign_key_rejects_the_signature() -> Result<(), TightBeamError> {
	let (_signing_key, wire) = signed_wire()?;
	let foreign_key = Secp256k1SigningKey::random(&mut OsRng);

	let received = Signed::<SignedData>::from_der(&wire)?;
	let recovered = CmsSigner::content(&received, DATA)?;
	let signer_info = received
		.signer_infos
		.0
		.get(0)
		.ok_or(HandshakeError::SignatureVerificationFailed)?;

	let content = SignedContent::data(recovered);
	let rejected = CmsSigner::verify::<Secp256k1Signature, _>(signer_info, foreign_key.verifying_key(), content);
	assert!(rejected.is_err());
	Ok(())
}
