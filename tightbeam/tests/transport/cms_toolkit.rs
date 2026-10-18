//! Integration tests for the public CMS toolkit.
//!
//! The tests exercise the toolkit end to end through public interfaces
//! only, including the failure paths a consumer relies on:
//!
//! - the content key wrapped to a `KEMRecipientInfo` and unwrapped by its holder,
//! - `AuthEnvelopedData` sealing and opening under a `KEKRecipientInfo`, and
//! - `SignedData` signing and verification.

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
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::secret::ToInsecure;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
use tightbeam::crypto::sign::{CmsSigner, Signed, SignedContent};
use tightbeam::der::asn1::{ObjectIdentifier, OctetString, OctetStringRef};
use tightbeam::der::{Decode, Encode};
use tightbeam::exactly;
use tightbeam::oids::DATA;
use tightbeam::random::OsRng;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{EnvelopeRecipient, SetupEnv, TestCmsServer, TestIdentity};
use tightbeam::transport::handshake::{HandshakeAttribute, HandshakeError};
use tightbeam::x509::attr::Attribute;

use tightbeam::urn::Urn;

pub(crate) const ATTRIBUTE_EXTRACTED: Urn<'static> = tightbeam::urn!("test", "event:cms-toolkit/attribute-extracted");
pub(crate) const CEK_RECOVERED: Urn<'static> = tightbeam::urn!("test", "event:cms-toolkit/cek-recovered");
pub(crate) const CEK_WRAPPED: Urn<'static> = tightbeam::urn!("test", "event:cms-toolkit/cek-wrapped");
pub(crate) const CONTENT_RECOVERED: Urn<'static> = tightbeam::urn!("test", "event:cms-toolkit/content-recovered");
pub(crate) const CONTENT_SIGNED: Urn<'static> = tightbeam::urn!("test", "event:cms-toolkit/content-signed");
pub(crate) const ENVELOPE_SEALED: Urn<'static> = tightbeam::urn!("test", "event:cms-toolkit/envelope-sealed");
pub(crate) const FOREIGN_KEY_REJECTED: Urn<'static> = tightbeam::urn!("test", "event:cms-toolkit/foreign-key-rejected");
pub(crate) const SIGNATURE_VERIFIED: Urn<'static> = tightbeam::urn!("test", "event:cms-toolkit/signature-verified");
pub(crate) const TAMPER_REJECTED: Urn<'static> = tightbeam::urn!("test", "event:cms-toolkit/tamper-rejected");
pub(crate) const WIRE_ROUNDTRIP: Urn<'static> = tightbeam::urn!("test", "event:cms-toolkit/wire-roundtrip");
pub(crate) const WRONG_KEY_REJECTED: Urn<'static> = tightbeam::urn!("test", "event:cms-toolkit/wrong-key-rejected");

/// The house provider, whose algorithms the envelope scenarios run.
type House = DefaultCryptoProvider;

/// OID for the test-only authenticated attribute carried through the envelope.
const TOOLKIT_ATTR: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1");

/// The purpose label that leads the `ukm` of the KEM scenario.
const TOOLKIT_UKM: &[u8] = b"tb/test/cms-toolkit/ukm/v1";

/// The key-encryption key of the envelope scenario.
static TOOLKIT_KEK: [u8; 32] = [0x42u8; 32];

/// The identifier that names [`TOOLKIT_KEK`].
const TOOLKIT_KEK_ID: &[u8] = b"tb/test/cms-toolkit/kek/v1";

/// `sealed` with the wrapped content key of its `KEMRecipientInfo` altered.
fn with_tampered_key(sealed: &AuthEnvelopedData) -> AuthEnvelopedData {
	let kem = sealed.kem_recipient();
	let mut tampered_bytes = kem.encrypted_key.as_bytes().to_vec();
	tampered_bytes[0] ^= 0x01;

	let encrypted_key = OctetString::new(tampered_bytes).expect("bytes are an OCTET STRING");
	let kem = KemRecipientInfo { encrypted_key, ..kem };
	sealed.to_owned().with_kem_recipient(&kem)
}

tb_assert_spec! {
	pub KemRecipientSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CEK_WRAPPED, exactly!(1)),
			(CEK_RECOVERED, exactly!(1)),
			(WRONG_KEY_REJECTED, exactly!(1)),
			(TAMPER_REJECTED, exactly!(1))
		]
	}
}

tb_scenario! {
	name: kem_recipient_roundtrip,
	spec: KemRecipientSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let recipient = TestCmsServer::generate("toolkit recipient").key_agreement_identity();
			let intruder = TestCmsServer::generate("toolkit intruder").key_agreement_identity();
			let plaintext = b"cms toolkit sealed payload";

			let sealed_to = Recipient::Kem { recipient: recipient.recipient(), ukm_label: TOOLKIT_UKM };
			let sealed = AuthEnvelopedData::seal::<House>(sealed_to, DATA, plaintext, [], None)?;
			let wrapped = sealed.kem_recipient().encrypted_key;
			assert_eq!(wrapped.as_bytes().len(), 40, "AES-256 key wrap adds one 8-octet block to the 32-octet CEK");

			trace.event(CEK_WRAPPED)?;

			let arrived = sealed.to_der()?;
			let opener = Opener::Kem { identity: &recipient, ukm_label: TOOLKIT_UKM };
			let received = AuthEnvelopedData::from_der(&arrived)?;
			let opened = received.open::<House>(&arrived, &opener, DATA).await?.to_insecure();
			assert_eq!(opened.as_slice(), plaintext.as_slice(), "the recipient must recover the exact content");

			trace.event(CEK_RECOVERED)?;

			let intruder_opener = Opener::Kem { identity: &intruder, ukm_label: TOOLKIT_UKM };
			let received = AuthEnvelopedData::from_der(&arrived)?;
			let wrong = received.open::<House>(&arrived, &intruder_opener, DATA).await;
			assert!(wrong.is_err(), "a foreign recipient must be refused");

			trace.event(WRONG_KEY_REJECTED)?;

			let forged = with_tampered_key(&sealed);
			let forged_der = forged.to_der()?;
			let forged = forged.open::<House>(forged_der, &opener, DATA).await;
			assert!(forged.is_err(), "a tampered wrapped CEK must fail the unwrap integrity check");

			trace.event(TAMPER_REJECTED)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub EnvelopeRoundTripSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(ENVELOPE_SEALED, exactly!(1)),
			(WIRE_ROUNDTRIP, exactly!(1)),
			(CONTENT_RECOVERED, exactly!(1)),
			(ATTRIBUTE_EXTRACTED, exactly!(1))
		]
	}
}

tb_scenario! {
	name: auth_enveloped_data_roundtrip,
	spec: EnvelopeRoundTripSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let attr_value = Any::encode_from(&OctetStringRef::new(b"toolkit-attr")?)?;
			let attr = Attribute::try_from(HandshakeAttribute::new_single(TOOLKIT_ATTR, attr_value)?)?;

			let plaintext = b"cms toolkit sealed payload";
			let recipient = Recipient::Kek { kek: &TOOLKIT_KEK, key_identifier: TOOLKIT_KEK_ID };
			let envelope = AuthEnvelopedData::seal::<House>(recipient, DATA, plaintext, [attr], None)?;

			trace.event(ENVELOPE_SEALED)?;

			// Wire fidelity: the recipient works from re-decoded DER only.
			let arrived = envelope.to_der()?;
			let envelope = AuthEnvelopedData::from_der(&arrived)?;

			trace.event(WIRE_ROUNDTRIP)?;

			let opener = Opener::Kek { kek: &TOOLKIT_KEK, key_identifier: TOOLKIT_KEK_ID };
			let received = AuthEnvelopedData::from_der(&arrived)?;
			let recovered = received.open::<House>(&arrived, &opener, DATA).await?.to_insecure();
			assert_eq!(&recovered[..], plaintext.as_slice(), "recipient must recover the sealed plaintext");

			trace.event(CONTENT_RECOVERED)?;

			let attrs = envelope.auth_attrs.as_ref().ok_or(HandshakeError::MissingAttribute)?;
			assert!(
				attrs.iter().any(|attr| attr.oid == TOOLKIT_ATTR),
				"the authenticated attribute must survive the wire roundtrip"
			);

			trace.event(ATTRIBUTE_EXTRACTED)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub SignedContentSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CONTENT_SIGNED, exactly!(1)),
			(SIGNATURE_VERIFIED, exactly!(1)),
			(FOREIGN_KEY_REJECTED, exactly!(1))
		]
	}
}

tb_scenario! {
	name: signed_data_roundtrip,
	spec: SignedContentSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let signing_key = Secp256k1SigningKey::random(&mut OsRng);
			let content = b"cms toolkit transcript commitment";
			let signed_content = SignedContent::data(content);
			let certified = TestIdentity::certified(signing_key.clone());
			let signer = CmsSigner::sign_with::<Secp256k1Signature, _>(&certified, signed_content)?;
			let signed = CmsSigner::signed_data(SignedContent::data(content), signer, None)?;
			let wire = signed.to_der()?;

			trace.event(CONTENT_SIGNED)?;

			let received = Signed::<SignedData>::from_der(&wire)?;
			let recovered = CmsSigner::content(&received, DATA)?;
			let signer_info = received.signer_infos.0.get(0).ok_or(HandshakeError::SignatureVerificationFailed)?;
			let recovered_content = SignedContent::data(recovered);
			let verified = CmsSigner::verify::<Secp256k1Signature, _>(
				signer_info,
				signing_key.verifying_key(),
				recovered_content,
			);
			assert!(verified.is_ok(), "the signer's key must verify the signature");
			assert_eq!(recovered, content.as_slice(), "the reader must return the exact signed content");

			trace.event(SIGNATURE_VERIFIED)?;

			let foreign_key = Secp256k1SigningKey::random(&mut OsRng);
			let rejected = CmsSigner::verify::<Secp256k1Signature, _>(
				signer_info,
				foreign_key.verifying_key(),
				SignedContent::data(recovered),
			);
			assert!(rejected.is_err(), "a different key must reject the signature");

			trace.event(FOREIGN_KEY_REJECTED)?;

			Ok(())
		}
	}
}
