//! Integration tests for the public CMS toolkit.
//!
//! The tests exercise the toolkit end to end through public interfaces
//! only, including the failure paths a consumer relies on:
//!
//! - KARI CEK wrap and unwrap,
//! - `EnvelopedData` sealing and decryption through the builder and processor pair, and
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
use tightbeam::cms::builder::RecipientInfoBuilder;
use tightbeam::cms::cert::IssuerAndSerialNumber;
use tightbeam::cms::enveloped_data::{
	EncryptedKey, EnvelopedData, KeyAgreeRecipientIdentifier, KeyAgreeRecipientInfo, RecipientInfo, UserKeyingMaterial,
};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::secret::ToInsecure;
use tightbeam::crypto::sign::ecdsa::k256::SecretKey;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey};
use tightbeam::crypto::sign::EcdsaSignatureVerifier;
use tightbeam::der::asn1::{ObjectIdentifier, OctetStringRef};
use tightbeam::der::{Decode, Encode};
use tightbeam::exactly;
use tightbeam::oids::{AES_256_WRAP, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256};
use tightbeam::random::{generate_nonce, OsRng};
use tightbeam::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::transport::handshake::builders::{
	TightBeamEnvelopedDataBuilder, TightBeamKariBuilder, TightBeamSignedDataBuilder,
};
use tightbeam::transport::handshake::processors::{
	TightBeamEnvelopedDataProcessor, TightBeamKariRecipient, TightBeamSignedDataProcessor,
};
use tightbeam::transport::handshake::{HandshakeAttribute, HandshakeError};
use tightbeam::x509::name::Name;
use tightbeam::x509::serial_number::SerialNumber;

use tightbeam::utils::urn::Urn;

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

/// OID for the test-only unprotected attribute carried through the envelope.
const TOOLKIT_ATTR: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1");

/// Recipient identifier fixture shared by the envelope scenarios.
fn recipient_identifier() -> Result<KeyAgreeRecipientIdentifier, HandshakeError> {
	Ok(KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
		issuer: Name::default(),
		serial_number: SerialNumber::new(&[0x01])?,
	}))
}

/// Open the KARI variant a [`TightBeamKariBuilder`] produces.
fn open_kari(recipient_info: RecipientInfo) -> KeyAgreeRecipientInfo {
	let RecipientInfo::Kari(kari) = recipient_info else {
		panic!("the KARI builder produces a KeyAgreeRecipientInfo");
	};

	kari
}

tb_assert_spec! {
	pub KariCekSpec,
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
	name: kari_cek_roundtrip,
	spec: KariCekSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let sender = SecretKey::random(&mut OsRng);
			let recipient = SecretKey::random(&mut OsRng);
			let intruder = SecretKey::random(&mut OsRng);
			let sender_spki = SubjectPublicKeyInfoOwned::from_key(sender.public_key())?;
			let ukm = UserKeyingMaterial::new(generate_nonce::<64>(None)?.to_vec())?;
			let cek = [0x42u8; 32];

			let mut builder = TightBeamKariBuilder::default()
				.with_sender_priv(sender)
				.with_sender_pub_spki(sender_spki)
				.with_recipient_pub(recipient.public_key())
				.with_recipient_rid(recipient_identifier()?)
				.with_ukm(ukm)
				.with_key_enc_alg(AlgorithmIdentifierOwned { oid: AES_256_WRAP, parameters: None });

			let recipient_info = builder.build(&cek).map_err(HandshakeError::CmsBuilderError)?;
			let kari = open_kari(recipient_info);
			let wrapped_entry = kari.recipient_enc_keys.first().ok_or(HandshakeError::InvalidRecipientIndex)?;
			let wrapped = wrapped_entry.enc_key.as_bytes();
			assert_ne!(wrapped, cek.as_slice(), "wrapped CEK must not expose the plaintext CEK");

			trace.event(CEK_WRAPPED)?;

			let recipient_processor = TightBeamKariRecipient::with_defaults(recipient);
			let unwrapped = recipient_processor.process_kari(&kari, 0)?;
			assert_eq!(unwrapped.to_insecure().as_slice(), cek.as_slice(), "recipient must recover the exact CEK");

			trace.event(CEK_RECOVERED)?;

			let intruder_processor = TightBeamKariRecipient::with_defaults(intruder);
			let wrong = intruder_processor.process_kari(&kari, 0);
			assert!(wrong.is_err(), "a foreign recipient key must fail the unwrap integrity check");

			trace.event(WRONG_KEY_REJECTED)?;

			let mut tampered_bytes = wrapped.to_vec();
			tampered_bytes[0] ^= 0x01;

			let mut tampered = kari.clone();
			let tampered_entry = tampered.recipient_enc_keys.first_mut().ok_or(HandshakeError::InvalidRecipientIndex)?;
			tampered_entry.enc_key = EncryptedKey::new(tampered_bytes)?;

			let forged = recipient_processor.process_kari(&tampered, 0);
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
	name: enveloped_data_roundtrip,
	spec: EnvelopeRoundTripSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let sender = SecretKey::random(&mut OsRng);
			let recipient = SecretKey::random(&mut OsRng);
			let sender_spki = SubjectPublicKeyInfoOwned::from_key(sender.public_key())?;
			let ukm = UserKeyingMaterial::new(generate_nonce::<64>(None)?.to_vec())?;

			let kari = TightBeamKariBuilder::default()
				.with_sender_priv(sender)
				.with_sender_pub_spki(sender_spki)
				.with_recipient_pub(recipient.public_key())
				.with_recipient_rid(recipient_identifier()?)
				.with_ukm(ukm)
				.with_key_enc_alg(AlgorithmIdentifierOwned { oid: AES_256_WRAP, parameters: None });

			let attr_value = Any::encode_from(&OctetStringRef::new(b"toolkit-attr")?)?;
			let attr = HandshakeAttribute::new_single(TOOLKIT_ATTR, attr_value)?;

			let plaintext = b"cms toolkit sealed payload";
			let envelope = TightBeamEnvelopedDataBuilder::with_defaults(kari)
				.with_unprotected_attr(attr)
				.build(plaintext, None, None)?;

			trace.event(ENVELOPE_SEALED)?;

			// Wire fidelity: the recipient works from re-decoded DER only.
			let envelope = EnvelopedData::from_der(&envelope.to_der()?)?;

			trace.event(WIRE_ROUNDTRIP)?;

			let kari = TightBeamKariRecipient::with_defaults(recipient);
			let processor = TightBeamEnvelopedDataProcessor::with_defaults(kari);
			let recovered = processor.process(&envelope)?.to_insecure();
			assert_eq!(&recovered[..], plaintext.as_slice(), "recipient must recover the sealed plaintext");

			trace.event(CONTENT_RECOVERED)?;

			let attrs = processor.extract_unprotected_attributes(&envelope);
			assert!(
				matches!(attrs, Some([attr]) if attr.oid == TOOLKIT_ATTR),
				"the unprotected attribute must survive the wire roundtrip"
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
			let builder = TightBeamSignedDataBuilder::<DefaultCryptoProvider, _>::new(
				&signing_key,
				AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None },
				AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None },
			)?;

			let content = b"cms toolkit transcript commitment";
			let signed = builder.build(content)?;

			trace.event(CONTENT_SIGNED)?;

			let verifier = EcdsaSignatureVerifier::<Secp256k1VerifyingKey, Secp256k1Signature, Sha3_256>::from_signing_key(
				&signing_key,
			)?;
			let verified = TightBeamSignedDataProcessor::new(verifier).process(&signed, &HASH_SHA3_256)?;
			assert_eq!(verified.as_slice(), content.as_slice(), "verifier must return the exact signed content");

			trace.event(SIGNATURE_VERIFIED)?;

			let foreign_key = Secp256k1SigningKey::random(&mut OsRng);
			let foreign_verifier =
				EcdsaSignatureVerifier::<Secp256k1VerifyingKey, Secp256k1Signature, Sha3_256>::from_signing_key(
					&foreign_key,
				)?;

			let rejected = TightBeamSignedDataProcessor::new(foreign_verifier).process(&signed, &HASH_SHA3_256);
			assert!(rejected.is_err(), "a verifier bound to a different key must reject the signature");

			trace.event(FOREIGN_KEY_REJECTED)?;

			Ok(())
		}
	}
}
