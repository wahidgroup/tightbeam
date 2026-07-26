//! Integration tests for the public CMS toolkit.
//!
//! Exercises the toolkit end to end through public interfaces only:
//! KARI CEK wrap/unwrap, `EnvelopedData` sealing and decryption via the
//! builder/processor pair, and `SignedData` signing and verification,
//! including the failure paths a consumer relies on.

#![cfg(all(
	feature = "transport-cms",
	feature = "builder",
	feature = "aead",
	feature = "secp256k1",
	feature = "signature",
	feature = "tokio"
))]

use tightbeam::asn1::Any;
use tightbeam::cms::cert::IssuerAndSerialNumber;
use tightbeam::cms::enveloped_data::{EnvelopedData, KeyAgreeRecipientIdentifier, UserKeyingMaterial};
use tightbeam::constants::TIGHTBEAM_KARI_KDF_INFO;
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
use tightbeam::transport::handshake::{kari_unwrap, kari_wrap, HandshakeAttribute, HandshakeError};
use tightbeam::x509::name::Name;
use tightbeam::x509::serial_number::SerialNumber;

/// OID for the test-only unprotected attribute carried through the envelope.
const TOOLKIT_ATTR: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1");

/// Recipient identifier fixture shared by the envelope scenarios.
fn recipient_identifier() -> Result<KeyAgreeRecipientIdentifier, HandshakeError> {
	Ok(KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
		issuer: Name::default(),
		serial_number: SerialNumber::new(&[0x01])?,
	}))
}

// ============================================================================
// KARI: CEK wrap/unwrap
// ============================================================================

tb_assert_spec! {
	pub KariCekSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(cek_wrapped, exactly!(1)),
			(cek_recovered, exactly!(1)),
			(wrong_key_rejected, exactly!(1)),
			(tamper_rejected, exactly!(1))
		]
	}
}

tb_scenario! {
	name: kari_cek_roundtrip,
	spec: KariCekSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let provider = DefaultCryptoProvider::default();
			let sender = SecretKey::random(&mut OsRng);
			let recipient = SecretKey::random(&mut OsRng);
			let intruder = SecretKey::random(&mut OsRng);
			let ukm = generate_nonce::<64>(None)?;
			let cek = [0x42u8; 32];

			let wrapped = kari_wrap(&provider, &sender, &recipient.public_key(), &ukm, TIGHTBEAM_KARI_KDF_INFO, &cek)?;
			assert_ne!(wrapped.as_slice(), cek.as_slice(), "wrapped CEK must not expose the plaintext CEK");
			trace.event(KariCekSpec::cek_wrapped)?;

			let unwrapped =
				kari_unwrap(&provider, &recipient, &sender.public_key(), &ukm, TIGHTBEAM_KARI_KDF_INFO, &wrapped)?;
			assert_eq!(unwrapped.as_slice(), cek.as_slice(), "recipient must recover the exact CEK");

			trace.event(KariCekSpec::cek_recovered)?;

			let wrong =
				kari_unwrap(&provider, &intruder, &sender.public_key(), &ukm, TIGHTBEAM_KARI_KDF_INFO, &wrapped);
			assert!(wrong.is_err(), "a foreign recipient key must fail the unwrap integrity check");

			trace.event(KariCekSpec::wrong_key_rejected)?;

			let mut tampered = wrapped;
			tampered[0] ^= 0x01;
			let forged =
				kari_unwrap(&provider, &recipient, &sender.public_key(), &ukm, TIGHTBEAM_KARI_KDF_INFO, &tampered);
			assert!(forged.is_err(), "a tampered wrapped CEK must fail the unwrap integrity check");

			trace.event(KariCekSpec::tamper_rejected)?;

			Ok(())
		}
	}
}

// ============================================================================
// EnvelopedData: builder -> wire -> processor
// ============================================================================

tb_assert_spec! {
	pub EnvelopeRoundTripSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(envelope_sealed, exactly!(1)),
			(wire_roundtrip, exactly!(1)),
			(content_recovered, exactly!(1)),
			(attribute_extracted, exactly!(1))
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

			trace.event(EnvelopeRoundTripSpec::envelope_sealed)?;

			// Wire fidelity: the recipient works from re-decoded DER only.
			let envelope = EnvelopedData::from_der(&envelope.to_der()?)?;

			trace.event(EnvelopeRoundTripSpec::wire_roundtrip)?;

			let kari = TightBeamKariRecipient::with_defaults(recipient);
			let processor = TightBeamEnvelopedDataProcessor::with_defaults(kari);
			let recovered = processor.process(&envelope)?.to_insecure()?;
			assert_eq!(&recovered[..], plaintext.as_slice(), "recipient must recover the sealed plaintext");

			trace.event(EnvelopeRoundTripSpec::content_recovered)?;

			let attrs = processor.extract_unprotected_attributes(&envelope);
			assert!(
				matches!(attrs, Some([attr]) if attr.oid == TOOLKIT_ATTR),
				"the unprotected attribute must survive the wire roundtrip"
			);

			trace.event(EnvelopeRoundTripSpec::attribute_extracted)?;

			Ok(())
		}
	}
}

// ============================================================================
// SignedData: builder -> processor
// ============================================================================

tb_assert_spec! {
	pub SignedContentSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(content_signed, exactly!(1)),
			(signature_verified, exactly!(1)),
			(foreign_key_rejected, exactly!(1))
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

			trace.event(SignedContentSpec::content_signed)?;

			let verifier = EcdsaSignatureVerifier::<Secp256k1VerifyingKey, Secp256k1Signature, Sha3_256>::from_signing_key(
				&signing_key,
			)?;
			let verified = TightBeamSignedDataProcessor::new(verifier).process(&signed, &HASH_SHA3_256)?;
			assert_eq!(verified.as_slice(), content.as_slice(), "verifier must return the exact signed content");

			trace.event(SignedContentSpec::signature_verified)?;

			let foreign_key = Secp256k1SigningKey::random(&mut OsRng);
			let foreign_verifier =
				EcdsaSignatureVerifier::<Secp256k1VerifyingKey, Secp256k1Signature, Sha3_256>::from_signing_key(
					&foreign_key,
				)?;

			let rejected = TightBeamSignedDataProcessor::new(foreign_verifier).process(&signed, &HASH_SHA3_256);
			assert!(rejected.is_err(), "a verifier bound to a different key must reject the signature");

			trace.event(SignedContentSpec::foreign_key_rejected)?;

			Ok(())
		}
	}
}
