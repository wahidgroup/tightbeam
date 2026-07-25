//! # Key-exchange splice threat (mutual authentication)
//!
//! ## Weakness
//! If the ECIES mutual-auth client signature covers only the transcript hash,
//! it does not commit to the ECIES `encrypted_data` carrying the session key.
//! ECIES encryption is a public-key operation, and `client_random` is public
//! (sent in `ClientHello`), so anyone can produce a decryptable payload with
//! the victim's random.
//!
//! ## Attack
//! 1. A MITM captures a victim's `ClientKeyExchange` (certificate + signature).
//! 2. The MITM encrypts `[attacker_key || victim_client_random]` to the
//!    server's public key.
//! 3. The MITM splices its `encrypted_data` into the victim's message, keeping
//!    the victim's certificate and signature intact.
//! 4. A transcript-only signature still verifies: the server would attribute an
//!    attacker-controlled session key to the victim's authenticated identity.
//!
//! ## Expected control
//! The client signature MUST commit to the exact `encrypted_data` and client
//! certificate (`Digest(transcript_hash || encrypted_data || cert_der)`), so a
//! spliced payload MUST fail signature verification.
//!
//! ## References
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>
//! - CWE-300: Channel Accessible by Non-Endpoint
//!   <https://cwe.mitre.org/data/definitions/300.html>
//! - CAPEC-94: Adversary in the Middle (AiTM)
//!   <https://capec.mitre.org/data/definitions/94.html>

use std::sync::Arc;

use tightbeam::{
	asn1::OctetString,
	crypto::{
		aead::Aes256Gcm,
		ecies::{encrypt, Secp256k1EciesMessage},
		kdf::HkdfSha3_256,
		key::{Secp256k1KeyProvider, SigningKeyProvider},
		profiles::DefaultCryptoProvider,
		secret::ToInsecure,
		sign::ecdsa::Secp256k1SigningKey,
		x509::policy::{CertificateValidation, ExpiryValidator},
	},
	der::{Decode, Encode, Sequence},
	exactly, job,
	random::OsRng,
	tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{
		utils::{create_test_certificate, create_test_signing_key},
		ScenarioConf, SetupEnv,
	},
	trace::TraceCollector,
	transport::handshake::{
		client::EciesHandshakeClient, negotiation::SecurityOffer, server::EciesHandshakeServer, ClientKeyExchange,
	},
	TightBeamError,
};

use crate::common::security::{default_security_profile, expectation_failure, pinning_validator, ServerMaterials};

/// Attacker's-eye view of the DER key-exchange plaintext: the two
/// leading OCTET STRINGs are all a splice needs (the trailing receipt
/// acknowledgement is absent on this unmetered session).
#[derive(Sequence)]
struct SplicedPayload {
	base_key: OctetString,
	client_random: OctetString,
}

tb_assert_spec! {
	pub SpliceAttackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(spliced_kex_rejected, exactly!(1u32))
		]
	}
}

tb_process_spec! {
	pub SpliceAttackProcess,
	events {
		observable { SpliceAttackSpec::spliced_kex_rejected }
		hidden { }
	}
	states {
		Idle => { SpliceAttackSpec::spliced_kex_rejected => Done },
		Done => { }
	}
	terminal { Done }
	annotations { description: "Splice attack: client signature must bind encrypted_data + certificate" }
}

tb_scenario! {
	name: splice_attack,
	config: ScenarioConf::builder()
		.with_spec(SpliceAttackSpec::latest())
		.with_csp(SpliceAttackProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			SpliceAttackScenario::run((trace.into(),)).await
		}
	}
}

job! {
	name: SpliceAttackScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let materials = ServerMaterials::generate();
		let profile = default_security_profile();

		// Victim client with an authenticated identity.
		let client_signing = create_test_signing_key();
		let client_cert = Arc::new(create_test_certificate(&client_signing));
		let signing_key = Secp256k1SigningKey::from(client_signing);
		let client_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(signing_key));
		let validator = pinning_validator(&materials.certificate);

		let mut client = EciesHandshakeClient::<DefaultCryptoProvider, Secp256k1EciesMessage>::new(None)
			.with_security_offer(SecurityOffer::new(vec![profile]))
			.with_certificate_validator(validator)
			.with_client_identity(Arc::clone(&client_cert), client_provider);

		// Server requires client authentication (validators present).
		let validators: Arc<Vec<Arc<dyn CertificateValidation>>> = Arc::new(vec![Arc::new(ExpiryValidator)]);
		let mut server = EciesHandshakeServer::<DefaultCryptoProvider>::new(
			Arc::clone(&materials.key_provider),
			Arc::clone(&materials.certificate),
			None,
			Some(validators),
		)
		.with_supported_profiles(vec![profile]);

		let client_hello = client.build_client_hello()?;
		let server_handshake = server.process_client_hello(&client_hello).await?;
		let client_kex_der = client.process_server_handshake(&server_handshake).await?;

		// Recover the victim's client_random from the legitimate payload so the
		// spliced ciphertext still passes the server's replay check.
		let victim_kex = ClientKeyExchange::from_der(&client_kex_der)?;
		let victim_message = Secp256k1EciesMessage::from_bytes(victim_kex.encrypted_data.as_bytes())?;
		let victim_plain = tightbeam::crypto::ecies::decrypt::<_, _, HkdfSha3_256, Aes256Gcm>(
			materials.secret_key(),
			&victim_message,
			Some(crate::security::common::HANDSHAKE_AAD),
		)?
		.to_insecure()?;

		// Attacker forges a payload with its own key under the server's
		// public key and splices it into the victim's message, preserving
		// the victim's client_random and the DER framing.
		let victim_payload = SplicedPayload::from_der(&victim_plain)?;
		let forged_payload = SplicedPayload {
			base_key: OctetString::new([0x41u8; 32])?, // attacker-chosen key
			client_random: victim_payload.client_random,
		};

		let forged_plain = forged_payload.to_der()?;
		let recipient_pub = materials.secret_key().public_key();
		let forged_message = encrypt::<_, _, _, Secp256k1EciesMessage, HkdfSha3_256, Aes256Gcm>(
			&recipient_pub,
			&forged_plain,
			Some(crate::security::common::HANDSHAKE_AAD),
			Some(&mut OsRng),
		)?;

		let spliced = ClientKeyExchange {
			encrypted_data: OctetString::new(forged_message.to_bytes())?,
			client_certificate: victim_kex.client_certificate.to_owned(),
			client_signature: victim_kex.client_signature.to_owned(),
		};

		let spliced_der = spliced.to_der()?;
		if spliced_der == client_kex_der {
			return Err(expectation_failure("splice produced identical ClientKeyExchange bytes"));
		}

		match server.process_client_key_exchange(&spliced_der).await {
			Err(_) => {
				trace.event(SpliceAttackSpec::spliced_kex_rejected)?;
			}
			Ok(_) => return Err(expectation_failure("server accepted a spliced key exchange under victim identity")),
		}

		Ok(())
	}
}
