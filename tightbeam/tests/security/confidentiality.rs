//! # Session-key confidentiality threat
//!
//! ## Weakness
//! If session-key material is transmitted in the clear (or "encryption" is not
//! actually applied), an observer can recover it.
//!
//! ## Attack
//! Captured ECIES ciphertext is examined: decrypted with the correct key,
//! attempted with a wrong key, and compared across two handshakes.
//!
//! ## Expected control
//! The session key MUST never be transmitted in the clear. It MUST be derived
//! via ECDH + HKDF into an AEAD key. Decryption MUST succeed only with the
//! correct private key, yield the expected DER plaintext (a SEQUENCE of the
//! 32-byte base session key and 32-byte client random OCTET STRINGs), and
//! produce fresh ciphertext per handshake.
//!
//! ## References
//! - CWE-311: Missing Encryption of Sensitive Data
//!   <https://cwe.mitre.org/data/definitions/311.html>
//! - CAPEC-157: Sniffing Attacks
//!   <https://capec.mitre.org/data/definitions/157.html>
//! - RFC 9180 (HPKE): ECDH + KDF + AEAD construction

use std::sync::Arc;

use tightbeam::{
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConf, SetupEnv},
	trace::TraceCollector,
	TightBeamError,
};

use crate::security::common::{
	expectation_failure, extract_ecies_ciphertext, generate_wrong_secret_key, try_decrypt_ecies, DecryptionResult,
	Direction, HandshakeBackendKind, SecurityThreatHarness,
};

tb_assert_spec! {
	pub ConfidentialitySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(conf_capture_handshake, exactly!(1u32)),
			(conf_extract_ciphertext, exactly!(1u32)),
			(conf_decrypt_correct_key, exactly!(1u32)),
			(conf_decrypt_wrong_key_fails, exactly!(1u32)),
			(conf_ciphertexts_differ, exactly!(1u32))
		]
	}
}

tb_process_spec! {
	pub ConfidentialityProcess,
	events {
		observable {
			ConfidentialitySpec::conf_capture_handshake,
			ConfidentialitySpec::conf_extract_ciphertext,
			ConfidentialitySpec::conf_decrypt_correct_key,
			ConfidentialitySpec::conf_decrypt_wrong_key_fails,
			ConfidentialitySpec::conf_ciphertexts_differ,
			SecurityThreatHarness::harness_spawn_session,
			SecurityThreatHarness::harness_spawn_ecies
		}
		hidden { }
	}
	states {
		Idle => { SecurityThreatHarness::harness_spawn_session => Spawning },
		Spawning => { SecurityThreatHarness::harness_spawn_ecies => SessionReady },
		SessionReady => {
			ConfidentialitySpec::conf_capture_handshake => Captured,
			ConfidentialitySpec::conf_ciphertexts_differ => Idle
		},
		Captured => { ConfidentialitySpec::conf_extract_ciphertext => Extracted },
		Extracted => { ConfidentialitySpec::conf_decrypt_correct_key => CorrectKeyVerified },
		CorrectKeyVerified => { ConfidentialitySpec::conf_decrypt_wrong_key_fails => WrongKeyVerified },
		WrongKeyVerified => { SecurityThreatHarness::harness_spawn_session => Spawning }
	}
	terminal { Idle }
	annotations { description: "Confidentiality: ECIES encryption verification via manual decryption" }
}

tb_scenario! {
	name: confidentiality,
	config: ScenarioConf::builder()
		.with_spec(ConfidentialitySpec::latest())
		.with_csp(ConfidentialityProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			ConfidentialityScenario::run((trace.into(),)).await
		}
	}
}

job! {
	name: ConfidentialityScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let harness = SecurityThreatHarness::with_trace(Arc::clone(&trace));

		// This test decrypts the ECIES ClientKeyExchange blob directly. CMS
		// transports the session key inside an EnvelopedData/KARI structure, so
		// its confidentiality is verified separately in the loopback suite.
		let kind = HandshakeBackendKind::Ecies;

		// ========================================
		// Step 1: Capture a complete handshake
		// ========================================
		let mut session = harness.spawn(kind);
		let captured = session.capture_full().await?;

		trace.event(ConfidentialitySpec::conf_capture_handshake)?;

		// ========================================
		// Step 2: Extract ECIES ciphertext from ClientKeyExchange (step 2)
		// ========================================
		let client_kex = captured
			.messages
			.iter()
			.find(|m| m.step == 2 && m.direction == Direction::ClientToServer)
			.ok_or_else(|| expectation_failure("no ClientKeyExchange message captured"))?;

		let ciphertext = extract_ecies_ciphertext(&client_kex.payload)?;

		// Verify we got meaningful ciphertext
		// ECIES overhead: 33 pubkey + 12 nonce + 16 tag + 70 plaintext = 131 bytes
		if ciphertext.len() < 100 {
			return Err(expectation_failure("ciphertext too short to be valid ECIES"));
		}

		trace.event(ConfidentialitySpec::conf_extract_ciphertext)?;

		// ========================================
		// Step 3: Decrypt with CORRECT key - proves encryption works
		// ========================================
		let correct_key = harness.materials().secret_key();
		match try_decrypt_ecies(&ciphertext, correct_key, None) {
			DecryptionResult::Success { plaintext_len } => {
				// Plaintext must be the 70-byte DER SEQUENCE of the
				// 32-byte base session key and 32-byte client random
				// OCTET STRINGs (no receipt acknowledgement on this
				// unmetered session)
				if plaintext_len != 70 {
					return Err(expectation_failure("decrypted plaintext is not the 70-byte DER payload"));
				}

				trace.event(ConfidentialitySpec::conf_decrypt_correct_key)?;
			}
			DecryptionResult::Failed => {
				return Err(expectation_failure("decryption with correct key failed"));
			}
		}

		// ========================================
		// Step 4: Decrypt with WRONG key - proves encryption is real
		// ========================================
		let wrong_key = generate_wrong_secret_key();
		match try_decrypt_ecies(&ciphertext, &wrong_key, None) {
			DecryptionResult::Failed => {
				// Expected - wrong key cannot decrypt
				trace.event(ConfidentialitySpec::conf_decrypt_wrong_key_fails)?;
			}
			DecryptionResult::Success { .. } => {
				return Err(expectation_failure("decryption with wrong key should fail"));
			}
		}

		// ========================================
		// Step 5: Verify different handshakes produce different ciphertexts
		// (Fresh ephemeral keys and nonces per handshake)
		// ========================================
		let mut session2 = harness.spawn(kind);
		let captured2 = session2.capture_full().await?;

		let client_kex2 = captured2
			.messages
			.iter()
			.find(|m| m.step == 2 && m.direction == Direction::ClientToServer)
			.ok_or_else(|| expectation_failure("no ClientKeyExchange in second handshake"))?;

		// Ciphertexts MUST differ (fresh ephemeral keys, fresh nonces)
		let ciphertext2 = extract_ecies_ciphertext(&client_kex2.payload)?;
		if ciphertext == ciphertext2 {
			return Err(expectation_failure("ciphertexts are identical across handshakes"));
		}

		trace.event(ConfidentialitySpec::conf_ciphertexts_differ)?;

		Ok(())
	}
}
