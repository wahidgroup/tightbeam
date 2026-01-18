//! Confidentiality threat test.
//!
//! Tests that session keys are encrypted in transit and can only be decrypted
//! with the correct private key. This proves ECDH + HKDF key derivation works.
//!
//! ## Control
//!
//! ECDH + HKDF derived AEAD key. Session key never transmitted in the clear;
//! derived from ECDH shared secret.
//!
//! ## What This Test Proves
//!
//! 1. Captured ECIES ciphertext can be decrypted with correct server key
//! 2. Decryption produces valid 64-byte plaintext (base_session_key || client_random)
//! 3. Decryption with wrong key fails (proving encryption is real)
//! 4. Different handshakes produce different ciphertexts (fresh encryption)

use std::sync::Arc;

use tightbeam::{
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{error::FdrConfigError, error::TestingError, ScenarioConf},
	trace::TraceCollector,
	TightBeamError,
};

use crate::security::common::{
	extract_ecies_ciphertext, generate_wrong_secret_key, try_decrypt_ecies, DecryptionResult, Direction,
	HandshakeBackendKind, SecurityThreatHarness,
};

fn expectation_failure(reason: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError {
		field: "confidentiality",
		reason,
	}))
}

tb_assert_spec! {
	pub ConfidentialitySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("conf_capture_handshake", exactly!(1u32)),
			("conf_extract_ciphertext", exactly!(1u32)),
			("conf_decrypt_correct_key", exactly!(1u32)),
			("conf_decrypt_wrong_key_fails", exactly!(1u32)),
			("conf_ciphertexts_differ", exactly!(1u32))
		]
	}
}

tb_process_spec! {
	pub ConfidentialityProcess,
	events {
		observable {
			"conf_capture_handshake",
			"conf_extract_ciphertext",
			"conf_decrypt_correct_key",
			"conf_decrypt_wrong_key_fails",
			"conf_ciphertexts_differ"
		}
		hidden {
			"harness_spawn_session",
			"harness_spawn_ecies"
		}
	}
	states {
		Idle => {
			"harness_spawn_session" => Spawning,
			"conf_ciphertexts_differ" => Idle
		},
		Spawning => { "harness_spawn_ecies" => SessionReady },
		SessionReady => {
			"conf_capture_handshake" => Captured,
			"harness_spawn_session" => Spawning
		},
		Captured => { "conf_extract_ciphertext" => Extracted },
		Extracted => { "conf_decrypt_correct_key" => CorrectKeyVerified },
		CorrectKeyVerified => { "conf_decrypt_wrong_key_fails" => WrongKeyVerified },
		WrongKeyVerified => { "harness_spawn_session" => Spawning }
	}
	terminal { Idle }
	annotations { description: "Confidentiality: ECIES encryption verification via manual decryption" }
}

tb_scenario! {
	name: confidentiality,
	config: ScenarioConf::<()>::builder()
		.with_spec(ConfidentialitySpec::latest())
		.with_csp(ConfidentialityProcess)
		.build(),
	environment Bare {
		exec: |trace| async move {
			ConfidentialityScenario::run((trace,)).await
		}
	}
}

job! {
	name: ConfidentialityScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let harness = SecurityThreatHarness::with_trace(Arc::clone(&trace));

		// Only test ECIES (CMS uses different encryption structure)
		let kind = HandshakeBackendKind::Ecies;

		// ========================================
		// Step 1: Capture a complete handshake
		// ========================================
		let mut session = harness.spawn(kind);
		let captured = session.capture_full().await?;

		trace.event("conf_capture_handshake")?;

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
		// ECIES overhead: 33 pubkey + 12 nonce + 16 tag + 64 plaintext = 125 bytes
		if ciphertext.len() < 100 {
			return Err(expectation_failure("ciphertext too short to be valid ECIES"));
		}

		trace.event("conf_extract_ciphertext")?;

		// ========================================
		// Step 3: Decrypt with CORRECT key - proves encryption works
		// ========================================
		let correct_key = harness.materials().secret_key();
		match try_decrypt_ecies(&ciphertext, correct_key, None) {
			DecryptionResult::Success { plaintext_len } => {
				// Plaintext must be 64 bytes: base_session_key (32) || client_random (32)
				if plaintext_len != 64 {
					return Err(expectation_failure("decrypted plaintext is not 64 bytes"));
				}
				trace.event("conf_decrypt_correct_key")?;
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
				trace.event("conf_decrypt_wrong_key_fails")?;
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

		let ciphertext2 = extract_ecies_ciphertext(&client_kex2.payload)?;

		// Ciphertexts MUST differ (fresh ephemeral keys, fresh nonces)
		if ciphertext == ciphertext2 {
			return Err(expectation_failure("ciphertexts are identical across handshakes"));
		}

		trace.event("conf_ciphertexts_differ")?;

		Ok(())
	}
}
