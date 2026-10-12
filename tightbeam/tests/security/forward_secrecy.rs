//! # Forward secrecy threat
//!
//! ## Weakness
//! Reusing ephemeral key material across handshakes means compromise of the
//! server's long-term key (or a single ephemeral key) can expose past sessions.
//!
//! ## Attack
//! Multiple handshakes are run and their ephemeral public keys compared for
//! uniqueness and randomness. A client holds two: the key of its agreement with
//! the server ephemeral, inside the sealed payload, and the key HPKE seals
//! that payload under, in the clear.
//!
//! ## Expected control
//! Each handshake MUST generate a fresh, random ephemeral key, so session keys
//! from different handshakes are independent and past traffic stays protected.
//! The two client keys of one handshake MUST differ, because the randomness of
//! an HPKE encapsulation serves nothing else.
//!
//! ## References
//! - CWE-323: Reusing a Nonce, Key Pair in Encryption <https://cwe.mitre.org/data/definitions/323.html>
//! - NIST SP 800-56A Rev. 3 §5.6: ephemeral key-pair generation
//! - RFC 9180 §9.2.3: KEM key reuse <https://www.rfc-editor.org/rfc/rfc9180#section-9.2.3>

use std::sync::Arc;

use tightbeam::{
	constants::EC_PUBKEY_UNCOMPRESSED_SIZE,
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	urn::Urn,
	TightBeamError,
};

use crate::security::common::{
	expectation_failure, extract_ephemeral_pubkey, extract_hpke_ciphertext, open_key_exchange, Direction,
	HandshakeBackendKind, SecurityThreatHarness, HANDSHAKE_AAD,
};

pub(crate) const FS_ALL_EPHEMERAL_UNIQUE: Urn<'static> =
	tightbeam::urn!("test", "event:forward-secrecy/fs-all-ephemeral-unique");
pub(crate) const FS_CAPTURE_HANDSHAKE: Urn<'static> =
	tightbeam::urn!("test", "event:forward-secrecy/fs-capture-handshake");
pub(crate) const FS_EXTRACT_EPHEMERAL: Urn<'static> =
	tightbeam::urn!("test", "event:forward-secrecy/fs-extract-ephemeral");

/// Number of handshakes to perform for forward secrecy verification.
const HANDSHAKE_COUNT: usize = 5;

tb_assert_spec! {
	pub ForwardSecrecySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(FS_CAPTURE_HANDSHAKE, exactly!(HANDSHAKE_COUNT as u32)),
			(FS_EXTRACT_EPHEMERAL, exactly!(HANDSHAKE_COUNT as u32)),
			(FS_ALL_EPHEMERAL_UNIQUE, exactly!(1u32))
		]
	}
}

tb_process_spec! {
	pub ForwardSecrecyProcess,
	events {
		observable {

			FS_CAPTURE_HANDSHAKE,
			FS_EXTRACT_EPHEMERAL,
			FS_ALL_EPHEMERAL_UNIQUE,
			SecurityThreatHarness::HARNESS_SPAWN_SESSION,
			SecurityThreatHarness::HARNESS_SPAWN_HPKE
		}
		hidden { }
	}
	states {
		Idle => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => Spawning },
		Spawning => { SecurityThreatHarness::HARNESS_SPAWN_HPKE => SessionReady },
		SessionReady => { FS_CAPTURE_HANDSHAKE => Captured },
		Captured => { FS_EXTRACT_EPHEMERAL => Extracted },
		Extracted => {
			SecurityThreatHarness::HARNESS_SPAWN_SESSION => Spawning,
			FS_ALL_EPHEMERAL_UNIQUE => Complete
		},
		Complete => { }
	}
	terminal { Complete }
	annotations { description: "Forward Secrecy: Ephemeral key uniqueness verification" }
}

tb_scenario! {
	name: forward_secrecy,
	config: ScenarioConfig::builder()
		.with_spec(ForwardSecrecySpec::latest())
		.with_csp(ForwardSecrecyProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			ForwardSecrecyScenario::run((trace.into(),)).await
		}
	}
}

job! {
	name: ForwardSecrecyScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let harness = SecurityThreatHarness::with_trace(Arc::clone(&trace));
		// Only test HPKE (has ephemeral keys in the clear)
		let kind = HandshakeBackendKind::Hpke;

		// Collect ephemeral public keys from multiple handshakes
		let mut ephemeral_keys: Vec<Vec<u8>> = Vec::with_capacity(HANDSHAKE_COUNT);
		let mut agreement_keys: Vec<Vec<u8>> = Vec::with_capacity(HANDSHAKE_COUNT);
		for _ in 0..HANDSHAKE_COUNT {
			// Capture a complete handshake
			let mut session = harness.spawn(kind);
			let captured = session.capture_full().await?;

			trace.event(FS_CAPTURE_HANDSHAKE)?;

			// Extract HPKE ciphertext from ClientKeyExchange (step 2)
			let client_kex = captured
				.messages
				.iter()
				.find(|m| m.step == 2 && m.direction == Direction::ClientToServer)
				.ok_or_else(|| expectation_failure("no ClientKeyExchange message captured"))?;

			// The encapsulated key leads the message in the clear, and the
			// server's static key opens the payload that holds the agreement
			// key.
			let ciphertext = extract_hpke_ciphertext(&client_kex.payload)?;
			let ephemeral_pubkey = extract_ephemeral_pubkey(&ciphertext)?;
			let payload = open_key_exchange(&ciphertext, harness.materials().secret_key(), HANDSHAKE_AAD)?;
			let agreement_key = payload.client_ephemeral.into_bytes();

			// The x coordinate follows the tag byte in both encodings. Equal
			// coordinates mean one scalar served the HPKE encapsulation and
			// the agreement.
			if ephemeral_pubkey.get(1..33) == agreement_key.get(1..33) {
				return Err(expectation_failure("the HPKE ephemeral is the agreement key"));
			}

			ephemeral_keys.push(ephemeral_pubkey);
			agreement_keys.push(agreement_key);

			trace.event(FS_EXTRACT_EPHEMERAL)?;
		}

		// ========================================
		// Verify all ephemeral keys are unique
		// ========================================

		// Check for duplicates by comparing each key against all others
		for keys in [&ephemeral_keys, &agreement_keys] {
			for i in 0..keys.len() {
				for j in (i + 1)..keys.len() {
					if keys[i] == keys[j] {
						return Err(expectation_failure("duplicate ephemeral keys detected - forward secrecy violated"));
					}
				}
			}
		}

		// Additional sanity checks:
		// 1. All keys should be 65 bytes (uncompressed secp256k1 public key)
		for key in &ephemeral_keys {
			if key.len() != EC_PUBKEY_UNCOMPRESSED_SIZE {
				return Err(expectation_failure("ephemeral key is not 65 bytes"));
			}

			// 2. First byte should be 0x04 (uncompressed point prefix)
			if key[0] != 0x04 {
				return Err(expectation_failure("ephemeral key has invalid prefix"));
			}
		}

		// 3. All agreement keys should be 33 bytes (compressed secp256k1 public key)
		for key in &agreement_keys {
			if key.len() != 33 {
				return Err(expectation_failure("agreement key is not 33 bytes"));
			}

			// 4. First byte should be 0x02 or 0x03 (compressed point prefix)
			if key[0] != 0x02 && key[0] != 0x03 {
				return Err(expectation_failure("agreement key has invalid prefix"));
			}
		}

		trace.event(FS_ALL_EPHEMERAL_UNIQUE)?;

		Ok(())
	}
}
