//! # Forward secrecy threat
//!
//! ## Weakness
//! Reusing ephemeral key material across handshakes means compromise of the
//! server's long-term key (or a single ephemeral key) can expose past sessions.
//!
//! ## Attack
//! Multiple handshakes are run and their ephemeral public keys compared for
//! uniqueness and randomness.
//!
//! ## Expected control
//! Each handshake MUST generate a fresh, random ephemeral key, so session keys
//! from different handshakes are independent and past traffic stays protected.
//!
//! ## References
//! - CWE-323: Reusing a Nonce, Key Pair in Encryption
//!   <https://cwe.mitre.org/data/definitions/323.html>
//! - NIST SP 800-56A Rev. 3 §5.6: ephemeral key-pair generation

use std::sync::Arc;

use tightbeam::{
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConf, SetupEnv},
	trace::TraceCollector,
	utils::urn::Urn,
	TightBeamError,
};

use crate::security::common::{
	expectation_failure, extract_ecies_ciphertext, extract_ephemeral_pubkey, Direction, HandshakeBackendKind,
	SecurityThreatHarness,
};

pub(crate) const FS_ALL_EPHEMERAL_UNIQUE: Urn<'static> =
	Urn::new("test", "event:forward-secrecy/fs-all-ephemeral-unique");
pub(crate) const FS_CAPTURE_HANDSHAKE: Urn<'static> = Urn::new("test", "event:forward-secrecy/fs-capture-handshake");
pub(crate) const FS_EXTRACT_EPHEMERAL: Urn<'static> = Urn::new("test", "event:forward-secrecy/fs-extract-ephemeral");

/// Number of handshakes to perform for forward secrecy verification.
const HANDSHAKE_COUNT: usize = 5;

tb_assert_spec! {
	pub ForwardSecrecySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
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
			SecurityThreatHarness::HARNESS_SPAWN_ECIES
		}
		hidden { }
	}
	states {
		Idle => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => Spawning },
		Spawning => { SecurityThreatHarness::HARNESS_SPAWN_ECIES => SessionReady },
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
	config: ScenarioConf::builder()
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
		// Only test ECIES (has ephemeral keys in the clear)
		let kind = HandshakeBackendKind::Ecies;

		// Collect ephemeral public keys from multiple handshakes
		let mut ephemeral_keys: Vec<Vec<u8>> = Vec::with_capacity(HANDSHAKE_COUNT);
		for _ in 0..HANDSHAKE_COUNT {
			// Capture a complete handshake
			let mut session = harness.spawn(kind);
			let captured = session.capture_full().await?;

			trace.event(FS_CAPTURE_HANDSHAKE)?;

			// Extract ECIES ciphertext from ClientKeyExchange (step 2)
			let client_kex = captured
				.messages
				.iter()
				.find(|m| m.step == 2 && m.direction == Direction::ClientToServer)
				.ok_or_else(|| expectation_failure("no ClientKeyExchange message captured"))?;

			let ciphertext = extract_ecies_ciphertext(&client_kex.payload)?;
			// Extract the ephemeral public key (first 33 bytes of ECIES message)
			let ephemeral_pubkey = extract_ephemeral_pubkey(&ciphertext)?;

			ephemeral_keys.push(ephemeral_pubkey);

			trace.event(FS_EXTRACT_EPHEMERAL)?;
		}

		// ========================================
		// Verify all ephemeral keys are unique
		// ========================================

		// Check for duplicates by comparing each key against all others
		for i in 0..ephemeral_keys.len() {
			for j in (i + 1)..ephemeral_keys.len() {
				if ephemeral_keys[i] == ephemeral_keys[j] {
					return Err(expectation_failure("duplicate ephemeral keys detected - forward secrecy violated"));
				}
			}
		}

		// Additional sanity checks:
		// 1. All keys should be 33 bytes (compressed secp256k1 public key)
		for key in &ephemeral_keys {
			if key.len() != 33 {
				return Err(expectation_failure("ephemeral key is not 33 bytes"));
			}

			// 2. First byte should be 0x02 or 0x03 (compressed point prefix)
			if key[0] != 0x02 && key[0] != 0x03 {
				return Err(expectation_failure("ephemeral key has invalid prefix"));
			}
		}

		trace.event(FS_ALL_EPHEMERAL_UNIQUE)?;

		Ok(())
	}
}
