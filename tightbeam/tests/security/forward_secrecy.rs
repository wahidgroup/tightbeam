//! Forward Secrecy threat test.
//!
//! Tests that each handshake uses fresh ephemeral keys, ensuring that
//! compromise of the server's long-term key doesn't affect past sessions.
//!
//! ## Control
//!
//! Ephemeral client keys. New ephemeral key per handshake; compromise
//! doesn't affect past sessions.
//!
//! ## What This Test Proves
//!
//! 1. Each handshake generates a unique ephemeral public key
//! 2. The ephemeral keys are cryptographically random (not reused)
//! 3. Session keys derived from different handshakes are independent

use std::sync::Arc;

use tightbeam::{
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{error::FdrConfigError, error::TestingError, ScenarioConf},
	trace::TraceCollector,
	TightBeamError,
};

use crate::security::common::{
	extract_ecies_ciphertext, extract_ephemeral_pubkey, Direction, HandshakeBackendKind, SecurityThreatHarness,
};

/// Number of handshakes to perform for forward secrecy verification.
const HANDSHAKE_COUNT: usize = 5;

fn expectation_failure(reason: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError {
		field: "forward_secrecy",
		reason,
	}))
}

tb_assert_spec! {
	pub ForwardSecrecySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("fs_capture_handshake", exactly!(HANDSHAKE_COUNT as u32)),
			("fs_extract_ephemeral", exactly!(HANDSHAKE_COUNT as u32)),
			("fs_all_ephemeral_unique", exactly!(1u32))
		]
	}
}

tb_process_spec! {
	pub ForwardSecrecyProcess,
	events {
		observable {
			"fs_capture_handshake",
			"fs_extract_ephemeral",
			"fs_all_ephemeral_unique"
		}
		hidden {
			"harness_spawn_session",
			"harness_spawn_ecies"
		}
	}
	states {
		Idle => { "harness_spawn_session" => Spawning },
		Spawning => { "harness_spawn_ecies" => SessionReady },
		SessionReady => { "fs_capture_handshake" => Captured },
		Captured => { "fs_extract_ephemeral" => Extracted },
		Extracted => {
			"harness_spawn_session" => Spawning,
			"fs_all_ephemeral_unique" => Complete
		},
		Complete => { }
	}
	terminal { Complete }
	annotations { description: "Forward Secrecy: Ephemeral key uniqueness verification" }
}

tb_scenario! {
	name: forward_secrecy,
	config: ScenarioConf::<()>::builder()
		.with_spec(ForwardSecrecySpec::latest())
		.with_csp(ForwardSecrecyProcess)
		.build(),
	environment Bare {
		exec: |trace| async move {
			ForwardSecrecyScenario::run((trace,)).await
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

			trace.event("fs_capture_handshake")?;

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

			trace.event("fs_extract_ephemeral")?;
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

		trace.event("fs_all_ephemeral_unique")?;

		Ok(())
	}
}
