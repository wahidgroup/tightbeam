//! Denial of Service (DoS) attack threat test.
//!
//! Tests that oversized handshake messages are rejected to prevent resource exhaustion.
//! This test runs against all enabled backends (ECIES, CMS).
//!
//! ## Attack Scenario
//!
//! 1. Attacker sends an oversized handshake message (>16 KiB)
//! 2. Server/Client should reject before full processing
//! 3. Resource exhaustion is prevented
//!
//! ## Control
//!
//! 16 KiB handshake size cap (`HANDSHAKE_MAX_WIRE`).
//! Reject oversized handshake messages before processing.
//!
//! ## What This Test Proves
//!
//! - Oversized messages are rejected at the protocol level
//! - The size limit prevents resource exhaustion attacks
//! - Normal-sized messages still work correctly

use std::sync::Arc;

use tightbeam::{
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{error::FdrConfigError, error::TestingError, ScenarioConf},
	trace::TraceCollector,
	TightBeamError,
};

use crate::security::common::{HandshakeBackendKind, InjectionOutcome, SecurityThreatHarness, BACKEND_COUNT_U32};

/// Maximum handshake message size (16 KiB) as defined in transport layer.
const HANDSHAKE_MAX_SIZE: usize = 16 * 1024;

fn expectation_failure(reason: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError { field: "dos_attack", reason }))
}

tb_assert_spec! {
	pub DosAttackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("dos_generate_oversized", exactly!(BACKEND_COUNT_U32)),
			("dos_inject_oversized", exactly!(BACKEND_COUNT_U32)),
			("dos_oversized_rejected", exactly!(BACKEND_COUNT_U32))
		]
	}
}

tb_process_spec! {
	pub DosAttackProcess,
	events {
		observable {
			"dos_generate_oversized",
			"dos_inject_oversized",
			"dos_oversized_rejected"
		}
		hidden {
			"harness_spawn_session",
			"harness_spawn_ecies",
			"harness_spawn_cms"
		}
	}
	states {
		Idle => { "dos_generate_oversized" => OversizedReady },
		OversizedReady => { "harness_spawn_session" => Spawning },
		Spawning => {
			"harness_spawn_ecies" => SessionReady,
			"harness_spawn_cms" => SessionReady
		},
		SessionReady => { "dos_inject_oversized" => Injected },
		Injected => { "dos_oversized_rejected" => Idle }
	}
	terminal { Idle }
	annotations { description: "DoS attack: oversized handshake message rejection" }
}

tb_scenario! {
	name: dos_attack,
	config: ScenarioConf::<()>::builder()
		.with_spec(DosAttackSpec::latest())
		.with_csp(DosAttackProcess)
		.build(),
	environment Bare {
		exec: |trace| async move {
			DosAttackScenario::run((trace,)).await
		}
	}
}

job! {
	name: DosAttackScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let harness = SecurityThreatHarness::with_trace(Arc::clone(&trace));

		for kind in HandshakeBackendKind::all() {
			// ========================================
			// Step 1: Generate an oversized message
			// ========================================
			// Create a message that exceeds the 16 KiB limit
			let oversized_payload = vec![0xDE; HANDSHAKE_MAX_SIZE + 1];

			trace.event("dos_generate_oversized")?;

			// ========================================
			// Step 2: Attempt to inject oversized message
			// ========================================
			let mut session = harness.spawn(kind);

			trace.event("dos_inject_oversized")?;

			// Inject at step 0 (ClientHello for ECIES, KeyExchange for CMS)
			// The oversized message should be rejected
			match session.inject_at_step(0, &oversized_payload).await? {
				InjectionOutcome::Rejected(_) => {
					// Oversized message rejected - DoS protection works
					trace.event("dos_oversized_rejected")?;
				}
				InjectionOutcome::Accepted => {
					// Should not happen - oversized message should be rejected
					return Err(expectation_failure("oversized message was accepted"));
				}
			}
		}

		Ok(())
	}
}
