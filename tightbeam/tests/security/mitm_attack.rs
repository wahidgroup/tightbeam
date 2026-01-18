//! Man-in-the-Middle (MITM) attack threat test.
//!
//! Tests that transcript signatures protect against message tampering by a MITM.
//! This test runs against all enabled backends (ECIES, CMS).
//!
//! ## Attack Scenario
//!
//! 1. Client and Server begin handshake
//! 2. MITM intercepts and modifies a message in transit
//! 3. Recipient processes the tampered message
//! 4. Signature verification fails due to:
//!    - ECIES: Tampered ServerHandshake has invalid signature over transcript
//!    - CMS: Tampered Finished messages have invalid SignedData signatures
//!
//! ## Control
//!
//! Both parties sign transcript_hash; verified against certificates.
//! Any modification to handshake messages causes signature verification failure.
//!
//! ## What This Test Proves
//!
//! - Tampered messages are detected and rejected
//! - Transcript integrity prevents MITM attacks
//! - Signature verification catches content modifications

use std::sync::Arc;

use tightbeam::{
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{error::FdrConfigError, error::TestingError, ScenarioConf},
	trace::TraceCollector,
	TightBeamError,
};

use crate::security::common::{
	tamper_payload, Direction, HandshakeBackendKind, InjectionOutcome, SecurityThreatHarness, BACKEND_COUNT_U32,
};

fn expectation_failure(reason: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError { field: "mitm_attack", reason }))
}

tb_assert_spec! {
	pub MitmAttackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("mitm_capture_handshake", exactly!(BACKEND_COUNT_U32)),
			("mitm_tamper_message", exactly!(BACKEND_COUNT_U32)),
			("mitm_inject_tampered", exactly!(BACKEND_COUNT_U32)),
			("mitm_tampering_detected", exactly!(BACKEND_COUNT_U32))
		]
	}
}

tb_process_spec! {
	pub MitmAttackProcess,
	events {
		observable {
			"mitm_capture_handshake",
			"mitm_tamper_message",
			"mitm_inject_tampered",
			"mitm_tampering_detected"
		}
		hidden {
			"harness_spawn_session",
			"harness_spawn_ecies",
			"harness_spawn_cms"
		}
	}
	states {
		Idle => { "harness_spawn_session" => SpawningCapture },
		SpawningCapture => {
			"harness_spawn_ecies" => CaptureReady,
			"harness_spawn_cms" => CaptureReady
		},
		CaptureReady => { "mitm_capture_handshake" => Captured },
		Captured => { "mitm_tamper_message" => Tampered },
		Tampered => { "harness_spawn_session" => SpawningAttack },
		SpawningAttack => {
			"harness_spawn_ecies" => AttackReady,
			"harness_spawn_cms" => AttackReady
		},
		AttackReady => { "mitm_inject_tampered" => Injected },
		Injected => { "mitm_tampering_detected" => Idle }
	}
	terminal { Idle }
	annotations { description: "MITM attack: message tampering detection via transcript signatures" }
}

tb_scenario! {
	name: mitm_attack,
	config: ScenarioConf::<()>::builder()
		.with_spec(MitmAttackSpec::latest())
		.with_csp(MitmAttackProcess)
		.build(),
	environment Bare {
		exec: |trace| async move {
			MitmAttackScenario::run((trace,)).await
		}
	}
}

job! {
	name: MitmAttackScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let harness = SecurityThreatHarness::with_trace(Arc::clone(&trace));

		for kind in HandshakeBackendKind::all() {
			// ========================================
			// Step 1: Capture a complete handshake
			// ========================================
			let mut session = harness.spawn(kind);
			let captured = session.capture_full().await?;

			trace.event("mitm_capture_handshake")?;

			// ========================================
			// Step 2: Find a server-to-client message to tamper
			// ECIES: ServerHandshake (step 1)
			// CMS: ServerFinished (step 2)
			// ========================================
			let target = captured
				.messages
				.iter()
				.find(|m| m.direction == Direction::ServerToClient)
				.ok_or_else(|| expectation_failure("no server-to-client messages captured"))?;

			// Tamper with the message (simulating MITM modification)
			let tampered_payload = tamper_payload(&target.payload);

			// Verify tampering actually changed the payload
			if tampered_payload == target.payload {
				return Err(expectation_failure("tampering did not modify payload"));
			}

			trace.event("mitm_tamper_message")?;

			// ========================================
			// Step 3: Inject tampered message into fresh session
			// ========================================
			let mut attack_session = harness.spawn(kind);

			trace.event("mitm_inject_tampered")?;

			// Inject the tampered message at the same step
			match attack_session.inject_at_step(target.step, &tampered_payload).await? {
				InjectionOutcome::Rejected(_) => {
					// Tampering detected - signature verification failed
					trace.event("mitm_tampering_detected")?;
				}
				InjectionOutcome::Accepted => {
					// Should not happen - tampered message should be rejected
					return Err(expectation_failure("tampered message was accepted"));
				}
			}
		}

		Ok(())
	}
}
