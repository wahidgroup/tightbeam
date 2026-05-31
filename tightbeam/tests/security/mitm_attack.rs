//! # Man-in-the-middle tampering threat
//!
//! ## Weakness
//! Handshake messages that are not integrity-bound to a verified transcript can
//! be modified in transit without detection.
//!
//! ## Attack
//! 1. Client and server begin a handshake (all enabled backends: ECIES, CMS).
//! 2. A MITM intercepts and modifies a message in transit.
//! 3. The recipient processes the tampered message.
//!
//! ## Expected control
//! Both parties MUST sign `transcript_hash`, verified against certificates. Any
//! modification MUST cause signature-verification failure (ECIES: tampered
//! `ServerHandshake`; CMS: tampered `Finished` `SignedData`).
//!
//! ## References
//! - CWE-300: Channel Accessible by Non-Endpoint
//!   <https://cwe.mitre.org/data/definitions/300.html>
//! - CAPEC-94: Adversary in the Middle (AiTM)
//!   <https://capec.mitre.org/data/definitions/94.html>
//! - RFC 8446 (TLS 1.3) §4.4.3: transcript-bound CertificateVerify/Finished

use std::sync::Arc;

use tightbeam::{
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario, testing::ScenarioConf, trace::TraceCollector,
	TightBeamError,
};

use crate::security::common::{
	expectation_failure, tamper_payload, Direction, HandshakeBackendKind, InjectionOutcome, SecurityThreatHarness,
	BACKEND_COUNT_U32,
};

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
