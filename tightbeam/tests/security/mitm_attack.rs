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
//! - RFC 9846 (TLS 1.3) §4.4.3: transcript-bound CertificateVerify/Finished

use std::sync::Arc;

use tightbeam::{
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	transport::handshake::HandshakeError,
	utils::urn::Urn,
	TightBeamError,
};

use crate::security::common::{
	expectation_failure, tamper_payload, Direction, HandshakeBackendKind, InjectionOutcome, SecurityThreatHarness,
	BACKEND_COUNT_U32,
};

pub(crate) const MITM_CAPTURE_HANDSHAKE: Urn<'static> = Urn::new("test", "event:mitm-attack/mitm-capture-handshake");
pub(crate) const MITM_INJECT_TAMPERED: Urn<'static> = Urn::new("test", "event:mitm-attack/mitm-inject-tampered");
pub(crate) const MITM_TAMPERING_DETECTED: Urn<'static> = Urn::new("test", "event:mitm-attack/mitm-tampering-detected");
pub(crate) const MITM_TAMPER_MESSAGE: Urn<'static> = Urn::new("test", "event:mitm-attack/mitm-tamper-message");

tb_assert_spec! {
	pub MitmAttackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(MITM_CAPTURE_HANDSHAKE, exactly!(BACKEND_COUNT_U32)),
			(MITM_TAMPER_MESSAGE, exactly!(BACKEND_COUNT_U32)),
			(MITM_INJECT_TAMPERED, exactly!(BACKEND_COUNT_U32)),
			(MITM_TAMPERING_DETECTED, exactly!(BACKEND_COUNT_U32))
		]
	}
}

tb_process_spec! {
	pub MitmAttackProcess,
	events {
		observable {

			MITM_CAPTURE_HANDSHAKE,
			MITM_TAMPER_MESSAGE,
			MITM_INJECT_TAMPERED,
			MITM_TAMPERING_DETECTED,
			SecurityThreatHarness::HARNESS_SPAWN_SESSION,
			SecurityThreatHarness::HARNESS_SPAWN_ECIES,
			SecurityThreatHarness::HARNESS_SPAWN_CMS
		}
		hidden { }
	}
	states {
		Idle => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => SpawningCapture },
		SpawningCapture => {
			SecurityThreatHarness::HARNESS_SPAWN_ECIES => CaptureReady,
			SecurityThreatHarness::HARNESS_SPAWN_CMS => CaptureReady
		},
		CaptureReady => { MITM_CAPTURE_HANDSHAKE => Captured },
		Captured => { MITM_TAMPER_MESSAGE => Tampered },
		Tampered => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => SpawningAttack },
		SpawningAttack => {
			SecurityThreatHarness::HARNESS_SPAWN_ECIES => AttackReady,
			SecurityThreatHarness::HARNESS_SPAWN_CMS => AttackReady
		},
		AttackReady => { MITM_INJECT_TAMPERED => Injected },
		Injected => { MITM_TAMPERING_DETECTED => Idle }
	}
	terminal { Idle }
	annotations { description: "MITM attack: message tampering detection via transcript signatures" }
}

tb_scenario! {
	name: mitm_attack,
	config: ScenarioConfig::builder()
		.with_spec(MitmAttackSpec::latest())
		.with_csp(MitmAttackProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			MitmAttackScenario::run((trace.into(),)).await
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

			trace.event(MITM_CAPTURE_HANDSHAKE)?;

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

			trace.event(MITM_TAMPER_MESSAGE)?;

			// ========================================
			// Step 3: Inject tampered message into fresh session
			// ========================================
			let mut attack_session = harness.spawn(kind);
			trace.event(MITM_INJECT_TAMPERED)?;

			// Inject the tampered message at the same step
			match attack_session.inject_at_step(target.step, &tampered_payload).await? {
				InjectionOutcome::Rejected(err) => {
					let TightBeamError::HandshakeError(handshake_err) = &err else {
						return Err(expectation_failure("MITM rejection must be a handshake error"));
					};
					assert!(
						!matches!(handshake_err, HandshakeError::DerError(_)),
						"MITM tampering must fail signature/transcript verification, not DER parsing (got {handshake_err:?})"
					);

					trace.event(MITM_TAMPERING_DETECTED)?;
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
