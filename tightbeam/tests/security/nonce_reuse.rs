//! # Nonce reuse / replay threat
//!
//! ## Weakness
//! A handshake whose transcript omits the fresh random of its opening lets a
//! reply made for one handshake complete another, so a captured reply
//! replays with its nonce.
//!
//! ## Attack
//! An attacker captures a valid reply, signed over the transcript of one
//! opening and its nonce, and replays it to a fresh client, whose opening
//! carries a nonce of its own (on every enabled backend: HPKE, CMS).
//!
//! ## Expected control
//! Handshake freshness comes from the client's per-connection random and
//! ephemeral, which the opening carries and the signed transcript binds. A
//! fresh client binds its own opening, so a replayed reply MUST fail its
//! signature (`SignatureVerificationFailed`). A client that accepts the reply
//! is the defect, and `NONCE_REPLAY_ACCEPTED` records it.
//!
//! ## References
//! - CWE-323: Reusing a Nonce, Key Pair in Encryption <https://cwe.mitre.org/data/definitions/323.html>
//! - CWE-294: Authentication Bypass by Capture-replay <https://cwe.mitre.org/data/definitions/294.html>
//! - NIST SP 800-38D §8: IV/nonce uniqueness requirements for GCM

use std::sync::Arc;

use tightbeam::{
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	transport::handshake::HandshakeError::SignatureVerificationFailed,
	urn::Urn,
	TightBeamError,
};

use crate::security::common::{
	expectation_failure, HandshakeBackendKind, InjectionOutcome, SecurityThreatHarness, BACKEND_COUNT_U32,
};

pub(crate) const NONCE_CAPTURE_VALID: Urn<'static> = tightbeam::urn!("test", "event:nonce-reuse/nonce-capture-valid");
pub(crate) const NONCE_REPLAY_ATTEMPT: Urn<'static> = tightbeam::urn!("test", "event:nonce-reuse/nonce-replay-attempt");
pub(crate) const NONCE_REPLAY_REJECTED: Urn<'static> =
	tightbeam::urn!("test", "event:nonce-reuse/nonce-replay-rejected");
pub(crate) const NONCE_REPLAY_ACCEPTED: Urn<'static> =
	tightbeam::urn!("test", "event:nonce-reuse/nonce-replay-accepted");

tb_assert_spec! {
	pub NonceReuseSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(NONCE_CAPTURE_VALID, exactly!(BACKEND_COUNT_U32)),
			(NONCE_REPLAY_ATTEMPT, exactly!(BACKEND_COUNT_U32)),
			(NONCE_REPLAY_REJECTED, exactly!(BACKEND_COUNT_U32), equals!(true)),
			(NONCE_REPLAY_ACCEPTED, exactly!(0))
		]
	}
}

tb_process_spec! {
	pub NonceReuseProcess,
	events {
		observable {

			NONCE_CAPTURE_VALID,
			NONCE_REPLAY_ATTEMPT,
			NONCE_REPLAY_REJECTED,
			NONCE_REPLAY_ACCEPTED,
			SecurityThreatHarness::HARNESS_SPAWN_SESSION,
			SecurityThreatHarness::HARNESS_SPAWN_HPKE,
			SecurityThreatHarness::HARNESS_SPAWN_CMS
		}
		hidden { }
	}
	states {
		Idle => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => SpawningCapture },
		SpawningCapture => {
			SecurityThreatHarness::HARNESS_SPAWN_HPKE => CaptureReady,
			SecurityThreatHarness::HARNESS_SPAWN_CMS => CaptureReady
		},
		CaptureReady => { NONCE_CAPTURE_VALID => Captured },
		Captured => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => SpawningReplay },
		SpawningReplay => {
			SecurityThreatHarness::HARNESS_SPAWN_HPKE => ReplayReady,
			SecurityThreatHarness::HARNESS_SPAWN_CMS => ReplayReady
		},
		ReplayReady => { NONCE_REPLAY_ATTEMPT => ReplayAttempted },
		ReplayAttempted => {
			NONCE_REPLAY_REJECTED => Idle,
			NONCE_REPLAY_ACCEPTED => Idle
		}
	}
	terminal { Idle }
	annotations { description: "Nonce reuse attack: freshness via the opening bound into the signed transcript" }
}

tb_scenario! {
	name: nonce_reuse,
	config: ScenarioConfig::builder()
		.with_spec(NonceReuseSpec::latest())
		.with_csp(NonceReuseProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			NonceReuseScenario::run((trace.into(),)).await
		}
	}
}

job! {
	name: NonceReuseScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let harness = SecurityThreatHarness::with_trace(Arc::clone(&trace));

		for kind in HandshakeBackendKind::all() {
			// 1. Capture a handshake, whose reply the server signed over the
			//    transcript of one opening and its nonce.
			let mut capture_session = harness.spawn(kind)?;
			let captured = capture_session.capture_full().await?;

			trace.event(NONCE_CAPTURE_VALID)?;

			let target = captured.server_reply().ok_or_else(|| expectation_failure("no reply captured"))?;

			// 2. Replay the reply to a fresh client, whose opening carries a nonce of its own.
			let mut replay_session = harness.spawn(kind)?;

			trace.event(NONCE_REPLAY_ATTEMPT)?;

			match replay_session.inject_at_step(target.step, &target.payload).await? {
				InjectionOutcome::Rejected(error) => {
					// The fresh client binds its own opening, so the reply's
					// signature over the captured one fails.
					let bound = matches!(error, TightBeamError::HandshakeError(SignatureVerificationFailed));
					trace.event_with(NONCE_REPLAY_REJECTED, &[], bound)?;
				}
				InjectionOutcome::Accepted => {
					trace.event(NONCE_REPLAY_ACCEPTED)?;
				}
			}
		}

		Ok(())
	}
}
