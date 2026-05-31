//! # Handshake replay threat
//!
//! ## Weakness
//! Captured handshake messages could be replayed to establish an unauthorized
//! session if completed handshakes are not bound to fresh, single-use state.
//!
//! ## Attack
//! A valid client handshake message is captured and re-sent to the server (all
//! enabled backends: ECIES, CMS).
//!
//! ## Expected control
//! Replayed handshake messages MUST be rejected.
//!
//! ## References
//! - CWE-294: Authentication Bypass by Capture-replay
//!   <https://cwe.mitre.org/data/definitions/294.html>
//! - CAPEC-60: Reusing Session IDs (aka Session Replay)
//!   <https://capec.mitre.org/data/definitions/60.html>

use std::sync::Arc;

use tightbeam::{
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario, testing::ScenarioConf, trace::TraceCollector,
	TightBeamError,
};

use crate::security::common::{
	expectation_failure, HandshakeBackendKind, InjectionOutcome, SecurityThreatHarness, BACKEND_COUNT_U32,
};

tb_assert_spec! {
	pub ReplayAttackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("replay_initial_handshake", exactly!(BACKEND_COUNT_U32)),
			("replay_attempt", exactly!(BACKEND_COUNT_U32)),
			("replay_detected", exactly!(BACKEND_COUNT_U32)),
			("replay_rejected", exactly!(BACKEND_COUNT_U32))
		]
	}
}

tb_process_spec! {
	pub ReplayAttackProcess,
	events {
		observable {
			"replay_initial_handshake",
			"replay_attempt",
			"replay_detected",
			"replay_rejected"
		}
		hidden {
			"harness_spawn_session",
			"harness_spawn_ecies",
			"harness_spawn_cms"
		}
	}
	states {
		Idle => { "harness_spawn_session" => Spawning },
		Spawning => {
			"harness_spawn_ecies" => SessionReady,
			"harness_spawn_cms" => SessionReady
		},
		SessionReady => { "replay_initial_handshake" => Established },
		Established => { "harness_spawn_session" => SpawningAttack },
		SpawningAttack => {
			"harness_spawn_ecies" => AttackSessionReady,
			"harness_spawn_cms" => AttackSessionReady
		},
		AttackSessionReady => { "replay_attempt" => AttackObserved },
		AttackObserved => { "replay_detected" => ReplaySuppressed },
		ReplaySuppressed => { "replay_rejected" => Idle }
	}
	terminal { Idle }
	annotations { description: "Replay attack detection state machine" }
}

tb_scenario! {
	name: replay_attack,
	config: ScenarioConf::<()>::builder()
		.with_spec(ReplayAttackSpec::latest())
		.with_csp(ReplayAttackProcess)
		.build(),
	environment Bare {
		exec: |trace| async move {
			ReplayAttackScenario::run((trace,)).await
		}
	}
}

job! {
	name: ReplayAttackScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let harness = SecurityThreatHarness::with_trace(Arc::clone(&trace));
		for kind in HandshakeBackendKind::all() {
			// Capture a complete handshake
			let mut session = harness.spawn(kind);
			let captured = session.capture_full().await?;

			trace.event("replay_initial_handshake")?;

			// Get the final client message (replay target for all backends)
			let target = captured
				.final_client_message()
				.ok_or_else(|| expectation_failure("no client messages captured"))?;

			// Attempt replay on a fresh session
			let mut attack_session = harness.spawn(captured.kind);

			trace.event("replay_attempt")?;

			match attack_session.inject_at_step(target.step, &target.payload).await? {
				InjectionOutcome::Rejected(_) => {
					trace.event("replay_detected")?;
					trace.event("replay_rejected")?;
				}
				InjectionOutcome::Accepted => {
					return Err(expectation_failure("replay was accepted"));
				}
			}
		}

		Ok(())
	}
}
