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
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConf, SetupEnv},
	trace::TraceCollector,
	TightBeamError,
};

use crate::security::common::{
	expectation_failure, HandshakeBackendKind, InjectionOutcome, SecurityThreatHarness, BACKEND_COUNT_U32,
};

tb_assert_spec! {
	pub ReplayAttackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(replay_initial_handshake, exactly!(BACKEND_COUNT_U32)),
			(replay_attempt, exactly!(BACKEND_COUNT_U32)),
			(replay_detected, exactly!(BACKEND_COUNT_U32)),
			(replay_rejected, exactly!(BACKEND_COUNT_U32))
		]
	}
}

tb_process_spec! {
	pub ReplayAttackProcess,
	events {
		observable {

			ReplayAttackSpec::replay_initial_handshake,
			ReplayAttackSpec::replay_attempt,
			ReplayAttackSpec::replay_detected,
			ReplayAttackSpec::replay_rejected,
			SecurityThreatHarness::harness_spawn_session,
			SecurityThreatHarness::harness_spawn_ecies,
			SecurityThreatHarness::harness_spawn_cms
		}
		hidden { }
	}
	states {
		Idle => { SecurityThreatHarness::harness_spawn_session => Spawning },
		Spawning => {
			SecurityThreatHarness::harness_spawn_ecies => SessionReady,
			SecurityThreatHarness::harness_spawn_cms => SessionReady
		},
		SessionReady => { ReplayAttackSpec::replay_initial_handshake => Established },
		Established => { SecurityThreatHarness::harness_spawn_session => SpawningAttack },
		SpawningAttack => {
			SecurityThreatHarness::harness_spawn_ecies => AttackSessionReady,
			SecurityThreatHarness::harness_spawn_cms => AttackSessionReady
		},
		AttackSessionReady => { ReplayAttackSpec::replay_attempt => AttackObserved },
		AttackObserved => { ReplayAttackSpec::replay_detected => ReplaySuppressed },
		ReplaySuppressed => { ReplayAttackSpec::replay_rejected => Idle }
	}
	terminal { Idle }
	annotations { description: "Replay attack detection state machine" }
}

tb_scenario! {
	name: replay_attack,
	config: ScenarioConf::builder()
		.with_spec(ReplayAttackSpec::latest())
		.with_csp(ReplayAttackProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			ReplayAttackScenario::run((trace.into(),)).await
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

			trace.event(ReplayAttackSpec::replay_initial_handshake)?;

			// Get the final client message (replay target for all backends)
			let target = captured
				.final_client_message()
				.ok_or_else(|| expectation_failure("no client messages captured"))?;

			// Attempt replay on a fresh session
			let mut attack_session = harness.spawn(captured.kind);

			trace.event(ReplayAttackSpec::replay_attempt)?;

			match attack_session.inject_at_step(target.step, &target.payload).await? {
				InjectionOutcome::Rejected(_) => {
					trace.event(ReplayAttackSpec::replay_detected)?;
					trace.event(ReplayAttackSpec::replay_rejected)?;
				}
				InjectionOutcome::Accepted => {
					return Err(expectation_failure("replay was accepted"));
				}
			}
		}

		Ok(())
	}
}
