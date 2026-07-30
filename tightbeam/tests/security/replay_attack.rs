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
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	utils::urn::Urn,
	TightBeamError,
};

use crate::security::common::{
	expectation_failure, HandshakeBackendKind, InjectionOutcome, SecurityThreatHarness, BACKEND_COUNT_U32,
};

pub(crate) const REPLAY_ATTEMPT: Urn<'static> = Urn::new("test", "event:replay-attack/replay-attempt");
pub(crate) const REPLAY_DETECTED: Urn<'static> = Urn::new("test", "event:replay-attack/replay-detected");
pub(crate) const REPLAY_INIT_HANDSHAKE: Urn<'static> = Urn::new("test", "event:replay-attack/replay-initial-handshake");
pub(crate) const REPLAY_REJECTED: Urn<'static> = Urn::new("test", "event:replay-attack/replay-rejected");

tb_assert_spec! {
	pub ReplayAttackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(REPLAY_INIT_HANDSHAKE, exactly!(BACKEND_COUNT_U32)),
			(REPLAY_ATTEMPT, exactly!(BACKEND_COUNT_U32)),
			(REPLAY_DETECTED, exactly!(BACKEND_COUNT_U32)),
			(REPLAY_REJECTED, exactly!(BACKEND_COUNT_U32))
		]
	}
}

tb_process_spec! {
	pub ReplayAttackProcess,
	events {
		observable {

			REPLAY_INIT_HANDSHAKE,
			REPLAY_ATTEMPT,
			REPLAY_DETECTED,
			REPLAY_REJECTED,
			SecurityThreatHarness::HARNESS_SPAWN_SESSION,
			SecurityThreatHarness::HARNESS_SPAWN_ECIES,
			SecurityThreatHarness::HARNESS_SPAWN_CMS
		}
		hidden { }
	}
	states {
		Idle => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => Spawning },
		Spawning => {
			SecurityThreatHarness::HARNESS_SPAWN_ECIES => SessionReady,
			SecurityThreatHarness::HARNESS_SPAWN_CMS => SessionReady
		},
		SessionReady => { REPLAY_INIT_HANDSHAKE => Established },
		Established => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => SpawningAttack },
		SpawningAttack => {
			SecurityThreatHarness::HARNESS_SPAWN_ECIES => AttackSessionReady,
			SecurityThreatHarness::HARNESS_SPAWN_CMS => AttackSessionReady
		},
		AttackSessionReady => { REPLAY_ATTEMPT => AttackObserved },
		AttackObserved => { REPLAY_DETECTED => ReplaySuppressed },
		ReplaySuppressed => { REPLAY_REJECTED => Idle }
	}
	terminal { Idle }
	annotations { description: "Replay attack detection state machine" }
}

tb_scenario! {
	name: replay_attack,
	config: ScenarioConfig::builder()
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

			trace.event(REPLAY_INIT_HANDSHAKE)?;

			// Get the final client message (replay target for all backends)
			let target = captured
				.final_client_message()
				.ok_or_else(|| expectation_failure("no client messages captured"))?;

			// Attempt replay on a fresh session
			let mut attack_session = harness.spawn(captured.kind);

			trace.event(REPLAY_ATTEMPT)?;

			match attack_session.inject_at_step(target.step, &target.payload).await? {
				InjectionOutcome::Rejected(_) => {
					trace.event(REPLAY_DETECTED)?;
					trace.event(REPLAY_REJECTED)?;
				}
				InjectionOutcome::Accepted => {
					return Err(expectation_failure("replay was accepted"));
				}
			}
		}

		Ok(())
	}
}
