//! # Handshake replay threat
//!
//! ## Weakness
//! An attacker could replay captured handshake messages to establish an
//! unauthorized session if completed handshakes are not bound to fresh,
//! single-use state.
//!
//! ## Attack
//! An attacker captures a valid client handshake message and re-sends it to
//! the server (on every enabled backend: HPKE, CMS).
//!
//! ## Expected control
//! The server MUST reject a replayed handshake message. The closing seals
//! under a key of its own handshake and authenticates that handshake's
//! transcript hash, so a fresh session MUST refuse a replayed closing by that
//! binding (`SealedClosing(AuthenticatedAttribute)`).
//!
//! ## References
//! - CWE-294: Authentication Bypass by Capture-replay <https://cwe.mitre.org/data/definitions/294.html>
//! - CAPEC-60: Reusing Session IDs (aka Session Replay) <https://capec.mitre.org/data/definitions/60.html>

use std::sync::Arc;

use tightbeam::{
	exactly,
	instrumentation::events,
	job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	urn::Urn,
	TightBeamError,
};

use crate::security::common::{expectation_failure, HandshakeBackendKind, SecurityThreatHarness};

#[cfg(feature = "testing-fault")]
use tightbeam::testing::{error::TestingError, FaultModel};

pub(crate) const REPLAY_ATTEMPT: Urn<'static> = tightbeam::urn!("test", "event:replay-attack/replay-attempt");
pub(crate) const REPLAY_INIT_HANDSHAKE: Urn<'static> =
	tightbeam::urn!("test", "event:replay-attack/replay-initial-handshake");

tb_assert_spec! {
	pub ReplayAttackSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(REPLAY_INIT_HANDSHAKE, exactly!(1)),
			(REPLAY_ATTEMPT, exactly!(1)),
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("sealed-closing/authenticated-attribute"))
		]
	}
}

tb_process_spec! {
	pub ReplayAttackProcess,
	events {
		observable {

			REPLAY_INIT_HANDSHAKE,
			REPLAY_ATTEMPT,
			events::SESSION_CERT_REJECTED,
			SecurityThreatHarness::HARNESS_SPAWN_SESSION,
			SecurityThreatHarness::HARNESS_SPAWN_HPKE,
			SecurityThreatHarness::HARNESS_SPAWN_CMS
		}
		hidden { }
	}
	states {
		Idle => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => Spawning },
		Spawning => {
			SecurityThreatHarness::HARNESS_SPAWN_HPKE => SessionReady,
			SecurityThreatHarness::HARNESS_SPAWN_CMS => SessionReady
		},
		SessionReady => { REPLAY_INIT_HANDSHAKE => Established },
		Established => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => SpawningAttack },
		SpawningAttack => {
			SecurityThreatHarness::HARNESS_SPAWN_HPKE => AttackSessionReady,
			SecurityThreatHarness::HARNESS_SPAWN_CMS => AttackSessionReady
		},
		AttackSessionReady => { REPLAY_ATTEMPT => AttackObserved },
		AttackObserved => { events::SESSION_CERT_REJECTED => Idle }
	}
	terminal { Idle }
	annotations { description: "Replay attack detection state machine" }
}

tb_scenario! {
	name: replay_attack_hpke,
	config: ScenarioConfig::builder()
		.with_spec(ReplayAttackSpec::latest())
		.with_csp(ReplayAttackProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			ReplayAttackScenario::run((trace.into(), HandshakeBackendKind::Hpke)).await
		}
	}
}

#[cfg(feature = "transport-cms")]
tb_scenario! {
	name: replay_attack_cms,
	config: ScenarioConfig::builder()
		.with_spec(ReplayAttackSpec::latest())
		.with_csp(ReplayAttackProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			ReplayAttackScenario::run((trace.into(), HandshakeBackendKind::Cms)).await
		}
	}
}

job! {
	name: ReplayAttackScenario,
	async fn run((trace, kind): (Arc<TraceCollector>, HandshakeBackendKind)) -> Result<(), TightBeamError> {
		let harness = SecurityThreatHarness::with_trace(Arc::clone(&trace));

		// Capture a complete handshake.
		let mut session = harness.spawn(kind)?;
		let captured = session.capture_full().await?;

		trace.event(REPLAY_INIT_HANDSHAKE)?;

		// The final client message is the replay target on every backend.
		let target = captured
			.final_client_message()
			.ok_or_else(|| expectation_failure("no client messages captured"))?;

		// Attempt the replay on a live handshake, whose server files its
		// verdict in the scenario trace.
		let injection = captured.kind.replacement(target.step, &target.payload)?;
		let attack = harness.live(captured.kind)?.audit_server(&trace).with_step(injection);

		trace.event(REPLAY_ATTEMPT)?;

		// The closing authenticates the transcript of the session that
		// sealed it, so the fresh session refuses it by that binding.
		let outcome = attack.run().await?;
		outcome.refused_by_server("replay was accepted")
	}
}

/// A fault that the trace injects at the spawn of a session fails the
/// scenario that spawns it, with the injected error.
#[cfg(feature = "testing-fault")]
#[tokio::test]
async fn a_fault_at_the_session_spawn_fails_the_scenario() -> Result<(), Box<dyn std::error::Error>> {
	let spawn = SecurityThreatHarness::HARNESS_SPAWN_SESSION;
	let fault = || TestingError::InvariantViolated;
	let model = FaultModel::default().with_event_fault(spawn, fault, tightbeam::bps!(10000));
	let trace = Arc::new(TraceCollector::new().with_fault_model(model));

	let outcome = ReplayAttackScenario::run((trace, HandshakeBackendKind::Hpke)).await;
	let injected = matches!(outcome, Err(TightBeamError::TestingError(TestingError::InvariantViolated)));
	assert!(injected);
	Ok(())
}
