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
//! The server MUST reject a replayed handshake message. The closing carries
//! the transcript hash of its own handshake as an authenticated attribute, so
//! a fresh session refuses a replayed closing by that attribute
//! (`SealedClosing(AuthenticatedAttribute)`) before any key runs. The
//! `confidentiality` scenario shows the key of the seal.
//!
//! A closing that arrives again on the established session is a cleartext
//! container where the session admits sealed records alone, so the session
//! refuses it (`MissingEncryption`).
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
	transport::{EncryptedMessageIO, TransportError},
	urn::Urn,
	TightBeamError,
};

use crate::common::security::{expectation_failure, ServerMaterials};
use crate::security::common::{HandshakeBackendKind, SecurityThreatHarness};
use crate::security::live::{AttackStep, FrameEdit, LiveHandshake, CLOSING_FRAME};

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

tb_assert_spec! {
	pub ReplayedClosingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(1)),
			(events::TRANSPORT_ENVELOPE_REFUSED, exactly!(1), equals!("MissingEncryption"))
		]
	}
}

/// A live handshake of `kind` whose relay sends the closing twice. The server
/// completes the handshake on the first, and its session refuses the second
/// as a cleartext container where it admits sealed records alone.
async fn a_replayed_closing_on_an_established_session_is_refused(
	trace: &TraceCollector,
	kind: HandshakeBackendKind,
) -> Result<(), TightBeamError> {
	let replay = AttackStep::new(CLOSING_FRAME, FrameEdit::Duplicate);
	let handshake = LiveHandshake::new(kind, ServerMaterials::fixed())
		.audit_server(trace)
		.with_step(replay);
	let (_client, mut server) = handshake.run().await?.established()?;

	let refused = server.collect_step().await;
	assert!(matches!(refused, Err(TransportError::MissingEncryption)));
	Ok(())
}

tb_scenario! {
	name: a_replayed_hpke_closing_on_an_established_session_is_refused,
	spec: ReplayedClosingSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			a_replayed_closing_on_an_established_session_is_refused(&trace, HandshakeBackendKind::Hpke).await
		}
	}
}

#[cfg(feature = "transport-cms")]
tb_scenario! {
	name: a_replayed_cms_closing_on_an_established_session_is_refused,
	spec: ReplayedClosingSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			a_replayed_closing_on_an_established_session_is_refused(&trace, HandshakeBackendKind::Cms).await
		}
	}
}

/// A fault that the trace injects at the spawn of a session fails the
/// scenario that spawns it, with the injected error.
#[cfg(feature = "testing-fault")]
#[tokio::test]
async fn a_fault_at_the_session_spawn_fails_the_scenario() {
	let spawn = SecurityThreatHarness::HARNESS_SPAWN_SESSION;
	let fault = || TestingError::InvariantViolated;
	let model = FaultModel::default().with_event_fault(spawn, fault, tightbeam::bps!(10000));
	let trace = Arc::new(TraceCollector::new().with_fault_model(model));

	let outcome = ReplayAttackScenario::run((trace, HandshakeBackendKind::Hpke)).await;
	assert!(matches!(
		outcome,
		Err(TightBeamError::TestingError(TestingError::InvariantViolated))
	));
}
