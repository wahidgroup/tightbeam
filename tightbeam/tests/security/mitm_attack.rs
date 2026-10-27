//! # Man-in-the-middle tampering threat
//!
//! ## Weakness
//! A MITM can modify, without detection, a handshake message in transit that
//! is not integrity-bound to a verified transcript.
//!
//! ## Attack
//! 1. The client and the server begin a handshake on every enabled backend (HPKE, CMS).
//! 2. A MITM intercepts and modifies a message in transit.
//! 3. The recipient processes the tampered message.
//!
//! ## Expected control
//! Both parties MUST sign `transcript_hash`, and each verifies the signature of
//! the other against its certificate. Any modification MUST cause a
//! signature-verification failure, on the tampered `ServerHandshake` the reply
//! signs for HPKE and on the tampered `Finished` `SignedData` for CMS.
//!
//! ## References
//! - CWE-300: Channel Accessible by Non-Endpoint <https://cwe.mitre.org/data/definitions/300.html>
//! - CAPEC-94: Adversary in the Middle (AiTM) <https://capec.mitre.org/data/definitions/94.html>
//! - RFC 9846 (TLS 1.3) §4.5.2 and §4.5.3: transcript-bound CertificateVerify and Finished

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

pub(crate) const MITM_CAPTURE_HANDSHAKE: Urn<'static> =
	tightbeam::urn!("test", "event:mitm-attack/mitm-capture-handshake");
pub(crate) const MITM_INJECT_TAMPERED: Urn<'static> = tightbeam::urn!("test", "event:mitm-attack/mitm-inject-tampered");
pub(crate) const MITM_TAMPER_MESSAGE: Urn<'static> = tightbeam::urn!("test", "event:mitm-attack/mitm-tamper-message");

tb_assert_spec! {
	pub MitmAttackSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(MITM_CAPTURE_HANDSHAKE, exactly!(1)),
			(MITM_TAMPER_MESSAGE, exactly!(1)),
			(MITM_INJECT_TAMPERED, exactly!(1)),
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("signature"))
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
			events::SESSION_CERT_REJECTED,
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
		CaptureReady => { MITM_CAPTURE_HANDSHAKE => Captured },
		Captured => { MITM_TAMPER_MESSAGE => Tampered },
		Tampered => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => SpawningAttack },
		SpawningAttack => {
			SecurityThreatHarness::HARNESS_SPAWN_HPKE => AttackReady,
			SecurityThreatHarness::HARNESS_SPAWN_CMS => AttackReady
		},
		AttackReady => { MITM_INJECT_TAMPERED => Injected },
		Injected => { events::SESSION_CERT_REJECTED => Idle }
	}
	terminal { Idle }
	annotations { description: "MITM attack: message tampering detection via transcript signatures" }
}

tb_scenario! {
	name: mitm_attack_hpke,
	config: ScenarioConfig::builder()
		.with_spec(MitmAttackSpec::latest())
		.with_csp(MitmAttackProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			MitmAttackScenario::run((trace.into(), HandshakeBackendKind::Hpke)).await
		}
	}
}

#[cfg(feature = "transport-cms")]
tb_scenario! {
	name: mitm_attack_cms,
	config: ScenarioConfig::builder()
		.with_spec(MitmAttackSpec::latest())
		.with_csp(MitmAttackProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			MitmAttackScenario::run((trace.into(), HandshakeBackendKind::Cms)).await
		}
	}
}

job! {
	name: MitmAttackScenario,
	async fn run((trace, kind): (Arc<TraceCollector>, HandshakeBackendKind)) -> Result<(), TightBeamError> {
		let harness = SecurityThreatHarness::with_trace(Arc::clone(&trace));

		// Step 1: Capture a complete handshake.
		let mut session = harness.spawn(kind)?;
		let captured = session.capture_full().await?;

		trace.event(MITM_CAPTURE_HANDSHAKE)?;

		// Step 2: Find a server-to-client message to tamper: the reply
		// (step 1) for HPKE, and the ServerFinished (step 2) for CMS.
		let target = captured.server_reply();
		let target = target.ok_or_else(|| expectation_failure("no server-to-client messages captured"))?;

		// The tamper models a MITM that modifies the message in transit.
		let tampered_payload = kind.tamper_server_message(&target.payload)?;

		// Only a changed payload puts the control under test.
		assert_ne!(tampered_payload, target.payload, "the tamper must change the payload");

		trace.event(MITM_TAMPER_MESSAGE)?;

		// Step 3: Inject the tampered message into a live handshake, whose
		// client files its verdict in the scenario trace.
		let injection = kind.replacement(target.step, &tampered_payload)?;
		let attack = harness.live(kind)?.audit_client(&trace).with_step(injection);

		trace.event(MITM_INJECT_TAMPERED)?;

		// The tampered message differs from the one the sender signed, so its
		// signature fails, and acceptance means the control missed the tamper.
		let outcome = attack.run().await?;
		outcome.refused_by_client("tampered message was accepted")
	}
}
