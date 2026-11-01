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
//! The server signs the content of its reply, and the client verifies that
//! signature against the server certificate. Any change to the content MUST
//! fail that signature: the tampered `ServerHandshake` for HPKE and the
//! tampered content of the server `Finished` for CMS. The transcript inside
//! the signature is the control of `nonce_reuse` and `transcript_binding`.
//!
//! A reply that a MITM decodes and encodes unchanged completes the handshake,
//! so the refusal comes from the tamper and from no re-encoding.
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

use crate::common::security::ServerMaterials;
use crate::security::common::{HandshakeBackendKind, SecurityThreatHarness};
use crate::security::live::{AttackStep, FrameEdit, LiveHandshake, REPLY_FRAME};

pub(crate) const MITM_INJECT_TAMPERED: Urn<'static> = tightbeam::urn!("test", "event:mitm-attack/mitm-inject-tampered");

tb_assert_spec! {
	pub MitmAttackSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(MITM_INJECT_TAMPERED, exactly!(1)),
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("signature"))
		]
	}
}

tb_process_spec! {
	pub MitmAttackProcess,
	events {
		observable {

			MITM_INJECT_TAMPERED,
			events::SESSION_CERT_REJECTED,
			SecurityThreatHarness::HARNESS_SPAWN_SESSION,
			SecurityThreatHarness::HARNESS_SPAWN_HPKE,
			SecurityThreatHarness::HARNESS_SPAWN_CMS
		}
		hidden { }
	}
	states {
		Idle => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => SpawningAttack },
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

		// The relay tampers the reply of the live session in transit, so the
		// reply stays bound to the transcript of the client that reads it.
		let tamper = kind.tamper_reply()?;
		let attack = harness.live(kind)?.audit_client(&trace).with_step(tamper);

		trace.event(MITM_INJECT_TAMPERED)?;

		// The tampered message differs from the one the sender signed, so its
		// signature fails, and acceptance means the control missed the tamper.
		let outcome = attack.run().await?;
		outcome.refused_by_client("tampered message was accepted")
	}
}

tb_assert_spec! {
	pub ReEncodedReplySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2))
		]
	}
}

/// A MITM that decodes the reply of `kind` and encodes it unchanged sends a
/// reply that completes the handshake on both endpoints. It is the control of
/// the tampers of this module: their refusals come from the tamper and from no
/// re-encoding of a decoded reply.
async fn a_re_encoded_reply_completes(
	trace: &TraceCollector,
	kind: HandshakeBackendKind,
) -> Result<(), TightBeamError> {
	let re_encode = FrameEdit::Rewrite(Box::new(move |reply| kind.re_encoded_reply(reply)));
	let handshake = LiveHandshake::new(kind, ServerMaterials::fixed())
		.audit_client(trace)
		.audit_server(trace);

	let outcome = handshake.with_step(AttackStep::new(REPLY_FRAME, re_encode)).run().await?;
	outcome.established().map(drop)
}

tb_scenario! {
	name: a_re_encoded_hpke_reply_completes_the_handshake,
	spec: ReEncodedReplySpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			a_re_encoded_reply_completes(&trace, HandshakeBackendKind::Hpke).await
		}
	}
}

#[cfg(feature = "transport-cms")]
tb_scenario! {
	name: a_re_encoded_cms_reply_completes_the_handshake,
	spec: ReEncodedReplySpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			a_re_encoded_reply_completes(&trace, HandshakeBackendKind::Cms).await
		}
	}
}
