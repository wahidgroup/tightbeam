//! # Transcript-binding downgrade threat
//!
//! ## Weakness
//! The `security_accept` of an HPKE reply travels inside the `ServerHandshake`
//! that the reply signs as its content, so the reply signature refuses a
//! swapped accept, and the transcript adds nothing there.
//!
//! The offer is another matter: if the transcript binds only the client
//! *random* and omits the full `ClientHello`, a MITM can forge the client's
//! `SecurityOffer` in transit, and the server signs a transcript over the hello
//! it received.
//!
//! ## Attack
//! The MITM changes the `SecurityOffer` inside `ClientHello` and keeps
//! `client_random` and the client ephemeral.
//!
//! The live client of this scenario sends no `SecurityOffer`, and its server
//! runs the strong profile alone, so the MITM adds an offer of that profile,
//! and the server selects what it selects without one. The reply then differs
//! from an honest run in its transcript alone.
//!
//! ## Expected control
//! The signed transcript MUST authenticate the hello as the client sent it, so
//! the client MUST reject a server signature computed over a `ClientHello`
//! that differs from the exact DER bytes it sent (TLS-style full-message
//! binding). The refusal is `SignatureVerificationFailed`.
//!
//! A transcript that leaves out the hello lets the reply signature verify and
//! the handshake complete, which the scenario fails on.
//!
//! ## References
//! - CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm
//!   Downgrade') <https://cwe.mitre.org/data/definitions/757.html>
//! - CWE-300: Channel Accessible by Non-Endpoint <https://cwe.mitre.org/data/definitions/300.html>
//! - CAPEC-220: Client-Server Protocol Manipulation <https://capec.mitre.org/data/definitions/220.html>
//! - RFC 9846 (TLS 1.3) §4.1.3: downgrade protection

use std::sync::Arc;

use tightbeam::{
	der::{Decode, Encode},
	exactly,
	instrumentation::events,
	job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	transport::handshake::{negotiation::SecurityOffer, ClientHello, HandshakeMessage},
	TightBeamError,
};

use crate::common::security::{carried_hello, expectation_failure, hello_opening, ServerMaterials};
use crate::security::common::{strong_security_profile, HandshakeBackendKind};
use crate::security::live::{AttackStep, FrameEdit, LiveHandshake, OPENING_FRAME};

tb_assert_spec! {
	pub TranscriptBindingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("signature"))
		]
	}
}

tb_process_spec! {
	pub TranscriptBindingProcess,
	events {
		observable { events::SESSION_CERT_REJECTED }
		hidden { }
	}
	states {
		Idle => { events::SESSION_CERT_REJECTED => Done },
		Done => { }
	}
	terminal { Done }
	annotations { description: "Transcript binding: the client offer must be authenticated" }
}

tb_scenario! {
	name: transcript_binding,
	config: ScenarioConfig::builder()
		.with_spec(TranscriptBindingSpec::latest())
		.with_csp(TranscriptBindingProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			TranscriptBindingScenario::run((trace.into(),)).await
		}
	}
}

/// `opening` with the `SecurityOffer` field of its ClientHello set to an
/// offer of the strong profile alone, as a MITM forges it. The hello keeps its
/// `client_random` and its client ephemeral.
fn forge_offer(opening: HandshakeMessage) -> Result<HandshakeMessage, TightBeamError> {
	let client_hello = carried_hello(opening);
	let mut forged = ClientHello::from_der(&client_hello)?;
	forged.security_offer = Some(SecurityOffer::new(vec![strong_security_profile()]));
	if forged.to_der()? == client_hello {
		return Err(expectation_failure("the forged offer must change the ClientHello bytes"));
	}

	Ok(hello_opening(&forged))
}

/// A live HPKE handshake over `materials` whose relay forges the opening
/// through `forge`, and whose client files its verdict in `trace`.
fn forged_opening(
	materials: &ServerMaterials,
	trace: &TraceCollector,
	forge: fn(HandshakeMessage) -> Result<HandshakeMessage, TightBeamError>,
) -> LiveHandshake {
	let step = AttackStep::new(OPENING_FRAME, FrameEdit::Rewrite(Box::new(forge)));
	let handshake = LiveHandshake::new(HandshakeBackendKind::Hpke, materials.to_owned());
	handshake.audit_client(trace).with_step(step)
}

job! {
	name: TranscriptBindingScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let materials = ServerMaterials::fixed();

		// A MITM changes the SecurityOffer field of the ClientHello. The
		// transcript binds the full ClientHello DER, so the client refuses.
		let outcome = forged_opening(&materials, &trace, forge_offer).run().await?;
		outcome.refused_by_client("client accepted a signature over a forged ClientHello")
	}
}
