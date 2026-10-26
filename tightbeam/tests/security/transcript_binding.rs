//! # Transcript-binding downgrade threat
//!
//! ## Weakness
//! Suppose the HPKE reply signs a transcript that omits the negotiated
//! `security_accept` and covers only
//! `client_random || server_random || server_public_key`. The signed transcript
//! then leaves the chosen profile unauthenticated, so negotiation is unbound.
//!
//! Likewise, if the transcript binds only the client *random* and omits the
//! full `ClientHello`, an attacker can rewrite the client's `SecurityOffer`
//! in transit.
//!
//! ## Attack
//! 1. An adversary-in-the-middle rewrites `security_accept` inside the reply's
//!    `ServerHandshake` to a weaker profile in transit. The randoms, the
//!    certificate, and the server signature stay untouched, so the signature
//!    over an unbound transcript verifies, and a client that offered the
//!    weaker profile adopts it.
//! 2. The MITM strips or rewrites the `SecurityOffer` inside `ClientHello`
//!    and keeps `client_random`. The server signs a transcript over the
//!    modified hello. If the client bound only its random, the signature
//!    verifies, so negotiation ran over an offer the client never made.
//!
//! The live client of this scenario sends no `SecurityOffer`, and its server
//! runs the strong profile alone. So no endpoint offers the weak profile of
//! step 1, and the rewrite of step 2 adds an offer of the strong profile. A
//! transcript that leaves out the accept or the hello lets the reply signature
//! verify, so the scenario fails on its count of `signature` refusals.
//!
//! ## Expected control
//! The signed transcript MUST authenticate the negotiated parameters. The
//! client MUST reject a `security_accept` it did not receive under signature,
//! and MUST reject a server signature computed over a `ClientHello` that
//! differs from the exact DER bytes it sent (TLS-style full-message binding).
//!
//! Each case fails the signature of the reply (`SignatureVerificationFailed`).
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
	transport::handshake::{
		negotiation::{SecurityAccept, SecurityOffer},
		ClientHello, HandshakeMessage,
	},
	transport::wire_der::WireDer,
	TightBeamError,
};

use crate::common::security::{
	carried_hello, expectation_failure, hello_opening, rewritten_reply, signed_handshake, strong_security_profile,
	weak_security_profile, ServerMaterials,
};
use crate::security::common::HandshakeBackendKind;
use crate::security::live::{AttackStep, FrameEdit, FrameSlot, LiveHandshake, OPENING_FRAME, REPLY_FRAME};

tb_assert_spec! {
	pub TranscriptBindingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(2u32), equals!("signature"))
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
		Idle => { events::SESSION_CERT_REJECTED => AcceptBound },
		AcceptBound => { events::SESSION_CERT_REJECTED => Done },
		Done => { }
	}
	terminal { Done }
	annotations { description: "Transcript binding: negotiated profile and client offer must be authenticated" }
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

/// `reply` with its `security_accept` rewritten to the weak profile. The
/// randoms, the certificate, and the signature stay unchanged.
fn weaken_accept(reply: HandshakeMessage) -> Result<HandshakeMessage, TightBeamError> {
	let mut server_handshake = signed_handshake(reply.to_owned());
	let accepted = server_handshake.security_accept.as_ref().map(|accept| accept.value().profile);
	if accepted != Some(strong_security_profile()) {
		return Err(expectation_failure("server must select the strong profile"));
	}

	server_handshake.security_accept = Some(WireDer::new(SecurityAccept::new(weak_security_profile()))?);
	Ok(rewritten_reply(reply, &server_handshake))
}

/// `opening` with the `SecurityOffer` field of its ClientHello set to an
/// offer of the strong profile alone. The rewrite keeps `client_random` and
/// the client ephemeral.
fn rewrite_offer(opening: HandshakeMessage) -> Result<HandshakeMessage, TightBeamError> {
	let client_hello = carried_hello(opening);
	let mut rewritten = ClientHello::from_der(&client_hello)?;
	rewritten.security_offer = Some(SecurityOffer::new(vec![strong_security_profile()]));
	if rewritten.to_der()? == client_hello {
		return Err(expectation_failure("offer rewriting must change ClientHello bytes"));
	}

	Ok(hello_opening(&rewritten))
}

/// A live HPKE handshake over `materials` whose relay applies `rewrite` to
/// the frame at `slot`, and whose client files its verdict in `trace`.
fn rewritten_at(
	materials: &ServerMaterials,
	trace: &TraceCollector,
	slot: FrameSlot,
	rewrite: fn(HandshakeMessage) -> Result<HandshakeMessage, TightBeamError>,
) -> LiveHandshake {
	let step = AttackStep::new(slot, FrameEdit::Rewrite(Box::new(rewrite)));
	let handshake = LiveHandshake::new(HandshakeBackendKind::Hpke, materials.to_owned());
	handshake.audit_client(trace).with_step(step)
}

job! {
	name: TranscriptBindingScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let materials = ServerMaterials::generate();

		// Phase 1: A MITM downgrade swaps the accepted profile. The reply signs
		// a transcript that differs from the client's, so its signature fails.
		let outcome = rewritten_at(&materials, &trace, REPLY_FRAME, weaken_accept).run().await?;
		outcome.refused_by_client("client accepted a tampered, unauthenticated security_accept")?;

		// Phase 2: A MITM rewrites the SecurityOffer field of the ClientHello.
		// A random-only transcript would verify over the rewrite, so the
		// binding of the full ClientHello DER must make the client reject it.
		let outcome = rewritten_at(&materials, &trace, OPENING_FRAME, rewrite_offer).run().await?;
		outcome.refused_by_client("client accepted a signature over a rewritten ClientHello")
	}
}
