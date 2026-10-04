//! # Transcript-binding downgrade threat
//!
//! ## Weakness
//! Suppose the ECIES handshake transcript omits the negotiated
//! `security_accept` and covers only
//! `client_random || server_random || server_spki`. The signed transcript
//! then leaves the chosen profile unauthenticated, so negotiation is unbound.
//!
//! Likewise, if the transcript binds only the client *random* and omits the
//! full `ClientHello`, the client's `SecurityOffer` can be rewritten in
//! transit.
//!
//! ## Attack
//! 1. An adversary-in-the-middle rewrites `security_accept` to a weaker (still
//!    offered) profile in transit. Randoms, certificate, and server signature
//!    are untouched, so the transcript still verifies and the client silently
//!    adopts the weaker profile.
//! 2. The MITM strips or rewrites the `SecurityOffer` inside `ClientHello`
//!    while preserving `client_random`. The server signs a transcript over the
//!    modified hello. If the client bound only its random, the signature still
//!    verifies and negotiation happened over an offer the client never made.
//!
//! ## Expected control
//! Negotiated parameters MUST be authenticated by the signed transcript. The
//! client MUST reject a `security_accept` it did not receive under signature,
//! and MUST reject a server signature computed over a `ClientHello` that
//! differs from the exact DER bytes it sent (TLS-style full-message binding).
//!
//! ## References
//! - CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm
//!   Downgrade') <https://cwe.mitre.org/data/definitions/757.html>
//! - CWE-300: Channel Accessible by Non-Endpoint <https://cwe.mitre.org/data/definitions/300.html>
//! - CAPEC-220: Client-Server Protocol Manipulation <https://capec.mitre.org/data/definitions/220.html>
//! - RFC 9846 (TLS 1.3) §4.1.3: downgrade protection

use std::sync::Arc;

use tightbeam::{
	crypto::{profiles::DefaultCryptoProvider, profiles::SecurityProfileDesc},
	der::{Decode, Encode},
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	transport::handshake::{
		negotiation::{SecurityAccept, SecurityOffer},
		Client, ClientHello, Ecies, Handshake, Server,
	},
	transport::wire_der::WireDer,
	utils::urn::Urn,
	TightBeamError,
};

use crate::common::security::{
	ecies_client_config, ecies_server_config, expectation_failure, pinning_validator, strong_security_profile,
	tunneled_handshake, tunneled_hello, tunneled_opening, tunneled_reply, weak_security_profile, ServerMaterials,
};

pub(crate) const STRIPPED_OFFER_REJECTED: Urn<'static> =
	tightbeam::urn!("test", "event:transcript-binding/stripped-offer-rejected");
pub(crate) const TAMPERED_ACCEPT_REJECTED: Urn<'static> =
	tightbeam::urn!("test", "event:transcript-binding/tampered-accept-rejected");

type EciesClient = Handshake<Client, Ecies, DefaultCryptoProvider>;
type EciesServer = Handshake<Server, Ecies, DefaultCryptoProvider>;

tb_assert_spec! {
	pub TranscriptBindingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(TAMPERED_ACCEPT_REJECTED, exactly!(1u32)),
			(STRIPPED_OFFER_REJECTED, exactly!(1u32))
		]
	}
}

tb_process_spec! {
	pub TranscriptBindingProcess,
	events {
		observable { TAMPERED_ACCEPT_REJECTED, STRIPPED_OFFER_REJECTED }
		hidden { }
	}
	states {
		Idle => { TAMPERED_ACCEPT_REJECTED => AcceptBound },
		AcceptBound => { STRIPPED_OFFER_REJECTED => Done },
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

fn strong_weak_pair(
	materials: &ServerMaterials,
) -> (EciesClient, EciesServer, SecurityProfileDesc, SecurityProfileDesc) {
	let strong = strong_security_profile();
	let weak = weak_security_profile();
	let validator = pinning_validator(&materials.certificate);

	let mut config = ecies_client_config(validator);
	config.security_offer = Some(SecurityOffer::new(vec![strong, weak]));

	let client = Handshake::client(config);
	let server = Handshake::server(ecies_server_config(materials, [strong, weak]));

	(client, server, strong, weak)
}

async fn expect_client_reject<T, E>(
	result: Result<T, E>,
	trace: &TraceCollector,
	event: Urn<'static>,
	on_accept: &'static str,
) -> Result<(), TightBeamError> {
	match result {
		Err(_) => {
			trace.event(event)?;
			Ok(())
		}
		Ok(_) => Err(expectation_failure(on_accept)),
	}
}

job! {
	name: TranscriptBindingScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let materials = ServerMaterials::generate();

		// Phase 1: A MITM downgrade swaps the accepted profile without
		// touching the randoms, the certificate, or the signature.
		let (mut client, mut server, strong, weak) = strong_weak_pair(&materials);
		let reply = server.reply(client.start()?).await?;

		let mut server_handshake = tunneled_handshake(reply);
		assert_eq!(
			server_handshake.security_accept.as_ref().map(|accept| accept.value().profile),
			Some(strong),
			"server must select the strong profile"
		);

		server_handshake.security_accept = Some(WireDer::new(SecurityAccept::new(weak))?);

		let tampered = tunneled_reply(&server_handshake);
		expect_client_reject(
			client.respond(tampered).await,
			&trace,
			TAMPERED_ACCEPT_REJECTED,
			"client accepted a tampered, unauthenticated security_accept",
		)
		.await?;

		// Phase 2: A MITM strips the SecurityOffer from the ClientHello. The
		// client_random is preserved, so a random-only transcript would still
		// verify. The full ClientHello DER binding must make the client reject.
		let (mut client, mut server, _strong, _weak) = strong_weak_pair(&materials);
		let client_hello = tunneled_hello(client.start()?);
		let mut stripped_hello = ClientHello::from_der(&client_hello)?;
		stripped_hello.security_offer = None;
		assert_ne!(
			stripped_hello.to_der()?,
			client_hello,
			"offer stripping must change ClientHello bytes"
		);

		let reply = server.reply(tunneled_opening(&stripped_hello)).await?;
		expect_client_reject(
			client.respond(reply).await,
			&trace,
			STRIPPED_OFFER_REJECTED,
			"client accepted a signature over a rewritten ClientHello",
		)
		.await?;

		Ok(())
	}
}
