//! # Transcript-binding downgrade threat
//!
//! ## Weakness
//! If the ECIES handshake transcript omits the negotiated `security_accept` -
//! covering only `client_random || server_random || server_spki` - the signed
//! transcript does not authenticate the chosen profile, leaving negotiation
//! unbound. Likewise, if only the client *random* (not the full `ClientHello`)
//! is bound, the client's `SecurityOffer` can be rewritten in transit.
//!
//! ## Attack
//! 1. An adversary-in-the-middle rewrites `security_accept` to a weaker (still
//!    offered) profile in transit. Randoms, certificate, and server signature
//!    are untouched, so the transcript still verifies and the client silently
//!    adopts the weaker profile.
//! 2. The MITM strips or rewrites the `SecurityOffer` inside `ClientHello`
//!    while preserving `client_random`. The server signs a transcript over the
//!    modified hello; if the client only bound its random, the signature still
//!    verifies and negotiation happened over an offer the client never made.
//!
//! ## Expected control
//! Negotiated parameters MUST be authenticated by the signed transcript. The
//! client MUST reject a `security_accept` it did not receive under signature,
//! and MUST reject a server signature computed over a `ClientHello` that
//! differs from the exact DER bytes it sent (TLS-style full-message binding).
//!
//! ## References
//! - CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')
//!   <https://cwe.mitre.org/data/definitions/757.html>
//! - CWE-300: Channel Accessible by Non-Endpoint
//!   <https://cwe.mitre.org/data/definitions/300.html>
//! - CAPEC-220: Client-Server Protocol Manipulation
//!   <https://capec.mitre.org/data/definitions/220.html>
//! - RFC 9846 (TLS 1.3) §4.1.3: downgrade protection

use std::sync::Arc;

use tightbeam::{
	crypto::{ecies::Secp256k1EciesMessage, profiles::DefaultCryptoProvider, profiles::SecurityProfileDesc},
	der::{Decode, Encode},
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	transport::handshake::{
		client::EciesHandshakeClient,
		negotiation::{SecurityAccept, SecurityOffer},
		server::EciesHandshakeServer,
		ClientHello, ServerHandshake,
	},
	utils::urn::Urn,
	TightBeamError,
};

use crate::common::security::{
	expectation_failure, pinning_validator, strong_security_profile, weak_security_profile, ServerMaterials,
};

pub(crate) const STRIPPED_OFFER_REJECTED: Urn<'static> =
	Urn::new("test", "event:transcript-binding/stripped-offer-rejected");
pub(crate) const TAMPERED_ACCEPT_REJECTED: Urn<'static> =
	Urn::new("test", "event:transcript-binding/tampered-accept-rejected");

type EciesClient = EciesHandshakeClient<DefaultCryptoProvider, Secp256k1EciesMessage>;
type EciesServer = EciesHandshakeServer<DefaultCryptoProvider>;

tb_assert_spec! {
	pub TranscriptBindingSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
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

	let client = EciesHandshakeClient::<DefaultCryptoProvider, Secp256k1EciesMessage>::new(None)
		.with_security_offer(SecurityOffer::new(vec![strong, weak]))
		.with_certificate_validator(validator);

	let server = EciesHandshakeServer::<DefaultCryptoProvider>::new(
		Arc::clone(&materials.key_provider),
		Arc::clone(&materials.certificate),
		None,
		None,
	)
	.with_supported_profiles(vec![strong, weak]);

	(client, server, strong, weak)
}

async fn expect_client_reject<E>(
	result: Result<Vec<u8>, E>,
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

		// Phase 1: MITM downgrade: swap accepted profile without touching
		// randoms, cert, or signature.
		let (mut client, mut server, strong, weak) = strong_weak_pair(&materials);
		let client_hello = client.build_client_hello()?;
		let server_handshake_der = server.process_client_hello(&client_hello).await?;

		let mut server_handshake = ServerHandshake::from_der(&server_handshake_der)?;
		assert_eq!(
			server_handshake.security_accept.as_ref().map(|a| a.profile),
			Some(strong),
			"server must select the strong profile"
		);

		server_handshake.security_accept = Some(SecurityAccept::new(weak));

		let tampered = server_handshake.to_der()?;
		expect_client_reject(
			client.process_server_handshake(&tampered).await,
			&trace,
			TAMPERED_ACCEPT_REJECTED,
			"client accepted a tampered, unauthenticated security_accept",
		)
		.await?;

		// Phase 2: MITM strips SecurityOffer from ClientHello.
		// client_random is preserved, so a random-only transcript would still
		// verify. The full ClientHello DER binding must make the client reject.
		let (mut client, mut server, _strong, _weak) = strong_weak_pair(&materials);
		let client_hello = client.build_client_hello()?;
		let mut stripped_hello = ClientHello::from_der(&client_hello)?;
		stripped_hello.security_offer = None;

		let stripped_hello = stripped_hello.to_der()?;
		assert_ne!(
			stripped_hello, client_hello,
			"offer stripping must change ClientHello bytes"
		);

		let server_handshake_der = server.process_client_hello(&stripped_hello).await?;
		expect_client_reject(
			client.process_server_handshake(&server_handshake_der).await,
			&trace,
			STRIPPED_OFFER_REJECTED,
			"client accepted a signature over a rewritten ClientHello",
		)
		.await?;

		Ok(())
	}
}
