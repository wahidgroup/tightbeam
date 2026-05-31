//! # Transcript-binding downgrade threat
//!
//! ## Weakness
//! If the ECIES handshake transcript omits the negotiated `security_accept` -
//! covering only `client_random || server_random || server_spki` - the signed
//! transcript does not authenticate the chosen profile, leaving negotiation
//! unbound.
//!
//! ## Attack
//! An adversary-in-the-middle rewrites `security_accept` to a weaker (still
//! offered) profile in transit. Randoms, certificate, and server signature are
//! untouched, so the transcript still verifies and the client silently adopts
//! the weaker profile.
//!
//! ## Expected control
//! Negotiated parameters MUST be authenticated by the signed transcript. The
//! client MUST reject a `security_accept` it did not receive under signature.
//!
//! ## References
//! - CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')
//!   <https://cwe.mitre.org/data/definitions/757.html>
//! - CWE-300: Channel Accessible by Non-Endpoint
//!   <https://cwe.mitre.org/data/definitions/300.html>
//! - CAPEC-220: Client-Server Protocol Manipulation
//!   <https://capec.mitre.org/data/definitions/220.html>
//! - RFC 8446 (TLS 1.3) §4.1.3: downgrade protection (analogous control)

use std::sync::Arc;

use tightbeam::{
	crypto::{ecies::Secp256k1EciesMessage, profiles::DefaultCryptoProvider},
	der::{Decode, Encode},
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::ScenarioConf,
	trace::TraceCollector,
	transport::handshake::{
		client::EciesHandshakeClient,
		negotiation::{SecurityAccept, SecurityOffer},
		server::EciesHandshakeServer,
		ServerHandshake,
	},
	TightBeamError,
};

use crate::common::security::{expectation_failure, strong_security_profile, weak_security_profile, ServerMaterials};

tb_assert_spec! {
	pub TranscriptBindingSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("tampered_accept_rejected", exactly!(1u32))
		]
	}
}

tb_process_spec! {
	pub TranscriptBindingProcess,
	events {
		observable { "tampered_accept_rejected" }
		hidden { }
	}
	states {
		Idle => { "tampered_accept_rejected" => Done },
		Done => { }
	}
	terminal { Done }
	annotations { description: "Transcript binding: negotiated profile must be authenticated" }
}

tb_scenario! {
	name: transcript_binding,
	config: ScenarioConf::<()>::builder()
		.with_spec(TranscriptBindingSpec::latest())
		.with_csp(TranscriptBindingProcess)
		.build(),
	environment Bare {
		exec: |trace| async move {
			TranscriptBindingScenario::run((trace,)).await
		}
	}
}

job! {
	name: TranscriptBindingScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let materials = ServerMaterials::generate();
		let strong = strong_security_profile();
		let weak = weak_security_profile();

		let mut client = EciesHandshakeClient::<DefaultCryptoProvider, Secp256k1EciesMessage>::new(None)
			.with_security_offer(SecurityOffer::new(vec![strong, weak]));

		let mut server = EciesHandshakeServer::<DefaultCryptoProvider>::new(
			Arc::clone(&materials.key_provider),
			Arc::clone(&materials.certificate),
			None,
			None,
		)
		.with_supported_profiles(vec![strong, weak]);

		let client_hello = client.build_client_hello()?;
		let server_handshake_der = server.process_client_hello(&client_hello).await?;

		// MITM downgrade: swap the accepted profile without touching randoms, cert, or signature.
		let mut server_handshake = ServerHandshake::from_der(&server_handshake_der)?;
		if server_handshake.security_accept.as_ref().map(|a| a.profile) != Some(strong) {
			return Err(expectation_failure("server did not select the strong profile"));
		}

		server_handshake.security_accept = Some(SecurityAccept::new(weak));

		let tampered = server_handshake.to_der()?;
		match client.process_server_handshake(&tampered).await {
			Err(_) => {
				trace.event("tampered_accept_rejected")?;
			}
			Ok(_) => return Err(expectation_failure("client accepted a tampered, unauthenticated security_accept")),
		}

		Ok(())
	}
}
