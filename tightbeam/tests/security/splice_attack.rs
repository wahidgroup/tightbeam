//! # Identity splice threat (mutual authentication)
//!
//! ## Weakness
//! A client certificate is public. If a server admitted an offered certificate
//! without a signature by its key over this session, an attacker could splice
//! the certificate of a victim into a closing of its own. The server would then
//! attribute a session key the attacker holds to the identity of the victim.
//!
//! ## Attack
//! 1. The attacker holds the certificate of a victim, but not its signing key.
//! 2. The attacker runs a handshake of its own and offers the certificate of the victim as its identity.
//! 3. The attacker signs the possession proof under its own key.
//!
//! The closing seals the certificate and its proof under a key of the
//! handshake secret, so an attacker cannot lift the proof of a victim from a
//! recorded closing and splice it into its own.
//!
//! ## Expected control
//! The possession signature MUST verify under the key of the offered
//! certificate, over the digest of the domain, the transcript hash, the client
//! ephemeral, and the certificate DER. The closing of the attacker MUST fail
//! signature verification.
//!
//! ## References
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>
//! - CWE-300: Channel Accessible by Non-Endpoint <https://cwe.mitre.org/data/definitions/300.html>
//! - CAPEC-94: Adversary in the Middle (AiTM) <https://capec.mitre.org/data/definitions/94.html>

use std::sync::Arc;

use tightbeam::{
	crypto::{
		profiles::DefaultCryptoProvider,
		x509::policy::{CertificateValidation, ExpiryValidator},
	},
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	transport::handshake::{negotiation::SecurityOffer, Handshake, HandshakeError, PeerAuthentication},
	transport::state::ClientIdentity,
	urn::Urn,
	TightBeamError,
};

use crate::common::security::{
	default_security_profile, expectation_failure, hpke_client_config, hpke_server_config, pinning_validator,
	ClientMaterials, ServerMaterials,
};

pub(crate) const SPLICED_KEX_REJECTED: Urn<'static> =
	tightbeam::urn!("test", "event:splice-attack/spliced-kex-rejected");

tb_assert_spec! {
	pub SpliceAttackSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SPLICED_KEX_REJECTED, exactly!(1u32))
		]
	}
}

tb_process_spec! {
	pub SpliceAttackProcess,
	events {
		observable { SPLICED_KEX_REJECTED }
		hidden { }
	}
	states {
		Idle => { SPLICED_KEX_REJECTED => Done },
		Done => { }
	}
	terminal { Done }
	annotations { description: "Splice attack: the possession signature must verify under the offered certificate" }
}

tb_scenario! {
	name: splice_attack,
	config: ScenarioConfig::builder()
		.with_spec(SpliceAttackSpec::latest())
		.with_csp(SpliceAttackProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			SpliceAttackScenario::run((trace.into(),)).await
		}
	}
}

job! {
	name: SpliceAttackScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let materials = ServerMaterials::generate();
		let profile = default_security_profile();

		// The victim holds an authenticated identity whose certificate is
		// public. The attacker offers that certificate and proves it with its
		// own key.
		let victim = ClientMaterials::deterministic();
		let attacker = ClientMaterials::generate();
		let spliced = ClientIdentity::new(Arc::clone(&victim.certificate), Arc::clone(&attacker.key_manager));
		let validator = pinning_validator(&materials.certificate);

		let mut config = hpke_client_config(validator);
		config.flow.identity = Some(spliced);
		config.security_offer = Some(SecurityOffer::new(vec![profile]));

		let mut client = Handshake::client(config);

		// The server holds a validator, so it requires client authentication.
		let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
		let mut server_config = hpke_server_config::<DefaultCryptoProvider>(&materials, [profile]);
		server_config.peer_authentication = PeerAuthentication::mutual([validator]);

		let mut server = Handshake::server(server_config);

		let reply = server.reply(client.start()?).await?;
		let closing = client.respond(reply).await?;

		// The possession signature is the control, so the refusal must name
		// it. The key confirmation and the validator both admit the closing of
		// the attacker, so no other check refuses it first.
		match server.finish(closing).await {
			Err(HandshakeError::SignatureError(_)) => {
				trace.event(SPLICED_KEX_REJECTED)?;
			}
			Err(_) => return Err(expectation_failure("the splice was refused by a check other than the possession signature")),
			Ok(_) => return Err(expectation_failure("server accepted a spliced identity")),
		}

		Ok(())
	}
}
