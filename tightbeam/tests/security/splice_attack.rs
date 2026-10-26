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
//! 3. The attacker's key provider claims the victim's key and signs the client Finished under its own key.
//! 4. A second forger holds a signature the victim made over another message,
//!    and answers the Finished with it.
//!
//! In both forms the attacker's own client derives the handshake secret, so
//! the key-confirmation tag verifies. The closing seals the client Finished,
//! which carries the certificate, under a key of the handshake secret, so an
//! attacker cannot lift the Finished of a victim from a recorded closing into
//! its own.
//!
//! ## Expected control
//! The client Finished MUST verify under the key of the certificate its signer
//! names, over signed attributes that bind the client role and the transcript
//! hash of this handshake. The closing of each forger MUST fail signature
//! verification, the one check that stands in its way.
//!
//! ## References
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>
//! - CWE-300: Channel Accessible by Non-Endpoint <https://cwe.mitre.org/data/definitions/300.html>
//! - CAPEC-94: Adversary in the Middle (AiTM) <https://capec.mitre.org/data/definitions/94.html>

use std::sync::Arc;

use tightbeam::{
	crypto::{
		hash::{Digest, Sha3_256},
		key::{KeyBackend, KeyError, SigningKeyProvider},
		sign::SigningIdentity,
		x509::policy::{CertificateValidation, ExpiryValidator},
	},
	exactly,
	instrumentation::events,
	job,
	spki::AlgorithmIdentifierOwned,
	tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	utils::marker::MaybeSendFuture,
	TightBeamError,
};

use crate::common::security::{ClientMaterials, ServerMaterials};
use crate::security::common::HandshakeBackendKind;
use crate::security::live::LiveHandshake;

/// A key provider that claims the public key of `claimed` and signs under
/// the key of `signer`, as software the attacker runs may.
#[derive(Debug)]
struct SplicedKeyProvider {
	claimed: Arc<dyn SigningKeyProvider>,
	signer: Arc<dyn SigningKeyProvider>,
}

impl KeyBackend for SplicedKeyProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.signer.algorithm()
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		self.claimed.to_public_key_bytes()
	}
}

impl SigningKeyProvider for SplicedKeyProvider {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		self.signer.sign_prehash(prehash)
	}
}

/// A key provider that claims the public key of `victim` and answers every
/// request with `lifted`, a signature the victim made over another message,
/// as an attacker that lifted a signature of the victim does.
#[derive(Debug)]
struct LiftedSignatureProvider {
	victim: Arc<dyn SigningKeyProvider>,
	lifted: Vec<u8>,
}

impl KeyBackend for LiftedSignatureProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.victim.algorithm()
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		self.victim.to_public_key_bytes()
	}
}

impl SigningKeyProvider for LiftedSignatureProvider {
	fn sign_prehash(&self, _prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		Box::pin(async move { Ok(self.lifted.to_owned()) })
	}
}

tb_assert_spec! {
	pub SpliceAttackSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(2u32), equals!("signature"))
		]
	}
}

tb_process_spec! {
	pub SpliceAttackProcess,
	events {
		observable { events::SESSION_CERT_REJECTED }
		hidden { }
	}
	states {
		Idle => { events::SESSION_CERT_REJECTED => Spliced },
		Spliced => { events::SESSION_CERT_REJECTED => Done },
		Done => { }
	}
	terminal { Done }
	annotations { description: "Splice attack: the client Finished must verify under the offered certificate" }
}

/// A live handshake with a mutual server of `materials`, which files its
/// verdict in `trace`, and a client that offers the certificate of `victim`
/// and signs through `provider`. The client is a real one, so it computes the
/// key-confirmation tag for its own secrets.
fn forged_by(
	materials: &ServerMaterials,
	victim: &ClientMaterials,
	provider: Arc<dyn SigningKeyProvider>,
	trace: &TraceCollector,
) -> Result<LiveHandshake, TightBeamError> {
	let spliced = SigningIdentity::new(Arc::clone(&victim.certificate), provider)?;

	// The server holds a validator, so it requires client authentication.
	let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
	let handshake = LiveHandshake::new(HandshakeBackendKind::Hpke, materials.to_owned());
	let handshake = handshake.with_client_validators([validator]).with_client_identity(spliced);
	Ok(handshake.audit_server(trace))
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

		// The first attacker offers the public certificate of the victim and
		// proves it with its own key, behind a provider that claims the key of
		// the victim.
		let victim = ClientMaterials::deterministic();
		let attacker = ClientMaterials::generate();
		let claimed = Arc::clone(&victim.key_provider);
		let signer = Arc::clone(&attacker.key_provider);
		let splicer = Arc::new(SplicedKeyProvider { claimed, signer });
		let spliced = forged_by(&materials, &victim, splicer, &trace)?.run().await?;

		// The signature of the client Finished is the control, so the refusal
		// must name it. The key confirmation and the validator both admit the
		// closing of the attacker, so no other check refuses it first.
		spliced.refused_by_server("server admitted a spliced client Finished")?;

		// The second forger holds a signature of the victim's own key over
		// another message, so the right key signed the wrong transcript.
		let other = Sha3_256::digest(b"the client Finished of another handshake");
		let lifted = victim.key_provider.sign_prehash(&other).await?;
		let forger = Arc::new(LiftedSignatureProvider { victim: Arc::clone(&victim.key_provider), lifted });
		let lifted = forged_by(&materials, &victim, forger, &trace)?.run().await?;

		lifted.refused_by_server("server admitted a lifted client Finished")
	}
}
