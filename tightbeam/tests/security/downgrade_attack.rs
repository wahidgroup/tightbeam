//! # Cipher downgrade threat
//!
//! ## Weakness
//! A negotiated handshake may complete with a weaker cipher than both parties
//! support if the signed transcript does not detect message substitution
//! across cipher strengths.
//!
//! ## Attack
//! 1. The victim offers AES-256-GCM, the strong cipher: the `SecurityOffer` of
//!    its opening carries the AEAD OID (`...3.4.1.46`).
//! 2. A MITM replaces the opening with one that offers AES-128-GCM, the weak cipher (OID `...3.4.1.6`).
//! 3. A server that runs the weak cipher answers it with a reply that selects AES-128-GCM.
//! 4. The MITM hands that reply to the victim. The harness takes it from a weak handshake of the MITM's own.
//!
//! ## Expected control
//! The transcript MUST bind the opening with its offer. The server signed a
//! transcript of the weak opening, and the victim checks the reply against a
//! transcript of its strong opening, so the reply's signature MUST fail
//! (`SignatureVerificationFailed`) before the victim reads the selection.
//!
//! ## References
//! - CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm
//!   Downgrade') <https://cwe.mitre.org/data/definitions/757.html>
//! - CAPEC-220: Client-Server Protocol Manipulation <https://capec.mitre.org/data/definitions/220.html>
//! - CAPEC-620: Drop Encryption Level <https://capec.mitre.org/data/definitions/620.html>
//! - RFC 9846 (TLS 1.3) §4.1.3: downgrade protection

use std::sync::Arc;

use tightbeam::{
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	transport::handshake::HandshakeError::SignatureVerificationFailed,
	urn::Urn,
	TightBeamError,
};

use crate::security::common::{
	expectation_failure, HandshakeBackendKind, InjectionOutcome, SecurityThreatHarness, BACKEND_COUNT_U32,
};

pub(crate) const DOWNGRADE_CAPTURE_STRONG: Urn<'static> =
	tightbeam::urn!("test", "event:downgrade-attack/downgrade-capture-strong");
pub(crate) const DOWNGRADE_CAPTURE_WEAK: Urn<'static> =
	tightbeam::urn!("test", "event:downgrade-attack/downgrade-capture-weak");
pub(crate) const DOWNGRADE_PROFILES_DIFFER: Urn<'static> =
	tightbeam::urn!("test", "event:downgrade-attack/downgrade-profiles-differ");
pub(crate) const DOWNGRADE_SUBSTITUTION_REJECTED: Urn<'static> =
	tightbeam::urn!("test", "event:downgrade-attack/downgrade-substitution-rejected");

tb_assert_spec! {
	pub DowngradeAttackSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(DOWNGRADE_CAPTURE_STRONG, exactly!(BACKEND_COUNT_U32)),
			(DOWNGRADE_CAPTURE_WEAK, exactly!(BACKEND_COUNT_U32)),
			(DOWNGRADE_PROFILES_DIFFER, exactly!(BACKEND_COUNT_U32)),
			(DOWNGRADE_SUBSTITUTION_REJECTED, exactly!(BACKEND_COUNT_U32), equals!(true))
		]
	}
}

tb_process_spec! {
	pub DowngradeAttackProcess,
	events {
		observable {

			DOWNGRADE_CAPTURE_STRONG,
			DOWNGRADE_CAPTURE_WEAK,
			DOWNGRADE_PROFILES_DIFFER,
			DOWNGRADE_SUBSTITUTION_REJECTED,
			SecurityThreatHarness::HARNESS_SPAWN_SESSION,
			SecurityThreatHarness::HARNESS_SPAWN_HPKE,
			SecurityThreatHarness::HARNESS_SPAWN_CMS,
			SecurityThreatHarness::HARNESS_SPAWN_WEAK,
			SecurityThreatHarness::HARNESS_SPAWN_HPKE_WEAK,
			SecurityThreatHarness::HARNESS_SPAWN_CMS_WEAK
		}
		hidden { }
	}
	states {
		Idle => {
			SecurityThreatHarness::HARNESS_SPAWN_SESSION => SpawningStrong,
			SecurityThreatHarness::HARNESS_SPAWN_WEAK => SpawningWeak
		},
		SpawningStrong => {
			SecurityThreatHarness::HARNESS_SPAWN_HPKE => StrongReady,
			SecurityThreatHarness::HARNESS_SPAWN_CMS => StrongReady
		},
		StrongReady => { DOWNGRADE_CAPTURE_STRONG => StrongCaptured },
		StrongCaptured => { SecurityThreatHarness::HARNESS_SPAWN_WEAK => SpawningWeak },
		SpawningWeak => {
			SecurityThreatHarness::HARNESS_SPAWN_HPKE_WEAK => WeakReady,
			SecurityThreatHarness::HARNESS_SPAWN_CMS_WEAK => WeakReady
		},
		WeakReady => { DOWNGRADE_CAPTURE_WEAK => WeakCaptured },
		WeakCaptured => { DOWNGRADE_PROFILES_DIFFER => ProfilesDiffer },
		ProfilesDiffer => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => SpawningAttack },
		SpawningAttack => {
			SecurityThreatHarness::HARNESS_SPAWN_HPKE => AttackReady,
			SecurityThreatHarness::HARNESS_SPAWN_CMS => AttackReady
		},
		AttackReady => { DOWNGRADE_SUBSTITUTION_REJECTED => Idle }
	}
	terminal { Idle }
	annotations { description: "Downgrade attack: AES-256 vs AES-128 cross-session substitution" }
}

tb_scenario! {
	name: downgrade_attack,
	config: ScenarioConfig::builder()
		.with_spec(DowngradeAttackSpec::latest())
		.with_csp(DowngradeAttackProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			DowngradeAttackScenario::run((trace.into(),)).await
		}
	}
}

job! {
	name: DowngradeAttackScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let harness = SecurityThreatHarness::with_trace(Arc::clone(&trace));
		for kind in HandshakeBackendKind::all() {
			// Step 1: Capture the strong handshake (AES-256-GCM) under
			// DefaultCryptoProvider.
			let mut strong_session = harness.spawn(kind)?;
			let strong_handshake = strong_session.capture_full().await?;

			trace.event(DOWNGRADE_CAPTURE_STRONG)?;

			// Step 2: Capture the weak handshake (AES-128-GCM) under
			// Aes128CryptoProvider, which runs AES-128 at the cipher level.
			let mut weak_session = harness.spawn_weak(kind)?;
			let weak_handshake = weak_session.capture_full().await?;

			trace.event(DOWNGRADE_CAPTURE_WEAK)?;

			// Step 3: Verify that the two openings differ in their wire bytes.
			// Their cipher OIDs differ, so their `SecurityOffer` values differ.
			let strong_hello = strong_handshake
				.client_messages()
				.next()
				.ok_or_else(|| expectation_failure("no strong client messages"))?;

			let weak_hello = weak_handshake
				.client_messages()
				.next()
				.ok_or_else(|| expectation_failure("no weak client messages"))?;

			if strong_hello.payload == weak_hello.payload {
				return Err(expectation_failure("AES-256 and AES-128 messages are identical"));
			}

			trace.event(DOWNGRADE_PROFILES_DIFFER)?;

			// Step 4: Attempt the downgrade substitution, and hand the reply to
			// the weak opening to a strong client.
			let weak_reply = weak_handshake.server_reply();
			let weak_reply = weak_reply.ok_or_else(|| expectation_failure("no weak reply"))?;

			let mut attack_session = harness.spawn(kind)?;
			match attack_session.inject_at_step(weak_reply.step, &weak_reply.payload).await? {
				InjectionOutcome::Rejected(error) => {
					// The reply signs a transcript of the weak opening, and the
					// strong client binds its own, so the signature fails
					// before the client reads the weak selection.
					let bound = matches!(error, TightBeamError::HandshakeError(SignatureVerificationFailed));
					trace.event_with(DOWNGRADE_SUBSTITUTION_REJECTED, &[], bound)?;
				}
				InjectionOutcome::Accepted => {
					// A strong client that accepts the reply to a weak opening
					// is a downgrade. The control MUST reject it.
					return Err(expectation_failure("downgrade substitution was accepted"));
				}
			}
		}

		Ok(())
	}
}
