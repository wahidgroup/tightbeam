//! # Cipher downgrade threat
//!
//! ## Weakness
//! A negotiated handshake may complete with a weaker cipher than both parties
//! support if message substitution across cipher strengths is not detected by
//! the signed transcript.
//!
//! ## Attack
//! 1. Victim offers AES-256-GCM (strong); the `SecurityOffer` in `ClientHello`
//!    carries the AEAD OID (`...3.4.1.46`).
//! 2. A MITM captures its own AES-128-GCM (weak) handshake (OID `...3.4.1.6`).
//! 3. The MITM substitutes the victim's `ClientHello` with the weak one.
//! 4. The server signs a transcript containing the weak hello; the victim
//!    verifies against a transcript containing the strong hello.
//!
//! ## Expected control
//! The transcript MUST bind the negotiated cipher: strong and weak sessions
//! produce different wire bytes, so substitution MUST cause a transcript-hash
//! mismatch and signature-verification failure.
//!
//! ## References
//! - CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')
//!   <https://cwe.mitre.org/data/definitions/757.html>
//! - CAPEC-220: Client-Server Protocol Manipulation
//!   <https://capec.mitre.org/data/definitions/220.html>
//! - CAPEC-620: Drop Encryption Level
//!   <https://capec.mitre.org/data/definitions/620.html>
//! - RFC 9846 (TLS 1.3) §4.1.3: downgrade protection

use std::sync::Arc;

use tightbeam::{
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConf, SetupEnv},
	trace::TraceCollector,
	utils::urn::Urn,
	TightBeamError,
};

use crate::security::common::{
	expectation_failure, HandshakeBackendKind, InjectionOutcome, SecurityThreatHarness, BACKEND_COUNT_U32,
};

pub(crate) const DOWNGRADE_CAPTURE_STRONG: Urn<'static> =
	Urn::new("test", "event:downgrade-attack/downgrade-capture-strong");
pub(crate) const DOWNGRADE_CAPTURE_WEAK: Urn<'static> =
	Urn::new("test", "event:downgrade-attack/downgrade-capture-weak");
pub(crate) const DOWNGRADE_PROFILES_DIFFER: Urn<'static> =
	Urn::new("test", "event:downgrade-attack/downgrade-profiles-differ");
pub(crate) const DOWNGRADE_SUBSTITUTION_REJECTED: Urn<'static> =
	Urn::new("test", "event:downgrade-attack/downgrade-substitution-rejected");

tb_assert_spec! {
	pub DowngradeAttackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(DOWNGRADE_CAPTURE_STRONG, exactly!(BACKEND_COUNT_U32)),
			(DOWNGRADE_CAPTURE_WEAK, exactly!(BACKEND_COUNT_U32)),
			(DOWNGRADE_PROFILES_DIFFER, exactly!(BACKEND_COUNT_U32)),
			(DOWNGRADE_SUBSTITUTION_REJECTED, exactly!(BACKEND_COUNT_U32))
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
			SecurityThreatHarness::HARNESS_SPAWN_ECIES,
			SecurityThreatHarness::HARNESS_SPAWN_CMS,
			SecurityThreatHarness::HARNESS_SPAWN_WEAK,
			SecurityThreatHarness::HARNESS_SPAWN_ECIES_WEAK,
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
			SecurityThreatHarness::HARNESS_SPAWN_ECIES => StrongReady,
			SecurityThreatHarness::HARNESS_SPAWN_CMS => StrongReady
		},
		StrongReady => { DOWNGRADE_CAPTURE_STRONG => StrongCaptured },
		StrongCaptured => { SecurityThreatHarness::HARNESS_SPAWN_WEAK => SpawningWeak },
		SpawningWeak => {
			SecurityThreatHarness::HARNESS_SPAWN_ECIES_WEAK => WeakReady,
			SecurityThreatHarness::HARNESS_SPAWN_CMS_WEAK => WeakReady
		},
		WeakReady => { DOWNGRADE_CAPTURE_WEAK => WeakCaptured },
		WeakCaptured => { DOWNGRADE_PROFILES_DIFFER => ProfilesDiffer },
		ProfilesDiffer => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => SpawningAttack },
		SpawningAttack => {
			SecurityThreatHarness::HARNESS_SPAWN_ECIES => AttackReady,
			SecurityThreatHarness::HARNESS_SPAWN_CMS => AttackReady
		},
		AttackReady => { DOWNGRADE_SUBSTITUTION_REJECTED => Idle }
	}
	terminal { Idle }
	annotations { description: "Downgrade attack: AES-256 vs AES-128 cross-session substitution" }
}

tb_scenario! {
	name: downgrade_attack,
	config: ScenarioConf::builder()
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
			// ========================================
			// Step 1: Capture STRONG handshake (AES-256-GCM)
			// Uses DefaultCryptoProvider
			// ========================================
			let mut strong_session = harness.spawn(kind);
			let strong_handshake = strong_session.capture_full().await?;

			trace.event(DOWNGRADE_CAPTURE_STRONG)?;

			// ========================================
			// Step 2: Capture WEAK handshake (AES-128-GCM)
			// Uses Aes128CryptoProvider - actual different cipher!
			// ========================================
			let mut weak_session = harness.spawn_weak(kind);
			let weak_handshake = weak_session.capture_full().await?;

			trace.event(DOWNGRADE_CAPTURE_WEAK)?;

			// ========================================
			// Step 3: Verify wire bytes are DIFFERENT
			// Different cipher OIDs -> different SecurityOffer -> different bytes
			// ========================================
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

			// ========================================
			// Step 4: Attempt downgrade substitution
			// Inject WEAK hello into a STRONG session
			// ========================================
			let mut attack_session = harness.spawn(kind);
			match attack_session.inject_at_step(weak_hello.step, &weak_hello.payload).await? {
				InjectionOutcome::Rejected(_) => {
					// Downgrade substitution rejected - the strong server's
					// strength floor refuses the AES-128 offer, and the
					// negotiated cipher is bound into the signed transcript.
					trace.event(DOWNGRADE_SUBSTITUTION_REJECTED)?;
				}
				InjectionOutcome::Accepted => {
					// A strong session that accepts a weak ClientHello is a
					// downgrade. The control MUST reject it.
					return Err(expectation_failure("downgrade substitution was accepted"));
				}
			}
		}

		Ok(())
	}
}
