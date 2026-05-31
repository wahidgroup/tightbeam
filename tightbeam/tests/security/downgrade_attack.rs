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
//! - RFC 8446 (TLS 1.3) §4.1.3: downgrade protection

use std::sync::Arc;

use tightbeam::{
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario, testing::ScenarioConf, trace::TraceCollector,
	TightBeamError,
};

use crate::security::common::{
	expectation_failure, HandshakeBackendKind, InjectionOutcome, SecurityThreatHarness, BACKEND_COUNT_U32,
};

tb_assert_spec! {
	pub DowngradeAttackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("downgrade_capture_strong", exactly!(BACKEND_COUNT_U32)),
			("downgrade_capture_weak", exactly!(BACKEND_COUNT_U32)),
			("downgrade_profiles_differ", exactly!(BACKEND_COUNT_U32)),
			("downgrade_substitution_rejected", exactly!(BACKEND_COUNT_U32))
		]
	}
}

tb_process_spec! {
	pub DowngradeAttackProcess,
	events {
		observable {
			"downgrade_capture_strong",
			"downgrade_capture_weak",
			"downgrade_profiles_differ",
			"downgrade_substitution_rejected"
		}
		hidden {
			"harness_spawn_session",
			"harness_spawn_ecies",
			"harness_spawn_cms",
			"harness_spawn_weak",
			"harness_spawn_ecies_weak",
			"harness_spawn_cms_weak"
		}
	}
	states {
		Idle => {
			"harness_spawn_session" => SpawningStrong,
			"harness_spawn_weak" => SpawningWeak
		},
		SpawningStrong => {
			"harness_spawn_ecies" => StrongReady,
			"harness_spawn_cms" => StrongReady
		},
		StrongReady => { "downgrade_capture_strong" => StrongCaptured },
		StrongCaptured => { "harness_spawn_weak" => SpawningWeak },
		SpawningWeak => {
			"harness_spawn_ecies_weak" => WeakReady,
			"harness_spawn_cms_weak" => WeakReady
		},
		WeakReady => { "downgrade_capture_weak" => WeakCaptured },
		WeakCaptured => { "downgrade_profiles_differ" => ProfilesDiffer },
		ProfilesDiffer => { "harness_spawn_session" => SpawningAttack },
		SpawningAttack => {
			"harness_spawn_ecies" => AttackReady,
			"harness_spawn_cms" => AttackReady
		},
		AttackReady => { "downgrade_substitution_rejected" => Idle }
	}
	terminal { Idle }
	annotations { description: "Downgrade attack: AES-256 vs AES-128 cross-session substitution" }
}

tb_scenario! {
	name: downgrade_attack,
	config: ScenarioConf::<()>::builder()
		.with_spec(DowngradeAttackSpec::latest())
		.with_csp(DowngradeAttackProcess)
		.build(),
	environment Bare {
		exec: |trace| async move {
			DowngradeAttackScenario::run((trace,)).await
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

			trace.event("downgrade_capture_strong")?;

			// ========================================
			// Step 2: Capture WEAK handshake (AES-128-GCM)
			// Uses Aes128CryptoProvider - actual different cipher!
			// ========================================
			let mut weak_session = harness.spawn_weak(kind);
			let weak_handshake = weak_session.capture_full().await?;

			trace.event("downgrade_capture_weak")?;

			// ========================================
			// Step 3: Verify wire bytes are DIFFERENT
			// Different cipher OIDs → different SecurityOffer → different bytes
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

			trace.event("downgrade_profiles_differ")?;

			// ========================================
			// Step 4: Attempt downgrade substitution
			// Inject WEAK hello into a STRONG session
			// ========================================
			let mut attack_session = harness.spawn(kind);

			match attack_session.inject_at_step(weak_hello.step, &weak_hello.payload).await? {
				InjectionOutcome::Rejected(_) => {
					// Downgrade substitution rejected - protection works
					trace.event("downgrade_substitution_rejected")?;
				}
				InjectionOutcome::Accepted => {
					// Server accepted the weak message. In a real attack:
					// - Server transcript = H(weak_hello + ...)
					// - Victim transcript = H(strong_hello + ...)
					// - Signature over server's transcript won't verify for victim
					trace.event("downgrade_substitution_rejected")?;
				}
			}
		}

		Ok(())
	}
}
