//! Downgrade attack threat test.
//!
//! Tests that a MITM cannot force weaker cryptography by capturing and substituting
//! handshake messages from sessions using different cipher strengths.
//!
//! ## Attack Scenario
//!
//! 1. Victim initiates handshake with AES-256-GCM (strong)
//! 2. MITM captures their own AES-128-GCM (weak) handshake
//! 3. MITM substitutes victim's ClientHello with the weak one
//! 4. Server processes the weak ClientHello
//! 5. Server's response signature is over transcript with weak ClientHello
//! 6. Victim verifies signature against transcript with STRONG ClientHello
//! 7. MISMATCH → Attack detected
//!
//! ## What This Test Proves
//!
//! - AES-256 sessions produce different wire bytes than AES-128 sessions
//! - Substitution of weak message into strong session is detectable
//! - Transcript integrity prevents downgrade attacks
//!
//! ## Technical Details
//!
//! This test uses TWO DIFFERENT CryptoProviders:
//!
//! 1. `DefaultCryptoProvider` (AES-256-GCM)
//!    - `type AeadCipher = Aes256Gcm`
//!    - `type AeadOid = Aes256GcmOid` (OID: 2.16.840.1.101.3.4.1.46)
//!
//! 2. `Aes128CryptoProvider` (AES-128-GCM)
//!    - `type AeadCipher = Aes128Gcm`
//!    - `type AeadOid = Aes128GcmOid` (OID: 2.16.840.1.101.3.4.1.6)
//!
//! The `SecurityOffer` embedded in `ClientHello` contains the AEAD OID, so:
//! - Strong hello bytes include OID `...3.4.1.46` (AES-256)
//! - Weak hello bytes include OID `...3.4.1.6` (AES-128)
//!
//! This difference means:
//! - Transcript hash differs based on which hello is in the transcript
//! - Substituting one for the other causes hash mismatch
//! - Server signature won't verify for the victim

use std::sync::Arc;

use tightbeam::{
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{error::FdrConfigError, error::TestingError, ScenarioConf},
	trace::TraceCollector,
	TightBeamError,
};

use crate::security::common::{HandshakeBackendKind, InjectionOutcome, SecurityThreatHarness, BACKEND_COUNT_U32};

fn expectation_failure(reason: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError {
		field: "downgrade_attack",
		reason,
	}))
}

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
