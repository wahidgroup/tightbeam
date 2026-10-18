//! # Closing confidentiality threat
//!
//! ## Weakness
//! If the client's closing travels in the clear, or under a key that a
//! server's static key recovers, an observer who records the handshake and
//! later obtains that key reads the client identity, the key-confirmation tag,
//! and the receipt acknowledgement.
//!
//! ## Attack
//! An observer captures an HPKE handshake and later obtains the server's
//! static key. It extracts the closing, and tries to open it under every
//! closing key that key and the legs in the clear yield. It also compares the
//! closings of two handshakes.
//!
//! CMS carries its base secret inside an `AuthEnvelopedData` with a
//! `KEMRecipientInfo`. The unit test
//! `the_base_secret_crosses_the_wire_only_sealed` in
//! `transport::handshake::orchestrator` covers that carriage.
//!
//! ## Expected control
//! The HPKE flow seals nothing to a server key. The closing MUST be an
//! `AuthEnvelopedData` whose one recipient is a `KEKRecipientInfo` under a key
//! of the ephemeral-ephemeral agreement, so no closing key the static key
//! yields unwraps its content key. Each handshake MUST seal its closing afresh.
//!
//! ## References
//! - CWE-311: Missing Encryption of Sensitive Data <https://cwe.mitre.org/data/definitions/311.html>
//! - CAPEC-157: Sniffing Attacks <https://capec.mitre.org/data/definitions/157.html>
//! - RFC 9846 Appendix F.1, the client identity under handshake keys:
//!   <https://datatracker.ietf.org/doc/html/rfc9846#appendix-F.1>

use std::sync::Arc;

use tightbeam::{
	cms::enveloped_data::RecipientInfo,
	crypto::cms::{AuthEnvelopedData, EnvelopeError},
	der::Decode,
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	urn::Urn,
	TightBeamError,
};

use crate::security::common::{
	closing_key, expectation_failure, CapturedHandshake, HandshakeBackendKind, SecurityThreatHarness,
	StaticKeyObserver, STATIC_KEY_CANDIDATES,
};

pub(crate) const CONF_CAPTURE_HANDSHAKE: Urn<'static> =
	tightbeam::urn!("test", "event:confidentiality/conf-capture-handshake");
pub(crate) const CONF_CIPHERTEXTS_DIFFER: Urn<'static> =
	tightbeam::urn!("test", "event:confidentiality/conf-ciphertexts-differ");
pub(crate) const CONF_SEALED_UNDER_KEK: Urn<'static> =
	tightbeam::urn!("test", "event:confidentiality/conf-sealed-under-kek");
pub(crate) const CONF_STATIC_KEY_OPENS_NOTHING: Urn<'static> =
	tightbeam::urn!("test", "event:confidentiality/conf-static-key-opens-nothing");

/// The DER of the message at `step` of a captured handshake.
fn message_of(captured: &CapturedHandshake, step: usize) -> Result<&[u8], TightBeamError> {
	let message = captured.message_at(step);
	let message = message.ok_or_else(|| expectation_failure("a leg is missing"))?;
	Ok(&message.payload)
}

/// Whether `closing` is an `AuthEnvelopedData` whose one recipient is a
/// `KEKRecipientInfo`.
fn sealed_under_kek(closing: &[u8]) -> Result<bool, TightBeamError> {
	let envelope = AuthEnvelopedData::from_der(closing)?;
	let recipients = envelope.recipient_infos.0.as_slice();
	Ok(matches!(recipients, [RecipientInfo::Kekri(_)]))
}

tb_assert_spec! {
	pub ConfidentialitySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CONF_CAPTURE_HANDSHAKE, exactly!(1u32)),
			(CONF_SEALED_UNDER_KEK, exactly!(1u32), equals!(true)),
			(CONF_STATIC_KEY_OPENS_NOTHING, exactly!(1u32), equals!(true)),
			(CONF_CIPHERTEXTS_DIFFER, exactly!(1u32), equals!(true))
		]
	}
}

tb_process_spec! {
	pub ConfidentialityProcess,
	events {
		observable {
			CONF_CAPTURE_HANDSHAKE,
			CONF_SEALED_UNDER_KEK,
			CONF_STATIC_KEY_OPENS_NOTHING,
			CONF_CIPHERTEXTS_DIFFER,
			SecurityThreatHarness::HARNESS_SPAWN_SESSION,
			SecurityThreatHarness::HARNESS_SPAWN_HPKE
		}
		hidden { }
	}
	states {
		Idle => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => Spawning },
		Spawning => { SecurityThreatHarness::HARNESS_SPAWN_HPKE => SessionReady },
		SessionReady => {
			CONF_CAPTURE_HANDSHAKE => Captured,
			CONF_CIPHERTEXTS_DIFFER => Idle
		},
		Captured => { CONF_SEALED_UNDER_KEK => Sealed },
		Sealed => { CONF_STATIC_KEY_OPENS_NOTHING => StaticKeyRefused },
		StaticKeyRefused => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => Spawning }
	}
	terminal { Idle }
	annotations { description: "Confidentiality: the HPKE closing opens under no key the server's static key yields" }
}

tb_scenario! {
	name: confidentiality,
	config: ScenarioConfig::builder()
		.with_spec(ConfidentialitySpec::latest())
		.with_csp(ConfidentialityProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			ConfidentialityScenario::run((trace.into(),)).await
		}
	}
}

job! {
	name: ConfidentialityScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let harness = SecurityThreatHarness::with_trace(Arc::clone(&trace));
		// The observer reads the HPKE closing, so the scenario runs over HPKE
		// alone.
		let kind = HandshakeBackendKind::Hpke;

		// Step 1: Capture a complete handshake.
		let mut session = harness.spawn(kind);
		let captured = session.capture_full().await?;

		trace.event(CONF_CAPTURE_HANDSHAKE)?;

		// Step 2: The closing is sealed under a key both endpoints derive, and
		// to no server key.
		let closing = message_of(&captured, 2)?;
		trace.event_with(CONF_SEALED_UNDER_KEK, &[], sealed_under_kek(closing)?)?;

		// Step 3: The server's static key, with the hello and the reply, yields
		// no closing key. Each candidate passes the key identifier and fails
		// the integrity check of the key wrap, so the observer reached the
		// recipient and lacked its key.
		let static_key = harness.materials().secret_key();
		let (hello, reply) = (message_of(&captured, 0)?, message_of(&captured, 1)?);
		let observer = StaticKeyObserver::new(hello, reply, closing, static_key)?;
		let attempts = observer.closing_attempts().await?;
		let unwrap_refused = attempts.iter().all(|attempt| matches!(attempt, Err(EnvelopeError::KeyUnwrap)));
		let refused = attempts.len() == STATIC_KEY_CANDIDATES && unwrap_refused;

		trace.event_with(CONF_STATIC_KEY_OPENS_NOTHING, &[], refused)?;

		// Step 4: Two handshakes seal two closings, each under a fresh content
		// key and nonce.
		let mut session2 = harness.spawn(kind);
		let captured2 = session2.capture_full().await?;
		let closing2 = message_of(&captured2, 2)?;

		trace.event_with(CONF_CIPHERTEXTS_DIFFER, &[], closing != closing2)?;

		Ok(())
	}
}

/// The observer's closing key over `ee` = `0x11` × 32 and the salt `0x99` ×
/// 32 matches an independent HKDF-SHA3-256 (Python's `hmac` and `hashlib`).
/// Its handshake secret on the way is the crate's known answer of the
/// ephemeral handshake secret, so the observer runs the flow's own schedule.
#[test]
fn the_observer_closing_key_matches_its_known_answer() -> Result<(), TightBeamError> {
	let closing = closing_key(&[0x11u8; 32], &[0x99u8; 32])?;
	let expected = [
		0x5d, 0xb3, 0x7d, 0x19, 0x92, 0xd1, 0x26, 0xa1, 0x41, 0x3e, 0x0a, 0xeb, 0xc5, 0x88, 0xd3, 0x19, 0xcc, 0xc8,
		0x26, 0x2c, 0xa8, 0x1b, 0x21, 0xb4, 0x12, 0x69, 0xfd, 0xd2, 0x6e, 0xc9, 0xf5, 0x3d,
	];
	assert_eq!(closing, expected);
	Ok(())
}
