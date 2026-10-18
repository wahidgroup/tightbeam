//! # Forward secrecy threat
//!
//! ## Weakness
//! Reusing ephemeral key material across handshakes means compromise of the
//! server's long-term key (or a single ephemeral key) can expose past sessions.
//! An ephemeral equal to the server's static key would collapse the agreement
//! into one that key recovers.
//!
//! ## Attack
//! Multiple handshakes are run and their ephemeral public keys compared for
//! uniqueness. Each handshake carries two in the clear: the client ephemeral
//! `R` of the hello and the server ephemeral `E` of the reply.
//!
//! ## Expected control
//! Each handshake MUST draw a fresh, random ephemeral on each side, so session
//! keys from different handshakes are independent and past traffic stays
//! protected. The HPKE handshake secret derives from `R` and `E` alone, so
//! `R` and `E` MUST NOT share the x-coordinate of the server's static key,
//! which ECDH keeps alone.
//!
//! ## References
//! - CWE-323: Reusing a Nonce, Key Pair in Encryption <https://cwe.mitre.org/data/definitions/323.html>
//! - NIST SP 800-56A Rev. 3 §5.6: ephemeral key-pair generation
//! - RFC 9846 §7.1: the ECDHE shared secret <https://datatracker.ietf.org/doc/html/rfc9846#section-7.1>

use std::collections::BTreeSet;
use std::sync::Arc;

use tightbeam::{
	crypto::sign::ecdsa::k256::elliptic_curve::sec1::ToEncodedPoint,
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	urn::Urn,
	TightBeamError,
};

use crate::security::common::{
	captured_ephemerals, expectation_failure, x_coordinate, HandshakeBackendKind, SecurityThreatHarness,
};

pub(crate) const FS_ALL_EPHEMERAL_UNIQUE: Urn<'static> =
	tightbeam::urn!("test", "event:forward-secrecy/fs-all-ephemeral-unique");
pub(crate) const FS_CAPTURE_HANDSHAKE: Urn<'static> =
	tightbeam::urn!("test", "event:forward-secrecy/fs-capture-handshake");
pub(crate) const FS_EXTRACT_EPHEMERAL: Urn<'static> =
	tightbeam::urn!("test", "event:forward-secrecy/fs-extract-ephemeral");

/// Number of handshakes to perform for forward secrecy verification.
const HANDSHAKE_COUNT: usize = 5;

tb_assert_spec! {
	pub ForwardSecrecySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(FS_CAPTURE_HANDSHAKE, exactly!(HANDSHAKE_COUNT as u32)),
			(FS_EXTRACT_EPHEMERAL, exactly!(HANDSHAKE_COUNT as u32)),
			(FS_ALL_EPHEMERAL_UNIQUE, exactly!(1u32), equals!(true))
		]
	}
}

tb_process_spec! {
	pub ForwardSecrecyProcess,
	events {
		observable {

			FS_CAPTURE_HANDSHAKE,
			FS_EXTRACT_EPHEMERAL,
			FS_ALL_EPHEMERAL_UNIQUE,
			SecurityThreatHarness::HARNESS_SPAWN_SESSION,
			SecurityThreatHarness::HARNESS_SPAWN_HPKE
		}
		hidden { }
	}
	states {
		Idle => { SecurityThreatHarness::HARNESS_SPAWN_SESSION => Spawning },
		Spawning => { SecurityThreatHarness::HARNESS_SPAWN_HPKE => SessionReady },
		SessionReady => { FS_CAPTURE_HANDSHAKE => Captured },
		Captured => { FS_EXTRACT_EPHEMERAL => Extracted },
		Extracted => {
			SecurityThreatHarness::HARNESS_SPAWN_SESSION => Spawning,
			FS_ALL_EPHEMERAL_UNIQUE => Complete
		},
		Complete => { }
	}
	terminal { Complete }
	annotations { description: "Forward Secrecy: Ephemeral key uniqueness verification" }
}

tb_scenario! {
	name: forward_secrecy,
	config: ScenarioConfig::builder()
		.with_spec(ForwardSecrecySpec::latest())
		.with_csp(ForwardSecrecyProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			ForwardSecrecyScenario::run((trace.into(),)).await
		}
	}
}

/// The x-coordinates of the two ephemerals of each of `count` captured HPKE
/// handshakes, client ephemeral first.
async fn captured_coordinates(
	harness: &SecurityThreatHarness,
	trace: &TraceCollector,
	count: usize,
) -> Result<Vec<Vec<u8>>, TightBeamError> {
	let mut coordinates = Vec::with_capacity(2 * count);
	for _ in 0..count {
		let mut session = harness.spawn(HandshakeBackendKind::Hpke);
		let captured = session.capture_full().await?;

		trace.event(FS_CAPTURE_HANDSHAKE)?;

		let hello = captured.message_at(0).ok_or_else(|| expectation_failure("no hello captured"))?;
		let reply = captured.message_at(1).ok_or_else(|| expectation_failure("no reply captured"))?;
		let (client_ephemeral, server_ephemeral) = captured_ephemerals(&hello.payload, &reply.payload)?;

		coordinates.push(x_coordinate(&client_ephemeral)?);
		coordinates.push(x_coordinate(&server_ephemeral)?);
		trace.event(FS_EXTRACT_EPHEMERAL)?;
	}

	Ok(coordinates)
}

job! {
	name: ForwardSecrecyScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let harness = SecurityThreatHarness::with_trace(Arc::clone(&trace));
		let coordinates = captured_coordinates(&harness, &trace, HANDSHAKE_COUNT).await?;

		// The server's static key joins the set, so an ephemeral that repeats
		// across handshakes, that one side reflects from the other, or that
		// shares the x-coordinate of the static key shrinks it.
		let static_key = harness.materials().secret_key().public_key().to_encoded_point(false);
		let static_coordinate = x_coordinate(static_key.as_bytes())?;
		let distinct: BTreeSet<Vec<u8>> = coordinates.into_iter().chain([static_coordinate]).collect();

		trace.event_with(FS_ALL_EPHEMERAL_UNIQUE, &[], distinct.len() == 2 * HANDSHAKE_COUNT + 1)?;

		Ok(())
	}
}
