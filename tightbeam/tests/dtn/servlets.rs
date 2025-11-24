//! DTN Servlets: Earth Ground Station and Relay Satellite
//!
//! This module contains the servlet definitions for the DTN architecture:
//! - Earth Ground Station: Receives telemetry and sends commands
//! - Relay Satellite: Forwards messages between Mars and Earth

#![cfg(all(
	feature = "testing-csp",
	feature = "testing-fdr",
	feature = "std",
	feature = "tcp",
	feature = "tokio",
	feature = "signature",
	feature = "secp256k1",
	feature = "sha3",
	feature = "x509"
))]

use std::sync::Arc;
use std::time::Duration;

use tightbeam::{
	builder::{frame::FrameBuilder, TypeBuilder},
	crypto::{
		aead::{Aes256Gcm, Aes256GcmOid},
		hash::Sha3_256,
		sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey},
	},
	decode,
	macros::client::builder::ClientBuilder,
	prelude::*,
	servlet,
	transport::policy::RestartExponentialBackoff,
	transport::tcp::r#async::TokioListener,
};

use crate::dtn::{
	certs::{EARTH_CERT, EARTH_KEY, EARTH_PINNING, SATELLITE_CERT, SATELLITE_KEY, SATELLITE_PINNING_ROVER},
	chain_processor::{ChainProcessor, ProcessResult},
	clock::{advance_clock, delays, mission_time_ms},
	fault_matrix::FaultMatrix,
	messages::{EarthCommand, RoverCommand, RoverTelemetry},
};

// ============================================================================
// Earth Ground Station Servlet
// ============================================================================

/// Select command based on telemetry and fault state using simple LCG RNG
fn select_random_command(
	telemetry: &RoverTelemetry,
	fault_matrix: &crate::dtn::fault_matrix::FaultMatrix,
	seed: u64,
) -> RoverCommand {
	// Simple linear congruential generator for deterministic randomness
	let rng_state = seed.wrapping_mul(1103515245).wrapping_add(12345);

	// Constraints: low battery or any fault -> standby
	if telemetry.battery_percent < 20 || fault_matrix.has_fault() {
		return RoverCommand::Standby;
	}

	// Random selection among operational commands
	match rng_state % 3 {
		0 => RoverCommand::CollectSample { location: "Jezero Crater Delta".to_string() },
		1 => RoverCommand::ProbeLocation { x: 100, y: 200 },
		2 => RoverCommand::TakePhoto { direction: "forward".to_string(), resolution: 1024 },
		_ => unreachable!(),
	}
}

servlet! {
	/// Earth ground station that receives science data from relay and sends commands
	pub EarthGroundStationServlet<RoverTelemetry>,
	protocol: TokioListener,
	x509: {
		certificate: EARTH_CERT,
		key_provider: EARTH_KEY,
		client_validators: [EARTH_PINNING]
	},
	config: {
		earth_signing_key: Secp256k1SigningKey,
		rover_verifying_key: Secp256k1VerifyingKey,
		shared_cipher: Aes256Gcm,
		chain_processor: Arc<ChainProcessor>,
	},
	handle: |frame, trace, config| async move {
		trace.event("earth_receive_telemetry")?;

		// 1. Verify Rover's signature
		if frame.nonrepudiation.is_some() {
			match frame.verify::<Secp256k1Signature>(&config.rover_verifying_key) {
				Ok(_) => println!("[Earth] ✓ Rover signature verified"),
				Err(e) => {
					eprintln!("[Earth] ✗ Rover signature verification FAILED");
					return Err(e);
				}
			}
		}

		// 2. Process frame (persist, order, validate chain)
		match config.chain_processor.process_incoming(frame)? {
			ProcessResult::Processed(ordered_frames) => {
				let mut last_response = None;

				for ordered_frame in ordered_frames {
					// Extract metadata before consuming frame
					let fault_matrix = FaultMatrix::try_from(&ordered_frame.metadata.matrix)?;

					// Decrypt telemetry
					let telemetry: RoverTelemetry = if ordered_frame.metadata.confidentiality.is_some() {
						println!("[Earth] Decrypting telemetry with shared cipher");
						ordered_frame.decrypt::<RoverTelemetry>(&config.shared_cipher, None)?
					} else {
						decode(&ordered_frame.message)?
					};

					trace.event("earth_analyze_telemetry")?;
					trace.event("earth_select_command")?;

					// Generate command
					let command = select_random_command(&telemetry, &fault_matrix, mission_time_ms());
					let earth_command = EarthCommand::new(command, Some(128), mission_time_ms());

					// Prepare outgoing frame with previous_frame hash
					let (next_order, previous_digest) = config.chain_processor.prepare_outgoing()?;

					// Build frame with previous_frame support
					let mut builder = FrameBuilder::from(Version::V3)
						.with_id(format!("earth-cmd-{:03}", next_order))
						.with_order(next_order)
						.with_message(earth_command)
						.with_message_hasher::<Sha3_256>()
						.with_witness_hasher::<Sha3_256>()
						.with_cipher::<Aes256GcmOid, _>(config.shared_cipher.clone())
						.with_signer::<Secp256k1Signature, _>(config.earth_signing_key.clone());

					// Set previous_frame if not the first frame
					if let Some(digest) = previous_digest {
						builder = builder.with_previous_hash(digest);
					}

					let response = builder.build()?;

					// Finalize outgoing frame
					config.chain_processor.finalize_outgoing(&response)?;

					trace.event("earth_send_command")?;
					last_response = Some(response);
				}

				Ok(last_response)
			},
			ProcessResult::Buffered => Ok(None),
			ProcessResult::ChainGap { current_head, missing_hash } => {
				// TODO: Request missing frames
				eprintln!("[Earth] Chain gap - would request frames (head: {:?}, missing: {:?})", current_head, missing_hash);
				Ok(None)
			}
		}
	}
}

// ============================================================================
// Relay Satellite Servlet
// ============================================================================

servlet! {
	/// Relay satellite that forwards frames from Rover to Earth
	pub RelaySatelliteServlet<RoverTelemetry>,
	protocol: TokioListener,
	x509: {
		certificate: SATELLITE_CERT,
		key_provider: SATELLITE_KEY,
		client_validators: [SATELLITE_PINNING_ROVER]
	},
	config: {
		earth_servlet: EarthGroundStationServlet,
		earth_addr: TightBeamSocketAddr,
		rover_verifying_key: Secp256k1VerifyingKey,
		earth_verifying_key: Secp256k1VerifyingKey,
		chain_processor: Arc<ChainProcessor>,
	},
	handle: |frame, trace, config| async move {
		trace.event("relay_receive_from_rover")?;

		// Verify Rover's signature
		if frame.nonrepudiation.is_some() {
			match frame.verify::<Secp256k1Signature>(&config.rover_verifying_key) {
				Ok(_) => println!("[Satellite] ✓ Rover signature verified - forwarding encrypted frame"),
				Err(e) => return Err(e),
			}
		}

		// Process uplink frame
		match config.chain_processor.process_incoming(frame)? {
			ProcessResult::Processed(ordered_frames) => {
				let mut last_response = None;

				for ordered_frame in ordered_frames {
					advance_clock(delays::RELAY_TO_EARTH_MS);
					trace.event("relay_forward_uplink")?;

					// Forward to Earth
					let mut earth_client = ClientBuilder::<TokioListener>::connect(config.earth_addr)
						.await?
						.with_server_certificate(EARTH_CERT)?
						.with_client_identity(SATELLITE_CERT, SATELLITE_KEY)?
						.with_restart(RestartExponentialBackoff::new(3, 100, None))
						.with_timeout(Duration::from_millis(2000))
						.build()?;

					let earth_response = earth_client.emit(ordered_frame, None).await?;

					// Process downlink response
					if let Some(response_frame) = earth_response {
						trace.event("relay_receive_from_earth")?;

						// Verify Earth's signature
						match response_frame.verify::<Secp256k1Signature>(&config.earth_verifying_key) {
							Ok(_) => println!("[Satellite] ✓ Earth signature verified - forwarding encrypted command"),
							Err(e) => return Err(e),
						}

						// Process downlink (also validates chain)
						match config.chain_processor.process_incoming(response_frame.clone())? {
							ProcessResult::Processed(_) | ProcessResult::Buffered => {
								last_response = Some(response_frame);
							},
							ProcessResult::ChainGap { .. } => {
								eprintln!("[Satellite] Chain gap in downlink");
							}
						}
					}

					advance_clock(delays::EARTH_TO_RELAY_MS);
					trace.event("relay_forward_downlink")?;
				}

				Ok(last_response)
			},
			ProcessResult::Buffered => Ok(None),
			ProcessResult::ChainGap { .. } => {
				eprintln!("[Satellite] Chain gap in uplink");
				Ok(None)
			}
		}
	}
}
