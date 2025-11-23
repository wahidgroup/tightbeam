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

use std::time::Duration;

use tightbeam::{
	compose, crypto::sign::ecdsa::Secp256k1SigningKey, decode, macros::client::builder::ClientBuilder,
	matrix::MatrixDyn, prelude::*, servlet, transport::policy::RestartExponentialBackoff,
	transport::tcp::r#async::TokioListener,
};

use crate::dtn::{
	certs::{
		EARTH_CERT, EARTH_KEY, EARTH_PINNING, SATELLITE_CERT, SATELLITE_KEY, SATELLITE_PINNING_EARTH,
		SATELLITE_PINNING_ROVER,
	},
	clock::{advance_clock, delays},
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
	handle: |frame, trace| async move {
		let current_time = crate::dtn::clock::mission_time_ms();

		trace.event("earth_receive_telemetry")?;

		let telemetry: RoverTelemetry = decode(&frame.message)?;

		trace.event("earth_analyze_telemetry")?;

		// Extract fault state from frame matrix
		let fault_matrix = FaultMatrix::try_from(&frame.metadata.matrix)?;

		trace.event("earth_select_command")?;
		let command = select_random_command(&telemetry, &fault_matrix, current_time);

		let earth_command = EarthCommand::new(
			command,
			Some(128),
			current_time,
		);

		trace.event("earth_send_command")?;

		let response = compose! {
			V0: id: "earth-cmd-001",
			order: frame.metadata.order + 1,
			message: earth_command
		}?;

		Ok(Some(response))
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
		earth_signing_key: Secp256k1SigningKey,
	},
	handle: |frame, trace, config| async move {
		trace.event("relay_receive_from_rover")?;

		// Simulate relay→earth transmission delay
		advance_clock(delays::RELAY_TO_EARTH_MS);

		trace.event("relay_forward_uplink")?;

		// Decode payload from rover
		// Forward to Earth, preserving matrix
		let telemetry: RoverTelemetry = decode(&frame.message)?;
		let earth_frame = if let Some(asn1_matrix) = frame.metadata.matrix.clone() {
			let matrix_dyn = MatrixDyn::try_from(&asn1_matrix)?;

			compose! {
				V3: id: format!("relay-fwd-{}", String::from_utf8_lossy(&frame.metadata.id)),
				order: frame.metadata.order + 1,
				message: telemetry,
				matrix: matrix_dyn
			}?
		} else {
			compose! {
				V0: id: format!("relay-fwd-{}", String::from_utf8_lossy(&frame.metadata.id)),
				order: frame.metadata.order + 1,
				message: telemetry
			}?
		};

		// Create client to Earth with retry policy and mutual TLS
		let restart_policy = RestartExponentialBackoff::new(3, 100, None);
		let mut earth_client = ClientBuilder::<TokioListener>::connect(config.earth_addr)
			.await?
			.with_server_certificate(EARTH_CERT)?
			.with_client_identity(SATELLITE_CERT, SATELLITE_KEY)?
			.with_restart(restart_policy)
			.with_timeout(Duration::from_millis(2000))
			.build()?;

		// Get Earth's response
		let earth_response = earth_client.emit(earth_frame, None).await?;

		trace.event("relay_receive_from_earth")?;

		// Simulate earth→relay transmission delay
		advance_clock(delays::EARTH_TO_RELAY_MS);

		trace.event("relay_forward_downlink")?;

		// Return Earth's response to Rover
		Ok(earth_response)
	}
}
