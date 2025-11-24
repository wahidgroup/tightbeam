//! DTN Servlets: Earth Ground Station and Relay Satellite
//!
//! This module contains the servlet definitions for the DTN architecture:
//! - Earth Ground Station: Receives telemetry and sends commands
//! - Relay Satellite: Forwards messages between Mars and Earth

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use tightbeam::{
	crypto::{
		aead::Aes256Gcm,
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
	certs::{
		EARTH_CERT, EARTH_KEY, EARTH_PINNING, ROVER_CERT, ROVER_KEY, ROVER_PINNING, SATELLITE_CERT, SATELLITE_KEY,
		SATELLITE_PINNING_ROVER,
	},
	chain_processor::{ChainProcessor, ProcessResult},
	command_executor::CommandExecutor,
	fault_manager::FaultManager,
	fault_matrix::FaultMatrix,
	frame_builder::FrameBuilderHelper,
	messages::{EarthCommand, RoverCommand, RoverTelemetry},
};

// ============================================================================
// Earth Ground Station Servlet
// ============================================================================

servlet! {
	/// Earth ground station that receives science data from relay
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
		frame_builder: Arc<FrameBuilderHelper>,
		relay_addr: TightBeamSocketAddr,
	},
	handle: |frame, trace, config| async move {
		// Verify Rover's signature
		if frame.nonrepudiation.is_some() {
			match frame.verify::<Secp256k1Signature>(&config.rover_verifying_key) {
				Ok(_) => println!("[Earth] ✓ Rover signature verified"),
				Err(e) => {
					eprintln!("[Earth] ✗ Rover signature verification FAILED");
					return Err(e);
				}
			}
		}

		// Process frame (persist, order, validate chain)
		match config.chain_processor.process_incoming(frame)? {
			ProcessResult::Processed(ordered_frames) => {
				let mut last_response = None;
				for ordered_frame in ordered_frames {
					trace.event("earth_receive_telemetry")?;
					let _fault_matrix = FaultMatrix::try_from(&ordered_frame.metadata.matrix)?;

					// Get order before consuming frame
					let order = ordered_frame.metadata.order;
					
					// Decode telemetry
					let _telemetry: RoverTelemetry = if ordered_frame.metadata.confidentiality.is_some() {
						use tightbeam::compress::{Inflator, ZstdCompression};
						let inflator: Option<&dyn Inflator> = if ordered_frame.metadata.compactness.is_some() {
							Some(&ZstdCompression)
						} else {
							None
						};
						ordered_frame.decrypt::<RoverTelemetry>(&config.shared_cipher, inflator)?
					} else {
						decode(&ordered_frame.message)?
					};

					println!("[Earth] Received telemetry");
					trace.event("earth_analyze_telemetry")?;

			// Build command response
			let command_type = (order % 3) as u8;
			let rover_cmd = match command_type {
				0 => RoverCommand::CollectSample { location: "Site Alpha".to_string() },
				1 => RoverCommand::ProbeLocation { x: 100, y: 200 },
				_ => RoverCommand::TakePhoto { direction: "North".to_string(), resolution: 1080 },
			};

			let (next_order, previous_digest) = config.chain_processor.prepare_outgoing()?;
			let command = EarthCommand::new(rover_cmd, tightbeam::asn1::MessagePriority::Normal, 0);
					
					let command_frame = config.frame_builder.build_command_frame(
						command,
						next_order,
						previous_digest,
						&config.earth_signing_key,
						&config.shared_cipher,
					)?;

					println!("[Earth] ✓ Command frame built, returning as response");
					last_response = Some(command_frame);
				}

				Ok(last_response)
			},
			ProcessResult::Buffered => Ok(None),
			ProcessResult::ChainGap { current_head, missing_hash } => {
				eprintln!("[Earth] Chain gap detected - requesting missing frames");

				// Convert Vec<u8> to [u8; 32]
				let requester_head: [u8; 32] = current_head.as_slice().try_into()
					.map_err(|_| TightBeamError::MissingSignature)?; // Using available error variant
				let last_received_hash: [u8; 32] = missing_hash.as_slice().try_into()
					.map_err(|_| TightBeamError::MissingSignature)?;

				// Build FrameRequest
				let _request = crate::dtn::messages::FrameRequest {
					requester_head,
					last_received_hash,
				};

				println!("[Earth] FrameRequest built (sending not implemented - needs frame building)");
				// TODO: Build frame containing FrameRequest, send to Relay, receive FrameResponse
				// This requires proper FrameBuilder support for RelayMessage enum

				Ok(None)
			}
		}
	}
}

// ============================================================================
// Relay Satellite Servlet
// ============================================================================

servlet! {
	/// Relay satellite that forwards messages between Earth and Rover
	pub RelaySatelliteServlet<RoverTelemetry>,
	protocol: TokioListener,
	x509: {
		certificate: SATELLITE_CERT,
		key_provider: SATELLITE_KEY,
		client_validators: [SATELLITE_PINNING_ROVER]
	},
	config: {
		earth_addr: TightBeamSocketAddr,
		rover_addr: TightBeamSocketAddr,
		rover_verifying_key: Secp256k1VerifyingKey,
		earth_verifying_key: Secp256k1VerifyingKey,
		chain_processor: Arc<ChainProcessor>,
		shared_cipher: Aes256Gcm,
	},
	handle: |frame, trace, config| async move {
		// Verify signature and determine source
		let from_rover = if frame.nonrepudiation.is_some() {
			if frame.verify::<Secp256k1Signature>(&config.rover_verifying_key).is_ok() {
				println!("[Satellite] ✓ Rover signature verified");
				true
			} else if frame.verify::<Secp256k1Signature>(&config.earth_verifying_key).is_ok() {
				println!("[Satellite] ✓ Earth signature verified");
				false
			} else {
				eprintln!("[Satellite] ✗ Signature verification FAILED");
				frame.verify::<Secp256k1Signature>(&config.rover_verifying_key)?;
				false
			}
		} else {
			false
		};

		// Emit appropriate receive event based on source
		if from_rover {
			trace.event("relay_receive_from_rover")?;
			trace.event("relay_forward_uplink")?;

		// Forward telemetry to Earth (Relay just forwards, doesn't process/order)
		let mut earth_client = ClientBuilder::<TokioListener>::connect(config.earth_addr)
			.await?
			.with_server_certificate(EARTH_CERT)?
			.with_client_identity(SATELLITE_CERT, SATELLITE_KEY)?
			.with_restart(RestartExponentialBackoff::new(3, 100, None))
			.with_timeout(Duration::from_millis(2000))
			.build()?;

		let response = earth_client.emit(frame, None).await?;
		Ok(response)
		} else {
		// Forward command from Earth to Rover (Relay just forwards, doesn't process/order)
		trace.event("relay_receive_from_earth")?;
		trace.event("relay_forward_downlink")?;
		
		let mut rover_client = ClientBuilder::<TokioListener>::connect(config.rover_addr)
			.await?
			.with_server_certificate(ROVER_CERT)?
			.with_client_identity(SATELLITE_CERT, SATELLITE_KEY)?
			.with_restart(RestartExponentialBackoff::new(3, 100, None))
			.with_timeout(Duration::from_millis(2000))
			.build()?;
			
		let response = rover_client.emit(frame, None).await?;
		Ok(response)
		}
	}
}

// ============================================================================
// Rover Servlet
// ============================================================================

/// Mission state for tracking rover mission progress
#[derive(Debug, Clone)]
pub struct MissionState {
	pub completed_rounds: usize,
	pub mission_started: bool,
	pub mission_complete: bool,
}

impl Default for MissionState {
	fn default() -> Self {
		Self { completed_rounds: 0, mission_started: false, mission_complete: false }
	}
}

servlet! {
	/// Mars rover servlet (currently unused - using direct client connection)
	pub RoverServlet<EarthCommand>,
	protocol: TokioListener,
	x509: {
		certificate: ROVER_CERT,
		key_provider: ROVER_KEY,
		client_validators: [ROVER_PINNING]
	},
	config: {
		relay_addr: TightBeamSocketAddr,
		rover_signing_key: Secp256k1SigningKey,
		earth_verifying_key: Secp256k1VerifyingKey,
		shared_cipher: Aes256Gcm,
		chain_processor: Arc<ChainProcessor>,
		fault_manager: Arc<FaultManager>,
		command_executor: Arc<RwLock<CommandExecutor>>,
		frame_builder: Arc<FrameBuilderHelper>,
		mission_state: Arc<RwLock<MissionState>>,
		max_rounds: usize,
		command_queue: Arc<RwLock<VecDeque<EarthCommand>>>,
	},
	handle: |_frame, _trace, _config| async move {
		// NOTE: Rover servlet currently unused - using direct client connection in mission loop
		// TODO: Migrate to servlet-based async command reception
		Ok(None)
	}
}
