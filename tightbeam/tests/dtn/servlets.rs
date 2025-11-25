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

use crate::{
	debug_log,
	dtn::{
		certs::{
			EARTH_CERT, EARTH_KEY, EARTH_PINNING, ROVER_CERT, ROVER_KEY, ROVER_PINNING, SATELLITE_CERT, SATELLITE_KEY,
			SATELLITE_PINNING,
		},
		chain_processor::{ChainProcessor, ProcessResult},
		clock::mission_time_ms,
		command_executor::CommandExecutor,
		fault_manager::FaultManager,
		fault_matrix::FaultMatrix,
		frame_builder::FrameBuilderHelper,
		messages::{EarthCommand, FrameRequest, FrameResponse, RelayMessage, RoverCommand, RoverTelemetry},
		utils::format_mission_time,
	},
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
				Ok(_) => debug_log!("[Earth] ✓ Rover signature verified"),
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

					debug_log!("[{}] [Earth] Received telemetry", format_mission_time(mission_time_ms()));
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

					debug_log!("[{}] [Earth] ✓ Command frame built, returning as response", format_mission_time(mission_time_ms()));
					last_response = Some(command_frame);
				}

				Ok(last_response)
			},
			ProcessResult::Buffered => Ok(None),
			ProcessResult::ChainGap { current_head, missing_hash } => {
				eprintln!("[Earth] Chain gap detected - requesting missing frames");

				// Convert Vec<u8> to [u8; 32]
				let requester_head: [u8; 32] = current_head.as_slice().try_into()
					.map_err(|_| TightBeamError::MissingSignature)?;
				let last_received_hash: [u8; 32] = missing_hash.as_slice().try_into()
					.map_err(|_| TightBeamError::MissingSignature)?;

				// Build FrameRequest
				let request = crate::dtn::messages::FrameRequest {
					requester_head,
					last_received_hash,
				};

				// Build frame containing the request
				let (next_order, previous_digest) = config.chain_processor.prepare_outgoing()?;
				let request_frame = config.frame_builder.build_frame_request_frame(
					request,
					next_order,
					previous_digest,
					&config.earth_signing_key,
				)?;

				debug_log!("[{}] [Earth] Sending FrameRequest to Relay", format_mission_time(mission_time_ms()));

				// Connect to Relay and send request
				let mut relay_client = ClientBuilder::<TokioListener>::connect(config.relay_addr)
					.await?
					.with_server_certificate(SATELLITE_CERT)?
					.with_client_identity(EARTH_CERT, EARTH_KEY)?
					.with_restart(RestartExponentialBackoff::new(3, 100, None))
					.with_timeout(Duration::from_millis(2000))
					.build()?;

				let response = relay_client.emit(request_frame, None).await?;

				if let Some(response_frame) = response {
					// Process the FrameResponse containing missing frames
					let frame_response: crate::dtn::messages::FrameResponse =
						tightbeam::decode(&response_frame.message)?;

					debug_log!("[{}] [Earth] Received {} missing frames from Relay", format_mission_time(mission_time_ms()), frame_response.frames.len());

					// Process missing frames in order
					for missing_frame in frame_response.frames {
						config.chain_processor.process_incoming(missing_frame)?;
					}

					debug_log!("[{}] [Earth] Chain gap resolved", format_mission_time(mission_time_ms()));
				}

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
		client_validators: [SATELLITE_PINNING]
	},
	config: {
		earth_addr: TightBeamSocketAddr,
		rover_addr: TightBeamSocketAddr,
		rover_verifying_key: Secp256k1VerifyingKey,
		earth_verifying_key: Secp256k1VerifyingKey,
		chain_processor: Arc<ChainProcessor>,
		shared_cipher: Aes256Gcm,
		relay_signing_key: Secp256k1SigningKey,
		frame_builder: Arc<FrameBuilderHelper>,
	},
	handle: |frame, trace, config| async move {
		// Check if this is a FrameRequest (chain gap recovery)
		let is_frame_request = if let Ok(request) = tightbeam::decode::<FrameRequest>(&frame.message) {
			// Handle FrameRequest from Earth
			debug_log!("[{}] [Satellite] Received FrameRequest from Earth", format_mission_time(mission_time_ms()));

			// Request missing frames from chain processor
			let missing_frames = config.chain_processor.request_missing_frames(
				&request.requester_head,
				&request.last_received_hash,
			)?;

			debug_log!("[{}] [Satellite] Found {} missing frames, sending response", format_mission_time(mission_time_ms()), missing_frames.len());

			// Build FrameResponse
			let response = FrameResponse { frames: missing_frames };
			let (next_order, previous_digest) = config.chain_processor.prepare_outgoing()?;
			let response_frame = config.frame_builder.build_frame_response_frame(
				response,
				next_order,
				previous_digest,
				&config.relay_signing_key,
			)?;

			return Ok(Some(response_frame));
		} else {
			false
		};

		if is_frame_request {
			return Ok(None);
		}

		// Verify signature and determine source
		let from_rover = if frame.nonrepudiation.is_some() {
			if frame.verify::<Secp256k1Signature>(&config.rover_verifying_key).is_ok() {
				debug_log!("[Satellite] ✓ Rover signature verified");
				true
			} else if frame.verify::<Secp256k1Signature>(&config.earth_verifying_key).is_ok() {
				debug_log!("[Satellite] ✓ Earth signature verified");
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
	/// Track if mission has started (available for pre-mission validation)
	pub _mission_started: bool,
	pub mission_complete: bool,
}

impl Default for MissionState {
	fn default() -> Self {
		Self { completed_rounds: 0, _mission_started: false, mission_complete: false }
	}
}

servlet! {
	/// Mars rover servlet - receives async commands from Earth (via Relay)
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
	handle: |frame, trace, config| async move {
		debug_log!("[{}] [Rover Servlet] Received async command", format_mission_time(mission_time_ms()));

		// Verify Earth's signature
		if frame.nonrepudiation.is_some() {
			match frame.verify::<Secp256k1Signature>(&config.earth_verifying_key) {
				Ok(_) => debug_log!("[Rover Servlet] ✓ Earth signature verified"),
				Err(e) => {
					eprintln!("[Rover Servlet] ✗ Earth signature verification FAILED");
					return Err(e);
				}
			}
		}

		// Decrypt and decompress the frame if needed
		let relay_message: RelayMessage = if frame.metadata.confidentiality.is_some() {
			use tightbeam::compress::{Inflator, ZstdCompression};
			let inflator: Option<&dyn Inflator> = if frame.metadata.compactness.is_some() {
				Some(&ZstdCompression)
			} else {
				None
			};
			debug_log!("[Rover Servlet] Decrypting frame...");
			frame.decrypt::<RelayMessage>(&config.shared_cipher, inflator)?
		} else {
			debug_log!("[Rover Servlet] Decoding unencrypted frame...");
			tightbeam::decode(&frame.message)?
		};

		debug_log!("[Rover Servlet] Successfully decoded RelayMessage");

		// Process the RelayMessage
		match relay_message {
			RelayMessage::Command(command) => {
				debug_log!("[{}] [Rover Servlet] Received async command", format_mission_time(mission_time_ms()));
				trace.event("rover_receive_async_command")?;

				// Execute command immediately (servlets are isolated, can't share queues)
				let cmd_type = RoverCommand::try_from(command.command_type)?;
				debug_log!("[{}] [Rover Servlet] Executing command: {}", format_mission_time(mission_time_ms()), cmd_type);

				config.command_executor.write()?.execute_command(cmd_type, &trace)?;
				trace.event("rover_command_complete")?;

				// Update mission state (shared via DtnScenarioConfig)
				{
					let mut state = config.mission_state.write()?;
					state.completed_rounds += 1;

					debug_log!("[{}] [Rover Servlet] Command {}/{} executed",
						format_mission_time(mission_time_ms()),
						state.completed_rounds,
						config.max_rounds);

					if state.completed_rounds >= config.max_rounds {
						state.mission_complete = true;
						debug_log!("[{}] [Rover Servlet] ✓ Mission complete!", format_mission_time(mission_time_ms()));
					}
				}

				// Return empty response (acknowledgment)
				Ok(None)
			}
			_ => {
				debug_log!("[{}] [Rover Servlet] Received non-command RelayMessage, ignoring", format_mission_time(mission_time_ms()));
				Ok(None)
			}
		}
	}
}
