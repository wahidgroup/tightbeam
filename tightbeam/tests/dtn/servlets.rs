//! DTN Servlets: 4-Tier Architecture
//!
//! This module contains the servlet definitions for the 4-tier DTN architecture:
//! - Mission Control: Receives telemetry, sends commands, validates ACKs
//! - Earth Relay Satellite: Forwards messages between Mission Control and Mars Relay
//! - Mars Relay Satellite: Forwards messages between Earth Relay and Rover
//! - Rover: Executes commands, sends telemetry and ACKs

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
	transport::tcp::r#async::TokioListener,
};

use crate::{
	debug_log,
	dtn::{
		certs::{
			EARTH_RELAY_CERT, EARTH_RELAY_KEY, EARTH_RELAY_PINNING, MARS_RELAY_CERT, MARS_RELAY_KEY,
			MARS_RELAY_PINNING, MISSION_CONTROL_CERT, MISSION_CONTROL_KEY, MISSION_CONTROL_PINNING, ROVER_CERT,
			ROVER_KEY, ROVER_PINNING,
		},
		chain_processor::{ChainProcessor, ProcessResult},
		clock::mission_time_ms,
		command_executor::CommandExecutor,
		fault_manager::FaultManager,
		frame_builder::FrameBuilderHelper,
		messages::{EarthCommand, RelayMessage, RoverCommand},
		utils::format_mission_time,
	},
};

// ============================================================================
// Mission Control Servlet
// ============================================================================

servlet! {
	/// Mission Control receives telemetry and sends commands to Rover via relays
	pub MissionControlServlet<RelayMessage>,
	protocol: TokioListener,
	x509: {
		certificate: MISSION_CONTROL_CERT,
		key_provider: MISSION_CONTROL_KEY,
		client_validators: [MISSION_CONTROL_PINNING]
	},
	config: {
		mission_control_signing_key: Secp256k1SigningKey,
		rover_verifying_key: Secp256k1VerifyingKey,
		earth_relay_verifying_key: Secp256k1VerifyingKey,
		shared_cipher: Aes256Gcm,
		chain_processor: Arc<ChainProcessor>,
		frame_builder: Arc<FrameBuilderHelper>,
		earth_relay_addr: TightBeamSocketAddr,
		shared_mission_state: Arc<RwLock<MissionState>>,
	},
	handle: |frame, trace, config| async move {
		// Verify signature (Earth Relay forwards messages, so could be from Rover)
		if frame.nonrepudiation.is_some() {
			if frame.verify::<Secp256k1Signature>(&config.rover_verifying_key).is_ok() {
				debug_log!("[Mission Control] ✓ Rover signature verified (via relays)");
			} else if frame.verify::<Secp256k1Signature>(&config.earth_relay_verifying_key).is_ok() {
				debug_log!("[Mission Control] ✓ Earth Relay signature verified");
			} else {
				eprintln!("[Mission Control] ✗ Signature verification FAILED");
				return Err(TightBeamError::MissingSignature);
			}
		}

		// Process frame (persist, order, validate chain)
		match config.chain_processor.process_incoming(frame.clone())? {
			ProcessResult::Processed(ordered_frames) => {
				for ordered_frame in ordered_frames {
					// Decrypt and decode RelayMessage
					let relay_message: RelayMessage = if ordered_frame.metadata.confidentiality.is_some() {
						use tightbeam::compress::{Inflator, ZstdCompression};
						let inflator: Option<&dyn Inflator> = if ordered_frame.metadata.compactness.is_some() {
							Some(&ZstdCompression)
						} else {
							None
						};
						ordered_frame.decrypt::<RelayMessage>(&config.shared_cipher, inflator)?
					} else {
						decode(&ordered_frame.message)?
					};

					// Handle based on message type
					match relay_message {
						RelayMessage::Telemetry(telemetry) => {
							trace.event("mission_control_receive_telemetry")?;

							debug_log!(
								"[{}] [Mission Control] Received telemetry (Battery: {}%)",
								format_mission_time(mission_time_ms()),
								telemetry.battery_percent
							);

							trace.event("mission_control_analyze_telemetry")?;

							// Increment telemetry counter
							config.shared_mission_state.write()?.telemetry_received_count += 1;
							let telemetry_count = config.shared_mission_state.read()?.telemetry_received_count;

							// Only send next command if we haven't reached the limit
							// We send 1 initial command + 5 subsequent = 6 total (COMMAND_ROUND_TRIPS)
							const MAX_COMMANDS: usize = 6;  // COMMAND_ROUND_TRIPS
							if telemetry_count < MAX_COMMANDS {
								// Spawn task to send next command
								let command_type = (telemetry_count % 3) as u8;
								let rover_cmd = match command_type {
									0 => RoverCommand::CollectSample { location: "Site Alpha".to_string() },
									1 => RoverCommand::ProbeLocation { x: 100, y: 200 },
									_ => RoverCommand::TakePhoto { direction: "North".to_string(), resolution: 1080 },
								};

								let (next_order, previous_digest) = config.chain_processor.prepare_outgoing()?;
								let command = EarthCommand::new(rover_cmd, tightbeam::asn1::MessagePriority::Normal, mission_time_ms());

								trace.event("mission_control_send_command")?;

								let command_frame = config.frame_builder.build_relay_command_frame(
									command,
									next_order,
									previous_digest,
									&config.mission_control_signing_key,
									&config.shared_cipher,
								)?;

								debug_log!(
									"[{}] [Mission Control] Sending command {} to Earth Relay",
									format_mission_time(mission_time_ms()),
									telemetry_count + 1
								);

								// Send command via new client connection
								let earth_relay_addr = config.earth_relay_addr;
								tokio::spawn(async move {
									match ClientBuilder::<TokioListener>::connect(earth_relay_addr)
										.await
										.and_then(|b| b.with_server_certificate(EARTH_RELAY_CERT))
										.and_then(|b| b.with_client_identity(MISSION_CONTROL_CERT, MISSION_CONTROL_KEY))
										.map(|b| b.with_timeout(Duration::from_millis(5000)))
										.and_then(|b| b.build())
									{
										Ok(mut client) => {
											match client.emit(command_frame, None).await {
												Ok(_) => debug_log!("[Mission Control] ✓ Command {} sent", telemetry_count + 1),
												Err(e) => eprintln!("[Mission Control] ✗ Send failed: {:?}", e),
											}
										},
										Err(e) => eprintln!("[Mission Control] ✗ Connect failed: {:?}", e),
									}
								});
							} else {
								debug_log!("[{}] [Mission Control] Mission complete, not sending more commands", format_mission_time(mission_time_ms()));
							}
						},
						RelayMessage::CommandAck(ack) => {
							trace.event("mission_control_receive_ack")?;
							debug_log!(
								"[{}] [Mission Control] Received ACK for command order {}",
								format_mission_time(mission_time_ms()),
								ack.command_order
							);
						},
						_ => {
							debug_log!("[Mission Control] Received unexpected message type");
						}
					}
				}

				// Return stateless ACK
				let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame.metadata.order)?;
				Ok(Some(stateless_ack))
			},
			ProcessResult::Buffered => Ok(None),
			ProcessResult::ChainGap { .. } => {
				// TODO: Send FrameRequest to Earth Relay (cascading gap recovery)
				Ok(None)
			},
		}
	}
}

// ============================================================================
// Earth Relay Satellite Servlet
// ============================================================================

servlet! {
	/// Earth Relay forwards messages between Mission Control and Mars Relay
	pub EarthRelaySatelliteServlet<RelayMessage>,
	protocol: TokioListener,
	x509: {
		certificate: EARTH_RELAY_CERT,
		key_provider: EARTH_RELAY_KEY,
		client_validators: [EARTH_RELAY_PINNING]
	},
	config: {
		mission_control_verifying_key: Secp256k1VerifyingKey,
		mars_relay_verifying_key: Secp256k1VerifyingKey,
		rover_verifying_key: Secp256k1VerifyingKey,
		mars_relay_addr: TightBeamSocketAddr,
		mission_control_addr: Arc<RwLock<Option<TightBeamSocketAddr>>>,
		chain_processor: Arc<ChainProcessor>,
		frame_builder: Arc<FrameBuilderHelper>,
	},
	handle: |frame, trace, config| async move {
		debug_log!("[Earth Relay] Received frame with order: {}", frame.metadata.order);

		// Verify signature and determine source
		let from_mission_control = if frame.nonrepudiation.is_some() {
			if frame.verify::<Secp256k1Signature>(&config.mission_control_verifying_key).is_ok() {
				debug_log!("[Earth Relay] ✓ Mission Control signature verified (order: {})", frame.metadata.order);
				true
			} else if frame.verify::<Secp256k1Signature>(&config.rover_verifying_key).is_ok() {
				debug_log!("[Earth Relay] ✓ Rover signature verified (order: {}) via Mars Relay", frame.metadata.order);
				false
		} else {
			eprintln!("[Earth Relay] ✗ Signature verification FAILED (order: {})", frame.metadata.order);
			return Err(TightBeamError::MissingSignature);
		}
	} else {
			eprintln!("[Earth Relay] ✗ No signature found (order: {})", frame.metadata.order);
			return Err(TightBeamError::MissingSignature);
		};

		// Get frame order before processing
		let frame_order = frame.metadata.order;

		// Process frame through Earth Relay's chain
		println!("[Earth Relay] Processing frame (order: {}, from_mission_control: {})", frame_order, from_mission_control);
		let process_result = match config.chain_processor.process_incoming(frame.clone()) {
			Ok(result) => {
				println!("[Earth Relay] process_incoming OK");
				result
			},
			Err(e) => {
				eprintln!("[Earth Relay] ✗ process_incoming FAILED: {:?}", e);
				return Err(e);
			}
		};
		println!("[Earth Relay] Matching on ProcessResult...");
		match process_result {
			ProcessResult::Processed(_) => {
				println!("[Earth Relay] ProcessResult::Processed branch");
				if from_mission_control {
					// Forward to Mars Relay
					println!("[Earth Relay] Recording trace events...");
					trace.event("earth_relay_receive_from_mc")?;
					trace.event("earth_relay_forward_to_mars")?;
					println!("[Earth Relay] Connecting to Mars Relay...");

					let mut mars_client = ClientBuilder::<TokioListener>::connect(config.mars_relay_addr)
						.await?
						.with_server_certificate(MARS_RELAY_CERT)?
						.with_client_identity(EARTH_RELAY_CERT, EARTH_RELAY_KEY)?
						.with_timeout(Duration::from_millis(5000))
						.build()?;

					let _ = mars_client.emit(frame, None).await?;

					// Return stateless ACK to Mission Control
					let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame_order)?;
					Ok(Some(stateless_ack))
				} else {
					// Determine message type from frame ID (relay-telem-NNN vs relay-ack-NNN)
					let is_telemetry = frame.metadata.id.starts_with(b"relay-telem");

					// Forward to Mission Control
					if is_telemetry {
						trace.event("earth_relay_receive_telemetry_from_mars")?;
						trace.event("earth_relay_forward_telemetry_to_mc")?;
					} else {
						trace.event("earth_relay_receive_ack_from_mars")?;
						trace.event("earth_relay_forward_ack_to_mc")?;
					}

					debug_log!("[{}] [Earth Relay] Forwarding from Mars Relay to Mission Control", format_mission_time(mission_time_ms()));

					// Get Mission Control address (wait if not set yet)
					let mc_addr = loop {
						if let Some(addr) = *config.mission_control_addr.read()? {
							break addr;
						}
						tokio::time::sleep(Duration::from_millis(10)).await;
					};

					let mut mc_client = ClientBuilder::<TokioListener>::connect(mc_addr)
						.await?
						.with_server_certificate(MISSION_CONTROL_CERT)?
						.with_client_identity(EARTH_RELAY_CERT, EARTH_RELAY_KEY)?
						.with_timeout(Duration::from_millis(5000))
						.build()?;

					let _ = mc_client.emit(frame, None).await?;

					// Fire-and-forget (no response to Mars Relay)
					Ok(None)
				}
			},
			ProcessResult::Buffered => Ok(None),
			ProcessResult::ChainGap { .. } => {
				// TODO: Handle gap recovery
				Ok(None)
			},
		}
	}
}

// ============================================================================
// Mars Relay Satellite Servlet
// ============================================================================

servlet! {
	/// Mars Relay forwards messages between Earth Relay and Rover
	pub MarsRelaySatelliteServlet<RelayMessage>,
	protocol: TokioListener,
	x509: {
		certificate: MARS_RELAY_CERT,
		key_provider: MARS_RELAY_KEY,
		client_validators: [MARS_RELAY_PINNING]
	},
	config: {
		mission_control_verifying_key: Secp256k1VerifyingKey,
		earth_relay_verifying_key: Secp256k1VerifyingKey,
		rover_verifying_key: Secp256k1VerifyingKey,
		rover_addr: TightBeamSocketAddr,
		earth_relay_addr: Arc<RwLock<Option<TightBeamSocketAddr>>>,
		chain_processor: Arc<ChainProcessor>,
		frame_builder: Arc<FrameBuilderHelper>,
	},
	handle: |frame, trace, config| async move {
		// Verify signature and determine source
		// Earth Relay forwards messages, so could be from Mission Control or Rover
		let from_rover = if frame.nonrepudiation.is_some() {
			if frame.verify::<Secp256k1Signature>(&config.rover_verifying_key).is_ok() {
				debug_log!("[Mars Relay] ✓ Rover signature verified");
				true
			} else if frame.verify::<Secp256k1Signature>(&config.mission_control_verifying_key).is_ok() {
				debug_log!("[Mars Relay] ✓ Mission Control signature verified (via Earth Relay)");
				false
			} else {
				eprintln!("[Mars Relay] ✗ Signature verification FAILED");
				return Err(TightBeamError::MissingSignature);
			}
		} else {
			eprintln!("[Mars Relay] ✗ No signature found");
			return Err(TightBeamError::MissingSignature);
		};

	// Get frame order before processing
	let frame_order = frame.metadata.order;

	// Process frame through Mars Relay's chain
	match config.chain_processor.process_incoming(frame.clone())? {
		ProcessResult::Processed(_) => {
			if from_rover {
				// Determine message type from frame ID (relay-telem-NNN vs relay-ack-NNN)
				let is_telemetry = frame.metadata.id.starts_with(b"relay-telem");

				// Forward to Earth Relay
				if is_telemetry {
					trace.event("mars_relay_receive_telemetry_from_rover")?;
					trace.event("mars_relay_forward_telemetry_to_earth")?;
				} else {
					trace.event("mars_relay_receive_ack_from_rover")?;
					trace.event("mars_relay_forward_ack_to_earth")?;
				}

				debug_log!("[{}] [Mars Relay] Forwarding from Rover to Earth Relay", format_mission_time(mission_time_ms()));

				// Get Earth Relay address (wait if not set yet)
				let earth_addr = loop {
					if let Some(addr) = *config.earth_relay_addr.read()? {
						break addr;
					}
					tokio::time::sleep(Duration::from_millis(10)).await;
				};

				let mut earth_client = ClientBuilder::<TokioListener>::connect(earth_addr)
					.await?
					.with_server_certificate(EARTH_RELAY_CERT)?
					.with_client_identity(MARS_RELAY_CERT, MARS_RELAY_KEY)?
					.with_timeout(Duration::from_millis(5000))
					.build()?;

				let _ = earth_client.emit(frame, None).await?;

				// Return stateless ACK to Rover
				let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame_order)?;
				Ok(Some(stateless_ack))
			} else {
				// Forward to Rover
				trace.event("mars_relay_receive_from_earth")?;
				trace.event("mars_relay_forward_to_rover")?;
				debug_log!("[{}] [Mars Relay] Forwarding from Earth Relay to Rover", format_mission_time(mission_time_ms()));

				let mut rover_client = ClientBuilder::<TokioListener>::connect(config.rover_addr)
					.await?
					.with_server_certificate(ROVER_CERT)?
					.with_client_identity(MARS_RELAY_CERT, MARS_RELAY_KEY)?
					.with_timeout(Duration::from_millis(5000))
					.build()?;

				println!("[Mars Relay] Emitting frame to Rover...");
				let response = rover_client.emit(frame, None).await?;
				println!("[Mars Relay] Response from Rover: {:?}", response.is_some());

				if let Some(ack_frame) = response {
					println!("[Mars Relay] Rover sent ACK, processing...");
					// Process Rover's ACK into chain and forward to Earth Relay
					config.chain_processor.process_incoming(ack_frame.clone())?;

					// Emit trace event for receiving ACK from Rover (stateful ACK for command)
					trace.event("mars_relay_receive_ack_from_rover")?;
					trace.event("mars_relay_forward_ack_to_earth")?;

					// Forward ACK to Earth Relay
					let earth_addr = loop {
						if let Some(addr) = *config.earth_relay_addr.read()? {
							break addr;
						}
						tokio::time::sleep(Duration::from_millis(10)).await;
					};

					let mut earth_client = ClientBuilder::<TokioListener>::connect(earth_addr)
						.await?
						.with_server_certificate(EARTH_RELAY_CERT)?
						.with_client_identity(MARS_RELAY_CERT, MARS_RELAY_KEY)?
						.with_timeout(Duration::from_millis(5000))
						.build()?;

					let _ = earth_client.emit(ack_frame, None).await?;
					println!("[Mars Relay] ACK forwarded to Earth Relay");
				}

				// Fire-and-forget (no response to Earth Relay)
				Ok(None)
			}
		},
			ProcessResult::Buffered => Ok(None),
			ProcessResult::ChainGap { .. } => {
				// TODO: Handle gap recovery
				Ok(None)
			},
		}
	}
}

// ============================================================================
// Rover Servlet
// ============================================================================

servlet! {
	/// Mars Rover executes commands and sends telemetry
	pub RoverServlet<RelayMessage>,
	protocol: TokioListener,
	x509: {
		certificate: ROVER_CERT,
		key_provider: ROVER_KEY,
		client_validators: [ROVER_PINNING]
	},
	config: {
		mars_relay_addr: TightBeamSocketAddr,
		rover_signing_key: Secp256k1SigningKey,
		mission_control_verifying_key: Secp256k1VerifyingKey,
		mars_relay_verifying_key: Secp256k1VerifyingKey,
		shared_cipher: Aes256Gcm,
		chain_processor: Arc<ChainProcessor>,
		fault_manager: Arc<FaultManager>,
		command_executor: Arc<RwLock<CommandExecutor>>,
		frame_builder: Arc<FrameBuilderHelper>,
		mission_state: Arc<RwLock<MissionState>>,
		max_rounds: usize,
	},
	handle: |frame, trace, config| async move {
		debug_log!("[{}] [Rover] Received frame", format_mission_time(mission_time_ms()));

		// Verify signature (Mars Relay forwards messages, so could be from Mission Control)
		if frame.nonrepudiation.is_some() {
			if frame.verify::<Secp256k1Signature>(&config.mission_control_verifying_key).is_ok() {
				debug_log!("[Rover] ✓ Mission Control signature verified (via relays)");
			} else if frame.verify::<Secp256k1Signature>(&config.mars_relay_verifying_key).is_ok() {
				debug_log!("[Rover] ✓ Mars Relay signature verified");
			} else {
				eprintln!("[Rover] ✗ Signature verification FAILED");
				return Err(TightBeamError::MissingSignature);
			}
		}

		// Get command order before consuming frame
		let command_order = frame.metadata.order;

		// Process frame through Rover's chain
		match config.chain_processor.process_incoming(frame.clone())? {
			ProcessResult::Processed(_) => {
				debug_log!("[{}] [Rover] Frame added to global chain", format_mission_time(mission_time_ms()));
			},
			ProcessResult::Buffered => {
				debug_log!("[{}] [Rover] Frame buffered", format_mission_time(mission_time_ms()));
				return Ok(None);
			},
			ProcessResult::ChainGap { .. } => {
				debug_log!("[{}] [Rover] Chain gap detected", format_mission_time(mission_time_ms()));
				return Ok(None);
			}
		}

		// Decrypt and decode RelayMessage
		let relay_message: RelayMessage = if frame.metadata.confidentiality.is_some() {
			use tightbeam::compress::{Inflator, ZstdCompression};
			let inflator: Option<&dyn Inflator> = if frame.metadata.compactness.is_some() {
				Some(&ZstdCompression)
			} else {
				None
			};
			frame.decrypt::<RelayMessage>(&config.shared_cipher, inflator)?
		} else {
			decode(&frame.message)?
		};

		// Process the RelayMessage
		match relay_message {
			RelayMessage::Command(command) => {
				debug_log!("[{}] [Rover] Received command", format_mission_time(mission_time_ms()));
				trace.event("rover_receive_command")?;

				// Execute command
				let cmd_type = RoverCommand::try_from(command.command_type)?;
				debug_log!("[{}] [Rover] Executing command: {}", format_mission_time(mission_time_ms()), cmd_type);

				trace.event("rover_execute_command")?;
				config.command_executor.write()?.execute_command(cmd_type, &trace)?;
				trace.event("rover_command_complete")?;

				// Update mission state
				{
					let mut state = config.mission_state.write()?;
					state.completed_rounds += 1;

					debug_log!("[{}] [Rover] Command {}/{} executed",
						format_mission_time(mission_time_ms()),
						state.completed_rounds,
						config.max_rounds);

					if state.completed_rounds >= config.max_rounds {
						state.mission_complete = true;
						debug_log!("[{}] [Rover] ✓ Mission complete!", format_mission_time(mission_time_ms()));
					}
				}

				// Build stateful ACK as response
				let (ack_order, ack_prev_digest) = config.chain_processor.prepare_outgoing()?;
				let ack_frame = config.frame_builder.build_relay_ack_frame(
					command_order,
					ack_order,
					ack_prev_digest,
					&config.rover_signing_key,
					&config.shared_cipher,
				)?;

				trace.event("rover_send_ack")?;
				debug_log!(
					"[{}] [Rover] Returning stateful ACK for command order {}",
					format_mission_time(mission_time_ms()),
					command_order
				);

				// Return stateful ACK as response
				Ok(Some(ack_frame))
			},
			_ => {
				debug_log!("[{}] [Rover] Received unexpected RelayMessage type", format_mission_time(mission_time_ms()));
				Ok(None)
			}
		}
	}
}

// ============================================================================
// Mission State (shared across nodes for coordination)
// ============================================================================

pub struct MissionState {
	pub completed_rounds: usize,
	pub telemetry_received_count: usize,
	/// Track if mission has started (available for pre-mission validation)
	pub _mission_started: bool,
	pub mission_complete: bool,
}

impl Default for MissionState {
	fn default() -> Self {
		Self {
			completed_rounds: 0,
			telemetry_received_count: 0,
			_mission_started: false,
			mission_complete: false,
		}
	}
}
