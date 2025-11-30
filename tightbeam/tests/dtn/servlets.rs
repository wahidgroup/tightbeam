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
	asn1::MessagePriority,
	compress::{Inflator, ZstdCompression},
	crypto::{
		aead::Aes256Gcm,
		sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey},
	},
	decode,
	prelude::*,
	servlet,
	testing::trace::TraceCollector,
	transport::{tcp::r#async::TokioListener, ConnectionPool},
};

use crate::dtn::{
	chain_processor::{ChainProcessor, ProcessResult},
	clock::mission_time_ms,
	fault_manager::FaultManager,
	frame_builder::FrameBuilderHelper,
	messages::{EarthCommand, FrameRequest, FrameResponse, RelayMessage, RoverCommand},
	workers::{command_execution::CommandExecutionWorker, messages::CommandExecutionRequest},
};

// ============================================================================
// DTN Node Trait - Shared behavior for all nodes
// ============================================================================

trait DtnNode {
	// Abstract methods (each servlet config implements)
	fn node_name(&self) -> &str;
	fn signing_key(&self) -> &Secp256k1SigningKey;
	fn verifying_keys(&self) -> Vec<&Secp256k1VerifyingKey>;
	fn cipher(&self) -> &Aes256Gcm;
	fn chain_processor(&self) -> &Arc<ChainProcessor>;
	fn frame_builder(&self) -> &Arc<FrameBuilderHelper>;

	// Default trait methods (reusable across all nodes)
	fn verify_signature(&self, frame: &Frame) -> Result<bool, TightBeamError> {
		if frame.nonrepudiation.is_none() {
			return Ok(false);
		}
		for key in self.verifying_keys() {
			if frame.verify::<Secp256k1Signature>(key).is_ok() {
				return Ok(true);
			}
		}
		Ok(false)
	}

	fn decrypt_relay_message(&self, frame: Frame) -> Result<RelayMessage, TightBeamError> {
		if frame.metadata.confidentiality.is_some() {
			let inflator: Option<&dyn Inflator> = if frame.metadata.compactness.is_some() {
				Some(&ZstdCompression)
			} else {
				None
			};
			frame.decrypt::<RelayMessage>(self.cipher(), inflator)
		} else {
			decode(&frame.message)
		}
	}

	// Send frame using pre-configured connection pool
	async fn send_frame(
		&self,
		pool: &Arc<ConnectionPool<TokioListener, 3>>,
		addr: TightBeamSocketAddr,
		frame: Frame,
	) -> Result<Option<Frame>, TightBeamError> {
		let mut client = pool.connect(addr).await?;
		Ok(client.emit(frame, None).await?)
	}

	// Gap recovery with pooling
	async fn handle_frame_request(
		&self,
		request: FrameRequest,
		trace: &TraceCollector,
		cascade_target: Option<(&Arc<ConnectionPool<TokioListener, 3>>, TightBeamSocketAddr)>,
	) -> Result<Option<Frame>, TightBeamError> {
		trace.event(format!("{}_receive_frame_request", self.node_name()))?;

		let missing_frames = self
			.chain_processor()
			.request_missing_frames(&request.requester_head, &request.last_received_hash)?;

		if !missing_frames.is_empty() {
			trace.event(format!("{}_send_frame_response", self.node_name()))?;

			let response = FrameResponse { frames: missing_frames };
			let (order, prev_digest) = self.chain_processor().prepare_outgoing()?;
			let response_frame = self.frame_builder().build_frame_response_frame(
				response,
				order,
				prev_digest,
				self.signing_key(),
				self.cipher(),
			)?;

			self.chain_processor().finalize_outgoing(&response_frame)?;
			Ok(Some(response_frame))
		} else if let Some((pool, addr)) = cascade_target {
			trace.event(format!("{}_cascade_frame_request", self.node_name()))?;

			let (order, prev_digest) = self.chain_processor().prepare_outgoing()?;
			let cascade_frame = self.frame_builder().build_frame_request_frame(
				request,
				order,
				prev_digest,
				self.signing_key(),
				self.cipher(),
			)?;

			self.chain_processor().finalize_outgoing(&cascade_frame)?;
			self.send_frame(pool, addr, cascade_frame).await?;
			Ok(None)
		} else {
			Ok(None)
		}
	}

	fn handle_frame_response(&self, response: FrameResponse, trace: &TraceCollector) -> Result<(), TightBeamError> {
		trace.event(format!("{}_receive_frame_response", self.node_name()))?;

		for frame in response.frames {
			self.chain_processor().process_incoming(frame)?;
		}

		Ok(())
	}

	// Helper: Process FrameResponse and return stateless ACK
	fn process_frame_response(
		&self,
		response: FrameResponse,
		frame_order: u64,
		trace: &TraceCollector,
	) -> Result<Option<Frame>, TightBeamError> {
		self.handle_frame_response(response, trace)?;
		let stateless_ack = self.frame_builder().build_stateless_ack_frame(frame_order)?;
		Ok(Some(stateless_ack))
	}

	// Helper: Build and send FrameResponse for gap recovery
	fn build_and_send_frame_response(
		&self,
		missing_frames: Vec<Frame>,
		trace: &TraceCollector,
	) -> Result<Frame, TightBeamError> {
		trace.event(format!("{}_send_frame_response", self.node_name()))?;

		let response = FrameResponse { frames: missing_frames };
		let (order, prev_digest) = self.chain_processor().prepare_outgoing()?;
		let response_frame = self.frame_builder().build_frame_response_frame(
			response,
			order,
			prev_digest,
			self.signing_key(),
			self.cipher(),
		)?;

		self.chain_processor().finalize_outgoing(&response_frame)?;
		Ok(response_frame)
	}

	async fn handle_chain_gap(
		&self,
		current_head: Vec<u8>,
		missing_hash: Vec<u8>,
		pool: &Arc<ConnectionPool<TokioListener, 3>>,
		upstream_addr: TightBeamSocketAddr,
		trace: &TraceCollector,
	) -> Result<(), TightBeamError> {
		trace.event(format!("{}_gap_detected", self.node_name()))?;

		let request = FrameRequest {
			requester_head: current_head.try_into().unwrap_or([0u8; 32]),
			last_received_hash: missing_hash.try_into().unwrap_or([0u8; 32]),
		};

		let (order, prev_digest) = self.chain_processor().prepare_outgoing()?;
		let request_frame = self.frame_builder().build_frame_request_frame(
			request,
			order,
			prev_digest,
			self.signing_key(),
			self.cipher(),
		)?;

		self.chain_processor().finalize_outgoing(&request_frame)?;
		trace.event(format!("{}_send_frame_request", self.node_name()))?;

		self.send_frame(pool, upstream_addr, request_frame).await?;
		Ok(())
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Helper: Wait for an address to be set (with timeout)
async fn wait_for_address(
	addr_lock: &Arc<RwLock<Option<TightBeamSocketAddr>>>,
) -> Result<TightBeamSocketAddr, TightBeamError> {
	loop {
		if let Some(addr) = *addr_lock.read()? {
			break Ok(addr);
		}

		tokio::time::sleep(Duration::from_millis(10)).await;
	}
}

// ============================================================================
// Mission Control Servlet
// ============================================================================

#[derive(Clone)]
pub struct MissionControlServletConf {
	pub mission_control_signing_key: Secp256k1SigningKey,
	pub rover_verifying_key: Secp256k1VerifyingKey,
	pub earth_relay_verifying_key: Secp256k1VerifyingKey,
	pub shared_cipher: Aes256Gcm,
	pub chain_processor: Arc<ChainProcessor>,
	pub frame_builder: Arc<FrameBuilderHelper>,
	pub earth_relay_addr: TightBeamSocketAddr,
	pub earth_relay_pool: Arc<ConnectionPool<TokioListener, 3>>,
	pub shared_mission_state: Arc<RwLock<MissionState>>,
}

servlet! {
	/// Mission Control receives telemetry and sends commands to Rover via relays
	pub MissionControlServlet<RelayMessage, EnvConfig = MissionControlServletConf>,
	protocol: TokioListener,
	handle: |frame, trace, config, _workers| async move {
		// Verify signature using trait method
		if !config.verify_signature(&frame)? {
			return Err(TightBeamError::MissingSignature);
		}

		// Process frame (persist, order, validate chain)
		match config.chain_processor.process_incoming(frame.clone())? {
			ProcessResult::Processed(ordered_frames) => {
				for ordered_frame in ordered_frames {
					// Decrypt and decode using trait method
					let relay_message = config.decrypt_relay_message(ordered_frame.clone())?;
					match relay_message {
						RelayMessage::Telemetry(_) => {
							trace.event("mission_control_receive_telemetry")?;
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
								let command = EarthCommand::new(rover_cmd, MessagePriority::Normal, mission_time_ms());

								trace.event("mission_control_send_command")?;

								let command_frame = config.frame_builder.build_relay_command_frame(
									command,
									next_order,
									previous_digest,
									&config.mission_control_signing_key,
									&config.shared_cipher,
								)?;

								// Send command via pooled client
								config.send_frame(
									&config.earth_relay_pool,
									config.earth_relay_addr,
									command_frame,
								).await?;
							}
						},
						RelayMessage::CommandAck(_) => {
							trace.event("mission_control_receive_ack")?;
						},
						RelayMessage::FrameRequest(request) => {
							// Use trait method - Mission Control is origin so no cascade target
							if let Some(response_frame) = config.handle_frame_request(request, &trace, None).await? {
								return Ok(Some(response_frame));
							}
						},
						RelayMessage::FrameResponse(response) => {
							// Use trait method
							config.handle_frame_response(response, &trace)?;
						},
						RelayMessage::Command(_) => {
							// Invalid message type
							return Err(TightBeamError::InvalidBody);
						}
					}
				}

				// Return stateless ACK
				let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame.metadata.order)?;
				Ok(Some(stateless_ack))
			},
			ProcessResult::Buffered => Ok(None),
			ProcessResult::ChainGap { current_head, missing_hash } => {
				// Use trait method with pooled client
				config.handle_chain_gap(
					current_head,
					missing_hash,
					&config.earth_relay_pool,
					config.earth_relay_addr,
					&trace,
				).await?;
				Ok(None)
			},
		}
	}
}

impl DtnNode for MissionControlServletConf {
	fn node_name(&self) -> &str {
		"mission_control"
	}

	fn signing_key(&self) -> &Secp256k1SigningKey {
		&self.mission_control_signing_key
	}

	fn verifying_keys(&self) -> Vec<&Secp256k1VerifyingKey> {
		vec![&self.rover_verifying_key, &self.earth_relay_verifying_key]
	}

	fn cipher(&self) -> &Aes256Gcm {
		&self.shared_cipher
	}

	fn chain_processor(&self) -> &Arc<ChainProcessor> {
		&self.chain_processor
	}

	fn frame_builder(&self) -> &Arc<FrameBuilderHelper> {
		&self.frame_builder
	}
}

// ============================================================================
// Earth Relay Satellite Servlet
// ============================================================================

#[derive(Clone)]
pub struct EarthRelaySatelliteServletConf {
	pub earth_relay_signing_key: Secp256k1SigningKey,
	pub mission_control_verifying_key: Secp256k1VerifyingKey,
	pub mars_relay_verifying_key: Secp256k1VerifyingKey,
	pub rover_verifying_key: Secp256k1VerifyingKey,
	pub shared_cipher: Aes256Gcm,
	pub mars_relay_addr: TightBeamSocketAddr,
	pub mission_control_addr: Arc<RwLock<Option<TightBeamSocketAddr>>>,
	pub mission_control_pool: Arc<ConnectionPool<TokioListener, 3>>,
	pub mars_relay_pool: Arc<ConnectionPool<TokioListener, 3>>,
	pub chain_processor: Arc<ChainProcessor>,
	pub frame_builder: Arc<FrameBuilderHelper>,
}

servlet! {
	/// Earth Relay forwards messages between Mission Control and Mars Relay
	pub EarthRelaySatelliteServlet<RelayMessage, EnvConfig = EarthRelaySatelliteServletConf>,
	protocol: TokioListener,
	handle: |frame, trace, config, _workers| async move {
		// Verify signature and determine source
		let from_mission_control = if frame.nonrepudiation.is_some() {
			if frame.verify::<Secp256k1Signature>(&config.mission_control_verifying_key).is_ok() {
				true
			} else if frame.verify::<Secp256k1Signature>(&config.rover_verifying_key).is_ok() {
				false
			} else {
				return Err(TightBeamError::MissingSignature);
			}
		} else {
			return Err(TightBeamError::MissingSignature);
		};

		// Get frame order before processing
		let frame_order = frame.metadata.order;
		// Process frame through Earth Relay's chain
		let process_result = match config.chain_processor.process_incoming(frame.clone()) {
			Ok(result) => {
				result
			},
			Err(e) => {
				return Err(e);
			}
		};

		match process_result {
			ProcessResult::Processed(ordered_frames) => {
				// Check if any processed frames are gap recovery messages
				if let Some(ordered_frame) = ordered_frames.into_iter().next() {
					// Decrypt and decode to check message type
					let relay_message = config.decrypt_relay_message(ordered_frame.clone())?;
					match relay_message {
						RelayMessage::FrameRequest(request) => {
							trace.event("earth_relay_receive_frame_request")?;

							let missing_frames = config.chain_processor.request_missing_frames(
								&request.requester_head,
								&request.last_received_hash,
							)?;

							if !missing_frames.is_empty() {
								let response_frame = config.build_and_send_frame_response(missing_frames, &trace)?;
								return Ok(Some(response_frame));
							} else {
								// We don't have frames - cascade to upstream
								trace.event("earth_relay_cascade_frame_request")?;

								let (cascade_pool, cascade_addr) = if from_mission_control {
									// Request from MC, cascade to Mars Relay
									(&config.mars_relay_pool, config.mars_relay_addr)
								} else {
									// Request from Mars, cascade to MC (rare but possible)
									match *config.mission_control_addr.read()? {
										Some(mc_addr) => (&config.mission_control_pool, mc_addr),
										None => return Ok(None), // MC address not available yet
									}
								};

								let (order, prev_digest) = config.chain_processor.prepare_outgoing()?;
								let cascade_frame = config.frame_builder.build_frame_request_frame(
									request,
									order,
									prev_digest,
									&config.earth_relay_signing_key,
									&config.shared_cipher,
								)?;

								config.chain_processor.finalize_outgoing(&cascade_frame)?;
								config.send_frame(cascade_pool, cascade_addr, cascade_frame).await?;

								return Ok(None); // Cascade is async, no immediate response
							}
						},
						RelayMessage::FrameResponse(response) => {
							return config.process_frame_response(response, frame_order, &trace);
						},
						_ => {
							// Regular message - route based on source
							if from_mission_control {
								// Forward to Mars Relay using cached client
								trace.event("earth_relay_receive_from_mc")?;
								trace.event("earth_relay_forward_to_mars")?;

								config.send_frame(
									&config.mars_relay_pool,
									config.mars_relay_addr,
									frame,
								).await?;

								// Return stateless ACK to Mission Control
								let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame_order)?;
								return Ok(Some(stateless_ack));
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

								// Get Mission Control address (wait if not set yet)
								let mc_addr = wait_for_address(&config.mission_control_addr).await?;

								// Use pooled client
								config.send_frame(
									&config.mission_control_pool,
									mc_addr,
									frame,
								).await?;

								// Fire-and-forget (no response to Mars Relay)
								return Ok(None);
							}
						}
					}
				}

				Ok(None)
			},
			ProcessResult::Buffered => Ok(None),
			ProcessResult::ChainGap { current_head, missing_hash } => {
				// Use trait method with pooled client
				config.handle_chain_gap(
					current_head,
					missing_hash,
					&config.mars_relay_pool,
					config.mars_relay_addr,
					&trace,
				).await?;
				Ok(None)
			},
		}
	}
}

impl DtnNode for EarthRelaySatelliteServletConf {
	fn node_name(&self) -> &str {
		"earth_relay"
	}

	fn signing_key(&self) -> &Secp256k1SigningKey {
		&self.earth_relay_signing_key
	}

	fn verifying_keys(&self) -> Vec<&Secp256k1VerifyingKey> {
		vec![
			&self.mission_control_verifying_key,
			&self.mars_relay_verifying_key,
			&self.rover_verifying_key,
		]
	}

	fn cipher(&self) -> &Aes256Gcm {
		&self.shared_cipher
	}

	fn chain_processor(&self) -> &Arc<ChainProcessor> {
		&self.chain_processor
	}

	fn frame_builder(&self) -> &Arc<FrameBuilderHelper> {
		&self.frame_builder
	}
}

// ============================================================================
// Mars Relay Satellite Servlet
// ============================================================================

#[derive(Clone)]
pub struct MarsRelaySatelliteServletConf {
	pub mars_relay_signing_key: Secp256k1SigningKey,
	pub mission_control_verifying_key: Secp256k1VerifyingKey,
	pub earth_relay_verifying_key: Secp256k1VerifyingKey,
	pub rover_verifying_key: Secp256k1VerifyingKey,
	pub shared_cipher: Aes256Gcm,
	pub rover_addr: TightBeamSocketAddr,
	pub earth_relay_addr: Arc<RwLock<Option<TightBeamSocketAddr>>>,
	pub earth_relay_pool: Arc<ConnectionPool<TokioListener, 3>>,
	pub rover_pool: Arc<ConnectionPool<TokioListener, 3>>,
	pub chain_processor: Arc<ChainProcessor>,
	pub frame_builder: Arc<FrameBuilderHelper>,
}

servlet! {
	/// Mars Relay forwards messages between Earth Relay and Rover
	pub MarsRelaySatelliteServlet<RelayMessage, EnvConfig = MarsRelaySatelliteServletConf>,
	protocol: TokioListener,
	handle: |frame, trace, config, _workers| async move {
		// Verify signature and determine source
		// Earth Relay forwards messages, so could be from Mission Control or Rover
		let from_rover = if frame.nonrepudiation.is_some() {
			if frame.verify::<Secp256k1Signature>(&config.rover_verifying_key).is_ok() {
				true
			} else if frame.verify::<Secp256k1Signature>(&config.mission_control_verifying_key).is_ok() {
				false
			} else {
				return Err(TightBeamError::MissingSignature);
			}
		} else {
			return Err(TightBeamError::MissingSignature);
		};

		// Get frame order before processing
		let frame_order = frame.metadata.order;
		// Process frame through Mars Relay's chain
		match config.chain_processor.process_incoming(frame.clone())? {
			ProcessResult::Processed(ordered_frames) => {
				// Check if any processed frames are gap recovery messages
				for ordered_frame in ordered_frames {
					// Decrypt and decode to check message type
					let relay_message = config.decrypt_relay_message(ordered_frame.clone())?;
					match relay_message {
						RelayMessage::FrameRequest(request) => {
							trace.event("mars_relay_receive_frame_request")?;

							let missing_frames = config.chain_processor.request_missing_frames(
								&request.requester_head,
								&request.last_received_hash,
							)?;

							if !missing_frames.is_empty() {
								let response_frame = config.build_and_send_frame_response(missing_frames, &trace)?;
								return Ok(Some(response_frame));
							} else {
								// We don't have frames - cascade to upstream
								trace.event("mars_relay_cascade_frame_request")?;

								let (cascade_pool, cascade_addr) = if from_rover {
									// Request from Rover, cascade to Earth Relay
									match *config.earth_relay_addr.read()? {
										Some(earth_addr) => (&config.earth_relay_pool, earth_addr),
										None => return Ok(None), // Earth address not available yet
									}
								} else {
									// Request from Earth, cascade to Rover
									(&config.rover_pool, config.rover_addr)
								};

								let (order, prev_digest) = config.chain_processor.prepare_outgoing()?;
								let cascade_frame = config.frame_builder.build_frame_request_frame(
									request,
									order,
									prev_digest,
									&config.mars_relay_signing_key,
									&config.shared_cipher,
								)?;

								config.chain_processor.finalize_outgoing(&cascade_frame)?;
								config.send_frame(cascade_pool, cascade_addr, cascade_frame).await?;
								return Ok(None); // Cascade is async, no immediate response
							}
						},
						RelayMessage::FrameResponse(response) => {
							return config.process_frame_response(response, frame_order, &trace);
						},
						_ => {
							// Regular message - route based on source
							// Fall through to routing logic below
						}
					}
				}

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

					// Get Earth Relay address (wait if not set yet)
					let earth_addr = wait_for_address(&config.earth_relay_addr).await?;

					// Use pooled client
					config.send_frame(
						&config.earth_relay_pool,
						earth_addr,
						frame,
					).await?;

					// Return stateless ACK to Rover
					let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame_order)?;
					Ok(Some(stateless_ack))
				} else {
					// Forward to Rover using cached client
					trace.event("mars_relay_receive_from_earth")?;
					trace.event("mars_relay_forward_to_rover")?;

					let response = config.send_frame(
						&config.rover_pool,
						config.rover_addr,
						frame,
					).await?;

					if let Some(ack_frame) = response {
						// Process Rover's ACK into chain and forward to Earth Relay
						config.chain_processor.process_incoming(ack_frame.clone())?;

						// Emit trace event for receiving ACK from Rover (stateful ACK for command)
						trace.event("mars_relay_receive_ack_from_rover")?;
						trace.event("mars_relay_forward_ack_to_earth")?;

						// Forward ACK to Earth Relay using cached client
						let earth_addr = wait_for_address(&config.earth_relay_addr).await?;

						config.send_frame(
							&config.earth_relay_pool,
							earth_addr,
							ack_frame,
						).await?;
					}

					// Fire-and-forget (no response to Earth Relay)
					Ok(None)
				}
			},
			ProcessResult::Buffered => Ok(None),
			ProcessResult::ChainGap { current_head, missing_hash } => {
				// Determine upstream based on gap source
				let (upstream_pool, upstream_addr) = if from_rover {
					// Gap from Rover direction, cascade to Earth Relay
					match *config.earth_relay_addr.read()? {
						Some(earth_addr) => (&config.earth_relay_pool, earth_addr),
						None => return Ok(None), // Earth address not available yet
					}
				} else {
					// Gap from Earth direction, cascade to Rover
					(&config.rover_pool, config.rover_addr)
				};

				// Use trait method with pooled client
				config.handle_chain_gap(
					current_head,
					missing_hash,
					upstream_pool,
					upstream_addr,
					&trace,
				).await?;
				Ok(None)
			},
		}
	}
}

impl DtnNode for MarsRelaySatelliteServletConf {
	fn node_name(&self) -> &str {
		"mars_relay"
	}

	fn signing_key(&self) -> &Secp256k1SigningKey {
		&self.mars_relay_signing_key
	}

	fn verifying_keys(&self) -> Vec<&Secp256k1VerifyingKey> {
		vec![
			&self.mission_control_verifying_key,
			&self.earth_relay_verifying_key,
			&self.rover_verifying_key,
		]
	}

	fn cipher(&self) -> &Aes256Gcm {
		&self.shared_cipher
	}

	fn chain_processor(&self) -> &Arc<ChainProcessor> {
		&self.chain_processor
	}

	fn frame_builder(&self) -> &Arc<FrameBuilderHelper> {
		&self.frame_builder
	}
}

// ============================================================================
// Rover Servlet
// ============================================================================

#[derive(Clone)]
pub struct RoverServletConf {
	pub mars_relay_addr: TightBeamSocketAddr,
	pub mars_relay_pool: Arc<ConnectionPool<TokioListener, 3>>,
	pub rover_signing_key: Secp256k1SigningKey,
	pub mission_control_verifying_key: Secp256k1VerifyingKey,
	pub mars_relay_verifying_key: Secp256k1VerifyingKey,
	pub shared_cipher: Aes256Gcm,
	pub chain_processor: Arc<ChainProcessor>,
	// TODO
	pub _fault_manager: Arc<FaultManager>,
	pub frame_builder: Arc<FrameBuilderHelper>,
	pub mission_state: Arc<RwLock<MissionState>>,
	pub max_rounds: usize,
}

servlet! {
	/// Mars Rover executes commands and sends telemetry
	pub RoverServlet<RelayMessage, EnvConfig = RoverServletConf>,
	protocol: TokioListener,
	handle: |frame, trace, config, workers| async move {
		// Verify signature
		if frame.nonrepudiation.is_some()
			&& frame.verify::<Secp256k1Signature>(&config.mission_control_verifying_key).is_err()
			&& frame.verify::<Secp256k1Signature>(&config.mars_relay_verifying_key).is_err()
		{
			return Err(TightBeamError::MissingSignature);
		}

		// Get command order before consuming frame
		let command_order = frame.metadata.order;

		// Process frame through Rover's chain
		match config.chain_processor.process_incoming(frame.clone())? {
			ProcessResult::Processed(_) => {
				// Processing accepted
			},
			ProcessResult::Buffered => {
				return Ok(None);
			},
			ProcessResult::ChainGap { current_head, missing_hash } => {
				// Use trait method with pooled client
				config.handle_chain_gap(
					current_head,
					missing_hash,
					&config.mars_relay_pool,
					config.mars_relay_addr,
					&trace,
				).await?;

				return Ok(None);
			}
		}

		// Decrypt and decode RelayMessage
		let relay_message = config.decrypt_relay_message(frame)?;
		match relay_message {
			RelayMessage::Command(command) => {
				trace.event("rover_receive_command")?;
				trace.event("rover_execute_command")?;

				// Execute command via worker
				let exec_request = CommandExecutionRequest { command_type: command.command_type };
				let _exec_result = workers.relay::<CommandExecutionWorker>(Arc::new(exec_request)).await??;

				trace.event("rover_command_complete")?;

				// Update mission state
				{
					let mut state = config.mission_state.write()?;
					state.completed_rounds += 1;

					if state.completed_rounds >= config.max_rounds {
						state.mission_complete = true;
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

				// Return stateful ACK as response
				Ok(Some(ack_frame))
			},
			RelayMessage::FrameRequest(request) => {
				trace.event("rover_receive_frame_request")?;

				let missing_frames = config.chain_processor.request_missing_frames(
					&request.requester_head,
					&request.last_received_hash,
				)?;

				if !missing_frames.is_empty() {
					// We have the frames - respond
					trace.event("rover_send_frame_response")?;

					let response = FrameResponse { frames: missing_frames };
					let (order, prev_digest) = config.chain_processor.prepare_outgoing()?;
					let response_frame = config.frame_builder.build_frame_response_frame(
						response,
						order,
						prev_digest,
						&config.rover_signing_key,
						&config.shared_cipher,
					)?;

					config.chain_processor.finalize_outgoing(&response_frame)?;
					Ok(Some(response_frame))
				} else {
					// Rover is origin - cannot cascade, return None
					Ok(None)
				}
			},
			RelayMessage::FrameResponse(response) => {
				config.process_frame_response(response, command_order, &trace)
			},
			RelayMessage::Telemetry(_) | RelayMessage::CommandAck(_) => {
				Ok(None)
			}
		}
	}
}

impl DtnNode for RoverServletConf {
	fn node_name(&self) -> &str {
		"rover"
	}

	fn signing_key(&self) -> &Secp256k1SigningKey {
		&self.rover_signing_key
	}

	fn verifying_keys(&self) -> Vec<&Secp256k1VerifyingKey> {
		vec![&self.mission_control_verifying_key, &self.mars_relay_verifying_key]
	}

	fn cipher(&self) -> &Aes256Gcm {
		&self.shared_cipher
	}

	fn chain_processor(&self) -> &Arc<ChainProcessor> {
		&self.chain_processor
	}

	fn frame_builder(&self) -> &Arc<FrameBuilderHelper> {
		&self.frame_builder
	}
}

// ============================================================================
// Mission State (shared across nodes for coordination)
// ============================================================================

#[derive(Default)]
pub struct MissionState {
	pub completed_rounds: usize,
	pub telemetry_received_count: usize,
	pub mission_complete: bool,
}
