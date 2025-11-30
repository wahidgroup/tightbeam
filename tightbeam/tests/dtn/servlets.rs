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
	messages::{EarthCommand, FrameRequest, FrameResponse, RelayMessage},
	workers::{
		command_ack_handler::{CommandAckHandlerRequest, CommandAckHandlerWorker},
		frame_request_handler::{FrameRequestAction, FrameRequestHandlerRequest, FrameRequestHandlerWorker},
		frame_response_handler::{FrameResponseHandlerRequest, FrameResponseHandlerWorker},
		mission_control_telemetry_handler::{MissionControlTelemetryHandlerWorker, TelemetryHandlerRequest},
		rover_command_handler::{RoverCommandHandlerRequest, RoverCommandHandlerWorker},
	},
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

	/// Default trait methods (reusable across all nodes)
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

	/// Helper: Decrypt relay message
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

	/// Send frame using pre-configured connection pool
	async fn send_frame(
		&self,
		pool: &Arc<ConnectionPool<TokioListener, 3>>,
		addr: TightBeamSocketAddr,
		frame: Frame,
	) -> Result<Option<Frame>, TightBeamError> {
		let mut client = pool.connect(addr).await?;
		Ok(client.emit(frame, None).await?)
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
}

servlet! {
	/// Mission Control receives telemetry and sends commands to Rover via relays
	pub MissionControlServlet<RelayMessage, EnvConfig = MissionControlServletConf>,
	protocol: TokioListener,
	handle: |frame, trace, config, workers| async move {
		let frame_order = frame.metadata.order;

		// Verify signature using trait method
		if !config.verify_signature(&frame)? {
			return Err(TightBeamError::MissingSignature);
		}

		// Process frame (persist, order, validate chain)
		match config.chain_processor.process_incoming(&frame)? {
			ProcessResult::Processed(ordered_frames) => {
				for ordered_frame in ordered_frames {
					// Decrypt and decode using trait method
					let relay_message = config.decrypt_relay_message(ordered_frame)?;
					match relay_message {
						RelayMessage::Telemetry(telemetry) => {
							// WORKER: Handle telemetry analysis and command decision
							let request = TelemetryHandlerRequest { telemetry };
							let result = workers.relay::<MissionControlTelemetryHandlerWorker>(Arc::new(request)).await??;
							if result.should_send_command {
								if let Some(next_cmd) = result.next_command {
									let (next_order, previous_digest) = config.chain_processor.prepare_outgoing()?;
									let command = EarthCommand {
										command_type: next_cmd.command,
										parameters: next_cmd.parameters,
										priority: next_cmd.priority,
										mission_time_ms: mission_time_ms(),
									};

									let command_frame = config.frame_builder.build_relay_command_frame(
										command,
										next_order,
										previous_digest,
										&config.mission_control_signing_key,
										&config.shared_cipher,
									)?;

									config.send_frame(
										&config.earth_relay_pool,
										config.earth_relay_addr,
										command_frame,
									).await?;
								}
							}
						},
						RelayMessage::CommandAck(ack) => {
							// WORKER: Handle ACK processing
							let request = CommandAckHandlerRequest { ack };
							workers.relay::<CommandAckHandlerWorker>(Arc::new(request)).await??;
						},
						RelayMessage::FrameRequest(request) => {
							// WORKER: Decide what to do with frame request
							let node_name = config.node_name().to_string();
							let worker_request = FrameRequestHandlerRequest { request, node_name };
							let result = workers.relay::<FrameRequestHandlerWorker>(Arc::new(worker_request)).await??;
							match result.action {
								FrameRequestAction::Respond(_) => {
									let (order, prev_digest) = config.chain_processor.prepare_outgoing()?;
									let response = FrameResponse { frames: result.missing_frames };
									let response_frame = config.frame_builder.build_frame_response_frame(
										response,
										order,
										prev_digest,
										&config.mission_control_signing_key,
										&config.shared_cipher,
									)?;

									config.chain_processor.finalize_outgoing(&response_frame)?;
									return Ok(Some(response_frame));
								},
								_ => {
									// NoAction or Cascade (but MC can't cascade)
								}
							}
						},
						RelayMessage::FrameResponse(response) => {
							// WORKER: Process frame response and validate chain
							let request = FrameResponseHandlerRequest {
								response,
								node_name: config.node_name().to_string(),
							};
							workers.relay::<FrameResponseHandlerWorker>(Arc::new(request)).await??;
						},
						RelayMessage::Command(_) => {
							// Invalid message type
							return Err(TightBeamError::InvalidBody);
						}
					}
				}

				// Return stateless ACK
				let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame_order)?;
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
	handle: |frame, trace, config, workers| async move {
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
		let process_result = match config.chain_processor.process_incoming(&frame) {
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
					let relay_message = config.decrypt_relay_message(ordered_frame)?;
					match relay_message {
						RelayMessage::FrameRequest(request) => {
							// WORKER: Decide what to do with frame request
							let node_name = config.node_name().to_string();
							let worker_request = FrameRequestHandlerRequest { request: request.clone(), node_name };
							let result = workers.relay::<FrameRequestHandlerWorker>(Arc::new(worker_request)).await??;
							match result.action {
								FrameRequestAction::Respond(_) => {
									let (order, prev_digest) = config.chain_processor.prepare_outgoing()?;
									let response = FrameResponse { frames: result.missing_frames };
									let response_frame = config.frame_builder.build_frame_response_frame(
										response,
										order,
										prev_digest,
										&config.earth_relay_signing_key,
										&config.shared_cipher,
									)?;
									config.chain_processor.finalize_outgoing(&response_frame)?;
									return Ok(Some(response_frame));
								},
								FrameRequestAction::Cascade(_) => {
									// Servlet builds and sends cascade frame
									let (cascade_pool, cascade_addr) = if from_mission_control {
										// Request from MC, cascade to Mars Relay
										(&config.mars_relay_pool, config.mars_relay_addr)
									} else {
										// Request from Mars, cascade to MC (rare but possible)
										match *config.mission_control_addr.read()? {
											Some(mc_addr) => (&config.mission_control_pool, mc_addr),
											None => return Ok(None),
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
									return Ok(None);
								},
								_ => {}
							}
						},
						RelayMessage::FrameResponse(response) => {
							// WORKER: Process frame response and validate chain
							let worker_request = FrameResponseHandlerRequest {
								response,
								node_name: config.node_name().to_string(),
							};
							workers.relay::<FrameResponseHandlerWorker>(Arc::new(worker_request)).await??;

							// Servlet builds ACK
							let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame_order)?;
							return Ok(Some(stateless_ack));
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
	handle: |frame, trace, config, workers| async move {
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
		match config.chain_processor.process_incoming(&frame)? {
			ProcessResult::Processed(ordered_frames) => {
				// Check if any processed frames are gap recovery messages
				for ordered_frame in ordered_frames {
					// Decrypt and decode to check message type
					let relay_message = config.decrypt_relay_message(ordered_frame)?;
					match relay_message {
						RelayMessage::FrameRequest(request) => {
							// WORKER: Decide what to do with frame request
							let node_name = config.node_name().to_string();
							let worker_request = FrameRequestHandlerRequest { request: request.clone(), node_name };
							let result = workers.relay::<FrameRequestHandlerWorker>(Arc::new(worker_request)).await??;
							match result.action {
								FrameRequestAction::Respond(_) => {
									let (order, prev_digest) = config.chain_processor.prepare_outgoing()?;
									let response = FrameResponse { frames: result.missing_frames };
									let response_frame = config.frame_builder.build_frame_response_frame(
										response,
										order,
										prev_digest,
										&config.mars_relay_signing_key,
										&config.shared_cipher,
									)?;
									config.chain_processor.finalize_outgoing(&response_frame)?;
									return Ok(Some(response_frame));
								},
								FrameRequestAction::Cascade(_) => {
									// Servlet builds and sends cascade frame
									let (cascade_pool, cascade_addr) = if from_rover {
										// Request from Rover, cascade to Earth Relay
										match *config.earth_relay_addr.read()? {
											Some(earth_addr) => (&config.earth_relay_pool, earth_addr),
											None => return Ok(None),
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
									return Ok(None);
								},
								_ => {}
							}
						},
						RelayMessage::FrameResponse(response) => {
							// WORKER: Process frame response and validate chain
							let worker_request = FrameResponseHandlerRequest {
								response,
								node_name: config.node_name().to_string(),
							};
							workers.relay::<FrameResponseHandlerWorker>(Arc::new(worker_request)).await??;

							// Servlet builds ACK
							let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame_order)?;
							return Ok(Some(stateless_ack));
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

					let response = config.send_frame(&config.rover_pool, config.rover_addr, frame).await?;
					if let Some(ack_frame) = response {
						// Process Rover's ACK into chain and forward to Earth Relay
						config.chain_processor.process_incoming(&ack_frame)?;

						// Emit trace event for receiving ACK from Rover (stateful ACK for command)
						trace.event("mars_relay_receive_ack_from_rover")?;
						trace.event("mars_relay_forward_ack_to_earth")?;

						// Forward ACK to Earth Relay using cached client
						let earth_addr = wait_for_address(&config.earth_relay_addr).await?;
						config.send_frame(&config.earth_relay_pool, earth_addr, ack_frame).await?;
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
		match config.chain_processor.process_incoming(&frame)? {
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
				let request = RoverCommandHandlerRequest {
					command,
					max_rounds: config.max_rounds as u64,
				};
				let _result = workers.relay::<RoverCommandHandlerWorker>(Arc::new(request)).await??;

				let (ack_order, ack_prev_digest) = config.chain_processor.prepare_outgoing()?;
				let ack_frame = config.frame_builder.build_relay_ack_frame(
					command_order,
					ack_order,
					ack_prev_digest,
					&config.rover_signing_key,
					&config.shared_cipher,
				)?;

				trace.event("rover_send_ack")?;
				Ok(Some(ack_frame))
			},
		RelayMessage::FrameRequest(request) => {
			// WORKER: Decide what to do with frame request
			let node_name = config.node_name().to_string();
			let worker_request = FrameRequestHandlerRequest { request, node_name };
			let result = workers.relay::<FrameRequestHandlerWorker>(Arc::new(worker_request)).await??;
			match result.action {
				FrameRequestAction::Respond(_) => {
					let (order, prev_digest) = config.chain_processor.prepare_outgoing()?;
					let response = FrameResponse { frames: result.missing_frames };
					let response_frame = config.frame_builder.build_frame_response_frame(
						response,
						order,
						prev_digest,
						&config.rover_signing_key,
						&config.shared_cipher,
					)?;
					config.chain_processor.finalize_outgoing(&response_frame)?;
					Ok(Some(response_frame))
				},
				_ => {
					// Rover is origin - cannot cascade
					Ok(None)
				}
			}
		},
		RelayMessage::FrameResponse(response) => {
			// WORKER: Process frame response and validate chain
			let worker_request = FrameResponseHandlerRequest {
				response,
				node_name: config.node_name().to_string(),
			};
			workers.relay::<FrameResponseHandlerWorker>(Arc::new(worker_request)).await??;

			// Servlet builds ACK
			let stateless_ack = config.frame_builder.build_stateless_ack_frame(command_order)?;
			Ok(Some(stateless_ack))
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
