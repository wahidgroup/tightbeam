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
		key::KeySpec,
		sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey},
		x509::CertificateSpec,
	},
	decode,
	macros::client::builder::{ClientBuilder, GenericClient},
	prelude::*,
	servlet,
	testing::trace::TraceCollector,
	transport::tcp::r#async::TokioListener,
};
use tokio::sync::{Mutex, OnceCell};

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
		messages::{EarthCommand, FrameRequest, FrameResponse, RelayMessage, RoverCommand},
		utils::format_mission_time,
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
	fn node_cert(&self) -> CertificateSpec;
	fn node_key(&self) -> KeySpec;

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
			use tightbeam::compress::{Inflator, ZstdCompression};
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

	// Send frame by creating fresh client each time
	// TODO: Re-enable caching once servlet keep-alive is verified working
	async fn send_frame(
		&self,
		_client_cache: &Arc<tokio::sync::OnceCell<tokio::sync::Mutex<GenericClient<TokioListener>>>>,
		addr: TightBeamSocketAddr,
		server_cert: CertificateSpec,
		frame: Frame,
	) -> Result<Option<Frame>, TightBeamError> {
		// Create fresh client for each request (temporary)
		let mut client = ClientBuilder::<TokioListener>::connect(addr)
			.await?
			.with_server_certificate(server_cert)?
			.with_client_identity(self.node_cert(), self.node_key())?
			.with_timeout(Duration::from_millis(5000))
			.build()?;

		Ok(client.emit(frame, None).await?)
	}

	// Gap recovery with client caching
	async fn handle_frame_request(
		&self,
		request: FrameRequest,
		trace: &TraceCollector,
		cascade_target: Option<(
			&Arc<OnceCell<Mutex<GenericClient<TokioListener>>>>,
			TightBeamSocketAddr,
			CertificateSpec,
		)>,
	) -> Result<Option<Frame>, TightBeamError> {
		trace.event(&format!("{}_receive_frame_request", self.node_name()))?;

		let missing_frames = self
			.chain_processor()
			.request_missing_frames(&request.requester_head, &request.last_received_hash)?;

		if !missing_frames.is_empty() {
			trace.event(&format!("{}_send_frame_response", self.node_name()))?;

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
		} else if let Some((client_cache, addr, cert)) = cascade_target {
			trace.event(&format!("{}_cascade_frame_request", self.node_name()))?;

			let (order, prev_digest) = self.chain_processor().prepare_outgoing()?;
			let cascade_frame = self.frame_builder().build_frame_request_frame(
				request,
				order,
				prev_digest,
				self.signing_key(),
				self.cipher(),
			)?;

			self.chain_processor().finalize_outgoing(&cascade_frame)?;
			self.send_frame(client_cache, addr, cert, cascade_frame).await?;
			Ok(None)
		} else {
			Ok(None)
		}
	}

	fn handle_frame_response(&self, response: FrameResponse, trace: &TraceCollector) -> Result<(), TightBeamError> {
		trace.event(&format!("{}_receive_frame_response", self.node_name()))?;

		for frame in response.frames {
			self.chain_processor().process_incoming(frame)?;
		}

		Ok(())
	}

	async fn handle_chain_gap(
		&self,
		current_head: Vec<u8>,
		missing_hash: Vec<u8>,
		client_cache: &Arc<OnceCell<Mutex<GenericClient<TokioListener>>>>,
		upstream_addr: TightBeamSocketAddr,
		server_cert: CertificateSpec,
		trace: &TraceCollector,
	) -> Result<(), TightBeamError> {
		trace.event(&format!("{}_gap_detected", self.node_name()))?;

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
		trace.event(&format!("{}_send_frame_request", self.node_name()))?;

		self.send_frame(client_cache, upstream_addr, server_cert, request_frame).await?;
		Ok(())
	}
}

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
		earth_relay_client: Arc<OnceCell<Mutex<GenericClient<TokioListener>>>>,
		shared_mission_state: Arc<RwLock<MissionState>>,
	},
	handle: |frame, trace, config| async move {
		// Verify signature using trait method
		if !config.verify_signature(&frame)? {
			debug_log!("[Mission Control] ✗ Signature verification FAILED");
			return Err(TightBeamError::MissingSignature);
		}
		debug_log!("[Mission Control] ✓ Signature verified");

		// Process frame (persist, order, validate chain)
		match config.chain_processor.process_incoming(frame.clone())? {
			ProcessResult::Processed(ordered_frames) => {
				for ordered_frame in ordered_frames {
					// Decrypt and decode using trait method
					let relay_message = config.decrypt_relay_message(ordered_frame.clone())?;

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

								// Send command via cached client
								config.send_frame(
									&config.earth_relay_client,
									config.earth_relay_addr,
									EARTH_RELAY_CERT,
									command_frame,
								).await?;

								debug_log!("[Mission Control] ✓ Command {} sent", telemetry_count + 1);
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
						debug_log!("[Mission Control] Received unexpected Command message");
					}
				}
				}

				// Return stateless ACK
				let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame.metadata.order)?;
				Ok(Some(stateless_ack))
			},
			ProcessResult::Buffered => Ok(None),
		ProcessResult::ChainGap { current_head, missing_hash } => {
			// Use trait method with cached client
			config.handle_chain_gap(
				current_head,
				missing_hash,
				&config.earth_relay_client,
				config.earth_relay_addr,
				EARTH_RELAY_CERT,
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

	fn node_cert(&self) -> CertificateSpec {
		MISSION_CONTROL_CERT
	}

	fn node_key(&self) -> KeySpec {
		MISSION_CONTROL_KEY
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
		earth_relay_signing_key: Secp256k1SigningKey,
		mission_control_verifying_key: Secp256k1VerifyingKey,
		mars_relay_verifying_key: Secp256k1VerifyingKey,
		rover_verifying_key: Secp256k1VerifyingKey,
		shared_cipher: Aes256Gcm,
		mars_relay_addr: TightBeamSocketAddr,
		mars_relay_client: Arc<OnceCell<Mutex<GenericClient<TokioListener>>>>,
		mission_control_addr: Arc<RwLock<Option<TightBeamSocketAddr>>>,
		mission_control_client: Arc<OnceCell<Mutex<GenericClient<TokioListener>>>>,
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
			ProcessResult::Processed(ordered_frames) => {
				println!("[Earth Relay] ProcessResult::Processed branch");

				// Check if any processed frames are gap recovery messages
				for ordered_frame in ordered_frames {
					// Decrypt and decode to check message type
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

					match relay_message {
				RelayMessage::FrameRequest(request) => {
					trace.event("earth_relay_receive_frame_request")?;

					let missing_frames = config.chain_processor.request_missing_frames(
						&request.requester_head,
						&request.last_received_hash,
					)?;

					if !missing_frames.is_empty() {
						// We have the frames - respond
						trace.event("earth_relay_send_frame_response")?;

						let response = FrameResponse { frames: missing_frames };
						let (order, prev_digest) = config.chain_processor.prepare_outgoing()?;
						let response_frame = config.frame_builder.build_frame_response_frame(
							response,
							order,
							prev_digest,
							&config.earth_relay_signing_key,
							&config.shared_cipher,
						)?;

						config.chain_processor.finalize_outgoing(&response_frame)?;
						return Ok(Some(response_frame));
					} else {
						// We don't have frames - cascade to upstream
						trace.event("earth_relay_cascade_frame_request")?;

						let (cascade_addr, cascade_cert) = if from_mission_control {
							// Request from MC, cascade to Mars Relay
							(config.mars_relay_addr, MARS_RELAY_CERT)
						} else {
							// Request from Mars, cascade to MC (rare but possible)
							match *config.mission_control_addr.read()? {
								Some(mc_addr) => (mc_addr, MISSION_CONTROL_CERT),
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

						let mut client = ClientBuilder::<TokioListener>::connect(cascade_addr)
							.await?
							.with_server_certificate(cascade_cert)?
							.with_client_identity(EARTH_RELAY_CERT, EARTH_RELAY_KEY)?
							.build()?;

						client.emit(cascade_frame, None).await?;
						return Ok(None); // Cascade is async, no immediate response
					}
				},
					RelayMessage::FrameResponse(response) => {
						trace.event("earth_relay_receive_frame_response")?;

						// Process all frames into chain
						for frame in response.frames {
							config.chain_processor.process_incoming(frame)?;
						}

						// Return stateless ACK
						let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame_order)?;
						return Ok(Some(stateless_ack));
					},
					_ => {
						// Regular message - route based on source
						if from_mission_control {
							// Forward to Mars Relay using cached client
							debug_log!("[Earth Relay] Recording trace events...");
							trace.event("earth_relay_receive_from_mc")?;
							trace.event("earth_relay_forward_to_mars")?;
							debug_log!("[Earth Relay] Forwarding to Mars Relay...");

							config.send_frame(
								&config.mars_relay_client,
								config.mars_relay_addr,
								MARS_RELAY_CERT,
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

							debug_log!("[{}] [Earth Relay] Forwarding from Mars Relay to Mission Control", format_mission_time(mission_time_ms()));

							// Get Mission Control address (wait if not set yet)
							let mc_addr = loop {
								if let Some(addr) = *config.mission_control_addr.read()? {
									break addr;
								}
								tokio::time::sleep(Duration::from_millis(10)).await;
							};

							// Use cached client
							config.send_frame(
								&config.mission_control_client,
								mc_addr,
								MISSION_CONTROL_CERT,
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
				// Use trait method with cached client
				config.handle_chain_gap(
					current_head,
					missing_hash,
					&config.mars_relay_client,
					config.mars_relay_addr,
					MARS_RELAY_CERT,
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

	fn node_cert(&self) -> CertificateSpec {
		EARTH_RELAY_CERT
	}

	fn node_key(&self) -> KeySpec {
		EARTH_RELAY_KEY
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
		mars_relay_signing_key: Secp256k1SigningKey,
		mission_control_verifying_key: Secp256k1VerifyingKey,
		earth_relay_verifying_key: Secp256k1VerifyingKey,
		rover_verifying_key: Secp256k1VerifyingKey,
		shared_cipher: Aes256Gcm,
		rover_addr: TightBeamSocketAddr,
		rover_client: Arc<OnceCell<Mutex<GenericClient<TokioListener>>>>,
		earth_relay_addr: Arc<RwLock<Option<TightBeamSocketAddr>>>,
		earth_relay_client: Arc<OnceCell<Mutex<GenericClient<TokioListener>>>>,
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
		ProcessResult::Processed(ordered_frames) => {
			// Check if any processed frames are gap recovery messages
			for ordered_frame in ordered_frames {
				// Decrypt and decode to check message type
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

				match relay_message {
				RelayMessage::FrameRequest(request) => {
					trace.event("mars_relay_receive_frame_request")?;

					let missing_frames = config.chain_processor.request_missing_frames(
						&request.requester_head,
						&request.last_received_hash,
					)?;

					if !missing_frames.is_empty() {
						// We have the frames - respond
						trace.event("mars_relay_send_frame_response")?;

						let response = FrameResponse { frames: missing_frames };
						let (order, prev_digest) = config.chain_processor.prepare_outgoing()?;
						let response_frame = config.frame_builder.build_frame_response_frame(
							response,
							order,
							prev_digest,
							&config.mars_relay_signing_key,
							&config.shared_cipher,
						)?;

						config.chain_processor.finalize_outgoing(&response_frame)?;
						return Ok(Some(response_frame));
					} else {
						// We don't have frames - cascade to upstream
						trace.event("mars_relay_cascade_frame_request")?;

						let (cascade_addr, cascade_cert) = if from_rover {
							// Request from Rover, cascade to Earth Relay
							match *config.earth_relay_addr.read()? {
								Some(earth_addr) => (earth_addr, EARTH_RELAY_CERT),
								None => return Ok(None), // Earth address not available yet
							}
						} else {
							// Request from Earth, cascade to Rover
							(config.rover_addr, ROVER_CERT)
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

						let mut client = ClientBuilder::<TokioListener>::connect(cascade_addr)
							.await?
							.with_server_certificate(cascade_cert)?
							.with_client_identity(MARS_RELAY_CERT, MARS_RELAY_KEY)?
							.build()?;

						client.emit(cascade_frame, None).await?;
						return Ok(None); // Cascade is async, no immediate response
					}
				},
				RelayMessage::FrameResponse(response) => {
					trace.event("mars_relay_receive_frame_response")?;

					// Process all frames into chain
					for frame in response.frames {
						config.chain_processor.process_incoming(frame)?;
					}

					// Return stateless ACK
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

				debug_log!("[{}] [Mars Relay] Forwarding from Rover to Earth Relay", format_mission_time(mission_time_ms()));

				// Get Earth Relay address (wait if not set yet)
				let earth_addr = loop {
					if let Some(addr) = *config.earth_relay_addr.read()? {
						break addr;
					}
					tokio::time::sleep(Duration::from_millis(10)).await;
				};

				// Use cached client
				config.send_frame(
					&config.earth_relay_client,
					earth_addr,
					EARTH_RELAY_CERT,
					frame,
				).await?;

				// Return stateless ACK to Rover
				let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame_order)?;
				Ok(Some(stateless_ack))
			} else {
				// Forward to Rover using cached client
				trace.event("mars_relay_receive_from_earth")?;
				trace.event("mars_relay_forward_to_rover")?;
				debug_log!("[{}] [Mars Relay] Forwarding from Earth Relay to Rover", format_mission_time(mission_time_ms()));

				debug_log!("[Mars Relay] Emitting frame to Rover...");
				let response = config.send_frame(
					&config.rover_client,
					config.rover_addr,
					ROVER_CERT,
					frame,
				).await?;
				debug_log!("[Mars Relay] Response from Rover: {:?}", response.is_some());

				if let Some(ack_frame) = response {
					debug_log!("[Mars Relay] Rover sent ACK, processing...");
					// Process Rover's ACK into chain and forward to Earth Relay
					config.chain_processor.process_incoming(ack_frame.clone())?;

					// Emit trace event for receiving ACK from Rover (stateful ACK for command)
					trace.event("mars_relay_receive_ack_from_rover")?;
					trace.event("mars_relay_forward_ack_to_earth")?;

					// Forward ACK to Earth Relay using cached client
					let earth_addr = loop {
						if let Some(addr) = *config.earth_relay_addr.read()? {
							break addr;
						}
						tokio::time::sleep(Duration::from_millis(10)).await;
					};

					config.send_frame(
						&config.earth_relay_client,
						earth_addr,
						EARTH_RELAY_CERT,
						ack_frame,
					).await?;
					debug_log!("[Mars Relay] ACK forwarded to Earth Relay");
				}

				// Fire-and-forget (no response to Earth Relay)
				Ok(None)
			}
		},
		ProcessResult::Buffered => Ok(None),
		ProcessResult::ChainGap { current_head, missing_hash } => {
			// Determine upstream based on gap source
			let (client_cache, upstream_addr, upstream_cert) = if from_rover {
				// Gap from Rover direction, cascade to Earth Relay
				match *config.earth_relay_addr.read()? {
					Some(earth_addr) => (&config.earth_relay_client, earth_addr, EARTH_RELAY_CERT),
					None => return Ok(None), // Earth address not available yet
				}
			} else {
				// Gap from Earth direction, cascade to Rover
				(&config.rover_client, config.rover_addr, ROVER_CERT)
			};

			// Use trait method with cached client
			config.handle_chain_gap(
				current_head,
				missing_hash,
				client_cache,
				upstream_addr,
				upstream_cert,
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

	fn node_cert(&self) -> CertificateSpec {
		MARS_RELAY_CERT
	}

	fn node_key(&self) -> KeySpec {
		MARS_RELAY_KEY
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
		mars_relay_client: Arc<OnceCell<Mutex<GenericClient<TokioListener>>>>,
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
		ProcessResult::ChainGap { current_head, missing_hash } => {
			// Use trait method with cached client
			config.handle_chain_gap(
				current_head,
				missing_hash,
				&config.mars_relay_client,
				config.mars_relay_addr,
				MARS_RELAY_CERT,
				&trace,
			).await?;
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
			trace.event("rover_receive_frame_response")?;

			// Process all frames into chain
			for frame in response.frames {
				config.chain_processor.process_incoming(frame)?;
			}

			// Return stateless ACK
			let stateless_ack = config.frame_builder.build_stateless_ack_frame(command_order)?;
			Ok(Some(stateless_ack))
		},
			RelayMessage::Telemetry(_) | RelayMessage::CommandAck(_) => {
				debug_log!("[{}] [Rover] Received unexpected RelayMessage type (Telemetry/ACK)", format_mission_time(mission_time_ms()));
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

	fn node_cert(&self) -> CertificateSpec {
		ROVER_CERT
	}

	fn node_key(&self) -> KeySpec {
		ROVER_KEY
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
