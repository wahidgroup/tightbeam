//! DTN Servlets: 4-Tier Architecture
//!
//! This module contains the servlet definitions for the 4-tier DTN
//! architecture:
//! - Mission Control receives telemetry, sends commands, and validates ACKs.
//! - The Earth Relay Satellite forwards messages between Mission Control and the Mars Relay.
//! - The Mars Relay Satellite forwards messages between the Earth Relay and the Rover.
//! - The Rover executes commands and sends telemetry and ACKs.

use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use tightbeam::{
	compress::{Inflator, ZstdCompression},
	crypto::sign::ecdsa::Secp256k1SigningKey,
	decode,
	prelude::*,
	servlet,
	trace::TraceCollector,
	transport::{tcp::r#async::TokioListener, ConnectionPool},
	utils::task::Pipeline,
};

use crate::common::poll::poll_until;
use crate::common::security::expectation_failure;
use crate::dtn::{
	certs::{FrameSigner, SharedCipher},
	chain_processor::{ChainProcessor, ProcessResult},
	clock::mission_time_ms,
	events::{
		EARTH_RELAY_FORWARD_ACK_TO_MC, EARTH_RELAY_FORWARD_TELEMETRY_TO_MC, EARTH_RELAY_FORWARD_TO_MARS,
		EARTH_RELAY_RECEIVE_ACK_FROM_MARS, EARTH_RELAY_RECEIVE_FROM_MC, EARTH_RELAY_RECEIVE_TELEMETRY_FROM_MARS,
		MARS_RELAY_FORWARD_ACK_TO_EARTH, MARS_RELAY_FORWARD_TELEMETRY_TO_EARTH, MARS_RELAY_FORWARD_TO_ROVER,
		MARS_RELAY_RECEIVE_ACK_FROM_ROVER, MARS_RELAY_RECEIVE_FROM_EARTH, MARS_RELAY_RECEIVE_TELEMETRY_FROM_ROVER,
		ROVER_SEND_ACK,
	},
	fault_manager::FaultManager,
	frame_builder::FrameBuilderHelper,
	jobs::{
		BuildGapRecoveryFrame, CreateFrameRequest, EmitFrameToNetwork, FinalizeChainOutgoing, GapRecoveryContext,
		PrepareGapRecoveryBuild,
	},
	messages::{EarthCommand, FrameResponse, RelayMessage},
	ultimate::{gap_recovery_event, GapRecoveryStep},
	workers::{
		command_ack_handler::{CommandAckHandlerRequest, CommandAckHandlerWorker},
		frame_request_handler::{FrameRequestAction, FrameRequestHandlerRequest, FrameRequestHandlerWorker},
		frame_response_handler::{FrameResponseHandlerRequest, FrameResponseHandlerWorker},
		mission_control_telemetry_handler::{MissionControlTelemetryHandlerWorker, TelemetryHandlerRequest},
		rover_command_handler::{RoverCommandHandlerRequest, RoverCommandHandlerWorker},
	},
};

/// Behavior every node on the DTN path shares.
trait DtnNode {
	// Each servlet config implements these required methods.
	fn node_name(&self) -> &str;
	fn signing_key(&self) -> &Secp256k1SigningKey;
	fn signers(&self) -> Vec<&FrameSigner>;
	fn cipher(&self) -> &SharedCipher;
	fn chain_processor(&self) -> &Arc<ChainProcessor>;
	fn frame_builder(&self) -> &Arc<FrameBuilderHelper>;

	/// Whether a signer of this node verifies the signature of `frame`, by a
	/// default method that every node shares.
	fn verify_signature(&self, frame: &Frame) -> Result<bool, TightBeamError> {
		if frame.nonrepudiation().is_none() {
			return Ok(false);
		}

		for signer in self.signers() {
			if frame.verify(signer).is_ok() {
				return Ok(true);
			}
		}

		Ok(false)
	}

	/// Decrypts the relay message of `frame`, or decodes it when the frame is
	/// cleartext.
	async fn decrypt_relay_message(&self, frame: Frame) -> Result<RelayMessage, TightBeamError> {
		if frame.metadata().confidentiality().is_some() {
			let zstd = ZstdCompression::default();
			let inflator: Option<&(dyn Inflator + Sync)> = if frame.metadata().compactness().is_some() {
				Some(&zstd)
			} else {
				None
			};

			frame.decrypt::<RelayMessage>(self.cipher(), inflator).await
		} else {
			decode(frame.message())
		}
	}

	/// Sends `frame` to `addr` through the preconfigured `pool` and returns the
	/// reply.
	async fn send_frame(
		&self,
		pool: &Arc<ConnectionPool<TokioListener>>,
		addr: TightBeamSocketAddr,
		frame: Frame,
	) -> Result<Option<Frame>, TightBeamError> {
		let mut client = pool.connect(addr).await?;
		Ok(client.conn()?.emit(frame, None).await?)
	}

	async fn handle_chain_gap(
		&self,
		current_head: impl Into<Vec<u8>>,
		missing_hash: impl Into<Vec<u8>>,
		pool: &Arc<ConnectionPool<TokioListener>>,
		upstream_addr: TightBeamSocketAddr,
		trace: &TraceCollector,
	) -> Result<(), TightBeamError> {
		let current_head: Vec<u8> = current_head.into();
		let missing_hash: Vec<u8> = missing_hash.into();
		trace.event(gap_recovery_event(self.node_name(), GapRecoveryStep::GapDetected))?;

		let ctx = Arc::new(GapRecoveryContext {
			chain_processor: Arc::clone(self.chain_processor()),
			frame_builder: Arc::clone(self.frame_builder()),
			signing_key: Arc::new(self.signing_key().to_owned()),
			cipher: Arc::new(self.cipher().to_owned()),
			pool: Arc::clone(pool),
		});

		let frame = CreateFrameRequest::run((current_head, missing_hash))
			.map(|req| (req, Arc::clone(&ctx)))
			.and_then(PrepareGapRecoveryBuild::run)
			.and_then(BuildGapRecoveryFrame::run)
			.map(|frame| (frame, Arc::clone(&ctx)))
			.and_then(FinalizeChainOutgoing::run)
			.run()?;

		trace.event(gap_recovery_event(self.node_name(), GapRecoveryStep::SendFrameRequest))?;

		EmitFrameToNetwork::run((frame, upstream_addr, ctx)).await?;
		Ok(())
	}
}

/// Wait for the upstream servlet to publish its address, for up to 5 s.
async fn wait_for_address(
	addr_lock: &Arc<RwLock<Option<TightBeamSocketAddr>>>,
) -> Result<TightBeamSocketAddr, TightBeamError> {
	let published = || addr_lock.read().is_ok_and(|addr| addr.is_some());
	if !poll_until(500, Duration::from_millis(10), published).await {
		return Err(expectation_failure("the upstream servlet never published its address"));
	}

	let addr = (*addr_lock.read()?).ok_or_else(|| expectation_failure("the published address vanished"))?;
	Ok(addr)
}

#[derive(Clone)]
pub struct MissionControlServletConfig {
	pub mission_control_signing_key: Secp256k1SigningKey,
	pub rover_signer: FrameSigner,
	pub earth_relay_signer: FrameSigner,
	pub shared_cipher: SharedCipher,
	pub chain_processor: Arc<ChainProcessor>,
	pub frame_builder: Arc<FrameBuilderHelper>,
	pub earth_relay_addr: TightBeamSocketAddr,
	pub earth_relay_pool: Arc<ConnectionPool<TokioListener>>,
}

servlet! {
	/// Mission Control receives telemetry and sends commands to the Rover
	/// through the relays.
	pub MissionControlServlet<RelayMessage, EnvConfig = MissionControlServletConfig>,
	protocol: TokioListener,
	handle: raw |frame, ctx| async move {
		let trace = &ctx.trace();
		let config: &MissionControlServletConfig = ctx.env_config();
		let frame_order = frame.metadata().order();

		// The node refuses a frame that no known signer signed.
		if !config.verify_signature(&frame)? {
			return Err(TightBeamError::MissingSignature);
		}

		// The chain processor persists the frame, orders it, and validates
		// the chain.
		match config.chain_processor.process_incoming(&frame)? {
			ProcessResult::Processed(ordered_frames) => {
				for ordered_frame in ordered_frames {
					let relay_message = config.decrypt_relay_message(ordered_frame).await?;
					match relay_message {
						RelayMessage::Telemetry(telemetry) => {
							// The telemetry worker analyzes the telemetry
							// and decides on the next command.
							let request = TelemetryHandlerRequest { telemetry };
							let result = ctx.relay::<MissionControlTelemetryHandlerWorker>(Arc::new(request)).await??;
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
							// The ACK worker processes the command ACK.
							let request = CommandAckHandlerRequest { ack };
							ctx.relay::<CommandAckHandlerWorker>(Arc::new(request)).await??;
						},
						RelayMessage::FrameRequest(request) => {
							// The frame request worker picks the action.
							let node_name = config.node_name().to_string();
							let worker_request = FrameRequestHandlerRequest { request, node_name };
							let result = ctx.relay::<FrameRequestHandlerWorker>(Arc::new(worker_request)).await??;
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
									// NoAction and Cascade remain, and Mission
									// Control has no hop to cascade to.
								}
							}
						},
						RelayMessage::FrameResponse(response) => {
							// The frame response worker processes the
							// response and validates the chain.
							let request = FrameResponseHandlerRequest {
								response,
								node_name: config.node_name().to_string(),
							};

							ctx.relay::<FrameResponseHandlerWorker>(Arc::new(request)).await??;
						},
						RelayMessage::Command(_) => {
							// A command travels toward the Rover, so
							// Mission Control refuses one.
							return Err(TightBeamError::InvalidBody);
						}
					}
				}

				let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame_order)?;
				Ok(Some(stateless_ack))
			},
			ProcessResult::Buffered => Ok(None),
			ProcessResult::ChainGap { current_head, missing_hash } => {
				// The node asks the Earth Relay for the missing frames.
				config.handle_chain_gap(
					current_head,
					missing_hash,
					&config.earth_relay_pool,
					config.earth_relay_addr,
					trace,
				).await?;

				Ok(None)
			},
		}
	}
}

impl DtnNode for MissionControlServletConfig {
	fn node_name(&self) -> &str {
		"mission_control"
	}

	fn signing_key(&self) -> &Secp256k1SigningKey {
		&self.mission_control_signing_key
	}

	fn signers(&self) -> Vec<&FrameSigner> {
		vec![&self.rover_signer, &self.earth_relay_signer]
	}

	fn cipher(&self) -> &SharedCipher {
		&self.shared_cipher
	}

	fn chain_processor(&self) -> &Arc<ChainProcessor> {
		&self.chain_processor
	}

	fn frame_builder(&self) -> &Arc<FrameBuilderHelper> {
		&self.frame_builder
	}
}

#[derive(Clone)]
pub struct EarthRelaySatelliteServletConfig {
	pub earth_relay_signing_key: Secp256k1SigningKey,
	pub mission_control_signer: FrameSigner,
	pub mars_relay_signer: FrameSigner,
	pub rover_signer: FrameSigner,
	pub shared_cipher: SharedCipher,
	pub mars_relay_addr: TightBeamSocketAddr,
	pub mission_control_addr: Arc<RwLock<Option<TightBeamSocketAddr>>>,
	pub mission_control_pool: Arc<ConnectionPool<TokioListener>>,
	pub mars_relay_pool: Arc<ConnectionPool<TokioListener>>,
	pub chain_processor: Arc<ChainProcessor>,
	pub frame_builder: Arc<FrameBuilderHelper>,
}

servlet! {
	/// The Earth Relay forwards messages between Mission Control and the Mars
	/// Relay.
	pub EarthRelaySatelliteServlet<RelayMessage, EnvConfig = EarthRelaySatelliteServletConfig>,
	protocol: TokioListener,
	handle: raw |frame, ctx| async move {
		let trace = &ctx.trace();
		let config: &EarthRelaySatelliteServletConfig = ctx.env_config();
		// The signer names the source: Mission Control, or the Rover
		// through the Mars Relay.
		let from_mission_control = if frame.nonrepudiation().is_some() {
			if frame.verify(&config.mission_control_signer).is_ok() {
				true
			} else if frame.verify(&config.rover_signer).is_ok() {
				false
			} else {
				return Err(TightBeamError::MissingSignature);
			}
		} else {
			return Err(TightBeamError::MissingSignature);
		};

		// The ACK needs the order after `frame` moves into a send.
		let frame_order = frame.metadata().order();
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
				// The relay reads the first ordered frame alone. A gap
				// recovery message gets its answer here, and any other
				// message routes by its source.
				if let Some(ordered_frame) = ordered_frames.into_iter().next() {
					let relay_message = config.decrypt_relay_message(ordered_frame).await?;
					match relay_message {
						RelayMessage::FrameRequest(request) => {
							// The frame request worker picks the action.
							let node_name = config.node_name().to_string();
							let worker_request = FrameRequestHandlerRequest { request: request.to_owned(), node_name };
							let result = ctx.relay::<FrameRequestHandlerWorker>(Arc::new(worker_request)).await??;
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
									// The relay builds the cascade frame and
									// sends it onward.
									let (cascade_pool, cascade_addr) = if from_mission_control {
										// A request from Mission Control
										// cascades to the Mars Relay.
										(&config.mars_relay_pool, config.mars_relay_addr)
									} else {
										// A rare request from the Mars side
										// cascades to Mission Control.
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
							// The frame response worker processes the
							// response and validates the chain.
							let worker_request = FrameResponseHandlerRequest {
								response,
								node_name: config.node_name().to_string(),
							};

							ctx.relay::<FrameResponseHandlerWorker>(Arc::new(worker_request)).await??;

							let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame_order)?;
							return Ok(Some(stateless_ack));
						},
						_ => {
							// Any other message routes by its source.
							if from_mission_control {
								// A frame from Mission Control goes on to
								// the Mars Relay through the pooled client.
								trace.event(EARTH_RELAY_RECEIVE_FROM_MC)?;
								trace.event(EARTH_RELAY_FORWARD_TO_MARS)?;

								config.send_frame(
									&config.mars_relay_pool,
									config.mars_relay_addr,
									frame,
								).await?;

								let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame_order)?;
								return Ok(Some(stateless_ack));
							} else {
								// The frame ID names the message type:
								// `relay-telem-NNN` or `relay-ack-NNN`.
								let is_telemetry = frame.metadata().id().starts_with(b"relay-telem");
								if is_telemetry {
									trace.event(EARTH_RELAY_RECEIVE_TELEMETRY_FROM_MARS)?;
									trace.event(EARTH_RELAY_FORWARD_TELEMETRY_TO_MC)?;
								} else {
									trace.event(EARTH_RELAY_RECEIVE_ACK_FROM_MARS)?;
									trace.event(EARTH_RELAY_FORWARD_ACK_TO_MC)?;
								}

								// Mission Control can publish its address
								// late, so the relay waits for it.
								let mc_addr = wait_for_address(&config.mission_control_addr).await?;

								config.send_frame(
									&config.mission_control_pool,
									mc_addr,
									frame,
								).await?;

								// The forward is fire-and-forget, so the
								// Mars Relay gets `None` as its reply.
								return Ok(None);
							}
						}
					}
				}

				Ok(None)
			},
			ProcessResult::Buffered => Ok(None),
			ProcessResult::ChainGap { current_head, missing_hash } => {
				// The relay asks the Mars Relay for the missing frames.
				config.handle_chain_gap(
					current_head,
					missing_hash,
					&config.mars_relay_pool,
					config.mars_relay_addr,
					trace,
				).await?;

				Ok(None)
			},
		}
	}
}

impl DtnNode for EarthRelaySatelliteServletConfig {
	fn node_name(&self) -> &str {
		"earth_relay"
	}

	fn signing_key(&self) -> &Secp256k1SigningKey {
		&self.earth_relay_signing_key
	}

	fn signers(&self) -> Vec<&FrameSigner> {
		vec![&self.mission_control_signer, &self.mars_relay_signer, &self.rover_signer]
	}

	fn cipher(&self) -> &SharedCipher {
		&self.shared_cipher
	}

	fn chain_processor(&self) -> &Arc<ChainProcessor> {
		&self.chain_processor
	}

	fn frame_builder(&self) -> &Arc<FrameBuilderHelper> {
		&self.frame_builder
	}
}

#[derive(Clone)]
pub struct MarsRelaySatelliteServletConfig {
	pub mars_relay_signing_key: Secp256k1SigningKey,
	pub mission_control_signer: FrameSigner,
	pub earth_relay_signer: FrameSigner,
	pub rover_signer: FrameSigner,
	pub shared_cipher: SharedCipher,
	pub rover_addr: TightBeamSocketAddr,
	pub earth_relay_addr: Arc<RwLock<Option<TightBeamSocketAddr>>>,
	pub earth_relay_pool: Arc<ConnectionPool<TokioListener>>,
	pub rover_pool: Arc<ConnectionPool<TokioListener>>,
	pub chain_processor: Arc<ChainProcessor>,
	pub frame_builder: Arc<FrameBuilderHelper>,
}

servlet! {
	/// The Mars Relay forwards messages between the Earth Relay and the Rover.
	pub MarsRelaySatelliteServlet<RelayMessage, EnvConfig = MarsRelaySatelliteServletConfig>,
	protocol: TokioListener,
	handle: raw |frame, ctx| async move {
		let trace = &ctx.trace();
		let config: &MarsRelaySatelliteServletConfig = ctx.env_config();
		// The signer names the source: the Rover, or Mission Control
		// through the Earth Relay, which forwards its frames.
		let from_rover = if frame.nonrepudiation().is_some() {
			if frame.verify(&config.rover_signer).is_ok() {
				true
			} else if frame.verify(&config.mission_control_signer).is_ok() {
				false
			} else {
				return Err(TightBeamError::MissingSignature);
			}
		} else {
			return Err(TightBeamError::MissingSignature);
		};

		// The ACK needs the order after `frame` moves into a send.
		let frame_order = frame.metadata().order();
		match config.chain_processor.process_incoming(&frame)? {
			ProcessResult::Processed(ordered_frames) => {
				// A gap recovery message among the ordered frames gets its
				// answer here.
				for ordered_frame in ordered_frames {
					let relay_message = config.decrypt_relay_message(ordered_frame).await?;
					match relay_message {
						RelayMessage::FrameRequest(request) => {
							// The frame request worker picks the action.
							let node_name = config.node_name().to_string();
							let worker_request = FrameRequestHandlerRequest { request: request.to_owned(), node_name };
							let result = ctx.relay::<FrameRequestHandlerWorker>(Arc::new(worker_request)).await??;
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
									// The relay builds the cascade frame and
									// sends it onward.
									let (cascade_pool, cascade_addr) = if from_rover {
										// A request from the Rover cascades
										// to the Earth Relay.
										match *config.earth_relay_addr.read()? {
											Some(earth_addr) => (&config.earth_relay_pool, earth_addr),
											None => return Ok(None),
										}
									} else {
										// A request from the Earth Relay
										// cascades to the Rover.
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
							// The frame response worker processes the
							// response and validates the chain.
							let worker_request = FrameResponseHandlerRequest {
								response,
								node_name: config.node_name().to_string(),
							};

							ctx.relay::<FrameResponseHandlerWorker>(Arc::new(worker_request)).await??;

							let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame_order)?;
							return Ok(Some(stateless_ack));
						},
						_ => {
							// Any other message routes by its source
							// after the loop.
						}
					}
				}

				if from_rover {
					// The frame ID names the message type: `relay-telem-NNN` or
					// `relay-ack-NNN`.
					let is_telemetry = frame.metadata().id().starts_with(b"relay-telem");
					if is_telemetry {
						trace.event(MARS_RELAY_RECEIVE_TELEMETRY_FROM_ROVER)?;
						trace.event(MARS_RELAY_FORWARD_TELEMETRY_TO_EARTH)?;
					} else {
						trace.event(MARS_RELAY_RECEIVE_ACK_FROM_ROVER)?;
						trace.event(MARS_RELAY_FORWARD_ACK_TO_EARTH)?;
					}

					// The Earth Relay can publish its address late, so the
					// relay waits for it.
					let earth_addr = wait_for_address(&config.earth_relay_addr).await?;

					config.send_frame(
						&config.earth_relay_pool,
						earth_addr,
						frame,
					).await?;

					let stateless_ack = config.frame_builder.build_stateless_ack_frame(frame_order)?;
					Ok(Some(stateless_ack))
				} else {
					// A frame from the Earth Relay goes on to the Rover through
					// the pooled client.
					trace.event(MARS_RELAY_RECEIVE_FROM_EARTH)?;
					trace.event(MARS_RELAY_FORWARD_TO_ROVER)?;

					let response = config.send_frame(&config.rover_pool, config.rover_addr, frame).await?;
					if let Some(ack_frame) = response {
						// The Rover's ACK enters the chain of this relay and
						// goes on to the Earth Relay.
						config.chain_processor.process_incoming(&ack_frame)?;

						// These events record the stateful ACK of the command
						// that the Rover sent.
						trace.event(MARS_RELAY_RECEIVE_ACK_FROM_ROVER)?;
						trace.event(MARS_RELAY_FORWARD_ACK_TO_EARTH)?;

						let earth_addr = wait_for_address(&config.earth_relay_addr).await?;
						config.send_frame(&config.earth_relay_pool, earth_addr, ack_frame).await?;
					}

					// The forward is fire-and-forget, so the Earth Relay gets
					// `None` as its reply.
					Ok(None)
				}
			},
			ProcessResult::Buffered => Ok(None),
			ProcessResult::ChainGap { current_head, missing_hash } => {
				// The side of the gap picks the upstream.
				let (upstream_pool, upstream_addr) = if from_rover {
					// A gap on the Rover side cascades to the Earth Relay.
					match *config.earth_relay_addr.read()? {
						Some(earth_addr) => (&config.earth_relay_pool, earth_addr),
						None => return Ok(None), // The Earth Relay address is still unset
					}
				} else {
					// A gap on the Earth side cascades to the Rover.
					(&config.rover_pool, config.rover_addr)
				};

				// The relay asks that upstream for the missing frames.
				config.handle_chain_gap(
					current_head,
					missing_hash,
					upstream_pool,
					upstream_addr,
					trace,
				).await?;

				Ok(None)
			},
		}
	}
}

impl DtnNode for MarsRelaySatelliteServletConfig {
	fn node_name(&self) -> &str {
		"mars_relay"
	}

	fn signing_key(&self) -> &Secp256k1SigningKey {
		&self.mars_relay_signing_key
	}

	fn signers(&self) -> Vec<&FrameSigner> {
		vec![&self.mission_control_signer, &self.earth_relay_signer, &self.rover_signer]
	}

	fn cipher(&self) -> &SharedCipher {
		&self.shared_cipher
	}

	fn chain_processor(&self) -> &Arc<ChainProcessor> {
		&self.chain_processor
	}

	fn frame_builder(&self) -> &Arc<FrameBuilderHelper> {
		&self.frame_builder
	}
}

#[derive(Clone)]
pub struct RoverServletConfig {
	pub mars_relay_addr: TightBeamSocketAddr,
	pub mars_relay_pool: Arc<ConnectionPool<TokioListener>>,
	pub rover_signing_key: Secp256k1SigningKey,
	pub mission_control_signer: FrameSigner,
	pub mars_relay_signer: FrameSigner,
	pub shared_cipher: SharedCipher,
	pub chain_processor: Arc<ChainProcessor>,
	// TODO
	pub _fault_manager: Arc<FaultManager>,
	pub frame_builder: Arc<FrameBuilderHelper>,
	pub max_rounds: usize,
}

servlet! {
	/// The Mars Rover executes commands and sends telemetry.
	pub RoverServlet<RelayMessage, EnvConfig = RoverServletConfig>,
	protocol: TokioListener,
	handle: raw |frame, ctx| async move {
		let trace = &ctx.trace();
		let config: &RoverServletConfig = ctx.env_config();
		// A signed frame must verify under Mission Control or the Mars Relay.
		if frame.nonrepudiation().is_some()
			&& frame.verify(&config.mission_control_signer).is_err()
			&& frame.verify(&config.mars_relay_signer).is_err()
		{
			return Err(TightBeamError::MissingSignature);
		}

		// The ACK needs the order of the command after the decrypt consumes
		// `frame`.
		let command_order = frame.metadata().order();
		match config.chain_processor.process_incoming(&frame)? {
			ProcessResult::Processed(_) => {
				// The chain accepted the frame, so the Rover reads its message.
			},
			ProcessResult::Buffered => {
				return Ok(None);
			},
			ProcessResult::ChainGap { current_head, missing_hash } => {
				// The Rover asks the Mars Relay for the missing frames.
				config.handle_chain_gap(
					current_head,
					missing_hash,
					&config.mars_relay_pool,
					config.mars_relay_addr,
					trace,
				).await?;

				return Ok(None);
			},
		}

		let relay_message = config.decrypt_relay_message(frame).await?;
		match relay_message {
			RelayMessage::Command(command) => {
				let request = RoverCommandHandlerRequest {
					command,
					max_rounds: config.max_rounds as u64,
				};
				let _result = ctx.relay::<RoverCommandHandlerWorker>(Arc::new(request)).await??;

				let (ack_order, ack_prev_digest) = config.chain_processor.prepare_outgoing()?;
				let ack_frame = config.frame_builder.build_relay_ack_frame(
					command_order,
					ack_order,
					ack_prev_digest,
					&config.rover_signing_key,
					&config.shared_cipher,
				)?;

				trace.event(ROVER_SEND_ACK)?;

				Ok(Some(ack_frame))
			},
		RelayMessage::FrameRequest(request) => {
			// The frame request worker picks the action.
			let node_name = config.node_name().to_string();
			let worker_request = FrameRequestHandlerRequest { request, node_name };
			let result = ctx.relay::<FrameRequestHandlerWorker>(Arc::new(worker_request)).await??;
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
					// The Rover is the origin, so it has no hop to cascade to.
					Ok(None)
				}
			}
		},
		RelayMessage::FrameResponse(response) => {
			// The frame response worker processes the response and
			// validates the chain.
			let worker_request = FrameResponseHandlerRequest {
				response,
				node_name: config.node_name().to_string(),
			};

			ctx.relay::<FrameResponseHandlerWorker>(Arc::new(worker_request)).await??;

			let stateless_ack = config.frame_builder.build_stateless_ack_frame(command_order)?;
			Ok(Some(stateless_ack))
		},
			RelayMessage::Telemetry(_) | RelayMessage::CommandAck(_) => {
				Ok(None)
			}
		}
	}
}

impl DtnNode for RoverServletConfig {
	fn node_name(&self) -> &str {
		"rover"
	}

	fn signing_key(&self) -> &Secp256k1SigningKey {
		&self.rover_signing_key
	}

	fn signers(&self) -> Vec<&FrameSigner> {
		vec![&self.mission_control_signer, &self.mars_relay_signer]
	}

	fn cipher(&self) -> &SharedCipher {
		&self.shared_cipher
	}

	fn chain_processor(&self) -> &Arc<ChainProcessor> {
		&self.chain_processor
	}

	fn frame_builder(&self) -> &Arc<FrameBuilderHelper> {
		&self.frame_builder
	}
}

/// Mission progress, shared across the nodes so they coordinate.
#[derive(Default)]
pub struct MissionState {
	pub completed_rounds: usize,
	pub telemetry_received_count: usize,
	pub mission_complete: bool,
}
