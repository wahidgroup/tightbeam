//! DTN Servlets: 4-Tier Architecture
//!
//! The module defines one servlet per tier of the 4-tier DTN architecture:
//! - Mission Control receives telemetry, sends commands, and validates ACKs.
//! - The Earth Relay Satellite forwards messages between Mission Control and the Mars Relay.
//! - The Mars Relay Satellite forwards messages between the Earth Relay and the Rover.
//! - The Rover executes commands and sends telemetry and ACKs.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use tightbeam::{
	colony::servlet::ServletContext,
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
	messages::{EarthCommand, FrameRequest, FrameResponse, RelayMessage},
	ultimate::{gap_recovery_event, GapRecoveryStep},
	workers::{
		command_ack_handler::{CommandAckHandlerRequest, CommandAckHandlerWorker},
		frame_request_handler::{FrameRequestAction, FrameRequestHandlerRequest, FrameRequestHandlerWorker},
		frame_response_handler::{FrameResponseHandlerRequest, FrameResponseHandlerWorker},
		mission_control_telemetry_handler::{MissionControlTelemetryHandlerWorker, TelemetryHandlerRequest},
		rover_command_handler::{RoverCommandHandlerRequest, RoverCommandHandlerWorker},
	},
};

/// The address of a hop that starts after the node that dials it, which the
/// hop publishes once its servlet runs.
pub type LateAddr = Arc<RwLock<Option<TightBeamSocketAddr>>>;

/// A side of a node on the path from Mission Control to the Rover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathSide {
	/// The side toward Mission Control.
	Earth,
	/// The side toward the Rover.
	Mars,
}

impl PathSide {
	/// Both sides, the Earth side first.
	const BOTH: [Self; 2] = [Self::Earth, Self::Mars];

	/// Returns the side across the node, where a frame from this side travels
	/// on.
	fn across(self) -> Self {
		match self {
			Self::Earth => Self::Mars,
			Self::Mars => Self::Earth,
		}
	}
}

/// What a node does with one frame that its chain releases.
enum Routed {
	/// A chain frame that the node owes the sender: a frame response, or the
	/// ACK of a command.
	Answer(Frame),
	/// A stateless receipt for the sender, a frame outside the chain.
	Receipt(Frame),
	/// A chain frame that the next hop returned, which enters the chain of the
	/// node.
	Returned(Frame),
	/// Nothing goes back.
	Nothing,
}

/// The behavior that every node on the DTN path shares.
trait DtnNode: Sized + Send + Sync + 'static {
	// Each servlet configuration implements these required methods.
	fn node_name(&self) -> &str;
	fn signing_key(&self) -> &Secp256k1SigningKey;
	fn cipher(&self) -> &SharedCipher;
	fn chain_processor(&self) -> &Arc<ChainProcessor>;
	fn frame_builder(&self) -> &Arc<FrameBuilderHelper>;

	/// Returns the signers of the peers on `side` of this node.
	fn signers_on(&self, side: PathSide) -> Vec<&FrameSigner>;

	/// Returns the next hop toward `side`: its pool, and its address once the
	/// hop publishes it.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingConfiguration`] -- the node has no hop on `side`.
	/// - [`TightBeamError`] -- the hop never publishes its address.
	async fn hop_toward(
		&self,
		side: PathSide,
	) -> Result<(&Arc<ConnectionPool<TokioListener>>, TightBeamSocketAddr), TightBeamError>;

	/// Routes `frame`, which the chain of this node released, from `side`.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the frame fails to open, a worker fails, or a send fails.
	async fn route(&self, frame: Frame, side: PathSide, ctx: &ServletContext<Self>) -> Result<Routed, TightBeamError>;

	/// Returns the side of the peer whose signer verifies `frame`.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingSignature`] -- no signer of a peer verifies the frame.
	fn side_of(&self, frame: &Frame) -> Result<PathSide, TightBeamError> {
		let signed_on = |side: &PathSide| self.signers_on(*side).into_iter().any(|signer| frame.verify(signer).is_ok());
		PathSide::BOTH
			.into_iter()
			.find(signed_on)
			.ok_or(TightBeamError::MissingSignature)
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

	/// Answers `request` from `side` with the frames that this node holds, or
	/// cascades it to the hop across this node.
	async fn answer_frame_request(
		&self,
		request: FrameRequest,
		side: PathSide,
		ctx: &ServletContext<Self>,
	) -> Result<Routed, TightBeamError> {
		// The frame request worker picks whether the node responds, cascades
		// the request, or takes no action.
		let node_name = self.node_name().to_string();
		let worker_request = FrameRequestHandlerRequest { request: request.to_owned(), node_name };
		let result = ctx.relay::<FrameRequestHandlerWorker>(Arc::new(worker_request)).await??;
		match result.action {
			FrameRequestAction::Respond(_) => {
				let (order, prev_digest) = self.chain_processor().prepare_outgoing()?;
				let response = FrameResponse { frames: result.missing_frames };
				let response_frame = self.frame_builder().build_frame_response_frame(
					response,
					order,
					prev_digest,
					self.signing_key(),
					self.cipher(),
				)?;

				Ok(Routed::Answer(response_frame))
			}
			FrameRequestAction::Cascade(_) => {
				// The request goes on away from its requester.
				let (cascade_pool, cascade_addr) = self.hop_toward(side.across()).await?;
				let (order, prev_digest) = self.chain_processor().prepare_outgoing()?;
				let cascade_frame = self.frame_builder().build_frame_request_frame(
					request,
					order,
					prev_digest,
					self.signing_key(),
					self.cipher(),
				)?;

				self.send_frame(cascade_pool, cascade_addr, cascade_frame).await?;
				Ok(Routed::Nothing)
			}
			// An origin of the path ends each cascade.
			FrameRequestAction::NoAction(_) => Ok(Routed::Nothing),
		}
	}

	/// Takes in the frames of `response` through the frame response worker,
	/// which validates the chain, and gives the sender of the frame at `order`
	/// a receipt.
	async fn take_frame_response(
		&self,
		response: FrameResponse,
		order: u64,
		ctx: &ServletContext<Self>,
	) -> Result<Routed, TightBeamError> {
		let request = FrameResponseHandlerRequest { response, node_name: self.node_name().to_string() };
		ctx.relay::<FrameResponseHandlerWorker>(Arc::new(request)).await??;

		Ok(Routed::Receipt(self.frame_builder().build_stateless_ack_frame(order)?))
	}

	/// Takes `frame` into the chain of this node and routes each frame that the
	/// chain releases, in chain order, by the side of its own signer.
	///
	/// - The frame that arrives is the first frame that the chain releases, so its route gives the reply.
	/// - A later frame waited in the buffer while its sender took `None`, so
	///   an answer that it owes goes to the hop on its side, and the node drops
	///   its receipt.
	/// - A frame that a next hop returns enters the chain after them.
	/// - A gap asks the hop on the side of the frame that shows it, which holds
	///   the missing frame: that hop chained the frame onto it, or validated
	///   the frame against its own chain before it sent the frame on.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingSignature`] -- no signer of a peer verifies a frame.
	/// - [`TightBeamError`] -- the chain refuses a frame, or a route fails.
	async fn take_in(&self, frame: Frame, ctx: &ServletContext<Self>) -> Result<Option<Frame>, TightBeamError> {
		let trace = ctx.trace();
		let mut reply = None;
		let mut owes_reply = true;
		let mut entering = VecDeque::from([frame]);

		while let Some(entry) = entering.pop_front() {
			// 1. The signer names the side, so the node refuses a frame that no
			// peer signed before its chain stores it.
			let side = self.side_of(&entry)?;

			// 2. The chain persists and orders the frame, and releases each
			// frame that follows its head in order.
			let released = match self.chain_processor().process_incoming(&entry)? {
				ProcessResult::Processed(released) => released,
				ProcessResult::Buffered => Vec::new(),
				ProcessResult::ChainGap { current_head, missing_hash } => {
					let (pool, addr) = self.hop_toward(side).await?;
					self.handle_chain_gap(current_head, missing_hash, pool, addr, &trace).await?;
					Vec::new()
				}
			};

			// 3. Each released frame routes by the side of its own signer.
			for released_frame in released {
				let released_side = self.side_of(&released_frame)?;
				let routed = self.route(released_frame, released_side, ctx).await?;
				match routed {
					Routed::Answer(sender_reply) | Routed::Receipt(sender_reply) if owes_reply => {
						reply = Some(sender_reply);
					}
					Routed::Answer(answer) => {
						let (pool, addr) = self.hop_toward(released_side).await?;
						self.send_frame(pool, addr, answer).await?;
					}
					Routed::Returned(returned) => entering.push_back(returned),
					Routed::Receipt(_) | Routed::Nothing => {}
				}

				owes_reply = false;
			}
		}

		Ok(reply)
	}
}

/// Waits for the upstream servlet to publish its address, for up to 5 s.
async fn wait_for_address(addr_lock: &LateAddr) -> Result<TightBeamSocketAddr, TightBeamError> {
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
		ctx.env_config().take_in(frame, ctx).await
	}
}

impl DtnNode for MissionControlServletConfig {
	fn node_name(&self) -> &str {
		"mission_control"
	}

	fn signing_key(&self) -> &Secp256k1SigningKey {
		&self.mission_control_signing_key
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

	fn signers_on(&self, side: PathSide) -> Vec<&FrameSigner> {
		match side {
			PathSide::Earth => Vec::new(),
			PathSide::Mars => vec![&self.rover_signer, &self.earth_relay_signer],
		}
	}

	async fn hop_toward(
		&self,
		side: PathSide,
	) -> Result<(&Arc<ConnectionPool<TokioListener>>, TightBeamSocketAddr), TightBeamError> {
		match side {
			PathSide::Earth => Err(TightBeamError::MissingConfiguration),
			PathSide::Mars => Ok((&self.earth_relay_pool, self.earth_relay_addr)),
		}
	}

	async fn route(&self, frame: Frame, side: PathSide, ctx: &ServletContext<Self>) -> Result<Routed, TightBeamError> {
		let frame_order = frame.metadata().order();
		match self.decrypt_relay_message(frame).await? {
			RelayMessage::Telemetry(telemetry) => {
				// The telemetry worker analyzes the telemetry and decides on
				// the next command.
				let request = TelemetryHandlerRequest { telemetry };
				let result = ctx.relay::<MissionControlTelemetryHandlerWorker>(Arc::new(request)).await??;
				if result.should_send_command {
					if let Some(next_cmd) = result.next_command {
						let (next_order, previous_digest) = self.chain_processor.prepare_outgoing()?;
						let command = EarthCommand {
							command_type: next_cmd.command,
							parameters: next_cmd.parameters,
							priority: next_cmd.priority,
							mission_time_ms: mission_time_ms(),
						};

						let command_frame = self.frame_builder.build_relay_command_frame(
							command,
							next_order,
							previous_digest,
							&self.mission_control_signing_key,
							&self.shared_cipher,
						)?;

						let (pool, addr) = self.hop_toward(PathSide::Mars).await?;
						self.send_frame(pool, addr, command_frame).await?;
					}
				}

				Ok(Routed::Receipt(self.frame_builder.build_stateless_ack_frame(frame_order)?))
			}
			RelayMessage::CommandAck(ack) => {
				// The ACK worker records that Mission Control received the ACK.
				let request = CommandAckHandlerRequest { ack };
				ctx.relay::<CommandAckHandlerWorker>(Arc::new(request)).await??;
				Ok(Routed::Receipt(self.frame_builder.build_stateless_ack_frame(frame_order)?))
			}
			RelayMessage::FrameRequest(request) => self.answer_frame_request(request, side, ctx).await,
			RelayMessage::FrameResponse(response) => self.take_frame_response(response, frame_order, ctx).await,
			RelayMessage::Command(_) => {
				// A command travels toward the Rover, so Mission Control
				// refuses one.
				Err(TightBeamError::InvalidBody)
			}
		}
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
	pub mission_control_addr: LateAddr,
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
		ctx.env_config().take_in(frame, ctx).await
	}
}

impl EarthRelaySatelliteServletConfig {
	/// Forwards `frame` from `side` to the hop across the relay.
	///
	/// A frame from Mission Control gets a receipt. A frame from the Mars side
	/// goes on as fire-and-forget, so the Mars Relay gets `None` as its reply.
	async fn forward(&self, frame: Frame, side: PathSide, trace: &TraceCollector) -> Result<Routed, TightBeamError> {
		let frame_order = frame.metadata().order();
		match side {
			PathSide::Earth => {
				trace.event(EARTH_RELAY_RECEIVE_FROM_MC)?;
				trace.event(EARTH_RELAY_FORWARD_TO_MARS)?;
			}
			PathSide::Mars => {
				// The frame ID names the message type: `relay-telem-NNN` or
				// `relay-ack-NNN`.
				let is_telemetry = frame.metadata().id().starts_with(b"relay-telem");
				if is_telemetry {
					trace.event(EARTH_RELAY_RECEIVE_TELEMETRY_FROM_MARS)?;
					trace.event(EARTH_RELAY_FORWARD_TELEMETRY_TO_MC)?;
				} else {
					trace.event(EARTH_RELAY_RECEIVE_ACK_FROM_MARS)?;
					trace.event(EARTH_RELAY_FORWARD_ACK_TO_MC)?;
				}
			}
		}

		let (pool, addr) = self.hop_toward(side.across()).await?;
		self.send_frame(pool, addr, frame).await?;

		match side {
			PathSide::Earth => Ok(Routed::Receipt(self.frame_builder.build_stateless_ack_frame(frame_order)?)),
			PathSide::Mars => Ok(Routed::Nothing),
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

	fn cipher(&self) -> &SharedCipher {
		&self.shared_cipher
	}

	fn chain_processor(&self) -> &Arc<ChainProcessor> {
		&self.chain_processor
	}

	fn frame_builder(&self) -> &Arc<FrameBuilderHelper> {
		&self.frame_builder
	}

	fn signers_on(&self, side: PathSide) -> Vec<&FrameSigner> {
		match side {
			PathSide::Earth => vec![&self.mission_control_signer],
			PathSide::Mars => vec![&self.mars_relay_signer, &self.rover_signer],
		}
	}

	async fn hop_toward(
		&self,
		side: PathSide,
	) -> Result<(&Arc<ConnectionPool<TokioListener>>, TightBeamSocketAddr), TightBeamError> {
		match side {
			PathSide::Earth => Ok((&self.mission_control_pool, wait_for_address(&self.mission_control_addr).await?)),
			PathSide::Mars => Ok((&self.mars_relay_pool, self.mars_relay_addr)),
		}
	}

	async fn route(&self, frame: Frame, side: PathSide, ctx: &ServletContext<Self>) -> Result<Routed, TightBeamError> {
		let frame_order = frame.metadata().order();
		match self.decrypt_relay_message(frame.to_owned()).await? {
			RelayMessage::FrameRequest(request) => self.answer_frame_request(request, side, ctx).await,
			RelayMessage::FrameResponse(response) => self.take_frame_response(response, frame_order, ctx).await,
			_ => self.forward(frame, side, &ctx.trace()).await,
		}
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
	pub earth_relay_addr: LateAddr,
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
		ctx.env_config().take_in(frame, ctx).await
	}
}

impl MarsRelaySatelliteServletConfig {
	/// Forwards `frame` from `side` to the hop across the relay.
	///
	/// A frame from the Rover gets a receipt. The Rover answers a command from
	/// the Earth side with its signed ACK, which enters the chain of this relay
	/// and goes on to the Earth Relay, so the Earth Relay gets `None` as its
	/// reply.
	async fn forward(&self, frame: Frame, side: PathSide, trace: &TraceCollector) -> Result<Routed, TightBeamError> {
		let frame_order = frame.metadata().order();
		match side {
			PathSide::Earth => {
				trace.event(MARS_RELAY_RECEIVE_FROM_EARTH)?;
				trace.event(MARS_RELAY_FORWARD_TO_ROVER)?;
			}
			PathSide::Mars => {
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
			}
		}

		let (pool, addr) = self.hop_toward(side.across()).await?;
		let reply = self.send_frame(pool, addr, frame).await?;

		match side {
			PathSide::Earth => Ok(reply.map_or(Routed::Nothing, Routed::Returned)),
			PathSide::Mars => Ok(Routed::Receipt(self.frame_builder.build_stateless_ack_frame(frame_order)?)),
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

	fn cipher(&self) -> &SharedCipher {
		&self.shared_cipher
	}

	fn chain_processor(&self) -> &Arc<ChainProcessor> {
		&self.chain_processor
	}

	fn frame_builder(&self) -> &Arc<FrameBuilderHelper> {
		&self.frame_builder
	}

	fn signers_on(&self, side: PathSide) -> Vec<&FrameSigner> {
		match side {
			PathSide::Earth => vec![&self.mission_control_signer, &self.earth_relay_signer],
			PathSide::Mars => vec![&self.rover_signer],
		}
	}

	async fn hop_toward(
		&self,
		side: PathSide,
	) -> Result<(&Arc<ConnectionPool<TokioListener>>, TightBeamSocketAddr), TightBeamError> {
		match side {
			PathSide::Earth => Ok((&self.earth_relay_pool, wait_for_address(&self.earth_relay_addr).await?)),
			PathSide::Mars => Ok((&self.rover_pool, self.rover_addr)),
		}
	}

	async fn route(&self, frame: Frame, side: PathSide, ctx: &ServletContext<Self>) -> Result<Routed, TightBeamError> {
		let frame_order = frame.metadata().order();
		match self.decrypt_relay_message(frame.to_owned()).await? {
			RelayMessage::FrameRequest(request) => self.answer_frame_request(request, side, ctx).await,
			RelayMessage::FrameResponse(response) => self.take_frame_response(response, frame_order, ctx).await,
			_ => self.forward(frame, side, &ctx.trace()).await,
		}
	}
}

#[derive(Clone)]
pub struct RoverServletConfig {
	pub mars_relay_addr: LateAddr,
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
		ctx.env_config().take_in(frame, ctx).await
	}
}

impl DtnNode for RoverServletConfig {
	fn node_name(&self) -> &str {
		"rover"
	}

	fn signing_key(&self) -> &Secp256k1SigningKey {
		&self.rover_signing_key
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

	fn signers_on(&self, side: PathSide) -> Vec<&FrameSigner> {
		match side {
			PathSide::Earth => vec![&self.mission_control_signer, &self.mars_relay_signer],
			PathSide::Mars => Vec::new(),
		}
	}

	async fn hop_toward(
		&self,
		side: PathSide,
	) -> Result<(&Arc<ConnectionPool<TokioListener>>, TightBeamSocketAddr), TightBeamError> {
		match side {
			PathSide::Earth => Ok((&self.mars_relay_pool, wait_for_address(&self.mars_relay_addr).await?)),
			PathSide::Mars => Err(TightBeamError::MissingConfiguration),
		}
	}

	async fn route(&self, frame: Frame, side: PathSide, ctx: &ServletContext<Self>) -> Result<Routed, TightBeamError> {
		// The ACK needs the order of the command after the decrypt consumes
		// `frame`.
		let command_order = frame.metadata().order();
		match self.decrypt_relay_message(frame).await? {
			RelayMessage::Command(command) => {
				let request = RoverCommandHandlerRequest { command, max_rounds: self.max_rounds as u64 };
				ctx.relay::<RoverCommandHandlerWorker>(Arc::new(request)).await??;

				let (ack_order, ack_prev_digest) = self.chain_processor.prepare_outgoing()?;
				let ack_frame = self.frame_builder.build_relay_ack_frame(
					command_order,
					ack_order,
					ack_prev_digest,
					&self.rover_signing_key,
					&self.shared_cipher,
				)?;

				ctx.trace().event(ROVER_SEND_ACK)?;

				Ok(Routed::Answer(ack_frame))
			}
			RelayMessage::FrameRequest(request) => self.answer_frame_request(request, side, ctx).await,
			RelayMessage::FrameResponse(response) => self.take_frame_response(response, command_order, ctx).await,
			RelayMessage::Telemetry(_) | RelayMessage::CommandAck(_) => Ok(Routed::Nothing),
		}
	}
}

/// The mission progress that the nodes share so they coordinate.
#[derive(Default)]
pub struct MissionState {
	pub completed_rounds: usize,
	pub telemetry_received_count: usize,
	pub mission_complete: bool,
}
