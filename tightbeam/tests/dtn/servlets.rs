//! The DTN servlets of the four-tier architecture.
//!
//! It defines one servlet per tier:
//! - Mission Control receives telemetry, sends commands, and validates ACKs.
//! - The Earth Relay Satellite forwards messages between Mission Control and the Mars Relay.
//! - The Mars Relay Satellite forwards messages between the Earth Relay and the Rover.
//! - The Rover executes commands and sends telemetry and ACKs.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::RwLock;

use tightbeam::{
	colony::servlet::ServletContext,
	crypto::sign::ecdsa::Secp256k1SigningKey,
	prelude::*,
	servlet,
	task::Pipeline,
	trace::TraceCollector,
	transport::{tcp::r#async::TokioListener, ConnectionPool},
};

use crate::dtn::{
	certs::{FrameSigner, SharedCipher},
	chain_processor::{ChainProcessor, ProcessResult},
	clock::mission_time_ms,
	events::{
		EARTH_RELAY_FORWARD_ACK_TO_MC, EARTH_RELAY_FORWARD_TELEMETRY_TO_MC, EARTH_RELAY_FORWARD_TO_MARS,
		EARTH_RELAY_RECEIVE_ACK_FROM_MARS, EARTH_RELAY_RECEIVE_FROM_MC, EARTH_RELAY_RECEIVE_TELEMETRY_FROM_MARS,
		MARS_RELAY_FORWARD_ACK_TO_EARTH, MARS_RELAY_FORWARD_TELEMETRY_TO_EARTH, MARS_RELAY_FORWARD_TO_ROVER,
		MARS_RELAY_RECEIVE_ACK_FROM_ROVER, MARS_RELAY_RECEIVE_FROM_EARTH, MARS_RELAY_RECEIVE_TELEMETRY_FROM_ROVER,
		MISSION_CONTROL_RECEIVE_LOW_POWER_FLAG, ROVER_SEND_ACK,
	},
	fault_manager::FaultManager,
	fault_matrix::FaultType,
	frame_builder::FrameBuilderHelper,
	intake::{ChainFrame, Intake, SignedFrame},
	jobs::{BuildGapRecoveryFrame, CreateFrameRequest, EmitFrameToNetwork, GapRecoveryContext},
	messages::{ChainMessage, EarthCommand, FrameRequest, FrameResponse, RelayMessage},
	nodes::{DtnRole, PathSide},
	ultimate::GapRecoveryStep,
	workers::{
		command_ack_handler::{CommandAckHandlerRequest, CommandAckHandlerWorker},
		frame_request_handler::{FrameRequestAction, FrameRequestHandlerRequest, FrameRequestHandlerWorker},
		frame_response_handler::{FrameResponseHandlerRequest, FrameResponseHandlerWorker},
		mission_control_telemetry_handler::{MissionControlTelemetryHandlerWorker, TelemetryHandlerRequest},
		rover_command_handler::{RoverCommandHandlerRequest, RoverCommandHandlerWorker},
	},
};

/// The address of a hop that starts after the node that dials it. The hop
/// publishes it once its servlet runs, before the first frame that the node
/// routes to it.
pub type LateAddr = Arc<RwLock<Option<TightBeamSocketAddr>>>;

/// What a node does with one frame that its chain releases.
enum Routed {
	/// A chain frame that the node owes the sender: the ACK of a command.
	Answer(Frame),
	/// A stateless receipt for the sender, a frame outside the chain.
	Receipt(Frame),
	/// A chain frame that the next hop returned, which enters the node's chain.
	Returned(Frame),
	/// Nothing goes back.
	Nothing,
}

/// What a take keeps from the route of one released frame.
enum Settled {
	/// The reply that the take owes the sender of its arrival.
	Reply(Frame),
	/// A frame that the next hop returned, which enters the chain next.
	Entering(ChainFrame),
	/// The route of the frame is complete.
	Done,
}

/// The behavior that every node on the DTN path shares.
trait DtnNode: Sized + Send + Sync + 'static {
	// Each servlet configuration implements these required methods.
	fn role(&self) -> DtnRole;
	fn signing_key(&self) -> &Secp256k1SigningKey;
	fn cipher(&self) -> &SharedCipher;
	fn chain_processor(&self) -> &Arc<ChainProcessor>;
	fn frame_builder(&self) -> &Arc<FrameBuilderHelper>;

	/// Returns the signers of the peers on `side` of this node, each with the
	/// role of its peer.
	fn signers_on(&self, side: PathSide) -> Vec<(DtnRole, &FrameSigner)>;

	/// Returns the next hop toward `side`: its pool and its address.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingConfiguration`] -- the node has no hop on
	///   `side`, or that hop has published no address.
	/// - [`TightBeamError`] -- the lock of the published address is poisoned.
	async fn hop_toward(
		&self,
		side: PathSide,
	) -> Result<(&Arc<ConnectionPool<TokioListener>>, TightBeamSocketAddr), TightBeamError>;

	/// Routes `entry`, which the chain of this node released, from `side`.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- a worker fails, or a send fails.
	async fn route(
		&self,
		entry: ChainFrame,
		side: PathSide,
		ctx: &ServletContext<Self>,
	) -> Result<Routed, TightBeamError>;

	/// Checks `frame` against the signers of the peers of this node, the Earth
	/// side first.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingSignature`] -- no signer of a peer verifies the frame.
	fn signer_of(&self, frame: Frame) -> Result<SignedFrame, TightBeamError> {
		let peers = PathSide::BOTH.into_iter().flat_map(|side| {
			let signers = self.signers_on(side).into_iter();
			signers.map(move |(role, signer)| (side, role, signer))
		});

		SignedFrame::check(frame, peers)
	}

	/// Opens `frame` as a frame of the chain, from the side of the peer whose
	/// signer verifies it.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingSignature`] -- no signer of a peer verifies the frame.
	/// - The errors of [`ChainFrame::open`].
	async fn open_into_chain(&self, frame: Frame) -> Result<ChainFrame, TightBeamError> {
		let signed = self.signer_of(frame)?;
		ChainFrame::open(signed, self.cipher()).await
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

	/// Asks the hop on `side` for the frames after `current_head` up to the
	/// frame of `missing_hash`, the gap that a frame from `side` shows, and
	/// returns the frames of its answer in chain order.
	///
	/// - The frame request and its answer travel outside the chain, so the frames of the answer fill the gap.
	/// - Each frame of the answer passes the signer check and the kind check of an arriving frame.
	/// - A hop that holds none of the frames answers `None`, and the next
	///   arrival that finds the buffer full asks again.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingConfiguration`] -- the node has no hop on `side`.
	/// - [`TightBeamError::MissingSignature`] -- no signer of a peer verifies the answer or a frame of it.
	/// - [`TightBeamError::InvalidBody`] -- a frame of the answer travels outside the chain.
	/// - [`TightBeamError`] -- the request fails to build or send, or the answer fails to open.
	async fn handle_chain_gap(
		&self,
		current_head: impl Into<Vec<u8>>,
		missing_hash: impl Into<Vec<u8>>,
		side: PathSide,
		ctx: &ServletContext<Self>,
	) -> Result<Vec<ChainFrame>, TightBeamError> {
		let trace = ctx.trace();
		let current_head: Vec<u8> = current_head.into();
		let missing_hash: Vec<u8> = missing_hash.into();
		trace.event(GapRecoveryStep::GapDetected.event_on(self.role()))?;

		let (pool, upstream_addr) = self.hop_toward(side).await?;
		let gap = Arc::new(GapRecoveryContext {
			frame_builder: Arc::clone(self.frame_builder()),
			signing_key: Arc::new(self.signing_key().to_owned()),
			cipher: Arc::new(self.cipher().to_owned()),
			pool: Arc::clone(pool),
		});

		let frame = CreateFrameRequest::run((current_head, missing_hash))
			.map(|req| (req, Arc::clone(&gap)))
			.and_then(BuildGapRecoveryFrame::run)
			.run()?;

		trace.event(GapRecoveryStep::SendFrameRequest.event_on(self.role()))?;

		let frames = match EmitFrameToNetwork::run((frame, upstream_addr, gap)).await? {
			Some(answer) => self.open_answer(answer, ctx).await?,
			None => Vec::new(),
		};

		let mut answer = Vec::with_capacity(frames.len());
		for frame in frames {
			// Each frame of the answer keeps the side that its signer check
			// finds, and routes by it once the chain releases it.
			answer.push(self.open_into_chain(frame).await?);
		}

		Ok(answer)
	}

	/// Answers `request`, which `requester` sent from `side` as its request
	/// `order`, with the frames this node holds or the frames that a cascade to
	/// the hop across brings back. It returns `None` when this node is an
	/// origin that holds none of the frames, or when the hop across has no
	/// answer.
	///
	/// # Errors
	///
	/// - [`TightBeamError::TransportError`] -- the request gate refuses a replayed or a stale request.
	/// - [`TightBeamError`] -- the worker fails, or the cascade or the answer fails.
	async fn answer_frame_request(
		&self,
		request: FrameRequest,
		requester: DtnRole,
		order: u64,
		side: PathSide,
		ctx: &ServletContext<Self>,
	) -> Result<Option<Frame>, TightBeamError> {
		// The frame request worker admits the request through the request
		// gate, then picks whether the node responds, cascades, or takes no
		// action.
		let worker_request =
			FrameRequestHandlerRequest { request: request.to_owned(), node: self.role(), requester, order };
		let result = ctx.relay::<FrameRequestHandlerWorker>(Arc::new(worker_request)).await??;
		let frames = match result.action {
			FrameRequestAction::Respond(_) => Some(result.missing_frames),
			// The request goes on away from its requester.
			FrameRequestAction::Cascade(_) => self.cascade(request, side.across(), ctx).await?,
			// An origin of the path ends each cascade.
			FrameRequestAction::NoAction(_) => None,
		};

		let answer = frames.map(|frames| {
			let response = FrameResponse { frames };
			let builder = self.frame_builder();
			builder.build_frame_response_frame(response, self.signing_key(), self.cipher())
		});

		answer.transpose()
	}

	/// Sends `request` on to the hop toward `across`, and returns the frames
	/// of its answer, or `None` when that hop has no answer.
	async fn cascade(
		&self,
		request: FrameRequest,
		across: PathSide,
		ctx: &ServletContext<Self>,
	) -> Result<Option<Vec<Frame>>, TightBeamError> {
		let (pool, addr) = self.hop_toward(across).await?;
		let builder = self.frame_builder();
		let frame = builder.build_frame_request_frame(request, self.signing_key(), self.cipher())?;
		let Some(answer) = self.send_frame(pool, addr, frame).await? else {
			return Ok(None);
		};

		self.open_answer(answer, ctx).await.map(Some)
	}

	/// Opens `answer`, the reply of a hop to a frame request, and returns its
	/// frames.
	///
	/// The answer passes the signer check, and the response worker records it.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingSignature`] -- no signer of a peer verifies the answer.
	/// - [`TightBeamError::InvalidBody`] -- the answer carries a message other than a frame response.
	/// - [`TightBeamError`] -- the answer fails to open, or the worker fails.
	async fn open_answer(&self, answer: Frame, ctx: &ServletContext<Self>) -> Result<Vec<Frame>, TightBeamError> {
		let signed = self.signer_of(answer)?;
		let Intake::Response(response) = Intake::open(signed, self.cipher()).await? else {
			return Err(TightBeamError::InvalidBody);
		};

		let request = FrameResponseHandlerRequest { node: self.role() };
		ctx.relay::<FrameResponseHandlerWorker>(Arc::new(request)).await??;

		Ok(response.frames)
	}

	/// Takes `frame` from the peer that sent it, and returns the reply that
	/// the node owes that peer.
	///
	/// The frame opens once. A frame request travels hop to hop outside the
	/// chain, so the node answers it at once. A command, telemetry, or an ACK
	/// enters the chain through [`DtnNode::take_into_chain`].
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingSignature`] -- no signer of a peer verifies the frame.
	/// - [`TightBeamError::InvalidBody`] -- the frame is a frame response,
	///   which comes back as the reply to a frame request alone.
	/// - [`TightBeamError`] -- the frame fails to open, or the request gate,
	///   the answer, the chain, or a route fails.
	async fn take_in(&self, frame: Frame, ctx: &ServletContext<Self>) -> Result<Option<Frame>, TightBeamError> {
		let signed = self.signer_of(frame)?;
		let (side, signer) = (signed.side(), signed.role());
		let order = signed.frame().metadata().order();
		match Intake::open(signed, self.cipher()).await? {
			Intake::Request(request) => self.answer_frame_request(request, signer, order, side, ctx).await,
			Intake::Response(_) => Err(TightBeamError::InvalidBody),
			Intake::Chain(entry) => self.take_into_chain(entry, ctx).await,
		}
	}

	/// Takes `entry` into the chain, and routes each released frame by the side
	/// of its signer check.
	///
	/// A frame that a route sends or returns can release more frames, which
	/// route next. The frames behind a failed route wait for the next take.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingSignature`] -- no signer of a peer verifies a frame.
	/// - [`TightBeamError`] -- the chain refuses a frame, the gap recovery fails, or a route fails.
	async fn take_into_chain(
		&self,
		entry: ChainFrame,
		ctx: &ServletContext<Self>,
	) -> Result<Option<Frame>, TightBeamError> {
		let arrival = entry.order();
		let mut reply = None;
		let mut entering = VecDeque::from([entry]);

		while let Some(entry) = entering.pop_front() {
			// 1. Each frame opens through the signer check of its peer, which
			// refuses a frame that no peer signed and names the side.
			let side = entry.side();
			let order = entry.order();

			// 2. The chain orders the frame, and a gap answer fills its gap.
			let released = match self.chain_processor().process_incoming(entry)? {
				ProcessResult::Processed(released) => released,
				ProcessResult::Duplicate if order == arrival => {
					reply = Some(self.frame_builder().build_stateless_ack_frame(order)?);
					Vec::new()
				}
				ProcessResult::Buffered | ProcessResult::Duplicate => Vec::new(),
				ProcessResult::ChainGap { current_head, missing_hash } => {
					let answer = self.handle_chain_gap(current_head, missing_hash, side, ctx).await?;
					self.chain_processor().fill(answer)?
				}
			};

			// 3. The frames that the chain took before this take route first.
			let mut releasing = VecDeque::from(self.chain_processor().take_released()?);
			releasing.extend(released);
			while let Some(released_frame) = releasing.pop_front() {
				let owes_reply = released_frame.order() == arrival;
				let settled = match self.settle(released_frame, owes_reply, ctx).await {
					Ok(settled) => settled,
					Err(error) => {
						self.chain_processor().keep_released(releasing)?;
						return Err(error);
					}
				};
				match settled {
					Settled::Reply(sender_reply) => reply = Some(sender_reply),
					Settled::Entering(returned) => entering.push_back(returned),
					Settled::Done => {}
				}

				releasing.extend(self.chain_processor().take_released()?);
			}
		}

		Ok(reply)
	}

	/// Routes `released_frame` by the side that its signer check found, and
	/// returns what the take keeps from the route.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the route, the send of an answer, or the open of a returned frame fails.
	async fn settle(
		&self,
		released_frame: ChainFrame,
		owes_reply: bool,
		ctx: &ServletContext<Self>,
	) -> Result<Settled, TightBeamError> {
		let released_side = released_frame.side();
		let routed = self.route(released_frame, released_side, ctx).await?;
		match routed {
			Routed::Answer(sender_reply) | Routed::Receipt(sender_reply) if owes_reply => {
				Ok(Settled::Reply(sender_reply))
			}
			// A frame that waited sends its answer to the hop on its side.
			Routed::Answer(answer) => {
				let (pool, addr) = self.hop_toward(released_side).await?;
				self.send_frame(pool, addr, answer).await?;
				Ok(Settled::Done)
			}
			Routed::Returned(returned) => Ok(Settled::Entering(self.open_into_chain(returned).await?)),
			Routed::Receipt(_) | Routed::Nothing => Ok(Settled::Done),
		}
	}
}

/// The address that the upstream servlet published into `addr_lock`. Each
/// start publishes the address of its hop before the first frame that routes
/// to that hop, so one read finds it.
///
/// # Errors
///
/// - [`TightBeamError::MissingConfiguration`] -- the upstream servlet has published no address.
/// - [`TightBeamError`] -- the lock of the address is poisoned.
fn published_address(addr_lock: &LateAddr) -> Result<TightBeamSocketAddr, TightBeamError> {
	let published = *addr_lock.read()?;
	published.ok_or(TightBeamError::MissingConfiguration)
}

/// The environment of [`MissionControlServlet`], which is the Mission Control
/// node of the path.
#[derive(Clone)]
pub struct MissionControlServletConfig {
	/// The key that signs the frames of Mission Control.
	pub mission_control_signing_key: Secp256k1SigningKey,
	/// The certificate that verifies the frames of the Rover.
	pub rover_signer: FrameSigner,
	/// The certificate that verifies the frames of the Earth Relay.
	pub earth_relay_signer: FrameSigner,
	/// The cipher that seals and opens each message of the path.
	pub shared_cipher: SharedCipher,
	/// The chain processor that orders the frames of Mission Control.
	pub chain_processor: Arc<ChainProcessor>,
	/// The frame builder that extends the chain of Mission Control.
	pub frame_builder: Arc<FrameBuilderHelper>,
	/// The address of the Earth Relay, the hop on the Mars side.
	pub earth_relay_addr: TightBeamSocketAddr,
	/// The pool that dials the Earth Relay.
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
	fn role(&self) -> DtnRole {
		DtnRole::MissionControl
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

	fn signers_on(&self, side: PathSide) -> Vec<(DtnRole, &FrameSigner)> {
		match side {
			PathSide::Earth => Vec::new(),
			PathSide::Mars => vec![
				(DtnRole::Rover, &self.rover_signer),
				(DtnRole::EarthRelay, &self.earth_relay_signer),
			],
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

	async fn route(
		&self,
		entry: ChainFrame,
		_side: PathSide,
		ctx: &ServletContext<Self>,
	) -> Result<Routed, TightBeamError> {
		let frame_order = entry.order();
		let faults = entry.fault_matrix()?;
		match entry.into_message() {
			ChainMessage::Telemetry(telemetry) => {
				// The matrix of the frame carries the fault flags of the Rover.
				if faults.is_fault_active(FaultType::LowPower) {
					ctx.trace().event(MISSION_CONTROL_RECEIVE_LOW_POWER_FLAG)?;
				}

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
			ChainMessage::CommandAck(ack) => {
				// The ACK worker records that Mission Control received the ACK.
				let request = CommandAckHandlerRequest { ack };
				ctx.relay::<CommandAckHandlerWorker>(Arc::new(request)).await??;
				Ok(Routed::Receipt(self.frame_builder.build_stateless_ack_frame(frame_order)?))
			}
			ChainMessage::Command(_) => {
				// A command travels toward the Rover, so Mission Control
				// refuses one.
				Err(TightBeamError::InvalidBody)
			}
		}
	}
}

/// The environment of [`EarthRelaySatelliteServlet`], which is the Earth Relay
/// node of the path.
#[derive(Clone)]
pub struct EarthRelaySatelliteServletConfig {
	/// The key that signs the frames of the Earth Relay.
	pub earth_relay_signing_key: Secp256k1SigningKey,
	/// The certificate that verifies the frames of Mission Control.
	pub mission_control_signer: FrameSigner,
	/// The certificate that verifies the frames of the Mars Relay.
	pub mars_relay_signer: FrameSigner,
	/// The certificate that verifies the frames of the Rover.
	pub rover_signer: FrameSigner,
	/// The cipher that seals and opens each message of the path.
	pub shared_cipher: SharedCipher,
	/// The address of the Mars Relay, the hop on the Mars side.
	pub mars_relay_addr: TightBeamSocketAddr,
	/// The published address of Mission Control, the hop on the Earth side.
	pub mission_control_addr: LateAddr,
	/// The pool that dials Mission Control.
	pub mission_control_pool: Arc<ConnectionPool<TokioListener>>,
	/// The pool that dials the Mars Relay.
	pub mars_relay_pool: Arc<ConnectionPool<TokioListener>>,
	/// The chain processor that orders the frames of the Earth Relay.
	pub chain_processor: Arc<ChainProcessor>,
	/// The frame builder that extends the chain of the Earth Relay.
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
	/// Forwards `entry` from `side` to the hop across the relay.
	///
	/// A frame from Mission Control gets a receipt. A frame from the Mars side
	/// goes on as fire-and-forget, so the Mars Relay gets `None` as its reply.
	async fn forward(
		&self,
		entry: ChainFrame,
		side: PathSide,
		trace: &TraceCollector,
	) -> Result<Routed, TightBeamError> {
		let frame_order = entry.order();
		match side {
			PathSide::Earth => {
				trace.event(EARTH_RELAY_RECEIVE_FROM_MC)?;
				trace.event(EARTH_RELAY_FORWARD_TO_MARS)?;
			}
			PathSide::Mars => {
				let is_telemetry = matches!(entry.message(), ChainMessage::Telemetry(_));
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
		self.send_frame(pool, addr, entry.into_frame()).await?;

		match side {
			PathSide::Earth => Ok(Routed::Receipt(self.frame_builder.build_stateless_ack_frame(frame_order)?)),
			PathSide::Mars => Ok(Routed::Nothing),
		}
	}
}

impl DtnNode for EarthRelaySatelliteServletConfig {
	fn role(&self) -> DtnRole {
		DtnRole::EarthRelay
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

	fn signers_on(&self, side: PathSide) -> Vec<(DtnRole, &FrameSigner)> {
		match side {
			PathSide::Earth => vec![(DtnRole::MissionControl, &self.mission_control_signer)],
			PathSide::Mars => vec![
				(DtnRole::MarsRelay, &self.mars_relay_signer),
				(DtnRole::Rover, &self.rover_signer),
			],
		}
	}

	async fn hop_toward(
		&self,
		side: PathSide,
	) -> Result<(&Arc<ConnectionPool<TokioListener>>, TightBeamSocketAddr), TightBeamError> {
		match side {
			PathSide::Earth => Ok((&self.mission_control_pool, published_address(&self.mission_control_addr)?)),
			PathSide::Mars => Ok((&self.mars_relay_pool, self.mars_relay_addr)),
		}
	}

	async fn route(
		&self,
		entry: ChainFrame,
		side: PathSide,
		ctx: &ServletContext<Self>,
	) -> Result<Routed, TightBeamError> {
		self.forward(entry, side, &ctx.trace()).await
	}
}

/// The environment of [`MarsRelaySatelliteServlet`], which is the Mars Relay
/// node of the path.
#[derive(Clone)]
pub struct MarsRelaySatelliteServletConfig {
	/// The key that signs the frames of the Mars Relay.
	pub mars_relay_signing_key: Secp256k1SigningKey,
	/// The certificate that verifies the frames of Mission Control.
	pub mission_control_signer: FrameSigner,
	/// The certificate that verifies the frames of the Earth Relay.
	pub earth_relay_signer: FrameSigner,
	/// The certificate that verifies the frames of the Rover.
	pub rover_signer: FrameSigner,
	/// The cipher that seals and opens each message of the path.
	pub shared_cipher: SharedCipher,
	/// The address of the Rover, the hop on the Mars side.
	pub rover_addr: TightBeamSocketAddr,
	/// The published address of the Earth Relay, the hop on the Earth side.
	pub earth_relay_addr: LateAddr,
	/// The pool that dials the Earth Relay.
	pub earth_relay_pool: Arc<ConnectionPool<TokioListener>>,
	/// The pool that dials the Rover.
	pub rover_pool: Arc<ConnectionPool<TokioListener>>,
	/// The chain processor that orders the frames of the Mars Relay.
	pub chain_processor: Arc<ChainProcessor>,
	/// The frame builder that extends the chain of the Mars Relay.
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
	/// Forwards `entry` from `side` to the hop across the relay.
	///
	/// A frame from the Rover gets a receipt. The Rover answers a command from
	/// the Earth side with its signed ACK, which enters this relay's chain and
	/// goes on to the Earth Relay. The Earth Relay gets `None` as its reply.
	async fn forward(
		&self,
		entry: ChainFrame,
		side: PathSide,
		trace: &TraceCollector,
	) -> Result<Routed, TightBeamError> {
		let frame_order = entry.order();
		match side {
			PathSide::Earth => {
				trace.event(MARS_RELAY_RECEIVE_FROM_EARTH)?;
				trace.event(MARS_RELAY_FORWARD_TO_ROVER)?;
			}
			PathSide::Mars => {
				let is_telemetry = matches!(entry.message(), ChainMessage::Telemetry(_));
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
		let reply = self.send_frame(pool, addr, entry.into_frame()).await?;

		match side {
			PathSide::Earth => Ok(reply.map_or(Routed::Nothing, Routed::Returned)),
			PathSide::Mars => Ok(Routed::Receipt(self.frame_builder.build_stateless_ack_frame(frame_order)?)),
		}
	}
}

impl DtnNode for MarsRelaySatelliteServletConfig {
	fn role(&self) -> DtnRole {
		DtnRole::MarsRelay
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

	fn signers_on(&self, side: PathSide) -> Vec<(DtnRole, &FrameSigner)> {
		match side {
			PathSide::Earth => vec![
				(DtnRole::MissionControl, &self.mission_control_signer),
				(DtnRole::EarthRelay, &self.earth_relay_signer),
			],
			PathSide::Mars => vec![(DtnRole::Rover, &self.rover_signer)],
		}
	}

	async fn hop_toward(
		&self,
		side: PathSide,
	) -> Result<(&Arc<ConnectionPool<TokioListener>>, TightBeamSocketAddr), TightBeamError> {
		match side {
			PathSide::Earth => Ok((&self.earth_relay_pool, published_address(&self.earth_relay_addr)?)),
			PathSide::Mars => Ok((&self.rover_pool, self.rover_addr)),
		}
	}

	async fn route(
		&self,
		entry: ChainFrame,
		side: PathSide,
		ctx: &ServletContext<Self>,
	) -> Result<Routed, TightBeamError> {
		self.forward(entry, side, &ctx.trace()).await
	}
}

/// The environment of [`RoverServlet`], which is the Rover node of the path.
#[derive(Clone)]
pub struct RoverServletConfig {
	/// The published address of the Mars Relay, the hop on the Earth side.
	pub mars_relay_addr: LateAddr,
	/// The pool that dials the Mars Relay.
	pub mars_relay_pool: Arc<ConnectionPool<TokioListener>>,
	/// The key that signs the frames of the Rover.
	pub rover_signing_key: Secp256k1SigningKey,
	/// The certificate that verifies the frames of Mission Control.
	pub mission_control_signer: FrameSigner,
	/// The certificate that verifies the frames of the Mars Relay.
	pub mars_relay_signer: FrameSigner,
	/// The cipher that seals and opens each message of the path.
	pub shared_cipher: SharedCipher,
	/// The chain processor that orders the frames of the Rover.
	pub chain_processor: Arc<ChainProcessor>,
	/// The fault manager that tracks the battery and the faults of the Rover.
	pub _fault_manager: Arc<FaultManager>,
	/// The frame builder that extends the chain of the Rover.
	pub frame_builder: Arc<FrameBuilderHelper>,
	/// The number of commands at which the Rover marks the mission complete.
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
	fn role(&self) -> DtnRole {
		DtnRole::Rover
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

	fn signers_on(&self, side: PathSide) -> Vec<(DtnRole, &FrameSigner)> {
		match side {
			PathSide::Earth => vec![
				(DtnRole::MissionControl, &self.mission_control_signer),
				(DtnRole::MarsRelay, &self.mars_relay_signer),
			],
			PathSide::Mars => Vec::new(),
		}
	}

	async fn hop_toward(
		&self,
		side: PathSide,
	) -> Result<(&Arc<ConnectionPool<TokioListener>>, TightBeamSocketAddr), TightBeamError> {
		match side {
			PathSide::Earth => Ok((&self.mars_relay_pool, published_address(&self.mars_relay_addr)?)),
			PathSide::Mars => Err(TightBeamError::MissingConfiguration),
		}
	}

	async fn route(
		&self,
		entry: ChainFrame,
		_side: PathSide,
		ctx: &ServletContext<Self>,
	) -> Result<Routed, TightBeamError> {
		// The ACK needs the order of the command, which the entry gives up
		// with its message.
		let command_order = entry.order();
		match entry.into_message() {
			ChainMessage::Command(command) => {
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
			ChainMessage::Telemetry(_) | ChainMessage::CommandAck(_) => Ok(Routed::Nothing),
		}
	}
}

/// The mission progress that the nodes share so they coordinate.
#[derive(Default)]
pub struct MissionState {
	/// The number of commands that the Rover has run.
	pub completed_rounds: usize,
	/// The number of telemetry messages that Mission Control has received.
	pub telemetry_received_count: usize,
	/// Whether the Rover has run the last command of the mission.
	pub mission_complete: bool,
}
