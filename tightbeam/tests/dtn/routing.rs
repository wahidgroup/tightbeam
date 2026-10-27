//! The routing of the DTN nodes.
//!
//! Each node routes every frame its chain releases, admits a frame that the
//! signer of a peer signs, and asks the hop that sent a frame for the frames
//! missing before it.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tightbeam::asn1::{Frame, MessagePriority};
use tightbeam::builder::frame::FrameBuilder;
use tightbeam::builder::TypeBuilder;
use tightbeam::compress::ZstdCompression;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::der::Encode;
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::{TightBeamSocketAddr, Version};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::GenericClient;
use tightbeam::utils::digest;
use tightbeam::{servlet, TightBeamError};

use crate::common::security::expectation_failure;
use crate::dtn::certs::generate_shared_cipher;
use crate::dtn::events::{
	EARTH_RELAY_RECEIVE_FRAME_REQUEST, EARTH_RELAY_RECEIVE_FROM_MC, MARS_RELAY_RECEIVE_FRAME_REQUEST,
	MISSION_CONTROL_RECEIVE_ACK, MISSION_CONTROL_RECEIVE_FRAME_REQUEST, ROVER_RECEIVE_COMMAND,
};
use crate::dtn::fault_manager::FaultManager;
use crate::dtn::intake::{ChainFrame, SignedFrame};
use crate::dtn::messages::{EarthCommand, FrameRequest, FrameResponse, RelayMessage, RoverCommand};
use crate::dtn::nodes::{DtnPath, DtnRole, NodeChain, PathSide, ORDER_BUFFER_FRAMES};
use crate::dtn::servlets::{
	EarthRelaySatelliteServlet, LateAddr, MarsRelaySatelliteServlet, MissionControlServlet, MissionState, RoverServlet,
};
use crate::dtn::storage::StorageRoot;

/// Returns an address that no node serves, for a hop that a test leaves out.
fn unserved() -> TightBeamSocketAddr {
	TightBeamSocketAddr::from(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
}

/// Mission Control and the Earth Relay, linked to each other.
struct Ground {
	/// Mission Control, whose servlet runs while this value holds it.
	_mission_control: MissionControlServlet,
	/// The Earth Relay, whose servlet runs while this value holds it.
	_earth_relay: EarthRelaySatelliteServlet,
	/// The address of the Earth Relay.
	earth_relay_addr: TightBeamSocketAddr,
	/// The address of Mission Control.
	mission_control_addr: TightBeamSocketAddr,
	/// The chain of Mission Control, which a test extends as Mission Control
	/// does.
	mission_control_chain: NodeChain,
	/// The chain of the Earth Relay, which a test fills as the Earth Relay
	/// does.
	earth_relay_chain: NodeChain,
}

/// The chains of the Rover and the Mars Relay after the Rover took two
/// commands in reverse order.
struct ReversedCommands {
	/// The chain of the Rover.
	rover_chain: NodeChain,
	/// The chain of the Mars Relay.
	mars_relay_chain: NodeChain,
}

/// The ACKs of a Rover chain whose first ACK a hop loses.
struct LostAck {
	/// The first ACK, which the hop after the Mars Relay loses.
	lost: Frame,
	/// The ACKs after the lost one, as many as the order buffer of a node
	/// holds.
	after: Vec<Frame>,
	/// The ACK after those, which finds the order buffer full.
	next: Frame,
}

/// The Mars Relay, the Rover behind it, and the ground in front of it.
struct MarsSide {
	/// The Rover, whose servlet runs while this value holds it. Its chain
	/// holds none of the ACKs that a test builds, so a frame request that
	/// the Mars Relay cascades to it gets no answer.
	_rover: RoverServlet,
	/// The Mars Relay, whose servlet runs while this value holds it.
	_mars_relay: MarsRelaySatelliteServlet,
	/// The chain of the Mars Relay, which a test fills as the Mars Relay does.
	mars_relay_chain: NodeChain,
	/// Mission Control and the Earth Relay, which the Mars Relay sends on to.
	ground: Ground,
}

/// The node of the ground whose order buffer the ACKs after a loss fill.
#[derive(Clone, Copy)]
enum GapAt {
	/// The Earth Relay, which takes the ACKs from the Mars Relay.
	EarthRelay,
	/// Mission Control, which takes the ACKs from the Earth Relay.
	MissionControl,
}

impl GapAt {
	/// The hop that sends this node the ACKs of the Rover, and the role of
	/// this node.
	fn link(self) -> (DtnRole, DtnRole) {
		match self {
			Self::EarthRelay => (DtnRole::MarsRelay, DtnRole::EarthRelay),
			Self::MissionControl => (DtnRole::EarthRelay, DtnRole::MissionControl),
		}
	}

	/// The address of this node on `ground`.
	fn addr(self, ground: &Ground) -> TightBeamSocketAddr {
		match self {
			Self::EarthRelay => ground.earth_relay_addr,
			Self::MissionControl => ground.mission_control_addr,
		}
	}
}

/// The configuration of a hop that answers each frame request with one
/// fixed answer, whatever the request names.
#[derive(Clone)]
struct FixedAnswerConfig {
	/// The answer that the hop sends back to each frame request.
	answer: Frame,
	/// The number of frame requests that the hop took.
	requests: Arc<AtomicUsize>,
}

servlet! {
	/// A hop in the place of the Mars Relay, which answers each frame request
	/// with the answer of its configuration.
	FixedAnswerHop<RelayMessage, EnvConfig = FixedAnswerConfig>,
	protocol: TokioListener,
	handle: raw |_frame, ctx| async move {
		let config = ctx.env_config();
		config.requests.fetch_add(1, Ordering::Relaxed);
		Ok(Some(config.answer.to_owned()))
	}
}

/// A hop in the place of the Mars Relay, with the count of the frame
/// requests that it took.
struct FixedHop {
	/// The servlet of the hop, which runs while this value holds it.
	servlet: FixedAnswerHop,
	/// The number of frame requests that the hop took.
	requests: Arc<AtomicUsize>,
}

/// A path whose node at a gap took the ACKs after a loss.
struct FilledGap {
	/// The path, whose Mars Relay holds the lost ACK.
	side: MarsSide,
	/// The ACK that the hop after the Mars Relay lost, whose slot the gap
	/// recovery filled.
	lost: Frame,
	/// The reply of the node at the gap to the last ACK.
	reply: Option<Frame>,
}

/// A DTN path whose nodes record into one trace, over a storage root of its
/// own.
struct TestPath {
	path: DtnPath,
	storage: StorageRoot,
}

impl TestPath {
	fn new() -> Self {
		let path = DtnPath {
			trace: Arc::new(TraceCollector::new()),
			cipher: generate_shared_cipher(),
			mission_state: Arc::new(RwLock::new(MissionState::default())),
			rounds: 1,
		};
		let storage = StorageRoot::create().expect("the storage root opens");

		Self { path, storage }
	}

	/// Returns the trace that every node of the path records into.
	fn trace(&self) -> &TraceCollector {
		&self.path.trace
	}

	/// Opens an empty chain in the directory `name`.
	fn chain(&self, name: &str) -> NodeChain {
		NodeChain::open(&self.storage, name).expect("a node chain opens under the storage root")
	}

	/// Starts Mission Control and the Earth Relay, with the Mars Relay at
	/// `mars_relay`.
	async fn start_ground(&self, mars_relay: TightBeamSocketAddr) -> Ground {
		let mission_control_chain = self.chain(DtnRole::MissionControl.node_name());
		let earth_relay_chain = self.chain(DtnRole::EarthRelay.node_name());
		let mission_control_addr = LateAddr::default();
		let earth_relay = self
			.path
			.start_earth_relay(&earth_relay_chain, mars_relay, &mission_control_addr);

		let earth_relay = earth_relay.await.expect("the Earth Relay starts");
		let earth_relay_addr = *earth_relay.addr();
		let mission_control = self.path.start_mission_control(&mission_control_chain, earth_relay_addr);
		let mission_control = mission_control.await.expect("Mission Control starts");

		*mission_control_addr.write().expect("the address slot is sound") = Some(*mission_control.addr());

		Ground {
			mission_control_addr: *mission_control.addr(),
			_mission_control: mission_control,
			_earth_relay: earth_relay,
			earth_relay_addr,
			mission_control_chain,
			earth_relay_chain,
		}
	}

	/// Starts the Mars Relay over `chain`, with the Rover at `rover` and the
	/// Earth Relay at the address that `earth_relay` publishes.
	async fn start_mars_relay(
		&self,
		chain: &NodeChain,
		rover: TightBeamSocketAddr,
		earth_relay: &LateAddr,
	) -> MarsRelaySatelliteServlet {
		let mars_relay = self.path.start_mars_relay(chain, rover, earth_relay);
		mars_relay.await.expect("the Mars Relay starts")
	}

	/// Starts the Rover over `chain`, with the Mars Relay at the address that
	/// `mars_relay` publishes.
	async fn start_rover(&self, chain: &NodeChain, mars_relay: &LateAddr) -> RoverServlet {
		let faults = FaultManager::from_refs(&RwLock::default(), &RwLock::default(), &RwLock::default());
		let rover = self.path.start_rover(chain, mars_relay, Arc::new(faults));
		rover.await.expect("the Rover starts")
	}

	/// Builds the next ACK of the Rover, chained on `rover`.
	fn rover_ack(&self, rover: &NodeChain) -> Frame {
		let key = DtnRole::Rover.signing_key();
		let (order, previous) = rover.processor.prepare_outgoing().expect("the Rover chain reads");
		let ack = rover
			.frame_builder
			.build_relay_ack_frame(0, order, previous, &key, &self.path.cipher);
		ack.expect("an ACK frame builds")
	}

	/// Builds the next command of Mission Control, chained on
	/// `mission_control`.
	fn command(&self, mission_control: &NodeChain) -> Frame {
		let key = DtnRole::MissionControl.signing_key();
		let (order, previous) = mission_control.processor.prepare_outgoing().expect("the chain reads");
		let builder = &mission_control.frame_builder;
		let command = builder.build_relay_command_frame(standby(), order, previous, &key, &self.path.cipher);
		command.expect("a command frame builds")
	}

	/// Builds the first command of a chain, sealed under the path's cipher and
	/// signed by no node.
	fn unsigned_command(&self) -> Frame {
		let frame = FrameBuilder::from(Version::V3)
			.with_id("relay-cmd-001")
			.with_order(1)
			.with_message(RelayMessage::Command(standby()))
			.with_message_hasher::<Sha3_256>([])
			.with_witness_hasher::<Sha3_256>()
			.with_compression(ZstdCompression::default())
			.with_encryptor(self.path.cipher.to_owned())
			.build();

		frame.expect("an unsigned command frame builds")
	}

	/// Takes `frame` from the peer `role` on `side` into `chain`.
	async fn take(&self, chain: &NodeChain, frame: Frame, role: DtnRole, side: PathSide) {
		let signed = SignedFrame::from_peer(frame, role, side);
		let signed = signed.expect("the signer of the role verifies the frame");
		let entry = ChainFrame::open(signed, &self.path.cipher).await;
		let entry = entry.expect("the frame opens as a frame of the chain");

		let taken = chain.processor.process_incoming(entry);
		taken.expect("the chain takes the frame");
	}

	/// Builds a frame request that `role` signs, for the frames between two
	/// fixed test hashes.
	fn frame_request(&self, role: DtnRole) -> Frame {
		let key = role.signing_key();
		let chain = self.chain(role.node_name());
		let request = FrameRequest::new([1; 32], [2; 32]).expect("two hashes fit an OCTET STRING");
		let frame = chain.frame_builder.build_frame_request_frame(request, &key, &self.path.cipher);
		frame.expect("a frame request builds")
	}

	/// Builds a frame response that `role` signs, which carries `frames`.
	fn frame_response(&self, role: DtnRole, frames: Vec<Frame>) -> Frame {
		let key = role.signing_key();
		let chain = self.chain(role.node_name());
		let response = FrameResponse { frames };
		let builder = &chain.frame_builder;
		let frame = builder.build_frame_response_frame(response, &key, &self.path.cipher);
		frame.expect("a frame response builds")
	}

	/// Builds a command that Mission Control signs at order 2 over a
	/// predecessor that no node holds.
	fn stray_command(&self) -> Frame {
		let key = DtnRole::MissionControl.signing_key();
		let builder = self.chain("stray").frame_builder;
		let unknown = digest::<Sha3_256>(b"a frame that no node holds").expect("SHA3-256 digests");

		let frame = builder.build_relay_command_frame(standby(), 2, Some(unknown), &key, &self.path.cipher);
		frame.expect("a stray command builds")
	}

	/// Starts the Rover and the Mars Relay, and sends the Rover two commands
	/// of Mission Control in reverse order.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the Mars Relay fails to connect to the Rover, or the Rover refuses a command.
	async fn send_rover_two_reversed_commands(&self) -> Result<ReversedCommands, TightBeamError> {
		let rover_chain = self.chain(DtnRole::Rover.node_name());
		let mars_relay_chain = self.chain(DtnRole::MarsRelay.node_name());
		let mars_relay_addr = LateAddr::default();
		let rover = self.start_rover(&rover_chain, &mars_relay_addr).await;
		let mars_relay = self
			.start_mars_relay(&mars_relay_chain, *rover.addr(), &LateAddr::default())
			.await;

		*mars_relay_addr.write()? = Some(*mars_relay.addr());

		let mission_control = self.chain(DtnRole::MissionControl.node_name());
		let first = self.command(&mission_control);
		let second = self.command(&mission_control);
		let mut client = DtnRole::MarsRelay.connect(DtnRole::Rover, *rover.addr()).await?;
		client.emit(second, None).await?;
		client.emit(first, None).await?;

		Ok(ReversedCommands { rover_chain, mars_relay_chain })
	}

	/// Builds the first ACK of a Rover chain, the ACKs after it that fill the
	/// order buffer of a node, and the ACK after those.
	fn rover_acks_past_a_loss(&self) -> LostAck {
		let rover = self.chain(DtnRole::Rover.node_name());

		let lost = self.rover_ack(&rover);
		let after = (0..ORDER_BUFFER_FRAMES).map(|_| self.rover_ack(&rover)).collect();
		let next = self.rover_ack(&rover);
		LostAck { lost, after, next }
	}

	/// Starts the Rover over a chain of its own, the Mars Relay in front of
	/// it, and the ground in front of the Mars Relay.
	async fn start_mars_side(&self) -> MarsSide {
		let rover_chain = self.chain("rover_servlet");
		let rover = self.start_rover(&rover_chain, &LateAddr::default()).await;
		let earth_relay_addr = LateAddr::default();
		let mars_relay_chain = self.chain(DtnRole::MarsRelay.node_name());
		let mars_relay = self.start_mars_relay(&mars_relay_chain, *rover.addr(), &earth_relay_addr).await;
		let ground = self.start_ground(*mars_relay.addr()).await;
		*earth_relay_addr.write().expect("the address slot is sound") = Some(ground.earth_relay_addr);

		MarsSide { _rover: rover, _mars_relay: mars_relay, mars_relay_chain, ground }
	}

	/// Starts a hop in the place of the Mars Relay, which answers each frame
	/// request with `frames`.
	async fn start_fixed_hop(&self, frames: Vec<Frame>) -> FixedHop {
		let requests = Arc::new(AtomicUsize::new(0));
		let answer = self.frame_response(DtnRole::MarsRelay, frames);
		let config = FixedAnswerConfig { answer, requests: Arc::clone(&requests) };
		let servlet_config = DtnRole::MarsRelay
			.servlet_config(config)
			.expect("the Mars Relay identity loads");

		let servlet = FixedAnswerHop::start(Arc::clone(&self.path.trace), servlet_config.build()).await;
		FixedHop { servlet: servlet.expect("the hop starts"), requests }
	}

	/// Starts a path whose Mars Relay takes the Rover's first ACK into its
	/// chain, as before a forward that the next hop loses. The hop before the
	/// node `at` then sends it the ACKs after the lost one, in turn.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the hop fails to connect, or the node at the gap refuses an ACK.
	async fn fill_gap_at(&self, at: GapAt) -> Result<FilledGap, TightBeamError> {
		let acks = self.rover_acks_past_a_loss();
		let side = self.start_mars_side().await;
		let lost = acks.lost.to_owned();

		self.take(&side.mars_relay_chain, lost, DtnRole::Rover, PathSide::Mars).await;

		let (sender, receiver) = at.link();
		let mut client = sender.connect(receiver, at.addr(&side.ground)).await?;

		let reply = send_in_turn(&mut client, acks.after).await?;
		Ok(FilledGap { side, lost: acks.lost, reply })
	}
}

/// Builds a standby command, which the Rover runs with no parameter.
fn standby() -> EarthCommand {
	let command = EarthCommand::new(RoverCommand::Standby, MessagePriority::Standard, 0);
	command.expect("a standby command has no parameter")
}

/// Whether `holder` stores the frame at the head of `origin`.
///
/// # Errors
///
/// - [`TightBeamError`] -- the origin chain holds no frame, or a chain fails to read.
fn holds_head_of(holder: &NodeChain, origin: &NodeChain) -> Result<bool, TightBeamError> {
	let (_, head) = origin.processor.prepare_outgoing()?;
	let head = head.ok_or_else(|| expectation_failure("the origin chain holds no frame"))?;

	holder.processor.stores(head.digest.as_bytes())
}

/// The transit status that `refusal` carries, if it carries one.
fn status_of(refusal: TightBeamError) -> Option<TransitStatus> {
	let TightBeamError::TransportError(refusal) = refusal else {
		return None;
	};

	refusal.transit_status()
}

/// Runs `future` to its end, which a test expects within 5 s.
async fn within_seconds<T>(future: impl Future<Output = T>) -> T {
	let settled = tokio::time::timeout(Duration::from_secs(5), future).await;
	settled.expect("the node answers within 5 s")
}

/// Sends each frame of `frames` in turn over `client`, and returns the reply
/// to the last frame.
///
/// # Errors
///
/// - [`TightBeamError`] -- the node refuses a frame, or a send fails.
async fn send_in_turn(
	client: &mut GenericClient<TokioListener>,
	frames: Vec<Frame>,
) -> Result<Option<Frame>, TightBeamError> {
	let mut reply = None;
	for frame in frames {
		reply = client.emit(frame, None).await?;
	}

	Ok(reply)
}

/// The Earth Relay buffers the second ACK until the first arrives, and then
/// sends both on to Mission Control.
#[tokio::test]
async fn the_earth_relay_forwards_every_frame_its_chain_releases() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let ground = path.start_ground(unserved()).await;
	let rover = path.chain(DtnRole::Rover.node_name());
	let first = path.rover_ack(&rover);
	let second = path.rover_ack(&rover);
	let mut client = DtnRole::MarsRelay.connect(DtnRole::EarthRelay, ground.earth_relay_addr).await?;
	client.emit(second, None).await?;
	client.emit(first, None).await?;

	assert_eq!(path.trace().recorded(MISSION_CONTROL_RECEIVE_ACK), 2);
	Ok(())
}

/// The Mars Relay buffers the second ACK until the first arrives, and then
/// sends both on toward Mission Control.
#[tokio::test]
async fn the_mars_relay_forwards_every_frame_its_chain_releases() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let earth_relay_addr = LateAddr::default();
	let mars_relay_chain = path.chain(DtnRole::MarsRelay.node_name());
	let mars_relay = path.start_mars_relay(&mars_relay_chain, unserved(), &earth_relay_addr).await;
	let ground = path.start_ground(*mars_relay.addr()).await;

	*earth_relay_addr.write()? = Some(ground.earth_relay_addr);

	let rover = path.chain(DtnRole::Rover.node_name());
	let first = path.rover_ack(&rover);
	let second = path.rover_ack(&rover);

	let mut client = DtnRole::Rover.connect(DtnRole::MarsRelay, *mars_relay.addr()).await?;
	client.emit(second, None).await?;
	client.emit(first, None).await?;

	assert_eq!(path.trace().recorded(MISSION_CONTROL_RECEIVE_ACK), 2);
	Ok(())
}

/// A frame request that the Mars Relay cascades carries its own signature,
/// which the Earth Relay admits.
#[tokio::test]
async fn the_earth_relay_admits_a_request_the_mars_relay_cascades() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let ground = path.start_ground(unserved()).await;
	let request = path.frame_request(DtnRole::MarsRelay);
	let mut client = DtnRole::MarsRelay.connect(DtnRole::EarthRelay, ground.earth_relay_addr).await?;
	client.emit(request, None).await?;

	assert_eq!(path.trace().recorded(EARTH_RELAY_RECEIVE_FRAME_REQUEST), 1);
	Ok(())
}

/// The Earth Relay admits a frame request of the Mars Relay once, so a replay
/// of that request gets a refusal and no second answer.
#[tokio::test]
async fn the_earth_relay_answers_a_replayed_request_once() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let ground = path.start_ground(unserved()).await;
	let request = path.frame_request(DtnRole::MarsRelay);
	let mut client = DtnRole::MarsRelay.connect(DtnRole::EarthRelay, ground.earth_relay_addr).await?;
	client.emit(request.to_owned(), None).await?;

	let replay = client.emit(request, None).await;
	assert_eq!(
		replay.err().and_then(|refusal| refusal.transit_status()),
		Some(TransitStatus::Internal)
	);
	assert_eq!(path.trace().recorded(EARTH_RELAY_RECEIVE_FRAME_REQUEST), 1);
	Ok(())
}

/// A frame request that the Earth Relay cascades carries its own signature,
/// which the Mars Relay admits.
#[tokio::test]
async fn the_mars_relay_admits_a_request_the_earth_relay_cascades() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let rover_chain = path.chain(DtnRole::Rover.node_name());
	let mars_relay_chain = path.chain(DtnRole::MarsRelay.node_name());
	let rover = path.start_rover(&rover_chain, &LateAddr::default()).await;
	let mars_relay = path
		.start_mars_relay(&mars_relay_chain, *rover.addr(), &LateAddr::default())
		.await;

	let request = path.frame_request(DtnRole::EarthRelay);
	let mut client = DtnRole::EarthRelay.connect(DtnRole::MarsRelay, *mars_relay.addr()).await?;
	client.emit(request, None).await?;

	assert_eq!(path.trace().recorded(MARS_RELAY_RECEIVE_FRAME_REQUEST), 1);
	Ok(())
}

/// The Rover runs a command that Mission Control signs.
#[tokio::test]
async fn the_rover_runs_a_signed_command() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let rover = path
		.start_rover(&path.chain(DtnRole::Rover.node_name()), &LateAddr::default())
		.await;

	let command = path.command(&path.chain(DtnRole::MissionControl.node_name()));
	let mut client = DtnRole::MarsRelay.connect(DtnRole::Rover, *rover.addr()).await?;
	client.emit(command, None).await?;

	assert_eq!(path.trace().recorded(ROVER_RECEIVE_COMMAND), 1);
	Ok(())
}

/// The Rover refuses a command that no node signs, so the command never
/// runs.
#[tokio::test]
async fn the_rover_refuses_an_unsigned_command() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let rover = path
		.start_rover(&path.chain(DtnRole::Rover.node_name()), &LateAddr::default())
		.await;

	let command = path.unsigned_command();
	let mut client = DtnRole::MarsRelay.connect(DtnRole::Rover, *rover.addr()).await?;

	let reply = client.emit(command, None).await;
	assert!(reply.is_err());
	assert_eq!(path.trace().recorded(ROVER_RECEIVE_COMMAND), 0);
	Ok(())
}

/// The Rover buffers the second command until the first arrives, and then
/// runs both.
#[tokio::test]
async fn the_rover_runs_every_command_its_chain_releases() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	path.send_rover_two_reversed_commands().await?;
	assert_eq!(path.trace().recorded(ROVER_RECEIVE_COMMAND), 2);
	Ok(())
}

/// The second command waited in the buffer while its sender took `None`, so
/// the Rover sends the ACK of that command to the Mars Relay.
#[tokio::test]
async fn the_rover_sends_the_ack_of_a_buffered_command_to_the_mars_relay() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let reversed = path.send_rover_two_reversed_commands().await?;
	assert!(holds_head_of(&reversed.mars_relay_chain, &reversed.rover_chain)?);
	Ok(())
}

/// A Mission Control command waits in the Earth Relay's buffer for the Rover's
/// ACK before it. The command keeps the side its signer check found on arrival,
/// so it goes on to the Mars Relay once the ACK from the Mars side releases it.
#[tokio::test]
async fn a_released_frame_routes_by_the_side_it_arrived_from() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let side = path.start_mars_side().await;
	let earth_relay_addr = side.ground.earth_relay_addr;
	let shared = path.chain("shared");
	let ack = path.rover_ack(&shared);
	let command = path.command(&shared);
	let mut mission_control = DtnRole::MissionControl.connect(DtnRole::EarthRelay, earth_relay_addr).await?;
	let mut mars_relay = DtnRole::MarsRelay.connect(DtnRole::EarthRelay, earth_relay_addr).await?;

	mission_control.emit(command, None).await?;
	mars_relay.emit(ack, None).await?;

	assert_eq!(path.trace().recorded(EARTH_RELAY_RECEIVE_FROM_MC), 1);
	Ok(())
}

/// An ACK waits in Mission Control's buffer for the command before it, which
/// Mission Control then sends outside a take. The ACK takes its turn at once,
/// and Mission Control's next take routes it ahead of the arriving ACK.
#[tokio::test]
async fn a_frame_that_a_send_releases_routes_at_the_next_take() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let ground = path.start_ground(unserved()).await;
	let origin = path.chain("origin");
	let command = path.command(&origin);
	let first_ack = path.rover_ack(&origin);
	let second_ack = path.rover_ack(&origin);
	let mission_control_addr = ground.mission_control_addr;
	let connect = DtnRole::EarthRelay.connect(DtnRole::MissionControl, mission_control_addr);
	let mut earth_relay = connect.await?;

	earth_relay.emit(first_ack, None).await?;
	ground.mission_control_chain.processor.finalize_outgoing(&command)?;
	earth_relay.emit(second_ack, None).await?;

	assert_eq!(path.trace().recorded(MISSION_CONTROL_RECEIVE_ACK), 2);
	Ok(())
}

/// A frame that a send releases still routes after a refused arrival.
#[tokio::test]
async fn a_frame_that_a_send_releases_routes_after_a_refused_arrival() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let ground = path.start_ground(unserved()).await;
	let origin = path.chain("origin");
	let other = path.chain("other");
	let command = path.command(&origin);
	let first_ack = path.rover_ack(&origin);
	let second_ack = path.rover_ack(&origin);

	path.command(&other);

	let fork = path.rover_ack(&other);
	let connect = DtnRole::EarthRelay.connect(DtnRole::MissionControl, ground.mission_control_addr);
	let mut earth_relay = connect.await?;

	earth_relay.emit(first_ack, None).await?;
	ground.mission_control_chain.processor.finalize_outgoing(&command)?;

	let refusal = earth_relay.emit(fork, None).await;
	earth_relay.emit(second_ack, None).await?;

	assert!(refusal.is_err());
	assert_eq!(path.trace().recorded(MISSION_CONTROL_RECEIVE_ACK), 2);
	Ok(())
}

/// A failed route keeps the frames behind it for the next take.
#[tokio::test]
async fn a_failed_route_keeps_the_frames_behind_it() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let ground = path.start_ground(unserved()).await;
	let origin = path.chain("origin");
	let first = path.command(&origin);
	let second = path.command(&origin);
	let connect = DtnRole::MissionControl.connect(DtnRole::EarthRelay, ground.earth_relay_addr);
	let mut mission_control = connect.await?;
	mission_control.emit(second, None).await?;

	let failed = mission_control.emit(first, None).await;
	let kept = ground.earth_relay_chain.processor.take_released()?;
	assert!(failed.is_err());
	assert!(matches!(kept.as_slice(), [frame] if frame.order() == 2));
	Ok(())
}

/// A frame of Mission Control whose predecessor the Earth Relay lacks sends
/// the Earth Relay's frame request to Mission Control, which holds it.
#[tokio::test]
async fn a_gap_in_a_mission_control_frame_asks_mission_control() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let ground = path.start_ground(unserved()).await;
	let first = path.command(&ground.mission_control_chain);
	let earth_relay = &ground.earth_relay_chain;

	path.take(earth_relay, first, DtnRole::MissionControl, PathSide::Earth).await;

	let mut client = DtnRole::MissionControl
		.connect(DtnRole::EarthRelay, ground.earth_relay_addr)
		.await?;
	client.emit(path.stray_command(), None).await?;

	assert_eq!(path.trace().recorded(MISSION_CONTROL_RECEIVE_FRAME_REQUEST), 1);
	Ok(())
}

/// The Earth Relay misses the Rover's first ACK, and the ACKs after it fill its
/// order buffer. It asks the Mars Relay for the missing ACK, so Mission Control
/// receives every ACK.
#[tokio::test]
async fn a_gap_at_the_earth_relay_fills_from_the_mars_relay() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let _filled = path.fill_gap_at(GapAt::EarthRelay).await?;
	assert_eq!(path.trace().recorded(MISSION_CONTROL_RECEIVE_ACK), ORDER_BUFFER_FRAMES + 1);
	Ok(())
}

/// Mission Control misses the Rover's first ACK, and the ACKs after it fill its
/// order buffer. The Earth Relay lacks the missing ACK, so it cascades the
/// frame request to the Mars Relay and brings the answer back. Mission Control
/// receives every ACK.
#[tokio::test]
async fn a_gap_at_mission_control_fills_through_a_cascade() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let _filled = path.fill_gap_at(GapAt::MissionControl).await?;
	assert_eq!(path.trace().recorded(MISSION_CONTROL_RECEIVE_ACK), ORDER_BUFFER_FRAMES + 1);
	Ok(())
}

/// The lost ACK reaches the Earth Relay after the gap recovery filled its
/// slot, so it passes as a duplicate, and the Mars Relay gets the receipt of
/// its order.
#[tokio::test]
async fn a_frame_that_arrives_after_its_recovery_passes_as_a_duplicate() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let filled = path.fill_gap_at(GapAt::EarthRelay).await?;
	let earth_relay_addr = filled.side.ground.earth_relay_addr;
	let mut client = DtnRole::MarsRelay.connect(DtnRole::EarthRelay, earth_relay_addr).await?;

	let reply = client.emit(filled.lost, None).await?;
	let receipt = reply.ok_or(TightBeamError::MissingResponse)?;
	assert_eq!(receipt.metadata().id(), b"stateless-ack-1");
	Ok(())
}

/// The Mars Relay answers the Earth Relay's frame request outside its chain,
/// so its next frame takes the order after the lost ACK.
#[tokio::test]
async fn the_answer_to_a_gap_leaves_the_chain_of_its_holder() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let filled = path.fill_gap_at(GapAt::EarthRelay).await?;

	let (next_order, _) = filled.side.mars_relay_chain.processor.prepare_outgoing()?;
	assert_eq!(next_order, 2);
	Ok(())
}

/// The frame that shows the gap of Mission Control releases after the frames
/// of the answer, and its own receipt is the reply to its sender.
#[tokio::test]
async fn mission_control_answers_the_frame_that_shows_a_gap_with_its_receipt() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let filled = path.fill_gap_at(GapAt::MissionControl).await?;

	let receipt = filled.reply.ok_or(TightBeamError::MissingResponse)?;
	let receipt_of_arrival = format!("stateless-ack-{}", ORDER_BUFFER_FRAMES + 1);
	assert_eq!(receipt.metadata().id(), receipt_of_arrival.as_bytes());
	Ok(())
}

/// The Mars Relay lacks the lost ACK when the Earth Relay first asks, so the
/// first recovery comes back empty. The next ACK finds the buffer full and
/// asks again once the Mars Relay holds the lost ACK, so Mission Control
/// receives every ACK the Earth Relay's buffer held.
#[tokio::test]
async fn a_failed_recovery_asks_again_at_the_next_arrival() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let acks = path.rover_acks_past_a_loss();
	let side = path.start_mars_side().await;
	let mut client = DtnRole::MarsRelay
		.connect(DtnRole::EarthRelay, side.ground.earth_relay_addr)
		.await?;

	send_in_turn(&mut client, acks.after).await?;

	let mars_relay = &side.mars_relay_chain;
	path.take(mars_relay, acks.lost, DtnRole::Rover, PathSide::Mars).await;
	client.emit(acks.next, None).await?;

	assert_eq!(path.trace().recorded(MISSION_CONTROL_RECEIVE_ACK), ORDER_BUFFER_FRAMES + 1);
	Ok(())
}

/// A hop whose answer leaves the gap open gets one frame request for that
/// gap, and the take of the Earth Relay ends.
#[tokio::test]
async fn a_hop_whose_answer_leaves_the_gap_open_gets_one_request() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let acks = path.rover_acks_past_a_loss();
	let hop = path.start_fixed_hop(vec![acks.next]).await;
	let ground = path.start_ground(*hop.servlet.addr()).await;
	let mut client = DtnRole::MarsRelay.connect(DtnRole::EarthRelay, ground.earth_relay_addr).await?;

	within_seconds(send_in_turn(&mut client, acks.after)).await?;

	assert_eq!(hop.requests.load(Ordering::Relaxed), 1);
	Ok(())
}

/// An answer frame that no peer signs fails the arrival signer check, so the
/// Earth Relay refuses the answer and stores none of it.
#[tokio::test]
async fn the_earth_relay_refuses_an_answer_whose_frame_no_peer_signs() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let acks = path.rover_acks_past_a_loss();
	let unsigned = path.unsigned_command();
	let unsigned_digest = digest::<Sha3_256>(unsigned.to_der()?)?;
	let hop = path.start_fixed_hop(vec![unsigned]).await;
	let ground = path.start_ground(*hop.servlet.addr()).await;
	let mut client = DtnRole::MarsRelay.connect(DtnRole::EarthRelay, ground.earth_relay_addr).await?;

	let refusal = send_in_turn(&mut client, acks.after).await;
	let stored = ground.earth_relay_chain.processor.stores(unsigned_digest.digest.as_bytes())?;
	assert_eq!(refusal.err().and_then(status_of), Some(TransitStatus::Internal));
	assert!(!stored);
	Ok(())
}

/// A frame response answers a frame request of the node that sent it, so the
/// Earth Relay refuses one that arrives as a request, and its chain takes none
/// of its frames.
#[tokio::test]
async fn the_earth_relay_refuses_a_frame_response_that_arrives_as_a_request() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let ground = path.start_ground(unserved()).await;
	let ack = path.rover_ack(&path.chain(DtnRole::Rover.node_name()));
	let response = path.frame_response(DtnRole::MissionControl, vec![ack]);
	let mut client = DtnRole::MissionControl
		.connect(DtnRole::EarthRelay, ground.earth_relay_addr)
		.await?;

	let refusal = client.emit(response, None).await;
	let (next_order, _) = ground.earth_relay_chain.processor.prepare_outgoing()?;
	assert_eq!(
		refusal.err().and_then(|refusal| refusal.transit_status()),
		Some(TransitStatus::Internal)
	);
	assert_eq!(next_order, 1);
	Ok(())
}
