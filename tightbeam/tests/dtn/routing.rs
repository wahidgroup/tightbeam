//! The routing of the DTN nodes.
//!
//! Each node routes every frame its chain releases, admits a frame that the
//! signer of a peer signs, and asks the hop that sent a frame for the frames
//! missing before it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use tightbeam::asn1::Frame;
use tightbeam::builder::frame::FrameBuilder;
use tightbeam::builder::TypeBuilder;
use tightbeam::compress::ZstdCompression;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::{TightBeamSocketAddr, Version};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::GenericClient;
use tightbeam::urn::Urn;
use tightbeam::{servlet, tb_cases, TightBeamError};

use crate::common::poll::within_hang_guard;
use crate::common::result::TestResult;
use crate::common::security::fixed_signing_key;
use crate::dtn::certs::generate_shared_cipher;
use crate::dtn::events::{
	EARTH_RELAY_RECEIVE_FRAME_REQUEST, EARTH_RELAY_RECEIVE_FROM_MC, MARS_RELAY_RECEIVE_FRAME_REQUEST,
	MISSION_CONTROL_RECEIVE_ACK, MISSION_CONTROL_RECEIVE_FRAME_REQUEST, ROVER_RECEIVE_COMMAND,
};
use crate::dtn::fault_manager::FaultManager;
use crate::dtn::messages::{EarthCommand, FrameResponse, RelayMessage};
use crate::dtn::nodes::{DtnPath, DtnRole, NodeChain, PathSide, ORDER_BUFFER_FRAMES};
use crate::dtn::ordering::orders_of;
use crate::dtn::servlets::{
	EarthRelaySatelliteServlet, LateAddr, MarsRelaySatelliteServlet, MissionControlServlet, MissionState, RoverServlet,
};
use crate::dtn::storage::StorageRoot;
use crate::dtn::transit_status_of;

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
	mars_relay: MarsRelaySatelliteServlet,
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

/// A relay satellite of the path.
#[derive(Clone, Copy)]
enum Relay {
	/// The relay in orbit around Earth.
	Earth,
	/// The relay in orbit around Mars.
	Mars,
}

impl Relay {
	/// The node that sends this relay the ACKs of the Rover, and the role of
	/// this relay.
	fn ack_link(self) -> (DtnRole, DtnRole) {
		match self {
			Self::Earth => (DtnRole::MarsRelay, DtnRole::EarthRelay),
			Self::Mars => (DtnRole::Rover, DtnRole::MarsRelay),
		}
	}

	/// The other relay, which cascades a frame request to this one, and the
	/// role of this relay.
	fn cascade_link(self) -> (DtnRole, DtnRole) {
		match self {
			Self::Earth => (DtnRole::MarsRelay, DtnRole::EarthRelay),
			Self::Mars => (DtnRole::EarthRelay, DtnRole::MarsRelay),
		}
	}

	/// The address of this relay on `side`.
	fn addr(self, side: &MarsSide) -> TightBeamSocketAddr {
		match self {
			Self::Earth => side.ground.earth_relay_addr,
			Self::Mars => *side.mars_relay.addr(),
		}
	}

	/// The event that this relay records as it admits a frame request.
	fn request_event(self) -> Urn<'static> {
		match self {
			Self::Earth => EARTH_RELAY_RECEIVE_FRAME_REQUEST,
			Self::Mars => MARS_RELAY_RECEIVE_FRAME_REQUEST,
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
	/// with the answer of its configuration. An honest Mars Relay answers
	/// with the frames of the gap it holds, so no real node sends an answer
	/// that leaves the gap open or carries a frame that no peer signs.
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
		let path = &self.path;
		let earth_relay = path.start_earth_relay(&earth_relay_chain, mars_relay, &mission_control_addr);

		let earth_relay = earth_relay.await.expect("the Earth Relay starts");
		let earth_relay_addr = *earth_relay.addr();
		let mission_control = path.start_mission_control(&mission_control_chain, earth_relay_addr);
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

	/// Builds the first command of a chain of Mission Control, which Mission
	/// Control signs.
	fn signed_command(&self) -> Frame {
		self.chain(DtnRole::MissionControl.node_name()).command()
	}

	/// Builds the first command of a chain, which the Mars Relay signs in the
	/// place of Mission Control.
	fn relay_signed_command(&self) -> Frame {
		let chain = self.chain(DtnRole::MissionControl.node_name());
		chain.command_signed_by(&DtnRole::MarsRelay.signing_key())
	}

	/// Builds the first command of a chain, which the key of no peer signs.
	fn stranger_signed_command(&self) -> Frame {
		let chain = self.chain(DtnRole::MissionControl.node_name());
		chain.command_signed_by(&fixed_signing_key(0x55))
	}

	/// Builds the first command of a chain, sealed under the path's cipher and
	/// signed by no node.
	fn unsigned_command(&self) -> Frame {
		let frame = FrameBuilder::from(Version::V3)
			.with_id("relay-cmd-001")
			.with_order(1)
			.with_message(RelayMessage::Command(EarthCommand::standby()))
			.with_message_hasher::<Sha3_256>([])
			.with_witness_hasher::<Sha3_256>()
			.with_compression(ZstdCompression::default())
			.with_encryptor(self.path.cipher.to_owned())
			.build();

		frame.expect("an unsigned command frame builds")
	}

	/// Builds a frame request that `role` signs, over a chain of its own.
	fn frame_request(&self, role: DtnRole) -> Frame {
		self.chain(role.node_name()).frame_request(role)
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
		let earth_relay_addr = LateAddr::default();
		let mars_relay = self.start_mars_relay(&mars_relay_chain, *rover.addr(), &earth_relay_addr).await;

		*mars_relay_addr.write()? = Some(*mars_relay.addr());

		let mission_control = self.chain(DtnRole::MissionControl.node_name());
		let first = mission_control.command();
		let second = mission_control.command();
		let mut client = DtnRole::MarsRelay.connect(DtnRole::Rover, *rover.addr()).await?;
		client.emit(second, None).await?;
		client.emit(first, None).await?;

		Ok(ReversedCommands { rover_chain, mars_relay_chain })
	}

	/// Builds the first ACK of a Rover chain, the ACKs after it that fill the
	/// order buffer of a node, and the ACK after those.
	fn rover_acks_past_a_loss(&self) -> LostAck {
		let rover = self.chain(DtnRole::Rover.node_name());

		let lost = rover.rover_ack();
		let after = (0..ORDER_BUFFER_FRAMES).map(|_| rover.rover_ack()).collect();
		let next = rover.rover_ack();
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

		MarsSide { _rover: rover, mars_relay, mars_relay_chain, ground }
	}

	/// Starts a hop in the place of the Mars Relay, which answers each frame
	/// request with `frames`.
	async fn start_fixed_hop(&self, frames: Vec<Frame>) -> FixedHop {
		let requests = Arc::new(AtomicUsize::new(0));
		let answer = self.frame_response(DtnRole::MarsRelay, frames);
		let config = FixedAnswerConfig { answer, requests: Arc::clone(&requests) };
		let servlet_config = DtnRole::MarsRelay.servlet_config(config);
		let servlet_config = servlet_config.expect("the Mars Relay identity loads");

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

		side.mars_relay_chain.take(&acks.lost, DtnRole::Rover, PathSide::Mars)?;

		let (sender, receiver) = at.link();
		let mut client = sender.connect(receiver, at.addr(&side.ground)).await?;

		let reply = send_in_turn(&mut client, acks.after).await?;
		Ok(FilledGap { side, lost: acks.lost, reply })
	}
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

// A relay buffers the second ACK until the first arrives, and then sends both
// on toward Mission Control.
tb_cases! {
	async fn a_relay_forwards_every_frame_its_chain_releases(relay: Relay) -> TestResult {
		let path = TestPath::new();
		let side = path.start_mars_side().await;
		let rover = path.chain(DtnRole::Rover.node_name());
		let first = rover.rover_ack();
		let second = rover.rover_ack();
		let (sender, receiver) = relay.ack_link();
		let mut client = sender.connect(receiver, relay.addr(&side)).await?;
		client.emit(second, None).await?;
		client.emit(first, None).await?;

		assert_eq!(path.trace().recorded(MISSION_CONTROL_RECEIVE_ACK), 2);
		Ok(())
	}
	cases {
		earth_relay => Relay::Earth,
		mars_relay => Relay::Mars,
	}
}

// A frame request that one relay cascades carries its own signature, which
// the other relay admits.
tb_cases! {
	async fn a_relay_admits_a_request_the_other_relay_cascades(relay: Relay) -> TestResult {
		let path = TestPath::new();
		let side = path.start_mars_side().await;
		let (sender, receiver) = relay.cascade_link();
		let request = path.frame_request(sender);
		let mut client = sender.connect(receiver, relay.addr(&side)).await?;
		client.emit(request, None).await?;

		assert_eq!(path.trace().recorded(relay.request_event()), 1);
		Ok(())
	}
	cases {
		earth_relay => Relay::Earth,
		mars_relay => Relay::Mars,
	}
}

/// The Earth Relay admits a frame request of the Mars Relay once, so a replay
/// of that request gets a refusal and no second answer.
#[tokio::test]
async fn the_earth_relay_answers_a_replayed_request_once() -> TestResult {
	let path = TestPath::new();
	let ground = path.start_ground(unserved()).await;
	let request = path.frame_request(DtnRole::MarsRelay);
	let mut client = DtnRole::MarsRelay.connect(DtnRole::EarthRelay, ground.earth_relay_addr).await?;
	client.emit(request.to_owned(), None).await?;

	let replay = client.emit(request, None).await;
	let status = replay.err().and_then(|refusal| refusal.transit_status());
	assert_eq!(status, Some(TransitStatus::Internal));
	assert_eq!(path.trace().recorded(EARTH_RELAY_RECEIVE_FRAME_REQUEST), 1);
	Ok(())
}

// The Rover runs a command that Mission Control signs. It refuses a command
// with no signature, the signature of a relay, or the signature of a stranger,
// and that command never runs. The row `signed` is the control of the others.
tb_cases! {
	async fn the_rover_runs_only_a_command_that_mission_control_signs(
		(build, refusal, runs): (fn(&TestPath) -> Frame, Option<TransitStatus>, usize)
	) -> TestResult {
		let path = TestPath::new();
		let rover_chain = path.chain(DtnRole::Rover.node_name());
		let rover = path.start_rover(&rover_chain, &LateAddr::default()).await;

		let command = build(&path);
		let mut client = DtnRole::MarsRelay.connect(DtnRole::Rover, *rover.addr()).await?;

		let reply = client.emit(command, None).await;
		assert_eq!(reply.err().and_then(|refused| refused.transit_status()), refusal);
		assert_eq!(path.trace().recorded(ROVER_RECEIVE_COMMAND), runs);
		Ok(())
	}
	cases {
		signed => (TestPath::signed_command, None, 1),
		unsigned => (TestPath::unsigned_command, Some(TransitStatus::Internal), 0),
		/// The Mars Relay is a peer of the Rover, and it issues no command.
		relay_signed => (TestPath::relay_signed_command, Some(TransitStatus::Internal), 0),
		/// The signer of the command is no peer of the Rover.
		stranger_signed => (TestPath::stranger_signed_command, Some(TransitStatus::Internal), 0),
	}
}

/// The Rover buffers the second command until the first arrives, and then
/// runs both.
#[tokio::test]
async fn the_rover_runs_every_command_its_chain_releases() -> TestResult {
	let path = TestPath::new();
	path.send_rover_two_reversed_commands().await?;
	assert_eq!(path.trace().recorded(ROVER_RECEIVE_COMMAND), 2);
	Ok(())
}

/// The second command waited in the buffer while its sender took `None`, so
/// the Rover sends the ACK of that command to the Mars Relay.
#[tokio::test]
async fn the_rover_sends_the_ack_of_a_buffered_command_to_the_mars_relay() -> TestResult {
	let path = TestPath::new();
	let reversed = path.send_rover_two_reversed_commands().await?;
	let rover_head = reversed.rover_chain.head();
	assert!(reversed.mars_relay_chain.processor.stores(rover_head.digest.as_bytes())?);
	Ok(())
}

/// A Mission Control command waits in the Earth Relay's buffer for the Rover's
/// ACK before it. The command keeps the side its signer check found on arrival,
/// so it goes on to the Mars Relay once the ACK from the Mars side releases it.
#[tokio::test]
async fn a_released_frame_routes_by_the_side_it_arrived_from() -> TestResult {
	let path = TestPath::new();
	let side = path.start_mars_side().await;
	let earth_relay_addr = side.ground.earth_relay_addr;
	let shared = path.chain("shared");
	let ack = shared.rover_ack();
	let command = shared.command();
	let mut mission_control = DtnRole::MissionControl.connect(DtnRole::EarthRelay, earth_relay_addr).await?;
	let mut mars_relay = DtnRole::MarsRelay.connect(DtnRole::EarthRelay, earth_relay_addr).await?;

	mission_control.emit(command.to_owned(), None).await?;
	mars_relay.emit(ack, None).await?;

	assert_eq!(path.trace().recorded(EARTH_RELAY_RECEIVE_FROM_MC), 1);
	assert!(side.mars_relay_chain.stores(&command));
	Ok(())
}

/// An ACK waits in Mission Control's buffer for the command before it, which
/// Mission Control then sends outside a take. The ACK takes its turn at once,
/// and Mission Control's next take routes it ahead of the arriving ACK.
#[tokio::test]
async fn a_frame_that_a_send_releases_routes_at_the_next_take() -> TestResult {
	let path = TestPath::new();
	let ground = path.start_ground(unserved()).await;
	let origin = path.chain("origin");
	let command = origin.command();
	let first_ack = origin.rover_ack();
	let second_ack = origin.rover_ack();
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
async fn a_frame_that_a_send_releases_routes_after_a_refused_arrival() -> TestResult {
	let path = TestPath::new();
	let ground = path.start_ground(unserved()).await;
	let origin = path.chain("origin");
	let other = path.chain("other");
	let command = origin.command();
	let first_ack = origin.rover_ack();
	let second_ack = origin.rover_ack();

	other.advance(1);

	let fork = other.rover_ack();
	let connect = DtnRole::EarthRelay.connect(DtnRole::MissionControl, ground.mission_control_addr);
	let mut earth_relay = connect.await?;

	earth_relay.emit(first_ack, None).await?;
	ground.mission_control_chain.processor.finalize_outgoing(&command)?;

	let refusal = earth_relay.emit(fork, None).await;
	earth_relay.emit(second_ack, None).await?;

	let status = refusal.err().and_then(|refused| refused.transit_status());
	assert_eq!(status, Some(TransitStatus::Internal));
	assert_eq!(path.trace().recorded(MISSION_CONTROL_RECEIVE_ACK), 2);
	Ok(())
}

/// A failed route keeps the frames behind it for the next take.
#[tokio::test]
async fn a_failed_route_keeps_the_frames_behind_it() -> TestResult {
	let path = TestPath::new();
	let ground = path.start_ground(unserved()).await;
	let origin = path.chain("origin");
	let first = origin.command();
	let second = origin.command();
	let connect = DtnRole::MissionControl.connect(DtnRole::EarthRelay, ground.earth_relay_addr);
	let mut mission_control = connect.await?;
	mission_control.emit(second, None).await?;

	let failed = mission_control.emit(first, None).await;
	let kept = ground.earth_relay_chain.processor.take_released()?;
	let status = failed.err().and_then(|refused| refused.transit_status());
	assert_eq!(status, Some(TransitStatus::Internal));
	assert_eq!(orders_of(&kept), [2]);
	Ok(())
}

/// A frame of Mission Control whose predecessor the Earth Relay lacks sends
/// the Earth Relay's frame request to Mission Control, which holds it.
#[tokio::test]
async fn a_gap_in_a_mission_control_frame_asks_mission_control() -> TestResult {
	let path = TestPath::new();
	let ground = path.start_ground(unserved()).await;
	let first = ground.mission_control_chain.command();
	let earth_relay = &ground.earth_relay_chain;

	earth_relay.take(&first, DtnRole::MissionControl, PathSide::Earth)?;

	let connect = DtnRole::MissionControl.connect(DtnRole::EarthRelay, ground.earth_relay_addr);
	let mut client = connect.await?;
	client.emit(path.chain("stray").stray_command(), None).await?;

	assert_eq!(path.trace().recorded(MISSION_CONTROL_RECEIVE_FRAME_REQUEST), 1);
	Ok(())
}

// A node of the ground misses the Rover's first ACK, and the ACKs after it
// fill its order buffer. The gap fills, so Mission Control receives every ACK.
tb_cases! {
	async fn a_gap_fills_so_mission_control_receives_every_ack(at: GapAt) -> TestResult {
		let path = TestPath::new();
		let _filled = path.fill_gap_at(at).await?;
		assert_eq!(path.trace().recorded(MISSION_CONTROL_RECEIVE_ACK), ORDER_BUFFER_FRAMES + 1);
		Ok(())
	}
	cases {
		/// The Earth Relay asks the Mars Relay for the missing ACK.
		earth_relay => GapAt::EarthRelay,
		/// The Earth Relay lacks the missing ACK, so it cascades the request of
		/// Mission Control to the Mars Relay and brings the answer back.
		mission_control => GapAt::MissionControl,
	}
}

/// The lost ACK reaches the Earth Relay after the gap recovery filled its
/// slot, so it passes as a duplicate, and the Mars Relay gets the receipt of
/// its order.
#[tokio::test]
async fn a_frame_that_arrives_after_its_recovery_passes_as_a_duplicate() -> TestResult {
	let path = TestPath::new();
	let filled = path.fill_gap_at(GapAt::EarthRelay).await?;
	let earth_relay_addr = filled.side.ground.earth_relay_addr;
	let mut client = DtnRole::MarsRelay.connect(DtnRole::EarthRelay, earth_relay_addr).await?;

	let reply = client.emit(filled.lost, None).await?;
	let receipt = reply.as_ref().map(|receipt| receipt.metadata().id());
	assert_eq!(receipt, Some(b"stateless-ack-1".as_slice()));
	Ok(())
}

/// The Mars Relay answers the Earth Relay's frame request outside its chain,
/// so its next frame takes the order after the lost ACK.
#[tokio::test]
async fn the_answer_to_a_gap_leaves_the_chain_of_its_holder() -> TestResult {
	let path = TestPath::new();
	let filled = path.fill_gap_at(GapAt::EarthRelay).await?;

	let (next_order, _) = filled.side.mars_relay_chain.processor.prepare_outgoing()?;
	assert_eq!(next_order, 2);
	Ok(())
}

/// The frame that shows the gap of Mission Control releases after the frames
/// of the answer, and its own receipt is the reply to its sender.
#[tokio::test]
async fn mission_control_answers_the_frame_that_shows_a_gap_with_its_receipt() -> TestResult {
	let path = TestPath::new();
	let filled = path.fill_gap_at(GapAt::MissionControl).await?;

	let receipt = filled.reply.as_ref().map(|receipt| receipt.metadata().id());
	let receipt_of_arrival = format!("stateless-ack-{}", ORDER_BUFFER_FRAMES + 1);
	assert_eq!(receipt, Some(receipt_of_arrival.as_bytes()));
	Ok(())
}

/// The Mars Relay lacks the lost ACK when the Earth Relay first asks, so the
/// first recovery comes back empty. The next ACK finds the buffer full and
/// asks again once the Mars Relay holds the lost ACK, so Mission Control
/// receives every ACK the Earth Relay's buffer held.
#[tokio::test]
async fn a_failed_recovery_asks_again_at_the_next_arrival() -> TestResult {
	let path = TestPath::new();
	let acks = path.rover_acks_past_a_loss();
	let side = path.start_mars_side().await;
	let earth_relay_addr = side.ground.earth_relay_addr;
	let mut client = DtnRole::MarsRelay.connect(DtnRole::EarthRelay, earth_relay_addr).await?;

	send_in_turn(&mut client, acks.after).await?;

	let mars_relay = &side.mars_relay_chain;
	mars_relay.take(&acks.lost, DtnRole::Rover, PathSide::Mars)?;
	client.emit(acks.next, None).await?;

	assert_eq!(path.trace().recorded(MISSION_CONTROL_RECEIVE_ACK), ORDER_BUFFER_FRAMES + 1);
	Ok(())
}

/// A hop whose answer leaves the gap open gets one frame request for that
/// gap, and the take of the Earth Relay ends.
#[tokio::test]
async fn a_hop_whose_answer_leaves_the_gap_open_gets_one_request() -> TestResult {
	let path = TestPath::new();
	let acks = path.rover_acks_past_a_loss();
	let hop = path.start_fixed_hop(vec![acks.next]).await;
	let ground = path.start_ground(*hop.servlet.addr()).await;
	let mut client = DtnRole::MarsRelay.connect(DtnRole::EarthRelay, ground.earth_relay_addr).await?;

	// The reply to the last frame is the one event that marks the end of a
	// take, so the bound only guards a hang.
	let take = send_in_turn(&mut client, acks.after);
	within_hang_guard(take, "the node answers within the hang guard").await?;

	assert_eq!(hop.requests.load(Ordering::Relaxed), 1);
	Ok(())
}

/// An answer frame that no peer signs fails the arrival signer check, so the
/// Earth Relay refuses the answer and stores none of it.
#[tokio::test]
async fn the_earth_relay_refuses_an_answer_whose_frame_no_peer_signs() -> TestResult {
	let path = TestPath::new();
	let acks = path.rover_acks_past_a_loss();
	let unsigned = path.unsigned_command();
	let hop = path.start_fixed_hop(vec![unsigned.to_owned()]).await;
	let ground = path.start_ground(*hop.servlet.addr()).await;
	let mut client = DtnRole::MarsRelay.connect(DtnRole::EarthRelay, ground.earth_relay_addr).await?;

	let refusal = send_in_turn(&mut client, acks.after).await;
	let stored = ground.earth_relay_chain.stores(&unsigned);
	assert_eq!(refusal.err().and_then(transit_status_of), Some(TransitStatus::Internal));
	assert!(!stored);
	Ok(())
}

/// A frame response answers a frame request of the node that sent it, so the
/// Earth Relay refuses one that arrives as a request, and its chain takes none
/// of its frames.
#[tokio::test]
async fn the_earth_relay_refuses_a_frame_response_that_arrives_as_a_request() -> TestResult {
	let path = TestPath::new();
	let ground = path.start_ground(unserved()).await;
	let ack = path.chain(DtnRole::Rover.node_name()).rover_ack();
	let response = path.frame_response(DtnRole::MissionControl, vec![ack]);
	let connect = DtnRole::MissionControl.connect(DtnRole::EarthRelay, ground.earth_relay_addr);
	let mut client = connect.await?;

	let refusal = client.emit(response, None).await;
	let (next_order, _) = ground.earth_relay_chain.processor.prepare_outgoing()?;
	let status = refusal.err().and_then(|refusal| refusal.transit_status());
	assert_eq!(status, Some(TransitStatus::Internal));
	assert_eq!(next_order, 1);
	Ok(())
}
