//! The routing of the DTN nodes.
//!
//! Each node handles every frame its chain releases, admits a frame that the
//! signer of a peer signs, and asks the hop that sent a frame for the frames
//! missing before it.

use std::sync::{Arc, RwLock};

use tightbeam::asn1::{Frame, MessagePriority};
use tightbeam::builder::frame::FrameBuilder;
use tightbeam::builder::TypeBuilder;
use tightbeam::compress::ZstdCompression;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::prelude::{TightBeamSocketAddr, Version};
use tightbeam::trace::TraceCollector;
use tightbeam::utils::digest;
use tightbeam::TightBeamError;

use crate::dtn::certs::generate_shared_cipher;
use crate::dtn::events::{
	EARTH_RELAY_RECEIVE_FRAME_REQUEST, MARS_RELAY_RECEIVE_FRAME_REQUEST, MISSION_CONTROL_RECEIVE_ACK,
	MISSION_CONTROL_RECEIVE_FRAME_REQUEST, ROVER_RECEIVE_COMMAND,
};
use crate::dtn::fault_manager::FaultManager;
use crate::dtn::messages::{EarthCommand, FrameRequest, FrameResponse, RelayMessage, RoverCommand};
use crate::dtn::nodes::{DtnPath, DtnRole, NodeChain};
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
	/// The chain of Mission Control, which a test extends as Mission Control
	/// does.
	mission_control_chain: NodeChain,
}

/// The chains of the Rover and the Mars Relay after the Rover took two
/// commands in reverse order.
struct ReversedCommands {
	/// The chain of the Rover.
	rover_chain: NodeChain,
	/// The chain of the Mars Relay.
	mars_relay_chain: NodeChain,
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
			_mission_control: mission_control,
			_earth_relay: earth_relay,
			earth_relay_addr,
			mission_control_chain,
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

	/// Builds a frame request that `role` signs as the first frame of a chain
	/// of its own.
	fn frame_request(&self, role: DtnRole) -> Frame {
		let key = role.signing_key();
		let chain = self.chain(role.node_name());
		let request = FrameRequest::new([1; 32], [2; 32]).expect("two hashes fit an OCTET STRING");
		let frame = chain
			.frame_builder
			.build_frame_request_frame(request, 1, None, &key, &self.path.cipher);
		frame.expect("a frame request builds")
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
	async fn send_rover_two_reversed_commands(&self) -> ReversedCommands {
		let rover_chain = self.chain(DtnRole::Rover.node_name());
		let mars_relay_chain = self.chain(DtnRole::MarsRelay.node_name());
		let mars_relay_addr = LateAddr::default();
		let rover = self.start_rover(&rover_chain, &mars_relay_addr).await;
		let mars_relay = self
			.start_mars_relay(&mars_relay_chain, *rover.addr(), &LateAddr::default())
			.await;
		*mars_relay_addr.write().expect("the address slot is sound") = Some(*mars_relay.addr());

		let mission_control = self.chain(DtnRole::MissionControl.node_name());
		let first = self.command(&mission_control);
		let second = self.command(&mission_control);
		let client = DtnRole::MarsRelay.connect(DtnRole::Rover, *rover.addr());
		let mut client = client.await.expect("the Mars Relay connects to the Rover");
		client.emit(second, None).await.expect("the Rover buffers the second command");
		client.emit(first, None).await.expect("the Rover runs the first command");

		ReversedCommands { rover_chain, mars_relay_chain }
	}
}

/// Builds a standby command, which the Rover runs with no parameter.
fn standby() -> EarthCommand {
	let command = EarthCommand::new(RoverCommand::Standby, MessagePriority::Standard, 0);
	command.expect("a standby command has no parameter")
}

/// Whether `holder` stores the frame at the head of `origin`.
fn holds_head_of(holder: &NodeChain, origin: &NodeChain) -> bool {
	let (_, head) = origin.processor.prepare_outgoing().expect("the chain reads");
	let head = head.expect("the origin chain holds a frame");
	let held = holder.processor.request_missing_frames([0u8; 32], head.digest.as_bytes());

	!held.expect("the store of the holder reads").is_empty()
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
async fn the_rover_runs_every_command_its_chain_releases() {
	let path = TestPath::new();
	path.send_rover_two_reversed_commands().await;
	assert_eq!(path.trace().recorded(ROVER_RECEIVE_COMMAND), 2);
}

/// The second command waited in the buffer while its sender took `None`, so
/// the Rover sends the ACK of that command to the Mars Relay.
#[tokio::test]
async fn the_rover_sends_the_ack_of_a_buffered_command_to_the_mars_relay() {
	let path = TestPath::new();
	let reversed = path.send_rover_two_reversed_commands().await;
	assert!(holds_head_of(&reversed.mars_relay_chain, &reversed.rover_chain));
}

/// A frame of Mission Control whose predecessor the Earth Relay lacks sends
/// the Earth Relay's frame request to Mission Control, which holds it.
#[tokio::test]
async fn a_gap_in_a_mission_control_frame_asks_mission_control() -> Result<(), TightBeamError> {
	let path = TestPath::new();
	let ground = path.start_ground(unserved()).await;
	let key = DtnRole::MissionControl.signing_key();
	let chain = &ground.mission_control_chain;
	let (order, previous) = chain.processor.prepare_outgoing()?;
	let response = FrameResponse { frames: Vec::new() };
	let response = chain
		.frame_builder
		.build_frame_response_frame(response, order, previous, &key, &path.path.cipher);

	let mut client = DtnRole::MissionControl
		.connect(DtnRole::EarthRelay, ground.earth_relay_addr)
		.await?;
	client.emit(response?, None).await?;
	client.emit(path.stray_command(), None).await?;

	assert_eq!(path.trace().recorded(MISSION_CONTROL_RECEIVE_FRAME_REQUEST), 1);
	Ok(())
}
