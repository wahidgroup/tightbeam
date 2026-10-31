//! The chain processor of a DTN node, which takes each frame of the chain in
//! order.
//!
//! [`ChainProcessor`] owns these steps:
//! - It persists each frame that the ordering buffer admits.
//! - It restores frame order through the ordering buffer.
//! - It validates the cryptographic chain.
//! - It updates the chain state.
//! - It passes a duplicate of a chain frame.
//! - It detects a gap, and answers a frame request with the frames of a gap.
//!
//! `a_chain_at_the_last_order_prepares_no_frame` is a self-check of this
//! fixture, because it builds no frame.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use tightbeam::asn1::{AlgorithmIdentifier, DigestInfo, Frame, OctetString};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::der::oid::AssociatedOid;
use tightbeam::TightBeamError;

use crate::dtn::intake::ChainFrame;
use crate::dtn::messages::MessageChainState;
use crate::dtn::ordering::{Admission, OutOfOrderBuffer, Slot, Stopped};
use crate::dtn::storage::FrameStore;

/// The result of [`ChainProcessor::process_incoming`] for one frame.
#[derive(Debug, PartialEq)]
pub enum ProcessResult {
	/// The buffer released these frames and the chain validated them, so the
	/// application acts on them in chain order.
	Processed(Vec<ChainFrame>),
	/// The buffer holds the frame, or its first copy, until its turn.
	Buffered,
	/// The frame repeats a frame of the chain, and the chain stays as it is.
	Duplicate,
	/// The chain has a gap, so the node requests the missing frames.
	ChainGap { current_head: Vec<u8>, missing_hash: Vec<u8> },
}

impl ProcessResult {
	/// The gap from the head of `chain` to the frame that `missing` names.
	fn gap(chain: &MessageChainState, missing: Option<&DigestInfo>) -> Self {
		let current_head = chain.last_hash.to_vec();
		let missing_hash = missing.map(|digest| digest.digest.as_bytes().to_vec()).unwrap_or_default();
		Self::ChainGap { current_head, missing_hash }
	}

	/// The answer to an exact repeat of the frame at `slot`: the answer of its
	/// first copy.
	fn repeat_at(slot: Slot) -> Self {
		match slot {
			Slot::Released => Self::Duplicate,
			Slot::Held => Self::Buffered,
		}
	}
}

/// The chain and the store of one take, which judge each frame at its turn
/// and each held frame that the buffer moves past.
struct Turn<'a> {
	chain: &'a mut MessageChainState,
	store: &'a mut FrameStore,
}

impl Turn<'_> {
	/// Whether the chain takes `next`, the frame at its turn. The chain
	/// advances to a frame it takes, and a frame it refuses leaves the store.
	fn take(&mut self, next: &ChainFrame) -> Result<bool, TightBeamError> {
		if self.chain.extend(next.frame())? {
			return Ok(true);
		}

		self.store.remove(next.frame())?;
		Ok(false)
	}

	/// Removes `passed` from the store: a held frame at an order that a frame
	/// of the node took. A held frame in the place of the node's frame already
	/// left the store when the store took that frame.
	fn leave(&mut self, passed: &ChainFrame) -> Result<(), TightBeamError> {
		if self.store.holds(passed.frame())? {
			self.store.remove(passed.frame())?;
		}

		Ok(())
	}
}

/// The ordering, validation, and storage of the chain of one DTN node.
pub struct ChainProcessor {
	store: Arc<RwLock<FrameStore>>,
	chain_state: Arc<RwLock<MessageChainState>>,
	order_buffer: Arc<RwLock<OutOfOrderBuffer<ChainFrame>>>,
	/// The frames that the chain took and that wait for a route, by order.
	released: Mutex<BTreeMap<u64, ChainFrame>>,
}

impl ChainProcessor {
	pub fn new(
		store: Arc<RwLock<FrameStore>>,
		chain_state: Arc<RwLock<MessageChainState>>,
		order_buffer: Arc<RwLock<OutOfOrderBuffer<ChainFrame>>>,
	) -> Self {
		Self { store, chain_state, order_buffer, released: Mutex::default() }
	}

	/// Orders `entry`, stores it once the buffer and the chain admit it, and
	/// returns the frames that the chain takes.
	///
	/// An exact repeat at a taken slot gets the answer of its first copy.
	///
	/// # Errors
	///
	/// - [`TightBeamError::TransportError`] -- the buffer refuses the order, and the refusal names no hole.
	/// - [`TightBeamError`] -- the store, the chain, or a lock fails. Taken frames wait for the next take.
	pub fn process_incoming(&self, entry: ChainFrame) -> Result<ProcessResult, TightBeamError> {
		// The take holds the buffer, the chain, and the store to its end, so no
		// other take sees the buffer ahead of the chain.
		let mut buffer = self.order_buffer.write()?;
		let mut chain = self.chain_state.write()?;
		let mut store = self.store.write()?;

		// 1. The buffer admits the frame by its order.
		if let Err(refusal) = buffer.admits(entry.order()) {
			// A copy of the frame in the store answers as its first copy.
			if let Some(slot) = refusal.occupied_slot() {
				if store.holds(entry.frame())? {
					return Ok(ProcessResult::repeat_at(slot));
				}
			}

			if let Some(hole_end) = refusal.hole_end() {
				return Ok(ProcessResult::gap(&chain, Some(hole_end)));
			}

			return Err(refusal.into());
		}

		// 2. A frame at its turn that misses the chain head forks the chain.
		// It stays out of the store and the buffer, and its gap asks the hop.
		let at_turn = entry.order() == buffer.next_expected();
		if at_turn && !chain.validate_frame(entry.frame())? {
			return Ok(ProcessResult::gap(&chain, entry.frame().metadata().previous_frame()));
		}

		// 3. The store writes before the buffer takes the frame, so a failed
		// write leaves the buffer and the chain as they were. The buffer then
		// releases each frame at its turn that the chain takes, and a held
		// fork leaves the store at its turn.
		store.persist(entry.frame().to_owned())?;
		let mut turn = Turn { chain: &mut chain, store: &mut store };
		let admission = buffer.insert_into(entry, |next| turn.take(next));
		let admission = admission.map_err(|stopped| self.keep(stopped))?;

		let result = match admission {
			Admission::Released(frames) => ProcessResult::Processed(frames),
			Admission::Held => ProcessResult::Buffered,
			Admission::Stalled(hole_end) => ProcessResult::gap(&chain, Some(&hole_end)),
		};

		Ok(result)
	}

	/// Takes an answer to a gap into the chain and returns the released frames.
	///
	/// A frame that the chain holds passes as a duplicate. A refused frame
	/// leaves the frames before it to the next take.
	///
	/// # Errors
	///
	/// - The errors of [`ChainProcessor::process_incoming`].
	pub fn fill(&self, answer: Vec<ChainFrame>) -> Result<Vec<ChainFrame>, TightBeamError> {
		let mut released = Vec::new();
		for entry in answer {
			let taken = match self.process_incoming(entry) {
				Ok(taken) => taken,
				Err(error) => {
					self.keep_released(released)?;
					return Err(error);
				}
			};

			if let ProcessResult::Processed(frames) = taken {
				released.extend(frames);
			}
		}

		Ok(released)
	}

	/// The order and the `previous_frame` digest of the next frame that this
	/// node sends. The first frame takes order 1 and no digest.
	///
	/// # Errors
	///
	/// - [`TightBeamError::InvalidOrder`] -- the chain holds a frame at the last order.
	/// - [`TightBeamError`] -- the lock of the chain is poisoned.
	pub fn prepare_outgoing(&self) -> Result<(u64, Option<DigestInfo>), TightBeamError> {
		let chain_state = self.chain_state.read()?;
		let next_order = chain_state.sequence.checked_add(1).ok_or(TightBeamError::InvalidOrder)?;
		let previous_digest = if chain_state.sequence > 0 {
			// The chain state holds the bare hash, so the digest names its
			// algorithm, SHA3-256.
			let algorithm = AlgorithmIdentifier { oid: Sha3_256::OID, parameters: None };
			let digest = OctetString::new(&chain_state.last_hash[..])?;
			Some(DigestInfo { algorithm, digest })
		} else {
			None
		};

		Ok((next_order, previous_digest))
	}

	/// Persists `frame`, which this node sends, as the head of its chain, and
	/// moves the ordering buffer past its order.
	///
	/// A passed held frame leaves the buffer and the store. The held frame at
	/// the new turn takes it at once ([`ChainProcessor::take_released`]).
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the store, the chain, or a lock fails. Taken frames wait for the next take.
	pub fn finalize_outgoing(&self, frame: &Frame) -> Result<(), TightBeamError> {
		let mut buffer = self.order_buffer.write()?;
		let mut chain = self.chain_state.write()?;
		let mut store = self.store.write()?;

		store.persist(frame.to_owned())?;
		chain.update_with_frame(frame)?;

		// The node sent the frame at this order, so the buffer moves its next
		// expected order past it and stays aligned with the chain.
		let mut turn = Turn { chain: &mut chain, store: &mut store };
		buffer.move_past(frame.metadata().order(), |passed| turn.leave(passed))?;

		// The frame at the new turn takes it with no wait for an arrival.
		let released = buffer.release_turn(|next| turn.take(next));
		let released = released.map_err(|stopped| self.keep(stopped))?;
		self.keep_released(released)
	}

	/// Keeps the frames that the chain took before `stopped` for the next
	/// take, and returns the failure.
	fn keep(&self, stopped: Stopped<ChainFrame, TightBeamError>) -> TightBeamError {
		match self.keep_released(stopped.taken) {
			Ok(()) => stopped.cause,
			Err(poisoned) => poisoned,
		}
	}

	/// Keeps `frames`, which the chain took, for the next take to route in
	/// chain order.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the lock of the frames is poisoned.
	pub fn keep_released(&self, frames: impl IntoIterator<Item = ChainFrame>) -> Result<(), TightBeamError> {
		let mut released = self.released.lock()?;
		released.extend(frames.into_iter().map(|frame| (frame.order(), frame)));
		Ok(())
	}

	/// Takes the frames that wait for a route, in chain order, so the node
	/// routes them.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the lock of the frames is poisoned.
	pub fn take_released(&self) -> Result<Vec<ChainFrame>, TightBeamError> {
		let mut released = self.released.lock()?;
		Ok(std::mem::take(&mut *released).into_values().collect())
	}

	/// Whether the store of this chain holds the frame whose SHA3-256 hash is
	/// `hash`.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the store fails to read a frame, or its lock is poisoned.
	pub fn stores(&self, hash: impl AsRef<[u8]>) -> Result<bool, TightBeamError> {
		let held = self.store.write()?.retrieve_by_hash(hash)?;
		Ok(held.is_some())
	}

	/// Returns the frames after `requester_head` up to the frame of
	/// `last_received_hash`, in chain order.
	///
	/// The walk runs back from the frame of `last_received_hash` through each
	/// `previous_frame` digest, and answers only when it meets the requester's
	/// head, so a request gets at most the hole it names.
	///
	/// - The first frame of the chain meets the head of an empty chain.
	/// - A walk that leaves the store, or that reaches the first frame without
	///   meeting the head, answers no frame.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the store fails to read a frame, or its lock is poisoned.
	pub fn request_missing_frames(
		&self,
		requester_head: impl AsRef<[u8]>,
		last_received_hash: impl AsRef<[u8]>,
	) -> Result<Vec<Frame>, TightBeamError> {
		let requester_head = requester_head.as_ref();
		let last_received_hash = last_received_hash.as_ref();

		// The requester holds the frame that the walk starts from.
		if last_received_hash == requester_head {
			return Ok(Vec::new());
		}

		let mut store = self.store.write()?;
		let mut hole = Vec::new();
		let mut link = last_received_hash.to_vec();
		loop {
			let Some(frame) = store.retrieve_by_hash(&link)? else {
				return Ok(Vec::new());
			};

			let link_back = frame.metadata().previous_frame();
			let previous = link_back.map(|digest| digest.digest.as_bytes().to_vec());
			hole.push(frame);
			match previous {
				Some(previous) if previous == requester_head => break,
				Some(previous) => link = previous,
				None if requester_head == MessageChainState::EMPTY_HEAD => break,
				None => return Ok(Vec::new()),
			}
		}

		hole.reverse();
		Ok(hole)
	}
}

mod tests {
	use tightbeam::policy::TransitStatus;
	use tightbeam::tb_cases;
	use tightbeam::utils::digest;

	use super::*;
	use crate::common::result::TestResult;
	use crate::dtn::nodes::{DtnRole, NodeChain, PathSide, ORDER_BUFFER_FRAMES};
	use crate::dtn::ordering::orders_of;
	use crate::dtn::storage::{FrameKey, StorageRoot};
	use crate::dtn::transit_status_of;

	/// A frame of [`Branches`], which a table row names before the frames
	/// exist.
	#[derive(Clone, Copy)]
	enum Pick {
		/// The first ACK of the Rover chain.
		First,
		/// The second ACK of the Rover chain.
		Second,
		/// The ACK at order 2 of another branch.
		Fork,
		/// The ACK at order 3 of another branch.
		ThirdFork,
	}

	/// How the first ACK of the Rover chain reaches the node.
	#[derive(Clone, Copy)]
	enum Delivery {
		/// The node takes the ACK as it arrives from the Rover.
		Taken,
		/// The node sends the ACK as a frame of its own.
		Sent,
	}

	impl Delivery {
		/// Delivers `frame` to `node` this way.
		///
		/// # Errors
		///
		/// - The errors of [`ChainProcessor::process_incoming`] and [`ChainProcessor::finalize_outgoing`].
		fn deliver(self, node: &NodeChain, frame: &Frame) -> Result<(), TightBeamError> {
			match self {
				Self::Taken => node.take(frame, DtnRole::Rover, PathSide::Mars).map(drop),
				Self::Sent => node.processor.finalize_outgoing(frame),
			}
		}
	}

	/// A node with an empty chain, the first two ACKs of a Rover chain, and
	/// two ACKs of another branch.
	struct Branches {
		/// The node, whose chain holds no frame until a test takes one.
		node: NodeChain,
		/// The first ACK of the Rover chain.
		first: Frame,
		/// The second ACK of the Rover chain.
		second: Frame,
		/// The ACK at order 2 of another branch, which forks the chain.
		fork: Frame,
		/// The ACK at order 3 of another branch, which forks the chain.
		third_fork: Frame,
		/// The storage root of the chains, which lives as long as the node.
		root: StorageRoot,
	}

	impl Branches {
		/// Opens the chains under a storage root of their own, and builds the
		/// ACKs.
		fn new() -> Self {
			let root = StorageRoot::create().expect("the storage root opens");
			let rover = NodeChain::open(&root, "rover").expect("the Rover chain opens");
			let branch = NodeChain::open(&root, "branch").expect("the branch chain opens");
			let node = NodeChain::open(&root, "node").expect("the node chain opens");
			let first = rover.rover_ack();
			let second = rover.rover_ack();
			let fork = branch.fork_ack(2);
			let third_fork = branch.fork_ack(3);

			Self { node, first, second, fork, third_fork, root }
		}

		/// The branches after the node took each of `picks` in turn.
		fn having_taken(picks: &[Pick]) -> Self {
			let branches = Self::new();
			for &pick in picks {
				let taken = branches.take(branches.pick(pick));
				taken.expect("the node takes each frame of the arrange");
			}

			branches
		}

		/// The frame that `pick` names.
		fn pick(&self, pick: Pick) -> &Frame {
			match pick {
				Pick::First => &self.first,
				Pick::Second => &self.second,
				Pick::Fork => &self.fork,
				Pick::ThirdFork => &self.third_fork,
			}
		}

		/// `frame` as it arrives at the node from the Rover.
		fn arrival(&self, frame: &Frame) -> ChainFrame {
			ChainFrame::arriving(frame, DtnRole::Rover, PathSide::Mars)
		}

		/// Takes `frame` into the chain of the node, as the frame arrives from
		/// the Rover.
		fn take(&self, frame: &Frame) -> Result<ProcessResult, TightBeamError> {
			self.node.take(frame, DtnRole::Rover, PathSide::Mars)
		}

		/// Puts a directory at the file of `frame`, so its removal fails.
		fn block_removal_of(&self, frame: &Frame) {
			let path = self.root.node("node").join(FrameKey::of(frame).file_name());
			std::fs::remove_file(&path).expect("the store holds the file of the frame");
			std::fs::create_dir(&path).expect("a directory takes the place of the file");
		}
	}

	/// A node whose order buffer holds the ACKs of the Rover after a lost
	/// one, as many as the buffer holds.
	struct FullBuffer {
		/// The node, whose chain holds no frame.
		node: NodeChain,
		/// The ACK after the held ones, which finds the buffer full.
		refused: Frame,
		/// The digest of the lost ACK, the last frame of the hole.
		lost: DigestInfo,
		/// The storage root of the chains, which lives as long as the node.
		_root: StorageRoot,
	}

	impl FullBuffer {
		/// Opens a Rover chain and a node under a storage root of their own,
		/// and fills the order buffer of the node with the ACKs after the
		/// first.
		fn new() -> Self {
			let root = StorageRoot::create().expect("the storage root opens");
			let rover = NodeChain::open(&root, "rover").expect("the Rover chain opens");
			let node = NodeChain::open(&root, "node").expect("the node chain opens");

			rover.advance(1);

			let lost = rover.head();
			for _ in 0..ORDER_BUFFER_FRAMES {
				let held = node.take(&rover.rover_ack(), DtnRole::Rover, PathSide::Mars);
				held.expect("the buffer holds an ACK after the lost one");
			}

			let refused = rover.rover_ack();
			Self { node, refused, lost, _root: root }
		}

		/// Takes the ACK that finds the buffer full, as it arrives from the
		/// Rover.
		fn take_refused(&self) -> Result<ProcessResult, TightBeamError> {
			self.node.take(&self.refused, DtnRole::Rover, PathSide::Mars)
		}
	}

	/// A frame that finds the buffer full asks for the hole before the held
	/// frames, so a failed recovery asks again at the next arrival.
	#[test]
	fn a_frame_that_finds_the_buffer_full_asks_for_the_hole() -> TestResult {
		let full = FullBuffer::new();

		let taken = full.take_refused()?;
		let current_head = MessageChainState::EMPTY_HEAD.to_vec();
		let missing_hash = full.lost.digest.as_bytes().to_vec();
		assert_eq!(taken, ProcessResult::ChainGap { current_head, missing_hash });
		Ok(())
	}

	/// A frame that finds the buffer full stays out of the store, which
	/// answers the frame requests of other nodes.
	#[test]
	fn a_frame_that_finds_the_buffer_full_stays_out_of_the_store() -> TestResult {
		let full = FullBuffer::new();
		full.take_refused()?;
		assert!(!full.node.stores(&full.refused));
		Ok(())
	}

	/// A walk that never meets the head of the requester answers no frame,
	/// so a request gets no more than the hole that it names.
	#[test]
	fn a_walk_that_misses_the_head_of_the_requester_answers_nothing() -> TestResult {
		let root = StorageRoot::create()?;
		let holder = NodeChain::open(&root, "holder")?;
		holder.advance(2);

		let unknown = digest::<Sha3_256>(b"a head that the walk never meets")?;
		let requester_head = unknown.digest.as_bytes();
		let head = holder.head();
		let processor = &holder.processor;

		let answer = processor.request_missing_frames(requester_head, head.digest.as_bytes())?;
		assert!(answer.is_empty());
		Ok(())
	}

	// A repeat of a frame at a taken slot gets the answer of its first copy.
	tb_cases! {
		fn a_repeat_answers_as_its_first_copy((pick, answer): (Pick, ProcessResult)) -> TestResult {
			let branches = Branches::having_taken(&[pick]);
			let repeat = branches.take(branches.pick(pick))?;
			assert_eq!(repeat, answer);
			Ok(())
		}
		cases {
			/// A repeat of a released frame passes as a duplicate.
			released => (Pick::First, ProcessResult::Duplicate),
			/// A repeat of a held frame waits as its first copy does.
			held => (Pick::Second, ProcessResult::Buffered),
		}
	}

	// Another frame at an order that the node took is no duplicate, so the
	// buffer refuses it as a frame that exists, and the frame at the order
	// keeps its slot.
	tb_cases! {
		fn another_frame_at_a_taken_order_is_refused_as_existing(taken: &[Pick]) -> TestResult {
			let branches = Branches::having_taken(taken);
			let refusal = branches.take(&branches.fork);
			assert_eq!(refusal.err().and_then(transit_status_of), Some(TransitStatus::AlreadyExists));
			Ok(())
		}
		cases {
			/// The chain holds a frame at the order.
			released_order => &[Pick::First, Pick::Second],
			/// The buffer holds a frame at the order.
			held_order => &[Pick::Second],
		}
	}

	// A frame that forks the chain at its turn leaves the turn open, so the
	// frame of the chain at that order extends the chain.
	tb_cases! {
		fn the_frame_of_the_chain_takes_the_turn_that_a_fork_missed(arrivals: [Pick; 2]) -> TestResult {
			let branches = Branches::having_taken(&arrivals);
			let taken = branches.take(&branches.second)?;
			assert_eq!(taken, ProcessResult::Processed(vec![branches.arrival(&branches.second)]));
			Ok(())
		}
		cases {
			/// The fork arrives at its turn, after the first ACK.
			fork_at_its_turn => [Pick::First, Pick::Fork],
			/// The fork waits in the buffer, and leaves it at its turn.
			held_fork => [Pick::Fork, Pick::First],
		}
	}

	// A held fork leaves the store once the chain takes its turn, which the
	// first ACK opens as it arrives or as the node sends it.
	tb_cases! {
		fn a_fork_leaves_the_store_once_the_chain_takes_its_turn(first: Delivery) -> TestResult {
			let branches = Branches::having_taken(&[Pick::Fork]);
			first.deliver(&branches.node, &branches.first)?;
			assert!(!branches.node.stores(&branches.fork));
			Ok(())
		}
		cases {
			taken => Delivery::Taken,
			sent => Delivery::Sent,
		}
	}

	/// A held frame that a frame of the node passes leaves the store.
	#[test]
	fn a_held_frame_that_an_outgoing_frame_passes_leaves_the_store() -> TestResult {
		let root = StorageRoot::create()?;
		let node = NodeChain::open(&root, "node")?;
		let branch = NodeChain::open(&root, "branch")?;
		let origin = NodeChain::open(&root, "origin")?;
		let held = branch.stray_command();

		node.take(&held, DtnRole::MissionControl, PathSide::Earth)?;
		origin.advance(1);

		let passing = origin.rover_ack();

		node.processor.finalize_outgoing(&passing)?;

		assert!(!node.stores(&held));
		Ok(())
	}

	/// A held frame at the turn that a frame of the node opens takes it at
	/// once, and the chain releases it for the node to route.
	#[test]
	fn a_frame_at_the_turn_that_an_outgoing_frame_opens_is_released() -> TestResult {
		let branches = Branches::new();
		branches.take(&branches.second)?;
		branches.node.processor.finalize_outgoing(&branches.first)?;

		let released = branches.node.processor.take_released()?;
		assert_eq!(released, [branches.arrival(&branches.second)]);
		Ok(())
	}

	// A failed turn keeps the frames that the chain took for the next take,
	// and the failure names the fault of the store.
	tb_cases! {
		fn a_failed_turn_keeps_the_frames_that_the_chain_took((first, kept): (Delivery, Vec<u64>)) -> TestResult {
			let branches = Branches::having_taken(&[Pick::Second, Pick::ThirdFork]);
			branches.block_removal_of(&branches.third_fork);

			let failed = first.deliver(&branches.node, &branches.first);
			let released = branches.node.processor.take_released()?;
			assert!(matches!(failed, Err(TightBeamError::IoError(_))));
			assert_eq!(orders_of(&released), kept);
			Ok(())
		}
		cases {
			/// An arrival opens the turn, so the chain took the first ACK too.
			taken => (Delivery::Taken, vec![1, 2]),
			/// A send opens the turn, so the node routes the first ACK itself.
			sent => (Delivery::Sent, vec![2]),
		}
	}

	/// A refused frame of an answer keeps the frames before it, and the
	/// refusal names the order that the chain holds.
	#[test]
	fn a_refused_frame_of_an_answer_keeps_the_frames_before_it() -> TestResult {
		let branches = Branches::new();
		let other = NodeChain::open(&branches.root, "other")?;
		let other_first = other.rover_ack();
		branches.take(&branches.second)?;

		let first = branches.arrival(&branches.first);
		let refused = branches.arrival(&other_first);

		let failed = branches.node.processor.fill(vec![first, refused]);
		let kept = branches.node.processor.take_released()?;
		assert_eq!(failed.err().and_then(transit_status_of), Some(TransitStatus::AlreadyExists));
		assert_eq!(orders_of(&kept), [1, 2]);
		Ok(())
	}

	/// A chain at the last order refuses to prepare a next frame.
	#[test]
	fn a_chain_at_the_last_order_prepares_no_frame() -> TestResult {
		let root = StorageRoot::create()?;
		let store = Arc::new(RwLock::new(root.store("node")));
		let mut chain = MessageChainState::new("node");
		chain.sequence = u64::MAX;

		let chain = Arc::new(RwLock::new(chain));
		let buffer = Arc::new(RwLock::new(OutOfOrderBuffer::new(ORDER_BUFFER_FRAMES)));
		let processor = ChainProcessor::new(store, chain, buffer);

		let prepared = processor.prepare_outgoing();
		assert!(matches!(prepared, Err(TightBeamError::InvalidOrder)));
		Ok(())
	}
}
