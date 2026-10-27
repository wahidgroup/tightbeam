//! The frame ordering of a DTN node.
//!
//! [`OutOfOrderBuffer`] holds each frame that arrives out of sequence. Once the
//! missing frames arrive, it releases in order each held frame that the chain
//! takes at its turn. [`RequestGate`] admits the frame requests of each peer in
//! their order.

use core::borrow::Borrow;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use tightbeam::asn1::{DigestInfo, Frame};
use tightbeam::policy::TransitStatus;
use tightbeam::testing::error::TestingError;
use tightbeam::transport::TransportError;
use tightbeam::TightBeamError;

use crate::dtn::nodes::DtnRole;

/// The refusal of a frame by its order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderingError {
	/// The frame repeats an order that the buffer released, so the chain holds
	/// a frame of that order already.
	Repeated {
		/// The order of the frame.
		order: u64,
		/// The order of the next frame that the buffer expects.
		next_expected: u64,
	},
	/// The frame arrives ahead of its turn at the order of a frame that the
	/// buffer holds, which keeps its slot.
	Held {
		/// The order of the frame.
		order: u64,
	},
	/// The frame arrives ahead of its turn and finds the buffer full.
	Full {
		/// The order of the frame.
		order: u64,
		/// The most frames that the buffer holds at once.
		capacity: usize,
		/// The last frame of the hole before the held frames: the frame before
		/// the lowest held frame, when that frame names one.
		hole_end: Option<DigestInfo>,
	},
	/// The frame request does not pass the last request that the gate admitted
	/// from its peer, so it repeats or precedes that request.
	Replayed {
		/// The order of the frame request.
		order: u64,
		/// The order of the last request that the gate admitted from the peer.
		admitted: u64,
	},
}

impl OrderingError {
	/// The transit status that refuses the frame. A repeated order, a held
	/// order, and a replayed request take [`TransitStatus::AlreadyExists`],
	/// and a full buffer takes [`TransitStatus::ResourceExhausted`], which a
	/// later retry can pass.
	pub fn status(&self) -> TransitStatus {
		match self {
			Self::Repeated { .. } | Self::Held { .. } | Self::Replayed { .. } => TransitStatus::AlreadyExists,
			Self::Full { .. } => TransitStatus::ResourceExhausted,
		}
	}

	/// The slot that the refused frame finds taken, when the refusal names one.
	pub fn occupied_slot(&self) -> Option<Slot> {
		match self {
			Self::Repeated { .. } => Some(Slot::Released),
			Self::Held { .. } => Some(Slot::Held),
			Self::Full { .. } | Self::Replayed { .. } => None,
		}
	}

	/// The last frame of the hole before the held frames, when the refusal
	/// names one.
	pub fn hole_end(&self) -> Option<&DigestInfo> {
		match self {
			Self::Full { hole_end, .. } => hole_end.as_ref(),
			Self::Repeated { .. } | Self::Held { .. } | Self::Replayed { .. } => None,
		}
	}
}

/// The slot that a refused frame finds taken at its order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
	/// The buffer released a frame at the order, so the chain holds it.
	Released,
	/// The buffer holds a frame at the order until its turn.
	Held,
}

/// A failure that stops an insert or a run of turns, with the frames taken
/// before it.
#[derive(Debug)]
pub struct Stopped<T, E> {
	/// The frames that the chain took before the failure, in order.
	pub taken: Vec<T>,
	/// The failure.
	pub cause: E,
}

impl<T, E: From<OrderingError>> From<OrderingError> for Stopped<T, E> {
	fn from(refusal: OrderingError) -> Self {
		Self { taken: Vec::new(), cause: E::from(refusal) }
	}
}

impl core::fmt::Display for OrderingError {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		match self {
			Self::Repeated { order, next_expected } => {
				write!(
					f,
					"frame order {order} repeats a released order, and the buffer expects {next_expected}"
				)
			}
			Self::Held { order } => write!(f, "frame order {order} repeats the order of a held frame"),
			Self::Full { order, capacity, .. } => {
				write!(f, "frame order {order} finds the buffer of {capacity} frames full")
			}
			Self::Replayed { order, admitted } => {
				write!(
					f,
					"frame request order {order} does not pass the admitted request order {admitted}"
				)
			}
		}
	}
}

impl core::error::Error for OrderingError {}

impl From<OrderingError> for TightBeamError {
	fn from(error: OrderingError) -> Self {
		TightBeamError::TransportError(TransportError::from(error.status()))
	}
}

/// What the buffer does with a frame that it takes.
#[derive(Debug)]
pub enum Admission<T> {
	/// The frame took its turn: the frame and the held frames after it that
	/// the chain took, in order.
	Released(Vec<T>),
	/// The buffer holds the frame until the frames before it arrive.
	Held,
	/// The frame took the last slot of the buffer, which ends the wait for the
	/// frames of the hole in flight. The digest names the last frame of the
	/// hole: the frame before the lowest held frame.
	Stalled(DigestInfo),
}

/// The buffer that restores the order of frames that arrive out of sequence.
///
/// It holds each frame that arrives ahead of its turn, as a `T` that borrows as
/// a [`Frame`], and releases the held frames in order once the gap before them
/// fills. A DTN path needs it, because network delays can reorder frames.
pub struct OutOfOrderBuffer<T> {
	/// The held frames, keyed by their order number.
	buffer: BTreeMap<u64, T>,
	/// The order number of the next frame that the buffer expects.
	next_expected: u64,
	/// The most frames that the buffer holds at once.
	max_buffer_size: usize,
}

impl<T: Borrow<Frame>> OutOfOrderBuffer<T> {
	/// Creates an empty buffer that expects order 1 first.
	///
	/// # Arguments
	/// - `max_buffer_size`: the most frames that the buffer holds before it refuses another.
	pub fn new(max_buffer_size: usize) -> Self {
		Self { buffer: BTreeMap::new(), next_expected: 1, max_buffer_size }
	}

	/// Inserts a frame, as [`OutOfOrderBuffer::insert_into`] does with a chain
	/// that takes every frame.
	///
	/// # Errors
	///
	/// - The refusals of [`OutOfOrderBuffer::admits`].
	pub fn insert(&mut self, entry: T) -> Result<Admission<T>, OrderingError> {
		// This chain takes every frame, so only an order refusal stops it.
		let admission = self.insert_into(entry, |_| Ok::<bool, OrderingError>(true));
		admission.map_err(|stopped| stopped.cause)
	}

	/// Inserts a frame, and releases each frame at its turn that `chain` takes.
	///
	/// A frame that `chain` refuses leaves the buffer. The next frame of its
	/// order takes the turn.
	///
	/// # Errors
	///
	/// - [`Stopped`] -- [`OutOfOrderBuffer::admits`] refuses the order, and `taken` is empty.
	/// - [`Stopped`] -- `chain` fails at a turn. That frame stays, and `taken` holds the frames before it.
	pub fn insert_into<E: From<OrderingError>>(
		&mut self,
		entry: T,
		chain: impl FnMut(&T) -> Result<bool, E>,
	) -> Result<Admission<T>, Stopped<T, E>> {
		let order = entry.borrow().metadata().order();
		self.admits(order)?;
		self.buffer.insert(order, entry);

		// A frame ahead of its turn waits for the frames before it.
		if order != self.next_expected {
			return Ok(self.held());
		}

		let released = self.release_turn(chain)?;
		Ok(Admission::Released(released))
	}

	/// Decides whether the buffer takes a frame of `order`, and leaves the
	/// buffer as it was.
	///
	/// # Errors
	///
	/// - [`OrderingError::Repeated`] -- `order` repeats a released order.
	/// - [`OrderingError::Held`] -- `order` is ahead of its turn, and the buffer holds a frame of that order.
	/// - [`OrderingError::Full`] -- `order` is ahead of its turn and the
	///   buffer is full. The refusal names the last frame of the hole.
	pub fn admits(&self, order: u64) -> Result<(), OrderingError> {
		// An order below the next expected one repeats a released frame.
		if order < self.next_expected {
			return Err(OrderingError::Repeated { order, next_expected: self.next_expected });
		}

		// A held frame keeps its slot against a later frame of its order.
		if order > self.next_expected && self.buffer.contains_key(&order) {
			return Err(OrderingError::Held { order });
		}

		// A frame ahead of its turn waits in the buffer while there is room.
		if order > self.next_expected && self.is_full() {
			let hole_end = self.hole_end();
			return Err(OrderingError::Full { order, capacity: self.max_buffer_size, hole_end });
		}

		Ok(())
	}

	/// Whether the buffer holds as many frames as it can.
	fn is_full(&self) -> bool {
		self.buffer.len() >= self.max_buffer_size
	}

	/// The last frame of the hole before the held frames, which the lowest
	/// held frame names through its `previous_frame` digest.
	fn hole_end(&self) -> Option<DigestInfo> {
		let (_, lowest) = self.buffer.first_key_value()?;
		lowest.borrow().metadata().previous_frame().cloned()
	}

	/// The admission of a frame that the buffer holds. A frame in the last
	/// slot stalls the buffer on the hole before its lowest held frame.
	fn held(&self) -> Admission<T> {
		if !self.is_full() {
			return Admission::Held;
		}

		self.hole_end().map_or(Admission::Held, Admission::Stalled)
	}

	/// Removes the frames that run in sequence from the next expected order,
	/// and returns the frames that `chain` takes. The first frame that `chain`
	/// refuses leaves the buffer and ends the run.
	///
	/// # Errors
	///
	/// - [`Stopped`] -- `chain` fails at a turn. That frame stays, and `taken` holds the frames before it.
	pub fn release_turn<E>(&mut self, mut chain: impl FnMut(&T) -> Result<bool, E>) -> Result<Vec<T>, Stopped<T, E>> {
		let mut released = Vec::new();
		while let Entry::Occupied(turn) = self.buffer.entry(self.next_expected) {
			let taken = match chain(turn.get()) {
				Ok(taken) => taken,
				Err(cause) => return Err(Stopped { taken: released, cause }),
			};
			let frame = turn.remove();
			if !taken {
				break;
			}

			released.push(frame);
			// The turn saturates at the last order, which the chain closes.
			self.next_expected = self.next_expected.saturating_add(1);
		}

		Ok(released)
	}

	/// Returns the number of held frames.
	pub fn buffered_count(&self) -> usize {
		self.buffer.len()
	}

	/// Returns the order number of the next frame that the buffer expects.
	pub fn next_expected(&self) -> u64 {
		self.next_expected
	}

	/// Moves the next expected order past `order`, the order of a frame that
	/// the node sends, which aligns the buffer with the chain.
	///
	/// A held frame at a passed order can take no turn, because the chain holds
	/// the node's frame there. The buffer offers each one to `leave`, then
	/// drops it.
	///
	/// # Errors
	///
	/// - `E` -- `leave` fails on a passed frame. That frame and the passed
	///   frames after it stay in the buffer.
	pub fn move_past<E>(&mut self, order: u64, mut leave: impl FnMut(&T) -> Result<(), E>) -> Result<(), E> {
		if order < self.next_expected {
			return Ok(());
		}

		// The turn saturates at the last order, which the chain closes.
		self.next_expected = order.saturating_add(1);
		while let Some(passed) = self.buffer.first_entry() {
			if *passed.key() >= self.next_expected {
				break;
			}

			leave(passed.get())?;
			passed.remove();
		}

		Ok(())
	}

	/// Drops every held frame, for a scenario that resets between test phases.
	#[allow(dead_code)]
	pub fn clear(&mut self) {
		self.buffer.clear();
	}
}

/// The order and replay gate of the frame requests that a node answers.
///
/// Each node numbers its frame requests from 1. The gate admits a peer's
/// request only when its order passes the last one it admitted from that peer,
/// so a replayed or stale request fails before the node answers it.
#[derive(Default)]
pub struct RequestGate {
	/// The order of the last request that the gate admitted from each peer.
	admitted: Mutex<HashMap<DtnRole, u64>>,
}

impl RequestGate {
	/// Admits the frame request of `peer` at `order`.
	///
	/// # Errors
	///
	/// - [`TightBeamError::TransportError`] -- `order` does not pass the last
	///   request that the gate admitted from `peer`, with the transit status
	///   of [`OrderingError::Replayed`].
	/// - [`TightBeamError::LockPoisoned`] -- the lock of the gate is poisoned.
	pub fn admit(&self, peer: DtnRole, order: u64) -> Result<(), TightBeamError> {
		let mut admitted = self.admitted.lock().map_err(|_| TightBeamError::LockPoisoned)?;
		let last = admitted.entry(peer).or_default();
		if order <= *last {
			return Err(OrderingError::Replayed { order, admitted: *last }.into());
		}

		*last = order;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::dtn::storage::DtnPayload;
	use tightbeam::compose;
	use tightbeam::crypto::hash::Sha3_256;
	use tightbeam::utils::digest;

	#[test]
	fn in_order_frames() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::new(10);
		let frame1 = compose! {
			V0: id: "frame-1",
				order: 1,
				message: DtnPayload::new(b"first", "test", "test", 0)?
		}?;
		let frame2 = compose! {
			V0: id: "frame-2",
				order: 2,
				message: DtnPayload::new(b"second", "test", "test", 0)?
		}?;

		// Each frame in order releases at once.
		let result1 = buffer.insert(frame1)?;
		let Admission::Released(result1) = result1 else {
			return Err(TightBeamError::TestingError(TestingError::InvariantViolated));
		};
		assert_eq!(result1.len(), 1);

		let result2 = buffer.insert(frame2)?;
		let Admission::Released(result2) = result2 else {
			return Err(TightBeamError::TestingError(TestingError::InvariantViolated));
		};
		assert_eq!(result2.len(), 1);

		assert_eq!(buffer.next_expected(), 3);
		assert_eq!(buffer.buffered_count(), 0);

		Ok(())
	}

	#[test]
	fn out_of_order_reordering() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::new(10);

		let frame1 = compose! {
			V0: id: "frame-1",
				order: 1,
				message: DtnPayload::new(b"first", "test", "test", 0)?
		}?;

		let frame3 = compose! {
			V0: id: "frame-3",
				order: 3,
				message: DtnPayload::new(b"third", "test", "test", 0)?
		}?;

		let frame2 = compose! {
			V0: id: "frame-2",
			order: 2,
			message: DtnPayload::new(b"second", "test", "test", 0)?
		}?;

		// Frame 1 is next, so it releases at once.
		let result1 = buffer.insert(frame1)?;
		let Admission::Released(result1) = result1 else {
			return Err(TightBeamError::TestingError(TestingError::InvariantViolated));
		};
		assert_eq!(result1.len(), 1);
		assert_eq!(buffer.next_expected(), 2);

		// Frame 3 arrives ahead of frame 2, so the buffer holds it.
		let result3 = buffer.insert(frame3)?;
		assert!(matches!(result3, Admission::Held));
		assert_eq!(buffer.buffered_count(), 1);
		assert_eq!(buffer.next_expected(), 2);

		// Frame 2 fills the gap, so frames 2 and 3 release together.
		let result2 = buffer.insert(frame2)?;
		let Admission::Released(frames) = result2 else {
			return Err(TightBeamError::TestingError(TestingError::InvariantViolated));
		};
		assert_eq!(frames.len(), 2);
		assert_eq!(frames[0].metadata().order(), 2);
		assert_eq!(frames[1].metadata().order(), 3);
		assert_eq!(buffer.next_expected(), 4);
		assert_eq!(buffer.buffered_count(), 0);

		Ok(())
	}

	#[test]
	fn buffer_full() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::new(2);
		let payload = |content: &[u8]| DtnPayload::new(content, "test", "test", 0);

		let frame1 = compose! {
			V0: id: "frame-1",
				order: 1,
				message: payload(b"first")?
		}?;
		buffer.insert(frame1)?;

		// Frames 3 and 4 wait for frame 2 and fill the buffer of two.
		let frame3 = compose! {
			V0: id: "frame-3",
			order: 3,
			message: payload(b"third")?
		}?;
		buffer.insert(frame3)?;

		let frame4 = compose! {
			V0: id: "frame-4",
				order: 4,
				message: payload(b"fourth")?
		}?;
		buffer.insert(frame4)?;

		// Frame 5 finds the buffer full, so its insert fails.
		let frame5 = compose! {
			V0: id: "frame-5",
				order: 5,
				message: payload(b"fifth")?
		}?;

		let result = buffer.insert(frame5);
		assert!(result.is_err());

		Ok(())
	}

	#[test]
	fn duplicate_frame_rejection() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::new(10);
		let payload = |content: &[u8]| DtnPayload::new(content, "test", "test", 0);
		let frame1 = compose! {
			V0: id: "frame-1",
			order: 1,
			message: payload(b"first")?
		}?;

		buffer.insert(frame1)?;

		// A second frame of order 1 repeats a released order, so it fails.
		let frame1_dup = compose! {
			V0: id: "frame-1-dup",
			order: 1,
			message: payload(b"duplicate")?
		}?;

		let result = buffer.insert(frame1_dup);
		assert!(result.is_err());

		Ok(())
	}

	/// A frame at `order` under `id` that carries a test payload and leaves
	/// `previous_frame` empty.
	fn frame_named(id: impl AsRef<str>, order: u64) -> Frame {
		let id = id.as_ref();
		let payload = DtnPayload::new(id, "test", "test", 0).expect("a short payload fits");
		let frame = compose! {
			V0: id: id,
				order: order,
				message: payload
		};

		frame.expect("a V0 frame with an order composes")
	}

	/// A frame at `order` that carries a test payload and leaves
	/// `previous_frame` empty.
	fn frame_at(order: u64) -> Frame {
		let payload = DtnPayload::new(b"payload", "test", "test", 0).expect("a short payload fits");
		let frame = compose! {
			V0: id: format!("frame-{order}"),
				order: order,
				message: payload
		};

		frame.expect("a V0 frame with an order composes")
	}

	/// A frame at `order` that carries a test payload after the frame that
	/// `previous` names.
	fn frame_after(order: u64, previous: DigestInfo) -> Frame {
		let payload = DtnPayload::new(b"payload", "test", "test", 0).expect("a short payload fits");
		let frame = compose! {
			V2: id: format!("frame-{order}"),
				order: order,
				previous_frame: previous,
				message: payload
		};

		frame.expect("a V2 frame with a previous frame composes")
	}

	/// The ids of the frames that `admission` releases, in order.
	fn released_ids(admission: &Admission<Frame>) -> Vec<&[u8]> {
		let Admission::Released(frames) = admission else {
			return Vec::new();
		};

		frames.iter().map(|frame| frame.metadata().id()).collect()
	}

	/// The orders of `frames`, in order.
	fn orders_of(frames: &[Frame]) -> Vec<u64> {
		frames.iter().map(|frame| frame.metadata().order()).collect()
	}

	/// A chain that takes each frame, and fails at the frame of `order`.
	fn fails_at(order: u64) -> impl FnMut(&Frame) -> Result<bool, TightBeamError> {
		move |frame| {
			if frame.metadata().order() == order {
				return Err(TightBeamError::InvalidOrder);
			}

			Ok(true)
		}
	}

	/// The transit status that `error` refuses a frame with, if it carries one.
	fn transit_status(error: TightBeamError) -> Option<TransitStatus> {
		let TightBeamError::TransportError(error) = error else {
			return None;
		};

		error.transit_status()
	}

	/// A frame that repeats a released order is refused as a frame that the
	/// chain holds already.
	#[test]
	fn a_repeated_order_is_refused_as_already_held() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::new(10);
		buffer.insert(frame_at(1))?;

		let refusal = buffer.insert(frame_at(1)).map_err(TightBeamError::from);
		assert_eq!(refusal.err().and_then(transit_status), Some(TransitStatus::AlreadyExists));
		Ok(())
	}

	/// A frame ahead of its turn that finds the buffer full is refused for lack
	/// of capacity.
	#[test]
	fn a_frame_past_a_full_buffer_is_refused_as_exhausted() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::new(1);
		buffer.insert(frame_at(2))?;

		let refusal = buffer.insert(frame_at(3)).map_err(TightBeamError::from);
		assert_eq!(refusal.err().and_then(transit_status), Some(TransitStatus::ResourceExhausted));
		Ok(())
	}

	/// A frame that takes the last slot stalls the buffer, and the stall names
	/// the frame before the lowest held frame, the last frame of the hole.
	#[test]
	fn a_frame_in_the_last_slot_names_the_end_of_the_hole() -> Result<(), TightBeamError> {
		let hole_end = digest::<Sha3_256>(b"the last frame of the hole")?;
		let held_end = digest::<Sha3_256>(b"the frame before the arriving frame")?;
		let mut buffer = OutOfOrderBuffer::new(2);
		buffer.insert(frame_after(3, hole_end.to_owned()))?;

		let admission = buffer.insert(frame_after(4, held_end))?;
		assert!(matches!(admission, Admission::Stalled(digest) if digest == hole_end));
		Ok(())
	}

	/// A frame past a full buffer names the last frame of the hole.
	#[test]
	fn a_frame_past_a_full_buffer_names_the_end_of_the_hole() -> Result<(), TightBeamError> {
		let hole_end = digest::<Sha3_256>(b"the last frame of the hole")?;
		let held_end = digest::<Sha3_256>(b"the frame before the arriving frame")?;
		let mut buffer = OutOfOrderBuffer::new(1);
		buffer.insert(frame_after(3, hole_end.to_owned()))?;

		let refusal = buffer.insert(frame_after(4, held_end)).err();
		assert_eq!(refusal.as_ref().and_then(OrderingError::hole_end), Some(&hole_end));
		Ok(())
	}

	/// A frame request that repeats the order of a request that the gate
	/// admitted is refused as one that the gate holds already.
	#[test]
	fn a_replayed_request_is_refused_as_already_admitted() -> Result<(), TightBeamError> {
		let gate = RequestGate::default();
		gate.admit(DtnRole::MarsRelay, 1)?;

		let refusal = gate.admit(DtnRole::MarsRelay, 1);
		assert_eq!(refusal.err().and_then(transit_status), Some(TransitStatus::AlreadyExists));
		Ok(())
	}

	/// A later frame at a held order leaves the held frame in its slot.
	#[test]
	fn a_later_frame_leaves_the_held_frame_in_its_slot() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::new(10);
		buffer.insert(frame_named("first", 2))?;

		let refusal = buffer.insert(frame_named("later", 2));
		let released = buffer.insert(frame_at(1))?;
		assert!(matches!(refusal, Err(OrderingError::Held { order: 2 })));
		assert_eq!(released_ids(&released), [b"frame-1".as_slice(), b"first"]);
		Ok(())
	}

	/// A frame at a held order finds a held slot.
	#[test]
	fn a_frame_at_a_held_order_finds_a_held_slot() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::new(10);
		buffer.insert(frame_at(2))?;

		let refusal = buffer.admits(2).err();
		assert_eq!(refusal.as_ref().and_then(OrderingError::occupied_slot), Some(Slot::Held));
		Ok(())
	}

	/// A chain that fails at a turn gets back the frames that it took before.
	#[test]
	fn a_failed_turn_returns_the_frames_that_the_chain_took() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::new(10);
		buffer.insert(frame_at(2))?;
		buffer.insert(frame_at(3))?;

		let stopped = buffer.insert_into(frame_at(1), fails_at(3));
		let taken = stopped.err().map(|stopped| orders_of(&stopped.taken));
		assert_eq!(taken, Some(vec![1, 2]));
		Ok(())
	}

	/// A move past the last order leaves the buffer at that order.
	#[test]
	fn a_move_past_the_last_order_leaves_the_buffer_there() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::<Frame>::new(10);
		buffer.move_past(u64::MAX, |_| Ok::<(), TightBeamError>(()))?;
		assert_eq!(buffer.next_expected(), u64::MAX);
		Ok(())
	}

	/// A release of the last order leaves the buffer at that order.
	#[test]
	fn a_release_of_the_last_order_leaves_the_buffer_there() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::new(10);
		buffer.move_past(u64::MAX - 1, |_| Ok::<(), TightBeamError>(()))?;
		buffer.insert(frame_at(u64::MAX))?;
		assert_eq!(buffer.next_expected(), u64::MAX);
		Ok(())
	}

	/// A held frame at an order that the buffer moves past leaves the buffer,
	/// because the chain holds the frame of the node there.
	#[test]
	fn a_held_frame_that_the_buffer_moves_past_leaves_it() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::new(10);
		buffer.insert(frame_at(3))?;
		buffer.move_past(3, |_| Ok::<(), TightBeamError>(()))?;
		assert_eq!(buffer.buffered_count(), 0);
		Ok(())
	}
}
