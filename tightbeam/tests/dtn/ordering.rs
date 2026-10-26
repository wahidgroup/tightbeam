//! The frame ordering of a DTN node.
//!
//! [`OutOfOrderBuffer`] holds each frame that arrives out of sequence and
//! releases the held frames in order once the missing frames arrive.

use std::collections::HashMap;

use tightbeam::{asn1::Frame, testing::error::TestingError, TightBeamError};

/// The error of a frame whose order sits below the next expected order.
#[derive(Debug, Clone)]
pub struct InvalidSequenceError {
	pub message: String,
}

impl core::fmt::Display for InvalidSequenceError {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "Invalid sequence: {}", self.message)
	}
}

impl From<InvalidSequenceError> for TightBeamError {
	fn from(e: InvalidSequenceError) -> Self {
		TightBeamError::InjectedFault(Box::new(e))
	}
}

/// The error of an out-of-order frame that finds the buffer full.
#[derive(Debug, Clone)]
pub struct BufferFullError {
	pub message: String,
}

impl core::fmt::Display for BufferFullError {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "Buffer full: {}", self.message)
	}
}

impl From<BufferFullError> for TightBeamError {
	fn from(e: BufferFullError) -> Self {
		TightBeamError::InjectedFault(Box::new(e))
	}
}

/// The buffer that restores the order of frames that arrive out of sequence.
///
/// It holds each frame that arrives ahead of its turn and releases the held
/// frames in order once the gap before them fills. A DTN path needs it,
/// because network delays can deliver frames in another order.
pub struct OutOfOrderBuffer {
	/// The held frames, keyed by their order number.
	buffer: HashMap<u64, Frame>,
	/// The order number of the next frame that the buffer expects.
	next_expected: u64,
	/// The most frames that the buffer holds at once.
	max_buffer_size: usize,
}

impl OutOfOrderBuffer {
	/// Creates an empty buffer that expects order 1 first.
	///
	/// # Arguments
	/// - `max_buffer_size`: the most frames that the buffer holds before it refuses another.
	pub fn new(max_buffer_size: usize) -> Self {
		Self { buffer: HashMap::new(), next_expected: 1, max_buffer_size }
	}

	/// Inserts a frame, and returns the frames that it releases in order.
	///
	/// # Returns
	/// - `Ok(Some(frames))`: the frame completed a sequence, and `frames` holds it and the frames after it.
	/// - `Ok(None)`: the buffer holds the frame until the frames before it arrive.
	/// - `Err(_)`: [`BufferFullError`] for a full buffer, or [`InvalidSequenceError`] for a repeated order.
	pub fn insert(&mut self, frame: Frame) -> Result<Option<Vec<Frame>>, TightBeamError> {
		let order = frame.metadata().order();

		// An order below the next expected one repeats a released frame.
		if order < self.next_expected {
			return Err(InvalidSequenceError {
				message: format!("Frame order {} already processed (expected >= {})", order, self.next_expected),
			}
			.into());
		}

		// The expected frame releases at once, with the held frames behind it.
		if order == self.next_expected {
			self.next_expected += 1;
			let mut result = vec![frame];

			result.extend(self.drain_sequential());

			return Ok(Some(result));
		}

		// A frame ahead of its turn waits in the buffer while there is room.
		if self.buffer.len() >= self.max_buffer_size {
			return Err(BufferFullError {
				message: format!(
					"Out-of-order buffer full ({} frames), cannot buffer order {}",
					self.max_buffer_size, order
				),
			}
			.into());
		}

		self.buffer.insert(order, frame);
		Ok(None)
	}

	/// Removes and returns the held frames that run in sequence from the next
	/// expected order, and advances that order past them.
	fn drain_sequential(&mut self) -> Vec<Frame> {
		let mut result = Vec::new();
		while let Some(frame) = self.buffer.remove(&self.next_expected) {
			result.push(frame);
			self.next_expected += 1;
		}

		result
	}

	/// Returns the number of held frames.
	pub fn buffered_count(&self) -> usize {
		self.buffer.len()
	}

	/// Returns the order number of the next frame that the buffer expects.
	pub fn next_expected(&self) -> u64 {
		self.next_expected
	}

	/// Sets the order number of the next frame that the buffer expects, which
	/// aligns the buffer with the global chain state.
	pub fn set_next_expected(&mut self, order: u64) {
		self.next_expected = order;
	}

	/// Drops every held frame, for a scenario that resets between test phases.
	#[allow(dead_code)]
	pub fn clear(&mut self) {
		self.buffer.clear();
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::dtn::storage::DtnPayload;
	use tightbeam::compose;

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
		let Some(result1) = result1 else {
			return Err(TightBeamError::TestingError(TestingError::InvariantViolated));
		};
		assert_eq!(result1.len(), 1);

		let result2 = buffer.insert(frame2)?;
		let Some(result2) = result2 else {
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
		let Some(result1) = result1 else {
			return Err(TightBeamError::TestingError(TestingError::InvariantViolated));
		};
		assert_eq!(result1.len(), 1);
		assert_eq!(buffer.next_expected(), 2);

		// Frame 3 arrives ahead of frame 2, so the buffer holds it.
		let result3 = buffer.insert(frame3)?;
		assert!(result3.is_none());
		assert_eq!(buffer.buffered_count(), 1);
		assert_eq!(buffer.next_expected(), 2);

		// Frame 2 fills the gap, so frames 2 and 3 release together.
		let result2 = buffer.insert(frame2)?;
		let Some(frames) = result2 else {
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
}
