//! Frame ordering and out-of-order buffer management for DTN
//!
//! Handles automatic reordering of frames that arrive out of sequence,
//! buffering them until missing frames arrive to maintain proper order.

use std::collections::HashMap;

use tightbeam::{asn1::Frame, TightBeamError};

use crate::dtn::types::{BufferFullError, InvalidSequenceError};

/// Buffer for handling out-of-order frame delivery
///
/// Maintains frames that arrive out of sequence and releases them
/// in order once gaps are filled. This is critical for DTN where
/// network delays can cause frames to arrive in different orders.
pub struct OutOfOrderBuffer {
	/// Buffered frames indexed by their order number
	buffer: HashMap<u64, Frame>,
	/// Next expected frame order number
	next_expected: u64,
	/// Maximum number of frames to buffer
	max_buffer_size: usize,
}

impl OutOfOrderBuffer {
	/// Create a new out-of-order buffer
	///
	/// # Arguments
	/// * `max_buffer_size` - Maximum frames to buffer before rejecting new ones
	pub fn new(max_buffer_size: usize) -> Self {
		Self { buffer: HashMap::new(), next_expected: 1, max_buffer_size }
	}

	/// Insert a frame and potentially get back ordered frames to process
	///
	/// # Returns
	/// - `Ok(Some(frames))` - Frame completed a sequence, process these frames in order
	/// - `Ok(None)` - Frame was buffered, waiting for missing frames
	/// - `Err(_)` - Buffer full or invalid sequence
	pub fn insert(&mut self, frame: Frame) -> Result<Option<Vec<Frame>>, TightBeamError> {
		let order = frame.metadata.order;

		// Check if this is a duplicate
		if order < self.next_expected {
			return Err(InvalidSequenceError {
				message: format!("Frame order {} already processed (expected >= {})", order, self.next_expected),
			}
			.into());
		}

		// If this is the next expected frame, process immediately
		if order == self.next_expected {
			self.next_expected += 1;
			let mut result = vec![frame];

			// Drain any sequential frames from buffer
			result.extend(self.drain_sequential());

			return Ok(Some(result));
		}

		// Frame is out of order, buffer it
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

	/// Drain all sequential frames starting from next_expected
	fn drain_sequential(&mut self) -> Vec<Frame> {
		let mut result = Vec::new();

		while let Some(frame) = self.buffer.remove(&self.next_expected) {
			result.push(frame);
			self.next_expected += 1;
		}

		result
	}

	/// Get the number of buffered frames
	pub fn buffered_count(&self) -> usize {
		self.buffer.len()
	}

	/// Get the next expected order number
	pub fn next_expected(&self) -> u64 {
		self.next_expected
	}

	/// Set the next expected order number
	/// This is used to synchronize the buffer with the global chain state
	pub fn set_next_expected(&mut self, order: u64) {
		self.next_expected = order;
	}

	/// Clear all buffered frames (for testing/reset)
	pub fn clear(&mut self) {
		self.buffer.clear();
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::dtn::types::DtnPayload;
	use tightbeam::compose;

	#[test]
	fn in_order_frames() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::new(10);

		// Create frames in order
		let frame1 = compose! {
			V0: id: "frame-1",
				order: 1,
				message: DtnPayload {
					content: b"first".to_vec(),
					source_node: "test".to_string(),
					dest_node: "test".to_string(),
					hop_count: 0,
				}
		}?;

		let frame2 = compose! {
			V0: id: "frame-2",
				order: 2,
				message: DtnPayload {
					content: b"second".to_vec(),
					source_node: "test".to_string(),
					dest_node: "test".to_string(),
					hop_count: 0,
				}
		}?;

		// Process in order
		let result1 = buffer.insert(frame1)?;
		assert!(result1.is_some());
		assert_eq!(result1.unwrap().len(), 1);

		let result2 = buffer.insert(frame2)?;
		assert!(result2.is_some());
		assert_eq!(result2.unwrap().len(), 1);

		assert_eq!(buffer.next_expected(), 3);
		assert_eq!(buffer.buffered_count(), 0);

		Ok(())
	}

	#[test]
	fn out_of_order_reordering() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::new(10);

		// Create frames
		let frame1 = compose! {
			V0: id: "frame-1",
				order: 1,
				message: DtnPayload {
					content: b"first".to_vec(),
					source_node: "test".to_string(),
					dest_node: "test".to_string(),
					hop_count: 0,
				}
		}?;

		let frame3 = compose! {
			V0: id: "frame-3",
				order: 3,
				message: DtnPayload {
					content: b"third".to_vec(),
					source_node: "test".to_string(),
					dest_node: "test".to_string(),
					hop_count: 0,
				}
		}?;

		let frame2 = compose! {
			V0: id: "frame-2",
			order: 2,
			message: DtnPayload {
				content: b"second".to_vec(),
				source_node: "test".to_string(),
				dest_node: "test".to_string(),
				hop_count: 0,
			}
		}?;

		// Insert frame 1 (in order)
		let result1 = buffer.insert(frame1)?;
		assert!(result1.is_some());
		assert_eq!(result1.unwrap().len(), 1);
		assert_eq!(buffer.next_expected(), 2);

		// Insert frame 3 (out of order, should buffer)
		let result3 = buffer.insert(frame3)?;
		assert!(result3.is_none());
		assert_eq!(buffer.buffered_count(), 1);
		assert_eq!(buffer.next_expected(), 2);

		// Insert frame 2 (fills gap, should return both 2 and 3)
		let result2 = buffer.insert(frame2)?;
		assert!(result2.is_some());
		let frames = result2.unwrap();
		assert_eq!(frames.len(), 2);
		assert_eq!(frames[0].metadata.order, 2);
		assert_eq!(frames[1].metadata.order, 3);
		assert_eq!(buffer.next_expected(), 4);
		assert_eq!(buffer.buffered_count(), 0);

		Ok(())
	}

	#[test]
	fn buffer_full() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::new(2);

		let payload = |content: &[u8]| DtnPayload {
			content: content.to_vec(),
			source_node: "test".to_string(),
			dest_node: "test".to_string(),
			hop_count: 0,
		};

		// Insert frame 1
		let frame1 = compose! {
			V0: id: "frame-1",
				order: 1,
				message: payload(b"first")
		}?;
		buffer.insert(frame1)?;

		// Buffer frames 3 and 4 (fills buffer)
		let frame3 = compose! {
			V0: id: "frame-3",
			order: 3,
			message: payload(b"third")
		}?;
		buffer.insert(frame3)?;

		let frame4 = compose! {
			V0: id: "frame-4",
				order: 4,
				message: payload(b"fourth")
		}?;
		buffer.insert(frame4)?;

		// Try to buffer frame 5 (should fail)
		let frame5 = compose! {
			V0: id: "frame-5",
				order: 5,
				message: payload(b"fifth")
		}?;
		let result = buffer.insert(frame5);
		assert!(result.is_err());

		Ok(())
	}

	#[test]
	fn duplicate_frame_rejection() -> Result<(), TightBeamError> {
		let mut buffer = OutOfOrderBuffer::new(10);

		let payload = |content: &[u8]| DtnPayload {
			content: content.to_vec(),
			source_node: "test".to_string(),
			dest_node: "test".to_string(),
			hop_count: 0,
		};

		let frame1 = compose! {
			V0: id: "frame-1",
			order: 1,
			message: payload(b"first")
		}?;
		buffer.insert(frame1)?;

		// Try to insert order 1 again
		let frame1_dup = compose! {
			V0: id: "frame-1-dup",
			order: 1,
			message: payload(b"duplicate")
		}?;
		let result = buffer.insert(frame1_dup);
		assert!(result.is_err());

		Ok(())
	}
}
