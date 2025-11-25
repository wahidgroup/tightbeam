//! Chain processing utilities for DTN message chain validation
//!
//! Encapsulates the logic for processing frames through the chain:
//! - Persistence to storage
//! - Ordering buffer management
//! - Cryptographic chain validation
//! - Chain state updates
//! - Missing message detection

use std::sync::{Arc, RwLock};

use tightbeam::asn1::{AlgorithmIdentifier, Frame, OctetString};
use tightbeam::crypto::hash::{Digest, Sha3_256};
use tightbeam::der::{oid::AssociatedOid, Encode};
use tightbeam::pkcs12::digest_info::DigestInfo;
use tightbeam::TightBeamError;

use crate::dtn::messages::MessageChainState;
use crate::dtn::ordering::OutOfOrderBuffer;
use crate::dtn::storage::FrameStore;

/// Result of processing a frame
#[derive(Debug)]
pub enum ProcessResult {
	/// Frame was processed, returns ordered frames ready for application logic
	Processed(Vec<Frame>),
	/// Frame was buffered, waiting for missing frames
	Buffered,
	/// Chain gap detected, need to request missing frames
	ChainGap { current_head: Vec<u8>, missing_hash: Vec<u8> },
}

/// Encapsulates chain validation, ordering, and storage
pub struct ChainProcessor {
	store: Arc<RwLock<FrameStore>>,
	chain_state: Arc<RwLock<MessageChainState>>,
	order_buffer: Arc<RwLock<OutOfOrderBuffer>>,
	node_name: String,
}

impl ChainProcessor {
	pub fn new(
		store: Arc<RwLock<FrameStore>>,
		chain_state: Arc<RwLock<MessageChainState>>,
		order_buffer: Arc<RwLock<OutOfOrderBuffer>>,
		node_name: String,
	) -> Self {
		Self { store, chain_state, order_buffer, node_name }
	}

	/// Process incoming frame: persist, order, validate chain
	pub fn process_incoming(&self, frame: Frame) -> Result<ProcessResult, TightBeamError> {
		println!(
			"[{}] >>> process_incoming called (order: {}, id: {:?})",
			self.node_name,
			frame.metadata.order,
			String::from_utf8_lossy(&frame.metadata.id)
		);

		// 1. Persist frame
		println!("[{}] Acquiring write lock on store...", self.node_name);
		let mut store_guard = self.store.write()?;
		println!("[{}] Write lock acquired, persisting frame...", self.node_name);
		store_guard.persist(&frame)?;
		drop(store_guard);
		println!("[{}] ✓ Frame persisted (order: {})", self.node_name, frame.metadata.order);

		// 2. Insert into ordering buffer
		println!("[{}] Inserting into order buffer...", self.node_name);
		let frames_to_process = self.order_buffer.write()?.insert(frame)?;
		println!("[{}] Order buffer insert complete", self.node_name);
		if let Some(frames) = frames_to_process {
			println!("[{}] Frames to process: {} frames", self.node_name, frames.len());
			// 3. Verify batch integrity before committing to chain state
			println!("[{}] Verifying chain batch...", self.node_name);
			let verdict = self.store.read()?.verify_chain(&frames)?;
			println!("[{}] Chain verification complete, valid: {}", self.node_name, verdict.valid);
			if !verdict.valid {
				// Batch verification failed - return chain gap
				let current_head = self.chain_state.read()?.last_hash.to_vec();
				let missing_hash = frames
					.first()
					.and_then(|f| f.metadata.previous_frame.as_ref())
					.map(|d| d.digest.as_bytes().to_vec())
					.unwrap_or_default();

				eprintln!(
					"[{}] ⚠ Batch chain verification failed ({} broken links)",
					self.node_name,
					verdict.broken_links.len()
				);
				for (idx, msg) in &verdict.broken_links {
					eprintln!("  Frame {}: {}", idx, msg);
				}

				return Ok(ProcessResult::ChainGap { current_head, missing_hash });
			}

			// 4. Validate and update chain for ordered frames
			println!("[{}] Validating frames against chain state...", self.node_name);
			let chain_state_guard = self.chain_state.read()?;
			println!(
				"[{}] Chain state read lock acquired (current sequence: {})",
				self.node_name, chain_state_guard.sequence
			);
			let mut validated_frames = Vec::new();
			let mut frames_to_update = Vec::new();
			for ordered_frame in frames {
				println!("[{}] Validating frame order: {}", self.node_name, ordered_frame.metadata.order);
				let chain_valid = chain_state_guard.validate_frame(&ordered_frame)?;
				println!("[{}] Validation result: {}", self.node_name, chain_valid);
				if !chain_valid {
					// Chain gap detected
					let current_head = chain_state_guard.last_hash.to_vec();
					let missing_hash = ordered_frame
						.metadata
						.previous_frame
						.as_ref()
						.map(|d| d.digest.as_bytes().to_vec())
						.unwrap_or_default();

					eprintln!(
						"[{}] ⚠ Chain gap detected (order: {})",
						self.node_name, ordered_frame.metadata.order
					);
					return Ok(ProcessResult::ChainGap { current_head, missing_hash });
				}

				// Collect frames to update (will update after releasing read lock)
				frames_to_update.push(ordered_frame);
			}

			// Release read lock before acquiring write lock
			println!("[{}] Dropping chain state read lock...", self.node_name);
			drop(chain_state_guard);
			println!("[{}] Read lock dropped", self.node_name);

			// Update chain state for all validated frames (single write lock acquisition)
			println!("[{}] Acquiring chain state write lock...", self.node_name);
			let mut chain_state_guard = self.chain_state.write()?;
			println!(
				"[{}] Chain state write lock acquired, updating {} frames...",
				self.node_name,
				frames_to_update.len()
			);
			for ordered_frame in frames_to_update {
				chain_state_guard.update_with_frame(&ordered_frame)?;
				validated_frames.push(ordered_frame);
			}
			println!("[{}] Chain state updated successfully", self.node_name);

			Ok(ProcessResult::Processed(validated_frames))
		} else {
			println!("[{}] Frame buffered (waiting for missing frames)", self.node_name);
			Ok(ProcessResult::Buffered)
		}
	}

	/// Prepare outgoing frame: get next order and previous hash
	pub fn prepare_outgoing(&self) -> Result<(u64, Option<DigestInfo>), TightBeamError> {
		let chain_state = self.chain_state.read()?;
		let next_order = chain_state.sequence + 1;
		let previous_digest = if chain_state.sequence > 0 {
			// Manually construct DigestInfo from the hash
			let algorithm = AlgorithmIdentifier { oid: Sha3_256::OID, parameters: None };
			let digest = OctetString::new(&chain_state.last_hash[..])?;
			Some(DigestInfo { algorithm, digest })
		} else {
			None
		};

		Ok((next_order, previous_digest))
	}

	/// Update chain state after sending frame
	pub fn finalize_outgoing(&self, frame: &Frame) -> Result<(), TightBeamError> {
		self.store.write()?.persist(frame)?;
		self.chain_state.write()?.update_with_frame(frame)?;

		// Update ordering buffer's next_expected to account for the frame we just sent
		// This ensures the ordering buffer is synchronized with the global chain
		let mut order_buffer = self.order_buffer.write()?;
		if frame.metadata.order >= order_buffer.next_expected() {
			order_buffer.set_next_expected(frame.metadata.order + 1);
		}

		Ok(())
	}

	/// Request missing frames between requester_head and last_received_hash
	///
	/// Traverses the chain backwards from last_received_hash to requester_head,
	/// collecting all frames in between.
	pub fn request_missing_frames(
		&self,
		requester_head: &[u8],
		last_received_hash: &[u8],
	) -> Result<Vec<Frame>, TightBeamError> {
		let mut store = self.store.write()?;

		// Find frame with hash matching last_received_hash (frame just before gap)
		let mut current_frame = match store.retrieve_by_hash(last_received_hash)? {
			Some(frame) => frame,
			None => {
				// Frame not found, return empty
				return Ok(Vec::new());
			}
		};

		// Traverse backwards collecting frames until we reach requester_head
		let mut collected_frames = Vec::new();
		loop {
			// Check if we've reached the requester's head
			let current_bytes = current_frame.to_der()?;
			let current_hash = Sha3_256::digest(&current_bytes);
			if current_hash.as_slice() == requester_head {
				// Found the requester's head, we're done
				break;
			}

			// Add current frame to collection
			collected_frames.push(current_frame.clone());

			// Move to previous frame using previous_frame hash
			match current_frame.metadata.previous_frame.as_ref() {
				Some(digest_info) => {
					let prev_hash = digest_info.digest.as_bytes();
					match store.retrieve_by_hash(prev_hash)? {
						Some(prev_frame) => {
							current_frame = prev_frame;
						}
						None => {
							// Previous frame not found, stop traversal
							break;
						}
					}
				}
				None => {
					// No previous frame, stop traversal
					break;
				}
			}
		}

		// Reverse to get forward chronological order
		collected_frames.reverse();
		Ok(collected_frames)
	}
}
