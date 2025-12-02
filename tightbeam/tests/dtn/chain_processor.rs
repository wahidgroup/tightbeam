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

use crate::dtn::jobs::{PersistAndBufferFrame, ValidateChain};
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
}

impl ChainProcessor {
	pub fn new(
		store: Arc<RwLock<FrameStore>>,
		chain_state: Arc<RwLock<MessageChainState>>,
		order_buffer: Arc<RwLock<OutOfOrderBuffer>>,
	) -> Self {
		Self { store, chain_state, order_buffer }
	}

	/// Process incoming frame: persist, order, validate chain
	pub fn process_incoming(&self, frame: &Frame) -> Result<ProcessResult, TightBeamError> {
		let store = Arc::clone(&self.store);
		let buffer = Arc::clone(&self.order_buffer);
		let state = Arc::clone(&self.chain_state);
		match PersistAndBufferFrame::run((frame.to_owned(), store, buffer))? {
			None => Ok(ProcessResult::Buffered),
			Some(frames) => {
				let store = Arc::clone(&self.store);
				let chain_state = Arc::clone(&self.chain_state);
				let result = ValidateChain::run((frames, store, chain_state))?;
				result.finalize(state)
			}
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

		// Update ordering buffer's next_expected to account for the frame we
		// just sent. This ensures the ordering buffer is synchronized with
		// the global chain
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
		// Find frame with hash matching last_received_hash (frame just before gap)
		let mut store = self.store.write()?;
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
