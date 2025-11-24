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
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::der::oid::AssociatedOid;
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
		// 1. Persist frame
		self.store.write()?.persist(&frame)?;
		println!("[{}] ✓ Frame persisted (order: {})", self.node_name, frame.metadata.order);

		// 2. Insert into ordering buffer
		let frames_to_process = self.order_buffer.write()?.insert(frame)?;
		if let Some(frames) = frames_to_process {
			// 3. Validate and update chain for ordered frames
			let mut validated_frames = Vec::new();
			for ordered_frame in frames {
				let chain_valid = self.chain_state.read()?.validate_frame(&ordered_frame)?;
				if !chain_valid {
					// Chain gap detected
					let current_head = self.chain_state.read()?.last_hash.to_vec();
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

				// Update chain state
				self.chain_state.write()?.update_with_frame(&ordered_frame)?;
				validated_frames.push(ordered_frame);
			}

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
}
