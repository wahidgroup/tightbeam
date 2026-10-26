use std::sync::{Arc, RwLock};

use tightbeam::{job, Frame, TightBeamError};

use crate::dtn::{messages::MessageChainState, storage::FrameStore};

use crate::dtn::chain_processor::ProcessResult;

use super::FinalizeChainUpdate;

/// The result of chain verification: valid frames, or a detected gap.
pub enum VerifyResult {
	/// The frames are valid and ready for finalization.
	Valid(Vec<Frame>),
	/// The chain has a gap, so the node must request the missing frames.
	Gap { current_head: Vec<u8>, missing_hash: Vec<u8> },
}

impl VerifyResult {
	/// Finalizes the verification into a `ProcessResult`.
	pub fn finalize(self, chain_state: Arc<RwLock<MessageChainState>>) -> Result<ProcessResult, TightBeamError> {
		match self {
			Self::Gap { current_head, missing_hash } => Ok(ProcessResult::ChainGap { current_head, missing_hash }),
			Self::Valid(frames) => FinalizeChainUpdate::run((frames, chain_state)).map(ProcessResult::Processed),
		}
	}
}

job! {
	/// Verifies the integrity of the chain and validates the frames against
	/// the chain state.
	name: ValidateChain,
	fn run(
		(frames, store, chain_state): (Vec<Frame>, Arc<RwLock<FrameStore>>, Arc<RwLock<MessageChainState>>)
	) -> Result<VerifyResult, TightBeamError> {
		let verdict = store.read()?.verify_chain(&frames)?;
		if !verdict.valid {
			let current_head = chain_state.read()?.last_hash.to_vec();
			let missing_hash = frames
				.first()
				.and_then(|f| f.metadata().previous_frame())
				.map(|d| d.digest.as_bytes().to_vec())
				.unwrap_or_default();

			return Ok(VerifyResult::Gap { current_head, missing_hash });
		}

		// The buffer releases consecutive orders, and `verify_chain` links each
		// frame of the batch to the frame before it, so the chain state judges
		// the first frame alone.
		let chain_state_guard = chain_state.read()?;
		if let Some(first) = frames.first() {
			if !chain_state_guard.validate_frame(first)? {
				let current_head = chain_state_guard.last_hash.to_vec();
				let missing_hash = first
					.metadata()
					.previous_frame()
					.as_ref()
					.map(|d| d.digest.as_bytes().to_vec())
					.unwrap_or_default();
				return Ok(VerifyResult::Gap { current_head, missing_hash });
			}
		}

		Ok(VerifyResult::Valid(frames))
	}
}
