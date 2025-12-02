use std::sync::{Arc, RwLock};

use tightbeam::{job, Frame, TightBeamError};

use crate::dtn::{messages::MessageChainState, storage::FrameStore};

use crate::dtn::chain_processor::ProcessResult;

use super::FinalizeChainUpdate;

/// Result of chain verification - either valid frames or a gap detected.
pub enum VerifyResult {
	/// Frames are valid and ready for finalization.
	Valid(Vec<Frame>),
	/// Chain gap detected, need to request missing frames.
	Gap { current_head: Vec<u8>, missing_hash: Vec<u8> },
}

impl VerifyResult {
	/// Finalize verification into a ProcessResult.
	pub fn finalize(self, chain_state: Arc<RwLock<MessageChainState>>) -> Result<ProcessResult, TightBeamError> {
		match self {
			Self::Gap { current_head, missing_hash } => Ok(ProcessResult::ChainGap { current_head, missing_hash }),
			Self::Valid(frames) => FinalizeChainUpdate::run((frames, chain_state)).map(ProcessResult::Processed),
		}
	}
}

job! {
	/// Verifies chain integrity and validates frames against chain state.
	name: ValidateChain,
	fn run(
		(frames, store, chain_state): (Vec<Frame>, Arc<RwLock<FrameStore>>, Arc<RwLock<MessageChainState>>)
	) -> Result<VerifyResult, TightBeamError> {
		let verdict = store.read()?.verify_chain(&frames)?;
		if !verdict.valid {
			let current_head = chain_state.read()?.last_hash.to_vec();
			let missing_hash = frames
				.first()
				.and_then(|f| f.metadata.previous_frame.as_ref())
				.map(|d| d.digest.as_bytes().to_vec())
				.unwrap_or_default();

			return Ok(VerifyResult::Gap { current_head, missing_hash });
		}

		let chain_state_guard = chain_state.read()?;
		let invalid_frame = frames
			.iter()
			.find(|frame| !chain_state_guard.validate_frame(frame).unwrap_or(false));

		if let Some(frame) = invalid_frame {
			let current_head = chain_state_guard.last_hash.to_vec();
			let missing_hash = frame
				.metadata
				.previous_frame
				.as_ref()
				.map(|d| d.digest.as_bytes().to_vec())
				.unwrap_or_default();
			return Ok(VerifyResult::Gap { current_head, missing_hash });
		}

		Ok(VerifyResult::Valid(frames))
	}
}
