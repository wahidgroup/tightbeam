use std::sync::{Arc, RwLock};

use tightbeam::{job, Frame, TightBeamError};

use crate::dtn::messages::MessageChainState;

job! {
	/// Finalizes chain state update with validated frames.
	/// Returns the processed frames.
	name: FinalizeChainUpdate,
	fn run((frames, chain_state): (Vec<Frame>, Arc<RwLock<MessageChainState>>)) -> Result<Vec<Frame>, TightBeamError> {
		let mut chain_state_guard = chain_state.write()?;
		frames.iter().try_for_each(|frame| chain_state_guard.update_with_frame(frame))?;
		Ok(frames)
	}
}
