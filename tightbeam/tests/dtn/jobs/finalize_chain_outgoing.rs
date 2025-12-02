use std::sync::Arc;

use tightbeam::{job, Frame, TightBeamError};

use crate::dtn::jobs::GapRecoveryContext;

job! {
	name: FinalizeChainOutgoing,
	fn run((frame, ctx): (Frame, Arc<GapRecoveryContext>)) -> Result<Frame, TightBeamError> {
		ctx.chain_processor.finalize_outgoing(&frame)?;
		Ok(frame)
	}
}
