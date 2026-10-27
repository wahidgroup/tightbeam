use std::sync::Arc;

use tightbeam::{job, Frame, TightBeamError};

use crate::dtn::{jobs::GapRecoveryContext, messages::FrameRequest};

job! {
	/// Builds the signed and encrypted frame that asks the upstream hop for the
	/// missing frames.
	name: BuildGapRecoveryFrame,
	fn run((req, ctx): (FrameRequest, Arc<GapRecoveryContext>)) -> Result<Frame, TightBeamError> {
		ctx.frame_builder.build_frame_request_frame(req, &ctx.signing_key, &ctx.cipher)
	}
}
