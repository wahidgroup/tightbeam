use std::sync::Arc;

use tightbeam::{asn1::DigestInfo, job, Frame, TightBeamError};

use crate::dtn::{jobs::GapRecoveryContext, messages::FrameRequest};

job! {
	/// Constructs a signed and encrypted frame for requesting missing frames
	/// from upstream.
	name: BuildGapRecoveryFrame,
	fn run(
		(req, order, prev, ctx): (FrameRequest, u64, Option<DigestInfo>, Arc<GapRecoveryContext>),
	) -> Result<Frame, TightBeamError> {
		ctx.frame_builder.build_frame_request_frame(req, order, prev, &ctx.signing_key, &ctx.cipher)
	}
}
