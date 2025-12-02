use std::sync::Arc;

use tightbeam::{asn1::DigestInfo, job, TightBeamError};

use crate::dtn::{jobs::GapRecoveryContext, messages::FrameRequest};

job! {
	/// Prepares chain state for building a gap recovery frame.
	/// Returns everything needed by BuildGapRecoveryFrame.
	name: PrepareGapRecoveryBuild,
	fn run(
		(req, ctx): (FrameRequest, Arc<GapRecoveryContext>),
	) -> Result<(FrameRequest, u64, Option<DigestInfo>, Arc<GapRecoveryContext>), TightBeamError> {
		let (order, prev) = ctx.chain_processor.prepare_outgoing()?;
		Ok((req, order, prev, ctx))
	}
}
