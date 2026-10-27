//! The frame response handler worker, which records the answer to a frame
//! request of its node.
//!
//! The node keeps the answer, and takes each frame of it into its chain.

use tightbeam::{der::Sequence, worker, Beamable, TightBeamError};

use crate::dtn::{nodes::DtnRole, ultimate::GapRecoveryStep};

/// The request to the frame response handler.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct FrameResponseHandlerRequest {
	/// The node that asked for the frames.
	pub node: DtnRole,
}

worker! {
	name: FrameResponseHandlerWorker<FrameResponseHandlerRequest, Result<(), TightBeamError>>,
	handle: |request, trace| async move {
		trace.event(GapRecoveryStep::ReceiveFrameResponse.event_on(request.node))?;
		Ok(())
	}
}
