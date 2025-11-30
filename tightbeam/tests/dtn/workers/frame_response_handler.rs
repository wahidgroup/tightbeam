//! Frame response handler worker - handles FrameResponse messages
//!
//! Business logic: Process recovered frames and validate chain integrity.

use std::sync::Arc;

use tightbeam::{der::Sequence, worker, Beamable, TightBeamError};

use crate::dtn::{chain_processor::ChainProcessor, messages::FrameResponse};

/// Frame response handler request
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct FrameResponseHandlerRequest {
	pub response: FrameResponse,
	pub node_name: String,
}

/// Frame response handler response (empty - worker does all the work)
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct FrameResponseHandlerResponse {
	pub frames_processed: u32,
}

worker! {
	name: FrameResponseHandlerWorker<FrameResponseHandlerRequest, Result<FrameResponseHandlerResponse, TightBeamError>>,
	config: {
		chain_processor: Arc<ChainProcessor>,
	},
	handle: |request, trace, config| async move {
		trace.event(format!("{}_receive_frame_response", request.node_name))?;

		// Business logic: Process recovered frames through chain processor
		let mut count = 0u32;
		for frame in &request.response.frames {
			config.chain_processor.process_incoming(frame)?;
			count += 1;
		}

		Ok(FrameResponseHandlerResponse {
			frames_processed: count,
		})
	}
}
