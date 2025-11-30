//! Frame request handler worker - handles FrameRequest messages
//!
//! Business logic: Check if we have the requested frames, decide to respond or cascade.
//! Returns frames and action for servlet to execute.

use std::sync::Arc;

use tightbeam::{
	der::{Choice, Sequence},
	worker, Beamable, Frame, TightBeamError,
};

use crate::dtn::{chain_processor::ChainProcessor, messages::FrameRequest};

/// Frame request handler request
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct FrameRequestHandlerRequest {
	pub request: FrameRequest,
	pub node_name: String,
}

/// Action to take after processing frame request
#[derive(Beamable, Choice, Clone, Debug, PartialEq)]
pub enum FrameRequestAction {
	/// Respond with frames
	#[asn1(context_specific = "0")]
	Respond(u8),
	/// Cascade upstream
	#[asn1(context_specific = "1")]
	Cascade(u8),
	/// No action
	#[asn1(context_specific = "2")]
	NoAction(u8),
}

/// Frame request handler response
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct FrameRequestHandlerResponse {
	pub action: FrameRequestAction,
	pub missing_frames: Vec<Frame>,
}

worker! {
	name: FrameRequestHandlerWorker<FrameRequestHandlerRequest, Result<FrameRequestHandlerResponse, TightBeamError>>,
	config: {
		chain_processor: Arc<ChainProcessor>,
		can_cascade: bool,
	},
	handle: |request, trace, config| async move {
		trace.event(format!("{}_receive_frame_request", request.node_name))?;

		// Check if we have the requested frames
		let missing_frames = config.chain_processor.request_missing_frames(
			&request.request.requester_head,
			&request.request.last_received_hash,
		)?;

		if !missing_frames.is_empty() {
			// We have frames - respond
			trace.event(format!("{}_send_frame_response", request.node_name))?;
			Ok(FrameRequestHandlerResponse {
				action: FrameRequestAction::Respond(0),
				missing_frames,
			})
		} else if config.can_cascade {
			// We don't have frames - cascade upstream
			trace.event(format!("{}_cascade_frame_request", request.node_name))?;
			Ok(FrameRequestHandlerResponse {
				action: FrameRequestAction::Cascade(0),
				missing_frames: vec![],
			})
		} else {
			// Can't cascade (we're the origin)
			Ok(FrameRequestHandlerResponse {
				action: FrameRequestAction::NoAction(0),
				missing_frames: vec![],
			})
		}
	}
}
