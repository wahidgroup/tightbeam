//! The frame request handler worker, which handles `FrameRequest` messages.
//!
//! The worker checks whether this node holds the requested frames, and then
//! responds with them or cascades the request upstream. It returns the frames
//! and the action for the servlet to execute.

use std::sync::Arc;

use tightbeam::{
	der::{Choice, Sequence},
	worker, Beamable, Frame, TightBeamError,
};

use crate::dtn::{
	chain_processor::ChainProcessor,
	messages::FrameRequest,
	ultimate::{gap_recovery_event, GapRecoveryStep},
};

/// The request to the frame request handler.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct FrameRequestHandlerRequest {
	pub request: FrameRequest,
	pub node_name: String,
}

/// The action that follows the handling of a frame request.
#[derive(Beamable, Choice, Clone, Debug, PartialEq)]
pub enum FrameRequestAction {
	/// Respond with the frames this node holds.
	#[asn1(context_specific = "0")]
	Respond(u8),
	/// Cascade the request upstream.
	#[asn1(context_specific = "1")]
	Cascade(u8),
	/// Take no action, because this node is the origin.
	#[asn1(context_specific = "2")]
	NoAction(u8),
}

/// The response of the frame request handler.
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
		trace.event(gap_recovery_event(&request.node_name, GapRecoveryStep::ReceiveFrameRequest))?;

		let missing_frames = config.chain_processor.request_missing_frames(
			&request.request.requester_head,
			&request.request.last_received_hash,
		)?;

		if !missing_frames.is_empty() {
			// This node holds the frames, so it responds with them.
			trace.event(gap_recovery_event(&request.node_name, GapRecoveryStep::SendFrameResponse))?;
			Ok(FrameRequestHandlerResponse {
				action: FrameRequestAction::Respond(0),
				missing_frames,
			})
		} else if config.can_cascade {
			// This node holds none of the frames, so it cascades upstream.
			trace.event(gap_recovery_event(&request.node_name, GapRecoveryStep::CascadeFrameRequest))?;
			Ok(FrameRequestHandlerResponse {
				action: FrameRequestAction::Cascade(0),
				missing_frames: vec![],
			})
		} else {
			// The origin has no upstream to cascade to.
			Ok(FrameRequestHandlerResponse {
				action: FrameRequestAction::NoAction(0),
				missing_frames: vec![],
			})
		}
	}
}
