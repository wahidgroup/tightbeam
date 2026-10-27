//! The frame request handler worker, which answers a [`FrameRequest`] for its
//! node.
//!
//! It admits the request through its node's request gate, checks whether the
//! node holds the requested frames, then responds with them or cascades the
//! request upstream. It returns the frames and the action for the servlet to
//! execute.

use std::sync::Arc;

use tightbeam::{
	der::{Choice, Sequence},
	worker, Beamable, Frame, TightBeamError,
};

use crate::dtn::{
	chain_processor::ChainProcessor, messages::FrameRequest, nodes::DtnRole, ordering::RequestGate,
	ultimate::GapRecoveryStep,
};

/// The request to the frame request handler.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct FrameRequestHandlerRequest {
	pub request: FrameRequest,
	/// The node that answers the request.
	pub node: DtnRole,
	/// The peer whose signer verifies the frame of the request.
	pub requester: DtnRole,
	/// The order of the frame of the request, the request order of the
	/// requester.
	pub order: u64,
}

/// The action that the servlet executes for a frame request.
#[derive(Beamable, Choice, Clone, Debug, PartialEq)]
pub enum FrameRequestAction {
	/// The node responds with the frames that it holds.
	#[asn1(context_specific = "0")]
	Respond(u8),
	/// The node cascades the request upstream.
	#[asn1(context_specific = "1")]
	Cascade(u8),
	/// The node takes no action, because it is the origin.
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
		gate: Arc<RequestGate>,
	},
	handle: |request, trace, config| async move {
		// The gate refuses a replayed or a stale request before the node
		// reads its store.
		config.gate.admit(request.requester, request.order)?;
		trace.event(GapRecoveryStep::ReceiveFrameRequest.event_on(request.node))?;

		let missing_frames = config.chain_processor.request_missing_frames(
			&request.request.requester_head,
			&request.request.last_received_hash,
		)?;

		if !missing_frames.is_empty() {
			// This node holds the frames, so it responds with them.
			trace.event(GapRecoveryStep::SendFrameResponse.event_on(request.node))?;
			Ok(FrameRequestHandlerResponse {
				action: FrameRequestAction::Respond(0),
				missing_frames,
			})
		} else if config.can_cascade {
			// This node holds none of the frames, so it cascades upstream.
			trace.event(GapRecoveryStep::CascadeFrameRequest.event_on(request.node))?;
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
