use tightbeam::{job, TightBeamError};

use crate::dtn::messages::FrameRequest;

job! {
	/// Creates a FrameRequest from gap detection information.
	name: CreateFrameRequest,
	fn run(current_head: Vec<u8>, missing_hash: Vec<u8>) -> Result<FrameRequest, TightBeamError> {
		Ok(FrameRequest {
			requester_head: current_head.try_into().unwrap_or([0u8; 32]),
			last_received_hash: missing_hash.try_into().unwrap_or([0u8; 32]),
		})
	}
}
