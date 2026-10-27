use tightbeam::{job, TightBeamError};

use crate::dtn::messages::FrameRequest;

job! {
	/// Creates a `FrameRequest` from the result of gap detection.
	name: CreateFrameRequest,
	fn run((current_head, missing_hash): (Vec<u8>, Vec<u8>)) -> Result<FrameRequest, TightBeamError> {
		Ok(FrameRequest::new(current_head, missing_hash)?)
	}
}
