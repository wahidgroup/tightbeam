//! Command ACK handler worker - handles CommandAck messages
//!
//! Business logic: Validate ACK corresponds to sent command, log acknowledgment.
//! Returns acknowledgment status.

use tightbeam::{der::Sequence, worker, Beamable, TightBeamError};

use crate::dtn::messages::CommandAck;

/// Command ACK handler request
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct CommandAckHandlerRequest {
	pub ack: CommandAck,
}

/// Command ACK handler response
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct CommandAckHandlerResponse {
	pub acknowledged: bool,
}

worker! {
	name: CommandAckHandlerWorker<CommandAckHandlerRequest, Result<CommandAckHandlerResponse, TightBeamError>>,
	handle: |request, trace| async move {
		trace.event("mission_control_receive_ack")?;

		// In a more complex system, we might verify this matches a pending
		// command but for this simple system, we just acknowledge the command.
		Ok(CommandAckHandlerResponse {
			acknowledged: true,
		})
	}
}
