//! The command ACK handler worker, which records that Mission Control
//! received a [`CommandAck`].

use tightbeam::{der::Sequence, worker, Beamable, TightBeamError};

use crate::dtn::events::MISSION_CONTROL_RECEIVE_ACK;
use crate::dtn::messages::CommandAck;

/// The request to the command ACK handler.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct CommandAckHandlerRequest {
	/// The ACK that Mission Control received.
	pub ack: CommandAck,
}

/// The response of the command ACK handler.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct CommandAckHandlerResponse {
	/// Whether Mission Control acknowledged the ACK, which is always `true`.
	pub acknowledged: bool,
}

worker! {
	name: CommandAckHandlerWorker<CommandAckHandlerRequest, Result<CommandAckHandlerResponse, TightBeamError>>,
	handle: |request, trace| async move {
		trace.event(MISSION_CONTROL_RECEIVE_ACK)?;

		Ok(CommandAckHandlerResponse {
			acknowledged: true,
		})
	}
}
