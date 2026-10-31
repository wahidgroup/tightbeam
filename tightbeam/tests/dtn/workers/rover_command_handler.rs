//! The rover command handler worker, which runs an [`EarthCommand`] on the
//! Rover and records the progress of the mission.

use std::sync::{Arc, RwLock};

use tightbeam::{der::Sequence, worker, Beamable, TightBeamError};

use crate::dtn::{
	events::{
		ROVER_COMMAND_COMPLETE, ROVER_EXECUTE_COLLECT_SAMPLE, ROVER_EXECUTE_COMMAND, ROVER_EXECUTE_PROBE_LOCATION,
		ROVER_EXECUTE_STANDBY, ROVER_EXECUTE_TAKE_PHOTO, ROVER_RECEIVE_COMMAND,
	},
	messages::{EarthCommand, RoverCommand},
	servlets::MissionState,
};

/// The request to the rover command handler.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct RoverCommandHandlerRequest {
	/// The command that the Rover runs.
	pub command: EarthCommand,
	/// The number of commands at which the Rover marks the mission complete.
	pub max_rounds: u64,
}

/// The response of the rover command handler.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct RoverCommandHandlerResponse {
	/// The order of the command frame, which the handler answers as 0.
	pub command_order: u64,
	/// Whether the Rover ran the command, which is always `true`.
	pub execution_success: bool,
}

worker! {
	name: RoverCommandHandlerWorker<RoverCommandHandlerRequest, Result<RoverCommandHandlerResponse, TightBeamError>>,
	config: {
		mission_state: Arc<RwLock<MissionState>>,
	},
	handle: |request, trace, config| async move {
		trace.event(ROVER_RECEIVE_COMMAND)?;
		trace.event(ROVER_EXECUTE_COMMAND)?;

		// The type of the command picks its execute event, so the handler reads
		// the type alone.
		let rover_command = RoverCommand::try_from(request.command.command_type)?;

		match rover_command {
			RoverCommand::CollectSample { .. } => {
				trace.event(ROVER_EXECUTE_COLLECT_SAMPLE)?;
			}
			RoverCommand::ProbeLocation { .. } => {
				trace.event(ROVER_EXECUTE_PROBE_LOCATION)?;
			}
			RoverCommand::TakePhoto { .. } => {
				trace.event(ROVER_EXECUTE_TAKE_PHOTO)?;
			}
			RoverCommand::Standby => {
				trace.event(ROVER_EXECUTE_STANDBY)?;
			}
		}

		trace.event(ROVER_COMMAND_COMPLETE)?;

		{
			let mut state = config.mission_state.write()?;
			state.completed_rounds += 1;

			if state.completed_rounds >= request.max_rounds as usize {
				state.mission_complete = true;
			}
		}

		Ok(RoverCommandHandlerResponse {
			// The servlet holds the order from the frame metadata.
			command_order: 0,
			execution_success: true,
		})
	}
}
