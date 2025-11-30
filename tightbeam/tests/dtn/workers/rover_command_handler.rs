//! Rover command handler worker - handles all Command message processing
//!
//! Business logic: Receives EarthCommand, validates, executes, updates mission state.
//! Returns data needed for servlet to build ACK frame.

use std::sync::{Arc, RwLock};

use tightbeam::{der::Sequence, worker, Beamable, TightBeamError};

use crate::dtn::{
	messages::{EarthCommand, RoverCommand},
	servlets::MissionState,
};

/// Rover command handler request (the full command message)
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct RoverCommandHandlerRequest {
	pub command: EarthCommand,
	pub max_rounds: u64,
}

/// Rover command handler response (data for ACK building)
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct RoverCommandHandlerResponse {
	pub command_order: u64,
	pub execution_success: bool,
}

worker! {
	name: RoverCommandHandlerWorker<RoverCommandHandlerRequest, Result<RoverCommandHandlerResponse, TightBeamError>>,
	config: {
		mission_state: Arc<RwLock<MissionState>>,
	},
	handle: |request, trace, config| async move {
		trace.event("rover_receive_command")?;
		trace.event("rover_execute_command")?;

		// Execute command based on type (parameters are in request.command.parameters if needed)
		let rover_command = RoverCommand::try_from(request.command.command_type)?;

		match rover_command {
			RoverCommand::CollectSample { .. } => {
				trace.event("rover_execute_collect_sample")?;
			}
			RoverCommand::ProbeLocation { .. } => {
				trace.event("rover_execute_probe_location")?;
			}
			RoverCommand::TakePhoto { .. } => {
				trace.event("rover_execute_take_photo")?;
			}
			RoverCommand::Standby => {
				trace.event("rover_execute_standby")?;
			}
		}

		trace.event("rover_command_complete")?;

		// Update mission state
		{
			let mut state = config.mission_state.write()?;
			state.completed_rounds += 1;

			if state.completed_rounds >= request.max_rounds as usize {
				state.mission_complete = true;
			}
		}

		// Return response data (servlet will build ACK frame)
		Ok(RoverCommandHandlerResponse {
			command_order: 0, // Servlet has this from frame metadata
			execution_success: true,
		})
	}
}
