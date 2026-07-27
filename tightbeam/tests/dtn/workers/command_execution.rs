//! Command execution worker for rover operations

use tightbeam::{worker, TightBeamError};

use super::messages::{CommandExecutionRequest, CommandExecutionResult};
use crate::dtn::{
	events::{
		ROVER_EXECUTE_COLLECT_SAMPLE, ROVER_EXECUTE_PROBE_LOCATION, ROVER_EXECUTE_STANDBY, ROVER_EXECUTE_TAKE_PHOTO,
	},
	messages::{RoverCommand, RoverInstrument},
};

worker! {
	name: CommandExecutionWorker<CommandExecutionRequest, Result<CommandExecutionResult, TightBeamError>>,
	handle: |request, trace| async move {
		// Convert command type back to RoverCommand for execution
		let command = RoverCommand::try_from(request.command_type)?;
		match command {
			RoverCommand::CollectSample { .. } => {
				trace.event(ROVER_EXECUTE_COLLECT_SAMPLE)?;
				Ok(CommandExecutionResult {
					success: true,
					instrument: RoverInstrument::Apxs,
					data_snippet: "Fe2O3:42.1%".to_string(),
				})
			}
			RoverCommand::ProbeLocation { .. } => {
				trace.event(ROVER_EXECUTE_PROBE_LOCATION)?;
				Ok(CommandExecutionResult {
					success: true,
					instrument: RoverInstrument::ChemCam,
					data_snippet: "Na:580nm:12.3".to_string(),
				})
			}
			RoverCommand::TakePhoto { .. } => {
				trace.event(ROVER_EXECUTE_TAKE_PHOTO)?;
				Ok(CommandExecutionResult {
					success: true,
					instrument: RoverInstrument::Mastcam,
					data_snippet: "IMG:1024x768".to_string(),
				})
			}
			RoverCommand::Standby => {
				trace.event(ROVER_EXECUTE_STANDBY)?;
				Ok(CommandExecutionResult {
					success: true,
					instrument: RoverInstrument::Apxs,
					data_snippet: "STATUS:OK".to_string(),
				})
			}
		}
	}
}
