//! Command execution worker for rover operations

use tightbeam::{worker, TightBeamError};

use super::messages::{CommandExecutionRequest, CommandExecutionResult};
use crate::dtn::messages::{RoverCommand, RoverInstrument};

worker! {
	name: CommandExecutionWorker<CommandExecutionRequest, Result<CommandExecutionResult, TightBeamError>>,
	handle: |request, trace| async move {
		// Convert command type back to RoverCommand for execution
		let command = RoverCommand::try_from(request.command_type)?;

		match command {
			RoverCommand::CollectSample { .. } => {
				trace.event("rover_execute_collect_sample")?;
				Ok(CommandExecutionResult {
					success: true,
					instrument: RoverInstrument::Apxs,
					data_snippet: "Fe2O3:42.1%".to_string(),
				})
			}
			RoverCommand::ProbeLocation { .. } => {
				trace.event("rover_execute_probe_location")?;
				Ok(CommandExecutionResult {
					success: true,
					instrument: RoverInstrument::ChemCam,
					data_snippet: "Na:580nm:12.3".to_string(),
				})
			}
			RoverCommand::TakePhoto { .. } => {
				trace.event("rover_execute_take_photo")?;
				Ok(CommandExecutionResult {
					success: true,
					instrument: RoverInstrument::Mastcam,
					data_snippet: "IMG:1024x768".to_string(),
				})
			}
			RoverCommand::Standby => {
				trace.event("rover_execute_standby")?;
				Ok(CommandExecutionResult {
					success: true,
					instrument: RoverInstrument::Apxs,
					data_snippet: "STATUS:OK".to_string(),
				})
			}
		}
	}
}
