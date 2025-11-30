//! Mission Control telemetry handler worker
//!
//! Business logic: Receives telemetry, analyzes it, decides on next command.
//! Returns command to send (if any).

use std::sync::{Arc, RwLock};

use tightbeam::{asn1::MessagePriority, der::Sequence, worker, Beamable, TightBeamError};

use crate::dtn::{
	messages::{RoverCommand, RoverTelemetry},
	servlets::MissionState,
};

/// Telemetry handler request
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct TelemetryHandlerRequest {
	pub telemetry: RoverTelemetry,
}

/// Next command to send (if any)
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct NextCommand {
	pub command: u8, // RoverCommand type as u8
	pub parameters: Vec<u8>,
	pub priority: MessagePriority,
}

/// Telemetry handler response
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct TelemetryHandlerResponse {
	pub should_send_command: bool,
	pub next_command: Option<NextCommand>,
}

worker! {
	name: MissionControlTelemetryHandlerWorker<TelemetryHandlerRequest, Result<TelemetryHandlerResponse, TightBeamError>>,
	config: {
		mission_state: Arc<RwLock<MissionState>>,
		max_commands: u64,
	},
	handle: |request, trace, config| async move {
		trace.event("mission_control_receive_telemetry")?;
		trace.event("mission_control_analyze_telemetry")?;

		// Increment telemetry counter
		let telemetry_count = {
			let mut state = config.mission_state.write()?;
			state.telemetry_received_count += 1;
			state.telemetry_received_count
		};

		// Decide if we should send another command
		if telemetry_count < config.max_commands as usize {
			// Determine next command type (cycle through command types)
			let command_type = (telemetry_count % 3) as u8;
			let rover_cmd = match command_type {
				0 => RoverCommand::CollectSample { location: "Site Alpha".to_string() },
				1 => RoverCommand::ProbeLocation { x: 100, y: 200 },
				_ => RoverCommand::TakePhoto { direction: "North".to_string(), resolution: 1080 },
			};

			// Determine priority based on battery level
			let priority = if request.telemetry.battery_percent < 20 {
				MessagePriority::High
			} else {
				MessagePriority::Normal
			};

			trace.event("mission_control_send_command")?;

			Ok(TelemetryHandlerResponse {
				should_send_command: true,
				next_command: Some(NextCommand {
					command: rover_cmd.command_type(),
					parameters: rover_cmd.encode_parameters(),
					priority,
				}),
			})
		} else {
			// No more commands to send
			Ok(TelemetryHandlerResponse {
				should_send_command: false,
				next_command: None,
			})
		}
	}
}
