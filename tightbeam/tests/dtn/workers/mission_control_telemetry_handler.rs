//! The telemetry handler worker of Mission Control.
//!
//! The worker receives telemetry, analyzes it, and decides the next command,
//! which it returns while the mission owes another command.

use std::sync::{Arc, RwLock};

use tightbeam::{
	asn1::MessagePriority,
	der::{asn1::OctetString, Sequence},
	worker, Beamable, TightBeamError,
};

use crate::dtn::{
	events::{MISSION_CONTROL_ANALYZE_TELEMETRY, MISSION_CONTROL_RECEIVE_TELEMETRY, MISSION_CONTROL_SEND_COMMAND},
	messages::{RoverCommand, RoverTelemetry},
	servlets::MissionState,
};

/// A telemetry message that the handler analyzes.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct TelemetryHandlerRequest {
	pub telemetry: RoverTelemetry,
}

/// The next command that Mission Control sends.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct NextCommand {
	pub command: u8, // RoverCommand type as u8
	pub parameters: OctetString,
	pub priority: MessagePriority,
}

/// The answer of the handler, with the next command when one follows.
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
		trace.event(MISSION_CONTROL_RECEIVE_TELEMETRY)?;
		trace.event(MISSION_CONTROL_ANALYZE_TELEMETRY)?;

		let telemetry_count = {
			let mut state = config.mission_state.write()?;
			state.telemetry_received_count += 1;
			state.telemetry_received_count
		};

		// A telemetry message draws a command while its count is under
		// `max_commands`.
		if telemetry_count < config.max_commands as usize {
			let command_type = (telemetry_count % 3) as u8;
			let rover_cmd = match command_type {
				0 => RoverCommand::CollectSample { location: "Site Alpha".to_string() },
				1 => RoverCommand::ProbeLocation { x: 100, y: 200 },
				_ => RoverCommand::TakePhoto { direction: "North".to_string(), resolution: 1080 },
			};

			let priority = if request.telemetry.battery_percent < 20 {
				MessagePriority::LowLatency
			} else {
				MessagePriority::Standard
			};

			trace.event(MISSION_CONTROL_SEND_COMMAND)?;

			Ok(TelemetryHandlerResponse {
				should_send_command: true,
				next_command: Some(NextCommand {
					command: rover_cmd.command_type(),
					parameters: OctetString::new(rover_cmd.encode_parameters())?,
					priority,
				}),
			})
		} else {
			// The mission has sent its last command.
			Ok(TelemetryHandlerResponse {
				should_send_command: false,
				next_command: None,
			})
		}
	}
}
