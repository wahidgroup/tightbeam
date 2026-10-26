//! The message types of the DTN workers.
//!
//! Each worker takes a request and returns a result, for command execution,
//! instrument selection, and telemetry building.

use tightbeam::{
	der::{asn1::OctetString, Sequence},
	Beamable,
};

use crate::dtn::messages::RoverInstrument;

// The messages of command execution.

/// A request to execute the rover command that `command_type` names.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct CommandExecutionRequest {
	pub command_type: u8,
}

/// The result of one command execution.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct CommandExecutionResult {
	pub success: bool,
	pub instrument: RoverInstrument,
	pub data_snippet: String,
}

// The messages of instrument selection.

/// A request to select the instrument for a command.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[allow(dead_code)]
pub struct InstrumentSelectionRequest {
	pub command_type: u8,
}

/// The instrument that a selection picks, with its sample data.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[allow(dead_code)]
pub struct InstrumentSelection {
	pub instrument: RoverInstrument,
	pub instrument_name: String,
	pub sample_data: OctetString,
}

// The messages of telemetry building.

/// A request to build a telemetry message.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct TelemetryBuildRequest {
	pub instrument: RoverInstrument,
	pub data: OctetString,
	pub mission_time_ms: u64,
}
