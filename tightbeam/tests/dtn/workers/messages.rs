//! Message types for DTN workers
//!
//! Defines input/output message structures for worker-based command execution,
//! instrument selection, and telemetry building.

use tightbeam::{der::Sequence, Beamable};

use crate::dtn::messages::RoverInstrument;

// ============================================================================
// Command Execution Messages
// ============================================================================

/// Request to execute a rover command (command type as u8)
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct CommandExecutionRequest {
	pub command_type: u8,
}

/// Result of command execution
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct CommandExecutionResult {
	pub success: bool,
	pub instrument: RoverInstrument,
	pub data_snippet: String,
}

// ============================================================================
// Instrument Selection Messages
// ============================================================================

/// Request to select instrument based on command
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[allow(dead_code)]
pub struct InstrumentSelectionRequest {
	pub command_type: u8,
}

/// Selected instrument with sample data
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[allow(dead_code)]
pub struct InstrumentSelection {
	pub instrument: RoverInstrument,
	pub instrument_name: String,
	pub sample_data: Vec<u8>,
}

// ============================================================================
// Telemetry Building Messages
// ============================================================================

/// Request to build telemetry message
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct TelemetryBuildRequest {
	pub instrument: RoverInstrument,
	pub data: Vec<u8>,
	pub mission_time_ms: u64,
}
