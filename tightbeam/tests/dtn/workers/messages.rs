//! The message types of the DTN workers.
//!
//! Each worker takes a request and returns a result, for instrument selection
//! and telemetry building.

use tightbeam::{
	der::{asn1::OctetString, Sequence},
	Beamable,
};

use crate::dtn::messages::RoverInstrument;

// The messages of instrument selection.

/// A request to select the instrument for a command.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[allow(dead_code)]
pub struct InstrumentSelectionRequest {
	/// The type of the command that needs an instrument.
	pub command_type: u8,
}

/// The instrument that a selection picks, with its sample data.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct InstrumentSelection {
	/// The instrument that the selection picks.
	pub instrument: RoverInstrument,
	/// The name of the instrument.
	pub instrument_name: String,
	/// The sample data that the instrument collected.
	pub sample_data: OctetString,
}

// The messages of telemetry building.

/// A request to build a telemetry message.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct TelemetryBuildRequest {
	/// The instrument that collected the data.
	pub instrument: RoverInstrument,
	/// The data payload, in the format of its instrument.
	pub data: OctetString,
	/// The mission elapsed time in milliseconds at which the instrument
	/// collected the data.
	pub mission_time_ms: u64,
}
