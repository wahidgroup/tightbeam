//! DTN message types for Mars rover communication
//!
//! Defines realistic message structures for:
//! - Rover telemetry (APXS, ChemCam, Mastcam instruments)
//! - Earth command & control
//! - Message chain consensus validation

use tightbeam::der::{Enumerated, Sequence};
use tightbeam::Beamable;

// ============================================================================
// Rover Telemetry Messages
// ============================================================================

/// Rover telemetry message with instrument data
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct RoverTelemetry {
	/// Instrument that generated this data (0=APXS, 1=ChemCam, 2=Mastcam)
	pub instrument: u8,
	/// Instrument-specific data payload
	pub data: Vec<u8>,
	/// Mission elapsed time when data was collected
	pub mission_time_ms: u64,
	/// Battery charge percentage (0-100)
	pub battery_percent: u8,
	/// Ambient temperature in Celsius
	pub temperature_c: i8,
	// Note: Fault flags are now encoded in Frame.matrix via FaultMatrix
}

impl RoverTelemetry {
	/// Create telemetry with typed instrument
	pub fn new(
		instrument: RoverInstrument,
		data: Vec<u8>,
		mission_time_ms: u64,
		battery_percent: u8,
		temperature_c: i8,
	) -> Self {
		Self {
			instrument: instrument.to_u8(),
			data,
			mission_time_ms,
			battery_percent,
			temperature_c,
		}
	}

	/// Get the instrument type
	pub fn get_instrument(&self) -> Option<RoverInstrument> {
		RoverInstrument::from_u8(self.instrument)
	}
}

/// Mars rover science instruments (encoded as u8)
#[derive(Enumerated, Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum RoverInstrument {
	/// Alpha Particle X-ray Spectrometer (soil composition)
	APXS = 0,
	/// Chemistry Camera (laser spectrometer)
	ChemCam = 1,
	/// Mast Camera (imaging)
	Mastcam = 2,
}

impl RoverInstrument {
	pub fn to_u8(&self) -> u8 {
		match self {
			RoverInstrument::APXS => 0,
			RoverInstrument::ChemCam => 1,
			RoverInstrument::Mastcam => 2,
		}
	}

	pub fn from_u8(value: u8) -> Option<Self> {
		match value {
			0 => Some(RoverInstrument::APXS),
			1 => Some(RoverInstrument::ChemCam),
			2 => Some(RoverInstrument::Mastcam),
			_ => None,
		}
	}
}

// ============================================================================
// Earth Command & Control Messages
// ============================================================================

/// Command from Earth to rover
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct EarthCommand {
	/// Command type (0=CollectSample, 1=ProbeLocation, 2=TakePhoto, 3=Standby)
	pub command_type: u8,
	/// Command-specific parameters
	pub parameters: Vec<u8>,
	/// Command priority (0=lowest, 255=highest)
	pub priority: u8,
	/// Mission time when command was issued
	pub mission_time_ms: u64,
}

impl EarthCommand {
	/// Create command from typed RoverCommand
	pub fn new(command: RoverCommand, priority: Option<u8>, mission_time_ms: u64) -> Self {
		Self {
			command_type: command.command_type(),
			parameters: command.encode_parameters(),
			priority: priority.unwrap_or(128), // Default priority: medium
			mission_time_ms,
		}
	}
}

/// Rover command types (encoded as u8 + parameters)
#[derive(Clone, Debug, PartialEq)]
pub enum RoverCommand {
	/// Collect soil/rock sample at location
	CollectSample { location: String },
	/// Probe specified coordinates
	ProbeLocation { x: i32, y: i32 },
	/// Take photo in direction with resolution
	TakePhoto { direction: String, resolution: u16 },
	/// Enter standby mode (for low power situations)
	Standby,
}

impl RoverCommand {
	pub fn command_type(&self) -> u8 {
		match self {
			RoverCommand::CollectSample { .. } => 0,
			RoverCommand::ProbeLocation { .. } => 1,
			RoverCommand::TakePhoto { .. } => 2,
			RoverCommand::Standby => 3,
		}
	}

	pub fn encode_parameters(&self) -> Vec<u8> {
		match self {
			RoverCommand::CollectSample { location } => location.as_bytes().to_vec(),
			RoverCommand::ProbeLocation { x, y } => {
				let mut params = Vec::new();
				params.extend_from_slice(&x.to_be_bytes());
				params.extend_from_slice(&y.to_be_bytes());
				params
			}
			RoverCommand::TakePhoto { direction, resolution } => {
				let mut params = Vec::new();
				params.extend_from_slice(direction.as_bytes());
				params.push(0); // Separator
				params.extend_from_slice(&resolution.to_be_bytes());
				params
			}
			RoverCommand::Standby => vec![],
		}
	}

	/// Create command from type byte
	pub fn from_u8(value: u8) -> Option<Self> {
		match value {
			0 => Some(RoverCommand::CollectSample { location: "default".to_string() }),
			1 => Some(RoverCommand::ProbeLocation { x: 0, y: 0 }),
			2 => Some(RoverCommand::TakePhoto { direction: "forward".to_string(), resolution: 1024 }),
			3 => Some(RoverCommand::Standby),
			_ => None,
		}
	}

	/// Get human-readable command name
	pub fn to_string(&self) -> &str {
		match self {
			RoverCommand::CollectSample { .. } => "CollectSample",
			RoverCommand::ProbeLocation { .. } => "ProbeLocation",
			RoverCommand::TakePhoto { .. } => "TakePhoto",
			RoverCommand::Standby => "Standby",
		}
	}
}

// ============================================================================
// Message Chain Consensus
// ============================================================================

/// Message chain state for a single node
#[derive(Clone, Debug, PartialEq)]
pub struct MessageChainState {
	/// Hash of last message in chain
	pub last_hash: [u8; 32],
	/// Sequence number
	pub sequence: u64,
	/// Node identifier
	pub node_id: String,
}

impl MessageChainState {
	pub fn new(node_id: String) -> Self {
		Self { last_hash: [0u8; 32], sequence: 0, node_id }
	}

	pub fn update(&mut self, new_hash: [u8; 32]) {
		self.last_hash = new_hash;
		self.sequence += 1;
	}
}

/// Consensus validator for 2/3 agreement on message chains
pub struct ConsensusValidator {
	pub rover_state: MessageChainState,
	pub earth_state: MessageChainState,
	pub relay_state: MessageChainState,
}

impl ConsensusValidator {
	pub fn new() -> Self {
		Self {
			rover_state: MessageChainState::new("rover".to_string()),
			earth_state: MessageChainState::new("earth".to_string()),
			relay_state: MessageChainState::new("relay".to_string()),
		}
	}

	/// Validate that at least 2/3 nodes agree on chain state
	pub fn validate(&self, new_hash: &[u8; 32]) -> bool {
		let mut agreements = 0;
		if self.rover_state.last_hash == *new_hash {
			agreements += 1;
		}
		if self.earth_state.last_hash == *new_hash {
			agreements += 1;
		}
		if self.relay_state.last_hash == *new_hash {
			agreements += 1;
		}
		agreements >= 2
	}

	/// Get the number of nodes that agree on a hash
	pub fn agreement_count(&self, hash: &[u8; 32]) -> usize {
		let mut count = 0;
		if self.rover_state.last_hash == *hash {
			count += 1;
		}
		if self.earth_state.last_hash == *hash {
			count += 1;
		}
		if self.relay_state.last_hash == *hash {
			count += 1;
		}
		count
	}
}

impl Default for ConsensusValidator {
	fn default() -> Self {
		Self::new()
	}
}
