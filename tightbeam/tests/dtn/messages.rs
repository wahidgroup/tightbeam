//! The DTN message types of the Mars rover communication tests.
//!
//! The module defines the message structures of these flows:
//! - Rover telemetry from the APXS, ChemCam, and Mastcam instruments.
//! - Command and control from Earth.
//! - Consensus validation of the message chain.
//! - Stateless and stateful acknowledgments.

use std::convert::TryFrom;
use std::fmt;

use tightbeam::asn1::{Choice, Frame, MessagePriority};
use tightbeam::crypto::hash::{Digest, Sha3_256};
use tightbeam::der::asn1::OctetString;
use tightbeam::der::{Encode, Enumerated, Sequence};
use tightbeam::{Beamable, TightBeamError};

// The stateless acknowledgment carries metadata alone.

/// A stateless acknowledgment: a minimal message body that stays outside the
/// message chain.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct StatelessAck {
	/// Whether the acknowledgment arrived, which is always `true`.
	pub ack: bool,
}

// The rover sends these telemetry messages.

/// A rover telemetry message that carries instrument data.
#[derive(Sequence, Clone, Debug, PartialEq)]
pub struct RoverTelemetry {
	/// The instrument that produced this data: 0 is APXS, 1 is ChemCam, and 2
	/// is Mastcam.
	pub instrument: u8,
	/// The data payload, in the format of its instrument.
	pub data: OctetString,
	/// The mission elapsed time in milliseconds at which the instrument
	/// collected the data.
	pub mission_time_ms: u64,
	/// The battery charge as a percentage from 0 to 100.
	pub battery_percent: u8,
	/// The ambient temperature in degrees Celsius.
	pub temperature_c: i8,
}

impl RoverTelemetry {
	/// Creates a telemetry message from a typed instrument.
	///
	/// # Errors
	///
	/// - [`tightbeam::der::Error`] -- `data` is longer than an OCTET STRING holds.
	pub fn new(
		instrument: RoverInstrument,
		data: impl Into<Vec<u8>>,
		mission_time_ms: u64,
		battery_percent: u8,
		temperature_c: i8,
	) -> tightbeam::der::Result<Self> {
		Ok(Self {
			instrument: instrument as u8,
			data: OctetString::new(data)?,
			mission_time_ms,
			battery_percent,
			temperature_c,
		})
	}
}

/// The science instruments of the Mars rover, each encoded as a `u8`.
#[derive(Enumerated, Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum RoverInstrument {
	/// The Alpha Particle X-ray Spectrometer, which measures soil composition.
	Apxs = 0,
	/// The Chemistry Camera, a laser spectrometer.
	ChemCam = 1,
	/// The Mast Camera, which takes images.
	Mastcam = 2,
}

// Earth sends these command and control messages.

/// A command from Earth to the rover.
#[derive(Sequence, Clone, Debug, PartialEq)]
pub struct EarthCommand {
	/// The command type: 0 is `CollectSample`, 1 is `ProbeLocation`, 2 is
	/// `TakePhoto`, and 3 is `Standby`.
	pub command_type: u8,
	/// The parameters, in the format of the command type.
	pub parameters: OctetString,
	/// The priority of the command.
	pub priority: MessagePriority,
	/// The mission time in milliseconds at which Earth issues the command.
	pub mission_time_ms: u64,
}

/// An acknowledgment that the rover received a command.
#[derive(Sequence, Clone, Debug, PartialEq)]
pub struct CommandAck {
	/// The frame order of the command that this message acknowledges.
	pub command_order: u64,
}

impl EarthCommand {
	/// Creates a command from a typed [`RoverCommand`].
	///
	/// # Errors
	///
	/// - [`tightbeam::der::Error`] -- the parameters of `command` are longer than an OCTET STRING holds.
	pub fn new(command: RoverCommand, priority: MessagePriority, mission_time_ms: u64) -> tightbeam::der::Result<Self> {
		Ok(Self {
			command_type: command.command_type(),
			parameters: OctetString::new(command.encode_parameters())?,
			priority,
			mission_time_ms,
		})
	}
}

/// The rover command types, each encoded as a `u8` and its parameters.
#[derive(Clone, Default, Debug, PartialEq)]
pub enum RoverCommand {
	/// Collects a soil or rock sample at a location.
	CollectSample { location: String },
	/// Probes the given coordinates.
	ProbeLocation { x: i32, y: i32 },
	/// Takes a photo in a direction at a resolution.
	TakePhoto { direction: String, resolution: u16 },
	/// Enters standby mode, for a low power situation.
	#[default]
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
}

impl TryFrom<u8> for RoverCommand {
	type Error = TightBeamError;

	fn try_from(value: u8) -> Result<Self, Self::Error> {
		match value {
			0 => Ok(RoverCommand::CollectSample { location: "default".to_string() }),
			1 => Ok(RoverCommand::ProbeLocation { x: 0, y: 0 }),
			2 => Ok(RoverCommand::TakePhoto { direction: "forward".to_string(), resolution: 1024 }),
			3 => Ok(RoverCommand::Standby),
			_ => Err(TightBeamError::InvalidBody),
		}
	}
}

impl fmt::Display for RoverCommand {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let name = match self {
			RoverCommand::CollectSample { .. } => "CollectSample",
			RoverCommand::ProbeLocation { .. } => "ProbeLocation",
			RoverCommand::TakePhoto { .. } => "TakePhoto",
			RoverCommand::Standby => "Standby",
		};
		write!(f, "{}", name)
	}
}

// The relay servlet accepts these relay and network messages.

/// A request for missing frames, which recovers a gap in the chain.
#[derive(Sequence, Clone, Debug, PartialEq)]
pub struct FrameRequest {
	/// The hash of the last frame received intact, which is the chain head.
	pub requester_head: OctetString,
	/// The hash of the received frame that revealed the gap.
	pub last_received_hash: OctetString,
}

impl FrameRequest {
	/// A request for the frames between `requester_head` and
	/// `last_received_hash`.
	///
	/// # Errors
	///
	/// - [`tightbeam::der::Error`] -- a hash is longer than an OCTET STRING holds.
	pub fn new(
		requester_head: impl Into<Vec<u8>>,
		last_received_hash: impl Into<Vec<u8>>,
	) -> tightbeam::der::Result<Self> {
		Ok(Self {
			requester_head: OctetString::new(requester_head)?,
			last_received_hash: OctetString::new(last_received_hash)?,
		})
	}
}

/// A response that carries the missing frames.
#[derive(Sequence, Clone, Debug, PartialEq)]
pub struct FrameResponse {
	pub frames: Vec<Frame>,
}

/// The message types that the relay servlet accepts from Earth or the rover.
#[derive(Beamable, Choice, Clone, Debug, PartialEq)]
pub enum RelayMessage {
	/// A command from Earth that the relay forwards to the rover.
	#[asn1(context_specific = "0", constructed = "true")]
	Command(EarthCommand),
	/// Telemetry from the rover that the relay forwards to Earth.
	#[asn1(context_specific = "1", constructed = "true")]
	Telemetry(RoverTelemetry),
	/// An acknowledgment from the rover to Earth.
	#[asn1(context_specific = "2", constructed = "true")]
	CommandAck(CommandAck),
	/// A frame request from Earth.
	#[asn1(context_specific = "3", constructed = "true")]
	FrameRequest(FrameRequest),
	/// A frame response that carries the missing frames.
	#[asn1(context_specific = "4", constructed = "true")]
	FrameResponse(FrameResponse),
}

// Each node keeps a message chain, and the nodes reach consensus on it.

/// The message chain state of one node.
#[derive(Clone, Debug, PartialEq)]
pub struct MessageChainState {
	/// The hash of the last message in the chain.
	pub last_hash: [u8; 32],
	/// The sequence number of the last message in the chain.
	pub sequence: u64,
	/// The identifier of the node.
	pub node_id: String,
}

impl MessageChainState {
	pub fn new(node_id: impl Into<String>) -> Self {
		let node_id: String = node_id.into();
		Self { last_hash: [0u8; 32], sequence: 0, node_id }
	}

	/// Sets the chain head to `new_hash` and advances the sequence by one.
	/// Test scenarios may call it to set the chain state by hand, so it can go
	/// unused.
	#[allow(dead_code)]
	pub fn update(&mut self, new_hash: [u8; 32]) {
		self.last_hash = new_hash;
		self.sequence += 1;
	}

	/// Validates `frame` against the chain state.
	///
	/// The checks run in order:
	/// 1. The frame order is the next sequence number.
	/// 2. When the sequence is past 0, the `previous_frame` hash of the frame matches `last_hash`.
	pub fn validate_frame(&self, frame: &Frame) -> Result<bool, TightBeamError> {
		if frame.metadata().order() != self.sequence + 1 {
			return Ok(false);
		}

		// The first frame, at sequence 0, has no previous hash.
		if self.sequence == 0 {
			return Ok(true);
		}

		if let Some(digest_info) = frame.metadata().previous_frame() {
			let expected_hash = digest_info.digest.as_bytes();
			Ok(expected_hash == self.last_hash.as_slice())
		} else {
			// A frame past the first one must carry a `previous_frame` hash.
			Ok(false)
		}
	}

	/// Advances the chain state to `frame`.
	///
	/// The chain head becomes the SHA3-256 hash of the DER encoding of the
	/// frame, and the sequence becomes the order of the frame.
	pub fn update_with_frame(&mut self, frame: &Frame) -> Result<(), TightBeamError> {
		let frame_bytes = frame.to_der()?;
		let frame_hash = Sha3_256::digest(&frame_bytes);

		self.last_hash.copy_from_slice(&frame_hash);
		self.sequence = frame.metadata().order();

		Ok(())
	}
}

/// A consensus validator that needs two of the three nodes to agree on the
/// message chain.
#[derive(Clone, Debug, PartialEq)]
pub struct ConsensusValidator {
	pub rover_state: MessageChainState,
	pub earth_state: MessageChainState,
	pub relay_state: MessageChainState,
}

impl ConsensusValidator {
	/// Whether at least two of the three nodes hold `new_hash` as their chain
	/// head. Distributed scenarios may call it to check Byzantine fault
	/// tolerance, so it can go unused.
	#[allow(dead_code)]
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

	/// The number of nodes whose chain head is `hash`. Quorum analysis may call
	/// it, so it can go unused.
	#[allow(dead_code)]
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
		Self {
			rover_state: MessageChainState::new("rover".to_string()),
			earth_state: MessageChainState::new("earth".to_string()),
			relay_state: MessageChainState::new("relay".to_string()),
		}
	}
}

#[cfg(test)]
mod tests {
	use tightbeam::der::{asn1::Any, Decode, Encode, Tag, Tagged};
	use tightbeam::tb_cases;

	use super::*;
	use crate::dtn::storage::DtnPayload;
	use crate::dtn::workers::messages::{InstrumentSelection, TelemetryBuildRequest};
	use crate::dtn::workers::mission_control_telemetry_handler::NextCommand;

	/// The tags of the fields of the SEQUENCE that `message` encodes to.
	fn tags_of(message: &impl Encode) -> Vec<Tag> {
		let encoding = message.to_der().expect("a DTN message encodes");
		let fields = Vec::<Any>::from_der(&encoding).expect("a DTN message is a SEQUENCE");
		fields.iter().map(Any::tag).collect()
	}

	/// `bytes` as an OCTET STRING.
	fn octets(bytes: &[u8]) -> OctetString {
		OctetString::new(bytes).expect("a short value fits an OCTET STRING")
	}

	/// A sample telemetry reading of the APXS.
	fn sample_telemetry() -> RoverTelemetry {
		RoverTelemetry::new(RoverInstrument::Apxs, b"STATUS:OK", 1, 85, -20).expect("a short reading fits")
	}

	/// A sample command that takes parameters.
	fn sample_command() -> EarthCommand {
		let command = RoverCommand::ProbeLocation { x: 100, y: 200 };
		EarthCommand::new(command, MessagePriority::Standard, 1).expect("two coordinates fit")
	}

	/// A sample request for the frames past a gap.
	fn sample_frame_request() -> FrameRequest {
		FrameRequest::new([1; 32], [2; 32]).expect("two hashes fit")
	}

	/// A sample payload of the multi-hop tests.
	fn sample_payload() -> DtnPayload {
		DtnPayload::new(b"payload", "Earth", "Mars", 0).expect("a short payload fits")
	}

	/// A sample instrument selection with its sample data.
	fn sample_selection() -> InstrumentSelection {
		InstrumentSelection {
			instrument: RoverInstrument::ChemCam,
			instrument_name: "ChemCam".to_string(),
			sample_data: octets(&[1, 2, 3]),
		}
	}

	/// A sample request to build a telemetry reading.
	fn sample_build_request() -> TelemetryBuildRequest {
		TelemetryBuildRequest {
			instrument: RoverInstrument::Mastcam,
			data: octets(&[1, 2, 3]),
			mission_time_ms: 1,
		}
	}

	/// A sample next command of Mission Control.
	fn sample_next_command() -> NextCommand {
		NextCommand {
			command: 1,
			parameters: octets(&[0, 0, 0, 100]),
			priority: MessagePriority::Standard,
		}
	}

	// Each byte field of a DTN message encodes as an OCTET STRING, so the tags
	// of a message's fields are its schema.
	tb_cases! {
		fn a_message_encodes_its_bytes_as_octet_strings((tags, schema): (Vec<Tag>, Vec<Tag>)) {
			assert_eq!(tags, schema);
		}
		cases {
			rover_telemetry => (
				tags_of(&sample_telemetry()),
				vec![Tag::Integer, Tag::OctetString, Tag::Integer, Tag::Integer, Tag::Integer],
			),
			earth_command => (
				tags_of(&sample_command()),
				vec![Tag::Integer, Tag::OctetString, Tag::Enumerated, Tag::Integer],
			),
			frame_request => (tags_of(&sample_frame_request()), vec![Tag::OctetString, Tag::OctetString]),
			dtn_payload => (
				tags_of(&sample_payload()),
				vec![Tag::OctetString, Tag::Utf8String, Tag::Utf8String, Tag::Integer],
			),
			instrument_selection => (
				tags_of(&sample_selection()),
				vec![Tag::Enumerated, Tag::Utf8String, Tag::OctetString],
			),
			telemetry_build_request => (
				tags_of(&sample_build_request()),
				vec![Tag::Enumerated, Tag::OctetString, Tag::Integer],
			),
			next_command => (tags_of(&sample_next_command()), vec![Tag::Integer, Tag::OctetString, Tag::Enumerated]),
		}
	}
}
