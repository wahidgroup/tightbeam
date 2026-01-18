//! Frame building helper for DTN messages
//!
//! Encapsulates frame building logic with chain support and compression

use std::sync::Arc;

use tightbeam::{
	asn1::{DigestInfo, Frame},
	builder::{frame::FrameBuilder, TypeBuilder},
	compress::ZstdCompression,
	crypto::{
		aead::{Aes256Gcm, Aes256GcmOid},
		hash::Sha3_256,
		sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey},
	},
	matrix::MatrixDyn,
	prelude::Version,
	TightBeamError,
};

use crate::dtn::{
	chain_processor::ChainProcessor,
	fault_matrix::FaultMatrix,
	messages::{CommandAck, EarthCommand, FrameRequest, FrameResponse, RelayMessage, RoverTelemetry, StatelessAck},
};

/// Helper for building frames with chain support and compression
pub struct FrameBuilderHelper {
	pub chain_processor: Arc<ChainProcessor>,
}

/// Macro to apply common builder patterns (hashers, cipher, signer, compression, previous_hash)
macro_rules! apply_common_builder_patterns {
	($builder:expr, $previous_digest:expr, $signing_key:expr, $cipher:expr) => {{
		let mut builder = $builder
			.with_message_hasher::<Sha3_256>()
			.with_witness_hasher::<Sha3_256>()
			.with_compression(ZstdCompression)
			.with_aead::<Aes256GcmOid, _>($cipher.to_owned())
			.with_signer::<Secp256k1Signature, _>($signing_key.to_owned());

		// Set previous_frame if not the first frame
		if let Some(digest) = $previous_digest {
			builder = builder.with_previous_hash(digest);
		}

		builder
	}};
}

impl FrameBuilderHelper {
	/// Create a new FrameBuilderHelper
	pub fn new(chain_processor: Arc<ChainProcessor>) -> Self {
		Self { chain_processor }
	}

	/// Apply common builder patterns (hashers, cipher, signer, compression, previous_hash)
	/// and finalize the frame
	fn finalize_frame(&self, frame: Frame) -> Result<Frame, TightBeamError> {
		// Finalize outgoing frame
		self.chain_processor.finalize_outgoing(&frame)?;
		Ok(frame)
	}

	/// Build a frame request for missing frames (chain gap recovery)
	pub fn build_frame_request_frame(
		&self,
		request: FrameRequest,
		next_order: u64,
		previous_digest: Option<DigestInfo>,
		signing_key: &Secp256k1SigningKey,
		cipher: &Aes256Gcm,
	) -> Result<Frame, TightBeamError> {
		let relay_message = RelayMessage::FrameRequest(request);
		let builder = FrameBuilder::from(Version::V3)
			.with_id(format!("frame-req-{:03}", next_order))
			.with_order(next_order)
			.with_message(relay_message);

		let builder = apply_common_builder_patterns!(builder, previous_digest, signing_key, cipher);
		let frame = builder.build()?;
		self.finalize_frame(frame)
	}

	/// Build a frame response with missing frames (chain gap recovery)
	pub fn build_frame_response_frame(
		&self,
		response: FrameResponse,
		next_order: u64,
		previous_digest: Option<DigestInfo>,
		signing_key: &Secp256k1SigningKey,
		cipher: &Aes256Gcm,
	) -> Result<Frame, TightBeamError> {
		let relay_message = RelayMessage::FrameResponse(response);
		let builder = FrameBuilder::from(Version::V3)
			.with_id(format!("frame-resp-{:03}", next_order))
			.with_order(next_order)
			.with_message(relay_message);

		let builder = apply_common_builder_patterns!(builder, previous_digest, signing_key, cipher);
		let frame = builder.build()?;
		self.finalize_frame(frame)
	}

	/// Build a relay message frame (for async Earth-initiated commands)
	pub fn build_relay_command_frame(
		&self,
		command: EarthCommand,
		next_order: u64,
		previous_digest: Option<DigestInfo>,
		signing_key: &Secp256k1SigningKey,
		cipher: &Aes256Gcm,
	) -> Result<Frame, TightBeamError> {
		let relay_message = RelayMessage::Command(command.clone());
		let builder = FrameBuilder::from(Version::V3)
			.with_id(format!("relay-cmd-{:03}", next_order))
			.with_order(next_order)
			.with_priority(command.priority)
			.with_message(relay_message);

		let builder = apply_common_builder_patterns!(builder, previous_digest, signing_key, cipher);
		let frame = builder.build()?;
		self.finalize_frame(frame)
	}

	/// Build a relay ACK frame (Rover acknowledges command)
	pub fn build_relay_ack_frame(
		&self,
		command_order: u64,
		next_order: u64,
		previous_digest: Option<DigestInfo>,
		signing_key: &Secp256k1SigningKey,
		cipher: &Aes256Gcm,
	) -> Result<Frame, TightBeamError> {
		let ack = CommandAck { command_order };
		let relay_message = RelayMessage::CommandAck(ack);
		let builder = FrameBuilder::from(Version::V3)
			.with_id(format!("relay-ack-{:03}", next_order))
			.with_order(next_order)
			.with_message(relay_message);

		let builder = apply_common_builder_patterns!(builder, previous_digest, signing_key, cipher);
		let frame = builder.build()?;
		self.finalize_frame(frame)
	}

	/// Build a relay telemetry frame (Rover sends telemetry)
	pub fn build_relay_telemetry_frame(
		&self,
		telemetry: RoverTelemetry,
		fault_matrix: FaultMatrix,
		next_order: u64,
		previous_digest: Option<DigestInfo>,
		signing_key: &Secp256k1SigningKey,
		cipher: &Aes256Gcm,
	) -> Result<Frame, TightBeamError> {
		let matrix_dyn = MatrixDyn::try_from(fault_matrix)?;
		let relay_message = RelayMessage::Telemetry(telemetry);
		let builder = FrameBuilder::from(Version::V3)
			.with_id(format!("relay-telem-{:03}", next_order))
			.with_order(next_order)
			.with_message(relay_message)
			.with_matrix(matrix_dyn);

		let builder = apply_common_builder_patterns!(builder, previous_digest, signing_key, cipher);
		let frame = builder.build()?;
		self.finalize_frame(frame)
	}

	/// Build a stateless ACK frame (metadata-only, not added to chain)
	/// Used for immediate acknowledgment responses at relay nodes
	pub fn build_stateless_ack_frame(&self, ack_for_order: u64) -> Result<Frame, TightBeamError> {
		// Metadata-only frame with minimal message body
		// Not added to chain (no order, no previous_hash)
		let ack = StatelessAck { ack: true };
		let frame = FrameBuilder::from(Version::V3)
			.with_id(format!("stateless-ack-{}", ack_for_order))
			.with_message(ack)
			.build()?;

		Ok(frame)
	}
}
