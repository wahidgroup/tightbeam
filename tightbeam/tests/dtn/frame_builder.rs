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
	messages::{EarthCommand, FrameRequest, FrameResponse, RelayMessage, RoverTelemetry},
	utils::generate_message_id,
};

/// Helper for building frames with chain support and compression
pub struct FrameBuilderHelper {
	chain_processor: Arc<ChainProcessor>,
}

/// Macro to apply common builder patterns (hashers, cipher, signer, compression, previous_hash)
macro_rules! apply_common_builder_patterns {
	($builder:expr, $previous_digest:expr, $signing_key:expr, $cipher:expr) => {{
		let mut builder = $builder
			.with_message_hasher::<Sha3_256>()
			.with_witness_hasher::<Sha3_256>()
			.with_compression(ZstdCompression)
			.with_cipher::<Aes256GcmOid, _>($cipher.to_owned())
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

	/// Build a telemetry frame from rover
	pub fn build_telemetry_frame(
		&self,
		telemetry: RoverTelemetry,
		fault_matrix: FaultMatrix,
		signing_key: &Secp256k1SigningKey,
		cipher: &Aes256Gcm,
	) -> Result<Frame, TightBeamError> {
		let (next_order, previous_digest) = self.chain_processor.prepare_outgoing()?;
		let matrix_dyn = MatrixDyn::try_from(fault_matrix)?;

		let builder = FrameBuilder::from(Version::V3)
			.with_id(generate_message_id("telemetry", "rover"))
			.with_order(next_order)
			.with_message(telemetry)
			.with_matrix(matrix_dyn);

		let builder = apply_common_builder_patterns!(builder, previous_digest, signing_key, cipher);
		let frame = builder.build()?;
		self.finalize_frame(frame)
	}

	/// Build a command frame from earth
	pub fn build_command_frame(
		&self,
		command: EarthCommand,
		next_order: u64,
		previous_digest: Option<DigestInfo>,
		signing_key: &Secp256k1SigningKey,
		cipher: &Aes256Gcm,
	) -> Result<Frame, TightBeamError> {
		let builder = FrameBuilder::from(Version::V3)
			.with_id(format!("earth-cmd-{:03}", next_order))
			.with_order(next_order)
			.with_priority(command.priority)
			.with_message(command);

		let builder = apply_common_builder_patterns!(builder, previous_digest, signing_key, cipher);
		let frame = builder.build()?;
		self.finalize_frame(frame)
	}

	/// Build a frame request for missing frames (chain gap recovery)
	pub fn build_frame_request_frame(
		&self,
		request: FrameRequest,
		next_order: u64,
		previous_digest: Option<DigestInfo>,
		signing_key: &Secp256k1SigningKey,
	) -> Result<Frame, TightBeamError> {
		let builder = FrameBuilder::from(Version::V3)
			.with_id(format!("frame-req-{:03}", next_order))
			.with_order(next_order)
			.with_message(request)
			.with_message_hasher::<Sha3_256>()
			.with_witness_hasher::<Sha3_256>()
			.with_signer::<Secp256k1Signature, _>(signing_key.to_owned());

		let builder = if let Some(digest) = previous_digest {
			builder.with_previous_hash(digest)
		} else {
			builder
		};

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
	) -> Result<Frame, TightBeamError> {
		let builder = FrameBuilder::from(Version::V3)
			.with_id(format!("frame-resp-{:03}", next_order))
			.with_order(next_order)
			.with_message(response)
			.with_message_hasher::<Sha3_256>()
			.with_witness_hasher::<Sha3_256>()
			.with_compression(ZstdCompression)
			.with_signer::<Secp256k1Signature, _>(signing_key.to_owned());

		let builder = if let Some(digest) = previous_digest {
			builder.with_previous_hash(digest)
		} else {
			builder
		};

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
		// Wrap command in RelayMessage
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
}
