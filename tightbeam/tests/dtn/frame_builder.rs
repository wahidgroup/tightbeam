//! The frame builder of the DTN nodes.
//!
//! [`FrameBuilderHelper`] signs, encrypts, and compresses each relay message
//! frame, and links a frame of the chain to the frame before it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tightbeam::{
	asn1::{DigestInfo, Frame},
	builder::{frame::FrameBuilder, TypeBuilder},
	compress::ZstdCompression,
	crypto::{
		hash::Sha3_256,
		sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey},
	},
	matrix::MatrixDyn,
	prelude::Version,
	TightBeamError,
};

use crate::dtn::{
	certs::SharedCipher,
	chain_processor::ChainProcessor,
	fault_matrix::FaultMatrix,
	messages::{CommandAck, EarthCommand, FrameRequest, FrameResponse, RelayMessage, RoverTelemetry, StatelessAck},
};

/// The frame builder of one DTN node, bound to the chain processor of that
/// node.
pub struct FrameBuilderHelper {
	pub chain_processor: Arc<ChainProcessor>,
	/// The order of the next frame request of the node, which numbers its
	/// requests from 1 for the request gate of each hop.
	next_request: AtomicU64,
}

/// Sets the hashers, the compression, the cipher, and the signer of a relay
/// frame, and its `previous_frame` hash when the frame has a predecessor.
macro_rules! apply_common_builder_patterns {
	($builder:expr, $previous_digest:expr, $signing_key:expr, $cipher:expr) => {{
		let mut builder = $builder
			.with_message_hasher::<Sha3_256>([])
			.with_witness_hasher::<Sha3_256>()
			.with_compression(ZstdCompression::default())
			.with_encryptor($cipher.to_owned())
			.with_signer::<Secp256k1Signature, _>(tightbeam::testing::TestIdentity::certified($signing_key.to_owned()));

		// Only a frame with a predecessor carries a `previous_frame` hash.
		if let Some(digest) = $previous_digest {
			builder = builder.with_previous_hash(digest);
		}

		builder
	}};
}

impl FrameBuilderHelper {
	/// A builder over `chain_processor`, whose first frame request takes
	/// order 1.
	pub fn new(chain_processor: Arc<ChainProcessor>) -> Self {
		Self { chain_processor, next_request: AtomicU64::new(1) }
	}

	/// Records `frame` as the head of the chain of this node through
	/// [`ChainProcessor::finalize_outgoing`], and returns it.
	fn finalize_frame(&self, frame: Frame) -> Result<Frame, TightBeamError> {
		self.chain_processor.finalize_outgoing(&frame)?;
		Ok(frame)
	}

	/// Builds a frame request for the missing frames of a gap.
	///
	/// The request travels hop to hop outside the chain, so this node's chain
	/// stays as it was. Its order is this node's next request order, which the
	/// hop's request gate checks.
	pub fn build_frame_request_frame(
		&self,
		request: FrameRequest,
		signing_key: &Secp256k1SigningKey,
		cipher: &SharedCipher,
	) -> Result<Frame, TightBeamError> {
		let relay_message = RelayMessage::FrameRequest(request);
		let order = self.next_request.fetch_add(1, Ordering::Relaxed);
		let builder = FrameBuilder::from(Version::V3)
			.with_id("frame-req")
			.with_order(order)
			.with_message(relay_message);

		let builder = apply_common_builder_patterns!(builder, None::<DigestInfo>, signing_key, cipher);
		builder.build()
	}

	/// Builds the answer to a frame request, which carries the missing frames
	/// of a gap.
	///
	/// The answer travels back to the requester outside the chain. Its frames
	/// fill the gap, and this node's chain stays as it was.
	pub fn build_frame_response_frame(
		&self,
		response: FrameResponse,
		signing_key: &Secp256k1SigningKey,
		cipher: &SharedCipher,
	) -> Result<Frame, TightBeamError> {
		let relay_message = RelayMessage::FrameResponse(response);
		let builder = FrameBuilder::from(Version::V3)
			.with_id("frame-resp")
			.with_message(relay_message);

		let builder = apply_common_builder_patterns!(builder, None::<DigestInfo>, signing_key, cipher);
		builder.build()
	}

	/// Builds the chain frame of `command`, which Earth sends, and records it
	/// in the chain of this node.
	pub fn build_relay_command_frame(
		&self,
		command: EarthCommand,
		next_order: u64,
		previous_digest: Option<DigestInfo>,
		signing_key: &Secp256k1SigningKey,
		cipher: &SharedCipher,
	) -> Result<Frame, TightBeamError> {
		let relay_message = RelayMessage::Command(command.to_owned());
		let builder = FrameBuilder::from(Version::V3)
			.with_id(format!("relay-cmd-{:03}", next_order))
			.with_order(next_order)
			.with_priority(command.priority)
			.with_message(relay_message);

		let builder = apply_common_builder_patterns!(builder, previous_digest, signing_key, cipher);
		let frame = builder.build()?;
		self.finalize_frame(frame)
	}

	/// Builds the chain frame of the Rover's ACK of the command at
	/// `command_order`, and records it in the chain of this node.
	pub fn build_relay_ack_frame(
		&self,
		command_order: u64,
		next_order: u64,
		previous_digest: Option<DigestInfo>,
		signing_key: &Secp256k1SigningKey,
		cipher: &SharedCipher,
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

	/// Builds the chain frame of the Rover's `telemetry`, with `fault_matrix`
	/// as its matrix, and records it in the chain of this node.
	pub fn build_relay_telemetry_frame(
		&self,
		telemetry: RoverTelemetry,
		fault_matrix: FaultMatrix,
		next_order: u64,
		previous_digest: Option<DigestInfo>,
		signing_key: &Secp256k1SigningKey,
		cipher: &SharedCipher,
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

	/// Builds the stateless ACK of the frame at `ack_for_order`, which a relay
	/// sends back at once, outside the chain.
	pub fn build_stateless_ack_frame(&self, ack_for_order: u64) -> Result<Frame, TightBeamError> {
		// The ACK carries one flag and no order or `previous_frame`, so it
		// stays outside the chain.
		let ack = StatelessAck { ack: true };
		let frame = FrameBuilder::from(Version::V3)
			.with_id(format!("stateless-ack-{}", ack_for_order))
			.with_message(ack)
			.build()?;

		Ok(frame)
	}
}
