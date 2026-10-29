//! The frames that a DTN node takes in from a peer.
//!
//! [`Intake::open`] opens a frame once and sorts it by its message. A command,
//! telemetry, or an ACK becomes a [`ChainFrame`], the one input of a node's
//! chain. A frame request and a frame response travel hop to hop outside the
//! chain.

use core::borrow::Borrow;

use tightbeam::asn1::Frame;
use tightbeam::compress::{Inflator, ZstdCompression};
use tightbeam::TightBeamError;

use crate::dtn::certs::{FrameSigner, SharedCipher};
use crate::dtn::messages::{ChainMessage, FrameRequest, FrameResponse, RelayMessage};
use crate::dtn::nodes::{DtnRole, PathSide};

/// A frame that the signer of a peer verifies, with the side and the role of
/// that peer.
///
/// Only [`SignedFrame::check`] makes one, so a side always comes from a check.
#[derive(Debug)]
pub struct SignedFrame {
	/// The frame, as it arrived.
	frame: Frame,
	/// The side of the node that the peer sits on.
	side: PathSide,
	/// The role of the peer.
	role: DtnRole,
}

impl SignedFrame {
	/// Checks `frame` against `peers` in order, and keeps the first peer whose
	/// signer verifies it.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingSignature`] -- no signer of `peers` verifies the frame.
	pub fn check<'a>(
		frame: Frame,
		peers: impl IntoIterator<Item = (PathSide, DtnRole, &'a FrameSigner)>,
	) -> Result<Self, TightBeamError> {
		let mut peers = peers.into_iter();
		let signer = peers.find(|(_, _, signer)| frame.verify(*signer).is_ok());
		let (side, role, _) = signer.ok_or(TightBeamError::MissingSignature)?;

		Ok(Self { frame, side, role })
	}

	/// Checks `frame` against the signer of `role` as the peer on `side`.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingSignature`] -- the signer of `role` fails to verify the frame.
	pub fn from_peer(frame: Frame, role: DtnRole, side: PathSide) -> Result<Self, TightBeamError> {
		let signer = role.signer();
		Self::check(frame, [(side, role, &signer)])
	}

	/// The frame, as it arrived.
	pub fn frame(&self) -> &Frame {
		&self.frame
	}

	/// The side of the node that the peer sits on.
	pub fn side(&self) -> PathSide {
		self.side
	}

	/// The role of the peer.
	pub fn role(&self) -> DtnRole {
		self.role
	}
}

/// What a node takes in from a peer, sorted by the message of the frame.
// An intake lives for one match, so its frame of the chain stays inline, off
// the heap.
#[allow(clippy::large_enum_variant)]
pub enum Intake {
	/// A frame of the chain, with its message.
	Chain(ChainFrame),
	/// A request for the frames of a gap, which the node answers at once.
	Request(FrameRequest),
	/// The answer to a frame request, which comes back as the reply to that
	/// request alone.
	Response(FrameResponse),
}

impl Intake {
	/// Opens `signed` under `cipher`, or decodes it when the frame is
	/// cleartext, and sorts it by its message.
	///
	/// The decrypt opens its buffer in place, so a sealed frame opens in a
	/// copy and the chain keeps the sealed frame its hash covers.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the frame fails to decrypt, to inflate, or to decode as a [`RelayMessage`].
	pub async fn open(signed: SignedFrame, cipher: &SharedCipher) -> Result<Self, TightBeamError> {
		let SignedFrame { frame, side, .. } = signed;
		let message = Self::message_of(&frame, cipher).await?;
		let intake = match message {
			RelayMessage::Command(command) => Self::chain(frame, ChainMessage::Command(command), side),
			RelayMessage::Telemetry(telemetry) => Self::chain(frame, ChainMessage::Telemetry(telemetry), side),
			RelayMessage::CommandAck(ack) => Self::chain(frame, ChainMessage::CommandAck(ack), side),
			RelayMessage::FrameRequest(request) => Self::Request(request),
			RelayMessage::FrameResponse(response) => Self::Response(response),
		};

		Ok(intake)
	}

	/// A frame of the chain that carries `message` and arrives from `side`.
	fn chain(frame: Frame, message: ChainMessage, side: PathSide) -> Self {
		Self::Chain(ChainFrame { frame, message, side })
	}

	/// The relay message that `frame` carries.
	async fn message_of(frame: &Frame, cipher: &SharedCipher) -> Result<RelayMessage, TightBeamError> {
		if frame.metadata().confidentiality().is_none() {
			return frame.decode_message();
		}

		let zstd = ZstdCompression::default();
		let inflator: Option<&(dyn Inflator + Sync)> = if frame.metadata().compactness().is_some() {
			Some(&zstd)
		} else {
			None
		};

		frame.to_owned().decrypt::<RelayMessage>(cipher, inflator).await
	}
}

/// A frame that takes a place in the chain, with its chain message and the
/// side it arrives from.
///
/// [`Intake::open`] makes each one from a [`SignedFrame`], so its side comes
/// from the signer check.
#[derive(Debug)]
pub struct ChainFrame {
	/// The sealed frame, as it arrived.
	frame: Frame,
	/// The chain message that the frame seals.
	message: ChainMessage,
	/// The side of the node that the frame arrives from.
	side: PathSide,
}

impl ChainFrame {
	/// Opens `signed` under `cipher` as a frame of the chain.
	///
	/// # Errors
	///
	/// - [`TightBeamError::InvalidBody`] -- the frame carries a frame request
	///   or a frame response, which travels outside the chain.
	/// - The errors of [`Intake::open`].
	pub async fn open(signed: SignedFrame, cipher: &SharedCipher) -> Result<Self, TightBeamError> {
		match Intake::open(signed, cipher).await? {
			Intake::Chain(entry) => Ok(entry),
			Intake::Request(_) | Intake::Response(_) => Err(TightBeamError::InvalidBody),
		}
	}

	/// The sealed frame, as it arrived.
	pub fn frame(&self) -> &Frame {
		&self.frame
	}

	/// The chain message that the frame seals.
	pub fn message(&self) -> &ChainMessage {
		&self.message
	}

	/// The order of the frame in its chain.
	pub fn order(&self) -> u64 {
		self.frame.metadata().order()
	}

	/// The side of the node that the frame arrives from.
	pub fn side(&self) -> PathSide {
		self.side
	}

	/// The sealed frame, which a relay sends on.
	pub fn into_frame(self) -> Frame {
		self.frame
	}

	/// The chain message that the frame seals, which an endpoint of the path
	/// acts on.
	pub fn into_message(self) -> ChainMessage {
		self.message
	}
}

impl Borrow<Frame> for ChainFrame {
	fn borrow(&self) -> &Frame {
		&self.frame
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::dtn::certs::generate_shared_cipher;
	use crate::dtn::nodes::NodeChain;
	use crate::dtn::storage::StorageRoot;

	/// A frame request that the Mars Relay signs, for the frames between two
	/// fixed test hashes.
	fn frame_request(cipher: &SharedCipher) -> Frame {
		let root = StorageRoot::create().expect("the storage root opens");
		let chain = NodeChain::open(&root, "requester").expect("a node chain opens");
		let request = FrameRequest::new([1; 32], [2; 32]).expect("two hashes fit an OCTET STRING");
		let key = DtnRole::MarsRelay.signing_key();
		let frame = chain.frame_builder.build_frame_request_frame(request, &key, cipher);
		frame.expect("a frame request builds")
	}

	/// A frame request fails to open as a frame of the chain.
	#[tokio::test]
	async fn a_frame_request_opens_as_no_frame_of_the_chain() -> Result<(), TightBeamError> {
		let cipher = generate_shared_cipher();
		let request = SignedFrame::from_peer(frame_request(&cipher), DtnRole::MarsRelay, PathSide::Mars)?;

		let opened = ChainFrame::open(request, &cipher).await;
		assert!(matches!(opened, Err(TightBeamError::InvalidBody)));
		Ok(())
	}

	/// A frame takes the side of the peer whose signer verifies it.
	#[tokio::test]
	async fn a_frame_takes_the_side_of_the_peer_whose_signer_verifies_it() -> Result<(), TightBeamError> {
		let cipher = generate_shared_cipher();
		let mission_control = DtnRole::MissionControl.signer();
		let mars_relay = DtnRole::MarsRelay.signer();
		let earth = (PathSide::Earth, DtnRole::MissionControl, &mission_control);
		let mars = (PathSide::Mars, DtnRole::MarsRelay, &mars_relay);

		let signed = SignedFrame::check(frame_request(&cipher), [earth, mars])?;
		assert_eq!(signed.side(), PathSide::Mars);
		Ok(())
	}
}
