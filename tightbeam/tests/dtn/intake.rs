//! The frames that a DTN node takes in from a peer.
//!
//! [`Intake::open`] opens a frame once and sorts it by its message. A command,
//! telemetry, or an ACK becomes a [`ChainFrame`], the one input of a node's
//! chain. A frame request and a frame response travel hop to hop outside the
//! chain.

use core::borrow::Borrow;

use tightbeam::asn1::Frame;
use tightbeam::compress::{Inflator, ZstdCompression};
use tightbeam::runtime::rt;
use tightbeam::TightBeamError;

use crate::dtn::certs::{generate_shared_cipher, FrameSigner, SharedCipher};
use crate::dtn::fault_matrix::FaultMatrix;
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
	/// - [`TightBeamError::MissingSignature`] -- Mission Control does not sign the command of the frame.
	/// - [`TightBeamError`] -- the frame fails to decrypt, to inflate, or to decode as a [`RelayMessage`].
	pub async fn open(signed: SignedFrame, cipher: &SharedCipher) -> Result<Self, TightBeamError> {
		let SignedFrame { frame, side, role } = signed;
		let message = Self::message_of(&frame, cipher).await?;
		let intake = match message {
			// Mission Control alone issues a command.
			RelayMessage::Command(_) if role != DtnRole::MissionControl => {
				return Err(TightBeamError::MissingSignature);
			}
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
#[derive(Debug, PartialEq)]
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

	/// `frame` as a node takes it from the peer `signer` on `side`, opened
	/// under the shared cipher of the path. It expects the signer of the peer
	/// to verify the frame and the frame to open as a frame of the chain.
	pub fn arriving(frame: &Frame, signer: DtnRole, side: PathSide) -> Self {
		let signed = SignedFrame::from_peer(frame.to_owned(), signer, side);
		let signed = signed.expect("the signer of the peer verifies the frame");
		let entry = rt::block_on(Self::open(signed, &generate_shared_cipher()));
		entry.expect("the frame opens as a frame of the chain")
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

	/// The fault flags in the matrix of the frame.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the flags fail to read from the matrix.
	pub fn fault_matrix(&self) -> Result<FaultMatrix, TightBeamError> {
		FaultMatrix::try_from(&self.frame.metadata().matrix().cloned())
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

mod tests {
	use super::*;
	use crate::common::result::TestResult;
	use crate::dtn::nodes::NodeChain;
	use crate::dtn::storage::StorageRoot;

	/// A frame request that the Mars Relay signs.
	fn frame_request() -> Frame {
		let root = StorageRoot::create().expect("the storage root opens");
		let chain = NodeChain::open(&root, "requester").expect("a node chain opens");
		chain.frame_request(DtnRole::MarsRelay)
	}

	/// A frame request fails to open as a frame of the chain.
	#[test]
	fn a_frame_request_opens_as_no_frame_of_the_chain() -> TestResult {
		let cipher = generate_shared_cipher();
		let request = SignedFrame::from_peer(frame_request(), DtnRole::MarsRelay, PathSide::Mars)?;

		let opened = rt::block_on(ChainFrame::open(request, &cipher));
		assert!(matches!(opened, Err(TightBeamError::InvalidBody)));
		Ok(())
	}

	/// A command that the Mars Relay signs fails to open, because Mission
	/// Control alone issues a command.
	#[test]
	fn a_command_that_a_relay_signs_opens_as_missing_its_signature() -> TestResult {
		let root = StorageRoot::create()?;
		let chain = NodeChain::open(&root, "relay")?;
		let command = chain.command_signed_by(&DtnRole::MarsRelay.signing_key());
		let signed = SignedFrame::from_peer(command, DtnRole::MarsRelay, PathSide::Earth)?;

		let opened = rt::block_on(ChainFrame::open(signed, &generate_shared_cipher()));
		assert!(matches!(opened, Err(TightBeamError::MissingSignature)));
		Ok(())
	}

	/// A frame takes the side of the peer whose signer verifies it.
	#[test]
	fn a_frame_takes_the_side_of_the_peer_whose_signer_verifies_it() -> TestResult {
		let mission_control = DtnRole::MissionControl.signer();
		let mars_relay = DtnRole::MarsRelay.signer();
		let earth = (PathSide::Earth, DtnRole::MissionControl, &mission_control);
		let mars = (PathSide::Mars, DtnRole::MarsRelay, &mars_relay);

		let signed = SignedFrame::check(frame_request(), [earth, mars])?;
		assert_eq!(signed.side(), PathSide::Mars);
		Ok(())
	}
}
