//! # Multi-hop delay tolerance
//!
//! These tests carry a signed chain of frames across the hops of a DTN path.
//!
//! ## Test Scenario: Earth to Mars Through a Relay
//!
//! The tests simulate interplanetary links with:
//! - **Hop delays** of 100 ms on a paused clock, in place of light-time delays.
//! - **Filesystem persistence** at each hop, where each frame reads back from disk.
//! - **Signature and chain verification** at the final destination.
//!
//! ## What This Proves
//!
//! - A signed chain crosses two stores and verifies at Mars with no custody transfer.
//! - A bit that a relay flips in a frame breaks the signature of its sender and the link of the next frame.
//!
//! `FrameStore::verify_chain` is test code over the `previous_frame` digest of
//! each frame, and `Frame::verify` is the check of tightbeam.
//! `a_wrong_previous_hash_breaks_the_chain_at_its_link` is a self-check of the
//! harness.

use std::time::Duration;

use tightbeam::asn1::Frame;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::sign::SignerError;
use tightbeam::der::Encode;
use tightbeam::testing::TestFrame;
use tightbeam::utils::digest;
use tightbeam::TightBeamError;

use crate::common::dedup::HarnessFrame;
use crate::common::result::TestResult;
use crate::dtn::delay::DelaySimulator;
use crate::dtn::nodes::{DtnRole, NodeChain};
use crate::dtn::storage::{ChainVerdict, FrameKey, LinkBreak, StorageRoot};

/// The delay of each hop on the paused clock.
const HOP_DELAY: Duration = Duration::from_millis(100);

/// Moves each frame of `keys` from a reopened store of the node `from` into
/// the store of the node `to`, so a frame of the chain sits on one disk.
///
/// # Errors
///
/// - [`TightBeamError`] -- a frame fails to read, to write, or to leave the store of `from`.
fn carry(root: &StorageRoot, from: &str, to: &str, keys: &[FrameKey]) -> Result<(), TightBeamError> {
	let mut source = root.store(from);
	let mut destination = root.store(to);
	for key in keys {
		destination.persist(source.retrieve(key)?)?;
	}

	source.clear()
}

/// The frames of `keys`, each read back from a reopened store of the node
/// `node`.
///
/// # Errors
///
/// - [`TightBeamError`] -- a frame fails to read or to decode.
fn read_back(root: &StorageRoot, node: &str, keys: &[FrameKey]) -> Result<Vec<Frame>, TightBeamError> {
	let mut store = root.store(node);
	keys.iter().map(|key| store.retrieve(key)).collect()
}

/// `frame` with the last bit of its sealed body flipped, as a relay that alters
/// the frame leaves it.
fn with_a_flipped_body_bit(frame: &Frame) -> Frame {
	let mut forged = frame.message().to_vec();
	if let Some(last) = forged.last_mut() {
		*last ^= 1;
	}

	TestFrame::tamper(frame, frame.message(), forged)
}

/// A signed chain that a relay stores and forwards reads back from the disk of
/// each hop and verifies at Mars, with each hop delayed on the paused clock.
#[tokio::test(start_paused = true)]
async fn a_chain_relayed_through_two_stores_verifies_at_mars() -> TestResult {
	// Mission Control signs two linked frames into the store of Earth.
	let root = StorageRoot::create()?;
	let earth = NodeChain::open(&root, "earth")?;
	let first = earth.command();
	let second = earth.command();
	let keys = [FrameKey::of(&first), FrameKey::of(&second)];
	let signer = DtnRole::MissionControl.signer();

	// The simulator delays each hop by 100 ms on the paused clock.
	let mut delays = DelaySimulator::new();
	delays.configure_delay("Earth->Relay", HOP_DELAY);
	delays.configure_delay("Relay->Mars", HOP_DELAY);
	let start = tokio::time::Instant::now();

	delays.simulate_hop("Earth", "Relay").await;
	carry(&root, "earth", "relay", &keys)?;
	delays.simulate_hop("Relay", "Mars").await;
	carry(&root, "relay", "mars", &keys)?;

	// Mars reads the chain from its own disk and verifies it.
	let chain = read_back(&root, "mars", &keys)?;
	let signed = chain.iter().filter(|frame| frame.verify(&signer).is_ok()).count();
	let verdict = root.store("mars").verify_chain(&chain)?;
	let broken_links = Vec::new();
	assert_eq!(start.elapsed(), HOP_DELAY * 2);
	assert_eq!(signed, 2);
	assert_eq!(verdict, ChainVerdict { valid: true, broken_links, verified_count: 2 });
	Ok(())
}

/// A bit that a relay flips in a frame breaks the signature of the sender at
/// the signed attributes, and breaks the link of the next frame.
/// `a_chain_relayed_through_two_stores_verifies_at_mars` is the control: the
/// same two frames verify when no relay alters them.
#[test]
fn a_bit_that_a_relay_flips_breaks_the_signature_and_the_link() -> TestResult {
	let root = StorageRoot::create()?;
	let earth = NodeChain::open(&root, "earth")?;
	let first = earth.command();
	let second = earth.command();
	let signer = DtnRole::MissionControl.signer();
	let chain = [with_a_flipped_body_bit(&first), second];

	let signature = chain[0].verify(&signer);
	let verdict = root.store("mars").verify_chain(&chain)?;
	let broken_links = vec![(1, LinkBreak::HashMismatch)];
	assert!(matches!(signature, Err(TightBeamError::Signer(SignerError::SignedAttributes))));
	assert_eq!(verdict, ChainVerdict { valid: false, broken_links, verified_count: 1 });
	Ok(())
}

/// A chain whose frame 3 carries a wrong `previous_frame` hash breaks at that
/// link.
#[test]
fn a_wrong_previous_hash_breaks_the_chain_at_its_link() -> TestResult {
	let root = StorageRoot::create()?;
	let store = root.store("store");

	// Frames 1 and 2 form a valid chain.
	let frame1 = HarnessFrame::at("frame-1", 1, "first");

	let frame1_bytes = frame1.to_der()?;
	let digest_info = digest::<Sha3_256>(&frame1_bytes)?;

	let frame2 = HarnessFrame::linked("frame-2", 2, "second", digest_info);

	// Frame 3 carries the hash of other bytes as its `previous_frame`.
	let wrong_digest = digest::<Sha3_256>(b"wrong")?;
	let frame3 = HarnessFrame::linked("frame-3", 3, "third", wrong_digest);

	let chain = vec![frame1, frame2, frame3];
	let verdict = store.verify_chain(&chain)?;
	let broken_links = vec![(2, LinkBreak::HashMismatch)];
	assert_eq!(verdict, ChainVerdict { valid: false, broken_links, verified_count: 2 });

	Ok(())
}
