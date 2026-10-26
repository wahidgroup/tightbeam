//! # Multi-hop delay tolerance
//!
//! A multi-hop DTN test of tightbeam's delay tolerance.
//!
//! ## Test Scenario: Earth to Mars Through a Relay
//!
//! This test simulates interplanetary communication with:
//! - **Hop delays** of 100 ms on a paused clock, which stand in for the light-time delays
//! - **Filesystem persistence** at each hop to survive delays
//! - **Cryptographic chain verification** at each hop and at the final destination
//!
//! ## What This Proves
//!
//! Traditional DTN systems require four parts, and tightbeam replaces each:
//! - A custody transfer protocol, where tightbeam uses the cryptographic chain.
//! - Trusted intermediaries, where tightbeam relays stay untrusted and cryptography proves integrity.
//! - The overhead of the Bundle Protocol, where tightbeam uses self-contained frames.
//! - Protocol-specific reliability, where tightbeam uses the metadata built into each frame.
//!
//! The test shows that tightbeam's first-principles design (`I(t) ∈ (0,1)`)
//! serves delay-tolerant scenarios with no extra infrastructure.

use std::time::Duration;

use tightbeam::compose;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::der::{Decode, Encode};
use tightbeam::utils::digest;
use tightbeam::TightBeamError;

use crate::dtn::delay::DelaySimulator;
use crate::dtn::storage::{DtnPayload, FrameStore, StorageRoot};

/// A payload that Earth addresses to Mars, which carries `content`.
fn earth_payload(content: impl AsRef<[u8]>) -> DtnPayload {
	let payload = DtnPayload::new(content.as_ref(), "Earth", "Mars", 0);
	payload.expect("a short payload fits an OCTET STRING")
}

/// A multi-hop DTN test from Earth to Mars through a relay.
#[tokio::test(start_paused = true)]
async fn dtn_multi_hop_earth_to_mars() -> Result<(), TightBeamError> {
	// Each node stores its frames in a directory of its own.
	let root = StorageRoot::create()?;

	let earth_dir = root.node("earth");
	let relay_dir = root.node("relay");
	let mars_dir = root.node("mars");

	let mut earth_store = FrameStore::new(earth_dir)?;
	let mut relay_store = FrameStore::new(relay_dir)?;
	let mut mars_store = FrameStore::new(mars_dir)?;

	// The simulator delays each hop by 100 ms on the paused clock.
	let mut delays = DelaySimulator::new();
	delays.configure_delay("Earth->Relay", Duration::from_millis(100));
	delays.configure_delay("Relay->Mars", Duration::from_millis(100));

	let payload = earth_payload(b"Hello Mars from Earth!");

	// Earth composes frame 1, which starts the chain.
	let frame1 = compose! {
		V0: id: "earth-msg-001",
		order: 1,
		message: payload.to_owned()
	}?;

	earth_store.persist(&frame1)?;

	delays.simulate_hop("Earth", "Relay").await?;

	// The relay reads frame 1 from the store of Earth and verifies it.
	let relay_frame1 = earth_store.retrieve("earth-msg-001")?;

	let relay_chain = vec![relay_frame1.to_owned()];
	let relay_verdict = relay_store.verify_chain(&relay_chain)?;
	assert!(relay_verdict.valid, "Chain verification failed at relay");

	// The relay forwards a frame whose `previous_frame` is the hash of frame 1.
	let frame1_bytes = relay_frame1.to_der()?;
	let digest_info = digest::<Sha3_256>(&frame1_bytes)?;

	let relay_payload = DtnPayload {
		content: payload.content.to_owned(),
		source_node: payload.source_node.to_owned(),
		dest_node: payload.dest_node.to_owned(),
		hop_count: payload.hop_count + 1,
	};

	let frame2 = compose! {
		V2: id: "relay-fwd-001",
		order: 2,
		previous_frame: digest_info,
		message: relay_payload
	}?;

	relay_store.persist(&frame2)?;

	delays.simulate_hop("Relay", "Mars").await?;

	// Mars reads the forwarded frame from the store of the relay and verifies
	// the full chain.
	let mars_frame1 = relay_store.retrieve("relay-fwd-001")?;
	let full_chain = vec![relay_frame1, mars_frame1.to_owned()];
	let mars_verdict = mars_store.verify_chain(&full_chain)?;
	assert!(mars_verdict.valid, "Chain verification failed at Mars");
	assert_eq!(mars_verdict.verified_count, 2, "Should verify 2 frames");
	assert!(mars_verdict.broken_links.is_empty(), "No broken links expected");

	let final_payload = DtnPayload::from_der(mars_frame1.message())?;
	assert_eq!(final_payload.content.as_bytes(), b"Hello Mars from Earth!");
	assert_eq!(final_payload.source_node, "Earth");
	assert_eq!(final_payload.dest_node, "Mars");
	assert_eq!(final_payload.hop_count, 1);

	earth_store.clear()?;
	relay_store.clear()?;
	mars_store.clear()?;

	Ok(())
}

/// A chain whose frame 3 carries a wrong `previous_frame` hash fails
/// verification at that link.
#[tokio::test]
async fn dtn_chain_verification_detects_tampering() -> Result<(), TightBeamError> {
	let root = StorageRoot::create()?;
	let store = FrameStore::new(root.node("store"))?;

	// Frames 1 and 2 form a valid chain.
	let frame1 = compose! {
		V0: id: "frame-1",
		order: 1,
		message: earth_payload(b"first")
	}?;

	let frame1_bytes = frame1.to_der()?;
	let digest_info = digest::<Sha3_256>(&frame1_bytes)?;

	let frame2 = compose! {
		V2: id: "frame-2",
		order: 2,
		previous_frame: digest_info,
		message: earth_payload(b"second")
	}?;

	// Frame 3 carries the hash of other bytes as its `previous_frame`.
	let wrong_digest = digest::<Sha3_256>(b"wrong")?;
	let frame3 = compose! {
		V2: id: "frame-3",
		order: 3,
		previous_frame: wrong_digest,
		message: earth_payload(b"third")
	}?;

	let chain = vec![frame1, frame2, frame3];
	let verdict = store.verify_chain(&chain)?;
	assert!(!verdict.valid, "Chain should be invalid");
	assert!(!verdict.broken_links.is_empty(), "Should detect broken link");
	assert_eq!(verdict.broken_links[0].0, 2, "Break should be at frame 3");

	Ok(())
}

/// A frame is a self-contained DER structure, so a store returns the message
/// it persisted, and a relay stores and forwards it as it arrived.
#[tokio::test]
async fn dtn_comparison_traditional_vs_tightbeam() -> Result<(), TightBeamError> {
	let root = StorageRoot::create()?;
	let mut store = FrameStore::new(root.node("store"))?;

	let frame = compose! {
		V0: id: "comparison-test",
		order: 1,
		message: earth_payload(b"Demonstrating tightbeam's DTN capabilities")
	}?;

	let frame_id = store.persist(&frame)?;
	let retrieved = store.retrieve(&frame_id)?;
	assert_eq!(retrieved.message(), frame.message());

	store.clear()?;

	Ok(())
}
