//! DTN Test - Mission-Critical Framework Demonstration
//!
//! ## Scenario: Mars Rover → Relay Satellite → Earth Ground Station
//!
//! This test demonstrates a 3-tier DTN architecture using tightbeam's primitives.
//!
//! ## Architecture (Simplified for MVP)
//!
//! ```
//! Mars Rover (Client)
//!     ↓
//! Relay Satellite (Servlet) ← Creates Earth server on-demand in handler
//!     ↓
//! Earth Ground Station (server! created in handler)
//! ```

#![cfg(all(
	feature = "testing-csp",
	feature = "testing-fdr",
	feature = "std",
	feature = "tcp",
	feature = "tokio",
	feature = "signature",
	feature = "secp256k1",
	feature = "sha3"
))]

use rand_core::OsRng;
use tightbeam::{
	compose,
	crypto::{
		hash::Sha3_256,
		sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey},
	},
	decode, exactly,
	macros::client::builder::ClientBuilder,
	prelude::*,
	servlet, tb_assert_spec, tb_scenario,
	transport::tcp::r#async::TokioListener,
};

use crate::dtn::types::DtnPayload;

// ============================================================================
// Earth Ground Station Servlet
// ============================================================================

servlet! {
	/// Earth ground station that receives science data from relay
	pub EarthGroundStationServlet<DtnPayload>,
	protocol: TokioListener,
	handle: |frame, _trace| async move {
		// Earth processes the data
		let payload: DtnPayload = decode(&frame.message)?;

		// Generate acknowledgment
		let ack_payload = DtnPayload {
			content: b"Data received by Earth".to_vec(),
			source_node: "Earth".to_string(),
			dest_node: payload.source_node,
			hop_count: payload.hop_count + 1,
		};

		let response = compose! {
			V0: id: "earth-ack-001",
			order: frame.metadata.order + 1,
			message: ack_payload
		}?;

		Ok(Some(response))
	}
}

// ============================================================================
// Relay Satellite Servlet (creates Earth server on first request)
// ============================================================================

servlet! {
	/// Relay satellite that forwards frames from Rover to Earth
	pub RelaySatelliteServlet<DtnPayload>,
	protocol: TokioListener,
	config: {
		earth_servlet: EarthGroundStationServlet,
		earth_addr: TightBeamSocketAddr,
		earth_signing_key: Secp256k1SigningKey,
	},
	handle: |frame, _trace, config| async move {
		// Decode payload from rover
		let mut payload: DtnPayload = decode(&frame.message)?;

		// Increment hop count
		payload.hop_count += 1;

		// Forward to Earth
		let earth_frame = compose! {
			V0: id: format!("relay-fwd-{}", String::from_utf8_lossy(&frame.metadata.id)),
			order: frame.metadata.order + 1,
			message: payload
		}?;

		// Create client to Earth and send
		let mut earth_client = ClientBuilder::<TokioListener>::connect(config.earth_addr)
			.await?
			.build()?;

		// Return Earth's response to Rover
		let earth_response = earth_client.emit(earth_frame, None).await?;
		Ok(earth_response)
	}
}

// ============================================================================
// DTN Scenario Configuration
// ============================================================================

use std::sync::Arc;

/// Configuration for DTN scenario with cryptographic keys
pub struct DtnScenarioConfig {
	/// Rover's signing key for nonrepudiation (set in setup)
	pub rover_signing_key: Secp256k1SigningKey,
}

impl Default for DtnScenarioConfig {
	fn default() -> Self {
		Self { rover_signing_key: Secp256k1SigningKey::random(&mut OsRng) }
	}
}

// ============================================================================
// Assertion Specification
// ============================================================================

tb_assert_spec! {
	pub DtnBaselineSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("rover_transmit_start", exactly!(1)),
			("rover_transmit_complete", exactly!(1))
		]
	}
}

// ============================================================================
// Tests
// ============================================================================

tb_scenario! {
	name: dtn_baseline,
	spec: DtnBaselineSpec,
	config: DtnScenarioConfig::default(),
	environment Servlet {
		servlet: RelaySatelliteServlet,
		start: |trace, _config| async move {
			// Start Earth Ground Station servlet
			let earth_servlet = EarthGroundStationServlet::start(Arc::clone(&trace)).await?;
			// Get Earth's address
			let earth_addr = earth_servlet.addr;
			// Generate Earth's signing key
			let earth_signing_key = Secp256k1SigningKey::random(&mut OsRng);

			// Create Relay servlet config with Earth info
			let relay_config = RelaySatelliteServletConf {
				earth_servlet,
				earth_addr,
				earth_signing_key,
			};

			// Start and return the Relay Satellite servlet with config
			RelaySatelliteServlet::start(Arc::clone(&trace), Arc::new(relay_config)).await
		},
		setup: |relay_addr, _config| async move {
			// Create Rover client
			let client = ClientBuilder::<TokioListener>::connect(relay_addr).await?.build()?;
			Ok(client)
		},
		client: |trace, mut rover_client, config| async move {
			// Rover sends science data
			let science_data = DtnPayload {
				content: b"Mars soil sample: 42% iron oxide".to_vec(),
				source_node: "MarsRover".to_string(),
				dest_node: "Earth".to_string(),
				hop_count: 0,
			};

			// Build frame with full cryptographic security:
			// - message_integrity: SHA3-256 hash of message payload
			// - frame_integrity: SHA3-256 hash of entire frame
			// - nonrepudiation: Secp256k1 signature for authenticity
			// - previous_frame: Hash chain for end-to-end integrity (built-in to compose!)
			let rover_signing_key = config.read()?.rover_signing_key.clone();
			let rover_frame = compose! {
				V2: id: "mars-science-001",
				order: 1,
				message: science_data,
				message_integrity: type Sha3_256,
				frame_integrity: type Sha3_256,
				nonrepudiation<Secp256k1Signature, _>: rover_signing_key
			}?;

			trace.event("rover_transmit_start")?;
			let response: Option<Frame> = rover_client.emit(rover_frame, None).await?;
			trace.event("rover_transmit_complete")?;

			// Verify we got a response from Earth (via relay)
			if let Some(response_frame) = response {
				let ack: DtnPayload = decode(&response_frame.message)?;
				assert_eq!(ack.source_node, "Earth");
				assert_eq!(ack.dest_node, "MarsRover");
				assert_eq!(ack.hop_count, 2, "Should have 2 hops total");
			} else {
				panic!("Should receive response from Earth");
			}

			Ok(())
		}
	}
}
