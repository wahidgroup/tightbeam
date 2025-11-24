//! Delay-Tolerant Networking (DTN) tests
//!
//! These tests demonstrate tightbeam's ability to provide DTN capabilities
//! without traditional DTN infrastructure (custody transfer, Bundle Protocol, etc.)
//!
//! ## Traditional DTN Architecture
//!
//! Traditional DTN systems require:
//! - **Custody Transfer Protocol**: Hop-by-hop acknowledgments with trusted intermediaries
//! - **Bundle Protocol**: Complex protocol stack for store-and-forward
//! - **Persistent Storage**: Each hop stores bundles until next hop available
//! - **Trusted Nodes**: Each relay must be trusted to handle custody
//!
//! ## Tightbeam DTN Approach
//!
//! Tightbeam achieves delay tolerance through first-principles design:
//! - **Cryptographic Chain**: `previous_frame` hash chain enables end-to-end verification
//! - **Self-Verifying Messages**: No custody transfer needed - destination verifies directly
//! - **No Trusted Intermediaries**: Relays are untrusted - crypto proves integrity
//! - **TTL & Priorities**: Built into metadata, not separate protocol layers
//! - **Matrix State**: Arbitrary application state encoded in cryptographically-bound matrix
//!
//! This represents a fundamental rethinking of DTN based on Information Theory's
//! constraint: `I(t) ∈ (0,1) for all t ∈ T`
//!
//! ## Test Structure
//!
//! - `clock.rs`: Simulated mission clock with realistic Mars-Earth delays
//! - `messages.rs`: Rover telemetry, Earth commands, and consensus types
//! - `faults.rs`: Fault flags and fault handling logic
//! - `utils.rs`: UUID generator and helper functions
//! - `servlets.rs`: Earth and Relay servlet definitions
//! - `types.rs`: Base DTN types and custom error types
//! - `ultimate.rs`: Ultimate DTN test demonstrating all framework capabilities

#![cfg(all(
	feature = "testing-csp",
	feature = "testing-fdr",
	feature = "std",
	feature = "tcp",
	feature = "tokio",
	feature = "signature",
	feature = "secp256k1",
	feature = "sha3",
	feature = "x509",
	feature = "compress"
))]

pub mod bms;
pub mod certs;
pub mod chain_processor;
pub mod clock;
pub mod command_executor;
pub mod fault_manager;
pub mod fault_matrix;
pub mod faults;
pub mod frame_builder;
pub mod messages;
pub mod ordering;
pub mod servlets;
pub mod storage;
pub mod types;
pub mod ultimate;
pub mod utils;
