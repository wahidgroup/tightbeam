//! The Delay-Tolerant Networking (DTN) tests.
//!
//! These tests show that tightbeam provides delay tolerance without the
//! traditional DTN infrastructure, such as custody transfer and the Bundle
//! Protocol.
//!
//! ## Traditional DTN Architecture
//!
//! Traditional DTN systems require:
//! - **Custody Transfer Protocol**: Hop-by-hop acknowledgments with trusted intermediaries.
//! - **Bundle Protocol**: A complex protocol stack for store-and-forward.
//! - **Persistent Storage**: Each hop stores bundles until the next hop is available.
//! - **Trusted Nodes**: Each relay must be trusted to handle custody.
//!
//! ## Tightbeam DTN Approach
//!
//! Tightbeam reaches delay tolerance through these parts of its design:
//! - **Cryptographic Chain**: The `previous_frame` hash chain gives end-to-end verification.
//! - **Self-Verifying Messages**: The destination verifies each message itself, with no custody transfer.
//! - **No Trusted Intermediaries**: Relays stay untrusted, and cryptography proves integrity.
//! - **TTL & Priorities**: The frame metadata carries them, with no separate protocol layer.
//! - **Matrix State**: A cryptographically bound matrix encodes arbitrary application state.
//!
//! The approach rests on the information fidelity constraint
//! `I(t) ∈ (0,1) for all t ∈ T`.

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
pub mod delay;
pub mod delay_tolerant;
pub mod events;
pub mod fault_manager;
pub mod fault_matrix;
pub mod faults;
pub mod frame_builder;
pub mod jobs;
pub mod messages;
pub mod nodes;
pub mod ordering;
pub mod routing;
pub mod servlets;
pub mod storage;
pub mod ultimate;
pub mod workers;
