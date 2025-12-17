//! Payment Processing Gateway Integration Tests
//!
//! Real-world scenario demonstrating TightBeam's full feature set:
//! - Integrity verification (Sha3_256 hashing)
//! - Non-repudiation (SignerInfo signatures)
//! - Idempotence (Frame-based deduplication)
//! - Queue-less backpressure (AdaptiveGate)
//! - DAG transaction chains (previous_frame linking)
//! - Priority routing (MessagePriority)
//! - TLS mutual authentication
//! - Bio-inspired ACO/ABC cluster routing
//!
//! Message types follow ISO 20022 pacs.008 structure.
//! Monetary amounts use ISO 4217 currency quanta.

#![cfg(all(
	feature = "std",
	feature = "tokio",
	feature = "testing",
	feature = "x509",
	feature = "secp256k1",
	feature = "signature",
	feature = "colony",
	feature = "transport-policy"
))]

pub mod currency;
pub mod messages;
pub mod harness;
pub mod servlets;
pub mod hives;
pub mod cluster;
mod scenarios;

