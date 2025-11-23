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
//! - `types.rs`: Message types and custom error types
//! - `storage.rs`: Frame persistence and chain verification utilities
//! - `delay.rs`: Delay simulation for multi-hop scenarios
//! - `delay_tolerant.rs`: Comprehensive multi-hop DTN test with fault injection

// TODO: Fix these - they use Vec<u8> instead of Beamable types
// pub mod delay;
// pub mod delay_tolerant;
// pub mod storage;
pub mod types;
pub mod ultimate;
