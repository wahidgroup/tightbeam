//! Handshake primitives for building custom protocols.
//!
//! This module provides composable building blocks for implementing
//! custom handshake protocols like PQXDH. These primitives handle:
//! - Multi-input key derivation functions
//! - Transcript hashing utilities  
//! - Prekey bundle ASN.1 structures

pub mod kdf;
pub mod prekeys;
pub mod transcript;

pub use kdf::{kdf_chain, multi_input_kdf};
pub use prekeys::{PrekeyBundle, PrekeyIdentifiers, PrekeyInitialMessage};
pub use transcript::transcript_hash;
