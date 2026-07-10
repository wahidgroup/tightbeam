//! Handshake primitives for building custom protocols.
//!
//! This module provides composable building blocks for implementing
//! custom handshake protocols like PQXDH. These primitives handle:
//! - Multi-input key derivation functions
//! - Transcript hashing utilities  
//! - Prekey bundle ASN.1 structures

pub mod kdf;
pub mod transcript;

/// UNSTABLE: PQXDH prekey structures; no orchestrator consumes them yet.
/// Gated behind `unstable-pqxdh` until an end-to-end protocol exists.
#[cfg(feature = "unstable-pqxdh")]
#[doc(hidden)]
pub mod prekeys;

pub use kdf::multi_input_kdf;
pub use transcript::transcript_hash;

#[cfg(feature = "unstable-pqxdh")]
pub use kdf::kdf_chain;
#[cfg(feature = "unstable-pqxdh")]
pub use prekeys::{PrekeyBundle, PrekeyIdentifiers, PrekeyInitialMessage};
