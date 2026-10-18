//! Handshake primitives for building custom protocols.
//!
//! This module provides composable building blocks for implementing
//! custom handshake protocols like PQXDH. These primitives handle:
//! - Multi-input key derivation functions
//! - Transcript hashing utilities
//! - Prekey bundle ASN.1 structures

mod kdf;
pub(crate) mod transcript;

// The prekey structures stay UNSTABLE while no handshake protocol consumes
// them.
#[cfg(feature = "unstable-pqxdh")]
mod prekeys;

pub use kdf::{kdf_chain, multi_input_kdf, KdfInfo, KdfSalt, KdfStage};
pub use transcript::{transcript_hash, TranscriptHash};

#[cfg(any(
	feature = "transport-hpke",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
pub(crate) use kdf::RandomsSalt;
#[cfg(feature = "unstable-pqxdh")]
pub use prekeys::{PrekeyBundle, PrekeyIdentifiers, PrekeyInitialMessage};
