//! Handshake primitives that a custom handshake protocol builds on.
//!
//! A custom protocol such as PQXDH composes these parts:
//!
//! - The multi-input key derivation of [`multi_input_kdf`] and [`kdf_chain`].
//! - The transcript hash of [`transcript_hash`] and [`TranscriptHash`].
//! - The prekey bundle ASN.1 structures, under the `preview-pqc` feature.

mod kdf;
pub(crate) mod transcript;

// The prekey structures stay in preview until a handshake protocol consumes
// them.
#[cfg(feature = "preview-pqc")]
mod prekeys;

pub use kdf::{kdf_chain, multi_input_kdf, KdfInfo, KdfStage};
pub use transcript::{transcript_hash, TranscriptHash};

#[cfg(any(feature = "transport-hpke", mux_rekey))]
pub(crate) use kdf::RandomsSalt;
#[cfg(feature = "preview-pqc")]
pub use prekeys::{PrekeyBundle, PrekeyIdentifiers, PrekeyInitialMessage};
