//! Transport envelope builders.
//!
//! The builders construct wire-level envelopes with size validation and
//! optional encryption.

mod envelope;

pub use envelope::EnvelopeBuilder;

#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub(crate) use envelope::Sealing;
