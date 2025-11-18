//! Transport envelope builders.
//!
//! This module provides builders for constructing wire-level envelopes with
//! size validation and optional encryption.

pub mod envelope;

pub use envelope::{EnvelopeBuilder, EnvelopeLimits};
