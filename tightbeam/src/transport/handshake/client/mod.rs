//! Client-side handshake logic for TightBeam protocol.
//!
//! This module contains client-specific handshake implementations and utilities.

#[cfg(feature = "transport-cms")]
mod cms;

#[cfg(feature = "transport-cms")]
pub use cms::CmsHandshakeClient;

#[cfg(feature = "x509")]
mod ecies;

#[cfg(feature = "x509")]
pub use ecies::{EciesHandshakeClient, ExtractVerifyingKey};
