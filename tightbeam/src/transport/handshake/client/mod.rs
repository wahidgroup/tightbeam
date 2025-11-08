//! Client-side handshake logic for TightBeam protocol.
//!
//! This module contains client-specific handshake implementations and utilities.

#[cfg(feature = "handshake_cms")]
mod cms;

#[cfg(feature = "handshake_cms")]
pub use cms::CmsHandshakeClient;

#[cfg(all(feature = "handshake_cms", feature = "secp256k1"))]
pub use cms::CmsHandshakeClientSecp256k1;

#[cfg(feature = "x509")]
mod ecies;

#[cfg(feature = "x509")]
pub use ecies::{EciesHandshakeClient, ExtractVerifyingKey};

#[cfg(all(feature = "x509", feature = "secp256k1"))]
pub use ecies::EciesHandshakeClientSecp256k1;
