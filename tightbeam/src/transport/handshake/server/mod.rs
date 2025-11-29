//! Server-side handshake logic for TightBeam protocol.
//!
//! This module contains server-specific handshake implementations and utilities.

#[cfg(feature = "transport-cms")]
mod cms;

#[cfg(feature = "transport-cms")]
pub use cms::CmsHandshakeServer;

#[cfg(all(feature = "x509", feature = "secp256k1"))]
mod ecies;

#[cfg(all(feature = "x509", feature = "secp256k1"))]
pub use ecies::EciesHandshakeServer;
