//! Server-side handshake logic for TightBeam protocol.
//!
//! This module contains server-specific handshake implementations and utilities.

#[cfg(feature = "handshake_cms")]
mod cms;

#[cfg(feature = "handshake_cms")]
pub use cms::CmsHandshakeServer;

#[cfg(all(feature = "handshake_cms", feature = "secp256k1"))]
pub use cms::CmsHandshakeServerSecp256k1;

#[cfg(all(feature = "x509", feature = "secp256k1"))]
mod ecies;

#[cfg(all(feature = "x509", feature = "secp256k1"))]
pub use ecies::EciesHandshakeServer;
