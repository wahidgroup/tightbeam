//! Server-side handshake logic for TightBeam protocol.
//!
//! This module contains server-specific handshake implementations and utilities.

#[cfg(feature = "transport-cms")]
mod cms;

#[cfg(feature = "transport-cms")]
pub use cms::CmsHandshakeServer;

#[cfg(feature = "transport-ecies")]
mod ecies;

#[cfg(feature = "transport-ecies")]
pub use ecies::EciesHandshakeServer;
