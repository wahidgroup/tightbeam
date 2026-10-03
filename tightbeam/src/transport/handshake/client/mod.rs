//! Client-side handshake logic for the TightBeam protocol.
//!
//! Each protocol has one client orchestrator: [`CmsHandshakeClient`] under the
//! `transport-cms` feature, and [`EciesHandshakeClient`] under the
//! `transport-ecies` feature.

#[cfg(feature = "transport-cms")]
mod cms;

#[cfg(feature = "transport-cms")]
pub use cms::CmsHandshakeClient;

#[cfg(feature = "transport-ecies")]
mod ecies;

#[cfg(feature = "transport-ecies")]
pub use ecies::EciesHandshakeClient;
