//! Client-side handshake logic for TightBeam protocol.
//!
//! This module contains client-specific handshake implementations and utilities.

#[cfg(all(
	feature = "builder",
	feature = "aead",
	feature = "signature",
	feature = "secp256k1"
))]
mod cms;

#[cfg(all(
	feature = "builder",
	feature = "aead",
	feature = "signature",
	feature = "secp256k1"
))]
pub use cms::CmsHandshakeClient;

#[cfg(all(feature = "x509", feature = "secp256k1"))]
mod ecies;

#[cfg(all(feature = "x509", feature = "secp256k1"))]
pub use ecies::EciesHandshakeClient;
