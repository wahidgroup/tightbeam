//! The test helpers that the integration suites share.
//!
//! They cover certificate creation, server fixtures, and validation helpers.

#[cfg(feature = "colony")]
pub mod hive;

// Every suite that waits on another task uses it: colony and DTN through
// `tokio`, and the multiplex transport suites, which can build without it.
#[cfg(any(feature = "tokio", feature = "transport-multiplex"))]
pub mod poll;

#[cfg(all(feature = "x509", feature = "hex"))]
pub mod static_pair;

#[cfg(all(
	feature = "x509",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "transport",
	feature = "tokio"
))]
pub mod x509;

#[cfg(all(
	feature = "x509",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "transport"
))]
pub mod security;

#[cfg(all(
	feature = "x509",
	feature = "secp256k1",
	feature = "signature",
	feature = "tokio"
))]
pub mod laser;
