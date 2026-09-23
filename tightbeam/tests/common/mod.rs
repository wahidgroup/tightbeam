//! Common test helpers and utilities
//!
//! Shared code for integration tests including certificate creation,
//! server fixtures, and validation helpers.

// Every suite that waits on another task: colony and DTN through `tokio`,
// and the multiplex transport suites, which can build without it.
#[cfg(any(feature = "tokio", feature = "transport-multiplex"))]
pub mod poll;

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
