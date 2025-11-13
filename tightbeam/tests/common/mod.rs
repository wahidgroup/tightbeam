//! Common test helpers and utilities
//!
//! Shared code for integration tests including certificate creation,
//! server fixtures, and validation helpers.

#[cfg(all(
    feature = "x509",
    feature = "secp256k1",
    feature = "signature",
    feature = "sha3",
    feature = "transport",
    feature = "tokio"
))]
pub mod x509;
