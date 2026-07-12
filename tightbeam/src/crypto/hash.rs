//! Digest algorithms used by tightbeam

#[cfg(feature = "sha3")]
pub use sha3::{Sha3_256, Sha3_512};

pub use digest::Digest;
