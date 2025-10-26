mod utils;

pub mod secret;

#[cfg(feature = "aead")]
pub mod aead;
#[cfg(feature = "ecies")]
pub mod ecies;
#[cfg(feature = "digest")]
pub mod hash;
#[cfg(feature = "kdf")]
pub mod kdf;
#[cfg(feature = "signature")]
pub mod sign;
#[cfg(feature = "x509")]
pub mod x509;

// Re-exports
pub use crypto_common as common;

#[cfg(feature = "secp256k1")]
pub const ECDSA_PUBKEY_SIZE: usize = 33;
#[cfg(feature = "secp256k1")]
pub const ECDSA_SECRET_SIZE: usize = 32;
