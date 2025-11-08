#![allow(dead_code)]

// ============================================================================
// Handshake Protocol Constants
// ============================================================================
// Re-export domain separation constants from crypto profiles
// These are the canonical constants for all handshake operations

/// KDF info string for ECIES session key derivation (HKDF)
pub use crate::crypto::profiles::DOMAIN_SESSION_KDF as TIGHTBEAM_SESSION_KDF_INFO;

/// KDF info string for CMS KARI (Key Agreement Recipient Info) KEK derivation
pub use crate::crypto::profiles::DOMAIN_KARI_KDF as TIGHTBEAM_KARI_KDF_INFO;

/// Domain tag for signed transcript (Finished messages)
pub use crate::crypto::profiles::DOMAIN_SIGNED_TRANSCRIPT as TIGHTBEAM_SIGNED_TRANSCRIPT_DOMAIN;

/// AAD (Additional Authenticated Data) domain tag prefix
pub const TIGHTBEAM_AAD_DOMAIN_TAG: &[u8] = b"tb/aead/v1";

// ============================================================================
// Bitcoin Constants
// ============================================================================

#[cfg(feature = "bitcoin")]
const BITCOIN_GENESIS_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
