#![allow(dead_code)]

// ============================================================================
// Handshake Protocol Constants
// ============================================================================

/// KDF info string for ECIES session key derivation (HKDF)
pub const TIGHTBEAM_SESSION_KDF_INFO: &[u8] = b"tightbeam-session-v1";

/// KDF info string for CMS KARI (Key Agreement Recipient Info) KEK derivation
pub const TIGHTBEAM_KARI_KDF_INFO: &[u8] = b"tb-kari-v1";

/// AAD (Additional Authenticated Data) domain tag for ECIES encryption
pub const TIGHTBEAM_AAD_DOMAIN_TAG: &[u8] = b"tb-v1";

// ============================================================================
// Bitcoin Constants
// ============================================================================

#[cfg(feature = "bitcoin")]
const BITCOIN_GENESIS_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
