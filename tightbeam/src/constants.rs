#![allow(dead_code)]

// ============================================================================
// Handshake Protocol Constants
// ============================================================================
// Domain separation constants for cryptographic operations
// These are the canonical constants for all handshake operations

/// KDF info string for ECIES session key derivation (HKDF)
pub const TIGHTBEAM_SESSION_KDF_INFO: &[u8] = b"tb/session/kdf/v1";

/// KDF info string for CMS KARI (Key Agreement Recipient Info) KEK derivation
pub const TIGHTBEAM_KARI_KDF_INFO: &[u8] = b"tb/kari/kdf/v1";

/// Domain tag for signed transcript (Finished messages)
pub const TIGHTBEAM_SIGNED_TRANSCRIPT_DOMAIN: &[u8] = b"tb/handshake/transcript/v1";

/// AAD (Additional Authenticated Data) domain tag prefix
pub const TIGHTBEAM_AAD_DOMAIN_TAG: &[u8] = b"tb/aead/v1";

/// Minimum salt entropy in bytes for secure key derivation (HKDF)
///
/// Used by both CMS and ECIES protocols to ensure sufficient randomness
/// in the salt parameter when deriving session keys via HKDF.
pub const MIN_SALT_ENTROPY_BYTES: usize = 16;

/// UKM (User Keying Material) prefix for KARI operations
pub const TIGHTBEAM_UKM_PREFIX: &[u8] = b"tb/kari/ukm/v1|";

/// ECIES KDF info parameter for domain separation and protocol versioning
pub const TIGHTBEAM_ECIES_KDF_INFO: &[u8] = b"tb/ecies/v1";

// ============================================================================
// Cryptographic Constants
// ============================================================================

/// Maximum HKDF output size for optimized dual-key expansion
pub const MAX_HKDF_OUTPUT_SIZE: usize = 128;

/// Minimum secure key size in bytes
pub const MIN_KEY_SIZE: usize = 16;

// ============================================================================
// Testing & Verification Constants
// ============================================================================

/// Linear Congruential Generator (LCG) multiplier constant
///
/// Source: Numerical Recipes (3rd Ed., 2007), Section 7.1.4 "Linear Congruential Generators"
/// - Authors: Press, Teukolsky, Vetterling, Flannery
/// - Value derived from Donald Knuth's MMIX LCG parameters
/// - Period: 2^64 (full period for 64-bit state)
/// - Spectral test: Passes all dimensions up to at least dimension 6
///
/// Used by:
/// - FDR exploration for deterministic state space traversal
/// - Runtime fault injection for reproducible test sequences
///
/// Certification compliance:
/// - DO-178C DAL A: Deterministic, reproducible pseudorandom sequences
/// - IEC 61508 SIL 4: Systematic fault injection with known seed behavior
pub const LCG_MULTIPLIER: u64 = 6364136223846793005;

/// Linear Congruential Generator (LCG) increment constant
///
/// Source: Numerical Recipes (3rd Ed., 2007), Section 7.1.4
/// - Must be odd for full period
/// - Co-prime with 2^64 (guaranteed since it's odd)
/// - Combined with LCG_MULTIPLIER provides good randomness properties
///
/// Certification compliance:
/// - Same seed produces identical sequences across all platforms
/// - No floating-point operations (pure integer arithmetic)
/// - Suitable for embedded/bare-metal environments (no_std compatible)
pub const LCG_INCREMENT: u64 = 1442695040888963407;

/// Default seed for fault injection reproducibility
///
/// Used by:
/// - FaultModel for FDR-based fault injection
/// - TraceCollector for runtime fault injection
///
/// The value 0xDEADBEEF is a recognizable debug marker commonly used in
/// systems programming to indicate "this is test/debug/uninitialized state".
///
/// For production fault testing, override with a specific seed via:
/// - `FaultModel::with_seed(custom_seed)`
pub const DEFAULT_FAULT_SEED: u64 = 0xDEADBEEF;

// ============================================================================
// Configuration Constants
// ============================================================================

/// Default backpressure threshold in basis points (90% = 9000 bps)
///
/// When aggregate utilization exceeds this threshold, the hive signals
/// `TransitStatus::Busy` to the cluster, indicating it should route work elsewhere.
pub const DEFAULT_BACKPRESSURE_THRESHOLD_BPS: u16 = 9000;

// ============================================================================
// Bitcoin Constants
// ============================================================================

#[cfg(feature = "bitcoin")]
const BITCOIN_GENESIS_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
