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

/// Minimum HKDF salt size in bytes (when a non-empty salt is supplied)
pub const MIN_SALT_SIZE: usize = 16;

// ----------------------------------------------------------------------------
// Elliptic Curve Key Sizes
// ----------------------------------------------------------------------------

/// Compressed secp256k1/P-256 public key size (SEC1 format: 0x02/0x03 prefix + 32 bytes)
pub const EC_PUBKEY_COMPRESSED_SIZE: usize = 33;

/// Uncompressed secp256k1/P-256 public key size (SEC1 format: 0x04 prefix + 64 bytes)
pub const EC_PUBKEY_UNCOMPRESSED_SIZE: usize = 65;

/// ECDH shared secret size for 256-bit curves (secp256k1, P-256, X25519)
pub const ECDH_SHARED_SECRET_SIZE: usize = 32;

// ----------------------------------------------------------------------------
// AES-GCM Constants
// ----------------------------------------------------------------------------

/// AES-GCM nonce size (96 bits per NIST SP 800-38D recommendation)
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// AES-GCM authentication tag size (128 bits)
pub const AES_GCM_TAG_SIZE: usize = 16;

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
pub const LCG_MULTIPLIER: u64 = 6364136223846793005;

/// Linear Congruential Generator (LCG) increment constant
///
/// Source: Numerical Recipes (3rd Ed., 2007), Section 7.1.4
/// - Must be odd for full period
/// - Co-prime with 2^64 (guaranteed since it's odd)
/// - Combined with [`LCG_MULTIPLIER`] provides good randomness properties
///
/// Properties:
/// - Same seed produces identical sequences across all platforms
/// - No floating-point operations (pure integer arithmetic)
pub const LCG_INCREMENT: u64 = 1442695040888963407;

/// SplitMix64 golden-gamma increment constant
///
/// Source: Sebastiano Vigna, `splitmix64.c` (2015, public domain),
/// <https://xoshiro.di.unimi.it/splitmix64.c> -- the fixed-increment
/// version of Java 8's `SplittableRandom` (Steele, Lea & Flood,
/// OOPSLA 2014, doi:10.1145/2714064.2660195).
///
/// Value: floor(((1+sqrt(5))/2) * 2^64) mod 2^64 (64-bit golden ratio).
/// Any 64-bit seed is valid, including zero.
///
/// Used by:
/// - `PowerOfTwoChoices` load balancer for candidate-pair selection
pub const SPLITMIX64_GAMMA: u64 = 0x9E3779B97F4A7C15;

/// SplitMix64 finalizer multiplier 1 (David Stafford's Mix13 variant of
/// the MurmurHash3 64-bit finalizer). See [`SPLITMIX64_GAMMA`] for source.
pub const SPLITMIX64_MIX_1: u64 = 0xBF58476D1CE4E5B9;

/// SplitMix64 finalizer multiplier 2. See [`SPLITMIX64_GAMMA`] for source.
pub const SPLITMIX64_MIX_2: u64 = 0x94D049BB133111EB;

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

/// Utilization assumed for servlets that do not report one (50% = 5000 bps)
///
/// The scaling task needs a per-instance figure to average; a servlet
/// without self-reported or hive-tracked utilization counts as half
/// loaded so it neither forces scale-up (as 100% would) nor masks load
/// on its siblings (as 0% would).
pub const UNKNOWN_SERVLET_UTILIZATION_BPS: u16 = 5000;

/// Default freshness window for signed cluster commands (30 seconds)
///
/// A hive accepts a signed `ClusterCommand` only when its `issued_at_ms`
/// is within this many milliseconds of the hive's own clock (both
/// directions, tolerating skew), and its signature has not been seen
/// before inside the window. Bounds the replay surface of captured
/// commands (CWE-294).
pub const DEFAULT_COMMAND_FRESHNESS_WINDOW_MS: u64 = 30_000;
