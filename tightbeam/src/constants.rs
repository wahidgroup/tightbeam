// ============================================================================
// Handshake Protocol Constants
// ============================================================================
// Domain separation constants for cryptographic operations
// These are the canonical constants for all handshake operations

/// KDF info string for ECIES session key derivation (HKDF)
pub const TIGHTBEAM_SESSION_KDF_INFO: &[u8] = b"tb/session/kdf/v1";

/// KDF info string for the client-to-server session key (HKDF)
///
/// Distinct info labels yield independent directional keys from the same
/// input key material (RFC 5869 domain separation), the same property
/// TLS 1.3 obtains from per-direction traffic secrets (RFC 8446, 7.1).
pub const TIGHTBEAM_C2S_KDF_INFO: &[u8] = b"tb/session/kdf/c2s/v1";

/// KDF info string for the server-to-client session key (HKDF)
pub const TIGHTBEAM_S2C_KDF_INFO: &[u8] = b"tb/session/kdf/s2c/v1";

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

/// AEAD record limit per directional key before a rekey is required (2^24)
///
/// [RFC 8446 § 5.5](https://datatracker.ietf.org/doc/html/rfc8446#section-5.5)
/// bounds AES-GCM near 2^24.5 records per key. No in-band key update:
/// senders fail closed with `RekeyRequired` (mux drains via GoAway first),
/// receivers refuse counters past the limit. Override via `with_rekey_limit`.
pub const DEFAULT_REKEY_RECORD_LIMIT: u64 = 1 << 24;

// ============================================================================
// Testing & Verification Constants
// ============================================================================

/// Linear Congruential Generator (LCG) multiplier constant
///
/// Source: Numerical Recipes (3rd Ed., 2007), § 7.1.4 "Linear Congruential Generators"
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
/// Source: Numerical Recipes (3rd Ed., 2007), § 7.1.4
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
/// `TransitStatus::ResourceExhausted` to the cluster, indicating it should route work elsewhere.
pub const DEFAULT_BACKPRESSURE_THRESHOLD_BPS: u16 = 9000;

/// Utilization assumed for servlets that do not report one (50% = 5000 bps)
///
/// The scaling task needs a per-instance figure to average. A servlet
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

/// Default per-connection budget of peer cancels that abort in-flight
/// multiplexed handlers
///
/// A peer that opens streams only to cancel them forces spawn/abort cycle
/// while staying under the concurrent-stream cap, the cost asymmetry
/// behind CVE-2023-44487 ("HTTP/2 Rapid Reset", CWE-400). Cancels of
/// already-completed streams are free. Each cancel that aborts a live
/// handler draws on this budget, and exhausting it ends the connection
/// with a GoAway. Only authenticated peers reach this path, so the budget
/// is generous. Tighten per connection via `MuxTransport::with_cancel_budget`.
pub const DEFAULT_MUX_CANCEL_BUDGET: u32 = 1024;

/// Ceiling on negotiated per-direction concurrent-stream caps
///
/// Handshake transport offers/accepts carry peer-chosen
/// `max_peer_initiated_streams` values. Deriving [`MuxSettings`] clamps
/// both directions to this ceiling so an absurd advertisement cannot
/// inflate bookkeeping bounds far beyond useful concurrency (CWE-770). Both
/// endpoints apply the same clamp to the same wire values.
///
/// [`MuxSettings`]: crate::transport::handshake::negotiation::MuxSettings
pub const MAX_MUX_STREAM_CAP: u32 = 1024;

/// Floor on the negotiated per-chunk payload size (1 KiB)
///
/// A peer advertising a tiny receive size would force the sender to burn
/// one AEAD record per few bytes, amplifying record-limit consumption and
/// per-record overhead (CWE-770). Advertisements below the floor clamp up.
pub const MIN_MUX_CHUNK_SIZE: u32 = 1024;

/// Ceiling on the negotiated per-chunk payload size (64 KiB)
///
/// Bounds the largest single envelope a stream chunk can occupy so one
/// stream cannot monopolize the shared writer, the motivation HTTP/2
/// solves with its frame-size ceiling
/// ([RFC 9113 § 4.2](https://datatracker.ietf.org/doc/html/rfc9113#section-4.2) analog).
pub const MAX_MUX_CHUNK_SIZE: u32 = 64 * 1024;

/// Default per-chunk payload size advertised when none is configured
/// (16 KiB, the HTTP/2 default frame size,
/// [RFC 9113 § 4.2](https://datatracker.ietf.org/doc/html/rfc9113#section-4.2))
pub const DEFAULT_MUX_CHUNK_SIZE: u32 = 16 * 1024;

/// Default bytes-per-credit unit for session budget debits
///
/// A chunk debits `ceil(payload_len / credit_unit)` credits from the
/// sender's per-direction session budget.
pub const DEFAULT_MUX_CREDIT_UNIT: u32 = 1024;

/// Ceiling on the negotiated initial per-stream chunk credit window
///
/// The initial window bounds receive-side reassembly memory per stream
/// (`window * chunk size`). An absurd advertisement cannot inflate that
/// bound (CWE-770). Grants may raise a live stream's absolute limit past
/// the initial window as reassembly drains.
pub const MAX_MUX_STREAM_CREDIT: u64 = 4096;

/// Default initial per-stream chunk credit window
///
/// 64 chunks at the default chunk size bounds per-stream reassembly at
/// 1 MiB before the receiver must grant more.
pub const DEFAULT_MUX_STREAM_CREDIT: u64 = 64;

/// Ceiling on a negotiated per-direction session budget, in credits
///
/// Budgets meter data-chunk credits only. Control envelopes (credit
/// grants, cancels, pings, GoAway) pass outside the budget but still
/// consume AEAD records. Every data chunk debits at least one credit
/// and consumes exactly one record, so capping budgets at half the
/// per-key record limit bounds worst-case epoch data-record consumption
/// under [`DEFAULT_REKEY_RECORD_LIMIT`]. The default batching grantor
/// keeps control traffic at `O(data chunks / window)` records, inside
/// the remaining half. The record limit itself stays the fail-closed
/// backstop either way.
pub const MAX_MUX_SESSION_BUDGET: u64 = DEFAULT_REKEY_RECORD_LIMIT / 2;

/// Default ceiling for decompressed message bodies (16 MiB)
///
/// Compressed frame bodies arrive under the transport's envelope ceiling,
/// but zstd can expand a small input by several orders of magnitude.
/// Capping the inflated size bounds the memory an attacker can force with
/// a decompression bomb (CWE-409). Override per inflator via
/// `ZstdCompression::with_max_output`.
pub const DEFAULT_MAX_DECOMPRESSED_LEN: usize = 16 * 1024 * 1024;
