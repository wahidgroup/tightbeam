//! Shared constants for the handshake, cryptography, serving, testing, and
//! configuration.
//!
//! - **Handshake protocol.** Domain separation labels for cryptographic
//!   operations. They are the canonical constants for every handshake
//!   operation.
//! - **Cryptographic.** HKDF, key, and salt sizes, elliptic curve key sizes,
//!   and the AES-GCM sizes and rekey limits.
//! - **Serving.** Accept-loop limits for the `server!` macro.
//! - **Testing and verification.** Generator constants and seeds for
//!   deterministic exploration and fault injection.
//! - **Configuration.** Backpressure, mux, envelope, timeout, colony, gossip,
//!   and peer discovery bounds.

/// KDF info string for ECIES session key derivation (HKDF).
pub const TIGHTBEAM_SESSION_KDF_INFO: &[u8] = b"tb/session/kdf/v1";

/// KDF info string for the client-to-server session key (HKDF).
///
/// Distinct info labels yield independent directional keys from the same
/// input key material.
///
/// # Sources
///
/// - RFC 5869, HKDF domain separation: <https://datatracker.ietf.org/doc/html/rfc5869>
/// - RFC 9846 § 7.1, per-direction traffic secrets (TLS 1.3):
///   <https://datatracker.ietf.org/doc/html/rfc9846#section-7.1>
pub const TIGHTBEAM_C2S_KDF_INFO: &[u8] = b"tb/session/kdf/c2s/v1";

/// KDF info string for the server-to-client session key (HKDF).
pub const TIGHTBEAM_S2C_KDF_INFO: &[u8] = b"tb/session/kdf/s2c/v1";

/// KDF info string for the epoch secret retained for in-band rekeying.
///
/// The label separates the epoch chain from the traffic keys.
///
/// - The raw handshake secret keeps its zeroize-at-complete lifecycle.
/// - The epoch chain rotates independently of that secret.
///
/// # Sources
///
/// - RFC 9846 § 7.2, delete `secret_N` once `secret_N+1` is derived:
///   <https://datatracker.ietf.org/doc/html/rfc9846#section-7.2>
pub const TIGHTBEAM_EPOCH_KDF_INFO: &[u8] = b"tb/session/kdf/epoch/v1";

/// KDF info string for CMS KARI (Key Agreement Recipient Info) KEK derivation.
pub const TIGHTBEAM_KARI_KDF_INFO: &[u8] = b"tb/kari/kdf/v1";

/// Domain label a server CMS Finished signs ahead of the transcript hash.
pub const TIGHTBEAM_SERVER_FINISHED_DOMAIN: &[u8] = b"tb/handshake/finished/server/v1";

/// Domain label a client CMS Finished signs ahead of the transcript hash.
pub const TIGHTBEAM_CLIENT_FINISHED_DOMAIN: &[u8] = b"tb/handshake/finished/client/v1";

/// AAD (Additional Authenticated Data) domain tag prefix.
pub const TIGHTBEAM_AAD_DOMAIN_TAG: &[u8] = b"tb/aead/v1";

/// Minimum salt entropy in bytes for secure key derivation (HKDF).
///
/// CMS and ECIES both read it when they derive session keys through HKDF, and
/// the salt must carry at least this many bytes of randomness.
pub const MIN_SALT_ENTROPY_BYTES: usize = 16;

/// UKM (User Keying Material) prefix for KARI operations.
pub const TIGHTBEAM_UKM_PREFIX: &[u8] = b"tb/kari/ukm/v1|";

/// ECIES KDF info parameter for domain separation and protocol versioning.
pub const TIGHTBEAM_ECIES_KDF_INFO: &[u8] = b"tb/ecies/v1";

/// Maximum HKDF output size in bytes for one dual-key expansion.
pub const MAX_HKDF_OUTPUT_SIZE: usize = 128;

/// Minimum secure key size in bytes.
pub const MIN_KEY_SIZE: usize = 16;

/// Minimum HKDF salt size in bytes when a non-empty salt is supplied.
pub const MIN_SALT_SIZE: usize = 16;

/// Compressed secp256k1 or P-256 public key size in SEC1 format.
///
/// The encoding is a `0x02` or `0x03` prefix byte plus 32 bytes.
pub const EC_PUBKEY_COMPRESSED_SIZE: usize = 33;

/// Uncompressed secp256k1 or P-256 public key size in SEC1 format.
///
/// The encoding is a `0x04` prefix byte plus 64 bytes.
pub const EC_PUBKEY_UNCOMPRESSED_SIZE: usize = 65;

/// ECDH shared secret size for 256-bit curves (secp256k1, P-256, X25519).
pub const ECDH_SHARED_SECRET_SIZE: usize = 32;

/// AES-GCM nonce size (96 bits).
///
/// # Sources
///
/// - NIST SP 800-38D, Recommendation for Block Cipher Modes of Operation:
///   Galois/Counter Mode (GCM):
///   <https://csrc.nist.gov/publications/detail/sp/800-38d/final>
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// AES-GCM authentication tag size (128 bits).
pub const AES_GCM_TAG_SIZE: usize = 16;

/// AEAD record limit per directional key before a rekey is required (2^24).
///
/// AES-GCM is bounded near 2^24.5 records per key. This constant is the
/// fail-closed volume floor used on both sides of the link.
///
/// - Senders fail closed with `RekeyRequired` at their configured limit.
/// - Receipt-bearing mux sessions renew in band first.
/// - Other sessions drain via GoAway.
/// - Receivers refuse counters past this constant volume bound.
/// - `with_rekey_limit` overrides the renewal and drain trigger. The
///   receive-side refusal bound stays at this constant.
///
/// # Sources
///
/// - RFC 9846 § 5.5, AEAD limits: <https://datatracker.ietf.org/doc/html/rfc9846#section-5.5>
pub const DEFAULT_REKEY_RECORD_LIMIT: u64 = 1 << 24;

/// Slack above the mux drain headroom before an in-band renewal opens.
///
/// The slack gives the three-leg exchange (request, ack, control) room to
/// finish before the hard floor parks data.
///
/// - If the exchange finishes in time, data resumes under the new epoch.
/// - Otherwise data parks until install completes, or the renewal deadline triggers GoAway drain.
pub const DEFAULT_REKEY_RENEWAL_ALLOWANCE: u64 = 64;

/// Minimum records a server must have received since the last epoch
/// install before it accepts another `RekeyRequest`.
///
/// The constant bounds rekey floods. Together with the one-exchange-in-flight
/// rule, it caps how often a client can force the server through signing and
/// settlement work. A violation is a protocol error.
///
/// # Sources
///
/// - CWE-400, uncontrolled resource consumption: <https://cwe.mitre.org/data/definitions/400.html>
/// - RFC 9846, limit on unanswered KeyUpdate messages (same shape):
///   <https://datatracker.ietf.org/doc/html/rfc9846>
pub const DEFAULT_REKEY_MIN_SPEND_RECORDS: u64 = 4;

/// Seconds a rekey initiator waits for the exchange to complete before
/// draining the connection.
///
/// The deadline bounds the c2s data park, which spans the Ack-to-Done window
/// plus the hard floor. When a peer stops answering, expiry releases the park
/// and converges on the GoAway drain path.
pub const DEFAULT_REKEY_DEADLINE_SECS: u64 = 30;

/// Concurrent-connection cap for the `server!` async accept loop.
///
/// The loop stops accepting while this many connection tasks are alive, so a
/// connection flood queues in the listener backlog instead of pinning
/// unbounded tasks and file descriptors.
///
/// # Sources
///
/// - CWE-400, uncontrolled resource consumption: <https://cwe.mitre.org/data/definitions/400.html>
pub const DEFAULT_MAX_SERVER_CONNECTIONS: usize = 1024;

/// Delay between accept retries after a failed accept.
///
/// The delay spaces the retries far enough apart that a descriptor shortage
/// has time to clear between attempts.
pub const DEFAULT_ACCEPT_RETRY_DELAY: core::time::Duration = core::time::Duration::from_millis(50);

/// Linear Congruential Generator (LCG) multiplier constant.
///
/// # Properties
///
/// - Period: 2^64, the full period for a 64-bit state.
/// - Spectral test: passes all dimensions up to at least dimension 6.
/// - The value comes from Donald Knuth's MMIX LCG parameters.
///
/// # Used by
///
/// - FDR exploration for deterministic state space traversal.
/// - Runtime fault injection for reproducible test sequences.
///
/// # Sources
///
/// - Press, Teukolsky, Vetterling & Flannery, *Numerical Recipes* (3rd Ed.,
///   2007), § 7.1.4 "Linear Congruential Generators"
pub const LCG_MULTIPLIER: u64 = 6364136223846793005;

/// Linear Congruential Generator (LCG) increment constant.
///
/// # Properties
///
/// - The increment must be odd for a full period.
/// - It is co-prime with 2^64 because it is odd.
/// - It pairs with [`LCG_MULTIPLIER`] for the properties listed there.
/// - The same seed produces identical sequences on every platform.
/// - The generator uses integer arithmetic only.
///
/// # Sources
///
/// - Press, Teukolsky, Vetterling & Flannery, *Numerical Recipes* (3rd Ed., 2007), § 7.1.4
pub const LCG_INCREMENT: u64 = 1442695040888963407;

/// SplitMix64 golden-gamma increment constant.
///
/// The value is `floor(((1+sqrt(5))/2) * 2^64) mod 2^64`, the 64-bit golden
/// ratio. Any 64-bit seed is valid, including zero.
///
/// # Used by
///
/// - The `PowerOfTwoChoices` load balancer for candidate-pair selection.
///
/// # Sources
///
/// - Sebastiano Vigna, `splitmix64.c` (2015, public domain):
///   <https://xoshiro.di.unimi.it/splitmix64.c>
/// - Steele, Lea & Flood, Java 8 `SplittableRandom` (OOPSLA 2014):
///   <https://doi.org/10.1145/2714064.2660195>
pub const SPLITMIX64_GAMMA: u64 = 0x9E3779B97F4A7C15;

/// SplitMix64 finalizer multiplier 1.
///
/// The value comes from David Stafford's Mix13 variant of the MurmurHash3
/// 64-bit finalizer. See [`SPLITMIX64_GAMMA`] for the sources.
pub const SPLITMIX64_MIX_1: u64 = 0xBF58476D1CE4E5B9;

/// SplitMix64 finalizer multiplier 2.
///
/// See [`SPLITMIX64_GAMMA`] for the sources.
pub const SPLITMIX64_MIX_2: u64 = 0x94D049BB133111EB;

/// Default seed for fault injection reproducibility.
///
/// The value `0xDEADBEEF` is a recognizable debug marker. Systems
/// programming conventionally uses it for test, debug, or uninitialized
/// state. Override it for production fault testing through
/// `FaultModel::with_seed(custom_seed)`.
///
/// # Used by
///
/// - `FaultModel` for FDR-based fault injection.
/// - `TraceCollector` for runtime fault injection.
pub const DEFAULT_FAULT_SEED: u64 = 0xDEADBEEF;

/// Default backpressure threshold in basis points (90% = 9000 bps).
///
/// When aggregate utilization exceeds this threshold, the hive signals
/// `TransitStatus::ResourceExhausted` to the cluster, so the cluster should
/// route work elsewhere.
pub const DEFAULT_BACKPRESSURE_THRESHOLD_BPS: u16 = 9000;

/// Utilization assumed for a servlet that reports none (50% = 5000 bps).
///
/// The scaling task needs a per-instance figure to average, so a servlet
/// without self-reported or hive-tracked utilization counts as half loaded.
///
/// - Half load leaves scale-up to a servlet that reports real load. A 100%
///   figure would force a scale-up.
/// - Half load surfaces on the averages of sibling servlets. A 0% figure would hide it.
pub const UNKNOWN_SERVLET_UTILIZATION_BPS: u16 = 5000;

/// Default freshness window for signed cluster commands (30 seconds).
///
/// The window bounds the replay surface of captured commands. A hive accepts
/// a signed `ClusterCommand` only when both checks pass:
///
/// - `Frame.metadata.order` is within this many milliseconds of the hive's own
///   clock, in both directions to tolerate skew.
/// - The signature is new inside the window.
///
/// # Sources
///
/// - CWE-294, authentication bypass by capture-replay:
///   <https://cwe.mitre.org/data/definitions/294.html>
pub const DEFAULT_COMMAND_FRESHNESS_WINDOW_MS: u64 = 30_000;

/// Default per-connection budget of peer cancels that abort in-flight
/// multiplexed handlers.
///
/// A peer that opens streams only to cancel them forces a spawn and abort
/// cycle while it stays under the concurrent-stream cap. That is the cost
/// asymmetry behind HTTP/2 Rapid Reset.
///
/// - Cancels of already-completed streams are free.
/// - Each cancel that aborts a live handler draws on this budget.
/// - Exhausting the budget ends the connection with a GoAway.
/// - Only authenticated peers reach this path, so the budget is generous.
///
/// Tighten it per connection through `MuxTransport::with_cancel_budget`.
///
/// # Sources
///
/// - CVE-2023-44487, HTTP/2 Rapid Reset: <https://nvd.nist.gov/vuln/detail/CVE-2023-44487>
/// - CWE-400, uncontrolled resource consumption: <https://cwe.mitre.org/data/definitions/400.html>
pub const DEFAULT_MUX_CANCEL_BUDGET: u32 = 1024;

/// Ceiling on negotiated per-direction concurrent-stream caps.
///
/// Handshake transport offers and accepts carry peer-chosen
/// `max_peer_initiated_streams` values, and deriving [`MuxSettings`] clamps
/// both directions to this ceiling.
///
/// - An advertisement inflates bookkeeping bounds only up to useful concurrency.
/// - Both endpoints apply the same clamp to the same advertised values.
///
/// [`MuxSettings`]: crate::transport::handshake::negotiation::MuxSettings
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_MUX_STREAM_CAP: u32 = 1024;

/// Floor on the negotiated per-chunk payload size (1 KiB).
///
/// A peer that advertises a tiny receive size would force the sender to burn
/// one AEAD record per few bytes, which amplifies record-limit consumption
/// and per-record overhead. An advertisement below the floor clamps up.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MIN_MUX_CHUNK_SIZE: u32 = 1024;

/// Ceiling on the negotiated per-chunk payload size (64 KiB).
///
/// The ceiling bounds the largest single envelope a stream chunk can occupy,
/// so one stream takes at most this share of the shared writer.
///
/// # Sources
///
/// - RFC 9113 § 4.2, HTTP/2 frame-size ceiling (same motivation):
///   <https://datatracker.ietf.org/doc/html/rfc9113#section-4.2>
pub const MAX_MUX_CHUNK_SIZE: u32 = 64 * 1024;

/// Default per-chunk payload size advertised when none is configured.
///
/// The value is 16 KiB, the HTTP/2 default frame size.
///
/// # Sources
///
/// - RFC 9113 § 4.2, frame size: <https://datatracker.ietf.org/doc/html/rfc9113#section-4.2>
pub const DEFAULT_MUX_CHUNK_SIZE: u32 = 16 * 1024;

/// Default bytes-per-credit unit for session budget debits.
///
/// A chunk debits `ceil(payload_len / credit_unit)` credits from the
/// sender's per-direction session budget.
pub const DEFAULT_MUX_CREDIT_UNIT: u32 = 1024;

/// Ceiling on the negotiated initial per-stream chunk credit window.
///
/// The initial window bounds receive-side reassembly memory per stream
/// (`window * chunk size`).
///
/// - An advertisement raises that bound only up to this ceiling.
/// - Grants may raise a live stream's absolute limit past the initial window
///   while bytes remain under [`MAX_MUX_REASSEMBLY_BYTES`].
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_MUX_STREAM_CREDIT: u64 = 4096;

/// Default initial per-stream chunk credit window.
///
/// 64 chunks at the default chunk size bounds per-stream reassembly at
/// 1 MiB before the receiver must grant more.
pub const DEFAULT_MUX_STREAM_CREDIT: u64 = 64;

/// Ceiling on a negotiated per-direction session budget, in credits.
///
/// Budgets meter data-chunk credits only.
///
/// - Control envelopes (credit grants, cancels, pings, GoAway) pass outside the
///   budget but still consume AEAD records.
/// - Every data chunk debits at least one credit and consumes exactly one record.
/// - Capping budgets at half the per-key record limit therefore bounds
///   worst-case epoch data-record consumption under
///   [`DEFAULT_REKEY_RECORD_LIMIT`].
/// - The default batching grantor keeps control traffic at `O(data chunks /
///   window)` records, inside the remaining half.
/// - The record limit itself stays the fail-closed backstop either way.
pub const MAX_MUX_SESSION_BUDGET: u64 = DEFAULT_REKEY_RECORD_LIMIT / 2;

/// Default ceiling in bytes for an encoded cleartext envelope (128 KiB).
///
/// [`TransportEncryptionConfig`] applies it when no explicit limit is
/// configured. Cleartext envelopes exist only during the handshake and in
/// unencrypted deployments, so the bound is half the encrypted ceiling.
///
/// [`TransportEncryptionConfig`]: crate::transport::TransportEncryptionConfig
pub const DEFAULT_MAX_CLEARTEXT_ENVELOPE: usize = 128 * 1024;

/// Default ceiling in bytes for an encoded encrypted envelope (256 KiB).
///
/// A server refuses a frame whose declared content length exceeds this
/// ceiling. It refuses before reading the content, so the declared length
/// bounds the allocation.
///
/// - The refusal closes the connection.
/// - The sender sees a reset instead of a typed error.
/// - Clients therefore preflight outgoing encrypted envelopes against this ceiling.
/// - When no explicit limit is set, the client fails locally with typed `SizeExceeded`.
///
/// # Sources
///
/// - CWE-400, uncontrolled resource consumption: <https://cwe.mitre.org/data/definitions/400.html>
pub const DEFAULT_MAX_ENCRYPTED_ENVELOPE: usize = 256 * 1024;

/// Default deadline for a single read or write on an established session.
///
/// The handshake carries its own allowance. Once a session is established,
/// a peer that stops speaking mid-frame holds the connection, its task, and
/// its accept-loop permit for as long as it stays silent.
///
/// Every transport carries this deadline, including one that sets no
/// explicit timeout, so an established session always has an expiry.
///
/// # Sources
///
/// - CWE-400, uncontrolled resource consumption: <https://cwe.mitre.org/data/definitions/400.html>
/// - CWE-772, missing release of resource after effective lifetime:
///   <https://cwe.mitre.org/data/definitions/772.html>
pub const DEFAULT_OPERATION_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(30);

/// Default allowance for a handshake to complete.
///
/// [`TransportEncryptionConfig`] and the TCP transports both read the
/// allowance from this constant.
///
/// [`TransportEncryptionConfig`]: crate::transport::TransportEncryptionConfig
pub const DEFAULT_HANDSHAKE_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(10);

/// Default ceiling in bytes for one encoded handshake-phase message.
///
/// A handshake message carries certificates, a key share, and a signature. It
/// is bounded far below a data envelope so an unauthenticated peer cannot make
/// this endpoint buffer a large allocation before proving its identity.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const DEFAULT_HANDSHAKE_MAX_WIRE: usize = 16 * 1024;

/// Default ceiling for decompressed message bodies (16 MiB).
///
/// Compressed frame bodies arrive under the transport's envelope ceiling, and
/// zstd can expand a small input by several orders of magnitude. Capping the
/// inflated size bounds the memory an attacker can force with a
/// decompression bomb.
///
/// Override it per inflator through `ZstdCompression::with_max_output`.
///
/// # Sources
///
/// - CWE-409, improper handling of highly compressed data:
///   <https://cwe.mitre.org/data/definitions/409.html>
pub const DEFAULT_MAX_DECOMPRESSED_LEN: usize = 16 * 1024 * 1024;

/// Hard ceiling on unary mux reassembly buffer bytes per stream.
///
/// Credit grants may raise the chunk window, and accepted payload bytes still
/// stay within this bound. The value equals
/// [`DEFAULT_MAX_DECOMPRESSED_LEN`].
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_MUX_REASSEMBLY_BYTES: usize = DEFAULT_MAX_DECOMPRESSED_LEN;

/// Reassembly bytes one connection may buffer across every open stream.
///
/// [`MAX_MUX_REASSEMBLY_BYTES`] bounds a single stream. A peer that opens many
/// streams multiplies it, so the connection carries this ceiling as well and
/// every stream charges against it. A connection legitimately reassembling
/// several streams at once stays inside four stream ceilings. Beyond that the
/// peer spends this endpoint's memory without making progress.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_MUX_CONNECTION_REASSEMBLY_BYTES: usize = 4 * MAX_MUX_REASSEMBLY_BYTES;

/// Ceiling on servlet types carried in one peer advertisement.
///
/// A peer gateway advertisement enumerates the servlet types its colony
/// exports. Bounding the count fail-closes an oversized advertisement
/// before it installs unbounded peer routes.
///
/// Gossip meshes apply the same control-message flood bound to their
/// advertisement path.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_ADVERTISED_TYPES: usize = 256;

/// Ceiling on distinct peer gateways tracked in one servlet registry.
///
/// Per-advertisement type caps alone leave trusted-peer registry growth
/// unbounded across many signers.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_PEER_GATEWAYS: usize = 64;

/// Ceiling on total live peer routes tracked in one servlet registry.
///
/// The ceiling bounds the aggregate Peer entries across all peer gateways.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_PEER_ROUTES: usize = 1024;

/// Ceiling on distinct relay-trail buckets tracked in one servlet registry.
///
/// Relay trails bucket per `(origin, relay)` pair, so a colony of `N`
/// members can create up to `N * (N - 1)` buckets. The budget is separate
/// from [`MAX_PEER_GATEWAYS`], because relay fan-in and direct-gateway
/// admission each hold their own budget.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_RELAY_BUCKETS: usize = 64;

/// Ceiling on total live relay-trail routes tracked in one servlet registry.
///
/// The ceiling is separate from [`MAX_PEER_ROUTES`] for the same reason that
/// [`MAX_RELAY_BUCKETS`] is separate from [`MAX_PEER_GATEWAYS`]. A full relay
/// plane must leave the direct-route budget untouched.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_RELAY_ROUTES: usize = 1024;

/// Origin sentinel for the relay budget on work and routed stream opens.
///
/// The budget is the number of gateway forwards a request may still spend.
/// Each peer hop decrements it, and `0` serves locally only.
///
/// - An origin stamps `u8::MAX`, which means "forward as far as policy allows".
/// - The first gateway clamps the value to its own `max_hops`, so the client
///   asserts its own reachability alone and a crafted large value clamps to the
///   same ceiling.
/// - A relayed hop carries the explicit value, which every later gateway clamps again.
/// - The sentinel is also the DER DEFAULT, so the common origin request omits
///   the field from its encoding.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const DEFAULT_HOP_BUDGET: u8 = u8::MAX;

/// Default advertisement-rumor refresh interval in milliseconds.
///
/// The advertise beat floods the local slate as an advertisement rumor only
/// when the slate or the flood target set changed. One refresh on this
/// interval lets late joiners and pruned witnesses relearn the origin.
/// Bitcoin self-announces addresses the same way, on change and on a slow
/// timer, well below one refresh per beat.
///
/// # Contract
///
/// The refresh MUST stay under the gossip freshness window
/// ([`DEFAULT_GOSSIP_SEEN_TTL_MS`]) so a refreshed rumor always admits as
/// fresh.
///
/// # Sources
///
/// - Bitcoin P2P network, periodic self-announcement of the local address to
///   peers: <https://developer.bitcoin.org/devguide/p2p_network.html>
pub const DEFAULT_AD_RUMOR_REFRESH_MS: u64 = 30_000;

/// Default `max_hops` relay cap on a cluster gateway.
///
/// The default allows one forward. A gateway relays a request to a peer at
/// most once, and the peer serves locally only. Operators raise the cap to
/// enable relay-trail fallback, which needs two forwards end to end.
///
/// The cap bounds the forwarding work one request can demand from this
/// gateway, whatever budget the request carries.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const DEFAULT_MAX_HOPS: u8 = 1;

/// Ceiling on the payload bytes carried in one gossip envelope.
///
/// A gossip rumor floods the peer graph, so an oversized payload amplifies
/// across every edge. Bounding the payload fail-closes the amplification
/// dose before the rumor is recorded or forwarded again.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_GOSSIP_PAYLOAD_BYTES: usize = 64 * 1024;

/// Ceiling on the initial time-to-live an origin gossip may request.
///
/// The time-to-live is the hop radius of a flood, so capping it bounds the
/// basic reproduction number of a single rumor, whatever value a publisher
/// requests.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_GOSSIP_TTL: u8 = 8;

/// Ceiling on distinct gossip rumors retained in one in-memory journal.
///
/// The journal retains recent rumors for deduplication and anti-entropy
/// reconciliation.
///
/// - Bounding the count keeps memory finite under a flood.
/// - The journal fails closed once the ceiling is reached.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_GOSSIP_LOG: usize = 4096;

/// Ceiling on gossip rumors retained per signer in one in-memory journal.
///
/// Partitioning the journal per signer isolates retention per identity.
/// One signer's distinct digests spend that signer's own retention, which
/// leaves other signers' rumors recorded.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_GOSSIP_LOG_PER_SIGNER: usize = 256;

/// Default gossip deduplication window in milliseconds.
///
/// A rumor whose digest was recorded within this window counts as already
/// seen, which is the recovered or immune state of the epidemic model. The
/// window must exceed the time a flood takes to traverse the peer graph, so
/// late duplicates are still suppressed.
pub const DEFAULT_GOSSIP_SEEN_TTL_MS: u64 = 120_000;

/// Default gossip retention window in milliseconds.
///
/// Anti-entropy reconciliation can repair only a rumor that a peer still
/// retains. Retention must be at least as long as the deduplication window,
/// so a node that returns within the window can still be repaired.
pub const DEFAULT_GOSSIP_RETENTION_MS: u64 = 120_000;

/// Default initial time-to-live an origin gossip requests.
///
/// [`MAX_GOSSIP_TTL`] bounds it from above.
pub const DEFAULT_GOSSIP_TTL: u8 = 8;

/// Default token-bucket burst one gossip signer may spend at once.
///
/// Rate admission bounds how many rumors one signer can push in a burst,
/// which caps the amplification one authenticated identity can trigger.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const DEFAULT_GOSSIP_RATE_BURST: u32 = 128;

/// Default interval that restores one token to a signer's gossip bucket.
///
/// Together with [`DEFAULT_GOSSIP_RATE_BURST`], this sets the sustained
/// per-signer publish rate a gateway admits. The default rate is four rumors
/// per second.
pub const DEFAULT_GOSSIP_RATE_REFILL_MS: u64 = 250;

/// Ceiling on distinct signers tracked by one in-memory admission store.
///
/// Bounding tracked signers keeps memory finite when many identities
/// publish. Admission fails closed once the ceiling is reached.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_GOSSIP_RATE_SIGNERS: usize = 4096;

/// Ceiling on unverified candidates held in the peer discovery table.
///
/// Peer-exchange hints are attacker-suppliable, so the new table is bounded
/// before any hint is dialed.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_PEER_TABLE_NEW: usize = 256;

/// Ceiling on verified learned peers held in the peer discovery table.
///
/// The value equals [`MAX_PEER_GATEWAYS`], so the dial graph stays within the
/// number of peer gateways one registry may track.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_PEER_TABLE_TRIED: usize = MAX_PEER_GATEWAYS;

/// Ceiling on peer-table entries sharing one address prefix bucket.
///
/// Discovery buckets learned peers by /16 (IPv4) or /32 (IPv6) prefix. The
/// per-bucket bound is the eclipse countermeasure, so one network position
/// holds its own share of either table.
///
/// # Sources
///
/// - Heilman, Kendler, Zohar & Goldberg (2015), eclipse attacks on Bitcoin's
///   peer-to-peer network, USENIX Security '15:
///   <https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman>
/// - The same paper as IACR ePrint 2015/263: <https://eprint.iacr.org/2015/263>
pub const MAX_PEER_BUCKET: usize = 8;

/// Ceiling on peers shared in one peer-exchange sample.
///
/// The ceiling bounds the reply, so one reconcile round returns at most this
/// many discovery hints.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_PEX_SAMPLE: usize = 8;

/// Ceiling on unverified candidates probed per advertise beat.
///
/// Feeler dials verify candidates before promotion. Bounding them per beat
/// keeps discovery traffic a small constant beside the anchor and tried
/// dials.
pub const PEER_PROBE_PER_BEAT: usize = 4;

/// Consecutive failed beat dials before a tried peer is evicted.
///
/// Tried residents re-dial on every beat, so consecutive failures are the
/// liveness clock.
///
/// - The threshold tolerates a two-beat partition.
/// - Eviction frees the prefix bucket slot for a live candidate.
/// - Discovery refills the table.
/// - Eviction is the fail-closed direction.
pub const MAX_PEER_TRIED_FAILURES: usize = 3;
