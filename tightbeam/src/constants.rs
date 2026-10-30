//! Shared constants for the handshake, cryptography, accept loops, testing,
//! and configuration.
//!
//! - **Handshake protocol.** The canonical domain separation labels of every handshake operation.
//! - **Cryptographic.** HKDF, key, and salt sizes, and the AES-GCM sizes and rekey limits.
//! - **Accept loops.** The connection cap and retry delay of the servlet, hive, gateway, and `server!` loops.
//! - **Testing and verification.** Generator constants and seeds for
//!   deterministic exploration and fault injection.
//! - **Configuration.** Backpressure, mux, envelope, timeout, pool, colony,
//!   gossip, and peer discovery bounds.

/// KDF info string for the handshake secret (HKDF), which both protocols
/// extract under the protocol salt:
///
/// - The CMS flow extracts it from the secret of the ephemeral key exchange
///   followed by the client's base secret.
/// - The HPKE flow extracts it from that secret alone.
pub const TIGHTBEAM_SESSION_KDF_INFO: &[u8] = b"tb/session/kdf/v1";

/// KDF info string for the key that seals the receipt acknowledgement (HKDF).
///
/// The key derives from the handshake secret (see
/// [forward secrecy](crate::transport::handshake#forward-secrecy)). One
/// acknowledgement travels per handshake, so the key is single-use.
///
/// # Sources
///
/// - RFC 5116 § 3.1, a nonce used once per key: <https://datatracker.ietf.org/doc/html/rfc5116#section-3.1>
pub const TIGHTBEAM_ACK_KDF_INFO: &[u8] = b"tb/session/kdf/ack/v1";

/// Domain label that leads the `kekid` of the receipt acknowledgement seal,
/// ahead of the transcript hash.
///
/// The label names the acknowledgement's key-encryption key, so an opener of
/// another purpose refuses the seal by its `kekid`.
pub const TIGHTBEAM_ACK_KEY_ID_DOMAIN: &[u8] = b"tb/handshake/ack/kekid/v1";

/// KDF info label of the key that seals the closing of a handshake (HKDF):
/// the client Finished, or the attributes of an anonymous client.
///
/// The key derives from the handshake secret, which mixes the
/// ephemeral-ephemeral agreement, so a later theft of a server static key
/// does not recover it. One closing travels per handshake, so the key is
/// single-use.
///
/// # Sources
///
/// - RFC 9846 § 4.5 and Appendix F.1, the client identity under handshake
///   keys: <https://datatracker.ietf.org/doc/html/rfc9846#appendix-F.1>
pub const TIGHTBEAM_CLOSING_KDF_INFO: &[u8] = b"tb/session/kdf/closing/v1";

/// Domain label that leads the `kekid` of the closing seal, ahead of the
/// transcript hash.
pub const TIGHTBEAM_CLOSING_KEY_ID_DOMAIN: &[u8] = b"tb/handshake/closing/kekid/v1";

/// HKDF-Expand label of the `MacKey` of the client Finished, the key of the
/// key-confirmation tag the closing carries.
///
/// The key expands from the PRK of the handshake secret to the output length
/// of the negotiated digest, and it keys the one HMAC over the transcript hash
/// that forms the tag. The server derives the same tag before it settles, so a
/// client that holds another secret ends the handshake at the closing.
///
/// # Sources
///
/// - RFC 9846 § 4.5.3, a Finished key per role: <https://datatracker.ietf.org/doc/html/rfc9846#section-4.5.3>
pub const TIGHTBEAM_CLIENT_FINISHED_KEY_INFO: &[u8] = b"tb/handshake/finished/client/mac/v1";

/// HKDF-Expand label of the `MacKey` of the server Finished, which the reply
/// of either flow carries.
///
/// The key keys one HMAC over the transcript hash followed by the octets of
/// the reply's signature, so the tag covers the transcript through the
/// signature. The client verifies it before it sends its closing.
///
/// # Sources
///
/// - RFC 9846 § 4.5.3, the server Finished in the server's first flight:
///   <https://datatracker.ietf.org/doc/html/rfc9846#section-4.5.3>
pub const TIGHTBEAM_SERVER_FINISHED_KEY_INFO: &[u8] = b"tb/handshake/finished/server/mac/v1";

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

/// Domain label that leads the `kekid` of every record, ahead of the
/// big-endian epoch of the directional key the record seals under.
///
/// Each directional key is the key-encryption key of its records, and the
/// epoch names the renewal that derived it.
///
/// # Sources
///
/// - RFC 5652 § 6.2.3, the `kekid` of a key both ends hold:
///   <https://datatracker.ietf.org/doc/html/rfc5652#section-6.2.3>
pub const TIGHTBEAM_RECORD_KEY_ID_DOMAIN: &[u8] = b"tb/session/record/kekid/v1";

/// KDF info string for the epoch secret retained for the in-band rekey.
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

/// The label that leads the fixed info of the combiner of a hybrid key
/// exchange, ahead of the identifier of its pairing and its shares.
///
/// # Sources
///
/// - NIST SP 800-56C Rev. 2 § 4.1, the one-step key derivation and its `FixedInfo`:
///   <https://csrc.nist.gov/pubs/sp/800/56/c/r2/final>
pub const TIGHTBEAM_HYBRID_EXCHANGE_LABEL: &[u8] = b"tb/exchange/hybrid/v1";

/// The purpose label that leads the `ukm` of the CMS opening's
/// `KEMRecipientInfo`, ahead of the 32 random octets the seal draws for
/// itself.
///
/// The `ukm` enters the KDF input of the key that wraps the content key, and
/// the server admits this label alone, so a KEM seal of another purpose does
/// not open as an opening.
///
/// # Sources
///
/// - RFC 9629 § 3 and § 5, the `ukm` and the KDF input:
///   <https://datatracker.ietf.org/doc/html/rfc9629#section-5>
pub const TIGHTBEAM_OPENING_UKM_LABEL: &[u8] = b"tb/handshake/opening/ukm/v1";

/// The purpose label that leads the `ukm` of the `KEMRecipientInfo` of a
/// frame sealed to a recipient key, ahead of the 32 random octets the seal
/// draws for itself.
///
/// A frame decryptor admits this label alone, so a KEM seal of another
/// purpose, such as the CMS opening, does not open as a frame.
///
/// # Sources
///
/// - RFC 9629 § 3 and § 5, the `ukm` and the KDF input:
///   <https://datatracker.ietf.org/doc/html/rfc9629#section-5>
pub const TIGHTBEAM_FRAME_UKM_LABEL: &[u8] = b"tb/frame/ukm/v1";

/// Domain label the CMS server Finished signs ahead of the transcript hash.
pub const TIGHTBEAM_SERVER_FINISHED_DOMAIN: &[u8] = b"tb/handshake/finished/server/v1";

/// Domain label the client Finished of either flow signs ahead of the
/// transcript hash.
pub const TIGHTBEAM_CLIENT_FINISHED_DOMAIN: &[u8] = b"tb/handshake/finished/client/v1";

/// Whether neither byte string is a prefix of the other, in a `const` context,
/// where slice comparison is unavailable. Two equal strings are each a prefix
/// of the other.
pub(crate) const fn prefix_free(a: &[u8], b: &[u8]) -> bool {
	let (mut a, mut b) = (a, b);
	while let ([a_first, a_rest @ ..], [b_first, b_rest @ ..]) = (a, b) {
		if *a_first != *b_first {
			return true;
		}
		(a, b) = (a_rest, b_rest);
	}

	false
}

/// Whether no member of `labels` is a prefix of another member.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) const fn pairwise_prefix_free(labels: &[&[u8]]) -> bool {
	let mut rest = labels;
	while let [first, later @ ..] = rest {
		let mut others = later;
		while let [second, after @ ..] = others {
			if !prefix_free(first, second) {
				return false;
			}
			others = after;
		}
		rest = later;
	}

	true
}

// Each Finished signs its role's label ahead of the transcript hash. When
// neither label is a prefix of the other, a Finished of one role never reads
// as one of the other.
const _: () = assert!(prefix_free(TIGHTBEAM_SERVER_FINISHED_DOMAIN, TIGHTBEAM_CLIENT_FINISHED_DOMAIN));

/// Minimum salt entropy in bytes for secure key derivation (HKDF).
///
/// The salt of every CMS and HPKE session key derivation must carry at least
/// this many bytes of randomness.
pub const MIN_SALT_ENTROPY_BYTES: usize = 16;

/// Maximum HKDF output size in bytes for one expansion, a dual-key expansion
/// included.
pub const MAX_HKDF_OUTPUT_SIZE: usize = 128;

/// Minimum secure key size in bytes.
pub const MIN_KEY_SIZE: usize = 16;

/// Minimum size in bytes of a non-empty blinding salt of a message commitment.
pub const MIN_SALT_SIZE: usize = 16;

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

/// Bytes in the full-size TLS record that the AES-GCM record analysis
/// counts in (2^14, RFC 9846 § 5.1).
const TLS_FULL_SIZE_RECORD_BYTES: u64 = 1 << 14;

/// Full-size TLS records AES-GCM admits per key with its safety margin
/// intact (2^24, RFC 9846 § 5.5).
const AES_GCM_FULL_SIZE_RECORDS_PER_KEY: u64 = 1 << 24;

/// The renewal volume of one directional key: 2^24 full-size TLS records,
/// which is 2^38 bytes (RFC 9846 § 5.5). Each record runs under a fresh
/// content key (RFC 5084 § 3.2), so this volume is the renewal trigger of the
/// key that wraps them.
pub(crate) const RENEWAL_VOLUME_BYTES: u64 = AES_GCM_FULL_SIZE_RECORDS_PER_KEY * TLS_FULL_SIZE_RECORD_BYTES;

/// Records one directional key wraps before its renewal at an
/// encrypted-envelope ceiling of `encrypted_envelope` bytes:
/// [`RENEWAL_VOLUME_BYTES`] divided by the ceiling. A ceiling of zero
/// counts as one byte.
///
/// # Sources
///
/// - RFC 9846 § 5.5, AEAD limits: <https://datatracker.ietf.org/doc/html/rfc9846#section-5.5>
pub(crate) const fn rekey_record_limit(encrypted_envelope: usize) -> u64 {
	match RENEWAL_VOLUME_BYTES.checked_div(encrypted_envelope as u64) {
		Some(limit) => limit,
		None => RENEWAL_VOLUME_BYTES,
	}
}

/// Record limit per directional key before a rekey is required.
///
/// It is the record limit at [`DEFAULT_MAX_ENCRYPTED_ENVELOPE`]: 2^20
/// records of up to 256 KiB, inside the renewal volume. A raised ceiling
/// lowers the limit. It keeps room for one renewal exchange up to a 2 GiB
/// ceiling (128 records) and loses it at 4 GiB (64 records).
///
/// # Enforcement
///
/// - Senders fail closed with `RekeyRequired` at their configured limit.
/// - Receipt-bearing mux sessions renew in band first.
/// - Other sessions drain through GoAway.
/// - Receivers refuse a sequence number at or past this constant, at any ceiling.
/// - Receivers refuse a record that takes the bytes one key opened past the renewal volume.
/// - Both receive-side refusals are the crate's own renewal policy. RFC 9846 § 5.5 sets the sender's limit.
/// - `with_rekey_limit` overrides the renewal and drain trigger. Both receive-side refusals stay fixed.
///
/// # Sources
///
/// - RFC 9846 § 5.5, AEAD limits: <https://datatracker.ietf.org/doc/html/rfc9846#section-5.5>
pub const DEFAULT_REKEY_RECORD_LIMIT: u64 = rekey_record_limit(DEFAULT_MAX_ENCRYPTED_ENVELOPE);

// The limit leaves room for the records one renewal exchange needs.
const _: () = assert!(DEFAULT_REKEY_RECORD_LIMIT > DEFAULT_REKEY_MIN_SPEND_RECORDS + DEFAULT_REKEY_RENEWAL_ALLOWANCE);

/// Slack above the mux drain headroom before an in-band renewal opens.
///
/// The slack gives the three-leg exchange (request, ack, control) room to
/// finish before the hard floor parks data.
///
/// - If the exchange finishes in time, data resumes under the next epoch.
/// - Otherwise data parks until the install completes, or the renewal deadline triggers the GoAway drain.
pub const DEFAULT_REKEY_RENEWAL_ALLOWANCE: u64 = 64;

/// Minimum records a server must have received since the last epoch
/// install before it accepts another `RekeyRequest`.
///
/// It bounds rekey floods. With the one-exchange-in-flight rule, it caps how
/// often a client can force the server through signature and settlement
/// work. A violation is a protocol error.
///
/// # Sources
///
/// - CWE-400, uncontrolled resource consumption: <https://cwe.mitre.org/data/definitions/400.html>
/// - RFC 9846, limit on unanswered KeyUpdate messages (same shape):
///   <https://datatracker.ietf.org/doc/html/rfc9846>
pub const DEFAULT_REKEY_MIN_SPEND_RECORDS: u64 = 4;

/// Seconds a rekey initiator waits for the exchange to complete before it
/// drains the connection.
///
/// The deadline bounds the c2s data park, which spans the Ack-to-Done window
/// plus the hard floor. When a peer goes silent, expiry releases the park and
/// takes the GoAway drain path.
pub const DEFAULT_REKEY_DEADLINE_SECS: u64 = 30;

/// Concurrent-connection cap of each accept loop, async or blocking.
///
/// The servlet, hive, and gateway planes take it, and the `server!` macro
/// takes it unless a `max_connections` policy names another.
///
/// The loop pauses its accepts while this many connections are alive, so a
/// connection flood waits in the listener backlog rather than pin unbounded
/// tasks and file descriptors.
///
/// # Sources
///
/// - CWE-400, uncontrolled resource consumption: <https://cwe.mitre.org/data/definitions/400.html>
pub const DEFAULT_MAX_SERVER_CONNECTIONS: core::num::NonZeroUsize = match core::num::NonZeroUsize::new(1024) {
	Some(cap) => cap,
	None => panic!("the default connection cap takes one connection or more"),
};

/// Delay between accept retries after a failed accept.
///
/// It spaces the retries so a descriptor shortage can clear between them.
pub const DEFAULT_ACCEPT_RETRY_DELAY: core::time::Duration = core::time::Duration::from_millis(50);

/// Linear Congruential Generator (LCG) multiplier constant.
///
/// # Properties
///
/// - Period: 2^64, the full period for a 64-bit state.
/// - Spectral test: the multiplier passes all dimensions up to at least dimension 6.
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
/// - The increment is odd, as a full period requires, so it is co-prime with 2^64.
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
/// - The `StochasticForager` load balancer for its weighted instance draw.
/// - The `PowerOfTwoChoices` load balancer for candidate-pair selection.
///
/// # Sources
///
/// - Sebastiano Vigna, `splitmix64.c` (2015, public domain): <https://xoshiro.di.unimi.it/splitmix64.c>
/// - Steele, Lea & Flood, Java 8 `SplittableRandom` (OOPSLA 2014): <https://doi.org/10.1145/2714064.2660195>
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

/// Default seed of the random fault injection strategy, so a run repeats.
///
/// The value `0xDEADBEEF` is the common debug marker for test or uninitialized
/// state. Override it in production fault tests through
/// `FaultModel::with_seed(custom_seed)`.
///
/// # Used by
///
/// - `FaultModel` for FDR-based fault injection.
/// - `TraceCollector` for runtime fault injection.
pub const DEFAULT_FAULT_SEED: u64 = 0xDEADBEEF;

/// Default backpressure threshold in basis points (90% = 9000 bps).
///
/// The hive signals `TransitStatus::ResourceExhausted` to the cluster at this
/// aggregate utilization, and the cluster should route work elsewhere.
pub const DEFAULT_BACKPRESSURE_THRESHOLD_BPS: u16 = 9000;

/// Utilization assumed for a servlet that reports none (50% = 5000 bps).
///
/// The scaling task needs a per-instance figure to average, so a servlet
/// without self-reported or hive-tracked utilization counts as half loaded.
///
/// - Half load leaves scale-up to a servlet that reports real load. A 100% figure would force a scale-up.
/// - Half load surfaces on the averages of sibling servlets. A 0% figure would hide it.
pub const UNKNOWN_SERVLET_UTILIZATION_BPS: u16 = 5000;

/// Default freshness window for signed cluster commands (30 seconds).
///
/// The window bounds the replay surface of captured commands. A hive accepts
/// a signed `ClusterCommand` only when both checks pass:
///
/// - `Frame.metadata.order` is within this many milliseconds of the hive's own
///   clock, in both directions to tolerate skew.
/// - The signature is unseen inside the window.
///
/// # Sources
///
/// - CWE-294, authentication bypass by capture-replay: <https://cwe.mitre.org/data/definitions/294.html>
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
/// - A connection that exhausts the budget ends with a GoAway.
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
/// `max_peer_initiated_streams` values, and the derivation of [`MuxSettings`]
/// clamps both directions to this ceiling.
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

/// Default per-chunk payload size advertised when none is configured: 16 KiB,
/// the HTTP/2 default frame size.
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
/// At the default chunk size, 64 chunks bound per-stream reassembly at 1 MiB
/// before the receiver must grant more.
pub const DEFAULT_MUX_STREAM_CREDIT: u64 = 64;

/// Ceiling on a negotiated per-direction session budget, in credits.
///
/// Budgets meter data-chunk credits only. The cap is half the per-key record
/// limit, so in the worst case the data records of one epoch stay under
/// [`DEFAULT_REKEY_RECORD_LIMIT`].
///
/// - Every data chunk debits at least one credit and consumes exactly one record.
/// - Control envelopes (credit grants, cancels, pings, GoAway) spend AEAD records outside the budget.
/// - The default grantor grants credit in batches, so control traffic stays at
///   `O(data chunks / window)` records, inside the other half.
/// - The bound holds at the default ceiling. At a raised one the record limit can fall below the budget.
/// - The record limit itself stays the fail-closed backstop either way.
pub const MAX_MUX_SESSION_BUDGET: u64 = DEFAULT_REKEY_RECORD_LIMIT / 2;

/// Default ceiling in bytes for an encoded cleartext envelope (128 KiB).
///
/// [`TransportLimits`] applies it when no explicit limit is configured.
/// Cleartext envelopes exist only during the handshake and in unencrypted
/// deployments, so the bound is half the encrypted ceiling.
///
/// [`TransportLimits`]: crate::transport::TransportLimits
pub const DEFAULT_MAX_CLEARTEXT_ENVELOPE: usize = 128 * 1024;

/// Default ceiling in bytes for an encoded encrypted envelope (256 KiB).
///
/// A server refuses a frame whose declared content length exceeds this
/// ceiling before it reads the content, so the declared length bounds the
/// allocation.
///
/// - The refusal closes the connection, so the sender sees a reset and no typed error.
/// - Clients therefore preflight outgoing encrypted envelopes against this ceiling.
/// - With no explicit limit set, the client fails locally with a typed `SizeExceeded`.
///
/// # Sources
///
/// - CWE-400, uncontrolled resource consumption: <https://cwe.mitre.org/data/definitions/400.html>
pub const DEFAULT_MAX_ENCRYPTED_ENVELOPE: usize = 256 * 1024;

/// Default deadline for a single read or write on an established session.
///
/// The handshake carries its own allowance. On an established session, a peer
/// that stalls mid-frame holds the connection, its task, and its accept-loop
/// permit while it stays silent. Every transport carries this deadline, even
/// one with no explicit timeout, so an established session always expires.
///
/// # Sources
///
/// - CWE-400, uncontrolled resource consumption: <https://cwe.mitre.org/data/definitions/400.html>
/// - CWE-772, missing release of resource after effective lifetime:
///   <https://cwe.mitre.org/data/definitions/772.html>
pub const DEFAULT_OPERATION_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(30);

/// Default allowance for a handshake to complete.
///
/// The default [`TransportLimits`] carries this allowance, so a server
/// configuration and every transport start from it.
///
/// [`TransportLimits`]: crate::transport::TransportLimits
pub const DEFAULT_HANDSHAKE_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(10);

/// Default ceiling in bytes for one encoded handshake-phase message.
///
/// A handshake message carries certificates, a key share, and a signature. It
/// is bounded far below a data envelope so an unauthenticated peer cannot make
/// this endpoint buffer a large allocation before it proves its identity.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const DEFAULT_HANDSHAKE_MAX_WIRE: usize = 16 * 1024;

/// Ceiling on the certificates a signer presents in the `certificates` of one
/// `SignedData`: its signing certificate and the issuers above it.
///
/// A reply, and the client Finished of a mutual client, carry the path of the
/// signing certificate below the trust anchor of the peer (RFC 5652 § 5.1). A
/// reader refuses a larger set before it walks a path or checks a signature,
/// so an unauthenticated peer cannot make it build a long path.
///
/// # Sources
///
/// - RFC 5652 § 5.1, the `certificates` of a `SignedData`:
///   <https://datatracker.ietf.org/doc/html/rfc5652#section-5.1>
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_PRESENTED_PATH: usize = 8;

/// Ceiling on the elements of a universal SET, or of a constructed
/// context-specific element, in the CMS values a peer sends, such as the
/// `signerInfos` or the `certificates` of a `SignedData`.
///
/// The pinned `der` decoder sorts such a set in time quadratic in its length
/// whatever order it arrives in. The value is above [`MAX_PRESENTED_PATH`]
/// and above every such set the crate emits.
///
/// # Sources
///
/// - ITU-T X.690 (02/2021) § 11.6, set-of components:
///   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items#page=29>
/// - CWE-407, inefficient algorithmic complexity: <https://cwe.mitre.org/data/definitions/407.html>
pub(crate) const MAX_CMS_SET_LEN: usize = 32;

/// Default ceiling for decompressed message bodies (16 MiB).
///
/// A compressed frame body arrives under the transport's envelope ceiling,
/// and zstd can inflate it past this one. The cap on the inflated size bounds
/// the memory an attacker can force with a decompression bomb.
///
/// Override it per inflator through `ZstdCompression::with_max_output`.
///
/// # Sources
///
/// - CWE-409, improper handling of highly compressed data: <https://cwe.mitre.org/data/definitions/409.html>
pub const DEFAULT_MAX_DECOMPRESSED_LEN: usize = 16 * 1024 * 1024;

/// Hard ceiling on the bytes one mux stream reassembles: a unary reassembly
/// buffer, or the body that `StreamBody::into_bytes` collects.
///
/// Credit grants may raise the chunk window, and accepted payload bytes stay
/// within this bound, which equals [`DEFAULT_MAX_DECOMPRESSED_LEN`].
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_MUX_REASSEMBLY_BYTES: usize = DEFAULT_MAX_DECOMPRESSED_LEN;

/// Reassembly bytes one connection may buffer across every open stream.
///
/// [`MAX_MUX_REASSEMBLY_BYTES`] bounds one stream, and a peer that opens many
/// streams multiplies it, so every stream also charges against this ceiling.
/// Concurrent streams in good faith stay inside four stream ceilings. Past
/// that, the peer spends this endpoint's memory and makes no progress.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_MUX_CONNECTION_REASSEMBLY_BYTES: usize = 4 * MAX_MUX_REASSEMBLY_BYTES;

/// Default cap on the live connections of one [`ConnectionPool`], across
/// every destination.
///
/// [`PoolConfig`] takes it as its default `max_connections`. A dial past the
/// cap fails with `ResourceExhausted` before it opens a socket.
///
/// # Examples
///
/// ```
/// # #[cfg(all(feature = "std", feature = "transport"))]
/// # {
/// use core::time::Duration;
///
/// use tightbeam::constants::DEFAULT_MAX_POOL_CONNECTIONS;
/// use tightbeam::transport::PoolConfig;
///
/// let idle_timeout = Some(Duration::from_secs(30));
/// let config = PoolConfig { idle_timeout, ..PoolConfig::default() };
/// assert_eq!(config.max_connections, DEFAULT_MAX_POOL_CONNECTIONS);
/// # }
/// ```
///
/// # Sources
///
/// - CWE-400, uncontrolled resource consumption: <https://cwe.mitre.org/data/definitions/400.html>
///
/// [`ConnectionPool`]: crate::transport::ConnectionPool
/// [`PoolConfig`]: crate::transport::PoolConfig
pub const DEFAULT_MAX_POOL_CONNECTIONS: core::num::NonZeroUsize = match core::num::NonZeroUsize::new(64) {
	Some(cap) => cap,
	None => panic!("the default pool cap takes one connection or more"),
};

/// Ceiling on servlet types carried in one peer advertisement.
///
/// A peer gateway advertisement lists the servlet types its colony exports.
/// A gateway refuses an oversized advertisement before it installs any of its
/// routes, and the slate it advertises and floods takes the same cap.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_ADVERTISED_TYPES: usize = 256;

/// Ceiling on distinct peer gateways tracked in one servlet registry.
///
/// Per-advertisement type caps alone leave the registry free to grow without
/// bound across many trusted signers.
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
/// members can create up to `N * (N - 1)` buckets. The budget is apart from
/// [`MAX_PEER_GATEWAYS`], so relay fan-in and direct-gateway admission each
/// hold their own.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_RELAY_BUCKETS: usize = 64;

/// Ceiling on total live relay-trail routes tracked in one servlet registry.
///
/// The ceiling is apart from [`MAX_PEER_ROUTES`], as [`MAX_RELAY_BUCKETS`] is
/// apart from [`MAX_PEER_GATEWAYS`], so a full relay plane leaves the
/// direct-route budget untouched.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_RELAY_ROUTES: usize = 1024;

/// Origin sentinel for the relay budget on work and routed stream opens.
///
/// The budget is the number of gateway forwards a request has left to spend.
/// Each peer hop decrements it, and `0` serves locally only.
///
/// - An origin stamps `u8::MAX`, which means "forward as far as policy allows".
/// - The first gateway clamps the value to its own `max_hops`, so the client
///   asserts its own reachability alone and a crafted large value clamps to the
///   same ceiling.
/// - A relayed hop carries the explicit value, which every later gateway clamps again.
/// - The sentinel is also the DER DEFAULT, so the common origin request omits the field.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const DEFAULT_HOP_BUDGET: u8 = u8::MAX;

/// Default advertisement-rumor refresh interval in milliseconds.
///
/// The advertise beat floods the local slate as an advertisement rumor when
/// the slate or the flood targets change, and once per interval, so late
/// joiners and pruned witnesses relearn the origin. Bitcoin self-announces
/// addresses the same way, on change and on a slow timer, well below one
/// refresh per beat.
///
/// # Contract
///
/// The refresh MUST stay under [`DEFAULT_GOSSIP_SEEN_TTL_MS`], the gossip
/// freshness window, so a refreshed rumor always admits as fresh.
///
/// # Sources
///
/// - Bitcoin P2P network, periodic self-announcement of the local address to
///   peers: <https://developer.bitcoin.org/devguide/p2p_network.html>
pub const DEFAULT_AD_RUMOR_REFRESH_MS: u64 = 30_000;

/// Default `max_hops` relay cap on a cluster gateway.
///
/// The default allows one forward: a gateway relays a request to a peer at
/// most once, and the peer serves locally only. Raise the cap to enable
/// relay-trail fallback, which needs two forwards end to end.
///
/// The cap bounds the forwards one request can demand from this gateway,
/// whatever budget it carries.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const DEFAULT_MAX_HOPS: u8 = 1;

/// Ceiling on the payload bytes carried in one gossip envelope.
///
/// A gossip rumor floods the peer graph, so an oversized payload amplifies
/// across every edge. The bound refuses an oversized payload before a gateway
/// records the rumor or forwards it again.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_GOSSIP_PAYLOAD_BYTES: usize = 64 * 1024;

/// Ceiling on the initial time-to-live an origin gossip may request.
///
/// The time-to-live is the hop radius of a flood, so the cap bounds the basic
/// reproduction number of one rumor, whatever a publisher requests.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_GOSSIP_TTL: u8 = 8;

/// Ceiling on distinct gossip rumors retained in one in-memory journal.
///
/// The journal retains recent rumors for deduplication and anti-entropy
/// reconciliation. The bound keeps its memory finite under a flood, and the
/// journal fails closed at the ceiling.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_GOSSIP_LOG: usize = 4096;

/// Ceiling on gossip rumors retained per signer in one in-memory journal.
///
/// The journal partitions retention per signer, so one signer's distinct
/// digests spend its own retention and leave other signers' rumors recorded.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_GOSSIP_LOG_PER_SIGNER: usize = 256;

/// Default gossip deduplication window in milliseconds.
///
/// A rumor is fresh while its stated issue time lies within this window of
/// the clock. The journal keeps its digest while it is fresh, so a replay
/// counts as seen: the recovered or immune state of the epidemic model. The
/// window must exceed the time a flood takes to cross the peer graph, so the
/// journal suppresses even a late duplicate.
pub const DEFAULT_GOSSIP_SEEN_TTL_MS: u64 = 120_000;

/// Default gossip retention window in milliseconds.
///
/// Anti-entropy reconciliation can repair only a rumor that a peer retains.
/// Retention must be at least as long as the deduplication window, so
/// reconciliation can repair a node that returns within the window.
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
/// With [`DEFAULT_GOSSIP_RATE_BURST`], it sets the sustained per-signer
/// publish rate a gateway admits: four rumors per second by default.
pub const DEFAULT_GOSSIP_RATE_REFILL_MS: u64 = 250;

/// Ceiling on distinct signers tracked by one in-memory admission store.
///
/// The bound on tracked signers keeps memory finite when many identities
/// publish. Admission fails closed once the store reaches the ceiling.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const MAX_GOSSIP_RATE_SIGNERS: usize = 4096;

/// Ceiling on unverified candidates held in the peer discovery table.
///
/// Peer-exchange hints are attacker-suppliable, so discovery bounds the `new`
/// table before it dials any hint.
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

/// Ceiling on peer-table entries that share one address prefix bucket.
///
/// Discovery buckets learned peers by /16 (IPv4) or /32 (IPv6) prefix. The
/// per-bucket bound is the eclipse countermeasure, so one network position
/// holds at most this many entries of either table.
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
/// Feeler dials verify candidates before promotion, and this bound keeps
/// discovery traffic a small constant beside the anchor and tried dials.
pub const PEER_PROBE_PER_BEAT: usize = 4;

/// Wait before a candidate that failed one feeler probe is probed again.
///
/// Each further failed probe doubles the wait, up to
/// [`PEER_PROBE_BACKOFF_MAX_MS`]. A dead address therefore costs a connect
/// timeout at a rate that drops with each failure, and its prefix yields the
/// probe slot meanwhile.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
pub const PEER_PROBE_BACKOFF_MS: u64 = 1_000;

/// Ceiling on the wait between two feeler probes of one failed candidate.
///
/// Discovery therefore probes a recovered candidate again within this wait
/// of its last failed probe.
pub const PEER_PROBE_BACKOFF_MAX_MS: u64 = 60_000;

/// Consecutive failed beat dials before a tried peer is evicted.
///
/// The beat re-dials every tried resident, so consecutive failures are the
/// liveness clock.
///
/// - The threshold tolerates a two-beat partition.
/// - Eviction frees the prefix bucket slot for a live candidate, and discovery refills the table.
/// - Eviction is the fail-closed direction.
pub const MAX_PEER_TRIED_FAILURES: usize = 3;

#[cfg(test)]
mod tests {
	use super::*;

	/// A prefix pair at the two ends of a set fails the check, so the check
	/// reaches every pair of the set.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[test]
	fn a_prefix_pair_at_the_ends_of_a_set_is_found() {
		let labels: [&[u8]; 3] = [b"tb/a", b"tb/b", b"tb/a/v1"];
		let free = pairwise_prefix_free(&labels);
		assert!(!free);
	}
}
