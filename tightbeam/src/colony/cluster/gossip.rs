//! Gossip admission, content digest, and retention journal
//!
//! Gossip is the rumor-mongering plane layered on the anti-entropy advertise
//! beat: a rumor floods the peer graph, is delivered to one local instance of
//! its target servlet type, and is forwarded while its time-to-live remains.
//!
//! [`AdmittedGossip`] is the only path from a wire envelope to a deliverable
//! rumor: construction validates payload size, freshness, and target, and
//! computes the content digest used for deduplication. [`GossipJournal`] is
//! the pluggable dedup-and-retention store; [`MemoryGossipJournal`] is the
//! in-memory default whose per-signer partitioning stops one signer from
//! evicting rumors recorded for others.

use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use digest::consts::U32;
use digest::OutputSizeUser;

use super::ClusterError;
use crate::colony::common::{canonical_bytes, is_bare_servlet_type, ColonyNamespace, GossipEnvelope};
use crate::constants::{
	DEFAULT_GOSSIP_RETENTION_MS, DEFAULT_GOSSIP_SEEN_TTL_MS, DEFAULT_GOSSIP_TTL, MAX_GOSSIP_LOG,
	MAX_GOSSIP_LOG_PER_SIGNER, MAX_GOSSIP_PAYLOAD_BYTES, MAX_GOSSIP_TTL,
};
use crate::crypto::hash::Digest;
use crate::policy::TransitStatus;

/// Fixed 32-byte content digest of a gossip rumor
///
/// The hash algorithm is the deployment's crypto profile digest (defaulting
/// to Sha3-256), constrained to a 256-bit output. It is a cluster-wide
/// invariant: deduplication and anti-entropy reconciliation require every
/// gateway to derive the identical digest for the same rumor.
pub type GossipDigest = [u8; 32];

/// Whether a recorded rumor is newly seen or a suppressed duplicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
	/// The digest was unseen and is now recorded; deliver and forward it.
	New,
	/// The digest was already recorded within the window; drop the rumor.
	Duplicate,
}

/// Content digest binding a rumor to its issue time, target, and payload
///
/// The time-to-live is excluded so the digest is stable as a rumor loses
/// hops across relays. Two publishes of identical content at different
/// times are distinct rumors because `issued_at_ms` participates. Each
/// variable-length field is prefixed with its length so distinct
/// target-and-payload splits cannot collide onto one digest (CWE-694).
///
/// The digest algorithm `D` is the deployment crypto profile digest and is
/// a cluster-wide invariant; a per-gateway choice would break dedup.
#[must_use]
pub fn gossip_digest<D>(envelope: &GossipEnvelope) -> GossipDigest
where
	D: Digest + OutputSizeUser<OutputSize = U32>,
{
	let target_bytes = canonical_bytes(&envelope.target);
	let mut hasher = D::new();
	hasher.update(envelope.issued_at_ms.to_be_bytes());
	hasher.update((target_bytes.len() as u64).to_be_bytes());
	hasher.update(&target_bytes);
	hasher.update((envelope.payload.len() as u64).to_be_bytes());
	hasher.update(&envelope.payload);

	let output = hasher.finalize();
	let mut digest = [0u8; 32];
	digest.copy_from_slice(&output);
	digest
}

/// A gossip envelope that passed payload, freshness, and target checks
///
/// Construction via [`AdmittedGossip::admit`] is the only path, so the
/// journal and delivery path never receive an unvalidated rumor. Signature
/// verification against the correct trust plane happens in the gateway
/// handler before admission; admission covers only envelope-level policy.
pub struct AdmittedGossip {
	digest: GossipDigest,
	type_key: Vec<u8>,
}

impl AdmittedGossip {
	/// Admit a wire envelope, failing closed with the refusal status
	///
	/// Refuses an oversized payload, a time-to-live above [`MAX_GOSSIP_TTL`],
	/// a rumor outside the freshness window, or a target that is not a bare
	/// servlet type in `namespace`. The time-to-live cap is enforced here,
	/// the trust boundary, so a hostile signer cannot request a wider flood
	/// radius by bypassing the publish-time clamp (CWE-770). The digest
	/// algorithm `D` matches the deployment crypto profile.
	pub fn admit<D>(
		envelope: &GossipEnvelope,
		namespace: &ColonyNamespace,
		seen_ttl_ms: u64,
		now_ms: u64,
	) -> Result<Self, TransitStatus>
	where
		D: Digest + OutputSizeUser<OutputSize = U32>,
	{
		let within_payload = envelope.payload.len() <= MAX_GOSSIP_PAYLOAD_BYTES;
		let within_ttl = envelope.ttl <= MAX_GOSSIP_TTL;
		let fresh = now_ms.abs_diff(envelope.issued_at_ms) <= seen_ttl_ms;
		let target_bare = is_bare_servlet_type(namespace, &envelope.target);

		if within_payload && within_ttl && fresh && target_bare {
			let type_key = canonical_bytes(&envelope.target);
			let digest = gossip_digest::<D>(envelope);

			let admitted = Self { digest, type_key };
			Ok(admitted)
		} else {
			Err(TransitStatus::PermissionDenied)
		}
	}

	/// Content digest used for deduplication and reconciliation.
	#[must_use]
	pub fn digest(&self) -> GossipDigest {
		self.digest
	}

	/// Canonical type key the rumor is delivered to on this colony.
	#[must_use]
	pub fn type_key(&self) -> &[u8] {
		&self.type_key
	}
}

/// Deduplication and retention store backing gossip delivery and anti-entropy
///
/// The gateway calls only this interface, so delivery strength is a policy
/// choice: the in-memory default gives bounded-window eventual delivery,
/// while a durable implementation can retain rumors across restarts. Errors
/// are typed [`ClusterError`] variants so a backend maps its own failure
/// opaquely.
pub trait GossipJournal: Send + Sync {
	/// Deduplicate and retain one rumor in a single step
	///
	/// Returns [`Admission::New`] when the digest was unseen (and is now
	/// recorded), [`Admission::Duplicate`] when it was already retained, and
	/// fails closed once a capacity bound is reached.
	fn record(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		envelope: &GossipEnvelope,
		now_ms: u64,
	) -> Result<Admission, ClusterError>;

	/// Digests still within the retention window, summarized to a peer
	/// during reconciliation. Entries older than the window are excluded.
	fn held_digests(&self, now_ms: u64) -> Result<Vec<GossipDigest>, ClusterError>;

	/// Retained envelopes for the digests a peer reported missing, excluding
	/// any that have aged out of the retention window.
	fn fetch(&self, wanted: &[GossipDigest], now_ms: u64) -> Result<Vec<GossipEnvelope>, ClusterError>;

	/// Retained rumors not yet delivered to a local instance (retry set),
	/// excluding any that have aged out of the retention window.
	fn pending_local(&self, now_ms: u64) -> Result<Vec<GossipEnvelope>, ClusterError>;

	/// Confirm a local delivery so the rumor stops being retried.
	fn ack_local(&self, digest: &GossipDigest) -> Result<(), ClusterError>;
}

/// One retained rumor and the bookkeeping the journal tracks for it.
struct JournalEntry {
	envelope: GossipEnvelope,
	signer: Vec<u8>,
	recorded_ms: u64,
	delivered_local: bool,
}

/// In-memory [`GossipJournal`] with per-signer partitioning
///
/// Dedup is global on the content digest, so a rumor re-signed by a relaying
/// gateway is still recognized. The per-signer capacity bounds how many
/// distinct rumors one signer may hold, so a signer minting digests cannot
/// evict rumors recorded for other signers. Retention prunes on every read
/// and write in both clock directions, tolerating a backward clock step, so
/// an aged-out rumor is never returned even during a quiet period.
pub struct MemoryGossipJournal {
	entries: Mutex<HashMap<GossipDigest, JournalEntry>>,
	retention_ms: u64,
	capacity: usize,
	per_signer_capacity: usize,
}

impl MemoryGossipJournal {
	/// Create a journal with the given retention window and default caps.
	#[must_use]
	pub fn new(retention_ms: u64) -> Self {
		Self::with_limits(retention_ms, MAX_GOSSIP_LOG, MAX_GOSSIP_LOG_PER_SIGNER)
	}

	/// Create a journal with explicit retention window and capacity bounds.
	#[must_use]
	pub fn with_limits(retention_ms: u64, capacity: usize, per_signer_capacity: usize) -> Self {
		Self { entries: Mutex::new(HashMap::new()), retention_ms, capacity, per_signer_capacity }
	}

	/// Drop entries whose age exceeds the retention window in either clock
	/// direction. The single pruning rule keeps reads and writes consistent.
	fn prune(entries: &mut HashMap<GossipDigest, JournalEntry>, retention_ms: u64, now_ms: u64) {
		entries.retain(|_, entry| now_ms.abs_diff(entry.recorded_ms) <= retention_ms);
	}
}

impl Default for MemoryGossipJournal {
	fn default() -> Self {
		Self::new(DEFAULT_GOSSIP_RETENTION_MS)
	}
}

/// Gossip subsystem configuration
///
/// Groups the rumor freshness window, origin time-to-live, anti-entropy
/// retention window, and the pluggable [`GossipJournal`] into one unit, the
/// same shape as the heartbeat and pheromone configurations.
pub struct GossipConf {
	/// Freshness window a relayed rumor's `issued_at_ms` must fall within;
	/// also the recovered-to-immune duration. Must exceed flood traversal.
	pub seen_ttl: Duration,
	/// Time-to-live an origin publish starts a rumor with, clamped to
	/// [`MAX_GOSSIP_TTL`]. Bounds the hop radius of one flood.
	pub ttl: u8,
	/// Anti-entropy retention window; must be greater than or equal to
	/// `seen_ttl`.
	pub retention: Duration,
	/// Dedup and retention store backing gossip delivery and anti-entropy.
	pub journal: Arc<dyn GossipJournal>,
}

impl Default for GossipConf {
	fn default() -> Self {
		Self {
			seen_ttl: Duration::from_millis(DEFAULT_GOSSIP_SEEN_TTL_MS),
			ttl: DEFAULT_GOSSIP_TTL,
			retention: Duration::from_millis(DEFAULT_GOSSIP_RETENTION_MS),
			journal: Arc::new(MemoryGossipJournal::default()),
		}
	}
}

impl core::fmt::Debug for GossipConf {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("GossipConf")
			.field("seen_ttl", &self.seen_ttl)
			.field("ttl", &self.ttl)
			.field("retention", &self.retention)
			.field("journal", &"<dyn GossipJournal>")
			.finish()
	}
}

impl GossipJournal for MemoryGossipJournal {
	fn record(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		envelope: &GossipEnvelope,
		now_ms: u64,
	) -> Result<Admission, ClusterError> {
		let mut entries = self.entries.lock()?;
		Self::prune(&mut entries, self.retention_ms, now_ms);

		if entries.contains_key(&digest) {
			return Ok(Admission::Duplicate);
		}

		let signer_held = entries.values().filter(|entry| entry.signer == signer).count();
		let within_global = entries.len() < self.capacity;
		let within_signer = signer_held < self.per_signer_capacity;

		if within_global && within_signer {
			let entry = JournalEntry {
				envelope: envelope.clone(),
				signer: signer.to_vec(),
				recorded_ms: now_ms,
				delivered_local: false,
			};
			entries.insert(digest, entry);

			Ok(Admission::New)
		} else {
			Err(ClusterError::GossipJournalAtCapacity)
		}
	}

	fn held_digests(&self, now_ms: u64) -> Result<Vec<GossipDigest>, ClusterError> {
		let mut entries = self.entries.lock()?;
		Self::prune(&mut entries, self.retention_ms, now_ms);
		let digests = entries.keys().copied().collect();

		Ok(digests)
	}

	fn fetch(&self, wanted: &[GossipDigest], now_ms: u64) -> Result<Vec<GossipEnvelope>, ClusterError> {
		let mut entries = self.entries.lock()?;
		Self::prune(&mut entries, self.retention_ms, now_ms);

		let found = wanted
			.iter()
			.filter_map(|digest| entries.get(digest))
			.map(|entry| entry.envelope.clone())
			.collect();

		Ok(found)
	}

	fn pending_local(&self, now_ms: u64) -> Result<Vec<GossipEnvelope>, ClusterError> {
		let mut entries = self.entries.lock()?;
		Self::prune(&mut entries, self.retention_ms, now_ms);

		let pending = entries
			.values()
			.filter(|entry| !entry.delivered_local)
			.map(|entry| entry.envelope.clone())
			.collect();

		Ok(pending)
	}

	fn ack_local(&self, digest: &GossipDigest) -> Result<(), ClusterError> {
		let mut entries = self.entries.lock()?;
		if let Some(entry) = entries.get_mut(digest) {
			entry.delivered_local = true;
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::common::servlet_instance;
	use crate::crypto::hash::Sha3_256;

	fn nestmate_ns() -> ColonyNamespace {
		ColonyNamespace::default()
	}

	fn digest(envelope: &GossipEnvelope) -> GossipDigest {
		gossip_digest::<Sha3_256>(envelope)
	}

	fn ping_target() -> crate::utils::urn::Urn<'static> {
		nestmate_ns().servlet("ping").expect("static servlet name")
	}

	fn envelope(issued_at_ms: u64, ttl: u8, payload: Vec<u8>) -> GossipEnvelope {
		GossipEnvelope { issued_at_ms, target: ping_target(), ttl, payload }
	}

	#[test]
	fn digest_is_deterministic() {
		let rumor = envelope(1_000, 4, vec![1, 2, 3]);
		assert_eq!(digest(&rumor), digest(&rumor));
	}

	#[test]
	fn digest_ignores_ttl() {
		let low = envelope(1_000, 1, vec![1, 2, 3]);
		let high = envelope(1_000, 8, vec![1, 2, 3]);
		assert_eq!(digest(&low), digest(&high));
	}

	#[test]
	fn digest_tracks_payload_and_time() {
		let base = envelope(1_000, 4, vec![1, 2, 3]);
		let other_payload = envelope(1_000, 4, vec![9, 9, 9]);
		let other_time = envelope(2_000, 4, vec![1, 2, 3]);
		assert_ne!(digest(&base), digest(&other_payload));
		assert_ne!(digest(&base), digest(&other_time));
	}

	#[test]
	fn digest_frames_target_payload_boundary() {
		let ping = nestmate_ns().servlet("ping").expect("static servlet name");
		let pin = nestmate_ns().servlet("pin").expect("static servlet name");
		let longer_target = GossipEnvelope { issued_at_ms: 1_000, target: ping, ttl: 4, payload: b"data".to_vec() };
		let shorter_target = GossipEnvelope { issued_at_ms: 1_000, target: pin, ttl: 4, payload: b"gdata".to_vec() };
		assert_ne!(digest(&longer_target), digest(&shorter_target));
	}

	#[test]
	fn admit_accepts_valid_rumor() {
		let rumor = envelope(1_000, 4, vec![1, 2, 3]);
		let admitted = AdmittedGossip::admit::<Sha3_256>(&rumor, &nestmate_ns(), 30_000, 1_000).expect("valid rumor");
		assert_eq!(admitted.type_key(), canonical_bytes(&ping_target()).as_slice());
		assert_eq!(admitted.digest(), digest(&rumor));
	}

	#[test]
	fn admit_refuses_oversized_payload() {
		let rumor = envelope(1_000, 4, vec![0u8; MAX_GOSSIP_PAYLOAD_BYTES + 1]);
		let status = AdmittedGossip::admit::<Sha3_256>(&rumor, &nestmate_ns(), 30_000, 1_000);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn admit_refuses_excessive_ttl() {
		let rumor = envelope(1_000, MAX_GOSSIP_TTL + 1, vec![1, 2, 3]);
		let status = AdmittedGossip::admit::<Sha3_256>(&rumor, &nestmate_ns(), 30_000, 1_000);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn admit_refuses_stale_rumor() {
		let rumor = envelope(1_000, 4, vec![1, 2, 3]);
		let status = AdmittedGossip::admit::<Sha3_256>(&rumor, &nestmate_ns(), 30_000, 100_000);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn admit_refuses_instance_target() {
		let instance = servlet_instance(&ping_target(), "127.0.0.1:9000");
		let rumor = GossipEnvelope { issued_at_ms: 1_000, target: instance, ttl: 4, payload: vec![1] };
		let status = AdmittedGossip::admit::<Sha3_256>(&rumor, &nestmate_ns(), 30_000, 1_000);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn record_dedups_same_digest() {
		let journal = MemoryGossipJournal::default();
		let rumor = envelope(1_000, 4, vec![1, 2, 3]);
		let digest = digest(&rumor);

		let first = journal.record(b"signer-a", digest, &rumor, 1_000).expect("first record");
		let second = journal.record(b"signer-a", digest, &rumor, 1_000).expect("second record");
		assert_eq!(first, Admission::New);
		assert_eq!(second, Admission::Duplicate);
	}

	#[test]
	fn record_fails_closed_at_global_capacity() {
		let journal = MemoryGossipJournal::with_limits(30_000, 1, 8);
		let first = envelope(1_000, 4, vec![1]);
		let second = envelope(1_000, 4, vec![2]);

		journal.record(b"signer-a", digest(&first), &first, 1_000).expect("first fits");

		let overflow = journal.record(b"signer-a", digest(&second), &second, 1_000);
		assert!(matches!(overflow, Err(ClusterError::GossipJournalAtCapacity)));
	}

	#[test]
	fn record_fails_closed_at_per_signer_capacity() {
		let journal = MemoryGossipJournal::with_limits(30_000, 8, 1);
		let first = envelope(1_000, 4, vec![1]);
		let second = envelope(1_000, 4, vec![2]);
		let other = envelope(1_000, 4, vec![3]);

		journal
			.record(b"signer-a", digest(&first), &first, 1_000)
			.expect("first signer fits");

		let over = journal.record(b"signer-a", digest(&second), &second, 1_000);
		let other_signer = journal
			.record(b"signer-b", digest(&other), &other, 1_000)
			.expect("other signer fits");
		assert!(matches!(over, Err(ClusterError::GossipJournalAtCapacity)));
		assert_eq!(other_signer, Admission::New);
	}

	#[test]
	fn pending_local_clears_on_ack() {
		let journal = MemoryGossipJournal::default();
		let rumor = envelope(1_000, 4, vec![1, 2, 3]);
		let digest = digest(&rumor);

		journal.record(b"signer-a", digest, &rumor, 1_000).expect("record");
		let before = journal.pending_local(1_000).expect("pending before ack");
		journal.ack_local(&digest).expect("ack");

		let after = journal.pending_local(1_000).expect("pending after ack");
		assert_eq!(before.len(), 1);
		assert_eq!(after.len(), 0);
	}

	#[test]
	fn fetch_returns_only_wanted() {
		let journal = MemoryGossipJournal::default();
		let first = envelope(1_000, 4, vec![1]);
		let second = envelope(1_000, 4, vec![2]);
		let first_digest = digest(&first);

		journal.record(b"signer-a", first_digest, &first, 1_000).expect("first");
		journal.record(b"signer-a", digest(&second), &second, 1_000).expect("second");

		let fetched = journal.fetch(&[first_digest], 1_000).expect("fetch");
		assert_eq!(fetched, vec![first]);
	}

	#[test]
	fn record_prunes_expired_entries() {
		let journal = MemoryGossipJournal::with_limits(100, 8, 8);
		let early = envelope(1_000, 4, vec![1]);
		let late = envelope(1_000, 4, vec![2]);

		journal.record(b"signer-a", digest(&early), &early, 0).expect("early record");
		journal.record(b"signer-a", digest(&late), &late, 200).expect("late record");

		let held = journal.held_digests(200).expect("held");
		assert_eq!(held, vec![digest(&late)]);
	}

	#[test]
	fn reads_prune_expired_entries_without_a_write() {
		let journal = MemoryGossipJournal::with_limits(100, 8, 8);
		let rumor = envelope(1_000, 4, vec![1]);
		let rumor_digest = digest(&rumor);

		journal.record(b"signer-a", rumor_digest, &rumor, 0).expect("record");

		let held = journal.held_digests(1_000).expect("held past window");
		let fetched = journal.fetch(&[rumor_digest], 1_000).expect("fetch past window");
		let pending = journal.pending_local(1_000).expect("pending past window");
		assert_eq!(held.len(), 0);
		assert_eq!(fetched.len(), 0);
		assert_eq!(pending.len(), 0);
	}
}
