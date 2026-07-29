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

use std::collections::HashMap;
use std::sync::Mutex;

use super::ClusterError;
use crate::colony::common::{canonical_bytes, is_bare_servlet_type, ColonyNamespace, GossipEnvelope};
use crate::constants::{
	DEFAULT_GOSSIP_RETENTION_MS, MAX_GOSSIP_LOG, MAX_GOSSIP_LOG_PER_SIGNER, MAX_GOSSIP_PAYLOAD_BYTES,
};
use crate::crypto::hash::{Digest, Sha3_256};
use crate::policy::TransitStatus;

/// Fixed 32-byte content digest of a gossip rumor (Sha3-256 output).
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
#[must_use]
pub fn gossip_digest(envelope: &GossipEnvelope) -> GossipDigest {
	let target_bytes = canonical_bytes(&envelope.target);
	let mut hasher = Sha3_256::new();
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
	/// Refuses an oversized payload, a rumor outside the freshness window,
	/// or a target that is not a bare servlet type in `namespace`.
	pub fn admit(
		envelope: &GossipEnvelope,
		namespace: &ColonyNamespace,
		seen_ttl_ms: u64,
		now_ms: u64,
	) -> Result<Self, TransitStatus> {
		let within_payload = envelope.payload.len() <= MAX_GOSSIP_PAYLOAD_BYTES;
		let fresh = now_ms.abs_diff(envelope.issued_at_ms) <= seen_ttl_ms;
		let target_bare = is_bare_servlet_type(namespace, &envelope.target);

		if within_payload && fresh && target_bare {
			let type_key = canonical_bytes(&envelope.target);
			let digest = gossip_digest(envelope);

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

	/// Digests currently retained, summarized to a peer during reconciliation.
	fn held_digests(&self) -> Result<Vec<GossipDigest>, ClusterError>;

	/// Retained envelopes for the digests a peer reported missing.
	fn fetch(&self, wanted: &[GossipDigest]) -> Result<Vec<GossipEnvelope>, ClusterError>;

	/// Retained rumors not yet delivered to a local instance (retry set).
	fn pending_local(&self) -> Result<Vec<GossipEnvelope>, ClusterError>;

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
/// evict rumors recorded for other signers. Retention prunes on write in
/// both clock directions, tolerating a backward clock step.
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
}

impl Default for MemoryGossipJournal {
	fn default() -> Self {
		Self::new(DEFAULT_GOSSIP_RETENTION_MS)
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
		entries.retain(|_, entry| now_ms.abs_diff(entry.recorded_ms) <= self.retention_ms);

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

	fn held_digests(&self) -> Result<Vec<GossipDigest>, ClusterError> {
		let entries = self.entries.lock()?;
		let digests = entries.keys().copied().collect();
		Ok(digests)
	}

	fn fetch(&self, wanted: &[GossipDigest]) -> Result<Vec<GossipEnvelope>, ClusterError> {
		let entries = self.entries.lock()?;
		let found = wanted
			.iter()
			.filter_map(|digest| entries.get(digest))
			.map(|entry| entry.envelope.clone())
			.collect();

		Ok(found)
	}

	fn pending_local(&self) -> Result<Vec<GossipEnvelope>, ClusterError> {
		let entries = self.entries.lock()?;
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

	fn nestmate_ns() -> ColonyNamespace {
		ColonyNamespace::default()
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
		assert_eq!(gossip_digest(&rumor), gossip_digest(&rumor));
	}

	#[test]
	fn digest_ignores_ttl() {
		let low = envelope(1_000, 1, vec![1, 2, 3]);
		let high = envelope(1_000, 8, vec![1, 2, 3]);
		assert_eq!(gossip_digest(&low), gossip_digest(&high));
	}

	#[test]
	fn digest_tracks_payload_and_time() {
		let base = envelope(1_000, 4, vec![1, 2, 3]);
		let other_payload = envelope(1_000, 4, vec![9, 9, 9]);
		let other_time = envelope(2_000, 4, vec![1, 2, 3]);
		assert_ne!(gossip_digest(&base), gossip_digest(&other_payload));
		assert_ne!(gossip_digest(&base), gossip_digest(&other_time));
	}

	#[test]
	fn digest_frames_target_payload_boundary() {
		let ping = nestmate_ns().servlet("ping").expect("static servlet name");
		let pin = nestmate_ns().servlet("pin").expect("static servlet name");
		let longer_target = GossipEnvelope { issued_at_ms: 1_000, target: ping, ttl: 4, payload: b"data".to_vec() };
		let shorter_target = GossipEnvelope { issued_at_ms: 1_000, target: pin, ttl: 4, payload: b"gdata".to_vec() };
		assert_ne!(gossip_digest(&longer_target), gossip_digest(&shorter_target));
	}

	#[test]
	fn admit_accepts_valid_rumor() {
		let rumor = envelope(1_000, 4, vec![1, 2, 3]);
		let admitted = AdmittedGossip::admit(&rumor, &nestmate_ns(), 30_000, 1_000).expect("valid rumor");
		assert_eq!(admitted.type_key(), canonical_bytes(&ping_target()).as_slice());
		assert_eq!(admitted.digest(), gossip_digest(&rumor));
	}

	#[test]
	fn admit_refuses_oversized_payload() {
		let rumor = envelope(1_000, 4, vec![0u8; MAX_GOSSIP_PAYLOAD_BYTES + 1]);
		let status = AdmittedGossip::admit(&rumor, &nestmate_ns(), 30_000, 1_000);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn admit_refuses_stale_rumor() {
		let rumor = envelope(1_000, 4, vec![1, 2, 3]);
		let status = AdmittedGossip::admit(&rumor, &nestmate_ns(), 30_000, 100_000);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn admit_refuses_instance_target() {
		let instance = servlet_instance(&ping_target(), "127.0.0.1:9000");
		let rumor = GossipEnvelope { issued_at_ms: 1_000, target: instance, ttl: 4, payload: vec![1] };
		let status = AdmittedGossip::admit(&rumor, &nestmate_ns(), 30_000, 1_000);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn record_dedups_same_digest() {
		let journal = MemoryGossipJournal::default();
		let rumor = envelope(1_000, 4, vec![1, 2, 3]);
		let digest = gossip_digest(&rumor);

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
		journal
			.record(b"signer-a", gossip_digest(&first), &first, 1_000)
			.expect("first fits");
		let overflow = journal.record(b"signer-a", gossip_digest(&second), &second, 1_000);
		assert!(matches!(overflow, Err(ClusterError::GossipJournalAtCapacity)));
	}

	#[test]
	fn record_fails_closed_at_per_signer_capacity() {
		let journal = MemoryGossipJournal::with_limits(30_000, 8, 1);
		let first = envelope(1_000, 4, vec![1]);
		let second = envelope(1_000, 4, vec![2]);
		let other = envelope(1_000, 4, vec![3]);

		journal
			.record(b"signer-a", gossip_digest(&first), &first, 1_000)
			.expect("first signer fits");

		let over = journal.record(b"signer-a", gossip_digest(&second), &second, 1_000);
		let other_signer = journal
			.record(b"signer-b", gossip_digest(&other), &other, 1_000)
			.expect("other signer fits");
		assert!(matches!(over, Err(ClusterError::GossipJournalAtCapacity)));
		assert_eq!(other_signer, Admission::New);
	}

	#[test]
	fn pending_local_clears_on_ack() {
		let journal = MemoryGossipJournal::default();
		let rumor = envelope(1_000, 4, vec![1, 2, 3]);
		let digest = gossip_digest(&rumor);

		journal.record(b"signer-a", digest, &rumor, 1_000).expect("record");
		let before = journal.pending_local().expect("pending before ack");
		journal.ack_local(&digest).expect("ack");

		let after = journal.pending_local().expect("pending after ack");
		assert_eq!(before.len(), 1);
		assert_eq!(after.len(), 0);
	}

	#[test]
	fn fetch_returns_only_wanted() {
		let journal = MemoryGossipJournal::default();
		let first = envelope(1_000, 4, vec![1]);
		let second = envelope(1_000, 4, vec![2]);
		let first_digest = gossip_digest(&first);

		journal.record(b"signer-a", first_digest, &first, 1_000).expect("first");
		journal
			.record(b"signer-a", gossip_digest(&second), &second, 1_000)
			.expect("second");

		let fetched = journal.fetch(&[first_digest]).expect("fetch");
		assert_eq!(fetched, vec![first]);
	}

	#[test]
	fn record_prunes_expired_entries() {
		let journal = MemoryGossipJournal::with_limits(100, 8, 8);
		let early = envelope(1_000, 4, vec![1]);
		let late = envelope(1_000, 4, vec![2]);

		journal
			.record(b"signer-a", gossip_digest(&early), &early, 0)
			.expect("early record");
		journal
			.record(b"signer-a", gossip_digest(&late), &late, 200)
			.expect("late record");

		let held = journal.held_digests().expect("held");
		assert_eq!(held, vec![gossip_digest(&late)]);
	}
}
