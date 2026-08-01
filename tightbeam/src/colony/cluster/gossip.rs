//! Gossip admission, content digest, and retention journal.
//!
//! - Floods origin-signed rumors across gateways of one colony.
//! - Local delivery follows the operator ingress policy.
//! - Forwarding continues while hop time-to-live remains.
//!
//! Flood scope is colony membership: the origin certificate URI SAN
//! colony URN MUST equal the local gateway colony URN.
//!
//! A rumor is an origin-signed [`Frame`]. The accepting gateway signs once.
//! Later hops and anti-entropy repair carry those same signed bytes.
//! Hop radius lives in OUTER relay-frame `metadata.lifetime`.
//!
//! [`AdmittedGossip`] is the only path from a wire rumor to delivery.
//! [`GossipJournal`] stores digests for deduplication and retention.
//! [`MemoryGossipJournal`] is the in-memory default.

use core::mem::discriminant;
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use super::ClusterError;
use crate::asn1::Frame;
use crate::colony::common::{GossipRumor, GossipRumorKind};
use crate::constants::{
	DEFAULT_GOSSIP_RATE_BURST, DEFAULT_GOSSIP_RATE_REFILL_MS, DEFAULT_GOSSIP_RETENTION_MS, DEFAULT_GOSSIP_SEEN_TTL_MS,
	DEFAULT_GOSSIP_TTL, MAX_GOSSIP_LOG, MAX_GOSSIP_LOG_PER_SIGNER, MAX_GOSSIP_PAYLOAD_BYTES, MAX_GOSSIP_RATE_SIGNERS,
	MAX_GOSSIP_TTL,
};
use crate::crypto::hash::{Digest, OutputSizeUser, U32};
use crate::der::Encode;
use crate::policy::TransitStatus;
use crate::utils::urn::Urn;
use crate::{decode, encode};

/// Fixed 32-byte content digest of a gossip rumor.
///
/// Algorithm is the deployment crypto-profile digest.
/// Every gateway MUST derive the same digest for the same rumor.
pub type GossipDigest = [u8; 32];

/// Whether a recorded rumor is newly seen or a suppressed duplicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
	/// Digest was unseen and is now recorded. Deliver and forward it.
	New,
	/// Digest was already recorded in the window. Drop the rumor.
	Duplicate,
}

/// Digest over the canonical DER encoding of a rumor [`Frame`].
///
/// Coverage includes identity, issue time, payload, and origin signature.
/// Hop radius lives on the OUTER relay frame and MUST NOT enter the digest.
/// Algorithm `D` MUST be the cluster crypto-profile digest (CWE-694).
pub fn gossip_digest<D>(rumor: &Frame) -> Result<GossipDigest, ClusterError>
where
	D: Digest + OutputSizeUser<OutputSize = U32>,
{
	let bytes = encode(rumor)?;
	let mut hasher = D::new();
	hasher.update(&bytes);

	let output = hasher.finalize();
	let mut digest = [0u8; 32];
	digest.copy_from_slice(&output);
	Ok(digest)
}

/// Digests advertised by a peer that this gateway does not retain.
///
/// Reconciliation is a set difference over content digests.
/// A repeated advertisement entry appears once in the want list so a peer
/// cannot inflate the reply by repeating itself (CWE-770).
#[must_use]
pub fn gossip_want(advertised: &[Vec<u8>], held: &[GossipDigest]) -> Vec<Vec<u8>> {
	let local: HashSet<&[u8]> = held.iter().map(|digest| digest.as_slice()).collect();
	let mut unique: HashSet<&[u8]> = HashSet::new();

	advertised
		.iter()
		.filter(|digest| !local.contains(digest.as_slice()))
		.filter(|digest| unique.insert(digest.as_slice()))
		.cloned()
		.collect()
}

/// Digests from a peer want-list that decode to a fixed 32-byte digest.
///
/// Wrong-length entries cannot be retained digests and are dropped (CWE-20).
/// Duplicates collapse to one so a peer MUST NOT multiply repair pushes (CWE-770).
#[must_use]
pub fn wanted_digests(want: &[Vec<u8>]) -> Vec<GossipDigest> {
	let mut unique: HashSet<GossipDigest> = HashSet::new();

	want.iter()
		.filter_map(|bytes| GossipDigest::try_from(bytes.as_slice()).ok())
		.filter(|digest| unique.insert(*digest))
		.collect()
}

/// Whether rumor issue time falls inside the freshness window.
///
/// Shared by admission and anti-entropy repair. Journals retain by record
/// time, so a relayed rumor may still be fetchable after the issue window.
#[must_use]
pub fn gossip_fresh(order_ms: u64, seen_ttl_ms: u64, now_ms: u64) -> bool {
	now_ms.abs_diff(order_ms) <= seen_ttl_ms
}

/// DER encoding of the claimed `SignerIdentifier` on a frame.
///
/// Audit evidence on gossip refusals before trust resolution.
/// `None` when the frame is unsigned or encoding fails.
#[must_use]
pub fn signer_attribution(frame: &Frame) -> Option<Vec<u8>> {
	let signer_info = frame.nonrepudiation.as_ref()?;
	let attribution = Encode::to_der(&signer_info.sid).ok()?;

	Some(attribution)
}

/// Rumor that passed payload, hop-radius, and freshness checks.
///
/// Construct only through [`AdmittedGossip::admit`].
/// Signature and colony-membership checks run in the gateway handler first.
pub struct AdmittedGossip {
	digest: GossipDigest,
	payload: Vec<u8>,
	kind: GossipRumorKind,
}

impl AdmittedGossip {
	/// Admit one rumor frame. Fail closed with a refusal status.
	///
	/// `ttl` is the remaining hop radius from OUTER `metadata.lifetime`.
	/// Freshness uses rumor `metadata.order` as the signed issue time.
	/// Refuse decode failure, oversized payload, `ttl` above [`MAX_GOSSIP_TTL`],
	/// or a stale issue time. Cap hop radius here at the trust boundary (CWE-770).
	pub fn admit<D>(rumor: &Frame, ttl: u64, seen_ttl_ms: u64, now_ms: u64) -> Result<Self, TransitStatus>
	where
		D: Digest + OutputSizeUser<OutputSize = U32>,
	{
		let body: GossipRumor = decode(&rumor.message).map_err(|_| TransitStatus::PermissionDenied)?;

		let within_payload = body.payload.len() <= MAX_GOSSIP_PAYLOAD_BYTES;
		let within_ttl = ttl <= u64::from(MAX_GOSSIP_TTL);
		let fresh = gossip_fresh(rumor.metadata.order, seen_ttl_ms, now_ms);
		if within_payload && within_ttl && fresh {
			let digest = gossip_digest::<D>(rumor).map_err(|_| TransitStatus::PermissionDenied)?;
			let admitted = Self { digest, payload: body.payload, kind: body.kind };
			Ok(admitted)
		} else {
			Err(TransitStatus::PermissionDenied)
		}
	}

	/// Content digest for deduplication and reconciliation.
	#[must_use]
	pub fn digest(&self) -> GossipDigest {
		self.digest
	}

	/// Application payload from the signed rumor body.
	#[must_use]
	pub fn payload(&self) -> &[u8] {
		&self.payload
	}

	/// Consume the admission and yield the owned payload.
	///
	/// Local delivery takes the bytes this admission already owns, so
	/// the handoff never copies them.
	#[must_use]
	pub fn into_payload(self) -> Vec<u8> {
		self.payload
	}

	/// How the origin intends this rumor to be consumed.
	#[must_use]
	pub fn kind(&self) -> GossipRumorKind {
		self.kind
	}
}

/// Per-signer rate admission gating the gossip pipeline.
///
/// Consulted after signature verification and before journal record or
/// reflood. An over-limit signer cannot grow retained state or amplify
/// traffic (CWE-770). The token-bucket default bounds burst and
/// sustained rate. A custom implementation may meter on any
/// signer-derived dimension.
pub trait GossipAdmission: Send + Sync {
	/// Admit one rumor from `signer` at `now_ms`.
	///
	/// `false` means over limit. An error reports a backend fault.
	/// The gateway refuses in both cases.
	fn allow(&self, signer: &[u8], now_ms: u64) -> Result<bool, ClusterError>;
}

/// One signer's bucket: remaining tokens and the last refill instant.
struct TokenBucket {
	tokens: u32,
	refilled_ms: u64,
}

/// In-memory token-bucket [`GossipAdmission`] keyed on the signer.
///
/// Each signer spends one token per rumor from a bucket of `burst` capacity.
/// The bucket regains one token every `refill_interval`.
/// Full-capacity buckets carry no state and are pruned on every call.
/// An unseen signer is refused once the tracked-signer ceiling is reached (CWE-770).
pub struct TokenBucketAdmission {
	buckets: Mutex<HashMap<Vec<u8>, TokenBucket>>,
	burst: u32,
	refill_interval_ms: u64,
	capacity: usize,
}

impl TokenBucketAdmission {
	/// Burst and refill interval with the default tracked-signer ceiling.
	#[must_use]
	pub fn new(burst: u32, refill_interval: Duration) -> Self {
		Self::with_limits(burst, refill_interval, MAX_GOSSIP_RATE_SIGNERS)
	}

	/// Burst, refill, and signer ceiling. A zero interval refills once per millisecond.
	#[must_use]
	pub fn with_limits(burst: u32, refill_interval: Duration, capacity: usize) -> Self {
		Self {
			buckets: Mutex::new(HashMap::new()),
			burst,
			refill_interval_ms: (refill_interval.as_millis() as u64).max(1),
			capacity,
		}
	}

	/// Drop buckets that have regained full capacity in either clock direction.
	/// A full bucket is indistinguishable from an absent one.
	fn prune(buckets: &mut HashMap<Vec<u8>, TokenBucket>, burst: u32, refill_interval_ms: u64, now_ms: u64) {
		let full_after_ms = u64::from(burst).saturating_mul(refill_interval_ms);
		buckets.retain(|_, bucket| now_ms.abs_diff(bucket.refilled_ms) < full_after_ms);
	}
}

impl Default for TokenBucketAdmission {
	fn default() -> Self {
		Self::new(DEFAULT_GOSSIP_RATE_BURST, Duration::from_millis(DEFAULT_GOSSIP_RATE_REFILL_MS))
	}
}

impl GossipAdmission for TokenBucketAdmission {
	fn allow(&self, signer: &[u8], now_ms: u64) -> Result<bool, ClusterError> {
		let mut buckets = self.buckets.lock()?;
		Self::prune(&mut buckets, self.burst, self.refill_interval_ms, now_ms);

		if !buckets.contains_key(signer) && buckets.len() >= self.capacity {
			return Ok(false);
		}

		let bucket = buckets
			.entry(signer.to_vec())
			.or_insert(TokenBucket { tokens: self.burst, refilled_ms: now_ms });

		// Refill advances by whole intervals so the fractional remainder
		// keeps accruing toward the next token instead of being dropped.
		let elapsed_ms = now_ms.saturating_sub(bucket.refilled_ms);
		let regained = elapsed_ms / self.refill_interval_ms;
		let tokens = u64::from(bucket.tokens).saturating_add(regained);

		if tokens >= u64::from(self.burst) {
			bucket.tokens = self.burst;
			bucket.refilled_ms = now_ms;
		} else {
			bucket.tokens = tokens as u32;
			bucket.refilled_ms = bucket
				.refilled_ms
				.saturating_add(regained.saturating_mul(self.refill_interval_ms));
		}

		if bucket.tokens == 0 {
			return Ok(false);
		}

		bucket.tokens -= 1;
		Ok(true)
	}
}

/// Deduplication and retention store for delivery and anti-entropy.
///
/// The gateway calls only this interface. The in-memory default gives
/// bounded-window eventual delivery. A durable backend can retain
/// across restarts. Errors are typed [`ClusterError`] variants.
pub trait GossipJournal: Send + Sync {
	/// Deduplicate and retain one origin-signed rumor in a single step.
	///
	/// The rumor is retained unchanged so anti-entropy repair can
	/// forward identical origin-signed bytes. Returns
	/// [`Admission::New`] when unseen and now recorded, and
	/// [`Admission::Duplicate`] when already retained. Fails closed at
	/// capacity.
	fn record(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		rumor: &Frame,
		now_ms: u64,
	) -> Result<Admission, ClusterError>;

	/// Deduplicate one ephemeral rumor digest without retaining the rumor.
	///
	/// Advertisement-class rumors dedup and loop-break on the seen set
	/// only. The advertise beat re-publishes fresh state, so repairing
	/// a stale hint would waste relay bandwidth and retention capacity.
	///
	/// A witnessed digest:
	///
	/// - MUST report as seen through [`GossipJournal::seen`].
	/// - MUST NOT appear in [`GossipJournal::held_digests`],
	///   [`GossipJournal::fetch`], or [`GossipJournal::pending_local`].
	///
	/// Returns [`Admission::New`] when unseen and now witnessed, or
	/// [`Admission::Duplicate`] when already seen. Fails closed at capacity.
	fn witness(&self, signer: &[u8], digest: GossipDigest, now_ms: u64) -> Result<Admission, ClusterError>;

	/// Whether a digest is already retained or witnessed, without recording it.
	///
	/// Probed before rate admission so a duplicate does not spend a
	/// signer's token: relay echoes are normal and MUST NOT drain the
	/// bucket. Advisory only. [`GossipJournal::record`] and
	/// [`GossipJournal::witness`] remain the atomic dedup steps for
	/// races past the probe.
	fn seen(&self, digest: &GossipDigest, now_ms: u64) -> Result<bool, ClusterError>;

	/// Digests still inside the retention window, for reconciliation summaries.
	fn held_digests(&self, now_ms: u64) -> Result<Vec<GossipDigest>, ClusterError>;

	/// Retained rumor frames for digests a peer reported missing.
	fn fetch(&self, wanted: &[GossipDigest], now_ms: u64) -> Result<Vec<Frame>, ClusterError>;

	/// Retained rumors not yet delivered locally (retry set).
	fn pending_local(&self, now_ms: u64) -> Result<Vec<Frame>, ClusterError>;

	/// Mark local delivery complete so the rumor stops being retried.
	fn ack_local(&self, digest: &GossipDigest) -> Result<(), ClusterError>;

	/// Retention horizon in milliseconds.
	///
	/// The gateway clamps admission freshness (`seen_ttl`) to this horizon
	/// at start: a rumor older than retention has no digest left to
	/// deduplicate against, so a wider window would re-admit a replayed
	/// rumor as new (CWE-294).
	fn retention_ms(&self) -> u64;
}

/// One deduplicated digest and the bookkeeping the journal tracks for it.
struct JournalEntry {
	signer: Vec<u8>,
	recorded_ms: u64,
	body: JournalBody,
}

/// What the journal keeps behind a deduplicated digest.
///
/// A retained rumor serves anti-entropy repair and local delivery
/// retry. A witnessed digest serves dedup only and holds no bytes.
/// The retained rumor is boxed so a witnessed entry costs one
/// pointer, never a full inline [`Frame`].
enum JournalBody {
	Retained { rumor: Box<Frame>, delivered_local: bool },
	Witnessed,
}

/// In-memory [`GossipJournal`] with per-signer partitioning.
///
/// Dedup is global on the content digest: rumor bytes travel unchanged
/// across relays (only the OUTER hop frame is rebuilt), so the digest
/// matches wherever the rumor arrives. Per-signer capacity bounds
/// retained and witnessed entries separately, so one signer's flood
/// on either plane cannot starve its own other plane. The global cap
/// is shared across signers and kinds: a memory ceiling, not a
/// fairness partition. Retention prunes on every read and write in
/// both clock directions so an aged-out rumor is never returned.
pub struct MemoryGossipJournal {
	entries: Mutex<HashMap<GossipDigest, JournalEntry>>,
	retention_ms: u64,
	capacity: usize,
	per_signer_capacity: usize,
}

impl MemoryGossipJournal {
	/// Retention window with default capacity caps.
	#[must_use]
	pub fn new(retention_ms: u64) -> Self {
		Self::with_limits(retention_ms, MAX_GOSSIP_LOG, MAX_GOSSIP_LOG_PER_SIGNER)
	}

	/// Retention window and capacity bounds.
	#[must_use]
	pub fn with_limits(retention_ms: u64, capacity: usize, per_signer_capacity: usize) -> Self {
		Self { entries: Mutex::new(HashMap::new()), retention_ms, capacity, per_signer_capacity }
	}

	/// Drop entries whose age exceeds the retention window in either clock
	/// direction. One pruning rule keeps reads and writes consistent.
	fn prune(entries: &mut HashMap<GossipDigest, JournalEntry>, retention_ms: u64, now_ms: u64) {
		entries.retain(|_, entry| now_ms.abs_diff(entry.recorded_ms) <= retention_ms);
	}
}

impl Default for MemoryGossipJournal {
	fn default() -> Self {
		Self::new(DEFAULT_GOSSIP_RETENTION_MS)
	}
}

/// Gossip subsystem: freshness, origin TTL, ingress, journal, and admission.
pub struct GossipConfig {
	/// Freshness window for rumor issue time (`metadata.order`).
	pub seen_ttl: Duration,
	/// Origin publish hop radius, clamped to [`MAX_GOSSIP_TTL`].
	pub ttl: u8,
	/// Servlet type URN admitted rumors are delivered to on this gateway.
	/// Local delivery is receiving-gateway policy, never rumor content.
	/// `None` journals and refloods only. The record is marked
	/// delivered so it never enters the pending retry set.
	pub ingress: Option<Urn<'static>>,
	/// Dedup and retention store. Owns its own retention window.
	pub journal: Arc<dyn GossipJournal>,
	/// Per-signer rate admission before record or reflood.
	pub admission: Arc<dyn GossipAdmission>,
}

impl Default for GossipConfig {
	fn default() -> Self {
		Self {
			seen_ttl: Duration::from_millis(DEFAULT_GOSSIP_SEEN_TTL_MS),
			ttl: DEFAULT_GOSSIP_TTL,
			ingress: None,
			journal: Arc::new(MemoryGossipJournal::default()),
			admission: Arc::new(TokenBucketAdmission::default()),
		}
	}
}

impl core::fmt::Debug for GossipConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("GossipConfig")
			.field("seen_ttl", &self.seen_ttl)
			.field("ttl", &self.ttl)
			.field("ingress", &self.ingress)
			.field("journal", &"<dyn GossipJournal>")
			.field("admission", &"<dyn GossipAdmission>")
			.finish()
	}
}

impl MemoryGossipJournal {
	/// Deduplicate `digest` under the capacity discipline and store
	/// `body` when it is new (CWE-770).
	///
	/// The per-signer budget counts only entries of the incoming body
	/// kind: a signer's witnessed advertisement digests can never
	/// crowd out its retained application rumors. The reverse holds
	/// too.
	fn admit(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		body: JournalBody,
		now_ms: u64,
	) -> Result<Admission, ClusterError> {
		let mut entries = self.entries.lock()?;
		Self::prune(&mut entries, self.retention_ms, now_ms);

		if entries.contains_key(&digest) {
			return Ok(Admission::Duplicate);
		}

		let body_kind = discriminant(&body);
		let signer_held = entries
			.values()
			.filter(|entry| entry.signer == signer)
			.filter(|entry| discriminant(&entry.body) == body_kind)
			.count();
		let within_global = entries.len() < self.capacity;
		let within_signer = signer_held < self.per_signer_capacity;

		if within_global && within_signer {
			let entry = JournalEntry { signer: signer.to_vec(), recorded_ms: now_ms, body };
			entries.insert(digest, entry);

			Ok(Admission::New)
		} else {
			Err(ClusterError::GossipJournalAtCapacity)
		}
	}
}

impl GossipJournal for MemoryGossipJournal {
	fn record(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		rumor: &Frame,
		now_ms: u64,
	) -> Result<Admission, ClusterError> {
		let body = JournalBody::Retained { rumor: Box::new(rumor.clone()), delivered_local: false };
		self.admit(signer, digest, body, now_ms)
	}

	fn witness(&self, signer: &[u8], digest: GossipDigest, now_ms: u64) -> Result<Admission, ClusterError> {
		self.admit(signer, digest, JournalBody::Witnessed, now_ms)
	}

	fn seen(&self, digest: &GossipDigest, now_ms: u64) -> Result<bool, ClusterError> {
		let mut entries = self.entries.lock()?;

		Self::prune(&mut entries, self.retention_ms, now_ms);

		Ok(entries.contains_key(digest))
	}

	fn retention_ms(&self) -> u64 {
		self.retention_ms
	}

	fn held_digests(&self, now_ms: u64) -> Result<Vec<GossipDigest>, ClusterError> {
		let mut entries = self.entries.lock()?;

		Self::prune(&mut entries, self.retention_ms, now_ms);

		let digests = entries
			.iter()
			.filter(|(_, entry)| matches!(entry.body, JournalBody::Retained { .. }))
			.map(|(digest, _)| *digest)
			.collect();

		Ok(digests)
	}

	fn fetch(&self, wanted: &[GossipDigest], now_ms: u64) -> Result<Vec<Frame>, ClusterError> {
		let mut entries = self.entries.lock()?;

		Self::prune(&mut entries, self.retention_ms, now_ms);

		let found = wanted
			.iter()
			.filter_map(|digest| entries.get(digest))
			.filter_map(|entry| match &entry.body {
				JournalBody::Retained { rumor, .. } => Some(rumor.as_ref().clone()),
				JournalBody::Witnessed => None,
			})
			.collect();

		Ok(found)
	}

	fn pending_local(&self, now_ms: u64) -> Result<Vec<Frame>, ClusterError> {
		let mut entries = self.entries.lock()?;

		Self::prune(&mut entries, self.retention_ms, now_ms);

		let pending = entries
			.values()
			.filter_map(|entry| match &entry.body {
				JournalBody::Retained { rumor, delivered_local: false } => Some(rumor.as_ref().clone()),
				_ => None,
			})
			.collect();

		Ok(pending)
	}

	fn ack_local(&self, digest: &GossipDigest) -> Result<(), ClusterError> {
		let mut entries = self.entries.lock()?;
		if let Some(entry) = entries.get_mut(digest) {
			if let JournalBody::Retained { delivered_local, .. } = &mut entry.body {
				*delivered_local = true;
			}
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::asn1::{Metadata, Version};
	use crate::crypto::hash::Sha3_256;

	fn digest(rumor: &Frame) -> GossipDigest {
		gossip_digest::<Sha3_256>(rumor).expect("test rumor frames encode")
	}

	fn rumor(order: u64, payload: Vec<u8>) -> Frame {
		let body = GossipRumor::application(payload);
		Frame {
			version: Version::V0,
			metadata: Metadata {
				id: b"rumor".to_vec(),
				order,
				compactness: None,
				integrity: None,
				confidentiality: None,
				priority: None,
				lifetime: None,
				previous_frame: None,
				matrix: None,
			},
			message: encode(&body).expect("test rumor bodies encode"),
			integrity: None,
			nonrepudiation: None,
		}
	}

	#[test]
	fn digest_is_deterministic() {
		let frame = rumor(1_000, vec![1, 2, 3]);
		assert_eq!(digest(&frame), digest(&frame));
	}

	#[test]
	fn digest_tracks_payload_and_order() {
		let base = rumor(1_000, vec![1, 2, 3]);
		let other_payload = rumor(1_000, vec![9, 9, 9]);
		let other_order = rumor(2_000, vec![1, 2, 3]);
		assert_ne!(digest(&base), digest(&other_payload));
		assert_ne!(digest(&base), digest(&other_order));
	}

	#[test]
	fn digest_survives_decode_reencode() {
		let frame = rumor(1_000, vec![1, 2, 3]);
		let relayed: Frame =
			decode(&encode(&frame).expect("test rumor frames encode")).expect("canonical bytes decode");
		assert_eq!(digest(&frame), digest(&relayed));
	}

	#[test]
	fn admit_accepts_valid_rumor() -> Result<(), TransitStatus> {
		let frame = rumor(1_000, vec![1, 2, 3]);
		let admitted = AdmittedGossip::admit::<Sha3_256>(&frame, 4, 30_000, 1_000)?;
		assert_eq!(admitted.digest(), digest(&frame));
		assert_eq!(admitted.payload(), &[1, 2, 3]);
		Ok(())
	}

	#[test]
	fn into_payload_yields_the_admitted_body() -> Result<(), TransitStatus> {
		let frame = rumor(1_000, vec![1, 2, 3]);
		let admitted = AdmittedGossip::admit::<Sha3_256>(&frame, 4, 30_000, 1_000)?;
		assert_eq!(admitted.into_payload(), vec![1, 2, 3]);
		Ok(())
	}

	#[test]
	fn admit_refuses_oversized_payload() {
		let frame = rumor(1_000, vec![0u8; MAX_GOSSIP_PAYLOAD_BYTES + 1]);
		let status = AdmittedGossip::admit::<Sha3_256>(&frame, 4, 30_000, 1_000);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn admit_refuses_excessive_ttl() {
		let frame = rumor(1_000, vec![1, 2, 3]);
		let over = u64::from(MAX_GOSSIP_TTL) + 1;
		let status = AdmittedGossip::admit::<Sha3_256>(&frame, over, 30_000, 1_000);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn admit_refuses_stale_rumor() {
		let frame = rumor(1_000, vec![1, 2, 3]);
		let status = AdmittedGossip::admit::<Sha3_256>(&frame, 4, 30_000, 100_000);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn admit_refuses_undecodable_body() {
		let mut frame = rumor(1_000, vec![1]);
		frame.message = vec![0xFF, 0x00, 0xFF];
		let status = AdmittedGossip::admit::<Sha3_256>(&frame, 4, 30_000, 1_000);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn record_dedups_same_digest() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		let first = journal.record(b"signer-a", digest, &frame, 1_000)?;
		let second = journal.record(b"signer-a", digest, &frame, 1_000)?;
		assert_eq!(first, Admission::New);
		assert_eq!(second, Admission::Duplicate);
		Ok(())
	}

	#[test]
	fn seen_tracks_retention_window() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::new(30_000);
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		let before = journal.seen(&digest, 1_000)?;
		journal.record(b"signer-a", digest, &frame, 1_000)?;
		let after = journal.seen(&digest, 1_000)?;
		let expired = journal.seen(&digest, 90_000)?;
		assert!(!before);
		assert!(after);
		assert!(!expired);
		Ok(())
	}

	#[test]
	fn witness_dedups_same_digest() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		let first = journal.witness(b"signer-a", digest, 1_000)?;
		let second = journal.witness(b"signer-a", digest, 1_000)?;
		assert_eq!(first, Admission::New);
		assert_eq!(second, Admission::Duplicate);
		Ok(())
	}

	#[test]
	fn witness_is_seen_but_never_retained() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.witness(b"signer-a", digest, 1_000)?;

		assert!(journal.seen(&digest, 1_000)?);
		assert!(journal.held_digests(1_000)?.is_empty());
		assert!(journal.fetch(&[digest], 1_000)?.is_empty());
		assert!(journal.pending_local(1_000)?.is_empty());
		Ok(())
	}

	#[test]
	fn witness_blocks_record_of_same_digest() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.witness(b"signer-a", digest, 1_000)?;
		let replay = journal.record(b"signer-a", digest, &frame, 1_000)?;
		assert_eq!(replay, Admission::Duplicate);
		Ok(())
	}

	#[test]
	fn witness_expires_with_retention() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::new(30_000);
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.witness(b"signer-a", digest, 1_000)?;
		assert!(journal.seen(&digest, 1_000)?);
		assert!(!journal.seen(&digest, 90_000)?);
		Ok(())
	}

	#[test]
	fn witness_fails_closed_at_signer_capacity() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::with_limits(30_000, 8, 1);
		let first = rumor(1_000, vec![1]);
		let second = rumor(1_000, vec![2]);

		journal.witness(b"signer-a", digest(&first), 1_000)?;

		let overflow = journal.witness(b"signer-a", digest(&second), 1_000);
		assert!(matches!(overflow, Err(ClusterError::GossipJournalAtCapacity)));
		Ok(())
	}

	#[test]
	fn witness_and_record_spend_separate_signer_budgets() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::with_limits(30_000, 8, 1);
		let witnessed = rumor(1_000, vec![1]);
		let retained = rumor(1_000, vec![2]);

		let hint = journal.witness(b"signer-a", digest(&witnessed), 1_000)?;
		let application = journal.record(b"signer-a", digest(&retained), &retained, 1_000)?;

		assert_eq!(hint, Admission::New);
		assert_eq!(application, Admission::New);
		Ok(())
	}

	#[test]
	fn record_fails_closed_at_global_capacity() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::with_limits(30_000, 1, 8);
		let first = rumor(1_000, vec![1]);
		let second = rumor(1_000, vec![2]);

		journal.record(b"signer-a", digest(&first), &first, 1_000)?;

		let overflow = journal.record(b"signer-a", digest(&second), &second, 1_000);
		assert!(matches!(overflow, Err(ClusterError::GossipJournalAtCapacity)));
		Ok(())
	}

	#[test]
	fn record_fails_closed_at_per_signer_capacity() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::with_limits(30_000, 8, 1);
		let first = rumor(1_000, vec![1]);
		let second = rumor(1_000, vec![2]);
		let other = rumor(1_000, vec![3]);

		journal.record(b"signer-a", digest(&first), &first, 1_000)?;

		let over = journal.record(b"signer-a", digest(&second), &second, 1_000);
		let other_signer = journal.record(b"signer-b", digest(&other), &other, 1_000)?;
		assert!(matches!(over, Err(ClusterError::GossipJournalAtCapacity)));
		assert_eq!(other_signer, Admission::New);
		Ok(())
	}

	#[test]
	fn pending_local_clears_on_ack() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.record(b"signer-a", digest, &frame, 1_000)?;
		let before = journal.pending_local(1_000)?;
		journal.ack_local(&digest)?;

		let after = journal.pending_local(1_000)?;
		assert_eq!(before.len(), 1);
		assert_eq!(after.len(), 0);
		Ok(())
	}

	#[test]
	fn fetch_returns_only_wanted() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let first = rumor(1_000, vec![1]);
		let second = rumor(1_000, vec![2]);
		let first_digest = digest(&first);

		journal.record(b"signer-a", first_digest, &first, 1_000)?;
		journal.record(b"signer-a", digest(&second), &second, 1_000)?;

		let fetched = journal.fetch(&[first_digest], 1_000)?;
		assert_eq!(fetched, vec![first]);
		Ok(())
	}

	#[test]
	fn want_requests_only_unheld_digests() {
		let held = rumor(1_000, vec![1]);
		let missing = rumor(1_000, vec![2]);
		let held_digest = digest(&held);
		let advertised = vec![held_digest.to_vec(), digest(&missing).to_vec()];

		let want = gossip_want(&advertised, &[held_digest]);
		assert_eq!(want, vec![digest(&missing).to_vec()]);
	}

	#[test]
	fn want_is_empty_when_all_advertised_are_held() {
		let first = digest(&rumor(1_000, vec![1]));
		let second = digest(&rumor(1_000, vec![2]));
		let advertised = vec![first.to_vec(), second.to_vec()];

		let want = gossip_want(&advertised, &[first, second]);
		assert!(want.is_empty());
	}

	#[test]
	fn wanted_digests_keeps_only_correct_length() {
		let good = digest(&rumor(1_000, vec![1]));
		let want = vec![good.to_vec(), vec![0u8; 8], vec![0u8; 64]];

		let decoded = wanted_digests(&want);
		assert_eq!(decoded, vec![good]);
	}

	#[test]
	fn wanted_digests_collapses_duplicates() {
		let good = digest(&rumor(1_000, vec![1]));
		let want = vec![good.to_vec(), good.to_vec(), good.to_vec()];

		let decoded = wanted_digests(&want);
		assert_eq!(decoded, vec![good]);
	}

	#[test]
	fn want_collapses_repeated_advertisements() {
		let missing = digest(&rumor(1_000, vec![2]));
		let advertised = vec![missing.to_vec(), missing.to_vec(), missing.to_vec()];

		let want = gossip_want(&advertised, &[]);
		assert_eq!(want, vec![missing.to_vec()]);
	}

	#[test]
	fn admission_spends_burst_then_refuses() -> Result<(), ClusterError> {
		let admission = TokenBucketAdmission::new(2, Duration::from_millis(1_000));
		assert!(admission.allow(b"signer", 1_000)?);
		assert!(admission.allow(b"signer", 1_000)?);
		assert!(!admission.allow(b"signer", 1_000)?);
		Ok(())
	}

	#[test]
	fn admission_refills_one_token_per_interval() -> Result<(), ClusterError> {
		let admission = TokenBucketAdmission::new(1, Duration::from_millis(1_000));
		assert!(admission.allow(b"signer", 1_000)?);
		assert!(!admission.allow(b"signer", 1_500)?);
		assert!(admission.allow(b"signer", 2_000)?);
		Ok(())
	}

	#[test]
	fn admission_isolates_signers() -> Result<(), ClusterError> {
		let admission = TokenBucketAdmission::new(1, Duration::from_millis(1_000));
		assert!(admission.allow(b"first", 1_000)?);
		assert!(!admission.allow(b"first", 1_000)?);
		assert!(admission.allow(b"second", 1_000)?);
		Ok(())
	}

	#[test]
	fn admission_refuses_unseen_signer_at_capacity() -> Result<(), ClusterError> {
		let admission = TokenBucketAdmission::with_limits(2, Duration::from_millis(1_000), 1);
		assert!(admission.allow(b"first", 1_000)?);
		assert!(!admission.allow(b"second", 1_000)?);
		Ok(())
	}

	#[test]
	fn admission_prunes_refilled_buckets() -> Result<(), ClusterError> {
		let admission = TokenBucketAdmission::with_limits(1, Duration::from_millis(1_000), 1);
		assert!(admission.allow(b"first", 1_000)?);
		assert!(admission.allow(b"second", 3_000)?);
		Ok(())
	}

	#[test]
	fn fresh_accepts_issue_time_inside_window() {
		assert!(gossip_fresh(1_000, 30_000, 1_000));
		assert!(gossip_fresh(1_000, 30_000, 31_000));
		assert!(gossip_fresh(31_000, 30_000, 1_000));
	}

	#[test]
	fn fresh_rejects_issue_time_outside_window() {
		assert!(!gossip_fresh(1_000, 30_000, 31_001));
		assert!(!gossip_fresh(31_001, 30_000, 1_000));
	}

	#[test]
	fn record_prunes_expired_entries() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::with_limits(100, 8, 8);
		let early = rumor(1_000, vec![1]);
		let late = rumor(1_000, vec![2]);

		journal.record(b"signer-a", digest(&early), &early, 0)?;
		journal.record(b"signer-a", digest(&late), &late, 200)?;

		let held = journal.held_digests(200)?;
		assert_eq!(held, vec![digest(&late)]);
		Ok(())
	}

	#[test]
	fn reads_prune_expired_entries_without_a_write() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::with_limits(100, 8, 8);
		let frame = rumor(1_000, vec![1]);
		let rumor_digest = digest(&frame);

		journal.record(b"signer-a", rumor_digest, &frame, 0)?;

		let held = journal.held_digests(1_000)?;
		let fetched = journal.fetch(&[rumor_digest], 1_000)?;
		let pending = journal.pending_local(1_000)?;
		assert_eq!(held.len(), 0);
		assert_eq!(fetched.len(), 0);
		assert_eq!(pending.len(), 0);
		Ok(())
	}
}
