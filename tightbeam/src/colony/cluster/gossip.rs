//! Gossip admission, content digest, and retention journal.
//!
//! Colony gateways flood origin-signed rumors within one colony and
//! deliver admitted rumors locally according to operator ingress policy.
//! Forwarding continues while hop time-to-live remains on the outer
//! relay frame.
//!
//! # Colony scope
//!
//! Flood scope is colony membership: the origin certificate URI SAN
//! colony URN MUST equal the local gateway colony URN.
//!
//! # Rumor model
//!
//! A rumor is an origin-signed [`Frame`]. The accepting gateway signs
//! once. Later hops and anti-entropy repair carry those same signed bytes.
//! Hop radius lives in the OUTER relay frame's `metadata.lifetime` rather
//! than in the content digest.
//!
//! # Admission path
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
use crate::colony::common::IssuedAt;
use crate::colony::common::{GossipRumor, GossipRumorKind, ServletTypeKey};
use crate::constants::{
	DEFAULT_GOSSIP_RATE_BURST, DEFAULT_GOSSIP_RATE_REFILL_MS, DEFAULT_GOSSIP_RETENTION_MS, DEFAULT_GOSSIP_SEEN_TTL_MS,
	DEFAULT_GOSSIP_TTL, MAX_GOSSIP_LOG, MAX_GOSSIP_LOG_PER_SIGNER, MAX_GOSSIP_PAYLOAD_BYTES, MAX_GOSSIP_RATE_SIGNERS,
	MAX_GOSSIP_TTL,
};
use crate::crypto::hash::{Digest, OutputSizeUser, U32};
use crate::policy::TransitStatus;
use crate::utils::time::UnixMillis;
use crate::{decode, encode};

/// Fixed 32-byte content digest of a gossip rumor.
///
/// The algorithm is the deployment crypto-profile digest. Every gateway
/// MUST derive the same digest for the same rumor.
pub type GossipDigest = [u8; 32];

/// Whether a recorded rumor is newly seen or a suppressed duplicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
	/// The digest was unseen and is now recorded, so the caller delivers and
	/// forwards the rumor.
	New,
	/// The digest was already recorded in the window, so the caller drops
	/// the rumor.
	Duplicate,
}

impl Frame {
	/// Digest over the canonical DER encoding of a rumor.
	///
	/// Coverage includes identity, issue time, payload, and origin
	/// signature. Hop radius lives on the OUTER relay frame and MUST NOT
	/// enter the digest.
	///
	/// # Algorithm
	///
	/// Algorithm `D` MUST be the cluster crypto-profile digest (CWE-694).
	pub fn gossip_digest<D>(&self) -> Result<GossipDigest, ClusterError>
	where
		D: Digest + OutputSizeUser<OutputSize = U32>,
	{
		let bytes = encode(self)?;
		let mut hasher = D::new();
		hasher.update(&bytes);

		let output = hasher.finalize();
		let mut digest = [0u8; 32];
		digest.copy_from_slice(&output);

		Ok(digest)
	}
}

/// Digests advertised by a peer that this gateway does not retain.
///
/// Reconciliation is a set difference over content digests. A repeated
/// advertisement entry appears once in the want list so a peer cannot
/// inflate the reply by repeating itself (CWE-770).
#[must_use]
pub fn gossip_want(advertised: impl AsRef<[Vec<u8>]>, held: impl AsRef<[GossipDigest]>) -> Vec<Vec<u8>> {
	let advertised = advertised.as_ref();
	let held = held.as_ref();
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
/// Wrong-length entries cannot be retained digests and are dropped
/// (CWE-20). Duplicates collapse to one, because a peer MUST NOT multiply
/// repair pushes (CWE-770).
#[must_use]
pub fn wanted_digests(want: impl AsRef<[Vec<u8>]>) -> Vec<GossipDigest> {
	let want = want.as_ref();
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
pub fn gossip_fresh(order: UnixMillis, seen_ttl: Duration, now: UnixMillis) -> bool {
	now.abs_diff(order) <= seen_ttl
}

/// Rumor that passed payload, hop-radius, and freshness checks.
///
/// Construct only through [`AdmittedGossip::admit`]. Signature and
/// colony-membership checks run in the gateway handler first.
pub struct AdmittedGossip {
	digest: GossipDigest,
	payload: Vec<u8>,
	kind: GossipRumorKind,
}

impl AdmittedGossip {
	/// Admits one rumor frame, failing closed with a refusal status.
	///
	/// `ttl` is the remaining hop radius from the OUTER `metadata.lifetime`.
	/// Freshness uses the rumor's `metadata.order` as the signed issue time.
	///
	/// # Refusal
	///
	/// Each of these refuses the rumor:
	///
	/// - The rumor body does not decode.
	/// - The payload exceeds [`MAX_GOSSIP_PAYLOAD_BYTES`].
	/// - `ttl` exceeds [`MAX_GOSSIP_TTL`], which caps the hop radius here at
	///   the trust boundary (CWE-770).
	/// - The issue time is stale.
	pub fn admit<D>(rumor: &Frame, ttl: u64, seen_ttl: Duration, now: UnixMillis) -> Result<Self, TransitStatus>
	where
		D: Digest + OutputSizeUser<OutputSize = U32>,
	{
		let body: GossipRumor = decode(rumor.message()).map_err(|_| TransitStatus::PermissionDenied)?;

		let within_payload = body.payload.len() <= MAX_GOSSIP_PAYLOAD_BYTES;
		let within_ttl = ttl <= u64::from(MAX_GOSSIP_TTL);
		let fresh = gossip_fresh(rumor.issued_at(), seen_ttl, now);
		if within_payload && within_ttl && fresh {
			let digest = rumor.gossip_digest::<D>().map_err(|_| TransitStatus::PermissionDenied)?;
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
/// traffic (CWE-770).
///
/// # Default
///
/// The token-bucket default bounds burst and sustained rate. A custom
/// implementation may meter on any signer-derived dimension.
pub trait GossipAdmission: Send + Sync {
	/// Admit one rumor from `signer` at `now`.
	///
	/// `false` means the signer is over its limit, and an error reports a
	/// backend fault. The gateway refuses in both cases.
	fn allow(&self, signer: &[u8], now: UnixMillis) -> Result<bool, ClusterError>;
}

/// One signer's bucket: remaining tokens and the last refill instant.
struct TokenBucket {
	tokens: u32,
	refilled_at: UnixMillis,
}

/// In-memory token-bucket [`GossipAdmission`] keyed on the signer.
///
/// Each signer spends one token per rumor from a bucket of `burst`
/// capacity. The bucket regains one token every `refill_interval`.
/// Full-capacity buckets carry no state and are pruned on every call.
///
/// # Signer ceiling
///
/// An unseen signer is refused once the tracked-signer ceiling is
/// reached (CWE-770).
pub struct TokenBucketAdmission {
	buckets: Mutex<HashMap<Vec<u8>, TokenBucket>>,
	burst: u32,
	refill_interval: Duration,
	capacity: usize,
}

impl TokenBucketAdmission {
	/// Builds an admission from `burst` and `refill_interval` with the default
	/// tracked-signer ceiling.
	#[must_use]
	pub fn new(burst: u32, refill_interval: Duration) -> Self {
		Self::with_limits(burst, refill_interval, MAX_GOSSIP_RATE_SIGNERS)
	}

	/// Builds an admission from `burst`, `refill_interval`, and a
	/// tracked-signer ceiling of `capacity`.
	///
	/// A zero interval refills once per millisecond.
	#[must_use]
	pub fn with_limits(burst: u32, refill_interval: Duration, capacity: usize) -> Self {
		Self {
			buckets: Mutex::new(HashMap::new()),
			burst,
			refill_interval: Duration::from_millis((refill_interval.as_millis() as u64).max(1)),
			capacity,
		}
	}

	/// Drop buckets that have regained full capacity in either clock
	/// direction, because a full bucket is indistinguishable from an absent
	/// one.
	fn prune(buckets: &mut HashMap<Vec<u8>, TokenBucket>, burst: u32, refill_interval: Duration, now: UnixMillis) {
		let full_after = refill_interval.saturating_mul(burst);
		buckets.retain(|_, bucket| now.abs_diff(bucket.refilled_at) < full_after);
	}
}

impl Default for TokenBucketAdmission {
	fn default() -> Self {
		Self::new(DEFAULT_GOSSIP_RATE_BURST, Duration::from_millis(DEFAULT_GOSSIP_RATE_REFILL_MS))
	}
}

impl GossipAdmission for TokenBucketAdmission {
	fn allow(&self, signer: &[u8], now: UnixMillis) -> Result<bool, ClusterError> {
		let mut buckets = self.buckets.lock()?;
		Self::prune(&mut buckets, self.burst, self.refill_interval, now);

		if !buckets.contains_key(signer) && buckets.len() >= self.capacity {
			return Ok(false);
		}

		let bucket = buckets
			.entry(signer.to_vec())
			.or_insert(TokenBucket { tokens: self.burst, refilled_at: now });

		// Refill advances by whole intervals so the fractional remainder
		// keeps accruing toward the next token instead of being dropped.
		let elapsed = now.saturating_since(bucket.refilled_at);
		let interval_ms = self.refill_interval.as_millis().max(1);
		let regained = u64::try_from(elapsed.as_millis() / interval_ms).unwrap_or(u64::MAX);
		let tokens = u64::from(bucket.tokens).saturating_add(regained);

		if tokens >= u64::from(self.burst) {
			bucket.tokens = self.burst;
			bucket.refilled_at = now;
		} else {
			// Below the burst, the regained count fits the bucket's own width.
			let regained_tokens = u32::try_from(regained).unwrap_or(u32::MAX);
			let advanced = self.refill_interval.saturating_mul(regained_tokens);

			bucket.tokens = tokens as u32;
			bucket.refilled_at = bucket.refilled_at.saturating_add(advanced);
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
/// The gateway reaches the journal through this interface alone. The
/// in-memory default gives bounded-window eventual delivery, and a durable
/// backend can retain across restarts. Errors are typed [`ClusterError`]
/// variants.
pub trait GossipJournal: Send + Sync {
	/// Deduplicate and retain one origin-signed rumor in a single step.
	///
	/// The rumor is retained unchanged so anti-entropy repair can
	/// forward identical origin-signed bytes. Returns
	/// [`Admission::New`] when unseen and now recorded, and
	/// [`Admission::Duplicate`] when already retained. The call fails closed
	/// at capacity.
	fn record(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		rumor: &Frame,
		now: UnixMillis,
	) -> Result<Admission, ClusterError>;

	/// Deduplicate one ephemeral rumor digest without retaining the rumor.
	///
	/// Advertisement-class rumors dedup and loop-break on the seen set
	/// only. The advertise beat re-publishes fresh state, so repairing a
	/// stale hint would waste relay bandwidth and retention capacity.
	///
	/// # Witnessed digest
	///
	/// A witnessed digest:
	///
	/// - MUST report as seen through [`GossipJournal::seen`].
	/// - MUST NOT appear in [`GossipJournal::held_digests`],
	///   [`GossipJournal::fetch`], or [`GossipJournal::pending_local`].
	///
	/// Returns [`Admission::New`] when unseen and now witnessed, or
	/// [`Admission::Duplicate`] when already seen. The call fails closed at
	/// capacity.
	fn witness(&self, signer: &[u8], digest: GossipDigest, now: UnixMillis) -> Result<Admission, ClusterError>;

	/// Whether a digest is already retained or witnessed, without recording it.
	///
	/// Probed before rate admission so a duplicate does not spend a signer's
	/// token: relay echoes are normal and MUST NOT drain the bucket.
	///
	/// The probe is advisory. [`GossipJournal::record`] and
	/// [`GossipJournal::witness`] remain the atomic dedup steps for races
	/// past it.
	fn seen(&self, digest: &GossipDigest, now: UnixMillis) -> Result<bool, ClusterError>;

	/// Digests still inside the retention window, for reconciliation summaries.
	fn held_digests(&self, now: UnixMillis) -> Result<Vec<GossipDigest>, ClusterError>;

	/// Retained rumor frames for digests a peer reported missing.
	fn fetch(&self, wanted: &[GossipDigest], now: UnixMillis) -> Result<Vec<Frame>, ClusterError>;

	/// Retained rumors awaiting local delivery, excluding those a task
	/// already claimed through [`GossipJournal::claim_local`].
	fn pending_local(&self, now: UnixMillis) -> Result<Vec<Frame>, ClusterError>;

	/// Take one rumor's local delivery, so no second task delivers it.
	///
	/// A caller that gets [`LocalClaim::Taken`] MUST finish with
	/// [`GossipJournal::ack_local`] on success or
	/// [`GossipJournal::release_local`] on failure, or the rumor stays
	/// unretried until retention drops it.
	fn claim_local(&self, digest: &GossipDigest, now: UnixMillis) -> Result<LocalClaim, ClusterError>;

	/// Return a claimed rumor to the retry set after a failed delivery.
	fn release_local(&self, digest: &GossipDigest) -> Result<(), ClusterError>;

	/// Mark local delivery complete so the rumor stops being retried.
	fn ack_local(&self, digest: &GossipDigest) -> Result<(), ClusterError>;

	/// Retention horizon in milliseconds.
	///
	/// The gateway clamps admission freshness (`seen_ttl`) to this horizon
	/// at start, because a rumor older than retention has no digest left
	/// to deduplicate against. A wider window would re-admit a replayed
	/// rumor as new (CWE-294).
	fn retention(&self) -> Duration;
}

/// One deduplicated digest and the bookkeeping the journal tracks for it.
struct JournalEntry {
	signer: Vec<u8>,
	recorded_at: UnixMillis,
	body: JournalBody,
}

/// What the journal keeps behind a deduplicated digest.
///
/// A retained rumor serves anti-entropy repair and local delivery retry.
/// A witnessed digest serves dedup only and holds no bytes. The retained
/// rumor is boxed so a witnessed entry costs one pointer rather than a full
/// inline [`Frame`].
enum JournalBody {
	Retained { rumor: Box<Frame>, local: LocalDelivery },
	Witnessed,
}

/// The answer to one [`GossipJournal::claim_local`] request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalClaim {
	/// This caller holds the delivery and answers for its outcome.
	Taken,
	/// Another task holds it, or it is already delivered.
	Held,
	/// The journal retains no rumor for this digest, so nothing retries it
	/// and the caller delivers without a claim.
	Untracked,
}

/// One local delivery in progress, released when this guard drops.
///
/// A claim taken by hand leaks when the delivery future is dropped: a
/// cancelled task or a disconnected caller leaves the rumor claimed with
/// nothing holding it, and no retry ever offers it again. Owning the
/// claim removes that path, because dropping the future drops the guard.
///
/// # Exits
///
/// - Dropping the guard releases the claim, so the rumor returns to the retry set.
/// - [`Self::ack`] retires the entry instead, and is the only exit that
///   stops the rumor being retried.
pub struct LocalClaimGuard<'a> {
	journal: &'a dyn GossipJournal,
	digest: &'a GossipDigest,
	/// Whether dropping this guard returns the rumor to the retry set.
	///
	/// An untracked rumor has no retry entry to return it to.
	retries: bool,
}

impl<'a> LocalClaimGuard<'a> {
	/// Claim `digest` for one delivery, or [`None`] when another task holds
	/// it.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- the journal's own fault, which the caller
	///   propagates, because a journal that cannot answer the claim cannot
	///   answer the ack either.
	pub fn take(
		journal: &'a dyn GossipJournal,
		digest: &'a GossipDigest,
		now: UnixMillis,
	) -> Result<Option<Self>, ClusterError> {
		let claim = match journal.claim_local(digest, now)? {
			LocalClaim::Taken => Some(Self { journal, digest, retries: true }),
			LocalClaim::Untracked => Some(Self { journal, digest, retries: false }),
			LocalClaim::Held => None,
		};

		Ok(claim)
	}

	/// Record the rumor as delivered, so it stops being retried.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- the journal's own fault. The claim is released
	///   to the retry set on the way out, so an unrecorded delivery is offered
	///   again rather than stranded.
	pub fn ack(mut self) -> Result<(), ClusterError> {
		self.journal.ack_local(self.digest)?;
		self.retries = false;

		Ok(())
	}
}

impl Drop for LocalClaimGuard<'_> {
	fn drop(&mut self) {
		if self.retries {
			// The retry beat offers the rumor again. A destructor has no
			// caller to answer, and a journal that refuses the release
			// refuses the next claim the same way, so the fault is seen
			// there.
			let _ = self.journal.release_local(self.digest);
		}
	}
}

/// How far one retained rumor has travelled toward its local ingress.
///
/// Delivery in flight is its own state, so a rumor a task is already
/// delivering is not offered to a second one (CWE-362).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalDelivery {
	/// Awaiting delivery, with no task holding it.
	Pending,
	/// One task is delivering it now.
	Claimed,
	/// Delivered, so the retry set drops it for good.
	Delivered,
}

/// In-memory [`GossipJournal`] with per-signer partitioning.
///
/// Dedup is global on the content digest: rumor bytes travel unchanged
/// across relays (only the OUTER hop frame is rebuilt), so the digest
/// matches wherever the rumor arrives.
///
/// # Capacity
///
/// Per-signer capacity bounds retained and witnessed entries separately,
/// so one signer's flood on either plane cannot starve its own other
/// plane. The global cap is shared across signers and kinds: a memory
/// ceiling, not a fairness partition.
///
/// # Retention
///
/// Retention prunes on every read and write in both clock directions so
/// an aged-out rumor is never returned.
pub struct MemoryGossipJournal {
	entries: Mutex<HashMap<GossipDigest, JournalEntry>>,
	retention: Duration,
	capacity: usize,
	per_signer_capacity: usize,
}

/// The two capacity bounds a journal holds.
///
/// Both are counts of retained rumors, so a positional pair lets a caller
/// exchange them and give every signer the whole log. The named fields are
/// what the call site binds (CWE-770).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalLimits {
	/// Rumors the journal retains across every signer.
	pub total: usize,
	/// Rumors the journal retains for any one signer.
	pub per_signer: usize,
}

impl MemoryGossipJournal {
	/// Builds a journal with the `retention` window and the default capacity
	/// caps.
	#[must_use]
	pub fn new(retention: Duration) -> Self {
		Self::with_limits(
			retention,
			JournalLimits { total: MAX_GOSSIP_LOG, per_signer: MAX_GOSSIP_LOG_PER_SIGNER },
		)
	}

	/// Builds a journal with the `retention` window and the given capacity
	/// bounds.
	#[must_use]
	pub fn with_limits(retention: Duration, limits: JournalLimits) -> Self {
		let JournalLimits { total, per_signer } = limits;

		Self {
			entries: Mutex::new(HashMap::new()),
			retention,
			capacity: total,
			per_signer_capacity: per_signer,
		}
	}

	/// Retained rumors that have not reached local ingress, whether or not a
	/// task has claimed one.
	///
	/// Zero means every retained rumor was delivered, which
	/// [`GossipJournal::pending_local`] cannot say on its own: a claimed rumor
	/// is in flight, so it leaves the retry set while its delivery is still
	/// unfinished. That distinction is what a convergence assertion needs.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the journal lock is poisoned.
	#[cfg(any(test, feature = "testing"))]
	pub fn undelivered_local(&self, now: UnixMillis) -> Result<usize, ClusterError> {
		let mut entries = self.entries.lock()?;

		Self::prune(&mut entries, self.retention, now);

		let undelivered = entries
			.values()
			.filter(|entry| {
				matches!(
					entry.body,
					JournalBody::Retained { local: LocalDelivery::Pending | LocalDelivery::Claimed, .. }
				)
			})
			.count();

		Ok(undelivered)
	}

	/// Drop entries whose age exceeds the retention window in either clock
	/// direction. One pruning rule keeps reads and writes consistent.
	fn prune(entries: &mut HashMap<GossipDigest, JournalEntry>, retention: Duration, now: UnixMillis) {
		entries.retain(|_, entry| now.abs_diff(entry.recorded_at) <= retention);
	}
}

impl Default for MemoryGossipJournal {
	fn default() -> Self {
		Self::new(Duration::from_millis(DEFAULT_GOSSIP_RETENTION_MS))
	}
}

/// Gossip subsystem: freshness, origin TTL, ingress, journal, and admission.
pub struct GossipConfig {
	/// Freshness window for rumor issue time (`metadata.order`).
	pub seen_ttl: Duration,
	/// Origin publish hop radius, clamped to [`MAX_GOSSIP_TTL`].
	pub ttl: u8,
	/// Route key admitted rumors are delivered to on this gateway.
	///
	/// - [`ColonyNamespace::servlet_type_key`] creates the key, so a
	///   configured ingress always names a servlet type this colony can route.
	/// - Local delivery is receiving-gateway policy rather than rumor content.
	/// - `None` journals and refloods only, and marks the record delivered so
	///   it stays out of the pending retry set.
	///
	/// [`ColonyNamespace::servlet_type_key`]:
	/// crate::colony::common::ColonyNamespace::servlet_type_key
	///
	/// # Export boundary
	///
	/// The ingress sink sits outside the export boundary. Colony scope and the
	/// origin signature already gate which peers may flood a rumor, and the
	/// operator chooses the delivery type, so the export allowlist does not
	/// apply here.
	///
	/// An operator who restricts exports should treat the ingress type as an
	/// intentional local delivery channel for admitted colony gossip.
	pub ingress: Option<ServletTypeKey>,
	/// Dedup and retention store, which owns its own retention window.
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
	/// Deduplicate `digest` under the capacity discipline and store `body`
	/// when it is new (CWE-770).
	///
	/// # Per-signer budget
	///
	/// The per-signer budget counts only entries of the incoming body kind:
	/// a signer's witnessed advertisement digests can never crowd out its
	/// retained application rumors. The reverse holds too.
	fn admit(
		&self,
		signer: impl AsRef<[u8]>,
		digest: GossipDigest,
		body: JournalBody,
		now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		let signer = signer.as_ref();
		let mut entries = self.entries.lock()?;
		Self::prune(&mut entries, self.retention, now);

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
			let entry = JournalEntry { signer: signer.to_vec(), recorded_at: now, body };
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
		now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		let body = JournalBody::Retained { rumor: Box::new(rumor.clone()), local: LocalDelivery::Pending };
		self.admit(signer, digest, body, now)
	}

	fn witness(&self, signer: &[u8], digest: GossipDigest, now: UnixMillis) -> Result<Admission, ClusterError> {
		self.admit(signer, digest, JournalBody::Witnessed, now)
	}

	fn seen(&self, digest: &GossipDigest, now: UnixMillis) -> Result<bool, ClusterError> {
		let mut entries = self.entries.lock()?;

		Self::prune(&mut entries, self.retention, now);

		Ok(entries.contains_key(digest))
	}

	fn retention(&self) -> Duration {
		self.retention
	}

	fn held_digests(&self, now: UnixMillis) -> Result<Vec<GossipDigest>, ClusterError> {
		let mut entries = self.entries.lock()?;

		Self::prune(&mut entries, self.retention, now);

		let digests = entries
			.iter()
			.filter(|(_, entry)| matches!(entry.body, JournalBody::Retained { .. }))
			.map(|(digest, _)| *digest)
			.collect();

		Ok(digests)
	}

	fn fetch(&self, wanted: &[GossipDigest], now: UnixMillis) -> Result<Vec<Frame>, ClusterError> {
		let mut entries = self.entries.lock()?;

		Self::prune(&mut entries, self.retention, now);

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

	fn pending_local(&self, now: UnixMillis) -> Result<Vec<Frame>, ClusterError> {
		let mut entries = self.entries.lock()?;

		Self::prune(&mut entries, self.retention, now);

		let pending = entries
			.values()
			.filter_map(|entry| match &entry.body {
				JournalBody::Retained { rumor, local: LocalDelivery::Pending } => Some(rumor.as_ref().clone()),
				_ => None,
			})
			.collect();

		Ok(pending)
	}

	fn claim_local(&self, digest: &GossipDigest, _now: UnixMillis) -> Result<LocalClaim, ClusterError> {
		let mut entries = self.entries.lock()?;
		let Some(entry) = entries.get_mut(digest) else {
			return Ok(LocalClaim::Untracked);
		};
		let JournalBody::Retained { local, .. } = &mut entry.body else {
			return Ok(LocalClaim::Untracked);
		};

		if *local != LocalDelivery::Pending {
			return Ok(LocalClaim::Held);
		}

		*local = LocalDelivery::Claimed;
		Ok(LocalClaim::Taken)
	}

	fn release_local(&self, digest: &GossipDigest) -> Result<(), ClusterError> {
		let mut entries = self.entries.lock()?;
		if let Some(entry) = entries.get_mut(digest) {
			if let JournalBody::Retained { local: local @ LocalDelivery::Claimed, .. } = &mut entry.body {
				*local = LocalDelivery::Pending;
			}
		}

		Ok(())
	}

	fn ack_local(&self, digest: &GossipDigest) -> Result<(), ClusterError> {
		let mut entries = self.entries.lock()?;
		if let Some(entry) = entries.get_mut(digest) {
			if let JournalBody::Retained { local, .. } = &mut entry.body {
				*local = LocalDelivery::Delivered;
			}
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::asn1::Version;
	use crate::builder::{FrameBuilder, TypeBuilder};
	use crate::crypto::hash::Sha3_256;

	/// The reference instant the fixture rumors are issued at.
	const T0: UnixMillis = UnixMillis::new(1_000);

	/// The freshness and retention window the fixtures run under.
	const WINDOW: Duration = Duration::from_millis(30_000);

	fn digest(rumor: &Frame) -> GossipDigest {
		rumor.gossip_digest::<Sha3_256>().expect("test rumor frames encode")
	}

	fn rumor(order: u64, payload: impl Into<Vec<u8>>) -> Frame {
		let payload: Vec<u8> = payload.into();
		let body = GossipRumor::application(payload);
		FrameBuilder::from(Version::V0)
			.with_id("rumor")
			.with_order(order)
			.with_message(body)
			.build()
			.expect("test rumor frames build")
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
		let admitted = AdmittedGossip::admit::<Sha3_256>(&frame, 4, WINDOW, T0)?;
		assert_eq!(admitted.digest(), digest(&frame));
		assert_eq!(admitted.payload(), &[1, 2, 3]);
		Ok(())
	}

	#[test]
	fn into_payload_yields_the_admitted_body() -> Result<(), TransitStatus> {
		let frame = rumor(1_000, vec![1, 2, 3]);
		let admitted = AdmittedGossip::admit::<Sha3_256>(&frame, 4, WINDOW, T0)?;
		assert_eq!(admitted.into_payload(), vec![1, 2, 3]);
		Ok(())
	}

	#[test]
	fn admit_refuses_oversized_payload() {
		let frame = rumor(1_000, vec![0u8; MAX_GOSSIP_PAYLOAD_BYTES + 1]);
		let status = AdmittedGossip::admit::<Sha3_256>(&frame, 4, WINDOW, T0);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn admit_refuses_excessive_ttl() {
		let frame = rumor(1_000, vec![1, 2, 3]);
		let over = u64::from(MAX_GOSSIP_TTL) + 1;
		let status = AdmittedGossip::admit::<Sha3_256>(&frame, over, WINDOW, T0);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn admit_refuses_stale_rumor() {
		let frame = rumor(1_000, vec![1, 2, 3]);
		let status = AdmittedGossip::admit::<Sha3_256>(&frame, 4, WINDOW, UnixMillis::new(100_000));
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn admit_refuses_undecodable_body() {
		let frame = Frame::v0(b"rumor", vec![0xFF, 0x00, 0xFF]);
		let status = AdmittedGossip::admit::<Sha3_256>(&frame, 4, WINDOW, T0);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn record_dedups_same_digest() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		let first = journal.record(b"signer-a", digest, &frame, T0)?;
		let second = journal.record(b"signer-a", digest, &frame, T0)?;
		assert_eq!(first, Admission::New);
		assert_eq!(second, Admission::Duplicate);
		Ok(())
	}

	#[test]
	fn seen_tracks_retention_window() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::new(WINDOW);
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);
		let before = journal.seen(&digest, T0)?;

		journal.record(b"signer-a", digest, &frame, T0)?;

		let after = journal.seen(&digest, T0)?;
		let expired = journal.seen(&digest, UnixMillis::new(90_000))?;
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

		let first = journal.witness(b"signer-a", digest, T0)?;
		let second = journal.witness(b"signer-a", digest, T0)?;
		assert_eq!(first, Admission::New);
		assert_eq!(second, Admission::Duplicate);
		Ok(())
	}

	#[test]
	fn witness_is_seen_but_never_retained() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.witness(b"signer-a", digest, T0)?;

		assert!(journal.seen(&digest, T0)?);
		assert!(journal.held_digests(T0)?.is_empty());
		assert!(journal.fetch(&[digest], T0)?.is_empty());
		assert!(journal.pending_local(T0)?.is_empty());
		Ok(())
	}

	#[test]
	fn witness_blocks_record_of_same_digest() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.witness(b"signer-a", digest, T0)?;

		let replay = journal.record(b"signer-a", digest, &frame, T0)?;
		assert_eq!(replay, Admission::Duplicate);
		Ok(())
	}

	#[test]
	fn witness_expires_with_retention() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::new(WINDOW);
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.witness(b"signer-a", digest, T0)?;
		assert!(journal.seen(&digest, T0)?);
		assert!(!journal.seen(&digest, UnixMillis::new(90_000))?);
		Ok(())
	}

	#[test]
	fn witness_fails_closed_at_signer_capacity() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::with_limits(WINDOW, JournalLimits { total: 8, per_signer: 1 });
		let first = rumor(1_000, vec![1]);
		let second = rumor(1_000, vec![2]);

		journal.witness(b"signer-a", digest(&first), T0)?;

		let overflow = journal.witness(b"signer-a", digest(&second), T0);
		assert!(matches!(overflow, Err(ClusterError::GossipJournalAtCapacity)));
		Ok(())
	}

	#[test]
	fn witness_and_record_spend_separate_signer_budgets() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::with_limits(WINDOW, JournalLimits { total: 8, per_signer: 1 });
		let witnessed = rumor(1_000, vec![1]);
		let retained = rumor(1_000, vec![2]);

		let hint = journal.witness(b"signer-a", digest(&witnessed), T0)?;
		let application = journal.record(b"signer-a", digest(&retained), &retained, T0)?;
		assert_eq!(hint, Admission::New);
		assert_eq!(application, Admission::New);
		Ok(())
	}

	#[test]
	fn record_fails_closed_at_global_capacity() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::with_limits(WINDOW, JournalLimits { total: 1, per_signer: 8 });
		let first = rumor(1_000, vec![1]);
		let second = rumor(1_000, vec![2]);

		journal.record(b"signer-a", digest(&first), &first, T0)?;

		let overflow = journal.record(b"signer-a", digest(&second), &second, T0);
		assert!(matches!(overflow, Err(ClusterError::GossipJournalAtCapacity)));
		Ok(())
	}

	#[test]
	fn record_fails_closed_at_per_signer_capacity() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::with_limits(WINDOW, JournalLimits { total: 8, per_signer: 1 });
		let first = rumor(1_000, vec![1]);
		let second = rumor(1_000, vec![2]);
		let other = rumor(1_000, vec![3]);

		journal.record(b"signer-a", digest(&first), &first, T0)?;

		let over = journal.record(b"signer-a", digest(&second), &second, T0);
		let other_signer = journal.record(b"signer-b", digest(&other), &other, T0)?;
		assert!(matches!(over, Err(ClusterError::GossipJournalAtCapacity)));
		assert_eq!(other_signer, Admission::New);
		Ok(())
	}

	#[test]
	fn pending_local_clears_on_ack() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.record(b"signer-a", digest, &frame, T0)?;
		let before = journal.pending_local(T0)?;
		journal.ack_local(&digest)?;

		let after = journal.pending_local(T0)?;
		assert_eq!(before.len(), 1);
		assert_eq!(after.len(), 0);
		Ok(())
	}

	// A rumor whose delivery is in flight is not re-offered, so the beat
	// and the admission path cannot both deliver it (CWE-362).
	#[test]
	fn a_claimed_rumor_is_not_offered_again() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.record(b"signer-a", digest, &frame, T0)?;

		assert_eq!(journal.claim_local(&digest, T0)?, LocalClaim::Taken);
		assert!(journal.pending_local(T0)?.is_empty());
		assert_eq!(journal.claim_local(&digest, T0)?, LocalClaim::Held);
		Ok(())
	}

	/// Claim `digest` for one delivery, which an unclaimed rumor always
	/// admits.
	fn claim<'a>(journal: &'a MemoryGossipJournal, digest: &'a GossipDigest) -> LocalClaimGuard<'a> {
		LocalClaimGuard::take(journal, digest, T0)
			.expect("the journal lock is live")
			.expect("an unclaimed rumor is claimable")
	}

	// A delivery task that never finishes, because it was cancelled or its
	// caller went away, must not strand the rumor as claimed forever.
	#[test]
	fn a_dropped_delivery_returns_its_rumor_to_the_retry_set() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.record(b"signer-a", digest, &frame, T0)?;

		{
			let _claim = claim(&journal, &digest);
			assert!(journal.pending_local(T0)?.is_empty());
		}

		assert_eq!(journal.pending_local(T0)?.len(), 1);
		Ok(())
	}

	// An acked delivery retires the rumor, so no later round retries it.
	#[test]
	fn an_acked_delivery_retires_its_rumor() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.record(b"signer-a", digest, &frame, T0)?;

		claim(&journal, &digest).ack()?;

		assert!(journal.pending_local(T0)?.is_empty());
		assert_eq!(journal.undelivered_local(T0)?, 0);
		Ok(())
	}

	// A delivery that failed releases its claim, so the next round retries it.
	#[test]
	fn a_released_rumor_is_offered_again() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = rumor(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.record(b"signer-a", digest, &frame, T0)?;
		assert_eq!(journal.claim_local(&digest, T0)?, LocalClaim::Taken);
		journal.release_local(&digest)?;

		assert_eq!(journal.pending_local(T0)?.len(), 1);
		Ok(())
	}

	#[test]
	fn fetch_returns_only_wanted() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let first = rumor(1_000, vec![1]);
		let second = rumor(1_000, vec![2]);
		let first_digest = digest(&first);

		journal.record(b"signer-a", first_digest, &first, T0)?;
		journal.record(b"signer-a", digest(&second), &second, T0)?;

		let fetched = journal.fetch(&[first_digest], T0)?;
		assert_eq!(fetched, vec![first]);
		Ok(())
	}

	#[test]
	fn want_requests_only_unheld_digests() {
		let held = rumor(1_000, vec![1]);
		let missing = rumor(1_000, vec![2]);
		let held_digest = digest(&held);
		let advertised = vec![held_digest.to_vec(), digest(&missing).to_vec()];

		let want = gossip_want(&advertised, [held_digest]);
		assert_eq!(want, vec![digest(&missing).to_vec()]);
	}

	#[test]
	fn want_is_empty_when_all_advertised_are_held() {
		let first = digest(&rumor(1_000, vec![1]));
		let second = digest(&rumor(1_000, vec![2]));
		let advertised = vec![first.to_vec(), second.to_vec()];

		let want = gossip_want(&advertised, [first, second]);
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

		let want = gossip_want(&advertised, []);
		assert_eq!(want, vec![missing.to_vec()]);
	}

	#[test]
	fn admission_spends_burst_then_refuses() -> Result<(), ClusterError> {
		let admission = TokenBucketAdmission::new(2, Duration::from_millis(1_000));
		assert!(admission.allow(b"signer", T0)?);
		assert!(admission.allow(b"signer", T0)?);
		assert!(!admission.allow(b"signer", T0)?);
		Ok(())
	}

	#[test]
	fn admission_refills_one_token_per_interval() -> Result<(), ClusterError> {
		let admission = TokenBucketAdmission::new(1, Duration::from_millis(1_000));
		assert!(admission.allow(b"signer", T0)?);
		assert!(!admission.allow(b"signer", UnixMillis::new(1_500))?);
		assert!(admission.allow(b"signer", UnixMillis::new(2_000))?);
		Ok(())
	}

	#[test]
	fn admission_isolates_signers() -> Result<(), ClusterError> {
		let admission = TokenBucketAdmission::new(1, Duration::from_millis(1_000));
		assert!(admission.allow(b"first", T0)?);
		assert!(!admission.allow(b"first", T0)?);
		assert!(admission.allow(b"second", T0)?);
		Ok(())
	}

	#[test]
	fn admission_refuses_unseen_signer_at_capacity() -> Result<(), ClusterError> {
		let admission = TokenBucketAdmission::with_limits(2, Duration::from_millis(1_000), 1);
		assert!(admission.allow(b"first", T0)?);
		assert!(!admission.allow(b"second", T0)?);
		Ok(())
	}

	#[test]
	fn admission_prunes_refilled_buckets() -> Result<(), ClusterError> {
		let admission = TokenBucketAdmission::with_limits(1, Duration::from_millis(1_000), 1);
		assert!(admission.allow(b"first", T0)?);
		assert!(admission.allow(b"second", UnixMillis::new(3_000))?);
		Ok(())
	}

	#[test]
	fn fresh_accepts_issue_time_inside_window() {
		assert!(gossip_fresh(T0, WINDOW, T0));
		assert!(gossip_fresh(T0, WINDOW, UnixMillis::new(31_000)));
		assert!(gossip_fresh(UnixMillis::new(31_000), WINDOW, T0));
	}

	#[test]
	fn fresh_rejects_issue_time_outside_window() {
		assert!(!gossip_fresh(T0, WINDOW, UnixMillis::new(31_001)));
		assert!(!gossip_fresh(UnixMillis::new(31_001), WINDOW, T0));
	}

	#[test]
	fn record_prunes_expired_entries() -> Result<(), ClusterError> {
		let short_retention = Duration::from_millis(100);
		let roomy = JournalLimits { total: 8, per_signer: 8 };
		let journal = MemoryGossipJournal::with_limits(short_retention, roomy);
		let early = rumor(1_000, vec![1]);
		let late = rumor(1_000, vec![2]);

		journal.record(b"signer-a", digest(&early), &early, UnixMillis::new(0))?;
		journal.record(b"signer-a", digest(&late), &late, UnixMillis::new(200))?;

		let held = journal.held_digests(UnixMillis::new(200))?;
		assert_eq!(held, vec![digest(&late)]);
		Ok(())
	}

	#[test]
	fn reads_prune_expired_entries_without_a_write() -> Result<(), ClusterError> {
		let short_retention = Duration::from_millis(100);
		let roomy = JournalLimits { total: 8, per_signer: 8 };
		let journal = MemoryGossipJournal::with_limits(short_retention, roomy);
		let frame = rumor(1_000, vec![1]);
		let rumor_digest = digest(&frame);

		journal.record(b"signer-a", rumor_digest, &frame, UnixMillis::new(0))?;

		let held = journal.held_digests(T0)?;
		let fetched = journal.fetch(&[rumor_digest], T0)?;
		let pending = journal.pending_local(T0)?;
		assert_eq!(held.len(), 0);
		assert_eq!(fetched.len(), 0);
		assert_eq!(pending.len(), 0);
		Ok(())
	}
}
