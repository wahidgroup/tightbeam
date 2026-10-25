//! Gossip admission, content digest, and retention journal.
//!
//! Gateways flood origin-signed rumors across the colonies of one namespace
//! and deliver admitted rumors locally according to operator ingress policy.
//! A gateway forwards a rumor while hop time-to-live remains on the outer
//! relay frame.
//!
//! # Flood scope
//!
//! The `Flood` type in `peer.rs` owns the scope. A rumor travels between the
//! gateways that the peer trust store admits and whose certificates carry a
//! colony URN of the local namespace.
//!
//! # Rumor model
//!
//! A rumor is an origin-signed [`Frame`]. The accepting gateway signs
//! once. Later hops and anti-entropy repair carry those same signed bytes.
//! The hop radius lives in the OUTER relay frame's `metadata.lifetime` rather
//! than in the content digest.
//!
//! # Admission path
//!
//! [`AdmittedGossip`] is the only path from a wire rumor to delivery.
//! [`GossipJournal`] stores digests for deduplication and retention.
//! [`MemoryGossipJournal`] is the in-memory default.

use core::mem::discriminant;
use core::num::NonZeroU128;
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use super::runtime::LoopFault;
use super::{ClusterError, ClusterTlsConfig};
use crate::asn1::Frame;
use crate::colony::common::IssuedAt;
use crate::colony::common::{GossipRumor, GossipRumorKind, ServletTypeKey};
use crate::constants::{
	DEFAULT_GOSSIP_RATE_BURST, DEFAULT_GOSSIP_RATE_REFILL_MS, DEFAULT_GOSSIP_RETENTION_MS, DEFAULT_GOSSIP_SEEN_TTL_MS,
	DEFAULT_GOSSIP_TTL, MAX_GOSSIP_LOG, MAX_GOSSIP_LOG_PER_SIGNER, MAX_GOSSIP_PAYLOAD_BYTES, MAX_GOSSIP_RATE_SIGNERS,
	MAX_GOSSIP_TTL,
};
use crate::crypto::hash::{Digest, OutputSizeUser};
use crate::crypto::sign::VerifiedSignature;
use crate::decode;
use crate::policy::TransitStatus;
use crate::transport::handshake::primitives::transcript::DigestOutput;
use crate::utils::time::UnixMillis;
use crate::TightBeamError;

/// The content digest of a gossip rumor, under the digest of the colony's
/// provider.
///
/// Every gateway of a colony runs one provider, so every gateway derives the
/// same digest for the same rumor, and the digest is as wide as the output of
/// that provider's digest. [`VerifiedRumor::gossip_digest`] computes one, and
/// [`GossipDigest::read`] reads one that a peer sent.
///
/// # Width
///
/// The digest sits inline at its width, from 32 to 64 octets, the widths of
/// the digests a handshake runs. It is [`Copy`], so a rumor admits, journals,
/// and compares its digest on the stack.
///
/// # Examples
///
/// ```
/// use tightbeam::colony::cluster::GossipDigest;
/// use tightbeam::crypto::hash::{Sha3_256, Sha3_512};
///
/// let digest = GossipDigest::read::<Sha3_512>([7u8; 64]);
/// assert!(digest.is_some_and(|digest| digest.as_bytes().len() == 64));
///
/// // An entry of another width names no rumor under the colony's digest.
/// assert!(GossipDigest::read::<Sha3_256>([7u8; 64]).is_none());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GossipDigest(DigestOutput);

impl GossipDigest {
	/// Read `bytes` as a digest under `D`, or [`None`] for an entry of
	/// another width, which names no rumor (CWE-20).
	///
	/// A durable [`GossipJournal`] keeps the [`Self::as_bytes`] of each digest
	/// and restores the digest through this method. `D` is then the digest of
	/// the colony's provider: for a gateway of protocol `P`,
	/// `<<P as Protocol>::CryptoProvider as DigestProvider>::Digest`.
	///
	/// # Examples
	///
	/// A journal of the house colony, whose protocol is [`TokioListener`],
	/// restores a digest it stored:
	///
	/// ```
	/// use tightbeam::colony::cluster::GossipDigest;
	/// use tightbeam::crypto::profiles::DigestProvider;
	/// use tightbeam::transport::{Protocol, TokioListener};
	///
	/// type ColonyDigest = <<TokioListener as Protocol>::CryptoProvider as DigestProvider>::Digest;
	///
	/// let stored = [7u8; 32];
	/// let restored = GossipDigest::read::<ColonyDigest>(stored).ok_or("a SHA3-256 digest is 32 octets")?;
	/// assert_eq!(restored.as_bytes(), stored);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	///
	/// [`TokioListener`]: crate::transport::TokioListener
	#[must_use]
	pub fn read<D: OutputSizeUser>(bytes: impl AsRef<[u8]>) -> Option<Self> {
		let bytes = bytes.as_ref();
		let at_width = bytes.len() == D::output_size();
		if !at_width {
			return None;
		}

		let output = DigestOutput::parse(bytes).ok()?;
		Some(Self(output))
	}

	/// The digest octets, as many as the output of the digest that made
	/// them.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::GossipDigest;
	/// use tightbeam::crypto::hash::Sha3_512;
	///
	/// let digest = GossipDigest::read::<Sha3_512>([9u8; 64]).ok_or("a SHA3-512 digest is 64 octets")?;
	/// assert_eq!(digest.as_bytes(), [9u8; 64]);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		self.0.as_bytes()
	}
}

/// Whether a recorded rumor is newly seen or a suppressed duplicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
	/// The journal had not seen the digest and recorded it, so the caller
	/// delivers and forwards the rumor.
	New,
	/// The journal already held the digest in the window, so the caller
	/// drops the rumor.
	Duplicate,
}

/// A rumor frame beside the origin signature that verified over it.
///
/// Only a verification makes one: the parse that verified the rumor on a
/// trust plane, or the gateway's check of a rumor it signed itself. The
/// digest of a rumor therefore covers the signature of that same rumor.
pub struct VerifiedRumor {
	frame: Frame,
	signature: VerifiedSignature,
}

impl VerifiedRumor {
	/// The rumor `frame` beside the `signature` that verified over it.
	pub(crate) fn new(frame: Frame, signature: VerifiedSignature) -> Self {
		Self { frame, signature }
	}

	/// The origin-signed rumor frame.
	#[must_use]
	pub fn frame(&self) -> &Frame {
		&self.frame
	}

	/// Take the rumor frame out of the pairing.
	#[must_use]
	pub fn into_frame(self) -> Frame {
		self.frame
	}

	/// Digest over the rumor's to-be-signed encoding and its origin signature
	/// in canonical form.
	///
	/// - Coverage includes identity, issue time, payload, and origin signature.
	/// - Hop radius lives on the OUTER relay frame and MUST NOT enter the digest.
	/// - A rumor relayed with `s` flipped to `n - s` digests as its original.
	///
	/// # Algorithm
	///
	/// Algorithm `D` MUST be the cluster crypto-profile digest (CWE-694).
	///
	/// # Errors
	///
	/// - [`ClusterError::Frame`] -- the to-be-signed encoding fails, or the
	///   output of `D` is outside the 32 to 64 octets of a [`GossipDigest`].
	pub fn gossip_digest<D: Digest>(&self) -> Result<GossipDigest, ClusterError> {
		let tbs = self.frame.to_tbs()?;
		let mut hasher = D::new();
		hasher.update(&tbs);
		hasher.update(self.signature.as_bytes());

		let output = hasher.finalize();
		let output = DigestOutput::parse(output).map_err(TightBeamError::from)?;

		Ok(GossipDigest(output))
	}
}

impl ClusterTlsConfig {
	/// Verify `frame`, which this gateway signed, against its own
	/// certificate, and pair it with its signature.
	///
	/// A rumor this gateway originates needs its own verified signature,
	/// which its digest covers, whether or not a trust plane holds this
	/// gateway's certificate.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the frame carries no signature, or the signature fails to verify.
	pub(crate) fn verify_own(&self, frame: Frame) -> Result<VerifiedRumor, TightBeamError> {
		let signature = frame.verify_under(self.identity.signing_certificate(), self.identity.policy())?;
		Ok(VerifiedRumor::new(frame, signature))
	}
}

/// Digests that a peer advertised and this gateway lacks, under the colony's
/// digest `D`. Reconciliation is a set difference over content digests.
///
/// - An entry whose width differs from the output of `D` names no rumor, so the want list drops it (CWE-20).
/// - A repeated entry appears once, so a peer cannot inflate the reply by repeating itself (CWE-770).
///
/// # Examples
///
/// ```
/// use tightbeam::colony::cluster::{gossip_want, GossipDigest};
/// use tightbeam::crypto::hash::Sha3_256;
///
/// let held = [GossipDigest::read::<Sha3_256>([7u8; 32]).ok_or("a 32-octet digest reads")?];
/// let advertised = vec![vec![7u8; 32], vec![9u8; 32], vec![1, 2, 3]];
/// let want = gossip_want::<Sha3_256>(&advertised, held);
/// assert_eq!(want, vec![vec![9u8; 32]]);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[must_use]
pub fn gossip_want<D: OutputSizeUser>(
	advertised: impl AsRef<[Vec<u8>]>,
	held: impl AsRef<[GossipDigest]>,
) -> Vec<Vec<u8>> {
	let advertised = advertised.as_ref();
	let held = held.as_ref();
	let local: HashSet<&[u8]> = held.iter().map(GossipDigest::as_bytes).collect();
	let mut unique: HashSet<&[u8]> = HashSet::new();

	advertised
		.iter()
		.filter(|digest| digest.len() == D::output_size())
		.filter(|digest| !local.contains(digest.as_slice()))
		.filter(|digest| unique.insert(digest.as_slice()))
		.cloned()
		.collect()
}

/// Digests from a peer want-list that read as digests under the colony's
/// digest `D`.
///
/// The width filter runs first, because an entry of another width cannot be a
/// retained digest (CWE-20). The digests it reads then collapse their
/// duplicates to one, because a peer MUST NOT multiply repair pushes
/// (CWE-770).
///
/// # Examples
///
/// ```
/// use tightbeam::colony::cluster::wanted_digests;
/// use tightbeam::crypto::hash::Sha3_512;
///
/// let want = vec![vec![9u8; 64], vec![9u8; 64], vec![7u8; 32]];
/// let wanted = wanted_digests::<Sha3_512>(&want);
/// assert_eq!(wanted.len(), 1);
/// ```
#[must_use]
pub fn wanted_digests<D: OutputSizeUser>(want: impl AsRef<[Vec<u8>]>) -> Vec<GossipDigest> {
	let want = want.as_ref();
	let mut unique: HashSet<GossipDigest> = HashSet::new();

	want.iter()
		.filter_map(GossipDigest::read::<D>)
		.filter(|digest| unique.insert(*digest))
		.collect()
}

/// Whether a rumor's issue time falls inside the freshness window.
///
/// Admission and anti-entropy repair share this check. Journals retain by
/// record time, so a relayed rumor may still be fetchable after the issue
/// window.
#[must_use]
pub fn gossip_fresh(order: UnixMillis, seen_ttl: Duration, now: UnixMillis) -> bool {
	now.abs_diff(order) <= seen_ttl
}

/// A rumor that passed the payload, hop-radius, and freshness checks.
///
/// Construct only through [`AdmittedGossip::admit`]. Signature and
/// flood-membership checks run in the gateway handler first.
pub struct AdmittedGossip {
	digest: GossipDigest,
	payload: Vec<u8>,
	kind: GossipRumorKind,
}

impl AdmittedGossip {
	/// Admits one verified rumor, and fails closed with
	/// [`TransitStatus::PermissionDenied`].
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
	/// - `ttl` exceeds [`MAX_GOSSIP_TTL`], which caps the hop radius here at the trust boundary (CWE-770).
	/// - The issue time is stale.
	/// - The to-be-signed encoding of the rumor fails, so it has no digest.
	pub fn admit<D: Digest>(
		rumor: &VerifiedRumor,
		ttl: u64,
		seen_ttl: Duration,
		now: UnixMillis,
	) -> Result<Self, TransitStatus> {
		let frame = rumor.frame();
		let body: GossipRumor = decode(frame.message()).map_err(|_| TransitStatus::PermissionDenied)?;

		let within_payload = body.payload.len() <= MAX_GOSSIP_PAYLOAD_BYTES;
		let within_ttl = ttl <= u64::from(MAX_GOSSIP_TTL);
		let fresh = gossip_fresh(frame.issued_at(), seen_ttl, now);
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
	pub fn digest(&self) -> &GossipDigest {
		&self.digest
	}

	/// Application payload from the signed rumor body.
	#[must_use]
	pub fn payload(&self) -> &[u8] {
		&self.payload
	}

	/// How the origin intends this rumor to be consumed.
	#[must_use]
	pub fn kind(&self) -> GossipRumorKind {
		self.kind
	}
}

/// The two consumers of an admitted rumor: the local ingress and the routing
/// state.
///
/// The gateway's gossip pipeline implements it, and the methods of
/// [`GossipRumorKind`] call the consumer that each kind's rule names.
pub(crate) trait RumorConsumer {
	/// Deliver `rumor`, journaled under `digest`, to the local ingress
	/// servlet.
	async fn deliver(self, rumor: Frame, digest: GossipDigest) -> Result<(), LoopFault>;

	/// Apply the advertisement frame that `payload` carries to the routing
	/// state.
	fn apply_advertisement(self, payload: &[u8]) -> Result<(), LoopFault>;
}

/// The rules that differ by the kind of a rumor.
///
/// Each one is a method here, so a new kind states its journal, its
/// consumption, its retry, and the signer it names in this one place.
impl GossipRumorKind {
	/// Journal one admitted rumor of this kind under `digest`, against the
	/// budget of `signer`.
	///
	/// - The journal retains an application rumor for anti-entropy repair and delivery retry.
	/// - The journal witnesses an advertisement rumor for deduplication alone,
	///   which keeps retention and repair bandwidth for the rumors that use
	///   them.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- the errors of [`GossipJournal::record`] and [`GossipJournal::witness`].
	pub(crate) fn journal(
		self,
		journal: &dyn GossipJournal,
		signer: &[u8],
		digest: GossipDigest,
		rumor: &Frame,
		now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		match self {
			Self::Application => journal.record(signer, digest, rumor, now),
			Self::PeerAdvertisement => journal.witness(signer, digest, now),
		}
	}

	/// Consume one admitted rumor of this kind through `consumer`.
	///
	/// - An application rumor goes to the local ingress. The ingress takes a
	///   copy of `rumor`, because the reflood still carries it.
	/// - An advertisement rumor applies the advertisement its `payload`
	///   carries to the routing state, as gateway routing control.
	///
	/// # Errors
	///
	/// - [`LoopFault`] -- the errors of the consumer it calls.
	pub(crate) async fn consume(
		self,
		consumer: impl RumorConsumer,
		rumor: &Frame,
		digest: GossipDigest,
		payload: &[u8],
	) -> Result<(), LoopFault> {
		match self {
			Self::Application => consumer.deliver(rumor.clone(), digest).await,
			Self::PeerAdvertisement => consumer.apply_advertisement(payload),
		}
	}

	/// Retry the local delivery of `rumor`, which the journal retained under
	/// `digest` and which waits for its ingress.
	///
	/// The journal retains the application kind, so a retry delivers a rumor
	/// of that kind. The journal witnesses an advertisement rumor alone, so
	/// its retry completes at once.
	///
	/// # Errors
	///
	/// - [`LoopFault`] -- the errors of [`RumorConsumer::deliver`].
	pub(crate) async fn retry(
		self,
		consumer: impl RumorConsumer,
		rumor: Frame,
		digest: GossipDigest,
	) -> Result<(), LoopFault> {
		match self {
			Self::Application => consumer.deliver(rumor, digest).await,
			Self::PeerAdvertisement => Ok(()),
		}
	}

	/// The signer that the consumption of an origin rumor of this kind reads.
	///
	/// - An advertisement reads the signer `name` gives, which its apply binds
	///   to the signer of the advertisement it carries.
	/// - An application rumor gives [`None`], because its delivery reads the rumor alone.
	pub(crate) fn origin_signer<S>(self, name: impl FnOnce() -> Option<S>) -> Option<S> {
		match self {
			Self::Application => None,
			Self::PeerAdvertisement => name(),
		}
	}
}

/// Per-signer rate admission that gates the gossip pipeline.
///
/// The gateway consults it after signature verification and before journal
/// record or reflood. An over-limit signer cannot grow retained state or
/// amplify traffic (CWE-770).
///
/// # Default
///
/// The token-bucket default bounds burst and sustained rate. A custom
/// implementation may meter on any signer-derived dimension.
pub trait GossipAdmission: Send + Sync {
	/// Admit one rumor from `signer` at `now`.
	///
	/// `false` means the signer is over its limit. The gateway refuses on
	/// `false` and on an error alike.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- a backend fault, such as a poisoned lock.
	fn allow(&self, signer: &[u8], now: UnixMillis) -> Result<bool, ClusterError>;
}

/// One signer's bucket, with its remaining tokens and its last refill instant.
struct TokenBucket {
	tokens: u32,
	refilled_at: UnixMillis,
}

/// In-memory token-bucket [`GossipAdmission`] keyed on the signer.
///
/// Each signer spends one token per rumor from a bucket of `burst`
/// capacity. The bucket regains one token every `refill_interval`. A bucket
/// at full capacity carries no state, and every call prunes it.
///
/// # Signer ceiling
///
/// The admission refuses an unseen signer once the tracked signers reach
/// the ceiling (CWE-770).
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

		// Refill advances by whole intervals, so the fractional remainder
		// carries over toward the next token.
		let elapsed = now.saturating_since(bucket.refilled_at);
		let interval_ms = NonZeroU128::new(self.refill_interval.as_millis()).unwrap_or(NonZeroU128::MIN);
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

		let Some(remaining) = bucket.tokens.checked_sub(1) else {
			return Ok(false);
		};

		bucket.tokens = remaining;
		Ok(true)
	}
}

/// Deduplication and retention store for delivery and anti-entropy.
///
/// The gateway reaches the journal through this interface alone. The
/// in-memory default gives bounded-window eventual delivery, and a durable
/// backend can retain across restarts. Errors are typed [`ClusterError`]
/// variants.
///
/// # Digest width
///
/// Every digest a gateway hands its journal has the width of the colony
/// digest, the digest of the gateway's provider, which is fixed for the life
/// of the gateway. A durable backend stores the [`GossipDigest::as_bytes`] of
/// each one and restores it with [`GossipDigest::read`] under that digest.
pub trait GossipJournal: Send + Sync {
	/// Deduplicate and retain one origin-signed rumor in a single step.
	///
	/// The journal retains the rumor unchanged so anti-entropy repair can
	/// forward identical origin-signed bytes. Returns
	/// [`Admission::New`] when unseen and now recorded, and
	/// [`Admission::Duplicate`] when already retained.
	///
	/// # Errors
	///
	/// - [`ClusterError::GossipJournalAtCapacity`] -- the journal is full, so the call fails closed.
	/// - [`ClusterError`] -- any other backend fault, such as a poisoned lock.
	fn record(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		rumor: &Frame,
		now: UnixMillis,
	) -> Result<Admission, ClusterError>;

	/// Deduplicate one ephemeral rumor digest without retaining the rumor.
	///
	/// An advertisement rumor uses the seen set alone, to deduplicate and to
	/// break loops. The advertise beat re-publishes fresh state, so a repair
	/// of a stale hint would waste relay bandwidth and retention capacity.
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
	/// [`Admission::Duplicate`] when already seen.
	///
	/// # Errors
	///
	/// - [`ClusterError::GossipJournalAtCapacity`] -- the journal is full, so the call fails closed.
	/// - [`ClusterError`] -- any other backend fault, such as a poisoned lock.
	fn witness(&self, signer: &[u8], digest: GossipDigest, now: UnixMillis) -> Result<Admission, ClusterError>;

	/// Whether a digest is already retained or witnessed, without recording it.
	///
	/// The gateway probes before rate admission so a duplicate does not spend
	/// a signer's token: relay echoes are normal and MUST NOT drain the bucket.
	///
	/// The probe is advisory. [`GossipJournal::record`] and
	/// [`GossipJournal::witness`] remain the atomic deduplication steps for
	/// races past it.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- a backend fault, such as a poisoned lock.
	fn seen(&self, digest: &GossipDigest, now: UnixMillis) -> Result<bool, ClusterError>;

	/// Digests still inside the retention window, for reconciliation summaries.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- a backend fault, such as a poisoned lock.
	fn held_digests(&self, now: UnixMillis) -> Result<Vec<GossipDigest>, ClusterError>;

	/// Retained rumor frames for digests a peer reported missing, each beside
	/// the digest it was recorded under.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- a backend fault, such as a poisoned lock.
	fn fetch(&self, wanted: &[GossipDigest], now: UnixMillis) -> Result<Vec<(GossipDigest, Frame)>, ClusterError>;

	/// Retained rumors that wait for local delivery, each beside the digest it
	/// was recorded under, apart from those a task already claimed through
	/// [`GossipJournal::claim_local`].
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- a backend fault, such as a poisoned lock.
	fn pending_local(&self, now: UnixMillis) -> Result<Vec<(GossipDigest, Frame)>, ClusterError>;

	/// Take one rumor's local delivery, so no second task delivers it.
	///
	/// A caller that gets [`LocalClaim::Taken`] MUST finish with
	/// [`GossipJournal::ack_local`] on success or
	/// [`GossipJournal::release_local`] on failure, or the rumor stays
	/// unretried until retention drops it.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- a backend fault, such as a poisoned lock.
	fn claim_local(&self, digest: &GossipDigest, now: UnixMillis) -> Result<LocalClaim, ClusterError>;

	/// Return a claimed rumor to the retry set after a failed delivery.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- a backend fault, such as a poisoned lock.
	fn release_local(&self, digest: &GossipDigest) -> Result<(), ClusterError>;

	/// Mark local delivery complete so the rumor leaves the retry set.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- a backend fault, such as a poisoned lock.
	fn ack_local(&self, digest: &GossipDigest) -> Result<(), ClusterError>;

	/// Retention horizon of this journal.
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
/// A witnessed digest serves deduplication alone and holds no bytes. The
/// retained rumor is boxed, so a witnessed entry costs one pointer rather
/// than a full inline [`Frame`].
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
/// nothing holding it, and no retry ever offers it again. A guard that owns
/// the claim removes that path, because a dropped future drops the guard.
///
/// # Exits
///
/// - The drop of the guard releases the claim, so the rumor returns to the retry set.
/// - [`Self::ack`] retires the entry instead, and is the only exit that takes the rumor out of the retry set.
pub struct LocalClaimGuard<'a> {
	journal: &'a dyn GossipJournal,
	digest: &'a GossipDigest,
	/// Whether the drop of this guard returns the rumor to the retry set.
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

	/// Record the rumor as delivered, so it leaves the retry set.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- the journal's own fault. The guard releases the
	///   claim to the retry set on the way out, so the retry beat offers an
	///   unrecorded delivery again rather than strand it.
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
			// refuses the next claim the same way, so the next claim
			// surfaces the fault.
			let _ = self.journal.release_local(self.digest);
		}
	}
}

/// How far one retained rumor has travelled toward its local ingress.
///
/// Delivery in flight is its own state, so one task at a time delivers a
/// rumor (CWE-362).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalDelivery {
	/// The rumor awaits delivery, with no task holding it.
	Pending,
	/// One task holds the rumor for its delivery.
	Claimed,
	/// The rumor is delivered, so the retry set drops it for good.
	Delivered,
}

/// In-memory [`GossipJournal`] with per-signer partitioning.
///
/// Deduplication is global on the content digest. Each relay rebuilds only
/// the OUTER hop frame, so rumor bytes travel unchanged across relays and the
/// digest matches wherever the rumor arrives.
///
/// # Capacity
///
/// Per-signer capacity bounds retained and witnessed entries separately,
/// so a signer that fills one kind cannot starve its own other kind.
/// Signers and kinds share the global cap: it is a memory ceiling, not a
/// fairness partition.
///
/// # Retention
///
/// Retention prunes on every record, witness, and read in both clock
/// directions, so a read returns only the rumors inside the window.
pub struct MemoryGossipJournal {
	entries: Mutex<HashMap<GossipDigest, JournalEntry>>,
	retention: Duration,
	capacity: usize,
	per_signer_capacity: usize,
}

/// The two capacity bounds a journal holds.
///
/// Both are counts of journal entries, so a positional pair lets a caller
/// exchange them and give every signer the whole log. The named fields are
/// what the call site binds (CWE-770).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalLimits {
	/// Retained rumors and witnessed digests the journal holds in total.
	pub total: usize,
	/// Retained rumors the journal holds for any one signer. The same count
	/// bounds that signer's witnessed digests separately.
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
	/// Route key that this gateway delivers admitted rumors to.
	///
	/// - [`ColonyNamespace::servlet_type_key`] creates the key, so a
	///   configured ingress always names a servlet type this colony can route.
	/// - Local delivery is receiving-gateway policy rather than rumor content.
	/// - The servlet receives the origin-signed rumor frame. Its message
	///   decodes as a [`GossipRumor`], and its signature names the publishing
	///   gateway.
	/// - `None` journals and refloods only, and marks the record delivered so
	///   it stays out of the pending retry set.
	///
	/// [`ColonyNamespace::servlet_type_key`]: crate::colony::common::ColonyNamespace::servlet_type_key
	///
	/// # Export boundary
	///
	/// The ingress sink sits outside the export boundary. Peer trust and the
	/// origin signature already gate which gateways may flood a rumor, and
	/// the operator chooses the delivery type, so the export allowlist does
	/// not apply here.
	///
	/// Every trusted colony delivers through this type, so an operator who
	/// restricts exports should treat it as a channel for the whole flood.
	pub ingress: Option<ServletTypeKey>,
	/// Deduplication and retention store, which owns its own retention window.
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

	fn fetch(&self, wanted: &[GossipDigest], now: UnixMillis) -> Result<Vec<(GossipDigest, Frame)>, ClusterError> {
		let mut entries = self.entries.lock()?;

		Self::prune(&mut entries, self.retention, now);

		let found = wanted
			.iter()
			.filter_map(|digest| entries.get(digest).map(|entry| (digest, entry)))
			.filter_map(|(digest, entry)| match &entry.body {
				JournalBody::Retained { rumor, .. } => Some((*digest, rumor.as_ref().clone())),
				JournalBody::Witnessed => None,
			})
			.collect();

		Ok(found)
	}

	fn pending_local(&self, now: UnixMillis) -> Result<Vec<(GossipDigest, Frame)>, ClusterError> {
		let mut entries = self.entries.lock()?;

		Self::prune(&mut entries, self.retention, now);

		let pending = entries
			.iter()
			.filter_map(|(digest, entry)| match &entry.body {
				JournalBody::Retained { rumor, local: LocalDelivery::Pending } => {
					Some((*digest, rumor.as_ref().clone()))
				}
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
	use crate::crypto::hash::{Sha3_256, Sha3_512};
	use crate::crypto::sign::ecdsa::Secp256k1Signature;
	use crate::encode;
	use crate::tb_cases;
	use crate::testing::{TestFrame, TestIdentity, TestKey, TestMessage, TestRumor};

	/// The reference instant the fixture rumors are issued at.
	const T0: UnixMillis = UnixMillis::new(1_000);

	/// The freshness and retention window the fixtures run under.
	const WINDOW: Duration = Duration::from_millis(30_000);

	fn digest(rumor: &Frame) -> GossipDigest {
		let verified = TestRumor::verified(rumor.clone());
		verified.gossip_digest::<Sha3_256>().expect("test rumor frames encode")
	}

	#[test]
	fn digest_is_deterministic() {
		let frame = TestRumor::application(1_000, vec![1, 2, 3]);
		assert_eq!(digest(&frame), digest(&frame));
	}

	#[test]
	fn digest_tracks_payload_and_order() {
		let base = TestRumor::application(1_000, vec![1, 2, 3]);
		let other_payload = TestRumor::application(1_000, vec![9, 9, 9]);
		let other_order = TestRumor::application(2_000, vec![1, 2, 3]);
		assert_ne!(digest(&base), digest(&other_payload));
		assert_ne!(digest(&base), digest(&other_order));
	}

	#[test]
	fn digest_survives_decode_reencode() {
		let frame = TestRumor::application(1_000, vec![1, 2, 3]);
		let relayed: Frame =
			decode(&encode(&frame).expect("test rumor frames encode")).expect("canonical bytes decode");
		assert_eq!(digest(&frame), digest(&relayed));
	}

	#[test]
	fn admit_accepts_valid_rumor() -> Result<(), TransitStatus> {
		let frame = TestRumor::application(1_000, vec![1, 2, 3]);
		let rumor = TestRumor::verified(frame.clone());
		let admitted = AdmittedGossip::admit::<Sha3_256>(&rumor, 4, WINDOW, T0)?;
		assert_eq!(admitted.digest(), &digest(&frame));
		assert_eq!(admitted.payload(), &[1, 2, 3]);
		Ok(())
	}

	#[test]
	fn admit_refuses_oversized_payload() {
		let frame = TestRumor::application(1_000, vec![0u8; MAX_GOSSIP_PAYLOAD_BYTES + 1]);
		let rumor = TestRumor::verified(frame);
		let status = AdmittedGossip::admit::<Sha3_256>(&rumor, 4, WINDOW, T0);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn admit_refuses_excessive_ttl() {
		let rumor = TestRumor::verified(TestRumor::application(1_000, vec![1, 2, 3]));
		let over = u64::from(MAX_GOSSIP_TTL) + 1;
		let status = AdmittedGossip::admit::<Sha3_256>(&rumor, over, WINDOW, T0);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	#[test]
	fn admit_refuses_stale_rumor() {
		let rumor = TestRumor::verified(TestRumor::application(1_000, vec![1, 2, 3]));
		let status = AdmittedGossip::admit::<Sha3_256>(&rumor, 4, WINDOW, UnixMillis::new(100_000));
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
	}

	/// Admission refuses a rumor whose own signature verifies but whose body
	/// is no `GossipRumor`.
	#[test]
	fn admit_refuses_undecodable_body() -> Result<(), TightBeamError> {
		let signer = TestIdentity::certified(TestKey::insecure_fixed_signing());
		let frame = FrameBuilder::from(Version::V1)
			.with_id("rumor")
			.with_order(1_000)
			.with_message(TestMessage::sample(None))
			.with_signer::<Secp256k1Signature, _>(signer)
			.build()?;

		let rumor = TestRumor::verified(frame);
		let status = AdmittedGossip::admit::<Sha3_256>(&rumor, 4, WINDOW, T0);
		assert_eq!(status.err(), Some(TransitStatus::PermissionDenied));
		Ok(())
	}

	/// A rumor relayed with its signature's `s` flipped to `n - s` verifies,
	/// and its digest is its original's, so the journal refuses it as a
	/// duplicate (SEC 1 v2.0 §4.1.4).
	#[test]
	fn a_rumor_replayed_with_its_s_flipped_is_a_duplicate() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = TestRumor::application(1_000, vec![1, 2, 3]);
		let flipped = TestFrame::with_flipped_s(&frame);

		journal.record(b"signer-a", digest(&frame), &frame, T0)?;

		let replayed = journal.record(b"signer-a", digest(&flipped), &flipped, T0)?;
		assert_eq!(replayed, Admission::Duplicate);
		Ok(())
	}

	#[test]
	fn record_dedups_same_digest() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = TestRumor::application(1_000, vec![1, 2, 3]);
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
		let frame = TestRumor::application(1_000, vec![1, 2, 3]);
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
		let frame = TestRumor::application(1_000, vec![1, 2, 3]);
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
		let frame = TestRumor::application(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.witness(b"signer-a", digest, T0)?;

		assert!(journal.seen(&digest, T0)?);
		assert!(journal.held_digests(T0)?.is_empty());
		assert!(journal.fetch(core::slice::from_ref(&digest), T0)?.is_empty());
		assert!(journal.pending_local(T0)?.is_empty());
		Ok(())
	}

	#[test]
	fn witness_blocks_record_of_same_digest() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = TestRumor::application(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.witness(b"signer-a", digest, T0)?;

		let replay = journal.record(b"signer-a", digest, &frame, T0)?;
		assert_eq!(replay, Admission::Duplicate);
		Ok(())
	}

	#[test]
	fn witness_expires_with_retention() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::new(WINDOW);
		let frame = TestRumor::application(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.witness(b"signer-a", digest, T0)?;
		assert!(journal.seen(&digest, T0)?);
		assert!(!journal.seen(&digest, UnixMillis::new(90_000))?);
		Ok(())
	}

	#[test]
	fn witness_fails_closed_at_signer_capacity() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::with_limits(WINDOW, JournalLimits { total: 8, per_signer: 1 });
		let first = TestRumor::application(1_000, vec![1]);
		let second = TestRumor::application(1_000, vec![2]);

		journal.witness(b"signer-a", digest(&first), T0)?;

		let overflow = journal.witness(b"signer-a", digest(&second), T0);
		assert!(matches!(overflow, Err(ClusterError::GossipJournalAtCapacity)));
		Ok(())
	}

	#[test]
	fn witness_and_record_spend_separate_signer_budgets() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::with_limits(WINDOW, JournalLimits { total: 8, per_signer: 1 });
		let witnessed = TestRumor::application(1_000, vec![1]);
		let retained = TestRumor::application(1_000, vec![2]);

		let hint = journal.witness(b"signer-a", digest(&witnessed), T0)?;
		let application = journal.record(b"signer-a", digest(&retained), &retained, T0)?;
		assert_eq!(hint, Admission::New);
		assert_eq!(application, Admission::New);
		Ok(())
	}

	#[test]
	fn record_fails_closed_at_global_capacity() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::with_limits(WINDOW, JournalLimits { total: 1, per_signer: 8 });
		let first = TestRumor::application(1_000, vec![1]);
		let second = TestRumor::application(1_000, vec![2]);

		journal.record(b"signer-a", digest(&first), &first, T0)?;

		let overflow = journal.record(b"signer-a", digest(&second), &second, T0);
		assert!(matches!(overflow, Err(ClusterError::GossipJournalAtCapacity)));
		Ok(())
	}

	#[test]
	fn record_fails_closed_at_per_signer_capacity() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::with_limits(WINDOW, JournalLimits { total: 8, per_signer: 1 });
		let first = TestRumor::application(1_000, vec![1]);
		let second = TestRumor::application(1_000, vec![2]);
		let other = TestRumor::application(1_000, vec![3]);

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
		let frame = TestRumor::application(1_000, vec![1, 2, 3]);
		let digest = digest(&frame);

		journal.record(b"signer-a", digest, &frame, T0)?;
		let before = journal.pending_local(T0)?;
		journal.ack_local(&digest)?;

		let after = journal.pending_local(T0)?;
		assert_eq!(before.len(), 1);
		assert_eq!(after.len(), 0);
		Ok(())
	}

	// The journal holds back a rumor whose delivery is in flight, so the beat
	// and the admission path cannot both deliver it (CWE-362).
	#[test]
	fn a_claimed_rumor_is_not_offered_again() -> Result<(), ClusterError> {
		let journal = MemoryGossipJournal::default();
		let frame = TestRumor::application(1_000, vec![1, 2, 3]);
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
		let frame = TestRumor::application(1_000, vec![1, 2, 3]);
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
		let frame = TestRumor::application(1_000, vec![1, 2, 3]);
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
		let frame = TestRumor::application(1_000, vec![1, 2, 3]);
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
		let first = TestRumor::application(1_000, vec![1]);
		let second = TestRumor::application(1_000, vec![2]);
		let first_digest = digest(&first);

		journal.record(b"signer-a", first_digest, &first, T0)?;
		journal.record(b"signer-a", digest(&second), &second, T0)?;

		let fetched = journal.fetch(core::slice::from_ref(&first_digest), T0)?;
		assert_eq!(fetched, vec![(first_digest, first)]);
		Ok(())
	}

	#[test]
	fn want_requests_only_unheld_digests() {
		let held = TestRumor::application(1_000, vec![1]);
		let missing = TestRumor::application(1_000, vec![2]);
		let held_digest = digest(&held);
		let advertised = vec![held_digest.as_bytes().to_vec(), digest(&missing).as_bytes().to_vec()];

		let want = gossip_want::<Sha3_256>(&advertised, [held_digest]);
		assert_eq!(want, vec![digest(&missing).as_bytes().to_vec()]);
	}

	#[test]
	fn want_is_empty_when_all_advertised_are_held() {
		let first = digest(&TestRumor::application(1_000, vec![1]));
		let second = digest(&TestRumor::application(1_000, vec![2]));
		let advertised = vec![first.as_bytes().to_vec(), second.as_bytes().to_vec()];

		let want = gossip_want::<Sha3_256>(&advertised, [first, second]);
		assert!(want.is_empty());
	}

	#[test]
	fn wanted_digests_keeps_only_correct_length() {
		let good = digest(&TestRumor::application(1_000, vec![1]));
		let want = vec![good.as_bytes().to_vec(), vec![0u8; 8], vec![0u8; 64]];

		let decoded = wanted_digests::<Sha3_256>(&want);
		assert_eq!(decoded, vec![good]);
	}

	#[test]
	fn wanted_digests_collapses_duplicates() {
		let good = digest(&TestRumor::application(1_000, vec![1]));
		let want = vec![good.as_bytes().to_vec(), good.as_bytes().to_vec(), good.as_bytes().to_vec()];

		let decoded = wanted_digests::<Sha3_256>(&want);
		assert_eq!(decoded, vec![good]);
	}

	/// Under a 64-octet digest, a 32-octet entry names no rumor, so the want
	/// list reads the 64-octet entry alone.
	#[test]
	fn wanted_digests_read_at_the_width_of_the_colony_digest() {
		let want = vec![vec![7u8; 32], vec![9u8; 64]];

		let decoded = wanted_digests::<Sha3_512>(&want);
		let read: Vec<&[u8]> = decoded.iter().map(GossipDigest::as_bytes).collect();
		assert_eq!(read, vec![[9u8; 64].as_slice()]);
	}

	/// An entry whose length differs from a digest names no rumor, so the want
	/// list drops it rather than echo it to its sender.
	#[test]
	fn want_drops_entries_of_another_length() {
		let advertised = vec![vec![0u8; 5000], vec![1, 2, 3]];

		let want = gossip_want::<Sha3_256>(&advertised, []);
		assert!(want.is_empty());
	}

	#[test]
	fn want_collapses_repeated_advertisements() {
		let missing = digest(&TestRumor::application(1_000, vec![2]));
		let entry = missing.as_bytes().to_vec();
		let advertised = vec![entry.clone(), entry.clone(), entry];

		let want = gossip_want::<Sha3_256>(&advertised, []);
		assert_eq!(want, vec![missing.as_bytes().to_vec()]);
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
		let early = TestRumor::application(1_000, vec![1]);
		let late = TestRumor::application(1_000, vec![2]);

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
		let frame = TestRumor::application(1_000, vec![1]);
		let rumor_digest = digest(&frame);

		journal.record(b"signer-a", rumor_digest, &frame, UnixMillis::new(0))?;

		let held = journal.held_digests(T0)?;
		let fetched = journal.fetch(core::slice::from_ref(&rumor_digest), T0)?;
		let pending = journal.pending_local(T0)?;
		assert_eq!(held.len(), 0);
		assert_eq!(fetched.len(), 0);
		assert_eq!(pending.len(), 0);
		Ok(())
	}

	// An origin advertisement names the signer its apply binds, and an origin
	// application rumor, whose delivery reads no signer, names none.
	tb_cases! {
		fn an_origin_rumor_names_the_signer_its_kind_reads((kind, named): (GossipRumorKind, Option<u8>)) {
			assert_eq!(kind.origin_signer(|| Some(7)), named);
		}
		cases {
			application => (GossipRumorKind::Application, None),
			peer_advertisement => (GossipRumorKind::PeerAdvertisement, Some(7)),
		}
	}
}
