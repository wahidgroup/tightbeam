//! The gossip admission, the content digest, and the retention journal.
//!
//! Gateways flood origin-signed rumors across the colonies of one namespace
//! and deliver admitted rumors locally under the operator's ingress policy.
//! A gateway forwards a rumor while its outer relay frame has hop
//! time-to-live left.
//!
//! # Flood scope
//!
//! The [`Flood`](super::peer::Flood) type owns the scope. A rumor travels
//! between the gateways that the peer trust store admits and whose
//! certificates carry a colony URN of the local namespace.
//!
//! # Rumor model
//!
//! A rumor is an origin-signed [`Frame`]. The origin gateway signs it once,
//! and later hops and anti-entropy repair carry those same signed bytes.
//! The hop radius is in the OUTER relay frame's `metadata.lifetime`, outside
//! the content digest.
//!
//! # Admission path
//!
//! [`AdmittedGossip`] is the only path from a received rumor to delivery. The
//! [`GossipJournal`] stores digests for deduplication and retention, and
//! [`MemoryGossipJournal`] is its in-memory default.

use core::mem::discriminant;
use core::num::NonZeroU128;
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use super::runtime::LoopFault;
use super::{ClusterError, ClusterTlsConfig, FreshnessWindow};
use crate::asn1::Frame;
use crate::clock::UnixMillis;
use crate::colony::protocol::IssuedAt;
use crate::colony::protocol::{GossipRumor, GossipRumorKind};
use crate::constants::{
	DEFAULT_GOSSIP_RATE_BURST, DEFAULT_GOSSIP_RATE_REFILL_MS, DEFAULT_GOSSIP_RETENTION_MS, DEFAULT_GOSSIP_SEEN_TTL_MS,
	DEFAULT_GOSSIP_TTL, MAX_GOSSIP_LOG, MAX_GOSSIP_LOG_PER_SIGNER, MAX_GOSSIP_PAYLOAD_BYTES, MAX_GOSSIP_RATE_SIGNERS,
	MAX_GOSSIP_TTL,
};
use crate::crypto::hash::{Digest, OutputSizeUser};
use crate::crypto::sign::VerifiedSignature;
use crate::policy::TransitStatus;
use crate::transport::handshake::primitives::transcript::DigestOutput;
use crate::urn::Urn;
use crate::TightBeamError;

/// The content digest of a gossip rumor, under the digest of the colony's
/// provider.
///
/// Every gateway of a colony runs one provider, so each derives the same
/// digest for a rumor, as wide as that provider's digest output.
/// [`VerifiedRumor::gossip_digest`] computes one, and [`GossipDigest::read`]
/// reads one that a peer sent.
///
/// # Width
///
/// The digest is inline at its width, 32 to 64 octets, the widths of the
/// handshake digests. It is [`Copy`], so the gateway admits, journals, and
/// compares a rumor's digest on the stack.
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
	/// A durable [`GossipJournal`] stores [`Self::as_bytes`] and restores each
	/// digest here, with `D` the digest of the colony's provider. For a gateway
	/// of protocol `P`, that is
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
	/// The journal held no entry for the digest and recorded it, so the
	/// caller delivers and forwards the rumor.
	New,
	/// The journal already held the digest in the window, so the caller
	/// drops the rumor.
	Duplicate,
}

/// A rumor frame beside the origin signature that verified over it.
///
/// Only a verification makes one: the parse that verified the rumor on a
/// trust plane, or the gateway's check of its own rumor. So a rumor's digest
/// covers that rumor's own signature.
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

	/// The digest over the rumor's to-be-signed encoding and its origin
	/// signature in canonical form.
	///
	/// - The digest covers the identity, issue time, payload, and origin signature.
	/// - The hop radius lives on the OUTER relay frame and MUST NOT enter the digest.
	/// - A rumor relayed with `s` flipped to `n - s` digests as its original.
	///
	/// # Algorithm
	///
	/// The algorithm `D` MUST be the digest of the cluster's crypto profile
	/// (CWE-694).
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
	/// A rumor this gateway originates needs a verified signature for its
	/// digest to cover, whether or not a trust plane holds this gateway's
	/// certificate.
	///
	/// # Errors
	///
	/// - [`ClusterError::OwnSignatureRefused`] -- the frame carries no
	///   signature, or the signature fails to verify.
	pub(crate) fn verify_own(&self, frame: Frame) -> Result<VerifiedRumor, ClusterError> {
		let verified = frame.verify_under(self.identity.signing_certificate(), self.identity.policy());
		let signature = verified.map_err(ClusterError::OwnSignatureRefused)?;
		Ok(VerifiedRumor::new(frame, signature))
	}
}

/// The rumor digests one side of a reconcile round wants, each read under the
/// colony's digest.
///
/// Reconciliation is a set difference over content digests, and both sides
/// of a round read entries by one rule:
///
/// - An entry of a width other than the colony's digest names no rumor, so the list drops it (CWE-20).
/// - A repeated entry appears once, so a peer cannot multiply the reply or the repair pushes (CWE-770).
///
/// [`Self::against`] builds the list a replier sends, and [`Self::read`] reads
/// the list a requester receives.
///
/// # Examples
///
/// ```
/// use tightbeam::colony::cluster::{GossipDigest, WantList};
/// use tightbeam::crypto::hash::Sha3_256;
///
/// let held = [GossipDigest::read::<Sha3_256>([7u8; 32]).ok_or("a 32-octet digest reads")?];
/// let advertised = vec![vec![7u8; 32], vec![9u8; 32], vec![9u8; 32], vec![1, 2, 3]];
///
/// let want = WantList::against::<Sha3_256>(&advertised, held);
/// assert_eq!(want.into_wire(), vec![vec![9u8; 32]]);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WantList(Vec<GossipDigest>);

impl WantList {
	/// The entries of a peer's `advertised` list that read as digests under
	/// the colony's digest `D` and that `held` lacks.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::WantList;
	/// use tightbeam::crypto::hash::Sha3_256;
	///
	/// // A 64-octet entry names no SHA3-256 rumor.
	/// let advertised = vec![vec![9u8; 32], vec![9u8; 64]];
	///
	/// let want = WantList::against::<Sha3_256>(&advertised, []);
	/// assert_eq!(want.digests().len(), 1);
	/// ```
	#[must_use]
	pub fn against<D: OutputSizeUser>(advertised: impl AsRef<[Vec<u8>]>, held: impl AsRef<[GossipDigest]>) -> Self {
		let advertised = advertised.as_ref();
		let held = held.as_ref();
		let local: HashSet<&[u8]> = held.iter().map(GossipDigest::as_bytes).collect();

		let lacking = advertised.iter().filter(|entry| !local.contains(entry.as_slice()));
		Self::first_of_each::<D>(lacking)
	}

	/// The entries of a received `want` list that read as digests under the
	/// colony's digest `D`.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::WantList;
	/// use tightbeam::crypto::hash::Sha3_512;
	///
	/// let want = vec![vec![9u8; 64], vec![9u8; 64], vec![7u8; 32]];
	///
	/// let wanted = WantList::read::<Sha3_512>(&want);
	/// assert_eq!(wanted.digests().len(), 1);
	/// ```
	#[must_use]
	pub fn read<D: OutputSizeUser>(want: impl AsRef<[Vec<u8>]>) -> Self {
		let want = want.as_ref();
		Self::first_of_each::<D>(want.iter())
	}

	/// The `entries` that read as digests under `D`, each once, in the order
	/// the entries first name it.
	///
	/// The set that drops a repeat borrows the received entries, so the list
	/// copies an entry only when it keeps it.
	fn first_of_each<'w, D: OutputSizeUser>(entries: impl Iterator<Item = &'w Vec<u8>>) -> Self {
		let mut named: HashSet<&'w [u8]> = HashSet::new();
		let first = entries.filter(|entry| named.insert(entry.as_slice()));

		let digests = first.filter_map(GossipDigest::read::<D>).collect();
		Self(digests)
	}

	/// The wanted digests, in the order the list first names each one.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::WantList;
	/// use tightbeam::crypto::hash::Sha3_256;
	///
	/// let wanted = WantList::read::<Sha3_256>([vec![3u8; 32]]);
	/// let first = wanted.digests().first().ok_or("the entry reads as a digest")?;
	/// assert_eq!(first.as_bytes(), [3u8; 32]);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[must_use]
	pub fn digests(&self) -> &[GossipDigest] {
		&self.0
	}

	/// The entries a [`GossipWant`] reply carries, one per wanted digest.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::WantList;
	/// use tightbeam::crypto::hash::Sha3_256;
	///
	/// let wanted = WantList::read::<Sha3_256>([vec![3u8; 32], vec![3u8; 32]]);
	/// assert_eq!(wanted.into_wire(), vec![vec![3u8; 32]]);
	/// ```
	///
	/// [`GossipWant`]: crate::colony::protocol::GossipWant
	#[must_use]
	pub fn into_wire(self) -> Vec<Vec<u8>> {
		self.0.iter().map(|digest| digest.as_bytes().to_vec()).collect()
	}
}

/// A rumor that passed the payload, hop-radius, and freshness checks.
///
/// Only [`AdmittedGossip::admit`] constructs one, and the gateway handler
/// runs the signature and flood-membership checks before it.
pub struct AdmittedGossip {
	digest: GossipDigest,
	payload: Vec<u8>,
	kind: GossipRumorKind,
}

impl AdmittedGossip {
	/// Admits one verified rumor, or fails closed with
	/// [`TransitStatus::PermissionDenied`].
	///
	/// `ttl` is the hop radius left in the OUTER `metadata.lifetime`. The
	/// `seen` window judges the rumor's `metadata.order`, its signed issue
	/// time, at `now`. A gateway passes its gossip configuration's window,
	/// which its anti-entropy repair also judges by.
	///
	/// # Refusal
	///
	/// Each of these refuses the rumor:
	///
	/// - The frame is no carrier of a [`GossipRumor`] ([`Frame::decode_message`]).
	/// - The payload exceeds [`MAX_GOSSIP_PAYLOAD_BYTES`].
	/// - `ttl` exceeds [`MAX_GOSSIP_TTL`], which caps the hop radius here at the trust boundary (CWE-770).
	/// - The issue time lies outside the `seen` window of `now`, on either side.
	/// - The to-be-signed encoding of the rumor fails, so it has no digest.
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::clock::UnixMillis;
	/// use tightbeam::colony::cluster::{AdmittedGossip, FreshnessWindow};
	/// use tightbeam::crypto::hash::Sha3_256;
	/// use tightbeam::policy::TransitStatus;
	/// use tightbeam::testing::fixtures::TestRumor;
	///
	/// let rumor = TestRumor::verified(TestRumor::application(1_000, [1, 2, 3]));
	/// let seen = FreshnessWindow::new(Duration::from_secs(30));
	///
	/// let admitted = AdmittedGossip::admit::<Sha3_256>(&rumor, 0, seen, UnixMillis::new(1_000));
	/// assert!(admitted.is_ok_and(|admitted| admitted.payload() == [1, 2, 3]));
	///
	/// // 31 s later the issue time is stale.
	/// let stale = AdmittedGossip::admit::<Sha3_256>(&rumor, 0, seen, UnixMillis::new(32_000));
	/// assert_eq!(stale.err(), Some(TransitStatus::PermissionDenied));
	/// ```
	pub fn admit<D: Digest>(
		rumor: &VerifiedRumor,
		ttl: u64,
		seen: impl Into<FreshnessWindow>,
		now: UnixMillis,
	) -> Result<Self, TransitStatus> {
		let frame = rumor.frame();
		let body: GossipRumor = frame.decode_message().map_err(|_| TransitStatus::PermissionDenied)?;

		let within_payload = body.payload.len() <= MAX_GOSSIP_PAYLOAD_BYTES;
		let within_ttl = ttl <= u64::from(MAX_GOSSIP_TTL);
		let fresh = seen.into().admits(frame.issued_at(), now);
		if within_payload && within_ttl && fresh {
			let digest = rumor.gossip_digest::<D>().map_err(|_| TransitStatus::PermissionDenied)?;
			let admitted = Self { digest, payload: body.payload, kind: body.kind };
			Ok(admitted)
		} else {
			Err(TransitStatus::PermissionDenied)
		}
	}

	/// The content digest for deduplication and reconciliation.
	#[must_use]
	pub fn digest(&self) -> &GossipDigest {
		&self.digest
	}

	/// The application payload from the signed rumor body.
	#[must_use]
	pub fn payload(&self) -> &[u8] {
		&self.payload
	}

	/// How the origin intends a gateway to consume this rumor.
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
/// Each one is a method here, so a new kind states its name, its journal, its
/// consumption, its retry, and the signer it names in this one place.
impl GossipRumorKind {
	/// The name of this kind, which the audit event of an admitted rumor
	/// carries as its label.
	#[must_use]
	pub(crate) const fn label(self) -> &'static str {
		match self {
			Self::Application => "application",
			Self::PeerAdvertisement => "peer-advertisement",
		}
	}

	/// Journal one admitted rumor of this kind under `digest`, against the
	/// budget of `signer`.
	///
	/// - The journal retains an application rumor for anti-entropy repair and delivery retry.
	/// - The journal witnesses an advertisement rumor for deduplication alone,
	///   so retention and repair bandwidth go to the rumors that use them.
	/// - Either entry keeps the issue time `rumor` states, the instant its admission judged fresh.
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
		let issued_at = rumor.issued_at();
		match self {
			Self::Application => journal.record(signer, digest, rumor, issued_at, now),
			Self::PeerAdvertisement => journal.witness(signer, digest, issued_at, now),
		}
	}

	/// Consume one admitted rumor of this kind through `consumer`.
	///
	/// - An application rumor goes to the local ingress. The ingress takes a
	///   copy of `rumor`, because the reflood also carries it.
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
	/// The journal retains application rumors, so a retry delivers one. It
	/// keeps only an advertisement rumor's digest, so that retry completes at
	/// once.
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

/// The per-signer rate admission that gates the gossip pipeline.
///
/// The gateway asks it after signature verification and before the journal
/// record or the reflood, so it refuses an over-limit signer before that
/// signer grows retained state or amplifies traffic (CWE-770).
///
/// # Default
///
/// [`TokenBucketAdmission`], the default, bounds burst and sustained rate. A
/// custom implementation may meter on any signer-derived dimension.
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

/// One signer's bucket, with the tokens it holds and its last refill instant.
struct TokenBucket {
	tokens: u32,
	refilled_at: UnixMillis,
}

/// An in-memory token-bucket [`GossipAdmission`] keyed on the signer.
///
/// Each signer spends one token per rumor from a bucket of `burst`
/// capacity, and the bucket regains one token every `refill_interval`. Each
/// call prunes a bucket that had time to refill from empty, because a full
/// bucket needs no state.
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
	/// tracked-signer ceiling, [`MAX_GOSSIP_RATE_SIGNERS`].
	#[must_use]
	pub fn new(burst: u32, refill_interval: Duration) -> Self {
		Self::with_limits(burst, refill_interval, MAX_GOSSIP_RATE_SIGNERS)
	}

	/// Builds an admission from `burst`, `refill_interval`, and a
	/// tracked-signer ceiling of `capacity`.
	///
	/// The interval counts in whole milliseconds. An interval under one
	/// millisecond refills once per millisecond, and an interval past
	/// `u64::MAX` milliseconds saturates there (CWE-197).
	#[must_use]
	pub fn with_limits(burst: u32, refill_interval: Duration, capacity: usize) -> Self {
		let whole_ms = u64::try_from(refill_interval.as_millis()).unwrap_or(u64::MAX);

		Self {
			buckets: Mutex::new(HashMap::new()),
			burst,
			refill_interval: Duration::from_millis(whole_ms.max(1)),
			capacity,
		}
	}

	/// Drop each bucket whose last refill lies `burst` refill intervals or
	/// more from `now`, in either clock direction. Such a bucket is full from
	/// any token count, and a full bucket admits the same as an absent one.
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

/// The deduplication and retention store for delivery and anti-entropy.
///
/// The gateway reaches the journal through this interface alone.
/// [`MemoryGossipJournal`], the in-memory default, gives bounded-window
/// eventual delivery, and a durable backend can retain across restarts.
/// Errors are typed [`ClusterError`] variants.
///
/// # Digest width
///
/// Every digest a gateway hands its journal is as wide as the colony digest,
/// the digest of the gateway's provider, fixed for the gateway's life. A
/// durable backend stores each [`GossipDigest::as_bytes`] and restores it with
/// [`GossipDigest::read`] under that digest.
///
/// # Retention
///
/// A journal keeps each entry while its rumor's issue time lies inside
/// [`GossipJournal::retention`] of the clock, by the rule of
/// [`FreshnessWindow::admits`]. Admission judges the same instant, so every
/// fresh rumor has its digest and its replay reads as a duplicate (CWE-294).
pub trait GossipJournal: Send + Sync {
	/// Deduplicate and retain one origin-signed rumor in a single step.
	///
	/// The journal keeps the rumor unchanged, so anti-entropy repair forwards
	/// the same origin-signed bytes, while `issued_at`, the rumor's issue time,
	/// lies inside retention of `now`. Returns [`Admission::New`] for an unseen
	/// digest and [`Admission::Duplicate`] for a held one.
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
		issued_at: UnixMillis,
		now: UnixMillis,
	) -> Result<Admission, ClusterError>;

	/// Deduplicate one ephemeral rumor digest, and keep the digest alone.
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
	/// The journal keeps it while `issued_at`, its rumor's issue time, lies
	/// inside retention of `now`. Returns [`Admission::New`] for an unseen
	/// digest and [`Admission::Duplicate`] for a held one.
	///
	/// # Errors
	///
	/// - [`ClusterError::GossipJournalAtCapacity`] -- the journal is full, so the call fails closed.
	/// - [`ClusterError`] -- any other backend fault, such as a poisoned lock.
	fn witness(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		issued_at: UnixMillis,
		now: UnixMillis,
	) -> Result<Admission, ClusterError>;

	/// Whether a digest is already retained or witnessed, as a read-only probe.
	///
	/// The gateway probes before rate admission, so a duplicate keeps its
	/// signer's token. Relay echoes are normal and MUST NOT drain the bucket.
	///
	/// The probe is advisory. [`GossipJournal::record`] and
	/// [`GossipJournal::witness`] stay the atomic deduplication steps for a
	/// race past it.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- a backend fault, such as a poisoned lock.
	fn seen(&self, digest: &GossipDigest, now: UnixMillis) -> Result<bool, ClusterError>;

	/// The digests of retained rumors inside the retention window, for
	/// reconciliation summaries.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- a backend fault, such as a poisoned lock.
	fn held_digests(&self, now: UnixMillis) -> Result<Vec<GossipDigest>, ClusterError>;

	/// The retained rumor frames for the digests a peer wants, each beside the
	/// digest the journal recorded it under.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- a backend fault, such as a poisoned lock.
	fn fetch(&self, wanted: &[GossipDigest], now: UnixMillis) -> Result<Vec<(GossipDigest, Frame)>, ClusterError>;

	/// The retained rumors that wait for local delivery, each beside the digest
	/// the journal recorded it under, apart from those a task already claimed
	/// through [`GossipJournal::claim_local`].
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- a backend fault, such as a poisoned lock.
	fn pending_local(&self, now: UnixMillis) -> Result<Vec<(GossipDigest, Frame)>, ClusterError>;

	/// Take one rumor's local delivery, so one task alone delivers it.
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

	/// The retention horizon of this journal.
	///
	/// At start, the gateway clamps admission freshness (`seen_ttl`) to it,
	/// because a rumor whose issue time lies outside retention has no digest
	/// left to deduplicate against. A wider window would admit a replay again
	/// (CWE-294).
	fn retention(&self) -> Duration;
}

/// One deduplicated digest and the bookkeeping the journal tracks for it.
struct JournalEntry {
	signer: Vec<u8>,
	/// The issue time the rumor states, which retention judges.
	issued_at: UnixMillis,
	body: JournalBody,
}

/// What the journal keeps behind a deduplicated digest.
///
/// A retained rumor serves anti-entropy repair and local delivery retry.
/// A witnessed digest serves deduplication alone, so its body is empty. The
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
	/// Another task holds the delivery, or the delivery is complete.
	Held,
	/// The journal retains no rumor for this digest, so nothing retries it
	/// and the caller delivers without a claim.
	Untracked,
}

/// One local delivery in progress, whose claim this guard releases on drop.
///
/// A claim taken by hand leaks when its delivery future drops: a cancelled
/// task or a disconnected caller leaves the rumor claimed by no live task,
/// and no retry offers it again. The guard owns the claim, and a dropped
/// future drops the guard.
///
/// # Exits
///
/// - The drop of the guard releases the claim, so the rumor returns to the retry set.
/// - [`Self::ack`] retires the entry instead, the one exit that takes the rumor out of the retry set.
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
	/// it or its delivery is complete.
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
	/// - [`ClusterError`] -- the journal's own fault. The guard then releases
	///   the claim to the retry set, so the retry beat offers the unrecorded
	///   delivery again.
	pub fn ack(mut self) -> Result<(), ClusterError> {
		self.journal.ack_local(self.digest)?;
		self.retries = false;

		Ok(())
	}
}

impl Drop for LocalClaimGuard<'_> {
	fn drop(&mut self) {
		if self.retries {
			// A destructor has no caller to answer. A journal that refuses the
			// release refuses the next claim the same way, so that claim
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
	/// The rumor awaits delivery, and any task may claim it.
	Pending,
	/// One task holds the rumor for its delivery.
	Claimed,
	/// The rumor's delivery is complete, so the retry set drops it for good.
	Delivered,
}

/// An in-memory [`GossipJournal`] with per-signer partitions.
///
/// Deduplication is global on the content digest. Each relay rebuilds only
/// the OUTER hop frame, so rumor bytes travel unchanged across relays and the
/// digest matches wherever the rumor arrives.
///
/// # Capacity
///
/// Per-signer capacity bounds retained and witnessed entries separately,
/// so a signer that fills one kind keeps its budget for the other.
/// Signers and kinds share the global cap, which bounds memory alone and
/// fills first come, first served.
///
/// # Retention
///
/// Each entry keeps its rumor's issue time. Retention prunes on every record,
/// witness, and read, and drops an entry once that instant lies outside the
/// window in either clock direction, so a read returns only rumors inside the
/// window.
pub struct MemoryGossipJournal {
	entries: Mutex<HashMap<GossipDigest, JournalEntry>>,
	retention: Duration,
	capacity: usize,
	per_signer_capacity: usize,
}

/// The two capacity bounds a journal holds.
///
/// Both count journal entries. A positional pair would let a caller swap them
/// and give every signer the whole log, so the call site names each one
/// (CWE-770).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalLimits {
	/// The cap on retained rumors and witnessed digests the journal holds in
	/// total.
	pub total: usize,
	/// The cap on retained rumors the journal holds for any one signer. The
	/// same count bounds that signer's witnessed digests separately.
	pub per_signer: usize,
}

impl MemoryGossipJournal {
	/// Builds a journal with the `retention` window and the default capacity
	/// caps, [`MAX_GOSSIP_LOG`] in total and [`MAX_GOSSIP_LOG_PER_SIGNER`] per
	/// signer.
	#[must_use]
	pub fn new(retention: Duration) -> Self {
		Self::with_limits(
			retention,
			JournalLimits { total: MAX_GOSSIP_LOG, per_signer: MAX_GOSSIP_LOG_PER_SIGNER },
		)
	}

	/// Builds a journal with the `retention` window and the capacity bounds
	/// of `limits`.
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

	/// The count of retained rumors pending or claimed for local delivery.
	///
	/// Zero means every retained rumor's delivery is complete.
	/// [`GossipJournal::pending_local`] leaves out a claimed rumor, in flight
	/// and off the retry set before its delivery ends, so a convergence
	/// assertion reads this count instead.
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

	/// Drop entries whose stated issue time lies outside the retention window
	/// in either clock direction. One prune rule serves reads and writes, so
	/// the two stay consistent.
	fn prune(entries: &mut HashMap<GossipDigest, JournalEntry>, retention: Duration, now: UnixMillis) {
		let window = FreshnessWindow::new(retention);
		entries.retain(|_, entry| window.admits(entry.issued_at, now));
	}
}

impl Default for MemoryGossipJournal {
	fn default() -> Self {
		Self::new(Duration::from_millis(DEFAULT_GOSSIP_RETENTION_MS))
	}
}

/// The gossip settings: freshness, origin TTL, ingress, journal, and
/// admission.
pub struct GossipConfig {
	/// The freshness window for a rumor's issue time (`metadata.order`), to
	/// each side of the clock.
	pub seen_ttl: Duration,
	/// The hop radius of an origin publish, clamped to [`MAX_GOSSIP_TTL`].
	pub ttl: u8,
	/// The servlet type that this gateway delivers admitted rumors to.
	///
	/// - [`Cluster::start`] mints its route key once, through
	///   [`ClusterConfig::gossip_ingress_key`], under the namespace the gateway
	///   serves. It refuses a URN that is no bare servlet type of that
	///   namespace, so the ingress of a running gateway names a servlet type it
	///   can route.
	/// - Local delivery is a policy of the receiving gateway, not part of the rumor.
	/// - The servlet receives the origin-signed rumor frame. Its message decodes
	///   as a [`GossipRumor`], and its signature names the publishing gateway.
	/// - `None` only journals and refloods, and marks the record delivered, out of the pending retry set.
	///
	/// [`ClusterConfig::gossip_ingress_key`]: crate::colony::cluster::ClusterConfig::gossip_ingress_key
	/// [`Cluster::start`]: crate::colony::cluster::Cluster::start
	///
	/// # Export boundary
	///
	/// The ingress sink is outside the export boundary. Peer trust and the
	/// origin signature gate which gateways may flood a rumor, and the operator
	/// picks the delivery type, so delivery bypasses the export allowlist.
	///
	/// Every trusted colony delivers through this type, so an operator who
	/// restricts exports should treat it as a channel for the whole flood.
	pub ingress: Option<Urn<'static>>,
	/// The deduplication and retention store, which owns its retention window.
	pub journal: Arc<dyn GossipJournal>,
	/// The per-signer rate admission that runs before record or reflood.
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

impl GossipConfig {
	/// The window a rumor's issue time must lie inside, [`Self::seen_ttl`] to
	/// each side of the clock.
	///
	/// Admission and anti-entropy repair both judge through it. A journal
	/// retains to its own horizon, which can reach past this window, so a
	/// fetch can return a rumor past it.
	pub(crate) fn seen_window(&self) -> FreshnessWindow {
		FreshnessWindow::new(self.seen_ttl)
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
	/// Deduplicate `digest` under the capacity discipline and store `body`,
	/// beside the `issued_at` its rumor states, when it is new (CWE-770).
	///
	/// # Per-signer budget
	///
	/// It counts only entries of `body`'s kind, so a signer's witnessed
	/// advertisement digests and its retained application rumors each fill
	/// their own budget.
	fn admit(
		&self,
		signer: impl AsRef<[u8]>,
		digest: GossipDigest,
		body: JournalBody,
		issued_at: UnixMillis,
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
			let entry = JournalEntry { signer: signer.to_vec(), issued_at, body };
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
		issued_at: UnixMillis,
		now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		let body = JournalBody::Retained { rumor: Box::new(rumor.clone()), local: LocalDelivery::Pending };
		self.admit(signer, digest, body, issued_at, now)
	}

	fn witness(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		issued_at: UnixMillis,
		now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		self.admit(signer, digest, JournalBody::Witnessed, issued_at, now)
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

	fn claim_local(&self, digest: &GossipDigest, now: UnixMillis) -> Result<LocalClaim, ClusterError> {
		let mut entries = self.entries.lock()?;

		Self::prune(&mut entries, self.retention, now);

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
	use crate::decode;
	use crate::encode;
	use crate::tb_cases;
	use crate::testing::{TestFrame, TestIdentity, TestKey, TestMessage, TestResult, TestRumor};

	/// The reference instant, which is the issue time of the fixture rumors.
	const T0: UnixMillis = UnixMillis::new(1_000);

	/// The freshness and retention window the fixtures run under.
	const WINDOW: Duration = Duration::from_millis(30_000);

	/// The fixed rumor, beside its digest.
	fn rumor() -> (Frame, GossipDigest) {
		let rumor = TestRumor::fixed();
		let digest = TestRumor::digest(&rumor);
		(rumor, digest)
	}

	/// `journal` once it records the fixed rumor of `signer-a` at [`T0`],
	/// beside that rumor and its digest.
	fn holding_the_rumor(journal: MemoryGossipJournal) -> (MemoryGossipJournal, Frame, GossipDigest) {
		let (rumor, digest) = rumor();
		let recorded = journal.record(b"signer-a", digest, &rumor, T0, T0);
		recorded.expect("a journal with room records a fresh rumor");
		(journal, rumor, digest)
	}

	/// The application rumor of the one payload octet `byte`, issued at
	/// [`T0`].
	fn rumor_carrying(byte: u8) -> Frame {
		TestRumor::application(1_000, [byte])
	}

	/// The digest of the rumor that carries `byte`.
	fn digest_carrying(byte: u8) -> GossipDigest {
		TestRumor::digest(&rumor_carrying(byte))
	}

	/// The wire form of the digest of the rumor that carries `byte`.
	fn wire(byte: u8) -> Vec<u8> {
		digest_carrying(byte).as_bytes().to_vec()
	}

	/// A journal of the fixture window that holds `total` entries at most,
	/// and `per_signer` entries of one signer at most.
	fn journal_capped(total: usize, per_signer: usize) -> MemoryGossipJournal {
		MemoryGossipJournal::with_limits(WINDOW, JournalLimits { total, per_signer })
	}

	/// A journal that retains an entry for 100 ms, with room for eight.
	fn short_lived_journal() -> MemoryGossipJournal {
		let roomy = JournalLimits { total: 8, per_signer: 8 };
		MemoryGossipJournal::with_limits(Duration::from_millis(100), roomy)
	}

	/// One rumor digests to one value on every run.
	#[test]
	fn digest_is_deterministic() {
		let frame = TestRumor::fixed();
		assert_eq!(TestRumor::digest(&frame), TestRumor::digest(&frame));
	}

	// A digest tracks the payload and the order of its rumor.
	tb_cases! {
		fn the_digest_tracks(other: Frame) {
			let (_rumor, digest) = rumor();
			assert_ne!(TestRumor::digest(&other), digest);
		}
		cases {
			payload => TestRumor::application(1_000, [9, 9, 9]),
			order => TestRumor::application(2_000, [1, 2, 3]),
		}
	}

	/// A rumor relayed through a decode and a re-encode keeps its digest.
	#[test]
	fn digest_survives_decode_reencode() -> TestResult {
		let (rumor, digest) = rumor();
		let relayed: Frame = decode(&encode(&rumor)?)?;
		assert_eq!(TestRumor::digest(&relayed), digest);
		Ok(())
	}

	/// The admission of `rumor` at [`T0`], with a hop budget of four, inside
	/// the fixture window.
	fn admitted(rumor: Frame) -> AdmittedGossip {
		let admission = AdmittedGossip::admit::<Sha3_256>(&TestRumor::verified(rumor), 4, WINDOW, T0);
		admission.expect("admission takes a fresh rumor inside its caps")
	}

	/// Admission of a fresh rumor inside its caps names the digest and the
	/// payload of the rumor.
	#[test]
	fn admit_accepts_valid_rumor() {
		let (rumor, digest) = rumor();
		let admitted = admitted(rumor);
		assert_eq!((admitted.digest(), admitted.payload()), (&digest, [1, 2, 3].as_slice()));
	}

	/// A rumor whose own signature verifies but whose body is no
	/// `GossipRumor`.
	fn undecodable_rumor() -> Frame {
		let signer = TestIdentity::certified(TestKey::insecure_fixed_signing());
		let built = FrameBuilder::from(Version::V1)
			.with_id("rumor")
			.with_order(1_000)
			.with_message(TestMessage::sample(None))
			.with_signer::<Secp256k1Signature, _>(signer)
			.build();

		built.expect("the fixed test key signs a frame")
	}

	// Admission refuses a payload past its cap, a hop budget past its cap, a
	// rumor outside the freshness window, and a body that is no
	// `GossipRumor`, each as a denial.
	tb_cases! {
		fn admit_refuses((rumor, ttl, now): (Frame, u64, u64)) {
			let verified = TestRumor::verified(rumor);
			let admission = AdmittedGossip::admit::<Sha3_256>(&verified, ttl, WINDOW, UnixMillis::new(now));
			assert!(matches!(admission, Err(TransitStatus::PermissionDenied)));
		}
		cases {
			oversized_payload => (TestRumor::application(1_000, vec![0u8; MAX_GOSSIP_PAYLOAD_BYTES + 1]), 4, 1_000),
			excessive_ttl => (TestRumor::fixed(), u64::from(MAX_GOSSIP_TTL) + 1, 1_000),
			stale_rumor => (TestRumor::fixed(), 4, 100_000),
			undecodable_body => (undecodable_rumor(), 4, 1_000),
		}
	}

	/// A rumor relayed with its signature's `s` flipped to `n - s` verifies,
	/// and its digest is its original's, so the journal refuses it as a
	/// duplicate (SEC 1 v2.0 §4.1.4).
	#[test]
	fn a_rumor_replayed_with_its_s_flipped_is_a_duplicate() -> TestResult {
		let (journal, rumor, _digest) = holding_the_rumor(MemoryGossipJournal::default());
		let flipped = TestFrame::with_flipped_s(&rumor);

		let replayed = journal.record(b"signer-a", TestRumor::digest(&flipped), &flipped, T0, T0)?;
		assert_eq!(replayed, Admission::Duplicate);
		Ok(())
	}

	// The journal takes a digest once, by record or by witness, and the
	// second take of that digest is a duplicate.
	tb_cases! {
		fn journaling_one_digest_twice_is_a_duplicate(kind: GossipRumorKind) -> TestResult {
			let journal = MemoryGossipJournal::default();
			let (rumor, digest) = rumor();

			let first = kind.journal(&journal, b"signer-a", digest, &rumor, T0)?;
			let second = kind.journal(&journal, b"signer-a", digest, &rumor, T0)?;

			assert_eq!((first, second), (Admission::New, Admission::Duplicate));
			Ok(())
		}
		cases {
			application => GossipRumorKind::Application,
			peer_advertisement => GossipRumorKind::PeerAdvertisement,
		}
	}

	// The journal reports a digest as seen once it takes it, by record or by
	// witness, until the digest leaves the retention window.
	tb_cases! {
		fn seen_follows_the_retention_window(kind: GossipRumorKind) -> TestResult {
			let journal = MemoryGossipJournal::new(WINDOW);
			let (rumor, digest) = rumor();
			let before = journal.seen(&digest, T0)?;

			kind.journal(&journal, b"signer-a", digest, &rumor, T0)?;

			let after = journal.seen(&digest, T0)?;
			let expired = journal.seen(&digest, UnixMillis::new(90_000))?;
			assert_eq!((before, after, expired), (false, true, false));
			Ok(())
		}
		cases {
			application => GossipRumorKind::Application,
			peer_advertisement => GossipRumorKind::PeerAdvertisement,
		}
	}

	/// A witnessed digest reads as seen, and the journal retains no rumor for
	/// it to hold, fetch, or deliver.
	#[test]
	fn witness_is_seen_but_never_retained() -> TestResult {
		let journal = MemoryGossipJournal::default();
		let (_rumor, digest) = rumor();

		journal.witness(b"signer-a", digest, T0, T0)?;

		let seen = journal.seen(&digest, T0)?;
		let held = journal.held_digests(T0)?.len();
		let fetched = journal.fetch(&[digest], T0)?.len();
		let pending = journal.pending_local(T0)?.len();
		assert_eq!((seen, held, fetched, pending), (true, 0, 0, 0));
		Ok(())
	}

	/// A witnessed digest makes a later record of the same digest a duplicate.
	#[test]
	fn witness_blocks_record_of_same_digest() -> TestResult {
		let journal = MemoryGossipJournal::default();
		let (rumor, digest) = rumor();
		journal.witness(b"signer-a", digest, T0, T0)?;

		let replay = journal.record(b"signer-a", digest, &rumor, T0, T0)?;
		assert_eq!(replay, Admission::Duplicate);
		Ok(())
	}

	// A full journal refuses the next entry rather than evict one it holds: a
	// witness or a record past the cap of its signer, and a record past the
	// cap of the journal.
	tb_cases! {
		fn the_journal_fails_closed_at_capacity((kind, journal): (GossipRumorKind, MemoryGossipJournal)) -> TestResult {
			kind.journal(&journal, b"signer-a", digest_carrying(1), &rumor_carrying(1), T0)?;

			let overflow = kind.journal(&journal, b"signer-a", digest_carrying(2), &rumor_carrying(2), T0);
			assert!(matches!(overflow, Err(ClusterError::GossipJournalAtCapacity)));
			Ok(())
		}
		cases {
			witness_per_signer => (GossipRumorKind::PeerAdvertisement, journal_capped(8, 1)),
			record_per_signer => (GossipRumorKind::Application, journal_capped(8, 1)),
			record_global => (GossipRumorKind::Application, journal_capped(1, 8)),
		}
	}

	/// The cap of one signer leaves room for the rumors of another.
	#[test]
	fn per_signer_capacity_admits_another_signer() -> TestResult {
		let journal = journal_capped(8, 1);
		journal.record(b"signer-a", digest_carrying(1), &rumor_carrying(1), T0, T0)?;

		let other = journal.record(b"signer-b", digest_carrying(3), &rumor_carrying(3), T0, T0)?;
		assert_eq!(other, Admission::New);
		Ok(())
	}

	/// A witness and a record of one signer each spend a cap of their own.
	#[test]
	fn witness_and_record_spend_separate_signer_budgets() -> TestResult {
		let journal = journal_capped(8, 1);

		let hint = journal.witness(b"signer-a", digest_carrying(1), T0, T0)?;
		let application = journal.record(b"signer-a", digest_carrying(2), &rumor_carrying(2), T0, T0)?;
		assert_eq!((hint, application), (Admission::New, Admission::New));
		Ok(())
	}

	/// An acknowledged rumor leaves the set of local rumors that wait for
	/// delivery.
	#[test]
	fn pending_local_clears_on_ack() -> TestResult {
		let (journal, _rumor, digest) = holding_the_rumor(MemoryGossipJournal::default());
		let before = journal.pending_local(T0)?.len();

		journal.ack_local(&digest)?;

		let after = journal.pending_local(T0)?.len();
		assert_eq!((before, after), (1, 0));
		Ok(())
	}

	/// The journal holds back a rumor whose delivery is in flight, so the beat
	/// and the admission path deliver it once between them (CWE-362).
	#[test]
	fn a_claimed_rumor_is_not_offered_again() -> TestResult {
		let (journal, _rumor, digest) = holding_the_rumor(MemoryGossipJournal::default());
		let first = journal.claim_local(&digest, T0)?;

		let pending = journal.pending_local(T0)?.len();
		let second = journal.claim_local(&digest, T0)?;
		assert_eq!((first, pending, second), (LocalClaim::Taken, 0, LocalClaim::Held));
		Ok(())
	}

	/// A claim prunes as every read does, so a rumor past retention reads as
	/// untracked rather than as a claim on an entry the next read drops.
	#[test]
	fn a_claim_past_retention_finds_no_rumor() -> TestResult {
		let (journal, _rumor, digest) = holding_the_rumor(MemoryGossipJournal::new(WINDOW));
		let claimed = journal.claim_local(&digest, UnixMillis::new(90_000))?;
		assert_eq!(claimed, LocalClaim::Untracked);
		Ok(())
	}

	/// Claim `digest` for one delivery, which an unclaimed rumor always
	/// admits.
	fn claim<'a>(journal: &'a MemoryGossipJournal, digest: &'a GossipDigest) -> LocalClaimGuard<'a> {
		LocalClaimGuard::take(journal, digest, T0)
			.expect("the journal lock is live")
			.expect("an unclaimed rumor is claimable")
	}

	/// A dropped delivery task, cancelled or left by its caller, returns its
	/// rumor to the retry set rather than strand it as claimed.
	#[test]
	fn a_dropped_delivery_returns_its_rumor_to_the_retry_set() -> TestResult {
		let (journal, _rumor, digest) = holding_the_rumor(MemoryGossipJournal::default());

		{
			let _claim = claim(&journal, &digest);
			assert!(journal.pending_local(T0)?.is_empty());
		}

		assert_eq!(journal.pending_local(T0)?.len(), 1);
		Ok(())
	}

	/// An acked delivery retires the rumor, so no later round retries it.
	#[test]
	fn an_acked_delivery_retires_its_rumor() -> TestResult {
		let (journal, _rumor, digest) = holding_the_rumor(MemoryGossipJournal::default());

		claim(&journal, &digest).ack()?;

		let pending = journal.pending_local(T0)?.len();
		assert_eq!((pending, journal.undelivered_local(T0)?), (0, 0));
		Ok(())
	}

	/// A delivery that failed releases its claim, so the next round retries it.
	#[test]
	fn a_released_rumor_is_offered_again() -> TestResult {
		let (journal, _rumor, digest) = holding_the_rumor(MemoryGossipJournal::default());
		let claimed = journal.claim_local(&digest, T0)?;

		journal.release_local(&digest)?;

		let pending = journal.pending_local(T0)?.len();
		assert_eq!((claimed, pending), (LocalClaim::Taken, 1));
		Ok(())
	}

	/// A fetch returns the rumors of the wanted digests alone.
	#[test]
	fn fetch_returns_only_wanted() -> TestResult {
		let journal = MemoryGossipJournal::default();
		journal.record(b"signer-a", digest_carrying(1), &rumor_carrying(1), T0, T0)?;
		journal.record(b"signer-a", digest_carrying(2), &rumor_carrying(2), T0, T0)?;

		let fetched = journal.fetch(&[digest_carrying(1)], T0)?;
		assert_eq!(fetched, vec![(digest_carrying(1), rumor_carrying(1))]);
		Ok(())
	}

	/// The digests a peer advertised, the digests this gateway holds, and the
	/// digests it asks for back.
	type Wants = (Vec<Vec<u8>>, Vec<GossipDigest>, Vec<GossipDigest>);

	// A want list asks, once, for each advertised digest of the colony width
	// that this gateway does not hold, and drops an entry of any other
	// length rather than echo it to its sender.
	tb_cases! {
		fn a_want_list_asks_for_each_unheld_digest_once((advertised, held, wanted): Wants) {
			let want = WantList::against::<Sha3_256>(&advertised, &held);
			assert_eq!(want.digests(), wanted);
		}
		cases {
			one_held_of_two => (vec![wire(1), wire(2)], vec![digest_carrying(1)], vec![digest_carrying(2)]),
			all_held => (vec![wire(1), wire(2)], vec![digest_carrying(1), digest_carrying(2)], Vec::new()),
			entries_of_another_length => (vec![vec![0u8; 5000], vec![1, 2, 3]], Vec::new(), Vec::new()),
			/// A 64-octet entry names no rumor under SHA3-256.
			an_entry_of_another_digest_width => (vec![vec![9u8; 64], wire(2)], Vec::new(), vec![digest_carrying(2)]),
			repeated_advertisements => (vec![wire(2), wire(2), wire(2)], Vec::new(), vec![digest_carrying(2)]),
		}
	}

	/// `want` as a gateway of the colony digest `D` reads it, back in its
	/// wire form.
	fn read_back<D: OutputSizeUser>(want: &[Vec<u8>]) -> Vec<Vec<u8>> {
		WantList::read::<D>(want).into_wire()
	}

	/// A reader of a want list, at one digest width.
	type WantReader = fn(&[Vec<u8>]) -> Vec<Vec<u8>>;

	// A read want list keeps each entry at the width of the colony digest,
	// once.
	tb_cases! {
		fn a_read_want_list_keeps_each_entry_of_the_digest_width_once(
			(read, want, kept): (WantReader, Vec<Vec<u8>>, Vec<Vec<u8>>)
		) {
			assert_eq!(read(&want), kept);
		}
		cases {
			drops_entries_of_another_length => (
				read_back::<Sha3_256>,
				vec![wire(1), vec![0u8; 8], vec![0u8; 64]],
				vec![wire(1)],
			),
			collapses_duplicates => (read_back::<Sha3_256>, vec![wire(1), wire(1), wire(1)], vec![wire(1)]),
			/// Under a 64-octet digest, a 32-octet entry names no rumor.
			reads_at_the_width_of_the_colony_digest => (
				read_back::<Sha3_512>,
				vec![vec![7u8; 32], vec![9u8; 64]],
				vec![vec![9u8; 64]],
			),
		}
	}

	/// The verdict of each draw of `draws` from `admission`, in order. A draw
	/// names its signer and the clock reading it draws at.
	fn allowances(admission: &TokenBucketAdmission, draws: &[(&str, u64)]) -> Vec<bool> {
		let allow = |&(signer, at): &(&str, u64)| admission.allow(signer.as_bytes(), UnixMillis::new(at));
		let verdicts: Result<Vec<bool>, ClusterError> = draws.iter().map(allow).collect();
		verdicts.expect("the admission lock is live")
	}

	/// A refill interval one millisecond past `u64::MAX` milliseconds, whose
	/// low 64 bits read as one millisecond.
	const WRAPPING_INTERVAL: Duration = Duration::new(18_446_744_073_709_551, 617_000_000);

	/// An admission, the draws taken from it, and the verdict of each draw.
	type Draws = (TokenBucketAdmission, &'static [(&'static str, u64)], &'static [bool]);

	// A bucket spends its burst, then refuses until an interval refills one
	// token, and each signer spends a bucket of its own. A full table refuses
	// an unseen signer until a refilled bucket prunes. An interval past the
	// `u64` range of milliseconds saturates, so a spent bucket stays spent
	// (CWE-197).
	tb_cases! {
		fn token_bucket_admission((admission, draws, allowed): Draws) {
			assert_eq!(allowances(&admission, draws), allowed);
		}
		cases {
			spends_burst_then_refuses => (
				TokenBucketAdmission::new(2, Duration::from_millis(1_000)),
				&[("signer", 1_000), ("signer", 1_000), ("signer", 1_000)],
				&[true, true, false],
			),
			refills_one_token_per_interval => (
				TokenBucketAdmission::new(1, Duration::from_millis(1_000)),
				&[("signer", 1_000), ("signer", 1_500), ("signer", 2_000)],
				&[true, false, true],
			),
			isolates_signers => (
				TokenBucketAdmission::new(1, Duration::from_millis(1_000)),
				&[("first", 1_000), ("first", 1_000), ("second", 1_000)],
				&[true, false, true],
			),
			refuses_an_unseen_signer_at_capacity => (
				TokenBucketAdmission::with_limits(2, Duration::from_millis(1_000), 1),
				&[("first", 1_000), ("second", 1_000)],
				&[true, false],
			),
			prunes_refilled_buckets => (
				TokenBucketAdmission::with_limits(1, Duration::from_millis(1_000), 1),
				&[("first", 1_000), ("second", 3_000)],
				&[true, true],
			),
			saturates_an_interval_past_the_u64_range => (
				TokenBucketAdmission::with_limits(1, WRAPPING_INTERVAL, 1),
				&[("signer", 1_000), ("signer", 2_000)],
				&[true, false],
			),
		}
	}

	// A rumor issued 900 ms ahead of the clock in a 1 s window stays fresh
	// 1.1 s after the journal first takes it, so the journal keeps its digest
	// and a replay of either kind is a duplicate (CWE-294).
	tb_cases! {
		fn a_future_dated_rumor_is_a_duplicate_while_it_is_fresh(kind: GossipRumorKind) -> TestResult {
			let journal = MemoryGossipJournal::new(Duration::from_millis(1_000));
			let rumor = TestRumor::application(1_900, vec![1]);
			let rumor_digest = TestRumor::digest(&rumor);

			kind.journal(&journal, b"signer-a", rumor_digest, &rumor, UnixMillis::new(1_000))?;

			let replayed = kind.journal(&journal, b"signer-a", rumor_digest, &rumor, UnixMillis::new(2_100))?;
			assert_eq!(replayed, Admission::Duplicate);
			Ok(())
		}
		cases {
			application => GossipRumorKind::Application,
			peer_advertisement => GossipRumorKind::PeerAdvertisement,
		}
	}

	/// A record prunes each entry past retention as it writes.
	#[test]
	fn record_prunes_expired_entries() -> TestResult {
		let journal = short_lived_journal();
		let (early, late) = (TestRumor::application(0, [1]), TestRumor::application(200, [2]));
		let (start, later) = (UnixMillis::new(0), UnixMillis::new(200));

		journal.record(b"signer-a", TestRumor::digest(&early), &early, start, start)?;
		journal.record(b"signer-a", TestRumor::digest(&late), &late, later, later)?;

		assert_eq!(journal.held_digests(later)?, vec![TestRumor::digest(&late)]);
		Ok(())
	}

	/// Each read prunes the entries past retention, with no write between.
	#[test]
	fn reads_prune_expired_entries_without_a_write() -> TestResult {
		let journal = short_lived_journal();
		let early = TestRumor::application(0, [1]);
		let (digest, start) = (TestRumor::digest(&early), UnixMillis::new(0));

		journal.record(b"signer-a", digest, &early, start, start)?;

		let held = journal.held_digests(T0)?.len();
		let fetched = journal.fetch(&[digest], T0)?.len();
		let pending = journal.pending_local(T0)?.len();
		assert_eq!((held, fetched, pending), (0, 0, 0));
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
