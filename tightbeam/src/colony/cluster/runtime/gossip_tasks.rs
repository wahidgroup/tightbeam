//! The gossip background tasks of the cluster advertise beat.
//!
//! The beat re-announces the local slate, publishes origin-signed
//! advertisement rumors, and runs anti-entropy reconcile rounds against
//! verified peers and feeler probes.
//!
//! # Planes
//!
//! - Direct advertisement: one signed frame goes to every beat target.
//! - Rumor flood: the same signed frame, wrapped in a gossip rumor, reaches members beyond direct reach.
//! - Pipeline: the gateway admits, rate-limits, journals, delivers locally, and refloods an inbound rumor.
//! - Reconcile: anti-entropy rounds repair the rumors a peer lacks and learn peer-exchange hints.

use core::num::NonZeroUsize;
use core::str::from_utf8;
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

use crate::builder::frame::FrameBuilder;
use crate::builder::TypeBuilder;
use crate::colony::cluster::export::ExportScope;
use crate::colony::cluster::gossip::{LocalClaimGuard, RumorConsumer};
use crate::colony::cluster::peer::AdmittedPeerAd;
use crate::colony::cluster::runtime::advertise::{Advertiser, SignedAdvertisement};
use crate::colony::cluster::runtime::bounds::{ColonyConfig, ColonyDialProtocol, ColonyDigest, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::hop::{FloodClient, HivePlane, PeerPlane};
use crate::colony::cluster::runtime::refuse::Refusal;
use crate::colony::cluster::runtime::verify::RequestAudit;
use crate::colony::cluster::runtime::work::RouteChoice;
use crate::colony::cluster::runtime::{LoopFault, VerifiedSignerId};
use crate::colony::cluster::servlet_registry::SlateChange;
use crate::colony::cluster::{
	Admission, AdmittedGossip, FreshnessWindow, GossipDigest, PeerCaps, PeerHint, RouteKind, VerifiedRumor, WantList,
};
use crate::colony::cluster::{AdmittedDial, ClusterConfig, ClusterError, PeerAddress, ServletRegistry, SharedId};
use crate::colony::protocol::IssuedAt;
use crate::colony::protocol::ReplyForm;
use crate::colony::protocol::{
	ClusterRequest, GossipReconciliation, GossipResponse, GossipRumor, GossipWant, PeerGossip,
};
use crate::constants::{MAX_ADVERTISED_TYPES, MAX_GOSSIP_LOG, MAX_GOSSIP_TTL, MAX_PEX_SAMPLE};
use crate::decode;
use crate::encode;
use crate::instrumentation::events::{
	CLUSTER_GOSSIP_ADMITTED, CLUSTER_GOSSIP_DELIVERED, CLUSTER_GOSSIP_DROP_SIGNAL, CLUSTER_GOSSIP_DUPLICATE,
	CLUSTER_GOSSIP_FANOUT_UNREACHED, CLUSTER_GOSSIP_ORIGIN_REFUSED_BY_PEER, CLUSTER_GOSSIP_REFLOOD_FAILED,
	CLUSTER_GOSSIP_RELAY_WEAKENED, CLUSTER_GOSSIP_REPAIR_PUSHED, CLUSTER_GOSSIP_WITNESS_REFUSED,
	CLUSTER_PEER_DISCOVERED, CLUSTER_PEER_EVICTED, CLUSTER_PEER_EXPELLED,
};
use crate::instrumentation::events::{
	CLUSTER_PEER_AD_DROPPED, CLUSTER_PEER_AD_LEARNED, CLUSTER_PEER_AD_PUBLISH_FAILED, CLUSTER_PEER_HINTS_LEARNED,
	CLUSTER_PEER_ROUTES_INSTALLED, CLUSTER_PEER_ROUTES_WITHDRAWN, CLUSTER_PEER_ROUTE_ABANDONED,
	CLUSTER_RECONCILE_FAILED, CLUSTER_RELAY_TRAIL_INSTALLED, CLUSTER_RELAY_TRAIL_REFUSED,
};
use crate::policy::TransitStatus;
use crate::runtime::{rt, TaskGroup};
use crate::trace::TraceCollector;
use crate::transport::Protocol;
use crate::urn::Urn;
use crate::utils::time::UnixMillis;
use crate::Frame;
use crate::TightBeamError;
use crate::{MessagePriority, Version};

/// The origin of one gossip pipeline run.
#[derive(Clone, Copy)]
pub(crate) enum GossipOrigin {
	/// A peer-relayed rumor. Invalid input may score the relay.
	Relay,
	/// A local publish. An admission failure refuses it and scores no trail.
	Origin,
}

impl GossipOrigin {
	/// The frame whose signer owns the rumor's rate and journal budget. A relay
	/// hop signs the outer frame, so a relayed rumor charges its origin.
	fn attributed<'a>(self, frame: &'a Frame, rumor: &'a Frame) -> &'a Frame {
		match self {
			Self::Origin => frame,
			Self::Relay => rumor,
		}
	}

	/// The relay hop of a rumor whose outer frame `sender` signed: `sender` for
	/// a relayed rumor, and `None` for a local publish from a hive.
	fn relay(self, sender: &VerifiedSignerId) -> Option<&VerifiedSignerId> {
		match self {
			Self::Relay => Some(sender),
			Self::Origin => None,
		}
	}
}

impl<P: Protocol> GatewayRuntimeCtx<P> {
	/// The plane this gateway dials peers on: the configured peer plane, which
	/// keeps peer traffic off the hive pool, or else the hive pool.
	pub(crate) fn peer_dial_plane(&self) -> PeerPlane<P> {
		match self.peer_plane.as_ref() {
			Some(peer_plane) => peer_plane.clone(),
			None => self.hive_plane.peers(self.config.clone()),
		}
	}
}

/// One signed advertisement rumor ready to witness and flood, with the digest
/// and the signer id that the witness and the reflood read.
struct MintedAdRumor {
	rumor: Frame,
	digest: GossipDigest,
	signer_id: Vec<u8>,
	minted_at: UnixMillis,
}

impl ServletRegistry {
	/// The dial socket of a relay peer. Only its live direct routes count,
	/// because a relay entry dials a further relay. [`None`] means the relay
	/// came through another hop, or the registry lock is poisoned, and the
	/// rumor's direct trail stands alone.
	fn relay_dial_addr(&self, relay_id: impl AsRef<[u8]>) -> Option<PeerAddress> {
		let relay_id = relay_id.as_ref();
		let entries = self.peer_entries().ok()?;
		entries
			.iter()
			.filter(|entry| entry.route_kind() == RouteKind::Peer)
			.find(|entry| entry.owner_id().as_ref() == relay_id)
			.and_then(|entry| entry.dial_target().as_socket().copied())
	}
}

impl<P: ColonyDialProtocol> ColonyConfig<P> {
	/// Creates, signs, and digests one advertisement rumor for a beat. It wraps
	/// `advertisement`, the [`ColonyConfig::mint_ad_frame`] frame the beat
	/// dials directly, so both copies carry one order.
	///
	/// [`None`] marks a local fault (key, codec, or journal input), which the
	/// caller records. A later beat publishes a fresh rumor.
	async fn mint_slate_rumor(&self, advertisement: &SignedAdvertisement) -> Option<MintedAdRumor> {
		let ad_bytes = encode(advertisement.frame()).ok()?;

		let minted_at = self.clock.unix();
		let body = GossipRumor::peer_advertisement(ad_bytes);
		let builder = FrameBuilder::from(Version::V2)
			.with_id(b"peer-ad-rumor")
			.with_order(minted_at.get())
			.with_message(body)
			.with_priority(MessagePriority::NetworkControl);

		let mut rumor = self.witnessed(builder).build().ok()?;
		rumor.sign_with_provider(self.tls.identity()).await.ok()?;

		let verified = self.tls.verify_own(rumor).ok()?;
		let digest = verified.gossip_digest::<ColonyDigest<P>>().ok()?;
		let rumor = verified.into_frame();
		let signer_id = rumor.signer_id()?;
		Some(MintedAdRumor { rumor, digest, signer_id, minted_at })
	}
}

impl<P: Protocol> ColonyConfig<P> {
	/// Admits one verified rumor under the colony digest, `hop_ttl` hops from
	/// its origin, against this gateway's seen window at `now`.
	///
	/// # Errors
	///
	/// - [`TransitStatus::PermissionDenied`] -- every refusal of [`AdmittedGossip::admit`].
	pub(crate) fn admit_rumor(
		&self,
		rumor: &VerifiedRumor,
		hop_ttl: u64,
		now: UnixMillis,
	) -> Result<AdmittedGossip, TransitStatus> {
		AdmittedGossip::admit::<ColonyDigest<P>>(rumor, hop_ttl, self.gossip.seen_window(), now)
	}

	/// The entries of a peer's `want` list that read as rumor digests under
	/// the colony digest, by the rule of [`WantList::read`].
	pub(crate) fn read_want(&self, want: impl AsRef<[Vec<u8>]>) -> WantList {
		WantList::read::<ColonyDigest<P>>(want)
	}
}

impl ClusterConfig {
	/// Whether `order` sits inside this colony's control freshness window. A
	/// control frame passes a replay guard, and a rumor the journal's digest
	/// deduplication. This bound makes both paths admit the same orders.
	///
	/// # Fail-closed
	///
	/// - An order outside the window is refused, so the ad-order tombstone
	///   covers every replay that reaches reconcile (CWE-294).
	/// - A far-future order is refused, so every ledger row stays prunable (CWE-770).
	fn ad_order_fresh(&self, order: UnixMillis, now: UnixMillis) -> bool {
		let window = FreshnessWindow::new(self.control_freshness_window);
		window.admits(order, now)
	}

	/// The peer-exchange hints this gateway may learn. Each entry passes
	/// [`PeerConfig::admit_hint`], so a feeler probe dials only addresses the
	/// operator's dial policy admits (CWE-284).
	///
	/// [`PeerConfig::admit_hint`]: crate::colony::cluster::PeerConfig::admit_hint
	fn admissible_pex_hints(&self, pex: impl IntoIterator<Item = PeerGossip>) -> impl Iterator<Item = PeerHint> + '_ {
		let pex: Vec<PeerGossip> = pex.into_iter().collect();

		pex.into_iter().filter_map(move |entry| self.peer.admit_hint(entry).ok())
	}

	/// Offers `hints` from `source` to the peer table, and records the count
	/// it admits as [`CLUSTER_PEER_HINTS_LEARNED`] on `trace`, because the
	/// table holds none. A learn that admits no hint records nothing.
	///
	/// # Errors
	///
	/// - [`LoopFault::Registry`] -- the table lock is poisoned.
	/// - [`LoopFault::Runtime`] -- the trace refused the event.
	pub(crate) fn learn_hints(
		&self,
		trace: &TraceCollector,
		source: HintSource<'_>,
		hints: impl IntoIterator<Item = PeerHint>,
		now: UnixMillis,
	) -> Result<(), LoopFault> {
		let admitted = self.peer.table.learn(hints, now)?;
		if let Some(admitted) = NonZeroUsize::new(admitted) {
			let label = source.label();
			source.with_payload(|payload| {
				trace.emit_event_with_value_and_evidence(CLUSTER_PEER_HINTS_LEARNED, label, admitted, Some(payload))
			})?;
		}

		Ok(())
	}
}

/// Where a batch of discovery hints came from. It names the label and the
/// payload of its [`CLUSTER_PEER_HINTS_LEARNED`].
#[derive(Clone, Copy)]
pub(crate) enum HintSource<'a> {
	/// The signer of a direct peer advertisement, by its fingerprint.
	Advertiser(&'a [u8]),
	/// The origin of an advertisement rumor, by its fingerprint.
	Origin(&'a [u8]),
	/// The peer-exchange sample of a reconcile reply, by the dial address of
	/// the peer that answered.
	Pex(PeerAddress),
}

impl HintSource<'_> {
	/// The label of the event: the kind of the source.
	fn label(self) -> &'static str {
		match self {
			Self::Advertiser(_) => "advertiser",
			Self::Origin(_) => "origin",
			Self::Pex(_) => "pex",
		}
	}

	/// Runs `record` on the event payload, the fingerprint or the address that
	/// names the source. An address renders only here, so an empty learn
	/// renders nothing.
	fn with_payload<R>(self, record: impl FnOnce(&[u8]) -> R) -> R {
		match self {
			Self::Advertiser(source) | Self::Origin(source) => record(source),
			Self::Pex(address) => record(address.route_bytes().as_ref()),
		}
	}
}

impl SlateChange {
	/// Records the direct routes this swap installed and withdrew for
	/// `advertiser`, as [`CLUSTER_PEER_ROUTES_INSTALLED`] and
	/// [`CLUSTER_PEER_ROUTES_WITHDRAWN`] on `trace`. A count of 0 records no
	/// event, so a refresh of the held slate records nothing.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refused an event.
	pub(crate) fn record_direct(
		&self,
		trace: &TraceCollector,
		advertiser: impl AsRef<[u8]>,
	) -> Result<(), TightBeamError> {
		let advertiser = Some(advertiser.as_ref());
		if let Some(installed) = self.installed() {
			trace.emit_event_with_value_and_evidence(CLUSTER_PEER_ROUTES_INSTALLED, "direct", installed, advertiser)?;
		}
		if let Some(withdrawn) = self.withdrawn() {
			trace.emit_event_with_value_and_evidence(CLUSTER_PEER_ROUTES_WITHDRAWN, "slate", withdrawn, advertiser)?;
		}

		Ok(())
	}
}

impl GossipWant {
	/// Whether this reconcile reply holds more than [`MAX_GOSSIP_LOG`] wants or
	/// [`MAX_PEX_SAMPLE`] peer-exchange entries. A gateway that follows the
	/// protocol never does, so the requester drops the whole round (CWE-770).
	fn is_oversized(&self) -> bool {
		self.want.len() > MAX_GOSSIP_LOG || self.pex.len() > MAX_PEX_SAMPLE
	}
}

/// How one reconcile round ended, as the peer's score reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Round {
	/// The peer answered in bounds or from outside the flood, or a local fault
	/// skipped the round, so the peer's score stands.
	Settled,
	/// The dial failed, or the peer answered out of bounds, so the caller
	/// scores the peer.
	Failed,
}

/// The step at which a reconcile round ended early. It names the label of the
/// round's [`CLUSTER_RECONCILE_FAILED`] and decides whether the round charges
/// the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoundEnd {
	/// The journal failed to list its held digests.
	Journal,
	/// The dial or the handshake failed.
	Unreachable,
	/// The request frame failed to build.
	Build,
	/// The signature of the request failed.
	Sign,
	/// The exchange failed, or the reply failed to decode or exceeded its
	/// bounds.
	Reply,
	/// A local step after the reply failed, such as the promotion or a repair.
	Bookkeeping,
}

impl RoundEnd {
	/// The label of the round's event.
	fn label(self) -> &'static str {
		match self {
			Self::Journal => "journal",
			Self::Unreachable => "unreachable",
			Self::Build => "build",
			Self::Sign => "sign",
			Self::Reply => "reply",
			Self::Bookkeeping => "bookkeeping",
		}
	}

	/// How the round reads to the peer's score: a step the peer failed charges
	/// the peer, and a step that failed on this gateway leaves the score alone.
	fn round(self) -> Round {
		match self {
			Self::Unreachable | Self::Reply => Round::Failed,
			Self::Journal | Self::Build | Self::Sign | Self::Bookkeeping => Round::Settled,
		}
	}
}

/// How one hop of a reflood ended.
enum FloodHop {
	/// The target answered, and this gateway's offer to it stands.
	Settled,
	/// A gateway outside the flood answered at the target, and this gateway
	/// owes it no rumor.
	OutsideFlood(AdmittedDial),
	/// The target answered that the rumor's origin is outside its trust.
	OriginRefused(AdmittedDial),
	/// The dial or the emit failed.
	Unreached,
}

/// The ledger of every gossip target, behind one lock that the beat's repair
/// and each inbound reflood share. [`Self::with`] releases the lock before it
/// returns, so no guard crosses an await.
///
/// # Poison recovery
///
/// Each write is one insert or one removal, so a panic leaves no ledger
/// half-written, and every method recovers a poisoned guard and runs on.
#[derive(Default)]
pub(crate) struct PeerLedgers {
	by_target: Mutex<HashMap<AdmittedDial, PeerLedger>>,
}

impl PeerLedgers {
	/// Runs `read` on the ledger of `target`, which starts empty.
	fn with<T>(&self, target: AdmittedDial, read: impl FnOnce(&mut PeerLedger) -> T) -> T {
		let mut by_target = self.by_target.lock().unwrap_or_else(PoisonError::into_inner);
		read(by_target.entry(target).or_default())
	}

	/// Keeps the ledgers of the targets `live` names, and forgets every refusal
	/// older than `window`. The table's caps bound the live set, so they bound
	/// this map (CWE-770).
	fn prune(&self, live: impl Fn(&AdmittedDial) -> bool, now: UnixMillis, window: Duration) {
		let mut by_target = self.by_target.lock().unwrap_or_else(PoisonError::into_inner);
		by_target.retain(|target, _| live(target));

		for ledger in by_target.values_mut() {
			ledger.expire(now, window);
		}
	}
}

/// What this gateway knows about one target's reception of its gossip.
#[derive(Default)]
struct PeerLedger {
	/// The digests the target acknowledged with an explicit `Ok`.
	acked: HashSet<GossipDigest>,
	/// The origins the target answered as outside its trust, each with the
	/// time of that answer.
	refused_origins: HashMap<Vec<u8>, UnixMillis>,
}

impl PeerLedger {
	/// Records that the target acknowledged `digest`.
	fn ack(&mut self, digest: GossipDigest) {
		self.acked.insert(digest);
	}

	/// Decides whether the target drops rumors, and forgets the acknowledgement
	/// of every digest in `wanted`. An acknowledged digest wanted again while
	/// retained is a drop.
	fn drop_signal(&mut self, wanted: impl AsRef<[GossipDigest]>) -> bool {
		let wanted = wanted.as_ref();
		let dropped = wanted.iter().any(|digest| self.acked.contains(digest));
		for digest in wanted {
			self.acked.remove(digest);
		}

		dropped
	}

	/// Records that the target answered `origin` as outside its trust.
	fn refuse_origin(&mut self, origin: impl Into<Vec<u8>>, now: UnixMillis) {
		self.refused_origins.insert(origin.into(), now);
	}

	/// Decides whether this gateway offers a rumor of `origin` to the target. A
	/// refusal stands for `window`, then the origin is offered once more, so a
	/// target that enrolled it since catches up.
	fn offers(&self, origin: impl AsRef<[u8]>, now: UnixMillis, window: Duration) -> bool {
		match self.refused_origins.get(origin.as_ref()) {
			Some(refused_at) => now.saturating_since(*refused_at) >= window,
			None => true,
		}
	}

	/// Forgets every refusal older than `window`.
	fn expire(&mut self, now: UnixMillis, window: Duration) {
		let stands = |refused_at: UnixMillis| now.saturating_since(refused_at) < window;
		self.refused_origins.retain(|_, refused_at| stands(*refused_at));
	}
}

/// The direct-advertisement arm of the advertise beat, which every gateway
/// with a dial list runs, in a flood or in none.
struct AdvertiseBeat<P: Protocol> {
	config: ColonyConfig<P>,
	advertiser: Advertiser<P>,
	servlet_registry: Arc<ServletRegistry>,
}

/// The gossip arm of the advertise beat and of the inbound pipeline:
/// reconcile rounds, feeler probes, the slate rumor, refloods, and repairs.
///
/// Both reach peers through it, so a rumor leaves on one plane either way.
/// [`Self::new`] builds one only for a gateway in a flood, so every method
/// runs on a flood member.
struct FloodBeat<P: Protocol> {
	config: ColonyConfig<P>,
	peer_plane: PeerPlane<P>,
	servlet_registry: Arc<ServletRegistry>,
	trace: Arc<TraceCollector>,
	ledgers: Arc<PeerLedgers>,
}

impl<P: Protocol> FloodBeat<P> {
	/// The gossip arm of a gateway in a flood, or `None` for a gateway in none.
	fn new(
		config: ColonyConfig<P>,
		peer_plane: PeerPlane<P>,
		servlet_registry: Arc<ServletRegistry>,
		trace: Arc<TraceCollector>,
		ledgers: Arc<PeerLedgers>,
	) -> Option<Self> {
		config.flood()?;

		Some(Self { config, peer_plane, servlet_registry, trace, ledgers })
	}

	/// Records that `target` answered `origin` as outside its trust, so this
	/// gateway offers it no further rumor of that origin for one window.
	fn settle_refused_origin(
		&self,
		target: AdmittedDial,
		origin: impl AsRef<[u8]>,
		now: UnixMillis,
	) -> Result<(), TightBeamError> {
		let origin = origin.as_ref();
		self.ledgers.with(target, |ledger| ledger.refuse_origin(origin, now));

		let evidence = || Some(target.address().route_bytes());
		self.trace
			.emit_marker_with_evidence(CLUSTER_GOSSIP_ORIGIN_REFUSED_BY_PEER, evidence)?;

		Ok(())
	}

	/// Whether this gateway offers a rumor of `origin` to `target`. A rumor
	/// with no signer has no origin a target could refuse, so it is offered.
	fn offers(&self, target: AdmittedDial, origin: Option<&[u8]>, now: UnixMillis) -> bool {
		let Some(origin) = origin else {
			return true;
		};

		let window = self.config.gossip.seen_ttl;
		self.ledgers.with(target, |ledger| ledger.offers(origin, now, window))
	}

	/// Keeps the ledgers of this beat's targets and probes, and expires the
	/// refusals that have stood for a whole seen window.
	fn prune_ledgers(&self, targets: impl AsRef<[AdmittedDial]>, probes: impl AsRef<[AdmittedDial]>) {
		let targets = targets.as_ref();
		let probes = probes.as_ref();
		let live = |peer: &AdmittedDial| targets.contains(peer) || probes.contains(peer);

		self.ledgers.prune(live, self.config.clock.unix(), self.config.gossip.seen_ttl);
	}
}

// Manual, because a derive would demand `P: Clone`, and the fields are
// reference-counted whatever `P` is.
impl<P: Protocol> Clone for FloodBeat<P> {
	fn clone(&self) -> Self {
		Self {
			config: self.config.clone(),
			peer_plane: self.peer_plane.clone(),
			servlet_registry: Arc::clone(&self.servlet_registry),
			trace: Arc::clone(&self.trace),
			ledgers: Arc::clone(&self.ledgers),
		}
	}
}

impl<P: ColonyDialProtocol> AdvertiseBeat<P> {
	/// The advertised types this gateway exports, capped at
	/// [`MAX_ADVERTISED_TYPES`]. The direct ads and the rumor flood both read
	/// it, so one export filter covers both. The filter asks the export scope
	/// per key each beat, so a live `ExportAllowlist` matches enforcement.
	fn exported_slate(&self) -> Result<Vec<Urn<'static>>, ClusterError> {
		let scope = ExportScope::from(&self.config.peer);
		let local = self.servlet_registry.local_servlets()?;
		let slate = local
			.iter()
			.filter(|bytes| scope.exports_canonical(bytes))
			.filter_map(|bytes| from_utf8(bytes).ok())
			.filter_map(|canonical| canonical.parse().ok())
			.take(MAX_ADVERTISED_TYPES)
			.collect();

		Ok(slate)
	}

	/// Advertises to each beat target, and hands each one to the flood arm when
	/// this gateway has one. The one signed `advertisement` serves every dial.
	async fn dial_targets(
		&self,
		flood: Option<&FloodBeat<P>>,
		targets: impl AsRef<[AdmittedDial]>,
		advertisement: Option<&SignedAdvertisement>,
		trace: &TraceCollector,
	) -> Result<(), LoopFault> {
		let targets = targets.as_ref();
		for peer in targets {
			// A protocol that cannot address this peer is this gateway's
			// choice, so the beat skips the peer and leaves it unscored.
			let Ok(peer_addr) = peer.protocol_address::<P::Address>() else {
				continue;
			};

			if let Some(advertisement) = advertisement {
				// The reconcile below reuses the address and scores a failed
				// dial, so the address clones and the status goes unread.
				let _advertised = self.advertiser.advertise(peer_addr.clone(), advertisement).await;
			}

			let Some(flood) = flood else {
				continue;
			};

			flood.reconcile_target(peer_addr, *peer, trace).await?;
		}

		Ok(())
	}
}

impl<P: ColonyDialProtocol> FloodBeat<P> {
	/// Refloods a live rumor, with a decremented TTL, to the anchors and the
	/// verified tried peers. Each dial proves in [`PeerPlane::connect_member`]
	/// that the answer is a flood member before the rumor leaves, so a
	/// configured peer outside the flood gets none (CWE-668).
	///
	/// # Re-encoding
	///
	/// The reflood re-encodes the rumor it embeds. DER is canonical
	/// (ITU-T X.690 §10), so the bytes equal the received ones, and the origin
	/// signature and the witness digest survive the hop. A splice of the
	/// received bytes would need an opaque passthrough field in the codec and
	/// buy no correctness.
	async fn reflood(&self, rumor: Frame, ttl: u64) -> Result<(), LoopFault> {
		let targets = self.config.peer.table.target_set()?;
		if targets.is_empty() {
			return Ok(());
		}

		// A target that answered this origin as outside its trust gets none
		// of its rumors until that answer expires.
		let origin = rumor.signer_id();
		let now = self.config.clock.unix();

		let request = ClusterRequest::Gossip(Box::new(rumor));
		let builder = FrameBuilder::from(Version::V2)
			.with_id(b"gossip-reflood")
			.with_message(request)
			.with_priority(MessagePriority::NetworkControl)
			.with_lifetime(ttl);
		let mut signed_frame = match self.config.witnessed(builder).build() {
			Ok(signed_frame) => signed_frame,
			Err(_unbuilt) => {
				self.trace.emit_marker(CLUSTER_GOSSIP_REFLOOD_FAILED)?;

				return Ok(());
			}
		};

		let signing = signed_frame.sign_with_provider(self.config.tls.identity()).await;
		if signing.is_err() {
			self.trace.emit_marker(CLUSTER_GOSSIP_REFLOOD_FAILED)?;
			return Ok(());
		}

		let mut fanout = tokio::task::JoinSet::new();
		let mut unreached: u64 = 0;
		for peer in targets.iter() {
			if !self.offers(*peer, origin.as_deref(), now) {
				continue;
			}
			let Ok(peer_addr) = peer.protocol_address::<P::Address>() else {
				unreached = unreached.saturating_add(1);
				continue;
			};

			let target = *peer;
			let dial_plane = self.peer_plane.clone();
			// Each emit owns its frame, so the fan-out clones one per target.
			let frame = signed_frame.clone();

			fanout.spawn(async move {
				let Ok(answered) = dial_plane.connect_member(peer_addr).await else {
					return FloodHop::Unreached;
				};
				// A gateway outside the flood is owed no rumor.
				let Some(mut client) = answered else {
					return FloodHop::OutsideFlood(target);
				};
				let Ok(reply) = client.emit(frame, None).await else {
					return FloodHop::Unreached;
				};

				// Only a reply that names the origin as outside the target's
				// trust changes what this gateway offers it next.
				let response = reply.and_then(|reply| decode::<GossipResponse>(reply.message()).ok());
				match response {
					Some(response) if response.refuses_origin() => FloodHop::OriginRefused(target),
					_ => FloodHop::Settled,
				}
			});
		}

		// A down peer must not stop the flood, so a failed hop, or a task that
		// fails to join, adds to the unreached count and the reflood moves on.
		while let Some(joined) = fanout.join_next().await {
			match joined {
				Ok(FloodHop::Settled) => {}
				// The answer is definitive on either path, so the reflood drops
				// the address the way the beat's reconcile round does.
				Ok(FloodHop::OutsideFlood(target)) => self.expel(target)?,
				Ok(FloodHop::OriginRefused(target)) => {
					if let Some(origin) = origin.as_deref() {
						self.settle_refused_origin(target, origin, now)?;
					}
				}
				Ok(FloodHop::Unreached) | Err(_) => unreached = unreached.saturating_add(1),
			}
		}

		if unreached > 0 {
			self.trace
				.emit_event_with_value_and_evidence(CLUSTER_GOSSIP_FANOUT_UNREACHED, "", unreached, None)?;
		}

		Ok(())
	}

	/// Publishes the local slate as an origin-signed advertisement rumor. A
	/// member beyond direct reach admits it on the signer-binds-to-address path
	/// of a direct ad.
	///
	/// # Journal
	///
	/// - The beat witnesses the digest only to deduplicate, so the origin's echo arrives as a duplicate.
	/// - Advertisements skip retention, which serves repair and retry. They are
	///   short-lived hints that each publish refreshes, and the origin holds
	///   its slate.
	/// - A refused witness lets this gateway admit its own echo again. The beat
	///   traces [`CLUSTER_GOSSIP_WITNESS_REFUSED`] and floods the rumor anyway.
	///
	/// # Failures
	///
	/// With no advertisement, or on a creation fault, the beat traces
	/// [`CLUSTER_PEER_AD_PUBLISH_FAILED`] and returns `false`. The caller keeps
	/// its publish baseline, so the next beat retries.
	async fn publish_slate_rumor(&self, advertisement: Option<&SignedAdvertisement>) -> Result<bool, LoopFault> {
		let minted = match advertisement {
			Some(advertisement) => self.config.mint_slate_rumor(advertisement).await,
			None => None,
		};
		let Some(minted) = minted else {
			self.trace.emit_marker(CLUSTER_PEER_AD_PUBLISH_FAILED)?;
			return Ok(false);
		};

		// The creation instant is the rumor's stated time and the prune clock.
		let journal = &self.config.gossip.journal;
		let witnessed = journal.witness(&minted.signer_id, minted.digest, minted.minted_at, minted.minted_at);
		if witnessed.is_err() {
			self.trace.emit_marker(CLUSTER_GOSSIP_WITNESS_REFUSED)?;
		}

		// The stamped lifetime is the budget left after this first hop, as the
		// pipeline stamps when it refloods a published rumor.
		let hop_ttl = u64::from(self.config.gossip.ttl.min(MAX_GOSSIP_TTL));
		self.reflood(minted.rumor, hop_ttl.saturating_sub(1)).await?;

		Ok(true)
	}

	/// Runs one anti-entropy reconcile round with a peer, and scores the
	/// grey-hole drops it finds. The beat loops score a [`Round::Failed`]
	/// toward the peer's eviction or probe discard.
	///
	/// # Round order
	///
	/// 1. Collect the held digests from the journal.
	/// 2. Complete the handshake and prove flood membership.
	/// 3. Emit a signed reconcile request and decode the reply.
	/// 4. Reject an oversized want-list or PEX sample.
	/// 5. Promote the peer, learn PEX hints, and score grey-hole drops.
	/// 6. Repair the rumors the peer lacks from the journal.
	///
	/// # Fault attribution
	///
	/// - A local fault before the emit or inside the post-reply scope leaves the peer unscored.
	/// - An oversized reply or a dial failure returns [`Round::Failed`].
	/// - Each early end records [`CLUSTER_RECONCILE_FAILED`] with the label its [`RoundEnd`] names.
	/// - A learned peer outside the flood leaves the peer table at once and keeps its routes.
	/// - A poisoned table at that expulsion ends the beat as [`LoopFault::Registry`], and the score stands.
	/// - A trace fault anywhere in the round, bookkeeping included, ends the beat as [`LoopFault::Runtime`].
	///
	/// # Errors
	///
	/// - [`LoopFault`] -- the errors of [`Self::expel`], and a trace that refused an event of the round.
	async fn reconcile_round(&self, peer_addr: P::Address, peer: AdmittedDial) -> Result<Round, LoopFault> {
		let now = self.config.clock.unix();
		// A journal fault is local, so the peer stays unscored.
		let Ok(held_digests) = self.config.gossip.journal.held_digests(now) else {
			return self.end_round(peer, RoundEnd::Journal);
		};
		// The message owns its OCTET STRING bytes, so each digest copies once.
		let held: Vec<Vec<u8>> = held_digests.iter().map(|digest| digest.as_bytes().to_vec()).collect();

		// The round proves membership on the completed handshake, before the
		// reconcile discloses anything (CWE-668).
		let Ok(answered) = self.peer_plane.connect_member(peer_addr).await else {
			return self.end_round(peer, RoundEnd::Unreachable);
		};
		let Some(mut client) = answered else {
			// An answer from outside the flood is definitive, so a learned
			// address leaves both learned tables at once.
			self.expel(peer)?;

			return Ok(Round::Settled);
		};

		let request = ClusterRequest::ReconcileGossip(GossipReconciliation { held });

		// The build and the signature are local and come before the peer is
		// asked anything, so a fault here leaves the peer unscored.
		let builder = FrameBuilder::from(Version::V2)
			.with_id(b"gossip-reconcile")
			.with_order(now.get())
			.with_message(request)
			.with_priority(MessagePriority::NetworkControl);
		let Ok(mut signed_frame) = self.config.witnessed(builder).build() else {
			return self.end_round(peer, RoundEnd::Build);
		};

		let signing = signed_frame.sign_with_provider(self.config.tls.identity()).await;
		if signing.is_err() {
			return self.end_round(peer, RoundEnd::Sign);
		}

		// Each fault of the exchange is the peer's, so it fails the round.
		let asked: Result<GossipWant, ClusterError> = async {
			let response = client.emit(signed_frame, None).await?.ok_or(ClusterError::NoResponse)?;
			let reply: GossipWant = decode(response.message())?;

			// An oversized reply fails the round (CWE-770). The beat scores it
			// like any failed round, so an abuser keeps its `new` entry with
			// one more failure, or counts toward eviction from `tried`.
			if reply.is_oversized() {
				return Err(ClusterError::OversizedReconcileReply);
			}

			Ok(reply)
		}
		.await;
		let Ok(reply) = asked else {
			return self.end_round(peer, RoundEnd::Reply);
		};

		// An in-bounds reply proves liveness, so a bookkeeping fault records a
		// skip and leaves the score. The next beat retries the skipped steps.
		match self.settle_round(&mut client, reply, peer, now).await {
			Ok(()) => Ok(Round::Settled),
			Err(LoopFault::Registry(_)) => self.end_round(peer, RoundEnd::Bookkeeping),
			Err(fault @ LoopFault::Runtime(_)) => Err(fault),
		}
	}

	/// Records that the round with `peer` ended early at `end`, as
	/// [`CLUSTER_RECONCILE_FAILED`] with the peer's dial address, and returns
	/// how the round reads to the peer's score.
	///
	/// # Errors
	///
	/// - [`LoopFault::Runtime`] -- the trace refused the event.
	fn end_round(&self, peer: AdmittedDial, end: RoundEnd) -> Result<Round, LoopFault> {
		let round = end.round();
		let charged = round == Round::Failed;
		let evidence = || Some(peer.address().route_bytes());
		self.trace.emit_event_with_value_and_rendered_evidence(
			CLUSTER_RECONCILE_FAILED,
			end.label(),
			charged,
			evidence,
		)?;

		Ok(round)
	}

	/// Takes `peer`, which answered from outside the flood, out of the peer
	/// table, and records [`CLUSTER_PEER_EXPELLED`] with its address.
	///
	/// - Its routes stay: it may serve work by direct peering, and each forward binds to its route's gateway.
	/// - A configured anchor keeps its slot, so each beat advertises to it.
	///
	/// A poisoned table is a local fault, so it ends the caller's loop and
	/// every score stands.
	///
	/// # Errors
	///
	/// - [`LoopFault::Registry`] -- the table lock is poisoned.
	/// - [`LoopFault::Runtime`] -- the trace refused the event.
	fn expel(&self, peer: AdmittedDial) -> Result<(), LoopFault> {
		self.config.peer.table.expel(peer)?;

		let evidence = || Some(peer.address().route_bytes());
		self.trace.emit_marker_with_evidence(CLUSTER_PEER_EXPELLED, evidence)?;

		Ok(())
	}

	/// Applies one answered round's bookkeeping: promotion, PEX hints,
	/// grey-hole scores, and journal repair.
	///
	/// A local fault in any step, a repair emit included, skips the rest, and
	/// the peer stays scored on its answer. A trace fault ends the beat.
	///
	/// # Errors
	///
	/// - [`LoopFault::Registry`] -- a poisoned table, registry, or journal, or a
	///   repair that failed to build, sign, or reach the peer.
	/// - [`LoopFault::Runtime`] -- the trace refused an event.
	async fn settle_round(
		&self,
		client: &mut FloodClient<P>,
		reply: GossipWant,
		peer: AdmittedDial,
		now: UnixMillis,
	) -> Result<(), LoopFault> {
		// A pooled connection keeps a dead peer's handshake certificate, so
		// promotion waits for the reply. Promotion on the membership proof
		// alone would reset the failure count each beat and hold the peer.
		let answer = client.peer_certificate();
		let peer_id = answer.and_then(|answer| self.config.peer_identity(answer));
		if self.config.peer.table.promote(peer, peer_id.as_deref(), now)? {
			let evidence = || Some(peer.address().route_bytes());
			self.trace.emit_marker_with_evidence(CLUSTER_PEER_DISCOVERED, evidence)?;
		}

		let GossipWant { want, pex } = reply;

		// PEX entries are unverified hints: the allowlist gates them, the
		// capped `new` table holds them, and a later feeler probe that
		// proves membership is the only path to a dial target (CWE-345).
		let hints = self.config.admissible_pex_hints(pex);
		self.config
			.learn_hints(&self.trace, HintSource::Pex(peer.address()), hints, now)?;

		let wanted = self.config.read_want(&want);

		// Grey-hole containment: one weaken per round scores a target whose
		// ledger shows drops of rumors it acknowledged.
		let dropping = self.ledgers.with(peer, |ledger| ledger.drop_signal(wanted.digests()));
		if dropping {
			let weakened = self.servlet_registry.weaken_peer_by_dial(peer.address())?;
			self.trace.emit_marker(CLUSTER_GOSSIP_DROP_SIGNAL)?;

			if let Some(abandoned) = weakened.abandoned() {
				let cause = "drop-signal";
				let address = peer.address().route_bytes();
				let payload = Some(address.as_ref());
				let trace = &self.trace;
				trace.emit_event_with_value_and_evidence(CLUSTER_PEER_ROUTE_ABANDONED, cause, abandoned, payload)?;
			}
		}

		self.push_repairs(client, wanted.digests(), peer).await
	}

	/// Reconciles with one beat target, and counts a failed round toward its
	/// eviction. At the threshold a dead tried peer frees its bucket slot, and
	/// the routes that dial it leave the registry.
	///
	/// # Lock order
	///
	/// `record_failure` releases the table guard before `withdraw_peer_by_dial`
	/// takes the route lock, so the two locks never nest.
	async fn reconcile_target(
		&self,
		peer_addr: P::Address,
		peer: AdmittedDial,
		trace: &TraceCollector,
	) -> Result<(), LoopFault> {
		let round = self.reconcile_round(peer_addr, peer).await?;
		if round == Round::Settled {
			return Ok(());
		}

		let evicted = self.config.peer.table.record_failure(peer)?;
		if !evicted {
			return Ok(());
		}

		// The routes leave first, so an observer of the eviction finds none.
		let withdrawn = self.servlet_registry.withdraw_peer_by_dial(peer.address())?;

		let address = peer.address().route_bytes();
		let payload = Some(address.as_ref());
		if let Some(withdrawn) = withdrawn {
			trace.emit_event_with_value_and_evidence(CLUSTER_PEER_ROUTES_WITHDRAWN, "evicted", withdrawn, payload)?;
		}

		trace.emit_marker_with_evidence(CLUSTER_PEER_EVICTED, || payload)?;

		Ok(())
	}

	/// Reconciles with unverified candidates and records the ones that fail.
	///
	/// A feeler probe runs reconcile only. A round that proves membership and
	/// gets an in-bounds reply promotes the candidate, and a failed candidate
	/// waits out its backoff behind every fresher one in its prefix bucket.
	async fn probe_candidates(&self, probes: impl AsRef<[AdmittedDial]>) -> Result<(), LoopFault> {
		let probes = probes.as_ref();
		for peer in probes {
			let Ok(peer_addr) = peer.protocol_address::<P::Address>() else {
				self.config.peer.table.discard(*peer)?;
				continue;
			};

			let round = self.reconcile_round(peer_addr, *peer).await?;
			if round == Round::Failed {
				let now = self.config.clock.unix();
				self.config.peer.table.record_probe_failure(*peer, now)?;
			}
		}

		Ok(())
	}

	/// Resends the journaled rumors that this peer wants.
	///
	/// - Each push carries an outer lifetime of 0, so a repair never refloods.
	/// - Only a rumor inside the seen window is admissible.
	/// - Only an explicit `Ok` reply arms the grey-hole ledger.
	/// - A peer lacks for good each rumor of an origin outside its trust. Its
	///   first refusal settles the origin, so the push goes once a window.
	/// - Each push whose reply decodes records [`CLUSTER_GOSSIP_REPAIR_PUSHED`] with the reply's status.
	///
	/// # Errors
	///
	/// - [`LoopFault::Registry`] -- the journal failed, or a push failed to build, sign, or reach the peer.
	/// - [`LoopFault::Runtime`] -- the trace refused an event.
	async fn push_repairs(
		&self,
		client: &mut FloodClient<P>,
		wanted: impl AsRef<[GossipDigest]>,
		peer: AdmittedDial,
	) -> Result<(), LoopFault> {
		let wanted = wanted.as_ref();
		let now = self.config.clock.unix();
		let seen = self.config.gossip.seen_window();
		let missing = self.config.gossip.journal.fetch(wanted, now)?;
		let admissible = missing.into_iter().filter(|(_, rumor)| seen.admits(rumor.issued_at(), now));

		// The address renders at the first reply that decodes, so a round that
		// pushes nothing renders nothing.
		let mut address: Option<SharedId> = None;

		for (pushed_digest, rumor) in admissible {
			let origin = rumor.signer_id();
			if !self.offers(peer, origin.as_deref(), now) {
				continue;
			}

			// A push that fails to build, sign, or reach the peer leaves as a
			// cluster error and skips the round. A trace fault ends the beat.
			let push = ClusterRequest::Gossip(Box::new(rumor));
			let builder = FrameBuilder::from(Version::V2)
				.with_id(b"gossip-repair")
				.with_message(push)
				.with_priority(MessagePriority::NetworkControl)
				.with_lifetime(0);

			let mut signed = self.config.witnessed(builder).build().map_err(ClusterError::from)?;
			let signing = signed.sign_with_provider(self.config.tls.identity()).await;
			signing.map_err(ClusterError::from)?;

			let Some(push_reply) = client.emit(signed, None).await.map_err(ClusterError::from)? else {
				continue;
			};
			let Ok(gossip_reply) = decode::<GossipResponse>(push_reply.message()) else {
				continue;
			};

			let status = gossip_reply.status;
			let label = status.as_str();
			let rendered = address.get_or_insert_with(|| peer.address().route_bytes());
			let payload = Some(rendered.as_ref());
			self.trace
				.emit_event_with_value_and_evidence(CLUSTER_GOSSIP_REPAIR_PUSHED, label, status, payload)?;

			let acknowledged = gossip_reply.status == TransitStatus::Ok;
			let refused_origin = origin.filter(|_| gossip_reply.refuses_origin());
			if acknowledged {
				self.ledgers.with(peer, |ledger| ledger.ack(pushed_digest));
			}
			if let Some(origin) = refused_origin {
				self.settle_refused_origin(peer, origin, now)?;
			}
		}

		Ok(())
	}
}

/// The shared state of one gossip pipeline invocation.
pub(crate) struct GossipPipelineCtx<P: Protocol> {
	/// The servlet routes that an admitted advertisement reconciles into.
	pub(crate) servlet_registry: Arc<ServletRegistry>,
	/// The colony identity, the gossip journal, the rate admission, and the
	/// peer caps that a rumor is checked against.
	pub(crate) config: ColonyConfig<P>,
	/// The plane that local ingress delivery dials its servlet on.
	pub(crate) hive_plane: HivePlane<P>,
	/// The peer dial plane, resolved once from the gateway's planes.
	pub(crate) peer_plane: PeerPlane<P>,
	/// The trace collector for gossip admission and refusal events.
	pub(crate) trace: Arc<TraceCollector>,
	/// The gateway's task group, which owns the reflood this pipeline starts,
	/// so a stop of the gateway also stops a reflood in flight.
	pub(crate) tasks: TaskGroup,
	/// What each gossip target acknowledged and refused, shared with the beat.
	pub(crate) ledgers: Arc<PeerLedgers>,
}

impl<P: Protocol> From<GatewayRuntimeCtx<P>> for GossipPipelineCtx<P> {
	/// Projects the gateway's runtime state onto what a rumor needs.
	fn from(ctx: GatewayRuntimeCtx<P>) -> Self {
		let peer_plane = ctx.peer_dial_plane();

		Self {
			servlet_registry: ctx.servlet_registry,
			config: ctx.config,
			peer_plane,
			hive_plane: ctx.hive_plane,
			trace: ctx.trace,
			tasks: ctx.tasks,
			ledgers: ctx.ledgers,
		}
	}
}

/// The consumers of one rumor on a gateway's gossip pipeline: the local
/// ingress, and the routing state an advertisement applies to.
struct RumorIntake<'a, P: Protocol> {
	/// The pipeline that delivers and applies the rumor.
	pipeline: &'a GossipPipelineCtx<P>,
	/// The verified relay that carried the rumor, when a peer relayed it.
	relay_id: Option<VerifiedSignerId>,
	/// The verified signer of the rumor, which an advertisement binds to the
	/// signer of the advertisement it carries.
	rumor_signer: Option<VerifiedSignerId>,
}

impl<P: ColonyDialProtocol> RumorConsumer for RumorIntake<'_, P> {
	async fn deliver(self, rumor: Frame, digest: GossipDigest) -> Result<(), LoopFault> {
		self.pipeline.deliver_local(rumor, digest).await
	}

	fn apply_advertisement(self, payload: &[u8]) -> Result<(), LoopFault> {
		self.pipeline.apply_peer_ad_rumor(self.relay_id, self.rumor_signer, payload)
	}
}

impl<P: ColonyDialProtocol> GossipPipelineCtx<P> {
	/// Delivers one admitted rumor to the configured local ingress servlet.
	///
	/// - The servlet receives the origin-signed rumor frame unchanged, as it receives a work frame.
	/// - The dial admits only the identity the servlet's registration names (CWE-346).
	/// - The frame's message decodes as a [`GossipRumor`], and its signature
	///   names the publishing gateway, so a servlet that serves many parties
	///   can tell them apart and verify each one.
	/// - A guard holds the claim from before the round trip, so admission and
	///   the reconcile beat never deliver one rumor twice (CWE-362).
	/// - A delivery this task never finishes returns the rumor to the retry set.
	async fn deliver_local(&self, rumor: Frame, digest_value: GossipDigest) -> Result<(), LoopFault> {
		let journal = &self.config.gossip.journal;
		let Some(type_key) = self.config.gossip.ingress.as_ref() else {
			// With no ingress servlet configured, the rumor has no local
			// consumer, so it leaves the retry set.
			journal.ack_local(&digest_value)?;
			return Ok(());
		};

		// Each early exit below drops the guard, which returns the rumor to the
		// retry set.
		let Some(claim) = LocalClaimGuard::take(journal.as_ref(), &digest_value, self.config.clock.unix())? else {
			return Ok(());
		};

		let entries = self.servlet_registry.local_entries_for_type(type_key)?;
		// An out-of-range balancer answer skips the delivery, and the gossip
		// task runs on (see `ClusterConfig::pick_instance`).
		let Some(entry) = self.config.pick_instance(&entries) else {
			return Ok(());
		};

		let choice = RouteChoice::of(entry);
		let Ok(hop) = choice.hop(&self.hive_plane, None) else {
			return Ok(());
		};
		let Ok(_response) = hop.deliver_frame(rumor).await else {
			return Ok(());
		};

		claim.ack()?;
		self.trace.emit_marker(CLUSTER_GOSSIP_DELIVERED)?;

		Ok(())
	}

	/// Delivers the journal entries whose local consumption is pending: a rumor
	/// admitted before ingress registered, or one whose delivery hit a
	/// transient fault. The kind of each rumor decides its retry.
	async fn retry_pending_local(&self) -> Result<(), LoopFault> {
		let pending = self.config.gossip.journal.pending_local(self.config.clock.unix())?;
		for (digest, rumor) in pending {
			let Ok(body) = decode::<GossipRumor>(rumor.message()) else {
				continue;
			};

			let intake = RumorIntake { pipeline: self, relay_id: None, rumor_signer: None };
			body.kind.retry(intake, rumor, digest).await?;
		}

		Ok(())
	}

	/// Admits, rate-limits, journals, delivers locally, and optionally
	/// refloods one rumor.
	///
	/// # Pipeline order
	///
	/// 1. Admit against the hop TTL and the seen window, and charge the verified origin signer's budget.
	/// 2. Drop known duplicates before rate admission.
	/// 3. Rate-limit before the journal and the reflood.
	/// 4. Witness advertisement rumors, and retain application rumors for repair.
	/// 5. Deliver application rumors locally, or apply advertisement rumors to routing.
	/// 6. Record the admission as [`CLUSTER_GOSSIP_ADMITTED`], once the flood targets read.
	/// 7. Reflood on a separate task when hop TTL and targets remain.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refuses an event, a delivery meets a
	///   runtime fault, or the reply frame fails to build. A refused rumor
	///   answers with a reply frame that carries its status.
	pub(crate) async fn run(
		self,
		origin: GossipOrigin,
		frame: Frame,
		rumor: VerifiedRumor,
		hop_ttl: u64,
		sender: VerifiedSignerId,
		rumor_signer: Option<VerifiedSignerId>,
	) -> Result<Option<Frame>, TightBeamError> {
		// The caller verified the outer signer, so each refusal names it.
		let audit = RequestAudit::proven(&self.trace);
		let refusal = Refusal::to(&frame, &audit).by(&sender);
		let relay_id = origin.relay(&sender);

		let now = self.config.clock.unix();
		let admitted = self.config.admit_rumor(&rumor, hop_ttl, now);
		let rumor = rumor.into_frame();
		let admitted = match admitted {
			Ok(admitted) => admitted,
			Err(status) => {
				let scored = self.weaken_invalid_relay(origin, relay_id);
				return refusal.gossip_scored(scored, status);
			}
		};

		// Rate and journal keys use the verified origin signer, so a relay
		// spends the origin's budget (CWE-770).
		let attributed = origin.attributed(&frame, &rumor);
		if attributed.nonrepudiation().is_none() {
			return refusal.gossip(TransitStatus::Unauthenticated);
		}

		let Some(signer_id) = attributed.signer_id() else {
			return refusal.gossip(TransitStatus::PermissionDenied);
		};

		// A duplicate drops before rate admission, so only unseen rumors spend.
		let now = self.config.clock.unix();
		match self.config.gossip.journal.seen(admitted.digest(), now) {
			Ok(true) => {
				self.trace.emit_marker(CLUSTER_GOSSIP_DUPLICATE)?;
				return ReplyForm::Plain.reply(frame.metadata().id(), GossipResponse { status: TransitStatus::Ok });
			}
			Ok(false) => {}
			Err(error) => {
				return refusal.gossip_error(&error);
			}
		}

		// The rate limit runs before the journal and the reflood (CWE-770). A
		// backend fault refuses closed.
		match self.config.gossip.admission.allow(&signer_id, now) {
			Ok(true) => {}
			Ok(false) => {
				return refusal.gossip(TransitStatus::ResourceExhausted);
			}
			Err(error) => {
				return refusal.gossip_error(&error);
			}
		}

		let digest = *admitted.digest();
		let journal = self.config.gossip.journal.as_ref();
		let journaled = admitted.kind().journal(journal, &signer_id, digest, &rumor, now);
		match journaled {
			Ok(Admission::Duplicate) => {
				self.trace.emit_marker(CLUSTER_GOSSIP_DUPLICATE)?;
				return ReplyForm::Plain.reply(frame.metadata().id(), GossipResponse { status: TransitStatus::Ok });
			}
			Ok(Admission::New) => {}
			Err(error) => {
				return refusal.gossip_error(&error);
			}
		}

		// The kind decides local consumption. Only a relayed rumor names a
		// relay hop to fall back on, and the origin already holds its slate.
		let intake = RumorIntake { pipeline: &self, relay_id: relay_id.cloned(), rumor_signer };
		let applied = admitted.kind().consume(intake, &rumor, digest, admitted.payload()).await;
		if let Err(fault) = applied {
			return refusal.gossip_fault(fault);
		}

		let has_targets = match self.config.peer.table.has_targets() {
			Ok(has_targets) => has_targets,
			Err(error) => {
				return refusal.gossip_error(&error);
			}
		};

		// Every check passed, and the payload names the budget's signer.
		let kind = admitted.kind().label();
		let signer = Some(signer_id.as_slice());
		self.trace
			.emit_event_with_value_and_evidence(CLUSTER_GOSSIP_ADMITTED, kind, hop_ttl, signer)?;

		let flood = FloodBeat::new(
			self.config.clone(),
			self.peer_plane.clone(),
			Arc::clone(&self.servlet_registry),
			Arc::clone(&self.trace),
			Arc::clone(&self.ledgers),
		);
		let GossipPipelineCtx { tasks, .. } = self;

		// The reflood runs on its own task, so the Ok reply returns at this
		// gateway's pace, and the reply needs only the outer frame id.
		match (flood, hop_ttl.checked_sub(1)) {
			(Some(flood), Some(next_ttl)) if has_targets => {
				tasks.spawn(async move {
					// With no caller, the task records a poisoned table
					// here. The reflood traces its unreached hops.
					if let Err(fault) = flood.reflood(rumor, next_ttl).await {
						fault.record(&flood.trace);
					}
				});
			}
			_ => {}
		}

		ReplyForm::Plain.reply(frame.metadata().id(), GossipResponse { status: TransitStatus::Ok })
	}

	/// Verifies, admits, and reconciles one advertisement rumor.
	///
	/// It returns the learned origin fingerprint, or [`None`] for any refusal.
	/// The caller owns the learned and dropped audit events. A relay-trail
	/// refusal traces here, because the ad is learned all the same.
	///
	/// # Evaluation order
	///
	/// 1. Decode and verify the inner frame on the peer trust plane.
	/// 2. Bind the rumor signer and the inner signer to the same origin.
	/// 3. Reject a stale or far-future control order.
	/// 4. Admit through [`AdmittedPeerAd::admit`].
	/// 5. Learn the discovery hint and reconcile the direct slate, and record what each changed.
	/// 6. Install a best-effort relay trail when the hop budget and the relay's dial address allow.
	/// 7. Record a new relay trail as [`CLUSTER_RELAY_TRAIL_INSTALLED`], and a
	///    refused one as [`CLUSTER_RELAY_TRAIL_REFUSED`].
	fn try_apply_peer_ad_rumor(
		&self,
		relay_id: Option<VerifiedSignerId>,
		rumor_signer: Option<VerifiedSignerId>,
		payload: impl AsRef<[u8]>,
	) -> Result<Option<Arc<[u8]>>, LoopFault> {
		let Some(rumor_signer) = rumor_signer else {
			return Ok(None);
		};

		let payload = payload.as_ref();
		let Ok(inner) = decode::<Frame>(&payload) else {
			return Ok(None);
		};
		let Ok(verified_inner) = self.config.verify_peer(&inner) else {
			return Ok(None);
		};

		// The same-origin bind means only the advertiser itself may rumor its
		// ad, so a rumor's freshness always belongs to the ad it carries.
		let inner_signer = verified_inner.fingerprint();
		if rumor_signer != inner_signer {
			return Ok(None);
		}

		// The direct path's order bound keeps every admitted order inside the
		// tombstone window (CWE-294) and the prunable range (CWE-770).
		if !self.config.ad_order_fresh(inner.issued_at(), self.config.clock.unix()) {
			return Ok(None);
		}

		let Ok(ClusterRequest::AdvertisePeer(advertisement)) = decode::<ClusterRequest>(inner.message()) else {
			return Ok(None);
		};
		let Ok(admitted) = AdmittedPeerAd::admit(&verified_inner, &advertisement, &self.config) else {
			return Ok(None);
		};

		let origin = Arc::clone(&admitted.peer_hive_id);

		// The relay hop is a verified peer, so its trail can install in its own
		// bucket beside the direct one (CWE-772).
		let relay_trail = relay_id.filter(|_| self.config.peer.max_hops >= 2).and_then(|relay_id| {
			let relay_socket = self.servlet_registry.relay_dial_addr(relay_id.as_shared())?;
			let relay_dial = self.config.peer.admit_dial(relay_socket).ok()?;
			admitted.relay_trail(relay_id.as_shared(), relay_dial, &self.config.pheromone)
		});

		// Like a direct advertiser, the origin is a discovery hint. It waits in
		// the capped `new` table until a local probe proves it a flood member.
		let hint = admitted.discovery_hint();
		let learned_at = self.config.clock.unix();
		self.config
			.learn_hints(&self.trace, HintSource::Origin(origin.as_ref()), [hint], learned_at)?;

		// The advertiser's fault drops the rumor, and a local fault, such as a
		// poisoned registry, ends the caller.
		let change = match self.servlet_registry.reconcile_peer_slate(admitted, PeerCaps::default()) {
			Ok(change) => change,
			Err(error) if error.blames_the_advertiser() => return Ok(None),
			Err(error) => return Err(LoopFault::Registry(error)),
		};
		change.record_direct(&self.trace, origin.as_ref())?;

		// The direct trail landed, so a refused relay bucket (caps or a stale
		// order) loses only the fallback, and it traces (ISO 27001 A.8.15).
		let Some(trail) = relay_trail else {
			return Ok(Some(origin));
		};

		let payload = Some(origin.as_ref());
		match self.servlet_registry.reconcile_relay_trail(trail, PeerCaps::default()) {
			Ok(change) if change.opens_bucket() => {
				self.trace
					.emit_marker_with_evidence(CLUSTER_RELAY_TRAIL_INSTALLED, || payload)?;
			}
			Ok(_refreshed) => {}
			Err(error) if error.blames_the_advertiser() => {
				self.trace.emit_marker_with_evidence(CLUSTER_RELAY_TRAIL_REFUSED, || payload)?;
			}
			Err(error) => return Err(LoopFault::Registry(error)),
		}

		Ok(Some(origin))
	}

	/// Applies one admitted peer-advertisement rumor to routing state. The
	/// wrapped frame MUST verify on the peer trust plane, and the rumor signer
	/// MUST match the inner signer, so an ad travels only under its author's
	/// identity.
	///
	/// # Admission
	///
	/// A rumor takes the direct-ad path of [`AdmittedPeerAd::admit`]: order
	/// freshness, flood membership, the dial allowlist, the message checks, and
	/// the discovery hint.
	///
	/// # Reconciliation
	///
	/// - The slate installs a direct trail that dials the origin.
	/// - When `max_hops` affords two forwards and the relay's dial address is
	///   known, a relay trail installs beside it, and only then can pheromone
	///   fail over (CWE-772).
	/// - Registry policy refuses a slate that collides with a local route, such as this gateway's echo.
	///
	/// # Audit
	///
	/// A learned slate traces [`CLUSTER_PEER_AD_LEARNED`] with the origin
	/// fingerprint. Every refusal traces [`CLUSTER_PEER_AD_DROPPED`], with the
	/// rumor signer when it is verifiable (ISO 27001 A.8.15).
	fn apply_peer_ad_rumor(
		&self,
		relay_id: Option<VerifiedSignerId>,
		rumor_signer: Option<VerifiedSignerId>,
		payload: impl AsRef<[u8]>,
	) -> Result<(), LoopFault> {
		let payload = payload.as_ref();
		match self.try_apply_peer_ad_rumor(relay_id, rumor_signer.clone(), payload)? {
			Some(origin) => {
				let origin = Some(origin.as_ref());
				self.trace.emit_marker_with_evidence(CLUSTER_PEER_AD_LEARNED, || origin)?;
			}
			None => {
				// The rumor signer is the closest identity a refusal can name.
				let signer = rumor_signer.as_ref().map(|signer| signer.as_shared().as_ref());
				self.trace.emit_marker_with_evidence(CLUSTER_PEER_AD_DROPPED, || signer)?;
			}
		}

		Ok(())
	}
}

// A relay score reads only the registry and the trace, so this impl bounds
// `P` by `Protocol` alone.
impl<P: Protocol> GossipPipelineCtx<P> {
	/// Scores a relay peer that sent invalid input. An origin publish has no
	/// relay to score.
	///
	/// A weakened route records [`CLUSTER_GOSSIP_RELAY_WEAKENED`], and a route
	/// the score drives to its abandonment limit records
	/// [`CLUSTER_PEER_ROUTE_ABANDONED`].
	///
	/// # Errors
	///
	/// - [`LoopFault::Registry`] -- the route lock is poisoned.
	/// - [`LoopFault::Runtime`] -- the trace refused the event.
	pub(crate) fn weaken_invalid_relay(
		&self,
		origin: GossipOrigin,
		relay_id: Option<&VerifiedSignerId>,
	) -> Result<(), LoopFault> {
		if matches!(origin, GossipOrigin::Origin) {
			return Ok(());
		}
		let Some(peer_id) = relay_id else {
			return Ok(());
		};

		// The audit payload names the scored peer's fingerprint.
		let weakened = self.servlet_registry.weaken_peer(peer_id.as_shared())?;
		let payload = Some(peer_id.as_shared().as_ref());
		if weakened.count() > 0 {
			self.trace
				.emit_marker_with_evidence(CLUSTER_GOSSIP_RELAY_WEAKENED, || payload)?;
		}
		if let Some(abandoned) = weakened.abandoned() {
			let cause = "relay-score";
			self.trace
				.emit_event_with_value_and_evidence(CLUSTER_PEER_ROUTE_ABANDONED, cause, abandoned, payload)?;
		}

		Ok(())
	}
}

/// The change-driven publish state of the advertisement rumor. The beat
/// publishes when the slate or the flood target set changes, and on a
/// configured refresh interval for late joiners
/// ([`DEFAULT_AD_RUMOR_REFRESH_MS`]).
///
/// # Poison recovery
///
/// Only plain field assignments write the guarded value, so a panic leaves it
/// whole, and every method recovers a poisoned guard and runs on.
///
/// # Claim lifecycle
///
/// 1. [`Self::take_due`] claims a publish slot and blocks re-entry while the task runs.
/// 2. The task that holds the claim creates and refloods the rumor.
/// 3. [`Self::commit`] records the baseline after a rumor goes out.
/// 4. [`Self::abort`] releases a failed claim with the committed baseline intact, so the next beat retries.
///
/// [`DEFAULT_AD_RUMOR_REFRESH_MS`]: crate::constants::DEFAULT_AD_RUMOR_REFRESH_MS
struct AdPublishState {
	inner: Mutex<AdPublishInner>,
	refresh: Duration,
}

/// The baseline and the claim flag behind the [`AdPublishState`] lock.
#[derive(Default)]
struct AdPublishInner {
	last: Option<(UnixMillis, Vec<Urn<'static>>, Vec<AdmittedDial>)>,
	in_flight: bool,
}

impl AdPublishState {
	fn new(refresh: Duration) -> Self {
		Self { inner: Mutex::new(AdPublishInner::default()), refresh }
	}

	/// Claims one due publish slot. `true` marks a publish in flight, and the
	/// baseline holds until [`Self::commit`] or [`Self::abort`] settles it.
	/// `false` means the slate and the targets match the baseline inside the
	/// refresh window, or a publish already holds the claim.
	fn take_due(
		&self,
		now: UnixMillis,
		slate: impl AsRef<[Urn<'static>]>,
		targets: impl AsRef<[AdmittedDial]>,
	) -> bool {
		let slate = slate.as_ref();
		let targets = targets.as_ref();
		let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
		if inner.in_flight {
			return false;
		}

		let due = match &inner.last {
			None => true,
			Some((at, published_slate, published_targets)) => {
				published_slate != slate || published_targets != targets || now.saturating_since(*at) >= self.refresh
			}
		};

		inner.in_flight = due;
		due
	}

	/// Records a completed publish as the suppression baseline, and releases
	/// the claim.
	fn commit(
		&self,
		now: UnixMillis,
		slate: impl IntoIterator<Item = Urn<'static>>,
		targets: impl IntoIterator<Item = AdmittedDial>,
	) {
		let slate: Vec<Urn<'static>> = slate.into_iter().collect();
		let targets: Vec<AdmittedDial> = targets.into_iter().collect();
		let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);

		inner.last = Some((now, slate, targets));
		inner.in_flight = false;
	}

	/// Releases a failed claim and keeps the baseline.
	fn abort(&self) {
		let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
		inner.in_flight = false;
	}
}

impl<P: ColonyDialProtocol> GatewayRuntimeCtx<P> {
	/// Spawns the beat that re-announces local types to peers.
	///
	/// Each beat retries pending local delivery, publishes due advertisement
	/// rumors, dials beat targets with one shared signed frame, and runs
	/// reconcile rounds for flood members and feeler probes.
	pub(crate) fn spawn_advertise(self, gateway_addr: Arc<[u8]>) -> rt::JoinHandle {
		// Repair delivery runs the gossip pipeline, so it reuses its context.
		let delivery = GossipPipelineCtx::from(self.clone());
		let peer_plane = self.peer_dial_plane();
		let beat = AdvertiseBeat {
			config: self.config.clone(),
			advertiser: peer_plane.advertiser(),
			servlet_registry: Arc::clone(&self.servlet_registry),
		};
		let flood = FloodBeat::new(
			self.config.clone(),
			peer_plane,
			Arc::clone(&self.servlet_registry),
			Arc::clone(&self.trace),
			Arc::clone(&self.ledgers),
		);

		let GatewayRuntimeCtx { config, trace, tasks, .. } = self;

		rt::spawn(async move {
			let beat: Result<(), LoopFault> = async {
				let Some(interval) = config.peer.advertise_interval else {
					return Ok(());
				};

				// PEX replies echo installed routes, which include this
				// gateway's own address, so the table excludes it up front.
				let local = PeerAddress::try_from(gateway_addr.as_ref()).ok();
				if let Some(local) = local {
					config.peer.table.exclude_self(local)?;
				}

				let ad_publish = Arc::new(AdPublishState::new(config.rumor_refresh()));
				loop {
					config.clock.sleep(interval).await;
					delivery.retry_pending_local().await?;

					// Probes are unverified candidates awaiting a feeler dial.
					let targets = config.peer.table.target_set()?;
					let probes = config.peer.table.probe_sample(config.clock.unix())?;

					// The ledgers feed grey-hole detection and hold refusals.
					if let Some(flood) = flood.as_ref() {
						flood.prune_ledgers(&targets, &probes);
					}

					if targets.is_empty() && probes.is_empty() {
						continue;
					}

					let slate = beat.exported_slate()?;

					// The rumor publish runs on its own task, so the direct
					// advertisements below dial at this gateway's pace.
					let now = config.clock.unix();
					let publishing = match flood.as_ref() {
						Some(flood) if ad_publish.take_due(now, &slate, &targets) => Some(flood.clone()),
						_ => None,
					};

					// Only a publishing beat copies the slate, which it keeps
					// as its commit baseline.
					let (ad_slate, publishing) = match publishing {
						Some(publish_beat) => (slate.clone(), Some((publish_beat, slate))),
						None => (slate, None),
					};

					// An advertisement that fails to build skips this beat's
					// advertisements, and the next beat builds another.
					let mut advertisement = None;
					if !targets.is_empty() || publishing.is_some() {
						let minted = config.mint_ad_frame(gateway_addr.as_ref(), ad_slate).await;
						advertisement = minted.ok().map(Arc::new);
					}

					if let Some((publish_beat, publish_slate)) = publishing {
						let publish_state = Arc::clone(&ad_publish);
						let publish_advertisement = advertisement.clone();

						// The captured vectors become the commit baseline.
						let publish_targets = targets.clone();
						tasks.spawn(async move {
							let publish_advertisement = publish_advertisement.as_deref();
							let published = publish_beat.publish_slate_rumor(publish_advertisement).await;

							// This task records a poisoned table here, because
							// it has no other observer.
							match published {
								Ok(true) => {
									publish_state.commit(
										publish_beat.config.clock.unix(),
										publish_slate,
										publish_targets,
									);
								}
								Ok(false) => publish_state.abort(),
								Err(fault) => {
									publish_state.abort();
									fault.record(&publish_beat.trace);
								}
							}
						});
					}

					let advertisement = advertisement.as_deref();
					beat.dial_targets(flood.as_ref(), &targets, advertisement, &trace).await?;
					if let Some(flood) = flood.as_ref() {
						flood.probe_candidates(&probes).await?;
					}
				}
			}
			.await;

			// A trace fault ends the beat silently, which is the effect a
			// `testing-fault` injection observes. A poisoned table or
			// registry ends it on the record.
			if let Err(fault) = beat {
				fault.record(&trace);
			}
		})
	}
}

#[cfg(test)]
mod tests {
	use core::num::{NonZeroU32, NonZeroUsize};

	use super::*;
	use crate::colony::cluster::{CertificateSpec, Cluster, ClusterGateway, ClusterTlsConfig, PeerConfig};
	use crate::colony::cluster::{PeerRoute, ServletEntry, DEFAULT_ABANDONMENT_LIMIT, DEFAULT_INITIAL_PHEROMONE};
	use crate::colony::urn::ColonyNamespace;
	use crate::constants::MAX_PEER_TRIED_FAILURES;
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
	use crate::crypto::x509::{Certificate, KeyCurves};
	use crate::instrumentation::events::CLUSTER_RECONCILE_ANSWERED;
	use crate::oids::HASH_SHA3_256;
	use crate::testing::{unhex, SetupEnv, TestCertificate, TestKey, TestRumor};
	use crate::transport::TokioListener;
	use crate::utils::time::ManualClock;
	use crate::{absent, exactly, tb_assert_spec, tb_cases, tb_scenario};

	/// The window a refusal stands for in these tests.
	const WINDOW: Duration = Duration::from_secs(120);

	#[test]
	fn ledger_holds_a_refused_origin_for_one_window() {
		let mut ledger = PeerLedger::default();
		ledger.refuse_origin(b"origin-a", UnixMillis::new(1_000));

		let offers = [
			ledger.offers(b"origin-a", UnixMillis::new(1_000), WINDOW),
			ledger.offers(b"origin-a", UnixMillis::new(120_999), WINDOW),
			ledger.offers(b"origin-a", UnixMillis::new(121_000), WINDOW),
			ledger.offers(b"origin-b", UnixMillis::new(1_000), WINDOW),
		];

		assert_eq!(offers, [false, false, true, true]);
	}

	#[test]
	fn ledger_expires_a_refusal_once_its_window_has_passed() {
		let mut ledger = PeerLedger::default();
		ledger.refuse_origin(b"origin-a", UnixMillis::new(1_000));
		ledger.refuse_origin(b"origin-b", UnixMillis::new(60_000));
		ledger.expire(UnixMillis::new(121_000), WINDOW);

		let held: Vec<&[u8]> = ledger.refused_origins.keys().map(Vec::as_slice).collect();
		assert_eq!(held, vec![b"origin-b".as_slice()]);
	}

	/// A SHA3-256 rumor digest of 32 octets of `fill`.
	fn digest_of(fill: u8) -> GossipDigest {
		GossipDigest::read::<Sha3_256>([fill; 32]).expect("32 octets read as a SHA3-256 digest")
	}

	#[test]
	fn ledger_reads_an_acknowledged_digest_wanted_again_as_a_drop() {
		let mut ledger = PeerLedger::default();
		ledger.ack(digest_of(1));
		let signals = [
			ledger.drop_signal([digest_of(2)]),
			ledger.drop_signal([digest_of(1)]),
			ledger.drop_signal([digest_of(1)]),
		];

		assert_eq!(signals, [false, true, false]);
	}

	#[test]
	fn ledgers_keep_the_live_targets_alone() {
		let ledgers = PeerLedgers::default();
		let live = dial("10.0.0.1:9000");
		let gone = dial("10.0.0.2:9000");
		ledgers.with(live, |ledger| ledger.refuse_origin(b"origin-a", UnixMillis::new(1_000)));
		ledgers.with(gone, |ledger| ledger.refuse_origin(b"origin-a", UnixMillis::new(1_000)));
		ledgers.prune(|target| *target == live, UnixMillis::new(2_000), WINDOW);

		let offers = [
			ledgers.with(live, |ledger| ledger.offers(b"origin-a", UnixMillis::new(2_000), WINDOW)),
			ledgers.with(gone, |ledger| ledger.offers(b"origin-a", UnixMillis::new(2_000), WINDOW)),
		];
		assert_eq!(offers, [false, true]);
	}

	/// The SHA3-256 digest of the to-be-signed encoding and then the signature
	/// of the fixed test rumor, `TestRumor::application(1_000, [1, 2, 3])`,
	/// computed with Python's `hashlib.sha3_256`.
	const HOUSE_RUMOR_DIGEST: &str = "6d94eba786b7f0f7dc8edf6f96289336b4d2fe4ffeddec6052ee8ccafbf70e20";

	/// A house gateway admits a rumor under the SHA3-256 digest its provider
	/// names, over the to-be-signed encoding and then the origin signature.
	#[test]
	fn a_house_gateway_digests_a_rumor_under_sha3_256() -> Result<(), TransitStatus> {
		let config = ColonyConfig::<TokioListener>::new(test_config());
		let rumor = TestRumor::verified(TestRumor::application(1_000, [1, 2, 3]));

		let admitted = config.admit_rumor(&rumor, 0, UnixMillis::new(1_000))?;
		assert_eq!(admitted.digest().as_bytes(), unhex(HOUSE_RUMOR_DIGEST));
		Ok(())
	}

	/// A house gateway witnesses each frame it builds under SHA3-256, the
	/// digest its protocol's provider names.
	#[test]
	fn a_house_gateway_witnesses_its_frames_under_sha3_256() -> Result<(), TightBeamError> {
		let config = ColonyConfig::<TokioListener>::new(test_config());
		let message = GossipRumor::application(vec![1, 2, 3]);
		let builder = FrameBuilder::from(Version::V2).with_id(b"witnessed").with_order(1_000);

		let frame = config.witnessed(builder.with_message(message)).build()?;
		let witness = frame.integrity().map(|info| info.algorithm.oid);
		assert_eq!(witness, Some(HASH_SHA3_256));
		Ok(())
	}

	/// A config that holds the fields these tests read.
	fn test_config() -> ClusterConfig {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();

		ClusterConfig::new(
			ClusterTlsConfig::new(
				CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key))),
				Arc::new(Secp256k1KeyProvider::from(key)),
			)
			.expect("the test certificate must decode"),
		)
	}

	fn config_with_window(window_ms: u64) -> ClusterConfig {
		let mut config = test_config();
		config.control_freshness_window = Duration::from_millis(window_ms);
		config
	}

	fn config_allowing(allowlist: impl IntoIterator<Item = String>) -> ClusterConfig {
		let mut config = test_config();
		config.peer = PeerConfig::allowing(allowlist);
		config
	}

	fn reply(want_len: usize, pex_len: usize) -> GossipWant {
		let want = vec![vec![0u8; 32]; want_len];
		let pex = vec![PeerGossip { peer_id: Vec::new(), gateway_addr: b"127.0.0.1:9000".to_vec() }; pex_len];
		GossipWant { want, pex }
	}

	// A reply at both caps is in bounds, and one entry past either cap makes
	// it oversized.
	tb_cases! {
		fn reconcile_reply_bounds_want_and_pex((want_len, pex_len, oversized): (usize, usize, bool)) {
			assert_eq!(reply(want_len, pex_len).is_oversized(), oversized);
		}
		cases {
			at_both_caps => (MAX_GOSSIP_LOG, MAX_PEX_SAMPLE, false),
			want_past_its_cap => (MAX_GOSSIP_LOG + 1, MAX_PEX_SAMPLE, true),
			pex_past_its_cap => (MAX_GOSSIP_LOG, MAX_PEX_SAMPLE + 1, true),
		}
	}

	fn pex_entry(addr: impl AsRef<str>) -> PeerGossip {
		let addr = addr.as_ref();
		PeerGossip { peer_id: Vec::new(), gateway_addr: addr.as_bytes().to_vec() }
	}

	#[test]
	fn pex_hints_admitted_without_allowlist() {
		let pex = vec![pex_entry("10.0.0.1:9000"), pex_entry("10.66.0.1:9000")];
		let admitted: Vec<PeerHint> = test_config().admissible_pex_hints(pex).collect();
		assert_eq!(admitted.len(), 2);
	}

	#[test]
	fn pex_hints_off_allowlist_refused() {
		let config = config_allowing(vec![String::from("10.0.0.1:9000")]);
		let pex = vec![pex_entry("10.0.0.1:9000"), pex_entry("10.66.0.1:9000")];
		let admitted: Vec<PeerHint> = config.admissible_pex_hints(pex).collect();
		assert_eq!(admitted.len(), 1);
		assert_eq!(admitted[0].dial.to_string(), "10.0.0.1:9000");
	}

	/// A fixture dial target, which the beat carries admitted.
	fn dial(text: &str) -> AdmittedDial {
		AdmittedDial::fixture(text)
	}

	fn ad_slate(names: &[&str]) -> Vec<Urn<'static>> {
		names
			.iter()
			.map(|name| {
				ColonyNamespace::default()
					.servlet(name)
					.expect("test names satisfy the mint grammar")
			})
			.collect()
	}

	#[test]
	fn ad_order_inside_window_is_fresh() {
		assert!(config_with_window(500).ad_order_fresh(UnixMillis::new(1_500), UnixMillis::new(2_000)));
		assert!(config_with_window(500).ad_order_fresh(UnixMillis::new(2_500), UnixMillis::new(2_000)));
	}

	#[test]
	fn ad_order_older_than_window_is_stale() {
		assert!(!config_with_window(500).ad_order_fresh(UnixMillis::new(1_499), UnixMillis::new(2_000)));
	}

	#[test]
	fn ad_order_past_future_window_is_stale() {
		assert!(!config_with_window(500).ad_order_fresh(UnixMillis::new(2_501), UnixMillis::new(2_000)));
		assert!(!config_with_window(500).ad_order_fresh(UnixMillis::new(u64::MAX), UnixMillis::new(2_000)));
	}

	#[test]
	fn ad_publish_first_beat_is_due() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		assert!(state.take_due(UnixMillis::new(0), [], []));
	}

	#[test]
	fn ad_publish_unchanged_state_suppresses_until_refresh() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(UnixMillis::new(0), [], []);
		state.commit(UnixMillis::new(0), Vec::new(), Vec::new());
		assert!(!state.take_due(UnixMillis::new(999), [], []));
		assert!(state.take_due(UnixMillis::new(1_000), [], []));
	}

	#[test]
	fn ad_publish_slate_change_fires_before_refresh() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(UnixMillis::new(0), [], []);
		state.commit(UnixMillis::new(0), Vec::new(), Vec::new());
		assert!(state.take_due(UnixMillis::new(1), ad_slate(&["ping"]), []));
	}

	#[test]
	fn ad_publish_target_change_fires_before_refresh() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(UnixMillis::new(0), [], []);
		state.commit(UnixMillis::new(0), Vec::new(), Vec::new());
		assert!(state.take_due(UnixMillis::new(1), [], [dial("10.0.0.1:9000")]));
	}

	#[test]
	fn ad_publish_suppressed_beat_keeps_the_refresh_baseline() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(UnixMillis::new(0), [], []);
		state.commit(UnixMillis::new(0), Vec::new(), Vec::new());
		state.take_due(UnixMillis::new(500), [], []);
		assert!(state.take_due(UnixMillis::new(1_000), [], []));
	}

	#[test]
	fn ad_publish_claim_in_flight_blocks_reentry() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(UnixMillis::new(0), [], []);
		assert!(!state.take_due(UnixMillis::new(1), ad_slate(&["ping"]), []));
	}

	#[test]
	fn ad_publish_aborted_claim_retries_on_the_next_beat() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(UnixMillis::new(0), [], []);
		state.abort();
		assert!(state.take_due(UnixMillis::new(1), [], []));
	}

	#[test]
	fn ad_publish_commit_settles_the_claim_and_the_baseline() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(UnixMillis::new(0), [], []);
		state.commit(UnixMillis::new(500), Vec::new(), Vec::new());
		assert!(!state.take_due(UnixMillis::new(1_499), [], []));
		assert!(state.take_due(UnixMillis::new(1_500), [], []));
	}

	/// The key of a gateway in no colony.
	fn stranger_key() -> Secp256k1SigningKey {
		Secp256k1SigningKey::from_bytes(&[3u8; 32].into()).expect("the fixture scalar is a valid key")
	}

	/// A live gateway in no colony, and its certificate. With no colony URN,
	/// a member that dials it finds it outside the flood.
	async fn stranger_gateway() -> (ClusterGateway<TokioListener>, Certificate) {
		let key = stranger_key();
		let certificate = TestCertificate::self_signed(&key);
		let spec = CertificateSpec::Built(Box::new(certificate.clone()));
		let tls = ClusterTlsConfig::new(spec, Arc::new(Secp256k1KeyProvider::from(key)));
		let config = ClusterConfig::new(tls.expect("the stranger certificate must decode"));

		let trace = Arc::new(TraceCollector::default());
		let gateway = ClusterGateway::start(trace, config).await.expect("the stranger gateway starts");
		(gateway, certificate)
	}

	/// The gossip arm of a colony member whose peer trust enrolls `stranger`,
	/// which records on `trace`.
	fn member_beat(stranger: &Certificate, trace: Arc<TraceCollector>) -> FloodBeat<TokioListener> {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let colony = ColonyNamespace::default().colony("main").expect("a literal colony name");
		let certificate = TestCertificate::with_uri_sans(&key, &[&colony.to_string()]);
		let spec = CertificateSpec::Built(Box::new(certificate));
		let tls = ClusterTlsConfig::new(spec, Arc::new(Secp256k1KeyProvider::from(key)));
		let enrolled = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
		let enrolled = enrolled.with_certificate(stranger.clone());
		let peer_trust: Arc<dyn CertificateTrust> = Arc::new(enrolled.expect("the stranger enrolls").build());
		let tls = tls.expect("the member certificate must decode").with_peer_trust(peer_trust);

		let config = ColonyConfig::new(ClusterConfig::new(tls));
		let pools = config.tls.pools::<TokioListener>(&config.pool_config, &config.clock, &trace);
		let peer_pool = pools.peer.expect("a peer trust builds a peer pool");
		let peer_plane = PeerPlane::new(peer_pool, config.clone(), Arc::clone(&trace));
		let registry = Arc::new(ServletRegistry::new(config.pheromone.clone(), Arc::clone(&config.clock)));

		FloodBeat::new(config, peer_plane, registry, trace, Arc::default()).expect("a colony member is in a flood")
	}

	// A poisoned peer table at an expulsion ends the beat as a local fault, so
	// the score of the peer that answered from outside the flood stands.
	#[tokio::test]
	async fn a_poisoned_table_at_an_expulsion_is_a_local_fault() -> Result<(), TightBeamError> {
		let (stranger, certificate) = stranger_gateway().await;
		let beat = member_beat(&certificate, Arc::default());
		beat.config.peer.table.poison();

		let address = *stranger.addr();
		let peer = dial(&address.to_string());

		let round = beat.reconcile_round(address, peer).await;
		assert!(matches!(round, Err(LoopFault::Registry(ClusterError::LockPoisoned))));
		Ok(())
	}

	/// The name of the authority that issues both certificates of
	/// [`SignerRotation`].
	const AUTHORITY: &str = "Signer Authority";

	/// One gateway key under two certificates that one authority issued, and
	/// the gossip arm of a colony member that enrolls the authority and the
	/// first certificate alone.
	///
	/// - `enrolled` serves under the enrolled certificate, and `rotated` under the second.
	/// - The member's discovery table holds one tried entry per signer.
	struct SignerRotation {
		beat: FloodBeat<TokioListener>,
		enrolled: ClusterGateway<TokioListener>,
		rotated: ClusterGateway<TokioListener>,
	}

	impl SignerRotation {
		/// Starts the member's beat and both gateways, which record on
		/// `scenario`.
		async fn start(scenario: &TraceCollector) -> Self {
			let colony = ColonyNamespace::default().colony("main");
			let colony = colony.expect("a literal colony name").to_string();
			let authority_key = Secp256k1SigningKey::from_bytes(&[6u8; 32].into()).expect("a valid fixture scalar");
			let gateway_key = Secp256k1SigningKey::from_bytes(&[7u8; 32].into()).expect("a valid fixture scalar");
			let member_key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
			let authority = TestCertificate::authority(&authority_key, AUTHORITY);
			let authority = authority.expect("the authority issues its certificate");
			let issue = |cn: &str| {
				let uris = [colony.as_str()];
				let issued = TestCertificate::issued_with_uri_sans(&authority_key, AUTHORITY, &gateway_key, cn, &uris);
				issued.expect("the authority issues a gateway certificate")
			};

			let enrolled = issue("Signer Gateway");
			let rotated = issue("Signer Gateway Rotated");
			let member = TestCertificate::with_uri_sans(&member_key, &[&colony]);

			let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
			let builder = builder.with_certificate(authority).expect("the store admits it");
			let builder = builder.with_certificate(enrolled.clone()).expect("the store admits it");
			let peer_trust: Arc<dyn CertificateTrust> = Arc::new(builder.build());

			let spec = CertificateSpec::Built(Box::new(member.clone()));
			let tls = ClusterTlsConfig::new(spec, Arc::new(Secp256k1KeyProvider::from(member_key)));
			let tls = tls.expect("the member certificate must decode").with_peer_trust(peer_trust);
			let config = ClusterConfig::builder(tls).with_tried_per_signer(NonZeroUsize::MIN).build();
			let config = ColonyConfig::new(config);

			let trace = Arc::new(scenario.share());
			let pools = config.tls.pools::<TokioListener>(&config.pool_config, &config.clock, &trace);
			let peer_pool = pools.peer.expect("a peer trust builds a peer pool");
			let peer_plane = PeerPlane::new(peer_pool, config.clone(), Arc::clone(&trace));
			let registry = Arc::new(ServletRegistry::new(config.pheromone.clone(), Arc::clone(&config.clock)));
			let beat = FloodBeat::new(config, peer_plane, registry, trace, Arc::default());

			Self {
				beat: beat.expect("a colony member is in a flood"),
				enrolled: Self::serve(enrolled, &gateway_key, &member, scenario).await,
				rotated: Self::serve(rotated, &gateway_key, &member, scenario).await,
			}
		}

		/// A gateway under `certificate` that enrolls `member`, answers its
		/// reconcile round, and records on `trace`.
		async fn serve(
			certificate: Certificate,
			key: &Secp256k1SigningKey,
			member: &Certificate,
			trace: &TraceCollector,
		) -> ClusterGateway<TokioListener> {
			let spec = CertificateSpec::Built(Box::new(certificate));
			let tls = ClusterTlsConfig::new(spec, Arc::new(Secp256k1KeyProvider::from(key.clone())));
			let enrolled = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
			let enrolled = enrolled.with_certificate(member.clone());
			let peer_trust: Arc<dyn CertificateTrust> = Arc::new(enrolled.expect("the member enrolls").build());
			let tls = tls.expect("the gateway certificate must decode").with_peer_trust(peer_trust);

			let gateway = ClusterGateway::start(Arc::new(trace.share()), ClusterConfig::new(tls)).await;
			gateway.expect("the gateway starts")
		}
	}

	// The discovery table names a gateway by the certificate the member
	// enrolls for its key, so a second certificate of that key at another
	// address takes no second slot under the signer cap (CWE-770).
	#[tokio::test]
	async fn a_rotated_certificate_counts_as_the_signer_its_key_enrolls() -> Result<(), TightBeamError> {
		let rotation = SignerRotation::start(&TraceCollector::default()).await;
		let beat = &rotation.beat;
		let enrolled = *rotation.enrolled.addr();
		let rotated = *rotation.rotated.addr();

		let first = beat.reconcile_round(enrolled, dial(&enrolled.to_string())).await;
		let second = beat.reconcile_round(rotated, dial(&rotated.to_string())).await;
		let learned = beat.config.peer.table.learned()?;
		assert_eq!([first.ok(), second.ok()], [Some(Round::Settled); 2]);
		assert_eq!(learned, (0, 1));
		Ok(())
	}

	/// The advertisement frame that a `MintedAdRumor` slate rumor carries.
	fn carried_ad_frame(minted: Option<MintedAdRumor>) -> Frame {
		let minted = minted.expect("the test identity mints a rumor");
		let rumor: GossipRumor = decode(minted.rumor.message()).expect("a minted rumor decodes");
		decode(&rumor.payload).expect("a slate rumor carries a frame")
	}

	/// The slate rumor that the test identity creates.
	fn minted_rumor(minted: Option<MintedAdRumor>) -> MintedAdRumor {
		minted.expect("the test identity mints a rumor")
	}

	// A beat witnesses its slate rumor under the digest its echo admits under,
	// so the journal refuses the echo that a peer floods back as a duplicate.
	#[tokio::test]
	async fn a_slate_rumor_carries_the_digest_its_echo_admits_under() -> Result<(), TightBeamError> {
		let config = ColonyConfig::<TokioListener>::new(test_config());
		let advertisement = config.mint_ad_frame(b"127.0.0.1:9000", ad_slate(&["ping"])).await?;
		let minted = minted_rumor(config.mint_slate_rumor(&advertisement).await);

		let echo = config.tls.verify_own(minted.rumor)?;
		let admitted = config.admit_rumor(&echo, 0, minted.minted_at);
		assert_eq!(admitted.map(|admitted| *admitted.digest()), Ok(minted.digest));
		Ok(())
	}

	// A beat's slate rumor wraps the frame the beat dials out directly, so both
	// copies carry one order. A receiver that admits either copy first then
	// admits the other, because its order ledger refuses only an older order.
	#[tokio::test]
	async fn a_slate_rumor_wraps_the_frame_its_beat_dials_out() -> Result<(), TightBeamError> {
		let clock = Arc::new(ManualClock::default());
		let mut config = test_config();
		config.clock = Arc::<ManualClock>::clone(&clock);

		let config = ColonyConfig::<TokioListener>::new(config);
		let advertisement = config.mint_ad_frame(b"127.0.0.1:9000", ad_slate(&["ping"])).await?;

		clock.advance(Duration::from_millis(1));

		let minted = config.mint_slate_rumor(&advertisement).await;
		assert_eq!(&carried_ad_frame(minted), advertisement.frame());
		Ok(())
	}

	// Each step names its event label, and only a step the peer failed
	// charges the peer.
	tb_cases! {
		fn a_round_end_names_its_label_and_its_charge((end, label, round): (RoundEnd, &str, Round)) {
			assert_eq!((end.label(), end.round()), (label, round));
		}
		cases {
			journal => (RoundEnd::Journal, "journal", Round::Settled),
			unreachable => (RoundEnd::Unreachable, "unreachable", Round::Failed),
			build => (RoundEnd::Build, "build", Round::Settled),
			sign => (RoundEnd::Sign, "sign", Round::Settled),
			reply => (RoundEnd::Reply, "reply", Round::Failed),
			bookkeeping => (RoundEnd::Bookkeeping, "bookkeeping", Round::Settled),
		}
	}

	/// A loopback socket that no listener holds, so a dial to it fails.
	fn closed_address() -> core::net::SocketAddr {
		let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port binds");
		listener.local_addr().expect("a bound listener has an address")
	}

	tb_assert_spec! {
		pub UnreachableRoundSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CLUSTER_RECONCILE_FAILED, exactly!(1), equals!(true))
			]
		}
	}

	// A round whose dial fails charges the peer, and its event says so.
	tb_scenario! {
		name: an_unreachable_peer_fails_its_round_on_the_record,
		spec: UnreachableRoundSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let stranger = TestCertificate::self_signed(&stranger_key());
				let beat = member_beat(&stranger, Arc::new(trace.share()));
				let closed = closed_address();

				let round = beat.reconcile_round(closed.into(), dial(&closed.to_string())).await;
				assert_eq!(round.ok(), Some(Round::Failed));
				Ok(())
			}
		}
	}

	/// Records, in `beat`'s journal, one application rumor that `beat`'s own
	/// identity signs at its clock reading, and returns its digest.
	async fn journal_a_rumor(beat: &FloodBeat<TokioListener>) -> Result<GossipDigest, TightBeamError> {
		let config = &beat.config;
		let now = config.clock.unix();
		let builder = FrameBuilder::from(Version::V2)
			.with_id(b"repaired")
			.with_order(now.get())
			.with_message(GossipRumor::application(vec![1, 2, 3]));

		let mut rumor = config.witnessed(builder).build()?;
		rumor.sign_with_provider(config.tls.identity()).await?;

		let verified = config.tls.verify_own(rumor)?;
		let admitted = config.admit_rumor(&verified, 0, now).expect("the member admits its own rumor");
		let rumor = verified.into_frame();
		let signer = rumor.signer_id().expect("a signed rumor names its signer");

		let digest = *admitted.digest();
		config.gossip.journal.record(&signer, digest, &rumor, rumor.issued_at(), now)?;
		Ok(digest)
	}

	tb_assert_spec! {
		pub AnsweredRoundSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CLUSTER_RECONCILE_ANSWERED, exactly!(1), equals!(1u64)),
				(CLUSTER_GOSSIP_REPAIR_PUSHED, exactly!(1), equals!(TransitStatus::Ok)),
				(CLUSTER_GOSSIP_ADMITTED, exactly!(1), equals!(0u64)),
				(CLUSTER_PEER_DISCOVERED, exactly!(1)),
				(CLUSTER_RECONCILE_FAILED, absent!())
			]
		}
	}

	// A member answers a round that holds one rumor it lacks. The member
	// records the answer and its want, the requester promotes the member and
	// pushes the rumor, and the member admits the push with no hop left.
	tb_scenario! {
		name: an_answered_round_records_the_answer_the_push_and_the_admission,
		spec: AnsweredRoundSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let rotation = SignerRotation::start(&trace).await;
				let beat = &rotation.beat;
				journal_a_rumor(beat).await?;

				let enrolled = *rotation.enrolled.addr();
				let round = beat.reconcile_round(enrolled, dial(&enrolled.to_string())).await;
				assert_eq!(round.ok(), Some(Round::Settled));
				Ok(())
			}
		}
	}

	/// A discovery hint for each socket of `sockets`.
	fn hints(sockets: &[&str]) -> Vec<PeerHint> {
		let config = test_config();
		let entries = sockets.iter().map(pex_entry);
		config.admissible_pex_hints(entries).collect()
	}

	/// The error a test reports for `fault`: the trace's own error, or the
	/// local fault that it carries.
	fn loop_error(fault: LoopFault) -> TightBeamError {
		match fault {
			LoopFault::Runtime(error) => error,
			LoopFault::Registry(error) => error.into(),
		}
	}

	tb_assert_spec! {
		pub LearnedHintsSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CLUSTER_PEER_HINTS_LEARNED, exactly!(1), equals!(2u64))
			]
		}
	}

	// A learn records the count of hints the table admits.
	tb_scenario! {
		name: a_learn_records_the_hints_the_table_admits,
		spec: LearnedHintsSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| {
				let config = test_config();
				let source = HintSource::Pex(PeerAddress::fixture("10.0.0.9:9000"));
				let now = UnixMillis::new(1_000);
				let offered = hints(&["10.0.0.1:9000", "10.1.0.1:9000"]);

				config.learn_hints(&trace, source, offered, now).map_err(loop_error)?;
				Ok(())
			}
		}
	}

	tb_assert_spec! {
		pub EmptyLearnSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CLUSTER_PEER_HINTS_LEARNED, exactly!(1), equals!(1u64))
			]
		}
	}

	// A learn that admits no hint records nothing. The learn after it admits
	// one hint, so its record proves the trace reaches the table, and the one
	// record proves that the empty learn leaves none.
	tb_scenario! {
		name: a_learn_that_admits_no_hint_records_nothing,
		spec: EmptyLearnSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| {
				let config = test_config();
				let source = HintSource::Pex(PeerAddress::fixture("10.0.0.9:9000"));
				let now = UnixMillis::new(1_000);

				config.learn_hints(&trace, source, hints(&[]), now).map_err(loop_error)?;
				config.learn_hints(&trace, source, hints(&["10.0.0.1:9000"]), now).map_err(loop_error)?;
				Ok(())
			}
		}
	}

	/// The advertisement of `peer` at `dial`, at `order`, whose slate names
	/// `types`, each route abandoned after `limit` failures.
	fn advertisement(
		peer: &[u8],
		dial: AdmittedDial,
		types: &[&[u8]],
		order: u64,
		limit: NonZeroU32,
	) -> AdmittedPeerAd {
		let route = |servlet_type: &&[u8]| {
			let route = PeerRoute { peer_id: Arc::from(peer), servlet_type: Arc::from(*servlet_type), dial };
			ServletEntry::peer(route, DEFAULT_INITIAL_PHEROMONE, limit)
		};

		let slate = types.iter().map(route).collect();
		AdmittedPeerAd { peer_hive_id: Arc::from(peer), dial, slate, order: UnixMillis::new(order) }
	}

	/// The advertisement of `gw` at the fixture socket, at `order`, whose
	/// slate names `types`.
	fn fixture_advertisement(types: &[&[u8]], order: u64) -> AdmittedPeerAd {
		advertisement(b"gw", dial("127.0.0.1:9000"), types, order, DEFAULT_ABANDONMENT_LIMIT)
	}

	/// A registry on the fixture config, which holds no route yet.
	fn empty_registry() -> ServletRegistry {
		let config = test_config();
		ServletRegistry::new(config.pheromone.clone(), Arc::clone(&config.clock))
	}

	tb_assert_spec! {
		pub FirstSlateSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CLUSTER_PEER_ROUTES_INSTALLED, exactly!(1), equals!(2u64)),
				(CLUSTER_PEER_ROUTES_WITHDRAWN, absent!())
			]
		}
	}

	// A first slate records the routes it installs.
	tb_scenario! {
		name: a_first_slate_records_its_installs,
		spec: FirstSlateSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| {
				let registry = empty_registry();
				let first = fixture_advertisement(&[b"ping", b"echo"], 1);
				let first = registry.reconcile_peer_slate(first, PeerCaps::default())?;
				first.record_direct(&trace, b"gw")?;
				Ok(())
			}
		}
	}

	tb_assert_spec! {
		pub ShrunkSlateSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CLUSTER_PEER_ROUTES_INSTALLED, exactly!(1), equals!(2u64)),
				(CLUSTER_PEER_ROUTES_WITHDRAWN, exactly!(1), equals!(1u64))
			]
		}
	}

	// A slate that leaves out a held route records its withdrawal.
	tb_scenario! {
		name: a_shrunk_slate_records_its_withdrawal,
		spec: ShrunkSlateSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| {
				let registry = empty_registry();
				let first = fixture_advertisement(&[b"ping", b"echo"], 1);
				let first = registry.reconcile_peer_slate(first, PeerCaps::default())?;
				first.record_direct(&trace, b"gw")?;

				let shrunk = fixture_advertisement(&[b"ping"], 2);
				let shrunk = registry.reconcile_peer_slate(shrunk, PeerCaps::default())?;
				shrunk.record_direct(&trace, b"gw")?;
				Ok(())
			}
		}
	}

	// A refresh of the held slate records nothing. The first slate's install
	// proves the trace reaches the registry, and its one record proves that
	// the refresh leaves none.
	tb_scenario! {
		name: a_refreshed_slate_records_nothing,
		spec: FirstSlateSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| {
				let registry = empty_registry();
				let first = fixture_advertisement(&[b"ping", b"echo"], 1);
				let first = registry.reconcile_peer_slate(first, PeerCaps::default())?;
				first.record_direct(&trace, b"gw")?;

				let refreshed = fixture_advertisement(&[b"ping", b"echo"], 2);
				let refreshed = registry.reconcile_peer_slate(refreshed, PeerCaps::default())?;
				refreshed.record_direct(&trace, b"gw")?;
				Ok(())
			}
		}
	}

	/// Runs `rounds` reconcile rounds against `peer` at the closed `address`,
	/// each of which fails, and returns the first fault of a round.
	async fn fail_rounds(
		beat: &FloodBeat<TokioListener>,
		address: core::net::SocketAddr,
		peer: AdmittedDial,
		rounds: usize,
	) -> Result<(), LoopFault> {
		for _ in 0..rounds {
			beat.reconcile_target(address.into(), peer, &beat.trace).await?;
		}

		Ok(())
	}

	tb_assert_spec! {
		pub EvictedPeerSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CLUSTER_RECONCILE_FAILED, exactly!(3), equals!(true)),
				(CLUSTER_PEER_ROUTES_WITHDRAWN, exactly!(1), equals!(1u64)),
				(CLUSTER_PEER_EVICTED, exactly!(1))
			]
		}
	}

	// The failed round at the eviction threshold withdraws the route that
	// dials the peer, and records the count before the eviction.
	tb_scenario! {
		name: an_evicted_peer_withdraws_the_routes_that_dial_it,
		spec: EvictedPeerSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let stranger = TestCertificate::self_signed(&stranger_key());
				let beat = member_beat(&stranger, Arc::new(trace.share()));
				let closed = closed_address();
				let peer = dial(&closed.to_string());
				beat.config.peer.table.promote(peer, None, UnixMillis::now())?;

				let slate = advertisement(b"gw", peer, &[b"ping"], 1, DEFAULT_ABANDONMENT_LIMIT);
				beat.servlet_registry.reconcile_peer_slate(slate, PeerCaps::default())?;

				fail_rounds(&beat, closed, peer, MAX_PEER_TRIED_FAILURES).await.map_err(loop_error)?;
				Ok(())
			}
		}
	}

	tb_assert_spec! {
		pub DroppingTargetSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CLUSTER_GOSSIP_DROP_SIGNAL, exactly!(1)),
				(CLUSTER_PEER_ROUTE_ABANDONED, exactly!(1), equals!(1u64))
			]
		}
	}

	// A target that wants again a rumor it acknowledged drops rumors, so the
	// round weakens the route that dials it, here to its abandonment limit.
	tb_scenario! {
		name: a_dropping_target_abandons_the_route_that_dials_it,
		spec: DroppingTargetSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let rotation = SignerRotation::start(&trace).await;
				let beat = &rotation.beat;
				let digest = journal_a_rumor(beat).await?;
				let enrolled = *rotation.enrolled.addr();
				let peer = dial(&enrolled.to_string());

				beat.ledgers.with(peer, |ledger| ledger.ack(digest));
				let slate = advertisement(b"gw", peer, &[b"ping"], 1, NonZeroU32::MIN);
				beat.servlet_registry.reconcile_peer_slate(slate, PeerCaps::default())?;

				let round = beat.reconcile_round(enrolled, peer).await;
				assert_eq!(round.ok(), Some(Round::Settled));
				Ok(())
			}
		}
	}

	tb_assert_spec! {
		pub SkippedBookkeepingSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CLUSTER_RECONCILE_ANSWERED, exactly!(1)),
				(CLUSTER_RECONCILE_FAILED, exactly!(1), equals!(false))
			]
		}
	}

	// A poisoned table fails the promotion after the member answers, so the
	// round records the skipped bookkeeping and leaves the score alone.
	tb_scenario! {
		name: a_local_fault_after_the_reply_skips_the_round_on_the_record,
		spec: SkippedBookkeepingSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let rotation = SignerRotation::start(&trace).await;
				let beat = &rotation.beat;
				beat.config.peer.table.poison();

				let enrolled = *rotation.enrolled.addr();
				let round = beat.reconcile_round(enrolled, dial(&enrolled.to_string())).await;
				assert_eq!(round.ok(), Some(Round::Settled));
				Ok(())
			}
		}
	}

	/// The error each fault of these tests injects.
	#[cfg(feature = "testing-fault")]
	fn closed() -> TightBeamError {
		TightBeamError::ChannelClosed
	}

	// A trace that refuses a bookkeeping event ends the beat, so a fault
	// injected at the promotion reaches the beat's exit.
	#[cfg(feature = "testing-fault")]
	#[tokio::test]
	async fn a_trace_fault_in_the_bookkeeping_ends_the_beat() -> Result<(), TightBeamError> {
		use crate::testing::fdr::FaultModel;

		let model = FaultModel::default().with_event_fault(CLUSTER_PEER_DISCOVERED, closed, crate::bps!(10000));
		let trace = TraceCollector::new().with_fault_model(model);
		let rotation = SignerRotation::start(&trace).await;
		let enrolled = *rotation.enrolled.addr();

		let round = rotation.beat.reconcile_round(enrolled, dial(&enrolled.to_string())).await;
		assert!(matches!(round, Err(LoopFault::Runtime(TightBeamError::ChannelClosed))));
		Ok(())
	}
}
