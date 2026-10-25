//! The gossip background tasks of the cluster advertise beat.
//!
//! The beat re-announces the local slate, publishes origin-signed
//! advertisement rumors, and runs anti-entropy reconcile rounds against
//! verified peers and feeler probes.
//!
//! # Planes
//!
//! - **Direct advertisement**: one signed frame goes to every beat target.
//! - **Rumor flood**: the same signed frame, wrapped in a gossip rumor, reaches members beyond direct reach.
//! - **Pipeline**: the gateway admits an inbound rumor, rate-limits it,
//!   journals it, delivers it locally, and refloods it.
//! - **Reconcile**: anti-entropy rounds repair missing rumors and learn peer-exchange hints.

use core::str::from_utf8;
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

use crate::builder::frame::FrameBuilder;
use crate::builder::TypeBuilder;
use crate::colony::cluster::gossip::{LocalClaimGuard, RumorConsumer};
use crate::colony::cluster::peer::AdmittedPeerAd;
use crate::colony::cluster::runtime::advertise::{Advertiser, SignedAdvertisement};
use crate::colony::cluster::runtime::bounds::{ColonyConfig, ColonyDialProtocol, ColonyDigest, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::hop::{FloodClient, HivePlane, PeerPlane};
use crate::colony::cluster::runtime::refuse::Refusal;
use crate::colony::cluster::runtime::work::RouteChoice;
use crate::colony::cluster::runtime::{LoopFault, VerifiedSignerId};
use crate::colony::cluster::{
	gossip_fresh, wanted_digests, Admission, AdmittedGossip, GossipDigest, PeerCaps, PeerHint, RouteKind, VerifiedRumor,
};
use crate::colony::cluster::{AdmittedDial, ClusterConfig, ClusterError, PeerAddress, ServletRegistry};
use crate::colony::common::IssuedAt;
use crate::colony::common::{reply_frame, TaskGroup};
use crate::colony::common::{
	ClusterRequest, GossipReconciliation, GossipResponse, GossipRumor, GossipWant, PeerGossip,
};
use crate::constants::{MAX_ADVERTISED_TYPES, MAX_GOSSIP_LOG, MAX_GOSSIP_TTL, MAX_PEX_SAMPLE};
use crate::decode;
use crate::encode;
use crate::instrumentation::events::{
	CLUSTER_GOSSIP_ACCEPTED, CLUSTER_GOSSIP_DROP_SIGNAL, CLUSTER_GOSSIP_DUPLICATE, CLUSTER_GOSSIP_FANOUT_UNREACHED,
	CLUSTER_GOSSIP_ORIGIN_REFUSED_BY_PEER, CLUSTER_GOSSIP_REFLOOD_FAILED, CLUSTER_GOSSIP_RELAY_WEAKENED,
	CLUSTER_GOSSIP_WITNESS_REFUSED, CLUSTER_PEER_DISCOVERED, CLUSTER_PEER_EVICTED, CLUSTER_PEER_EXPELLED,
};
use crate::instrumentation::events::{
	CLUSTER_PEER_AD_DROPPED, CLUSTER_PEER_AD_LEARNED, CLUSTER_PEER_AD_PUBLISH_FAILED, CLUSTER_RELAY_TRAIL_REFUSED,
};
use crate::policy::TransitStatus;
use crate::runtime::rt;
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
	/// A local publish. An admission failure refuses and scores no trail.
	Origin,
}

impl GossipOrigin {
	/// The frame whose signer owns this rumor's rate and journal budget.
	///
	/// A relay hop signs the outer frame, so the origin's own signature
	/// on the inner rumor is what a relayed invocation spends against.
	fn attributed<'a>(self, frame: &'a Frame, rumor: &'a Frame) -> &'a Frame {
		match self {
			Self::Origin => frame,
			Self::Relay => rumor,
		}
	}
}

impl<P: Protocol> GatewayRuntimeCtx<P> {
	/// The plane this gateway dials peers on.
	///
	/// A configured peer plane keeps peer traffic off the hive pool. With
	/// no peer plane the hive pool serves both.
	pub(crate) fn peer_dial_plane(&self) -> PeerPlane<P> {
		match self.peer_plane.as_ref() {
			Some(peer_plane) => peer_plane.clone(),
			None => self.hive_plane.peers(self.config.clone()),
		}
	}
}

/// One signed advertisement rumor ready to witness and flood.
struct MintedAdRumor {
	rumor: Frame,
	digest: GossipDigest,
	signer_id: Vec<u8>,
	minted_at: UnixMillis,
}

impl ServletRegistry {
	/// The dial socket of a relaying peer, from its live direct routes.
	///
	/// Only direct routes qualify, because a relay entry's dial address
	/// belongs to a further relay while a direct route holds `relay_id`'s
	/// own. [`None`] means the relay reached this gateway through another
	/// hop, so the direct trail from the rumor stands on its own.
	fn relay_dial_addr(&self, relay_id: impl AsRef<[u8]>) -> Option<PeerAddress> {
		let relay_id = relay_id.as_ref();
		let entries = self.peer_entries().ok()?;
		entries
			.iter()
			.filter(|entry| entry.route_kind() == RouteKind::Peer)
			.find(|entry| entry.owner_id().as_ref() == relay_id)
			.and_then(|entry| entry.dial_target().socket())
	}
}

impl<P: ColonyDialProtocol> ColonyConfig<P> {
	/// Creates, signs, and digests one advertisement rumor for a beat.
	///
	/// The rumor wraps `advertisement`, the [`ColonyConfig::mint_ad_frame`]
	/// frame that the beat dials out directly, so both copies carry one order.
	/// The method extracts the digest and signer id for witness and reflood.
	///
	/// It returns [`None`] on a local fault (key, codec, or journal input).
	/// The caller records it, and a later beat re-publishes fresh.
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
	/// - Every refusal of [`AdmittedGossip::admit`].
	pub(crate) fn admit_rumor(
		&self,
		rumor: &VerifiedRumor,
		hop_ttl: u64,
		now: UnixMillis,
	) -> Result<AdmittedGossip, TransitStatus> {
		AdmittedGossip::admit::<ColonyDigest<P>>(rumor, hop_ttl, self.gossip.seen_ttl, now)
	}

	/// The entries of a peer's `want` list that read as rumor digests under
	/// the colony digest, by the rule of [`wanted_digests`].
	pub(crate) fn wanted_digests(&self, want: impl AsRef<[Vec<u8>]>) -> Vec<GossipDigest> {
		wanted_digests::<ColonyDigest<P>>(want)
	}
}

impl ClusterConfig {
	/// Whether `order` sits inside this colony's control freshness window.
	///
	/// The gossip journal deduplicates rumors by digest, so the rumor path
	/// relies on it where a signed control frame passes a replay guard. This
	/// bound keeps the two paths admitting the same orders.
	///
	/// # Fail-closed
	///
	/// - Admission requires an order inside the window, so the ad-order
	///   tombstone covers every replay that reaches reconcile (CWE-294).
	/// - Admission refuses a far-future order, so every ledger row stays prunable (CWE-770).
	fn ad_order_fresh(&self, order: UnixMillis, now: UnixMillis) -> bool {
		now.abs_diff(order) <= self.control_freshness_window
	}

	/// The peer-exchange hints that this gateway may learn.
	///
	/// An entry becomes a hint through [`PeerConfig::admit_hint`], so a
	/// later feeler probe dials only addresses the operator's dial policy
	/// admitted (CWE-284).
	///
	/// [`PeerConfig::admit_hint`]: crate::colony::cluster::PeerConfig::admit_hint
	fn admissible_pex_hints(&self, pex: impl IntoIterator<Item = PeerGossip>) -> impl Iterator<Item = PeerHint> + '_ {
		let pex: Vec<PeerGossip> = pex.into_iter().collect();

		pex.into_iter().filter_map(move |entry| self.peer.admit_hint(entry).ok())
	}
}

impl GossipWant {
	/// Whether this reconcile reply exceeds its protocol bounds.
	///
	/// A conforming gateway holds its reply to [`MAX_GOSSIP_LOG`] wants
	/// and [`MAX_PEX_SAMPLE`] peer-exchange entries, so an oversized reply
	/// is abuse and the requester drops the whole round (CWE-770).
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

/// The ledger of every gossip target, behind one lock.
///
/// The beat's repair and each inbound reflood both record what a target
/// answered, so the gateway holds one map and shares it. [`Self::with`] takes
/// the lock and releases it before it returns, so no guard crosses an await.
///
/// # Poison recovery
///
/// Each write is one insert or one removal on a set or a map, so a panic
/// cannot leave a ledger half-written, and every method recovers a poisoned
/// guard rather than stop the flood.
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

	/// Keeps the ledgers of the targets `live` names, and forgets every
	/// refusal older than `window`.
	///
	/// The table's caps bound the live set, so they bound this map (CWE-770).
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

	/// Decides whether the target drops rumors it acknowledged, and forgets
	/// the acknowledgement of every digest in `wanted`.
	///
	/// A digest this gateway saw acknowledged, wanted again while retained,
	/// is a drop.
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

	/// Decides whether this gateway offers a rumor of `origin` to the target.
	///
	/// A refusal stands for `window`. This gateway then offers the origin once
	/// more, so a target that enrolled it since catches up.
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

/// The direct-advertisement arm of the advertise beat.
///
/// Every gateway with a dial list runs it, in a flood or in none.
struct AdvertiseBeat<P: Protocol> {
	config: ColonyConfig<P>,
	advertiser: Advertiser<P>,
	servlet_registry: Arc<ServletRegistry>,
}

/// The gossip arm of the advertise beat and of the inbound pipeline:
/// reconcile rounds, feeler probes, the slate rumor, refloods, and repairs.
///
/// The beat and the inbound reflood both reach peers through this one
/// owner, so a rumor leaves on the same plane either way. [`Self::new`]
/// returns a beat only for a gateway that is in a flood, so every method
/// here runs on a flood member.
struct FloodBeat<P: Protocol> {
	config: ColonyConfig<P>,
	peer_plane: PeerPlane<P>,
	servlet_registry: Arc<ServletRegistry>,
	trace: Arc<TraceCollector>,
	ledgers: Arc<PeerLedgers>,
}

impl<P: Protocol> FloodBeat<P> {
	/// The gossip arm of a gateway that is in a flood, or `None` for a
	/// gateway that is in none.
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

		let event = self.trace.event(CLUSTER_GOSSIP_ORIGIN_REFUSED_BY_PEER)?;
		event.with_payload(target.address().route_bytes().as_ref()).emit();

		Ok(())
	}

	/// Whether this gateway offers a rumor of `origin` to `target`. A rumor
	/// with no signer names no origin that a target could have refused, so
	/// this gateway offers it.
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

// The impl is manual because a derive would demand `P: Clone`, and the
// fields are reference-counted regardless of `P`.
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
	/// The advertised types that this gateway exports, capped at
	/// [`MAX_ADVERTISED_TYPES`].
	///
	/// This is the single place that gathers advertised types, so one
	/// export filter covers the direct ads and the rumor flood. The filter
	/// asks membership per key each beat, so a live `ExportAllowlist` stays
	/// aligned with enforcement.
	fn exported_slate(&self) -> Result<Vec<Urn<'static>>, ClusterError> {
		let exports = self.config.peer.exported_types.as_deref();
		let local = self.servlet_registry.local_servlets()?;
		let slate = local
			.iter()
			.filter(|bytes| exports.is_none_or(|list| list.allows_canonical(bytes)))
			.filter_map(|bytes| from_utf8(bytes).ok())
			.filter_map(|canonical| canonical.parse().ok())
			.take(MAX_ADVERTISED_TYPES)
			.collect();

		Ok(slate)
	}

	/// Advertises to every beat target, and hands each one to the flood arm
	/// when this gateway has one.
	///
	/// `advertisement` is the single signed advertisement this beat created,
	/// so one signature serves every dial.
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
			// choice, so the beat skips the peer rather than score it.
			let Ok(peer_addr) = peer.protocol_address::<P::Address>() else {
				continue;
			};

			if let Some(advertisement) = advertisement {
				// The address clones, because the reconcile below reuses it.
				// The reconcile round scores a failed dial, so the status goes
				// unread.
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
	/// Refloods a still-live rumor to the dial targets with a decremented TTL.
	///
	/// Targets are anchors plus verified tried peers. Each dial proves the
	/// answer is a flood member in [`PeerPlane::connect_member`] before the
	/// rumor leaves, so a configured peer outside the flood receives none
	/// (CWE-668). Each target receives an owned clone of the signed frame
	/// because emit consumes the frame.
	///
	/// # Re-encoding
	///
	/// The reflood re-encodes the decoded rumor when it embeds it. DER is
	/// canonical (ITU-T X.690 §10), so the bytes equal the received bytes, and
	/// the origin signature and the witness digest survive the hop. A splice
	/// of the pre-encoded bytes would need an opaque passthrough field in the
	/// codec, a redesign that buys no correctness.
	async fn reflood(&self, rumor: Frame, ttl: u64) -> Result<(), LoopFault> {
		let targets = self.config.peer.table.target_set()?;
		if targets.is_empty() {
			return Ok(());
		}

		// A target that answered this origin as outside its trust gets none
		// of its rumors until that answer expires.
		let origin = rumor.signer_id();
		let now = self.config.clock.unix();

		// The rumor re-encodes to the bytes that arrived, so the origin
		// signature still verifies at the next hop.
		let request = ClusterRequest::Gossip(Box::new(rumor));
		let builder = FrameBuilder::from(Version::V2)
			.with_id(b"gossip-reflood")
			.with_message(request)
			.with_priority(MessagePriority::NetworkControl)
			.with_lifetime(ttl);
		let mut signed_frame = match self.config.witnessed(builder).build() {
			Ok(signed_frame) => signed_frame,
			Err(_unbuilt) => {
				self.trace.event(CLUSTER_GOSSIP_REFLOOD_FAILED)?;

				return Ok(());
			}
		};

		let signing = signed_frame.sign_with_provider(self.config.tls.identity()).await;
		if signing.is_err() {
			self.trace.event(CLUSTER_GOSSIP_REFLOOD_FAILED)?;
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
			// Each emit consumes an owned frame, so a fan-out to N targets
			// needs N owned frames. The clone is that fan-out cost.
			let frame = signed_frame.clone();
			fanout.spawn(async move {
				let Ok(answered) = dial_plane.connect_member(peer_addr).await else {
					return FloodHop::Unreached;
				};
				// A gateway outside the flood is owed no rumor, so the hop ends
				// without an emit.
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

		// A down peer must not stop the flood to the live ones, so the reflood
		// counts a failed hop rather than return it. A task that did not join
		// reached no peer either, so it folds into the same count.
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
			self.trace.event_with(CLUSTER_GOSSIP_FANOUT_UNREACHED, &[], unreached)?;
		}

		Ok(())
	}

	/// Publishes the local slate as an origin-signed advertisement rumor.
	///
	/// The rumor wraps the identical signed frame that direct advertisement
	/// dials out, so members beyond direct reach admit through the same
	/// signer-binds-to-address path once the flood relays it.
	///
	/// # Journal
	///
	/// - The beat witnesses the published digest for deduplication alone, so
	///   the origin's own echo arrives as a duplicate.
	/// - Retention serves repair and retry, which advertisements forgo. They
	///   are ephemeral hints that re-publish keeps fresh, and the origin
	///   already holds the slate it published.
	/// - A journal that refuses the witness leaves this gateway able to
	///   re-admit its own echo. The rumor is already created, so the beat
	///   traces [`CLUSTER_GOSSIP_WITNESS_REFUSED`] and floods the live rumor
	///   anyway.
	///
	/// # Failures
	///
	/// A beat that built no advertisement, or a creation fault, returns
	/// `false`, traces [`CLUSTER_PEER_AD_PUBLISH_FAILED`], and leaves the
	/// caller's publish baseline intact so the next beat retries.
	async fn publish_slate_rumor(&self, advertisement: Option<&SignedAdvertisement>) -> Result<bool, LoopFault> {
		let minted = match advertisement {
			Some(advertisement) => self.config.mint_slate_rumor(advertisement).await,
			None => None,
		};
		let Some(minted) = minted else {
			self.trace.event(CLUSTER_PEER_AD_PUBLISH_FAILED)?;
			return Ok(false);
		};

		// The rumor is already live, so the beat records a refused witness and
		// the flood goes ahead.
		if self
			.config
			.gossip
			.journal
			.witness(&minted.signer_id, minted.digest, minted.minted_at)
			.is_err()
		{
			self.trace.event(CLUSTER_GOSSIP_WITNESS_REFUSED)?;
		}

		// The stamped lifetime is the budget remaining after this first
		// hop arrives, the same value the pipeline stamps when it refloods
		// a published rumor.
		let hop_ttl = u64::from(self.config.gossip.ttl.min(MAX_GOSSIP_TTL));
		self.reflood(minted.rumor, hop_ttl.saturating_sub(1)).await?;

		Ok(true)
	}

	/// Runs one anti-entropy reconcile round with a peer, and scores the
	/// grey-hole drops the round finds.
	///
	/// A [`Round::Failed`] is peer-attributable, so the beat loops score it
	/// toward eviction or probe discard. A local fault skips its own step, or
	/// ends the beat as a [`LoopFault`] when it does not clear, which keeps
	/// every score attributable to the peer alone.
	///
	/// # Round order
	///
	/// 1. Collect the held digests from the journal.
	/// 2. Complete the handshake and prove flood membership.
	/// 3. Emit a signed reconcile request and decode the reply.
	/// 4. Reject an oversized want-list or PEX sample.
	/// 5. Promote the peer, learn PEX hints, and score grey-hole drops.
	/// 6. Repair missing rumors from the journal.
	///
	/// # Fault attribution
	///
	/// - A local fault before the emit or inside the post-reply scope leaves the peer unscored.
	/// - An oversized reply or a dial failure returns [`Round::Failed`], so the caller scores the peer.
	/// - A learned peer outside the flood leaves the peer table at once and keeps its routes.
	/// - A poisoned peer table at that expulsion ends the beat as
	///   [`LoopFault::Registry`], and the peer's score stands.
	///
	/// # Errors
	///
	/// - [`LoopFault`] -- the errors of [`Self::expel`].
	async fn reconcile_round(&self, peer_addr: P::Address, peer: AdmittedDial) -> Result<Round, LoopFault> {
		let now = self.config.clock.unix();
		// A journal fault belongs to this gateway, so this gateway skips the
		// round, and every score stays attributable to the peer.
		let Ok(held_digests) = self.config.gossip.journal.held_digests(now) else {
			return Ok(Round::Settled);
		};
		// The reconciliation message type carries digests as owned OCTET
		// STRING bytes, so each digest copies once here.
		let held: Vec<Vec<u8>> = held_digests.iter().map(|digest| digest.as_bytes().to_vec()).collect();

		// The round proves membership on the completed handshake, before the
		// reconcile discloses anything (CWE-668).
		let Ok(answered) = self.peer_plane.connect_member(peer_addr).await else {
			return Ok(Round::Failed);
		};
		let Some(mut client) = answered else {
			// An answer from outside the flood is definitive, so a learned
			// address leaves both learned tables at once. A configured anchor
			// keeps its slot, so each beat still advertises to it. The routes
			// stay, because that gateway may serve work by direct peering and
			// each forward is bound to the gateway its route names.
			self.expel(peer)?;

			return Ok(Round::Settled);
		};

		let request = ClusterRequest::ReconcileGossip(GossipReconciliation { held });

		// The frame build and the signature are local. A fault here happened
		// before the round asked the peer anything, so this gateway skips the
		// round rather than score it.
		let builder = FrameBuilder::from(Version::V2)
			.with_id(b"gossip-reconcile")
			.with_order(now.get())
			.with_message(request)
			.with_priority(MessagePriority::NetworkControl);
		let Ok(mut signed_frame) = self.config.witnessed(builder).build() else {
			return Ok(Round::Settled);
		};

		let signing = signed_frame.sign_with_provider(self.config.tls.identity()).await;
		if signing.is_err() {
			return Ok(Round::Settled);
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
			return Ok(Round::Failed);
		};

		let local_round = self.settle_round(&mut client, reply, peer, now).await;
		// A decoded, in-bounds reply proves liveness, so a local fault in the
		// bookkeeping skips the rest of the round, and the peer's score stands.
		// The next beat retries the skipped bookkeeping and repair.
		let _ = local_round;

		Ok(Round::Settled)
	}

	/// Takes `peer`, which answered from outside the flood, out of the peer
	/// table, and records it as [`CLUSTER_PEER_EXPELLED`] with the address as
	/// its payload.
	///
	/// A poisoned table is this gateway's fault, so it ends the caller's loop,
	/// and every peer's score stands.
	///
	/// # Errors
	///
	/// - [`LoopFault::Registry`] -- the table lock is poisoned.
	/// - [`LoopFault::Runtime`] -- the trace refused the event.
	fn expel(&self, peer: AdmittedDial) -> Result<(), LoopFault> {
		self.config.peer.table.expel(peer)?;

		let event = self.trace.event(CLUSTER_PEER_EXPELLED)?;
		event.with_payload(peer.address().route_bytes().as_ref()).emit();

		Ok(())
	}

	/// Applies one answered round's bookkeeping: promotion, PEX hints,
	/// grey-hole scores, and journal repair.
	///
	/// Every step here is local, so a fault skips the rest of the round
	/// and leaves the peer scored on the answer it already gave.
	async fn settle_round(
		&self,
		client: &mut FloodClient<P>,
		reply: GossipWant,
		peer: AdmittedDial,
		now: UnixMillis,
	) -> Result<(), ClusterError> {
		let round: Result<(), ClusterError> = async {
			// A pooled connection keeps its handshake certificate after the
			// peer dies, so promotion waits for the reply. The membership
			// proof alone would reset the failure count every beat and hold a
			// dead peer.
			let answer = client.peer_certificate();
			let peer_id = answer.and_then(|answer| self.config.peer_identity(answer));
			if self.config.peer.table.promote(peer, peer_id.as_deref(), now)? {
				self.trace
					.event(CLUSTER_PEER_DISCOVERED)?
					.with_payload(peer.address().route_bytes().as_ref())
					.emit();
			}

			let GossipWant { want, pex } = reply;

			// PEX entries are unverified hints: the allowlist gates them, the
			// capped new table holds them, and a later feeler probe that proves
			// membership is the only path to a dial target (CWE-345).
			let hints = self.config.admissible_pex_hints(pex);
			self.config.peer.table.learn(hints, now)?;

			let wanted: Vec<GossipDigest> = self.config.wanted_digests(&want);

			// Grey-hole containment: one weaken per round scores a target whose
			// ledger shows drops of rumors it acknowledged.
			let dropping = self.ledgers.with(peer, |ledger| ledger.drop_signal(&wanted));
			if dropping {
				self.servlet_registry.weaken_peer_by_dial(peer.address())?;
				self.trace.event(CLUSTER_GOSSIP_DROP_SIGNAL)?;
			}

			self.push_repairs(client, &wanted, peer).await
		}
		.await;

		round
	}

	/// Reconciles with one beat target, and counts a failed round toward its
	/// eviction.
	///
	/// A dead tried peer frees its bucket slot at the threshold, and the
	/// routes that dial it leave the registry.
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

		// The routes that dial the evicted address leave before the beat
		// emits the eviction event, so an observer of the event finds none
		// of them.
		self.servlet_registry.withdraw_peer_by_dial(peer.address())?;

		trace
			.event(CLUSTER_PEER_EVICTED)?
			.with_payload(peer.address().route_bytes().as_ref())
			.emit();

		Ok(())
	}

	/// Reconciles with unverified candidates and records the ones that fail.
	///
	/// Feeler probes run reconcile only, and the membership proof inside the
	/// round promotes a verified candidate. A failed round stays on its
	/// candidate, which then waits out its backoff behind every fresher one in
	/// its prefix bucket.
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

	/// Resends the journaled rumors that this peer still wants.
	///
	/// - Each push carries an outer lifetime of 0, so a repair never refloods.
	/// - Only a rumor still inside the seen window is admissible.
	/// - Only an explicit `Ok` reply arms the grey-hole ledger.
	/// - The peer names every digest it lacks, and it lacks for good the
	///   rumors of an origin its trust does not hold. Its first refusal of
	///   such an origin settles that origin for the window, so this gateway
	///   offers the push once.
	async fn push_repairs(
		&self,
		client: &mut FloodClient<P>,
		wanted: impl AsRef<[GossipDigest]>,
		peer: AdmittedDial,
	) -> Result<(), ClusterError> {
		let wanted = wanted.as_ref();
		let now = self.config.clock.unix();
		let seen_ttl = self.config.gossip.seen_ttl;
		let missing = self.config.gossip.journal.fetch(wanted, now)?;
		let admissible = missing
			.into_iter()
			.filter(|(_, rumor)| gossip_fresh(rumor.issued_at(), seen_ttl, now));

		for (pushed_digest, rumor) in admissible {
			let origin = rumor.signer_id();
			if !self.offers(peer, origin.as_deref(), now) {
				continue;
			}

			let push = ClusterRequest::Gossip(Box::new(rumor));
			let builder = FrameBuilder::from(Version::V2)
				.with_id(b"gossip-repair")
				.with_message(push)
				.with_priority(MessagePriority::NetworkControl)
				.with_lifetime(0);
			let mut signed = self.config.witnessed(builder).build()?;

			signed.sign_with_provider(self.config.tls.identity()).await?;

			let Some(push_reply) = client.emit(signed, None).await? else {
				continue;
			};
			let Ok(gossip_reply) = decode::<GossipResponse>(push_reply.message()) else {
				continue;
			};

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
	/// so a stop of the gateway stops a reflood that still dials.
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
	///   names the gateway that published the rumor, so a servlet that serves
	///   many parties can tell them apart and verify each one.
	/// - The task takes the claim before the round trip, and a guard owns it,
	///   so the admission path and the reconcile beat never deliver one rumor
	///   twice (CWE-362).
	/// - A delivery this task never finishes returns the rumor to the retry set.
	async fn deliver_local(&self, rumor: Frame, digest_value: GossipDigest) -> Result<(), LoopFault> {
		let journal = &self.config.gossip.journal;
		let Some(type_key) = self.config.gossip.ingress.as_ref() else {
			// With no ingress servlet configured, the rumor has no local
			// consumer, so it leaves the retry set.
			journal.ack_local(&digest_value)?;
			return Ok(());
		};

		// A claim taken before the round trip keeps the reconcile beat
		// off this rumor. Every exit below drops the guard, which returns
		// the rumor to the retry set.
		let Some(claim) = LocalClaimGuard::take(journal.as_ref(), &digest_value, self.config.clock.unix())? else {
			return Ok(());
		};

		let entries = self.servlet_registry.local_entries_for_type(type_key)?;
		// An out-of-range balancer answer skips delivery rather than panic
		// the gossip task (see `ClusterConfig::pick_instance`).
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
		self.trace.event(CLUSTER_GOSSIP_ACCEPTED)?;

		Ok(())
	}

	/// Delivers the journal entries whose local consumption is still pending.
	///
	/// A rumor is still pending when ingress registered after admission,
	/// or when a delivery hit a transient fault. The kind of each rumor
	/// decides its retry.
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
	/// 1. Admit the rumor against its hop TTL and the seen window, then
	///    attribute the rate and journal budget to the verified origin signer.
	/// 2. Drop known duplicates before rate admission.
	/// 3. Rate-limit before the journal and the reflood.
	/// 4. Witness advertisement rumors, and retain application rumors for repair.
	/// 5. Deliver application rumors locally, or apply advertisement rumors to routing.
	/// 6. Reflood on a separate task when hop TTL and targets remain.
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
		relay_id: Option<VerifiedSignerId>,
		rumor_signer: Option<VerifiedSignerId>,
	) -> Result<Option<Frame>, TightBeamError> {
		let now = self.config.clock.unix();
		let admitted = self.config.admit_rumor(&rumor, hop_ttl, now);
		let rumor = rumor.into_frame();
		let admitted = match admitted {
			Ok(admitted) => admitted,
			Err(status) => {
				let scored = self.weaken_invalid_relay(origin, relay_id.as_ref());
				return Refusal::to(&frame, &self.trace).gossip_scored(scored, status);
			}
		};

		// Rate and journal keys use the verified origin signer, so a relay
		// spends the origin's budget (CWE-770).
		let attributed = origin.attributed(&frame, &rumor);
		if attributed.nonrepudiation().is_none() {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::Unauthenticated);
		}
		let Some(signer_id) = attributed.signer_id() else {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::PermissionDenied);
		};

		// Drop known duplicates before rate admission so the bucket spends on
		// new rumors only.
		let now = self.config.clock.unix();
		match self.config.gossip.journal.seen(admitted.digest(), now) {
			Ok(true) => {
				self.trace.event(CLUSTER_GOSSIP_DUPLICATE)?;
				return reply_frame(frame.metadata().id(), GossipResponse { status: TransitStatus::Ok });
			}
			Ok(false) => {}
			Err(_) => {
				return Refusal::to(&frame, &self.trace).gossip(TransitStatus::Unavailable);
			}
		}

		// The rate limit runs before the journal and the reflood (CWE-770). A
		// backend fault refuses closed.
		match self.config.gossip.admission.allow(&signer_id, now) {
			Ok(true) => {}
			Ok(false) => {
				return Refusal::to(&frame, &self.trace).gossip(TransitStatus::ResourceExhausted);
			}
			Err(_) => {
				return Refusal::to(&frame, &self.trace).gossip(TransitStatus::Unavailable);
			}
		}

		// The kind decides whether the journal retains the rumor or witnesses
		// its digest alone.
		let digest = *admitted.digest();
		let journal = self.config.gossip.journal.as_ref();
		let journaled = admitted.kind().journal(journal, &signer_id, digest, &rumor, now);
		match journaled {
			Ok(Admission::Duplicate) => {
				self.trace.event(CLUSTER_GOSSIP_DUPLICATE)?;
				return reply_frame(frame.metadata().id(), GossipResponse { status: TransitStatus::Ok });
			}
			Ok(Admission::New) => {}
			Err(_) => {
				return Refusal::to(&frame, &self.trace).gossip(TransitStatus::Unavailable);
			}
		}

		// Local consumption is separate from journal admission, and the kind
		// decides it. Only a relayed rumor names a relay hop to fall back on,
		// and the origin already holds the slate it published.
		let intake = RumorIntake { pipeline: &self, relay_id, rumor_signer };
		let applied = admitted.kind().consume(intake, &rumor, digest, admitted.payload()).await;
		if let Err(fault) = applied {
			return Refusal::to(&frame, &self.trace).gossip_fault(fault);
		}

		let has_targets = match self.config.peer.table.has_targets() {
			Ok(has_targets) => has_targets,
			Err(error) => {
				return Refusal::to(&frame, &self.trace).gossip_fault(LoopFault::Registry(error));
			}
		};

		let flood = FloodBeat::new(
			self.config.clone(),
			self.peer_plane.clone(),
			Arc::clone(&self.servlet_registry),
			Arc::clone(&self.trace),
			Arc::clone(&self.ledgers),
		);
		let GossipPipelineCtx { tasks, .. } = self;

		// The reflood runs on its own task so the Ok reply below returns at
		// this gateway's pace. The rumor moves into the task unchanged, and the
		// reply only needs the outer frame id.
		match (flood, hop_ttl.checked_sub(1)) {
			(Some(flood), Some(next_ttl)) if has_targets => {
				tasks.spawn(async move {
					// This task is detached, so its outcome has no caller. A
					// delivery fault is already on the trace, and this task
					// records a poisoned table here, which is where a reader
					// looks.
					if let Err(fault) = flood.reflood(rumor, next_ttl).await {
						fault.record(&flood.trace);
					}
				});
			}
			_ => {}
		}

		reply_frame(frame.metadata().id(), GossipResponse { status: TransitStatus::Ok })
	}

	/// Verifies, admits, and reconciles one advertisement rumor.
	///
	/// It returns the learned origin fingerprint, or [`None`] for any refusal.
	/// The caller owns the learned and dropped audit events. A relay-trail
	/// refusal traces here because the ad itself still learns.
	///
	/// # Evaluation order
	///
	/// 1. Decode and verify the inner frame on the peer trust plane.
	/// 2. Bind the rumor signer and the inner signer to the same origin.
	/// 3. Reject a stale or far-future control order.
	/// 4. Admit through [`AdmittedPeerAd::admit`].
	/// 5. Learn the discovery hint and reconcile the direct slate.
	/// 6. Install a best-effort relay trail when the hop budget and the relay's dial address allow.
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
		// `decode` borrows through `AsRef`, so its signature requires the extra
		// reference.
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

		// The rumor path applies the direct path's order bound here, so every
		// admitted order falls inside the withdrawal tombstone's window
		// (CWE-294) and the ledger's prunable range (CWE-770).
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

		// The relay hop that delivered this rumor is itself a verified peer, so
		// its trail can install under its own bucket beside the direct one
		// (CWE-772).
		let relay_trail = relay_id.filter(|_| self.config.peer.max_hops >= 2).and_then(|relay_id| {
			let relay_socket = self.servlet_registry.relay_dial_addr(relay_id.as_shared())?;
			let relay_dial = self.config.peer.admit_dial(relay_socket).ok()?;
			admitted.relay_trail(relay_id.as_shared(), relay_dial, &self.config.pheromone)
		});

		// The learned origin is also a discovery hint, as a direct
		// advertiser is. It waits in the capped new table until this
		// gateway's own probe proves it a flood member.
		let hint = admitted.discovery_hint();
		let learned_at = self.config.clock.unix();
		self.config.peer.table.learn([hint], learned_at)?;

		// A poisoned registry is this gateway's fault and ends the caller,
		// where a refused slate is the advertisement's and drops it.
		match self.servlet_registry.reconcile_peer_slate(admitted, PeerCaps::default()) {
			Ok(()) => {}
			Err(ClusterError::LockPoisoned) => return Err(LoopFault::Registry(ClusterError::LockPoisoned)),
			Err(_) => return Ok(None),
		}

		// The direct trail already landed, so a refused relay bucket (caps or a
		// stale order) forfeits the fallback path alone. The refusal still
		// traces, so a missing fallback is diagnosable (ISO 27001 A.8.15).
		if let Some(trail) = relay_trail {
			match self.servlet_registry.reconcile_relay_trail(trail, PeerCaps::default()) {
				Ok(()) => {}
				Err(ClusterError::LockPoisoned) => return Err(LoopFault::Registry(ClusterError::LockPoisoned)),
				Err(_) => {
					self.trace
						.event(CLUSTER_RELAY_TRAIL_REFUSED)?
						.with_payload(origin.as_ref())
						.emit();
				}
			}
		}

		Ok(Some(origin))
	}

	/// Applies one admitted peer-advertisement rumor to routing state.
	///
	/// The wrapped frame MUST verify on the peer trust plane, and the rumor
	/// signer MUST match the inner advertisement signer. An advertisement
	/// therefore travels only under the identity that authored it.
	///
	/// # Admission
	///
	/// A rumor follows the identical direct-ad path
	/// ([`AdmittedPeerAd::admit`]): order freshness, flood membership, the dial
	/// allowlist, the message checks, and the discovery hint.
	///
	/// # Reconciliation
	///
	/// - Slate reconciliation installs a direct trail that dials the origin.
	/// - When `max_hops` affords the two forwards a relay needs and the
	///   relaying peer's dial address is known, a relay trail installs beside
	///   the direct trail as fallback. Only then can pheromone fail over to it
	///   (CWE-772).
	/// - Registry policy refuses a slate that collides with a local route,
	///   including this gateway's own echoed slate.
	///
	/// # Audit
	///
	/// A learned slate traces [`CLUSTER_PEER_AD_LEARNED`] with the origin
	/// fingerprint. Every refusal traces [`CLUSTER_PEER_AD_DROPPED`] (ISO 27001
	/// A.8.15), carrying the rumor signer when it is verifiable.
	fn apply_peer_ad_rumor(
		&self,
		relay_id: Option<VerifiedSignerId>,
		rumor_signer: Option<VerifiedSignerId>,
		payload: impl AsRef<[u8]>,
	) -> Result<(), LoopFault> {
		let payload = payload.as_ref();
		match self.try_apply_peer_ad_rumor(relay_id, rumor_signer.clone(), payload)? {
			Some(origin) => {
				self.trace.event(CLUSTER_PEER_AD_LEARNED)?.with_payload(origin.as_ref()).emit();
			}
			None => {
				// The rumor signer is the closest identity a refusal can
				// name for the audit trail. An unverifiable signer drops
				// without attribution (ISO 27001 A.8.15).
				let event = self.trace.event(CLUSTER_PEER_AD_DROPPED)?;
				match rumor_signer {
					Some(signer) => event.with_payload(signer.as_shared().as_ref()).emit(),
					None => event.emit(),
				}
			}
		}

		Ok(())
	}
}

// A relay score reads the registry and the trace alone, so it needs none of
// the dial bounds the pipeline's own impl carries.
impl<P: Protocol> GossipPipelineCtx<P> {
	/// Scores a misbehaving relay peer.
	///
	/// An origin publish has no relay to score, so it returns without
	/// effect.
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

		let weakened = self.servlet_registry.weaken_peer(peer_id.as_shared())?;
		if weakened > 0 {
			// The audit payload names the scored peer's fingerprint.
			self.trace
				.event(CLUSTER_GOSSIP_RELAY_WEAKENED)?
				.with_payload(peer_id.as_shared().as_ref())
				.emit();
		}

		Ok(())
	}
}

/// The change-driven publish state of the advertisement rumor.
///
/// The beat publishes when the slate or the flood target set changed, and on
/// a configured refresh interval for late joiners (see
/// [`DEFAULT_AD_RUMOR_REFRESH_MS`]).
///
/// # Poison recovery
///
/// Plain field assignments alone write the guarded value, so a panic cannot
/// leave it half-written, and every method recovers a poisoned guard rather
/// than refuse the beat.
///
/// # Claim lifecycle
///
/// 1. [`Self::take_due`] claims a publish slot and blocks re-entry while the task runs.
/// 2. The claiming task creates and refloods the rumor.
/// 3. [`Self::commit`] records the baseline after a rumor went out.
/// 4. [`Self::abort`] releases a failed claim with the old baseline intact, so the next beat retries.
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

	/// Claims one due publish slot.
	///
	/// `true` marks a publish in flight and leaves the baseline untouched
	/// until [`Self::commit`] or [`Self::abort`] settles the claim. `false`
	/// means that the slate and the targets still match the baseline inside
	/// the refresh window, or that a publish already holds the claim.
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

	/// Records a completed publish as the new suppression baseline.
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
		// Repair delivery is a gossip pipeline invocation, so it reuses the
		// inbound context rather than re-pair the same four handles.
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

					// Beat targets are anchors plus verified tried peers.
					// Probes are unverified candidates that wait for their
					// feeler dial.
					let targets = config.peer.table.target_set()?;
					let probes = config.peer.table.probe_sample(config.clock.unix())?;

					// The per-peer ledgers feed grey-hole detection and hold
					// each target's refusals. Each beat keeps the live target
					// and probe addresses alone.
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

					// A publishing beat keeps the slate as its commit baseline,
					// so that beat alone copies the slate for `mint_ad_frame`.
					let (ad_slate, publishing) = match publishing {
						Some(publish_beat) => (slate.clone(), Some((publish_beat, slate))),
						None => (slate, None),
					};

					// One advertisement carries the slate on the direct dials
					// and in the rumor, so a receiver reads one order for the
					// beat whichever copy lands first. An advertisement that
					// fails to build skips this beat's advertisements, and the
					// next beat builds another.
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
	use core::num::NonZeroUsize;

	use super::*;
	use crate::colony::cluster::{CertificateSpec, Cluster, ClusterGateway, ClusterTlsConfig, PeerConfig};
	use crate::colony::common::ColonyNamespace;
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
	use crate::crypto::x509::Certificate;
	use crate::oids::HASH_SHA3_256;
	use crate::testing::{unhex, TestCertificate, TestKey, TestRumor};
	use crate::transport::TokioListener;
	use crate::utils::time::ManualClock;

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

	/// A house gateway admits a rumor under the SHA3-256 digest of its
	/// to-be-signed encoding and then its origin signature, the digest its
	/// protocol's provider names.
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

	#[test]
	fn reconcile_reply_bounds_want_and_pex() {
		let cases = [
			(MAX_GOSSIP_LOG, MAX_PEX_SAMPLE, false),
			(MAX_GOSSIP_LOG + 1, MAX_PEX_SAMPLE, true),
			(MAX_GOSSIP_LOG, MAX_PEX_SAMPLE + 1, true),
		];
		for (want_len, pex_len, oversized) in cases {
			assert_eq!(reply(want_len, pex_len).is_oversized(), oversized);
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

	/// A running gateway in no colony, and its certificate. The certificate
	/// carries no colony URN, so a member that dials it finds it outside the
	/// flood.
	async fn stranger_gateway() -> (ClusterGateway<TokioListener>, Certificate) {
		let key = Secp256k1SigningKey::from_bytes(&[3u8; 32].into()).expect("the fixture scalar is a valid key");
		let certificate = TestCertificate::self_signed(&key);
		let spec = CertificateSpec::Built(Box::new(certificate.clone()));
		let tls = ClusterTlsConfig::new(spec, Arc::new(Secp256k1KeyProvider::from(key)));
		let config = ClusterConfig::new(tls.expect("the stranger certificate must decode"));

		let trace = Arc::new(TraceCollector::default());
		let gateway = ClusterGateway::start(trace, config).await.expect("the stranger gateway starts");
		(gateway, certificate)
	}

	/// The gossip arm of a colony member whose peer trust enrolls `stranger`,
	/// with its peer table lock poisoned.
	fn member_beat_with_a_poisoned_table(stranger: &Certificate) -> FloodBeat<TokioListener> {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let colony = ColonyNamespace::default().colony("main").expect("a literal colony name");
		let certificate = TestCertificate::with_uri_sans(&key, &[&colony.to_string()]);
		let spec = CertificateSpec::Built(Box::new(certificate));
		let tls = ClusterTlsConfig::new(spec, Arc::new(Secp256k1KeyProvider::from(key)));
		let enrolled = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_certificate(stranger.clone());
		let peer_trust: Arc<dyn CertificateTrust> = Arc::new(enrolled.expect("the stranger enrolls").build());
		let tls = tls.expect("the member certificate must decode").with_peer_trust(peer_trust);

		let config = ColonyConfig::new(ClusterConfig::new(tls));
		config.peer.table.poison();

		let trace = Arc::new(TraceCollector::default());
		let pools = config.tls.pools::<TokioListener>(&config.pool_config, &config.clock);
		let peer_pool = pools.peer.expect("a peer trust builds a peer pool");
		let peer_plane = PeerPlane::new(peer_pool, config.clone(), Arc::clone(&trace));
		let registry = Arc::new(ServletRegistry::new(config.pheromone.clone(), Arc::clone(&config.clock)));

		FloodBeat::new(config, peer_plane, registry, trace, Arc::default()).expect("a colony member is in a flood")
	}

	// A poisoned peer table is this gateway's own fault. A round that meets it
	// at an expulsion ends the beat as a local fault, so the score of the peer
	// that answered from outside the flood stands.
	#[tokio::test]
	async fn a_poisoned_table_at_an_expulsion_is_a_local_fault() -> Result<(), TightBeamError> {
		let (stranger, certificate) = stranger_gateway().await;
		let beat = member_beat_with_a_poisoned_table(&certificate);
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
		async fn start() -> Self {
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

			let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
			let builder = builder.with_certificate(authority).expect("the store admits it");
			let builder = builder.with_certificate(enrolled.clone()).expect("the store admits it");
			let peer_trust: Arc<dyn CertificateTrust> = Arc::new(builder.build());

			let spec = CertificateSpec::Built(Box::new(member.clone()));
			let tls = ClusterTlsConfig::new(spec, Arc::new(Secp256k1KeyProvider::from(member_key)));
			let tls = tls.expect("the member certificate must decode").with_peer_trust(peer_trust);
			let config = ClusterConfig::builder(tls).with_tried_per_signer(NonZeroUsize::MIN).build();
			let config = ColonyConfig::new(config);

			let trace = Arc::new(TraceCollector::default());
			let pools = config.tls.pools::<TokioListener>(&config.pool_config, &config.clock);
			let peer_pool = pools.peer.expect("a peer trust builds a peer pool");
			let peer_plane = PeerPlane::new(peer_pool, config.clone(), Arc::clone(&trace));
			let registry = Arc::new(ServletRegistry::new(config.pheromone.clone(), Arc::clone(&config.clock)));
			let beat = FloodBeat::new(config, peer_plane, registry, trace, Arc::default());

			Self {
				beat: beat.expect("a colony member is in a flood"),
				enrolled: Self::serve(enrolled, &gateway_key, &member).await,
				rotated: Self::serve(rotated, &gateway_key, &member).await,
			}
		}

		/// A gateway that serves under `certificate` and answers the reconcile
		/// round of `member`, which its peer trust enrolls.
		async fn serve(
			certificate: Certificate,
			key: &Secp256k1SigningKey,
			member: &Certificate,
		) -> ClusterGateway<TokioListener> {
			let spec = CertificateSpec::Built(Box::new(certificate));
			let tls = ClusterTlsConfig::new(spec, Arc::new(Secp256k1KeyProvider::from(key.clone())));
			let enrolled = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_certificate(member.clone());
			let peer_trust: Arc<dyn CertificateTrust> = Arc::new(enrolled.expect("the member enrolls").build());
			let tls = tls.expect("the gateway certificate must decode").with_peer_trust(peer_trust);

			let trace = Arc::new(TraceCollector::default());
			let gateway = ClusterGateway::start(trace, ClusterConfig::new(tls)).await;
			gateway.expect("the gateway starts")
		}
	}

	// A gateway's name in the discovery table is the certificate the member
	// enrolls for its key, so one gateway that presents a second certificate
	// of that key at another address takes no second slot under the signer
	// cap (CWE-770).
	#[tokio::test]
	async fn a_rotated_certificate_counts_as_the_signer_its_key_enrolls() -> Result<(), TightBeamError> {
		let rotation = SignerRotation::start().await;
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
}
