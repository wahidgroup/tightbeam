//! Gossip background tasks for the cluster advertise beat.
//!
//! The beat re-announces the local slate, publishes origin-signed
//! advertisement rumors, and runs anti-entropy reconcile rounds against
//! verified peers and feeler probes.
//!
//! # Planes
//!
//! - **Direct advertisement**: one signed frame dials every verified target.
//! - **Rumor flood**: the same signed frame wraps in a gossip rumor for
//!   members beyond direct reach.
//! - **Pipeline**: admit, rate-limit, journal, deliver locally, and reflood
//!   inbound rumors.
//! - **Reconcile**: anti-entropy repair and peer-exchange hint learning.

use core::hash::Hash;
use core::str::{from_utf8, FromStr};
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;

use crate::builder::frame::FrameBuilder;
use crate::builder::TypeBuilder;
use crate::colony::cluster::peer::ColonyCertificate;
use crate::colony::cluster::peer::{peer_dial_allowed, AdmittedPeerAd};
use crate::colony::cluster::runtime::bounds::{ClusterDigest, ClusterPool, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::hop::Hop;
use crate::colony::cluster::runtime::refuse::Refusal;
use crate::colony::cluster::{
	gossip_fresh, peer_signer_fingerprint, wanted_digests, Admission, AdmittedGossip, GossipDigest, PeerCaps, PeerHint,
	RouteKind,
};
use crate::colony::cluster::{ClusterConfig, ClusterError, ServletRegistry};
use crate::colony::common::{
	current_timestamp_ms, ClusterRequest, GossipReconciliation, GossipResponse, GossipRumor, GossipRumorKind,
	GossipWant, PeerAdvertisement, PeerAdvertisementResponse, PeerGossip,
};
use crate::colony::common::{reply_frame, TaskGroup};
use crate::colony::hive::{verify_frame_signature, TrustVerification};
use crate::colony::servlet::servlet_runtime::rt;
use crate::constants::{MAX_ADVERTISED_TYPES, MAX_GOSSIP_LOG, MAX_GOSSIP_TTL, MAX_PEX_SAMPLE};
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::decode;
use crate::encode;
use crate::instrumentation::events::{
	CLUSTER_GOSSIP_ACCEPTED, CLUSTER_GOSSIP_DROP_SIGNAL, CLUSTER_GOSSIP_DUPLICATE, CLUSTER_GOSSIP_RELAY_WEAKENED,
	CLUSTER_PEER_DISCOVERED, CLUSTER_PEER_EVICTED,
};
use crate::instrumentation::events::{
	CLUSTER_PEER_AD_DROPPED, CLUSTER_PEER_AD_LEARNED, CLUSTER_PEER_AD_PUBLISH_FAILED, CLUSTER_RELAY_TRAIL_REFUSED,
};
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{EncryptedProtocol, PersistentConnection, Protocol, X509ClientConfig};
use crate::utils::urn::Urn;
use crate::Frame;
use crate::TightBeamError;
use crate::{MessagePriority, Version};

/// Origin of a gossip pipeline invocation.
#[derive(Clone, Copy)]
pub(crate) enum GossipOrigin {
	/// A peer-relayed rumor. Invalid input may score the relay.
	Relay,
	/// A local publish. An admission failure refuses without trail scoring.
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
	/// The pool peers are dialed on.
	///
	/// A configured peer plane keeps peer traffic off the hive pool. With
	/// no peer plane the hive pool serves both.
	pub(crate) fn peer_dial_pool(&self) -> Arc<ClusterPool<P>> {
		self.peer_pool
			.as_ref()
			.map(Arc::clone)
			.unwrap_or_else(|| Arc::clone(&self.pool))
	}
}

/// One signed advertisement rumor ready to witness and flood.
struct MintedAdRumor {
	rumor: Frame,
	digest: GossipDigest,
	signer_id: Vec<u8>,
	minted_ms: u64,
}

impl ServletRegistry {
	/// Dial address of a relaying peer, from its live direct routes.
	///
	/// Only direct routes qualify, because a relay entry's dial address
	/// belongs to a further relay while a direct route holds `relay_id`'s
	/// own. [`None`] means the relay reached this gateway through another
	/// hop, so the direct trail from the rumor stands on its own.
	fn relay_dial_addr(&self, relay_id: &[u8]) -> Option<Arc<[u8]>> {
		let entries = self.peer_entries().ok()?;
		entries
			.iter()
			.filter(|entry| entry.route_kind() == RouteKind::Peer)
			.find(|entry| entry.owner_id().as_ref() == relay_id)
			.map(|entry| Arc::clone(entry.dial_target()))
	}
}

impl ClusterConfig {
	/// Create and sign one peer advertisement frame for this gateway's slate.
	///
	/// One frame serves both delivery paths, so direct dials and gossip
	/// rumors carry the same signer-binds-to-address unit.
	///
	/// # Delivery paths
	///
	/// - Direct dial through [`send_advertisement_async`]
	/// - Advertisement rumor through [`ClusterConfig::mint_slate_rumor`]
	async fn mint_ad_frame<D: ClusterDigest>(
		&self,
		gateway_addr: &[u8],
		types: Vec<Urn<'static>>,
	) -> Result<Frame, ClusterError> {
		// The wire type owns its bytes, so the encode boundary takes an
		// owned copy of the address.
		let request = ClusterRequest::AdvertisePeer(PeerAdvertisement {
			gateway_addr: gateway_addr.to_vec(),
			advertised_types: types,
		});

		let frame = FrameBuilder::from(Version::V2)
			.with_id(b"peer-advertise")
			.with_order(current_timestamp_ms())
			.with_message(request)
			.with_priority(MessagePriority::NetworkControl)
			.with_witness_hasher::<D>()
			.build()?;

		let signed_frame = frame.sign_with_provider::<D, _>(self.tls.identity().signing_provider()).await?;
		Ok(signed_frame)
	}

	/// Create, sign, and digest one advertisement rumor for the local slate.
	///
	/// Wraps a [`ClusterConfig::mint_ad_frame`] payload in a signed rumor
	/// and extracts the digest and signer id for witness and reflood.
	///
	/// Returns `None` on a local fault (key, codec, or journal input). The
	/// caller records it, and a later beat re-publishes fresh.
	async fn mint_slate_rumor<D: ClusterDigest>(
		&self,
		gateway_addr: &[u8],
		types: Vec<Urn<'static>>,
	) -> Option<MintedAdRumor> {
		let ad_frame = self.mint_ad_frame::<D>(gateway_addr, types).await.ok()?;
		let ad_bytes = encode(&ad_frame).ok()?;

		let minted_ms = current_timestamp_ms();
		let body = GossipRumor::peer_advertisement(ad_bytes);
		let rumor = FrameBuilder::from(Version::V2)
			.with_id(b"peer-ad-rumor")
			.with_order(minted_ms)
			.with_message(body)
			.with_priority(MessagePriority::NetworkControl)
			.with_witness_hasher::<D>()
			.build()
			.ok()?;

		let rumor = rumor
			.sign_with_provider::<D, _>(self.tls.identity().signing_provider())
			.await
			.ok()?;
		let digest = rumor.gossip_digest::<D>().ok()?;
		let signer_id = rumor.signer_id()?;

		Some(MintedAdRumor { rumor, digest, signer_id, minted_ms })
	}

	/// Whether `order` sits inside this colony's control freshness window.
	///
	/// The rumor path carries no signed-control replay guard, because the
	/// gossip journal already dedups identical rumors by digest. This bound
	/// keeps the two paths admitting the same orders.
	///
	/// # Fail-closed
	///
	/// - Admission requires an order inside the window, so the ad-order
	///   tombstone covers every replay that reaches reconcile (CWE-294).
	/// - A far-future order is refused, so every ledger row stays prunable
	///   (CWE-770).
	fn ad_order_fresh(&self, order: u64, now: u64) -> bool {
		now.abs_diff(order) <= self.control_freshness_window_ms
	}

	/// Peer-exchange hints this gateway may learn.
	///
	/// An entry must parse as a discovery hint and pass the operator's
	/// dial allowlist, so a later feeler probe dials only addresses the
	/// operator allowed (CWE-284).
	fn admissible_pex_hints(&self, pex: Vec<PeerGossip>) -> impl Iterator<Item = PeerHint> + '_ {
		let allowlist = self.peer.peer_dial_allowlist.as_deref();

		pex.into_iter()
			.filter_map(|entry| PeerHint::try_from(entry).ok())
			.filter(move |hint| peer_dial_allowed(hint.gateway_addr.as_bytes(), allowlist))
	}
}

impl GossipWant {
	/// Whether this reconcile reply exceeds its wire bounds.
	///
	/// A conforming gateway holds its reply to [`MAX_GOSSIP_LOG`] wants
	/// and [`MAX_PEX_SAMPLE`] peer-exchange entries, so an oversized reply
	/// is abuse and the requester drops the whole round (CWE-770).
	fn is_oversized(&self) -> bool {
		self.want.len() > MAX_GOSSIP_LOG || self.pex.len() > MAX_PEX_SAMPLE
	}
}

/// The peer pool outbound gossip floods and reconciles on.
///
/// The advertise beat and the inbound reflood both reach peers through
/// this one owner, so a rumor leaves on the same plane either way.
struct GossipBeat<P: Protocol> {
	config: Arc<ClusterConfig>,
	peer_pool: Arc<ClusterPool<P>>,
	servlet_registry: Arc<ServletRegistry>,
	trace: Arc<TraceCollector>,
}

// The impl is manual because a derive would demand `P: Clone`, and the
// fields are reference-counted regardless of `P`.
impl<P: Protocol> Clone for GossipBeat<P> {
	fn clone(&self) -> Self {
		Self {
			config: Arc::clone(&self.config),
			peer_pool: Arc::clone(&self.peer_pool),
			servlet_registry: Arc::clone(&self.servlet_registry),
			trace: Arc::clone(&self.trace),
		}
	}
}

impl<P> GossipBeat<P>
where
	P: Protocol
		+ PersistentConnection
		+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static,
	P::Address: Hash + Eq + Clone + Send + Sync + FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
{
	/// Fan out a still-live rumor to configured peers with decremented hop TTL.
	///
	/// Targets are anchors plus verified tried peers, so rumor bytes reach
	/// verified identities only. Each target receives an owned clone of the
	/// signed frame because emit consumes the frame.
	async fn reflood<D: ClusterDigest>(&self, rumor: Frame, ttl: u64) {
		// Flood targets are anchors plus verified tried peers, so rumor bytes
		// reach verified identities only.
		let targets = self.config.peer.table.target_set().unwrap_or_default();
		if targets.is_empty() {
			return;
		}

		// Embedding the decoded rumor re-encodes it, which is byte-identical
		// to the received bytes because DER is canonical (ITU-T X.690 §10).
		//
		// The origin signature and witness digest therefore survive the hop.
		// Splicing pre-encoded bytes would need an opaque passthrough field
		// in the codec, a redesign that buys no correctness.
		let request = ClusterRequest::Gossip(Box::new(rumor));
		let frame = match FrameBuilder::from(Version::V2)
			.with_id(b"gossip-reflood")
			.with_message(request)
			.with_priority(MessagePriority::NetworkControl)
			.with_lifetime(ttl)
			.with_witness_hasher::<D>()
			.build()
		{
			Ok(frame) => frame,
			Err(_) => return,
		};

		let signed_frame = match frame
			.sign_with_provider::<D, _>(self.config.tls.identity().signing_provider())
			.await
		{
			Ok(signed) => signed,
			Err(_) => return,
		};

		let mut fanout = tokio::task::JoinSet::new();
		for peer in targets.iter() {
			let Ok(peer_addr) = peer.parse::<P::Address>() else {
				continue;
			};

			let dial_pool = Arc::clone(&self.peer_pool);
			// Each emit consumes an owned frame, so a fan-out to N targets
			// needs N owned frames. The clone is that fan-out cost.
			let frame = signed_frame.clone();
			fanout.spawn(async move {
				if let Ok(mut client) = dial_pool.connect(peer_addr).await {
					let _ = client.emit(frame, None).await;
				}
			});
		}

		while fanout.join_next().await.is_some() {}
	}

	/// Send one pre-signed peer advertisement to a dialed peer gateway.
	///
	/// The caller creates and signs one frame per beat and fans it out, so
	/// one signature serves every dial.
	async fn send_advertisement(
		&self,
		peer_addr: P::Address,
		signed_frame: Frame,
	) -> Result<TransitStatus, ClusterError> {
		let mut client = self.peer_pool.connect(peer_addr).await?;
		let response = client.emit(signed_frame, None).await?.ok_or(ClusterError::NoResponse)?;

		let decoded: PeerAdvertisementResponse = decode(&response.message)?;
		Ok(decoded.status)
	}

	/// Publish the local slate as an origin-signed advertisement rumor.
	///
	/// The rumor wraps the identical signed frame that direct advertisement
	/// dials out, so members beyond direct reach admit through the same
	/// signer-binds-to-address path once the flood relays it.
	///
	/// # Journal
	///
	/// The published digest is witnessed for dedup only. Advertisements are
	/// ephemeral hints that re-publish keeps fresh, and the origin already
	/// holds the slate it published.
	///
	/// # Failures
	///
	/// A creation fault returns `false`, traces `CLUSTER_PEER_AD_PUBLISH_FAILED`,
	/// and leaves the caller's publish baseline intact so the next beat retries.
	async fn publish_slate_rumor<D: ClusterDigest>(
		&self,
		gateway_addr: Arc<[u8]>,
		types: Vec<Urn<'static>>,
	) -> Result<bool, TightBeamError> {
		let Some(minted) = self.config.mint_slate_rumor::<D>(gateway_addr.as_ref(), types).await else {
			self.trace.event(CLUSTER_PEER_AD_PUBLISH_FAILED)?;
			return Ok(false);
		};

		// Witness the published digest so the origin's own echo dedups.
		// Retention serves repair and retry, which advertisements forgo.
		let _ = self
			.config
			.gossip
			.journal
			.witness(&minted.signer_id, minted.digest, minted.minted_ms);

		// The stamped lifetime is the budget remaining after this first
		// hop arrives, matching what the pipeline stamps when it refloods
		// a published rumor.
		let hop_ttl = u64::from(self.config.gossip.ttl.min(MAX_GOSSIP_TTL));
		self.reflood::<D>(minted.rumor, hop_ttl.saturating_sub(1)).await;

		Ok(true)
	}

	/// One anti-entropy reconcile round with a peer, including grey-hole scoring.
	///
	/// An `Err` from this function is peer-attributable, so the beat loops
	/// score it toward eviction or probe discard. A local fault skips its own
	/// step, which keeps scoring attributable to the peer alone.
	///
	/// # Round order
	///
	/// 1. Collect held digests from the journal.
	/// 2. Complete handshake and verify colony scope.
	/// 3. Emit signed reconcile request and decode the reply.
	/// 4. Reject oversized want-lists or PEX samples.
	/// 5. Promote the peer, learn PEX hints, and score grey-hole drops.
	/// 6. Repair missing rumors from the journal.
	///
	/// # Fault attribution
	///
	/// - Local faults before emit or inside the post-reply scope skip scoring.
	/// - Oversized replies and dial failures return `Err` for peer scoring.
	async fn reconcile_round<D: ClusterDigest>(
		&self,
		peer_addr: P::Address,
		acked: &mut HashSet<GossipDigest>,
		peer: &str,
	) -> Result<(), ClusterError> {
		let now = current_timestamp_ms();
		// A journal fault belongs to this gateway, so the round is skipped and
		// scoring stays attributable to the peer.
		let Ok(held_digests) = self.config.gossip.journal.held_digests(now) else {
			return Ok(());
		};
		// The reconciliation wire type carries digests as owned OCTET
		// STRING bytes, so each fixed-size digest copies once here.
		let held: Vec<Vec<u8>> = held_digests.iter().map(|digest| digest.to_vec()).collect();

		let mut client = self.peer_pool.connect(peer_addr).await?;

		// A feeler probe reconciles on a cold connection whose handshake
		// defers to first emit. Completing it here is the only way to learn
		// peer identity before the reconcile discloses anything (CWE-668).
		client.complete_handshake().await?;

		// The colony scope gate requires the peer handshake cert to match
		// the local colony.
		let peer_colony = client
			.peer_certificate()
			.and_then(|cert| self.config.namespace.cert_colony_urn(cert));
		if peer_colony.as_ref() != self.config.colony_urn() {
			// A definitive foreign identity leaves both learned tables at
			// once. Waiting out the failure threshold would keep advertising
			// to a peer that re-keyed outside the colony.
			let _ = self.config.peer.table.expel(peer);
			return Ok(());
		}

		let request = ClusterRequest::ReconcileGossip(GossipReconciliation { held });

		// Frame construction and signing are local. A fault here happened
		// before the peer was asked anything, so the round is skipped rather
		// than scored.
		let Ok(frame) = FrameBuilder::from(Version::V2)
			.with_id(b"gossip-reconcile")
			.with_order(now)
			.with_message(request)
			.with_priority(MessagePriority::NetworkControl)
			.with_witness_hasher::<D>()
			.build()
		else {
			return Ok(());
		};

		let Ok(signed_frame) = frame
			.sign_with_provider::<D, _>(self.config.tls.identity().signing_provider())
			.await
		else {
			return Ok(());
		};
		let response = client.emit(signed_frame, None).await?.ok_or(ClusterError::NoResponse)?;
		let reply: GossipWant = decode(&response.message)?;

		// An oversized want-list or PEX sample is abuse, so the round fails
		// (CWE-770). The beat then scores the peer like any failed round, so an abuser
		// is discarded from `new` or counted toward eviction from `tried`.
		if reply.is_oversized() {
			return Err(ClusterError::OversizedReconcileReply);
		}

		// The decoded, in-bounds reply already proves liveness, so a fault in
		// the bookkeeping below leaves the peer scored on its answer.
		let local_round = self.settle_round::<D>(&mut client, reply, acked, peer, now).await;

		// Tolerate boundary: the reconcile round already succeeded, so a local
		// fault above skips the rest of the round without charging the peer.
		// The next beat retries the skipped bookkeeping and repair.
		let _ = local_round;

		Ok(())
	}

	/// Apply one answered round's bookkeeping: promotion, PEX hints,
	/// grey-hole scoring, and journal repair.
	///
	/// Every step here is local, so a fault skips the rest of the round
	/// and leaves the peer scored on the answer it already gave.
	async fn settle_round<D: ClusterDigest>(
		&self,
		client: &mut crate::transport::PooledClient<P, DefaultCryptoProvider>,
		reply: GossipWant,
		acked: &mut HashSet<GossipDigest>,
		peer: &str,
		now: u64,
	) -> Result<(), ClusterError> {
		let round: Result<(), ClusterError> = async {
			// Promotion waits for the reply because a pooled connection keeps
			// its handshake certificate after the peer dies. Promoting on the
			// gate alone would reset the failure count every beat, holding a
			// dead peer in the table.
			let peer_id = client.peer_certificate().and_then(ColonyCertificate::fingerprint_id);
			if self.config.peer.table.promote(peer, peer_id.as_deref(), now)? {
				self.trace.event(CLUSTER_PEER_DISCOVERED)?.with_payload(peer.as_bytes()).emit();
			}

			let GossipWant { want, pex } = reply;

			// PEX entries are unverified hints: the allowlist gates them, the
			// capped new table holds them, and a later feeler probe under the
			// colony gate is the only path to dial target (CWE-345).
			let hints = self.config.admissible_pex_hints(pex);
			self.config.peer.table.learn(hints)?;

			let wanted = wanted_digests(&want);

			// Grey-hole containment: a digest this gateway acked, wanted again
			// while retained, is a drop. One weaken per round scores it.
			let dropped = wanted.iter().any(|digest| acked.contains(digest));
			if dropped {
				let _ = self.servlet_registry.weaken_peer_by_dial(peer.as_bytes());
				self.trace.event(CLUSTER_GOSSIP_DROP_SIGNAL)?;
			}

			for digest in &wanted {
				acked.remove(digest);
			}

			self.push_repairs::<D>(client, &wanted, acked).await
		}
		.await;

		round
	}

	/// Advertise to and reconcile with every verified target.
	///
	/// `ad_frame` is the single signed advertisement this beat minted, so
	/// one signature serves every dial. A failed round counts toward
	/// eviction, so a dead tried peer frees its bucket slot at the
	/// threshold.
	async fn dial_targets<D: ClusterDigest>(
		&self,
		targets: &[String],
		ad_frame: Option<&Frame>,
		push_ledger: &mut HashMap<String, HashSet<GossipDigest>>,
		trace: &TraceCollector,
	) -> Result<(), TightBeamError> {
		let reconciling = self.config.colony_urn().is_some();
		for peer in targets {
			let Ok(peer_addr) = peer.parse::<P::Address>() else {
				continue;
			};

			if let Some(frame) = ad_frame {
				// The dial consumes both arguments. The address serves the
				// reconcile below again, and the frame serves every
				// remaining target.
				let _ = self.send_advertisement(peer_addr.clone(), frame.clone()).await;
			}

			if !reconciling {
				continue;
			}

			// The entry API takes an owned key even on a hit, and the short
			// address clone costs less than a second lookup.
			let acked = push_ledger.entry(peer.clone()).or_default();
			let round = self.reconcile_round::<D>(peer_addr, acked, peer).await;
			if round.is_err() && self.config.peer.table.record_failure(peer).unwrap_or(false) {
				trace.event(CLUSTER_PEER_EVICTED)?.with_payload(peer.as_bytes()).emit();
			}
		}

		Ok(())
	}

	/// Reconcile with unverified candidates, discarding the ones that fail.
	///
	/// Feeler probes run reconcile only: the colony gate inside the round
	/// promotes a verified candidate, and a failed dial discards it, so a
	/// prefix bucket keeps holding live addresses.
	async fn probe_candidates<D: ClusterDigest>(
		&self,
		probes: &[String],
		push_ledger: &mut HashMap<String, HashSet<GossipDigest>>,
	) {
		if self.config.colony_urn().is_none() {
			return;
		}

		for peer in probes {
			let Ok(peer_addr) = peer.parse::<P::Address>() else {
				let _ = self.config.peer.table.discard(peer);
				continue;
			};

			let acked = push_ledger.entry(peer.clone()).or_default();
			if self.reconcile_round::<D>(peer_addr, acked, peer).await.is_err() {
				let _ = self.config.peer.table.discard(peer);
			}
		}
	}

	/// Advertised types this gateway exports, capped at
	/// [`MAX_ADVERTISED_TYPES`].
	///
	/// This is the single place advertised types are gathered, so one
	/// export filter covers the direct ads and the rumor flood.
	/// Membership is asked per key each beat, so a live `ExportAllowlist`
	/// stays aligned with enforcement.
	fn exported_slate(&self) -> Vec<Urn<'static>> {
		let exports = self.config.peer.exported_types.as_deref();
		self.servlet_registry
			.local_servlets()
			.unwrap_or_default()
			.iter()
			.filter(|bytes| exports.is_none_or(|list| list.allows_canonical(bytes)))
			.filter_map(|bytes| from_utf8(bytes).ok())
			.filter_map(|canonical| canonical.parse().ok())
			.take(MAX_ADVERTISED_TYPES)
			.collect()
	}

	/// Resend the journaled rumors this peer still wants.
	///
	/// Each push carries an outer lifetime of 0, so a repair never
	/// refloods. Only a rumor still inside the seen window is admissible,
	/// and only an explicit `Ok` reply arms the grey-hole ledger.
	async fn push_repairs<D: ClusterDigest>(
		&self,
		client: &mut crate::transport::PooledClient<P, DefaultCryptoProvider>,
		wanted: &[GossipDigest],
		acked: &mut HashSet<GossipDigest>,
	) -> Result<(), ClusterError> {
		let now = current_timestamp_ms();
		let seen_ttl_ms = self.config.gossip.seen_ttl.as_millis() as u64;
		let missing = self.config.gossip.journal.fetch(wanted, now)?;
		let admissible = missing
			.into_iter()
			.filter(|rumor| gossip_fresh(rumor.metadata.order, seen_ttl_ms, now));

		for rumor in admissible {
			let Ok(pushed_digest) = rumor.gossip_digest::<D>() else {
				continue;
			};

			let push = ClusterRequest::Gossip(Box::new(rumor));
			let frame = FrameBuilder::from(Version::V2)
				.with_id(b"gossip-repair")
				.with_message(push)
				.with_priority(MessagePriority::NetworkControl)
				.with_lifetime(0)
				.with_witness_hasher::<D>()
				.build()?;

			let signed = frame
				.sign_with_provider::<D, _>(self.config.tls.identity().signing_provider())
				.await?;
			// Arm the grey-hole ledger only on an explicit Ok reply.
			let Some(push_reply) = client.emit(signed, None).await? else {
				continue;
			};
			let Ok(gossip_reply) = decode::<GossipResponse>(&push_reply.message) else {
				continue;
			};
			if matches!(gossip_reply.status, TransitStatus::Ok) {
				acked.insert(pushed_digest);
			}
		}

		Ok(())
	}
}

/// Shared state for one gossip pipeline invocation.
pub(crate) struct GossipPipelineCtx<P: Protocol> {
	/// Servlet routes an admitted advertisement reconciles into.
	pub(crate) servlet_registry: Arc<ServletRegistry>,
	/// Colony identity, gossip journal, rate admission, and peer caps.
	pub(crate) config: Arc<ClusterConfig>,
	/// Connection pool local ingress delivery dials on.
	pub(crate) pool: Arc<ClusterPool<P>>,
	/// Pool peers are dialed on, resolved once from the gateway's planes.
	pub(crate) peer_pool: Arc<ClusterPool<P>>,
	/// Instrumentation collector for gossip admission and refusal events.
	pub(crate) trace: Arc<TraceCollector>,
	/// Owner of the reflood this pipeline starts.
	pub(crate) tasks: TaskGroup,
}

impl<P: Protocol> From<GatewayRuntimeCtx<P>> for GossipPipelineCtx<P> {
	/// Projects the gateway's runtime state onto what a rumor needs.
	fn from(ctx: GatewayRuntimeCtx<P>) -> Self {
		let peer_pool = ctx.peer_dial_pool();

		Self {
			servlet_registry: ctx.servlet_registry,
			config: ctx.config,
			peer_pool,
			pool: ctx.pool,
			trace: ctx.trace,
			tasks: ctx.tasks,
		}
	}
}

impl<P> GossipPipelineCtx<P>
where
	P: Protocol
		+ PersistentConnection
		+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static,
	P::Address: Hash + Eq + Clone + Send + Sync + FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
{
	/// Deliver one admitted rumor payload to the configured local ingress servlet.
	///
	/// A journal lock is poisoned only by a panic this crate forbids, so an
	/// unrecorded ack leaves the digest pending and the next reconcile round
	/// re-offers it.
	async fn deliver_local(&self, payload: Vec<u8>, digest_value: GossipDigest) -> Result<(), TightBeamError> {
		match self.config.gossip.ingress.as_ref() {
			None => {
				let _ = self.config.gossip.journal.ack_local(&digest_value);
			}
			Some(ingress) => {
				let type_key = ingress.canonical_bytes();
				let entries = self.servlet_registry.local_entries_for_type(&type_key).unwrap_or_default();

				// An out-of-range balancer answer skips delivery instead
				// of panicking the gossip task (see [`ClusterConfig::pick_instance`]).
				let selected = self.config.pick_instance(&entries);
				if let Some(entry) = selected {
					let dial_addr = Arc::clone(entry.dial_target());
					if let Ok(_response) = Hop::new(&self.pool, dial_addr).deliver_envelope(payload).await {
						let _ = self.config.gossip.journal.ack_local(&digest_value);
						self.trace.event(CLUSTER_GOSSIP_ACCEPTED)?;
					}
				}
			}
		}

		Ok(())
	}

	/// Deliver journal entries whose local consumption is still pending.
	///
	/// A rumor is still pending when ingress registered after admission,
	/// or when a delivery hit a transient fault. Application rumors are the
	/// retained kind, so delivery accepts that kind alone.
	async fn retry_pending_local<D: ClusterDigest>(&self) -> Result<(), TightBeamError> {
		let Ok(pending) = self.config.gossip.journal.pending_local(current_timestamp_ms()) else {
			return Ok(());
		};

		for rumor in pending {
			let Ok(body) = decode::<GossipRumor>(&rumor.message) else {
				continue;
			};
			let Ok(digest) = rumor.gossip_digest::<D>() else {
				continue;
			};
			let GossipRumorKind::Application = body.kind else {
				continue;
			};

			self.deliver_local(body.payload, digest).await?;
		}

		Ok(())
	}

	/// Admits, rate-limits, journals, delivers locally, and optionally
	/// refloods one rumor.
	///
	/// # Pipeline order
	///
	/// 1. Attribute rate and journal to the verified origin signer.
	/// 2. Drop known duplicates before rate admission.
	/// 3. Rate-limit before journal and reflood.
	/// 4. Witness advertisement rumors, and retain application rumors for repair.
	/// 5. Deliver application rumors locally or apply advertisement rumors to routing.
	/// 6. Reflood on a separate task when hop TTL and targets remain.
	pub(crate) async fn run<D: ClusterDigest>(
		self,
		origin: GossipOrigin,
		frame: Frame,
		rumor: Frame,
		hop_ttl: u64,
	) -> Result<Option<Frame>, TightBeamError> {
		let admitted = match AdmittedGossip::admit::<D>(
			&rumor,
			hop_ttl,
			self.config.gossip.seen_ttl.as_millis() as u64,
			current_timestamp_ms(),
		) {
			Ok(admitted) => admitted,
			Err(status) => {
				self.weaken_invalid_relay(origin, &frame)?;
				return Refusal::to(&frame, &self.trace).gossip(status);
			}
		};

		// Rate and journal keys use the verified origin signer, so a relay
		// spends the origin's budget (CWE-770).
		let attributed = origin.attributed(&frame, &rumor);
		if attributed.nonrepudiation.is_none() {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::Unauthenticated);
		}
		let Some(signer_id) = attributed.signer_id() else {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::PermissionDenied);
		};

		let now = current_timestamp_ms();

		// Drop known duplicates before rate admission so the bucket spends on
		// new rumors only.
		match self.config.gossip.journal.seen(&admitted.digest(), now) {
			Ok(true) => {
				self.trace.event(CLUSTER_GOSSIP_DUPLICATE)?;
				return reply_frame(&frame.metadata.id, GossipResponse { status: TransitStatus::Ok });
			}
			Ok(false) => {}
			Err(_) => {
				return Refusal::to(&frame, &self.trace).gossip(TransitStatus::Unavailable);
			}
		}

		// The rate limit runs before journal and reflood (CWE-770). A
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

		// Application rumors retain for anti-entropy repair and delivery
		// retry. Advertisement rumors witness for dedup only, which keeps
		// retention and repair bandwidth for the rumors that use them.
		let journaled = match admitted.kind() {
			GossipRumorKind::Application => {
				self.config.gossip.journal.record(&signer_id, admitted.digest(), &rumor, now)
			}
			GossipRumorKind::PeerAdvertisement => {
				self.config.gossip.journal.witness(&signer_id, admitted.digest(), now)
			}
		};
		match journaled {
			Ok(Admission::Duplicate) => {
				self.trace.event(CLUSTER_GOSSIP_DUPLICATE)?;
				return reply_frame(&frame.metadata.id, GossipResponse { status: TransitStatus::Ok });
			}
			Ok(Admission::New) => {}
			Err(_) => {
				return Refusal::to(&frame, &self.trace).gossip(TransitStatus::Unavailable);
			}
		}

		// Local consumption is separate from journal admission. A retained
		// application rumor acks after delivery, and an advertisement rumor is
		// gateway routing control that applies to the registry instead.
		match admitted.kind() {
			GossipRumorKind::Application => {
				let digest_value = admitted.digest();
				self.deliver_local(admitted.into_payload(), digest_value).await?;
			}
			GossipRumorKind::PeerAdvertisement => {
				// Only a relayed rumor names a relay hop to fall back on, and
				// the origin already holds the slate it published.
				let relay = match origin {
					GossipOrigin::Relay => Some(&frame),
					GossipOrigin::Origin => None,
				};
				self.apply_peer_ad_rumor(&rumor, relay, admitted.payload())?;
			}
		}

		let flood = GossipBeat {
			config: Arc::clone(&self.config),
			peer_pool: Arc::clone(&self.peer_pool),
			servlet_registry: Arc::clone(&self.servlet_registry),
			trace: Arc::clone(&self.trace),
		};
		let GossipPipelineCtx { config, tasks, .. } = self;

		// The reflood runs on its own task so the Ok reply below returns at
		// this gateway's pace. The gateway's group owns it, so stopping the
		// gateway stops a reflood still dialling. The rumor moves into the task
		// unchanged, and the reply only needs the outer frame id.
		if hop_ttl > 0 && config.peer.table.has_targets() {
			let next_ttl = hop_ttl - 1;
			tasks.spawn(async move { flood.reflood::<D>(rumor, next_ttl).await });
		}

		reply_frame(&frame.metadata.id, GossipResponse { status: TransitStatus::Ok })
	}

	/// Verify, admit, and reconcile one advertisement rumor.
	///
	/// Returns the learned origin fingerprint, or `None` for any refusal.
	/// The caller owns learned and dropped audit events. Relay-trail refusal
	/// traces here because the ad itself still learns.
	///
	/// # Evaluation order
	///
	/// 1. Decode and verify the inner frame on the peer trust plane.
	/// 2. Bind rumor and inner signers to the same origin.
	/// 3. Reject stale or far-future control orders.
	/// 4. Admit through [`AdmittedPeerAd::admit`].
	/// 5. Learn the discovery hint and reconcile the direct slate.
	/// 6. Best-effort relay-trail install when hops and dial address allow.
	fn try_apply_peer_ad_rumor(
		&self,
		rumor: &Frame,
		relay: Option<&Frame>,
		payload: &[u8],
	) -> Result<Option<Arc<[u8]>>, TightBeamError> {
		// `decode` borrows through `AsRef`, so the extra reference is the
		// signature's requirement, not an indirection slip.
		let Ok(inner) = decode::<Frame>(&payload) else {
			return Ok(None);
		};
		let Some(trust) = self.config.tls.peer_trust.as_ref() else {
			return Ok(None);
		};
		if !matches!(verify_frame_signature(trust.as_ref(), &inner), TrustVerification::Verified) {
			return Ok(None);
		}

		// The same-origin bind means only the advertiser itself may rumor its
		// ad, so a rumor's freshness always belongs to the ad it carries.
		let Some(rumor_signer) = peer_signer_fingerprint(Some(trust.as_ref()), rumor) else {
			return Ok(None);
		};
		let Some(inner_signer) = peer_signer_fingerprint(Some(trust.as_ref()), &inner) else {
			return Ok(None);
		};
		if rumor_signer != inner_signer {
			return Ok(None);
		}

		// The direct path bounds the control order through its replay guard.
		// The rumor path applies the same bound here, so every admitted order
		// falls inside the withdrawal tombstone's window (CWE-294) and inside
		// the ledger's prunable range (CWE-770).
		if !self.config.ad_order_fresh(inner.metadata.order, current_timestamp_ms()) {
			return Ok(None);
		}

		let Ok(ClusterRequest::AdvertisePeer(advertisement)) = decode::<ClusterRequest>(&inner.message) else {
			return Ok(None);
		};
		let Ok(admitted) = AdmittedPeerAd::admit(&inner, &advertisement, &self.config) else {
			return Ok(None);
		};
		let origin = Arc::clone(&admitted.peer_hive_id);

		// The relay hop that delivered this rumor is itself a verified peer.
		// A trail installs under its own bucket beside the direct trail when
		// this gateway may spend the two forwards a relay needs and the
		// relay's dial address is known, which is exactly when pheromone can
		// fail over to it (CWE-772).
		let relay_id = relay.and_then(|relay_frame| peer_signer_fingerprint(Some(trust.as_ref()), relay_frame));
		let relay_trail = relay_id.filter(|_| self.config.peer.max_hops >= 2).and_then(|relay_id| {
			let relay_dial = self.servlet_registry.relay_dial_addr(&relay_id)?;
			admitted.relay_trail(&relay_id, relay_dial, &self.config.pheromone)
		});

		// The learned origin is also a discovery hint, exactly like a
		// direct advertiser. It waits in the capped new table until this
		// gateway's own probe passes the colony gate.
		let hint = admitted.discovery_hint();
		let _ = self.config.peer.table.learn(hint);

		if self
			.servlet_registry
			.reconcile_peer_slate(admitted, PeerCaps::default())
			.is_err()
		{
			return Ok(None);
		}

		// Fallback install is best-effort. The direct trail already
		// landed, and a refused relay bucket (caps or a stale order) only
		// forfeits the fallback path. The refusal still traces, so a
		// missing fallback is diagnosable (ISO 27001 A.8.15).
		if let Some(trail) = relay_trail {
			if self.servlet_registry.reconcile_relay_trail(trail, PeerCaps::default()).is_err() {
				self.trace
					.event(CLUSTER_RELAY_TRAIL_REFUSED)?
					.with_payload(origin.as_ref())
					.emit();
			}
		}

		Ok(Some(origin))
	}

	/// Apply one admitted peer-advertisement rumor to routing state.
	///
	/// The wrapped frame MUST verify on the peer trust plane, and the rumor
	/// signer MUST match the inner advertisement signer. An advertisement
	/// therefore travels only under the identity that authored it.
	///
	/// # Admission
	///
	/// Follows the identical direct-ad path ([`AdmittedPeerAd::admit`]):
	/// order freshness, colony gate, dial allowlist, wire checks, and the
	/// discovery hint.
	///
	/// # Reconciliation
	///
	/// - Slate reconciliation installs a direct trail that dials the origin.
	/// - When `max_hops` affords relay forwarding and the relaying peer is
	///   known, a relay trail installs beside the direct trail as fallback.
	/// - Registry policy refuses a slate that collides with a local route,
	///   including this gateway's own echoed slate.
	///
	/// # Audit
	///
	/// A learned slate traces `CLUSTER_PEER_AD_LEARNED` with the origin
	/// fingerprint. Every refusal traces `CLUSTER_PEER_AD_DROPPED` (ISO 27001
	/// A.8.15), carrying the rumor signer when verifiable.
	fn apply_peer_ad_rumor(&self, rumor: &Frame, relay: Option<&Frame>, payload: &[u8]) -> Result<(), TightBeamError> {
		match self.try_apply_peer_ad_rumor(rumor, relay, payload)? {
			Some(origin) => {
				self.trace.event(CLUSTER_PEER_AD_LEARNED)?.with_payload(origin.as_ref()).emit();
			}
			None => {
				// The rumor signer is the closest identity a refusal can
				// name for the audit trail. An unverifiable signer drops
				// without attribution (ISO 27001 A.8.15).
				let signer = peer_signer_fingerprint(self.config.tls.peer_trust.as_deref(), rumor);
				let event = self.trace.event(CLUSTER_PEER_AD_DROPPED)?;
				match signer {
					Some(signer) => event.with_payload(signer.as_ref()).emit(),
					None => event.emit(),
				}
			}
		}

		Ok(())
	}

	/// Score a misbehaving relay peer.
	///
	/// An origin publish has no relay to score, so it returns without
	/// effect.
	pub(crate) fn weaken_invalid_relay(&self, origin: GossipOrigin, frame: &Frame) -> Result<(), TightBeamError> {
		if matches!(origin, GossipOrigin::Origin) {
			return Ok(());
		}
		let Some(peer_id) = peer_signer_fingerprint(self.config.tls.peer_trust.as_deref(), frame) else {
			return Ok(());
		};

		// A poisoned registry lock is unreachable in a zero-panic crate, so
		// an unscored trail leaves the refusal itself intact.
		let Ok(weakened) = self.servlet_registry.weaken_peer(&peer_id) else {
			return Ok(());
		};
		if weakened > 0 {
			// Audit payload names the scored peer fingerprint.
			self.trace
				.event(CLUSTER_GOSSIP_RELAY_WEAKENED)?
				.with_payload(peer_id.as_ref())
				.emit();
		}

		Ok(())
	}
}

/// Change-driven publish state for the advertisement rumor.
///
/// The beat publishes when the slate or flood target set changed, and on
/// a configured refresh interval for late joiners (see
/// [`DEFAULT_AD_RUMOR_REFRESH_MS`]).
///
/// # Claim lifecycle
///
/// 1. [`Self::take_due`] claims a publish slot and blocks re-entry while
///    the task runs.
/// 2. The claiming task creates and refloods the rumor.
/// 3. [`Self::commit`] records the baseline after a rumor went out.
/// 4. [`Self::abort`] releases a failed claim with the old baseline
///    intact, so the next beat retries.
///
/// [`DEFAULT_AD_RUMOR_REFRESH_MS`]: crate::constants::DEFAULT_AD_RUMOR_REFRESH_MS
struct AdPublishState {
	inner: Mutex<AdPublishInner>,
	refresh_ms: u64,
}

/// Baseline and claim flag behind the [`AdPublishState`] lock.
#[derive(Default)]
struct AdPublishInner {
	last: Option<(u64, Vec<Urn<'static>>, Vec<String>)>,
	in_flight: bool,
}

impl AdPublishState {
	fn new(refresh: Duration) -> Self {
		let refresh_ms = u64::try_from(refresh.as_millis()).unwrap_or(u64::MAX);
		Self { inner: Mutex::new(AdPublishInner::default()), refresh_ms }
	}

	/// Claim one due publish slot.
	///
	/// `true` marks a publish in flight and leaves the baseline
	/// `true` marks a publish in flight and leaves the baseline untouched
	/// targets still match the baseline inside the refresh window, or a
	/// publish already holds the claim.
	fn take_due(&self, now: u64, slate: &[Urn<'static>], targets: &[String]) -> bool {
		let Ok(mut inner) = self.inner.lock() else {
			return false;
		};
		if inner.in_flight {
			return false;
		}

		let due = match &inner.last {
			None => true,
			Some((at_ms, published_slate, published_targets)) => {
				published_slate != slate
					|| published_targets != targets
					|| now.saturating_sub(*at_ms) >= self.refresh_ms
			}
		};

		inner.in_flight = due;
		due
	}

	/// Record a completed publish as the new suppression baseline.
	fn commit(&self, now: u64, slate: Vec<Urn<'static>>, targets: Vec<String>) {
		let Ok(mut inner) = self.inner.lock() else {
			return;
		};

		inner.last = Some((now, slate, targets));
		inner.in_flight = false;
	}

	/// Release a failed claim without touching the baseline.
	fn abort(&self) {
		let Ok(mut inner) = self.inner.lock() else {
			return;
		};

		inner.in_flight = false;
	}
}

impl<P> GatewayRuntimeCtx<P>
where
	P: Protocol
		+ PersistentConnection
		+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static,
	P::Address: Hash + Eq + Clone + Send + Sync + FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
{
	/// Spawns the beat that re-announces local types to peers.
	///
	/// Each beat retries pending local delivery, publishes due advertisement
	/// rumors, dials verified targets with one shared signed frame, and runs
	/// reconcile rounds for colony members and feeler probes.
	pub(crate) fn spawn_advertise<D: ClusterDigest>(self, gateway_addr: Arc<[u8]>) -> rt::JoinHandle {
		// Repair delivery is a gossip pipeline invocation, so it reuses the
		// inbound context rather than re-pairing the same four handles.
		let delivery = GossipPipelineCtx::from(self.clone());
		let beat = GossipBeat {
			config: Arc::clone(&self.config),
			peer_pool: self.peer_dial_pool(),
			servlet_registry: Arc::clone(&self.servlet_registry),
			trace: Arc::clone(&self.trace),
		};

		let GatewayRuntimeCtx { config, trace, tasks, .. } = self;

		rt::spawn(async move {
			let beat: Result<(), TightBeamError> = async move {
				let Some(interval) = config.peer.advertise_interval else {
					return Ok(());
				};

				// PEX replies echo installed routes, which include this
				// gateway's own address, so the table excludes it up front.
				if let Ok(local) = from_utf8(&gateway_addr) {
					let _ = config.peer.table.exclude_self(local);
				}

				// Per-peer Ok ledger for grey-hole detection. Each beat retains
				// the live target and probe addresses, which bounds the map by
				// the table's own caps (CWE-770).
				let mut push_ledger: HashMap<String, HashSet<GossipDigest>> = HashMap::new();
				let ad_publish = Arc::new(AdPublishState::new(config.peer.rumor_refresh));

				loop {
					rt::sleep(interval).await;

					delivery.retry_pending_local::<D>().await?;

					// Beat targets are anchors plus verified tried peers.
					// Probes are unverified candidates awaiting their feeler
					// dial.
					let targets = config.peer.table.target_set().unwrap_or_default();
					let probes = config.peer.table.probe_sample(current_timestamp_ms()).unwrap_or_default();

					push_ledger.retain(|peer, _| targets.contains(peer) || probes.contains(peer));

					if targets.is_empty() && probes.is_empty() {
						continue;
					}

					let slate = beat.exported_slate();

					// The slate also floods as an origin-signed rumor, so
					// members its own task so the direct advertisements below
					// dial at this gateway's pace.
					let now = current_timestamp_ms();
					if config.colony_urn().is_some() && ad_publish.take_due(now, &slate, &targets) {
						let publish_state = Arc::clone(&ad_publish);
						let publish_beat = beat.clone();
						let publish_addr = Arc::clone(&gateway_addr);

						// The captured vectors become the commit baseline,
						// and the publish consumes its own slate copy inside
						// the task.
						let publish_slate = slate.clone();
						let publish_targets = targets.clone();
						tasks.spawn(async move {
							let published =
								publish_beat.publish_slate_rumor::<D>(publish_addr, publish_slate.clone()).await;

							// A publish that faulted releases its claim, so
							// the next beat retries it.
							match published {
								Ok(true) => {
									publish_state.commit(current_timestamp_ms(), publish_slate, publish_targets);
								}
								Ok(false) | Err(_) => publish_state.abort(),
							}
						});
					}

					// One frame and one signature serve every direct target
					// each dial takes a clone of the signed frame. The frame
					// build takes the slate by move, as its last use this beat.
					let mut ad_frame = None;
					if !targets.is_empty() {
						ad_frame = config.mint_ad_frame::<D>(gateway_addr.as_ref(), slate).await.ok();
					}

					beat.dial_targets::<D>(&targets, ad_frame.as_ref(), &mut push_ledger, &trace)
						.await?;
					beat.probe_candidates::<D>(&probes, &mut push_ledger).await;
				}
			}
			.await;

			// A trace fault ends the beat, which is the effect a
			// `testing-fault` injection observes.
			drop(beat);
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::cluster::{CertificateSpec, ClusterTlsConfig};
	use crate::colony::common::ColonyNamespace;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::testing::{create_test_certificate, create_test_signing_key};

	/// Config holding the fields these tests read.
	fn test_config() -> ClusterConfig {
		let key: Secp256k1SigningKey = create_test_signing_key();

		ClusterConfig::new(
			ClusterTlsConfig::new(
				CertificateSpec::Built(Box::new(create_test_certificate(&key))),
				Arc::new(Secp256k1KeyProvider::from(key)),
			)
			.expect("the test certificate must decode"),
		)
	}

	fn config_with_window(window_ms: u64) -> ClusterConfig {
		let mut config = test_config();
		config.control_freshness_window_ms = window_ms;
		config
	}

	fn config_allowing(allowlist: Vec<String>) -> ClusterConfig {
		let mut config = test_config();
		config.peer.peer_dial_allowlist = Some(allowlist);
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

	fn pex_entry(addr: &str) -> PeerGossip {
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
		assert_eq!(admitted[0].gateway_addr, "10.0.0.1:9000");
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
		assert!(config_with_window(500).ad_order_fresh(1_500, 2_000));
		assert!(config_with_window(500).ad_order_fresh(2_500, 2_000));
	}

	#[test]
	fn ad_order_older_than_window_is_stale() {
		assert!(!config_with_window(500).ad_order_fresh(1_499, 2_000));
	}

	#[test]
	fn ad_order_past_future_window_is_stale() {
		assert!(!config_with_window(500).ad_order_fresh(2_501, 2_000));
		assert!(!config_with_window(500).ad_order_fresh(u64::MAX, 2_000));
	}

	#[test]
	fn ad_publish_first_beat_is_due() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		assert!(state.take_due(0, &[], &[]));
	}

	#[test]
	fn ad_publish_unchanged_state_suppresses_until_refresh() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(0, &[], &[]);
		state.commit(0, Vec::new(), Vec::new());
		assert!(!state.take_due(999, &[], &[]));
		assert!(state.take_due(1_000, &[], &[]));
	}

	#[test]
	fn ad_publish_slate_change_fires_before_refresh() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(0, &[], &[]);
		state.commit(0, Vec::new(), Vec::new());
		assert!(state.take_due(1, &ad_slate(&["ping"]), &[]));
	}

	#[test]
	fn ad_publish_target_change_fires_before_refresh() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(0, &[], &[]);
		state.commit(0, Vec::new(), Vec::new());
		assert!(state.take_due(1, &[], &[String::from("peer:1")]));
	}

	#[test]
	fn ad_publish_suppressed_beat_keeps_the_refresh_baseline() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(0, &[], &[]);
		state.commit(0, Vec::new(), Vec::new());
		state.take_due(500, &[], &[]);
		assert!(state.take_due(1_000, &[], &[]));
	}

	#[test]
	fn ad_publish_claim_in_flight_blocks_reentry() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(0, &[], &[]);
		assert!(!state.take_due(1, &ad_slate(&["ping"]), &[]));
	}

	#[test]
	fn ad_publish_aborted_claim_retries_on_the_next_beat() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(0, &[], &[]);
		state.abort();
		assert!(state.take_due(1, &[], &[]));
	}

	#[test]
	fn ad_publish_commit_settles_the_claim_and_the_baseline() {
		let state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(0, &[], &[]);
		state.commit(500, Vec::new(), Vec::new());
		assert!(!state.take_due(1_499, &[], &[]));
		assert!(state.take_due(1_500, &[], &[]));
	}
}
