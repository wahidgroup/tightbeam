//! Gossip background tasks: local deliver, reflood, reconcile, advertise beat.

use core::hash::Hash;
use core::str::{from_utf8, FromStr};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::colony::cluster::runtime::bounds::{ClusterDigest, ClusterPool};
use crate::colony::cluster::runtime::refuse::refuse_gossip;
use crate::colony::cluster::runtime::work::{balancer_pick, forward_work};
use crate::colony::cluster::{ClusterConfig, ClusterError, ServletRegistry};
use crate::colony::common::{canonical_bytes, reply_frame};
use crate::colony::servlet::servlet_runtime::rt;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::instrumentation::events::{
	CLUSTER_GOSSIP_ACCEPTED, CLUSTER_GOSSIP_DROP_SIGNAL, CLUSTER_GOSSIP_DUPLICATE, CLUSTER_GOSSIP_RELAY_WEAKENED,
	CLUSTER_PEER_DISCOVERED, CLUSTER_PEER_EVICTED,
};

#[cfg(feature = "x509")]
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
use crate::Frame;
use crate::TightBeamError;

#[cfg(feature = "x509")]
use core::time::Duration;

#[cfg(feature = "x509")]
use crate::builder::frame::FrameBuilder;
#[cfg(feature = "x509")]
use crate::builder::TypeBuilder;
#[cfg(feature = "x509")]
use crate::colony::cluster::peer::{cert_fingerprint_id, peer_dial_allowed, AdmittedPeerAd};
#[cfg(feature = "x509")]
use crate::colony::cluster::{
	cert_colony_urn, gossip_digest, gossip_fresh, peer_signer_fingerprint, wanted_digests, Admission, AdmittedGossip,
	GossipDigest, PeerCaps, PeerHint, RouteKind,
};
#[cfg(feature = "x509")]
use crate::colony::common::{
	current_timestamp_ms, ClusterRequest, GossipReconciliation, GossipResponse, GossipRumor, GossipRumorKind,
	GossipWant, PeerAdvertisement, PeerAdvertisementResponse, PeerGossip,
};
#[cfg(feature = "x509")]
use crate::colony::hive::{verify_frame_signature, TrustVerification};
#[cfg(feature = "x509")]
use crate::constants::{MAX_ADVERTISED_TYPES, MAX_GOSSIP_LOG, MAX_GOSSIP_TTL, MAX_PEX_SAMPLE};
#[cfg(feature = "x509")]
use crate::decode;
#[cfg(feature = "x509")]
use crate::der::Encode;
#[cfg(feature = "x509")]
use crate::encode;
#[cfg(feature = "x509")]
use crate::utils::urn::Urn;
#[cfg(feature = "x509")]
use crate::{MessagePriority, Version};

#[cfg(not(feature = "x509"))]
type GossipDigest = [u8; 32];

/// Origin of a gossip pipeline invocation.
#[derive(Clone, Copy)]
pub(crate) enum GossipOrigin {
	/// Peer-relayed rumor: invalid input may score the relay.
	Relay,
	/// Local publish: admission failure refuses without trail scoring.
	Origin,
}

/// Prefer the peer-plane pool when present. Otherwise dial peers on
/// the hive pool.
pub fn peer_dial_pool<P: Protocol>(
	peer_pool: &Option<Arc<ClusterPool<P>>>,
	pool: &Arc<ClusterPool<P>>,
) -> Arc<ClusterPool<P>> {
	peer_pool.as_ref().map(Arc::clone).unwrap_or_else(|| Arc::clone(pool))
}

/// Score a misbehaving relay peer.
///
/// An origin publish has no relay to score, so it returns without
/// effect.
pub(crate) fn weaken_invalid_relay(
	origin: GossipOrigin,
	frame: &Frame,
	servlet_registry: &ServletRegistry,
	config: &ClusterConfig,
	trace: &TraceCollector,
) {
	if matches!(origin, GossipOrigin::Origin) {
		return;
	}
	#[cfg(feature = "x509")]
	{
		if let Some(peer_id) = peer_signer_fingerprint(config.tls.peer_trust.as_deref(), frame) {
			if let Ok(weakened) = servlet_registry.weaken_peer(&peer_id) {
				if weakened > 0 {
					// Audit payload names the scored peer fingerprint.
					if let Ok(event) = trace.event(CLUSTER_GOSSIP_RELAY_WEAKENED) {
						event.with_payload(peer_id.as_ref()).emit();
					}
				}
			}
		}
	}
	#[cfg(not(feature = "x509"))]
	{
		let _ = (frame, servlet_registry, config, trace);
	}
}

fn gossip_attribution<'a>(origin: GossipOrigin, frame: &'a Frame, rumor: &'a Frame) -> &'a Frame {
	match origin {
		GossipOrigin::Origin => frame,
		GossipOrigin::Relay => rumor,
	}
}

/// Deliver one admitted rumor payload to the configured local ingress servlet.
pub(crate) async fn gossip_deliver_local<P>(
	servlet_registry: &ServletRegistry,
	config: &Arc<ClusterConfig>,
	pool: &Arc<ClusterPool<P>>,
	trace: &TraceCollector,
	payload: Vec<u8>,
	digest_value: GossipDigest,
) where
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
	match config.gossip.ingress.as_ref() {
		None => {
			let _ = config.gossip.journal.ack_local(&digest_value);
		}
		Some(ingress) => {
			let type_key = canonical_bytes(ingress);
			let entries = servlet_registry.local_entries_for_type(&type_key).unwrap_or_default();

			// An out-of-range balancer answer skips delivery instead
			// of panicking the gossip task (see [`balancer_pick`]).
			let selected = balancer_pick(config.load_balancer.as_ref(), &entries);
			if let Some(entry) = selected {
				let dial_addr = Arc::clone(entry.dial_target());
				if let Ok(_response) = forward_work(pool, dial_addr, payload).await {
					let _ = config.gossip.journal.ack_local(&digest_value);
					let _ = trace.event(CLUSTER_GOSSIP_ACCEPTED);
				}
			}
		}
	}
}

/// Fan out a still-live rumor to configured peers with decremented hop TTL.
#[cfg(feature = "x509")]
pub(crate) async fn reflood_gossip<P, D>(
	peer_pool: Arc<ClusterPool<P>>,
	config: Arc<ClusterConfig>,
	rumor: Frame,
	ttl: u64,
) where
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
	D: ClusterDigest,
{
	// Flood targets are anchors plus verified tried peers. An
	// unverified candidate never receives rumor bytes.
	let targets = config.peer.table.target_set().unwrap_or_default();
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

	let signed_frame = match frame.sign_with_provider::<D, _>(config.tls.key.as_ref()).await {
		Ok(signed) => signed,
		Err(_) => return,
	};

	let mut fanout = tokio::task::JoinSet::new();
	for peer in targets.iter() {
		let Ok(peer_addr) = peer.parse::<P::Address>() else {
			continue;
		};

		let peer_pool = Arc::clone(&peer_pool);
		let frame = signed_frame.clone();
		fanout.spawn(async move {
			if let Ok(mut client) = peer_pool.connect(peer_addr).await {
				let _ = client.emit(frame, None).await;
			}
		});
	}

	while fanout.join_next().await.is_some() {}
}

/// Mint and sign one peer advertisement frame for this gateway's slate.
///
/// One mint serves both delivery paths: the direct dial to a peer and
/// the advertisement rumor on the gossip flood, so both carry the same
/// signer-binds-to-address unit.
#[cfg(feature = "x509")]
async fn mint_ad_frame<D>(
	config: &ClusterConfig,
	gateway_addr: &[u8],
	types: Vec<Urn<'static>>,
) -> Result<Frame, ClusterError>
where
	D: ClusterDigest,
{
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

	let signed_frame = frame.sign_with_provider::<D, _>(config.tls.key.as_ref()).await?;
	Ok(signed_frame)
}

/// Sign and send one peer advertisement to a dialed peer gateway.
#[cfg(feature = "x509")]
pub(crate) async fn send_advertisement_async<P, D>(
	pool: Arc<ClusterPool<P>>,
	config: Arc<ClusterConfig>,
	peer_addr: P::Address,
	gateway_addr: Arc<[u8]>,
	types: Vec<Urn<'static>>,
) -> Result<TransitStatus, ClusterError>
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
	D: ClusterDigest,
{
	let signed_frame = mint_ad_frame::<D>(&config, gateway_addr.as_ref(), types).await?;

	let mut client = pool.connect(peer_addr).await?;
	let response = client.emit(signed_frame, None).await?.ok_or(ClusterError::NoResponse)?;

	let decoded: PeerAdvertisementResponse = decode(&response.message)?;
	Ok(decoded.status)
}

/// One minted advertisement rumor ready to witness and flood.
#[cfg(feature = "x509")]
struct MintedAdRumor {
	rumor: Frame,
	digest: GossipDigest,
	signer_id: Vec<u8>,
	minted_ms: u64,
}

/// Mint, sign, and digest one advertisement rumor for the local slate.
///
/// Returns `None` on a local fault (key, codec, or journal input). The
/// caller records it, and a later beat re-publishes fresh.
#[cfg(feature = "x509")]
async fn mint_slate_rumor<D>(
	config: &ClusterConfig,
	gateway_addr: &[u8],
	types: Vec<Urn<'static>>,
) -> Option<MintedAdRumor>
where
	D: ClusterDigest,
{
	let ad_frame = mint_ad_frame::<D>(config, gateway_addr, types).await.ok()?;
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

	let rumor = rumor.sign_with_provider::<D, _>(config.tls.key.as_ref()).await.ok()?;
	let digest = gossip_digest::<D>(&rumor).ok()?;
	let signer_id = rumor
		.nonrepudiation
		.as_ref()
		.and_then(|signer_info| Encode::to_der(&signer_info.sid).ok())?;

	Some(MintedAdRumor { rumor, digest, signer_id, minted_ms })
}

/// Publish the local slate as an origin-signed advertisement rumor.
///
/// The rumor wraps the identical signed frame that a direct
/// advertisement dials out. A member beyond direct reach therefore
/// admits it through the same signer-binds-to-address path once the
/// flood relays it.
///
/// - The published digest is witnessed, never retained. An
///   advertisement is an ephemeral hint, and re-publish is what keeps
///   it fresh.
/// - The origin never applies its own slate.
/// - A local fault skips this beat and traces
///   `CLUSTER_PEER_AD_PUBLISH_FAILED` for the audit trail. A later
///   beat publishes a fresh rumor.
#[cfg(feature = "x509")]
pub(crate) async fn publish_slate_rumor<P, D>(
	pool: Arc<ClusterPool<P>>,
	config: Arc<ClusterConfig>,
	trace: Arc<TraceCollector>,
	gateway_addr: Arc<[u8]>,
	types: Vec<Urn<'static>>,
) where
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
	D: ClusterDigest,
{
	let Some(minted) = mint_slate_rumor::<D>(&config, gateway_addr.as_ref(), types).await else {
		let _ = trace.event(CLUSTER_PEER_AD_PUBLISH_FAILED);
		return;
	};

	// Witness the published digest so the origin's own echo dedups
	// without occupying retention (ads are never repaired or retried).
	let _ = config
		.gossip
		.journal
		.witness(&minted.signer_id, minted.digest, minted.minted_ms);

	// The stamped lifetime is the budget remaining after this first
	// hop arrives, matching what the pipeline stamps when it refloods
	// a published rumor.
	let hop_ttl = u64::from(config.gossip.ttl.min(MAX_GOSSIP_TTL));
	reflood_gossip::<P, D>(pool, config, minted.rumor, hop_ttl.saturating_sub(1)).await;
}

/// Dial address of a relaying peer, from its live direct routes.
///
/// Only direct routes qualify: a relay entry's dial address belongs to
/// yet another relay, never to `relay_id` itself. Returns `None` when
/// the relay never advertised directly to this gateway. Without a
/// verified dial address there is no relay trail to install, and the
/// direct trail from the rumor still stands alone.
#[cfg(feature = "x509")]
fn relay_dial_addr(servlet_registry: &ServletRegistry, relay_id: &[u8]) -> Option<Arc<[u8]>> {
	let entries = servlet_registry.peer_entries().ok()?;
	let dial = entries
		.iter()
		.filter(|entry| entry.route_kind() == RouteKind::Peer)
		.find(|entry| entry.owner_id().as_ref() == relay_id)
		.map(|entry| Arc::clone(entry.dial_target()));

	dial
}

/// Apply one admitted peer-advertisement rumor to routing state.
///
/// The wrapped frame MUST verify on the peer trust plane, and it MUST
/// be signed by the same origin as the rumor itself. A member can
/// therefore neither create nor re-wrap another member's advertisement
/// under a fresh rumor.
///
/// - Admission follows the identical direct-ad path
///   ([`AdmittedPeerAd::admit`]): order freshness, colony gate, dial
///   allowlist, wire checks, and the discovery hint.
/// - Slate reconciliation installs a direct trail that dials the
///   origin.
/// - When this gateway's `max_hops` affords relay forwarding and the
///   relaying peer is known, a relay trail through it installs beside
///   the direct trail as the fallback route.
/// - Registry policy refuses a slate that collides with a local route.
///   The same policy keeps a gateway from installing its own echoed
///   slate as a peer route.
///
/// A learned slate traces `CLUSTER_PEER_AD_LEARNED` with the origin
/// fingerprint. Every refusal traces `CLUSTER_PEER_AD_DROPPED`, so a
/// dropped advertisement is never silent (ISO 27001 A.8.15). The drop
/// carries the rumor signer fingerprint when it is verifiable.
#[cfg(feature = "x509")]
pub(crate) fn apply_peer_ad_rumor(
	servlet_registry: &ServletRegistry,
	config: &ClusterConfig,
	trace: &TraceCollector,
	rumor: &Frame,
	relay: Option<&Frame>,
	payload: &[u8],
) {
	match try_apply_peer_ad_rumor(servlet_registry, config, trace, rumor, relay, payload) {
		Some(origin) => {
			if let Ok(event) = trace.event(CLUSTER_PEER_AD_LEARNED) {
				event.with_payload(origin.as_ref()).emit();
			}
		}
		None => {
			// The rumor signer is the closest identity a refusal can
			// name for the audit trail. An unverifiable signer drops
			// without attribution (ISO 27001 A.8.15).
			let signer = peer_signer_fingerprint(config.tls.peer_trust.as_deref(), rumor);
			if let Ok(event) = trace.event(CLUSTER_PEER_AD_DROPPED) {
				match signer {
					Some(signer) => event.with_payload(signer.as_ref()).emit(),
					None => event.emit(),
				}
			}
		}
	}
}

/// Verify, admit, and reconcile one advertisement rumor.
///
/// Returns the learned origin fingerprint, or `None` for any refusal.
/// The caller owns the learned and dropped audit events. The
/// best-effort relay-trail refusal traces here, since the ad itself
/// still learns.
#[cfg(feature = "x509")]
fn try_apply_peer_ad_rumor(
	servlet_registry: &ServletRegistry,
	config: &ClusterConfig,
	trace: &TraceCollector,
	rumor: &Frame,
	relay: Option<&Frame>,
	payload: &[u8],
) -> Option<Arc<[u8]>> {
	// `decode` borrows through `AsRef`, so the extra reference is the
	// signature's requirement, not an indirection slip.
	let inner = decode::<Frame>(&payload).ok()?;

	let trust = config.tls.peer_trust.as_ref()?;
	if !matches!(verify_frame_signature(trust.as_ref(), &inner), TrustVerification::Verified) {
		return None;
	}

	// The same-origin bind means only the advertiser itself may rumor
	// its ad. A stale ad therefore cannot travel inside a fresh rumor
	// created by someone else.
	let rumor_signer = peer_signer_fingerprint(Some(trust.as_ref()), rumor)?;
	let inner_signer = peer_signer_fingerprint(Some(trust.as_ref()), &inner)?;
	if rumor_signer != inner_signer {
		return None;
	}

	// The direct path bounds the control order through its replay
	// guard. The rumor path applies the same bound here, so a captured
	// old ad cannot outlive the withdrawal tombstone (CWE-294) and a
	// far-future order cannot pin the ad-order ledger (CWE-770).
	if !ad_order_fresh(inner.metadata.order, current_timestamp_ms(), config.control_freshness_window_ms) {
		return None;
	}

	let ClusterRequest::AdvertisePeer(advertisement) = decode::<ClusterRequest>(&inner.message).ok()? else {
		return None;
	};

	let admitted = AdmittedPeerAd::admit(&inner, &advertisement, config).ok()?;
	let origin = Arc::clone(&admitted.peer_hive_id);

	// The relay hop that delivered this rumor is itself a verified
	// peer. When this gateway may spend the two forwards a relay trail
	// needs, and the relay's dial address is known, the trail installs
	// under its own bucket beside the direct trail. Pheromone can then
	// fail over to it. Below two hops the trail could never be
	// selected, so it is never installed (CWE-772).
	let relay_id = relay.and_then(|relay_frame| peer_signer_fingerprint(Some(trust.as_ref()), relay_frame));
	let relay_trail = relay_id.filter(|_| config.peer.max_hops >= 2).and_then(|relay_id| {
		let relay_dial = relay_dial_addr(servlet_registry, &relay_id)?;
		admitted.relay_trail(&relay_id, relay_dial, &config.pheromone)
	});

	// The learned origin is also a discovery hint, exactly like a
	// direct advertiser. It waits in the capped new table until this
	// gateway's own probe passes the colony gate.
	let hint = admitted.discovery_hint();
	let _ = config.peer.table.learn(hint);

	servlet_registry.reconcile_peer_slate(admitted, PeerCaps::default()).ok()?;

	// Fallback install is best-effort: the direct trail already
	// landed, and a refused relay bucket (caps or a stale order) only
	// forfeits the fallback path. The refusal still traces, so a
	// missing fallback is diagnosable (ISO 27001 A.8.15).
	if let Some(trail) = relay_trail {
		if servlet_registry.reconcile_relay_trail(trail, PeerCaps::default()).is_err() {
			if let Ok(event) = trace.event(CLUSTER_RELAY_TRAIL_REFUSED) {
				event.with_payload(origin.as_ref()).emit();
			}
		}
	}

	Some(origin)
}

/// Whether an inner advertisement order sits inside the freshness window.
///
/// The rumor path has no signed-control replay guard, because the
/// gossip journal already dedups identical rumors by digest. This
/// order bound alone aligns the rumor path with the direct path's
/// `verify_control_freshness` order check. A replayed ad older than
/// the window never reconciles, so the ad-order tombstone covers every
/// admissible replay (CWE-294). A far-future order is refused, so it
/// cannot pin a ledger row forever (CWE-770).
#[cfg(feature = "x509")]
fn ad_order_fresh(order: u64, now: u64, window_ms: u64) -> bool {
	now.abs_diff(order) <= window_ms
}

/// Whether a reconcile reply exceeds its wire bounds.
///
/// A conforming gateway never sends more than [`MAX_GOSSIP_LOG`] wants
/// or [`MAX_PEX_SAMPLE`] peer-exchange entries, so an oversized reply
/// is abuse and the requester drops the whole round (CWE-770).
#[cfg(feature = "x509")]
fn reconcile_reply_oversized(reply: &GossipWant) -> bool {
	reply.want.len() > MAX_GOSSIP_LOG || reply.pex.len() > MAX_PEX_SAMPLE
}

/// Peer-exchange hints that this gateway may learn.
///
/// An entry must parse as a discovery hint and pass the operator's dial
/// allowlist. The allowlist gates a shared address exactly like an
/// inbound advertisement claim, so a later feeler probe never dials an
/// address the operator refused (CWE-284).
///
/// Sources:
/// - CWE-284, improper access control:
///   <https://cwe.mitre.org/data/definitions/284.html>
#[cfg(feature = "x509")]
fn admissible_pex_hints<'c>(
	pex: Vec<PeerGossip>,
	allowlist: Option<&'c [String]>,
) -> impl Iterator<Item = PeerHint> + 'c {
	pex.into_iter()
		.filter_map(|entry| PeerHint::try_from(entry).ok())
		.filter(move |hint| peer_dial_allowed(hint.gateway_addr.as_bytes(), allowlist))
}

/// One anti-entropy reconcile round with a peer, including grey-hole scoring.
///
/// An `Err` from this function is peer-attributable: the beat loops score it
/// toward eviction or probe discard. A local fault (journal, lock, frame
/// signing) skips the affected step instead, so a healthy peer is never
/// penalized for a fault on this gateway.
#[cfg(feature = "x509")]
pub(crate) async fn reconcile_gossip_async<P, D>(
	pool: Arc<ClusterPool<P>>,
	config: Arc<ClusterConfig>,
	peer_addr: P::Address,
	servlet_registry: Arc<ServletRegistry>,
	trace: Arc<TraceCollector>,
	acked: &mut HashSet<GossipDigest>,
	peer: &str,
) -> Result<(), ClusterError>
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
	D: ClusterDigest,
{
	let now = current_timestamp_ms();
	// A journal fault is this gateway's, not the peer's: skip the round so
	// the beat does not score every peer for a fault none of them caused.
	let Ok(held_digests) = config.gossip.journal.held_digests(now) else {
		return Ok(());
	};
	let held: Vec<Vec<u8>> = held_digests.iter().map(|digest| digest.to_vec()).collect();

	let mut client = pool.connect(peer_addr).await?;

	// A feeler probe reconciles on a cold single-flight connection whose
	// handshake defers to first emit.
	//
	// - Warm the lease before the gate reads the peer certificate.
	// - The gate MUST precede any request emit.
	// - Completing the handshake here is the only way to learn peer
	//   identity without first disclosing the reconcile.
	//
	// Sources:
	// - CWE-668, exposure of resource to wrong sphere:
	//   <https://cwe.mitre.org/data/definitions/668.html>
	client.complete_handshake().await?;

	// Colony scope gate: peer handshake cert MUST match local colony.
	let peer_colony = client
		.peer_certificate()
		.and_then(|cert| cert_colony_urn(&config.namespace, cert));
	if peer_colony.as_ref() != config.colony_urn() {
		// A definitive foreign identity leaves both learned tables at once.
		//
		// - Waiting out the failure threshold would keep advertising to a
		//   peer that re-keyed outside the colony.
		let _ = config.peer.table.expel(peer);
		return Ok(());
	}

	let request = ClusterRequest::ReconcileGossip(GossipReconciliation { held });

	// Frame construction and signing are local: a fault here happened
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

	let Ok(signed_frame) = frame.sign_with_provider::<D, _>(config.tls.key.as_ref()).await else {
		return Ok(());
	};
	let response = client.emit(signed_frame, None).await?.ok_or(ClusterError::NoResponse)?;
	let reply: GossipWant = decode(&response.message)?;

	// Oversized want-list or PEX sample is abuse: fail the round (CWE-770).
	// The beat then scores the peer like any failed round, so an abuser
	// is discarded from `new` or counted toward eviction from `tried`.
	if reconcile_reply_oversized(&reply) {
		return Err(ClusterError::OversizedReconcileReply);
	}

	// The reply is decoded and within bounds: the peer has proven liveness.
	// Everything below is local bookkeeping and best-effort repair inside
	// one fallible scope.
	//
	// - `?` inside the scope keeps every step, including each trace event,
	//   a usable fault-injection point (testing-fault).
	// - The boundary after the scope tolerates its error, so a local fault
	//   is never scored against the peer that just answered.
	// - A peer that dies mid-repair is caught by the next beat's dial.
	let local_round: Result<(), ClusterError> = async {
		// The completed round is the verified probe of the addrman
		// discipline. This dialed address answered a signed reconcile
		// under a same-colony certificate, so it earns a tried slot and
		// joins the beat/reflood target set.
		//
		// - Promotion waits for the reply: a pooled connection keeps its
		//   handshake certificate after the peer dies.
		// - Promoting on the gate alone would reset the failure count
		//   every beat, and a dead peer could never be evicted.
		let peer_id = client.peer_certificate().and_then(cert_fingerprint_id);
		if config.peer.table.promote(peer, peer_id.as_deref(), now)? {
			trace.event(CLUSTER_PEER_DISCOVERED)?.with_payload(peer.as_bytes()).emit();
		}

		let GossipWant { want, pex } = reply;

		// PEX entries are unverified hints.
		//
		// - The dial allowlist gates them before they are learned.
		// - They enter the capped new table only.
		// - They become dial targets solely through a later feeler probe
		//   that passes the same colony gate as above.
		//
		// Sources:
		// - CWE-345, insufficient verification of data authenticity:
		//   <https://cwe.mitre.org/data/definitions/345.html>
		let hints = admissible_pex_hints(pex, config.peer.peer_dial_allowlist.as_deref());
		config.peer.table.learn(hints)?;

		let wanted = wanted_digests(&want);

		// Grey-hole containment signal.
		//
		// - A previously acked digest wanted again while retained is a drop.
		// - Score at most one weaken per reconciliation round.
		let dropped = wanted.iter().any(|digest| acked.contains(digest));
		if dropped {
			let _ = servlet_registry.weaken_peer_by_dial(peer.as_bytes());
			trace.event(CLUSTER_GOSSIP_DROP_SIGNAL)?;
		}
		for digest in &wanted {
			acked.remove(digest);
		}

		let now = current_timestamp_ms();
		let seen_ttl_ms = config.gossip.seen_ttl.as_millis() as u64;
		let missing = config.gossip.journal.fetch(&wanted, now)?;

		// The repair push resends the journaled rumor unchanged, with
		// an outer lifetime of 0, and only while the rumor is fresh.
		let admissible = missing
			.into_iter()
			.filter(|rumor| gossip_fresh(rumor.metadata.order, seen_ttl_ms, now));

		for rumor in admissible {
			let Ok(pushed_digest) = gossip_digest::<D>(&rumor) else {
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

			let signed = frame.sign_with_provider::<D, _>(config.tls.key.as_ref()).await?;

			// Arm grey-hole ledger only on explicit Ok reply.
			if let Some(push_reply) = client.emit(signed, None).await? {
				let decoded: Result<GossipResponse, _> = decode(&push_reply.message);
				if let Ok(gossip_reply) = decoded {
					if matches!(gossip_reply.status, TransitStatus::Ok) {
						acked.insert(pushed_digest);
					}
				}
			}
		}

		Ok(())
	}
	.await;

	// Tolerate boundary: the reconcile round already succeeded, so a local
	// fault above skips the rest of the round without charging the peer.
	// The next beat retries the skipped bookkeeping and repair.
	let _ = local_round;

	Ok(())
}

/// Shared state for one gossip pipeline invocation.
#[cfg(feature = "x509")]
pub(crate) struct GossipPipelineCtx<P: Protocol> {
	pub(crate) servlet_registry: Arc<ServletRegistry>,
	pub(crate) config: Arc<ClusterConfig>,
	pub(crate) pool: Arc<ClusterPool<P>>,
	pub(crate) peer_pool: Option<Arc<ClusterPool<P>>>,
	pub(crate) trace: Arc<TraceCollector>,
}

/// Admit, rate-limit, journal, deliver locally, and optionally reflood one rumor.
#[cfg(feature = "x509")]
pub(crate) async fn gossip_pipeline<P, D>(
	origin: GossipOrigin,
	frame: Frame,
	ctx: GossipPipelineCtx<P>,
	rumor: Frame,
	hop_ttl: u64,
) -> Result<Option<Frame>, TightBeamError>
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
	D: ClusterDigest,
{
	let GossipPipelineCtx { servlet_registry, config, pool, peer_pool, trace } = ctx;

	let admitted = match AdmittedGossip::admit::<D>(
		&rumor,
		hop_ttl,
		config.gossip.seen_ttl.as_millis() as u64,
		current_timestamp_ms(),
	) {
		Ok(admitted) => admitted,
		Err(status) => {
			weaken_invalid_relay(origin, &frame, &servlet_registry, &config, &trace);
			return refuse_gossip(&frame, &trace, status);
		}
	};

	// Key rate/journal on verified origin signer, never the relay (CWE-770).
	let attributed = gossip_attribution(origin, &frame, &rumor);
	let signer_id = match attributed.nonrepudiation.as_ref() {
		Some(signer_info) => match Encode::to_der(&signer_info.sid) {
			Ok(signer_id) => signer_id,
			Err(_) => {
				return refuse_gossip(&frame, &trace, TransitStatus::PermissionDenied);
			}
		},
		None => {
			return refuse_gossip(&frame, &trace, TransitStatus::Unauthenticated);
		}
	};

	let now = current_timestamp_ms();

	// Drop known duplicates before rate admission so echoes cannot drain the bucket.
	match config.gossip.journal.seen(&admitted.digest(), now) {
		Ok(true) => {
			trace.event(CLUSTER_GOSSIP_DUPLICATE)?;
			return reply_frame(&frame.metadata.id, GossipResponse { status: TransitStatus::Ok });
		}
		Ok(false) => {}
		Err(_) => {
			return refuse_gossip(&frame, &trace, TransitStatus::Unavailable);
		}
	}

	// Rate-limit before journal/reflood (CWE-770). Backend fault refuses closed.
	match config.gossip.admission.allow(&signer_id, now) {
		Ok(true) => {}
		Ok(false) => {
			return refuse_gossip(&frame, &trace, TransitStatus::ResourceExhausted);
		}
		Err(_) => {
			return refuse_gossip(&frame, &trace, TransitStatus::Unavailable);
		}
	}

	// Application rumors retain for anti-entropy repair and delivery
	// retry. Advertisement rumors witness for dedup only, so ephemeral
	// routing hints never occupy retention or repair bandwidth.
	let journaled = match admitted.kind() {
		GossipRumorKind::Application => config.gossip.journal.record(&signer_id, admitted.digest(), &rumor, now),
		GossipRumorKind::PeerAdvertisement => config.gossip.journal.witness(&signer_id, admitted.digest(), now),
	};
	match journaled {
		Ok(Admission::Duplicate) => {
			trace.event(CLUSTER_GOSSIP_DUPLICATE)?;
			return reply_frame(&frame.metadata.id, GossipResponse { status: TransitStatus::Ok });
		}
		Ok(Admission::New) => {}
		Err(_) => {
			return refuse_gossip(&frame, &trace, TransitStatus::Unavailable);
		}
	}

	// Local consumption is separate from journal admission. Only a
	// retained application rumor acks after delivery. An advertisement
	// rumor is gateway routing control and never reaches the ingress
	// policy.
	match admitted.kind() {
		GossipRumorKind::Application => {
			let digest_value = admitted.digest();
			gossip_deliver_local::<P>(&servlet_registry, &config, &pool, &trace, admitted.into_payload(), digest_value)
				.await;
		}
		GossipRumorKind::PeerAdvertisement => {
			// Only a relayed rumor names a relay hop to fall back on.
			// A locally published ad never applies to its own origin.
			let relay = match origin {
				GossipOrigin::Relay => Some(&frame),
				GossipOrigin::Origin => None,
			};
			apply_peer_ad_rumor(&servlet_registry, &config, &trace, &rumor, relay, admitted.payload());
		}
	}

	// The reflood detaches so a slow or dead peer cannot stall the Ok
	// reply below. The rumor moves into the task unchanged, and the
	// reply only needs the outer frame id.
	if hop_ttl > 0 && config.peer.table.has_targets() {
		let reflood_pool = peer_dial_pool(&peer_pool, &pool);
		let config = Arc::clone(&config);
		let next_ttl = hop_ttl - 1;
		drop(rt::spawn(reflood_gossip::<P, D>(reflood_pool, config, rumor, next_ttl)));
	}

	reply_frame(&frame.metadata.id, GossipResponse { status: TransitStatus::Ok })
}

/// Change-driven publish state for the advertisement rumor.
///
/// The beat publishes when the slate or the flood target set changed.
/// One refresh on the configured interval lets late joiners and pruned
/// witnesses relearn the origin. Bitcoin self-announces addresses on
/// the same cadence: on change and on a slow timer, never per beat
/// (see [`DEFAULT_AD_RUMOR_REFRESH_MS`] for the source).
///
/// [`DEFAULT_AD_RUMOR_REFRESH_MS`]: crate::constants::DEFAULT_AD_RUMOR_REFRESH_MS
#[cfg(feature = "x509")]
struct AdPublishState {
	last: Option<(u64, Vec<Urn<'static>>, Vec<String>)>,
	refresh_ms: u64,
}

#[cfg(feature = "x509")]
impl AdPublishState {
	fn new(refresh: Duration) -> Self {
		let refresh_ms = u64::try_from(refresh.as_millis()).unwrap_or(u64::MAX);
		Self { last: None, refresh_ms }
	}

	/// Claim one due publish: `true` records `now` and the published
	/// state, `false` leaves the state untouched so the next beat
	/// re-evaluates against the same baseline.
	fn take_due(&mut self, now: u64, slate: &[Urn<'static>], targets: &[String]) -> bool {
		let due = match &self.last {
			None => true,
			Some((at_ms, published_slate, published_targets)) => {
				published_slate != slate
					|| published_targets != targets
					|| now.saturating_sub(*at_ms) >= self.refresh_ms
			}
		};
		if due {
			self.last = Some((now, slate.to_vec(), targets.to_vec()));
		}

		due
	}
}

/// Spawn the advertise/reconcile beat that re-announces local types to peers.
#[cfg(feature = "x509")]
pub fn build_advertise_task<P, D>(
	servlet_registry: Arc<ServletRegistry>,
	pool: Arc<ClusterPool<P>>,
	local_pool: Arc<ClusterPool<P>>,
	config: Arc<ClusterConfig>,
	gateway_addr: Arc<[u8]>,
	trace: Arc<TraceCollector>,
) -> rt::JoinHandle
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
	D: ClusterDigest,
{
	rt::spawn(async move {
		let Some(interval) = config.peer.advertise_interval else {
			return;
		};

		// A gateway must never learn itself as a peer: PEX replies echo
		// installed routes, which include this gateway's own address.
		if let Ok(local) = from_utf8(&gateway_addr) {
			let _ = config.peer.table.exclude_self(local);
		}

		// Per-peer Ok ledger for grey-hole detection. Each beat retains only
		// the live target and probe addresses, so churned PEX hints cannot
		// grow the map without bound (CWE-770).
		let mut push_ledger: HashMap<String, HashSet<GossipDigest>> = HashMap::new();
		let mut ad_publish = AdPublishState::new(config.peer.rumor_refresh);
		loop {
			rt::sleep(interval).await;

			// Retry pending local consumption (e.g. ingress registered
			// after admit, or a delivery refused by a transient fault).
			// Only application rumors retain, so only they can pend. A
			// non-application kind from a foreign journal is skipped
			// rather than delivered unvalidated.
			if let Ok(pending) = config.gossip.journal.pending_local(current_timestamp_ms()) {
				// Skip undecodable journal entries rather than deliver unvalidated.
				for rumor in pending {
					let Ok(body) = decode::<GossipRumor>(&rumor.message) else {
						continue;
					};
					let Ok(digest) = gossip_digest::<D>(&rumor) else {
						continue;
					};
					let GossipRumorKind::Application = body.kind else {
						continue;
					};

					gossip_deliver_local::<P>(&servlet_registry, &config, &local_pool, &trace, body.payload, digest)
						.await;
				}
			}

			// Beat targets are anchors plus verified tried peers.
			// Probes are unverified candidates awaiting their feeler
			// dial.
			let targets = config.peer.table.target_set().unwrap_or_default();
			let probes = config.peer.table.probe_sample(current_timestamp_ms()).unwrap_or_default();
			push_ledger.retain(|peer, _| targets.contains(peer) || probes.contains(peer));
			if targets.is_empty() && probes.is_empty() {
				continue;
			}

			let slate: Vec<Urn<'static>> = servlet_registry
				.local_servlets()
				.unwrap_or_default()
				.iter()
				.filter_map(|bytes| from_utf8(bytes).ok())
				.filter_map(|canonical| canonical.parse().ok())
				.take(MAX_ADVERTISED_TYPES)
				.collect();

			// The slate also floods as an origin-signed rumor, so
			// members beyond direct dial reach learn this gateway and
			// install a direct trail to it. The flood detaches, like
			// the pipeline reflood, because a slow or dead flood
			// target must not stall the direct advertisements below.
			let now = current_timestamp_ms();
			if config.colony_urn().is_some() && ad_publish.take_due(now, &slate, &targets) {
				drop(rt::spawn(publish_slate_rumor::<P, D>(
					Arc::clone(&pool),
					Arc::clone(&config),
					Arc::clone(&trace),
					Arc::clone(&gateway_addr),
					slate.clone(),
				)));
			}

			for peer in targets.iter() {
				let Ok(peer_addr) = peer.parse::<P::Address>() else {
					continue;
				};
				let _ = send_advertisement_async::<P, D>(
					Arc::clone(&pool),
					Arc::clone(&config),
					peer_addr.clone(),
					Arc::clone(&gateway_addr),
					slate.clone(),
				)
				.await;
				// Anti-entropy runs in the same beat, for colony
				// members only.
				if config.colony_urn().is_some() {
					let acked = push_ledger.entry(peer.clone()).or_default();
					let round = reconcile_gossip_async::<P, D>(
						Arc::clone(&pool),
						Arc::clone(&config),
						peer_addr,
						Arc::clone(&servlet_registry),
						Arc::clone(&trace),
						acked,
						peer,
					)
					.await;
					// A failed round counts toward eviction.
					//
					// - A dead tried peer frees its bucket slot after the
					//   failure threshold.
					// - Anchors never live in tried, so the count does not
					//   affect them.
					if round.is_err() && config.peer.table.record_failure(peer).unwrap_or(false) {
						if let Ok(event) = trace.event(CLUSTER_PEER_EVICTED) {
							event.with_payload(peer.as_bytes()).emit();
						}
					}
				}
			}

			// Feeler probes run reconcile only.
			//
			// - The colony gate inside the round verifies the candidate and
			//   promotes it.
			// - An unverified hint never receives the advertised slate.
			// - A failed dial discards the candidate so dead addresses cannot
			//   clog a prefix bucket.
			if config.colony_urn().is_some() {
				for peer in probes.iter() {
					let Ok(peer_addr) = peer.parse::<P::Address>() else {
						let _ = config.peer.table.discard(peer);
						continue;
					};
					let acked = push_ledger.entry(peer.clone()).or_default();
					let probed = reconcile_gossip_async::<P, D>(
						Arc::clone(&pool),
						Arc::clone(&config),
						peer_addr,
						Arc::clone(&servlet_registry),
						Arc::clone(&trace),
						acked,
						peer,
					)
					.await;
					if probed.is_err() {
						let _ = config.peer.table.discard(peer);
					}
				}
			}
		}
	})
}

#[cfg(all(test, feature = "x509"))]
mod tests {
	use super::*;
	use crate::colony::common::ColonyNamespace;

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
			assert_eq!(reconcile_reply_oversized(&reply(want_len, pex_len)), oversized);
		}
	}

	fn pex_entry(addr: &str) -> PeerGossip {
		PeerGossip { peer_id: Vec::new(), gateway_addr: addr.as_bytes().to_vec() }
	}

	#[test]
	fn pex_hints_admitted_without_allowlist() {
		let pex = vec![pex_entry("10.0.0.1:9000"), pex_entry("10.66.0.1:9000")];
		let admitted: Vec<PeerHint> = admissible_pex_hints(pex, None).collect();
		assert_eq!(admitted.len(), 2);
	}

	#[test]
	fn pex_hints_off_allowlist_refused() {
		let allowlist = vec![String::from("10.0.0.1:9000")];
		let pex = vec![pex_entry("10.0.0.1:9000"), pex_entry("10.66.0.1:9000")];
		let admitted: Vec<PeerHint> = admissible_pex_hints(pex, Some(&allowlist)).collect();
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
		assert!(ad_order_fresh(1_500, 2_000, 500));
		assert!(ad_order_fresh(2_500, 2_000, 500));
	}

	#[test]
	fn ad_order_older_than_window_is_stale() {
		assert!(!ad_order_fresh(1_499, 2_000, 500));
	}

	#[test]
	fn ad_order_past_future_window_is_stale() {
		assert!(!ad_order_fresh(2_501, 2_000, 500));
		assert!(!ad_order_fresh(u64::MAX, 2_000, 500));
	}

	#[test]
	fn ad_publish_first_beat_is_due() {
		let mut state = AdPublishState::new(Duration::from_millis(1_000));
		assert!(state.take_due(0, &[], &[]));
	}

	#[test]
	fn ad_publish_unchanged_state_suppresses_until_refresh() {
		let mut state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(0, &[], &[]);

		assert!(!state.take_due(999, &[], &[]));
		assert!(state.take_due(1_000, &[], &[]));
	}

	#[test]
	fn ad_publish_slate_change_fires_before_refresh() {
		let mut state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(0, &[], &[]);

		assert!(state.take_due(1, &ad_slate(&["ping"]), &[]));
	}

	#[test]
	fn ad_publish_target_change_fires_before_refresh() {
		let mut state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(0, &[], &[]);

		assert!(state.take_due(1, &[], &[String::from("peer:1")]));
	}

	#[test]
	fn ad_publish_suppressed_beat_keeps_the_refresh_baseline() {
		let mut state = AdPublishState::new(Duration::from_millis(1_000));
		state.take_due(0, &[], &[]);
		state.take_due(500, &[], &[]);

		assert!(state.take_due(1_000, &[], &[]));
	}
}
