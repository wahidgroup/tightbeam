//! Gossip background tasks: local deliver, reflood, reconcile, advertise beat.

use core::hash::Hash;
use core::str::{from_utf8, FromStr};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::colony::cluster::runtime::bounds::{ClusterDigest, ClusterPool};
use crate::colony::cluster::runtime::refuse::refuse_gossip;
use crate::colony::cluster::runtime::work::forward_work;
use crate::colony::cluster::{ClusterConfig, ClusterError, ServletRegistry};
use crate::colony::common::{canonical_bytes, reply_frame, InstanceMetrics};
use crate::colony::servlet::servlet_runtime::rt;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::instrumentation::events::{
	CLUSTER_GOSSIP_ACCEPTED, CLUSTER_GOSSIP_DROP_SIGNAL, CLUSTER_GOSSIP_DUPLICATE, CLUSTER_GOSSIP_RELAY_WEAKENED,
	CLUSTER_PEER_DISCOVERED, CLUSTER_PEER_EVICTED,
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
use crate::builder::frame::FrameBuilder;
#[cfg(feature = "x509")]
use crate::builder::TypeBuilder;
#[cfg(feature = "x509")]
use crate::colony::cluster::peer::cert_fingerprint_id;
#[cfg(feature = "x509")]
use crate::colony::cluster::{
	cert_colony_urn, gossip_digest, gossip_fresh, peer_signer_fingerprint, wanted_digests, Admission, AdmittedGossip,
	GossipDigest, PeerHint,
};
#[cfg(feature = "x509")]
use crate::colony::common::{
	current_timestamp_ms, ClusterRequest, GossipReconciliation, GossipResponse, GossipRumor, GossipWant,
	PeerAdvertisement, PeerAdvertisementResponse,
};
#[cfg(feature = "x509")]
use crate::constants::{MAX_ADVERTISED_TYPES, MAX_GOSSIP_LOG, MAX_PEX_SAMPLE};
#[cfg(feature = "x509")]
use crate::decode;
#[cfg(feature = "x509")]
use crate::der::Encode;
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

/// Prefer the peer-plane pool when present; otherwise dial peers on the hive pool.
pub fn peer_dial_pool<P: Protocol>(
	peer_pool: &Option<Arc<ClusterPool<P>>>,
	pool: &Arc<ClusterPool<P>>,
) -> Arc<ClusterPool<P>> {
	peer_pool.as_ref().map(Arc::clone).unwrap_or_else(|| Arc::clone(pool))
}

/// Score a misbehaving relay peer. No-op for origin publishes.
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

			let metrics: Vec<InstanceMetrics> = entries
				.iter()
				.map(|entry| InstanceMetrics {
					instance_key: entry.route_key().to_vec(),
					pheromone: entry.pheromone_level(),
				})
				.collect();

			if let Some(selected_idx) = config.load_balancer.select(&metrics) {
				let dial_addr = Arc::clone(entries[selected_idx].dial_target());
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
	// Flood targets are anchors plus verified tried peers; an
	// unverified candidate never receives rumor bytes.
	let targets = config.peer.table.target_set().unwrap_or_default();
	if targets.is_empty() {
		return;
	}

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
	let gateway_addr = gateway_addr.as_ref().to_vec();
	let request = ClusterRequest::AdvertisePeer(PeerAdvertisement { gateway_addr, advertised_types: types });
	let frame = FrameBuilder::from(Version::V2)
		.with_id(b"peer-advertise")
		.with_order(current_timestamp_ms())
		.with_message(request)
		.with_priority(MessagePriority::NetworkControl)
		.with_witness_hasher::<D>()
		.build()?;

	let signed_frame = frame.sign_with_provider::<D, _>(config.tls.key.as_ref()).await?;

	let mut client = pool.connect(peer_addr).await?;
	let response = client.emit(signed_frame, None).await?.ok_or(ClusterError::NoResponse)?;

	let decoded: PeerAdvertisementResponse = decode(&response.message)?;
	Ok(decoded.status)
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

/// One anti-entropy reconcile round with a peer, including grey-hole scoring.
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
	let held: Vec<Vec<u8>> = config
		.gossip
		.journal
		.held_digests(now)?
		.iter()
		.map(|digest| digest.to_vec())
		.collect();

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

	let frame = FrameBuilder::from(Version::V2)
		.with_id(b"gossip-reconcile")
		.with_order(now)
		.with_message(request)
		.with_priority(MessagePriority::NetworkControl)
		.with_witness_hasher::<D>()
		.build()?;

	let signed_frame = frame.sign_with_provider::<D, _>(config.tls.key.as_ref()).await?;
	let response = client.emit(signed_frame, None).await?.ok_or(ClusterError::NoResponse)?;
	let reply: GossipWant = decode(&response.message)?;

	// Oversized want-list or PEX sample is abuse: drop the round (CWE-770).
	if reconcile_reply_oversized(&reply) {
		return Ok(());
	}

	// The completed round is the verified probe of the addrman discipline.
	// This dialed address answered a signed reconcile under a same-colony
	// certificate, so it earns a tried slot and joins the beat/reflood
	// target set.
	//
	// - Promotion waits for the reply: a pooled connection keeps its
	//   handshake certificate after the peer dies.
	// - Promoting on the gate alone would reset the failure count every
	//   beat, and a dead peer could never be evicted.
	let peer_id = client.peer_certificate().and_then(cert_fingerprint_id);
	if config.peer.table.promote(peer, peer_id.as_deref(), now)? {
		if let Ok(event) = trace.event(CLUSTER_PEER_DISCOVERED) {
			event.with_payload(peer.as_bytes()).emit();
		}
	}

	let GossipWant { want, pex } = reply;

	// PEX entries are unverified hints.
	//
	// - They enter the capped new table only.
	// - They become dial targets solely through a later feeler probe that
	//   passes the same colony gate as above.
	//
	// Sources:
	// - CWE-345, insufficient verification of data authenticity:
	//   <https://cwe.mitre.org/data/definitions/345.html>
	let hints = pex.into_iter().filter_map(|entry| PeerHint::try_from(entry).ok());
	let _ = config.peer.table.learn(hints)?;

	let wanted = wanted_digests(&want);

	// Grey-hole containment signal.
	//
	// - A previously acked digest wanted again while retained is a drop.
	// - Score at most one weaken per reconciliation round.
	let dropped = wanted.iter().any(|digest| acked.contains(digest));
	if dropped {
		let _ = servlet_registry.weaken_peer_by_dial(peer.as_bytes());
		let _ = trace.event(CLUSTER_GOSSIP_DROP_SIGNAL);
	}
	for digest in &wanted {
		acked.remove(digest);
	}

	let now = current_timestamp_ms();
	let seen_ttl_ms = config.gossip.seen_ttl.as_millis() as u64;
	let missing = config.gossip.journal.fetch(&wanted, now)?;

	// Repair push: verbatim rumor, outer lifetime 0, only if still fresh.
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
			let _ = trace.event(CLUSTER_GOSSIP_DUPLICATE);
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

	match config.gossip.journal.record(&signer_id, admitted.digest(), &rumor, now) {
		Ok(Admission::Duplicate) => {
			let _ = trace.event(CLUSTER_GOSSIP_DUPLICATE);
			return reply_frame(&frame.metadata.id, GossipResponse { status: TransitStatus::Ok });
		}
		Ok(Admission::New) => {}
		Err(_) => {
			return refuse_gossip(&frame, &trace, TransitStatus::Unavailable);
		}
	}

	// Local delivery is separate from journal record; ack only after delivery.
	gossip_deliver_local::<P>(
		&servlet_registry,
		&config,
		&pool,
		&trace,
		admitted.payload().to_vec(),
		admitted.digest(),
	)
	.await;

	// Detached reflood: verbatim rumor, decremented outer TTL. Skip if no peers.
	if hop_ttl > 0 && config.peer.table.has_targets() {
		let reflood_pool = peer_dial_pool(&peer_pool, &pool);
		let config = Arc::clone(&config);
		let reflood_rumor = rumor.clone();
		let next_ttl = hop_ttl - 1;
		drop(rt::spawn(reflood_gossip::<P, D>(reflood_pool, config, reflood_rumor, next_ttl)));
	}

	reply_frame(&frame.metadata.id, GossipResponse { status: TransitStatus::Ok })
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

		// Per-peer Ok ledger for grey-hole detection; bounded by journal x peers (CWE-770).
		let mut push_ledger: HashMap<String, HashSet<GossipDigest>> = HashMap::new();

		loop {
			rt::sleep(interval).await;

			// Retry pending local delivery (e.g. ingress registered after admit).
			if let Ok(pending) = config.gossip.journal.pending_local(current_timestamp_ms()) {
				// Skip undecodable journal entries rather than deliver unvalidated.
				for rumor in pending {
					let Ok(body) = decode::<GossipRumor>(&rumor.message) else {
						continue;
					};
					let Ok(digest) = gossip_digest::<D>(&rumor) else {
						continue;
					};

					gossip_deliver_local::<P>(&servlet_registry, &config, &local_pool, &trace, body.payload, digest)
						.await;
				}
			}

			// Beat targets are anchors plus verified tried peers; probes
			// are unverified candidates awaiting their feeler dial.
			let targets = config.peer.table.target_set().unwrap_or_default();
			let probes = config.peer.table.probe_sample(current_timestamp_ms()).unwrap_or_default();
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
				// Same-beat anti-entropy; colony members only.
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
	use crate::colony::common::PeerGossip;

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
}
