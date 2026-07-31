//! Peer-ad, gossip relay, publish, and reconcile request handlers.

use core::hash::Hash;
use core::str::FromStr;
use std::sync::Arc;

use crate::colony::cluster::peer::AdmittedPeerAd;
use crate::colony::cluster::runtime::bounds::{ClusterDigest, ClusterPool, GatewayReplayGuard};
use crate::colony::cluster::runtime::gossip_tasks::{
	gossip_pipeline, weaken_invalid_relay, GossipOrigin, GossipPipelineCtx,
};
use crate::colony::cluster::runtime::refuse::{
	refuse_gossip, refuse_peer_ad, refuse_peer_ad_release, refuse_reconcile,
};
use crate::colony::cluster::runtime::verify::{verify_control_freshness, verify_hive_origin, verify_peer_origin};
use crate::colony::cluster::{ClusterConfig, ClusterError, PeerCaps, ServletRegistry};
use crate::colony::common::{
	current_timestamp_ms, reply_frame, GossipReconciliation, GossipRumor, GossipWant, PeerAdvertisement,
	PeerAdvertisementResponse,
};
use crate::colony::hive::{verify_frame_signature, TrustVerification};
use crate::constants::{MAX_GOSSIP_LOG, MAX_GOSSIP_TTL};
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::instrumentation::events::CLUSTER_PEER_ADVERTISED;
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{EncryptedProtocol, PersistentConnection, Protocol, X509ClientConfig};
use crate::Frame;
use crate::TightBeamError;
use crate::Version;

#[cfg(feature = "x509")]
use crate::builder::frame::FrameBuilder;
#[cfg(feature = "x509")]
use crate::builder::TypeBuilder;
#[cfg(feature = "x509")]
use crate::colony::cluster::{frame_colony_urn, gossip_want};
#[cfg(feature = "x509")]
use crate::colony::common::PeerGossip;
#[cfg(feature = "x509")]
use crate::constants::MAX_PEX_SAMPLE;

/// Admit a peer advertisement and reconcile its servlet slate.
pub(crate) async fn handle_peer_ad(
	frame: Frame,
	advertisement: PeerAdvertisement,
	servlet_registry: Arc<ServletRegistry>,
	config: Arc<ClusterConfig>,
	trace: Arc<TraceCollector>,
	replay_guard: &GatewayReplayGuard,
) -> Result<Option<Frame>, TightBeamError> {
	let origin_status = verify_peer_origin(&config, &frame);
	if origin_status != TransitStatus::Ok {
		return refuse_peer_ad(&frame, &trace, origin_status);
	}

	let freshness_status = verify_control_freshness(&frame, replay_guard);
	if freshness_status != TransitStatus::Ok {
		return refuse_peer_ad(&frame, &trace, freshness_status);
	}

	// `admit` binds signer fingerprint to dial address so they cannot swap.
	let admitted = match AdmittedPeerAd::admit(&frame, &advertisement, &config) {
		Ok(admitted) => admitted,
		Err(status) => {
			return refuse_peer_ad_release(&frame, &trace, replay_guard, status);
		}
	};

	// A verified advertiser is also a discovery hint: without it the
	// beat graph stays unidirectional and a seed-bootstrapped node is
	// never dialed back. The hint sits in the capped new table until
	// this gateway's own probe passes the colony gate.
	let hint = admitted.discovery_hint();

	if let Err(error) = servlet_registry.reconcile_peer_slate(admitted, PeerCaps::default()) {
		let status = match error {
			ClusterError::PeerSlateConflict | ClusterError::PeerCapExceeded => TransitStatus::PermissionDenied,
			_ => TransitStatus::Unavailable,
		};
		return refuse_peer_ad_release(&frame, &trace, replay_guard, status);
	}

	let _ = config.peer.table.learn(hint);
	let _ = trace.event(CLUSTER_PEER_ADVERTISED);
	reply_frame(&frame.metadata.id, PeerAdvertisementResponse { status: TransitStatus::Ok })
}

/// Admit a peer-relayed origin-signed rumor and continue the flood.
#[cfg(feature = "x509")]
pub(crate) async fn handle_gossip_relay<P, D>(
	frame: Frame,
	rumor: Box<Frame>,
	servlet_registry: Arc<ServletRegistry>,
	config: Arc<ClusterConfig>,
	pool: Arc<ClusterPool<P>>,
	peer_pool: Option<Arc<ClusterPool<P>>>,
	trace: Arc<TraceCollector>,
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
	let rumor = *rumor;
	let origin_status = verify_peer_origin(&config, &frame);
	if origin_status != TransitStatus::Ok {
		return refuse_gossip(&frame, &trace, origin_status);
	}

	// Colony flood scope (CWE-668): peer MUST share this gateway's colony URN.
	// Mismatch is policy refusal; do not score the relay.
	let Some(local_colony) = config.colony_urn() else {
		return refuse_gossip(&frame, &trace, TransitStatus::PermissionDenied);
	};
	let peer_colony = frame_colony_urn(&config.namespace, config.tls.peer_trust.as_deref(), &frame);
	if peer_colony.as_ref() != Some(local_colony) {
		return refuse_gossip(&frame, &trace, TransitStatus::PermissionDenied);
	}

	// Outer `lifetime` is hop-authenticated. Missing TTL is relay misbehavior.
	let hop_ttl = match frame.metadata.lifetime {
		Some(hop_ttl) => hop_ttl,
		None => {
			weaken_invalid_relay(GossipOrigin::Relay, &frame, &servlet_registry, &config, &trace);
			return refuse_gossip(&frame, &trace, TransitStatus::PermissionDenied);
		}
	};

	// Origin signature on the peer trust plane (§5.7.5). Unverifiable rumor scores the relay.
	let rumor_status = match config.tls.peer_trust.as_ref() {
		Some(trust) => match verify_frame_signature(trust.as_ref(), &rumor) {
			TrustVerification::Verified => TransitStatus::Ok,
			TrustVerification::MissingSignature => TransitStatus::Unauthenticated,
			_ => TransitStatus::PermissionDenied,
		},
		None => TransitStatus::PermissionDenied,
	};
	if rumor_status != TransitStatus::Ok {
		weaken_invalid_relay(GossipOrigin::Relay, &frame, &servlet_registry, &config, &trace);
		return refuse_gossip(&frame, &trace, rumor_status);
	}

	// Origin colony from the signer cert, never rumor bytes (CWE-345). Policy refuse; no score.
	let origin_colony = frame_colony_urn(&config.namespace, config.tls.peer_trust.as_deref(), &rumor);
	if origin_colony.as_ref() != Some(local_colony) {
		return refuse_gossip(&frame, &trace, TransitStatus::PermissionDenied);
	}

	// Freshness uses rumor issue time in `admit` (seen-ttl), not the control window.
	let ctx = GossipPipelineCtx { servlet_registry, config, pool, peer_pool, trace };
	gossip_pipeline::<P, D>(GossipOrigin::Relay, frame, ctx, rumor, hop_ttl).await
}

/// Mint and flood origin-signed gossip from a local hive-plane publisher.
#[cfg(feature = "x509")]
pub(crate) async fn handle_publish<P, D>(
	frame: Frame,
	body: GossipRumor,
	servlet_registry: Arc<ServletRegistry>,
	config: Arc<ClusterConfig>,
	pool: Arc<ClusterPool<P>>,
	peer_pool: Option<Arc<ClusterPool<P>>>,
	trace: Arc<TraceCollector>,
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
	let origin_status = verify_hive_origin(&config, &frame);
	if origin_status != TransitStatus::Ok {
		return refuse_gossip(&frame, &trace, origin_status);
	}

	// Origin mint scopes the flood by this gateway's colony SAN.
	if config.colony_urn().is_none() {
		return refuse_gossip(&frame, &trace, TransitStatus::PermissionDenied);
	}

	// Clamp hop radius outside the rumor body so identity stays stable.
	let radius_cap = u64::from(config.gossip.ttl.min(MAX_GOSSIP_TTL));
	let hop_ttl = frame.metadata.lifetime.unwrap_or(radius_cap).min(radius_cap);

	// Copy id/order from publish so replay remints an identical digest (CWE-294).
	let rumor = FrameBuilder::from(Version::V2)
		.with_id(&frame.metadata.id)
		.with_order(frame.metadata.order)
		.with_message(body)
		.with_witness_hasher::<D>()
		.build();
	let rumor = match rumor {
		Ok(rumor) => rumor,
		Err(_) => {
			return refuse_gossip(&frame, &trace, TransitStatus::Unavailable);
		}
	};
	let rumor = match rumor.sign_with_provider::<D, _>(config.tls.key.as_ref()).await {
		Ok(rumor) => rumor,
		Err(_) => {
			return refuse_gossip(&frame, &trace, TransitStatus::Unavailable);
		}
	};

	gossip_pipeline::<P, D>(
		GossipOrigin::Origin,
		frame,
		GossipPipelineCtx { servlet_registry, config, pool, peer_pool, trace },
		rumor,
		hop_ttl,
	)
	.await
}

/// Peer-exchange sample for a reconcile reply.
///
/// Probe-verified peers from the discovery table merge with live peer
/// routes installed from signed advertisements.
///
/// - Entries are deduped by dial address.
/// - The sample is capped at [`MAX_PEX_SAMPLE`].
/// - This gateway verified both sources.
/// - The receiver still treats every entry as an unverified hint until its
///   own probe passes the colony gate.
///
/// # Sources
///
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
#[cfg(feature = "x509")]
fn pex_sample(config: &ClusterConfig, servlet_registry: &ServletRegistry) -> Vec<PeerGossip> {
	let verified = config
		.peer
		.table
		.sample_for_pex(MAX_PEX_SAMPLE)
		.unwrap_or_default()
		.into_iter()
		.map(|record| PeerGossip {
			peer_id: record.peer_id.unwrap_or_default(),
			gateway_addr: record.gateway_addr.into_bytes(),
		});

	// Registry entries are borrowed, so the wire message copies them once.
	let routes = servlet_registry
		.peer_entries()
		.unwrap_or_default()
		.into_iter()
		.map(|entry| PeerGossip { peer_id: entry.owner_id().to_vec(), gateway_addr: entry.dial_target().to_vec() });

	// The sample never exceeds MAX_PEX_SAMPLE, so a linear scan dedupes
	// by dial address without a set allocation per entry.
	let mut pex: Vec<PeerGossip> = Vec::new();
	for candidate in verified.chain(routes) {
		if pex.len() == MAX_PEX_SAMPLE {
			break;
		}
		if !pex.iter().any(|shared| shared.gateway_addr == candidate.gateway_addr) {
			pex.push(candidate);
		}
	}

	pex
}

/// Compare peer digests and reply with digests this gateway still needs.
#[cfg(feature = "x509")]
pub(crate) async fn handle_reconcile(
	frame: Frame,
	reconciliation: GossipReconciliation,
	servlet_registry: Arc<ServletRegistry>,
	config: Arc<ClusterConfig>,
	trace: Arc<TraceCollector>,
	replay_guard: &GatewayReplayGuard,
) -> Result<Option<Frame>, TightBeamError> {
	let origin_status = verify_peer_origin(&config, &frame);
	if origin_status != TransitStatus::Ok {
		return refuse_reconcile(&frame, &trace);
	}

	// Same-colony only before freshness (CWE-668); avoid replay record on policy refuse (CWE-772).
	let requester_colony = frame_colony_urn(&config.namespace, config.tls.peer_trust.as_deref(), &frame);
	if config.colony_urn().is_none() || requester_colony.as_ref() != config.colony_urn() {
		return refuse_reconcile(&frame, &trace);
	}

	let freshness_status = verify_control_freshness(&frame, replay_guard);
	if freshness_status != TransitStatus::Ok {
		return refuse_reconcile(&frame, &trace);
	}

	// Cap held digests at journal capacity (CWE-770).
	if reconciliation.held.len() > MAX_GOSSIP_LOG {
		return refuse_reconcile(&frame, &trace);
	}

	// Journal fault: empty want; repair waits for a later beat.
	let want = match config.gossip.journal.held_digests(current_timestamp_ms()) {
		Ok(held) => gossip_want(&reconciliation.held, &held),
		Err(_) => Vec::new(),
	};

	// The reply carries the peer-exchange sample, the GossipSub v1.1 PX
	// piggyback shape. A seed-bootstrapped requester discovers the
	// colony graph on its existing beat with no extra round trip.
	let pex = pex_sample(&config, &servlet_registry);

	reply_frame(&frame.metadata.id, GossipWant { want, pex })
}
