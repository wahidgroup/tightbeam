//! Peer-ad, gossip relay, publish, and reconcile request handlers.

use core::hash::Hash;
use core::str::FromStr;

use crate::builder::frame::FrameBuilder;
use crate::builder::TypeBuilder;
use crate::colony::cluster::peer::AdmittedPeerAd;
use crate::colony::cluster::runtime::bounds::{ClusterDigest, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::gossip_tasks::{GossipOrigin, GossipPipelineCtx};
use crate::colony::cluster::runtime::refuse::Refusal;
use crate::colony::cluster::{gossip_want, RouteKind};
use crate::colony::cluster::{ClusterConfig, ClusterError, PeerCaps, ServletRegistry};
use crate::colony::common::PeerGossip;
use crate::colony::common::{
	current_timestamp_ms, reply_frame, GossipReconciliation, GossipRumor, GossipWant, PeerAdvertisement,
	PeerAdvertisementResponse,
};
use crate::colony::hive::{verify_frame_signature, TrustVerification};
use crate::constants::MAX_PEX_SAMPLE;
use crate::constants::{MAX_GOSSIP_LOG, MAX_GOSSIP_TTL};
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::instrumentation::events::CLUSTER_PEER_ADVERTISED;
use crate::policy::TransitStatus;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{EncryptedProtocol, PersistentConnection, Protocol, X509ClientConfig};
use crate::Frame;
use crate::TightBeamError;
use crate::Version;

impl<P: Protocol> GatewayRuntimeCtx<P> {
	/// Admit one directly dialed peer advertisement and reconcile its slate.
	pub(crate) async fn handle_peer_ad(
		&self,
		frame: Frame,
		advertisement: PeerAdvertisement,
	) -> Result<Option<Frame>, TightBeamError> {
		let origin_status = self.config.verify_peer_origin(&frame);
		if origin_status != TransitStatus::Ok {
			return Refusal::to(&frame, &self.trace).peer_ad(origin_status);
		}

		let freshness_status = self.replay_guard.admits(&frame);
		if freshness_status != TransitStatus::Ok {
			return Refusal::to(&frame, &self.trace).peer_ad(freshness_status);
		}

		// `admit` binds signer fingerprint to dial address, so the pair holds together.
		let admitted = match AdmittedPeerAd::admit(&frame, &advertisement, &self.config) {
			Ok(admitted) => admitted,
			Err(status) => {
				return Refusal::to(&frame, &self.trace).peer_ad_release(&self.replay_guard, status);
			}
		};

		// A verified advertiser is also a discovery hint: without it the
		// beat graph stays unidirectional and a seed-bootstrapped node is
		// dialed on this gateway's own probe. The hint sits in the capped new table until
		// this gateway's own probe passes the colony gate.
		//
		// Learning precedes slate reconciliation because the hint depends
		// only on the admitted identity and dial address, not on routing
		// state, so graph connectivity survives a slate refusal below.
		let hint = admitted.discovery_hint();
		let _ = self.config.peer.table.learn(hint);

		if let Err(error) = self.servlet_registry.reconcile_peer_slate(admitted, PeerCaps::default()) {
			let status = match error {
				ClusterError::PeerSlateConflict | ClusterError::PeerCapExceeded | ClusterError::StalePeerAd => {
					TransitStatus::PermissionDenied
				}
				_ => TransitStatus::Unavailable,
			};
			return Refusal::to(&frame, &self.trace).peer_ad_release(&self.replay_guard, status);
		}

		self.trace.event(CLUSTER_PEER_ADVERTISED)?;

		reply_frame(&frame.metadata.id, PeerAdvertisementResponse { status: TransitStatus::Ok })
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
	/// Admit a peer-relayed origin-signed rumor and continue the flood.
	pub(crate) async fn relay<D: ClusterDigest>(
		self,
		frame: Frame,
		rumor: Box<Frame>,
	) -> Result<Option<Frame>, TightBeamError> {
		let rumor = *rumor;
		let origin_status = self.config.verify_peer_origin(&frame);
		if origin_status != TransitStatus::Ok {
			return Refusal::to(&frame, &self.trace).gossip(origin_status);
		}

		// Colony flood scope (CWE-668): peer MUST share gateway's colony URN.
		// Mismatch is policy refusal. Do not score the relay.
		let Some(local_colony) = self.config.colony_urn() else {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::PermissionDenied);
		};

		let peer_colony = self
			.config
			.namespace
			.frame_colony_urn(self.config.tls.peer_trust.as_deref(), &frame);
		if peer_colony.as_ref() != Some(local_colony) {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::PermissionDenied);
		}

		// Outer `lifetime` is hop-authenticated. Missing TTL is relay misbehavior.
		let hop_ttl = match frame.metadata.lifetime {
			Some(hop_ttl) => hop_ttl,
			None => {
				self.weaken_invalid_relay(GossipOrigin::Relay, &frame)?;
				return Refusal::to(&frame, &self.trace).gossip(TransitStatus::PermissionDenied);
			}
		};

		// Origin signature on the peer trust plane (§5.7.5). Unverifiable rumor scores the relay.
		let rumor_status = match self.config.tls.peer_trust.as_ref() {
			Some(trust) => match verify_frame_signature(trust.as_ref(), &rumor) {
				TrustVerification::Verified => TransitStatus::Ok,
				TrustVerification::MissingSignature => TransitStatus::Unauthenticated,
				_ => TransitStatus::PermissionDenied,
			},
			None => TransitStatus::PermissionDenied,
		};
		if rumor_status != TransitStatus::Ok {
			self.weaken_invalid_relay(GossipOrigin::Relay, &frame)?;
			return Refusal::to(&frame, &self.trace).gossip(rumor_status);
		}

		// Origin colony comes from the signer cert (CWE-345). A mismatch
		// refuses on policy, and relay scoring stays with wire faults.
		let origin_colony = self
			.config
			.namespace
			.frame_colony_urn(self.config.tls.peer_trust.as_deref(), &rumor);
		if origin_colony.as_ref() != Some(local_colony) {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::PermissionDenied);
		}

		// Freshness uses rumor issue time in `admit` (seen-ttl), not the control window.
		self.run::<D>(GossipOrigin::Relay, frame, rumor, hop_ttl).await
	}

	/// Mint and flood origin-signed gossip from a local hive-plane publisher.
	pub(crate) async fn publish<D: ClusterDigest>(
		self,
		frame: Frame,
		body: GossipRumor,
	) -> Result<Option<Frame>, TightBeamError> {
		let origin_status = self.config.verify_hive_origin(&frame);
		if origin_status != TransitStatus::Ok {
			return Refusal::to(&frame, &self.trace).gossip(origin_status);
		}

		// Origin mint scopes the flood by this gateway's colony SAN.
		if self.config.colony_urn().is_none() {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::PermissionDenied);
		}

		// Clamp hop radius outside the rumor body so identity stays stable.
		let radius_cap = u64::from(self.config.gossip.ttl.min(MAX_GOSSIP_TTL));
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
				return Refusal::to(&frame, &self.trace).gossip(TransitStatus::Unavailable);
			}
		};
		let rumor = match rumor
			.sign_with_provider::<D, _>(self.config.tls.identity().signing_provider())
			.await
		{
			Ok(rumor) => rumor,
			Err(_) => {
				return Refusal::to(&frame, &self.trace).gossip(TransitStatus::Unavailable);
			}
		};

		self.run::<D>(GossipOrigin::Origin, frame, rumor, hop_ttl).await
	}
}

impl ClusterConfig {
	/// Peer-exchange sample for a reconcile reply.
	///
	/// Probe-verified peers from the discovery table merge with live peer
	/// routes installed from signed advertisements.
	///
	/// - Entries are deduped by dial address.
	/// - The sample is capped at [`MAX_PEX_SAMPLE`].
	/// - This gateway verified both sources.
	/// - The receiver still treats every entry as an unverified hint until
	///   its own probe passes the colony gate.
	///
	/// # Sources
	///
	/// - CWE-770, allocation of resources without limits or throttling:
	///   <https://cwe.mitre.org/data/definitions/770.html>
	fn pex_sample(&self, servlet_registry: &ServletRegistry) -> Vec<PeerGossip> {
		let verified = self
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
		// Only direct routes qualify: a relay trail pairs the origin's
		// identity with the relay's dial address, which is not a dialable
		// hint.
		let routes = servlet_registry
			.peer_entries()
			.unwrap_or_default()
			.into_iter()
			.filter(|entry| entry.route_kind() == RouteKind::Peer)
			.map(|entry| PeerGossip { peer_id: entry.owner_id().to_vec(), gateway_addr: entry.dial_target().to_vec() });

		// The sample holds to MAX_PEX_SAMPLE, so a linear scan dedupes
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
}

/// Compare peer digests and reply with digests this gateway still needs.
impl<P: Protocol> GatewayRuntimeCtx<P> {
	/// Answer one anti-entropy reconcile round from a colony member.
	pub(crate) async fn handle_reconcile(
		&self,
		frame: Frame,
		reconciliation: GossipReconciliation,
	) -> Result<Option<Frame>, TightBeamError> {
		let origin_status = self.config.verify_peer_origin(&frame);
		if origin_status != TransitStatus::Ok {
			return Refusal::to(&frame, &self.trace).reconcile();
		}

		// Same-colony only before freshness (CWE-668). A policy refuse
		// must not leave a replay record behind (CWE-772).
		let requester_colony = self
			.config
			.namespace
			.frame_colony_urn(self.config.tls.peer_trust.as_deref(), &frame);
		if self.config.colony_urn().is_none() || requester_colony.as_ref() != self.config.colony_urn() {
			return Refusal::to(&frame, &self.trace).reconcile();
		}

		let freshness_status = self.replay_guard.admits(&frame);
		if freshness_status != TransitStatus::Ok {
			return Refusal::to(&frame, &self.trace).reconcile();
		}

		// Cap held digests at journal capacity (CWE-770).
		if reconciliation.held.len() > MAX_GOSSIP_LOG {
			return Refusal::to(&frame, &self.trace).reconcile();
		}

		// A journal fault yields an empty want. Repair waits for a later beat.
		let want = match self.config.gossip.journal.held_digests(current_timestamp_ms()) {
			Ok(held) => gossip_want(&reconciliation.held, &held),
			Err(_) => Vec::new(),
		};

		// The reply carries the peer-exchange sample, the GossipSub v1.1 PX
		// piggyback shape. A seed-bootstrapped requester discovers the
		// colony graph on its existing beat with no extra round trip.
		let pex = self.config.pex_sample(&self.servlet_registry);

		reply_frame(&frame.metadata.id, GossipWant { want, pex })
	}
}
