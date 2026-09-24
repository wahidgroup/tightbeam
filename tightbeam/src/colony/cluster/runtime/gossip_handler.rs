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
	reply_frame, GossipReconciliation, GossipRumor, GossipRumorKind, GossipWant, PeerAdvertisement,
	PeerAdvertisementResponse,
};
use crate::constants::MAX_PEX_SAMPLE;
use crate::constants::{MAX_GOSSIP_LOG, MAX_GOSSIP_TTL};
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::instrumentation::events::CLUSTER_PEER_ADVERTISED;
use crate::policy::TransitStatus;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{EncryptedProtocol, PersistentConnection, Protocol};
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
		let verified = match self.config.verify_peer(&frame) {
			Ok(verified) => verified,
			Err(status) => {
				return Refusal::to(&frame, &self.trace).peer_ad(status);
			}
		};

		let freshness_status = self.replay_guard.admits(&frame);
		if freshness_status != TransitStatus::Ok {
			return Refusal::to(&frame, &self.trace).peer_ad(freshness_status);
		}

		// `admit` binds the signer fingerprint to the dial address, so the
		// rest of this handler reads one bound pair.
		let admitted = match AdmittedPeerAd::admit(&verified, &advertisement, &self.config) {
			Ok(admitted) => admitted,
			Err(status) => {
				return Refusal::to(&frame, &self.trace).peer_ad_release(&self.replay_guard, status);
			}
		};

		// A verified advertiser is also a discovery hint, so the beat graph
		// runs in both directions and this gateway's own probe dials a
		// seed-bootstrapped node. The hint sits in the capped new table until
		// that probe passes the colony gate.
		let hint = admitted.discovery_hint();
		if self.config.peer.table.learn([hint]).is_err() {
			return Refusal::to(&frame, &self.trace).peer_ad_release(&self.replay_guard, TransitStatus::Unavailable);
		}

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

		reply_frame(frame.metadata().id(), PeerAdvertisementResponse { status: TransitStatus::Ok })
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
		// The flood is scoped to one colony (CWE-668), so the relaying peer
		// MUST share this gateway's colony URN. A mismatch is a policy
		// refusal, so the relay's score stays as it is.
		let Some(local_colony) = self.config.colony_urn() else {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::PermissionDenied);
		};

		let relay_id = match self.config.verify_peer(&frame) {
			Ok(verified) => {
				let peer_colony = self.config.namespace.cert_colony_urn(verified.signer_cert());
				if peer_colony.as_ref() != Some(local_colony) {
					return Refusal::to(&frame, &self.trace).gossip(TransitStatus::PermissionDenied);
				}

				verified.fingerprint()
			}
			Err(status) => {
				return Refusal::to(&frame, &self.trace).gossip(status);
			}
		};

		// The outer `lifetime` is hop-authenticated, so a missing TTL is relay
		// misbehavior and scores the relay.
		let hop_ttl = match frame.metadata().lifetime() {
			Some(hop_ttl) => hop_ttl,
			None => {
				let scored = self.weaken_invalid_relay(GossipOrigin::Relay, Some(&relay_id));
				return Refusal::to(&frame, &self.trace).gossip_scored(scored, TransitStatus::PermissionDenied);
			}
		};

		// The origin signature verifies on the peer trust plane, and an
		// unverifiable rumor scores the relay.
		let (origin_colony, rumor_signer) = match self.config.verify_peer(&rumor) {
			Ok(verified) => {
				let colony = self.config.namespace.cert_colony_urn(verified.signer_cert());
				let signer = verified.fingerprint();
				(colony, signer)
			}
			Err(status) => {
				let scored = self.weaken_invalid_relay(GossipOrigin::Relay, Some(&relay_id));
				return Refusal::to(&frame, &self.trace).gossip_scored(scored, status);
			}
		};
		if origin_colony.as_ref() != Some(local_colony) {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::PermissionDenied);
		}

		// Freshness for a relayed rumor is its issue time, which `admit`
		// checks against the seen TTL (seen-ttl) rather than the control
		// window.
		self.run::<D>(GossipOrigin::Relay, frame, rumor, hop_ttl, Some(relay_id), Some(rumor_signer))
			.await
	}

	/// Signs and floods origin gossip from a local hive-plane publisher.
	pub(crate) async fn publish<D: ClusterDigest>(
		self,
		frame: Frame,
		body: GossipRumor,
	) -> Result<Option<Frame>, TightBeamError> {
		if let Err(status) = self.config.verify_hive(&frame) {
			return Refusal::to(&frame, &self.trace).gossip(status);
		}

		// An origin rumor is scoped by this gateway's colony SAN, which the
		// gateway MUST hold to publish.
		if self.config.colony_urn().is_none() {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::PermissionDenied);
		}

		// The hop radius is clamped outside the rumor body, so the rumor
		// identity stays stable.
		let radius_cap = u64::from(self.config.gossip.ttl.min(MAX_GOSSIP_TTL));
		let hop_ttl = frame.metadata().lifetime().unwrap_or(radius_cap).min(radius_cap);

		// The rumor copies the id and order of the publish frame, so a
		// replayed publish rebuilds an identical digest (CWE-294).
		let peer_ad = matches!(body.kind, GossipRumorKind::PeerAdvertisement);
		let rumor = FrameBuilder::from(Version::V2)
			.with_id(frame.metadata().id())
			.with_order(frame.metadata().order())
			.with_message(body)
			.with_witness_hasher::<D>()
			.build();
		let mut rumor = match rumor {
			Ok(rumor) => rumor,
			Err(_) => {
				return Refusal::to(&frame, &self.trace).gossip(TransitStatus::Unavailable);
			}
		};
		let signing = rumor
			.sign_with_provider::<D, _>(self.config.tls.identity().signing_provider())
			.await;
		if signing.is_err() {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::Unavailable);
		}

		// A local peer-ad apply names the signer that this signing step
		// proved. A hive-plane publish floods even when peer trust holds no
		// anchor for this gateway, and the signer is then `None`.
		let rumor_signer = if peer_ad {
			self.config.verify_peer(&rumor).map(|verified| verified.fingerprint()).ok()
		} else {
			None
		};

		self.run::<D>(GossipOrigin::Origin, frame, rumor, hop_ttl, None, rumor_signer)
			.await
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
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the discovery table or the route registry is poisoned.
	fn pex_sample(&self, servlet_registry: &ServletRegistry) -> Result<Vec<PeerGossip>, ClusterError> {
		let sampled = self.peer.table.sample_for_pex(MAX_PEX_SAMPLE)?;
		let verified = sampled.into_iter().map(|record| PeerGossip {
			peer_id: record.peer_id.unwrap_or_default(),
			gateway_addr: record.gateway_addr.to_string().into_bytes(),
		});

		// Registry entries are borrowed, so the wire message copies them once.
		// Only direct routes qualify, because a relay trail pairs the origin's
		// identity with the relay's dial address, and that pair names no
		// dialable peer.
		let peer_entries = servlet_registry.peer_entries()?;
		let routes = peer_entries
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

		Ok(pex)
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
		let requester_colony = match self.config.verify_peer(&frame) {
			Ok(verified) => self.config.namespace.cert_colony_urn(verified.signer_cert()),
			Err(_) => {
				return Refusal::to(&frame, &self.trace).reconcile();
			}
		};
		if self.config.colony_urn().is_none() || requester_colony.as_ref() != self.config.colony_urn() {
			return Refusal::to(&frame, &self.trace).reconcile();
		}

		let freshness_status = self.replay_guard.admits(&frame);
		if freshness_status != TransitStatus::Ok {
			return Refusal::to(&frame, &self.trace).reconcile();
		}

		// The held digest list is capped at journal capacity (CWE-770).
		if reconciliation.held.len() > MAX_GOSSIP_LOG {
			return Refusal::to(&frame, &self.trace).reconcile();
		}

		// A journal, table or registry this gateway cannot read refuses the
		// round, so the requester repairs from a member that can answer.
		let Ok(held) = self.config.gossip.journal.held_digests(self.config.clock.unix()) else {
			return Refusal::to(&frame, &self.trace).reconcile();
		};
		let want = gossip_want(&reconciliation.held, &held);

		// The reply carries the peer-exchange sample, the GossipSub v1.1 PX
		// piggyback shape. A seed-bootstrapped requester discovers the
		// colony graph on its existing beat with no extra round trip.
		let Ok(pex) = self.config.pex_sample(&self.servlet_registry) else {
			return Refusal::to(&frame, &self.trace).reconcile();
		};

		reply_frame(frame.metadata().id(), GossipWant { want, pex })
	}
}
