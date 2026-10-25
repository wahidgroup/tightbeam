//! The request handlers for a peer ad, a gossip relay, a publish, and a
//! reconcile round.

use crate::builder::frame::FrameBuilder;
use crate::builder::TypeBuilder;
use crate::colony::cluster::peer::AdmittedPeerAd;
use crate::colony::cluster::runtime::bounds::{ColonyConfig, ColonyDialProtocol, ColonyDigest, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::gossip_tasks::{GossipOrigin, GossipPipelineCtx};
use crate::colony::cluster::runtime::refuse::Refusal;
use crate::colony::cluster::{ClusterConfig, ClusterError, PeerCaps, ServletRegistry, VerifiedRumor};
use crate::colony::cluster::{GossipDigest, RouteKind, WantList};
use crate::colony::common::PeerGossip;
use crate::colony::common::{
	GossipReconciliation, GossipRumor, GossipWant, PeerAdvertisement, PeerAdvertisementResponse, ReplyForm,
};
use crate::constants::MAX_PEX_SAMPLE;
use crate::constants::{MAX_GOSSIP_LOG, MAX_GOSSIP_TTL};
use crate::instrumentation::events::CLUSTER_PEER_ADVERTISED;
use crate::policy::TransitStatus;
use crate::transport::Protocol;
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
			Err(refusal) => {
				return Refusal::to(&frame, &self.trace).peer_ad(refusal.into());
			}
		};

		let signature = verified.signature();
		let freshness_status = self.replay_guard.admits(&frame, signature);
		if freshness_status != TransitStatus::Ok {
			return Refusal::to(&frame, &self.trace).peer_ad(freshness_status);
		}

		// `admit` binds the signer fingerprint to the dial address, so the
		// rest of this handler reads one bound pair.
		let admitted = match AdmittedPeerAd::admit(&verified, &advertisement, &self.config) {
			Ok(admitted) => admitted,
			Err(status) => {
				return Refusal::to(&frame, &self.trace).peer_ad_release(&self.replay_guard, signature, status);
			}
		};

		// A verified advertiser is also a discovery hint, so the beat graph
		// runs in both directions and this gateway's own probe dials a
		// seed-bootstrapped node. The hint sits in the capped new table until
		// that probe proves the address answers as a flood member.
		let hint = admitted.discovery_hint();
		let learned_at = self.config.clock.unix();
		if self.config.peer.table.learn([hint], learned_at).is_err() {
			let unavailable = TransitStatus::Unavailable;
			return Refusal::to(&frame, &self.trace).peer_ad_release(&self.replay_guard, signature, unavailable);
		}

		if let Err(error) = self.servlet_registry.reconcile_peer_slate(admitted, PeerCaps::default()) {
			let status = match error {
				ClusterError::PeerSlateConflict | ClusterError::PeerCapExceeded | ClusterError::StalePeerAd => {
					TransitStatus::PermissionDenied
				}
				_ => TransitStatus::Unavailable,
			};
			return Refusal::to(&frame, &self.trace).peer_ad_release(&self.replay_guard, signature, status);
		}

		self.trace.event(CLUSTER_PEER_ADVERTISED)?;

		ReplyForm::Plain.reply(frame.metadata().id(), PeerAdvertisementResponse { status: TransitStatus::Ok })
	}
}

impl<P: ColonyDialProtocol> GossipPipelineCtx<P> {
	/// Admit a peer-relayed origin-signed rumor and continue the flood.
	pub(crate) async fn relay(self, frame: Frame, rumor: Box<Frame>) -> Result<Option<Frame>, TightBeamError> {
		let rumor = *rumor;
		// The flood is scoped (CWE-668), so the relay peer MUST be a member of
		// it. A peer outside it is a policy refusal, so the relay's score stays
		// as it is.
		let Some(flood) = self.config.flood() else {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::PermissionDenied);
		};

		let relay_id = match self.config.verify_peer(&frame) {
			Ok(verified) => {
				if let Err(status) = flood.member(verified.signer_cert()) {
					return Refusal::to(&frame, &self.trace).gossip(status);
				}

				verified.fingerprint()
			}
			Err(refusal) => {
				return Refusal::to(&frame, &self.trace).gossip(refusal.into());
			}
		};

		// The outer `lifetime` is hop-authenticated, so an absent TTL is relay
		// misbehavior and scores the relay.
		let hop_ttl = match frame.metadata().lifetime() {
			Some(hop_ttl) => hop_ttl,
			None => {
				let scored = self.weaken_invalid_relay(GossipOrigin::Relay, Some(&relay_id));
				return Refusal::to(&frame, &self.trace).gossip_scored(scored, TransitStatus::PermissionDenied);
			}
		};

		// The origin signature verifies on the peer trust plane, and the
		// refusal settles what an unverifiable rumor costs the relay. An
		// origin outside the flood is a policy refusal, as for the relay.
		let (rumor_signer, signature) = match self.config.verify_peer(&rumor) {
			Ok(verified) => {
				if let Err(status) = flood.member(verified.signer_cert()) {
					return Refusal::to(&frame, &self.trace).gossip(status);
				}

				(verified.fingerprint(), verified.into_signature())
			}
			Err(refusal) => {
				let settled = refusal.settle_origin(&self, &frame, &relay_id);
				return Refusal::to(&frame, &self.trace).gossip_settled(settled);
			}
		};
		let rumor = VerifiedRumor::new(rumor, signature);

		// Freshness for a relayed rumor is its issue time, which `admit`
		// checks against the seen window (`seen_ttl`) rather than the control
		// window.
		self.run(GossipOrigin::Relay, frame, rumor, hop_ttl, Some(relay_id), Some(rumor_signer))
			.await
	}

	/// Signs and floods origin gossip from a local hive-plane publisher.
	pub(crate) async fn publish(self, frame: Frame, body: GossipRumor) -> Result<Option<Frame>, TightBeamError> {
		if let Err(refusal) = self.config.verify_hive(&frame) {
			return Refusal::to(&frame, &self.trace).gossip(refusal.into());
		}

		// An origin rumor travels in this gateway's flood, so a gateway in no
		// flood has nowhere to publish.
		if self.config.flood().is_none() {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::PermissionDenied);
		}

		// The handler clamps the hop radius outside the rumor body, so the
		// rumor identity stays stable.
		let radius_cap = u64::from(self.config.gossip.ttl.min(MAX_GOSSIP_TTL));
		let hop_ttl = frame.metadata().lifetime().unwrap_or(radius_cap).min(radius_cap);

		// The rumor copies the id and order of the publish frame, so a
		// replayed publish rebuilds an identical digest (CWE-294).
		let kind = body.kind;
		let builder = FrameBuilder::from(Version::V2)
			.with_id(frame.metadata().id())
			.with_order(frame.metadata().order())
			.with_message(body);

		let rumor = self.config.witnessed(builder).build();
		let mut rumor = match rumor {
			Ok(rumor) => rumor,
			Err(_) => {
				return Refusal::to(&frame, &self.trace).gossip(TransitStatus::Unavailable);
			}
		};

		let signing = rumor.sign_with_provider(self.config.tls.identity()).await;
		if signing.is_err() {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::Unavailable);
		}

		// The rumor's digest covers its signature, so `verify_own` verifies
		// the signature this gateway made and pairs the two.
		let Ok(rumor) = self.config.tls.verify_own(rumor) else {
			return Refusal::to(&frame, &self.trace).gossip(TransitStatus::Unavailable);
		};

		// A local peer-ad apply names the signer that the signature above
		// proved. A hive-plane publish floods even when peer trust holds no
		// anchor for this gateway, and the signer is then `None`.
		let rumor_signer = kind.origin_signer(|| {
			let verified = self.config.verify_peer(rumor.frame());
			verified.map(|verified| verified.fingerprint()).ok()
		});

		self.run(GossipOrigin::Origin, frame, rumor, hop_ttl, None, rumor_signer).await
	}
}

impl ClusterConfig {
	/// The peer-exchange sample of a reconcile reply.
	///
	/// Probe-verified peers from the discovery table merge with live peer
	/// routes installed from signed advertisements.
	///
	/// - The sample deduplicates its entries by dial address.
	/// - The sample holds at most [`MAX_PEX_SAMPLE`] entries.
	/// - Both sources name flood members: a probe proved each table entry, and
	///   a member's signed advertisement installed each route.
	/// - A route outlives an expel, so the sample shares a route's address
	///   only while the peer table still holds it.
	/// - The receiver still treats every entry as an unverified hint until its own probe proves membership.
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
		let direct = peer_entries.iter().filter(|entry| entry.route_kind() == RouteKind::Peer);

		// A route outlives an expel, so the table says which advertised sockets
		// it still holds, and the sample shares those alone.
		let advertised = direct.clone().filter_map(|entry| entry.dial_target().as_socket().copied());
		let held = self.peer.table.held_among(advertised)?;
		let routes = direct
			.filter(|entry| entry.dial_target().as_socket().is_some_and(|socket| held.contains(socket)))
			.map(|entry| PeerGossip {
				peer_id: entry.owner_id().to_vec(),
				gateway_addr: entry.dial_target().as_bytes().to_vec(),
			});

		// The sample holds at most `MAX_PEX_SAMPLE` entries, so a linear scan
		// deduplicates by dial address with no set allocation per entry.
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

impl<P: Protocol> ColonyConfig<P> {
	/// The digests of a peer's `advertised` list that this gateway lacks
	/// beside its `held` digests, under the colony digest, by the rule of
	/// [`WantList::against`].
	fn want_against(&self, advertised: impl AsRef<[Vec<u8>]>, held: impl AsRef<[GossipDigest]>) -> WantList {
		WantList::against::<ColonyDigest<P>>(advertised, held)
	}
}

impl<P: Protocol> GatewayRuntimeCtx<P> {
	/// Answer one anti-entropy reconcile round from a flood member.
	///
	/// The reply names the digests this gateway still needs, beside a
	/// peer-exchange sample.
	pub(crate) async fn handle_reconcile(
		&self,
		frame: Frame,
		reconciliation: GossipReconciliation,
	) -> Result<Option<Frame>, TightBeamError> {
		let Some(flood) = self.config.flood() else {
			return Refusal::to(&frame, &self.trace).reconcile();
		};
		let Ok(verified) = self.config.verify_peer(&frame) else {
			return Refusal::to(&frame, &self.trace).reconcile();
		};
		if flood.member(verified.signer_cert()).is_err() {
			return Refusal::to(&frame, &self.trace).reconcile();
		}

		let freshness_status = self.replay_guard.admits(&frame, verified.signature());
		if freshness_status != TransitStatus::Ok {
			return Refusal::to(&frame, &self.trace).reconcile();
		}

		// The handler caps the held digest list at journal capacity (CWE-770).
		if reconciliation.held.len() > MAX_GOSSIP_LOG {
			return Refusal::to(&frame, &self.trace).reconcile();
		}

		// A journal, table, or registry this gateway cannot read refuses the
		// round, so the requester repairs from a member that can answer.
		let Ok(held) = self.config.gossip.journal.held_digests(self.config.clock.unix()) else {
			return Refusal::to(&frame, &self.trace).reconcile();
		};

		let want = self.config.want_against(&reconciliation.held, &held).into_wire();

		// The reply carries the peer-exchange sample, the GossipSub v1.1 PX
		// piggyback shape. A seed-bootstrapped requester discovers the
		// colony graph on the beat it already runs, with no extra round trip.
		let Ok(pex) = self.config.pex_sample(&self.servlet_registry) else {
			return Refusal::to(&frame, &self.trace).reconcile();
		};

		ReplyForm::Plain.reply(frame.metadata().id(), GossipWant { want, pex })
	}
}
