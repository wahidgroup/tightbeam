//! The request handlers for a peer ad, a gossip relay, a publish, and a
//! reconcile round.

use std::sync::Arc;

use crate::builder::frame::FrameBuilder;
use crate::builder::TypeBuilder;
use crate::colony::cluster::peer::AdmittedPeerAd;
use crate::colony::cluster::runtime::bounds::{ColonyConfig, ColonyDialProtocol, ColonyDigest, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::gossip_tasks::{GossipOrigin, GossipPipelineCtx, HintSource};
use crate::colony::cluster::runtime::refuse::Refusal;
use crate::colony::cluster::runtime::verify::RequestAudit;
use crate::colony::cluster::{ClusterConfig, ClusterError, PeerCaps, ServletRegistry, VerifiedRumor};
use crate::colony::cluster::{GossipDigest, RouteKind, WantList};
use crate::colony::protocol::PeerGossip;
use crate::colony::protocol::{
	GossipReconciliation, GossipRumor, GossipWant, PeerAdvertisement, PeerAdvertisementResponse, ReplyForm,
};
use crate::constants::MAX_PEX_SAMPLE;
use crate::constants::{MAX_GOSSIP_LOG, MAX_GOSSIP_TTL};
use crate::instrumentation::events::{CLUSTER_PEER_ADVERTISED, CLUSTER_RECONCILE_ANSWERED};
use crate::policy::TransitStatus;
use crate::transport::Protocol;
use crate::Frame;
use crate::TightBeamError;
use crate::Version;

impl<P: Protocol> GatewayRuntimeCtx<P> {
	/// Admits one directly dialed peer advertisement and reconciles its slate.
	///
	/// It records the hint it learns from the advertiser, the routes the slate
	/// installs and withdraws, and the admission, each before the reply.
	pub(crate) async fn handle_peer_ad(
		&self,
		frame: Frame,
		advertisement: PeerAdvertisement,
		audit: &RequestAudit,
	) -> Result<Option<Frame>, TightBeamError> {
		let verified = match self.config.verify_peer(&frame) {
			Ok(verified) => verified,
			Err(refusal) => {
				return Refusal::to(&frame, audit).peer_ad(refusal.into());
			}
		};
		let advertiser_id = verified.fingerprint();
		let refusal = Refusal::to(&frame, audit).by(&advertiser_id);

		let signature = verified.signature();
		let freshness_status = self.replay_guard.admits(&frame, signature);
		if freshness_status != TransitStatus::Ok {
			return refusal.peer_ad(freshness_status);
		}

		// `admit` binds the signer fingerprint to the dial address, so the
		// rest of this handler reads one bound pair.
		let admitted = match AdmittedPeerAd::admit(&verified, &advertisement, &self.config) {
			Ok(admitted) => admitted,
			Err(status) => {
				return refusal.peer_ad_release(&self.replay_guard, signature, status);
			}
		};

		// A verified advertiser is also a discovery hint, so the beat graph
		// runs in both directions, and this gateway's own probe dials a
		// seed-bootstrapped node.
		let advertiser = Arc::clone(&admitted.peer_hive_id);
		let hint = admitted.discovery_hint();
		let learned_at = self.config.clock.unix();
		let source = HintSource::Advertiser(advertiser.as_ref());
		let learned = self.config.learn_hints(&self.trace, source, [hint], learned_at);
		if let Err(fault) = learned {
			let error = fault.local()?;
			return refusal.peer_ad_fault_release(&self.replay_guard, signature, &error);
		}

		// The advertiser reads `PermissionDenied` for a slate it got wrong, and
		// `Unavailable` for a registry this gateway cannot write.
		let change = match self.servlet_registry.reconcile_peer_slate(admitted, PeerCaps::default()) {
			Ok(change) => change,
			Err(error) if error.blames_the_advertiser() => {
				let denied = TransitStatus::PermissionDenied;
				return refusal.peer_ad_release(&self.replay_guard, signature, denied);
			}
			Err(error) => {
				return refusal.peer_ad_fault_release(&self.replay_guard, signature, &error);
			}
		};

		change.record_direct(&self.trace, advertiser.as_ref())?;
		self.trace.emit_marker(CLUSTER_PEER_ADVERTISED)?;

		ReplyForm::Plain.reply(frame.metadata().id(), PeerAdvertisementResponse { status: TransitStatus::Ok })
	}
}

impl<P: ColonyDialProtocol> GossipPipelineCtx<P> {
	/// Admits a peer-relayed origin-signed rumor and continues the flood.
	pub(crate) async fn relay(
		self,
		frame: Frame,
		rumor: Box<Frame>,
		audit: &RequestAudit,
	) -> Result<Option<Frame>, TightBeamError> {
		let rumor = *rumor;
		// The flood is scoped (CWE-668), so the relay peer MUST be a member of
		// it. A peer outside it is a policy refusal, so the relay's score stays
		// as it is.
		let Some(flood) = self.config.flood() else {
			return Refusal::to(&frame, audit).gossip(TransitStatus::PermissionDenied);
		};

		let relay_id = match self.config.verify_peer(&frame) {
			Ok(verified) => {
				let relay_id = verified.fingerprint();
				if let Err(status) = flood.member(verified.signer_cert()) {
					return Refusal::to(&frame, audit).by(&relay_id).gossip(status);
				}

				relay_id
			}
			Err(refusal) => {
				return Refusal::to(&frame, audit).gossip(refusal.into());
			}
		};
		let refusal = Refusal::to(&frame, audit).by(&relay_id);

		// The outer `lifetime` is hop-authenticated, so an absent TTL is relay
		// misbehavior and scores the relay.
		let hop_ttl = match frame.metadata().lifetime() {
			Some(hop_ttl) => hop_ttl,
			None => {
				let scored = self.weaken_invalid_relay(GossipOrigin::Relay, Some(&relay_id));
				return refusal.gossip_scored(scored, TransitStatus::PermissionDenied);
			}
		};

		// The origin signature verifies on the peer trust plane, and the
		// refusal settles what an unverifiable rumor costs the relay. An
		// origin outside the flood is a policy refusal, as for the relay.
		let (rumor_signer, signature) = match self.config.verify_peer(&rumor) {
			Ok(verified) => {
				if let Err(status) = flood.member(verified.signer_cert()) {
					return refusal.gossip(status);
				}

				(verified.fingerprint(), verified.into_signature())
			}
			Err(origin_refusal) => {
				let settled = origin_refusal.settle_origin(&self, &frame, &relay_id);
				return refusal.gossip_settled(settled);
			}
		};
		let rumor = VerifiedRumor::new(rumor, signature);

		// The freshness of a relayed rumor is its issue time, which `admit`
		// checks against the seen window (`seen_ttl`) in place of the control
		// window.
		self.run(GossipOrigin::Relay, frame, rumor, hop_ttl, relay_id, Some(rumor_signer))
			.await
	}

	/// Signs and floods origin gossip from a local hive-plane publisher.
	pub(crate) async fn publish(
		self,
		frame: Frame,
		body: GossipRumor,
		audit: &RequestAudit,
	) -> Result<Option<Frame>, TightBeamError> {
		let publisher = match self.config.verify_hive(&frame) {
			Ok(verified) => verified.fingerprint(),
			Err(refusal) => return Refusal::to(&frame, audit).gossip(refusal.into()),
		};
		let refusal = Refusal::to(&frame, audit).by(&publisher);

		// An origin rumor travels in this gateway's flood, so a gateway in no
		// flood has nowhere to publish.
		if self.config.flood().is_none() {
			return refusal.gossip(TransitStatus::PermissionDenied);
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
			Err(error) => {
				return refusal.gossip_error(&ClusterError::Frame(error));
			}
		};

		let signing = rumor.sign_with_provider(self.config.tls.identity()).await;
		if let Err(error) = signing {
			return refusal.gossip_error(&ClusterError::Frame(error));
		}

		// The rumor's digest covers its signature, so `verify_own` verifies
		// the signature this gateway made and pairs the two.
		let rumor = match self.config.tls.verify_own(rumor) {
			Ok(rumor) => rumor,
			Err(error) => return refusal.gossip_error(&error),
		};

		// A local peer-ad apply names the signer that the signature above
		// proved. A hive-plane publish floods even when peer trust holds no
		// anchor for this gateway, and the signer is then `None`.
		let rumor_signer = kind.origin_signer(|| {
			let verified = self.config.verify_peer(rumor.frame());
			verified.map(|verified| verified.fingerprint()).ok()
		});

		self.run(GossipOrigin::Origin, frame, rumor, hop_ttl, publisher, rumor_signer)
			.await
	}
}

impl ClusterConfig {
	/// The peer-exchange sample of a reconcile reply.
	///
	/// Probe-verified peers from the discovery table merge with live peer
	/// routes installed from signed advertisements.
	///
	/// - The sample deduplicates by dial address and holds at most [`MAX_PEX_SAMPLE`] entries.
	/// - Both sources name flood members: a probe proved each table entry, and
	///   a member's signed advertisement installed each route.
	/// - A route outlives an expel, so the sample shares a route's address
	///   only while the peer table holds it.
	/// - The receiver treats every entry as an unverified hint until its own probe proves membership.
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

		// The wire message copies each borrowed entry once. Only direct routes
		// qualify, because a relay trail pairs the origin's identity with the
		// relay's dial address, a pair that names no dialable peer.
		let peer_entries = servlet_registry.peer_entries()?;
		let direct = peer_entries.iter().filter(|entry| entry.route_kind() == RouteKind::Peer);

		// A route outlives an expel, so the table says which advertised sockets
		// it holds, and the sample shares those alone.
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
	/// Answers one anti-entropy reconcile round from a flood member.
	///
	/// The reply names the digests this gateway lacks, beside a peer-exchange
	/// sample. An answered round records [`CLUSTER_RECONCILE_ANSWERED`] with
	/// the count it wants, and a refused round records `CLUSTER_GOSSIP_REFUSED`
	/// with its cause's status.
	pub(crate) async fn handle_reconcile(
		&self,
		frame: Frame,
		reconciliation: GossipReconciliation,
		audit: &RequestAudit,
	) -> Result<Option<Frame>, TightBeamError> {
		// A gateway in no flood has no rumors to reconcile, so it refuses as it
		// refuses a relay.
		let Some(flood) = self.config.flood() else {
			return Refusal::to(&frame, audit).reconcile(TransitStatus::PermissionDenied);
		};
		let verified = match self.config.verify_peer(&frame) {
			Ok(verified) => verified,
			Err(refusal) => return Refusal::to(&frame, audit).reconcile(refusal.into()),
		};

		let requester = verified.fingerprint();
		let refusal = Refusal::to(&frame, audit).by(&requester);
		if let Err(status) = flood.member(verified.signer_cert()) {
			return refusal.reconcile(status);
		}

		let freshness_status = self.replay_guard.admits(&frame, verified.signature());
		if freshness_status != TransitStatus::Ok {
			return refusal.reconcile(freshness_status);
		}

		// The handler caps the held digest list at journal capacity (CWE-770).
		// A requester that follows the protocol holds no more, so a longer
		// list is malformed whatever this gateway holds.
		if reconciliation.held.len() > MAX_GOSSIP_LOG {
			return refusal.reconcile(TransitStatus::InvalidArgument);
		}

		// A journal, table, or registry this gateway cannot read refuses the
		// round, so the requester repairs from a member that can answer.
		let held = match self.config.gossip.journal.held_digests(self.config.clock.unix()) {
			Ok(held) => held,
			Err(error) => return refusal.reconcile_fault(&error),
		};

		let want = self.config.want_against(&reconciliation.held, &held).into_wire();

		// The reply carries the peer-exchange sample, the GossipSub v1.1 PX
		// piggyback shape. A seed-bootstrapped requester discovers the
		// colony graph on the beat it already runs, with no extra round trip.
		let pex = match self.config.pex_sample(&self.servlet_registry) {
			Ok(pex) => pex,
			Err(error) => return refusal.reconcile_fault(&error),
		};

		let wanted = want.len();
		let payload = Some(requester.as_shared().as_ref());
		self.trace
			.emit_event_with_value_and_evidence(CLUSTER_RECONCILE_ANSWERED, "", wanted, payload)?;

		ReplyForm::Plain.reply(frame.metadata().id(), GossipWant { want, pex })
	}
}

#[cfg(all(test, feature = "instrument"))]
mod tests {
	use super::*;
	use crate::colony::cluster::runtime::bounds::fixtures::self_peering_config;
	use crate::colony::protocol::ClusterRequest;
	use crate::colony::urn::ColonyNamespace;
	use crate::instrumentation::events::{CLUSTER_GOSSIP_REFUSED, CLUSTER_PEER_ADVERTISE_REFUSED};
	use crate::policy::SessionContext;
	use crate::trace::TraceCollector;
	use crate::transport::TokioListener;

	/// The gateway socket the test advertisement claims, which the default
	/// dial policy admits.
	const AD_GATEWAY: &[u8] = b"192.0.2.7:9000";

	/// The request context of a gateway under [`self_peering_config`] that
	/// records on `trace`. It binds no listener, so a test hands each frame to
	/// a handler.
	fn self_peering_gateway(trace: &Arc<TraceCollector>) -> GatewayRuntimeCtx<TokioListener> {
		GatewayRuntimeCtx::for_test(self_peering_config(), trace, trace)
	}

	/// The label of each [`CLUSTER_PEER_ADVERTISE_REFUSED`] that `gateway`
	/// records as it answers one advertisement that it signed itself.
	async fn refused_labels(gateway: &GatewayRuntimeCtx<TokioListener>) -> Result<Vec<Option<String>>, TightBeamError> {
		let types = vec![ColonyNamespace::default().servlet("ping")?];
		let signed = gateway.config.mint_ad_frame(AD_GATEWAY, types.clone()).await?;
		let advertisement = PeerAdvertisement { gateway_addr: AD_GATEWAY.to_vec(), advertised_types: types };
		let audit = gateway.audit(&SessionContext::default());
		gateway.handle_peer_ad(signed.frame().clone(), advertisement, &audit).await?;

		let recorded = gateway.trace.drain_events().into_iter();
		let refused = recorded.filter(|record| record.urn == CLUSTER_PEER_ADVERTISE_REFUSED);
		Ok(refused.map(|record| record.label.as_deref().map(String::from)).collect())
	}

	// A peer table that cannot record the advertiser's hint is this gateway's
	// own fault, and the refusal names that fault in its record (CWE-778).
	#[tokio::test]
	async fn an_advertisement_refused_by_a_poisoned_table_names_the_fault() -> Result<(), TightBeamError> {
		let gateway = self_peering_gateway(&Arc::new(TraceCollector::default()));
		gateway.config.peer.table.poison();

		let labels = refused_labels(&gateway).await?;
		assert_eq!(labels, [Some(String::from("Unavailable/lock-poisoned"))]);
		Ok(())
	}

	// A route registry that cannot install the advertiser's slate is this
	// gateway's own fault, and the refusal names that fault in its record.
	#[tokio::test]
	async fn an_advertisement_refused_by_a_poisoned_registry_names_the_fault() -> Result<(), TightBeamError> {
		let gateway = self_peering_gateway(&Arc::new(TraceCollector::default()));
		gateway.servlet_registry.poison_routes();

		let labels = refused_labels(&gateway).await?;
		assert_eq!(labels, [Some(String::from("Unavailable/lock-poisoned"))]);
		Ok(())
	}

	/// The label of each [`CLUSTER_GOSSIP_REFUSED`] that `gateway` records as
	/// it answers one reconcile round that it signed itself, which names no
	/// digest.
	async fn reconcile_refusal_labels(
		gateway: &GatewayRuntimeCtx<TokioListener>,
	) -> Result<Vec<Option<String>>, TightBeamError> {
		let request = ClusterRequest::ReconcileGossip(GossipReconciliation { held: Vec::new() });
		let builder = FrameBuilder::from(Version::V2)
			.with_id(b"gossip-reconcile")
			.with_order(gateway.config.clock.unix().get())
			.with_message(request);

		let mut frame = gateway.config.witnessed(builder).build()?;
		frame.sign_with_provider(gateway.config.tls.identity()).await?;

		let reconciliation = GossipReconciliation { held: Vec::new() };
		let audit = gateway.audit(&SessionContext::default());

		gateway.handle_reconcile(frame, reconciliation, &audit).await?;

		let recorded = gateway.trace.drain_events().into_iter();
		let refused = recorded.filter(|record| record.urn == CLUSTER_GOSSIP_REFUSED);
		Ok(refused.map(|record| record.label.as_deref().map(String::from)).collect())
	}

	// A peer table that cannot draw the peer-exchange sample is this
	// gateway's own fault, and the refusal of the reconcile round names that
	// fault in its record (CWE-778).
	#[tokio::test]
	async fn a_reconcile_refused_by_a_poisoned_table_names_the_fault() -> Result<(), TightBeamError> {
		let gateway = self_peering_gateway(&Arc::new(TraceCollector::default()));
		gateway.config.peer.table.poison();

		let labels = reconcile_refusal_labels(&gateway).await?;
		assert_eq!(labels, [Some(String::from("Unavailable/lock-poisoned"))]);
		Ok(())
	}
}
