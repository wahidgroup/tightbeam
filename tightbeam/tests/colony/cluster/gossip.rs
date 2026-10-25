//! The gossip flood scenarios of the rumor plane.
//!
//! Shared [`cluster_certs`] gateways put the gateway identity in
//! `peer_trust` for relay verification. Hive registration and origin
//! publishes therefore use [`hive_plane_certs`] with [`split_hive_trust`],
//! so the hive-plane signer stays outside `peer_trust` and the hive plane
//! admits it.

use super::common::*;
use super::federation::{drive_until_advertised, federation_conf, flood_ad_rumor};
use crate::seams::outside_identity_of;
use core::sync::atomic::AtomicUsize;
use std::sync::PoisonError;
use tightbeam::colony::cluster::{PeerRecord, PeerStore};
use tightbeam::colony::common::{reply_frame, PeerGossip};
use tightbeam::constants::MAX_PEX_SAMPLE;
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::server;
use tightbeam::testing::TestFrame;
use tightbeam::transport::{EncryptedProtocol, TransportEncryptionConfig};
use tightbeam::utils::time::{Clock, ManualClock};

/// A peering conf that refloods to `peers`.
///
/// It returns the journal handle, so scenarios can poll flood convergence
/// through the public journal trait.
///
/// The hive plane refuses a signer that `peer_trust` also holds, so the
/// hive trust splits off the hive-plane identity (see
/// [`hive_plane_certs`]) beside the shared gateway identity.
fn gossip_cluster_conf(
	certs: &ClusterTestCerts,
	peers: impl IntoIterator<Item = String>,
) -> (ClusterConfig, Arc<MemoryGossipJournal>) {
	let peers: Vec<String> = peers.into_iter().collect();
	let journal = Arc::new(MemoryGossipJournal::default());
	let mut conf = peering_cluster_conf_with_peers(certs, peers);
	conf.tls.hive_trust = Some(split_hive_trust(certs));
	conf.gossip = GossipConfig {
		journal: Arc::clone(&journal) as Arc<dyn GossipJournal>,
		ingress: Some(servlet_ingress("rumor")),
		..Default::default()
	};

	(conf, journal)
}

/// A publish frame signed on the hive-plane identity of `gateway`.
///
/// Origin publishes verify against `hive_trust`, and the hive plane refuses a
/// signer that `peer_trust` also holds.
pub async fn hive_publish_gossip(
	gateway: &ClusterTestCerts,
	id: impl AsRef<[u8]>,
	body: GossipRumor,
	ttl: u64,
) -> Result<Frame, TightBeamError> {
	hive_publish_gossip_at(gateway, id, body, ttl, UnixMillis::now()).await
}

/// A publish frame like [`hive_publish_gossip`], issued at `issued_at` on the
/// clock its gateway judges freshness on.
pub async fn hive_publish_gossip_at(
	gateway: &ClusterTestCerts,
	id: impl AsRef<[u8]>,
	body: GossipRumor,
	ttl: u64,
	issued_at: UnixMillis,
) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let publisher = hive_plane_certs(gateway);

	signed_publish_gossip_at(&publisher.key, id, body, ttl, issued_at).await
}

/// A payload-only rumor body.
///
/// The flood scope and each receiving gateway decide where the rumor goes.
///
/// - Flood scope is the namespace, and the origin certificate's colony URN proves membership.
/// - Local delivery is the receiving gateway's ingress policy.
/// - The outer frame's `metadata.lifetime` carries the hop radius, and the body carries none.
pub fn rumor_body(payload: impl Into<Vec<u8>>) -> GossipRumor {
	let payload: Vec<u8> = payload.into();
	GossipRumor::application(payload)
}

/// Creates an origin-signed rumor [`Frame`], the nested gossip content.
async fn mint_origin_rumor(
	key: &Secp256k1SigningKey,
	id: impl AsRef<[u8]>,
	body: GossipRumor,
) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let mut signed = Version::V2
		.compose()
		.with_id(id)
		.with_order(UnixMillis::now().get())
		.with_message(body)
		.build()?;

	let identity = TestIdentity::of(key);
	signed.sign_with_provider(&identity).await?;
	Ok(signed)
}

/// Signs a [`Gossip`] relay frame that carries an unchanged origin rumor.
async fn signed_relay_gossip(
	key: &Secp256k1SigningKey,
	id: impl AsRef<[u8]>,
	rumor: Frame,
	hop_ttl: u64,
) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let mut signed = Version::V2
		.compose()
		.with_id(id)
		.with_order(UnixMillis::now().get())
		.with_lifetime(hop_ttl)
		.with_message(ClusterRequest::Gossip(Box::new(rumor)))
		.build()?;

	let identity = TestIdentity::of(key);
	signed.sign_with_provider(&identity).await?;
	Ok(signed)
}

/// Emits one signed gossip frame and records the decoded status on the
/// trace as `GOSSIP_PUBLISH_STATUS`.
pub async fn send_gossip_frame(
	trace: &TraceCollector,
	connect_certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	frame: Frame,
) -> Result<(), TightBeamError> {
	send_gossip_frame_as(trace, connect_certs, cluster, frame, GOSSIP_PUBLISH_STATUS).await
}

/// Emits one signed gossip frame and records the decoded status under
/// `marker`, so one scenario can tell its publish outcomes apart.
async fn send_gossip_frame_as(
	trace: &TraceCollector,
	connect_certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	frame: Frame,
	marker: Urn<'static>,
) -> Result<(), TightBeamError> {
	let mut client = connect_cluster(connect_certs, cluster.addr()).await?;
	let response: GossipResponse = decode(&emit_frame(&mut client, frame).await?.message())?;
	trace.event_with(marker, &[], response.status)?;
	Ok(())
}

/// Relays one ping application rumor to `cluster` and records the status.
///
/// `origin_key` signs the rumor, and `relay_key` signs the zero-hop relay
/// envelope that wraps it. The decoded status records as
/// `GOSSIP_RELAY_STATUS`. Frame ids derive from `label`, so each call floods
/// a distinct digest.
pub async fn relay_application_rumor(
	trace: &TraceCollector,
	connect_certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	origin_key: &Secp256k1SigningKey,
	relay_key: &Secp256k1SigningKey,
	label: impl AsRef<str>,
) -> Result<(), TightBeamError> {
	let relay = RumorRelay { origin_key, relay_key, marker: GOSSIP_RELAY_STATUS };
	relay.send(trace, connect_certs, cluster, label).await
}

/// One relayed ping application rumor: who signed it, who relays it, and the
/// marker its status records under.
///
/// A scenario whose relays end differently gives each its own marker.
pub struct RumorRelay<'k> {
	/// The key that signs the origin rumor.
	pub origin_key: &'k Secp256k1SigningKey,
	/// The key that signs the relay envelope around the rumor.
	pub relay_key: &'k Secp256k1SigningKey,
	/// The event the decoded relay status records under.
	pub marker: Urn<'static>,
}

impl RumorRelay<'_> {
	/// Relays the rumor to `cluster` in a zero-hop envelope and records the
	/// decoded status. Frame ids derive from `label`, so each call floods a
	/// distinct digest.
	pub async fn send(
		self,
		trace: &TraceCollector,
		connect_certs: &ClusterTestCerts,
		cluster: &ClusterGateway,
		label: impl AsRef<str>,
	) -> Result<(), TightBeamError> {
		self.send_with_hops(trace, connect_certs, cluster, label, 0).await
	}

	/// [`Self::send`] in an envelope with `hop_ttl` hops left, so the gateway
	/// that receives the rumor floods it on.
	async fn send_with_hops(
		self,
		trace: &TraceCollector,
		connect_certs: &ClusterTestCerts,
		cluster: &ClusterGateway,
		label: impl AsRef<str>,
		hop_ttl: u64,
	) -> Result<(), TightBeamError> {
		let label = label.as_ref();
		let inner_id = format!("{label}-inner");
		let relay_id = format!("{label}-relay");
		let body = rumor_body(encode(&PingRequest { value: 21 })?);
		let rumor = mint_origin_rumor(self.origin_key, inner_id.as_bytes(), body).await?;
		let frame = signed_relay_gossip(self.relay_key, relay_id.as_bytes(), rumor, hop_ttl).await?;
		send_gossip_frame_as(trace, connect_certs, cluster, frame, self.marker).await
	}
}

/// Signs a [`ReconcileGossip`] control frame that lists the sender's held
/// digests.
async fn signed_reconcile_gossip(
	key: &Secp256k1SigningKey,
	id: impl AsRef<[u8]>,
	held: impl IntoIterator<Item = Vec<u8>>,
) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let held: Vec<Vec<u8>> = held.into_iter().collect();
	let mut signed = Version::V2
		.compose()
		.with_id(id)
		.with_order(UnixMillis::now().get())
		.with_message(ClusterRequest::ReconcileGossip(GossipReconciliation { held }))
		.build()?;

	let identity = TestIdentity::of(key);
	signed.sign_with_provider(&identity).await?;
	Ok(signed)
}

/// Emits one signed reconcile frame and records the want-list size under
/// `marker`. A refused reconciliation answers with an empty want.
async fn send_reconcile_frame_as(
	trace: &TraceCollector,
	connect_certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	frame: Frame,
	marker: Urn<'static>,
) -> Result<(), TightBeamError> {
	let response = reconcile_reply(connect_certs, cluster, frame).await?;
	trace.event_with(marker, &[], response.want.len() as u64)?;
	Ok(())
}

/// Emits one signed reconcile frame and returns the decoded reply.
async fn reconcile_reply(
	connect_certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	frame: Frame,
) -> Result<GossipWant, TightBeamError> {
	let mut client = connect_cluster(connect_certs, cluster.addr()).await?;
	let reply: GossipWant = decode(&emit_frame(&mut client, frame).await?.message())?;
	Ok(reply)
}

/// One convergence probe over the public journal interface: every journal
/// holds exactly `held` rumors, and none awaits local delivery.
fn gossip_converged(journals: impl AsRef<[Arc<MemoryGossipJournal>]>, held: usize) -> bool {
	let journals = journals.as_ref();
	let now = UnixMillis::now();
	journals.iter().all(|journal| {
		let held_now = journal.held_digests(now).is_ok_and(|digests| digests.len() == held);
		// A delivery in flight counts as undelivered, so convergence
		// waits for the local ingress round trip rather than the claim.
		let all_delivered = journal.undelivered_local(now).is_ok_and(|count| count == 0);
		held_now && all_delivered
	})
}

/// Polls until every journal converges, or the attempts run out.
///
/// Refloods run detached from the publish reply, so only a poll can observe
/// convergence.
pub async fn wait_for_gossip_converged(
	journals: impl AsRef<[Arc<MemoryGossipJournal>]>,
	held: usize,
	attempts: u32,
	interval: Duration,
) -> bool {
	let journals = journals.as_ref();
	poll_until(attempts, interval, || gossip_converged(journals, held)).await
}

/// Polls until the journal holds exactly `count` rumors that await local
/// delivery, or the attempts run out.
///
/// A rumor accepted before the ingress servlet registers stays pending for
/// the beat to retry.
async fn wait_for_pending_local(
	journal: &Arc<MemoryGossipJournal>,
	count: usize,
	attempts: u32,
	interval: Duration,
) -> bool {
	let pending = || {
		journal
			.pending_local(UnixMillis::now())
			.is_ok_and(|rumors| rumors.len() == count)
	};
	poll_until(attempts, interval, pending).await
}

tb_assert_spec! {
	pub ClusterGossipFloodSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(3), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(2), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(3)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// A rumor floods a fan-out.
//
// A refloods to B and C. Every cluster delivers the rumor to its local
// ping servlet exactly once (ACCEPTED = 3).
//
// - The journal absorbs a second publish of the byte-identical rumor as one DUPLICATE.
// - The gateway answers the duplicate Ok and delivers it nowhere a second time.
// - The duplicate fires before its reply, so the count needs no poll.
tb_scenario! {
	name: cluster_gossip_floods_every_cluster_once,
	spec: ClusterGossipFloodSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_c, journal_c) = gossip_cluster_conf(&certs, vec![]);
			let gateway_c = start_cluster(&trace, conf_c).await?;

			let (conf_b, journal_b) = gossip_cluster_conf(&certs, vec![]);
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let peers_a = vec![gateway_b.addr().to_string(), gateway_c.addr().to_string()];
			let (conf_a, journal_a) = gossip_cluster_conf(&certs, peers_a);
			let gateway_a = start_cluster(&trace, conf_a).await?;

			let hive_b = start_scenario_rumor_hive(trace.share(), &certs).await?;
			let hive_c = start_scenario_rumor_hive(trace.share(), &certs).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;
			hive_b.register_with_cluster(gateway_b.addr()).await?;
			hive_c.register_with_cluster(gateway_c.addr()).await?;

			// The test resends one signed publish frame byte-identical. The
			// origin gateway re-creates the same rumor, with the same id,
			// order, and body, and the journal absorbs the second as a
			// Duplicate.
			let frame = hive_publish_gossip(
				&certs,
				b"flood-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				4,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_a, frame.clone()).await?;

			let journals = [journal_a, journal_b, journal_c];
			let converged = wait_for_gossip_converged(&journals, 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			send_gossip_frame(&trace, &certs, &gateway_a, frame).await?;

			gateway_a.stop();
			gateway_b.stop();
			gateway_c.stop();
			hive_b.stop();
			hive_c.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipChainSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(3), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(3)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// A rumor crosses a partial topology: A peers to B, B peers to C, and C is
// outside A's peer list. The rumor therefore reaches C only through the
// reflood at B.
//
// - The publish starts at ttl 2 and arrives at C with ttl 0.
// - The rumor spends the hop budget exactly.
// - The chain delivers once per cluster with no duplicate.
tb_scenario! {
	name: cluster_gossip_relays_across_partial_topology,
	spec: ClusterGossipChainSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_c, journal_c) = gossip_cluster_conf(&certs, vec![]);
			let gateway_c = start_cluster(&trace, conf_c).await?;

			let (conf_b, journal_b) = gossip_cluster_conf(&certs, vec![gateway_c.addr().to_string()]);
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let (conf_a, journal_a) = gossip_cluster_conf(&certs, vec![gateway_b.addr().to_string()]);
			let gateway_a = start_cluster(&trace, conf_a).await?;

			let hive_b = start_scenario_rumor_hive(trace.share(), &certs).await?;
			let hive_c = start_scenario_rumor_hive(trace.share(), &certs).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;
			hive_b.register_with_cluster(gateway_b.addr()).await?;
			hive_c.register_with_cluster(gateway_c.addr()).await?;

			let frame = hive_publish_gossip(
				&certs,
				b"chain-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				2,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_a, frame).await?;

			let journals = [journal_a, journal_b, journal_c];
			let converged = wait_for_gossip_converged(&journals, 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			gateway_a.stop();
			gateway_b.stop();
			gateway_c.stop();
			hive_b.stop();
			hive_c.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipHiveTrustOnlySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// A rumor propagates on hive trust alone.
//
// A configures a peer but no `peer_trust`, so it builds no peer pool. The
// reflood falls back to the hive pool, the same preference the advertise beat
// uses.
//
// - The rumor reaches B.
// - B verifies A's relay on its own peer plane.
// - The publish starts at ttl 1: each cluster delivers once and B refloods nowhere.
tb_scenario! {
	name: cluster_gossip_refloods_under_hive_trust_only,
	spec: ClusterGossipHiveTrustOnlySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_b, journal_b) = gossip_cluster_conf(&certs, vec![]);
			let gateway_b = start_cluster(&trace, conf_b).await?;
			let (mut conf_a, journal_a) = gossip_cluster_conf(&certs, vec![gateway_b.addr().to_string()]);

			conf_a.tls.peer_trust = None;

			let gateway_a = start_cluster(&trace, conf_a).await?;

			let hive_b = start_scenario_rumor_hive(trace.share(), &certs).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;
			hive_b.register_with_cluster(gateway_b.addr()).await?;

			let frame = hive_publish_gossip(
				&certs,
				b"hive-only-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				1,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_a, frame).await?;

			let journals = [journal_a, journal_b];
			let converged = wait_for_gossip_converged(&journals, 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			gateway_a.stop();
			gateway_b.stop();
			hive_b.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipTtlClampSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(GOSSIP_CLAMP_LEAKED, exactly!(1), equals!(0u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// The operator's configured gossip ttl caps the hop radius an origin
// publish may request.
//
// - With ttl 0 configured, the gateway clamps a publish that requests the protocol maximum.
// - The gateway delivers it locally, and the journal of B, the configured peer, stays empty.
// - A leaked reflood would raise ACCEPTED past one.
tb_scenario! {
	name: cluster_gossip_origin_clamps_configured_ttl,
	spec: ClusterGossipTtlClampSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_b, journal_b) = gossip_cluster_conf(&certs, vec![]);
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let (mut conf_a, journal_a) = gossip_cluster_conf(&certs, vec![gateway_b.addr().to_string()]);
			conf_a.gossip.ttl = 0;
			let gateway_a = start_cluster(&trace, conf_a).await?;

			let hive_b = start_scenario_rumor_hive(trace.share(), &certs).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;
			hive_b.register_with_cluster(gateway_b.addr()).await?;

			let frame = hive_publish_gossip(
				&certs,
				b"clamped-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				u64::from(MAX_GOSSIP_TTL),
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_a, frame).await?;

			let converged = wait_for_gossip_converged(&[journal_a], 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			// A leaked reflood would land within this window, so a correct
			// clamp leaves B's journal empty for the whole wait.
			let leaked = wait_for_gossip_converged(&[journal_b], 1, 3, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CLAMP_LEAKED, &[], u64::from(leaked))?;

			gateway_a.stop();
			gateway_b.stop();
			hive_b.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// The fixture of the plane-separation scenario.
///
/// The gateway's own certs anchor the hive plane. A distinct random identity
/// anchors the peer plane.
///
/// The peer identity draws its own random key, so each plane's signer
/// verifies only under its own anchor.
struct GossipPlaneCtx {
	gateway: ClusterTestCerts,
	peer_key: Secp256k1SigningKey,
	peer_trust: Arc<dyn CertificateTrust>,
}

fn gossip_plane_ctx() -> GossipPlaneCtx {
	use tightbeam::random::OsRng;
	use tightbeam::testing::fixtures::TestCertificate;

	let raw = k256::ecdsa::SigningKey::random(&mut OsRng);
	let peer_cert = TestCertificate::self_signed(&raw);
	let peer_key = Secp256k1SigningKey::from(raw);
	let peer_trust: Arc<dyn CertificateTrust> = Arc::new(
		CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(peer_cert)
			.expect("peer trust")
			.build(),
	);

	GossipPlaneCtx { gateway: cluster_certs(), peer_key, peer_trust }
}

tb_assert_spec! {
	pub ClusterGossipPlaneSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(GOSSIP_PUBLISH_STATUS, exactly!(3), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(3)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0))
		]
	}
}

// The trust planes stay apart, and admission bounds the rumor size.
//
// - A hive-plane signer must not relay peer gossip.
// - A peer-plane signer must not publish origin gossip.
// - Admission refuses an oversized rumor even on the correct plane.
// - The gateway delivers nothing and records nothing for reflood.
tb_scenario! {
	name: cluster_gossip_refuses_wrong_plane_and_oversized,
	spec: ClusterGossipPlaneSpec,
	environment Cluster {
		context: gossip_plane_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			// The oversized rumor exceeds a single-flight envelope, so the
			// gateway offers mux, and the frame must chunk across the link to
			// reach gossip admission.
			let conf = with_mux_offer(peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust)));
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			// The hive-plane identity signs the outer frame, so peer trust
			// refuses it before the gateway examines the nested rumor.
			let dummy = mint_origin_rumor(
				&ctx.gateway.key,
				b"cross-plane-inner",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&ctx.gateway.key, b"cross-plane-relay", dummy, 2).await?;
			send_gossip_frame(&trace, &ctx.gateway, &cluster, frame).await?;

			let frame = signed_publish_gossip(
				&ctx.peer_key,
				b"cross-plane-publish",
				rumor_body(encode(&PingRequest { value: 21 })?),
				2,
			)
			.await?;
			send_gossip_frame(&trace, &ctx.gateway, &cluster, frame).await?;

			// The oversized rumor crosses a pooled mux link, the same chunked
			// path that reflood uses, to reach admission. The payload bound
			// then refuses it on the correct plane.
			let pool_config = PoolConfig {
				mux_offer: Some(Arc::new(TransportOffer::mux(8))),
				..Default::default()
			};
			let pool = Arc::new(
				ConnectionPool::<TokioListener>::builder()
					.with_config(pool_config)
					.with_trust_store(Arc::clone(&ctx.gateway.trust))
					.with_trace(trace.share())
					.build(),
			);

			let mut mux_client = pool.connect(cluster.addr().to_owned()).await?;
			let frame = signed_publish_gossip(
				&ctx.gateway.key,
				b"oversized-rumor",
				rumor_body(vec![0u8; MAX_GOSSIP_PAYLOAD_BYTES + 1]),
				2,
			)
			.await?;

			let reply = mux_client.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let response: GossipResponse = decode(reply.message())?;
			trace.event_with(GOSSIP_PUBLISH_STATUS, &[], response.status)?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipReconcileRepairSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Anti-entropy repairs a rumor over the beat.
//
// - Publisher F starts the rumor at ttl 0, so it moves by reconcile alone.
// - Receiver R learns the rumor only when F's beat reconciles digests and pushes it.
tb_scenario! {
	name: cluster_gossip_repairs_missing_peer_over_beat,
	spec: ClusterGossipReconcileRepairSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_r, journal_r) = gossip_cluster_conf(&certs, vec![]);
			let gateway_r = start_cluster(&trace, conf_r).await?;
			let hive_r = start_scenario_rumor_hive(trace.share(), &certs).await?;

			let (mut conf_f, journal_f) = gossip_cluster_conf(&certs, vec![gateway_r.addr().to_string()]);
			conf_f.peer.advertise_interval = Some(Duration::from_millis(100));
			let gateway_f = start_cluster(&trace, conf_f).await?;

			hive_r.register_with_cluster(gateway_r.addr()).await?;
			hive.register_with_cluster(gateway_f.addr()).await?;

			let frame = hive_publish_gossip(
				&certs,
				b"repair-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_f, frame).await?;

			let converged = wait_for_gossip_converged(&[journal_f, journal_r], 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			gateway_f.stop();
			gateway_r.stop();
			hive_r.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipRetrySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_PENDING_BEFORE_REGISTER, exactly!(1), equals!(1u64)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// The beat retries a local delivery.
//
// The rumor reaches R before R's ping servlet registers, so it stays pending.
//
// - After registration, R's beat delivers from the pending set and acks.
// - R has no peers, so the beat runs solely for the `pending_local` retry.
tb_scenario! {
	name: cluster_gossip_retries_pending_local_delivery,
	spec: ClusterGossipRetrySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (mut conf_r, journal_r) = gossip_cluster_conf(&certs, vec![]);
			conf_r.peer.advertise_interval = Some(Duration::from_millis(100));
			let gateway_r = start_cluster(&trace, conf_r).await?;

			let (conf_f, journal_f) = gossip_cluster_conf(&certs, vec![gateway_r.addr().to_string()]);
			let gateway_f = start_cluster(&trace, conf_f).await?;

			hive.register_with_cluster(gateway_f.addr()).await?;

			let frame = hive_publish_gossip(
				&certs,
				b"retry-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				1,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_f, frame).await?;

			let pending = wait_for_pending_local(&journal_r, 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_PENDING_BEFORE_REGISTER, &[], u64::from(pending))?;

			let hive_r = start_scenario_rumor_hive(trace.share(), &certs).await?;
			hive_r.register_with_cluster(gateway_r.addr()).await?;

			let converged = wait_for_gossip_converged(&[journal_f, journal_r], 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			gateway_f.stop();
			gateway_r.stop();
			hive_r.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// A counting [`GossipJournal`] that wraps the in-memory default.
///
/// The counters show that the gateway records and acks through the injected
/// trait object. A durable backend swaps in the same way.
#[derive(Default)]
struct CountingJournal {
	inner: MemoryGossipJournal,
	records: AtomicU64,
	acks: AtomicU64,
}

impl GossipJournal for CountingJournal {
	fn record(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		rumor: &Frame,
		now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		self.records.fetch_add(1, Ordering::SeqCst);
		self.inner.record(signer, digest, rumor, now)
	}

	fn witness(&self, signer: &[u8], digest: GossipDigest, now: UnixMillis) -> Result<Admission, ClusterError> {
		self.inner.witness(signer, digest, now)
	}

	fn seen(&self, digest: &GossipDigest, now: UnixMillis) -> Result<bool, ClusterError> {
		self.inner.seen(digest, now)
	}

	fn held_digests(&self, now: UnixMillis) -> Result<Vec<GossipDigest>, ClusterError> {
		self.inner.held_digests(now)
	}

	fn fetch(&self, wanted: &[GossipDigest], now: UnixMillis) -> Result<Vec<(GossipDigest, Frame)>, ClusterError> {
		self.inner.fetch(wanted, now)
	}

	fn pending_local(&self, now: UnixMillis) -> Result<Vec<(GossipDigest, Frame)>, ClusterError> {
		self.inner.pending_local(now)
	}

	fn claim_local(&self, digest: &GossipDigest, now: UnixMillis) -> Result<LocalClaim, ClusterError> {
		self.inner.claim_local(digest, now)
	}

	fn release_local(&self, digest: &GossipDigest) -> Result<(), ClusterError> {
		self.inner.release_local(digest)
	}

	fn ack_local(&self, digest: &GossipDigest) -> Result<(), ClusterError> {
		self.acks.fetch_add(1, Ordering::SeqCst);
		self.inner.ack_local(digest)
	}

	fn retention(&self) -> Duration {
		self.inner.retention()
	}
}

tb_assert_spec! {
	pub ClusterGossipJournalSeamSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1)),
			(JOURNAL_RECORDS, exactly!(1), equals!(1u64)),
			(JOURNAL_ACKS, exactly!(1), equals!(1u64))
		]
	}
}

tb_assert_spec! {
	pub ClusterGossipRateLimitSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_LIMITED_STATUS, exactly!(1), equals!(TransitStatus::ResourceExhausted)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0))
		]
	}
}

// Rate admission runs per signer at the pipeline chokepoint. A one-token bucket
// with a slow refill admits the first publish and refuses the second with
// ResourceExhausted before the journal records it.
tb_scenario! {
	name: cluster_gossip_rate_limits_signer,
	spec: ClusterGossipRateLimitSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut conf = peering_cluster_conf(&certs);
			conf.tls.hive_trust = Some(split_hive_trust(&certs));
			conf.gossip = GossipConfig {
				admission: Arc::new(TokenBucketAdmission::new(1, Duration::from_secs(3_600)))
					as Arc<dyn GossipAdmission>,
				ingress: Some(servlet_ingress("rumor")),
				..Default::default()
			};
			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;

			let frame = hive_publish_gossip(
				&certs,
				b"rate-rumor-1",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway, frame).await?;

			let frame = hive_publish_gossip(
				&certs,
				b"rate-rumor-2",
				rumor_body(encode(&PingRequest { value: 22 })?),
				0,
			)
			.await?;
			send_gossip_frame_as(&trace, &certs, &gateway, frame, GOSSIP_LIMITED_STATUS).await?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipRetentionClampSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_REPLAY_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0))
		]
	}
}

// The gateway clamps the freshness window (seen_ttl) to the journal's
// retention horizon at start.
//
// The conf asks for an hour-wide window over a one-second journal.
// After the journal prunes the entry, the gateway refuses a byte-identical
// replay as stale rather than re-admit it as New. The scenario issues the
// rumor at the reading of the gateway's manual clock, which it alone moves.
//
// - Without the clamp the replay reads as "fresh".
// - It records again and delivers the same rumor to local servlets twice.
//
// Sources:
//
// - CWE-294, authentication bypass by capture-replay: <https://cwe.mitre.org/data/definitions/294.html>
tb_scenario! {
	name: cluster_gossip_clamps_seen_ttl_to_retention,
	spec: ClusterGossipRetentionClampSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let clock = Arc::new(ManualClock::default());
			let mut conf = peering_cluster_conf(&certs);
			conf.tls.hive_trust = Some(split_hive_trust(&certs));
			conf.clock = Arc::clone(&clock) as Arc<dyn Clock>;
			conf.gossip = GossipConfig {
				journal: Arc::new(MemoryGossipJournal::new(Duration::from_millis(1_000))) as Arc<dyn GossipJournal>,
				seen_ttl: Duration::from_secs(3_600),
				ingress: Some(servlet_ingress("rumor")),
				..Default::default()
			};

			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;

			let frame = hive_publish_gossip_at(
				&certs,
				b"clamp-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
				clock.unix(),
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway, frame.clone()).await?;

			// The clock moves past the one-second retention, so the journal
			// has pruned the entry and only the clamped freshness window can
			// refuse it.
			clock.advance(Duration::from_secs(2));
			send_gossip_frame_as(&trace, &certs, &gateway, frame, GOSSIP_REPLAY_STATUS).await?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipDuplicateFreeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(4), equals!(TransitStatus::Ok)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(2)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Duplicates leave rate tokens unspent.
//
// A two-token bucket with a slow refill admits rumor A.
//
// - It absorbs two byte-identical echoes of A for free.
// - It keeps the token to admit rumor B.
// - If duplicates spent tokens, the echoes would drain the bucket.
// - The bucket would then refuse B with ResourceExhausted.
//
// Relay echo traffic is normal, so it spends no rate token.
tb_scenario! {
	name: cluster_gossip_duplicates_spend_no_tokens,
	spec: ClusterGossipDuplicateFreeSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut conf = peering_cluster_conf(&certs);
			conf.tls.hive_trust = Some(split_hive_trust(&certs));
			conf.gossip = GossipConfig {
				admission: Arc::new(TokenBucketAdmission::new(2, Duration::from_secs(3_600)))
					as Arc<dyn GossipAdmission>,
				ingress: Some(servlet_ingress("rumor")),
				..Default::default()
			};
			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;

			let first = hive_publish_gossip(
				&certs,
				b"dup-rumor-1",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway, first.clone()).await?;
			send_gossip_frame(&trace, &certs, &gateway, first.clone()).await?;
			send_gossip_frame(&trace, &certs, &gateway, first).await?;

			let second = hive_publish_gossip(
				&certs,
				b"dup-rumor-2",
				rumor_body(encode(&PingRequest { value: 22 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway, second).await?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

// The gateway drives an injected journal through the trait alone.
//
// - One origin publish records once and acks once on local delivery.
// - Counts are final when the publish returns.
// - Record and ack precede the reply.
tb_scenario! {
	name: cluster_gossip_uses_injected_journal,
	spec: ClusterGossipJournalSeamSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let journal = Arc::new(CountingJournal::default());
			let mut conf = peering_cluster_conf(&certs);
			conf.tls.hive_trust = Some(split_hive_trust(&certs));
			conf.gossip = GossipConfig {
				journal: Arc::clone(&journal) as Arc<dyn GossipJournal>,
				ingress: Some(servlet_ingress("rumor")),
				..Default::default()
			};
			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;

			let frame = hive_publish_gossip(
				&certs,
				b"seam-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway, frame).await?;

			trace.event_with(JOURNAL_RECORDS, &[], journal.records.load(Ordering::SeqCst))?;
			trace.event_with(JOURNAL_ACKS, &[], journal.acks.load(Ordering::SeqCst))?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// A journal that reports every rumor as claimed by another task.
///
/// That is what the reconcile beat sees while an admission is mid-delivery,
/// and what the admission sees while the beat is mid-delivery. Either way the
/// second caller must not deliver.
struct HeldJournal {
	inner: MemoryGossipJournal,
	acks: AtomicU64,
}

impl Default for HeldJournal {
	fn default() -> Self {
		Self { inner: MemoryGossipJournal::default(), acks: AtomicU64::new(0) }
	}
}

impl GossipJournal for HeldJournal {
	fn record(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		rumor: &Frame,
		now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		self.inner.record(signer, digest, rumor, now)
	}

	fn witness(&self, signer: &[u8], digest: GossipDigest, now: UnixMillis) -> Result<Admission, ClusterError> {
		self.inner.witness(signer, digest, now)
	}

	fn seen(&self, digest: &GossipDigest, now: UnixMillis) -> Result<bool, ClusterError> {
		self.inner.seen(digest, now)
	}

	fn held_digests(&self, now: UnixMillis) -> Result<Vec<GossipDigest>, ClusterError> {
		self.inner.held_digests(now)
	}

	fn fetch(&self, wanted: &[GossipDigest], now: UnixMillis) -> Result<Vec<(GossipDigest, Frame)>, ClusterError> {
		self.inner.fetch(wanted, now)
	}

	fn pending_local(&self, now: UnixMillis) -> Result<Vec<(GossipDigest, Frame)>, ClusterError> {
		self.inner.pending_local(now)
	}

	fn claim_local(&self, _digest: &GossipDigest, _now: UnixMillis) -> Result<LocalClaim, ClusterError> {
		Ok(LocalClaim::Held)
	}

	fn release_local(&self, digest: &GossipDigest) -> Result<(), ClusterError> {
		self.inner.release_local(digest)
	}

	fn ack_local(&self, digest: &GossipDigest) -> Result<(), ClusterError> {
		self.acks.fetch_add(1, Ordering::SeqCst);
		self.inner.ack_local(digest)
	}

	fn retention(&self) -> Duration {
		self.inner.retention()
	}
}

tb_assert_spec! {
	pub ClusterGossipHeldClaimSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0)),
			(JOURNAL_ACKS, exactly!(1), equals!(0u64))
		]
	}
}

// A rumor that another task already claimed gets no second delivery.
//
// The delivery path must take the claim before the ingress round trip. A
// path that skipped the claim would deliver this rumor, ack it, and trace
// CLUSTER_GOSSIP_ACCEPTED, which is the at-least-once behaviour the claim
// exists to remove (CWE-362).
tb_scenario! {
	name: cluster_gossip_held_claim_is_not_delivered_twice,
	spec: ClusterGossipHeldClaimSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let journal = Arc::new(HeldJournal::default());
			let mut conf = peering_cluster_conf(&certs);
			conf.tls.hive_trust = Some(split_hive_trust(&certs));
			conf.gossip = GossipConfig {
				journal: Arc::clone(&journal) as Arc<dyn GossipJournal>,
				ingress: Some(servlet_ingress("rumor")),
				..Default::default()
			};

			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;

			let frame = hive_publish_gossip(
				&certs,
				b"held-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway, frame).await?;

			trace.event_with(JOURNAL_ACKS, &[], journal.acks.load(Ordering::SeqCst))?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipInvalidRelaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(GOSSIP_RELAY_STATUS, exactly!(4), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(4)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(3)),
			(GOSSIP_ROUTES_AFTER_SCORING, exactly!(1), equals!(0u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1))
		]
	}
}

// The gateway scores a relay whose rumors admission refuses.
//
// A trusted peer that relays rumors refused at admission (here an over-TTL
// flood request) weakens its own advertised work routes.
//
// - Each refusal weakens the trail by one trial until the gateway abandons it.
// - `peer_routes` then leaves it out.
// - The fourth refusal scores nothing once the trail is gone.
// - An honest relay from the same signer still delivers.
// - Work-route abandonment leaves the flood untouched.
tb_scenario! {
	name: cluster_gossip_abandons_invalid_relay_routes,
	spec: ClusterGossipInvalidRelaySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut conf = containment_cluster_conf(&certs);
			conf.tls.hive_trust = Some(split_hive_trust(&certs));
			conf.gossip.ingress = Some(servlet_ingress("rumor"));

			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;
			install_ping_peer(&trace, &certs, &gateway).await?;

			// The loop sends one more relay than the abandonment budget. Each
			// relay carries a valid origin-signed rumor, so the refusal is the
			// over-radius hop lifetime and not an unverifiable origin.
			for i in 0..=CONTAINMENT_ABANDON_LIMIT {
				let rumor_id = [b'r', i as u8];
				let rumor = mint_origin_rumor(
					&certs.key,
					&rumor_id,
					rumor_body(encode(&PingRequest { value: i })?),
				)
				.await?;
				let id = [b'b', b'a', b'd', i as u8];
				let frame = signed_relay_gossip(
					&certs.key,
					&id,
					rumor,
					u64::from(MAX_GOSSIP_TTL) + 1,
				)
				.await?;
				send_gossip_frame_as(&trace, &certs, &gateway, frame, GOSSIP_RELAY_STATUS).await?;
			}

			trace.event_with(GOSSIP_ROUTES_AFTER_SCORING, &[], gateway.peer_routes()?.len() as u64)?;

			let honest = mint_origin_rumor(
				&certs.key,
				b"honest-inner",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&certs.key, b"honest-relay", honest, 0).await?;
			send_gossip_frame(&trace, &certs, &gateway, frame).await?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// A grey-hole [`GossipJournal`].
///
/// It records every rumor as new and retains none.
///
/// - The gateway acknowledges each push with `Ok`.
/// - It then re-wants the same digest on every reconciliation round.
#[derive(Default)]
struct AmnesiacJournal;

impl GossipJournal for AmnesiacJournal {
	fn record(
		&self,
		_signer: &[u8],
		_digest: GossipDigest,
		_rumor: &Frame,
		_now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		Ok(Admission::New)
	}

	fn witness(&self, _signer: &[u8], _digest: GossipDigest, _now: UnixMillis) -> Result<Admission, ClusterError> {
		Ok(Admission::New)
	}

	// The grey hole retains nothing, so `seen` answers `false` for every
	// digest, and every repair push reaches `record` and earns a fresh
	// acknowledgement.
	fn seen(&self, _digest: &GossipDigest, _now: UnixMillis) -> Result<bool, ClusterError> {
		Ok(false)
	}

	fn held_digests(&self, _now: UnixMillis) -> Result<Vec<GossipDigest>, ClusterError> {
		Ok(Vec::new())
	}

	fn fetch(&self, _wanted: &[GossipDigest], _now: UnixMillis) -> Result<Vec<(GossipDigest, Frame)>, ClusterError> {
		Ok(Vec::new())
	}

	fn pending_local(&self, _now: UnixMillis) -> Result<Vec<(GossipDigest, Frame)>, ClusterError> {
		Ok(Vec::new())
	}

	// The grey hole retains nothing, so it answers every claim as untracked.
	fn claim_local(&self, _digest: &GossipDigest, _now: UnixMillis) -> Result<LocalClaim, ClusterError> {
		Ok(LocalClaim::Untracked)
	}

	fn release_local(&self, _digest: &GossipDigest) -> Result<(), ClusterError> {
		Ok(())
	}

	fn ack_local(&self, _digest: &GossipDigest) -> Result<(), ClusterError> {
		Ok(())
	}

	// The grey hole claims the default retention while it retains nothing. A
	// misbehaving journal lies, and the start-time seen-ttl clamp defends
	// against honest misconfiguration alone.
	fn retention(&self) -> Duration {
		Duration::from_millis(DEFAULT_GOSSIP_RETENTION_MS)
	}
}

tb_assert_spec! {
	pub ClusterGossipGreyHoleSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_DROP_SIGNAL, at_least!(3)),
			(GOSSIP_GREY_HOLE_CONTAINED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(2))
		]
	}
}

// The beat contains a grey hole.
//
// B acknowledges every repair push with `Ok` and retains nothing. Each
// reconciliation round therefore re-wants a digest A already saw acknowledged.
//
// - A's beat reads the reappearance as a drop signal.
// - It weakens B's advertised work route once per round.
// - It abandons the route past the limit.
// - The rumor still converges to honest C through the same beat.
// - The flood to B keeps running off the static peer list.
// - Only work routing drops the grey hole.
tb_scenario! {
	name: cluster_gossip_abandons_grey_hole_peer,
	spec: ClusterGossipGreyHoleSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_c, journal_c) = gossip_cluster_conf(&certs, vec![]);
			let gateway_c = start_cluster(&trace, conf_c).await?;
			let hive_c = start_scenario_rumor_hive(trace.share(), &certs).await?;
			hive_c.register_with_cluster(gateway_c.addr()).await?;

			let mut conf_b = peering_cluster_conf(&certs);
			conf_b.gossip = GossipConfig {
				journal: Arc::new(AmnesiacJournal) as Arc<dyn GossipJournal>,
				..Default::default()
			};
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let peers_a = vec![gateway_b.addr().to_string(), gateway_c.addr().to_string()];
			let (mut conf_a, journal_a) = gossip_cluster_conf(&certs, peers_a);
			conf_a.peer.advertise_interval = Some(Duration::from_millis(100));
			conf_a.pheromone.abandonment_limit = CONTAINMENT_ABANDON_LIMIT;

			let gateway_a = start_cluster(&trace, conf_a).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;

			// B advertises a ping route dialed at the same address A
			// reconciles with, so the drop signals have a trail to weaken.
			let dial = gateway_b.addr().to_string();
			advertise_peer(&trace, &certs, &gateway_a, dial.as_bytes(), vec![servlet_urn("ping")]).await?;

			let frame = hive_publish_gossip(
				&certs,
				b"grey-hole-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_a, frame).await?;

			// Honest convergence comes first: A holds its own publish, and the
			// beat repairs C. B never converges, by design.
			let converged =
				wait_for_gossip_converged(&[journal_a, journal_c], 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			let contained = wait_for_no_peer_routes(&gateway_a, 100, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_GREY_HOLE_CONTAINED, &[], u64::from(contained))?;

			gateway_a.stop();
			gateway_b.stop();
			gateway_c.stop();
			hive_c.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipTamperedRelaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(GOSSIP_RELAY_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(1)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0))
		]
	}
}

// The gateway scores a relay that tampers with a rumor.
//
// A trusted peer forwards an origin-signed rumor whose content it altered,
// which breaks the origin signature.
//
// - The gateway refuses it with PermissionDenied.
// - It weakens the relay's advertised routes.
// - An honest relay verifies a rumor before it forwards it.
tb_scenario! {
	name: cluster_gossip_weakens_tampered_relay,
	spec: ClusterGossipTamperedRelaySpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, containment_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;

			let signed_body = encode(&rumor_body(encode(&PingRequest { value: 21 })?))?;
			let forged_body = encode(&rumor_body(encode(&PingRequest { value: 99 })?))?;
			let signed = mint_origin_rumor(
				&certs.key,
				b"tamper-inner",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;

			let rumor = TestFrame::tamper(&signed, &signed_body, &forged_body);
			let frame = signed_relay_gossip(&certs.key, b"tamper-relay", rumor, 0).await?;
			send_gossip_frame_as(&trace, &certs, &cluster, frame, GOSSIP_RELAY_STATUS).await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipUnknownOriginSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(GOSSIP_RELAY_STATUS, exactly!(1), equals!(TransitStatus::Unauthenticated)),
			(GOSSIP_LIMITED_STATUS, exactly!(2), equals!(TransitStatus::ResourceExhausted)),
			(events::CLUSTER_GOSSIP_ORIGIN_UNKNOWN, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(3)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0)),
			(PEER_ROUTES_AFTER_UNKNOWN_ORIGIN, exactly!(1), equals!(1u64))
		]
	}
}

// An origin outside this gateway's trust is the edge of a subnet.
//
// A trusted peer relays two rumors whose origin the gateway does not hold. The
// relay's own rate bucket holds one token.
//
// - The first rumor draws Unauthenticated, which tells the relay to stop its offers of that origin.
// - The drop spends the relay's one token, so the second answers ResourceExhausted.
// - The token came from the relay's own bucket, so a rumor the relay signed itself is limited too.
// - The gateway never scores the relay, so its routes stay (PEER_ROUTES_AFTER_UNKNOWN_ORIGIN).
tb_scenario! {
	name: cluster_gossip_unknown_origin_costs_the_relay_a_token_and_no_score,
	spec: ClusterGossipUnknownOriginSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let mut conf = containment_cluster_conf(&certs);
			let one_token = TokenBucketAdmission::new(1, Duration::from_secs(3_600));
			conf.gossip.admission = Arc::new(one_token) as Arc<dyn GossipAdmission>;
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;
			let (_unenrolled, outsider_key) = member_identity("Origin Outside Trust");

			relay_application_rumor(&trace, &certs, &cluster, &outsider_key, &certs.key, "outsider-1").await?;

			let relay = &certs.key;
			let limited = RumorRelay { origin_key: &outsider_key, relay_key: relay, marker: GOSSIP_LIMITED_STATUS };
			limited.send(&trace, &certs, &cluster, "outsider-2").await?;
			let own = RumorRelay { origin_key: relay, relay_key: relay, marker: GOSSIP_LIMITED_STATUS };
			own.send(&trace, &certs, &cluster, "relay-own").await?;

			let routes = cluster.peer_routes()?.len();
			trace.event_with(PEER_ROUTES_AFTER_UNKNOWN_ORIGIN, &[], count_u64(routes))?;

			cluster.stop();
			Ok(())
		}
	}
}

/// The fixture for partial trust inside one colony.
///
/// - The bridge gateway trusts the edge gateway and both origins.
/// - The edge gateway trusts the bridge alone, so both origins sit outside its trust.
struct PartialTrustCtx {
	bridge: Arc<ClusterTestCerts>,
	edge: Arc<ClusterTestCerts>,
	first_origin: Secp256k1SigningKey,
	second_origin: Secp256k1SigningKey,
	peers_of_bridge: Arc<dyn CertificateTrust>,
	peers_of_edge: Arc<dyn CertificateTrust>,
}

fn partial_trust_ctx() -> PartialTrustCtx {
	let (cert_bridge, key_bridge) = member_identity("Partial Trust Bridge");
	let (cert_edge, key_edge) = member_identity("Partial Trust Edge");
	let (cert_first, first_origin) = member_identity("Partial Trust First Origin");
	let (cert_second, second_origin) = member_identity("Partial Trust Second Origin");

	let trust = combined_trust(&[&cert_bridge, &cert_edge, &cert_first, &cert_second]);
	let peers_of_bridge = combined_trust(&[&cert_edge, &cert_first, &cert_second]);
	let peers_of_edge = combined_trust(&[&cert_bridge]);

	PartialTrustCtx {
		bridge: Arc::new(GatewayCerts { cert: cert_bridge, key: key_bridge, trust: Arc::clone(&trust) }),
		edge: Arc::new(GatewayCerts { cert: cert_edge, key: key_edge, trust }),
		first_origin,
		second_origin,
		peers_of_bridge,
		peers_of_edge,
	}
}

/// Places one rumor of `origin` at `cluster`, relayed by the origin itself
/// with `hop_ttl` hops left, and records the status as `GOSSIP_RELAY_STATUS`.
async fn place_origin_rumor(
	trace: &TraceCollector,
	connect_certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	origin: &Secp256k1SigningKey,
	label: impl AsRef<str>,
	hop_ttl: u64,
) -> Result<(), TightBeamError> {
	let relay = RumorRelay { origin_key: origin, relay_key: origin, marker: GOSSIP_RELAY_STATUS };
	relay.send_with_hops(trace, connect_certs, cluster, label, hop_ttl).await
}

/// Polls until a peer has refused `count` origins, or five seconds pass.
pub async fn wait_for_refused_origins(trace: &TraceCollector, count: usize) -> bool {
	let refused = || trace.recorded(events::CLUSTER_GOSSIP_ORIGIN_REFUSED_BY_PEER) >= count;
	poll_until(50, Duration::from_millis(100), refused).await
}

tb_assert_spec! {
	pub ClusterGossipRefusedOriginSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(GOSSIP_RELAY_STATUS, exactly!(3), equals!(TransitStatus::Ok)),
			(GOSSIP_ORIGIN_SETTLED, exactly!(2), equals!(true)),
			(events::CLUSTER_GOSSIP_ORIGIN_UNKNOWN, exactly!(2)),
			(events::CLUSTER_GOSSIP_ORIGIN_REFUSED_BY_PEER, exactly!(2)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(events::CLUSTER_GOSSIP_DROP_SIGNAL, exactly!(0))
		]
	}
}

// A target that refuses an origin gets that origin once.
//
// The bridge holds rumors of two origins the edge does not trust, and beats on
// a clock only this test moves. Each origin costs the bridge one refusal at the
// edge, by repair for the first and by reflood for the second.
//
// - The first origin's rumor waits in the journal, and the first beat's repair pushes it. The edge refuses.
// - A second rumor of that origin refloods to nobody, because the refusal stands.
// - The second origin's rumor refloods at once. The edge refuses.
// - Three more beats push neither origin again, although the edge still lacks all three rumors.
tb_scenario! {
	name: cluster_gossip_refused_origin_is_offered_to_that_target_once,
	spec: ClusterGossipRefusedOriginSpec,
	environment Cluster {
		context: partial_trust_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let mut edge_conf = federation_conf(&ctx.edge, Arc::clone(&ctx.peers_of_edge), vec![], 1);
			edge_conf.peer.advertise_interval = None;
			start_cluster(&trace, edge_conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let clock = Arc::new(ManualClock::default());
			let peers_of_bridge = Arc::clone(&ctx.peers_of_bridge);
			let mut bridge_conf = federation_conf(&ctx.bridge, peers_of_bridge, vec![cluster.addr().to_string()], 1);
			bridge_conf.clock = Arc::clone(&clock) as Arc<dyn Clock>;
			let bridge = start_cluster(&trace, bridge_conf).await?;

			place_origin_rumor(&trace, &ctx.bridge, &bridge, &ctx.first_origin, "first-origin-held", 0).await?;
			drive_until_advertised(&clock, &trace, 1).await;
			let repair_settled = wait_for_refused_origins(&trace, 1).await;
			trace.event_with(GOSSIP_ORIGIN_SETTLED, &[], repair_settled)?;

			place_origin_rumor(&trace, &ctx.bridge, &bridge, &ctx.first_origin, "first-origin-again", 1).await?;
			place_origin_rumor(&trace, &ctx.bridge, &bridge, &ctx.second_origin, "second-origin", 1).await?;
			let reflood_settled = wait_for_refused_origins(&trace, 2).await;
			trace.event_with(GOSSIP_ORIGIN_SETTLED, &[], reflood_settled)?;

			let beats_so_far = trace.recorded(events::CLUSTER_PEER_ADVERTISED);
			drive_until_advertised(&clock, &trace, beats_so_far + 3).await;

			bridge.stop();
			cluster.stop();
			Ok(())
		}
	}
}

/// The fixture for flood membership.
///
/// The gateway belongs to colony "main".
///
/// - One trusted peer identity carries the colony URN of "other", so it is inside the flood.
/// - Another carries no SAN, so it is outside every flood.
/// - Both use random keys so the three identities never share a subject key id (see [`gossip_plane_ctx`]).
struct NeighborColonyCtx {
	gateway: ClusterTestCerts,
	neighbor_key: Secp256k1SigningKey,
	stranger_key: Secp256k1SigningKey,
	peer_trust: Arc<dyn CertificateTrust>,
}

/// A fresh gateway identity in colony "other".
///
/// A random key keeps its subject key id distinct from every "main"-colony
/// identity.
///
/// Its own `CN` keeps trust-store issuer resolution unambiguous, so one trust
/// store can anchor both identities.
fn neighbor_colony_certs() -> ClusterTestCerts {
	let neighbor_urn = colony_ns().colony("other").expect("static colony name");
	let (cert, key) = colony_identity("Neighbor Gateway", &neighbor_urn);
	let trust = combined_trust(&[&cert]);

	GatewayCerts { cert, key, trust }
}

fn neighbor_colony_ctx() -> NeighborColonyCtx {
	let gateway = cluster_certs();
	let neighbor = neighbor_colony_certs();
	let stranger = stranger_gateway_certs();
	let peer_trust = combined_trust(&[&gateway.cert, &neighbor.cert, &stranger.cert]);

	NeighborColonyCtx { gateway, neighbor_key: neighbor.key, stranger_key: stranger.key, peer_trust }
}

tb_assert_spec! {
	pub ClusterGossipNeighborColonySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(GOSSIP_RELAY_STATUS, exactly!(2), equals!(TransitStatus::Ok)),
			(GOSSIP_STRANGER_STATUS, exactly!(3), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(3)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(GOSSIP_ROUTES_AFTER_SCORING, exactly!(1), equals!(1u64))
		]
	}
}

// A neighbor colony is inside the flood, and a trusted stranger is outside it.
//
// A trusted peer of colony "other" federates work routes (the advertisement
// installs) and gossips. The gateway refuses a trusted identity with no colony
// URN with PermissionDenied.
//
// - Admitted: a rumor of colony "main" that the neighbor relays.
// - Admitted: a rumor the neighbor signed itself.
// - Refused: a rumor the stranger both signed and relays.
// - Refused: a rumor of colony "main" that the stranger relays.
// - Refused: a rumor the stranger signed and the neighbor relays.
// - Each refusal is policy, so it weakens no route.
// - The abandonment limit is 1, so one weaken event would evict the advertised route.
// - The route survives.
tb_scenario! {
	name: cluster_gossip_admits_neighbor_colony_and_refuses_stranger,
	spec: ClusterGossipNeighborColonySpec,
	environment Cluster {
		context: neighbor_colony_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let mut conf = peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust));
			conf.pheromone.abandonment_limit = 1;
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			advertise_peer_signed(
				&trace,
				&ctx.gateway,
				&ctx.neighbor_key,
				&cluster,
				PEER_GATEWAY_ADDR,
				vec![servlet_urn("ping")],
			)
			.await?;

			let own_origin = &ctx.gateway.key;
			let neighbor = &ctx.neighbor_key;
			relay_application_rumor(&trace, &ctx.gateway, &cluster, own_origin, neighbor, "main-origin").await?;
			relay_application_rumor(&trace, &ctx.gateway, &cluster, neighbor, neighbor, "other-origin").await?;

			let stranger = &ctx.stranger_key;
			let marker = GOSSIP_STRANGER_STATUS;
			let all_stranger = RumorRelay { origin_key: stranger, relay_key: stranger, marker: marker.clone() };
			all_stranger.send(&trace, &ctx.gateway, &cluster, "stranger").await?;
			let stranger_relays = RumorRelay { origin_key: own_origin, relay_key: stranger, marker: marker.clone() };
			stranger_relays.send(&trace, &ctx.gateway, &cluster, "stranger-relays").await?;
			let stranger_signed = RumorRelay { origin_key: stranger, relay_key: neighbor, marker };
			stranger_signed.send(&trace, &ctx.gateway, &cluster, "stranger-signed").await?;

			let routes = cluster.peer_routes()?.len();
			trace.event_with(GOSSIP_ROUTES_AFTER_SCORING, &[], count_u64(routes))?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterStrangerAdvertisementSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(0u64)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, exactly!(1))
		]
	}
}

// A trusted identity with no colony URN federates nothing.
//
// Peer trust admits the stranger, so its advertisement verifies. The stranger
// is outside the flood, so admission refuses the advertisement and installs no
// route.
tb_scenario! {
	name: cluster_refuses_an_advertisement_from_a_stranger,
	spec: ClusterStrangerAdvertisementSpec,
	environment Cluster {
		context: neighbor_colony_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let conf = peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust));
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let stranger = &ctx.stranger_key;
			let types = vec![servlet_urn("ping")];
			advertise_peer_signed(&trace, &ctx.gateway, stranger, &cluster, PEER_GATEWAY_ADDR, types).await?;

			cluster.stop();
			Ok(())
		}
	}
}

/// The fixture for a rate budget keyed on the origin.
///
/// It holds one origin identity and two relay identities, all members of
/// the gateway's colony.
///
/// - Every identity uses a random key so no two share a subject key id (see [`gossip_plane_ctx`]).
struct RelayFanoutCtx {
	gateway: ClusterTestCerts,
	origin_key: Secp256k1SigningKey,
	relay_a_key: Secp256k1SigningKey,
	relay_b_key: Secp256k1SigningKey,
	peer_trust: Arc<dyn CertificateTrust>,
}

fn relay_fanout_ctx() -> RelayFanoutCtx {
	use tightbeam::random::OsRng;
	use tightbeam::testing::fixtures::TestCertificate;

	let gateway = cluster_certs();
	let member_urn = test_colony_urn().to_string();
	let raw_origin = k256::ecdsa::SigningKey::random(&mut OsRng);
	let origin_cert = TestCertificate::with_uri_sans(&raw_origin, &[&member_urn]);
	let raw_relay_a = k256::ecdsa::SigningKey::random(&mut OsRng);
	let relay_a_cert = TestCertificate::with_uri_sans(&raw_relay_a, &[&member_urn]);
	let raw_relay_b = k256::ecdsa::SigningKey::random(&mut OsRng);
	let relay_b_cert = TestCertificate::with_uri_sans(&raw_relay_b, &[&member_urn]);
	let peer_trust = combined_trust(&[&gateway.cert, &origin_cert, &relay_a_cert, &relay_b_cert]);

	RelayFanoutCtx {
		gateway,
		origin_key: Secp256k1SigningKey::from(raw_origin),
		relay_a_key: Secp256k1SigningKey::from(raw_relay_a),
		relay_b_key: Secp256k1SigningKey::from(raw_relay_b),
		peer_trust,
	}
}

tb_assert_spec! {
	pub ClusterGossipOriginBudgetSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(GOSSIP_RELAY_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_LIMITED_STATUS, exactly!(1), equals!(TransitStatus::ResourceExhausted)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0))
		]
	}
}

// Rate admission keys on the rumor's origin, not the relaying peer.
//
// A one-token bucket admits the origin's first rumor through relay A.
//
// - It refuses the same origin's second rumor through relay B with ResourceExhausted.
// - An origin whose flood fans out through many relays gets no extra budget.
// - The refusal is local policy, so the gateway never weakens relay B's routes.
tb_scenario! {
	name: cluster_gossip_relays_share_origin_budget,
	spec: ClusterGossipOriginBudgetSpec,
	environment Cluster {
		context: relay_fanout_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let mut conf = peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust));
			conf.gossip = GossipConfig {
				admission: Arc::new(TokenBucketAdmission::new(1, Duration::from_secs(3_600)))
					as Arc<dyn GossipAdmission>,
				..Default::default()
			};
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let first = mint_origin_rumor(
				&ctx.origin_key,
				b"budget-rumor-1",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&ctx.relay_a_key, b"budget-relay-1", first, 0).await?;
			send_gossip_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RELAY_STATUS).await?;

			let second = mint_origin_rumor(
				&ctx.origin_key,
				b"budget-rumor-2",
				rumor_body(encode(&PingRequest { value: 22 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&ctx.relay_b_key, b"budget-relay-2", second, 0).await?;
			send_gossip_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_LIMITED_STATUS).await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipNonMemberSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0))
		]
	}
}

// A gateway whose own certificate carries no colony URN SAN is not a
// colony member.
//
// - It refuses origin publishes PermissionDenied even from a trusted hive-plane signer.
// - It cannot scope the flood.
tb_scenario! {
	name: cluster_gossip_non_member_gateway_refuses_publish,
	spec: ClusterGossipNonMemberSpec,
	environment Cluster {
		context: GatewayCerts::generate("CN=Non-Member Gateway"),
		start: |SetupEnv { trace, context: certs }| async move {
			// The hive-plane signer must verify, so the refusal below
			// isolates the missing colony SAN rather than the origin check.
			let mut conf = peering_cluster_conf(&certs);
			conf.tls.hive_trust = Some(split_hive_trust(&certs));

			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let frame = hive_publish_gossip(
				&certs,
				b"non-member-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &cluster, frame).await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipReconcileMembershipSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(GOSSIP_RECONCILE_MEMBER_WANT, exactly!(1), equals!(1u64)),
			(GOSSIP_RECONCILE_NEIGHBOR_WANT, exactly!(1), equals!(1u64)),
			(GOSSIP_RECONCILE_STRANGER_WANT, exactly!(1), equals!(0u64)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1))
		]
	}
}

// Flood membership gates reconciliation, the same scope the flood uses.
//
// A want list names local rumor state, and the follow-up repair push carries
// rumor bytes.
//
// - A gateway of colony "main" receives the want-list for a digest this gateway lacks.
// - A gateway of colony "other" receives it too, because it is inside the flood.
// - A trusted peer with no colony SAN gets an empty want, and the refusal fires one REFUSED event.
tb_scenario! {
	name: cluster_gossip_reconcile_requires_flood_membership,
	spec: ClusterGossipReconcileMembershipSpec,
	environment Cluster {
		context: neighbor_colony_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let conf = peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust));
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let held = vec![vec![0xABu8; 32]];

			let frame = signed_reconcile_gossip(&ctx.gateway.key, b"member-reconcile", held.clone()).await?;
			send_reconcile_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RECONCILE_MEMBER_WANT).await?;

			let frame = signed_reconcile_gossip(&ctx.neighbor_key, b"neighbor-reconcile", held.clone()).await?;
			send_reconcile_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RECONCILE_NEIGHBOR_WANT).await?;

			let frame = signed_reconcile_gossip(&ctx.stranger_key, b"stranger-reconcile", held).await?;
			send_reconcile_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RECONCILE_STRANGER_WANT).await?;

			cluster.stop();
			Ok(())
		}
	}
}

/// The fixture for a peer trust store that changes while the gateway runs.
struct RunTimeTrustCtx {
	local: ClusterTestCerts,
	neighbor: ClusterTestCerts,
	/// The gateway's peer trust store, which the scenario switches.
	trust: Arc<SwitchTrust>,
}

/// The gateway trusts itself alone, and the switch enrolls the neighbor.
fn trust_ctx_enrolling_the_neighbor() -> RunTimeTrustCtx {
	let local = cluster_certs();
	let neighbor = neighbor_colony_certs();
	let alone = combined_trust(&[&local.cert]);
	let both = combined_trust(&[&local.cert, &neighbor.cert]);
	RunTimeTrustCtx { local, neighbor, trust: SwitchTrust::new(alone, both) }
}

/// The gateway trusts itself and the neighbor, and the switch removes the
/// neighbor.
fn trust_ctx_removing_the_neighbor() -> RunTimeTrustCtx {
	let local = cluster_certs();
	let neighbor = neighbor_colony_certs();
	let alone = combined_trust(&[&local.cert]);
	let both = combined_trust(&[&local.cert, &neighbor.cert]);
	RunTimeTrustCtx { local, neighbor, trust: SwitchTrust::new(both, alone) }
}

/// A gateway on the shared identity whose peer plane reads the fixture's
/// switchable store, with no beat. Its hive plane admits the hive-plane
/// identity, which signs the publishes.
fn run_time_trust_conf(ctx: &RunTimeTrustCtx) -> ClusterConfig {
	let peer_trust = Arc::clone(&ctx.trust) as Arc<dyn CertificateTrust>;
	let tls = cluster_tls_config(&ctx.local).with_peer_trust(peer_trust);

	let mut conf = ClusterConfig::new(tls);
	conf.tls.hive_trust = Some(split_hive_trust(&ctx.local));
	conf
}

tb_assert_spec! {
	pub ClusterTrustEnrolledAtRunTimeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(GOSSIP_STATUS_BEFORE_SWITCH, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(GOSSIP_STATUS_AFTER_SWITCH, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1))
		]
	}
}

// A peer enrolled while the gateway runs joins the flood at once.
//
// The gateway's peer trust holds the gateway alone. A neighbor relays its own
// rumor, the operator then enrolls the neighbor, and the neighbor relays
// another.
//
// - The gateway refuses the first relay, because the store does not hold the signer.
// - The gateway admits the second with no restart, because every frame reads the store.
tb_scenario! {
	name: cluster_gossip_admits_a_peer_enrolled_while_the_gateway_runs,
	spec: ClusterTrustEnrolledAtRunTimeSpec,
	environment Cluster {
		context: trust_ctx_enrolling_the_neighbor(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_cluster(&trace, run_time_trust_conf(&ctx)).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let neighbor = &ctx.neighbor.key;
			let marker = GOSSIP_STATUS_BEFORE_SWITCH;
			let before = RumorRelay { origin_key: neighbor, relay_key: neighbor, marker };
			before.send(&trace, &ctx.local, &cluster, "before-enrollment").await?;

			ctx.trust.switch();

			let marker = GOSSIP_STATUS_AFTER_SWITCH;
			let after = RumorRelay { origin_key: neighbor, relay_key: neighbor, marker };
			after.send(&trace, &ctx.local, &cluster, "after-enrollment").await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterTrustRemovedAtRunTimeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_EXPEL_ADDRESS_VERIFIED, exactly!(1), equals!(true)),
			(GOSSIP_PUBLISH_STATUS, exactly!(2), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(PEER_EXPEL_TARGET_DROPPED, exactly!(1), equals!(true)),
			(GOSSIP_HELD_AFTER_REMOVAL, exactly!(1), equals!(1u64)),
			(GOSSIP_STATUS_AFTER_SWITCH, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// A peer removed from trust while the gateway runs leaves the flood at once,
// in both directions.
//
// The gateway holds a neighbor as a verified target, and no beat runs. One
// published rumor reaches the neighbor over a pooled connection. The operator
// then removes the neighbor from peer trust, and the scenario publishes a
// second rumor.
//
// - The second rumor stays unsent, although the connection is still open (GOSSIP_HELD_AFTER_REMOVAL).
// - The neighbor leaves the targets, as any gateway outside the flood does (PEER_EXPEL_TARGET_DROPPED).
// - The gateway refuses a rumor the neighbor relays (GOSSIP_STATUS_AFTER_SWITCH).
tb_scenario! {
	name: cluster_gossip_stops_at_a_peer_removed_from_trust_while_the_gateway_runs,
	spec: ClusterTrustRemovedAtRunTimeSpec,
	environment Bare {
		context: trust_ctx_removing_the_neighbor(),
		exec: |SetupEnv { trace, context: ctx }| async move {
			let journal_of_neighbor = Arc::new(MemoryGossipJournal::default());
			let neighbor_trust = combined_trust(&[&ctx.local.cert, &ctx.neighbor.cert]);
			let neighbor_tls = cluster_tls_config_with_trust(&ctx.neighbor, None)
				.with_hive_trust(Arc::clone(&neighbor_trust))
				.with_peer_trust(neighbor_trust);

			let mut neighbor_conf = ClusterConfig::new(neighbor_tls);
			neighbor_conf.gossip.journal = Arc::clone(&journal_of_neighbor) as Arc<dyn GossipJournal>;

			let neighbor = start_cluster(&trace, neighbor_conf).await?;
			let conf = run_time_trust_conf(&ctx);
			let table = Arc::clone(conf.peer.table());
			let neighbor_addr = dial_admitted_by(&conf, neighbor.addr().to_string());
			let gateway = start_cluster(&trace, conf).await?;

			let verified = table.promote(neighbor_addr, None, UnixMillis::now())?;
			trace.event_with(PEER_EXPEL_ADDRESS_VERIFIED, &[], verified)?;

			let body = rumor_body(encode(&PingRequest { value: 21 })?);
			let frame = hive_publish_gossip(&ctx.local, b"before-removal", body, 1).await?;
			send_gossip_frame(&trace, &ctx.local, &gateway, frame).await?;

			let journals = [Arc::clone(&journal_of_neighbor)];
			let converged = wait_for_gossip_converged(journals, 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			ctx.trust.switch();

			let body = rumor_body(encode(&PingRequest { value: 22 })?);
			let frame = hive_publish_gossip(&ctx.local, b"after-removal", body, 1).await?;
			send_gossip_frame(&trace, &ctx.local, &gateway, frame).await?;

			let dropped = wait_for_target_dropped(&table, neighbor_addr, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_EXPEL_TARGET_DROPPED, &[], dropped)?;

			let held = journal_of_neighbor.held_digests(UnixMillis::now())?.len();
			trace.event_with(GOSSIP_HELD_AFTER_REMOVAL, &[], count_u64(held))?;

			let neighbor_key = &ctx.neighbor.key;
			let marker = GOSSIP_STATUS_AFTER_SWITCH;
			let refused = RumorRelay { origin_key: neighbor_key, relay_key: neighbor_key, marker };
			refused.send(&trace, &ctx.local, &gateway, "neighbor-after-removal").await?;

			gateway.stop();
			neighbor.stop();
			Ok(())
		}
	}
}

/// The fixture for a peer trust store that holds a certificate authority and
/// none of the certificates it issued.
struct AuthorityTrustCtx {
	local: ClusterTestCerts,
	/// A gateway of colony "other" whose certificate the authority issued.
	leaf: ClusterTestCerts,
	/// The local gateway's peer trust: its own certificate and the authority.
	peer_trust: Arc<dyn CertificateTrust>,
}

fn authority_trust_ctx() -> AuthorityTrustCtx {
	use tightbeam::random::OsRng;
	use tightbeam::testing::fixtures::TestCertificate;

	let local = cluster_certs();
	let authority_key = k256::ecdsa::SigningKey::random(&mut OsRng);
	let authority = TestCertificate::authority(&authority_key, "Flood Authority");
	let authority = authority.expect("the fixture authority signs itself");

	let leaf_key = k256::ecdsa::SigningKey::random(&mut OsRng);
	let colony = colony_ns().colony("other").expect("static colony name").to_string();
	let uris = [colony.as_str()];
	let issued = TestCertificate::issued_with_uri_sans(&authority_key, "Flood Authority", &leaf_key, "Leaf", &uris);
	let leaf_cert = issued.expect("the fixture authority signs the leaf");

	let peer_trust = combined_trust(&[&local.cert, &authority]);
	let leaf_trust = combined_trust(&[&local.cert, &leaf_cert]);
	let leaf = GatewayCerts { cert: leaf_cert, key: Secp256k1SigningKey::from(leaf_key), trust: leaf_trust };

	AuthorityTrustCtx { local, leaf, peer_trust }
}

tb_assert_spec! {
	pub ClusterAuthorityTrustSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_EXPEL_ADDRESS_VERIFIED, exactly!(1), equals!(true)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_EXPEL_TARGET_DROPPED, exactly!(1), equals!(true)),
			(events::CLUSTER_GOSSIP_FANOUT_UNREACHED, exactly!(0)),
			(GOSSIP_HELD_BY_AUTHORITY_LEAF, exactly!(1), equals!(0u64)),
			(GOSSIP_RELAY_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// A certificate authority in peer trust admits no gateway to the flood.
//
// The gateway's peer trust holds its own certificate and an authority. A second
// gateway presents a certificate that authority issued, with a colony URN of
// the namespace. The gateway holds its address as a verified target, and no
// beat runs.
//
// - The dial completes, because the handshake validates the chain (CLUSTER_GOSSIP_FANOUT_UNREACHED).
// - The gateway sends no rumor, because the store holds no certificate for the leaf's key.
// - The gateway refuses a rumor the leaf relays for the same reason, so both directions agree.
tb_scenario! {
	name: cluster_gossip_admits_no_gateway_through_a_certificate_authority,
	spec: ClusterAuthorityTrustSpec,
	environment Bare {
		context: authority_trust_ctx(),
		exec: |SetupEnv { trace, context: ctx }| async move {
			let journal_of_leaf = Arc::new(MemoryGossipJournal::default());
			let leaf_trust = Arc::clone(&ctx.leaf.trust);
			let leaf_tls = cluster_tls_config_with_trust(&ctx.leaf, None)
				.with_hive_trust(Arc::clone(&leaf_trust))
				.with_peer_trust(leaf_trust);

			let mut leaf_conf = ClusterConfig::new(leaf_tls);
			leaf_conf.gossip.journal = Arc::clone(&journal_of_leaf) as Arc<dyn GossipJournal>;

			let leaf = start_cluster(&trace, leaf_conf).await?;
			let tls = cluster_tls_config(&ctx.local).with_peer_trust(Arc::clone(&ctx.peer_trust));
			let mut conf = ClusterConfig::new(tls);
			conf.tls.hive_trust = Some(split_hive_trust(&ctx.local));

			let table = Arc::clone(conf.peer.table());
			let leaf_addr = dial_admitted_by(&conf, leaf.addr().to_string());
			let gateway = start_cluster(&trace, conf).await?;

			let verified = table.promote(leaf_addr, None, UnixMillis::now())?;
			trace.event_with(PEER_EXPEL_ADDRESS_VERIFIED, &[], verified)?;

			let body = rumor_body(encode(&PingRequest { value: 21 })?);
			let frame = hive_publish_gossip(&ctx.local, b"authority-rumor", body, 1).await?;
			send_gossip_frame(&trace, &ctx.local, &gateway, frame).await?;

			let dropped = wait_for_target_dropped(&table, leaf_addr, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_EXPEL_TARGET_DROPPED, &[], dropped)?;

			let held = journal_of_leaf.held_digests(UnixMillis::now())?.len();
			trace.event_with(GOSSIP_HELD_BY_AUTHORITY_LEAF, &[], count_u64(held))?;

			let leaf_key = &ctx.leaf.key;
			relay_application_rumor(&trace, &ctx.local, &gateway, leaf_key, leaf_key, "authority-leaf").await?;

			gateway.stop();
			leaf.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPexExpelledAddressSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(PEX_SHARED_BEFORE_EXPEL, exactly!(1), equals!(1u64)),
			(PEX_SHARED_AFTER_EXPEL, exactly!(1), equals!(0u64)),
			(PEER_ROUTES_AFTER_EXPEL, exactly!(1), equals!(1u64))
		]
	}
}

// Peer exchange withholds an address that the table expelled.
//
// A member's advertisement installs a route and teaches the table its address.
// No beat runs, so the address stays a candidate until the scenario expels it,
// as a probe does when a gateway outside the flood answers there.
//
// - While the table holds the address, a reconcile reply shares it (PEX_SHARED_BEFORE_EXPEL).
// - After the expel the reply shares nothing, although the route stays (PEER_ROUTES_AFTER_EXPEL).
tb_scenario! {
	name: cluster_peer_exchange_drops_an_address_the_table_expelled,
	spec: ClusterPexExpelledAddressSpec,
	environment Bare {
		context: cluster_certs(),
		exec: |SetupEnv { trace, context: certs }| async move {
			let conf = peering_cluster_conf(&certs);
			let table = Arc::clone(conf.peer.table());
			let advertised = dial_admitted_by(&conf, String::from_utf8_lossy(PEER_GATEWAY_ADDR));
			let gateway = start_cluster(&trace, conf).await?;
			install_ping_peer(&trace, &certs, &gateway).await?;

			let frame = signed_reconcile_gossip(&certs.key, b"pex-before-expel", vec![]).await?;
			let before = reconcile_reply(&certs, &gateway, frame).await?;
			trace.event_with(PEX_SHARED_BEFORE_EXPEL, &[], count_u64(before.pex.len()))?;

			table.expel(advertised)?;

			let frame = signed_reconcile_gossip(&certs.key, b"pex-after-expel", vec![]).await?;
			let after = reconcile_reply(&certs, &gateway, frame).await?;
			trace.event_with(PEX_SHARED_AFTER_EXPEL, &[], count_u64(after.pex.len()))?;

			let routes = gateway.peer_routes()?.len();
			trace.event_with(PEER_ROUTES_AFTER_EXPEL, &[], count_u64(routes))?;

			gateway.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipIngressOriginSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_INGRESS_SIGNED_BY_GATEWAY, exactly!(1), equals!(true)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1))
		]
	}
}

// The ingress servlet receives the rumor as its origin signed it.
//
// A hive publishes, and the gateway signs the rumor and delivers it to the
// ingress servlet before it answers the publish.
//
// - The servlet decodes a `GossipRumor` from the frame's message, so it reads the payload and the kind.
// - The frame's signature verifies under the publishing gateway's key (GOSSIP_INGRESS_SIGNED_BY_GATEWAY).
tb_scenario! {
	name: cluster_gossip_ingress_receives_the_origin_signed_rumor,
	spec: ClusterGossipIngressOriginSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf, _journal) = gossip_cluster_conf(&certs, vec![]);
			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;

			let body = rumor_body(encode(&PingRequest { value: 21 })?);
			let frame = hive_publish_gossip(&certs, b"ingress-origin-rumor", body, 0).await?;
			send_gossip_frame(&trace, &certs, &gateway, frame).await?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipIngressImpostorSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(REGISTER_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_DIAL_REFUSED, at_least!(1)),
			(GOSSIP_INGRESS_SIGNED_BY_GATEWAY, exactly!(0)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0))
		]
	}
}

// The ingress delivery reaches the ingress servlet only under the identity
// its registration names. The gateway's hive trust holds both identities, so
// the handshake completes, and the dial's binding alone refuses the answer
// (CWE-346). The rumor stays in the retry set, and the binding refuses each
// retry the same way.
tb_scenario! {
	name: cluster_gossip_ingress_refuses_a_servlet_answering_under_another_identity,
	spec: ClusterGossipIngressImpostorSpec,
	environment Bare {
		context: cluster_certs(),
		exec: |SetupEnv { trace, context: certs }| async move {
			let hive_plane = hive_plane_certs(&certs);
			let impostor_certs = stranger_gateway_certs();
			let impostor_conf = servlet_tls_builder(&impostor_certs)?.with_config(Arc::new(None)).build();
			let impostor = ClusterRumorServlet::start(Arc::new(trace.share()), impostor_conf).await?;

			let (mut conf, _journal) = gossip_cluster_conf(&certs, vec![]);
			conf.tls.hive_trust = Some(combined_trust(&[&certs.cert, &hive_plane.cert, &impostor_certs.cert]));
			let gateway = start_cluster(&trace, conf).await?;

			let mut control = connect_cluster(&certs, gateway.addr()).await?;
			let hive_addr = b"127.0.0.1:65035";
			let signer = signer_of(&hive_plane.cert);
			let servlets = [servlet_info_signed_by("rumor", impostor.addr().to_string(), signer)];
			let registered =
				register_signed_hive_serving(&mut control, &hive_plane.key, b"impostor", hive_addr, servlets).await?;
			trace.event_with(REGISTER_STATUS, &[], registered.status)?;

			let body = rumor_body(encode(&PingRequest { value: 21 })?);
			let frame = hive_publish_gossip(&certs, b"ingress-impostor-rumor", body, 0).await?;
			send_gossip_frame(&trace, &certs, &gateway, frame).await?;

			gateway.stop();
			impostor.stop();
			Ok(())
		}
	}
}

/// The fixture for the ingress-None delivery policy.
///
/// The scenario needs the journal handle to observe retention and the retry
/// set from outside.
struct IngressNoneCtx {
	certs: ClusterTestCerts,
	journal: Arc<MemoryGossipJournal>,
}

fn ingress_none_ctx() -> IngressNoneCtx {
	IngressNoneCtx { certs: cluster_certs(), journal: Arc::new(MemoryGossipJournal::default()) }
}

tb_assert_spec! {
	pub ClusterGossipIngressNoneSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0)),
			(GOSSIP_HELD_NO_INGRESS, exactly!(1), equals!(1u64)),
			(GOSSIP_PENDING_NO_INGRESS, exactly!(1), equals!(1u64))
		]
	}
}

// With no configured ingress the gateway journals and refloods only.
//
// - The gateway answers the publish Ok and retains it (held = 1).
// - The gateway acks the record at once, so it never enters the pending retry set.
// - The gateway reports no local delivery (ACCEPTED = 0).
// - The journal settles before the publish reply returns, so the probes need no poll.
tb_scenario! {
	name: cluster_gossip_ingress_none_acks_on_record,
	spec: ClusterGossipIngressNoneSpec,
	environment Cluster {
		context: ingress_none_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let mut conf = peering_cluster_conf(&ctx.certs);
			conf.tls.hive_trust = Some(split_hive_trust(&ctx.certs));
			conf.gossip = GossipConfig {
				journal: Arc::clone(&ctx.journal) as Arc<dyn GossipJournal>,
				ingress: None,
				..Default::default()
			};
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let frame = hive_publish_gossip(
				&ctx.certs,
				b"ingress-none-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &ctx.certs, &cluster, frame).await?;

			let now = UnixMillis::now();
			let held_one = ctx.journal.held_digests(now).is_ok_and(|digests| digests.len() == 1);
			let none_pending = ctx.journal.pending_local(now).is_ok_and(|rumors| rumors.is_empty());
			trace.event_with(GOSSIP_HELD_NO_INGRESS, &[], u64::from(held_one))?;
			trace.event_with(GOSSIP_PENDING_NO_INGRESS, &[], u64::from(none_pending))?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerDiscoverySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, at_least!(2), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_PEER_DISCOVERED, at_least!(2)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64))
		]
	}
}

// The beat discovers peers from one seed through peer exchange.
//
// X anchors only seed S, S anchors publisher P, and P anchors nobody.
//
// - S's beat verifies its anchor P and shares P over PEX.
// - X learns P, feeler-probes it, proves its flood membership, and promotes it (CLUSTER_PEER_DISCOVERED).
// - X's advertisement teaches P to dial back, and P promotes X the same way.
// - A rumor that P publishes at ttl 0 moves by repair alone.
// - It reaches X's ingress only across those two discovered edges.
tb_scenario! {
	name: cluster_peer_discovery_bootstraps_from_seed,
	spec: ClusterPeerDiscoverySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (mut conf_p, journal_p) = gossip_cluster_conf(&certs, vec![]);
			conf_p.peer.advertise_interval = Some(Duration::from_millis(100));
			let gateway_p = start_cluster(&trace, conf_p).await?;

			let (mut conf_s, _journal_s) = gossip_cluster_conf(&certs, vec![gateway_p.addr().to_string()]);
			conf_s.peer.advertise_interval = Some(Duration::from_millis(100));
			let table_s = Arc::clone(conf_s.peer.table());
			let gateway_s = start_cluster(&trace, conf_s).await?;

			let (mut conf_x, journal_x) = gossip_cluster_conf(&certs, vec![gateway_s.addr().to_string()]);
			conf_x.peer.advertise_interval = Some(Duration::from_millis(100));
			let table_x = Arc::clone(conf_x.peer.table());
			let gateway_x = start_cluster(&trace, conf_x).await?;

			let hive_x = start_scenario_rumor_hive(trace.share(), &certs).await?;
			hive_x.register_with_cluster(gateway_x.addr()).await?;
			hive.register_with_cluster(gateway_p.addr()).await?;

			let frame = hive_publish_gossip(
				&certs,
				b"discovery-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_p, frame).await?;

			let converged =
				wait_for_gossip_converged(&[journal_p, journal_x], 1, 100, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			// The spec counts promotions, and each one is a beat apart from
			// convergence. Wait for the beats this scenario is about before
			// the scenario takes the gateways away from them.
			wait_for_promoted(&table_s, 1, 100, Duration::from_millis(100)).await;
			wait_for_promoted(&table_x, 1, 100, Duration::from_millis(100)).await;

			gateway_p.stop();
			gateway_s.stop();
			gateway_x.stop();
			hive_x.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerEclipseBoundSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_TABLE_FLOOD_ADMITTED, exactly!(1), equals!(MAX_PEER_BUCKET as u64)),
			(PEER_TABLE_ANCHOR_RETAINED, exactly!(1), equals!(true)),
			(PEER_TABLE_TARGETS_BOUNDED, exactly!(1), equals!(true))
		]
	}
}

// The discovery table bounds an eclipse attack.
//
// An attacker inside one /16 prefix floods hints past the bucket cap and
// even passes every probe.
//
// - Admission stops at the per-prefix cap.
// - The configured anchor keeps its leading dial slot.
// - The target set stays bounded.
// - The attacker can never steer the beat wholly onto its own addresses.
//
// Sources:
//
// - Heilman, Kendler, Zohar & Goldberg (2015), eclipse attacks on
//   Bitcoin's peer-to-peer network, USENIX Security '15
//   (https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman),
//   and ePrint 2015/263 (https://eprint.iacr.org/2015/263)
// - CWE-770, allocation of resources without limits or throttling:
//   <https://cwe.mitre.org/data/definitions/770.html>
tb_scenario! {
	name: cluster_peer_table_bounds_eclipse_flood,
	spec: ClusterPeerEclipseBoundSpec,
	environment Bare {
		context: cluster_certs(),
		exec: |SetupEnv { trace, context: certs }| {
			let anchor = peer_addr("127.0.0.1:9000");
			let conf = peering_cluster_conf_with_peers(&certs, vec![anchor.to_string()]);
			let table = Arc::clone(conf.peer.table());
			let flood: Vec<PeerHint> = (0..MAX_PEER_BUCKET + 8)
				.map(|host| PeerHint {
					dial: dial_admitted_by(&conf, format!("10.66.0.{}:9000", host + 1)),
					peer_id: None,
				})
				.collect();

			let admitted = table.learn(flood.clone(), UnixMillis::now()).unwrap_or_default();
			trace.event_with(PEER_TABLE_FLOOD_ADMITTED, &[], admitted as u64)?;

			for hint in &flood {
				// A full bucket answers a promotion with `Ok(false)`, and the
				// scenario reads the target set that the promotions leave.
				let _ = table.promote(hint.dial, None, UnixMillis::now());
			}

			let targets = table.target_set().unwrap_or_default();
			trace.event_with(PEER_TABLE_ANCHOR_RETAINED, &[], targets.first().map(AdmittedDial::address) == Some(anchor))?;
			trace.event_with(PEER_TABLE_TARGETS_BOUNDED, &[], targets.len() <= MAX_PEER_BUCKET + 1)?;
			Ok(())
		}
	}
}

/// The fixture for the feeler-probe membership proof.
///
/// The prober TLS-trusts a gateway of colony "other" and a gateway whose
/// certificate carries no colony URN, so the membership proof alone tells the
/// stranger from the two colonies.
struct NeighborGatewayCtx {
	local: ClusterTestCerts,
	neighbor: ClusterTestCerts,
	stranger: ClusterTestCerts,
	shared_trust: Arc<dyn CertificateTrust>,
}

fn neighbor_gateway_ctx() -> NeighborGatewayCtx {
	let local = cluster_certs();
	let neighbor = neighbor_colony_certs();
	let stranger = stranger_gateway_certs();
	let shared_trust = combined_trust(&[&local.cert, &neighbor.cert, &stranger.cert]);
	NeighborGatewayCtx { local, neighbor, stranger, shared_trust }
}

/// A running gateway whose certificate carries no colony URN, TLS-anchored
/// both ways.
///
/// A probe against it completes the handshake and fails the membership proof
/// alone.
fn stranger_gateway_conf(ctx: &NeighborGatewayCtx) -> ClusterConfig {
	let tls = cluster_tls_config_with_trust(&ctx.stranger, None)
		.with_hive_trust(Arc::clone(&ctx.shared_trust))
		.with_peer_trust(Arc::clone(&ctx.shared_trust));
	ClusterConfig::new(tls)
}

/// A running gateway from colony "other", TLS-anchored both ways.
///
/// A probe against it completes the handshake and proves flood membership.
fn neighbor_gateway_conf(ctx: &NeighborGatewayCtx) -> ClusterConfig {
	let tls = cluster_tls_config_with_trust(&ctx.neighbor, None)
		.with_hive_trust(Arc::clone(&ctx.shared_trust))
		.with_peer_trust(Arc::clone(&ctx.shared_trust));
	ClusterConfig::new(tls)
}

/// A prober with no anchors and a fast beat.
///
/// Discovery runs on feeler probes alone.
///
/// - `peer_trust` decides which probed identities complete the handshake.
/// - The membership proof then separates flood members from strangers.
fn fast_probing_conf(certs: &ClusterTestCerts, peer_trust: Arc<dyn CertificateTrust>) -> ClusterConfig {
	let tls = cluster_tls_config(certs).with_peer_trust(peer_trust);
	ClusterConfig::builder(tls)
		.with_advertise_interval(Duration::from_millis(100))
		.build()
}

/// A prober whose trust anchors every identity of [`NeighborGatewayCtx`], so
/// the membership proof alone separates them.
fn probing_cluster_conf(ctx: &NeighborGatewayCtx) -> ClusterConfig {
	fast_probing_conf(&ctx.local, Arc::clone(&ctx.shared_trust))
}

/// Polls until the discovery table holds no new-bucket candidates, or the
/// attempts run out.
///
/// Feeler probes run on the advertise beat's cadence, so only a poll can
/// observe their outcome.
async fn wait_for_new_candidates_drained(table: &PeerTable, attempts: u32, interval: Duration) -> bool {
	let drained = || table.learned().is_ok_and(|(new_count, _)| new_count == 0);
	poll_until(attempts, interval, drained).await
}

tb_assert_spec! {
	pub ClusterPeerMembershipProbeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_PROBE_HINTS_ADMITTED, exactly!(1), equals!(3u64)),
			(events::CLUSTER_PEER_DISCOVERED, exactly!(2)),
			(PEER_PROBE_MEMBER_PROMOTED, exactly!(1), equals!(true)),
			(PEER_PROBE_NEIGHBOR_PROMOTED, exactly!(1), equals!(true)),
			(PEER_PROBE_STRANGER_REFUSED, exactly!(1), equals!(true))
		]
	}
}

// Feeler probes promote on flood membership.
//
// Three learned hints name a gateway of colony "main", a gateway of colony
// "other", and a TLS-trusted gateway whose certificate carries no colony URN.
// All three probes complete the handshake.
//
// - Both colonies prove membership and join the beat targets (CLUSTER_PEER_DISCOVERED exactly twice).
// - The stranger leaves the new table through expel, so it holds no bucket slot and stays off the targets.
//
// Sources:
//
// - CWE-668, exposure of resource to wrong sphere: <https://cwe.mitre.org/data/definitions/668.html>
tb_scenario! {
	name: cluster_feeler_probe_promotes_neighbor_and_discards_stranger,
	spec: ClusterPeerMembershipProbeSpec,
	environment Cluster {
		context: neighbor_gateway_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_cluster(&trace, stranger_gateway_conf(&ctx)).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let member_conf = peering_cluster_conf_with_trust(&ctx.local, Arc::clone(&ctx.shared_trust));
			let member = start_cluster(&trace, member_conf).await?;
			let neighbor = start_cluster(&trace, neighbor_gateway_conf(&ctx)).await?;

			let prober_conf = probing_cluster_conf(&ctx);
			let table = Arc::clone(prober_conf.peer.table());
			let stranger_addr = dial_admitted_by(&prober_conf, cluster.addr().to_string());
			let member_addr = dial_admitted_by(&prober_conf, member.addr().to_string());
			let neighbor_addr = dial_admitted_by(&prober_conf, neighbor.addr().to_string());
			let prober = start_cluster(&trace, prober_conf).await?;

			let hints = vec![
				PeerHint { dial: stranger_addr, peer_id: None },
				PeerHint { dial: member_addr, peer_id: None },
				PeerHint { dial: neighbor_addr, peer_id: None },
			];

			let admitted = table.learn(hints, UnixMillis::now())?;
			trace.event_with(PEER_PROBE_HINTS_ADMITTED, &[], count_u64(admitted))?;

			let drained = wait_for_new_candidates_drained(&table, 50, Duration::from_millis(100)).await;
			let targets = table.target_set()?;
			trace.event_with(PEER_PROBE_MEMBER_PROMOTED, &[], targets.contains(&member_addr))?;
			trace.event_with(PEER_PROBE_NEIGHBOR_PROMOTED, &[], targets.contains(&neighbor_addr))?;
			trace.event_with(PEER_PROBE_STRANGER_REFUSED, &[], drained && !targets.contains(&stranger_addr))?;

			prober.stop();
			neighbor.stop();
			member.stop();
			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerExpelSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(PEER_EXPEL_ADDRESS_VERIFIED, exactly!(1), equals!(true)),
			(PEER_EXPEL_TARGET_DROPPED, exactly!(1), equals!(true)),
			(events::CLUSTER_PEER_EVICTED, exactly!(0)),
			(events::CLUSTER_PEER_EXPELLED, at_least!(1)),
			(PEER_ROUTES_AFTER_EXPEL, exactly!(1), equals!(1u64))
		]
	}
}

// A verified peer that answers from outside the flood leaves the beat targets
// and keeps its routes.
//
// A slate arrives under the local colony's key from an address, and the table
// holds that address as verified. The address answers the next beat with a
// certificate that carries no colony URN.
//
// - The beat expels the address at its first answer, ahead of the failure threshold (CLUSTER_PEER_EVICTED).
// - The expulsion is on the record (CLUSTER_PEER_EXPELLED), once or more,
//   because a feeler probe can expel the address before the table verifies it.
// - The routes that dial the address stay: membership decides gossip, and the hop binding decides work.
tb_scenario! {
	name: cluster_peer_that_leaves_the_flood_leaves_the_targets_and_keeps_its_routes,
	spec: ClusterPeerExpelSpec,
	environment Cluster {
		context: neighbor_gateway_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_cluster(&trace, stranger_gateway_conf(&ctx)).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let prober_conf = probing_cluster_conf(&ctx);
			let table = Arc::clone(prober_conf.peer.table());
			let outside_addr = dial_admitted_by(&prober_conf, cluster.addr().to_string());
			let prober = start_cluster(&trace, prober_conf).await?;

			// The slate gives the address routes to keep.
			advertise_peer(&trace, &ctx.local, &prober, cluster.addr().to_string(), vec![servlet_urn("ping")]).await?;

			let verified = table.promote(outside_addr, None, UnixMillis::now())?;
			trace.event_with(PEER_EXPEL_ADDRESS_VERIFIED, &[], verified)?;

			let dropped = wait_for_target_dropped(&table, outside_addr, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_EXPEL_TARGET_DROPPED, &[], dropped)?;

			let routes = prober.peer_routes()?.len();
			trace.event_with(PEER_ROUTES_AFTER_EXPEL, &[], count_u64(routes))?;

			prober.stop();
			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterOutsideCandidateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(PEER_PROBE_STRANGER_REFUSED, exactly!(1), equals!(true)),
			(events::CLUSTER_PEER_DISCOVERED, exactly!(0)),
			(PEER_ROUTES_AFTER_EXPEL, exactly!(1), equals!(1u64))
		]
	}
}

// An unverified candidate that answers from outside the flood leaves the new
// table and keeps its routes.
//
// A slate arrives under the local colony's key from an address, so the table
// holds that address as an unverified candidate while the routes already dial
// it. The feeler probe finds a certificate that carries no colony URN there.
//
// - The probe expels the candidate, so it holds no bucket slot and never joins the beat targets.
// - The routes that dial the address stay (PEER_ROUTES_AFTER_EXPEL).
tb_scenario! {
	name: cluster_candidate_that_answers_outside_the_flood_keeps_its_routes,
	spec: ClusterOutsideCandidateSpec,
	environment Cluster {
		context: neighbor_gateway_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_cluster(&trace, stranger_gateway_conf(&ctx)).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let prober_conf = probing_cluster_conf(&ctx);
			let table = Arc::clone(prober_conf.peer.table());
			let outside_addr = dial_admitted_by(&prober_conf, cluster.addr().to_string());
			let prober = start_cluster(&trace, prober_conf).await?;

			advertise_peer(&trace, &ctx.local, &prober, cluster.addr().to_string(), vec![servlet_urn("ping")]).await?;

			let drained = wait_for_new_candidates_drained(&table, 50, Duration::from_millis(100)).await;
			let targets = table.target_set()?;
			trace.event_with(PEER_PROBE_STRANGER_REFUSED, &[], drained && !targets.contains(&outside_addr))?;

			let routes = prober.peer_routes()?.len();
			trace.event_with(PEER_ROUTES_AFTER_EXPEL, &[], count_u64(routes))?;

			prober.stop();
			cluster.stop();
			Ok(())
		}
	}
}

/// Polls until the gateways refuse `count` advertisements, or five seconds
/// pass.
async fn wait_for_refused_advertisements(trace: &TraceCollector, count: usize) -> bool {
	let refused = || trace.recorded(events::CLUSTER_PEER_ADVERTISE_REFUSED) >= count;
	poll_until(50, Duration::from_millis(100), refused).await
}

tb_assert_spec! {
	pub ClusterOutsideAnchorSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(PEER_ANCHOR_BEATS_ANSWERED, exactly!(1), equals!(true)),
			(PEER_ANCHOR_STILL_TARGET, exactly!(1), equals!(true)),
			(events::CLUSTER_PEER_EVICTED, exactly!(0)),
			(PEER_ROUTES_AFTER_BEATS, exactly!(1), equals!(1u64))
		]
	}
}

// An anchor that answers from outside the flood keeps its slot and the routes
// that dial it.
//
// An operator configured the anchor, so no learned table holds its address.
// A slate arrives under the local colony's key and claims that address. The
// anchor answers each beat with a certificate that carries no colony URN.
//
// - The anchor refuses one advertisement per beat, so two refusals are two beats that dialed it.
// - The anchor stays a beat target, because an operator configured it (PEER_ANCHOR_STILL_TARGET).
// - The routes that dial the anchor stay (PEER_ROUTES_AFTER_BEATS).
tb_scenario! {
	name: cluster_anchor_that_answers_outside_the_flood_keeps_its_slot_and_its_routes,
	spec: ClusterOutsideAnchorSpec,
	environment Cluster {
		context: neighbor_gateway_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_cluster(&trace, stranger_gateway_conf(&ctx)).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let anchor = cluster.addr().to_string();
			let prober_conf = federation_conf(&ctx.local, Arc::clone(&ctx.shared_trust), vec![anchor.clone()], 1);
			let table = Arc::clone(prober_conf.peer.table());
			let anchor_addr = dial_admitted_by(&prober_conf, &anchor);
			let prober = start_cluster(&trace, prober_conf).await?;

			advertise_peer(&trace, &ctx.local, &prober, &anchor, vec![servlet_urn("ping")]).await?;

			// The count starts after the routes exist, so both beats ran over
			// them.
			let refused_so_far = trace.recorded(events::CLUSTER_PEER_ADVERTISE_REFUSED);
			let beats_answered = wait_for_refused_advertisements(&trace, refused_so_far + 2).await;
			trace.event_with(PEER_ANCHOR_BEATS_ANSWERED, &[], beats_answered)?;

			let targets = table.target_set()?;
			trace.event_with(PEER_ANCHOR_STILL_TARGET, &[], targets.contains(&anchor_addr))?;

			let routes = prober.peer_routes()?.len();
			trace.event_with(PEER_ROUTES_AFTER_BEATS, &[], count_u64(routes))?;

			prober.stop();
			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterRefloodExpelSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_EXPEL_ADDRESS_VERIFIED, exactly!(1), equals!(true)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_EXPEL_TARGET_DROPPED, exactly!(1), equals!(true)),
			(events::CLUSTER_PEER_EVICTED, exactly!(0)),
			(events::CLUSTER_GOSSIP_FANOUT_UNREACHED, exactly!(0))
		]
	}
}

// A reflood drops a target that answers from outside the flood.
//
// The table holds an address as verified, and no beat runs. A hive publishes a
// rumor, and the address answers the reflood with a certificate that carries
// no colony URN.
//
// - The hop sends no rumor, and the address leaves the targets at once (PEER_EXPEL_TARGET_DROPPED).
// - The answer is no failed dial, so nothing counts as unreached (CLUSTER_GOSSIP_FANOUT_UNREACHED).
tb_scenario! {
	name: cluster_reflood_drops_a_target_that_answers_outside_the_flood,
	spec: ClusterRefloodExpelSpec,
	environment Cluster {
		context: neighbor_gateway_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_cluster(&trace, stranger_gateway_conf(&ctx)).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			// No beat runs, so the reflood alone can dial the address.
			let mut publisher_conf = probing_cluster_conf(&ctx);
			publisher_conf.peer.advertise_interval = None;
			publisher_conf.tls.hive_trust = Some(split_hive_trust(&ctx.local));
			let table = Arc::clone(publisher_conf.peer.table());
			let outside_addr = dial_admitted_by(&publisher_conf, cluster.addr().to_string());
			let publisher = start_cluster(&trace, publisher_conf).await?;

			let verified = table.promote(outside_addr, None, UnixMillis::now())?;
			trace.event_with(PEER_EXPEL_ADDRESS_VERIFIED, &[], verified)?;

			let body = rumor_body(encode(&PingRequest { value: 21 })?);
			let frame = hive_publish_gossip(&ctx.local, b"reflood-expel-rumor", body, 1).await?;
			send_gossip_frame(&trace, &ctx.local, &publisher, frame).await?;

			let dropped = wait_for_target_dropped(&table, outside_addr, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_EXPEL_TARGET_DROPPED, &[], dropped)?;

			publisher.stop();
			cluster.stop();
			Ok(())
		}
	}
}

/// Parses a fixture dial address, which the peer table takes parsed.
pub fn peer_addr(text: impl AsRef<str>) -> PeerAddress {
	text.as_ref().parse().expect("fixture address parses as a socket")
}

/// The fixture dial address `text`, admitted by `conf`'s dial policy the
/// way the policy admits a peer-exchange entry before the table learns it.
pub fn dial_admitted_by(conf: &ClusterConfig, text: impl AsRef<str>) -> AdmittedDial {
	let socket = peer_addr(text);
	let admitted = conf.peer.admit_dial(socket);
	admitted.expect("the fixture plane admits every fixture socket")
}

/// Waits until `table` has promoted at least `count` learned peers.
///
/// `CLUSTER_PEER_DISCOVERED` fires on that promotion, which the advertise beat
/// drives. A scenario that stops its gateways the moment gossip converges can
/// outrun the beat, so a spec that asserts a discovery count needs this wait
/// rather than the convergence one.
pub async fn wait_for_promoted(table: &PeerTable, count: usize, attempts: u32, interval: Duration) -> bool {
	let promoted = || table.learned().is_ok_and(|(_, tried)| tried >= count);
	poll_until(attempts, interval, promoted).await
}

/// Polls until `addr` leaves the beat targets, or the attempts run out.
///
/// Eviction runs on the advertise beat's cadence, so only a poll can observe
/// the outcome.
async fn wait_for_target_dropped(table: &PeerTable, addr: AdmittedDial, attempts: u32, interval: Duration) -> bool {
	let dropped = || table.target_set().is_ok_and(|targets| !targets.contains(&addr));
	poll_until(attempts, interval, dropped).await
}

/// A running gateway that answers every reconcile round with one fixed
/// peer-exchange sample.
struct ReconcileReplier {
	/// The accept task, which the scenario aborts when it ends.
	task: tokio::task::JoinHandle<()>,
	/// The address the gateway answers at.
	addr: String,
	/// How many reconcile rounds the gateway has answered.
	answered: Arc<AtomicUsize>,
	/// The order of the last round the gateway answered, which the prober
	/// stamps from its clock when the round starts.
	last_order: Arc<AtomicU64>,
}

/// A same-colony gateway that answers every frame with `pex` as its
/// peer-exchange sample.
///
/// The TLS identity is honest, so the prober's membership proof passes.
async fn start_reconcile_server(
	certs: &ClusterTestCerts,
	pex: Vec<PeerGossip>,
) -> Result<ReconcileReplier, TightBeamError> {
	let identity = signing_identity(certs.cert.to_owned(), certs.key.to_owned());
	let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(identity);
	let bind_addr = "127.0.0.1:0".parse::<TightBeamSocketAddr>()?;
	let (listener, addr) = <TokioListener as EncryptedProtocol>::bind_with(bind_addr, config).await?;

	let answered = Arc::new(AtomicUsize::new(0));
	let last_order = Arc::new(AtomicU64::new(0));
	let rounds = Arc::clone(&answered);
	let orders = Arc::clone(&last_order);
	let task = server! {
		protocol TokioListener: listener,
		handle: move |frame: Frame| {
			let rounds = Arc::clone(&rounds);
			let orders = Arc::clone(&orders);
			let pex = pex.clone();
			async move {
				orders.store(frame.metadata().order(), Ordering::SeqCst);
				rounds.fetch_add(1, Ordering::SeqCst);

				reply_frame(frame.metadata().id(), GossipWant { want: Vec::new(), pex })
			}
		}
	};

	Ok(ReconcileReplier { task, addr: addr.to_string(), answered, last_order })
}

/// Polls until `replier` has answered `rounds` reconcile rounds, or five
/// seconds pass.
async fn wait_for_answered_rounds(replier: &ReconcileReplier, rounds: usize) -> bool {
	let answered = || replier.answered.load(Ordering::SeqCst) >= rounds;
	poll_until(50, Duration::from_millis(100), answered).await
}

tb_assert_spec! {
	pub ClusterOversizedReplySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_DISCOVERED, exactly!(0)),
			(PEER_ABUSE_CANDIDATE_HELD_BACK, exactly!(1), equals!(true))
		]
	}
}

// An oversized reconcile reply is misbehavior, not a completed round.
//
// The rogue holds a valid same-colony certificate, so it passes the
// handshake and the membership proof. Its reply exceeds MAX_PEX_SAMPLE, and
// only the reply volume abuses the protocol.
//
// - The prober never promotes the candidate (CLUSTER_PEER_DISCOVERED exactly 0).
// - The failed round stays on the candidate, which keeps its slot until a newcomer needs it.
// - A second probe reaches it, which only a kept candidate can receive (PEER_ABUSE_CANDIDATE_HELD_BACK).
tb_scenario! {
	name: cluster_feeler_keeps_an_abusive_candidate_unpromoted,
	spec: ClusterOversizedReplySpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let entry = PeerGossip { peer_id: Vec::new(), gateway_addr: b"10.66.0.1:9000".to_vec() };
			let rogue = start_reconcile_server(&certs, vec![entry; MAX_PEX_SAMPLE + 1]).await?;

			let prober_conf = fast_probing_conf(&certs, Arc::clone(&certs.trust));
			let table = Arc::clone(prober_conf.peer.table());
			let rogue_addr = dial_admitted_by(&prober_conf, &rogue.addr);
			let prober = start_cluster(&trace, prober_conf).await?;

			let admitted = table.learn(vec![PeerHint { dial: rogue_addr, peer_id: None }], UnixMillis::now())?;

			let probed_twice = wait_for_answered_rounds(&rogue, 2).await;
			let targets = table.target_set()?;
			let held = table.learned()? == (1, 0);
			let held_back = admitted == 1 && probed_twice && held && !targets.contains(&rogue_addr);
			trace.event_with(PEER_ABUSE_CANDIDATE_HELD_BACK, &[], held_back)?;

			rogue.task.abort();
			prober.stop();
			cluster.stop();
			Ok(())
		}
	}
}

/// A peer store that keeps the snapshot the table persisted last.
#[derive(Default)]
struct RecordingPeerStore {
	snapshot: Mutex<Vec<PeerRecord>>,
}

impl RecordingPeerStore {
	/// The stamp the last snapshot holds for `addr`, when it holds the
	/// address.
	fn stamp_of(&self, addr: AdmittedDial) -> Option<UnixMillis> {
		let snapshot = self.snapshot.lock().unwrap_or_else(PoisonError::into_inner);
		let record = snapshot.iter().find(|record| record.gateway_addr == addr.address())?;

		Some(record.last_probe)
	}
}

impl PeerStore for RecordingPeerStore {
	fn hydrate(&self) -> Result<Vec<PeerRecord>, ClusterError> {
		Ok(Vec::new())
	}

	fn persist(&self, records: &[PeerRecord]) -> Result<(), ClusterError> {
		let mut snapshot = self.snapshot.lock().unwrap_or_else(PoisonError::into_inner);
		*snapshot = records.to_vec();

		Ok(())
	}
}

/// The beat of [`recording_conf`], on its manual clock.
const RECORDING_BEAT: Duration = Duration::from_millis(100);

/// A gateway conf on `clock` whose peer table persists to `store`, with
/// `peers` as its peer trust and a beat every [`RECORDING_BEAT`] of the
/// clock.
fn recording_conf(
	certs: &ClusterTestCerts,
	peers: Arc<dyn CertificateTrust>,
	clock: &Arc<ManualClock>,
	store: &Arc<RecordingPeerStore>,
) -> ClusterConfig {
	let tls = cluster_tls_config(certs).with_peer_trust(peers);
	let mut conf = ClusterConfig::builder(tls)
		.with_advertise_interval(RECORDING_BEAT)
		.with_peer_store(Arc::clone(store) as Arc<dyn PeerStore>)
		.build();
	conf.clock = Arc::clone(clock) as Arc<dyn Clock>;

	conf
}

/// Polls until `store` holds `addr`, or five seconds pass, and answers the
/// stamp it holds then.
async fn wait_for_stamp(store: &RecordingPeerStore, addr: AdmittedDial) -> Option<UnixMillis> {
	poll_until(50, Duration::from_millis(100), || store.stamp_of(addr).is_some()).await;

	store.stamp_of(addr)
}

/// Moves `clock` one beat at a time until `store` holds `addr`, or five
/// seconds pass.
///
/// The clock moves only while the address is absent, so the beat that learns
/// it is the last beat to run.
async fn beat_until_learned(clock: &ManualClock, store: &RecordingPeerStore, addr: AdmittedDial) -> bool {
	poll_until(50, Duration::from_millis(100), || {
		let learned = store.stamp_of(addr).is_some();
		if !learned {
			clock.advance(RECORDING_BEAT);
		}

		learned
	})
	.await
}

tb_assert_spec! {
	pub ClusterRelearnedHintStampSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_RELEARNED_HINT_STAMPED, exactly!(1), equals!(true))
		]
	}
}

// A hint that a peer-exchange reply teaches again carries the reading of the
// gateway's clock at the round that taught it.
//
// - The prober learns the shared address and drops it, so the reply teaches it again.
// - The manual clock moves one beat at a time until the prober's store holds the address.
// - The replier records the round's order, which the prober stamps from its clock.
// - The persisted stamp of the address equals that reading (PEER_RELEARNED_HINT_STAMPED).
tb_scenario! {
	name: cluster_relearned_hint_takes_the_clock_reading,
	spec: ClusterRelearnedHintStampSpec,
	environment Bare {
		context: cluster_certs(),
		exec: |SetupEnv { trace, context: certs }| async move {
			let shared = PeerGossip { peer_id: Vec::new(), gateway_addr: b"10.66.0.1:9000".to_vec() };
			let replier = start_reconcile_server(&certs, vec![shared]).await?;

			let clock = Arc::new(ManualClock::default());
			let store = Arc::new(RecordingPeerStore::default());
			let prober_conf = recording_conf(&certs, Arc::clone(&certs.trust), &clock, &store);

			let table = Arc::clone(prober_conf.peer.table());
			let shared_addr = dial_admitted_by(&prober_conf, "10.66.0.1:9000");
			let replier_addr = dial_admitted_by(&prober_conf, &replier.addr);
			table.learn(vec![PeerHint { dial: shared_addr, peer_id: None }], clock.unix())?;
			table.discard(shared_addr)?;
			table.learn(vec![PeerHint { dial: replier_addr, peer_id: None }], clock.unix())?;
			let prober = start_cluster(&trace, prober_conf).await?;

			let relearned = beat_until_learned(&clock, &store, shared_addr).await;
			let round_reading = UnixMillis::new(replier.last_order.load(Ordering::SeqCst));
			let stamped = relearned && store.stamp_of(shared_addr) == Some(round_reading);
			trace.event_with(PEER_RELEARNED_HINT_STAMPED, &[], stamped)?;

			replier.task.abort();
			prober.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterAdvertiserHintStampSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(ADVERTISER_HINT_STAMPED, exactly!(1), equals!(true))
		]
	}
}

// A verified advertiser joins the table as a hint stamped with the reading
// of the gateway's clock when its advertisement arrived.
tb_scenario! {
	name: cluster_advertiser_hint_takes_the_clock_reading,
	spec: ClusterAdvertiserHintStampSpec,
	environment Bare {
		context: cluster_certs(),
		exec: |SetupEnv { trace, context: certs }| async move {
			let clock = Arc::new(ManualClock::default());
			let store = Arc::new(RecordingPeerStore::default());
			let conf = recording_conf(&certs, Arc::clone(&certs.trust), &clock, &store);
			let advertiser = dial_admitted_by(&conf, String::from_utf8_lossy(PEER_GATEWAY_ADDR));
			let gateway = start_cluster(&trace, conf).await?;

			install_ping_peer(&trace, &certs, &gateway).await?;
			let stamped = wait_for_stamp(&store, advertiser).await == Some(clock.unix());
			trace.event_with(ADVERTISER_HINT_STAMPED, &[], stamped)?;

			gateway.stop();
			Ok(())
		}
	}
}

/// The address the origin of a relayed advertisement rumor claims.
const ORIGIN_GATEWAY_ADDR: &str = "127.0.0.1:9002";

tb_assert_spec! {
	pub ClusterOriginHintStampSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(ORIGIN_HINT_STAMPED, exactly!(1), equals!(true))
		]
	}
}

// The origin of a relayed advertisement rumor joins the table as a hint
// stamped with the reading of the gateway's clock when the rumor arrived.
tb_scenario! {
	name: cluster_rumored_origin_hint_takes_the_clock_reading,
	spec: ClusterOriginHintStampSpec,
	environment Bare {
		context: cluster_certs(),
		exec: |SetupEnv { trace, context: certs }| async move {
			let (origin_cert, origin_key) = member_identity("Origin gateway");
			let clock = Arc::new(ManualClock::default());
			let store = Arc::new(RecordingPeerStore::default());
			let peers = combined_trust(&[&certs.cert, &origin_cert]);
			let conf = recording_conf(&certs, peers, &clock, &store);
			let origin = dial_admitted_by(&conf, ORIGIN_GATEWAY_ADDR);
			let gateway = start_cluster(&trace, conf).await?;

			let types = vec![servlet_urn("ping")];
			let status = flood_ad_rumor(&certs, &origin_key, &gateway, ORIGIN_GATEWAY_ADDR, types, 0, b"origin").await?;
			trace.event_with(PEER_AD_STATUS, &[], status)?;

			let stamped = wait_for_stamp(&store, origin).await == Some(clock.unix());
			trace.event_with(ORIGIN_HINT_STAMPED, &[], stamped)?;

			gateway.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerEvictionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_DISCOVERED, exactly!(1)),
			(PEER_EVICT_MEMBER_PROMOTED, exactly!(1), equals!(true)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_EVICTED, exactly!(1)),
			(PEER_EVICT_TARGET_DROPPED, exactly!(1), equals!(true)),
			(PEER_EVICT_ROUTES_WITHDRAWN, exactly!(1), equals!(true))
		]
	}
}

// The beat evicts a verified tried peer that goes dark (liveness).
//
// The prober learns the member as a hint, feeler-probes it, proves its flood
// membership, and promotes it into tried (CLUSTER_PEER_DISCOVERED). The
// member then advertises one type, so the prober routes to it
// (PEER_ROUTES_AFTER is 1).
//
// - The member then stops.
// - Idle pool leases expire fast, so every beat makes a fresh dial, which the
//   dropped listener refuses as a dead remote process would.
// - Each later beat fails its reconcile.
// - The failure threshold evicts the entry exactly once (CLUSTER_PEER_EVICTED).
// - The beat stops dialing the dead address.
// - The eviction withdraws the member's routes (PEER_EVICT_ROUTES_WITHDRAWN).
// - A dead peer cannot hold a prefix bucket slot forever.
tb_scenario! {
	name: cluster_beat_evicts_dark_tried_peer,
	spec: ClusterPeerEvictionSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let mut prober_conf = fast_probing_conf(&certs, Arc::clone(&certs.trust));
			// The stopped member's accepted-connection tasks outlive its
			// listener inside this test process, so idle pool leases expire
			// fast.
			prober_conf.pool_config.idle_timeout = Some(Duration::from_millis(50));

			let table = Arc::clone(prober_conf.peer.table());
			let member_addr = dial_admitted_by(&prober_conf, cluster.addr().to_string());
			let prober = start_cluster(&trace, prober_conf).await?;

			// The scenario reads what the probe does with the hint. A hint the
			// table refused shows as the missing outcome below.
			let _ = table.learn(vec![PeerHint { dial: member_addr, peer_id: None }], UnixMillis::now());

			let drained = wait_for_new_candidates_drained(&table, 50, Duration::from_millis(100)).await;
			let targets = table.target_set().unwrap_or_default();
			trace.event_with(PEER_EVICT_MEMBER_PROMOTED, &[], drained && targets.contains(&member_addr))?;

			// The member's slate gives the eviction routes to withdraw.
			advertise_peer(&trace, &certs, &prober, cluster.addr().to_string(), vec![servlet_urn("ping")]).await?;

			cluster.stop();

			let dropped = wait_for_target_dropped(&table, member_addr, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_EVICT_TARGET_DROPPED, &[], dropped)?;

			let withdrawn = wait_for_no_peer_routes(&prober, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_EVICT_ROUTES_WITHDRAWN, &[], withdrawn)?;

			prober.stop();
			Ok(())
		}
	}
}

/// A [`GossipJournal`] that serves normally until the scenario switches it
/// faulty, then fails [`GossipJournal::held_digests`] and
/// [`GossipJournal::fetch`].
///
/// The switch models a storage fault that appears on a live gateway whose
/// peers keep answering.
#[derive(Default)]
struct FaultSwitchJournal {
	inner: MemoryGossipJournal,
	faulty: AtomicBool,
}

impl FaultSwitchJournal {
	fn fail_now(&self) {
		self.faulty.store(true, Ordering::SeqCst);
	}

	fn guard(&self) -> Result<(), ClusterError> {
		if self.faulty.load(Ordering::SeqCst) {
			return Err(ClusterError::GossipJournalUnavailable);
		}

		Ok(())
	}
}

impl GossipJournal for FaultSwitchJournal {
	fn record(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		rumor: &Frame,
		now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		self.inner.record(signer, digest, rumor, now)
	}

	fn witness(&self, signer: &[u8], digest: GossipDigest, now: UnixMillis) -> Result<Admission, ClusterError> {
		self.inner.witness(signer, digest, now)
	}

	fn seen(&self, digest: &GossipDigest, now: UnixMillis) -> Result<bool, ClusterError> {
		self.inner.seen(digest, now)
	}

	fn held_digests(&self, now: UnixMillis) -> Result<Vec<GossipDigest>, ClusterError> {
		self.guard()?;
		self.inner.held_digests(now)
	}

	fn fetch(&self, wanted: &[GossipDigest], now: UnixMillis) -> Result<Vec<(GossipDigest, Frame)>, ClusterError> {
		self.guard()?;
		self.inner.fetch(wanted, now)
	}

	fn pending_local(&self, now: UnixMillis) -> Result<Vec<(GossipDigest, Frame)>, ClusterError> {
		self.inner.pending_local(now)
	}

	fn claim_local(&self, digest: &GossipDigest, now: UnixMillis) -> Result<LocalClaim, ClusterError> {
		self.inner.claim_local(digest, now)
	}

	fn release_local(&self, digest: &GossipDigest) -> Result<(), ClusterError> {
		self.inner.release_local(digest)
	}

	fn ack_local(&self, digest: &GossipDigest) -> Result<(), ClusterError> {
		self.inner.ack_local(digest)
	}

	fn retention(&self) -> Duration {
		self.inner.retention()
	}
}

tb_assert_spec! {
	pub ClusterLocalFaultSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_DISCOVERED, exactly!(1)),
			(PEER_LOCAL_FAULT_MEMBER_PROMOTED, exactly!(1), equals!(true)),
			(PEER_LOCAL_FAULT_MEMBER_RETAINED, exactly!(1), equals!(true)),
			(events::CLUSTER_PEER_EVICTED, exactly!(0))
		]
	}
}

// The beat charges a local journal fault to this gateway, not to an
// answering peer.
//
// The prober promotes the live member into tried, then its own journal
// fails `held_digests` at the start of every reconcile round.
//
// - Each beat skips the round rather than record a dial failure.
// - The failure count never reaches the eviction threshold.
// - The member stays a beat target (no CLUSTER_PEER_EVICTED).
tb_scenario! {
	name: cluster_local_journal_fault_retains_answering_peer,
	spec: ClusterLocalFaultSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let journal = Arc::new(FaultSwitchJournal::default());
			let mut prober_conf = fast_probing_conf(&certs, Arc::clone(&certs.trust));
			prober_conf.gossip.journal = Arc::clone(&journal) as Arc<dyn GossipJournal>;

			let table = Arc::clone(prober_conf.peer.table());
			let member_addr = dial_admitted_by(&prober_conf, cluster.addr().to_string());
			let prober = start_cluster(&trace, prober_conf).await?;

			// The scenario reads what the probe does with the hint. A hint the
			// table refused shows as the missing outcome below.
			let _ = table.learn(vec![PeerHint { dial: member_addr, peer_id: None }], UnixMillis::now());

			let drained = wait_for_new_candidates_drained(&table, 50, Duration::from_millis(100)).await;
			let targets = table.target_set().unwrap_or_default();
			trace.event_with(PEER_LOCAL_FAULT_MEMBER_PROMOTED, &[], drained && targets.contains(&member_addr))?;

			journal.fail_now();

			// The poll window spans about 15 beats at the fast cadence, five
			// times `MAX_PEER_TRIED_FAILURES`, so a scored fault would show.
			let dropped = wait_for_target_dropped(&table, member_addr, 15, Duration::from_millis(100)).await;
			trace.event_with(PEER_LOCAL_FAULT_MEMBER_RETAINED, &[], !dropped)?;

			prober.stop();
			cluster.stop();
			Ok(())
		}
	}
}

/// The one anchor of [`outside_origin_conf`], a dead loopback address that the
/// fan-out counts as unreached.
const DEAD_ANCHOR: &str = "127.0.0.1:9";

/// A colony member whose identity signs under the outside provider of
/// `tests/seams`, anchored to [`DEAD_ANCHOR`] on a fast beat.
fn outside_origin_conf() -> ClusterConfig {
	let (certificate, key) = member_identity("Outside gateway");
	let trust = combined_trust(&[&certificate]);
	let identity = outside_identity_of(certificate, key);
	let tls = ClusterTlsConfig::from_identity(identity, KeyPurposes::HOUSE)
		.expect("the member certificate names no key purpose")
		.with_hive_trust(Arc::clone(&trust))
		.with_peer_trust(trust);

	ClusterConfig::builder(tls)
		.with_peers(vec![DEAD_ANCHOR.to_string()])
		.expect("the anchor names a socket")
		.with_advertise_interval(Duration::from_millis(100))
		.build()
}

tb_assert_spec! {
	pub ClusterOutsideOriginSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(OUTSIDE_RUMOR_FANNED_OUT, exactly!(1), equals!(true)),
			(events::CLUSTER_PEER_AD_PUBLISH_FAILED, exactly!(0))
		]
	}
}

// A gateway whose identity signs under an outside provider originates its
// slate rumor. The gateway verifies its own signature under the identity's
// policy, so the rumor reaches its fan-out.
//
// - The fan-out traces the dead anchor as unreached (OUTSIDE_RUMOR_FANNED_OUT).
// - No publish fails (CLUSTER_PEER_AD_PUBLISH_FAILED).
tb_scenario! {
	name: cluster_outside_identity_originates_its_rumor,
	spec: ClusterOutsideOriginSpec,
	environment Bare {
		exec: |SetupEnv { trace, context: _ }| async move {
			let gateway = start_cluster(&trace, outside_origin_conf()).await?;

			let fanned_out = || trace.recorded(events::CLUSTER_GOSSIP_FANOUT_UNREACHED) >= 1;
			let fanned_out = poll_until(50, Duration::from_millis(100), fanned_out).await;
			trace.event_with(OUTSIDE_RUMOR_FANNED_OUT, &[], fanned_out)?;

			gateway.stop();
			Ok(())
		}
	}
}
