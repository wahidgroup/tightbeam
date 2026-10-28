//! The gossip flood scenarios of the rumor plane.
//!
//! Shared [`cluster_certs`] gateways put the gateway identity in `peer_trust`
//! for relay verification, so hive registration and origin publishes use
//! [`hive_plane_certs`] with [`split_hive_trust`]. The hive-plane signer then
//! stays outside `peer_trust`, and the hive plane admits it.

use std::sync::PoisonError;

use tightbeam::colony::cluster::{PeerRecord, PeerStore};
use tightbeam::colony::protocol::PeerGossip;
use tightbeam::constants::{MAX_PEER_TRIED_FAILURES, MAX_PEX_SAMPLE};
use tightbeam::crypto::key::{KeyBackend, KeyError, SigningKeyProvider};
use tightbeam::crypto::sign::Error as SignatureError;
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::spki::AlgorithmIdentifierOwned;
use tightbeam::testing::TestFrame;
use tightbeam::trace::IntoEventLabel;
use tightbeam::transport::{EncryptedProtocol, TransportEncryptionConfig};
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::utils::time::{Clock, ManualClock};
use tightbeam::{compose, server};

use super::common::*;
use super::federation::{drive_until_advertised, federation_conf, flood_ad_rumor};
use crate::seams::outside_identity_of;

/// A peering configuration that refloods to `peers`, and the journal handle
/// that a scenario reads through the public journal trait.
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
/// The flood scope and each gateway that receives the rumor decide where it
/// goes.
///
/// - The flood scope is the namespace, and the origin certificate's colony URN proves membership.
/// - Local delivery is the ingress policy of the gateway that receives the rumor.
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

/// Signs a [`ClusterRequest::Gossip`] relay frame that carries an unchanged
/// origin rumor.
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

/// Emits one signed gossip frame and returns the status of the gateway's
/// reply.
///
/// The gateway also records its verdict as an event on the scenario trace,
/// so the spec pins the gateway's side.
pub async fn send_gossip_frame(
	connect_certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	frame: Frame,
) -> Result<TransitStatus, TightBeamError> {
	let mut client = connect_cluster(connect_certs, cluster.addr()).await?;
	let response: GossipResponse = decode(&emit_frame(&mut client, frame).await?.message())?;
	Ok(response.status)
}

/// Relays one ping application rumor to `cluster` through [`RumorRelay::send`],
/// with `origin_key` signing the rumor and `relay_key` its envelope.
pub async fn relay_application_rumor(
	connect_certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	origin_key: &Secp256k1SigningKey,
	relay_key: &Secp256k1SigningKey,
	label: impl AsRef<str>,
) -> Result<TransitStatus, TightBeamError> {
	let relay = RumorRelay { origin_key, relay_key };
	relay.send(connect_certs, cluster, label).await
}

/// One relayed ping application rumor: who signed it, and who relays it.
pub struct RumorRelay<'k> {
	/// The key that signs the origin rumor.
	pub origin_key: &'k Secp256k1SigningKey,
	/// The key that signs the relay envelope around the rumor.
	pub relay_key: &'k Secp256k1SigningKey,
}

impl RumorRelay<'_> {
	/// Relays the rumor to `cluster` in a zero-hop envelope, and returns the
	/// status of the gateway's reply. Frame ids derive from `label`, so each
	/// call floods a distinct digest.
	pub async fn send(
		self,
		connect_certs: &ClusterTestCerts,
		cluster: &ClusterGateway,
		label: impl AsRef<str>,
	) -> Result<TransitStatus, TightBeamError> {
		self.status_with_hops(connect_certs, cluster, label, 0).await
	}

	/// Relays the rumor as [`Self::send`] does, in an envelope with
	/// `hop_ttl` hops left, so the gateway that receives the rumor floods it
	/// on.
	async fn status_with_hops(
		self,
		connect_certs: &ClusterTestCerts,
		cluster: &ClusterGateway,
		label: impl AsRef<str>,
		hop_ttl: u64,
	) -> Result<TransitStatus, TightBeamError> {
		let label = label.as_ref();
		let inner_id = format!("{label}-inner");
		let relay_id = format!("{label}-relay");
		let body = rumor_body(encode(&PingRequest { value: 21 })?);
		let rumor = mint_origin_rumor(self.origin_key, inner_id.as_bytes(), body).await?;
		let frame = signed_relay_gossip(self.relay_key, relay_id.as_bytes(), rumor, hop_ttl).await?;
		send_gossip_frame(connect_certs, cluster, frame).await
	}
}

/// Signs a [`ClusterRequest::ReconcileGossip`] control frame that lists the
/// sender's held digests.
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

/// Polls until the journal holds exactly `count` rumors that await local
/// delivery, or the attempts run out.
///
/// A rumor that the gateway accepts before the ingress servlet registers
/// stays pending for the beat to retry.
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

/// Polls until `trace` holds at least `count` records of `event`, or
/// `attempts` polls 100 ms apart run out.
///
/// The event marks a decision that a reflood, a beat, or a probe makes on
/// another task. The spec judges the count, so the wait leaves the verdict to
/// the spec.
async fn wait_for_recorded(trace: &TraceCollector, event: impl IntoEventLabel + Clone, count: usize, attempts: u32) {
	let recorded = || trace.recorded(event.clone()) >= count;
	poll_until(attempts, Duration::from_millis(100), recorded).await;
}

tb_assert_spec! {
	pub ClusterGossipFloodSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(3), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(3)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(3)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// A rumor floods a fan-out: A refloods to B and C, and each cluster admits
// the rumor and delivers it to its local ingress servlet once. The DUPLICATE
// of the second publish fires before its Ok reply, so the count needs no poll.
tb_scenario! {
	name: cluster_gossip_floods_every_cluster_once,
	spec: ClusterGossipFloodSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_c, _journal_c) = gossip_cluster_conf(&certs, vec![]);
			let gateway_c = start_cluster(&trace, conf_c).await?;

			let (conf_b, _journal_b) = gossip_cluster_conf(&certs, vec![]);
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let peers_a = vec![gateway_b.addr().to_string(), gateway_c.addr().to_string()];
			let (conf_a, _journal_a) = gossip_cluster_conf(&certs, peers_a);
			let gateway_a = start_cluster(&trace, conf_a).await?;

			let hive_b = start_scenario_rumor_hive(trace.share(), &certs).await?;
			let hive_c = start_scenario_rumor_hive(trace.share(), &certs).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;
			hive_b.register_with_cluster(gateway_b.addr()).await?;
			hive_c.register_with_cluster(gateway_c.addr()).await?;

			// The test sends this signed publish frame twice, byte for byte, so
			// the origin gateway re-creates one rumor with the same id, order,
			// and body, and the journal absorbs the second as a Duplicate.
			let frame = hive_publish_gossip(
				&certs,
				b"flood-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				4,
			)
			.await?;
			let replied = send_gossip_frame(&certs, &gateway_a, frame.clone()).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			// Each cluster tries its local delivery ahead of the admission, so
			// the wait for the third admission also waits out each delivery.
			wait_for_recorded(&trace, events::CLUSTER_GOSSIP_ADMITTED, 3, 50).await;

			let replied = send_gossip_frame(&certs, &gateway_a, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

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
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(3)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(3)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// A rumor crosses a partial topology: A peers to B alone, and B peers to C,
// so the rumor reaches C only through the reflood at B. The publish leaves
// at ttl 2 and reaches C at ttl 0, its whole hop budget spent.
tb_scenario! {
	name: cluster_gossip_relays_across_partial_topology,
	spec: ClusterGossipChainSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_c, _journal_c) = gossip_cluster_conf(&certs, vec![]);
			let gateway_c = start_cluster(&trace, conf_c).await?;

			let (conf_b, _journal_b) = gossip_cluster_conf(&certs, vec![gateway_c.addr().to_string()]);
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let (conf_a, _journal_a) = gossip_cluster_conf(&certs, vec![gateway_b.addr().to_string()]);
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
			let replied = send_gossip_frame(&certs, &gateway_a, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");
			wait_for_recorded(&trace, events::CLUSTER_GOSSIP_ADMITTED, 3, 50).await;

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
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(2)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// A rumor propagates on hive trust alone: A has no `peer_trust`, so it builds
// no peer pool and refloods over the hive pool, as the advertise beat does. B
// verifies the relay on its peer plane, where the ttl-1 publish's hops end.
tb_scenario! {
	name: cluster_gossip_refloods_under_hive_trust_only,
	spec: ClusterGossipHiveTrustOnlySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_b, _journal_b) = gossip_cluster_conf(&certs, vec![]);
			let gateway_b = start_cluster(&trace, conf_b).await?;
			let (mut conf_a, _journal_a) = gossip_cluster_conf(&certs, vec![gateway_b.addr().to_string()]);

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
			let replied = send_gossip_frame(&certs, &gateway_a, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");
			wait_for_recorded(&trace, events::CLUSTER_GOSSIP_ADMITTED, 2, 50).await;

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
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(1), equals!(0u64)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(1)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// The configured gossip ttl caps the hops of an origin publish: at 0, the
// gateway admits a publish that asks for the maximum with 0 hops left, starts
// no reflood to B, and delivers before it answers, so no count needs a poll.
tb_scenario! {
	name: cluster_gossip_origin_clamps_configured_ttl,
	spec: ClusterGossipTtlClampSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_b, _journal_b) = gossip_cluster_conf(&certs, vec![]);
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let (mut conf_a, _journal_a) = gossip_cluster_conf(&certs, vec![gateway_b.addr().to_string()]);
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
			let replied = send_gossip_frame(&certs, &gateway_a, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

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
/// The gateway's own certificates anchor the hive plane, and a distinct
/// random identity anchors the peer plane, so each plane's signer verifies
/// only under its own anchor.
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
		CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation)
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
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(3), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(0))
		]
	}
}

// The trust planes stay apart, and admission bounds the rumor size: the
// gateway refuses a hive-plane relay, a peer-plane publish, and an oversized
// rumor on the correct plane, so none of them reaches delivery or the journal.
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
			let replied = send_gossip_frame(&ctx.gateway, &cluster, frame).await?;
			assert_eq!(replied, TransitStatus::PermissionDenied, "peer trust refuses a relay that a hive-plane signer signs");

			let frame = signed_publish_gossip(
				&ctx.peer_key,
				b"cross-plane-publish",
				rumor_body(encode(&PingRequest { value: 21 })?),
				2,
			)
			.await?;
			let replied = send_gossip_frame(&ctx.gateway, &cluster, frame).await?;
			assert_eq!(replied, TransitStatus::PermissionDenied, "hive trust refuses a publish that a peer-plane signer signs");

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
			assert_eq!(response.status, TransitStatus::PermissionDenied, "admission refuses an oversized rumor");

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
			(events::CLUSTER_GOSSIP_ADMITTED, at_least!(2)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(2)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Anti-entropy repairs a rumor over the beat. Publisher F starts the rumor at
// ttl 0, so R learns it only when F's beat reconciles digests and pushes it.
// R also admits the slate rumors of F's beat, so ADMITTED is a lower bound.
tb_scenario! {
	name: cluster_gossip_repairs_missing_peer_over_beat,
	spec: ClusterGossipReconcileRepairSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_r, _journal_r) = gossip_cluster_conf(&certs, vec![]);
			let gateway_r = start_cluster(&trace, conf_r).await?;
			let hive_r = start_scenario_rumor_hive(trace.share(), &certs).await?;

			let (mut conf_f, _journal_f) = gossip_cluster_conf(&certs, vec![gateway_r.addr().to_string()]);
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
			let replied = send_gossip_frame(&certs, &gateway_f, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			// The repair reaches R on a beat. R also admits the slate rumors of
			// the beat, so the second delivery marks the repair, and the
			// admission count has its own wait.
			wait_for_recorded(&trace, events::CLUSTER_GOSSIP_DELIVERED, 2, 50).await;
			wait_for_recorded(&trace, events::CLUSTER_GOSSIP_ADMITTED, 2, 50).await;

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
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(2)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// The beat retries a local delivery. The rumor reaches R before R's ingress
// servlet registers, so R admits it and holds it pending. R has no peers, so
// its beat runs for the `pending_local` retry alone, which delivers and acks.
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

			let (conf_f, _journal_f) = gossip_cluster_conf(&certs, vec![gateway_r.addr().to_string()]);
			let gateway_f = start_cluster(&trace, conf_f).await?;

			hive.register_with_cluster(gateway_f.addr()).await?;

			let frame = hive_publish_gossip(
				&certs,
				b"retry-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				1,
			)
			.await?;
			let replied = send_gossip_frame(&certs, &gateway_f, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");
			wait_for_recorded(&trace, events::CLUSTER_GOSSIP_ADMITTED, 2, 50).await;

			let pending = wait_for_pending_local(&journal_r, 1, 50, Duration::from_millis(100)).await;
			assert!(pending, "the rumor waits in R's journal for its ingress");

			let hive_r = start_scenario_rumor_hive(trace.share(), &certs).await?;
			hive_r.register_with_cluster(gateway_r.addr()).await?;

			wait_for_recorded(&trace, events::CLUSTER_GOSSIP_DELIVERED, 2, 50).await;

			gateway_f.stop();
			gateway_r.stop();
			hive_r.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// A [`GossipJournal`] that wraps the in-memory default and counts records
/// and acks.
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
		issued_at: UnixMillis,
		now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		self.records.fetch_add(1, Ordering::SeqCst);
		self.inner.record(signer, digest, rumor, issued_at, now)
	}

	fn witness(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		issued_at: UnixMillis,
		now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		self.inner.witness(signer, digest, issued_at, now)
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
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(1))
		]
	}
}

tb_assert_spec! {
	pub ClusterGossipRateLimitSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1), equals!(TransitStatus::ResourceExhausted)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(1)),
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
			let replied = send_gossip_frame(&certs, &gateway, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			let frame = hive_publish_gossip(
				&certs,
				b"rate-rumor-2",
				rumor_body(encode(&PingRequest { value: 22 })?),
				0,
			)
			.await?;
			let replied = send_gossip_frame(&certs, &gateway, frame).await?;
			assert_eq!(replied, TransitStatus::ResourceExhausted, "the second rumor passes the signer's rate");

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
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(1)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0))
		]
	}
}

// The gateway clamps the freshness window (seen_ttl) to the journal's
// retention at start, so it refuses a replay after the prune as stale. Without
// the clamp it records the replay as New and delivers it twice.
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
			let replied = send_gossip_frame(&certs, &gateway, frame.clone()).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			// The clock moves past the one-second retention, so the journal
			// has pruned the entry and only the clamped freshness window can
			// refuse it.
			clock.advance(Duration::from_secs(2));
			let replied = send_gossip_frame(&certs, &gateway, frame).await?;
			assert_eq!(replied, TransitStatus::PermissionDenied, "the gateway refuses the replay as stale");

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
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(2)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(2)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Duplicates leave rate tokens unspent. A two-token bucket with a slow refill
// admits rumor A, keeps its second token through two byte-identical echoes of
// A, and admits B, which would draw ResourceExhausted if echoes spent tokens.
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

			let replied = send_gossip_frame(&certs, &gateway, first.clone()).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");
			let replied = send_gossip_frame(&certs, &gateway, first.clone()).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");
			let replied = send_gossip_frame(&certs, &gateway, first).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			let second = hive_publish_gossip(
				&certs,
				b"dup-rumor-2",
				rumor_body(encode(&PingRequest { value: 22 })?),
				0,
			)
			.await?;
			let replied = send_gossip_frame(&certs, &gateway, second).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

// The gateway drives an injected journal through the trait alone. It records
// the origin publish and acks its local delivery before the reply, so the
// counts are final when the publish returns.
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
			let replied = send_gossip_frame(&certs, &gateway, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			let records = journal.records.load(Ordering::SeqCst);
			assert_eq!(records, 1, "the gateway records the publish through the injected journal");
			let acks = journal.acks.load(Ordering::SeqCst);
			assert_eq!(acks, 1, "the gateway acks the delivered rumor through the injected journal");

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// A journal that reports every rumor as claimed by another task.
///
/// The reconcile beat sees this while an admission is mid-delivery, and the
/// admission sees it while the beat is mid-delivery. Either way the second
/// caller skips the delivery.
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
		issued_at: UnixMillis,
		now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		self.inner.record(signer, digest, rumor, issued_at, now)
	}

	fn witness(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		issued_at: UnixMillis,
		now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		self.inner.witness(signer, digest, issued_at, now)
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
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(0))
		]
	}
}

// A rumor that another task claimed gets no second delivery. The delivery path
// must take the claim before the ingress round trip, or it would deliver, ack,
// and trace DELIVERED, the at-least-once behavior the claim removes (CWE-362).
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
			let replied = send_gossip_frame(&certs, &gateway, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			let acks = journal.acks.load(Ordering::SeqCst);
			assert_eq!(acks, 0, "a rumor that another task claimed gets no ack");

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
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(4), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(3)),
			(events::CLUSTER_PEER_ROUTE_ABANDONED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(1))
		]
	}
}

// Each over-TTL relay that admission refuses weakens the relay's work route by
// one trial until the gateway abandons it, so the fourth finds it gone. The
// abandonment spares the flood, and the signer's honest relay delivers.
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

			let ad_reply = install_ping_peer(&certs, &gateway).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(gateway.peer_servlets()?.len(), 1, "the advertisement installs the relay's ping route");

			// The scenario sends one more relay than the abandonment budget.
			// Each relay carries a valid origin-signed rumor, so the
			// over-radius hop lifetime alone draws the refusal.
			let refused = over_radius_relays(&certs, &gateway, CONTAINMENT_ABANDON_LIMIT.get() + 1).await?;
			let expected = [TransitStatus::PermissionDenied; CONTAINMENT_ABANDON_LIMIT.get() as usize + 1];
			assert_eq!(refused, expected, "the gateway refuses each over-radius relay");

			let honest = mint_origin_rumor(
				&certs.key,
				b"honest-inner",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&certs.key, b"honest-relay", honest, 0).await?;
			let replied = send_gossip_frame(&certs, &gateway, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// Relays `count` valid origin-signed rumors to `gateway`, each in an envelope
/// one hop past the radius cap, and returns the status of each reply.
async fn over_radius_relays(
	certs: &ClusterTestCerts,
	gateway: &ClusterGateway,
	count: u32,
) -> Result<Vec<TransitStatus>, TightBeamError> {
	let mut statuses = Vec::new();
	for index in 0..count {
		let index_octet = u8::try_from(index).expect("a fixture count fits a u8");
		let rumor_id = [b'r', index_octet];
		let rumor =
			mint_origin_rumor(&certs.key, &rumor_id, rumor_body(encode(&PingRequest { value: index })?)).await?;
		let id = [b'b', b'a', b'd', index_octet];
		let frame = signed_relay_gossip(&certs.key, &id, rumor, u64::from(MAX_GOSSIP_TTL) + 1).await?;
		statuses.push(send_gossip_frame(certs, gateway, frame).await?);
	}

	Ok(statuses)
}

/// A grey-hole [`GossipJournal`] that records every rumor as new and retains
/// none. Its gateway acknowledges each push with `Ok`, then re-wants the same
/// digest on every reconciliation round.
#[derive(Default)]
struct AmnesiacJournal;

impl GossipJournal for AmnesiacJournal {
	fn record(
		&self,
		_signer: &[u8],
		_digest: GossipDigest,
		_rumor: &Frame,
		_issued_at: UnixMillis,
		_now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		Ok(Admission::New)
	}

	fn witness(
		&self,
		_signer: &[u8],
		_digest: GossipDigest,
		_issued_at: UnixMillis,
		_now: UnixMillis,
	) -> Result<Admission, ClusterError> {
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
	// faulty journal can lie, so the start-time seen-ttl clamp defends against
	// honest misconfiguration alone.
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
			(events::CLUSTER_GOSSIP_ADMITTED, at_least!(2)),
			(events::CLUSTER_GOSSIP_DROP_SIGNAL, at_least!(3)),
			(events::CLUSTER_PEER_ROUTE_ABANDONED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(2))
		]
	}
}

// The beat contains a grey hole. B acknowledges every repair push with `Ok`
// and retains nothing, so each round re-wants a digest A saw acknowledged.
//
// - A's beat reads each reappearance as a drop signal and weakens B's work route until it abandons it.
// - The same beat carries the rumor to honest C (DELIVERED at A and C).
// - B and C admit the slate rumors of A's beat, and B admits each repair again, so ADMITTED is a lower bound.
// - The flood to B runs off the static peer list, so only work routing drops the grey hole.
tb_scenario! {
	name: cluster_gossip_abandons_grey_hole_peer,
	spec: ClusterGossipGreyHoleSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_c, _journal_c) = gossip_cluster_conf(&certs, vec![]);
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
			let (mut conf_a, _journal_a) = gossip_cluster_conf(&certs, peers_a);
			conf_a.peer.advertise_interval = Some(Duration::from_millis(100));
			conf_a.pheromone.abandonment_limit = CONTAINMENT_ABANDON_LIMIT;

			let gateway_a = start_cluster(&trace, conf_a).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;

			// B advertises a ping route dialed at the same address A
			// reconciles with, so the drop signals have a trail to weaken.
			let dial = gateway_b.addr().to_string();
			let ad_reply = advertise_peer(&certs, &gateway_a, dial.as_bytes(), vec![servlet_urn("ping")]).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(gateway_a.peer_servlets()?.len(), 1, "B's advertisement installs its ping route at A");

			let frame = hive_publish_gossip(
				&certs,
				b"grey-hole-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			let replied = send_gossip_frame(&certs, &gateway_a, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			// Honest delivery comes first: A delivers its own publish, and the
			// beat repairs C. B delivers nothing by design.
			wait_for_recorded(&trace, events::CLUSTER_GOSSIP_DELIVERED, 2, 50).await;
			wait_for_recorded(&trace, events::CLUSTER_PEER_ROUTE_ABANDONED, 1, 100).await;

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
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(1)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(0))
		]
	}
}

// A trusted peer that alters an origin-signed rumor breaks its signature, so
// the gateway refuses it with PermissionDenied and weakens the relay's
// advertised routes. An honest relay verifies a rumor before it forwards it.
tb_scenario! {
	name: cluster_gossip_weakens_tampered_relay,
	spec: ClusterGossipTamperedRelaySpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, containment_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let ad_reply = install_ping_peer(&certs, &cluster).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(cluster.peer_servlets()?.len(), 1, "the advertisement installs the relay's ping route");

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
			let replied = send_gossip_frame(&certs, &cluster, frame).await?;
			assert_eq!(replied, TransitStatus::PermissionDenied, "the gateway refuses the tampered rumor");

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
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_GOSSIP_ORIGIN_UNKNOWN, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(3)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(0))
		]
	}
}

// An origin outside this gateway's trust is the edge of a subnet. A trusted
// relay with a one-token bucket offers two rumors of such an origin.
//
// - The first draws Unauthenticated, which tells the relay to stop its offers of that origin.
// - The drop spends the relay's token, so the second and the relay's own rumor draw ResourceExhausted.
// - The gateway leaves the relay unscored (RELAY_WEAKENED exactly 0), so its routes stay.
// - The three refusals carry two statuses, so the spec counts them and the body asserts each status.
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
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let ad_reply = install_ping_peer(&certs, &cluster).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(cluster.peer_servlets()?.len(), 1, "the advertisement installs the relay's ping route");

			let (_unenrolled, outsider_key) = member_identity("Origin Outside Trust");

			let relay = &certs.key;
			let outsider = RumorRelay { origin_key: &outsider_key, relay_key: relay };
			let status = outsider.send(&certs, &cluster, "outsider-1").await?;
			assert_eq!(status, TransitStatus::Unauthenticated, "the gateway answers an origin outside its trust");

			let limited = RumorRelay { origin_key: &outsider_key, relay_key: relay };
			let status = limited.send(&certs, &cluster, "outsider-2").await?;
			assert_eq!(status, TransitStatus::ResourceExhausted, "the drop spent the relay's one token");

			let own = RumorRelay { origin_key: relay, relay_key: relay };
			let status = own.send(&certs, &cluster, "relay-own").await?;
			assert_eq!(status, TransitStatus::ResourceExhausted, "the relay's own rumor draws on the same bucket");
			assert_eq!(cluster.peer_routes()?.len(), 1, "the relay's route survives the refusals");

			cluster.stop();
			Ok(())
		}
	}
}

/// A [`GossipAdmission`] whose backend faults on every rumor.
///
/// The house admission faults only behind a poisoned lock of its own, which
/// no caller outside the gateway can poison, so this admission stands in for
/// the backend fault.
struct FaultedAdmission;

impl GossipAdmission for FaultedAdmission {
	fn allow(&self, _signer: &[u8], _now: UnixMillis) -> Result<bool, ClusterError> {
		Err(ClusterError::LockPoisoned)
	}
}

/// The labels of the [`events::CLUSTER_GOSSIP_REFUSED`] records that `trace`
/// holds.
#[cfg(feature = "instrument")]
fn gossip_refusal_labels(trace: &TraceCollector) -> Vec<Option<String>> {
	let recorded = trace.drain_events().into_iter();
	let refused = recorded.filter(|event| event.urn == events::CLUSTER_GOSSIP_REFUSED);
	refused.map(|event| event.label.as_deref().map(String::from)).collect()
}

/// The status of the reply and the labels of the
/// [`events::CLUSTER_GOSSIP_REFUSED`] records that a gateway leaves, under the
/// configuration that `fault` edits, as its trusted relay offers one rumor
/// signed with the key that `origin` picks.
#[cfg(feature = "instrument")]
async fn faulted_relay_refusals(
	origin: impl FnOnce(&ClusterTestCerts) -> Secp256k1SigningKey,
	fault: impl FnOnce(&mut ClusterConfig),
) -> Result<(TransitStatus, Vec<Option<String>>), TightBeamError> {
	let certs = cluster_certs();
	let trace = TraceCollector::default();
	let mut conf = containment_cluster_conf(&certs);
	fault(&mut conf);

	let cluster = start_cluster(&trace, conf).await?;
	install_ping_peer(&certs, &cluster).await?;

	let origin_key = origin(&certs);
	let relay = RumorRelay { origin_key: &origin_key, relay_key: &certs.key };
	let status = relay.send(&certs, &cluster, "faulted").await?;
	cluster.stop();

	Ok((status, gossip_refusal_labels(&trace)))
}

/// Gives `conf` a [`FaultedAdmission`].
#[cfg(feature = "instrument")]
fn with_faulted_admission(conf: &mut ClusterConfig) {
	conf.gossip.admission = Arc::new(FaultedAdmission) as Arc<dyn GossipAdmission>;
}

/// The refusal that names the fault of a poisoned lock, as a relay reads it
/// and as the gateway records it.
#[cfg(feature = "instrument")]
fn lock_poisoned_refusal() -> (TransitStatus, Vec<Option<String>>) {
	let label = Some(String::from("Unavailable/lock-poisoned"));
	(TransitStatus::Unavailable, vec![label])
}

/// The refusal that names the fault of a journal that cannot serve, as a
/// relay reads it and as the gateway records it.
#[cfg(feature = "instrument")]
fn journal_unavailable_refusal() -> (TransitStatus, Vec<Option<String>>) {
	let label = Some(String::from("Unavailable/gossip-journal-unavailable"));
	(TransitStatus::Unavailable, vec![label])
}

/// A rumor of an origin outside the gateway's trust spends a token of its
/// relay, and a fault of the admission refuses it as unavailable with the
/// fault named in the refusal record (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_faulted_admission_names_its_fault_for_an_origin_outside_trust() -> Result<(), TightBeamError> {
	let outside = |_: &ClusterTestCerts| member_identity("Origin Outside Faulted Trust").1;
	let refusals = faulted_relay_refusals(outside, with_faulted_admission).await?;
	assert_eq!(refusals, lock_poisoned_refusal());
	Ok(())
}

/// A rumor of a trusted origin spends a token of that origin, and a fault of
/// the admission refuses it as unavailable with the fault named in the
/// refusal record.
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_faulted_admission_names_its_fault_for_a_trusted_origin() -> Result<(), TightBeamError> {
	let refusals = faulted_relay_refusals(|certs| certs.key.clone(), with_faulted_admission).await?;
	assert_eq!(refusals, lock_poisoned_refusal());
	Ok(())
}

/// How a [`FaultSwitchKeyProvider`] signs once it is faulty.
#[derive(Clone, Copy, Debug)]
enum KeyFault {
	/// The backend refuses each signature, as a key store that went offline
	/// does.
	Refuses,
	/// The backend signs with a key that the identity does not certify.
	SignsWithAnotherKey,
}

/// A signing backend that signs with its own key until the scenario switches
/// it faulty, then faults as its [`KeyFault`] names.
///
/// The house providers sign with the key they hold on every call, so this
/// backend stands in for a key store that fails while the gateway serves.
#[derive(Debug)]
struct FaultSwitchKeyProvider {
	own: Secp256k1KeyProvider,
	other: Secp256k1KeyProvider,
	fault: KeyFault,
	faulty: AtomicBool,
}

impl FaultSwitchKeyProvider {
	/// A backend of `key` that faults as `fault` names once it is switched.
	fn of(key: &Secp256k1SigningKey, fault: KeyFault) -> Self {
		let other_key = Secp256k1SigningKey::from_bytes(&[0x5a; 32].into()).expect("a small nonzero scalar is a key");
		let own = Secp256k1KeyProvider::from(key.to_owned());
		let other = Secp256k1KeyProvider::from(other_key);
		Self { own, other, fault, faulty: AtomicBool::new(false) }
	}

	fn fail_now(&self) {
		self.faulty.store(true, Ordering::SeqCst);
	}
}

impl KeyBackend for FaultSwitchKeyProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.own.algorithm()
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		self.own.to_public_key_bytes()
	}
}

impl SigningKeyProvider for FaultSwitchKeyProvider {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		if !self.faulty.load(Ordering::SeqCst) {
			return self.own.sign_prehash(prehash);
		}

		match self.fault {
			KeyFault::Refuses => Box::pin(async { Err(KeyError::SignatureError(SignatureError::new())) }),
			KeyFault::SignsWithAnotherKey => self.other.sign_prehash(prehash),
		}
	}
}

/// The status of the reply and the labels of the
/// [`events::CLUSTER_GOSSIP_REFUSED`] records that a gateway leaves as it
/// answers one publish from its hive plane, once the backend of its own key
/// faults as `fault` names.
///
/// The publisher runs one publish before the backend faults, which the
/// gateway admits, so the handshake of the gateway signs under its own key.
#[cfg(feature = "instrument")]
async fn faulted_publish_refusals(fault: KeyFault) -> Result<(TransitStatus, Vec<Option<String>>), TightBeamError> {
	let certs = cluster_certs();
	let trace = TraceCollector::default();
	let backend = Arc::new(FaultSwitchKeyProvider::of(&certs.key, fault));
	let spec = CertificateSpec::Built(Box::new(certs.cert.to_owned()));
	let tls = ClusterTlsConfig::new(spec, Arc::clone(&backend) as Arc<dyn SigningKeyProvider>)?
		.with_hive_trust(Some(split_hive_trust(&certs)))
		.with_peer_trust(Arc::clone(&certs.trust));
	let gateway = start_cluster(&trace, ClusterConfig::builder(tls).build()).await?;
	let mut client = connect_cluster(&certs, gateway.addr()).await?;
	let first = hive_publish_gossip(&certs, b"publish-before-fault", rumor_body(vec![1]), 1).await?;
	let opened: GossipResponse = decode(&emit_frame(&mut client, first).await?.message())?;
	assert_eq!(opened.status, TransitStatus::Ok, "the gateway admits the first publish");

	backend.fail_now();
	let frame = hive_publish_gossip(&certs, b"faulted-publish", rumor_body(vec![1, 2, 3]), 1).await?;
	let reply: GossipResponse = decode(&emit_frame(&mut client, frame).await?.message())?;
	gateway.stop();

	Ok((reply.status, gossip_refusal_labels(&trace)))
}

/// A key backend that refuses to sign the rumor of a publish refuses the
/// publish as unavailable, with the fault named in the refusal record
/// (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_publish_whose_signature_faults_names_the_fault() -> Result<(), TightBeamError> {
	let refusals = faulted_publish_refusals(KeyFault::Refuses).await?;
	let expected = (TransitStatus::Unavailable, vec![Some(String::from("Unavailable/frame"))]);
	assert_eq!(refusals, expected);
	Ok(())
}

/// A key backend that signs with a key the gateway's identity does not certify
/// makes a signature that the gateway's own check refuses, and the refusal
/// record names that check apart from a frame fault (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_publish_that_its_own_certificate_refuses_names_the_fault() -> Result<(), TightBeamError> {
	let refusals = faulted_publish_refusals(KeyFault::SignsWithAnotherKey).await?;
	let refused = Some(String::from("Unavailable/own-signature-refused"));
	assert_eq!(refusals, (TransitStatus::Unavailable, vec![refused]));
	Ok(())
}

/// Gives `conf` a journal that fails `step` from its first call.
#[cfg(feature = "instrument")]
fn with_faulty_journal(conf: &mut ClusterConfig, step: JournalStep) {
	conf.gossip.journal = Arc::new(FaultSwitchJournal::failing(step)) as Arc<dyn GossipJournal>;
}

/// A journal that cannot check whether it holds an inbound rumor refuses the
/// rumor as unavailable, with the fault named in the refusal record
/// (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_faulted_duplicate_check_names_its_fault() -> Result<(), TightBeamError> {
	let seen = |conf: &mut ClusterConfig| with_faulty_journal(conf, JournalStep::Seen);
	let refusals = faulted_relay_refusals(|certs| certs.key.clone(), seen).await?;
	assert_eq!(refusals, journal_unavailable_refusal());
	Ok(())
}

/// A journal that cannot record an admitted rumor refuses the rumor as
/// unavailable, with the fault named in the refusal record.
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_faulted_journal_write_names_its_fault() -> Result<(), TightBeamError> {
	let writes = |conf: &mut ClusterConfig| with_faulty_journal(conf, JournalStep::Writes);
	let refusals = faulted_relay_refusals(|certs| certs.key.clone(), writes).await?;
	assert_eq!(refusals, journal_unavailable_refusal());
	Ok(())
}

/// A journal that cannot list the digests it holds refuses a reconcile
/// round, with the fault named in the refusal record (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_faulted_reconcile_read_names_its_fault() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let trace = TraceCollector::default();
	let mut conf = peering_cluster_conf(&certs);
	with_faulty_journal(&mut conf, JournalStep::Reads);
	let gateway = start_cluster(&trace, conf).await?;
	let frame = signed_reconcile_gossip(&certs.key, b"faulted-reconcile", vec![]).await?;
	// A reconcile reply carries no status, so the record alone names the
	// cause of the refusal.
	reconcile_reply(&certs, &gateway, frame).await?;
	gateway.stop();

	let expected = [Some(String::from("Unavailable/gossip-journal-unavailable"))];
	assert_eq!(gossip_refusal_labels(&trace), expected);
	Ok(())
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

/// Places one rumor of `origin` at `cluster`, which the origin itself relays
/// with `hop_ttl` hops left, and returns the status of the reply.
async fn place_origin_rumor(
	connect_certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	origin: &Secp256k1SigningKey,
	label: impl AsRef<str>,
	hop_ttl: u64,
) -> Result<TransitStatus, TightBeamError> {
	let relay = RumorRelay { origin_key: origin, relay_key: origin };
	relay.status_with_hops(connect_certs, cluster, label, hop_ttl).await
}

/// Polls until a peer has refused `count` origins, or five seconds pass.
pub async fn wait_for_refused_origins(trace: &TraceCollector, count: usize) {
	wait_for_recorded(trace, events::CLUSTER_GOSSIP_ORIGIN_REFUSED_BY_PEER, count, 50).await;
}

tb_assert_spec! {
	pub ClusterGossipRefusedOriginSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_GOSSIP_ADMITTED, at_least!(3)),
			(events::CLUSTER_GOSSIP_ORIGIN_UNKNOWN, exactly!(2)),
			(events::CLUSTER_GOSSIP_ORIGIN_REFUSED_BY_PEER, exactly!(2)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(events::CLUSTER_GOSSIP_DROP_SIGNAL, exactly!(0))
		]
	}
}

// A target that refuses an origin gets that origin once. The bridge holds
// rumors of two origins outside the edge's trust, and only this test moves
// the clock of its beat.
//
// - The first beat's repair pushes the first origin's rumor from the journal, and the edge refuses it.
// - The bridge withholds a second rumor of that origin from the edge, because the refusal stands.
// - The second origin's rumor refloods at once, and the edge refuses it.
// - Three more beats push neither origin again, although the edge lacks all three rumors.
// - The edge also admits the slate rumors of the bridge's beat, so ADMITTED is a lower bound.
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
			let held = place_origin_rumor(&ctx.bridge, &bridge, &ctx.first_origin, "first-origin-held", 0).await?;
			assert_eq!(held, TransitStatus::Ok, "the bridge admits the first origin's rumor");
			drive_until_advertised(&clock, &trace, 1).await;
			wait_for_refused_origins(&trace, 1).await;

			let again = place_origin_rumor(&ctx.bridge, &bridge, &ctx.first_origin, "first-origin-again", 1).await?;
			assert_eq!(again, TransitStatus::Ok, "the bridge admits a second rumor of the first origin");

			let second = place_origin_rumor(&ctx.bridge, &bridge, &ctx.second_origin, "second-origin", 1).await?;
			assert_eq!(second, TransitStatus::Ok, "the bridge admits the second origin's rumor");
			wait_for_refused_origins(&trace, 2).await;

			let beats_so_far = trace.recorded(events::CLUSTER_PEER_ADVERTISED);
			drive_until_advertised(&clock, &trace, beats_so_far + 3).await;

			bridge.stop();
			cluster.stop();
			Ok(())
		}
	}
}

/// The fixture for flood membership, on a gateway of colony "main":
///
/// - One trusted peer identity carries the colony URN of "other", so it is inside the flood.
/// - Another carries no SAN, so it is outside every flood.
/// - Both use random keys, so the three identities have distinct subject key ids (see [`gossip_plane_ctx`]).
struct NeighborColonyCtx {
	gateway: ClusterTestCerts,
	neighbor_key: Secp256k1SigningKey,
	stranger_key: Secp256k1SigningKey,
	peer_trust: Arc<dyn CertificateTrust>,
}

/// A fresh gateway identity in colony "other".
///
/// A random key keeps its subject key id distinct from every "main"-colony
/// identity. Its own `CN` keeps trust-store issuer resolution unambiguous, so
/// one trust store can anchor both identities.
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
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(3), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(events::CLUSTER_PEER_ROUTE_ABANDONED, exactly!(0))
		]
	}
}

// A neighbor colony is inside the flood, and a trusted stranger with no colony
// URN is outside it. The neighbor of colony "other" gossips and federates its
// advertised work routes, and the stranger draws PermissionDenied.
//
// - Admitted: a rumor of colony "main" that the neighbor relays, and a rumor the neighbor signed itself.
// - Refused: a rumor that the stranger signs, relays, or both.
// - Each refusal is policy and weakens no route, so the route survives an abandonment limit of 1.
tb_scenario! {
	name: cluster_gossip_admits_neighbor_colony_and_refuses_stranger,
	spec: ClusterGossipNeighborColonySpec,
	environment Cluster {
		context: neighbor_colony_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let mut conf = peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust));
			conf.pheromone.abandonment_limit = NonZeroU32::MIN;
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { context: ctx, cluster, .. }| async move {
			let ad_reply = advertise_peer_signed(
				&ctx.gateway,
				&ctx.neighbor_key,
				&cluster,
				PEER_GATEWAY_ADDR,
				vec![servlet_urn("ping")],
			)
			.await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(cluster.peer_servlets()?.len(), 1, "the neighbor's advertisement installs its ping route");

			let own_origin = &ctx.gateway.key;
			let neighbor = &ctx.neighbor_key;
			let replied = relay_application_rumor(&ctx.gateway, &cluster, own_origin, neighbor, "main-origin").await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			let replied = relay_application_rumor(&ctx.gateway, &cluster, neighbor, neighbor, "other-origin").await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			let stranger = &ctx.stranger_key;
			let all_stranger = RumorRelay { origin_key: stranger, relay_key: stranger };
			let replied = all_stranger.send(&ctx.gateway, &cluster, "stranger").await?;
			assert_eq!(replied, TransitStatus::PermissionDenied, "the gateway refuses a stranger's own rumor");

			let stranger_relays = RumorRelay { origin_key: own_origin, relay_key: stranger };
			let replied = stranger_relays.send(&ctx.gateway, &cluster, "stranger-relays").await?;
			assert_eq!(replied, TransitStatus::PermissionDenied, "the gateway refuses a stranger's relay");

			let stranger_signed = RumorRelay { origin_key: stranger, relay_key: neighbor };
			let replied = stranger_signed.send(&ctx.gateway, &cluster, "stranger-signed").await?;
			assert_eq!(replied, TransitStatus::PermissionDenied, "the gateway refuses a stranger's origin");
			assert_eq!(cluster.peer_routes()?.len(), 1, "the advertised route survives the refusals");

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
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// A trusted identity with no colony URN federates nothing. Peer trust admits
// the stranger, so its advertisement verifies, and admission refuses it
// because the stranger is outside the flood.
tb_scenario! {
	name: cluster_refuses_an_advertisement_from_a_stranger,
	spec: ClusterStrangerAdvertisementSpec,
	environment Cluster {
		context: neighbor_colony_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let conf = peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust));
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { context: ctx, cluster, .. }| async move {
			let stranger = &ctx.stranger_key;
			let types = vec![servlet_urn("ping")];
			let ad_reply = advertise_peer_signed(&ctx.gateway, stranger, &cluster, PEER_GATEWAY_ADDR, types).await?;
			assert_eq!(ad_reply, TransitStatus::PermissionDenied, "the gateway refuses a stranger's advertisement");
			assert_eq!(cluster.peer_servlets()?.len(), 0, "a refused advertisement installs no route");

			cluster.stop();
			Ok(())
		}
	}
}

/// The fixture for a rate budget keyed on the origin.
///
/// It holds one origin identity and two relay identities, all members of the
/// gateway's colony. Each uses a random key, so each has its own subject key
/// id (see [`gossip_plane_ctx`]).
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
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1), equals!(TransitStatus::ResourceExhausted)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0))
		]
	}
}

// Rate admission keys on the rumor's origin, whichever peer relays it: a
// one-token bucket admits the first rumor through relay A and refuses the
// second through relay B. The refusal is local policy, so B's routes stay.
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
		client: |ClusterEnv { context: ctx, cluster, .. }| async move {
			let first = mint_origin_rumor(
				&ctx.origin_key,
				b"budget-rumor-1",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;

			let frame = signed_relay_gossip(&ctx.relay_a_key, b"budget-relay-1", first, 0).await?;
			let replied = send_gossip_frame(&ctx.gateway, &cluster, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			let second = mint_origin_rumor(
				&ctx.origin_key,
				b"budget-rumor-2",
				rumor_body(encode(&PingRequest { value: 22 })?),
			)
			.await?;

			let frame = signed_relay_gossip(&ctx.relay_b_key, b"budget-relay-2", second, 0).await?;
			let replied = send_gossip_frame(&ctx.gateway, &cluster, frame).await?;
			assert_eq!(replied, TransitStatus::ResourceExhausted, "the origin's one token is spent through relay A");

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
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(0))
		]
	}
}

// A gateway whose own certificate carries no colony URN SAN is outside every
// colony, so it has no flood scope and refuses an origin publish with
// PermissionDenied, even from a trusted hive-plane signer.
tb_scenario! {
	name: cluster_gossip_non_member_gateway_refuses_publish,
	spec: ClusterGossipNonMemberSpec,
	environment Cluster {
		context: GatewayCerts::generate("CN=Non-Member Gateway"),
		start: |SetupEnv { trace, context: certs }| async move {
			// The hive-plane signer must verify, so only the lack of a colony
			// SAN can draw the refusal below.
			let mut conf = peering_cluster_conf(&certs);
			conf.tls.hive_trust = Some(split_hive_trust(&certs));

			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let frame = hive_publish_gossip(
				&certs,
				b"non-member-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;

			let replied = send_gossip_frame(&certs, &cluster, frame).await?;
			assert_eq!(replied, TransitStatus::PermissionDenied, "a gateway outside every colony refuses the publish");

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
			(events::CLUSTER_RECONCILE_ANSWERED, exactly!(2), equals!(1u64)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// Flood membership gates reconciliation, because a want list names local
// rumor state and the repair push carries rumor bytes. Members of "main" and
// "other" get the want, and a trusted peer with no colony SAN gets it empty.
tb_scenario! {
	name: cluster_gossip_reconcile_requires_flood_membership,
	spec: ClusterGossipReconcileMembershipSpec,
	environment Cluster {
		context: neighbor_colony_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let conf = peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust));
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace: _, context: ctx, cluster }| async move {
			let held = vec![vec![0xABu8; 32]];

			let frame = signed_reconcile_gossip(&ctx.gateway.key, b"member-reconcile", held.clone()).await?;
			let member = reconcile_reply(&ctx.gateway, &cluster, frame).await?;
			assert_eq!(member.want.len(), 1, "a member of colony main learns the digest the gateway lacks");

			let frame = signed_reconcile_gossip(&ctx.neighbor_key, b"neighbor-reconcile", held.clone()).await?;
			let neighbor = reconcile_reply(&ctx.gateway, &cluster, frame).await?;
			assert_eq!(neighbor.want.len(), 1, "a member of colony other learns the digest the gateway lacks");

			let frame = signed_reconcile_gossip(&ctx.stranger_key, b"stranger-reconcile", held).await?;
			let stranger = reconcile_reply(&ctx.gateway, &cluster, frame).await?;
			assert!(stranger.want.is_empty(), "a peer outside the flood gets an empty want");

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

/// The configuration of a gateway on the shared identity whose peer plane
/// reads the fixture's switchable store, with no beat. Its hive plane admits
/// the hive-plane identity, which signs the publishes.
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
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(1))
		]
	}
}

// A peer enrolled while the gateway runs joins the flood at once, because
// every frame reads the store. The gateway refuses the neighbor's rumor before
// the operator enrolls it and admits the one after, with no restart.
tb_scenario! {
	name: cluster_gossip_admits_a_peer_enrolled_while_the_gateway_runs,
	spec: ClusterTrustEnrolledAtRunTimeSpec,
	environment Cluster {
		context: trust_ctx_enrolling_the_neighbor(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_cluster(&trace, run_time_trust_conf(&ctx)).await
		},
		client: |ClusterEnv { context: ctx, cluster, .. }| async move {
			let neighbor = &ctx.neighbor.key;
			let before = RumorRelay { origin_key: neighbor, relay_key: neighbor };
			let refused = before.send(&ctx.local, &cluster, "before-enrollment").await?;
			assert_eq!(refused, TransitStatus::PermissionDenied, "the gateway refuses a signer outside its trust");

			ctx.trust.switch();

			let after = RumorRelay { origin_key: neighbor, relay_key: neighbor };
			let admitted = after.send(&ctx.local, &cluster, "after-enrollment").await?;
			assert_eq!(admitted, TransitStatus::Ok, "the gateway admits the signer it enrolled");

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
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(3)),
			(events::CLUSTER_PEER_EXPELLED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// A peer removed from trust while the gateway runs leaves the flood at once,
// in both directions. The gateway, with no beat, sends the neighbor one rumor
// over a pooled connection, and then the operator removes the neighbor.
//
// - The gateway admits both rumors, and the neighbor admits the first alone, so ADMITTED counts three.
// - The second rumor stays unsent, although the pooled connection is open.
// - The neighbor leaves the targets as any gateway outside the flood does, and the gateway refuses its relay.
tb_scenario! {
	name: cluster_gossip_stops_at_a_peer_removed_from_trust_while_the_gateway_runs,
	spec: ClusterTrustRemovedAtRunTimeSpec,
	environment Bare {
		context: trust_ctx_removing_the_neighbor(),
		exec: |SetupEnv { trace, context: ctx }| async move {
			let neighbor_trust = combined_trust(&[&ctx.local.cert, &ctx.neighbor.cert]);
			let neighbor_tls = cluster_tls_config_with_trust(&ctx.neighbor, None)
				.with_hive_trust(Arc::clone(&neighbor_trust))
				.with_peer_trust(neighbor_trust);

			let neighbor_conf = ClusterConfig::new(neighbor_tls);

			let neighbor = start_cluster(&trace, neighbor_conf).await?;
			let conf = run_time_trust_conf(&ctx);
			let table = Arc::clone(conf.peer.table());
			let neighbor_addr = dial_admitted_by(&conf, neighbor.addr().to_string());
			let gateway = start_cluster(&trace, conf).await?;

			let verified = table.promote(neighbor_addr, None, UnixMillis::now())?;
			assert!(verified, "the table holds the neighbor as a verified target");

			let body = rumor_body(encode(&PingRequest { value: 21 })?);
			let frame = hive_publish_gossip(&ctx.local, b"before-removal", body, 1).await?;
			let replied = send_gossip_frame(&ctx.local, &gateway, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");
			wait_for_recorded(&trace, events::CLUSTER_GOSSIP_ADMITTED, 2, 50).await;

			ctx.trust.switch();

			let body = rumor_body(encode(&PingRequest { value: 22 })?);
			let frame = hive_publish_gossip(&ctx.local, b"after-removal", body, 1).await?;
			let replied = send_gossip_frame(&ctx.local, &gateway, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");
			wait_for_recorded(&trace, events::CLUSTER_PEER_EXPELLED, 1, 50).await;

			let neighbor_key = &ctx.neighbor.key;
			let refused = RumorRelay { origin_key: neighbor_key, relay_key: neighbor_key };
			let replied = refused.send(&ctx.local, &gateway, "neighbor-after-removal").await?;
			assert_eq!(replied, TransitStatus::PermissionDenied, "the gateway refuses a signer it removed");

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
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(1)),
			(events::CLUSTER_PEER_EXPELLED, exactly!(1)),
			(events::CLUSTER_GOSSIP_FANOUT_UNREACHED, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// With no beat, a certificate authority in peer trust admits no gateway to the
// flood.
//
// - The dial completes, because the handshake validates the chain (FANOUT_UNREACHED exactly 0).
// - The store holds no certificate for the leaf's key, so the gateway sends no rumor and expels the leaf.
// - The local gateway alone admits the rumor (ADMITTED = 1).
// - The gateway refuses a rumor the leaf relays for the same reason, so both directions agree.
tb_scenario! {
	name: cluster_gossip_admits_no_gateway_through_a_certificate_authority,
	spec: ClusterAuthorityTrustSpec,
	environment Bare {
		context: authority_trust_ctx(),
		exec: |SetupEnv { trace, context: ctx }| async move {
			let leaf_trust = Arc::clone(&ctx.leaf.trust);
			let leaf_tls = cluster_tls_config_with_trust(&ctx.leaf, None)
				.with_hive_trust(Arc::clone(&leaf_trust))
				.with_peer_trust(leaf_trust);

			let leaf_conf = ClusterConfig::new(leaf_tls);

			let leaf = start_cluster(&trace, leaf_conf).await?;
			let tls = cluster_tls_config(&ctx.local).with_peer_trust(Arc::clone(&ctx.peer_trust));
			let mut conf = ClusterConfig::new(tls);
			conf.tls.hive_trust = Some(split_hive_trust(&ctx.local));

			let table = Arc::clone(conf.peer.table());
			let leaf_addr = dial_admitted_by(&conf, leaf.addr().to_string());
			let gateway = start_cluster(&trace, conf).await?;

			let verified = table.promote(leaf_addr, None, UnixMillis::now())?;
			assert!(verified, "the table holds the leaf as a verified target");

			let body = rumor_body(encode(&PingRequest { value: 21 })?);
			let frame = hive_publish_gossip(&ctx.local, b"authority-rumor", body, 1).await?;
			let replied = send_gossip_frame(&ctx.local, &gateway, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");
			wait_for_recorded(&trace, events::CLUSTER_PEER_EXPELLED, 1, 50).await;

			let leaf_key = &ctx.leaf.key;
			let replied = relay_application_rumor(&ctx.local, &gateway, leaf_key, leaf_key, "authority-leaf").await?;
			assert_eq!(replied, TransitStatus::PermissionDenied, "the gateway refuses a rumor the leaf relays");

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
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!())
		]
	}
}

// Peer exchange withholds an address that the table expelled. The advertised
// address stays a candidate with no beat until the scenario expels it, as a
// probe does on an answer from outside the flood. The body asserts each reply.
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
			let ad_reply = install_ping_peer(&certs, &gateway).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(gateway.peer_servlets()?.len(), 1, "the member's advertisement installs its ping route");

			let frame = signed_reconcile_gossip(&certs.key, b"pex-before-expel", vec![]).await?;
			let before = reconcile_reply(&certs, &gateway, frame).await?;
			assert_eq!(before.pex.len(), 1, "a reconcile reply shares the address the table holds");

			table.expel(advertised)?;

			let frame = signed_reconcile_gossip(&certs.key, b"pex-after-expel", vec![]).await?;
			let after = reconcile_reply(&certs, &gateway, frame).await?;
			assert!(after.pex.is_empty(), "a reconcile reply withholds an address the table expelled");

			let routes = gateway.peer_routes()?.len();
			assert_eq!(routes, 1, "the route that dials the expelled address stays");

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
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(1)),
			(GOSSIP_INGRESS_SIGNED_BY_GATEWAY, exactly!(1), equals!(true)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(1))
		]
	}
}

// The ingress servlet receives the rumor as its origin gateway signed it,
// before the gateway answers the publish. The frame's message decodes as a
// `GossipRumor`, and the frame's signature verifies under the gateway's key.
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
			let replied = send_gossip_frame(&certs, &gateway, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

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
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(1)),
			(events::CLUSTER_DIAL_REFUSED, at_least!(1)),
			(GOSSIP_INGRESS_SIGNED_BY_GATEWAY, exactly!(0)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(0))
		]
	}
}

// The ingress delivery reaches only the servlet identity its registration
// names. Hive trust holds the impostor too, so the handshake completes, and the
// dial's binding alone refuses the answer and each retry (CWE-346).
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
			assert_eq!(registered.status, TransitStatus::Ok, "the gateway registers the hive that names the servlet");

			let body = rumor_body(encode(&PingRequest { value: 21 })?);
			let frame = hive_publish_gossip(&certs, b"ingress-impostor-rumor", body, 0).await?;
			let replied = send_gossip_frame(&certs, &gateway, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			gateway.stop();
			impostor.stop();
			Ok(())
		}
	}
}

/// The fixture for the ingress-None delivery policy. Its journal handle lets
/// the scenario observe the retry set from outside.
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
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(0))
		]
	}
}

// With no ingress, the gateway journals and refloods only. It admits a publish
// once the journal retains it and acks the record at once, off the pending
// retry set, before the reply, so the probe needs no poll.
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
		client: |ClusterEnv { context: ctx, cluster, .. }| async move {
			let frame = hive_publish_gossip(
				&ctx.certs,
				b"ingress-none-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			let replied = send_gossip_frame(&ctx.certs, &cluster, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			let pending = ctx.journal.pending_local(UnixMillis::now())?;
			assert!(pending.is_empty(), "with no ingress the gateway acks the record at once");

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
			(events::CLUSTER_GOSSIP_ADMITTED, at_least!(2)),
			(events::CLUSTER_PEER_DISCOVERED, at_least!(2)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(2))
		]
	}
}

// The beat discovers peers from one seed through peer exchange: X anchors seed
// S alone, and S anchors publisher P.
//
// - S's beat verifies its anchor P and shares P over PEX.
// - X learns P, feeler-probes it, proves its flood membership, and promotes it (CLUSTER_PEER_DISCOVERED).
// - X's advertisement teaches P to dial back, and P promotes X the same way.
// - A rumor that P publishes at ttl 0 moves by repair alone, so it reaches X's
//   ingress only across those two discovered edges (DELIVERED at P and X).
// - Each gateway also admits the slate rumors of the others' beats, so ADMITTED is a lower bound.
tb_scenario! {
	name: cluster_peer_discovery_bootstraps_from_seed,
	spec: ClusterPeerDiscoverySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| {
			start_scenario_rumor_hive(trace, &certs)
		},
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (mut conf_p, _journal_p) = gossip_cluster_conf(&certs, vec![]);
			conf_p.peer.advertise_interval = Some(Duration::from_millis(100));

			let gateway_p = start_cluster(&trace, conf_p).await?;
			let (mut conf_s, _journal_s) = gossip_cluster_conf(&certs, vec![gateway_p.addr().to_string()]);
			conf_s.peer.advertise_interval = Some(Duration::from_millis(100));

			let table_s = Arc::clone(conf_s.peer.table());
			let gateway_s = start_cluster(&trace, conf_s).await?;

			let (mut conf_x, _journal_x) = gossip_cluster_conf(&certs, vec![gateway_s.addr().to_string()]);
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
			let replied = send_gossip_frame(&certs, &gateway_p, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");
			wait_for_recorded(&trace, events::CLUSTER_GOSSIP_DELIVERED, 2, 100).await;

			// The spec counts promotions, and each one lands a beat apart from
			// the delivery at X, so the scenario waits for a promotion in each
			// table before it stops the gateways.
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

/// The discovery table bounds an eclipse attack.
///
/// An attacker inside one /16 prefix floods hints past the bucket cap and
/// even passes every probe.
///
/// - Admission stops at the per-prefix cap.
/// - Promotion into tried stops at the per-prefix cap.
/// - The configured anchor keeps its first dial slot.
/// - The target set stays bounded.
/// - The beat always keeps a target outside the attacker's addresses.
///
/// # Sources
///
/// - Heilman, Kendler, Zohar & Goldberg (2015), eclipse attacks on Bitcoin's
///   peer-to-peer network, at USENIX Security '15 and as ePrint 2015/263:
///   - <https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman>
///   - <https://eprint.iacr.org/2015/263>
/// - CWE-770, allocation of resources without limits or throttling:
///   <https://cwe.mitre.org/data/definitions/770.html>
#[test]
fn cluster_peer_table_bounds_eclipse_flood() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let anchor = peer_addr("127.0.0.1:9000");
	let conf = peering_cluster_conf_with_peers(&certs, vec![anchor.to_string()]);
	let table = Arc::clone(conf.peer.table());
	let flood: Vec<PeerHint> = (0..MAX_PEER_BUCKET + 8)
		.map(|host| PeerHint {
			dial: dial_admitted_by(&conf, format!("10.66.0.{}:9000", host + 1)),
			peer_id: None,
		})
		.collect();

	let admitted = table.learn(flood.clone(), UnixMillis::now())?;
	assert_eq!(admitted, MAX_PEER_BUCKET, "admission stops at the per-prefix cap");

	// A full tried bucket answers a promotion with `Ok(false)`, so the
	// count stops at the per-prefix cap.
	let answers = flood.iter().map(|hint| table.promote(hint.dial, None, UnixMillis::now()));
	let promotions: Vec<bool> = answers.collect::<Result<_, _>>()?;
	let promoted = promotions.into_iter().filter(|promotion| *promotion).count();
	assert_eq!(promoted, MAX_PEER_BUCKET, "promotion into tried stops at the per-prefix cap");

	let targets = table.target_set()?;
	let first = targets.first().map(AdmittedDial::address);
	assert_eq!(first, Some(anchor), "the configured anchor keeps the first dial slot");
	assert!(targets.len() <= MAX_PEER_BUCKET + 1, "the target set stays bounded");
	Ok(())
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

/// The configuration of a gateway whose certificate carries no colony URN,
/// TLS-anchored both ways.
///
/// A probe against it completes the handshake and fails the membership proof
/// alone.
fn stranger_gateway_conf(ctx: &NeighborGatewayCtx) -> ClusterConfig {
	let tls = cluster_tls_config_with_trust(&ctx.stranger, None)
		.with_hive_trust(Arc::clone(&ctx.shared_trust))
		.with_peer_trust(Arc::clone(&ctx.shared_trust));
	ClusterConfig::new(tls)
}

/// The configuration of a gateway from colony "other", TLS-anchored both ways.
///
/// A probe against it completes the handshake and proves flood membership.
fn neighbor_gateway_conf(ctx: &NeighborGatewayCtx) -> ClusterConfig {
	let tls = cluster_tls_config_with_trust(&ctx.neighbor, None)
		.with_hive_trust(Arc::clone(&ctx.shared_trust))
		.with_peer_trust(Arc::clone(&ctx.shared_trust));
	ClusterConfig::new(tls)
}

/// The configuration of a prober with no anchors and a fast beat, so discovery
/// runs on feeler probes alone:
///
/// - `peer_trust` decides which probed identities complete the handshake.
/// - The membership proof then separates flood members from strangers.
fn fast_probing_conf(certs: &ClusterTestCerts, peer_trust: Arc<dyn CertificateTrust>) -> ClusterConfig {
	let tls = cluster_tls_config(certs).with_peer_trust(peer_trust);
	ClusterConfig::builder(tls)
		.with_advertise_interval(Duration::from_millis(100))
		.build()
}

/// The configuration of a prober whose trust anchors every identity of
/// [`NeighborGatewayCtx`], so the membership proof alone separates them.
fn probing_cluster_conf(ctx: &NeighborGatewayCtx) -> ClusterConfig {
	fast_probing_conf(&ctx.local, Arc::clone(&ctx.shared_trust))
}

tb_assert_spec! {
	pub ClusterPeerMembershipProbeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_DISCOVERED, exactly!(2)),
			(events::CLUSTER_PEER_EXPELLED, exactly!(1))
		]
	}
}

// Feeler probes promote on flood membership. Three hints name gateways of
// colonies "main" and "other" and a TLS-trusted stranger with no colony URN,
// and all three probes complete the handshake.
//
// - Both colonies prove membership and join the beat targets.
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
			assert_eq!(admitted, 3, "the table admits the three hints the probes start from");

			wait_for_recorded(&trace, events::CLUSTER_PEER_DISCOVERED, 2, 50).await;
			wait_for_recorded(&trace, events::CLUSTER_PEER_EXPELLED, 1, 50).await;

			let targets = table.target_set()?;
			let joined = [member_addr, neighbor_addr].map(|addr| targets.contains(&addr));
			assert_eq!(joined, [true, true], "both colonies join the beat targets");
			assert!(!targets.contains(&stranger_addr), "the stranger stays off the beat targets");

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
			(events::CLUSTER_PEER_EVICTED, exactly!(0)),
			(events::CLUSTER_PEER_EXPELLED, at_least!(1))
		]
	}
}

// A verified peer that answers from outside the flood leaves the beat targets
// and keeps its routes. Its slate arrives under the local colony's key, and it
// answers the next beat with a certificate that carries no colony URN.
//
// - The beat expels the address at its first answer, ahead of the failure threshold (EVICTED exactly 0).
// - A feeler probe can expel the address before the table verifies it, so EXPELLED counts once or more.
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
			let ad_reply = advertise_peer(&ctx.local, &prober, cluster.addr().to_string(), vec![servlet_urn("ping")]).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(prober.peer_servlets()?.len(), 1, "the slate installs the ping route");

			let verified = table.promote(outside_addr, None, UnixMillis::now())?;
			assert!(verified, "the table holds the address as a verified target");

			// A feeler probe can expel the address ahead of the promotion, so
			// the wait counts the expulsions that follow it.
			let expelled = trace.recorded(events::CLUSTER_PEER_EXPELLED);
			wait_for_recorded(&trace, events::CLUSTER_PEER_EXPELLED, expelled + 1, 50).await;

			let targets = table.target_set()?;
			assert!(!targets.contains(&outside_addr), "the beat drops the expelled address from its targets");

			let routes = prober.peer_routes()?.len();
			assert_eq!(routes, 1, "the routes that dial an expelled address stay");

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
			(events::CLUSTER_PEER_EXPELLED, exactly!(1)),
			(events::CLUSTER_PEER_DISCOVERED, exactly!(0))
		]
	}
}

// An unverified candidate that answers from outside the flood keeps its routes.
// Its slate under the local colony's key installs them, and the feeler probe
// finds no colony URN there, so it expels the candidate from the new table.
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
			let prober = start_cluster(&trace, prober_conf).await?;

			let ad_reply = advertise_peer(&ctx.local, &prober, cluster.addr().to_string(), vec![servlet_urn("ping")]).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(prober.peer_servlets()?.len(), 1, "the slate installs the ping route");

			wait_for_recorded(&trace, events::CLUSTER_PEER_EXPELLED, 1, 50).await;

			let routes = prober.peer_routes()?.len();
			assert_eq!(routes, 1, "the routes that dial an expelled candidate stay");

			prober.stop();
			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterOutsideAnchorSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, at_least!(2)),
			(events::CLUSTER_PEER_EVICTED, exactly!(0))
		]
	}
}

// An anchor that answers from outside the flood keeps its slot and routes,
// because operator configuration puts it outside the learned table. Its
// certificate carries no colony URN, so it refuses each beat's advertisement.
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

			let ad_reply = advertise_peer(&ctx.local, &prober, &anchor, vec![servlet_urn("ping")]).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(prober.peer_servlets()?.len(), 1, "the slate installs the ping route");

			// The count starts after the routes exist, so the two beats it
			// waits for run over them.
			let refused_so_far = trace.recorded(events::CLUSTER_PEER_ADVERTISE_REFUSED);
			wait_for_recorded(&trace, events::CLUSTER_PEER_ADVERTISE_REFUSED, refused_so_far + 2, 50).await;

			let refused = trace.recorded(events::CLUSTER_PEER_ADVERTISE_REFUSED);
			assert!(refused >= refused_so_far + 2, "two beats dial the anchor over the installed routes");

			let targets = table.target_set()?;
			assert!(targets.contains(&anchor_addr), "a configured anchor keeps its beat slot");

			let routes = prober.peer_routes()?.len();
			assert_eq!(routes, 1, "the routes that dial the anchor outlive its beats");

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
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(1)),
			(events::CLUSTER_PEER_EXPELLED, exactly!(1)),
			(events::CLUSTER_PEER_EVICTED, exactly!(0)),
			(events::CLUSTER_GOSSIP_FANOUT_UNREACHED, exactly!(0))
		]
	}
}

// A reflood drops a verified target that answers with no colony URN: the hop
// sends no rumor, and the address leaves the targets at once. The dial
// completes, so the unreached count (FANOUT_UNREACHED) stays at zero.
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
			assert!(verified, "the table holds the address as a verified target");

			let body = rumor_body(encode(&PingRequest { value: 21 })?);
			let frame = hive_publish_gossip(&ctx.local, b"reflood-expel-rumor", body, 1).await?;
			let replied = send_gossip_frame(&ctx.local, &publisher, frame).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");
			wait_for_recorded(&trace, events::CLUSTER_PEER_EXPELLED, 1, 50).await;

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
/// [`events::CLUSTER_PEER_DISCOVERED`] fires on that promotion, which the
/// advertise beat drives. A scenario that stops its gateways the moment gossip
/// converges can outrun the beat, so a spec that asserts a discovery count
/// also needs this wait.
pub async fn wait_for_promoted(table: &PeerTable, count: usize, attempts: u32, interval: Duration) -> bool {
	let promoted = || table.learned().is_ok_and(|(_, tried)| tried >= count);
	poll_until(attempts, interval, promoted).await
}

/// A live gateway that answers every reconcile round with one fixed
/// peer-exchange sample.
struct ReconcileReplier {
	/// The accept task, which the scenario aborts when it ends.
	task: tokio::task::JoinHandle<()>,
	/// The address the gateway answers at.
	addr: String,
	/// The order of the last round the gateway answered, which the prober
	/// stamps from its clock when the round starts.
	last_order: Arc<AtomicU64>,
}

/// Starts a same-colony gateway that answers every frame with `pex` as its
/// peer-exchange sample. Its honest TLS identity passes the prober's
/// membership proof.
async fn start_reconcile_server(
	certs: &ClusterTestCerts,
	pex: Vec<PeerGossip>,
) -> Result<ReconcileReplier, TightBeamError> {
	let identity = signing_identity(certs.cert.to_owned(), certs.key.to_owned());
	let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(identity);
	let bind_addr = "127.0.0.1:0".parse::<TightBeamSocketAddr>()?;
	let (listener, addr) = <TokioListener as EncryptedProtocol>::bind_with(bind_addr, config).await?;

	let last_order = Arc::new(AtomicU64::new(0));
	let orders = Arc::clone(&last_order);
	let task = server! {
		protocol TokioListener: listener,
		handle: move |frame: Frame| {
			let orders = Arc::clone(&orders);
			let pex = pex.clone();
			async move {
				orders.store(frame.metadata().order(), Ordering::SeqCst);

				Ok(Some(compose! {
					V0: id: frame.metadata().id(),
						message: GossipWant { want: Vec::new(), pex }
				}?))
			}
		}
	};

	Ok(ReconcileReplier { task, addr: addr.to_string(), last_order })
}

tb_assert_spec! {
	pub ClusterOversizedReplySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_DISCOVERED, exactly!(0)),
			(events::CLUSTER_RECONCILE_FAILED, at_least!(2), equals!(true))
		]
	}
}

// An oversized reconcile reply is misbehavior, and its round fails. The rogue
// passes the handshake and the membership proof on a valid same-colony
// certificate, so its reply past MAX_PEX_SAMPLE is its one abuse.
//
// - The prober keeps the candidate unpromoted and charges it at each failed probe.
// - The candidate keeps its slot until a newcomer needs it, so a second probe reaches it.
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
			assert_eq!(admitted, 1, "the table admits the rogue as a candidate");

			wait_for_recorded(&trace, events::CLUSTER_RECONCILE_FAILED, 2, 50).await;

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

/// A gateway configuration on `clock` whose peer table persists to `store`,
/// with `peers` as its peer trust and a beat every [`RECORDING_BEAT`] of the
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

/// Polls until `store` holds `addr`, or five seconds pass, and returns the
/// stamp it holds then.
async fn wait_for_stamp(store: &RecordingPeerStore, addr: AdmittedDial) -> Option<UnixMillis> {
	poll_until(50, Duration::from_millis(100), || store.stamp_of(addr).is_some()).await;
	store.stamp_of(addr)
}

/// Moves `clock` one beat at a time until `store` holds `addr`, or five
/// seconds pass. The clock moves only while the address is absent, so the
/// beat that learns it is the last beat to run.
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

/// A hint that a peer-exchange reply teaches again carries the reading of the
/// gateway's clock at the round that taught it.
///
/// - The prober learns the shared address and drops it, so the reply teaches it again.
/// - The manual clock moves one beat at a time until the prober's store holds the address.
/// - The replier records the round's order, which the prober stamps from its clock.
/// - The persisted stamp of the address equals that reading.
#[tokio::test]
async fn cluster_relearned_hint_takes_the_clock_reading() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let trace = TraceCollector::new();
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
	assert!(relearned, "the prober learns the shared address again");

	let round_reading = UnixMillis::new(replier.last_order.load(Ordering::SeqCst));
	let stamp = store.stamp_of(shared_addr);
	assert_eq!(
		stamp,
		Some(round_reading),
		"the relearned hint carries the round's clock reading"
	);

	replier.task.abort();
	prober.stop();
	Ok(())
}

tb_assert_spec! {
	pub ClusterAdvertiserHintStampSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!())
		]
	}
}

// A verified advertiser joins the table as a hint stamped with the gateway's
// clock reading at the advertisement's arrival. The manual clock starts at the
// system clock, so the body asserts the stamp in the test's peer store.
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

			let ad_reply = install_ping_peer(&certs, &gateway).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");

			let stamp = wait_for_stamp(&store, advertiser).await;
			assert_eq!(stamp, Some(clock.unix()), "the advertiser hint carries the clock reading");

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
			(events::CLUSTER_PEER_AD_LEARNED, exactly!(1))
		]
	}
}

// The origin of a relayed advertisement rumor joins the table as a hint
// stamped with the gateway's clock reading at the rumor's arrival. The stamp
// sits in the test's peer store, so the body asserts it.
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
			assert_eq!(status, TransitStatus::Ok, "the gateway admits the relayed advertisement rumor");

			let stamp = wait_for_stamp(&store, origin).await;
			assert_eq!(stamp, Some(clock.unix()), "the rumored origin hint carries the clock reading");

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
			(events::CLUSTER_PEER_EVICTED, exactly!(1)),
			(events::CLUSTER_PEER_ROUTES_WITHDRAWN, exactly!(1), equals!(1u64))
		]
	}
}

// The beat evicts a verified tried peer that goes dark (liveness). A feeler
// probe proves the member's flood membership and promotes it into tried, the
// prober routes to its one advertised type, and then the member stops.
//
// - Each later beat fails its reconcile: the dropped listener refuses its fresh dial as a dead remote would.
// - The failure threshold evicts the entry once, and the beat stops its dials to the dead address.
// - The eviction withdraws the member's one route first, and the dead peer releases its prefix bucket slot.
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
			wait_for_recorded(&trace, events::CLUSTER_PEER_DISCOVERED, 1, 50).await;

			// The member's slate gives the eviction routes to withdraw.
			let ad_reply = advertise_peer(&certs, &prober, cluster.addr().to_string(), vec![servlet_urn("ping")]).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(prober.peer_servlets()?.len(), 1, "the member's slate installs its ping route");

			cluster.stop();

			// The routes leave ahead of the eviction event, so one wait covers
			// both counts.
			wait_for_recorded(&trace, events::CLUSTER_PEER_EVICTED, 1, 50).await;

			prober.stop();
			Ok(())
		}
	}
}

/// The steps of a [`GossipJournal`] that a [`FaultSwitchJournal`] fails once
/// it is faulty.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum JournalStep {
	/// [`GossipJournal::held_digests`] and [`GossipJournal::fetch`], the reads
	/// of a reconcile round.
	#[default]
	Reads,
	/// [`GossipJournal::seen`], the duplicate check of an inbound rumor.
	Seen,
	/// [`GossipJournal::record`] and [`GossipJournal::witness`], the writes of
	/// an admitted rumor.
	Writes,
}

/// A [`GossipJournal`] that serves normally until it is faulty, then fails
/// the steps that its [`JournalStep`] names.
///
/// The switch models a storage fault that appears on a live gateway while its
/// peers answer.
#[derive(Default)]
struct FaultSwitchJournal {
	inner: MemoryGossipJournal,
	faulty: AtomicBool,
	step: JournalStep,
}

impl FaultSwitchJournal {
	/// A journal that fails `step` from its first call.
	fn failing(step: JournalStep) -> Self {
		Self { inner: MemoryGossipJournal::default(), faulty: AtomicBool::new(true), step }
	}

	fn fail_now(&self) {
		self.faulty.store(true, Ordering::SeqCst);
	}

	fn guard(&self, step: JournalStep) -> Result<(), ClusterError> {
		if self.step == step && self.faulty.load(Ordering::SeqCst) {
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
		issued_at: UnixMillis,
		now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		self.guard(JournalStep::Writes)?;
		self.inner.record(signer, digest, rumor, issued_at, now)
	}

	fn witness(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		issued_at: UnixMillis,
		now: UnixMillis,
	) -> Result<Admission, ClusterError> {
		self.guard(JournalStep::Writes)?;
		self.inner.witness(signer, digest, issued_at, now)
	}

	fn seen(&self, digest: &GossipDigest, now: UnixMillis) -> Result<bool, ClusterError> {
		self.guard(JournalStep::Seen)?;
		self.inner.seen(digest, now)
	}

	fn held_digests(&self, now: UnixMillis) -> Result<Vec<GossipDigest>, ClusterError> {
		self.guard(JournalStep::Reads)?;
		self.inner.held_digests(now)
	}

	fn fetch(&self, wanted: &[GossipDigest], now: UnixMillis) -> Result<Vec<(GossipDigest, Frame)>, ClusterError> {
		self.guard(JournalStep::Reads)?;
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
			(events::CLUSTER_RECONCILE_FAILED, at_least!(MAX_PEER_TRIED_FAILURES as u32 + 1), equals!(false)),
			(events::CLUSTER_PEER_EVICTED, exactly!(0))
		]
	}
}

// A local journal fault on the prober fails `held_digests` at the start of
// each round. The beat charges the fault to this gateway and skips the round,
// which leaves the member unscored, so the member stays a beat target.
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
			wait_for_recorded(&trace, events::CLUSTER_PEER_DISCOVERED, 1, 50).await;

			journal.fail_now();

			// A beat settles each round before the next one starts, so the
			// round past `MAX_PEER_TRIED_FAILURES` follows the one a scored
			// fault would evict at.
			wait_for_recorded(&trace, events::CLUSTER_RECONCILE_FAILED, MAX_PEER_TRIED_FAILURES + 1, 50).await;

			prober.stop();
			cluster.stop();
			Ok(())
		}
	}
}

/// The one anchor of [`outside_origin_conf`], a dead loopback address that the
/// fan-out counts as unreached.
const DEAD_ANCHOR: &str = "127.0.0.1:9";

/// The configuration of a colony member whose identity signs under the
/// outside provider of `tests/seams`, anchored to [`DEAD_ANCHOR`] on a fast
/// beat.
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
			(events::CLUSTER_GOSSIP_FANOUT_UNREACHED, at_least!(1)),
			(events::CLUSTER_PEER_AD_PUBLISH_FAILED, exactly!(0))
		]
	}
}

// A gateway whose identity signs under an outside provider originates its
// slate rumor. It verifies its own signature under the identity's policy, so
// the rumor reaches its fan-out, which traces the dead anchor as unreached.
tb_scenario! {
	name: cluster_outside_identity_originates_its_rumor,
	spec: ClusterOutsideOriginSpec,
	environment Bare {
		exec: |SetupEnv { trace, context: _ }| async move {
			let gateway = start_cluster(&trace, outside_origin_conf()).await?;
			wait_for_recorded(&trace, events::CLUSTER_GOSSIP_FANOUT_UNREACHED, 1, 50).await;

			gateway.stop();
			Ok(())
		}
	}
}
