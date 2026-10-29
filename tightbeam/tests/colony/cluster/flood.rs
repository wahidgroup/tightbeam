//! The gossip flood across colonies.
//!
//! Three colonies of one namespace run one gateway each. A rumor travels
//! between the gateways that trust each other, whichever colony each belongs
//! to, so the parties share state while each keeps its own colony.
//!
//! - With trust stores that agree, a rumor floods through all three colonies,
//!   anti-entropy repairs one between two of them, and peer exchange
//!   introduces the third to the first.
//! - With trust stores that differ, the namespace divides into subnets: a
//!   gateway receives the rumors of the origins it trusts and of no other.

use super::common::*;
use super::federation::federation_conf;
use super::gossip::{
	dial_admitted_by, hive_publish_gossip, rumor_body, send_gossip_frame, wait_for_promoted, wait_for_refused_origins,
};

/// Three colonies of one namespace, with one gateway identity each.
struct ThreeColonyCtx {
	main: Arc<ClusterTestCerts>,
	other: Arc<ClusterTestCerts>,
	third: Arc<ClusterTestCerts>,
	/// The peer-plane store of each gateway, which decides whose rumors it
	/// accepts.
	peers_of_main: Arc<dyn CertificateTrust>,
	peers_of_other: Arc<dyn CertificateTrust>,
	peers_of_third: Arc<dyn CertificateTrust>,
}

/// One gateway identity of colony `name`, with its certificate.
fn gateway_of(name: &str) -> (Certificate, Secp256k1SigningKey) {
	let colony = colony_ns().colony(name).expect("static colony name");
	colony_identity(format!("Flood Gateway {name}"), &colony)
}

/// Assembles the context from three identities and the peer store each one
/// gets.
///
/// - The transport store holds all three certificates, so each scenario's
///   trust layout lives on the peer plane alone.
/// - Each peer store holds its own gateway's certificate, so a rumor that a
///   neighbor echoes back verifies, and the gateway drops it as a duplicate.
fn three_colonies(
	identities: [(Certificate, Secp256k1SigningKey); 3],
	peer_stores: [Arc<dyn CertificateTrust>; 3],
) -> ThreeColonyCtx {
	let [(cert_main, key_main), (cert_other, key_other), (cert_third, key_third)] = identities;
	let [peers_of_main, peers_of_other, peers_of_third] = peer_stores;
	let trust = combined_trust(&[&cert_main, &cert_other, &cert_third]);

	ThreeColonyCtx {
		main: Arc::new(GatewayCerts { cert: cert_main, key: key_main, trust: Arc::clone(&trust) }),
		other: Arc::new(GatewayCerts { cert: cert_other, key: key_other, trust: Arc::clone(&trust) }),
		third: Arc::new(GatewayCerts { cert: cert_third, key: key_third, trust }),
		peers_of_main,
		peers_of_other,
		peers_of_third,
	}
}

/// Three colonies whose gateways all trust one another, where `main` is the
/// identity of the gateway of colony "main".
fn uniform_trust_ctx_around(main: (Certificate, Secp256k1SigningKey)) -> ThreeColonyCtx {
	let identities = [main, gateway_of("other"), gateway_of("third")];
	let [(main, _), (other, _), (third, _)] = &identities;
	let everyone = combined_trust(&[main, other, third]);
	let peer_stores = [Arc::clone(&everyone), Arc::clone(&everyone), everyone];

	three_colonies(identities, peer_stores)
}

/// Three colonies whose gateways all trust one another.
fn uniform_trust_ctx() -> ThreeColonyCtx {
	uniform_trust_ctx_around(gateway_of("main"))
}

/// Three colonies where "other" is a bridge: it trusts both neighbors, and
/// each neighbor trusts it alone.
fn bridged_trust_ctx() -> ThreeColonyCtx {
	let identities = [gateway_of("main"), gateway_of("other"), gateway_of("third")];
	let [(main, _), (other, _), (third, _)] = &identities;
	let peer_stores = [
		combined_trust(&[main, other]),
		combined_trust(&[main, other, third]),
		combined_trust(&[other, third]),
	];

	three_colonies(identities, peer_stores)
}

/// A gateway of the flood with `peers` as anchors and the fast beat of
/// [`federation_conf`].
///
/// The hive plane admits the hive-plane identity, which signs every publish
/// here: the gateway's own key is a peer key in these stores, and the hive
/// plane refuses a peer key.
fn flood_conf(
	certs: &ClusterTestCerts,
	peer_trust: &Arc<dyn CertificateTrust>,
	peers: impl IntoIterator<Item = String>,
) -> ClusterConfig {
	let mut conf = federation_conf(certs, Arc::clone(peer_trust), peers, 1);
	conf.tls.hive_trust = Some(split_hive_trust(certs));
	conf
}

/// [`flood_conf`] with no beat, so the gateway moves rumors by flood alone
/// and a scenario's counts are exact.
fn quiet_flood_conf(
	certs: &ClusterTestCerts,
	peer_trust: &Arc<dyn CertificateTrust>,
	peers: impl IntoIterator<Item = String>,
) -> ClusterConfig {
	let mut conf = flood_conf(certs, peer_trust, peers);
	conf.peer.advertise_interval = None;
	conf
}

/// Publishes one application rumor at `gateway` with `ttl` hops, and
/// returns the status of the gateway's reply.
async fn publish_at(
	certs: &ClusterTestCerts,
	gateway: &ClusterGateway,
	id: impl AsRef<[u8]>,
	ttl: u64,
) -> Result<TransitStatus, TightBeamError> {
	let body = rumor_body(encode(&PingRequest { value: 21 })?);
	let frame = hive_publish_gossip(certs, id, body, ttl).await?;
	send_gossip_frame(certs, gateway, frame).await
}

/// Polls until `trace` holds `count` records of `event`, or ten seconds pass.
///
/// The gateways decide on their own tasks, so a poll is the wait. The spec
/// judges the count, so the wait answers nothing.
async fn wait_for_recorded(trace: &TraceCollector, event: Urn<'static>, count: usize) {
	let recorded = || trace.recorded(&event) >= count;
	poll_until(100, Duration::from_millis(100), recorded).await;
}

tb_assert_spec! {
	pub ClusterFloodThreeColoniesSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(3)),
			(GOSSIP_INGRESS_SIGNED_BY_GATEWAY, exactly!(1), equals!(true)),
			(events::CLUSTER_GOSSIP_DELIVERED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0)),
			(events::CLUSTER_GOSSIP_ORIGIN_UNKNOWN, exactly!(0))
		]
	}
}

// One rumor floods three colonies: a publish at "main" with two hops reaches
// "third" through "other", every hop admits it because all three colonies sit
// in one flood, and the servlet at "third" gets the frame that "main" signed.
tb_scenario! {
	name: cluster_flood_reaches_three_colonies,
	spec: ClusterFloodThreeColoniesSpec,
	environment Bare {
		context: uniform_trust_ctx(),
		exec: |SetupEnv { trace, context: ctx }| async move {
			let mut conf_third = quiet_flood_conf(&ctx.third, &ctx.peers_of_third, vec![]);
			conf_third.gossip.ingress = Some(servlet_urn("rumor"));

			let third = start_cluster(&trace, conf_third).await?;
			let ingress_hive = start_rumor_hive(trace.share(), hive_plane_certs(&ctx.third), ctx.main.key.to_owned()).await?;
			ingress_hive.register_with_cluster(third.addr()).await?;

			let dials_third = vec![third.addr().to_string()];
			let conf_other = quiet_flood_conf(&ctx.other, &ctx.peers_of_other, dials_third);
			let other = start_cluster(&trace, conf_other).await?;

			let dials_other = vec![other.addr().to_string()];
			let conf_main = quiet_flood_conf(&ctx.main, &ctx.peers_of_main, dials_other);
			let main = start_cluster(&trace, conf_main).await?;

			let replied = publish_at(&ctx.main, &main, b"three-colony-rumor", 2).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			wait_for_recorded(&trace, events::CLUSTER_GOSSIP_ADMITTED, 3).await;

			main.stop();
			other.stop();
			third.stop();
			ingress_hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterFloodRepairSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_GOSSIP_ADMITTED, at_least!(2)),
			(events::CLUSTER_GOSSIP_REPAIR_PUSHED, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0)),
			(events::CLUSTER_GOSSIP_ORIGIN_UNKNOWN, exactly!(0))
		]
	}
}

// Anti-entropy repairs a rumor across colonies. "main" publishes at zero hops,
// so "other" learns the rumor only from the reconcile of the beat of "main",
// which also floods slate rumors that "other" admits beside it.
tb_scenario! {
	name: cluster_flood_repairs_a_rumor_across_colonies,
	spec: ClusterFloodRepairSpec,
	environment Bare {
		context: uniform_trust_ctx(),
		exec: |SetupEnv { trace, context: ctx }| async move {
			let conf_other = quiet_flood_conf(&ctx.other, &ctx.peers_of_other, vec![]);
			let other = start_cluster(&trace, conf_other).await?;

			let dials_other = vec![other.addr().to_string()];
			let conf_main = flood_conf(&ctx.main, &ctx.peers_of_main, dials_other);
			let main = start_cluster(&trace, conf_main).await?;

			let replied = publish_at(&ctx.main, &main, b"repaired-rumor", 0).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			wait_for_recorded(&trace, events::CLUSTER_GOSSIP_REPAIR_PUSHED, 1).await;

			main.stop();
			other.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterFloodDiscoverySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_DISCOVERED, at_least!(3)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Peer exchange discovers a third colony. The seed "other" promotes both of
// its dialers from their advertisements, its reconcile reply shares "third"
// with "main", and the probe of "main" proves "third" a flood member.
tb_scenario! {
	name: cluster_flood_peer_exchange_discovers_a_third_colony,
	spec: ClusterFloodDiscoverySpec,
	environment Bare {
		context: uniform_trust_ctx(),
		exec: |SetupEnv { trace, context: ctx }| async move {
			let conf_other = flood_conf(&ctx.other, &ctx.peers_of_other, vec![]);
			let other = start_cluster(&trace, conf_other).await?;
			let dials_other = vec![other.addr().to_string()];

			let conf_third = flood_conf(&ctx.third, &ctx.peers_of_third, dials_other.clone());
			let third = start_cluster(&trace, conf_third).await?;

			let conf_main = flood_conf(&ctx.main, &ctx.peers_of_main, dials_other);
			let table_of_main = Arc::clone(conf_main.peer.table());
			let third_addr = dial_admitted_by(&conf_main, third.addr().to_string());
			let main = start_cluster(&trace, conf_main).await?;

			// The spec counts three discoveries: the seed promotes both
			// dialers, and "main" promotes "third".
			wait_for_promoted(&table_of_main, 1, 100, Duration::from_millis(100)).await;
			wait_for_recorded(&trace, events::CLUSTER_PEER_DISCOVERED, 3).await;

			let targets = table_of_main.target_set()?;
			assert!(targets.contains(&third_addr), "main promotes third from the peer exchange of the seed");

			main.stop();
			third.stop();
			other.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterFloodBridgeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(9)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(3)),
			(events::CLUSTER_GOSSIP_ORIGIN_UNKNOWN, exactly!(2)),
			(events::CLUSTER_GOSSIP_ORIGIN_REFUSED_BY_PEER, exactly!(2)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0))
		]
	}
}

// Trust stores that differ divide the namespace into subnets around the bridge
// "other", which admits all four rumors.
//
// - Each side refuses the origin of the other once, so neither holds the
//   rumors of the other, and the bridge then offers it no further rumor of
//   that origin, at no cost to its score.
// - The bridge's own rumor reaches both sides, because both trust the bridge.
// - The nine admissions are three at "main", four at the bridge, and two at
//   "third", and each side drops the echo of its own rumors as a duplicate.
tb_scenario! {
	name: cluster_flood_bridge_relays_only_what_each_side_can_verify,
	spec: ClusterFloodBridgeSpec,
	environment Bare {
		context: bridged_trust_ctx(),
		exec: |SetupEnv { trace, context: ctx }| async move {
			let conf_main = quiet_flood_conf(&ctx.main, &ctx.peers_of_main, vec![]);
			let table_of_main = Arc::clone(conf_main.peer.table());
			let main = start_cluster(&trace, conf_main).await?;

			let conf_third = quiet_flood_conf(&ctx.third, &ctx.peers_of_third, vec![]);
			let table_of_third = Arc::clone(conf_third.peer.table());
			let third = start_cluster(&trace, conf_third).await?;

			let dials_both = vec![main.addr().to_string(), third.addr().to_string()];
			let conf_other = quiet_flood_conf(&ctx.other, &ctx.peers_of_other, dials_both);
			let other = start_cluster(&trace, conf_other).await?;

			// Each side gets the bridge as a verified peer, which a beat would
			// otherwise discover. The spare config lends its dial policy to
			// admit an address that the test binds at run time.
			let dial_policy = federation_conf(&ctx.main, Arc::clone(&ctx.peers_of_main), vec![], 1);
			let bridge_addr = dial_admitted_by(&dial_policy, other.addr().to_string());
			let main_joined = table_of_main.promote(bridge_addr, None, UnixMillis::now())?;
			let third_joined = table_of_third.promote(bridge_addr, None, UnixMillis::now())?;
			assert!(main_joined && third_joined, "each side admits the bridge as a verified peer");

			let replied = publish_at(&ctx.main, &main, b"bridge-main-1", 2).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			wait_for_refused_origins(&trace, 1).await;

			let replied = publish_at(&ctx.main, &main, b"bridge-main-2", 2).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");
			let replied = publish_at(&ctx.third, &third, b"bridge-third-1", 2).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			wait_for_refused_origins(&trace, 2).await;

			let replied = publish_at(&ctx.other, &other, b"bridge-other-1", 1).await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			wait_for_recorded(&trace, events::CLUSTER_GOSSIP_ADMITTED, 9).await;

			other.stop();
			third.stop();
			main.stop();
			Ok(())
		}
	}
}
