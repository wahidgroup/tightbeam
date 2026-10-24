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
	dial_admitted_by, hive_publish_gossip, rumor_body, send_gossip_frame, wait_for_gossip_converged, wait_for_promoted,
	wait_for_refused_origins,
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
	/// The journal of each gateway, which a scenario reads to see what
	/// arrived.
	journal_of_main: Arc<MemoryGossipJournal>,
	journal_of_other: Arc<MemoryGossipJournal>,
	journal_of_third: Arc<MemoryGossipJournal>,
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
		journal_of_main: Arc::new(MemoryGossipJournal::default()),
		journal_of_other: Arc::new(MemoryGossipJournal::default()),
		journal_of_third: Arc::new(MemoryGossipJournal::default()),
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

/// A gateway of the flood with `peers` as anchors, the fast beat of
/// [`federation_conf`], and `journal` as its journal.
///
/// The hive plane admits the hive-plane identity, which signs every publish
/// here: the gateway's own key is a peer key in these stores, and the hive
/// plane refuses a peer key.
fn flood_conf(
	certs: &ClusterTestCerts,
	peer_trust: &Arc<dyn CertificateTrust>,
	peers: impl IntoIterator<Item = String>,
	journal: &Arc<MemoryGossipJournal>,
) -> ClusterConfig {
	let mut conf = federation_conf(certs, Arc::clone(peer_trust), peers, 1);
	conf.tls.hive_trust = Some(split_hive_trust(certs));
	conf.gossip.journal = Arc::clone(journal) as Arc<dyn GossipJournal>;
	conf
}

/// [`flood_conf`] with no beat, so the gateway moves rumors by flood alone
/// and a scenario's counts are exact.
fn quiet_flood_conf(
	certs: &ClusterTestCerts,
	peer_trust: &Arc<dyn CertificateTrust>,
	peers: impl IntoIterator<Item = String>,
	journal: &Arc<MemoryGossipJournal>,
) -> ClusterConfig {
	let mut conf = flood_conf(certs, peer_trust, peers, journal);
	conf.peer.advertise_interval = None;
	conf
}

/// Publishes one application rumor at `gateway` with `ttl` hops, and records
/// the status as `GOSSIP_PUBLISH_STATUS`.
async fn publish_at(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	gateway: &ClusterGateway,
	id: impl AsRef<[u8]>,
	ttl: u64,
) -> Result<(), TightBeamError> {
	let body = rumor_body(encode(&PingRequest { value: 21 })?);
	let frame = hive_publish_gossip(certs, id, body, ttl).await?;
	send_gossip_frame(trace, certs, gateway, frame).await
}

/// Polls until the gateways promote `count` peers, or ten seconds pass.
async fn wait_for_discoveries(trace: &TraceCollector, count: usize) -> bool {
	let discovered = || trace.recorded(events::CLUSTER_PEER_DISCOVERED) >= count;
	poll_until(100, Duration::from_millis(100), discovered).await
}

/// Polls until `journal` holds `held` rumors, or five seconds pass, and
/// answers how many it holds then.
async fn held_after_settling(journal: &Arc<MemoryGossipJournal>, held: usize) -> u64 {
	wait_for_gossip_converged([Arc::clone(journal)], held, 50, Duration::from_millis(100)).await;

	let digests = journal.held_digests(UnixMillis::now());
	count_u64(digests.expect("the fixture journal lock is live").len())
}

tb_assert_spec! {
	pub ClusterFloodThreeColoniesSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(GOSSIP_INGRESS_SIGNED_BY_GATEWAY, exactly!(1), equals!(true)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0)),
			(events::CLUSTER_GOSSIP_ORIGIN_UNKNOWN, exactly!(0))
		]
	}
}

// One rumor reaches three colonies by flood.
//
// The three gateways trust one another and form a chain: "main" dials "other",
// and "other" dials "third". No beat runs. "third" alone holds an ingress
// servlet.
//
// - A publish at "main" with two hops reaches "third" through "other" (GOSSIP_CONVERGED).
// - Every hop admits it, because all three colonies are inside one flood (CLUSTER_GOSSIP_REFUSED).
// - The servlet at "third" receives the frame "main" signed (GOSSIP_INGRESS_SIGNED_BY_GATEWAY).
tb_scenario! {
	name: cluster_flood_reaches_three_colonies,
	spec: ClusterFloodThreeColoniesSpec,
	environment Bare {
		context: uniform_trust_ctx(),
		exec: |SetupEnv { trace, context: ctx }| async move {
			let mut conf_third = quiet_flood_conf(&ctx.third, &ctx.peers_of_third, vec![], &ctx.journal_of_third);
			conf_third.gossip.ingress = Some(servlet_ingress("rumor"));

			let third = start_cluster(&trace, conf_third).await?;
			let ingress_hive = start_rumor_hive(trace.share(), hive_plane_certs(&ctx.third), ctx.main.key.to_owned()).await?;
			ingress_hive.register_with_cluster(third.addr()).await?;

			let dials_third = vec![third.addr().to_string()];
			let conf_other = quiet_flood_conf(&ctx.other, &ctx.peers_of_other, dials_third, &ctx.journal_of_other);
			let other = start_cluster(&trace, conf_other).await?;

			let dials_other = vec![other.addr().to_string()];
			let conf_main = quiet_flood_conf(&ctx.main, &ctx.peers_of_main, dials_other, &ctx.journal_of_main);
			let main = start_cluster(&trace, conf_main).await?;

			publish_at(&trace, &ctx.main, &main, b"three-colony-rumor", 2).await?;

			let journals = [
				Arc::clone(&ctx.journal_of_main),
				Arc::clone(&ctx.journal_of_other),
				Arc::clone(&ctx.journal_of_third),
			];

			let converged = wait_for_gossip_converged(journals, 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

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
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0)),
			(events::CLUSTER_GOSSIP_ORIGIN_UNKNOWN, exactly!(0))
		]
	}
}

// Anti-entropy repairs a rumor across colonies.
//
// - "main" publishes at zero hops, so the rumor moves by reconcile alone.
// - "other" learns it only when the beat of "main" reconciles digests and pushes it (GOSSIP_CONVERGED).
tb_scenario! {
	name: cluster_flood_repairs_a_rumor_across_colonies,
	spec: ClusterFloodRepairSpec,
	environment Bare {
		context: uniform_trust_ctx(),
		exec: |SetupEnv { trace, context: ctx }| async move {
			let conf_other = quiet_flood_conf(&ctx.other, &ctx.peers_of_other, vec![], &ctx.journal_of_other);
			let other = start_cluster(&trace, conf_other).await?;

			let dials_other = vec![other.addr().to_string()];
			let conf_main = flood_conf(&ctx.main, &ctx.peers_of_main, dials_other, &ctx.journal_of_main);
			let main = start_cluster(&trace, conf_main).await?;

			publish_at(&trace, &ctx.main, &main, b"repaired-rumor", 0).await?;

			let journals = [Arc::clone(&ctx.journal_of_main), Arc::clone(&ctx.journal_of_other)];
			let converged = wait_for_gossip_converged(journals, 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

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
			(FLOOD_THIRD_COLONY_PROMOTED, exactly!(1), equals!(true)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Peer exchange discovers a third colony.
//
// "main" and "third" each dial the seed "other", and all three beat.
//
// - The seed learns both from their advertisements and promotes them.
// - The seed's reconcile reply shares "third" with "main" over peer exchange.
// - "main" probes that address, the answer proves flood membership, and "third" joins its beat targets.
tb_scenario! {
	name: cluster_flood_peer_exchange_discovers_a_third_colony,
	spec: ClusterFloodDiscoverySpec,
	environment Bare {
		context: uniform_trust_ctx(),
		exec: |SetupEnv { trace, context: ctx }| async move {
			let conf_other = flood_conf(&ctx.other, &ctx.peers_of_other, vec![], &ctx.journal_of_other);
			let other = start_cluster(&trace, conf_other).await?;
			let dials_other = vec![other.addr().to_string()];

			let conf_third = flood_conf(&ctx.third, &ctx.peers_of_third, dials_other.clone(), &ctx.journal_of_third);
			let third = start_cluster(&trace, conf_third).await?;

			let conf_main = flood_conf(&ctx.main, &ctx.peers_of_main, dials_other, &ctx.journal_of_main);
			let table_of_main = Arc::clone(conf_main.peer.table());
			let third_addr = dial_admitted_by(&conf_main, third.addr().to_string());
			let main = start_cluster(&trace, conf_main).await?;

			// The spec counts three discoveries: the seed promotes both
			// dialers, and "main" promotes "third".
			wait_for_promoted(&table_of_main, 1, 100, Duration::from_millis(100)).await;
			wait_for_discoveries(&trace, 3).await;

			let targets = table_of_main.target_set()?;
			trace.event_with(FLOOD_THIRD_COLONY_PROMOTED, &[], targets.contains(&third_addr))?;

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
			(FLOOD_BRIDGE_JOINED, exactly!(1), equals!(true)),
			(GOSSIP_PUBLISH_STATUS, exactly!(4), equals!(TransitStatus::Ok)),
			(GOSSIP_ORIGIN_SETTLED, exactly!(2), equals!(true)),
			(FLOOD_HELD_BY_MAIN, exactly!(1), equals!(3u64)),
			(FLOOD_HELD_BY_OTHER, exactly!(1), equals!(4u64)),
			(FLOOD_HELD_BY_THIRD, exactly!(1), equals!(2u64)),
			(events::CLUSTER_GOSSIP_ORIGIN_UNKNOWN, exactly!(2)),
			(events::CLUSTER_GOSSIP_ORIGIN_REFUSED_BY_PEER, exactly!(2)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0))
		]
	}
}

// Trust stores that differ divide the namespace into subnets.
//
// "other" is a bridge: it trusts "main" and "third", and each of them trusts
// it alone. No beat runs, so every rumor moves by flood and the counts are
// exact. "main" publishes twice, "third" once, and the bridge once.
//
// - The bridge accepts every rumor and holds all four (FLOOD_HELD_BY_OTHER).
// - "third" refuses the origin "main" once, and the bridge then offers it no further rumor of that origin.
// - "main" refuses the origin "third" the same way, so neither side holds the other's rumors.
// - The bridge's own rumor reaches both sides, because both trust the bridge.
// - A refused origin costs the bridge no score (CLUSTER_GOSSIP_RELAY_WEAKENED).
tb_scenario! {
	name: cluster_flood_bridge_relays_only_what_each_side_can_verify,
	spec: ClusterFloodBridgeSpec,
	environment Bare {
		context: bridged_trust_ctx(),
		exec: |SetupEnv { trace, context: ctx }| async move {
			let conf_main = quiet_flood_conf(&ctx.main, &ctx.peers_of_main, vec![], &ctx.journal_of_main);
			let table_of_main = Arc::clone(conf_main.peer.table());
			let main = start_cluster(&trace, conf_main).await?;

			let conf_third = quiet_flood_conf(&ctx.third, &ctx.peers_of_third, vec![], &ctx.journal_of_third);
			let table_of_third = Arc::clone(conf_third.peer.table());
			let third = start_cluster(&trace, conf_third).await?;

			let dials_both = vec![main.addr().to_string(), third.addr().to_string()];
			let conf_other = quiet_flood_conf(&ctx.other, &ctx.peers_of_other, dials_both, &ctx.journal_of_other);
			let other = start_cluster(&trace, conf_other).await?;

			// Each side gets the bridge as a verified peer, which a beat would
			// otherwise discover. The spare config lends its dial policy to
			// admit an address that exists only now.
			let dial_policy = federation_conf(&ctx.main, Arc::clone(&ctx.peers_of_main), vec![], 1);
			let bridge_addr = dial_admitted_by(&dial_policy, other.addr().to_string());
			let main_joined = table_of_main.promote(bridge_addr, None, UnixMillis::now())?;
			let third_joined = table_of_third.promote(bridge_addr, None, UnixMillis::now())?;
			trace.event_with(FLOOD_BRIDGE_JOINED, &[], main_joined && third_joined)?;

			publish_at(&trace, &ctx.main, &main, b"bridge-main-1", 2).await?;

			let third_refused_main = wait_for_refused_origins(&trace, 1).await;
			trace.event_with(GOSSIP_ORIGIN_SETTLED, &[], third_refused_main)?;

			publish_at(&trace, &ctx.main, &main, b"bridge-main-2", 2).await?;
			publish_at(&trace, &ctx.third, &third, b"bridge-third-1", 2).await?;

			let main_refused_third = wait_for_refused_origins(&trace, 2).await;
			trace.event_with(GOSSIP_ORIGIN_SETTLED, &[], main_refused_third)?;

			publish_at(&trace, &ctx.other, &other, b"bridge-other-1", 1).await?;

			let held_by_other = held_after_settling(&ctx.journal_of_other, 4).await;
			let held_by_main = held_after_settling(&ctx.journal_of_main, 3).await;
			let held_by_third = held_after_settling(&ctx.journal_of_third, 2).await;
			trace.event_with(FLOOD_HELD_BY_OTHER, &[], held_by_other)?;
			trace.event_with(FLOOD_HELD_BY_MAIN, &[], held_by_main)?;
			trace.event_with(FLOOD_HELD_BY_THIRD, &[], held_by_third)?;

			other.stop();
			third.stop();
			main.stop();
			Ok(())
		}
	}
}
