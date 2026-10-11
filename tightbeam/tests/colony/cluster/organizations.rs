//! Multi-organization federation tests for the flood boundary at the
//! gateway edge.
//!
//! One transport trust store admits two colonies and one outside identity:
//!
//! - Colony "main" runs the entry and origin gateways.
//! - Colony "other" holds one trusted gateway identity.
//! - A third identity is trusted for transport but belongs to no colony.
//!
//! Both colonies are inside one flood: gossip and work cross the organization
//! edge, and every in-organization route stays intact. The outside identity
//! is refused on every gossip path, because it carries no colony URN.
//!
//! Transitive discovery over live beats lives in `federation`.

use super::common::*;
use super::federation::{drive_until_advertised, federation_conf, flood_ad_rumor, type_route_count};
use super::gossip::{relay_application_rumor, RumorRelay};
use tightbeam::utils::time::{Clock, ManualClock};

#[cfg(feature = "testing-fdr")]
use tightbeam::testing::fdr::FdrConfig;
#[cfg(feature = "testing-fdr")]
use tightbeam::testing::{Expect, Layer};

/// Two organizations and one drifter under a single transport trust store.
struct MultiOrgCtx {
	/// The entry member gateway of colony "main", built by
	/// [`member_identity`].
	entry: Arc<ClusterTestCerts>,
	/// The origin member gateway of colony "main", built by
	/// [`member_identity`].
	origin: Arc<ClusterTestCerts>,
	/// The gateway identity of colony "other". Transport admits it, and it is
	/// inside the flood. It carries full gateway certs, so a scenario can also
	/// run it as a live gateway.
	neighbor: Arc<ClusterTestCerts>,
	/// A "main" member whose advertisement claims a type from a foreign realm.
	/// The outer relay gate admits it and the inner advertisement admission
	/// must drop it.
	rogue_key: Secp256k1SigningKey,
	/// A trusted transport identity with no colony SAN.
	stranger_key: Secp256k1SigningKey,
	/// The peer-plane store for `entry`, excluding its own identity. Peer
	/// membership wins on the hive plane, so a member's hive registrations
	/// must not verify on its own peer store.
	peers_of_entry: Arc<dyn CertificateTrust>,
	/// The peer-plane store for `origin`, excluding its own identity.
	peers_of_origin: Arc<dyn CertificateTrust>,
	/// The peer-plane store for `neighbor`, excluding its own identity.
	peers_of_neighbor: Arc<dyn CertificateTrust>,
}

fn multi_org_ctx() -> MultiOrgCtx {
	let (cert_entry, key_entry) = member_identity("Org Main Entry Gateway");
	let (cert_origin, key_origin) = member_identity("Org Main Origin Gateway");

	let other_urn = colony_ns().colony("other").expect("static colony name");
	let (cert_neighbor, neighbor_key) = colony_identity("Org Other Gateway", &other_urn);
	let (cert_rogue, rogue_key) = member_identity("Org Main Rogue");

	let stranger = stranger_gateway_certs();

	let trust = combined_trust(&[&cert_entry, &cert_origin, &cert_neighbor, &cert_rogue, &stranger.cert]);
	let peers_of_entry = combined_trust(&[&cert_origin, &cert_neighbor, &cert_rogue, &stranger.cert]);
	let peers_of_origin = combined_trust(&[&cert_entry, &cert_neighbor, &cert_rogue, &stranger.cert]);
	let peers_of_neighbor = combined_trust(&[&cert_entry, &cert_origin, &cert_rogue, &stranger.cert]);

	MultiOrgCtx {
		entry: Arc::new(GatewayCerts { cert: cert_entry, key: key_entry, trust: Arc::clone(&trust) }),
		origin: Arc::new(GatewayCerts { cert: cert_origin, key: key_origin, trust: Arc::clone(&trust) }),
		neighbor: Arc::new(GatewayCerts { cert: cert_neighbor, key: neighbor_key, trust }),
		rogue_key,
		stranger_key: stranger.key,
		peers_of_entry,
		peers_of_origin,
		peers_of_neighbor,
	}
}

/// A live advertise beat races direct advertisements against slate rumors, so
/// a rumor can land after a fresher advertisement and drop as stale. Scenarios
/// built on this config inject their control-plane frames instead, which is
/// what keeps their traces exact enough to refine a process.
fn quiet_member_conf(certs: &ClusterTestCerts, peer_trust: Arc<dyn CertificateTrust>) -> ClusterConfig {
	let mut conf = federation_conf(certs, peer_trust, vec![], 1);
	conf.peer.advertise_interval = None;
	conf
}

tb_assert_spec! {
	pub ClusterMultiOrgBoundarySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_PEER_AD_LEARNED, exactly!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(WORK_ECHOED, exactly!(1), equals!(42u64)),
			(GOSSIP_RELAY_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_STRANGER_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_PEER_AD_DROPPED, exactly!(1)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64))
		]
	}
}

// Each event has exactly one legal position only because the beats are off.
tb_process_spec! {
	pub MultiOrgControlPlane,
	events {
		observable {
			events::CLUSTER_PEER_AD_LEARNED,
			events::CLUSTER_WORK_FORWARDED,
			events::CLUSTER_GOSSIP_REFUSED,
			events::CLUSTER_PEER_AD_DROPPED
		}
		hidden { }
	}
	states {
		Isolated => { events::CLUSTER_PEER_AD_LEARNED => Federated },
		Federated => { events::CLUSTER_WORK_FORWARDED => Routed },
		Routed => { events::CLUSTER_GOSSIP_REFUSED => EdgeRefused },
		EdgeRefused => { events::CLUSTER_PEER_AD_DROPPED => EdgeDropped },
		EdgeDropped => { }
	}
	terminal { EdgeDropped }
}

/// FDR bounds for the multi-organization control plane. The process has no
/// hidden events, so `max_internal_run` guards against model regressions.
#[cfg(feature = "testing-fdr")]
fn multi_org_fdr() -> FdrConfig {
	FdrConfig {
		seeds: 2,
		max_depth: 16,
		max_internal_run: 4,
		timeout_ms: 5000,
		specs: vec![MultiOrgControlPlane::process()],
		fail_fast: true,
		..Default::default()
	}
}

#[cfg(feature = "testing-fdr")]
fn multi_org_config() -> Result<ScenarioConfig, ScenarioConfigError> {
	ScenarioConfig::builder()
		.with_spec(ClusterMultiOrgBoundarySpec::latest())
		.with_csp(MultiOrgControlPlane)
		.with_fdr(multi_org_fdr())
		.build()
}

#[cfg(not(feature = "testing-fdr"))]
fn multi_org_config() -> Result<ScenarioConfig, ScenarioConfigError> {
	ScenarioConfig::builder()
		.with_spec(ClusterMultiOrgBoundarySpec::latest())
		.with_csp(MultiOrgControlPlane)
		.build()
}

tb_scenario! {
	name: cluster_flood_admits_neighbor_colony_and_refuses_the_stranger,
	config: multi_org_config(),
	environment Hive {
		context: multi_org_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_ping_hive(trace, Arc::clone(&ctx.origin), None).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let gateway_origin = start_cluster(&trace, quiet_member_conf(&ctx.origin, Arc::clone(&ctx.peers_of_origin))).await?;
			let gateway_entry = start_cluster(&trace, quiet_member_conf(&ctx.entry, Arc::clone(&ctx.peers_of_entry))).await?;

			hive.register_with_cluster(gateway_origin.addr()).await?;

			// This publish stands in for the origin's own publish beat.
			let origin_addr = gateway_origin.addr().to_string();
			let status = flood_ad_rumor(
				&ctx.entry,
				&ctx.origin.key,
				&gateway_entry,
				origin_addr.as_bytes(),
				vec![servlet_urn("ping")],
				0,
				b"origin-ad",
			)
			.await?;
			trace.event_with(PEER_AD_STATUS, &[], status)?;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], count_u64(type_route_count(&gateway_entry, "ping")))?;

			let mut client = connect_cluster(&ctx.entry, gateway_entry.addr()).await?;
			trace.event(WORK_SENT)?;

			let servlet_frame = emit_ping_work(&mut client, &ctx.entry.key, b"multi-org-work").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;

			// Cross-organization relay: colony "other" is inside the flood,
			// so its rumor is admitted.
			let neighbor = &ctx.neighbor.key;
			relay_application_rumor(&trace, &ctx.entry, &gateway_entry, neighbor, neighbor, "other-org").await?;

			// No-colony relay: a trusted identity outside every organization
			// is outside the flood, so only the membership proof can refuse.
			let stranger = &ctx.stranger_key;
			let refused = RumorRelay { origin_key: stranger, relay_key: stranger, marker: GOSSIP_STRANGER_STATUS };
			refused.send(&trace, &ctx.entry, &gateway_entry, "stranger").await?;

			// The relay envelope is admitted, so only the inner realm
			// admission can drop this one.
			let foreign_ns =
				ColonyNamespace::new("tightbeam", "other-realm").map_err(|_| TightBeamError::MissingResponse)?;
			let foreign_type = foreign_ns.servlet("ping").map_err(|_| TightBeamError::MissingResponse)?;
			let status = flood_ad_rumor(
				&ctx.entry,
				&ctx.rogue_key,
				&gateway_entry,
				PEER_GATEWAY_ADDR,
				vec![foreign_type],
				0,
				b"rogue-realm-ad",
			)
			.await?;
			trace.event_with(GOSSIP_PUBLISH_STATUS, &[], status)?;

			// The in-organization route stays intact through every refusal.
			trace.event_with(PEER_ROUTES_AFTER, &[], count_u64(type_route_count(&gateway_entry, "ping")))?;

			gateway_entry.stop();
			gateway_origin.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// Polls until gateways have learned `count` slate rumors, or five seconds
/// pass.
async fn wait_for_learned_slates(trace: &TraceCollector, count: usize) -> bool {
	let learned = || trace.recorded(events::CLUSTER_PEER_AD_LEARNED) >= count;
	poll_until(50, Duration::from_millis(100), learned).await
}

tb_assert_spec! {
	pub ClusterLiveNeighborGatewaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, at_least!(2)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0)),
			(events::CLUSTER_GOSSIP_FANOUT_UNREACHED, exactly!(0)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(events::CLUSTER_PEER_AD_LEARNED, at_least!(1)),
			(events::CLUSTER_PEER_AD_DROPPED, exactly!(0)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(0u64))
		]
	}
}

// A real gateway's beat drives this run, so the counts are bounds rather than
// exacts. The entry gateway admits the neighbor's direct advertisement and the
// slate rumor its beat floods, because colony "other" is inside the flood. The
// slate is empty, so the rumor is learned and installs no route.
tb_scenario! {
	name: cluster_live_neighbor_beat_floods_its_slate_across_the_org_edge,
	spec: ClusterLiveNeighborGatewaySpec,
	environment Cluster {
		context: multi_org_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_cluster(&trace, quiet_member_conf(&ctx.entry, Arc::clone(&ctx.peers_of_entry))).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			// The neighbor gateway beats on a clock only this test moves.
			let clock = Arc::new(ManualClock::default());
			let mut neighbor_conf = federation_conf(&ctx.neighbor, Arc::clone(&ctx.peers_of_neighbor), vec![cluster.addr().to_string()], 1);
			neighbor_conf.clock = Arc::clone(&clock) as Arc<dyn Clock>;
			let gateway_neighbor = start_cluster(&trace, neighbor_conf).await?;

			// The beat floods the slate rumor after it advertises, so the
			// scenario also waits for the entry gateway to learn that rumor.
			drive_until_advertised(&clock, &trace, 2).await;
			wait_for_learned_slates(&trace, 1).await;

			trace.event_with(PEER_ROUTES_AFTER, &[], count_u64(cluster.peer_routes()?.len()))?;

			gateway_neighbor.stop();
			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterNeighborColonySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(PEER_NEIGHBOR_CANDIDATES, exactly!(1), equals!(1u64)),
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(WORK_ECHOED, exactly!(1), equals!(42u64))
		]
	}
}

// A gateway of another colony serves work by direct peering.
//
// The neighbor is a gateway of colony "other". It serves ping, and the
// scenario places its advertisement at the entry gateway, signed with the
// neighbor's key.
//
// - The advertisement installs its route (PEER_ROUTES_AFTER).
// - The advertiser is inside the flood, so the peer table learns it (PEER_NEIGHBOR_CANDIDATES).
// - Work is forwarded and served, because the gateway that answers is the advertiser (WORK_ECHOED).
tb_scenario! {
	name: cluster_neighbor_colony_serves_work_and_enters_discovery,
	spec: ClusterNeighborColonySpec,
	environment Hive {
		context: multi_org_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_ping_hive(trace, Arc::clone(&ctx.neighbor), None).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let neighbor_conf = quiet_member_conf(&ctx.neighbor, Arc::clone(&ctx.peers_of_neighbor));
			let gateway_neighbor = start_cluster(&trace, neighbor_conf).await?;
			hive.register_with_cluster(gateway_neighbor.addr()).await?;

			let entry_conf = quiet_member_conf(&ctx.entry, Arc::clone(&ctx.peers_of_entry));
			let table = Arc::clone(entry_conf.peer.table());
			let gateway_entry = start_cluster(&trace, entry_conf).await?;

			let neighbor_key = &ctx.neighbor.key;
			let neighbor_addr = gateway_neighbor.addr().to_string();
			let claimed = neighbor_addr.as_bytes();
			let types = vec![servlet_urn("ping")];
			advertise_peer_signed(&trace, &ctx.entry, neighbor_key, &gateway_entry, claimed, types).await?;

			let (candidates, _) = table.learned()?;
			trace.event_with(PEER_NEIGHBOR_CANDIDATES, &[], count_u64(candidates))?;

			let mut client = connect_cluster(&ctx.entry, gateway_entry.addr()).await?;
			trace.event(WORK_SENT)?;

			let servlet_frame = emit_ping_work(&mut client, &ctx.entry.key, b"neighbor-work").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;

			gateway_entry.stop();
			gateway_neighbor.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterNeighborAnchorSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(3)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0)),
			(events::CLUSTER_GOSSIP_FANOUT_UNREACHED, exactly!(0)),
			(events::CLUSTER_PEER_AD_LEARNED, at_least!(1)),
			(PEER_ROUTES_AFTER_BEATS, exactly!(1), equals!(1u64)),
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(WORK_ECHOED, exactly!(1), equals!(42u64))
		]
	}
}

// A configured peer of another colony keeps its routes through live beats.
//
// The neighbor is a gateway of colony "other". The entry gateway lists it as a
// peer and beats on a clock only this test moves. The neighbor serves ping,
// and the scenario places its advertisement at the entry gateway, signed with
// the neighbor's key. Two beats then dial the neighbor.
//
// - Each beat advertises to the neighbor, which admits it (CLUSTER_PEER_ADVERTISED).
// - Each beat reconciles with the neighbor, and the routes stay (PEER_ROUTES_AFTER_BEATS).
// - The neighbor admits the slate rumor the first beat floods (CLUSTER_PEER_AD_LEARNED).
// - Work is forwarded and served, because the gateway that answers is the advertiser (WORK_ECHOED).
tb_scenario! {
	name: cluster_neighbor_anchor_keeps_its_routes_through_the_beat,
	spec: ClusterNeighborAnchorSpec,
	environment Hive {
		context: multi_org_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_ping_hive(trace, Arc::clone(&ctx.neighbor), None).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let neighbor_conf = quiet_member_conf(&ctx.neighbor, Arc::clone(&ctx.peers_of_neighbor));
			let gateway_neighbor = start_cluster(&trace, neighbor_conf).await?;
			hive.register_with_cluster(gateway_neighbor.addr()).await?;

			// The entry gateway beats on a clock only this test moves.
			let clock = Arc::new(ManualClock::default());
			let neighbor_addr = gateway_neighbor.addr().to_string();
			let peers_of_entry = Arc::clone(&ctx.peers_of_entry);
			let mut entry_conf = federation_conf(&ctx.entry, peers_of_entry, vec![neighbor_addr.clone()], 1);
			entry_conf.clock = Arc::clone(&clock) as Arc<dyn Clock>;

			let gateway_entry = start_cluster(&trace, entry_conf).await?;
			let neighbor_key = &ctx.neighbor.key;
			let claimed = neighbor_addr.as_bytes();
			let types = vec![servlet_urn("ping")];
			advertise_peer_signed(&trace, &ctx.entry, neighbor_key, &gateway_entry, claimed, types).await?;

			// One advertisement is the neighbor's own, placed above. The other
			// two are the entry gateway's, one from each of two beats.
			drive_until_advertised(&clock, &trace, 3).await;

			let routes = type_route_count(&gateway_entry, "ping");
			trace.event_with(PEER_ROUTES_AFTER_BEATS, &[], count_u64(routes))?;

			let mut client = connect_cluster(&ctx.entry, gateway_entry.addr()).await?;
			trace.event(WORK_SENT)?;

			let servlet_frame = emit_ping_work(&mut client, &ctx.entry.key, b"neighbor-anchor-work").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;

			gateway_entry.stop();
			gateway_neighbor.stop();
			hive.stop();
			Ok(())
		}
	}
}

#[cfg(feature = "testing-fdr")]
tb_assert_spec! {
	pub ClusterMultiOrgModelSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_AD_LEARNED, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_PEER_AD_DROPPED, exactly!(1))
		]
	}
}

#[cfg(feature = "testing-fdr")]
tb_scenario! {
	name: cluster_multi_org_control_plane_refines_model,
	config: ScenarioConfig::builder()
		.with_spec(ClusterMultiOrgModelSpec::latest())
		.with_fdr(multi_org_fdr())
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(events::CLUSTER_PEER_AD_LEARNED)?;
			trace.event(events::CLUSTER_WORK_FORWARDED)?;
			trace.event(events::CLUSTER_GOSSIP_REFUSED)?;
			trace.event(events::CLUSTER_PEER_AD_DROPPED)?;
			Ok(())
		}
	}
}

#[cfg(feature = "testing-fdr")]
tb_assert_spec! {
	pub ClusterMultiOrgViolationSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_AD_LEARNED, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_PEER_AD_DROPPED, exactly!(1))
		]
	}
}

// This order keeps every count legal, so the L1 spec passes and only the
// refinement rejects it.
#[cfg(feature = "testing-fdr")]
tb_scenario! {
	name: cluster_multi_org_model_rejects_forward_before_learn,
	config: ScenarioConfig::builder()
		.with_spec(ClusterMultiOrgViolationSpec::latest())
		.with_fdr(multi_org_fdr())
		.with_expect(Expect::Violation(Layer::Refinement))
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(events::CLUSTER_WORK_FORWARDED)?;
			trace.event(events::CLUSTER_PEER_AD_LEARNED)?;
			trace.event(events::CLUSTER_GOSSIP_REFUSED)?;
			trace.event(events::CLUSTER_PEER_AD_DROPPED)?;
			Ok(())
		}
	}
}
