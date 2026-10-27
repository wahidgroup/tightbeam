//! The multi-organization federation tests of the flood boundary at the
//! gateway edge.
//!
//! One transport trust store admits two colonies and one outside identity:
//!
//! - Colony "main" runs the entry and origin gateways.
//! - Colony "other" holds one trusted gateway identity.
//! - The store also trusts a third identity, which belongs to no colony.
//!
//! Both colonies are inside one flood: gossip and work cross the organization
//! edge, and every in-organization route stays intact. Every gossip path
//! refuses the outside identity, because it carries no colony URN.
//!
//! Transitive discovery over live beats lives in `federation`.

use super::common::*;
use super::federation::{drive_until_advertised, federation_conf, flood_ad_rumor, type_route_count};
use super::gossip::relay_application_rumor;
use tightbeam::utils::time::{Clock, ManualClock};

#[cfg(feature = "testing-fdr")]
use tightbeam::testing::fdr::FdrConfig;
#[cfg(feature = "testing-fdr")]
use tightbeam::testing::specs::csp::ProcessBuildError;
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
	/// inside the flood. It carries the full gateway certificates, so a
	/// scenario can also run it as a live gateway.
	neighbor: Arc<ClusterTestCerts>,
	/// A "main" member whose advertisement claims a type from a foreign realm.
	/// The outer relay gate admits it and the inner advertisement admission
	/// must drop it.
	rogue_key: Secp256k1SigningKey,
	/// A trusted transport identity with no colony SAN.
	stranger_key: Secp256k1SigningKey,
	/// The peer-plane store of `entry`, without its own identity. Peer
	/// membership wins on the hive plane, so a member's hive registrations
	/// must not verify on its own peer store.
	peers_of_entry: Arc<dyn CertificateTrust>,
	/// The peer-plane store of `origin`, without its own identity.
	peers_of_origin: Arc<dyn CertificateTrust>,
	/// The peer-plane store of `neighbor`, without its own identity.
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

/// A member configuration with the advertise beat off. A live beat races
/// direct advertisements against slate rumors, so a rumor can land after a
/// fresher advertisement and drop as stale. Scenarios on it inject their
/// control-plane frames, so each trace stays exact enough to refine a process.
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
			(events::CLUSTER_PEER_AD_LEARNED, exactly!(1)),
			(events::CLUSTER_PEER_ROUTES_INSTALLED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_GOSSIP_ADMITTED, exactly!(3)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(events::CLUSTER_PEER_AD_DROPPED, exactly!(1))
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
fn multi_org_fdr() -> Result<FdrConfig, ProcessBuildError> {
	Ok(FdrConfig {
		seeds: 2,
		max_depth: 16,
		max_internal_run: 4,
		timeout_ms: 5000,
		specs: vec![MultiOrgControlPlane::process()?],
		fail_fast: true,
		..Default::default()
	})
}

#[cfg(feature = "testing-fdr")]
fn multi_org_config() -> Result<ScenarioConfig, Box<dyn core::error::Error>> {
	let builder = ScenarioConfig::builder()
		.with_spec(ClusterMultiOrgBoundarySpec::latest())
		.with_csp(MultiOrgControlPlane);

	Ok(builder.with_fdr(multi_org_fdr()?).build()?)
}

#[cfg(not(feature = "testing-fdr"))]
fn multi_org_config() -> Result<ScenarioConfig, Box<dyn core::error::Error>> {
	let builder = ScenarioConfig::builder()
		.with_spec(ClusterMultiOrgBoundarySpec::latest())
		.with_csp(MultiOrgControlPlane);

	Ok(builder.build()?)
}

/// The configuration that grades `spec`, refines the run against the
/// multi-organization control plane, and expects `expect`.
#[cfg(feature = "testing-fdr")]
fn multi_org_model_config(
	spec: &'static tightbeam::testing::macros::BuiltAssertSpec,
	expect: Expect,
) -> Result<ScenarioConfig, Box<dyn core::error::Error>> {
	let builder = ScenarioConfig::builder().with_spec(spec).with_fdr(multi_org_fdr()?);
	Ok(builder.with_expect(expect).build()?)
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
			assert_eq!(status, TransitStatus::Ok, "the entry gateway admits the advertisement rumor of the origin");
			assert_eq!(type_route_count(&gateway_entry, "ping"), 1, "the rumor of the origin installs one ping route");

			let mut client = connect_cluster(&ctx.entry, gateway_entry.addr()).await?;

			let servlet_frame = emit_ping_work(&mut client, &ctx.entry.key, b"multi-org-work").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			assert_eq!(ping_response.doubled, 42, "the ping servlet doubles the request");

			// Cross-organization relay: colony "other" is inside the flood,
			// so the gateway admits its rumor.
			let neighbor = &ctx.neighbor.key;
			let replied = relay_application_rumor(&ctx.entry, &gateway_entry, neighbor, neighbor, "other-org").await?;
			assert_eq!(replied, TransitStatus::Ok, "the gateway admits the rumor");

			// No-colony relay: a trusted identity outside every organization
			// is outside the flood, so only the membership proof can refuse.
			let stranger = &ctx.stranger_key;
			let replied = relay_application_rumor(&ctx.entry, &gateway_entry, stranger, stranger, "stranger").await?;
			assert_eq!(replied, TransitStatus::PermissionDenied, "the gateway refuses a stranger's rumor");

			// The gateway admits the relay envelope, so only the inner realm
			// admission can drop this one.
			let foreign_ns = ColonyNamespace::new("tightbeam", "other-realm")?;
			let foreign_type = foreign_ns.servlet("ping")?;
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
			assert_eq!(
				status,
				TransitStatus::Ok,
				"the entry gateway admits the relay envelope of the rogue advertisement"
			);

			assert_eq!(type_route_count(&gateway_entry, "ping"), 1, "the in-organization route survives every refusal");

			gateway_entry.stop();
			gateway_origin.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// Polls until gateways have learned `count` slate rumors, or five seconds
/// pass. The spec judges the count, so the wait leaves the verdict to the spec.
async fn wait_for_learned_slates(trace: &TraceCollector, count: usize) {
	let learned = || trace.recorded(events::CLUSTER_PEER_AD_LEARNED) >= count;
	poll_until(50, Duration::from_millis(100), learned).await;
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
			(events::CLUSTER_PEER_AD_DROPPED, exactly!(0))
		]
	}
}

// A real gateway's beat drives this run, so the counts are bounds. The entry
// gateway admits the neighbor's direct advertisement and the slate rumor its
// beat floods, because colony "other" is inside the flood.
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

			assert!(cluster.peer_routes()?.is_empty(), "an empty neighbor slate installs no route");

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
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_PEER_HINTS_LEARNED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1))
		]
	}
}

// A gateway of colony "other" serves work by direct peering, through the route
// that its signed advertisement installs at the entry gateway.
//
// - The advertiser is inside the flood, so the peer table learns it.
// - The gateway that answers is the advertiser, so the entry forwards the work.
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
			let gateway_entry = start_cluster(&trace, entry_conf).await?;

			let neighbor_key = &ctx.neighbor.key;
			let neighbor_addr = gateway_neighbor.addr().to_string();
			let claimed = neighbor_addr.as_bytes();
			let types = vec![servlet_urn("ping")];
			let ad_reply = advertise_peer_signed(&ctx.entry, neighbor_key, &gateway_entry, claimed, types).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(gateway_entry.peer_servlets()?.len(), 1, "the advertisement of the neighbor installs its route");

			let mut client = connect_cluster(&ctx.entry, gateway_entry.addr()).await?;

			let servlet_frame = emit_ping_work(&mut client, &ctx.entry.key, b"neighbor-work").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			assert_eq!(ping_response.doubled, 42, "the ping servlet doubles the request");

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
			(events::CLUSTER_PEER_ADVERTISED, at_least!(3)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0)),
			(events::CLUSTER_GOSSIP_FANOUT_UNREACHED, exactly!(0)),
			(events::CLUSTER_PEER_AD_LEARNED, at_least!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1))
		]
	}
}

// A configured peer of colony "other" keeps its routes through two live beats
// of the entry gateway, after its signed advertisement installs them.
//
// - The neighbor admits the advertisement of each beat and the slate rumor
//   that the first beat floods, and each reconcile leaves the routes in place.
// - The gateway that answers is the advertiser, so the entry forwards the work.
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
			let ad_reply = advertise_peer_signed(&ctx.entry, neighbor_key, &gateway_entry, claimed, types).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(gateway_entry.peer_servlets()?.len(), 1, "the advertisement of the neighbor installs its route");

			// One advertisement is the neighbor's own, placed above. The other
			// two are the entry gateway's, one from each of two beats.
			drive_until_advertised(&clock, &trace, 3).await;

			let routes = type_route_count(&gateway_entry, "ping");
			assert_eq!(routes, 1, "the neighbor keeps its route through the beats");

			let mut client = connect_cluster(&ctx.entry, gateway_entry.addr()).await?;

			let servlet_frame = emit_ping_work(&mut client, &ctx.entry.key, b"neighbor-anchor-work").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			assert_eq!(ping_response.doubled, 42, "the ping servlet doubles the request");

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
	config: multi_org_model_config(ClusterMultiOrgModelSpec::latest(), Expect::Pass),
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
	config: multi_org_model_config(ClusterMultiOrgViolationSpec::latest(), Expect::Violation(Layer::Refinement)),
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
