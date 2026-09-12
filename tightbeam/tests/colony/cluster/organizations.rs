//! Multi-organization federation (colony boundary at the gateway edge).
//!
//! One transport trust store, two colonies: "main" runs the entry and origin
//! gateways, "other" holds one trusted gateway identity, and a third identity
//! is trusted for transport but belongs to no colony. Work federates inside
//! "main" while every cross-organization control-plane frame is refused at the
//! edge, weakening no in-organization route.
//!
//! The boundary scenario injects every control-plane frame with the advertise
//! beats off, which makes the trace exact enough for the L2 and L3
//! refinements. A separate scenario runs the foreign gateway live so its own
//! beat produces those frames. Beat-driven discovery lives in `federation`.

use super::common::*;
use super::federation::{federation_conf, flood_ad_rumor, type_route_count};
use super::gossip::relay_application_rumor;

#[cfg(feature = "testing-fdr")]
use tightbeam::testing::fdr::FdrConfig;
#[cfg(feature = "testing-fdr")]
use tightbeam::testing::{Expect, Layer};

/// Two organizations and one drifter under a single transport trust
/// store.
///
/// - `entry`, `origin`: member gateways of colony "main" (see [`member_identity`]).
/// - `foreign`: gateway identity of colony "other". Transport admits
///   it, the colony gate must not. Full gateway certs, so a scenario
///   can also run it as a live gateway.
/// - `rogue_key`: a "main" member whose advertisement claims a type
///   from a foreign realm. The outer relay gate admits it, the inner
///   advertisement admission must drop it.
/// - `stranger_key`: trusted transport identity with no colony SAN.
struct MultiOrgCtx {
	entry: Arc<ClusterTestCerts>,
	origin: Arc<ClusterTestCerts>,
	foreign: Arc<ClusterTestCerts>,
	rogue_key: Secp256k1SigningKey,
	stranger_key: Secp256k1SigningKey,
	/// Peer-plane stores per gateway, excluding the gateway's own
	/// identity: peer membership wins on the hive plane, so a member's
	/// hive registrations must not verify on its own peer store.
	peers_of_entry: Arc<dyn CertificateTrust>,
	peers_of_origin: Arc<dyn CertificateTrust>,
	peers_of_foreign: Arc<dyn CertificateTrust>,
}

fn multi_org_ctx() -> MultiOrgCtx {
	use tightbeam::random::OsRng;
	use tightbeam::testing::utils::create_test_certificate;

	let (cert_entry, key_entry) = member_identity("Org Main Entry Gateway");
	let (cert_origin, key_origin) = member_identity("Org Main Origin Gateway");

	let other_urn = colony_ns().colony("other").expect("static colony name");
	let (cert_foreign, foreign_key) = colony_identity("Org Other Gateway", &other_urn);
	let (cert_rogue, rogue_key) = member_identity("Org Main Rogue");

	let raw_stranger = k256::ecdsa::SigningKey::random(&mut OsRng);
	let stranger_cert = create_test_certificate(&raw_stranger);

	let trust = combined_trust(&[&cert_entry, &cert_origin, &cert_foreign, &cert_rogue, &stranger_cert]);
	let peers_of_entry = combined_trust(&[&cert_origin, &cert_foreign, &cert_rogue, &stranger_cert]);
	let peers_of_origin = combined_trust(&[&cert_entry, &cert_foreign, &cert_rogue, &stranger_cert]);
	let peers_of_foreign = combined_trust(&[&cert_entry, &cert_origin, &cert_rogue, &stranger_cert]);

	MultiOrgCtx {
		entry: Arc::new(GatewayCerts { cert: cert_entry, key: key_entry, trust: Arc::clone(&trust) }),
		origin: Arc::new(GatewayCerts { cert: cert_origin, key: key_origin, trust: Arc::clone(&trust) }),
		foreign: Arc::new(GatewayCerts { cert: cert_foreign, key: foreign_key, trust }),
		rogue_key,
		stranger_key: Secp256k1SigningKey::from(raw_stranger),
		peers_of_entry,
		peers_of_origin,
		peers_of_foreign,
	}
}

/// [`federation_conf`] with the advertise beat disabled.
///
/// A live beat creates direct advertisements and slate rumors
/// concurrently, so a rumor can land after a fresher direct ad and
/// drop as stale. The scenario injects every control-plane frame
/// instead, which keeps the trace exact for the refinements below.
fn quiet_member_conf(certs: &ClusterTestCerts, peer_trust: Arc<dyn CertificateTrust>) -> ClusterConfig {
	let mut conf = federation_conf(certs, peer_trust, vec![], 1);
	conf.peer.advertise_interval = None;
	conf
}

tb_assert_spec! {
	pub ClusterMultiOrgBoundarySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_PEER_AD_LEARNED, exactly!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(WORK_ECHOED, exactly!(1), equals!(42u64)),
			(GOSSIP_RELAY_STATUS, exactly!(2), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(2)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_PEER_AD_DROPPED, exactly!(1)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64))
		]
	}
}

// Control-plane order of the multi-organization run.
//
// Four events, each with exactly one legal position once the beats are off:
// learn precedes forward, and the cross-organization refusals follow the
// in-organization forward in the order the scenario drives them.
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
		EdgeRefused => {
			events::CLUSTER_GOSSIP_REFUSED => EdgeRefused,
			events::CLUSTER_PEER_AD_DROPPED => EdgeDropped
		},
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

/// L1 + L2 + L3 when FDR is compiled in, and L1 + L2 otherwise.
#[cfg(feature = "testing-fdr")]
fn multi_org_config() -> ScenarioConfig {
	ScenarioConfig::builder()
		.with_spec(ClusterMultiOrgBoundarySpec::latest())
		.with_csp(MultiOrgControlPlane)
		.with_fdr(multi_org_fdr())
		.build()
}

#[cfg(not(feature = "testing-fdr"))]
fn multi_org_config() -> ScenarioConfig {
	ScenarioConfig::builder()
		.with_spec(ClusterMultiOrgBoundarySpec::latest())
		.with_csp(MultiOrgControlPlane)
		.build()
}

// The organization boundary holds while federation routes.
//
// In "main": the origin's advertisement rumor installs the route
// synchronously, then the entry gateway forwards real work in one hop.
//
// Across organizations, every frame arriving after that forward: the
// "other"-colony gateway and the no-colony stranger are both refused
// `PermissionDenied` at the outer colony gate, and a "main" member's
// foreign-realm advertisement passes the outer gate but is dropped by the
// inner admission. No refusal weakens the one ping route.
tb_scenario! {
	name: cluster_org_boundary_holds_while_federation_routes,
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

			// The origin's advertisement rumor, exactly as its own
			// publish beat would flood it.
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
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], type_route_count(&gateway_entry, "ping") as u64)?;

			let mut client = connect_cluster(&ctx.entry, gateway_entry.addr()).await?;
			trace.event(WORK_SENT)?;

			let servlet_frame = emit_ping_work(&mut client, &ctx.entry.key, b"multi-org-work").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;

			// Cross-organization relay: colony "other" is trusted on
			// the transport plane, so only the colony gate can refuse.
			relay_application_rumor(&trace, &ctx.entry, &gateway_entry, &ctx.foreign.key, &ctx.foreign.key, "other-org")
				.await?;

			// No-colony relay: a trusted identity outside every
			// organization is refused the same way.
			relay_application_rumor(
				&trace,
				&ctx.entry,
				&gateway_entry,
				&ctx.stranger_key,
				&ctx.stranger_key,
				"stranger",
			)
			.await?;

			// Foreign-realm advertisement from a "main" member: the
			// relay envelope is admitted (status Ok), the inner
			// advertisement fails realm admission and drops before
			// any route installs.
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

			// No refusal weakened the in-organization route.
			trace.event_with(PEER_ROUTES_AFTER, &[], type_route_count(&gateway_entry, "ping") as u64)?;

			gateway_entry.stop();
			gateway_origin.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterLiveForeignGatewaySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, at_least!(1)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(events::CLUSTER_PEER_AD_LEARNED, exactly!(0)),
			(events::CLUSTER_PEER_AD_DROPPED, exactly!(0)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(0u64))
		]
	}
}

// A live "other"-colony gateway beats against the "main" edge.
//
// The scenario above injects frames signed by the foreign identity; this one
// stands the real gateway up and lets its advertise beat produce them, so the
// counts are bounds rather than exacts.
//
// The direct advertisement plane admits the foreign member by design, and its
// empty slate installs nothing. Every gossip frame the beat floods is refused
// at the colony gate, weakening no route and learning no slate. The entry ends
// holding zero peer routes.
tb_scenario! {
	name: cluster_live_foreign_gateway_beat_refused_at_org_edge,
	spec: ClusterLiveForeignGatewaySpec,
	environment Cluster {
		context: multi_org_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_cluster(&trace, quiet_member_conf(&ctx.entry, Arc::clone(&ctx.peers_of_entry))).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let foreign_conf = federation_conf(&ctx.foreign, Arc::clone(&ctx.peers_of_foreign), vec![cluster.addr().to_string()], 1);
			let gateway_foreign = start_cluster(&trace, foreign_conf).await?;

			// No public state changes at the entry (that is the
			// point), so there is nothing to poll. The client holds
			// the window open for a dozen 100 ms beats instead.
			tokio::time::sleep(Duration::from_millis(1500)).await;

			trace.event_with(PEER_ROUTES_AFTER, &[], cluster.peer_routes().len() as u64)?;

			gateway_foreign.stop();
			cluster.stop();
			Ok(())
		}
	}
}

#[cfg(feature = "testing-fdr")]
tb_assert_spec! {
	pub ClusterMultiOrgModelSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_PEER_AD_LEARNED, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(2)),
			(events::CLUSTER_PEER_AD_DROPPED, exactly!(1))
		]
	}
}

// The canonical boundary order refines the model: learn, forward, refuse
// twice, drop.
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
		gate: Ok,
		assertions: [
			(events::CLUSTER_PEER_AD_LEARNED, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_PEER_AD_DROPPED, exactly!(1))
		]
	}
}

// Negative twin: a forward before any learn violates the model. Counting
// cannot catch it, because these counts are legal and the L1 spec passes.
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
