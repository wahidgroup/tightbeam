//! Multi-organization federation (colony boundary at the gateway edge).
//!
//! Two organizations share one transport trust store: colony "main"
//! runs the entry and origin gateways, colony "other" holds one
//! trusted gateway identity. A third identity is trusted for
//! transport but belongs to no colony. Work federates inside "main"
//! while every cross-organization control-plane frame is refused at
//! the edge, without weakening any in-organization route.
//!
//! In the boundary scenario every control-plane frame is injected and
//! the advertise beats stay off, so the recorded trace is exact. The
//! organic beat-driven discovery has its own scenarios in
//! `federation`. Here exactness buys the strict L2/L3 refinements: L1
//! counts the boundary facts, L2 refines the control-plane order
//! against a CSP process, and L3 (FDR) checks trace refinement,
//! divergence freedom, and deadlock freedom against the same process.
//! A separate scenario then runs the foreign gateway live, so its own
//! beat produces the cross-organization frames the exact scenario
//! injects directly.

use super::common::*;
use super::federation::{federation_conf, flood_ad_rumor, type_route_count};
use super::gossip::relay_application_rumor;

#[cfg(feature = "testing-fdr")]
use tightbeam::testing::fdr::FdrConfig;

/// Two organizations and one drifter under a single transport trust
/// store.
///
/// - `entry`, `origin`: member gateways of colony "main" (see
///   [`member_identity`]).
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
// The alphabet is the four built-in events the boundary story turns
// on. Every other trace event is outside the alphabet and ignored.
// The machine is strict: with the beats off, each alphabet event has
// exactly one legal position.
//
// - No work forwards before the rumor teaches the route (learn
//   precedes forward).
// - Cross-organization refusals arrive only after the
//   in-organization forward, in the order the scenario drives them:
//   the relay refusals, then the inner advertisement drop.
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

/// FDR bounds for the multi-organization control plane. The process
/// has no hidden events, so `max_internal_run` guards against model
/// regressions, not expected internal churn.
#[cfg(feature = "testing-fdr")]
fn multi_org_fdr(expect_failure: bool) -> FdrConfig {
	FdrConfig {
		seeds: 2,
		max_depth: 16,
		max_internal_run: 4,
		timeout_ms: 5000,
		specs: vec![MultiOrgControlPlane::process()],
		fail_fast: true,
		expect_failure,
		..Default::default()
	}
}

/// L1 + L2 + L3 when FDR is compiled in, and L1 + L2 otherwise.
#[cfg(feature = "testing-fdr")]
fn multi_org_config() -> ScenarioConfig {
	ScenarioConfig::builder()
		.with_spec(ClusterMultiOrgBoundarySpec::latest())
		.with_csp(MultiOrgControlPlane)
		.with_fdr(multi_org_fdr(false))
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
// In-organization half (colony "main"):
//
// - The origin gateway hosts the ping hive. Its advertisement rumor,
//   injected at the entry gateway, installs the route synchronously
//   (delivery precedes the gossip reply).
// - The entry gateway forwards real work to the origin in one hop.
//
// Cross-organization half (all frames arrive at the entry gateway
// after the forward):
//
// - The "other"-colony gateway relays a gossip rumor: refused
//   `PermissionDenied` at the outer colony gate.
// - The no-colony stranger relays a rumor: refused the same way.
// - A "main" member floods an advertisement rumor claiming a
//   foreign-realm type: the outer gate admits it (valid member
//   relay), the inner admission drops it (`CLUSTER_PEER_AD_DROPPED`).
// - No refusal weakens a route: the entry gateway still holds exactly
//   one ping route.
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
// The boundary scenario above injects frames signed by the foreign
// identity. This one stands up the real gateway, anchored on the
// entry, and lets its own advertise beat produce them. The counts are
// bounds, not exacts: the beat fires on its own clock.
//
// - The direct advertisement plane admits the foreign member
//   (`CLUSTER_PEER_ADVERTISED`): cross-organization work federation
//   is by design, and the empty slate installs nothing.
// - Every gossip frame the beat floods (slate rumor, reconcile) is
//   refused at the colony gate (`CLUSTER_GOSSIP_REFUSED`), with no
//   route weakened, no slate learned, and nothing dropped from the
//   rumor apply path.
// - The entry ends the run holding zero peer routes.
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

// The canonical boundary order refines the model: learn, forward,
// refuse twice, drop. Divergence freedom is trivial (no hidden
// events), and deadlock freedom holds because the trace ends in the
// terminal state.
#[cfg(feature = "testing-fdr")]
tb_scenario! {
	name: cluster_multi_org_control_plane_refines_model,
	config: ScenarioConfig::builder()
		.with_spec(ClusterMultiOrgModelSpec::latest())
		.with_fdr(multi_org_fdr(false))
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

// Negative twin: a forward before any learn violates the model, so
// refinement must fail. Counting alone cannot catch this, because the
// counts here are legal and the L1 spec passes.
#[cfg(feature = "testing-fdr")]
tb_scenario! {
	name: cluster_multi_org_model_rejects_forward_before_learn,
	config: ScenarioConfig::builder()
		.with_spec(ClusterMultiOrgViolationSpec::latest())
		.with_fdr(multi_org_fdr(true))
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
