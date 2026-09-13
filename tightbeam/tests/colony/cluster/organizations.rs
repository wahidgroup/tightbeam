//! Multi-organization federation (colony boundary at the gateway edge).
//!
//! One transport trust store, two colonies: "main" runs the entry and origin
//! gateways, "other" holds one trusted gateway identity, and a third identity
//! is trusted for transport but belongs to no colony. Work federates inside
//! "main" while every cross-organization control-plane frame is refused at the
//! edge, weakening no in-organization route.
//!
//! Beat-driven discovery lives in `federation`.

use super::common::*;
use super::federation::{federation_conf, flood_ad_rumor, type_route_count};
use super::gossip::relay_application_rumor;

#[cfg(feature = "testing-fdr")]
use tightbeam::testing::fdr::FdrConfig;
#[cfg(feature = "testing-fdr")]
use tightbeam::testing::{Expect, Layer};

/// Two organizations and one drifter under a single transport trust store.
struct MultiOrgCtx {
	/// Member gateway of colony "main", see [`member_identity`].
	entry: Arc<ClusterTestCerts>,
	/// Member gateway of colony "main", see [`member_identity`].
	origin: Arc<ClusterTestCerts>,
	/// Gateway identity of colony "other". Transport admits it and the colony
	/// gate must not. Carries full gateway certs, so a scenario can also run
	/// it as a live gateway.
	foreign: Arc<ClusterTestCerts>,
	/// A "main" member whose advertisement claims a type from a foreign realm.
	/// The outer relay gate admits it and the inner advertisement admission
	/// must drop it.
	rogue_key: Secp256k1SigningKey,
	/// A trusted transport identity with no colony SAN.
	stranger_key: Secp256k1SigningKey,
	/// Peer-plane store for `entry`, excluding its own identity: peer
	/// membership wins on the hive plane, so a member's hive registrations
	/// must not verify on its own peer store.
	peers_of_entry: Arc<dyn CertificateTrust>,
	/// Peer-plane store for `origin`, excluding its own identity.
	peers_of_origin: Arc<dyn CertificateTrust>,
	/// Peer-plane store for `foreign`, excluding its own identity.
	peers_of_foreign: Arc<dyn CertificateTrust>,
}

fn multi_org_ctx() -> MultiOrgCtx {
	use tightbeam::random::OsRng;
	use tightbeam::testing::fixtures::TestCertificate;

	let (cert_entry, key_entry) = member_identity("Org Main Entry Gateway");
	let (cert_origin, key_origin) = member_identity("Org Main Origin Gateway");

	let other_urn = colony_ns().colony("other").expect("static colony name");
	let (cert_foreign, foreign_key) = colony_identity("Org Other Gateway", &other_urn);
	let (cert_rogue, rogue_key) = member_identity("Org Main Rogue");

	let raw_stranger = k256::ecdsa::SigningKey::random(&mut OsRng);
	let stranger_cert = TestCertificate::self_signed(&raw_stranger);

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
			(GOSSIP_RELAY_STATUS, exactly!(2), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(2)),
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

			// Stands in for the origin's own publish beat.
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

// A real gateway's beat drives this run, so the counts are bounds rather than
// exacts. The direct advertisement plane admits the foreign member by design
// and its empty slate installs nothing, which is why an advertisement is
// observed while nothing is learned.
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

			// A refusal changes no public state, so there is nothing
			// to poll: hold the window open for a dozen 100 ms beats.
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
		assertions: [
			(events::CLUSTER_PEER_AD_LEARNED, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(2)),
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

// Counting cannot catch this order: the counts are legal and the L1 spec
// passes, so only the refinement rejects it.
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
