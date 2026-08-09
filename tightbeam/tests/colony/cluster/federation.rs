//! Multi-hop federation (transitive discovery and relay fallback).
//!
//! Three member gateways with distinct identities: rumors teach a
//! gateway about origins it never dialed, relay trails carry work
//! around a dead direct address, and the `max_hops` clamp bounds the
//! origin's sentinel budget.

use super::common::*;
use super::streaming::{pooled_cluster_client, start_stream_hive};
use tightbeam::colony::cluster::{ServletEntry, DEFAULT_ABANDONMENT_LIMIT, DEFAULT_INITIAL_PHEROMONE};

/// Dial address nothing listens on: a dead direct trail fails fast.
const DEAD_GATEWAY_ADDR: &[u8] = b"127.0.0.1:9";

/// Three distinct colony-member identities (see [`member_identity`]
/// for why [`cluster_certs`] cannot serve here: relay trails refuse
/// self-relay).
///
/// The combined store on `.trust` serves the hive and dial planes.
/// Each gateway's peer store excludes its own identity: peer membership
/// wins on the hive plane, so a member's hive registrations must not
/// verify on its own peer store.
struct FederationCtx {
	a: Arc<ClusterTestCerts>,
	b: Arc<ClusterTestCerts>,
	c: Arc<ClusterTestCerts>,
	peers_of_a: Arc<dyn CertificateTrust>,
	peers_of_b: Arc<dyn CertificateTrust>,
	peers_of_c: Arc<dyn CertificateTrust>,
}

fn federation_ctx() -> FederationCtx {
	let (cert_a, key_a) = member_identity("Gateway A");
	let (cert_b, key_b) = member_identity("Gateway B");
	let (cert_c, key_c) = member_identity("Gateway C");
	let trust = combined_trust(&[&cert_a, &cert_b, &cert_c]);
	let peers_of_a = combined_trust(&[&cert_b, &cert_c]);
	let peers_of_b = combined_trust(&[&cert_a, &cert_c]);
	let peers_of_c = combined_trust(&[&cert_a, &cert_b]);

	FederationCtx {
		a: Arc::new(GatewayCerts { cert: cert_a, key: key_a, trust: Arc::clone(&trust) }),
		b: Arc::new(GatewayCerts { cert: cert_b, key: key_b, trust: Arc::clone(&trust) }),
		c: Arc::new(GatewayCerts { cert: cert_c, key: key_c, trust }),
		peers_of_a,
		peers_of_b,
		peers_of_c,
	}
}

/// Member gateway conf on a fast beat: `peers` as anchors, the given
/// peer-plane store, and a fast rumor refresh so late-promoted flood
/// targets still learn the slate within the test window.
pub(super) fn federation_conf(
	certs: &ClusterTestCerts,
	peer_trust: Arc<dyn CertificateTrust>,
	peers: Vec<String>,
	max_hops: u8,
) -> ClusterConfig {
	let tls = ClusterTlsConfig { peer_trust: Some(peer_trust), ..cluster_tls_config(certs) };

	ClusterConfig::builder(tls)
		.with_peers(peers)
		.with_advertise_interval(Duration::from_millis(100))
		.with_rumor_refresh(Duration::from_millis(200))
		.with_max_hops(max_hops)
		.build()
}

/// [`federation_conf`] with a mux offer, so the gateway serves routed
/// streams and its pools open them.
fn mux_federation_conf(
	certs: &ClusterTestCerts,
	peer_trust: Arc<dyn CertificateTrust>,
	peers: Vec<String>,
	max_hops: u8,
) -> ClusterConfig {
	with_mux_offer(federation_conf(certs, peer_trust, peers, max_hops))
}

/// Hive hosting the ping servlet under a distinct "beacon" type, so a
/// relay gateway owns registry entries (its dial address is learnable)
/// without serving the type under test.
async fn start_beacon_hive(
	trace: TraceCollector,
	certs: Arc<ClusterTestCerts>,
) -> Result<ClusterTestHive, TightBeamError> {
	let servlet_conf = servlet_tls_config(&certs)?;
	let servlet = ClusterTestServlet::start(Arc::new(trace.share()), Some(servlet_conf)).await?;

	let mut hive = ClusterTestHive::new(Some(hive_tls_config(&certs)))?;
	hive.register(servlet_urn("beacon"), servlet, |t| ClusterTestServlet::start(t, None))?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// Flood one origin-signed advertisement rumor for `gateway_addr` to
/// `cluster`, exactly as a peer gateway would. The rumor frame carries
/// the origin's signature inside a `Gossip` relay envelope with
/// `hop_ttl` reflood hops, so the same-origin bind holds at every hop.
/// `PublishGossip` cannot serve here: the publish plane re-creates the
/// rumor under the receiving gateway's own key. Each call creates a
/// fresh rumor, so every call floods anew (ads dedup on digest and are
/// never repaired). Returns the admission status the gateway replied.
pub(super) async fn flood_ad_rumor(
	connect_certs: &ClusterTestCerts,
	signer: &Secp256k1SigningKey,
	cluster: &ClusterGateway,
	gateway_addr: &[u8],
	advertised_types: Vec<Urn<'static>>,
	hop_ttl: u64,
	id: &[u8],
) -> Result<TransitStatus, TightBeamError> {
	let advertisement =
		ClusterRequest::AdvertisePeer(PeerAdvertisement { gateway_addr: gateway_addr.to_vec(), advertised_types });
	let inner = signed_control_frame_with(signer, id, advertisement).await?;

	let provider = Secp256k1KeyProvider::from(signer.to_owned());
	let rumor = frame_compose(Version::V2)
		.with_id(id)
		.with_order(current_timestamp_ms())
		.with_message(GossipRumor::peer_advertisement(encode(&inner)?))
		.build()?
		.sign_with_provider::<Sha3_256, _>(&provider)
		.await?;

	let frame = frame_compose(Version::V2)
		.with_id(id)
		.with_order(current_timestamp_ms())
		.with_lifetime(hop_ttl)
		.with_message(ClusterRequest::Gossip(Box::new(rumor)))
		.build()?
		.sign_with_provider::<Sha3_256, _>(&provider)
		.await?;

	let mut client = connect_cluster(connect_certs, cluster.addr()).await?;
	let response: GossipResponse = decode(&emit_frame(&mut client, frame).await?.message)?;
	Ok(response.status)
}

/// Count the live peer routes for `type_name` on `cluster`.
pub(super) fn type_route_count(cluster: &ClusterGateway, type_name: &str) -> usize {
	let canonical = type_canonical_bytes(&servlet_urn(type_name));
	cluster
		.peer_routes()
		.iter()
		.filter(|route| route.servlet_type.as_ref() == canonical.as_slice())
		.count()
}

/// Poll until `cluster` holds `want` routes for `type_name` or
/// attempts exhaust. Branching lives here, not in scenarios.
pub(super) async fn wait_for_type_routes(
	cluster: &ClusterGateway,
	type_name: &str,
	want: usize,
	attempts: u32,
	interval: Duration,
) -> usize {
	for _ in 0..attempts {
		let held = type_route_count(cluster, type_name);
		if held >= want {
			return held;
		}

		tokio::time::sleep(interval).await;
	}

	type_route_count(cluster, type_name)
}

/// Flood fresh advertisement rumors claiming `claimed_addr` for
/// `type_name` through `relay` until `observer` holds `want` routes or
/// attempts exhaust. Fresh instances flood until the relay has
/// promoted the observer as a flood target. Branching lives here, not
/// in scenarios.
async fn flood_until_routes(
	connect_certs: &ClusterTestCerts,
	signer: &Secp256k1SigningKey,
	relay: &ClusterGateway,
	observer: &ClusterGateway,
	claimed_addr: &[u8],
	type_name: &str,
	want: usize,
) -> Result<usize, TightBeamError> {
	let mut installed = 0usize;
	for attempt in 0u32..50 {
		let id = format!("relay-ad-{type_name}-{attempt}");
		flood_ad_rumor(
			connect_certs,
			signer,
			relay,
			claimed_addr,
			vec![servlet_urn(type_name)],
			2,
			id.as_bytes(),
		)
		.await?;

		installed = wait_for_type_routes(observer, type_name, want, 2, Duration::from_millis(100)).await;
		if installed >= want {
			break;
		}
	}

	Ok(installed)
}

/// Whether any route for `type_name` on `cluster` dials `dial_addr`.
fn type_route_dials(cluster: &ClusterGateway, type_name: &str, dial_addr: &[u8]) -> bool {
	let canonical = type_canonical_bytes(&servlet_urn(type_name));
	cluster
		.peer_routes()
		.iter()
		.any(|route| route.servlet_type.as_ref() == canonical.as_slice() && route.dial_addr.as_ref() == dial_addr)
}

tb_assert_spec! {
	pub ClusterTransitiveDiscoverySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_AD_LEARNED, at_least!(2)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(WORK_ECHOED, exactly!(1), equals!(42u64))
		]
	}
}

// Transitive discovery routes real work: A learns C's ping type only
// from B's relayed advertisement rumor, then dials C directly.
//
// - C anchors B and floods its slate rumor to it. B applies and
//   refloods once its own beat promotes A.
// - C's dial allowlist admits only B, so C never dials A: the trail A
//   installs can only come from the rumor.
// - The forward is one hop from A to C, not a data hop through B.
tb_scenario! {
	name: cluster_transitive_rumor_installs_routable_trail,
	spec: ClusterTransitiveDiscoverySpec,
	environment Hive {
		context: federation_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_ping_hive(trace, Arc::clone(&ctx.c), None).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let gateway_b = start_cluster(&trace, federation_conf(&ctx.b, Arc::clone(&ctx.peers_of_b), vec![], 1)).await?;

			let mut conf_c = federation_conf(&ctx.c, Arc::clone(&ctx.peers_of_c), vec![gateway_b.addr().to_string()], 1);
			conf_c.peer.peer_dial_allowlist = Some(vec![gateway_b.addr().to_string()]);

			let gateway_c = start_cluster(&trace, conf_c).await?;
			let gateway_a = start_cluster(&trace, federation_conf(&ctx.a, Arc::clone(&ctx.peers_of_a), vec![gateway_b.addr().to_string()], 1)).await?;

			hive.register_with_cluster(gateway_c.addr()).await?;

			let learned = wait_for_type_routes(&gateway_a, "ping", 1, 100, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned as u64)?;

			let mut client = connect_cluster(&ctx.a, gateway_a.addr()).await?;
			trace.event(WORK_SENT)?;

			let servlet_frame = emit_ping_work(&mut client, &ctx.a.key, b"transitive-work").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;

			gateway_a.stop();
			gateway_c.stop();
			gateway_b.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterRelayFallbackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(events::CLUSTER_PEER_AD_LEARNED, at_least!(1)),
			(RELAY_ROUTES_INSTALLED, exactly!(1), equals!(2u64)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(RELAY_TRUE_ADDR_RESTORED, exactly!(1), equals!(true)),
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(2)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(0)),
			(WORK_ECHOED, exactly!(1), equals!(42u64))
		]
	}
}

// Relay fallback end-to-end at `max_hops = 2`: the origin's advertised
// address is dead for A, yet work succeeds from A through B to C.
//
// - A learns C's slate only from a rumor claiming a dead dial address,
//   relayed by B: A installs the dead direct trail and a relay trail
//   through B (B's dial address is known from its beacon slate).
// - B learns C's true address from a direct advertisement, so B's
//   trail to C is live.
// - A's work spends its clamped budget of two. A dead direct pick
//   weakens and the bounded retry crosses the relay trail, while a
//   relay pick crosses it immediately. Two forwards prove the two-hop path
//   (A never reaches C in one), and zero `CLUSTER_WORK_UNAVAILABLE`
//   proves fallback, not exhaustion.
tb_scenario! {
	name: cluster_relay_trail_carries_work_around_dead_origin_addr,
	spec: ClusterRelayFallbackSpec,
	environment Hive {
		context: federation_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_ping_hive(trace, Arc::clone(&ctx.c), None).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let gateway_b = start_cluster(&trace, federation_conf(&ctx.b, Arc::clone(&ctx.peers_of_b), vec![], 1)).await?;
			let beacon_hive = start_beacon_hive(trace.share(), Arc::clone(&ctx.b)).await?;
			beacon_hive.register_with_cluster(gateway_b.addr()).await?;

			// C serves ping at its real address but never advertises on
			// its own. The test injects both of C's advertisements, so
			// the dead claim at A can never be repaired by a fresh one.
			let mut conf_c = federation_conf(&ctx.c, Arc::clone(&ctx.peers_of_c), vec![], 1);
			conf_c.peer.advertise_interval = None;

			let gateway_c = start_cluster(&trace, conf_c).await?;
			hive.register_with_cluster(gateway_c.addr()).await?;

			let gateway_a = start_cluster(&trace, federation_conf(&ctx.a, Arc::clone(&ctx.peers_of_a), vec![gateway_b.addr().to_string()], 2)).await?;

			// Flood until A holds both trails: the dead direct and the
			// relay via B.
			let installed =
				flood_until_routes(&ctx.a, &ctx.c.key, &gateway_b, &gateway_a, DEAD_GATEWAY_ADDR, "ping", 2).await?;
			trace.event_with(RELAY_ROUTES_INSTALLED, &[], installed as u64)?;

			// The direct advertisement restores C's true address at B,
			// overwriting the dead claim the rumors installed there.
			let true_addr = gateway_c.addr().to_string();
			advertise_peer_signed(&trace, &ctx.a, &ctx.c.key, &gateway_b, true_addr.as_bytes(), vec![servlet_urn("ping")])
				.await?;
			trace.event_with(RELAY_TRUE_ADDR_RESTORED, &[], type_route_dials(&gateway_b, "ping", true_addr.as_bytes()))?;

			let mut client = connect_cluster(&ctx.a, gateway_a.addr()).await?;
			trace.event(WORK_SENT)?;

			let servlet_frame = emit_ping_work(&mut client, &ctx.a.key, b"relay-fallback-work").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;

			gateway_a.stop();
			gateway_c.stop();
			gateway_b.stop();
			beacon_hive.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterStreamRelayFallbackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(events::CLUSTER_PEER_AD_LEARNED, at_least!(1)),
			(RELAY_ROUTES_INSTALLED, exactly!(1), equals!(2u64)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(RELAY_TRUE_ADDR_RESTORED, exactly!(1), equals!(true)),
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(2)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(0)),
			(STREAM_SERVLET_HANDLED, exactly!(1)),
			(STREAM_ECHOED, exactly!(1), equals!(8u64))
		]
	}
}

// Relay fallback covers routed streams at `max_hops = 2`: the same
// topology as the unary scenario above, driven through a spliced
// stream instead of unary work.
//
// - A holds a dead direct trail and a relay trail through B, and B
//   holds C's true address.
// - A's splice spends its clamped budget of two. A dead direct pick fails
//   at dial and the bounded retry crosses the relay trail, while a relay
//   pick crosses it immediately. Two forwards prove the two-hop splice,
//   and the servlet handling proves the body crossed both hops intact.
tb_scenario! {
	name: cluster_relay_trail_carries_stream_around_dead_origin_addr,
	spec: ClusterStreamRelayFallbackSpec,
	environment Hive {
		context: federation_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_stream_hive(trace, Arc::clone(&ctx.c)).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let gateway_b = start_cluster(&trace, mux_federation_conf(&ctx.b, Arc::clone(&ctx.peers_of_b), vec![], 1)).await?;
			let beacon_hive = start_beacon_hive(trace.share(), Arc::clone(&ctx.b)).await?;
			beacon_hive.register_with_cluster(gateway_b.addr()).await?;

			// C serves stream-echo at its real address but never
			// advertises on its own. The test injects both of C's
			// advertisements, so the dead claim at A can never be
			// repaired by a fresh one.
			let mut conf_c = mux_federation_conf(&ctx.c, Arc::clone(&ctx.peers_of_c), vec![], 1);
			conf_c.peer.advertise_interval = None;

			let gateway_c = start_cluster(&trace, conf_c).await?;
			hive.register_with_cluster(gateway_c.addr()).await?;

			let gateway_a =
				start_cluster(&trace, mux_federation_conf(&ctx.a, Arc::clone(&ctx.peers_of_a), vec![gateway_b.addr().to_string()], 2)).await?;

			// Flood until A holds both trails: the dead direct and the
			// relay via B.
			let installed =
				flood_until_routes(&ctx.a, &ctx.c.key, &gateway_b, &gateway_a, DEAD_GATEWAY_ADDR, "stream-echo", 2)
					.await?;
			trace.event_with(RELAY_ROUTES_INSTALLED, &[], installed as u64)?;

			// The direct advertisement restores C's true address at B,
			// overwriting the dead claim the rumors installed there.
			let true_addr = gateway_c.addr().to_string();
			advertise_peer_signed(
				&trace,
				&ctx.a,
				&ctx.c.key,
				&gateway_b,
				true_addr.as_bytes(),
				vec![servlet_urn("stream-echo")],
			)
			.await?;
			trace.event_with(
				RELAY_TRUE_ADDR_RESTORED,
				&[],
				type_route_dials(&gateway_b, "stream-echo", true_addr.as_bytes()),
			)?;

			let client = pooled_cluster_client(&trace, &ctx.a, gateway_a.addr()).await?;
			trace.event(WORK_SENT)?;

			let (mut sink, response) = client.open_stream_to(servlet_urn("stream-echo"))?;
			sink.push(b"abcd").await?;
			sink.close_with(b"efgh").await?;

			let reply = response.await?.ok_or(TightBeamError::MissingResponse)?;
			let echoed: PingResponse = decode(&reply.message)?;
			trace.event_with(STREAM_ECHOED, &[], u64::from(echoed.doubled))?;

			gateway_a.stop();
			gateway_c.stop();
			gateway_b.stop();
			beacon_hive.stop();
			hive.stop();
			Ok(())
		}
	}
}

// A zero-hop gateway clamps the origin sentinel: the client's "as far
// as policy allows" budget becomes zero, so a peer-only type refuses
// Unavailable instead of forwarding. Reuses the loop-guard spec: the
// same contract as a spent wire budget.
tb_scenario! {
	name: cluster_zero_hop_gateway_clamps_origin_sentinel,
	spec: super::peering::ClusterPeerForwardLoopGuardSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let mut conf = peering_cluster_conf(&certs);
			conf.peer.max_hops = 0;
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;

			let mut client = connect_cluster(&certs, cluster.addr()).await?;
			trace.event(WORK_SENT)?;

			let refused_work = emit_ping_work(&mut client, &certs.key, b"sentinel-clamp").await;
			record_work_refusal(&trace, refused_work)?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterStreamBudgetSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(WORK_SENT, exactly!(1)),
			(STREAM_BUDGET_REFUSED, exactly!(1), equals!(true))
		]
	}
}

// The clamp covers routed stream opens: a zero-hop gateway plans a
// splice with a spent budget, so a peer-only target refuses before any
// dial, the same contract as the unary sentinel clamp.
tb_scenario! {
	name: cluster_zero_hop_gateway_refuses_routed_stream,
	spec: ClusterStreamBudgetSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let mut conf = with_mux_offer(peering_cluster_conf(&certs));
			conf.peer.max_hops = 0;
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("stream-echo")]).await?;

			let config = PoolConfig {
				idle_timeout: None,
				max_connections: 1,
				mux_offer: Some(Arc::new(TransportOffer::mux(8))),
			};
			let pool = Arc::new(
				ConnectionPool::<TokioListener>::builder()
					.with_config(config)
					.with_trust_store(Arc::clone(&certs.trust))
					.with_trace(trace.share())
					.build(),
			);
			let client = pool.connect(cluster.addr().to_owned()).await?;
			trace.event(WORK_SENT)?;

			let (sink, response) = client.open_stream_to(servlet_urn("stream-echo"))?;
			sink.close_with(b"budget-spent").await?;

			let refused = response.await.is_err();
			trace.event_with(STREAM_BUDGET_REFUSED, &[], refused)?;

			cluster.stop();
			Ok(())
		}
	}
}

/// Balancer that pins the first pick to one route key, so a scenario
/// deterministically dials a decoy before the bounded failover. An
/// unset or excluded preference defers to the first candidate.
struct DecoyFirstBalancer {
	preferred: Arc<Mutex<Option<Vec<u8>>>>,
}

impl LoadBalancer for DecoyFirstBalancer {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		let preferred = self.preferred.lock().ok()?;
		let pinned = preferred
			.as_ref()
			.and_then(|key| candidates.iter().position(|candidate| candidate.instance_key == *key));

		pinned.or(Some(0))
	}
}

/// Sets the balancer preference. The lock only poisons after a balancer
/// panic, which fails the scenario anyway.
fn pin_preference(cell: &Mutex<Option<Vec<u8>>>, key: Vec<u8>) {
	let mut preferred = cell.lock().expect("preference lock poisons only after a balancer panic");
	*preferred = Some(key);
}

/// Route key `cluster` holds for `type_name` toward `dial_addr`,
/// rebuilt through the public [`ServletEntry::peer`] constructor so
/// the key discipline stays in one place.
fn peer_route_key_for_dial(cluster: &ClusterGateway, type_name: &str, dial_addr: &[u8]) -> Option<Vec<u8>> {
	let canonical = type_canonical_bytes(&servlet_urn(type_name));
	cluster
		.peer_routes()
		.into_iter()
		.find(|route| route.dial_addr.as_ref() == dial_addr && route.servlet_type.as_ref() == canonical.as_slice())
		.map(|route| {
			ServletEntry::peer(
				route.peer_id,
				route.servlet_type,
				route.dial_addr,
				DEFAULT_INITIAL_PHEROMONE,
				DEFAULT_ABANDONMENT_LIMIT,
			)
		})
		.map(|entry| entry.route_key().to_vec())
}

tb_assert_spec! {
	pub ClusterLiveDecoyFailoverSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(PEER_AD_STATUS, exactly!(2), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(2u64)),
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(WORK_ECHOED, exactly!(1), equals!(42u64))
		]
	}
}

// A live decoy answers but cannot serve: its well-formed `Unavailable`
// reply joins the bounded failover instead of relaying to the client.
//
// - B is a live member gateway with no ping servlet. Its injected
//   advertisement claims ping at its own address, so A installs a
//   trail to a gateway that answers and refuses.
// - Every advertise beat is off, so both of A's trails come from the
//   two injected advertisements and the event counts are exact.
// - The pinned balancer makes A dial B first, deterministically. The
//   one `CLUSTER_WORK_UNAVAILABLE` fires on B, never on A.
// - The echo proves the failover: A weakens the decoy trail and
//   retries C's trail within the same request.
tb_scenario! {
	name: cluster_live_peer_unavailable_reply_fails_over,
	spec: ClusterLiveDecoyFailoverSpec,
	environment Hive {
		context: federation_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_ping_hive(trace, Arc::clone(&ctx.c), None).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let mut conf_b = federation_conf(&ctx.b, Arc::clone(&ctx.peers_of_b), vec![], 1);
			conf_b.peer.advertise_interval = None;
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let mut conf_c = federation_conf(&ctx.c, Arc::clone(&ctx.peers_of_c), vec![], 1);
			conf_c.peer.advertise_interval = None;

			let gateway_c = start_cluster(&trace, conf_c).await?;
			hive.register_with_cluster(gateway_c.addr()).await?;

			let preferred = Arc::new(Mutex::new(None));
			let mut conf_a = federation_conf(&ctx.a, Arc::clone(&ctx.peers_of_a), vec![], 1);
			conf_a.peer.advertise_interval = None;
			conf_a.load_balancer = Arc::new(DecoyFirstBalancer { preferred: Arc::clone(&preferred) });

			let gateway_a = start_cluster(&trace, conf_a).await?;

			// Both trails install by injected advertisement: the decoy
			// claim from B and the honest claim from C.
			let decoy_addr = gateway_b.addr().to_string();
			advertise_peer_signed(&trace, &ctx.a, &ctx.b.key, &gateway_a, decoy_addr.as_bytes(), vec![servlet_urn("ping")])
				.await?;
			let origin_addr = gateway_c.addr().to_string();
			advertise_peer_signed(
				&trace,
				&ctx.a,
				&ctx.c.key,
				&gateway_a,
				origin_addr.as_bytes(),
				vec![servlet_urn("ping")],
			)
			.await?;
			let installed = wait_for_type_routes(&gateway_a, "ping", 2, 100, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], installed as u64)?;

			// Pin the first pick to the decoy trail.
			let decoy_key = peer_route_key_for_dial(&gateway_a, "ping", decoy_addr.as_bytes())
				.ok_or(TightBeamError::MissingResponse)?;
			pin_preference(&preferred, decoy_key);

			let mut client = connect_cluster(&ctx.a, gateway_a.addr()).await?;
			trace.event(WORK_SENT)?;

			let servlet_frame = emit_ping_work(&mut client, &ctx.a.key, b"live-decoy-failover").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;

			gateway_a.stop();
			gateway_c.stop();
			gateway_b.stop();
			hive.stop();
			Ok(())
		}
	}
}
