//! Multi-hop federation tests for transitive discovery and relay fallback.
//!
//! The scenarios run three member gateways with distinct identities:
//!
//! - Rumors teach a gateway about origins it never dialed.
//! - Relay trails carry work around a dead direct address.
//! - The `max_hops` clamp bounds the origin's sentinel budget.
//! - A forward reaches only the gateway that signed the advertisement.
//! - A forward reaches a gateway that rotated its certificate under one key.

use super::common::*;
use super::streaming::{pooled_cluster_client, start_stream_hive};
use tightbeam::clock::ManualClock;
use tightbeam::crypto::x509::policy::{CertificateValidation, DirectTrustValidator};
use tightbeam::der::asn1::OctetString;
use tightbeam::testing::TestCertificate;
use tightbeam::x509::ext::pkix::SubjectKeyIdentifier;

/// A dial address nothing listens on, so a dead direct trail fails fast.
const DEAD_GATEWAY_ADDR: &[u8] = b"127.0.0.1:9";

/// Three distinct colony-member identities. [`cluster_certs`] cannot serve
/// here, because relay trails refuse self-relay (see [`member_identity`]).
///
/// - The combined store on `.trust` serves the hive and dial planes.
/// - Each gateway's peer store excludes its own identity. Peer membership
///   wins on the hive plane, so a member's hive registrations must not verify
///   on its own peer store.
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

/// A member gateway configuration on a fast beat: `peers` as anchors, the
/// given peer-plane store, and a fast rumor refresh so late-promoted flood
/// targets learn the slate within the test window.
pub fn federation_conf(
	certs: &ClusterTestCerts,
	peer_trust: Arc<dyn CertificateTrust>,
	peers: impl IntoIterator<Item = String>,
	max_hops: u8,
) -> ClusterConfig {
	let peers: Vec<String> = peers.into_iter().collect();
	let tls = cluster_tls_config(certs).with_peer_trust(peer_trust);

	ClusterConfig::builder(tls)
		.with_peers(peers)
		.expect("fixture peers name sockets")
		.with_advertise_interval(Duration::from_millis(100))
		.with_rumor_refresh(Duration::from_millis(200))
		.with_max_hops(max_hops)
		.build()
}

/// One advertise beat of the gateway [`federation_conf`] builds.
const BEAT: Duration = Duration::from_millis(100);

/// Beats a scenario drives on a manual clock before it gives up.
///
/// Twenty beats move that clock two seconds, well inside a gateway's freshness
/// window, so every frame signed meanwhile stays admissible.
const DRIVEN_BEATS: u32 = 20;

/// Drives `clock` one beat at a time until `trace` holds `count` peer
/// advertisements, or the beats run out. Each branch lives here, so the
/// scenario reads as one straight line.
///
/// - The beat task may reach its first sleep after the scenario starts, and a
///   sleep that begins after an advance waits a whole beat from there, so each
///   round advances again.
/// - Each round reads the trace once the round's socket work has had a moment to run.
/// - A round that falls short polls to its end, so a rumor that beat flooded has landed before the next.
pub async fn drive_until_advertised(clock: &ManualClock, trace: &TraceCollector, count: usize) {
	let landed = || trace.recorded(events::CLUSTER_PEER_ADVERTISED) >= count;
	for _ in 0..DRIVEN_BEATS {
		clock.advance(BEAT);
		if poll_until(5, Duration::from_millis(20), landed).await {
			return;
		}
	}
}

/// [`federation_conf`] that also restricts inbound ads to the peers it
/// dials, so a claimed address outside the list is refused.
pub fn federation_conf_allowing(
	certs: &ClusterTestCerts,
	peer_trust: Arc<dyn CertificateTrust>,
	peers: impl IntoIterator<Item = String>,
	max_hops: u8,
) -> ClusterConfig {
	let peers: Vec<String> = peers.into_iter().collect();
	let tls = cluster_tls_config(certs).with_peer_trust(peer_trust);

	ClusterConfig::builder(tls)
		.with_peers(peers.clone())
		.expect("fixture peers name sockets")
		.with_peer_dial_allowlist(peers)
		.expect("fixture allowlist entries name sockets")
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
	peers: impl IntoIterator<Item = String>,
	max_hops: u8,
) -> ClusterConfig {
	let peers: Vec<String> = peers.into_iter().collect();
	with_mux_offer(federation_conf(certs, peer_trust, peers, max_hops))
}

/// A hive that hosts the ping servlet under a distinct "beacon" type, so a
/// relay gateway owns registry entries, which make its dial address
/// learnable, while the relay leaves the type under test unserved.
async fn start_beacon_hive(
	trace: TraceCollector,
	certs: Arc<ClusterTestCerts>,
) -> Result<ClusterTestHive, TightBeamError> {
	let servlet_conf = servlet_tls_config(&certs)?;
	let servlet = ClusterTestServlet::start(Arc::new(trace.share()), servlet_conf).await?;

	let mut hive = ClusterTestHive::new(Some(hive_tls_config(&certs)))?;
	hive.register(servlet_urn("beacon"), servlet, |t| {
		ClusterTestServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// Floods one origin-signed advertisement rumor for `gateway_addr` to
/// `cluster`, exactly as a peer gateway would, and returns the admission
/// status the gateway replied.
///
/// - The rumor frame carries the origin's signature inside a `Gossip` relay
///   envelope with `hop_ttl` reflood hops, so the same-origin bind holds at
///   every hop.
/// - `PublishGossip` cannot serve here, because the publish plane re-creates
///   the rumor under the receiver's own key.
/// - Each call creates a fresh rumor, so every call floods anew. The gateway
///   deduplicates ads by digest and never repairs them.
pub async fn flood_ad_rumor(
	connect_certs: &ClusterTestCerts,
	signer: &Secp256k1SigningKey,
	cluster: &ClusterGateway,
	gateway_addr: impl AsRef<[u8]>,
	advertised_types: impl IntoIterator<Item = Urn<'static>>,
	hop_ttl: u64,
	id: impl AsRef<[u8]>,
) -> Result<TransitStatus, TightBeamError> {
	let gateway_addr = gateway_addr.as_ref();
	let advertised_types: Vec<Urn<'static>> = advertised_types.into_iter().collect();
	let id = id.as_ref();
	let advertisement =
		ClusterRequest::AdvertisePeer(PeerAdvertisement { gateway_addr: gateway_addr.to_vec(), advertised_types });

	let inner = signed_control_frame_with(signer, id, advertisement).await?;
	let identity = TestIdentity::of(signer);
	let mut rumor = Version::V2
		.compose()
		.with_id(id)
		.with_order(UnixMillis::now().get())
		.with_message(GossipRumor::peer_advertisement(encode(&inner)?))
		.build()?;
	rumor.sign_with_provider(&identity).await?;

	let mut frame = Version::V2
		.compose()
		.with_id(id)
		.with_order(UnixMillis::now().get())
		.with_lifetime(hop_ttl)
		.with_message(ClusterRequest::Gossip(Box::new(rumor)))
		.build()?;
	frame.sign_with_provider(&identity).await?;

	let mut client = connect_cluster(connect_certs, cluster.addr()).await?;
	let response: GossipResponse = emit_frame(&mut client, frame).await?.decode_message()?;
	Ok(response.status)
}

/// Counts the live peer routes for `type_name` on `cluster`.
pub fn type_route_count(cluster: &ClusterGateway, type_name: impl AsRef<str>) -> usize {
	let type_name = type_name.as_ref();
	let canonical = servlet_urn(type_name).type_canonical_bytes();
	cluster
		.peer_routes()
		.expect("the gateway under test holds no poisoned lock")
		.iter()
		.filter(|route| route.servlet_type.as_ref() == canonical.as_slice())
		.count()
}

/// Polls until `cluster` holds `want` routes for `type_name` or the attempts
/// run out, and returns the count it holds.
pub async fn wait_for_type_routes(
	cluster: &ClusterGateway,
	type_name: impl AsRef<str>,
	want: usize,
	attempts: u32,
	interval: Duration,
) -> usize {
	let type_name = type_name.as_ref();
	poll_until(attempts, interval, || type_route_count(cluster, type_name) >= want).await;

	type_route_count(cluster, type_name)
}

/// Floods fresh advertisement rumors that claim `claimed_addr` for
/// `type_name` through `relay` until `trace` holds an installed relay trail,
/// or the attempts run out. The trail installs once the relay has promoted
/// the installing gateway as a flood target. Each branch lives here, so each
/// scenario reads as one straight line.
///
/// - Each flood discards the relay's answer, because a refused rumor floods again under a fresh id.
/// - The spec judges the count of [`events::CLUSTER_RELAY_TRAIL_INSTALLED`], so the wait returns no count.
async fn flood_until_relay_trail(
	trace: &TraceCollector,
	connect_certs: &ClusterTestCerts,
	signer: &Secp256k1SigningKey,
	relay: &ClusterGateway,
	claimed_addr: impl AsRef<[u8]>,
	type_name: impl AsRef<str>,
) -> Result<(), TightBeamError> {
	let claimed_addr = claimed_addr.as_ref();
	let type_name = type_name.as_ref();
	let installed = || trace.recorded(events::CLUSTER_RELAY_TRAIL_INSTALLED) > 0;
	for attempt in 0u32..50 {
		let id = format!("relay-ad-{type_name}-{attempt}");
		let _status = flood_ad_rumor(
			connect_certs,
			signer,
			relay,
			claimed_addr,
			vec![servlet_urn(type_name)],
			2,
			id.as_bytes(),
		)
		.await?;

		if poll_until(2, Duration::from_millis(100), installed).await {
			break;
		}
	}

	Ok(())
}

/// Whether any route for `type_name` on `cluster` dials `dial_addr`.
fn type_route_dials(cluster: &ClusterGateway, type_name: impl AsRef<str>, dial_addr: impl AsRef<[u8]>) -> bool {
	let type_name = type_name.as_ref();
	let dial_addr = dial_addr.as_ref();
	let canonical = servlet_urn(type_name).type_canonical_bytes();
	cluster
		.peer_routes()
		.expect("the gateway under test holds no poisoned lock")
		.iter()
		.any(|route| route.servlet_type.as_ref() == canonical.as_slice() && route.dial_addr.as_ref() == dial_addr)
}

tb_assert_spec! {
	pub ClusterTransitiveDiscoverySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_AD_LEARNED, at_least!(2)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1))
		]
	}
}

// Transitive discovery routes real work: A learns C's ping type only
// from B's relayed advertisement rumor, then dials C directly.
//
// - C anchors B and floods its slate rumor to it. B applies the rumor and
//   refloods it once its own beat promotes A.
// - C's dial allowlist admits only B, so C never dials A: the trail A installs can only come from the rumor.
// - The forward is one direct hop from A to C, with no data hop through B.
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

			let conf_c = federation_conf_allowing(
				&ctx.c,
				Arc::clone(&ctx.peers_of_c),
				vec![gateway_b.addr().to_string()],
				1,
			);

			let gateway_c = start_cluster(&trace, conf_c).await?;
			let gateway_a = start_cluster(&trace, federation_conf(&ctx.a, Arc::clone(&ctx.peers_of_a), vec![gateway_b.addr().to_string()], 1)).await?;

			hive.register_with_cluster(gateway_c.addr()).await?;

			let learned = wait_for_type_routes(&gateway_a, "ping", 1, 100, Duration::from_millis(100)).await;
			assert_eq!(learned, 1, "A learns the ping route of C from the rumor B relays");

			let mut client = connect_cluster(&ctx.a, gateway_a.addr()).await?;

			let servlet_frame = emit_ping_work(&mut client, &ctx.a.key, b"transitive-work").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			assert_eq!(ping_response.doubled, 42, "the ping servlet doubles the request");

			gateway_a.stop();
			gateway_c.stop();
			gateway_b.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterBoundHopSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_WORK_ROUTED, exactly!(0)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(0)),
			(events::CLUSTER_WORK_FAILED, exactly!(1), equals!(TransitStatus::Unavailable)),
			(events::CLUSTER_WORK_UNAVAILABLE, absent!())
		]
	}
}

// Client work reaches only the gateway that signed the advertisement.
//
// C serves ping. An advertisement under B's key claims C's address at A, and
// A trusts both on its peer plane. Neither gateway beats, so no probe touches
// the route.
//
// - A ends the hop before the client's frame leaves, so C routes no work (CLUSTER_WORK_ROUTED exactly 0).
// - A fails the forward, and the client reads the refusal as `Unavailable` (CLUSTER_WORK_FAILED).
tb_scenario! {
	name: cluster_work_reaches_only_the_gateway_that_advertised,
	spec: ClusterBoundHopSpec,
	environment Hive {
		context: federation_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_ping_hive(trace, Arc::clone(&ctx.c), None).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let mut conf_c = federation_conf(&ctx.c, Arc::clone(&ctx.peers_of_c), vec![], 1);
			conf_c.peer.advertise_interval = None;

			let gateway_c = start_cluster(&trace, conf_c).await?;
			hive.register_with_cluster(gateway_c.addr()).await?;

			let mut conf_a = federation_conf(&ctx.a, Arc::clone(&ctx.peers_of_a), vec![], 1);
			conf_a.peer.advertise_interval = None;

			let gateway_a = start_cluster(&trace, conf_a).await?;

			let claimed = gateway_c.addr().to_string();
			let ad_reply = advertise_peer_signed(&ctx.a, &ctx.b.key, &gateway_a, claimed.as_bytes(), vec![servlet_urn("ping")]).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(gateway_a.peer_servlets()?.len(), 1, "A installs the advertised ping route");

			let mut client = connect_cluster(&ctx.a, gateway_a.addr()).await?;

			let refused_work = emit_ping_work(&mut client, &ctx.a.key, b"bound-hop-work").await;
			let status = work_refusal_status(refused_work)?;
			assert_eq!(status, TransitStatus::Unavailable, "the client reads the refused hop as unavailable");

			gateway_a.stop();
			gateway_c.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// Gateway B under the certificate it rotated to, beside gateway A, which
/// imports B's routes.
///
/// - A's peer store enrolls B's certificate from before the rotation, and the rotated one after it.
/// - The rotated certificate keeps B's key and names another key identifier,
///   so B's advertisement names the rotated certificate alone.
struct RotationCtx {
	a: Arc<ClusterTestCerts>,
	b: Arc<ClusterTestCerts>,
	peers_of_a: Arc<dyn CertificateTrust>,
	peers_of_b: Arc<dyn CertificateTrust>,
}

/// The certificate gateway B rotates to: B's key under a name of its own, and
/// a `subjectKeyIdentifier` that a method other than the crate's derives.
fn rotated_certificate(key: &Secp256k1SigningKey) -> Certificate {
	let colony = test_colony_urn().to_string();
	let rotated = TestCertificate::with_cn_and_uri_sans(key, "Gateway B Rotated", &[&colony]);
	let identifier = OctetString::new([0x52u8; 20]).expect("twenty octets wrap in an OctetString");
	let rotated = TestCertificate::with_key_identifier(rotated, SubjectKeyIdentifier::from(identifier));

	TestCertificate::signed_by(rotated, key)
}

fn rotation_ctx() -> RotationCtx {
	let (cert_a, key_a) = member_identity("Gateway A");
	let (enrolled, key_b) = member_identity("Gateway B");
	let rotated = rotated_certificate(&key_b);
	let trust = combined_trust(&[&cert_a, &rotated]);
	let peers_of_a = RotatingTrust::new(combined_trust(&[&enrolled]), combined_trust(&[&rotated]));
	let peers_of_b = combined_trust(&[&cert_a]);

	RotationCtx {
		a: Arc::new(GatewayCerts { cert: cert_a, key: key_a, trust: Arc::clone(&trust) }),
		b: Arc::new(GatewayCerts { cert: rotated, key: key_b, trust }),
		peers_of_a,
		peers_of_b,
	}
}

tb_assert_spec! {
	pub ClusterRotatedPeerHopSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(0)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1))
		]
	}
}

// A gateway that rotated its certificate under one key keeps its name.
//
// B advertises to A under the rotated certificate, and A's peer store
// resolves B's key to the certificate it enrolled before the rotation.
//
// - A keys the route it learns from the advertisement by B's name.
// - B answers A's hop with the rotated certificate, and A names it by the
//   same rule (CLUSTER_DIAL_REFUSED exactly 0).
// - The work crosses to B and echoes (CLUSTER_WORK_FORWARDED).
tb_scenario! {
	name: cluster_peer_hop_admits_a_gateway_that_rotated_its_certificate,
	spec: ClusterRotatedPeerHopSpec,
	environment Hive {
		context: rotation_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_ping_hive(trace, Arc::clone(&ctx.b), None).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let conf_a = federation_conf(&ctx.a, Arc::clone(&ctx.peers_of_a), vec![], 1);
			let gateway_a = start_cluster(&trace, conf_a).await?;
			let conf_b = federation_conf(&ctx.b, Arc::clone(&ctx.peers_of_b), vec![gateway_a.addr().to_string()], 1);
			let gateway_b = start_cluster(&trace, conf_b).await?;

			hive.register_with_cluster(gateway_b.addr()).await?;

			let learned = wait_for_type_routes(&gateway_a, "ping", 1, 100, Duration::from_millis(100)).await;
			assert_eq!(learned, 1, "A keys the route of the rotated B by the name of B");

			let echo = submit_ping(&ctx.a, &gateway_a).await?;
			assert_eq!(echo.doubled, 42, "A routes to the rotated B");

			gateway_b.stop();
			gateway_a.stop();
			hive.stop();
			Ok(())
		}
	}
}

// The gateway that forwards the work runs `ClusterTlsConfig::validators` as
// the server policy of each dial on its peer plane, so a policy that admits
// no certificate leaves the work unrouted.
//
// The topology is that of
// `cluster_work_reaches_only_the_gateway_that_advertised`, with the
// advertisement signed by C's own key, so A's policy alone ends the hop.
//
// - A ends the hop at its dial to C, so C routes no work (CLUSTER_WORK_ROUTED exactly 0).
// - A fails the forward, and the client reads the refusal as `Unavailable` (CLUSTER_WORK_FAILED).
tb_scenario! {
	name: cluster_server_policy_runs_on_the_dial_to_its_peer,
	spec: ClusterBoundHopSpec,
	environment Hive {
		context: federation_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_ping_hive(trace, Arc::clone(&ctx.c), None).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let mut conf_c = federation_conf(&ctx.c, Arc::clone(&ctx.peers_of_c), vec![], 1);
			conf_c.peer.advertise_interval = None;

			let gateway_c = start_cluster(&trace, conf_c).await?;
			hive.register_with_cluster(gateway_c.addr()).await?;

			let refuses_every_server: Arc<dyn CertificateValidation> = Arc::new(DirectTrustValidator::default());
			let mut conf_a = federation_conf(&ctx.a, Arc::clone(&ctx.peers_of_a), vec![], 1);
			conf_a.peer.advertise_interval = None;
			conf_a.tls.validators = vec![refuses_every_server];

			let gateway_a = start_cluster(&trace, conf_a).await?;

			let claimed = gateway_c.addr().to_string();
			let slate = vec![servlet_urn("ping")];
			let ad_reply = advertise_peer_signed(&ctx.a, &ctx.c.key, &gateway_a, claimed.as_bytes(), slate).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(gateway_a.peer_servlets()?.len(), 1, "A installs the advertised ping route");

			let mut client = connect_cluster(&ctx.a, gateway_a.addr()).await?;

			let refused_work = emit_ping_work(&mut client, &ctx.a.key, b"peer-policy-work").await;
			let status = work_refusal_status(refused_work)?;
			assert_eq!(status, TransitStatus::Unavailable, "the client reads the refused hop as unavailable");

			gateway_a.stop();
			gateway_c.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterBoundStreamSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(STREAM_SERVLET_HANDLED, exactly!(0)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(1))
		]
	}
}

// A routed stream reaches only the gateway that signed the advertisement.
//
// The topology is the unary scenario above with stream-echo in place of ping.
//
// - A ends the splice at the dial, so C's servlet handles no stream (STREAM_SERVLET_HANDLED exactly 0).
// - A refuses its dial to the claimed address, where C answers under its own identity (CLUSTER_DIAL_REFUSED).
// - The client reads the refusal.
tb_scenario! {
	name: cluster_stream_reaches_only_the_gateway_that_advertised,
	spec: ClusterBoundStreamSpec,
	environment Hive {
		context: federation_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_stream_hive(trace, Arc::clone(&ctx.c)).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let mut conf_c = mux_federation_conf(&ctx.c, Arc::clone(&ctx.peers_of_c), vec![], 1);
			conf_c.peer.advertise_interval = None;

			let gateway_c = start_cluster(&trace, conf_c).await?;
			hive.register_with_cluster(gateway_c.addr()).await?;

			let mut conf_a = mux_federation_conf(&ctx.a, Arc::clone(&ctx.peers_of_a), vec![], 1);
			conf_a.peer.advertise_interval = None;

			let gateway_a = start_cluster(&trace, conf_a).await?;

			let claimed = gateway_c.addr().to_string();
			let types = vec![servlet_urn("stream-echo")];
			let ad_reply = advertise_peer_signed(&ctx.a, &ctx.b.key, &gateway_a, claimed.as_bytes(), types).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(gateway_a.peer_servlets()?.len(), 1, "A installs the advertised stream-echo route");

			let client = pooled_cluster_client(&trace, &ctx.a, gateway_a.addr()).await?;

			let (sink, response) = client.open_stream_to(servlet_urn("stream-echo"))?;
			let closed = sink.close_with(b"bound-hop").await;
			let answered = response.await;
			assert!(closed.is_err() || answered.is_err(), "the client reads the refused stream");

			gateway_a.stop();
			gateway_c.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterRelayFallbackSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(events::CLUSTER_PEER_AD_LEARNED, at_least!(1)),
			(events::CLUSTER_RELAY_TRAIL_INSTALLED, at_least!(1)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_WORK_FORWARDED, exactly!(2)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(0))
		]
	}
}

// Relay fallback runs end-to-end at `max_hops = 2`: the origin's advertised
// address is dead for A, yet work succeeds from A through B to C.
//
// - A learns C's slate only from a rumor that B relays, which claims a dead
//   dial address. A installs the dead direct trail and a relay trail through
//   B, whose dial address A knows from B's beacon slate.
// - B learns C's true address from a direct advertisement, so B's trail to C is live.
// - A's work spends its clamped budget of two. A dead direct pick weakens
//   and the bounded retry crosses the relay trail, while a relay pick crosses
//   it at once.
// - Two forwards prove the two-hop path, because A never reaches C in one.
//   Zero `CLUSTER_WORK_UNAVAILABLE` proves the fallback, because an exhausted
//   budget records one.
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

			// C serves ping at its real address with its advertise beat
			// off. The test injects both of C's advertisements, so no
			// fresh one repairs the dead claim at A.
			let mut conf_c = federation_conf(&ctx.c, Arc::clone(&ctx.peers_of_c), vec![], 1);
			conf_c.peer.advertise_interval = None;

			let gateway_c = start_cluster(&trace, conf_c).await?;
			hive.register_with_cluster(gateway_c.addr()).await?;

			let gateway_a = start_cluster(&trace, federation_conf(&ctx.a, Arc::clone(&ctx.peers_of_a), vec![gateway_b.addr().to_string()], 2)).await?;

			// A's two routes are the dead direct trail and the relay through B.
			flood_until_relay_trail(&trace, &ctx.a, &ctx.c.key, &gateway_b, DEAD_GATEWAY_ADDR, "ping").await?;

			// The direct advertisement restores C's true address at B, and
			// overwrites the dead claim that the rumors installed there.
			let true_addr = gateway_c.addr().to_string();
			let ad_reply = advertise_peer_signed(&ctx.a, &ctx.c.key, &gateway_b, true_addr.as_bytes(), vec![servlet_urn("ping")])
				.await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert!(
				type_route_dials(&gateway_b, "ping", true_addr.as_bytes()),
				"the direct advertisement of C restores its true address at B"
			);

			let mut client = connect_cluster(&ctx.a, gateway_a.addr()).await?;

			let servlet_frame = emit_ping_work(&mut client, &ctx.a.key, b"relay-fallback-work").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			assert_eq!(ping_response.doubled, 42, "the ping servlet doubles the request");

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
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(events::CLUSTER_PEER_AD_LEARNED, at_least!(1)),
			(events::CLUSTER_RELAY_TRAIL_INSTALLED, at_least!(1)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_WORK_FORWARDED, exactly!(2)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(0)),
			(STREAM_SERVLET_HANDLED, exactly!(1))
		]
	}
}

// Relay fallback covers routed streams at `max_hops = 2`. The topology is the
// unary scenario above, driven through a spliced stream instead of unary work.
//
// - A holds a dead direct trail and a relay trail through B, and B holds C's true address.
// - A's splice spends its clamped budget of two. A dead direct pick fails
//   at dial and the bounded retry crosses the relay trail, while a relay
//   pick crosses it at once.
// - Two forwards prove the two-hop splice, and `STREAM_SERVLET_HANDLED`
//   proves that the body crosses both hops intact.
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

			// C serves stream-echo at its real address with its advertise
			// beat off. The test injects both of C's advertisements, so no
			// fresh one repairs the dead claim at A.
			let mut conf_c = mux_federation_conf(&ctx.c, Arc::clone(&ctx.peers_of_c), vec![], 1);
			conf_c.peer.advertise_interval = None;

			let gateway_c = start_cluster(&trace, conf_c).await?;
			hive.register_with_cluster(gateway_c.addr()).await?;

			let gateway_a =
				start_cluster(&trace, mux_federation_conf(&ctx.a, Arc::clone(&ctx.peers_of_a), vec![gateway_b.addr().to_string()], 2)).await?;

			// A's two routes are the dead direct trail and the relay through B.
			flood_until_relay_trail(&trace, &ctx.a, &ctx.c.key, &gateway_b, DEAD_GATEWAY_ADDR, "stream-echo").await?;

			// The direct advertisement restores C's true address at B, and
			// overwrites the dead claim that the rumors installed there.
			let true_addr = gateway_c.addr().to_string();
			let ad_reply = advertise_peer_signed(
				&ctx.a,
				&ctx.c.key,
				&gateway_b,
				true_addr.as_bytes(),
				vec![servlet_urn("stream-echo")],
			)
			.await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert!(
				type_route_dials(&gateway_b, "stream-echo", true_addr.as_bytes()),
				"the direct advertisement of C restores its true address at B"
			);

			let client = pooled_cluster_client(&trace, &ctx.a, gateway_a.addr()).await?;

			let (mut sink, response) = client.open_stream_to(servlet_urn("stream-echo"))?;
			sink.push(b"abcd").await?;
			sink.close_with(b"efgh").await?;

			let reply = response.await?.ok_or(TightBeamError::MissingResponse)?;
			let echoed: PingResponse = reply.decode_message()?;
			assert_eq!(echoed.doubled, 8, "the body crossed both hops intact");

			gateway_a.stop();
			gateway_c.stop();
			gateway_b.stop();
			beacon_hive.stop();
			hive.stop();
			Ok(())
		}
	}
}

// A zero-hop gateway clamps the origin sentinel, the client's "as far as
// policy allows" budget, to zero, so a peer-only type refuses `Unavailable`.
// The loop-guard spec applies, because a spent wire budget has this contract.
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
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let ad_reply = install_ping_peer(&certs, &cluster).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");

			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			let refused_work = emit_ping_work(&mut client, &certs.key, b"sentinel-clamp").await;
			let status = work_refusal_status(refused_work)?;
			assert_eq!(status, TransitStatus::Unavailable, "a zero-hop gateway leaves a peer-only type unavailable");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterStreamBudgetSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(1))
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
			let ad_reply = advertise_peer(&certs, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("stream-echo")]).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");

			let config = PoolConfig {
				idle_timeout: None,
				max_connections: NonZeroUsize::MIN,
				mux_offer: Some(Arc::new(TransportOffer::mux(8)))
			};
			let pool = Arc::new(
				ConnectionPool::<TokioListener>::builder()
					.with_config(config)
					.with_trust_store(Arc::clone(&certs.trust))
					.with_trace(trace.share())
					.build(),
			);
			let client = pool.connect(cluster.addr().to_owned()).await?;

			let (sink, response) = client.open_stream_to(servlet_urn("stream-echo"))?;
			sink.close_with(b"budget-spent").await?;

			let refused = response.await.is_err();
			assert!(refused, "a zero-hop gateway refuses a routed stream to a peer-only type");

			cluster.stop();
			Ok(())
		}
	}
}

/// A balancer that pins the first pick to one route key, so a scenario
/// deterministically dials a decoy before the bounded failover. An unset or
/// excluded preference defers to the first candidate.
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
fn pin_preference(cell: &Mutex<Option<Vec<u8>>>, key: impl Into<Vec<u8>>) {
	let key: Vec<u8> = key.into();
	let mut preferred = cell.lock().expect("preference lock poisons only after a balancer panic");
	*preferred = Some(key);
}

/// The route key `cluster` holds for `type_name` toward `dial_addr`, read from
/// the operator view so the key discipline stays with the registry.
fn peer_route_key_for_dial(
	cluster: &ClusterGateway,
	type_name: impl AsRef<str>,
	dial_addr: impl AsRef<[u8]>,
) -> Option<Vec<u8>> {
	let type_name = type_name.as_ref();
	let dial_addr = dial_addr.as_ref();
	let canonical = servlet_urn(type_name).type_canonical_bytes();
	cluster
		.peer_routes()
		.expect("the gateway under test holds no poisoned lock")
		.into_iter()
		.find(|route| route.dial_addr.as_ref() == dial_addr && route.servlet_type.as_ref() == canonical.as_slice())
		.map(|route| route.route_key.to_vec())
}

tb_assert_spec! {
	pub ClusterLiveDecoyFailoverSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(2)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1))
		]
	}
}

// A live decoy answers but cannot serve: its well-formed `Unavailable`
// reply joins the bounded failover, and the client never reads it.
//
// - B is a live member gateway with no ping servlet. Its injected
//   advertisement claims ping at its own address, so A installs a
//   trail to a gateway that answers and refuses.
// - Every advertise beat is off, so both of A's trails come from the
//   two injected advertisements and the event counts are exact.
// - The pinned balancer makes A dial B first, deterministically. The
//   one `CLUSTER_WORK_UNAVAILABLE` fires on B, never on A.
// - The echo proves the failover: A weakens the decoy trail and retries C's trail within the same request.
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
			let ad_reply = advertise_peer_signed(&ctx.a, &ctx.b.key, &gateway_a, decoy_addr.as_bytes(), vec![servlet_urn("ping")])
				.await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			let origin_addr = gateway_c.addr().to_string();
			let ad_reply = advertise_peer_signed(
				&ctx.a,
				&ctx.c.key,
				&gateway_a,
				origin_addr.as_bytes(),
				vec![servlet_urn("ping")],
			)
			.await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			let installed = wait_for_type_routes(&gateway_a, "ping", 2, 100, Duration::from_millis(100)).await;
			assert_eq!(installed, 2, "the decoy and the honest trail install");

			let decoy_key = peer_route_key_for_dial(&gateway_a, "ping", decoy_addr.as_bytes())
				.ok_or(TightBeamError::MissingResponse)?;
			pin_preference(&preferred, decoy_key);

			let mut client = connect_cluster(&ctx.a, gateway_a.addr()).await?;

			let servlet_frame = emit_ping_work(&mut client, &ctx.a.key, b"live-decoy-failover").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			assert_eq!(ping_response.doubled, 42, "the ping servlet doubles the request");

			gateway_a.stop();
			gateway_c.stop();
			gateway_b.stop();
			hive.stop();
			Ok(())
		}
	}
}
