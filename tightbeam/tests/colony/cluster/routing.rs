//! The tests of work routing through the cluster gateway.

use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use tightbeam::colony::hive::{HiveContext, HiveContextImpl};
use tightbeam::crypto::x509::policy::{CertificateValidation, DirectTrustValidator};
use tightbeam::testing::TestDigest;
use tightbeam::{cluster, servlet};

#[cfg(feature = "instrument")]
use tightbeam::testing::fixtures::TestTrace;

use super::common::*;
use super::federation::{federation_conf, wait_for_type_routes};
use crate::common::security::expectation_failure;

tb_assert_spec! {
	pub ClusterRoutingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1))
		]
	}
}

tb_scenario! {
	name: cluster_work_routing,
	spec: ClusterRoutingSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, routing_cluster_conf(&certs, Some(TransportOffer::mux(8)))).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![start_ping_hive(trace, certs, Some(TransportOffer::mux(8)))],
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let echo = submit_ping(&certs, &cluster).await?;
			assert_eq!(echo.doubled, 42, "the ping servlet doubles the request");
			cluster.stop();
			Ok(())
		}
	}
}

// This scenario takes the same routing path with no mux offer, so colony
// links stay single-flight.
tb_scenario! {
	name: cluster_work_routing_single_flight,
	spec: ClusterRoutingSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, routing_cluster_conf(&certs, None)).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![start_ping_hive(trace, certs, None)],
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let echo = submit_ping(&certs, &cluster).await?;
			assert_eq!(echo.doubled, 42, "the ping servlet doubles the request");
			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterServerPolicySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(0)),
			(events::CLUSTER_WORK_FAILED, exactly!(1), equals!(TransitStatus::Unavailable)),
			(events::CLUSTER_WORK_UNAVAILABLE, absent!())
		]
	}
}

// The gateway runs `ClusterTlsConfig::validators` as the server policy of each
// dial to its hive, so a policy that admits no certificate leaves the work
// unrouted. `cluster_work_routing_single_flight` routes it with no policy.
tb_scenario! {
	name: cluster_server_policy_runs_on_the_dial_to_its_hive,
	spec: ClusterServerPolicySpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let refuses_every_server: Arc<dyn CertificateValidation> = Arc::new(DirectTrustValidator::default());
			let mut conf = routing_cluster_conf(&certs, None);
			conf.tls.validators = vec![refuses_every_server];
			start_cluster(&trace, conf).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![start_ping_hive(trace, certs, None)],
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			let refused_work = emit_ping_work(&mut client, &certs.key, b"server-policy-work").await;
			check_work_refusal(refused_work, TransitStatus::Unavailable)?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterMultiGatewaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, at_least!(2), equals!(1u64)),
			(events::CLUSTER_REGISTER_REFUSED, absent!()),
			(events::CLUSTER_WORK_ROUTED, exactly!(2))
		]
	}
}

// One hive registers with two independent gateways, and each gateway counts
// exactly this hive and routes work to the same servlet slate. The hive keeps
// each registry fresh as soft state, so the redundancy needs no consensus.
tb_scenario! {
	name: cluster_hive_serves_two_gateways,
	spec: ClusterMultiGatewaySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, Some(TransportOffer::mux(8))),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let first = start_cluster(&trace, routing_cluster_conf(&certs, Some(TransportOffer::mux(8)))).await?;
			let second = start_cluster(&trace, routing_cluster_conf(&certs, Some(TransportOffer::mux(8)))).await?;

			hive.register_with_cluster(first.addr()).await?;
			hive.register_with_cluster(second.addr()).await?;

			let first_echo = submit_ping(&certs, &first).await?;
			let second_echo = submit_ping(&certs, &second).await?;
			assert_eq!(first_echo.doubled, 42, "the first gateway routes to the servlet");
			assert_eq!(second_echo.doubled, 42, "the second gateway routes to the servlet");

			first.stop();
			second.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterInstanceWorkSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_WORK_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// The scenarios below prove end-to-end delivery of cluster-routed work. The
// servlet handler receives the frame the client created, and the client
// receives the frame the servlet responded with.

servlet! {
	/// Records what the handler observes about the frame it receives for
	/// cluster-routed work, and responds with a signed frame so the client can
	/// verify the response envelope the same way.
	///
	/// The probes cover:
	///
	/// - the client's frame id,
	/// - the nonrepudiation block,
	/// - the previous-frame linkage,
	/// - whether the client's signature verifies over the received bytes.
	pub FrameProbeServlet<PingRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |req, frame, ctx| async move {
		let trace = ctx.trace();

		// The SIGNED and PREVIOUS probes witness presence only. Byte fidelity
		// rests on SIG_VALID alone, whose signature check covers the frame's
		// to-be-signed bytes, so no change may weaken that probe.
		let sig_valid = frame_signature_verifies(&frame, &probe_signing_key());

		trace.event_with(PROBE_FRAME_CLIENT_ID, &[], u32::from(frame.metadata().id() == b"client-signed-work"))?;
		trace.event_with(PROBE_FRAME_SIGNED, &[], u32::from(frame.nonrepudiation().is_some()))?;
		trace.event_with(PROBE_FRAME_PREVIOUS, &[], u32::from(frame.metadata().previous_frame().is_some()))?;
		trace.event_with(PROBE_FRAME_SIG_VALID, &[], u32::from(sig_valid))?;

		let unsigned = Version::V1.compose()
			.with_id(b"probe-response")
			.with_message(PingResponse { doubled: req.value * 2 })
			.build()?;

		Ok(Some(sign_frame(unsigned, &probe_signing_key()).await?))
	}
}

/// Starts a hive of the probe servlet, registered under the ping type, on the
/// scenario trace.
async fn start_probe_hive(
	trace: TraceCollector,
	certs: Arc<ClusterTestCerts>,
) -> Result<ClusterTestHive, TightBeamError> {
	let servlet_conf = servlet_tls_config(&certs)?;
	let servlet = FrameProbeServlet::start(Arc::new(trace.share()), servlet_conf).await?;

	let mut hive = ClusterTestHive::new(Some(hive_tls_config(&certs)))?;
	hive.register(servlet_urn("ping"), servlet, |t| {
		FrameProbeServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// What the client observes of one full-frame delivery: the frame it sent,
/// and the servlet's response frame that the gateway relays back.
#[derive(Debug, PartialEq)]
struct FrameContract {
	/// Whether the client frame carries its signature.
	sent_signed: bool,
	/// Whether the client frame links its previous frame.
	sent_linked: bool,
	/// The id of the response frame.
	reply_id: Vec<u8>,
	/// Whether the response frame keeps the servlet's signature.
	reply_signed: bool,
	/// Whether that signature verifies over the received bytes.
	reply_verifies: bool,
	/// The value that the ping servlet answered.
	doubled: u32,
}

impl FrameContract {
	/// The delivery the contract promises: a signed client frame that links
	/// its previous frame, and the servlet's own signed frame, which doubles
	/// the request.
	fn held() -> Self {
		Self {
			sent_signed: true,
			sent_linked: true,
			reply_id: b"probe-response".to_vec(),
			reply_signed: true,
			reply_verifies: true,
			doubled: 42,
		}
	}
}

/// Sends the standard signed contract frame to `gateway` from the client
/// side, and returns every client-observable property of the delivery.
///
/// The local-delivery and peer-hop scenarios share it, so both routes prove
/// the identical contract.
async fn submit_contract_frame(
	certs: &ClusterTestCerts,
	gateway: &ClusterGateway,
) -> Result<FrameContract, TightBeamError> {
	let unsigned = Version::V2
		.compose()
		.with_id(b"client-signed-work")
		.with_order(UnixMillis::now().get())
		.with_previous_hash(TestDigest::info())
		.with_message(PingRequest { value: 21 })
		.build()?;

	let inner = sign_frame(unsigned, &probe_signing_key()).await?;
	let sent_signed = inner.nonrepudiation().is_some();
	let sent_linked = inner.metadata().previous_frame().is_some();

	let mut client = connect_cluster(certs, gateway.addr()).await?;

	// The public client surface under test is this one call. It wraps the work
	// frame in the hop-local transport envelope and resolves the gateway's
	// reply down to the servlet's response frame.
	let servlet_frame = client.submit_work_to(servlet_urn("ping"), &inner).await?;

	let reply_id = servlet_frame.metadata().id().to_vec();
	let reply_signed = servlet_frame.nonrepudiation().is_some();
	let reply_verifies = frame_signature_verifies(&servlet_frame, &probe_signing_key());

	let ping_response: PingResponse = decode(servlet_frame.message())?;
	let doubled = ping_response.doubled;
	Ok(FrameContract { sent_signed, sent_linked, reply_id, reply_signed, reply_verifies, doubled })
}

tb_assert_spec! {
	pub ClusterClientFrameDeliverySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(PROBE_FRAME_CLIENT_ID, exactly!(1), equals!(1u32)),
			(PROBE_FRAME_SIGNED, exactly!(1), equals!(1u32)),
			(PROBE_FRAME_PREVIOUS, exactly!(1), equals!(1u32)),
			(PROBE_FRAME_SIG_VALID, exactly!(1), equals!(1u32))
		]
	}
}

// The client nests its complete signed frame in the work payload and submits
// it as unary work. The servlet's SIG_VALID probe and the client's reply check
// prove byte fidelity, because a signature verifies only over the signed bytes.
tb_scenario! {
	name: cluster_work_delivers_client_frame,
	spec: ClusterClientFrameDeliverySpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, routing_cluster_conf(&certs, None)).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![start_probe_hive(trace, certs)],
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let contract = submit_contract_frame(&certs, &cluster).await?;
			assert_eq!(contract, FrameContract::held());

			cluster.stop();
			Ok(())
		}
	}
}

// Work must target a servlet TYPE: the gateway refuses instance-narrowed URNs
// even when the type is routable, so nothing bypasses the load balancer.
tb_scenario! {
	name: cluster_refuses_instance_addressed_work,
	spec: ClusterInstanceWorkSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, routing_cluster_conf(&certs, None)).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![start_ping_hive(trace, certs, None)],
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let inner = signed_work_frame(&certs.key, b"instance-work").await?;
			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			let instance = servlet_urn("ping").servlet_instance("127.0.0.1:9999")?;
			let refused_work = client.submit_work_to(instance, &inner).await;
			check_work_refusal(refused_work, TransitStatus::PermissionDenied)?;

			cluster.stop();

			Ok(())
		}
	}
}

// Peer-hop frame delivery: the same end-to-end contract must hold when a
// peer forward, not a local route, reaches the gateway that serves the work.

/// The certificates and peer trust of two member gateways with distinct
/// identities.
///
/// Gateway B hosts the probe hive and anchors gateway A, so A learns
/// B's ping route from B's advertisement beat and forwards work to it.
struct PeerHopCtx {
	a: Arc<ClusterTestCerts>,
	b: Arc<ClusterTestCerts>,
	peers_of_a: Arc<dyn CertificateTrust>,
	peers_of_b: Arc<dyn CertificateTrust>,
}

fn peer_hop_ctx() -> PeerHopCtx {
	let (cert_a, key_a) = member_identity("Hop Gateway A");
	let (cert_b, key_b) = member_identity("Hop Gateway B");
	let trust = combined_trust(&[&cert_a, &cert_b]);
	let peers_of_a = combined_trust(&[&cert_b]);
	let peers_of_b = combined_trust(&[&cert_a]);

	PeerHopCtx {
		a: Arc::new(GatewayCerts { cert: cert_a, key: key_a, trust: Arc::clone(&trust) }),
		b: Arc::new(GatewayCerts { cert: cert_b, key: key_b, trust }),
		peers_of_a,
		peers_of_b,
	}
}

tb_assert_spec! {
	pub ClusterPeerHopFrameDeliverySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, exactly!(2)),
			(PROBE_FRAME_CLIENT_ID, exactly!(1), equals!(1u32)),
			(PROBE_FRAME_SIGNED, exactly!(1), equals!(1u32)),
			(PROBE_FRAME_PREVIOUS, exactly!(1), equals!(1u32)),
			(PROBE_FRAME_SIG_VALID, exactly!(1), equals!(1u32))
		]
	}
}

// The client's frames keep their envelopes across a gateway relay:
// - A holds only B's ping route, so the work crosses the peer plane before B hands it to the probe servlet.
// - Every PROBE_FRAME_* assertion and client check of the local contract must hold, both signatures included.
// - CLUSTER_WORK_FORWARDED pins the peer hop.
// - The two CLUSTER_WORK_ROUTED events pin one reinforced trail per gateway.
tb_scenario! {
	name: cluster_peer_hop_preserves_end_to_end_frames,
	spec: ClusterPeerHopFrameDeliverySpec,
	environment Hive {
		context: peer_hop_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_probe_hive(trace, Arc::clone(&ctx.b)).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let gateway_a =
				start_cluster(&trace, federation_conf(&ctx.a, Arc::clone(&ctx.peers_of_a), vec![], 1)).await?;
			let gateway_b = start_cluster(
				&trace,
				federation_conf(&ctx.b, Arc::clone(&ctx.peers_of_b), vec![gateway_a.addr().to_string()], 1),
			)
			.await?;

			hive.register_with_cluster(gateway_b.addr()).await?;

			let learned = wait_for_type_routes(&gateway_a, "ping", 1, 100, Duration::from_millis(100)).await;
			assert_eq!(learned, 1, "gateway A learns B's ping route");

			let contract = submit_contract_frame(&ctx.a, &gateway_a).await?;
			assert_eq!(contract, FrameContract::held());

			gateway_b.stop();
			gateway_a.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterMalformedWorkSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_WORK_REFUSED, exactly!(1), equals!(TransitStatus::InvalidArgument)),
			(events::CLUSTER_WORK_FAILED, exactly!(0)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(0)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1))
		]
	}
}

// A work payload that fails to decode as a frame is a permanent caller fault,
// so the gateway must refuse it as InvalidArgument at admission, before route
// selection.
// - Zero CLUSTER_WORK_FAILED proves the gateway weakened no healthy pheromone
//   trail and burned no failover retry.
// - The valid work that follows echoes through the same trail, which proves the route stays serviceable.
tb_scenario! {
	name: cluster_refuses_malformed_work_payload,
	spec: ClusterMalformedWorkSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, routing_cluster_conf(&certs, None)).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![start_ping_hive(trace, certs, None)],
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			// The test composes the dual wrap by hand because the malformed
			// `Work` payload is itself the wire shape under test.
			let malformed = ClusterWorkRequest {
				servlet_type: servlet_urn("ping"),
				payload: b"not-a-frame".to_vec(),
				hops_remaining: 0,
			};

			let frame = Version::V0.compose()
				.with_id(b"malformed-work")
				.with_order(0)
				.with_message(ClusterRequest::Work(malformed))
				.build()?;

			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			let response_frame = emit_frame(&mut client, frame).await?;
			let work_response: ClusterWorkResponse = decode(response_frame.message())?;
			check_refused_reply(&work_response);

			let echo = submit_ping(&certs, &cluster).await?;
			assert_eq!(echo.doubled, 42, "a well-formed request still routes");

			cluster.stop();

			Ok(())
		}
	}
}

cluster! {
	/// A gateway with an edge accept plane, which proves the `edge:` macro arm.
	///
	/// The edge protocol matches the colony protocol here because core
	/// ships one async transport, so the transport extensions exercise a
	/// mixed-transport colony (TCP colony, WebSocket edge).
	EdgeClusterGateway,
	protocol: TokioListener,
	edge: TokioListener
}

tb_assert_spec! {
	pub ClusterEdgePlaneSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_EDGE_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1))
		]
	}
}

// The edge accept plane is a work-only surface on its own listener:
// - Work at the edge address routes to the servlet as colony work does.
// - The edge refuses a validly signed hive registration on the same connection with PermissionDenied.
// - The hive registers through the colony plane alone, so CLUSTER_HIVE_REGISTERED stays 1.
tb_scenario! {
	name: cluster_edge_plane_admits_work_only,
	spec: ClusterEdgePlaneSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let mut conf = routing_cluster_conf(&certs, Some(TransportOffer::mux(8)));
			conf.edge_bind_addr = Some("127.0.0.1:0".into());
			EdgeClusterGateway::start(Arc::new(trace.share()), conf).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![start_ping_hive(trace, certs, Some(TransportOffer::mux(8)))],
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let Some(edge_addr) = cluster.edge_addr() else {
				return Err(expectation_failure("edge plane did not bind"));
			};

			let inner = signed_work_frame(&certs.key, b"edge-work").await?;

			let mut client = connect_cluster(&certs, edge_addr).await?;
			let servlet_frame = client.submit_work_to(servlet_urn("ping"), &inner).await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			assert_eq!(ping_response.doubled, 42, "the ping servlet doubles the request");

			let signed = signed_control_frame(
				&certs,
				b"edge-reg",
				registration_request(b"127.0.0.1:65001"),
			)
			.await?;

			let response_frame = emit_frame(&mut client, signed).await?;
			let refusal: ClusterWorkResponse = decode(response_frame.message())?;
			assert_eq!(refusal.status, TransitStatus::PermissionDenied, "the edge refuses a registration");

			cluster.stop();

			Ok(())
		}
	}
}

// The edge plane names the caller of a refused unary call by the key that its
// session proved. Two refusals on one session name one caller, though each
// frame claims a signer of its own (CWE-345).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn cluster_edge_refusal_names_the_session_and_not_the_frame_signer() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let trace = payload_trace();
	let mut tls = cluster_tls_config(&certs);
	tls.client_authentication = PeerAuthentication::Anonymous.and(combined_validator(&[&certs.cert]));

	let mut conf = ClusterConfig::new(tls);
	conf.edge_bind_addr = Some("127.0.0.1:0".into());

	let cluster = EdgeClusterGateway::start(Arc::new(trace.share()), conf).await?;
	let edge_addr = cluster
		.edge_addr()
		.ok_or_else(|| expectation_failure("edge plane did not bind"))?;

	let identity = signing_identity(certs.cert.to_owned(), certs.key.to_owned());
	let builder = ClientBuilder::<TokioListener>::builder().with_trust_store(Arc::clone(&certs.trust));
	let mut client = builder
		.with_client_identity(identity)
		.build()
		.connect(edge_addr.to_owned())
		.await?;

	let own = signed_control_frame_with(&certs.key, b"edge-own", registration_request(b"127.0.0.1:65001")).await?;
	let claimed = registration_request(b"127.0.0.1:65002");
	let claimed = signed_control_frame_with(&probe_signing_key(), b"edge-claimed", claimed).await?;

	emit_frame(&mut client, own).await?;
	emit_frame(&mut client, claimed).await?;
	cluster.stop();

	let callers = payload_digests(&trace, events::CLUSTER_EDGE_REFUSED);
	let session = callers.first().copied().flatten();
	assert!(session.is_some());
	assert_eq!(callers, [session, session]);
	Ok(())
}

/// Whether `started` failed on a bind address that names `octets`.
fn refused_the_address<T>(started: &Result<T, TightBeamError>, octets: &[u8]) -> bool {
	let Err(TightBeamError::ClusterError(error)) = started else {
		return false;
	};

	matches!(error.as_ref(), ClusterError::InvalidAddress(named) if named.as_slice() == octets)
}

// A configured edge plane that cannot parse its bind address fails
// Cluster::start closed: the call returns Err and no accept loop outlives it
// (bind-then-spawn owns both listeners before spawn).
#[tokio::test]
async fn cluster_edge_bind_failure_fails_start() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let mut conf = routing_cluster_conf(&certs, Some(TransportOffer::mux(8)));
	conf.edge_bind_addr = Some("not-a-socket-addr".into());

	let started = EdgeClusterGateway::start(Arc::new(TraceCollector::new()), conf).await;
	let unparsed = refused_the_address(&started, b"not-a-socket-addr");
	assert!(unparsed, "an unparsable edge bind address fails Cluster::start");
	Ok(())
}

servlet! {
	/// The first instance of a two-instance type. It reads each frame and
	/// answers with no frame, so the forward that reached it ends after a
	/// delivered frame.
	FirstInstanceServlet<PingRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |_req, _frame, ctx| async move {
		ctx.trace().event(FIRST_INSTANCE_RECEIVED)?;
		Ok(None)
	}
}

servlet! {
	/// The second instance of a two-instance type. It echoes the ping, so a
	/// forward that reached it routes.
	SecondInstanceServlet<PingRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |req, frame, _ctx| async move {
		let response = Version::V0.compose()
			.with_id(frame.metadata().id())
			.with_message(PingResponse { doubled: req.value * 2 })
			.build()?;
		Ok(Some(response))
	}
}

/// A balancer that picks the instance at `first` while it is in the draw,
/// and the first candidate otherwise, so a scenario decides which instance
/// a forward tries before the bounded retry.
struct FirstAddressBalancer {
	first: Vec<u8>,
}

impl LoadBalancer for FirstAddressBalancer {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		let preferred = candidates.iter().position(|candidate| candidate.instance_key == self.first);
		preferred.or_else(|| candidates.first().map(|_| 0))
	}
}

/// A loopback port that refuses every connect for as long as this value
/// lives, against a concurrent test that binds a port of its own.
///
/// - The socket holds the port in the bound state, so the kernel answers a connect to it with a reset.
/// - The socket binds with `SO_REUSEADDR` cleared, so every other bind of the port conflicts with it.
/// - A port that went back to the kernel could go to a listener of another test, which would answer the dial.
struct RefusingPort {
	_held: HeldPort,
	address: String,
}

impl RefusingPort {
	/// Holds a fresh loopback port.
	fn hold() -> Self {
		let held = HeldPort::hold(Ipv4Addr::LOCALHOST, PortSharing::Exclusive);
		let address = held.address().to_string();

		Self { _held: held, address }
	}

	/// Returns the held port's address, in the spelling a hive registers.
	fn address(&self) -> &str {
		&self.address
	}
}

/// Starts a gateway whose balancer tries `first` before any other instance,
/// and registers one hive that serves `ping` at `first` and at `second`. The
/// hive pool offers `mux_offer`, or stays single-flight with none.
async fn gateway_trying_first(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	first: &str,
	second: &str,
	mux_offer: Option<TransportOffer>,
) -> Result<(ClusterGateway, GenericClient<TokioListener>), TightBeamError> {
	let balancer = FirstAddressBalancer { first: first.as_bytes().to_vec() };
	let builder = ClusterConfig::builder(cluster_tls_config(certs));
	let mut conf = builder.with_load_balancer(balancer).build();
	conf.pool_config.mux_offer = mux_offer.map(Arc::new);

	let cluster = start_cluster(trace, conf).await?;

	let mut client = connect_cluster(certs, cluster.addr()).await?;
	let hive_addr = b"127.0.0.1:65030";
	let servlets = [servlet_info(certs, "ping", first), servlet_info(certs, "ping", second)];
	register_signed_hive_serving(&mut client, &certs.key, b"two", hive_addr, servlets).await?;

	Ok((cluster, client))
}

tb_assert_spec! {
	pub ClusterNoRetryAfterDeliverySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(FIRST_INSTANCE_RECEIVED, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, absent!()),
			(events::CLUSTER_WORK_FAILED, exactly!(1), equals!(TransitStatus::Unknown))
		]
	}
}

// A signed client command runs at most once. The frame may have run at the
// first instance, so the gateway keeps it there and answers the client that
// the outcome is unknown.
tb_scenario! {
	name: cluster_work_never_retries_a_frame_the_first_instance_read,
	spec: ClusterNoRetryAfterDeliverySpec,
	environment Bare {
		context: cluster_certs(),
		exec: |SetupEnv { trace, context: certs }| async move {
			let first = FirstInstanceServlet::start(Arc::new(trace.share()), servlet_tls_config(&certs)?).await?;
			let second = SecondInstanceServlet::start(Arc::new(trace.share()), servlet_tls_config(&certs)?).await?;
			let first_addr = first.addr().to_string();
			let second_addr = second.addr().to_string();
			let (cluster, mut client) = gateway_trying_first(&trace, &certs, &first_addr, &second_addr, None).await?;

			let refused = emit_ping_work(&mut client, &certs.key, b"read-once").await;
			check_work_refusal(refused, TransitStatus::Unknown)?;

			cluster.stop();
			first.stop();
			second.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterRetryAfterRefusedConnectSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_FAILED, exactly!(1), equals!(TransitStatus::Unavailable)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1))
		]
	}
}

// A refused connect proves the frame never left, so the bounded retry takes
// it to the second instance, which answers.
tb_scenario! {
	name: cluster_work_retries_a_frame_the_first_instance_refused,
	spec: ClusterRetryAfterRefusedConnectSpec,
	environment Bare {
		context: cluster_certs(),
		exec: |SetupEnv { trace, context: certs }| async move {
			let second = SecondInstanceServlet::start(Arc::new(trace.share()), servlet_tls_config(&certs)?).await?;
			let refusing = RefusingPort::hold();
			let first_addr = refusing.address();
			let second_addr = second.addr().to_string();
			let (cluster, mut client) = gateway_trying_first(&trace, &certs, first_addr, &second_addr, None).await?;

			let echoed = emit_ping_work(&mut client, &certs.key, b"refused-first").await?;
			let ping = decode_ping_echo(&echoed)?;
			assert_eq!(ping.doubled, 42, "the second instance doubles the request");

			cluster.stop();
			second.stop();
			Ok(())
		}
	}
}

servlet! {
	/// The first instance behind an [`OversizedReplyRelay`]. It sets its
	/// environment flag once it ran the frame, so the relay answers the
	/// gateway in place of its reply, and echoes the ping.
	RelayedFirstServlet<PingRequest, EnvConfig = AtomicBool>,
	protocol: TokioListener,
	handle: |req, frame, ctx| async move {
		ctx.trace().event(FIRST_INSTANCE_RECEIVED)?;
		ctx.env_config().store(true, Ordering::SeqCst);

		let response = Version::V0.compose()
			.with_id(frame.metadata().id())
			.with_message(PingResponse { doubled: req.value * 2 })
			.build()?;
		Ok(Some(response))
	}
}

/// The length octets a relayed reply header carries: 1 MiB, past the 256 KiB
/// cap the gateway reads an encrypted envelope under.
const OVERSIZED_LENGTH: [u8; 4] = [0x83, 0x10, 0x00, 0x00];

/// A loopback relay in front of one servlet, as an on-path party that
/// rewrites the length octets of a reply.
///
/// - The relay forwards the handshake and the request whole.
/// - Once the servlet's handler ran, the relay answers the gateway with the
///   tag of the servlet's reply and [`OVERSIZED_LENGTH`] in place of that
///   reply.
struct OversizedReplyRelay {
	address: String,
	task: JoinHandle<()>,
}

impl OversizedReplyRelay {
	/// Relays each connection to the servlet at `servlet`, whose handler sets
	/// `ran`.
	async fn start(servlet: String, ran: Arc<AtomicBool>) -> Self {
		let bound = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await;
		let listener = bound.expect("a loopback port binds");
		let address = listener.local_addr().expect("a bound listener has an address").to_string();
		let task = tokio::spawn(async move {
			while let Ok((gateway, _)) = listener.accept().await {
				let Ok(upstream) = TcpStream::connect(servlet.as_str()).await else {
					return;
				};

				tokio::spawn(Self::relay(gateway, upstream, Arc::clone(&ran)));
			}
		});

		Self { address, task }
	}

	/// Returns the relay's address, in the spelling a hive registers.
	fn address(&self) -> &str {
		&self.address
	}

	/// Forwards the gateway's bytes to the servlet, and the servlet's replies
	/// to the gateway through [`Self::replies`].
	async fn relay(gateway: TcpStream, servlet: TcpStream, ran: Arc<AtomicBool>) {
		let (mut gateway_read, mut gateway_write) = gateway.into_split();
		let (mut servlet_read, mut servlet_write) = servlet.into_split();
		let requests = tokio::io::copy(&mut gateway_read, &mut servlet_write);
		let replies = Self::replies(&mut servlet_read, &mut gateway_write, &ran);

		// Either side's close ends the relay of this connection, and the
		// scenario reads the gateway's answer, so the relay reads neither
		// outcome.
		let _ended = tokio::join!(requests, replies);
	}

	/// Forwards each DER element the servlet writes until its handler ran,
	/// and then writes the element's tag and [`OVERSIZED_LENGTH`] in its place.
	async fn replies(
		servlet: &mut OwnedReadHalf,
		gateway: &mut OwnedWriteHalf,
		ran: &AtomicBool,
	) -> std::io::Result<()> {
		loop {
			let (tag, element) = Self::read_element(servlet).await?;
			if ran.load(Ordering::SeqCst) {
				let header = [&[tag], &OVERSIZED_LENGTH[..]].concat();
				return gateway.write_all(&header).await;
			}

			gateway.write_all(&element).await?;
		}
	}

	/// Reads one DER element off `stream`, and returns its tag beside the
	/// whole element.
	async fn read_element(stream: &mut OwnedReadHalf) -> std::io::Result<(u8, Vec<u8>)> {
		let mut header = [0u8; 2];
		stream.read_exact(&mut header).await?;
		let [tag, first] = header;
		let mut element = header.to_vec();

		let length = if first < 0x80 {
			usize::from(first)
		} else {
			let mut octets = vec![0u8; usize::from(first & 0x7f)];
			stream.read_exact(&mut octets).await?;
			element.extend_from_slice(&octets);
			octets.iter().fold(0, |length, octet| (length << 8) | usize::from(*octet))
		};

		let start = element.len();
		element.resize(start + length, 0);
		stream.read_exact(&mut element[start..]).await?;

		Ok((tag, element))
	}
}

impl Drop for OversizedReplyRelay {
	fn drop(&mut self) {
		self.task.abort();
	}
}

// A reply header past the read cap arrives after the frame ran, so it proves
// nothing about delivery. The gateway keeps the frame on the first instance
// and answers the client that the outcome is unknown.
tb_scenario! {
	name: cluster_work_never_retries_a_frame_whose_reply_header_passes_the_cap,
	spec: ClusterNoRetryAfterDeliverySpec,
	environment Bare {
		context: cluster_certs(),
		exec: |SetupEnv { trace, context: certs }| async move {
			let ran = Arc::new(AtomicBool::new(false));
			let first_conf = servlet_tls_builder(&certs)?.with_config(Arc::clone(&ran)).build();
			let first = RelayedFirstServlet::start(Arc::new(trace.share()), first_conf).await?;
			let relay = OversizedReplyRelay::start(first.addr().to_string(), ran).await;
			let second = SecondInstanceServlet::start(Arc::new(trace.share()), servlet_tls_config(&certs)?).await?;
			let second_addr = second.addr().to_string();
			let first_addr = relay.address();
			let (cluster, mut client) = gateway_trying_first(&trace, &certs, first_addr, &second_addr, None).await?;

			let refused = emit_ping_work(&mut client, &certs.key, b"oversized-reply").await;
			check_work_refusal(refused, TransitStatus::Unknown)?;

			cluster.stop();
			first.stop();
			second.stop();
			Ok(())
		}
	}
}

servlet! {
	/// A sibling whose gate refuses every call as unavailable, as a draining
	/// servlet does. It records each frame its handler receives.
	DrainingSiblingServlet<PingRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |_req, _frame, ctx| async move {
		ctx.trace().event(SIBLING_RECEIVED)?;
		Ok(None)
	}
}

/// A collector gate that refuses every call as unavailable, the refusal a
/// draining servlet answers before its handler runs.
struct DrainingGate;

impl GatePolicy for DrainingGate {
	fn evaluate(&self, _message: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		TransitStatus::Unavailable
	}
}

servlet! {
	/// The first instance of a two-instance type. Its handler calls a sibling
	/// with the frame and fails with the sibling's refusal, so the handler has
	/// run when its failure answers the gateway.
	SiblingCallingServlet<PingRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |_req, frame, ctx| async move {
		ctx.trace().event(FIRST_INSTANCE_RECEIVED)?;

		let siblings = ctx.hive_context().ok_or(TightBeamError::MissingResponse)?;
		let sibling = servlet_urn("sibling");
		siblings.call(&sibling, frame).await?;
		Ok(None)
	}
}

/// The connection cap of the pool that [`sibling_routes`] dials through.
const SIBLING_POOL_CONNECTIONS: NonZeroUsize = match NonZeroUsize::new(2) {
	Some(cap) => cap,
	None => panic!("a pool cap takes one connection or more"),
};

/// The routes a servlet under the [`cluster_certs`] identity calls its
/// siblings through: one route to the sibling of type `sibling` at
/// `address`, which answers under that identity too. A dial that the routes
/// refuse records on `trace`.
fn sibling_routes(trace: &TraceCollector, certs: &ClusterTestCerts, address: impl AsRef<str>) -> Arc<dyn HiveContext> {
	let address = address.as_ref();
	let mux_offer = Some(Arc::new(TransportOffer::mux(8)));
	let config = PoolConfig { idle_timeout: None, max_connections: SIBLING_POOL_CONNECTIONS, mux_offer };
	let pool = ConnectionPool::<TokioListener>::builder().with_config(config);
	let pool = pool.with_trust_store(Arc::clone(&certs.trust)).build();

	let routes = HiveContextImpl::new(Arc::new(pool)).with_trace(trace.share());
	let sibling_type = servlet_urn("sibling");
	let instance = sibling_type.servlet_instance(address);
	let instance = instance.expect("a servlet type URN yields an instance URN");
	let instance_key = instance.canonical_bytes();
	let type_key = sibling_type.canonical_bytes();
	let route_address: Arc<[u8]> = Arc::from(address.as_bytes());
	routes.add_route(instance_key, route_address, signer_of(&certs.cert), type_key);

	Arc::new(routes)
}

tb_assert_spec! {
	pub ClusterNoRetryAfterHandlerFailureSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(FIRST_INSTANCE_RECEIVED, exactly!(1)),
			(SIBLING_RECEIVED, exactly!(0)),
			(events::CLUSTER_WORK_ROUTED, absent!()),
			(events::CLUSTER_WORK_FAILED, exactly!(1), equals!(TransitStatus::Unknown))
		]
	}
}

// A handler that ran and failed answers `Unknown`, though its failure carries
// a sibling gate's `Unavailable`. A gateway retries only the `Unavailable` of
// a gate before any handler runs, so it keeps the frame on the first instance.
tb_scenario! {
	name: cluster_work_never_retries_a_frame_whose_handler_relayed_unavailable,
	spec: ClusterNoRetryAfterHandlerFailureSpec,
	environment Bare {
		context: cluster_certs(),
		exec: |SetupEnv { trace, context: certs }| async move {
			let sibling_builder = servlet_tls_builder(&certs)?.with_collector_gate(DrainingGate);
			let sibling_conf = sibling_builder.with_config(Arc::new(())).build();
			let sibling = DrainingSiblingServlet::start(Arc::new(trace.share()), sibling_conf).await?;
			let siblings = sibling_routes(&trace, &certs, sibling.addr().to_string());
			let first_conf = servlet_tls_builder(&certs)?.with_hive_context(siblings).with_config(Arc::new(())).build();
			let first = SiblingCallingServlet::start(Arc::new(trace.share()), first_conf).await?;
			let second = SecondInstanceServlet::start(Arc::new(trace.share()), servlet_tls_config(&certs)?).await?;
			let first_addr = first.addr().to_string();
			let second_addr = second.addr().to_string();
			let mux = Some(TransportOffer::mux(8));
			let (cluster, mut client) = gateway_trying_first(&trace, &certs, &first_addr, &second_addr, mux).await?;

			let refused = emit_ping_work(&mut client, &certs.key, b"relayed-unavailable").await;
			check_work_refusal(refused, TransitStatus::Unknown)?;

			cluster.stop();
			first.stop();
			second.stop();
			sibling.stop();
			Ok(())
		}
	}
}

servlet! {
	/// A servlet that answers at a registered address under an identity the
	/// registration does not name. It echoes the ping.
	ImpostorServlet<PingRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |req, frame, _ctx| async move {
		let response = Version::V0.compose()
			.with_id(frame.metadata().id())
			.with_message(PingResponse { doubled: req.value * 2 })
			.build()?;
		Ok(Some(response))
	}
}

tb_assert_spec! {
	pub ClusterWorkImpostorSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(1)),
			(events::CLUSTER_WORK_FAILED, exactly!(1), equals!(TransitStatus::Unavailable)),
			(events::CLUSTER_WORK_UNAVAILABLE, absent!())
		]
	}
}

// A work forward reaches a servlet only under the identity its registration
// names (CWE-346):
// - The gateway's hive trust holds both identities, so the handshake completes.
// - Only the dial's binding refuses the answer, so the frame never leaves and the client hears `Unavailable`.
tb_scenario! {
	name: cluster_work_refuses_a_servlet_answering_under_another_identity,
	spec: ClusterWorkImpostorSpec,
	environment Bare {
		context: cluster_certs(),
		exec: |SetupEnv { trace, context: certs }| async move {
			let impostor_certs = stranger_gateway_certs();
			let impostor_conf = servlet_tls_config(&impostor_certs)?;
			let impostor = ImpostorServlet::start(Arc::new(trace.share()), impostor_conf).await?;
			let cluster = start_cluster(&trace, impostor_trusting_conf(&certs, &impostor_certs)).await?;

			let mut client = connect_cluster(&certs, cluster.addr()).await?;
			let hive_addr = b"127.0.0.1:65033";
			let servlets = [servlet_info(&certs, "ping", impostor.addr().to_string())];
			register_signed_hive_serving(&mut client, &certs.key, b"impostor", hive_addr, servlets).await?;

			let refused = emit_ping_work(&mut client, &certs.key, b"impostor-work").await;
			check_work_refusal(refused, TransitStatus::Unavailable)?;

			cluster.stop();
			impostor.stop();
			Ok(())
		}
	}
}

// A sibling dial that another identity answers records its refusal on the
// trace that the context's builder named, so a builder outside the crate
// reads the refusals of the context it built.
#[tokio::test]
async fn a_sibling_context_records_a_refused_dial_on_the_trace_it_was_given() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let impostor_certs = stranger_gateway_certs();
	let trace = TraceCollector::default();
	let impostor_conf = servlet_tls_config(&impostor_certs)?;
	let impostor = ImpostorServlet::start(Arc::new(TraceCollector::default()), impostor_conf).await?;
	let trust = combined_trust(&[&certs.cert, &impostor_certs.cert]);
	let pool = ConnectionPool::<TokioListener>::builder().with_trust_store(trust).build();
	let routes = HiveContextImpl::new(Arc::new(pool)).with_trace(trace.share());
	let sibling_type = servlet_urn("sibling");
	let address = impostor.addr().to_string();
	let instance = sibling_type.servlet_instance(&address)?;
	let route_address: Arc<[u8]> = Arc::from(address.as_bytes());
	routes.add_route(
		instance.canonical_bytes(),
		route_address,
		signer_of(&certs.cert),
		sibling_type.canonical_bytes(),
	);

	let frame = signed_work_frame(&certs.key, b"sibling-call").await?;
	let refused = routes.call(&sibling_type, frame).await;
	impostor.stop();

	let mismatched = matches!(refused, Err(TightBeamError::ClusterError(ref error)) if matches!(**error, ClusterError::PeerMismatch));
	assert!(mismatched);
	assert_eq!(trace.recorded(events::CLUSTER_DIAL_REFUSED), 1);
	Ok(())
}

tb_assert_spec! {
	pub ClusterAbandonedPeerRouteSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_WORK_FAILED, exactly!(1), equals!(TransitStatus::Unavailable)),
			(events::CLUSTER_PEER_ROUTES_WITHDRAWN, exactly!(1), equals!(1u64))
		]
	}
}

// A peer route abandons at its first failed forward, because its limit is
// one, and the next evaporation sweep withdraws it. The sweep runs every
// 50ms, so the withdrawal lands inside the scenario.
tb_scenario! {
	name: cluster_evaporation_withdraws_an_abandoned_peer_route,
	spec: ClusterAbandonedPeerRouteSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let mut conf = peering_cluster_conf(&certs);
			conf.pheromone.abandonment_limit = NonZeroU32::MIN;
			conf.pheromone.evaporation_interval = Duration::from_millis(50);
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let ad_reply = install_ping_peer(&certs, &cluster).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");

			let mut client = connect_cluster(&certs, cluster.addr()).await?;
			let refused = emit_ping_work(&mut client, &certs.key, b"dead-peer-work").await;
			check_work_refusal(refused, TransitStatus::Unavailable)?;

			let withdrawn = || trace.recorded(events::CLUSTER_PEER_ROUTES_WITHDRAWN) >= 1;
			poll_until(50, Duration::from_millis(50), withdrawn).await;
			assert!(cluster.peer_routes()?.is_empty(), "the sweep withdraws the abandoned peer route");

			cluster.stop();
			Ok(())
		}
	}
}

/// The dials that a gateway's own trace records as it routes one work
/// request to the servlet of a hive. The hive and the client record into
/// traces of their own, and the gateway's heartbeat waits an hour, so the
/// gateway's trace holds the dials of its hive pool alone.
#[cfg(feature = "instrument")]
async fn gateway_work_dials() -> Result<Vec<Urn<'static>>, TightBeamError> {
	let certs = Arc::new(cluster_certs());
	let mut conf = routing_cluster_conf(&certs, None);
	conf.heartbeat.interval = Duration::from_secs(3_600);
	let gateway_trace = TraceCollector::new();
	let cluster = start_cluster(&gateway_trace, conf).await?;
	let hive = start_ping_hive(TraceCollector::new(), Arc::clone(&certs), None).await?;
	hive.register_with_cluster(cluster.addr()).await?;

	// The trail of the gateway's dials is the observation, so the echo goes
	// unread.
	let _echo = submit_ping(&certs, &cluster).await?;
	hive.stop();
	cluster.stop();

	Ok(TestTrace::trail(&gateway_trace, &[events::POOL_DIAL]))
}

/// A gateway records each dial of its hive pool on its own trace.
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_gateway_records_the_dials_of_its_hive_pool_on_its_own_trace() -> Result<(), TightBeamError> {
	assert_eq!(gateway_work_dials().await?, [events::POOL_DIAL]);
	Ok(())
}
