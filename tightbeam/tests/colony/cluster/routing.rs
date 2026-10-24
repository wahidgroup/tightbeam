//! Work routing through the cluster gateway.

use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use tightbeam::colony::hive::{HiveContext, HiveContextImpl};
use tightbeam::crypto::x509::policy::{CertificateValidation, DirectTrustValidator};
use tightbeam::testing::TestDigest;
use tightbeam::{cluster, servlet};

use super::common::*;
use super::federation::{federation_conf, wait_for_type_routes};
use crate::common::security::expectation_failure;

tb_assert_spec! {
	pub ClusterRoutingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(WORK_SENT, exactly!(1)),
			(WORK_ECHOED, exactly!(1), equals!(42u64)),
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
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			record_ping_echo(&trace, &certs, &cluster).await?;
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
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			record_ping_echo(&trace, &certs, &cluster).await?;
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
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, exactly!(0)),
			(WORK_STATUS, exactly!(1), equals!(TransitStatus::Unavailable)),
			(WORK_PAYLOAD, exactly!(1), equals!(0u64))
		]
	}
}

// The gateway runs `ClusterTlsConfig::validators` as the server policy of
// each dial to its hive, so a policy that admits no certificate leaves the
// work unrouted. `cluster_work_routing_single_flight` routes the same work
// with no policy.
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
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let mut client = connect_cluster(&certs, cluster.addr()).await?;
			trace.event(WORK_SENT)?;

			let refused_work = emit_ping_work(&mut client, &certs.key, b"server-policy-work").await;
			record_work_refusal(&trace, refused_work)?;

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
			(MULTI_REGISTER_STATUS, exactly!(2), equals!(TransitStatus::Ok)),
			(WORK_SENT, exactly!(2)),
			(WORK_ECHOED, exactly!(2), equals!(42u64)),
			(events::CLUSTER_HIVE_REGISTERED, at_least!(2), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(2))
		]
	}
}

// One hive registers with two independent gateways. Registration fans out,
// each gateway converges on its own registry (both count exactly this one
// hive), and each routes work to the same servlet slate. Gateway redundancy
// needs no consensus, because every registry is soft state the hive keeps
// fresh.
tb_scenario! {
	name: cluster_hive_serves_two_gateways,
	spec: ClusterMultiGatewaySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, Some(TransportOffer::mux(8))),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let first = start_cluster(&trace, routing_cluster_conf(&certs, Some(TransportOffer::mux(8)))).await?;
			let second = start_cluster(&trace, routing_cluster_conf(&certs, Some(TransportOffer::mux(8)))).await?;

			let registered = hive.register_with_cluster(first.addr()).await?;
			trace.event_with(MULTI_REGISTER_STATUS, &[], registered.status)?;

			let registered = hive.register_with_cluster(second.addr()).await?;
			trace.event_with(MULTI_REGISTER_STATUS, &[], registered.status)?;

			record_ping_echo(&trace, &certs, &first).await?;
			record_ping_echo(&trace, &certs, &second).await?;

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
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_REFUSED, exactly!(1)),
			(WORK_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(WORK_PAYLOAD, exactly!(1), equals!(0u64))
		]
	}
}

// The scenarios below prove end-to-end frame delivery. The frame a
// servlet handler receives for cluster-routed work is the frame the
// client created, and the frame the client receives back is the frame
// the servlet responded with.

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

		// The SIGNED and PREVIOUS probes witness presence only. Byte
		// fidelity rests on SIG_VALID, whose signature covers the
		// frame's to-be-signed bytes, so SIG_VALID must not be weakened
		// on the assumption the presence probes cover fidelity.
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

/// Run the full-frame delivery contract from the client side against
/// `gateway`: send the standard signed contract frame and record every
/// client-observable property of the servlet's response envelope.
///
/// The local-delivery and peer-hop scenarios share it, so both routes prove
/// the identical contract.
async fn record_frame_contract(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	gateway: &ClusterGateway,
) -> Result<(), TightBeamError> {
	let unsigned = Version::V2
		.compose()
		.with_id(b"client-signed-work")
		.with_order(UnixMillis::now().get())
		.with_previous_hash(TestDigest::info())
		.with_message(PingRequest { value: 21 })
		.build()?;

	let inner = sign_frame(unsigned, &probe_signing_key()).await?;

	trace.event_with(CLIENT_WORK_SIGNED, &[], u32::from(inner.nonrepudiation().is_some()))?;
	trace.event_with(
		CLIENT_WORK_PREVIOUS,
		&[],
		u32::from(inner.metadata().previous_frame().is_some()),
	)?;

	let mut client = connect_cluster(certs, gateway.addr()).await?;
	trace.event(WORK_SENT)?;

	// The public client surface under test: one method call wraps the
	// work frame in the hop-local transport envelope and resolves the
	// gateway's reply down to the servlet's response frame.
	let servlet_frame = client.submit_work_to(servlet_urn("ping"), &inner).await?;

	trace.event_with(
		CLIENT_GOT_SERVLET_ID,
		&[],
		u32::from(servlet_frame.metadata().id() == b"probe-response"),
	)?;
	trace.event_with(
		CLIENT_GOT_SERVLET_SIGNED,
		&[],
		u32::from(servlet_frame.nonrepudiation().is_some()),
	)?;
	trace.event_with(
		CLIENT_GOT_SERVLET_SIG_VALID,
		&[],
		u32::from(frame_signature_verifies(&servlet_frame, &probe_signing_key())),
	)?;

	let ping_response: PingResponse = decode(servlet_frame.message())?;
	trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;
	Ok(())
}

tb_assert_spec! {
	pub ClusterClientFrameDeliverySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(WORK_SENT, exactly!(1)),
			(CLIENT_WORK_SIGNED, exactly!(1), equals!(1u32)),
			(CLIENT_WORK_PREVIOUS, exactly!(1), equals!(1u32)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(PROBE_FRAME_CLIENT_ID, exactly!(1), equals!(1u32)),
			(PROBE_FRAME_SIGNED, exactly!(1), equals!(1u32)),
			(PROBE_FRAME_PREVIOUS, exactly!(1), equals!(1u32)),
			(PROBE_FRAME_SIG_VALID, exactly!(1), equals!(1u32)),
			(CLIENT_GOT_SERVLET_ID, exactly!(1), equals!(1u32)),
			(CLIENT_GOT_SERVLET_SIGNED, exactly!(1), equals!(1u32)),
			(CLIENT_GOT_SERVLET_SIG_VALID, exactly!(1), equals!(1u32)),
			(WORK_ECHOED, exactly!(1), equals!(42u64))
		]
	}
}

// The client nests its complete signed frame in the work payload and
// submits it as unary work. The presence probes only witness that an id,
// a signature block, and a previous-frame digest exist, so they cannot
// prove byte fidelity. The two SIG_VALID assertions carry that proof,
// because each signature verifies only over the exact bytes the other
// side signed.
tb_scenario! {
	name: cluster_work_delivers_client_frame,
	spec: ClusterClientFrameDeliverySpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, routing_cluster_conf(&certs, None)).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![start_probe_hive(trace, certs)],
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			record_frame_contract(&trace, &certs, &cluster).await?;

			cluster.stop();
			Ok(())
		}
	}
}

// Work must target a servlet TYPE: instance-narrowed URNs are refused
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
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let inner = signed_work_frame(&certs.key, b"instance-work").await?;
			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			trace.event(WORK_SENT)?;

			let refused_work = client
				.submit_work_to(servlet_urn("ping").servlet_instance("127.0.0.1:9999").expect("a servlet type URN yields an instance URN"), &inner)
				.await;
			record_work_refusal(&trace, refused_work)?;

			cluster.stop();

			Ok(())
		}
	}
}

// Peer-hop frame delivery: the same end-to-end contract must hold when
// the serving gateway is reached through a peer forward, not locally.

/// Two member gateways with distinct identities.
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
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(WORK_SENT, exactly!(1)),
			(CLIENT_WORK_SIGNED, exactly!(1), equals!(1u32)),
			(CLIENT_WORK_PREVIOUS, exactly!(1), equals!(1u32)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, exactly!(2)),
			(PROBE_FRAME_CLIENT_ID, exactly!(1), equals!(1u32)),
			(PROBE_FRAME_SIGNED, exactly!(1), equals!(1u32)),
			(PROBE_FRAME_PREVIOUS, exactly!(1), equals!(1u32)),
			(PROBE_FRAME_SIG_VALID, exactly!(1), equals!(1u32)),
			(CLIENT_GOT_SERVLET_ID, exactly!(1), equals!(1u32)),
			(CLIENT_GOT_SERVLET_SIGNED, exactly!(1), equals!(1u32)),
			(CLIENT_GOT_SERVLET_SIG_VALID, exactly!(1), equals!(1u32)),
			(WORK_ECHOED, exactly!(1), equals!(42u64))
		]
	}
}

// Envelope preservation across a gateway relay: A holds no local ping
// route, so the work crosses the peer plane to B before B delivers the
// client's frame to the probe servlet. Every PROBE_FRAME_* and
// CLIENT_GOT_SERVLET_* assertion from the local contract must hold
// unchanged, including cryptographic signature verification in both
// directions. CLUSTER_WORK_FORWARDED pins the peer hop and the two
// CLUSTER_WORK_ROUTED events pin one reinforced trail per gateway.
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
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned as u64)?;

			record_frame_contract(&trace, &ctx.a, &gateway_a).await?;

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
			(WORK_SENT, exactly!(2)),
			(events::CLUSTER_WORK_REFUSED, exactly!(1)),
			(WORK_STATUS, exactly!(1), equals!(TransitStatus::InvalidArgument)),
			(WORK_PAYLOAD, exactly!(1), equals!(0u64)),
			(events::CLUSTER_WORK_FAILED, exactly!(0)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(0)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(WORK_ECHOED, exactly!(1), equals!(42u64))
		]
	}
}

// A work payload that does not decode as a frame is a permanent caller
// fault. The gateway must refuse it as InvalidArgument at admission,
// before route selection. Zero CLUSTER_WORK_FAILED proves that no healthy
// pheromone trail was weakened and no failover retry burned. The follow-up
// valid work then echoes through the same trail, which proves the route
// stayed serviceable.
tb_scenario! {
	name: cluster_refuses_malformed_work_payload,
	spec: ClusterMalformedWorkSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, routing_cluster_conf(&certs, None)).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![start_ping_hive(trace, certs, None)],
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			// The dual wrap is composed manually because the malformed
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

			trace.event(WORK_SENT)?;

			let response_frame = emit_frame(&mut client, frame).await?;
			let work_response: ClusterWorkResponse = decode(response_frame.message())?;
			record_work_status(&trace, &work_response)?;

			record_ping_echo(&trace, &certs, &cluster).await?;

			cluster.stop();

			Ok(())
		}
	}
}

cluster! {
	/// Gateway with an edge accept plane, which proves the `edge:` macro arm.
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
			(WORK_SENT, exactly!(1)),
			(WORK_ECHOED, exactly!(1), equals!(42u64)),
			(EDGE_CONTROL_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1))
		]
	}
}

// The edge accept plane is a work-only surface on its own listener. Work
// submitted at the edge address routes to the servlet exactly like colony
// work, while a validly signed hive registration on the same connection
// is refused with PermissionDenied. The hive keeps registering through
// the colony plane (CLUSTER_HIVE_REGISTERED stays 1).
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
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let Some(edge_addr) = cluster.edge_addr() else {
				return Err(expectation_failure("edge plane did not bind"));
			};

			let inner = signed_work_frame(&certs.key, b"edge-work").await?;

			trace.event(WORK_SENT)?;

			let mut client = connect_cluster(&certs, edge_addr).await?;
			let servlet_frame = client.submit_work_to(servlet_urn("ping"), &inner).await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;

			trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;

			let signed = signed_control_frame(
				&certs,
				b"edge-reg",
				registration_request(b"127.0.0.1:65001"),
			)
			.await?;

			let response_frame = emit_frame(&mut client, signed).await?;
			let refusal: ClusterWorkResponse = decode(response_frame.message())?;

			trace.event_with(EDGE_CONTROL_STATUS, &[], refusal.status)?;

			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterEdgeBindFailureSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(EDGE_START_FAILED, exactly!(1), equals!(true))
		]
	}
}

// A configured edge plane that cannot parse its bind address fails
// Cluster::start closed: the call returns Err and no accept loop is
// left running (bind-then-spawn owns both listeners before spawn).
tb_scenario! {
	name: cluster_edge_bind_failure_fails_start,
	spec: ClusterEdgeBindFailureSpec,
	environment Bare {
		context: cluster_certs(),
		exec: |SetupEnv { trace, context: certs }| async move {
			let mut conf = routing_cluster_conf(&certs, Some(TransportOffer::mux(8)));
			conf.edge_bind_addr = Some("not-a-socket-addr".into());

			let failed = EdgeClusterGateway::start(Arc::new(trace.share()), conf)
				.await
				.is_err();

			trace.event_with(EDGE_START_FAILED, &[], failed)?;

			Ok(())
		}
	}
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
	/// The second instance of a two-instance type. It records each frame it
	/// receives and echoes the ping.
	SecondInstanceServlet<PingRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |req, frame, ctx| async move {
		ctx.trace().event(SECOND_INSTANCE_RECEIVED)?;

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

	/// The held port's address, in the spelling a hive registers.
	fn address(&self) -> &str {
		&self.address
	}
}

/// Starts a gateway whose balancer tries `first` before any other instance,
/// and registers one hive that serves `ping` at `first` and at `second`.
///
/// The gateway's hive pool offers `mux_offer`, and with none it stays
/// single-flight.
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
	let servlets = [servlet_info("ping", first), servlet_info("ping", second)];
	let registered = register_signed_hive_serving(&mut client, &certs.key, b"two", hive_addr, servlets).await?;
	trace.event_with(REGISTER_STATUS, &[], registered.status)?;

	Ok((cluster, client))
}

tb_assert_spec! {
	pub ClusterNoRetryAfterDeliverySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(REGISTER_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(FIRST_INSTANCE_RECEIVED, exactly!(1)),
			(SECOND_INSTANCE_RECEIVED, exactly!(0)),
			(WORK_STATUS, exactly!(1), equals!(TransitStatus::Unknown)),
			(WORK_PAYLOAD, exactly!(1), equals!(0u64))
		]
	}
}

// A signed client command runs at most once. The first instance reads the
// frame and answers with no frame, so the frame may have run there. The
// gateway keeps it on the first instance and answers the client that the
// outcome is unknown.
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
			record_work_refusal(&trace, refused)?;

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
			(REGISTER_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(SECOND_INSTANCE_RECEIVED, exactly!(1)),
			(WORK_ECHOED, exactly!(1), equals!(42u64))
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
			trace.event_with(WORK_ECHOED, &[], u64::from(ping.doubled))?;

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

	/// The relay's address, in the spelling a hive registers.
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
		// scenario reads the gateway's answer, so neither outcome is read.
		let _ended = tokio::join!(requests, replies);
	}

	/// Forwards each DER element the servlet writes until its handler ran,
	/// then writes the element's tag and [`OVERSIZED_LENGTH`] in its place.
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
			record_work_refusal(&trace, refused)?;

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

/// The routes a servlet under the [`cluster_certs`] identity calls its
/// siblings through: one route to the sibling of type `sibling` at
/// `address`, which answers under that identity too.
fn sibling_routes(certs: &ClusterTestCerts, address: impl AsRef<str>) -> Arc<dyn HiveContext> {
	let address = address.as_ref();
	let mux_offer = Some(Arc::new(TransportOffer::mux(8)));
	let config = PoolConfig { idle_timeout: None, max_connections: 2, mux_offer };
	let pool = ConnectionPool::<TokioListener>::builder().with_config(config);
	let pool = pool.with_trust_store(Arc::clone(&certs.trust)).build();

	let routes = HiveContextImpl::new(Arc::new(pool));
	let sibling_type = servlet_urn("sibling");
	let instance = sibling_type.servlet_instance(address);
	let instance = instance.expect("a servlet type URN yields an instance URN");
	let instance_key = instance.canonical_bytes();
	let type_key = sibling_type.canonical_bytes();
	let route_address: Arc<[u8]> = Arc::from(address.as_bytes());
	routes.add_route(instance_key, route_address, servlet_signer(), type_key);

	Arc::new(routes)
}

tb_assert_spec! {
	pub ClusterNoRetryAfterHandlerFailureSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(REGISTER_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(FIRST_INSTANCE_RECEIVED, exactly!(1)),
			(SIBLING_RECEIVED, exactly!(0)),
			(SECOND_INSTANCE_RECEIVED, exactly!(0)),
			(WORK_STATUS, exactly!(1), equals!(TransitStatus::Unknown)),
			(WORK_PAYLOAD, exactly!(1), equals!(0u64))
		]
	}
}

// A handler that ran and failed answers `Unknown`, though its failure carries
// the `Unavailable` a sibling's gate refused it with. A gateway retries only
// the `Unavailable` a gate answers before any handler runs, so it keeps the
// frame on the first instance.
tb_scenario! {
	name: cluster_work_never_retries_a_frame_whose_handler_relayed_unavailable,
	spec: ClusterNoRetryAfterHandlerFailureSpec,
	environment Bare {
		context: cluster_certs(),
		exec: |SetupEnv { trace, context: certs }| async move {
			let sibling_builder = servlet_tls_builder(&certs)?.with_collector_gate(DrainingGate);
			let sibling_conf = sibling_builder.with_config(Arc::new(())).build();
			let sibling = DrainingSiblingServlet::start(Arc::new(trace.share()), sibling_conf).await?;
			let siblings = sibling_routes(&certs, sibling.addr().to_string());
			let first_conf = servlet_tls_builder(&certs)?.with_hive_context(siblings).with_config(Arc::new(())).build();
			let first = SiblingCallingServlet::start(Arc::new(trace.share()), first_conf).await?;
			let second = SecondInstanceServlet::start(Arc::new(trace.share()), servlet_tls_config(&certs)?).await?;
			let first_addr = first.addr().to_string();
			let second_addr = second.addr().to_string();
			let mux = Some(TransportOffer::mux(8));
			let (cluster, mut client) = gateway_trying_first(&trace, &certs, &first_addr, &second_addr, mux).await?;

			let refused = emit_ping_work(&mut client, &certs.key, b"relayed-unavailable").await;
			record_work_refusal(&trace, refused)?;

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
	/// registration does not name. It records each frame it receives and
	/// echoes the ping.
	ImpostorServlet<PingRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |req, frame, ctx| async move {
		ctx.trace().event(IMPOSTOR_RECEIVED)?;

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
			(REGISTER_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(1)),
			(IMPOSTOR_RECEIVED, exactly!(0)),
			(WORK_STATUS, exactly!(1), equals!(TransitStatus::Unavailable)),
			(WORK_PAYLOAD, exactly!(1), equals!(0u64))
		]
	}
}

// A work forward reaches a servlet only under the identity its registration
// names. The gateway's hive trust holds both identities, so the handshake
// completes, and the dial's binding alone refuses the answer (CWE-346). The
// refusal proves the frame never left, so the client hears `Unavailable`.
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
			let servlets = [servlet_info("ping", impostor.addr().to_string())];
			let registered =
				register_signed_hive_serving(&mut client, &certs.key, b"impostor", hive_addr, servlets).await?;
			trace.event_with(REGISTER_STATUS, &[], registered.status)?;

			let refused = emit_ping_work(&mut client, &certs.key, b"impostor-work").await;
			record_work_refusal(&trace, refused)?;

			cluster.stop();
			impostor.stop();
			Ok(())
		}
	}
}
