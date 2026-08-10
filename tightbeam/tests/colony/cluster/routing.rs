//! Work routing through the cluster gateway.

use tightbeam::testing::create_test_hash_info;
use tightbeam::{cluster, servlet};

use super::common::*;
use super::federation::{federation_conf, wait_for_type_routes};
use crate::common::security::expectation_failure;

tb_assert_spec! {
	pub ClusterRoutingSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
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

// Same routing path without mux offers: colony links stay single-flight.
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
	pub ClusterMultiGatewaySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(MULTI_REGISTER_STATUS, exactly!(2), equals!(TransitStatus::Ok)),
			(WORK_SENT, exactly!(2)),
			(WORK_ECHOED, exactly!(2), equals!(42u64)),
			(events::CLUSTER_HIVE_REGISTERED, at_least!(2), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(2))
		]
	}
}

// One hive, two independent gateways: registration fans out, each gateway
// converges on its own registry (both count exactly this one hive), and
// each routes work to the same servlet slate. Gateway redundancy needs no
// consensus -- every registry is soft state the hive keeps fresh.
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
		gate: Ok,
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
	/// cluster-routed work. The probes cover the client's frame id, the
	/// nonrepudiation block, the previous-frame linkage, and whether the
	/// client's signature verifies over the received bytes. The handler
	/// responds with a signed frame so the client can verify the response
	/// envelope the same way.
	pub FrameProbeServlet<PingRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |req, frame, ctx| async move {
		let trace = ctx.trace();

		// The SIGNED and PREVIOUS probes witness presence only. Byte
		// fidelity rests on SIG_VALID, whose signature covers the
		// frame's to-be-signed bytes, so SIG_VALID must not be weakened
		// on the assumption the presence probes cover fidelity.
		let sig_valid = frame_signature_verifies(&frame, &probe_signing_key());

		trace.event_with(PROBE_FRAME_CLIENT_ID, &[], u32::from(frame.metadata.id == b"client-signed-work"))?;
		trace.event_with(PROBE_FRAME_SIGNED, &[], u32::from(frame.nonrepudiation.is_some()))?;
		trace.event_with(PROBE_FRAME_PREVIOUS, &[], u32::from(frame.metadata.previous_frame.is_some()))?;
		trace.event_with(PROBE_FRAME_SIG_VALID, &[], u32::from(sig_valid))?;

		let unsigned = frame_compose(Version::V0)
			.with_id(b"probe-response")
			.with_message(PingResponse { doubled: req.value * 2 })
			.build()?;

		Ok(Some(sign_frame(unsigned, &probe_signing_key()).await?))
	}
}

/// Probe-servlet hive registered under the ping type, on the scenario trace.
async fn start_probe_hive(
	trace: TraceCollector,
	certs: Arc<ClusterTestCerts>,
) -> Result<ClusterTestHive, TightBeamError> {
	let servlet_conf = servlet_tls_config(&certs)?;
	let servlet = FrameProbeServlet::start(Arc::new(trace.share()), Some(servlet_conf)).await?;

	let mut hive = ClusterTestHive::new(Some(hive_tls_config(&certs)))?;
	hive.register(servlet_urn("ping"), servlet, |t| FrameProbeServlet::start(t, None))?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// Run the full-frame delivery contract from the client side against
/// `gateway`: send the standard signed contract frame and record every
/// client-observable property of the servlet's response envelope.
///
/// Shared by the local-delivery and peer-hop scenarios, so both routes
/// prove the identical contract.
async fn record_frame_contract(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	gateway: &ClusterGateway,
) -> Result<(), TightBeamError> {
	let unsigned = frame_compose(Version::V2)
		.with_id(b"client-signed-work")
		.with_order(current_timestamp_ms())
		.with_previous_hash(create_test_hash_info())
		.with_message(PingRequest { value: 21 })
		.build()?;

	let inner = sign_frame(unsigned, &probe_signing_key()).await?;

	trace.event_with(CLIENT_WORK_SIGNED, &[], u32::from(inner.nonrepudiation.is_some()))?;
	trace.event_with(CLIENT_WORK_PREVIOUS, &[], u32::from(inner.metadata.previous_frame.is_some()))?;

	let mut client = connect_cluster(certs, gateway.addr()).await?;
	trace.event(WORK_SENT)?;

	// The public client surface under test: one method call wraps the
	// work frame in the hop-local transport envelope and resolves the
	// gateway's reply down to the servlet's response frame.
	let servlet_frame = client.submit_work_to(servlet_urn("ping"), &inner).await?;

	trace.event_with(
		CLIENT_GOT_SERVLET_ID,
		&[],
		u32::from(servlet_frame.metadata.id == b"probe-response"),
	)?;
	trace.event_with(
		CLIENT_GOT_SERVLET_SIGNED,
		&[],
		u32::from(servlet_frame.nonrepudiation.is_some()),
	)?;
	trace.event_with(
		CLIENT_GOT_SERVLET_SIG_VALID,
		&[],
		u32::from(frame_signature_verifies(&servlet_frame, &probe_signing_key())),
	)?;

	let ping_response: PingResponse = decode(&servlet_frame.message)?;
	trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;
	Ok(())
}

tb_assert_spec! {
	pub ClusterClientFrameDeliverySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
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
				.submit_work_to(servlet_instance(&servlet_urn("ping"), "127.0.0.1:9999"), &inner)
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
		gate: Ok,
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
		gate: Ok,
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
// before route selection: zero CLUSTER_WORK_FAILED proves no healthy
// pheromone trail was weakened and no failover retry burned, and the
// follow-up valid work echoing through the same trail proves the route
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

			let frame = frame_compose(Version::V0)
				.with_id(b"malformed-work")
				.with_order(0)
				.with_message(ClusterRequest::Work(malformed))
				.build()?;

			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			trace.event(WORK_SENT)?;

			let response_frame = emit_frame(&mut client, frame).await?;
			let work_response: ClusterWorkResponse = decode(&response_frame.message)?;
			record_work_status(&trace, &work_response)?;

			record_ping_echo(&trace, &certs, &cluster).await?;

			cluster.stop();

			Ok(())
		}
	}
}

cluster! {
	/// Gateway with an edge accept plane, proving the `edge:` macro arm.
	///
	/// The edge protocol matches the colony protocol here because core
	/// ships one async transport, so a mixed-transport colony (TCP colony,
	/// WebSocket edge) is exercised by the transport extensions.
	EdgeClusterGateway,
	protocol: TokioListener,
	edge: TokioListener
}

tb_assert_spec! {
	pub ClusterEdgePlaneSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
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
			let refusal: ClusterWorkResponse = decode(&response_frame.message)?;

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
		gate: Ok,
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
