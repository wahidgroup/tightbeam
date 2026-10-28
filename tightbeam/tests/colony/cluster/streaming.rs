//! The scenarios that forward a stream or a duplex across the gateway splice.
//!
//! The stream-echo servlet lives in cluster B alone. A client opens a routed
//! stream on cluster A ([`PooledClient::open_stream_to`] or
//! [`PooledClient::open_duplex_to`]). A splices it to B's gateway with the hop
//! budget spent, and B serves it locally. A cancel of the client stream
//! crosses the splice to the servlet.

use tightbeam::transport::{PooledClient, Protocol, TransportError};
use tightbeam::{compose, servlet};

use super::common::*;
use crate::common::security::expectation_failure;

servlet! {
	/// A servlet with stream and duplex arms alone. The stream arm reports the
	/// body length, and the duplex arm echoes each request chunk to the reply
	/// sink.
	pub StreamEchoServlet<PingRequest, EnvConfig = ()>,
	protocol: TokioListener,
	stream: |body, ctx| async move {
		ctx.trace().event(STREAM_SERVLET_HANDLED)?;
		let bytes = body.into_bytes().await?;
		Ok(Some(compose! {
			V0: id: b"stream-echo-reply",
				message: PingResponse { doubled: bytes.len() as u32 }
		}?))
	},
	duplex: |body, reply, ctx| async move {
		ctx.trace().event(DUPLEX_SERVLET_HANDLED)?;
		let mut body = body;
		let mut reply = reply;
		while let Some(chunk) = body.chunk().await? {
			reply.push(&chunk).await?;
		}

		Ok(())
	}
}

/// Starts a hive that hosts one stream-echo servlet, muxed on both the
/// servlet server and the hive-to-cluster pool.
pub async fn start_stream_hive(
	trace: TraceCollector,
	certs: Arc<ClusterTestCerts>,
) -> Result<ClusterTestHive, TightBeamError> {
	let servlet_conf = servlet_tls_config(&certs)?;
	let servlet = StreamEchoServlet::start(Arc::new(trace.share()), servlet_conf).await?;

	let conf = hive_tls_config(&certs);
	let mut hive = ClusterTestHive::new(Some(conf))?;
	hive.register(servlet_urn("stream-echo"), servlet, |t| {
		StreamEchoServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// [`peering_cluster_conf`] with a mux offer, so the gateway serves
/// routed streams and its pools open them.
fn mux_peering_conf(certs: &ClusterTestCerts) -> ClusterConfig {
	with_mux_offer(peering_cluster_conf(certs))
}

/// [`advertising_cluster_conf`] with a mux offer, so the exporter serves
/// forwarded streams from its peer.
fn mux_advertising_conf(certs: &ClusterTestCerts, peer: impl Into<String>) -> ClusterConfig {
	let peer: String = peer.into();
	with_mux_offer(advertising_cluster_conf(certs, peer))
}

/// A pooled mux lease against a gateway, for the routed stream entry points
/// [`PooledClient::open_stream_to`] and [`PooledClient::open_duplex_to`].
pub async fn pooled_cluster_client(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	addr: &<TokioListener as Protocol>::Address,
) -> Result<PooledClient<TokioListener>, TightBeamError> {
	let config = PoolConfig {
		idle_timeout: None,
		max_connections: NonZeroUsize::MIN,
		mux_offer: Some(Arc::new(TransportOffer::mux(8))),
	};
	let pool = Arc::new(
		ConnectionPool::<TokioListener>::builder()
			.with_config(config)
			.with_trust_store(Arc::clone(&certs.trust))
			.with_trace(trace.share())
			.build(),
	);

	let client = pool.connect(addr.to_owned()).await?;
	Ok(client)
}

/// Starts two peered gateways and registers the stream-echo hive in the
/// exporter, for the forward and cancel scenarios. It returns the importer,
/// which the client dials, then the exporter.
async fn start_spliced_clusters(
	trace: &TraceCollector,
	certs: &Arc<ClusterTestCerts>,
	hive: &ClusterTestHive,
) -> Result<(ClusterGateway, ClusterGateway), TightBeamError> {
	let importer = start_cluster(trace, mux_peering_conf(certs)).await?;
	let exporter = start_cluster(trace, mux_advertising_conf(certs, importer.addr().to_string())).await?;

	hive.register_with_cluster(exporter.addr()).await?;

	let learned = wait_for_peer_types(trace, &importer, 50, Duration::from_millis(100)).await;
	assert_eq!(learned.len(), 1, "the importer learns the exporter's one type");

	Ok((importer, exporter))
}

tb_assert_spec! {
	pub ClusterStreamForwardSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, exactly!(2)),
			(STREAM_SERVLET_HANDLED, exactly!(1))
		]
	}
}

// A stream crosses the splice. The importer splices the routed open to the
// exporter, whose hive alone hosts stream-echo, and the servlet's reply frame
// relays back unchanged.
tb_scenario! {
	name: cluster_forwards_streaming_to_peer_gateway,
	spec: ClusterStreamForwardSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_stream_hive(trace, certs),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (importer, exporter) = start_spliced_clusters(&trace, &certs, &hive).await?;
			let client = pooled_cluster_client(&trace, &certs, importer.addr()).await?;

			let (mut sink, response) = client.open_stream_to(servlet_urn("stream-echo"))?;
			sink.push(b"abcd").await?;
			sink.close_with(b"efgh").await?;

			let reply = response.await?.ok_or(TightBeamError::MissingResponse)?;
			let echoed: PingResponse = decode(reply.message())?;
			assert_eq!(echoed.doubled, 8, "the servlet received the whole spliced body");

			exporter.stop();
			importer.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterDuplexForwardSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, exactly!(2)),
			(DUPLEX_SERVLET_HANDLED, exactly!(1))
		]
	}
}

// A duplex crosses the splice with both directions live at once. Request
// chunks reach the exporter's servlet as the client pushes them, and the
// echoes arrive before the request closes.
tb_scenario! {
	name: cluster_forwards_duplex_to_peer_gateway,
	spec: ClusterDuplexForwardSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_stream_hive(trace, certs),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (importer, exporter) = start_spliced_clusters(&trace, &certs, &hive).await?;
			let client = pooled_cluster_client(&trace, &certs, importer.addr()).await?;

			let (mut sink, mut body) = client.open_duplex_to(servlet_urn("stream-echo"))?;
			sink.push(b"ping-1").await?;

			let first = body.chunk().await?;
			sink.close_with(b"ping-2").await?;

			let second = body.chunk().await?;
			let trailer = body.chunk().await?;

			let opening = Some(b"ping-1".as_slice());
			let closing = Some(b"ping-2".as_slice());
			assert_eq!(first.as_deref(), opening, "the first chunk echoes before the request closes");
			assert_eq!(second.as_deref(), closing, "the closing chunk echoes");
			assert!(trailer.is_none(), "the echo ends with the request");

			exporter.stop();
			importer.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterStreamGateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_GATE_BLOCKED, exactly!(2), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// Gate policies cover stream opens. The reject-all policy that denies unary
// work also refuses routed stream and duplex opens before any route lookup, so
// mux streams cannot bypass `with_gate_policy`.
tb_scenario! {
	name: cluster_policy_gate_blocks_streams,
	spec: ClusterStreamGateSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let conf = with_mux_offer(
				ClusterConfig::builder(cluster_tls_config(&certs))
					.with_gate_policy(Arc::new(RejectAllPolicy))
					.build(),
			);

			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let client = pooled_cluster_client(&trace, &certs, cluster.addr()).await?;

			let (sink, response) = client.open_stream_to(servlet_urn("stream-echo"))?;
			sink.close_with(b"denied").await?;

			let refused = response.await.is_err();
			assert!(refused, "the gate refuses the stream open");

			let (sink, mut body) = client.open_duplex_to(servlet_urn("stream-echo"))?;
			sink.close_with(b"denied").await?;

			let refused = body.chunk().await.is_err();
			assert!(refused, "the gate refuses the duplex open");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterEdgePlaneStreamRefuseSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_EDGE_REFUSED, exactly!(2), equals!(TransitStatus::PermissionDenied))
		]
	}
}

/// The wire status that a refused open carries, or `None` for a served open
/// or a failure with no wire status.
///
/// A bare failure check passes on any refusal, even the `Unimplemented` of a
/// plane with no route. Each scenario checks the status it expects instead,
/// such as the edge policy's `PermissionDenied`.
fn refusal_status<T>(outcome: Result<T, TransportError>) -> Option<TransitStatus> {
	outcome.err().and_then(|error| error.transit_status())
}

// The edge accept plane admits Work frames alone. A stream servlet is live on
// the colony plane, so mux stream and duplex opens on the edge address would
// splice without the plane's refusal. Both fail closed.
tb_scenario! {
	name: cluster_edge_plane_refuses_streams,
	spec: ClusterEdgePlaneStreamRefuseSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_stream_hive(trace, certs),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut conf = routing_cluster_conf(&certs, Some(TransportOffer::mux(8)));
			conf.edge_bind_addr = Some("127.0.0.1:0".into());

			let cluster = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(cluster.addr()).await?;

			let Some(edge_addr) = cluster.edge_addr() else {
				return Err(expectation_failure("edge plane did not bind"));
			};

			let client = pooled_cluster_client(&trace, &certs, edge_addr).await?;

			let (sink, response) = client.open_stream_to(servlet_urn("stream-echo"))?;
			sink.close_with(b"denied").await?;

			let refused = refusal_status(response.await);
			assert_eq!(refused, Some(TransitStatus::PermissionDenied), "the edge refuses the stream open");

			let (sink, mut body) = client.open_duplex_to(servlet_urn("stream-echo"))?;
			sink.close_with(b"denied").await?;

			let refused = refusal_status(body.chunk().await);
			assert_eq!(refused, Some(TransitStatus::PermissionDenied), "the edge refuses the duplex open");

			cluster.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterSpliceInstanceTargetSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_WORK_REFUSED, exactly!(2), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_WORK_FAILED, absent!())
		]
	}
}

// A splice must target a servlet type, as unary work must. The gateway
// refuses an instance-narrowed stream or duplex open before route selection,
// so no open bypasses the load balancer and no dial runs.
tb_scenario! {
	name: cluster_refuses_instance_addressed_stream_opens,
	spec: ClusterSpliceInstanceTargetSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, with_mux_offer(routing_cluster_conf(&certs, None))).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let client = pooled_cluster_client(&trace, &certs, cluster.addr()).await?;
			let instance = servlet_urn("stream-echo").servlet_instance("127.0.0.1:9999")?;

			let (sink, response) = client.open_stream_to(instance.clone())?;
			sink.close_with(b"instance").await?;

			let refused = refusal_status(response.await);
			assert_eq!(refused, Some(TransitStatus::PermissionDenied), "the gateway refuses the stream open");

			let (sink, mut body) = client.open_duplex_to(instance)?;
			sink.close_with(b"instance").await?;

			let refused = refusal_status(body.chunk().await);
			assert_eq!(refused, Some(TransitStatus::PermissionDenied), "the gateway refuses the duplex open");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterSpliceUnroutedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(2)),
			(events::CLUSTER_WORK_FAILED, absent!())
		]
	}
}

// A stream or duplex open for a servlet type with no live trail refuses at
// its first route selection, as unary work does, and dials nothing. The
// refusal is the gateway handler's failure, so the client hears `Unknown`.
tb_scenario! {
	name: cluster_refuses_stream_opens_with_no_live_trail,
	spec: ClusterSpliceUnroutedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, with_mux_offer(routing_cluster_conf(&certs, None))).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let client = pooled_cluster_client(&trace, &certs, cluster.addr()).await?;

			let (sink, response) = client.open_stream_to(servlet_urn("stream-echo"))?;
			sink.close_with(b"unrouted").await?;

			let refused = refusal_status(response.await);
			assert_eq!(refused, Some(TransitStatus::Unknown), "the client hears the splice's refusal as unknown");

			let (sink, mut body) = client.open_duplex_to(servlet_urn("stream-echo"))?;
			sink.close_with(b"unrouted").await?;

			let refused = refusal_status(body.chunk().await);
			assert_eq!(refused, Some(TransitStatus::Unknown), "the client hears the splice's refusal as unknown");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterDuplexCancelSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(DUPLEX_SERVLET_HANDLED, exactly!(1)),
			(events::CLUSTER_WORK_FAILED, exactly!(2)),
			(events::HANDLER_FAILED, exactly!(3), equals!(TransitStatus::Internal))
		]
	}
}

// The cancel ends the splice on the importer, then on the exporter. Each
// gateway records its splice end as a failed forward, so two records prove the
// cancel crossed both hops. The servlet's duplex handler then fails, and each
// of the three handlers on the path records `Internal`. The client waits for
// every record before teardown, so a shutdown cannot pass the spec by chance.
tb_scenario! {
	name: cluster_duplex_cancel_propagates_to_peer,
	spec: ClusterDuplexCancelSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_stream_hive(trace, certs),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (importer, exporter) = start_spliced_clusters(&trace, &certs, &hive).await?;

			let client = pooled_cluster_client(&trace, &certs, importer.addr()).await?;

			let (mut sink, mut body) = client.open_duplex_to(servlet_urn("stream-echo"))?;
			sink.push(b"ping-1").await?;

			let first = body.chunk().await?;
			let live = Some(b"ping-1".as_slice());
			assert_eq!(first.as_deref(), live, "the duplex path echoes end to end before the cancel");

			drop(sink);
			drop(body);

			let propagated =
				|| trace.recorded(events::CLUSTER_WORK_FAILED) >= 2 && trace.recorded(events::HANDLER_FAILED) >= 3;
			poll_until(50, Duration::from_millis(100), propagated).await;

			exporter.stop();
			importer.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterStreamImpostorSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(2)),
			(events::CLUSTER_WORK_FAILED, exactly!(2), equals!(TransitStatus::Unavailable)),
			(STREAM_SERVLET_HANDLED, exactly!(0)),
			(DUPLEX_SERVLET_HANDLED, exactly!(0))
		]
	}
}

// A stream and a duplex splice reach a servlet only under the identity its
// registration names. Under `impostor_trusting_conf`, the dial's binding alone
// refuses each open before any body chunk leaves (CWE-346). The refusal is the
// gateway handler's failure, so the client hears `Unknown`.
tb_scenario! {
	name: cluster_splice_refuses_a_servlet_answering_under_another_identity,
	spec: ClusterStreamImpostorSpec,
	environment Bare {
		context: cluster_certs(),
		exec: |SetupEnv { trace, context: certs }| async move {
			let impostor_certs = stranger_gateway_certs();
			let impostor_conf = servlet_tls_config(&impostor_certs)?;
			let impostor = StreamEchoServlet::start(Arc::new(trace.share()), impostor_conf).await?;
			let cluster = start_cluster(&trace, impostor_trusting_conf(&certs, &impostor_certs)).await?;

			let mut control = connect_cluster(&certs, cluster.addr()).await?;
			let hive_addr = b"127.0.0.1:65034";
			let servlets = [servlet_info(&certs, "stream-echo", impostor.addr().to_string())];
			register_signed_hive_serving(&mut control, &certs.key, b"impostor", hive_addr, servlets).await?;

			let client = pooled_cluster_client(&trace, &certs, cluster.addr()).await?;

			let (sink, response) = client.open_stream_to(servlet_urn("stream-echo"))?;
			sink.close_with(b"impostor").await?;

			let refused = refusal_status(response.await);
			assert_eq!(refused, Some(TransitStatus::Unknown), "the client hears the splice's failure as unknown");

			let (sink, mut body) = client.open_duplex_to(servlet_urn("stream-echo"))?;
			sink.close_with(b"impostor").await?;

			let refused = refusal_status(body.chunk().await);
			assert_eq!(refused, Some(TransitStatus::Unknown), "the client hears the splice's failure as unknown");

			cluster.stop();
			impostor.stop();
			Ok(())
		}
	}
}
