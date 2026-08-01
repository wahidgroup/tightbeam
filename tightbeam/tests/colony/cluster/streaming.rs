//! Cross-cluster streaming and duplex forwarding (gateway splice).
//!
//! The stream-echo servlet lives only in cluster B. A client opens a
//! routed stream against cluster A (`open_stream_to` / `open_duplex_to`),
//! and A splices it to B's gateway with the stream loop guard set; B
//! serves it locally. Cancelling the client stream propagates across
//! the splice to the servlet.

use tightbeam::transport::{PooledClient, Protocol};
use tightbeam::{compose, servlet};

use super::common::*;

/// Set by the duplex cancel probe so the cancel scenario can wait for
/// propagation deterministically instead of sleeping a fixed time.
///
/// Shared by every scenario in this binary, yet only a genuine
/// mid-stream abort can set it: a completing duplex handler disarms
/// its probe before the responder sends the End trailer the client
/// waits on. A new scenario that cancels this servlet must not run
/// beside [`cluster_duplex_cancel_propagates_to_peer`].
static DUPLEX_CANCEL_SEEN: AtomicBool = AtomicBool::new(false);

/// Observes a propagated cancel from inside the duplex servlet handler.
///
/// A cancelled stream aborts the handler task, dropping its future and
/// this probe with it. A normal completion disarms first, so only an
/// abort reports.
struct CancelProbe {
	trace: TraceCollector,
	armed: bool,
}

impl CancelProbe {
	fn disarm(&mut self) {
		self.armed = false;
	}
}

impl Drop for CancelProbe {
	fn drop(&mut self) {
		if self.armed {
			DUPLEX_CANCEL_SEEN.store(true, Ordering::SeqCst);
			let _ = self.trace.event(SERVLET_DUPLEX_CANCELLED);
		}
	}
}

servlet! {
	/// Streaming and duplex arms only: stream reports the collected body
	/// length, duplex echoes every request chunk back through the reply
	/// sink. The duplex arm carries the cancel probe.
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
		let mut probe = CancelProbe { trace: ctx.trace().share(), armed: true };
		let mut body = body;
		let mut reply = reply;
		while let Some(chunk) = body.chunk().await? {
			reply.push(&chunk).await?;
		}

		probe.disarm();
		Ok(())
	}
}

/// Hive hosting one stream-echo servlet, muxed on both the servlet
/// server and the hive -> cluster pool.
async fn start_stream_hive(
	trace: TraceCollector,
	certs: Arc<ClusterTestCerts>,
) -> Result<ClusterTestHive, TightBeamError> {
	let servlet_conf = servlet_tls_config(&certs)?;
	let servlet = StreamEchoServlet::start(Arc::new(trace.share()), Some(servlet_conf)).await?;

	let conf = hive_tls_config(&certs);
	let mut hive = ClusterTestHive::new(Some(conf))?;
	hive.register(servlet_urn("stream-echo"), servlet, |t| StreamEchoServlet::start(t, None))?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// [`peering_cluster_conf`] with a mux offer, so the gateway serves
/// routed streams and its pools open them.
fn mux_peering_conf(certs: &ClusterTestCerts) -> ClusterConfig {
	let mut conf = peering_cluster_conf(certs);
	conf.pool_config.mux_offer = Some(Arc::new(TransportOffer::mux(8)));
	conf
}

/// [`advertising_cluster_conf`] with a mux offer, so the exporting
/// gateway serves forwarded streams from its peer.
fn mux_advertising_conf(certs: &ClusterTestCerts, peer: String) -> ClusterConfig {
	let mut conf = advertising_cluster_conf(certs, peer);
	conf.pool_config.mux_offer = Some(Arc::new(TransportOffer::mux(8)));
	conf
}

/// Pooled mux lease against a gateway, for the routed stream entry
/// points ([`PooledClient::open_stream_to`] / [`PooledClient::open_duplex_to`]).
async fn pooled_cluster_client(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	addr: &<TokioListener as Protocol>::Address,
) -> Result<PooledClient<TokioListener>, TightBeamError> {
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

	let client = pool.connect(addr.to_owned()).await?;
	Ok(client)
}

/// Two peered gateways with the stream-echo hive registered in the
/// exporter: the shared preamble for every splice scenario. Returns
/// the importer the client dials first, the exporter second.
async fn start_spliced_clusters(
	trace: &TraceCollector,
	certs: &Arc<ClusterTestCerts>,
	hive: &ClusterTestHive,
) -> Result<(ClusterGateway, ClusterGateway), TightBeamError> {
	let importer = start_cluster(trace, mux_peering_conf(certs)).await?;
	let exporter = start_cluster(trace, mux_advertising_conf(certs, importer.addr().to_string())).await?;

	hive.register_with_cluster(exporter.addr()).await?;

	let learned = wait_for_peer_types(&importer, 50, Duration::from_millis(100)).await;
	trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned.len() as u64)?;

	Ok((importer, exporter))
}

/// Poll until the servlet-side cancel probe reports or attempts
/// exhaust. Branching lives here, not in scenarios.
async fn wait_for_cancel_probe(attempts: u32, interval: Duration) -> bool {
	for _ in 0..attempts {
		if DUPLEX_CANCEL_SEEN.load(Ordering::SeqCst) {
			return true;
		}

		tokio::time::sleep(interval).await;
	}

	DUPLEX_CANCEL_SEEN.load(Ordering::SeqCst)
}

tb_assert_spec! {
	pub ClusterStreamForwardSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, exactly!(2)),
			(STREAM_SERVLET_HANDLED, exactly!(1)),
			(STREAM_ECHOED, exactly!(1), equals!(8u64))
		]
	}
}

// Streaming cross-cluster forward: stream-echo lives only in the
// exporter; the client opens a routed stream against the importer; the
// importer splices to the exporter (loop guard set), the exporter
// serves locally, and the servlet's reply frame relays back verbatim.
tb_scenario! {
	name: cluster_forwards_streaming_to_peer_gateway,
	spec: ClusterStreamForwardSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_stream_hive(trace, certs),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (importer, exporter) = start_spliced_clusters(&trace, &certs, &hive).await?;

			let client = pooled_cluster_client(&trace, &certs, importer.addr()).await?;
			trace.event(WORK_SENT)?;

			let (mut sink, response) = client.open_stream_to(servlet_urn("stream-echo"))?;
			sink.push(b"abcd").await?;
			sink.close_with(b"efgh").await?;

			let reply = response.await?.ok_or(TightBeamError::MissingResponse)?;
			let echoed: PingResponse = decode(&reply.message)?;
			trace.event_with(STREAM_ECHOED, &[], u64::from(echoed.doubled))?;

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
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, exactly!(2)),
			(DUPLEX_SERVLET_HANDLED, exactly!(1)),
			(DUPLEX_ECHOED, exactly!(1), equals!(true))
		]
	}
}

// Duplex cross-cluster forward: both directions relay concurrently
// across the splice - request chunks reach the exporter's servlet as
// they are pushed, and its echoes arrive before the request closes.
tb_scenario! {
	name: cluster_forwards_duplex_to_peer_gateway,
	spec: ClusterDuplexForwardSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_stream_hive(trace, certs),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (importer, exporter) = start_spliced_clusters(&trace, &certs, &hive).await?;

			let client = pooled_cluster_client(&trace, &certs, importer.addr()).await?;
			trace.event(WORK_SENT)?;

			let (mut sink, mut body) = client.open_duplex_to(servlet_urn("stream-echo"))?;
			sink.push(b"ping-1").await?;

			let first = body.chunk().await?;
			sink.close_with(b"ping-2").await?;

			let second = body.chunk().await?;
			let trailer = body.chunk().await?;

			let value = first.as_deref() == Some(b"ping-1".as_slice())
				&& second.as_deref() == Some(b"ping-2".as_slice())
				&& trailer.is_none();

			trace.event_with(DUPLEX_ECHOED, &[], value)?;

			exporter.stop();
			importer.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterDuplexCancelSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(DUPLEX_SERVLET_HANDLED, exactly!(1)),
			(DUPLEX_LIVE_BEFORE_CANCEL, exactly!(1), equals!(true)),
			(DUPLEX_CANCEL_PROPAGATED, exactly!(1), equals!(true)),
			(SERVLET_DUPLEX_CANCELLED, exactly!(1))
		]
	}
}

// Cancel propagation across the splice: the client proves the duplex
// path is live (one chunk echoes end to end), then drops its stream
// halves. The cancel crosses importer -> exporter -> servlet, aborting
// the servlet handler, which the cancel probe reports. The propagation
// flag is recorded before any teardown, so a shutdown abort cannot
// satisfy the spec spuriously.
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
			trace.event_with(DUPLEX_LIVE_BEFORE_CANCEL, &[], first.as_deref() == Some(b"ping-1".as_slice()))?;

			drop(sink);
			drop(body);

			let propagated = wait_for_cancel_probe(50, Duration::from_millis(100)).await;
			trace.event_with(DUPLEX_CANCEL_PROPAGATED, &[], propagated)?;

			exporter.stop();
			importer.stop();
			hive.stop();
			Ok(())
		}
	}
}
