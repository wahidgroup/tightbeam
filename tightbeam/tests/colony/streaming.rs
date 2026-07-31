//! Streaming and duplex interactions through the colony stack: `servlet!`
//! stream/duplex arms served over one multiplexed connection and consumed
//! through the pooled client, alongside unary requests.

use std::sync::Arc;

use tightbeam::{
	colony::{
		common::ColonyNamespace,
		hive::{Hive, HiveConfig},
		servlet::ServletConfig,
	},
	compose,
	crypto::x509::CertificateSpec,
	decode,
	der::Sequence,
	exactly, hive, servlet, tb_assert_spec, tb_scenario,
	testing::{ClientEnv, HiveEnv, ServletEnv, SetupEnv},
	trace::TraceCollector,
	transport::{
		client::pool::{ConnectionBuilder, ConnectionPool, PoolConfig},
		handshake::negotiation::TransportOffer,
		tcp::r#async::TokioListener,
	},
	utils::urn::Urn,
	Beamable, Frame, TightBeamError,
};

use tightbeam::transport::{PooledClient, TransportError, TransportFailure};

use crate::common::security::{pinning_trust_store, ServerMaterials};

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct StreamLabel {
	pub label: String,
}

pub(crate) const SERVLET_UNARY_HANDLED: Urn<'static> = Urn::new("test", "event:colony-streaming/servlet-unary-handled");
pub(crate) const SERVLET_STREAM_HANDLED: Urn<'static> =
	Urn::new("test", "event:colony-streaming/servlet-stream-handled");
pub(crate) const SERVLET_DUPLEX_HANDLED: Urn<'static> =
	Urn::new("test", "event:colony-streaming/servlet-duplex-handled");
pub(crate) const UNARY_ECHOES: Urn<'static> = Urn::new("test", "event:colony-streaming/unary-echoes");
pub(crate) const STREAM_REPLY_REPORTS_LENGTH: Urn<'static> =
	Urn::new("test", "event:colony-streaming/stream-reply-reports-length");
pub(crate) const DUPLEX_ECHOES_CHUNKS: Urn<'static> = Urn::new("test", "event:colony-streaming/duplex-echoes-chunks");

fn reply_frame(label: &str) -> Result<Frame, TightBeamError> {
	Ok(compose! {
		V0: id: b"colony-streaming-reply",
			message: StreamLabel { label: label.to_string() }
	}?)
}

servlet! {
	/// One servlet answering all three interaction kinds: unary echoes the
	/// frame, stream reports the collected body length, duplex echoes every
	/// request chunk back through the reply sink.
	pub StreamingEchoServlet<StreamLabel, EnvConfig = ()>,
	protocol: TokioListener,
	handle: raw |frame, ctx| async move {
		ctx.trace().event(SERVLET_UNARY_HANDLED)?;
		Ok(Some(frame))
	},
	stream: |body, ctx| async move {
		ctx.trace().event(SERVLET_STREAM_HANDLED)?;
		let bytes = body.into_bytes().await?;
		let label = bytes.len().to_string();
		let frame = reply_frame(&label)?;

		Ok(Some(frame))
	},
	duplex: |body, reply, ctx| async move {
		ctx.trace().event(SERVLET_DUPLEX_HANDLED)?;
		let mut body = body;
		let mut reply = reply;
		while let Some(chunk) = body.chunk().await? {
			reply.push(&chunk).await?;
		}

		Ok(())
	}
}

fn streaming_servlet_conf(
	materials: &ServerMaterials,
) -> Result<ServletConfig<TokioListener, StreamLabel>, TightBeamError> {
	let cert = CertificateSpec::Built(Box::new((*materials.certificate).to_owned()));
	let key = Arc::clone(&materials.key_provider);
	Ok(ServletConfig::<TokioListener, StreamLabel>::builder()
		.with_certificate(cert, key, vec![])?
		.with_mux_offer(Some(TransportOffer::mux(8)))
		.with_config(Arc::new(()))
		.build())
}

/// Pooled mux lease with pinned server trust, shared by every scenario
/// in this file. The servlets here install no client validators, so the
/// handshake authenticates the server only.
async fn pooled_lease(
	trace: &tightbeam::trace::TraceCollector,
	materials: &ServerMaterials,
	addr: <TokioListener as tightbeam::transport::Protocol>::Address,
) -> Result<PooledClient<TokioListener>, TightBeamError> {
	let trust_store = pinning_trust_store(&materials.certificate)?;
	let config = PoolConfig {
		idle_timeout: None,
		max_connections: 1,
		mux_offer: Some(Arc::new(TransportOffer::mux(8))),
	};
	let pool = Arc::new(
		ConnectionPool::<TokioListener>::builder()
			.with_config(config)
			.with_trust_store(trust_store)
			.with_trace(trace.share())
			.build(),
	);

	Ok(pool.connect(addr).await?)
}

tb_assert_spec! {
	pub ColonyStreamingSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(SERVLET_UNARY_HANDLED, exactly!(1)),
			(SERVLET_STREAM_HANDLED, exactly!(1)),
			(SERVLET_DUPLEX_HANDLED, exactly!(1)),
			(UNARY_ECHOES, exactly!(1), equals!(true)),
			(STREAM_REPLY_REPORTS_LENGTH, exactly!(1), equals!(true)),
			(DUPLEX_ECHOES_CHUNKS, exactly!(1), equals!(true))
		]
	}
}

// All three interaction kinds reach one servlet over one pooled mux
// connection: the handler arm's shape is the only thing the servlet decides.
tb_scenario! {
	name: servlet_serves_unary_stream_and_duplex,
	spec: ColonyStreamingSpec,
	environment Servlet {
		context: ServerMaterials::generate(),
		start: |SetupEnv { trace, context: materials }| async move {
			let conf = streaming_servlet_conf(&materials)?;
			StreamingEchoServlet::start(Arc::new(trace), Some(conf)).await
		},
		setup: |ClientEnv { trace, context: materials, addr }| async move {
			pooled_lease(&trace, &materials, addr).await
		},
		client: |ServletEnv { trace, mut client, .. }| async move {
			// Unary
			let request = reply_frame("unary-body")?;
			let reply = client.emit(request.to_owned(), None).await?;
			let value = reply.map(|frame| frame.message.to_owned()) == Some(request.message.to_owned());

			trace.event_with(UNARY_ECHOES, &[], value)?;

			// Streaming: 8 bytes pushed, servlet reports "8"
			let (mut sink, response) = client.open_stream()?;
			sink.push(b"abcd").await?;
			sink.close_with(b"efgh").await?;

			let reply = response.await?;
			let expected = reply_frame("8")?;
			let value = reply.map(|frame| frame.message.to_owned()) == Some(expected.message.to_owned());

			trace.event_with(STREAM_REPLY_REPORTS_LENGTH, &[], value)?;

			// Duplex: chunks echo back in order
			let (mut sink, mut body) = client.open_duplex()?;
			sink.push(b"ping-1").await?;

			let first = body.chunk().await?;
			sink.close_with(b"ping-2").await?;

			let second = body.chunk().await?;
			let trailer = body.chunk().await?;

			let value = first.as_deref() == Some(b"ping-1".as_slice())
				&& second.as_deref() == Some(b"ping-2".as_slice())
				&& trailer.is_none();

			trace.event_with(DUPLEX_ECHOES_CHUNKS, &[], value)?;

			Ok(())
		}
	}
}

pub(crate) const STREAM_ONLY_REPLY_OK: Urn<'static> = Urn::new("test", "event:colony-streaming/stream-only-reply-ok");
pub(crate) const STREAM_ONLY_UNARY_REFUSED: Urn<'static> =
	Urn::new("test", "event:colony-streaming/stream-only-unary-refused");

servlet! {
	/// Streaming-only servlet: no `handle:` arm at all. Unary requests
	/// refuse with `Unimplemented` through the service defaults.
	pub StreamOnlyServlet<StreamLabel, EnvConfig = ()>,
	protocol: TokioListener,
	stream: |body, _ctx| async move {
		let bytes = body.into_bytes().await?;
		let label = bytes.len().to_string();
		let frame = reply_frame(&label)?;

		Ok(Some(frame))
	}
}

tb_assert_spec! {
	pub StreamOnlyServletSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(STREAM_ONLY_REPLY_OK, exactly!(1), equals!(true)),
			(STREAM_ONLY_UNARY_REFUSED, exactly!(1), equals!(true))
		]
	}
}

// A servlet without a unary arm serves streams and refuses unary emits
// with `Unimplemented` while the connection keeps serving.
tb_scenario! {
	name: stream_only_servlet_refuses_unary,
	spec: StreamOnlyServletSpec,
	environment Servlet {
		context: ServerMaterials::generate(),
		start: |SetupEnv { trace, context: materials }| async move {
			let conf = streaming_servlet_conf(&materials)?;
			StreamOnlyServlet::start(Arc::new(trace), Some(conf)).await
		},
		setup: |ClientEnv { trace, context: materials, addr }| async move {
			pooled_lease(&trace, &materials, addr).await
		},
		client: |ServletEnv { trace, mut client, .. }| async move {
			let request = reply_frame("unary-body")?;
			let unary_refused = matches!(
				client.emit(request, None).await,
				Err(TransportError::OperationFailed(TransportFailure::Unimplemented))
			);

			trace.event_with(STREAM_ONLY_UNARY_REFUSED, &[], unary_refused)?;

			let (mut sink, response) = client.open_stream()?;
			sink.push(b"abc").await?;
			sink.close_with(b"de").await?;

			let reply = response.await?;
			let expected = reply_frame("5")?;
			let value = reply.map(|frame| frame.message.to_owned()) == Some(expected.message.to_owned());

			trace.event_with(STREAM_ONLY_REPLY_OK, &[], value)?;

			Ok(())
		}
	}
}

// ============================================================================
// Intra-hive streaming: HiveContext::open_stream against a sibling servlet
// ============================================================================

hive! {
	StreamingHive,
	protocol: TokioListener
}

pub(crate) const HIVE_STREAM_REPLY_REPORTS_LENGTH: Urn<'static> =
	Urn::new("test", "event:colony-streaming/hive-stream-reply-reports-length");
pub(crate) const HIVE_DUPLEX_ECHOES_CHUNKS: Urn<'static> =
	Urn::new("test", "event:colony-streaming/hive-duplex-echoes-chunks");

/// Type URN every hive scenario in this file registers and targets.
fn stream_echo_urn() -> Urn<'static> {
	ColonyNamespace::default()
		.servlet("stream-echo")
		.expect("test names satisfy the mint grammar")
}

/// Established hive with one `StreamingEchoServlet` sibling: the
/// intra-hive pool pins the servlet certificate and offers mux.
async fn start_streaming_hive(
	trace: TraceCollector,
	materials: &ServerMaterials,
) -> Result<StreamingHive, TightBeamError> {
	let config = Some(streaming_servlet_conf(materials)?);
	let trace = Arc::new(trace.share());
	let servlet = StreamingEchoServlet::start(Arc::clone(&trace), config).await?;

	let trust_store = pinning_trust_store(&materials.certificate)?;
	let mut conf = HiveConfig { trust_store: Some(trust_store), ..Default::default() };
	conf.pool.mux_offer = Some(Arc::new(TransportOffer::mux(8)));

	let mut hive = StreamingHive::new(Some(conf))?;
	hive.register(stream_echo_urn(), servlet, |t| StreamingEchoServlet::start(t, None))?;
	hive.establish(trace).await?;
	Ok(hive)
}

tb_assert_spec! {
	pub HiveStreamingSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(SERVLET_STREAM_HANDLED, exactly!(1)),
			(HIVE_STREAM_REPLY_REPORTS_LENGTH, exactly!(1), equals!(true))
		]
	}
}

// `HiveContext::open_stream` drives a real sibling servlet: the hive's
// intra-hive pool validates the servlet certificate through
// `HiveConfig::trust_store`, negotiates mux, and the streamed body's
// unary reply comes back as message bytes, the same shape as `call`.
tb_scenario! {
	name: hive_context_streams_to_sibling_servlet,
	spec: HiveStreamingSpec,
	environment Hive {
		context: ServerMaterials::generate(),
		start: |SetupEnv { trace, context: materials }| async move {
			start_streaming_hive(trace, &materials).await
		},
		client: |HiveEnv { trace, hive, .. }| async move {
			let ctx = hive.context();
			let stream_echo = stream_echo_urn();
			let (mut sink, response) = ctx.open_stream(&stream_echo).await?;
			sink.push(b"hive-").await?;
			sink.close_with(b"beam").await?;

			let reply_bytes = response.await?;
			let label: StreamLabel = decode(&reply_bytes)?;
			let value = label.label == "9";

			trace.event_with(HIVE_STREAM_REPLY_REPORTS_LENGTH, &[], value)?;

			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub HiveDuplexSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(SERVLET_DUPLEX_HANDLED, exactly!(1)),
			(HIVE_DUPLEX_ECHOES_CHUNKS, exactly!(1), equals!(true))
		]
	}
}

// `HiveContext::open_duplex` against the same sibling: request chunks
// echo back on the reply body in order, and the trailer closes it.
tb_scenario! {
	name: hive_context_duplexes_to_sibling_servlet,
	spec: HiveDuplexSpec,
	environment Hive {
		context: ServerMaterials::generate(),
		start: |SetupEnv { trace, context: materials }| async move {
			start_streaming_hive(trace, &materials).await
		},
		client: |HiveEnv { trace, hive, .. }| async move {
			let ctx = hive.context();
			let stream_echo = stream_echo_urn();
			let (mut sink, mut body) = ctx.open_duplex(&stream_echo).await?;

			sink.push(b"hive-1").await?;

			let first = body.chunk().await?;

			sink.close_with(b"hive-2").await?;

			let second = body.chunk().await?;
			let trailer = body.chunk().await?;

			let value = first.as_deref() == Some(b"hive-1".as_slice())
				&& second.as_deref() == Some(b"hive-2".as_slice())
				&& trailer.is_none();

			trace.event_with(HIVE_DUPLEX_ECHOES_CHUNKS, &[], value)?;

			hive.stop();
			Ok(())
		}
	}
}
