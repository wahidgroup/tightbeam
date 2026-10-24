//! Streaming and duplex interactions through the colony stack.
//!
//! The `servlet!` stream and duplex arms serve over one multiplexed
//! connection, and the pooled client consumes them alongside unary
//! requests.

use std::sync::Arc;

use tightbeam::{
	cms::signed_data::SignerIdentifier,
	colony::{
		cluster::ClusterError,
		common::ColonyNamespace,
		hive::{Hive, HiveConfig, ServletBox},
		servlet::ServletConfig,
	},
	compose,
	crypto::{
		key::Secp256k1KeyProvider,
		x509::{utils::CertificateExt, CertificateSpec},
	},
	decode,
	der::Sequence,
	exactly, hive, servlet, tb_assert_spec, tb_scenario,
	testing::{ClientEnv, HiveEnv, ServletEnv, SetupEnv},
	trace::TraceCollector,
	transport::{
		client::{ConnectionBuilder, ConnectionPool, PoolConfig},
		handshake::negotiation::TransportOffer,
		tcp::r#async::TokioListener,
	},
	urn::Urn,
	Beamable, Frame, TightBeamError,
};

use tightbeam::transport::{PooledClient, TransportError, TransportFailure};

use crate::common::security::{pinning_trust_store, random_signing_key, test_certificate, ServerMaterials};
use crate::common::x509::combined_trust;

/// The message the streaming servlets take and answer with.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct StreamLabel {
	/// The text the message carries.
	pub label: String,
}

pub(crate) const SERVLET_UNARY_HANDLED: Urn<'static> =
	tightbeam::urn!("test", "event:colony-streaming/servlet-unary-handled");
pub(crate) const SERVLET_STREAM_HANDLED: Urn<'static> =
	tightbeam::urn!("test", "event:colony-streaming/servlet-stream-handled");
pub(crate) const SERVLET_DUPLEX_HANDLED: Urn<'static> =
	tightbeam::urn!("test", "event:colony-streaming/servlet-duplex-handled");
pub(crate) const UNARY_ECHOES: Urn<'static> = tightbeam::urn!("test", "event:colony-streaming/unary-echoes");
pub(crate) const STREAM_REPLY_REPORTS_LENGTH: Urn<'static> =
	tightbeam::urn!("test", "event:colony-streaming/stream-reply-reports-length");
pub(crate) const DUPLEX_ECHOES_CHUNKS: Urn<'static> =
	tightbeam::urn!("test", "event:colony-streaming/duplex-echoes-chunks");

fn reply_frame(label: impl AsRef<str>) -> Result<Frame, TightBeamError> {
	let label = label.as_ref();
	Ok(compose! {
		V0: id: b"colony-streaming-reply",
			message: StreamLabel { label: label.to_string() }
	}?)
}

servlet! {
	/// One servlet that answers all three interaction kinds.
	///
	/// - The unary arm echoes the frame.
	/// - The stream arm reports the collected body length.
	/// - The duplex arm echoes every request chunk back through the reply sink.
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

/// Builds a pooled mux lease with pinned server trust, shared by every
/// scenario in this file. The servlets here install no client validators,
/// so the handshake authenticates the server only.
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
// connection. The handler arm's shape is the only thing the servlet decides.
tb_scenario! {
	name: servlet_serves_unary_stream_and_duplex,
	spec: ColonyStreamingSpec,
	environment Servlet {
		context: ServerMaterials::generate(),
		start: |SetupEnv { trace, context: materials }| async move {
			let conf = streaming_servlet_conf(&materials)?;
			StreamingEchoServlet::start(Arc::new(trace), conf).await
		},
		setup: |ClientEnv { trace, context: materials, addr }| async move {
			pooled_lease(&trace, &materials, addr).await
		},
		client: |ServletEnv { trace, mut client, .. }| async move {
			let request = reply_frame("unary-body")?;
			let reply = client.emit(request.to_owned(), None).await?;
			let value = reply.map(|frame| frame.message().to_owned()) == Some(request.message().to_owned());

			trace.event_with(UNARY_ECHOES, &[], value)?;

			// The stream pushes 8 bytes, so the servlet reports "8".
			let (mut sink, response) = client.open_stream()?;
			sink.push(b"abcd").await?;
			sink.close_with(b"efgh").await?;

			let reply = response.await?;
			let expected = reply_frame("8")?;
			let value = reply.map(|frame| frame.message().to_owned()) == Some(expected.message().to_owned());

			trace.event_with(STREAM_REPLY_REPORTS_LENGTH, &[], value)?;

			// Duplex chunks echo back in order.
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

pub(crate) const STREAM_ONLY_REPLY_OK: Urn<'static> =
	tightbeam::urn!("test", "event:colony-streaming/stream-only-reply-ok");
pub(crate) const STREAM_ONLY_UNARY_REFUSED: Urn<'static> =
	tightbeam::urn!("test", "event:colony-streaming/stream-only-unary-refused");

servlet! {
	/// A servlet with a `stream:` arm alone. The service defaults refuse unary
	/// requests with `Unimplemented`.
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
			StreamOnlyServlet::start(Arc::new(trace), conf).await
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
			let value = reply.map(|frame| frame.message().to_owned()) == Some(expected.message().to_owned());

			trace.event_with(STREAM_ONLY_REPLY_OK, &[], value)?;

			Ok(())
		}
	}
}

hive! {
	StreamingHive,
	protocol: TokioListener
}

pub(crate) const HIVE_STREAM_REPLY_REPORTS_LENGTH: Urn<'static> =
	tightbeam::urn!("test", "event:colony-streaming/hive-stream-reply-reports-length");
pub(crate) const HIVE_DUPLEX_ECHOES_CHUNKS: Urn<'static> =
	tightbeam::urn!("test", "event:colony-streaming/hive-duplex-echoes-chunks");

/// Returns the type URN that every hive scenario in this file registers
/// and targets.
fn stream_echo_urn() -> Urn<'static> {
	ColonyNamespace::default()
		.servlet("stream-echo")
		.expect("test names satisfy the mint grammar")
}

/// Starts an established hive with one `StreamingEchoServlet` sibling.
/// The intra-hive pool pins the servlet certificate and offers mux.
async fn start_streaming_hive(
	trace: TraceCollector,
	materials: &ServerMaterials,
) -> Result<StreamingHive, TightBeamError> {
	let config = streaming_servlet_conf(materials)?;
	let trace = Arc::new(trace.share());
	let servlet = StreamingEchoServlet::start(Arc::clone(&trace), config).await?;

	let trust_store = pinning_trust_store(&materials.certificate)?;
	let mut conf = HiveConfig { trust_store: Some(trust_store), ..Default::default() };
	conf.pool.mux_offer = Some(Arc::new(TransportOffer::mux(8)));

	let mut hive = StreamingHive::new(Some(conf))?;
	hive.register(stream_echo_urn(), servlet, |t| {
		StreamingEchoServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.establish(trace).await?;
	Ok(hive)
}

tb_assert_spec! {
	pub HiveStreamingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SERVLET_STREAM_HANDLED, exactly!(1)),
			(HIVE_STREAM_REPLY_REPORTS_LENGTH, exactly!(1), equals!(true))
		]
	}
}

// `HiveContext::open_stream` drives a real sibling servlet. The hive's
// intra-hive pool validates the servlet certificate through
// `HiveConfig::trust_store` and negotiates mux. The streamed body's
// unary reply comes back as the servlet's complete reply frame, the
// same shape as `call`.
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

			let reply = response.await?;
			let label: StreamLabel = decode(reply.message())?;
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
		assertions: [
			(SERVLET_DUPLEX_HANDLED, exactly!(1)),
			(HIVE_DUPLEX_ECHOES_CHUNKS, exactly!(1), equals!(true))
		]
	}
}

// `HiveContext::open_duplex` targets the same sibling. Request chunks
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

pub(crate) const HIVE_IMPOSTOR_CALL_REFUSED: Urn<'static> =
	tightbeam::urn!("test", "event:colony-streaming/hive-impostor-call-refused");
pub(crate) const HIVE_IMPOSTOR_STREAM_REFUSED: Urn<'static> =
	tightbeam::urn!("test", "event:colony-streaming/hive-impostor-stream-refused");
pub(crate) const HIVE_IMPOSTOR_DUPLEX_REFUSED: Urn<'static> =
	tightbeam::urn!("test", "event:colony-streaming/hive-impostor-duplex-refused");

/// A servlet registered under the signer of another identity: its
/// registration names `claimed`, and `inner` presents a certificate of its
/// own.
struct ClaimedServlet<S> {
	inner: S,
	claimed: SignerIdentifier,
}

impl<S: ServletBox> ServletBox for ClaimedServlet<S> {
	fn addr_bytes(&self) -> Arc<[u8]> {
		self.inner.addr_bytes()
	}

	fn stop_boxed(self: Box<Self>) {
		Box::new(self.inner).stop_boxed();
	}

	fn signer(&self) -> Option<&SignerIdentifier> {
		Some(&self.claimed)
	}
}

/// Starts an established hive whose one sibling answers under an identity of
/// its own, while its registration names the [`ServerMaterials`] identity.
/// The intra-hive pool trusts both identities and offers mux, so the
/// handshake completes, and the dial's signer binding alone tells the two
/// apart.
async fn start_impostor_hive(
	trace: TraceCollector,
	materials: &ServerMaterials,
) -> Result<StreamingHive, TightBeamError> {
	let impostor_key = random_signing_key();
	let impostor_certificate = test_certificate(&impostor_key);
	let impostor_spec = CertificateSpec::Built(Box::new(impostor_certificate.clone()));
	let impostor_provider = Arc::new(Secp256k1KeyProvider::from(impostor_key));
	let config = ServletConfig::<TokioListener, StreamLabel>::builder()
		.with_certificate(impostor_spec, impostor_provider, vec![])?
		.with_mux_offer(Some(TransportOffer::mux(8)))
		.with_config(Arc::new(()))
		.build();
	let trace = Arc::new(trace.share());
	let inner = StreamingEchoServlet::start(Arc::clone(&trace), config).await?;
	let claimed = materials.certificate.signer_identifier()?;
	let servlet = ClaimedServlet { inner, claimed: claimed.clone() };

	let trust_store = combined_trust(&[&*materials.certificate, &impostor_certificate]);
	let mut conf = HiveConfig { trust_store: Some(trust_store), ..Default::default() };
	conf.pool.mux_offer = Some(Arc::new(TransportOffer::mux(8)));

	let mut hive = StreamingHive::new(Some(conf))?;
	hive.register(stream_echo_urn(), servlet, move |t| {
		let claimed = claimed.clone();
		async move {
			let inner = StreamingEchoServlet::start(t, ServletConfig::cleartext()).await?;
			Ok(ClaimedServlet { inner, claimed })
		}
	})?;
	hive.establish(trace).await?;
	Ok(hive)
}

/// Whether `outcome` is the refusal of a sibling dial whose answer presented
/// a certificate its route does not name.
fn is_peer_mismatch<T>(outcome: &Result<T, TightBeamError>) -> bool {
	matches!(outcome, Err(TightBeamError::ClusterError(error)) if matches!(**error, ClusterError::PeerMismatch))
}

tb_assert_spec! {
	pub HiveImpostorCallSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SERVLET_UNARY_HANDLED, exactly!(0)),
			(HIVE_IMPOSTOR_CALL_REFUSED, exactly!(1), equals!(true))
		]
	}
}

// A sibling call reaches a servlet only under the identity its registration
// names. The hive pool trusts both identities, so the handshake completes,
// and the dial's binding alone refuses the call before the frame leaves
// (CWE-346).
tb_scenario! {
	name: hive_context_call_refuses_a_sibling_answering_under_another_identity,
	spec: HiveImpostorCallSpec,
	environment Hive {
		context: ServerMaterials::generate(),
		start: |SetupEnv { trace, context: materials }| async move {
			start_impostor_hive(trace, &materials).await
		},
		client: |HiveEnv { trace, hive, .. }| async move {
			let ctx = hive.context();
			let stream_echo = stream_echo_urn();
			let request = reply_frame("impostor-call")?;

			let refused = ctx.call(&stream_echo, request).await;

			trace.event_with(HIVE_IMPOSTOR_CALL_REFUSED, &[], is_peer_mismatch(&refused))?;

			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub HiveImpostorStreamSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SERVLET_STREAM_HANDLED, exactly!(0)),
			(HIVE_IMPOSTOR_STREAM_REFUSED, exactly!(1), equals!(true))
		]
	}
}

// A sibling stream opens only toward the identity its registration names, so
// the dial's binding refuses the open before any chunk leaves (CWE-346).
tb_scenario! {
	name: hive_context_stream_refuses_a_sibling_answering_under_another_identity,
	spec: HiveImpostorStreamSpec,
	environment Hive {
		context: ServerMaterials::generate(),
		start: |SetupEnv { trace, context: materials }| async move {
			start_impostor_hive(trace, &materials).await
		},
		client: |HiveEnv { trace, hive, .. }| async move {
			let ctx = hive.context();
			let stream_echo = stream_echo_urn();

			let refused = ctx.open_stream(&stream_echo).await;

			trace.event_with(HIVE_IMPOSTOR_STREAM_REFUSED, &[], is_peer_mismatch(&refused))?;

			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub HiveImpostorDuplexSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SERVLET_DUPLEX_HANDLED, exactly!(0)),
			(HIVE_IMPOSTOR_DUPLEX_REFUSED, exactly!(1), equals!(true))
		]
	}
}

// A sibling duplex opens only toward the identity its registration names, so
// the dial's binding refuses the open before any chunk leaves (CWE-346).
tb_scenario! {
	name: hive_context_duplex_refuses_a_sibling_answering_under_another_identity,
	spec: HiveImpostorDuplexSpec,
	environment Hive {
		context: ServerMaterials::generate(),
		start: |SetupEnv { trace, context: materials }| async move {
			start_impostor_hive(trace, &materials).await
		},
		client: |HiveEnv { trace, hive, .. }| async move {
			let ctx = hive.context();
			let stream_echo = stream_echo_urn();

			let refused = ctx.open_duplex(&stream_echo).await;

			trace.event_with(HIVE_IMPOSTOR_DUPLEX_REFUSED, &[], is_peer_mismatch(&refused))?;

			hive.stop();
			Ok(())
		}
	}
}
