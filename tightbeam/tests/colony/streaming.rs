//! Tests of the streaming and duplex interactions through the colony stack.
//!
//! The `servlet!` stream and duplex arms serve over one multiplexed
//! connection, and the pooled client consumes them alongside unary
//! requests.

use std::sync::Arc;

use tightbeam::{
	cms::signed_data::SignerIdentifier,
	colony::{
		cluster::ClusterError,
		hive::{Hive, HiveConfig, HiveContext, ServletBox},
		servlet::ServletConfig,
		urn::ColonyNamespace,
	},
	compose,
	crypto::{
		key::Secp256k1KeyProvider,
		x509::{utils::CertificateExt, CertificateSpec},
	},
	decode,
	der::Sequence,
	exactly, hive,
	instrumentation::events,
	servlet, tb_assert_spec, tb_scenario,
	testing::{fixtures::TestTrace, ClientEnv, HiveEnv, ScenarioConfig, ServletEnv, SetupEnv},
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
	stream: |body, _ctx| async move {
		let bytes = body.into_bytes().await?;
		let label = bytes.len().to_string();
		let frame = reply_frame(&label)?;

		Ok(Some(frame))
	},
	duplex: |body, reply, _ctx| async move {
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

/// Builds a pooled mux lease with pinned server trust, the client side of
/// every scenario in this file. The servlets here leave client validation
/// unset, so the handshake authenticates the server alone.
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

// Each handler arm runs inside the handler span of the servlet's trace, so on
// a trace with the detail flag set each arm that answers records one
// `HANDLER_ENTER`.
tb_assert_spec! {
	pub ColonyStreamingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SERVLET_UNARY_HANDLED, exactly!(1)),
			(events::HANDLER_ENTER, exactly!(3))
		]
	}
}

// All three interaction kinds reach one servlet over one pooled mux
// connection. The servlet chooses the shape of its handler arms alone.
tb_scenario! {
	name: servlet_serves_unary_stream_and_duplex,
	config: ScenarioConfig::builder()
		.with_spec(ColonyStreamingSpec::latest())
		.with_trace(TestTrace::with_detail(true))
		.build(),
	environment Servlet {
		context: ServerMaterials::generate(),
		start: |SetupEnv { trace, context: materials }| async move {
			let conf = streaming_servlet_conf(&materials)?;
			StreamingEchoServlet::start(Arc::new(trace), conf).await
		},
		setup: |ClientEnv { trace, context: materials, addr }| async move {
			pooled_lease(&trace, &materials, addr).await
		},
		client: |ServletEnv { mut client, .. }| async move {
			let request = reply_frame("unary-body")?;
			let reply = client.emit(request.to_owned(), None).await?;
			let echoed = reply.map(|frame| frame.message().to_owned());
			assert_eq!(echoed, Some(request.message().to_owned()), "the unary arm echoes the frame");

			// The stream pushes 8 bytes, so the servlet reports "8".
			let (mut sink, response) = client.open_stream()?;
			sink.push(b"abcd").await?;
			sink.close_with(b"efgh").await?;

			let reply = response.await?;
			let expected = reply_frame("8")?;
			let reported = reply.map(|frame| frame.message().to_owned());
			assert_eq!(reported, Some(expected.message().to_owned()), "the stream arm reports the 8-byte body");

			// Duplex chunks echo back in order.
			let (mut sink, mut body) = client.open_duplex()?;
			sink.push(b"ping-1").await?;

			let first = body.chunk().await?;
			sink.close_with(b"ping-2").await?;

			let second = body.chunk().await?;
			let trailer = body.chunk().await?;

			let chunks = (first.as_deref(), second.as_deref(), trailer);
			let expected = (Some(b"ping-1".as_slice()), Some(b"ping-2".as_slice()), None);
			assert_eq!(chunks, expected, "the duplex arm echoes each chunk in order and closes");

			Ok(())
		}
	}
}

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
			(events::GATE_ACCEPT, exactly!(2))
		]
	}
}

// A servlet with a `stream:` arm alone serves streams and refuses unary
// emits with `Unimplemented` while the connection continues to serve.
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
		client: |ServletEnv { mut client, .. }| async move {
			let request = reply_frame("unary-body")?;
			let refused = client.emit(request, None).await;
			let unimplemented =
				matches!(refused, Err(TransportError::OperationFailed(TransportFailure::Unimplemented)));
			assert!(unimplemented, "a stream-only servlet refuses a unary call");

			let (mut sink, response) = client.open_stream()?;
			sink.push(b"abc").await?;
			sink.close_with(b"de").await?;

			let reply = response.await?;
			let expected = reply_frame("5")?;
			let reported = reply.map(|frame| frame.message().to_owned());
			assert_eq!(reported, Some(expected.message().to_owned()), "the stream arm reports the 5-byte body");

			Ok(())
		}
	}
}

hive! {
	StreamingHive,
	protocol: TokioListener
}

/// Returns the type URN that every hive scenario in this file registers
/// and targets.
fn stream_echo_urn() -> Urn<'static> {
	ColonyNamespace::default()
		.servlet("stream-echo")
		.expect("test names satisfy the mint grammar")
}

/// Starts an established hive with one `StreamingEchoServlet` sibling. The
/// intra-hive pool pins the servlet certificate through
/// `HiveConfig::trust_store` and offers mux.
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
			(events::HANDLER_ENTER, exactly!(1))
		]
	}
}

// `HiveContext::open_stream` drives a real sibling servlet through the
// intra-hive pool. The unary reply to the streamed body comes back as the
// complete reply frame of the servlet, the same shape as `call`.
tb_scenario! {
	name: hive_context_streams_to_sibling_servlet,
	config: ScenarioConfig::builder()
		.with_spec(HiveStreamingSpec::latest())
		.with_trace(TestTrace::with_detail(true))
		.build(),
	environment Hive {
		context: ServerMaterials::generate(),
		start: |SetupEnv { trace, context: materials }| async move {
			start_streaming_hive(trace, &materials).await
		},
		client: |HiveEnv { hive, .. }| async move {
			let ctx = hive.context();
			let stream_echo = stream_echo_urn();
			let (mut sink, response) = ctx.open_stream(&stream_echo).await?;
			sink.push(b"hive-").await?;
			sink.close_with(b"beam").await?;

			let reply = response.await?;
			let label: StreamLabel = decode(reply.message())?;
			assert_eq!(label.label, "9", "the sibling's stream arm reports the 9-byte body");

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
			(events::HANDLER_ENTER, exactly!(1))
		]
	}
}

// `HiveContext::open_duplex` targets the same sibling. Request chunks
// echo back on the reply body in order, and the trailer closes it.
tb_scenario! {
	name: hive_context_duplexes_to_sibling_servlet,
	config: ScenarioConfig::builder()
		.with_spec(HiveDuplexSpec::latest())
		.with_trace(TestTrace::with_detail(true))
		.build(),
	environment Hive {
		context: ServerMaterials::generate(),
		start: |SetupEnv { trace, context: materials }| async move {
			start_streaming_hive(trace, &materials).await
		},
		client: |HiveEnv { hive, .. }| async move {
			let ctx = hive.context();
			let stream_echo = stream_echo_urn();
			let (mut sink, mut body) = ctx.open_duplex(&stream_echo).await?;

			sink.push(b"hive-1").await?;

			let first = body.chunk().await?;

			sink.close_with(b"hive-2").await?;

			let second = body.chunk().await?;
			let trailer = body.chunk().await?;

			let chunks = (first.as_deref(), second.as_deref(), trailer);
			let expected = (Some(b"hive-1".as_slice()), Some(b"hive-2".as_slice()), None);
			assert_eq!(chunks, expected, "the sibling echoes each chunk in order and closes");

			hive.stop();
			Ok(())
		}
	}
}

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

/// Returns the type URN of the sibling that answers under the identity its
/// registration names, beside the impostor.
fn honest_echo_urn() -> Urn<'static> {
	ColonyNamespace::default()
		.servlet("honest-echo")
		.expect("test names satisfy the mint grammar")
}

/// Streams a 9-byte body to the honest sibling of `ctx`, and returns the
/// label of its reply.
async fn honest_stream_label(ctx: &Arc<dyn HiveContext>) -> Result<String, TightBeamError> {
	let honest_echo = honest_echo_urn();
	let (mut sink, response) = ctx.open_stream(&honest_echo).await?;
	sink.push(b"hive-").await?;
	sink.close_with(b"beam").await?;

	let reply = response.await?;
	let label: StreamLabel = decode(reply.message())?;
	Ok(label.label)
}

/// Starts an established hive with two siblings, whose registrations both
/// name the [`ServerMaterials`] identity.
///
/// - The `stream-echo` sibling answers under an identity of its own. The
///   intra-hive pool trusts both identities and offers mux, so the handshake
///   completes, and the dial's signer binding alone tells the two apart.
/// - The `honest-echo` sibling answers under the identity its registration names.
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

	let honest = StreamingEchoServlet::start(Arc::clone(&trace), streaming_servlet_conf(materials)?).await?;

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
	hive.register(honest_echo_urn(), honest, |t| {
		StreamingEchoServlet::start(t, ServletConfig::cleartext())
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
			(events::CLUSTER_DIAL_REFUSED, exactly!(1))
		]
	}
}

// A sibling call reaches a servlet only under the identity its registration
// names. The hive pool trusts both identities, so the handshake completes and
// the dial's binding alone refuses the call before the frame leaves (CWE-346).
tb_scenario! {
	name: hive_context_call_refuses_a_sibling_answering_under_another_identity,
	spec: HiveImpostorCallSpec,
	environment Hive {
		context: ServerMaterials::generate(),
		start: |SetupEnv { trace, context: materials }| async move {
			start_impostor_hive(trace, &materials).await
		},
		client: |HiveEnv { hive, .. }| async move {
			let ctx = hive.context();
			let stream_echo = stream_echo_urn();
			let request = reply_frame("impostor-call")?;

			let refused = ctx.call(&stream_echo, request).await;
			assert!(is_peer_mismatch(&refused), "the hive's dial refuses the sibling's answer");

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
			(events::HANDLER_ENTER, exactly!(1)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(1))
		]
	}
}

// A sibling stream opens only toward the identity its registration names, so
// the dial's binding refuses the open before any chunk leaves (CWE-346). The
// handler count of 1 is the honest sibling's stream alone, which proves that
// the trace reaches the siblings' handlers.
tb_scenario! {
	name: hive_context_stream_refuses_a_sibling_answering_under_another_identity,
	config: ScenarioConfig::builder()
		.with_spec(HiveImpostorStreamSpec::latest())
		.with_trace(TestTrace::with_detail(true))
		.build(),
	environment Hive {
		context: ServerMaterials::generate(),
		start: |SetupEnv { trace, context: materials }| async move {
			start_impostor_hive(trace, &materials).await
		},
		client: |HiveEnv { hive, .. }| async move {
			let ctx = hive.context();
			let stream_echo = stream_echo_urn();
			let honest = honest_stream_label(&ctx).await?;

			let refused = ctx.open_stream(&stream_echo).await;
			assert_eq!(honest, "9", "the honest sibling's stream arm reports the 9-byte body");
			assert!(is_peer_mismatch(&refused), "the hive's dial refuses the sibling's answer");

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
			(events::HANDLER_ENTER, exactly!(1)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(1))
		]
	}
}

// A sibling duplex opens only toward the identity its registration names, so
// the dial's binding refuses the open before any chunk leaves (CWE-346). The
// handler count of 1 is the honest sibling's stream alone, which proves that
// the trace reaches the siblings' handlers.
tb_scenario! {
	name: hive_context_duplex_refuses_a_sibling_answering_under_another_identity,
	config: ScenarioConfig::builder()
		.with_spec(HiveImpostorDuplexSpec::latest())
		.with_trace(TestTrace::with_detail(true))
		.build(),
	environment Hive {
		context: ServerMaterials::generate(),
		start: |SetupEnv { trace, context: materials }| async move {
			start_impostor_hive(trace, &materials).await
		},
		client: |HiveEnv { hive, .. }| async move {
			let ctx = hive.context();
			let stream_echo = stream_echo_urn();
			let honest = honest_stream_label(&ctx).await?;

			let refused = ctx.open_duplex(&stream_echo).await;
			assert_eq!(honest, "9", "the honest sibling's stream arm reports the 9-byte body");
			assert!(is_peer_mismatch(&refused), "the hive's dial refuses the sibling's answer");

			hive.stop();
			Ok(())
		}
	}
}

/// The steps of one unary request that a servlet serves over a multiplexed
/// connection, with its gate verdict, in the order the request takes them.
const SERVLET_STEPS: [Urn<'static>; 5] = [
	events::ROUTE_STEP,
	events::POLICY_EVAL,
	events::GATE_ACCEPT,
	events::HANDLER_ENTER,
	events::HANDLER_EXIT,
];

/// The [`SERVLET_STEPS`] that the servlet's own trace records, in order, as it
/// serves one unary request, under a trace whose config sets
/// `enable_internal_detail` to `detail`. The client records into a trace of
/// its own.
async fn servlet_trail(detail: bool) -> Result<Vec<Urn<'static>>, TightBeamError> {
	let servlet_trace = Arc::new(TestTrace::with_detail(detail));
	let materials = ServerMaterials::generate();
	let conf = streaming_servlet_conf(&materials)?;
	let servlet = StreamingEchoServlet::start(Arc::clone(&servlet_trace), conf).await?;

	let mut lease = pooled_lease(&TraceCollector::new(), &materials, servlet.addr().to_owned()).await?;
	lease.emit(reply_frame("servlet-trail")?, None).await?;
	servlet.stop();

	Ok(TestTrace::trail(&servlet_trace, &SERVLET_STEPS))
}

/// A servlet's trace records the gate verdict of each request it serves, and,
/// when its config sets the detail flag, the route step, the policy step, and
/// the span of the handler around that verdict.
#[tokio::test]
async fn a_servlet_records_the_steps_of_its_requests_on_its_own_trace() -> Result<(), TightBeamError> {
	let trails = [servlet_trail(true).await?, servlet_trail(false).await?];
	assert_eq!(trails, [SERVLET_STEPS.to_vec(), vec![events::GATE_ACCEPT]]);
	Ok(())
}

/// The gate verdicts, and the count of unary handler events, that `replaced`
/// records as a servlet serves one request after `set_trace` installs
/// `replaced` in place of the trace the servlet started with.
async fn replaced_trace_records() -> Result<(Vec<Urn<'static>>, usize), TightBeamError> {
	let materials = ServerMaterials::generate();
	let conf = streaming_servlet_conf(&materials)?;
	let servlet = StreamingEchoServlet::start(Arc::new(TraceCollector::new()), conf).await?;
	let replaced = Arc::new(TraceCollector::new());
	servlet.set_trace(Arc::clone(&replaced));

	let mut lease = pooled_lease(&TraceCollector::new(), &materials, servlet.addr().to_owned()).await?;
	lease.emit(reply_frame("replaced-trace")?, None).await?;
	servlet.stop();

	let handled = replaced.recorded(SERVLET_UNARY_HANDLED);
	Ok((TestTrace::trail(&replaced, &[events::GATE_ACCEPT]), handled))
}

/// A servlet records each request that it serves after `set_trace` into the
/// trace that the call installs: the gate verdict of the connection, and the
/// event of the handler.
#[tokio::test]
async fn a_replaced_trace_records_the_requests_after_the_replacement() -> Result<(), TightBeamError> {
	assert_eq!(replaced_trace_records().await?, (vec![events::GATE_ACCEPT], 1));
	Ok(())
}
