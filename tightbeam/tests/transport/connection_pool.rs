//! The integration tests of the connection pool.
//!
//! The tests cover these pool behaviors:
//! - Connection pool reuse across three acquire and release cycles
//! - Per-destination pool isolation
//! - Concurrent leases of one pool, which stop at its connection cap
//! - A lease whose exchange failed or was dropped leaves the pool, so the next lease dials fresh
//!
//! The basic connection keep-alive tests live in `connection_reuse.rs`.

#![cfg(all(
	feature = "tcp",
	feature = "testing",
	feature = "colony",
	feature = "hex",
	feature = "instrument"
))]

use core::future::Future;
use core::num::NonZeroUsize;
use core::pin::{pin, Pin};
use std::{
	sync::{
		atomic::{AtomicUsize, Ordering},
		mpsc::{self, Sender},
		Arc,
	},
	time::Duration,
};

use tokio::net::TcpListener;
use tokio::sync::Notify;

use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::{
	colony::servlet::ServletConfig,
	der::Sequence,
	exactly,
	instrumentation::events,
	prelude::TightBeamSocketAddr,
	servlet, tb_assert_spec, tb_cases, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, ScenarioConfigError, SetupEnv, TestFrame},
	trace::TraceCollector,
	transport::{
		client::ConnectionPoolBuilder,
		error::{TransportError, TransportFailure},
		tcp::r#async::{TcpTransport, TokioListener, TokioStream},
		ConnectionBuilder, ConnectionPool, EndpointConfig, MessageCollector, PoolConfig, TransportLimits,
	},
	Beamable, Frame,
};
use tightbeam::{
	crypto::{sign::ecdsa::Secp256k1, x509::store::CertificateTrust},
	error::TightBeamError,
};

use crate::common::poll::HANG_GUARD;
use crate::common::result::TestResult;
use crate::transport::static_pair::{
	client_identity, client_validators, server_trust, CLIENT_CERT, CLIENT_KEY, SERVER_CERT, SERVER_KEY,
};

// The tests exchange this message type.

/// The message that the echo servlet serves.
#[derive(Clone, Debug, PartialEq, Beamable, Sequence)]
struct TestMessage {
	/// The text that the message carries.
	content: String,
}

// The tests share this function.

/// The client's trust store of the static server, as the scenarios take it.
fn make_server_trust_store() -> Result<Arc<dyn CertificateTrust>, TightBeamError> {
	Ok(server_trust())
}

/// The builder of a pool that trusts the static server and presents the
/// static client.
fn static_pool() -> ConnectionPoolBuilder<TokioListener> {
	let builder = ConnectionPool::<TokioListener>::builder().with_trust_store(server_trust());
	builder.with_client_identity(client_identity())
}

/// A pool cap that leaves one connection of headroom past a single live
/// connection.
const TWO_CONNECTIONS: NonZeroUsize = match NonZeroUsize::new(2) {
	Some(cap) => cap,
	None => panic!("a pool cap takes one connection or more"),
};

/// A pool of [`static_pool`] that records on `trace` and holds at most
/// [`TWO_CONNECTIONS`], so one slot of drift in its count shows at the cap.
fn capped_pool(trace: &TraceCollector) -> Arc<ConnectionPool<TokioListener>> {
	let config = PoolConfig { max_connections: TWO_CONNECTIONS, ..PoolConfig::default() };
	let builder = static_pool().with_config(config);
	Arc::new(builder.with_trace(trace.share()).build())
}

// These specs state the event contract of each scenario.

// Each lease of the reuse scenarios takes its connection, carries one frame
// through the servlet's gate, and returns the connection before the next
// lease reuses it.
tb_process_spec! {
	pub PoolReuseProcess,
	events {
		observable { events::POOL_DIAL, events::POOL_REUSE_READY, events::GATE_ACCEPT, events::POOL_RELEASED }
		hidden { }
	}
	states {
		Init => { events::POOL_DIAL => Leased1 },
		Leased1 => { events::GATE_ACCEPT => Served1 },
		Served1 => { events::POOL_RELEASED => Released1 },
		Released1 => { events::POOL_REUSE_READY => Leased2 },
		Leased2 => { events::GATE_ACCEPT => Served2 },
		Served2 => { events::POOL_RELEASED => Released2 },
		Released2 => { events::POOL_REUSE_READY => Leased3 },
		Leased3 => { events::GATE_ACCEPT => Served3 },
		Served3 => { events::POOL_RELEASED => Complete }
	}
	terminal { Complete }
}

tb_assert_spec! {
	pub PoolReuseSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_RELEASED, exactly!(3)),
			(events::POOL_DIAL, exactly!(1)),
			(events::POOL_REUSE_READY, exactly!(2)),
			(events::POOL_EXHAUSTED, exactly!(0)),
			(events::GATE_ACCEPT, exactly!(3))
		]
	}
}

tb_assert_spec! {
	pub PoolIsolationSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_RELEASED, exactly!(3)),
			(events::POOL_DIAL, exactly!(2)),
			(events::POOL_REUSE_READY, exactly!(1)),
			(events::POOL_EXHAUSTED, exactly!(0)),
			(events::GATE_ACCEPT, exactly!(3))
		]
	}
}

/// Grades `PoolReuseSpec`, and orders the pool and gate events by
/// `PoolReuseProcess` in a build with `testing-csp`.
fn pool_reuse_config() -> Result<ScenarioConfig, ScenarioConfigError> {
	let builder = ScenarioConfig::builder().with_spec(PoolReuseSpec::latest());
	#[cfg(feature = "testing-csp")]
	let builder = builder.with_csp(PoolReuseProcess);
	builder.build()
}

// The pool tests share this echo servlet fixture.

/// The environment of the echo servlet.
pub struct PoolEchoServletConfig {
	/// The count of the frames that the servlet echoed.
	message_count: Arc<AtomicUsize>,
}

servlet! {
	PoolEchoServlet<TestMessage, EnvConfig = PoolEchoServletConfig>,
	protocol: TokioListener,
	handle: |_msg, frame, ctx| async move {
		let config: &PoolEchoServletConfig = ctx.env_config();
		config.message_count.fetch_add(1, Ordering::SeqCst);
		Ok(Some(frame))
	}
}

/// The configuration of an echo servlet that presents [`SERVER_CERT`],
/// admits the static client alone, and counts each frame it echoes into
/// `message_count`.
fn pool_echo_conf(
	message_count: Arc<AtomicUsize>,
) -> Result<
	ServletConfig<
		TokioListener,
		TestMessage,
		tightbeam::crypto::profiles::DefaultCryptoProvider,
		PoolEchoServletConfig,
	>,
	TightBeamError,
> {
	let key = SERVER_KEY.to_provider::<Secp256k1>()?;
	let validators = client_validators();

	let builder = ServletConfig::<TokioListener, TestMessage>::builder();
	let builder = builder.with_certificate(SERVER_CERT, key, validators)?;
	let builder = builder.with_config(Arc::new(PoolEchoServletConfig { message_count }));
	Ok(builder.build())
}

/// Starts the echo servlet of [`pool_echo_conf`] on `trace`, which counts
/// each frame it echoes into `message_count`.
async fn start_pool_echo_servlet(
	trace: TraceCollector,
	message_count: Arc<AtomicUsize>,
) -> Result<PoolEchoServlet, TightBeamError> {
	PoolEchoServlet::start(Arc::new(trace), pool_echo_conf(message_count)?).await
}

/// Leases a connection to `addr` from `pool`, sends one frame that carries
/// `label` on it, and returns the reply. The lease returns to the pool when
/// the step ends.
async fn pooled_emit(
	pool: &Arc<ConnectionPool<TokioListener>>,
	addr: TightBeamSocketAddr,
	label: impl AsRef<str>,
) -> Result<Option<Frame>, TightBeamError> {
	let mut client = pool.connect(addr).await?;
	let reply = client.conn()?.emit(TestFrame::v0(Some(label.as_ref()), None), None).await?;
	Ok(reply)
}

// Scenario: the pool reuses one connection across three acquire cycles.

#[cfg(all(
	feature = "x509",
	feature = "transport-policy",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead"
))]
tb_scenario! {
	name: connection_pool_reuse,
	config: pool_reuse_config(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let servlet = start_pool_echo_servlet(trace.share(), Arc::default()).await?;
			let server_addr = servlet.addr().to_owned();

			let pool = Arc::new(
				ConnectionPool::<TokioListener>::builder()
					.with_config(PoolConfig::default())
					.with_trust_store(make_server_trust_store()?)
					.with_client_identity(SigningIdentity::from_spec(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?)
					.with_timeout(Duration::from_millis(1000))
					.with_trace(trace.share())
					.build(),
			);

			let first = pooled_emit(&pool, server_addr, "test1").await?;
			let second = pooled_emit(&pool, server_addr, "test2").await?;
			let third = pooled_emit(&pool, server_addr, "test3").await?;
			assert!(first.is_some(), "the first pooled emit must return its echo");
			assert!(second.is_some(), "the second pooled emit must return its echo");
			assert!(third.is_some(), "the third pooled emit must return its echo");
			Ok(())
		}
	}
}

// Scenario: the connection accounting holds across reuse cycles.

/// A full cycle of acquire, release, reuse, and release leaves the pool's
/// connection accounting intact: the one connection counts once, so the pool
/// admits a brand-new connection to another destination, which the reuse path
/// cannot serve, and it refuses the next destination at its cap of two.
#[tokio::test]
async fn a_pool_admits_a_new_destination_after_a_reuse_cycle() -> TestResult {
	let servlet1 = start_pool_echo_servlet(TraceCollector::default(), Arc::default()).await?;
	let servlet2 = start_pool_echo_servlet(TraceCollector::default(), Arc::default()).await?;
	let servlet3 = start_pool_echo_servlet(TraceCollector::default(), Arc::default()).await?;
	let addr1 = servlet1.addr().to_owned();
	let addr2 = servlet2.addr().to_owned();
	let addr3 = servlet3.addr().to_owned();
	let trace = TraceCollector::new();
	let pool = capped_pool(&trace);

	// Cycle 1: a fresh connection goes back to the pool healthy.
	pooled_emit(&pool, addr1, "cycle-1").await?;

	// Cycle 2: the same destination must reuse the pooled connection.
	pooled_emit(&pool, addr1, "cycle-2").await?;

	// The idle set of addr1 cannot serve a new destination, so the pool must
	// admit a brand-new connection. A wedged counter reports ResourceExhausted
	// here.
	let third = pool.connect(addr2).await;
	let past_the_cap = pool.connect(addr3).await;
	assert!(third.is_ok());
	assert!(matches!(
		past_the_cap,
		Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted))
	));
	assert_eq!(trace.recorded(events::POOL_REUSE_READY), 1);
	Ok(())
}

/// The match of the reply that a row of the ceiling table expects.
type Reply = fn(&Result<Option<Frame>, TransportError>) -> bool;

// The single-flight envelope bound holds on both sides of the default
// encrypted ceiling (256 KiB): content near it round-trips, and the client
// refuses content past it locally with a typed `SizeExceeded` (CWE-400) in
// place of a connection reset from the server's fail-before-read path.
tb_cases! {
	async fn an_emit_of_content((size, verdict): (usize, Reply)) -> TestResult {
		let servlet = start_pool_echo_servlet(TraceCollector::default(), Arc::default()).await?;
		let addr = servlet.addr().to_owned();
		// The round trip near the ceiling is CPU work that a loaded machine
		// stretches, so the default operation deadline bounds it.
		let pool = Arc::new(static_pool().build());
		let content = "x".repeat(size);
		let mut client = pool.connect(addr).await?;

		let reply = client.conn()?.emit(TestFrame::v0(Some(&content), None), None).await;
		assert!(verdict(&reply));
		Ok(())
	}
	cases {
		under_the_ceiling_round_trips => (260_000, |reply| matches!(reply, Ok(Some(_)))),
		/// The builder refuses with `MessageNotSent(frame, SizeExceeded)`, and
		/// the retry layer strips the frame once the restart policy declines,
		/// so the public emit surface reports `OperationFailed(SizeExceeded)`.
		past_the_ceiling_fails_locally => (
			263_000,
			|reply| matches!(reply, Err(TransportError::OperationFailed(TransportFailure::SizeExceeded))),
		),
	}
}

// Scenario: the pool keeps the connections of each destination apart.

#[cfg(all(
	feature = "x509",
	feature = "transport-policy",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead"
))]
tb_scenario! {
	name: pool_per_destination_isolation,
	spec: PoolIsolationSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let count1 = Arc::new(AtomicUsize::new(0));
			let count2 = Arc::new(AtomicUsize::new(0));
			let servlet1 = start_pool_echo_servlet(trace.share(), Arc::clone(&count1)).await?;
			let servlet2 = start_pool_echo_servlet(trace.share(), Arc::clone(&count2)).await?;
			let addr1 = servlet1.addr().to_owned();
			let addr2 = servlet2.addr().to_owned();

			let pool = Arc::new(
				ConnectionPool::<TokioListener>::builder()
					.with_trust_store(make_server_trust_store()?)
					.with_client_identity(SigningIdentity::from_spec(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?)
					.with_trace(trace.share())
					.build(),
			);

			let first = pooled_emit(&pool, addr1, "addr1-test").await?;
			let second = pooled_emit(&pool, addr2, "addr2-test").await?;
			let third = pooled_emit(&pool, addr1, "addr1-test2").await?;
			assert!(first.is_some(), "the first emit to servlet 1 must return its echo");
			assert!(second.is_some(), "the emit to servlet 2 must return its echo");
			assert!(third.is_some(), "the second emit to servlet 1 must return its echo");

			assert_eq!(count1.load(Ordering::SeqCst), 2, "servlet 1 must serve both of its messages");
			assert_eq!(count2.load(Ordering::SeqCst), 1, "servlet 2 must serve its one message");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PoolContentionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(2)),
			(events::POOL_REUSE_READY, exactly!(0)),
			(events::POOL_EXHAUSTED, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(2))
		]
	}
}

// Scenario: three leases race one pool whose cap admits two. A lease reserves
// its slot before its dial starts, so the third lease meets the cap while the
// first two dials are in flight, and the two leases then exchange at once,
// each on its own connection.

#[cfg(all(
	feature = "x509",
	feature = "transport-policy",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead"
))]
tb_scenario! {
	name: racing_leases_stop_at_the_pool_cap,
	spec: PoolContentionSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let servlet = start_pool_echo_servlet(trace.share(), Arc::default()).await?;
			let server_addr = servlet.addr().to_owned();
			let pool = capped_pool(&trace);
			let first_request = TestFrame::v0(Some("lease-one"), None);
			let second_request = TestFrame::v0(Some("lease-two"), None);

			let (first, second, third) = tokio::join!(
				pool.connect(server_addr),
				pool.connect(server_addr),
				pool.connect(server_addr),
			);
			assert!(matches!(
				third,
				Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted))
			));

			let (mut first, mut second) = (first?, second?);
			let (first_answer, second_answer) = tokio::join!(
				first.emit(Frame::clone(&first_request), None),
				second.emit(Frame::clone(&second_request), None),
			);
			assert_eq!((first_answer?, second_answer?), (Some(first_request), Some(second_request)));
			Ok(())
		}
	}
}

// Scenario: a lease whose exchange broke, or whose emit was dropped, leaves
// the pool, so the next lease reads the answer to its own request.

/// The operation timeout of a pool whose first exchange runs past it. The
/// test of that exchange holds its paused clock and moves it by this span
/// once the echo server holds the request.
const LEASE_TIMEOUT: Duration = Duration::from_millis(100);

/// How the echo server of these cases serves the first connection it accepts.
enum FirstConnection {
	/// It echoes the first request once the test releases its late answer,
	/// and then every later request at once.
	AnswersLate,
	/// It reads the first request and closes the connection before it
	/// answers.
	Closes,
}

/// The three signals of the late answer on the first connection.
struct LateAnswer {
	/// The server raises it once the first request arrived.
	received: Arc<Notify>,
	/// The test fires it once it observed the client give up the exchange, so
	/// the answer cannot arrive inside the deadline of the client.
	release: Arc<Notify>,
	/// The server raises it once the late answer is out.
	answered: Arc<Notify>,
}

impl LateAnswer {
	/// Three signals that no end raised yet.
	fn new() -> Self {
		Self {
			received: Arc::new(Notify::new()),
			release: Arc::new(Notify::new()),
			answered: Arc::new(Notify::new()),
		}
	}

	/// The same three signals, for the other end.
	fn share(&self) -> Self {
		Self {
			received: Arc::clone(&self.received),
			release: Arc::clone(&self.release),
			answered: Arc::clone(&self.answered),
		}
	}

	/// Releases the late answer and waits until the server sent it.
	async fn release_and_await(&self) {
		self.release.notify_one();
		self.answered.notified().await;
	}
}

/// Echoes each request that arrives on `transport`, until the connection
/// ends.
async fn echo_each(mut transport: TcpTransport<TokioStream>) {
	while let Ok((request, status)) = transport.collect_message().await {
		let answer = Some(Frame::clone(&request));
		if transport.send_response(status, answer).await.is_err() {
			return;
		}
	}
}

/// Serves the first connection of the echo server as `first` says. The
/// server raises `received` once the first request arrived, and a late answer
/// waits for its release and raises `answered` once it is out.
async fn serve_first(mut transport: TcpTransport<TokioStream>, first: FirstConnection, late: LateAnswer) {
	let Ok((request, status)) = transport.collect_message().await else {
		return;
	};

	late.received.notify_one();

	if let FirstConnection::Closes = first {
		return;
	}

	late.release.notified().await;
	let answer = transport.send_response(status, Some(Frame::clone(&request))).await;
	late.answered.notify_one();
	if answer.is_ok() {
		echo_each(transport).await;
	}
}

/// Starts a cleartext echo server on a loopback port, which serves its first
/// connection as `first` says and echoes on every later one. It returns the
/// address beside the signals of the late answer.
async fn start_echo_server(first: FirstConnection) -> (TightBeamSocketAddr, LateAnswer) {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("a loopback port binds");
	let addr = TightBeamSocketAddr(listener.local_addr().expect("a bound listener has an address"));
	let late = LateAnswer::new();
	let served = late.share();

	tokio::spawn(async move {
		let mut first = Some((first, served));
		while let Ok((stream, _)) = listener.accept().await {
			let transport = TcpTransport::new(TokioStream::from(stream), EndpointConfig::cleartext());
			match first.take() {
				Some((first, served)) => tokio::spawn(serve_first(transport, first, served)),
				None => tokio::spawn(echo_each(transport)),
			};
		}
	});

	(addr, late)
}

/// A cleartext pool whose connections run each exchange under
/// `operation_timeout`.
fn cleartext_pool(operation_timeout: Duration) -> Arc<ConnectionPool<TokioListener>> {
	let builder = ConnectionPool::<TokioListener>::builder().allow_cleartext();
	Arc::new(builder.with_timeout(operation_timeout).build())
}

/// Leases a connection to `addr` from `pool`, sends one request on it, and
/// returns the request beside its answer.
async fn fresh_lease(pool: &Arc<ConnectionPool<TokioListener>>, addr: TightBeamSocketAddr) -> (Frame, Option<Frame>) {
	let request = TestFrame::v0(Some("request-two"), None);
	let mut lease = pool.connect(addr).await.expect("the pool dials the echo server");
	let answer = lease.emit(Frame::clone(&request), None).await.expect("the echo server answers");
	(request, answer)
}

/// A hold on the paused clock of the test runtime, which keeps every deadline
/// where it is until the test advances the clock.
///
/// Tokio holds a paused clock still while a blocking task runs, so the hold
/// is a blocking task that waits for the hold to drop. The task waits for at
/// most [`HANG_GUARD`], so a stalled exchange still fails at its deadline.
struct HeldClock {
	/// The sender whose drop ends the blocking task.
	_release: Sender<()>,
}

impl HeldClock {
	/// Holds the paused clock until the hold drops.
	fn new() -> Self {
		let (release, held) = mpsc::channel::<()>();
		tokio::task::spawn_blocking(move || held.recv_timeout(HANG_GUARD));
		HeldClock { _release: release }
	}
}

/// Drives `emit` until the echo server holds its request, with the exchange
/// still in flight.
async fn until_arrival(emit: Pin<&mut impl Future>, late: &LateAnswer) {
	tokio::select! {
		_ = emit => panic!("the echo server holds its first answer until the release"),
		() = late.received.notified() => {}
	}
}

/// Drives `emit` until the echo server holds its request, and then drops it
/// with the exchange in flight.
async fn abandon_after_arrival(emit: impl Future, late: &LateAnswer) {
	until_arrival(pin!(emit), late).await;
}

/// Drives `emit` until the echo server holds its request, moves the held
/// clock by [`LEASE_TIMEOUT`], and returns the outcome of the exchange.
async fn past_the_deadline<T>(emit: impl Future<Output = T>, late: &LateAnswer) -> T {
	let mut emit = pin!(emit);
	until_arrival(emit.as_mut(), late).await;

	tokio::time::advance(LEASE_TIMEOUT).await;
	emit.await
}

/// An exchange that runs past its deadline fails its connection, so the pool
/// discards it, and the next lease reads the answer to its own request on a
/// fresh dial (CWE-672).
#[tokio::test(start_paused = true)]
async fn a_timed_out_lease_leaves_the_pool_and_the_next_lease_dials_fresh() -> TestResult {
	let _held = HeldClock::new();
	let (addr, late) = start_echo_server(FirstConnection::AnswersLate).await;
	let pool = cleartext_pool(LEASE_TIMEOUT);
	let mut first = pool.connect(addr).await?;
	let emit = first.emit(TestFrame::v0(Some("request-one"), None), None);
	let timed_out = past_the_deadline(emit, &late).await;

	drop(first);

	late.release_and_await().await;

	let (request, answer) = fresh_lease(&pool, addr).await;
	assert!(matches!(
		timed_out,
		Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded))
	));
	assert_eq!(answer, Some(request));
	Ok(())
}

/// An exchange that meets the close of its peer fails its connection, so the
/// pool discards it, and the next lease dials fresh.
#[tokio::test]
async fn a_connection_the_peer_closed_is_not_leased_twice() -> TestResult {
	let (addr, _late) = start_echo_server(FirstConnection::Closes).await;
	let pool = cleartext_pool(TransportLimits::default().operation_timeout);
	let mut first = pool.connect(addr).await?;
	let closed = first.emit(TestFrame::v0(Some("request-one"), None), None).await;

	drop(first);

	let (request, answer) = fresh_lease(&pool, addr).await;
	assert!(matches!(closed, Err(TransportError::ConnectionClosed)));
	assert_eq!(answer, Some(request));
	Ok(())
}

/// A caller that drops an emit before its answer leaves the exchange in
/// flight, so the pool discards the connection, and the next lease reads the
/// answer to its own request on a fresh dial.
#[tokio::test]
async fn a_lease_whose_emit_was_dropped_mid_exchange_is_not_leased_again() -> TestResult {
	let (addr, late) = start_echo_server(FirstConnection::AnswersLate).await;
	let pool = cleartext_pool(TransportLimits::default().operation_timeout);
	let mut first = pool.connect(addr).await?;
	let emit = first.emit(TestFrame::v0(Some("request-one"), None), None);
	abandon_after_arrival(emit, &late).await;

	drop(first);

	late.release_and_await().await;

	let (request, answer) = fresh_lease(&pool, addr).await;
	assert_eq!(answer, Some(request));
	Ok(())
}
