//! Integration tests of the connection pool.
//!
//! The tests cover these pool behaviors:
//! - Connection pool reuse across three acquire and release cycles
//! - Per-destination pool isolation
//! - Sequential access through one shared pool (`pool_concurrent_access`)
//!
//! The basic connection keep-alive tests live in `connection_reuse.rs`.

#![cfg(all(
	feature = "std",
	feature = "tcp",
	feature = "tokio",
	feature = "builder",
	feature = "testing",
	feature = "colony",
	feature = "hex",
	feature = "instrument"
))]

use std::{
	sync::{
		atomic::{AtomicUsize, Ordering},
		Arc,
	},
	time::Duration,
};

use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::{
	colony::servlet::ServletConfig,
	der::Sequence,
	exactly,
	instrumentation::events,
	prelude::TightBeamSocketAddr,
	servlet, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, ScenarioConfigError, SetupEnv, TestFrame},
	trace::TraceCollector,
	transport::{tcp::r#async::TokioListener, ConnectionBuilder, ConnectionPool, PoolConfig},
	Beamable, Frame,
};

#[cfg(feature = "x509")]
use crate::common::static_pair::{client_pinning, CLIENT_CERT, CLIENT_KEY, SERVER_CERT, SERVER_KEY};
#[cfg(feature = "x509")]
use tightbeam::{
	crypto::{
		policy::Secp256k1Policy,
		sign::ecdsa::Secp256k1,
		x509::{
			policy::CertificateValidation,
			store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder},
			Certificate,
		},
	},
	error::TightBeamError,
};

// The tests exchange this message type.

#[derive(Clone, Debug, PartialEq, Beamable, Sequence)]
struct TestMessage {
	content: String,
}

// The tests share this function.

#[cfg(feature = "x509")]
fn make_server_trust_store() -> Result<Arc<dyn CertificateTrust>, TightBeamError> {
	let server_cert = Certificate::try_from(SERVER_CERT)?;
	Ok(Arc::new(
		CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(server_cert)?
			.build(),
	))
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
#[cfg(all(
	feature = "x509",
	feature = "transport-policy",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead"
))]
fn pool_reuse_config() -> Result<ScenarioConfig, ScenarioConfigError> {
	let builder = ScenarioConfig::builder().with_spec(PoolReuseSpec::latest());
	#[cfg(feature = "testing-csp")]
	let builder = builder.with_csp(PoolReuseProcess);
	builder.build()
}

// The pool scenarios share this echo servlet fixture.

#[cfg(all(
	feature = "x509",
	feature = "transport-policy",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead"
))]
pub struct PoolEchoServletConfig {
	message_count: Arc<AtomicUsize>,
}

#[cfg(all(
	feature = "x509",
	feature = "transport-policy",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead"
))]
servlet! {
	PoolEchoServlet<TestMessage, EnvConfig = PoolEchoServletConfig>,
	protocol: TokioListener,
	handle: |_msg, frame, ctx| async move {
		let config: &PoolEchoServletConfig = ctx.env_config();
		config.message_count.fetch_add(1, Ordering::SeqCst);
		Ok(Some(frame))
	}
}

#[cfg(all(
	feature = "x509",
	feature = "transport-policy",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead"
))]
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
	let validators = vec![Arc::new(client_pinning()) as Arc<dyn CertificateValidation>];

	Ok(ServletConfig::<TokioListener, TestMessage>::builder()
		.with_certificate(SERVER_CERT, key, validators)?
		.with_config(Arc::new(PoolEchoServletConfig { message_count }))
		.build())
}

#[cfg(all(
	feature = "x509",
	feature = "transport-policy",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead"
))]
async fn start_pool_echo_servlet(
	trace: TraceCollector,
	message_count: Arc<AtomicUsize>,
) -> Result<PoolEchoServlet, TightBeamError> {
	PoolEchoServlet::start(Arc::new(trace), pool_echo_conf(message_count)?).await
}

/// Leases a connection to `addr` from `pool`, sends one frame that carries
/// `label` on it, and returns the reply. The lease returns to the pool when
/// the step ends.
#[cfg(all(
	feature = "x509",
	feature = "transport-policy",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead"
))]
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

/// A full cycle of acquire, release, reuse, and release must leave the pool's
/// connection accounting intact. The pool must then admit a later brand-new
/// connection to another destination, which the reuse path cannot serve.
#[cfg(all(
	feature = "x509",
	feature = "transport-policy",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead"
))]
#[tokio::test]
async fn pool_admits_new_connections_after_reuse_cycle() -> Result<(), Box<dyn std::error::Error>> {
	let count1 = Arc::new(AtomicUsize::new(0));
	let count2 = Arc::new(AtomicUsize::new(0));
	let servlet1 = start_pool_echo_servlet(TraceCollector::default(), Arc::clone(&count1)).await?;
	let servlet2 = start_pool_echo_servlet(TraceCollector::default(), Arc::clone(&count2)).await?;
	let addr1 = servlet1.addr().to_owned();
	let addr2 = servlet2.addr().to_owned();

	let pool = Arc::new(
		ConnectionPool::<TokioListener>::builder()
			.with_trust_store(make_server_trust_store()?)
			.with_client_identity(SigningIdentity::from_spec(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?)
			.build(),
	);

	// Cycle 1: a fresh connection goes back to the pool healthy.
	let mut first = pool.connect(addr1).await?;
	let first_reply = first.conn()?.emit(TestFrame::v0(Some("cycle-1"), None), None).await?;
	assert!(first_reply.is_some(), "first acquire must round-trip a message");
	drop(first);

	// Cycle 2: the same destination must reuse the pooled connection.
	let mut second = pool.connect(addr1).await?;
	let second_reply = second.conn()?.emit(TestFrame::v0(Some("cycle-2"), None), None).await?;
	assert!(second_reply.is_some(), "reused connection must round-trip a message");
	drop(second);

	// The idle set of addr1 cannot serve a new destination, so the pool must
	// admit a brand-new connection. A wedged counter reports ResourceExhausted
	// here.
	let third = pool.connect(addr2).await;
	assert!(
		third.is_ok(),
		"pool refused a new connection after a reuse cycle: {:?}",
		third.err()
	);

	assert_eq!(count1.load(Ordering::SeqCst), 2, "both cycles must have reached servlet 1");

	Ok(())
}

// The single-flight envelope bound holds on both sides of the default
// encrypted ceiling (256 KiB): content near it round-trips, and the client
// refuses content past it locally with a typed `SizeExceeded` (CWE-400) in
// place of a connection reset from the server's fail-before-read path.
#[cfg(all(
	feature = "x509",
	feature = "transport-policy",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead"
))]
#[tokio::test]
async fn envelope_ceiling_refuses_oversize_locally() -> Result<(), Box<dyn std::error::Error>> {
	use tightbeam::transport::error::{TransportError, TransportFailure};

	let count = Arc::new(AtomicUsize::new(0));
	let servlet = start_pool_echo_servlet(TraceCollector::default(), Arc::clone(&count)).await?;
	let addr = servlet.addr().to_owned();
	// The round trip near the ceiling is CPU work that a loaded machine
	// stretches, so the default operation deadline bounds it.
	let pool = Arc::new(
		ConnectionPool::<TokioListener>::builder()
			.with_trust_store(make_server_trust_store()?)
			.with_client_identity(SigningIdentity::from_spec(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?)
			.build(),
	);

	let under_cap = "x".repeat(260_000);
	let msg = TestFrame::v0(Some(&under_cap), None);
	let mut client = pool.connect(addr).await?;
	let reply = client.conn()?.emit(msg, None).await;
	assert!(
		matches!(reply, Ok(Some(_))),
		"content under the encrypted envelope ceiling must round-trip"
	);

	drop(client);

	// The builder refuses with `MessageNotSent(frame, SizeExceeded)`, and the
	// retry layer strips the frame once the restart policy declines. The public
	// emit surface therefore reports `OperationFailed(SizeExceeded)`.
	let over_cap = "x".repeat(263_000);
	let msg = TestFrame::v0(Some(&over_cap), None);
	let mut client = pool.connect(addr).await?;
	let refusal = client.conn()?.emit(msg, None).await;
	assert!(
		matches!(refusal, Err(TransportError::OperationFailed(TransportFailure::SizeExceeded))),
		"content past the encrypted envelope ceiling must fail locally with a typed SizeExceeded, got {refusal:?}"
	);

	Ok(())
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

// Scenario: three acquire cycles run in sequence through one shared pool.

#[cfg(all(
	feature = "x509",
	feature = "transport-policy",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead"
))]
tb_scenario! {
	name: pool_concurrent_access,
	config: pool_reuse_config(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let servlet = start_pool_echo_servlet(trace.share(), Arc::default()).await?;
			let server_addr = servlet.addr().to_owned();

			let pool = Arc::new(
				ConnectionPool::<TokioListener>::builder()
					.with_trust_store(make_server_trust_store()?)
					.with_client_identity(SigningIdentity::from_spec(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?)
					.with_trace(trace.share())
					.build(),
			);

			let first = pooled_emit(&pool, server_addr, "concurrent-test").await?;
			let second = pooled_emit(&pool, server_addr, "concurrent-test").await?;
			let third = pooled_emit(&pool, server_addr, "concurrent-test").await?;
			assert!(first.is_some(), "the first pooled emit must return its echo");
			assert!(second.is_some(), "the second pooled emit must return its echo");
			assert!(third.is_some(), "the third pooled emit must return its echo");
			Ok(())
		}
	}
}
