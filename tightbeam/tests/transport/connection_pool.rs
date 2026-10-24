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
	servlet, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{SetupEnv, TestFrame},
	trace::TraceCollector,
	transport::{tcp::r#async::TokioListener, ConnectionBuilder, ConnectionPool, PoolConfig},
	urn::Urn,
	Beamable,
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

pub(crate) const ACQUIRE_CLIENT: Urn<'static> = tightbeam::urn!("test", "event:connection-pool/acquire-client");
pub(crate) const MESSAGE_COUNT: Urn<'static> = tightbeam::urn!("test", "event:connection-pool/message-count");
pub(crate) const POOL_CREATE: Urn<'static> = tightbeam::urn!("test", "event:connection-pool/pool-create");
pub(crate) const RECEIVE_RESPONSE: Urn<'static> = tightbeam::urn!("test", "event:connection-pool/receive-response");
pub(crate) const SEND_MESSAGE: Urn<'static> = tightbeam::urn!("test", "event:connection-pool/send-message");
pub(crate) const SERVLET1_COUNT: Urn<'static> = tightbeam::urn!("test", "event:connection-pool/servlet1-count");
pub(crate) const SERVLET2_COUNT: Urn<'static> = tightbeam::urn!("test", "event:connection-pool/servlet2-count");

// The tests exchange this message type.

#[derive(Clone, Debug, PartialEq, Beamable, Sequence)]
struct TestMessage {
	content: String,
}

// The tests share this helper.

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

tb_process_spec! {
	pub PoolReuseProcess,
	events {
		observable { POOL_CREATE, ACQUIRE_CLIENT, SEND_MESSAGE, RECEIVE_RESPONSE, events::POOL_RELEASED }
		hidden { }
	}
	states {
		Init => { POOL_CREATE => PoolReady },
		PoolReady => { ACQUIRE_CLIENT => Acquired1 },
		Acquired1 => { SEND_MESSAGE => Sent1 },
		Sent1 => { RECEIVE_RESPONSE => Received1 },
		Received1 => { events::POOL_RELEASED => Released1 },
		Released1 => { ACQUIRE_CLIENT => Acquired2 },
		Acquired2 => { SEND_MESSAGE => Sent2 },
		Sent2 => { RECEIVE_RESPONSE => Received2 },
		Received2 => { events::POOL_RELEASED => Released2 },
		Released2 => { ACQUIRE_CLIENT => Acquired3 },
		Acquired3 => { SEND_MESSAGE => Sent3 },
		Sent3 => { RECEIVE_RESPONSE => Received3 },
		Received3 => { events::POOL_RELEASED => Complete }
	}
	terminal { Complete }
}

tb_assert_spec! {
	pub PoolReuseSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(POOL_CREATE, exactly!(1)),
			(ACQUIRE_CLIENT, exactly!(3)),
			(SEND_MESSAGE, exactly!(3)),
			(RECEIVE_RESPONSE, exactly!(3)),
			(events::POOL_RELEASED, exactly!(3)),
			(events::POOL_DIAL, exactly!(1)),
			(events::POOL_REUSE_READY, exactly!(2)),
			(events::POOL_EXHAUSTED, exactly!(0)),
			(MESSAGE_COUNT, exactly!(1), equals!(3u64))
		]
	},
	// Version 1.1.0 adds the round-trip outcome to the contract. Every response
	// event must carry proof that the pooled emit returned a reply, so the spec
	// verifies delivery instead of an inline assert.
	V(1,1,0): {
		mode: Accept,
		assertions: [
			(POOL_CREATE, exactly!(1)),
			(ACQUIRE_CLIENT, exactly!(3)),
			(SEND_MESSAGE, exactly!(3)),
			(RECEIVE_RESPONSE, exactly!(3), equals!(1u64)),
			(events::POOL_RELEASED, exactly!(3)),
			(events::POOL_DIAL, exactly!(1)),
			(events::POOL_REUSE_READY, exactly!(2)),
			(events::POOL_EXHAUSTED, exactly!(0)),
			(MESSAGE_COUNT, exactly!(1), equals!(3u64))
		]
	}
}

tb_assert_spec! {
	pub PoolIsolationSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(POOL_CREATE, exactly!(1)),
			(ACQUIRE_CLIENT, exactly!(3)),
			(SEND_MESSAGE, exactly!(3)),
			(RECEIVE_RESPONSE, exactly!(3)),
			(events::POOL_RELEASED, exactly!(3)),
			(events::POOL_DIAL, exactly!(2)),
			(events::POOL_REUSE_READY, exactly!(1)),
			(events::POOL_EXHAUSTED, exactly!(0)),
			(SERVLET1_COUNT, exactly!(1), equals!(2u64)),
			(SERVLET2_COUNT, exactly!(1), equals!(1u64))
		]
	},
	// Version 1.1.0 adds the round-trip outcome to the contract. Every response
	// event must carry proof that the pooled emit returned a reply, so the spec
	// verifies delivery instead of an inline assert.
	V(1,1,0): {
		mode: Accept,
		assertions: [
			(POOL_CREATE, exactly!(1)),
			(ACQUIRE_CLIENT, exactly!(3)),
			(SEND_MESSAGE, exactly!(3)),
			(RECEIVE_RESPONSE, exactly!(3), equals!(1u64)),
			(events::POOL_RELEASED, exactly!(3)),
			(events::POOL_DIAL, exactly!(2)),
			(events::POOL_REUSE_READY, exactly!(1)),
			(events::POOL_EXHAUSTED, exactly!(0)),
			(SERVLET1_COUNT, exactly!(1), equals!(2u64)),
			(SERVLET2_COUNT, exactly!(1), equals!(1u64))
		]
	}
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
async fn start_pool_echo_servlet(message_count: Arc<AtomicUsize>) -> Result<PoolEchoServlet, TightBeamError> {
	PoolEchoServlet::start(Arc::new(TraceCollector::default()), pool_echo_conf(message_count)?).await
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
	spec: PoolReuseSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let message_count = Arc::new(AtomicUsize::new(0));
			let servlet = start_pool_echo_servlet(Arc::clone(&message_count)).await?;
			let server_addr = servlet.addr().to_owned();

			trace.event(POOL_CREATE)?;

			let pool = Arc::new(
				ConnectionPool::<TokioListener>::builder()
					.with_config(PoolConfig::default())
					.with_trust_store(make_server_trust_store()?)
					.with_client_identity(SigningIdentity::from_spec(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?)
					.with_timeout(Duration::from_millis(1000))
					.with_trace(trace.share())
					.build(),
			);

			for i in 1..=3 {
				trace.event(ACQUIRE_CLIENT)?;

				let mut client = pool.connect(server_addr).await?;

				trace.event(SEND_MESSAGE)?;

				let msg = TestFrame::v0(Some(&format!("test{i}")), None);
				let reply = client.conn()?.emit(msg, None).await?;
				trace.event_with(RECEIVE_RESPONSE, &[], u64::from(reply.is_some()))?;
			}

			trace.event_with(MESSAGE_COUNT, &[], message_count.load(Ordering::SeqCst) as u64)?;

			Ok(())
		}
	}
}

// Regression: the connection accounting holds across reuse cycles.

/// A full cycle of acquire, release, reuse, and release must leave the pool's
/// connection accounting intact. The pool must still admit a later brand-new
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
	let servlet1 = start_pool_echo_servlet(Arc::clone(&count1)).await?;
	let servlet2 = start_pool_echo_servlet(Arc::clone(&count2)).await?;
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

// The single-flight envelope bound holds on both sides of the ceiling.
// Content near the default encrypted ceiling (256 KiB) round-trips, and the
// client refuses content past it locally with a typed `SizeExceeded`
// (CWE-400). The refusal must not be a connection reset from the server's
// fail-before-read path.
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
	let servlet = start_pool_echo_servlet(Arc::clone(&count)).await?;
	let addr = servlet.addr().to_owned();
	let pool = Arc::new(
		ConnectionPool::<TokioListener>::builder()
			.with_trust_store(make_server_trust_store()?)
			.with_client_identity(SigningIdentity::from_spec(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?)
			.with_timeout(Duration::from_millis(3000))
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
			let servlet1 = start_pool_echo_servlet(Arc::clone(&count1)).await?;
			let servlet2 = start_pool_echo_servlet(Arc::clone(&count2)).await?;
			let addr1 = servlet1.addr().to_owned();
			let addr2 = servlet2.addr().to_owned();

			trace.event(POOL_CREATE)?;

			let pool = Arc::new(
				ConnectionPool::<TokioListener>::builder()
					.with_trust_store(make_server_trust_store()?)
					.with_client_identity(SigningIdentity::from_spec(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?)
					.with_trace(trace.share())
					.build(),
			);

			for (addr, name) in [(addr1, "addr1-test"), (addr2, "addr2-test"), (addr1, "addr1-test2")] {
				trace.event(ACQUIRE_CLIENT)?;

				let mut client = pool.connect(addr).await?;

				trace.event(SEND_MESSAGE)?;

				let reply = client.conn()?.emit(TestFrame::v0(Some(name), None), None).await?;

				trace.event_with(RECEIVE_RESPONSE, &[], u64::from(reply.is_some()))?;
			}

			trace.event_with(SERVLET1_COUNT, &[], count1.load(Ordering::SeqCst) as u64)?;
			trace.event_with(SERVLET2_COUNT, &[], count2.load(Ordering::SeqCst) as u64)?;

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
	spec: PoolReuseSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let message_count = Arc::new(AtomicUsize::new(0));
			let servlet = start_pool_echo_servlet(Arc::clone(&message_count)).await?;
			let server_addr = servlet.addr().to_owned();

			trace.event(POOL_CREATE)?;

			let pool = Arc::new(
				ConnectionPool::<TokioListener>::builder()
					.with_trust_store(make_server_trust_store()?)
					.with_client_identity(SigningIdentity::from_spec(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?)
					.with_trace(trace.share())
					.build(),
			);

			for _ in 0..3 {
				trace.event(ACQUIRE_CLIENT)?;
				let mut client = pool.connect(server_addr).await?;
				trace.event(SEND_MESSAGE)?;

				let reply = client
					.conn()?
					.emit(TestFrame::v0(Some("concurrent-test"), None), None)
					.await?;

				trace.event_with(RECEIVE_RESPONSE, &[], u64::from(reply.is_some()))?;
			}

			trace.event_with(MESSAGE_COUNT, &[], message_count.load(Ordering::SeqCst) as u64)?;

			Ok(())
		}
	}
}
