//! Connection Pool Integration Tests
//!
//! Tests connection pooling functionality:
//! - Connection pool reuse across multiple acquire/release cycles
//! - Per-destination pool isolation
//! - Concurrent pool access
//!
//! For basic connection keep-alive tests, see connection_reuse.rs

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

use tightbeam::{
	colony::servlet::ServletConfig,
	der::Sequence,
	exactly,
	instrumentation::events,
	servlet, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{create_v0_tightbeam, trace::TraceCollector, SetupEnv},
	transport::{tcp::r#async::TokioListener, ConnectionBuilder, ConnectionPool, PoolConfig},
	utils::urn::Urn,
	Beamable,
};

#[cfg(feature = "x509")]
use tightbeam::{
	crypto::{
		hash::Sha3_256,
		key::SigningKeySpec,
		policy::Secp256k1Policy,
		sign::ecdsa::Secp256k1,
		x509::{
			policy::PublicKeyPinning,
			store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder},
			Certificate, CertificateSpec,
		},
	},
	error::TightBeamError,
	hex,
};

pub(crate) const ACQUIRE_CLIENT: Urn<'static> = Urn::new("test", "event:connection-pool/acquire-client");
pub(crate) const MESSAGE_COUNT: Urn<'static> = Urn::new("test", "event:connection-pool/message-count");
pub(crate) const POOL_CREATE: Urn<'static> = Urn::new("test", "event:connection-pool/pool-create");
pub(crate) const RECEIVE_RESPONSE: Urn<'static> = Urn::new("test", "event:connection-pool/receive-response");
pub(crate) const SEND_MESSAGE: Urn<'static> = Urn::new("test", "event:connection-pool/send-message");
pub(crate) const SERVLET1_COUNT: Urn<'static> = Urn::new("test", "event:connection-pool/servlet1-count");
pub(crate) const SERVLET2_COUNT: Urn<'static> = Urn::new("test", "event:connection-pool/servlet2-count");

// ============================================================================
// Test Message Types
// ============================================================================

#[derive(Clone, Debug, PartialEq, Beamable, Sequence)]
struct TestMessage {
	content: String,
}

// ============================================================================
// TLS Test Certificates (x509 feature only)
// ============================================================================

#[cfg(feature = "x509")]
const SERVER_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"-----BEGIN CERTIFICATE-----
MIIBajCCAQ+gAwIBAgIBATALBglghkgBZQMEAwowHTEbMBkGA1UEAwwSU3RhdGlj
IFRlc3QgU2VydmVyMB4XDTI1MTEyMTIyMDkxMVoXDTM1MTExOTIyMDkxMVowHTEb
MBkGA1UEAwwSU3RhdGljIFRlc3QgU2VydmVyMFYwEAYHKoZIzj0CAQYFK4EEAAoD
QgAEG4TFVnsSZECZXT7VqroFZdceGDRgSBn/nBf16dXdB49wvq+PWItUFQf+1qZC
xatC39+BIKf2Od5RItR6aajo0aNCMEAwHQYDVR0OBBYEFEOubLl6za81S4KG3bKb
SSyV6VhwMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAsGCWCGSAFl
AwQDCgNIADBFAiEA2aChCQdJ1LI46IWMds2yNoOG8Pq4nYqbEgETdIR+vnQCID7U
88OyM9q8+mrRAHYOyG7zYxKaxeWQTpwQVoVgCjs+
-----END CERTIFICATE-----"#,
);

#[cfg(feature = "x509")]
const CLIENT_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"-----BEGIN CERTIFICATE-----
MIIBajCCAQ+gAwIBAgIBATALBglghkgBZQMEAwowHTEbMBkGA1UEAwwSU3RhdGlj
IFRlc3QgQ2xpZW50MB4XDTI1MTEyMTIyMDkxMVoXDTM1MTExOTIyMDkxMVowHTEb
MBkGA1UEAwwSU3RhdGljIFRlc3QgQ2xpZW50MFYwEAYHKoZIzj0CAQYFK4EEAAoD
QgAETUts0TYQMsqb0q652QCqTUXZ6tgKyUIzdMRRpyVNB2YqPq2i0P4gi20lfOsP
BkKEZi6Ff1e2a1TBmL0xDe020KNCMEAwHQYDVR0OBBYEFKPczeMV5zGTz6VPSCJD
QZFgb0XEMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAsGCWCGSAFl
AwQDCgNIADBFAiEA0HI5WVq8ch27rQx7SO+hGwsQGLGHHvc34pfa7MQ3R4kCICJP
7O7AR01io0/m4Hez90niWi1m+zeJS00hvuznD/Hp
-----END CERTIFICATE-----"#,
);

#[cfg(feature = "x509")]
const SERVER_KEY: SigningKeySpec =
	SigningKeySpec::Bytes(&hex!("0101010101010101010101010101010101010101010101010101010101010101"));

#[cfg(feature = "x509")]
const CLIENT_KEY: SigningKeySpec =
	SigningKeySpec::Bytes(&hex!("0202020202020202020202020202020202020202020202020202020202020202"));

#[cfg(feature = "x509")]
const CLIENT_PUB_KEY: &[u8] = &hex!("044d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07662a3eada2d0fe208b6d257ceb0f064284662e857f57b66b54c198bd310ded36d0");

#[cfg(feature = "x509")]
const CLIENT_PINNING: PublicKeyPinning<1> = PublicKeyPinning::new([CLIENT_PUB_KEY]);

// ============================================================================
// Test Helpers
// ============================================================================

#[cfg(feature = "x509")]
fn make_server_trust_store() -> Result<Arc<dyn CertificateTrust>, TightBeamError> {
	let server_cert = Certificate::try_from(SERVER_CERT)?;
	Ok(Arc::new(
		CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
			.with_certificate(server_cert)?
			.build(),
	))
}

// ============================================================================
// Spec Definitions
// ============================================================================

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
		gate: Ok,
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
	// 1.1.0: the round-trip outcome joins the contract: every response
	// event must carry proof that the pooled emit returned a reply, so
	// the spec verifies delivery instead of an inline assert.
	V(1,1,0): {
		mode: Accept,
		gate: Ok,
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
		gate: Ok,
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
	// 1.1.0: the round-trip outcome joins the contract: every response
	// event must carry proof that the pooled emit returned a reply, so
	// the spec verifies delivery instead of an inline assert.
	V(1,1,0): {
		mode: Accept,
		gate: Ok,
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

// ============================================================================
// Shared echo servlet fixture (pool scenarios)
// ============================================================================

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
		let config: &PoolEchoServletConfig = ctx.env_config()?;
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
fn pool_echo_conf(message_count: Arc<AtomicUsize>) -> Result<ServletConfig<TokioListener, TestMessage>, TightBeamError> {
	Ok(ServletConfig::<TokioListener, TestMessage>::builder()
		.with_certificate(
			SERVER_CERT,
			SERVER_KEY.to_provider::<Secp256k1>()?,
			vec![Arc::new(CLIENT_PINNING)],
		)?
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
	PoolEchoServlet::start(Arc::new(TraceCollector::default()), Some(pool_echo_conf(message_count)?)).await
}

// ============================================================================
// Scenario: Connection Pool Reuse
// ============================================================================

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
			let server_addr = servlet.addr();

			trace.event(POOL_CREATE)?;

			let pool = Arc::new(
				ConnectionPool::<TokioListener>::builder()
					.with_config(PoolConfig::default())
					.with_trust_store(make_server_trust_store()?)
					.with_client_identity(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?
					.with_timeout(Duration::from_millis(1000))
					.with_trace(trace.share())
					.build(),
			);

			for i in 1..=3 {
				trace.event(ACQUIRE_CLIENT)?;

				let mut client = pool.connect(server_addr).await?;

				trace.event(SEND_MESSAGE)?;

				let msg = create_v0_tightbeam(Some(&format!("test{i}")), None);
				let reply = client.conn()?.emit(msg, None).await?;
				trace.event_with(RECEIVE_RESPONSE, &[], u64::from(reply.is_some()))?;
			}

			trace.event_with(MESSAGE_COUNT, &[], message_count.load(Ordering::SeqCst) as u64)?;

			Ok(())
		}
	}
}

// ============================================================================
// Regression: connection accounting across reuse cycles
// ============================================================================

/// A full acquire -> release -> reuse -> release cycle must leave the pool's
/// connection accounting intact: a subsequent brand-new connection (different
/// destination, so the reuse path cannot serve it) must still be admitted.
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
	let addr1 = servlet1.addr();
	let addr2 = servlet2.addr();

	let pool = Arc::new(
		ConnectionPool::<TokioListener>::builder()
			.with_trust_store(make_server_trust_store()?)
			.with_client_identity(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?
			.build(),
	);

	// Cycle 1: fresh connection, released healthy back to the pool.
	let mut first = pool.connect(addr1).await?;
	let first_reply = first.conn()?.emit(create_v0_tightbeam(Some("cycle-1"), None), None).await?;
	assert!(first_reply.is_some(), "first acquire must round-trip a message");
	drop(first);

	// Cycle 2: same destination, must be served from the pool (reuse path).
	let mut second = pool.connect(addr1).await?;
	let second_reply = second.conn()?.emit(create_v0_tightbeam(Some("cycle-2"), None), None).await?;
	assert!(second_reply.is_some(), "reused connection must round-trip a message");
	drop(second);

	// A new destination cannot be served from addr1's idle set, so the pool
	// must admit a brand-new connection; a wedged counter reports ResourceExhausted here.
	let third = pool.connect(addr2).await;
	assert!(
		third.is_ok(),
		"pool refused a new connection after a reuse cycle: {:?}",
		third.err()
	);

	assert_eq!(count1.load(Ordering::SeqCst), 2, "both cycles must have reached servlet 1");

	Ok(())
}

// Single-flight envelope bound.
// Content near the default encrypted ceiling (256 KiB) round-trips.
// Content past it is refused locally with typed `SizeExceeded` (CWE-400).
// The refusal must not be a connection reset from the server's fail-before-read path.
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
	let addr = servlet.addr();

	let pool = Arc::new(
		ConnectionPool::<TokioListener>::builder()
			.with_trust_store(make_server_trust_store()?)
			.with_client_identity(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?
			.with_timeout(Duration::from_millis(3000))
			.build(),
	);

	let under_cap = "x".repeat(260_000);
	let msg = create_v0_tightbeam(Some(&under_cap), None);
	let mut client = pool.connect(addr).await?;
	let reply = client.conn()?.emit(msg, None).await;
	assert!(
		matches!(reply, Ok(Some(_))),
		"content under the encrypted envelope ceiling must round-trip"
	);

	drop(client);

	// The builder refuses with `MessageNotSent(frame, SizeExceeded)`.
	// The retry layer strips the frame once the restart policy declines.
	// The public emit surface therefore reports `OperationFailed(SizeExceeded)`.
	let over_cap = "x".repeat(263_000);
	let msg = create_v0_tightbeam(Some(&over_cap), None);
	let mut client = pool.connect(addr).await?;
	let refusal = client.conn()?.emit(msg, None).await;
	assert!(
		matches!(refusal, Err(TransportError::OperationFailed(TransportFailure::SizeExceeded))),
		"content past the encrypted envelope ceiling must fail locally with a typed SizeExceeded, got {refusal:?}"
	);

	Ok(())
}

// ============================================================================
// Scenario: Pool Per-Destination Isolation
// ============================================================================

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
			let addr1 = servlet1.addr();
			let addr2 = servlet2.addr();

			trace.event(POOL_CREATE)?;

			let pool = Arc::new(
				ConnectionPool::<TokioListener>::builder()
					.with_trust_store(make_server_trust_store()?)
					.with_client_identity(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?
					.with_trace(trace.share())
					.build(),
			);

			for (addr, name) in [(addr1, "addr1-test"), (addr2, "addr2-test"), (addr1, "addr1-test2")] {
				trace.event(ACQUIRE_CLIENT)?;

				let mut client = pool.connect(addr).await?;

				trace.event(SEND_MESSAGE)?;

				let reply = client.conn()?.emit(create_v0_tightbeam(Some(name), None), None).await?;

				trace.event_with(RECEIVE_RESPONSE, &[], u64::from(reply.is_some()))?;
			}

			trace.event_with(SERVLET1_COUNT, &[], count1.load(Ordering::SeqCst) as u64)?;
			trace.event_with(SERVLET2_COUNT, &[], count2.load(Ordering::SeqCst) as u64)?;

			Ok(())
		}
	}
}

// ============================================================================
// Scenario: Concurrent Pool Access
// ============================================================================

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
			let server_addr = servlet.addr();

			trace.event(POOL_CREATE)?;

			let pool = Arc::new(
				ConnectionPool::<TokioListener>::builder()
					.with_trust_store(make_server_trust_store()?)
					.with_client_identity(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?
					.with_trace(trace.share())
					.build(),
			);

			for _ in 0..3 {
				trace.event(ACQUIRE_CLIENT)?;

				let mut client = pool.connect(server_addr).await?;

				trace.event(SEND_MESSAGE)?;

				let reply = client
					.conn()?
					.emit(create_v0_tightbeam(Some("concurrent-test"), None), None)
					.await?;

				trace.event_with(RECEIVE_RESPONSE, &[], u64::from(reply.is_some()))?;
			}

			trace.event_with(MESSAGE_COUNT, &[], message_count.load(Ordering::SeqCst) as u64)?;

			Ok(())
		}
	}
}
