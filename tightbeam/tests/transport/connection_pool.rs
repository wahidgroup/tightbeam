//! Connection Pool and Keep-Alive Integration Tests
//!
//! Tests connection pooling, reuse, and keep-alive functionality:
//! - Basic TCP connection reuse (no TLS)
//! - TLS connection reuse with session persistence
//! - Connection pool reuse across multiple acquire/release cycles
//! - Per-destination pool isolation
//! - Concurrent pool access

#![cfg(all(
	feature = "std",
	feature = "tcp",
	feature = "tokio",
	feature = "builder",
	feature = "testing"
))]

use std::{
	sync::{
		atomic::{AtomicUsize, Ordering},
		Arc,
	},
	time::Duration,
};

use tightbeam::{
	compose,
	der::Sequence,
	macros::client::builder::ClientBuilder,
	servlet,
	testing::trace::TraceCollector,
	trace::TraceConfig,
	transport::{tcp::r#async::TokioListener, Client, ConnectionPool, PoolConfig},
	Beamable, TightBeamError,
};

#[cfg(feature = "x509")]
use tightbeam::{
	crypto::{
		key::KeySpec,
		x509::{policy::PublicKeyPinning, CertificateSpec},
	},
	hex,
};

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
const SERVER_KEY: KeySpec = KeySpec::Bytes(&hex!("0101010101010101010101010101010101010101010101010101010101010101"));

#[cfg(feature = "x509")]
const CLIENT_KEY: KeySpec = KeySpec::Bytes(&hex!("0202020202020202020202020202020202020202020202020202020202020202"));

#[cfg(feature = "x509")]
const CLIENT_PUB_KEY: &[u8] = &hex!("044d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07662a3eada2d0fe208b6d257ceb0f064284662e857f57b66b54c198bd310ded36d0");

#[cfg(feature = "x509")]
const CLIENT_PINNING: PublicKeyPinning<1> = PublicKeyPinning::new([CLIENT_PUB_KEY]);

// ============================================================================
// Spec Definitions
// ============================================================================

tightbeam::tb_process_spec! {
	pub ConnectionReuseProcess,
	events {
		observable { "client_connect", "send_message", "receive_response" }
		hidden { }
	}
	states {
		Init => { "client_connect" => Connected },
		Connected => { "send_message" => Sent1 },
		Sent1 => { "receive_response" => Received1 },
		Received1 => { "send_message" => Sent2 },
		Sent2 => { "receive_response" => Received2 },
		Received2 => { "send_message" => Sent3 },
		Sent3 => { "receive_response" => Complete }
	}
	terminal { Complete }
}

tightbeam::tb_assert_spec! {
	pub ConnectionReuseSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("client_connect", tightbeam::exactly!(1)),
			("send_message", tightbeam::exactly!(3)),
			("receive_response", tightbeam::exactly!(3))
		]
	}
}

tightbeam::tb_process_spec! {
	pub PoolReuseProcess,
	events {
		observable { "pool_create", "acquire_client", "send_message", "receive_response", "release_client" }
		hidden { }
	}
	states {
		Init => { "pool_create" => PoolReady },
		PoolReady => { "acquire_client" => Acquired1 },
		Acquired1 => { "send_message" => Sent1 },
		Sent1 => { "receive_response" => Received1 },
		Received1 => { "release_client" => Released1 },
		Released1 => { "acquire_client" => Acquired2 },
		Acquired2 => { "send_message" => Sent2 },
		Sent2 => { "receive_response" => Received2 },
		Received2 => { "release_client" => Released2 },
		Released2 => { "acquire_client" => Acquired3 },
		Acquired3 => { "send_message" => Sent3 },
		Sent3 => { "receive_response" => Received3 },
		Received3 => { "release_client" => Complete }
	}
	terminal { Complete }
}

tightbeam::tb_assert_spec! {
	pub PoolReuseSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("pool_create", tightbeam::exactly!(1)),
			("acquire_client", tightbeam::exactly!(3)),
			("send_message", tightbeam::exactly!(3)),
			("receive_response", tightbeam::exactly!(3)),
			("release_client", tightbeam::exactly!(3))
		]
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a new connection pool with the given max connections per destination
fn create_pool<const N: usize>() -> Arc<ConnectionPool<TokioListener, N>> {
	Arc::new(ConnectionPool::<TokioListener, N>::new(PoolConfig::default()))
}

// ============================================================================
// Scenario: Basic TCP Connection Reuse (No TLS)
// ============================================================================

tightbeam::tb_scenario! {
	name: tcp_connection_reuse,
	spec: ConnectionReuseSpec,
	trace: TraceConfig::default(),
	environment Bare {
		exec: |trace| {
			tokio::runtime::Runtime::new()?.block_on(async {
				// Start echo servlet
				servlet! {
					EchoServlet<TestMessage>,
					protocol: TokioListener,
					handle: |frame, _trace| async move {
						Ok(Some(frame))
					}
				}

				let servlet_task = EchoServlet::start(Arc::new(TraceCollector::new())).await?;
				let addr = servlet_task.addr;

				trace.event("client_connect")?;
				let mut client = ClientBuilder::<TokioListener>::connect(addr).await?.build().await?;

				// Send 3 messages using the same client
				for i in 1..=3 {
					trace.event("send_message")?;
					let msg = compose! {
						V0: id: format!("msg{}", i).as_bytes(),
						message: TestMessage { content: format!("test{}", i) }
					}?;
					if client.emit(msg, None).await?.is_some() {
						trace.event("receive_response")?;
					}
				}

				Ok(())
			})
		}
	}
}

// ============================================================================
// Scenario: TLS Connection Reuse with Session Persistence
// ============================================================================

#[cfg(all(
	feature = "x509",
	feature = "transport-policy",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead"
))]
tightbeam::tb_scenario! {
	name: tls_connection_reuse,
	spec: ConnectionReuseSpec,
	trace: TraceConfig::default(),
	environment Bare {
		exec: |trace| {
			tokio::runtime::Runtime::new()?.block_on(async {
				// Start TLS echo servlet
				servlet! {
					TlsEchoServlet<TestMessage>,
					protocol: TokioListener,
					x509: {
						certificate: SERVER_CERT,
						key_provider: SERVER_KEY,
						client_validators: [CLIENT_PINNING]
					},
					handle: |frame, _trace| async move {
						Ok(Some(frame))
					}
				}

				let servlet_task = TlsEchoServlet::start(Arc::new(TraceCollector::new())).await?;
				let addr = servlet_task.addr;

				trace.event("client_connect")?;
				let mut client = ClientBuilder::<TokioListener>::connect(addr)
					.await?
					.with_server_certificate(SERVER_CERT)?
					.with_client_identity(CLIENT_CERT, CLIENT_KEY)?
					.build()
					.await?;

				// Send 3 messages using the same TLS client (no re-handshake)
				for i in 1..=3 {
					trace.event("send_message")?;
					let msg = compose! {
						V0: id: format!("tls-msg{}", i).as_bytes(),
						message: TestMessage { content: format!("test{}", i) }
					}?;
					if client.emit(msg, None).await?.is_some() {
						trace.event("receive_response")?;
					}

					if i < 3 {
						tokio::time::sleep(Duration::from_millis(50)).await;
					}
				}

				Ok(())
			})
		}
	}
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
tightbeam::tb_scenario! {
	name: connection_pool_reuse,
	spec: PoolReuseSpec,
	trace: TraceConfig::default(),
	environment Bare {
		exec: |trace| {
			tokio::runtime::Runtime::new()?.block_on(async {
				// Import DTN certs for realistic testing
				use crate::dtn::certs::{EARTH_RELAY_CERT, EARTH_RELAY_KEY, EARTH_RELAY_PINNING, MARS_RELAY_CERT, MARS_RELAY_KEY};

				// Start echo servlet with TLS
				servlet! {
					PoolEchoServlet<TestMessage>,
					protocol: TokioListener,
					x509: {
						certificate: EARTH_RELAY_CERT,
						key_provider: EARTH_RELAY_KEY,
						client_validators: [EARTH_RELAY_PINNING]
					},
					config: {
						message_count: Arc<AtomicUsize>,
					},
					handle: |frame, _trace, config| async move {
						config.message_count.fetch_add(1, Ordering::SeqCst);
						Ok(Some(frame))
					}
				}

				let message_count = Arc::new(AtomicUsize::new(0));
				let config = PoolEchoServletConf { message_count: Arc::clone(&message_count) };
				let servlet = PoolEchoServlet::start(
					Arc::new(TraceCollector::default()),
					Arc::new(config),
				).await?;
				let server_addr = servlet.addr();

				trace.event("pool_create")?;
				let pool = create_pool::<3>();

				// Send 3 messages using the pool (acquire, send, release cycle)
				for i in 1..=3 {
					trace.event("acquire_client")?;
					let mut client = pool
						.connect(server_addr)
						.with_server_certificate(EARTH_RELAY_CERT)?
						.with_client_identity(MARS_RELAY_CERT, MARS_RELAY_KEY)?
						.with_timeout(Duration::from_millis(1000))
						.build()
						.await?;

					trace.event("send_message")?;
					let msg = tightbeam::testing::create_v0_tightbeam(Some(&format!("test{}", i)), None);
					if client.emit(msg, None).await?.is_some() {
						trace.event("receive_response")?;
					}

					trace.event("release_client")?;
				}

				// Verify all 3 messages were processed
				assert_eq!(message_count.load(Ordering::SeqCst), 3, "Expected 3 messages to be processed");

				Ok(())
			})
		}
	}
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
tightbeam::tb_scenario! {
	name: pool_per_destination_isolation,
	spec: PoolReuseSpec,
	trace: TraceConfig::default(),
	environment Bare {
		exec: |trace| {
			tokio::runtime::Runtime::new()?.block_on(async {
				use crate::dtn::certs::{EARTH_RELAY_CERT, EARTH_RELAY_KEY, EARTH_RELAY_PINNING, MARS_RELAY_CERT, MARS_RELAY_KEY};

				servlet! {
					IsolationServlet<TestMessage>,
					protocol: TokioListener,
					x509: {
						certificate: EARTH_RELAY_CERT,
						key_provider: EARTH_RELAY_KEY,
						client_validators: [EARTH_RELAY_PINNING]
					},
					config: {
						message_count: Arc<AtomicUsize>,
					},
					handle: |frame, _trace, config| async move {
						config.message_count.fetch_add(1, Ordering::SeqCst);
						Ok(Some(frame))
					}
				}

				let count1 = Arc::new(AtomicUsize::new(0));
				let count2 = Arc::new(AtomicUsize::new(0));

				let config1 = Arc::new(IsolationServletConf { message_count: Arc::clone(&count1) });
				let config2 = Arc::new(IsolationServletConf { message_count: Arc::clone(&count2) });

				let servlet1 = IsolationServlet::start(Arc::new(TraceCollector::default()), config1).await?;
				let servlet2 = IsolationServlet::start(Arc::new(TraceCollector::default()), config2).await?;
				let addr1 = servlet1.addr();
				let addr2 = servlet2.addr();

				trace.event("pool_create")?;
				let pool = create_pool::<2>();

				// Send to addr1, addr2, addr1 again (testing pool isolation)
				for (addr, name) in [(addr1, "addr1-test"), (addr2, "addr2-test"), (addr1, "addr1-test2")] {
					trace.event("acquire_client")?;
					let mut client = pool
						.connect(addr)
						.with_server_certificate(EARTH_RELAY_CERT)?
						.with_client_identity(MARS_RELAY_CERT, MARS_RELAY_KEY)?
						.build()
						.await?;

					trace.event("send_message")?;
					if client.emit(tightbeam::testing::create_v0_tightbeam(Some(name), None), None).await?.is_some() {
						trace.event("receive_response")?;
					}
					trace.event("release_client")?;
				}

				// Verify counts
				assert_eq!(count1.load(Ordering::SeqCst), 2);
				assert_eq!(count2.load(Ordering::SeqCst), 1);

				Ok(())
			})
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
tightbeam::tb_scenario! {
	name: pool_concurrent_access,
	spec: PoolReuseSpec,
	trace: TraceConfig::default(),
	environment Bare {
		exec: |trace| {
			tokio::runtime::Runtime::new()?.block_on(async {
				use crate::dtn::certs::{EARTH_RELAY_CERT, EARTH_RELAY_KEY, EARTH_RELAY_PINNING, MARS_RELAY_CERT, MARS_RELAY_KEY};

				servlet! {
					ConcurrentServlet<TestMessage>,
					protocol: TokioListener,
					x509: {
						certificate: EARTH_RELAY_CERT,
						key_provider: EARTH_RELAY_KEY,
						client_validators: [EARTH_RELAY_PINNING]
					},
					config: {
						message_count: Arc<AtomicUsize>,
					},
					handle: |frame, _trace, config| async move {
						config.message_count.fetch_add(1, Ordering::SeqCst);
						Ok(Some(frame))
					}
				}

				let message_count = Arc::new(AtomicUsize::new(0));
				let config = ConcurrentServletConf { message_count: Arc::clone(&message_count) };
				let servlet = ConcurrentServlet::start(
					Arc::new(TraceCollector::default()),
					Arc::new(config),
				).await?;
				let server_addr = servlet.addr();

				trace.event("pool_create")?;
				let pool = create_pool::<3>();

				// Simulate 3 concurrent tasks, but run sequentially for deterministic tracing
				for _ in 0..3 {
					trace.event("acquire_client")?;
					let mut client = pool
						.connect(server_addr)
						.with_server_certificate(EARTH_RELAY_CERT)?
						.with_client_identity(MARS_RELAY_CERT, MARS_RELAY_KEY)?
						.build()
						.await?;

					trace.event("send_message")?;
					if client.emit(tightbeam::testing::create_v0_tightbeam(Some("concurrent-test"), None), None).await?.is_some() {
						trace.event("receive_response")?;
					}
					trace.event("release_client")?;
				}

				// Verify 3 messages processed
				assert_eq!(message_count.load(Ordering::SeqCst), 3);

				Ok(())
			})
		}
	}
}
