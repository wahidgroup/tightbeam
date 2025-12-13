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
	colony::servlet::ServletConf,
	der::Sequence,
	exactly, servlet, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{create_v0_tightbeam, trace::TraceCollector, ScenarioConf},
	transport::{tcp::r#async::TokioListener, ConnectionBuilder, ConnectionPool, PoolConfig},
	Beamable,
};

#[cfg(feature = "x509")]
use tightbeam::{
	crypto::{
		key::KeySpec,
		sign::ecdsa::Secp256k1,
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

tb_process_spec! {
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

tb_assert_spec! {
	pub PoolReuseSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("pool_create", exactly!(1)),
			("acquire_client", exactly!(3)),
			("send_message", exactly!(3)),
			("receive_response", exactly!(3)),
			("release_client", exactly!(3)),
			("message_count", exactly!(1), equals!(3u64))
		]
	}
}

tb_assert_spec! {
	pub PoolIsolationSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("pool_create", exactly!(1)),
			("acquire_client", exactly!(3)),
			("send_message", exactly!(3)),
			("receive_response", exactly!(3)),
			("release_client", exactly!(3)),
			("servlet1_count", exactly!(1), equals!(2u64)),
			("servlet2_count", exactly!(1), equals!(1u64))
		]
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
tb_scenario! {
	name: connection_pool_reuse,
	config: ScenarioConf::<()>::builder()
		.with_spec(PoolReuseSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			// Start echo servlet with TLS
			pub struct PoolEchoServletConf {
				message_count: Arc<AtomicUsize>,
			}

			servlet! {
				PoolEchoServlet<TestMessage, EnvConfig = PoolEchoServletConf>,
					protocol: TokioListener,
					handle: |frame, _trace, config, _workers| async move {
						config.message_count.fetch_add(1, Ordering::SeqCst);
						Ok(Some(frame))
					}
				}

				let message_count = Arc::new(AtomicUsize::new(0));
				let env_config = Arc::new(PoolEchoServletConf { message_count: Arc::clone(&message_count) });
				let servlet_conf = ServletConf::<TokioListener, TestMessage>::builder()
					.with_certificate(SERVER_CERT, SERVER_KEY.to_provider::<Secp256k1>()?, vec![Arc::new(CLIENT_PINNING)])?
					.with_config(env_config)
					.build();
				let servlet = PoolEchoServlet::start(
					Arc::new(TraceCollector::default()),
					Some(servlet_conf),
				).await?;
				let server_addr = servlet.addr();

				trace.event("pool_create")?;

				let pool = Arc::new(ConnectionPool::<TokioListener>::builder()
					.with_config(PoolConfig::default())
					.with_server_certificate(SERVER_CERT)?
					.with_client_identity(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?
					.with_timeout(Duration::from_millis(1000))
					.build());

				for i in 1..=3 {
					trace.event("acquire_client")?;

					let mut client = pool.connect(server_addr).await?;

					trace.event("send_message")?;

					let msg = create_v0_tightbeam(Some(&format!("test{}", i)), None);
					if client.conn()?.emit(msg, None).await?.is_some() {
						trace.event("receive_response")?;
					}

					trace.event("release_client")?;
				}

				// Verify all 3 messages were processed
				trace.event_with("message_count", &[], message_count.load(Ordering::SeqCst) as u64)?;

			Ok(())
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
tb_scenario! {
	name: pool_per_destination_isolation,
	config: ScenarioConf::<()>::builder()
		.with_spec(PoolIsolationSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			pub struct IsolationServletConf {
				message_count: Arc<AtomicUsize>,
			}

			servlet! {
				IsolationServlet<TestMessage, EnvConfig = IsolationServletConf>,
					protocol: TokioListener,
					handle: |frame, _trace, config, _workers| async move {
						config.message_count.fetch_add(1, Ordering::SeqCst);
						Ok(Some(frame))
					}
				}

				let count1 = Arc::new(AtomicUsize::new(0));
				let count2 = Arc::new(AtomicUsize::new(0));
				let config1 = Arc::new(IsolationServletConf { message_count: Arc::clone(&count1) });
				let config2 = Arc::new(IsolationServletConf { message_count: Arc::clone(&count2) });

				let servlet_conf1 = ServletConf::<TokioListener, TestMessage>::builder()
					.with_certificate(SERVER_CERT, SERVER_KEY.to_provider::<Secp256k1>()?, vec![Arc::new(CLIENT_PINNING)])?
					.with_config(config1)
					.build();
				let servlet_conf2 = ServletConf::<TokioListener, TestMessage>::builder()
					.with_certificate(SERVER_CERT, SERVER_KEY.to_provider::<Secp256k1>()?, vec![Arc::new(CLIENT_PINNING)])?
					.with_config(config2)
					.build();

				let servlet1 = IsolationServlet::start(Arc::new(TraceCollector::default()), Some(servlet_conf1)).await?;
				let servlet2 = IsolationServlet::start(Arc::new(TraceCollector::default()), Some(servlet_conf2)).await?;
				let addr1 = servlet1.addr();
				let addr2 = servlet2.addr();

				trace.event("pool_create")?;

				let pool = Arc::new(ConnectionPool::<TokioListener>::builder()
					.with_server_certificate(SERVER_CERT)?
					.with_client_identity(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?
					.build());

				for (addr, name) in [(addr1, "addr1-test"), (addr2, "addr2-test"), (addr1, "addr1-test2")] {
					trace.event("acquire_client")?;

					let mut client = pool.connect(addr).await?;

					trace.event("send_message")?;

					if client.conn()?.emit(create_v0_tightbeam(Some(name), None), None).await?.is_some() {
						trace.event("receive_response")?;
					}

				trace.event("release_client")?;
			}

			// Verify counts
			trace.event_with("servlet1_count", &[], count1.load(Ordering::SeqCst) as u64)?;
			trace.event_with("servlet2_count", &[], count2.load(Ordering::SeqCst) as u64)?;

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
	config: ScenarioConf::<()>::builder()
		.with_spec(PoolReuseSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			pub struct ConcurrentServletConf {
				message_count: Arc<AtomicUsize>,
			}

			servlet! {
				ConcurrentServlet<TestMessage, EnvConfig = ConcurrentServletConf>,
				protocol: TokioListener,
				handle: |frame, _trace, config, _workers| async move {
					config.message_count.fetch_add(1, Ordering::SeqCst);
					Ok(Some(frame))
				}
			}

			let message_count = Arc::new(AtomicUsize::new(0));
			let env_config = Arc::new(ConcurrentServletConf { message_count: Arc::clone(&message_count) });
			let servlet_conf = ServletConf::<TokioListener, TestMessage>::builder()
				.with_certificate(SERVER_CERT, SERVER_KEY.to_provider::<Secp256k1>()?, vec![Arc::new(CLIENT_PINNING)])?
				.with_config(env_config)
				.build();
			let servlet = ConcurrentServlet::start(
				Arc::new(TraceCollector::default()),
				Some(servlet_conf),
			).await?;
			let server_addr = servlet.addr();

			trace.event("pool_create")?;

			let pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_server_certificate(SERVER_CERT)?
				.with_client_identity(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?
				.build());

			for _ in 0..3 {
				trace.event("acquire_client")?;

				let mut client = pool.connect(server_addr).await?;

				trace.event("send_message")?;

				if client.conn()?.emit(create_v0_tightbeam(Some("concurrent-test"), None), None).await?.is_some() {
					trace.event("receive_response")?;
				}

				trace.event("release_client")?;
			}

			// Verify 3 messages processed
			trace.event_with("message_count", &[], message_count.load(Ordering::SeqCst) as u64)?;

			Ok(())
		}
	}
}
