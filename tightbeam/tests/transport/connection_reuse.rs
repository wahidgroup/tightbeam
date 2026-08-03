//! Connection Keep-Alive and Reuse Tests
//!
//! Tests that a single client connection can send multiple messages
//! without reconnecting (connection keep-alive):
//! - Basic TCP connection reuse (no TLS)
//! - TLS connection reuse with session persistence

#![cfg(all(
	feature = "std",
	feature = "tcp",
	feature = "tokio",
	feature = "builder",
	feature = "testing",
	feature = "colony",
	feature = "hex"
))]

use std::sync::Arc;

use tightbeam::utils::urn::Urn;

pub(crate) const CLIENT_CONNECT: Urn<'static> = Urn::new("test", "event:connection-reuse/client-connect");
pub(crate) const RECEIVE_RESPONSE: Urn<'static> = Urn::new("test", "event:connection-reuse/receive-response");
pub(crate) const SEND_MESSAGE: Urn<'static> = Urn::new("test", "event:connection-reuse/send-message");

use tightbeam::{
	colony::servlet::ServletConfig,
	compose,
	der::Sequence,
	exactly, servlet, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::SetupEnv,
	transport::{tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder},
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
			policy::{CertificateValidation, PublicKeyPinning},
			store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder},
			Certificate, CertificateSpec,
		},
	},
	error::TightBeamError,
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
	pub ConnectionReuseProcess,
	events {
		observable { CLIENT_CONNECT, SEND_MESSAGE, RECEIVE_RESPONSE }
		hidden { }
	}
	states {
		Init => { CLIENT_CONNECT => Connected },
		Connected => { SEND_MESSAGE => Sent1 },
		Sent1 => { RECEIVE_RESPONSE => Received1 },
		Received1 => { SEND_MESSAGE => Sent2 },
		Sent2 => { RECEIVE_RESPONSE => Received2 },
		Received2 => { SEND_MESSAGE => Sent3 },
		Sent3 => { RECEIVE_RESPONSE => Complete }
	}
	terminal { Complete }
}

tb_assert_spec! {
	pub ConnectionReuseSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(CLIENT_CONNECT, exactly!(1)),
			(SEND_MESSAGE, exactly!(3)),
			(RECEIVE_RESPONSE, exactly!(3))
		]
	}
}

// ============================================================================
// Scenario: Basic TCP Connection Reuse (No TLS)
// ============================================================================

tb_scenario! {
	name: tcp_connection_reuse,
	spec: ConnectionReuseSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			// Start echo servlet
			servlet! {
				EchoServlet<TestMessage, EnvConfig = ()>,
				protocol: TokioListener,
				handle: |_msg, frame, _ctx| async move {
					Ok(Some(frame))
				}
			}

			let servlet_task = EchoServlet::start(Arc::new(trace.share()), None).await?;
			let addr = servlet_task.addr();

			trace.event(CLIENT_CONNECT)?;

			// Send 3 messages using the same client (connection keep-alive)
			let client_builder = ClientBuilder::<TokioListener>::builder().build();
			let mut client = client_builder.connect(addr).await?;
			for i in 1..=3 {
				trace.event(SEND_MESSAGE)?;

				let msg = compose! {
					V0: id: format!("msg{}", i).as_bytes(),
						message: TestMessage { content: format!("test{}", i) }
				}?;

				if client.emit(msg, None).await?.is_some() {
					trace.event(RECEIVE_RESPONSE)?;
				}
			}

			Ok(())
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
tb_scenario! {
	name: tls_connection_reuse,
	spec: ConnectionReuseSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			// Start TLS echo servlet
			servlet! {
				TlsEchoServlet<TestMessage, EnvConfig = ()>,
				protocol: TokioListener,
				handle: |_msg, frame, _ctx| async move {
					Ok(Some(frame))
				}
			}

			let key = SERVER_KEY.to_provider::<Secp256k1>()?;
			let validators = vec![Arc::new(CLIENT_PINNING) as Arc<dyn CertificateValidation>];
			let servlet_conf = ServletConfig::<TokioListener, TestMessage>::builder()
				.with_certificate(SERVER_CERT, key, validators)?
				.with_config(Arc::new(()))
				.build();

			let servlet_task = TlsEchoServlet::start(Arc::new(trace.share()), Some(servlet_conf)).await?;
			let addr = servlet_task.addr();

			trace.event(CLIENT_CONNECT)?;

			// Configure client with TLS credentials
			let key = CLIENT_KEY.to_provider::<Secp256k1>()?;
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(make_server_trust_store()?)
				.with_client_identity(CLIENT_CERT, key)?
				.build();
			let mut client = builder.connect(addr).await?;

			// Send 3 messages using the same TLS client (no re-handshake, session reuse)
			for i in 1..=3 {
				trace.event(SEND_MESSAGE)?;

				let msg = compose! {
					V0: id: format!("tls-msg{}", i).as_bytes(),
						message: TestMessage { content: format!("test{}", i) }
				}?;

				if client.emit(msg, None).await?.is_some() {
					trace.event(RECEIVE_RESPONSE)?;
				}
			}

			Ok(())
		}
	}
}
