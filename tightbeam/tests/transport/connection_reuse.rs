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

use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::urn::Urn;

pub(crate) const CLIENT_CONNECT: Urn<'static> = tightbeam::urn!("test", "event:connection-reuse/client-connect");
pub(crate) const RECEIVE_RESPONSE: Urn<'static> = tightbeam::urn!("test", "event:connection-reuse/receive-response");
pub(crate) const SEND_MESSAGE: Urn<'static> = tightbeam::urn!("test", "event:connection-reuse/send-message");

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
use crate::common::static_pair::{CLIENT_CERT, CLIENT_KEY, CLIENT_PINNING, SERVER_CERT, SERVER_KEY};
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

// ============================================================================
// Test Message Types
// ============================================================================

#[derive(Clone, Debug, PartialEq, Beamable, Sequence)]
struct TestMessage {
	content: String,
}

// ============================================================================
// Test Helpers
// ============================================================================

#[cfg(feature = "x509")]
fn make_server_trust_store() -> Result<Arc<dyn CertificateTrust>, TightBeamError> {
	let server_cert = Certificate::try_from(SERVER_CERT)?;
	Ok(Arc::new(
		CertificateTrustBuilder::from(Secp256k1Policy::default())
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

			let servlet_task = EchoServlet::start(Arc::new(trace.share()), ServletConfig::cleartext()).await?;
			let addr = servlet_task.addr().to_owned();

			trace.event(CLIENT_CONNECT)?;

			// Send 3 messages using the same client (connection keep-alive)
			let client_builder = ClientBuilder::<TokioListener>::builder().allow_cleartext().build();
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

			let servlet_task = TlsEchoServlet::start(Arc::new(trace.share()), servlet_conf).await?;
			let addr = servlet_task.addr().to_owned();

			trace.event(CLIENT_CONNECT)?;

			// Configure client with TLS credentials
			let key = CLIENT_KEY.to_provider::<Secp256k1>()?;
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(make_server_trust_store()?)
				.with_client_identity(SigningIdentity::from_spec(CLIENT_CERT, key)?)
				.build();

			// Send 3 messages using the same TLS client
			// (no re-handshake, session reuse)
			let mut client = builder.connect(addr).await?;
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
