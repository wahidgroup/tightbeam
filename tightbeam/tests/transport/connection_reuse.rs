//! The tests of connection keep-alive and reuse.
//!
//! Each test checks that one client connection sends three messages without a
//! reconnect (connection keep-alive), in two cases:
//! - the reuse of a cleartext TCP connection, and
//! - the reuse of a TLS connection, whose one session carries all three.

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

use std::sync::Arc;

use tightbeam::crypto::sign::SigningIdentity;

use tightbeam::{
	colony::servlet::ServletConfig,
	compose,
	der::Sequence,
	exactly,
	instrumentation::events,
	servlet, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{macros::BuiltAssertSpec, ScenarioConfig, ScenarioConfigError, SetupEnv},
	transport::{tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder},
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

// The tests exchange this message type.

#[derive(Clone, Debug, PartialEq, Beamable, Sequence)]
struct TestMessage {
	content: String,
}

// The TLS scenario trusts the server certificate through this store.

#[cfg(feature = "x509")]
fn make_server_trust_store() -> Result<Arc<dyn CertificateTrust>, TightBeamError> {
	let server_cert = Certificate::try_from(SERVER_CERT)?;
	Ok(Arc::new(
		CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(server_cert)?
			.build(),
	))
}

// These specs state the event contract of both scenarios.

// The servlet accepts one connection, and its gate then admits the three
// messages on that same connection.
tb_process_spec! {
	pub ConnectionReuseProcess,
	events {
		observable { events::CONNECTION_ACCEPTED, events::GATE_ACCEPT }
		hidden { }
	}
	states {
		Init => { events::CONNECTION_ACCEPTED => Connected },
		Connected => { events::GATE_ACCEPT => Served1 },
		Served1 => { events::GATE_ACCEPT => Served2 },
		Served2 => { events::GATE_ACCEPT => Complete }
	}
	terminal { Complete }
}

tb_assert_spec! {
	pub ConnectionReuseSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CONNECTION_ACCEPTED, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(3))
		]
	}
}

tb_assert_spec! {
	pub TlsConnectionReuseSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CONNECTION_ACCEPTED, exactly!(1)),
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(3))
		]
	}
}

/// The message whose id is `prefix` and `index`, and whose content is `test`
/// and `index`.
fn numbered(prefix: &str, index: usize) -> Result<tightbeam::Frame, tightbeam::TightBeamError> {
	compose! {
		V0: id: format!("{prefix}{index}").as_bytes(),
			message: TestMessage { content: format!("test{index}") }
	}
}

/// Grades `spec`, and orders the accept and gate events by
/// `ConnectionReuseProcess` in a build with `testing-csp`.
fn connection_reuse_config(spec: &'static BuiltAssertSpec) -> Result<ScenarioConfig, ScenarioConfigError> {
	let builder = ScenarioConfig::builder().with_spec(spec);
	#[cfg(feature = "testing-csp")]
	let builder = builder.with_csp(ConnectionReuseProcess);
	builder.build()
}

// Scenario: one cleartext TCP connection carries three messages.

tb_scenario! {
	name: tcp_connection_reuse,
	config: connection_reuse_config(ConnectionReuseSpec::latest()),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			// The echo servlet answers each frame with itself.
			servlet! {
				EchoServlet<TestMessage, EnvConfig = ()>,
				protocol: TokioListener,
				handle: |_msg, frame, _ctx| async move {
					Ok(Some(frame))
				}
			}

			let servlet_task = EchoServlet::start(Arc::new(trace.share()), ServletConfig::cleartext()).await?;
			let addr = servlet_task.addr().to_owned();
			// One client sends all three messages over its one connection.
			let client_builder = ClientBuilder::<TokioListener>::builder().allow_cleartext().build();
			let mut client = client_builder.connect(addr).await?;

			let first = client.emit(numbered("msg", 1)?, None).await?;
			let second = client.emit(numbered("msg", 2)?, None).await?;
			let third = client.emit(numbered("msg", 3)?, None).await?;
			assert!(first.is_some(), "message 1 must draw its echo on the kept connection");
			assert!(second.is_some(), "message 2 must draw its echo on the kept connection");
			assert!(third.is_some(), "message 3 must draw its echo on the kept connection");
			Ok(())
		}
	}
}

// Scenario: one TLS connection carries three messages in one session.

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
	config: connection_reuse_config(TlsConnectionReuseSpec::latest()),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			// The TLS echo servlet answers each frame with itself.
			servlet! {
				TlsEchoServlet<TestMessage, EnvConfig = ()>,
				protocol: TokioListener,
				handle: |_msg, frame, _ctx| async move {
					Ok(Some(frame))
				}
			}

			let key = SERVER_KEY.to_provider::<Secp256k1>()?;
			let validators = vec![Arc::new(client_pinning()) as Arc<dyn CertificateValidation>];
			let servlet_conf = ServletConfig::<TokioListener, TestMessage>::builder()
				.with_certificate(SERVER_CERT, key, validators)?
				.with_config(Arc::new(()))
				.build();

			let servlet_task = TlsEchoServlet::start(Arc::new(trace.share()), servlet_conf).await?;
			let addr = servlet_task.addr().to_owned();

			// The client presents its own certificate and trusts the server's.
			let key = CLIENT_KEY.to_provider::<Secp256k1>()?;
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(make_server_trust_store()?)
				.with_client_identity(SigningIdentity::from_spec(CLIENT_CERT, key)?)
				.build();

			// One TLS client sends all three messages after one handshake.
			let mut client = builder.connect(addr).await?;

			let first = client.emit(numbered("tls-msg", 1)?, None).await?;
			let second = client.emit(numbered("tls-msg", 2)?, None).await?;
			let third = client.emit(numbered("tls-msg", 3)?, None).await?;
			assert!(first.is_some(), "message 1 must draw its echo on the kept session");
			assert!(second.is_some(), "message 2 must draw its echo on the kept session");
			assert!(third.is_some(), "message 3 must draw its echo on the kept session");
			Ok(())
		}
	}
}
