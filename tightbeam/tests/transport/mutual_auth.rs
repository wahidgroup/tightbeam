//! Integration test of mutual authentication.
//!
//! The test runs end-to-end mutual authentication with X.509 certificates.

#![cfg(all(
	feature = "x509",
	feature = "std",
	feature = "transport-policy",
	feature = "tcp",
	feature = "tokio",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead",
	feature = "builder",
	feature = "colony",
	feature = "hex"
))]

use std::sync::Arc;

use crate::common::static_pair::{client_pinning, CLIENT_CERT, CLIENT_KEY, SERVER_CERT, SERVER_KEY};
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::{
	colony::servlet::ServletConfig,
	compose,
	crypto::{
		policy::Secp256k1Policy,
		sign::ecdsa::Secp256k1,
		x509::{
			policy::CertificateValidation,
			store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder},
			Certificate, CertificateSpec, KeyCurves,
		},
	},
	exactly,
	instrumentation::events,
	prelude::*,
	servlet, tb_assert_spec, tb_scenario,
	trace::TraceCollector,
	transport::{tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder, MessageEmitter},
	Beamable,
};

// Every scenario trusts the server certificate through this store.

fn make_server_trust_store() -> Result<Arc<dyn CertificateTrust>, TightBeamError> {
	let server_cert = Certificate::try_from(SERVER_CERT)?;
	Ok(Arc::new(
		CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation)
			.with_certificate(server_cert)?
			.build(),
	))
}

// The client and the servlet exchange these message types.

#[derive(Clone, Debug, PartialEq, Beamable, Sequence)]
struct AuthRequest {
	client_id: String,
}

#[derive(Clone, Debug, PartialEq, Beamable, Sequence)]
struct AuthResponse {
	server_id: String,
	authenticated: bool,
}

// This servlet runs mutual authentication with X.509 certificates.

servlet! {
	pub MutualAuthServlet<AuthRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |request, frame, _ctx| async move {
		let response = AuthResponse {
			server_id: "mutual-auth-server".to_string(),
			authenticated: request.client_id == "test-client-mutual-001",
		};

		let response_frame = compose! {
			V0: id: frame.metadata().id(),
			message: response
		}?;

		Ok(Some(response_frame))
	}
}

// The positive scenario authenticates both ends and exchanges one request.

// The servlet admits the pinned client and completes the handshake. The
// servlet alone records into the scenario trace, so each event is its own.
tb_assert_spec! {
	MutualAuthSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(1)),
			(events::SESSION_CERT_REJECTED, exactly!(0))
		]
	}
}

tb_scenario! {
	name: test_mutual_auth_with_servlet,
	spec: MutualAuthSpec,
	environment Servlet {
		start: |env| async move {
			let trace = Arc::new(env.trace);
			let key = SERVER_KEY.to_provider::<Secp256k1>()?;
			let validators = vec![Arc::new(client_pinning()) as Arc<dyn CertificateValidation>];
			let servlet_conf = ServletConfig::<TokioListener, AuthRequest>::builder()
				.with_certificate(SERVER_CERT, key, validators)?
				.with_config(Arc::new(()))
				.build();

			MutualAuthServlet::start(Arc::clone(&trace), servlet_conf).await
		},
		setup: |env| async move {
			let key = CLIENT_KEY.to_provider::<Secp256k1>()?;
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(make_server_trust_store()?)
				.with_client_identity(SigningIdentity::from_spec(CLIENT_CERT, key)?)
				.build();

			let client = builder.connect(env.addr).await?;
			Ok(client)
		},
		client: |env| async move {
			let mut client = env.client;
			let request = AuthRequest {
				client_id: "test-client-mutual-001".to_string(),
			};

			let request_frame = compose! {
				V0: id: b"mutual-auth-req-001",
				message: request
			}?;

			let response_frame: Option<Frame> = client.emit(request_frame, None).await?;
			let response_frame = response_frame.ok_or(TightBeamError::MissingResponse)?;
			let response: AuthResponse = response_frame.decode_message()?;
			assert_eq!(response.server_id, "mutual-auth-server", "the reply must name the servlet");
			assert!(response.authenticated, "the servlet must accept the client id");
			Ok(())
		}
	}
}

/// Drives the lazy encryption handshake to a verdict and returns whether it
/// refused. `connect` only dials, so a certificate rejection shows on the
/// first exchange. The probe is a well-formed request, so a decode failure
/// cannot pass as a handshake refusal. The client transport carries the
/// scenario collector, which records the client's handshake verdicts.
async fn handshake_rejected(
	builder: ClientBuilder<TokioListener>,
	addr: TightBeamSocketAddr,
	trace: &TraceCollector,
) -> Result<bool, TightBeamError> {
	let request = AuthRequest { client_id: "handshake-probe".to_string() };
	let request_frame = compose! {
		V0: id: b"mutual-auth-neg-probe",
		message: request
	}?;

	let Ok(client) = builder.connect(addr).await else {
		return Ok(true);
	};

	let mut transport = client.into_transport().with_trace(trace.share());
	let result = transport.emit(request_frame, None).await;
	Ok(result.is_err())
}

// Negative test A: the server refuses an invalid client certificate. The
// servlet's pinning validator records the refusal. The HPKE client completes
// when it sends the closing, and records that completion.
tb_assert_spec! {
	pub InvalidClientSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("certificate/public-key-not-pinned")),
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(1))
		]
	}
}

tb_scenario! {
	name: test_invalid_client_cert,
	spec: InvalidClientSpec,
	environment Servlet {
		start: |env| async move {
			let trace = Arc::new(env.trace);
			let key = SERVER_KEY.to_provider::<Secp256k1>()?;
			let validators = vec![Arc::new(client_pinning()) as Arc<dyn CertificateValidation>];
			let servlet_conf = ServletConfig::<TokioListener, AuthRequest>::builder()
				.with_certificate(SERVER_CERT, key, validators)?
				.with_config(Arc::new(()))
				.build();

			MutualAuthServlet::start(Arc::clone(&trace), servlet_conf).await
		},
		setup: |env| async move {
			use tightbeam::crypto::key::Secp256k1KeyProvider;
			use tightbeam::testing::fixtures::{TestKey, TestCertificate};

			// The client identity sits outside the server's pin set. Its
			// certificate and signing provider share one key, so the rejection
			// is the pin check and not a key/certificate mismatch.
			let invalid_key = TestKey::insecure_fixed_signing();
			let invalid_cert = TestCertificate::self_signed(&invalid_key);

			let certificate = CertificateSpec::Built(Box::new(invalid_cert));
			let provider = Arc::new(Secp256k1KeyProvider::from(invalid_key));
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(make_server_trust_store()?)
				.with_client_identity(SigningIdentity::from_spec(certificate, provider)?)
				.build();

			let rejected = handshake_rejected(builder, env.addr, &env.trace).await?;
			assert!(rejected, "the pinning server must refuse the client identity");
			Ok(())
		},
		client: |_env| async move {
			Ok(())
		}
	}
}

// Negative test B: the client refuses an invalid server certificate. The
// client transport carries the scenario collector, and the servlet reads the
// close outside its handshake, so the one refusal on the trail is the client's.
tb_assert_spec! {
	pub InvalidServerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("certificate/certificate-not-trusted"))
		]
	}
}

tb_scenario! {
	name: test_invalid_server_cert,
	spec: InvalidServerSpec,
	environment Servlet {
		start: |env| async move {
			let trace = Arc::new(env.trace);
			use tightbeam::crypto::key::Secp256k1KeyProvider;
			use tightbeam::testing::fixtures::{TestKey, TestCertificate};

			// The server certificate sits outside the client's trust store. Its
			// certificate and signing provider share one key, so the rejection
			// is the trust check and not a key/certificate mismatch.
			let invalid_server_key = TestKey::insecure_fixed_signing();
			let invalid_server_cert = TestCertificate::self_signed(&invalid_server_key);

			let certificate = CertificateSpec::Built(Box::new(invalid_server_cert));
			let provider = Arc::new(Secp256k1KeyProvider::from(invalid_server_key));
			let validators = vec![Arc::new(client_pinning()) as Arc<dyn CertificateValidation>];
			let servlet_conf = ServletConfig::<TokioListener, AuthRequest>::builder()
				.with_certificate(certificate, provider, validators)?
				.with_config(Arc::new(()))
				.build();

			MutualAuthServlet::start(Arc::clone(&trace), servlet_conf).await
		},
		setup: |env| async move {
			// The client trusts only SERVER_CERT. The presented certificate
			// differs, so the client-side validation must refuse it.
			let key = CLIENT_KEY.to_provider::<Secp256k1>()?;
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(make_server_trust_store()?)
				.with_client_identity(SigningIdentity::from_spec(CLIENT_CERT, key)?)
				.build();

			let rejected = handshake_rejected(builder, env.addr, &env.trace).await?;
			assert!(rejected, "the client must refuse the untrusted server certificate");
			Ok(())
		},
		client: |_env| async move {
			Ok(())
		}
	}
}
