//! Mutual Authentication Integration Test
//!
//! Tests end-to-end mutual authentication using X.509 certificates

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

use tightbeam::utils::urn::Urn;

pub(crate) const AUTHENTICATED: Urn<'static> = Urn::new("test", "event:mutual-auth/authenticated");
pub(crate) const RESPONSE_RECEIVED: Urn<'static> = Urn::new("test", "event:mutual-auth/response-received");
pub(crate) const SERVER_ID: Urn<'static> = Urn::new("test", "event:mutual-auth/server-id");
pub(crate) const CLIENT_CERT_REJECTED: Urn<'static> = Urn::new("test", "event:mutual-auth/client-cert-rejected");
pub(crate) const SERVER_CERT_REJECTED: Urn<'static> = Urn::new("test", "event:mutual-auth/server-cert-rejected");
use tightbeam::{
	at_least,
	colony::servlet::ServletConfig,
	compose,
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
	decode, exactly, hex,
	instrumentation::events,
	prelude::*,
	servlet, tb_assert_spec, tb_scenario,
	testing::{assertions::Presence, macros::IsSome},
	trace::TraceCollector,
	transport::{tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder, MessageEmitter},
	Beamable,
};

// ============================================================================
// Static X.509 Configuration
// ============================================================================

const SERVER_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"
    -----BEGIN CERTIFICATE-----
    MIIBajCCAQ+gAwIBAgIBATALBglghkgBZQMEAwowHTEbMBkGA1UEAwwSU3RhdGlj
    IFRlc3QgU2VydmVyMB4XDTI1MTEyMTIyMDkxMVoXDTM1MTExOTIyMDkxMVowHTEb
    MBkGA1UEAwwSU3RhdGljIFRlc3QgU2VydmVyMFYwEAYHKoZIzj0CAQYFK4EEAAoD
    QgAEG4TFVnsSZECZXT7VqroFZdceGDRgSBn/nBf16dXdB49wvq+PWItUFQf+1qZC
    xatC39+BIKf2Od5RItR6aajo0aNCMEAwHQYDVR0OBBYEFEOubLl6za81S4KG3bKb
    SSyV6VhwMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAsGCWCGSAFl
    AwQDCgNIADBFAiEA2aChCQdJ1LI46IWMds2yNoOG8Pq4nYqbEgETdIR+vnQCID7U
    88OyM9q8+mrRAHYOyG7zYxKaxeWQTpwQVoVgCjs+
    -----END CERTIFICATE-----
"#,
);

const CLIENT_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"
    -----BEGIN CERTIFICATE-----
    MIIBajCCAQ+gAwIBAgIBATALBglghkgBZQMEAwowHTEbMBkGA1UEAwwSU3RhdGlj
    IFRlc3QgQ2xpZW50MB4XDTI1MTEyMTIyMDkxMVoXDTM1MTExOTIyMDkxMVowHTEb
    MBkGA1UEAwwSU3RhdGljIFRlc3QgQ2xpZW50MFYwEAYHKoZIzj0CAQYFK4EEAAoD
    QgAETUts0TYQMsqb0q652QCqTUXZ6tgKyUIzdMRRpyVNB2YqPq2i0P4gi20lfOsP
    BkKEZi6Ff1e2a1TBmL0xDe020KNCMEAwHQYDVR0OBBYEFKPczeMV5zGTz6VPSCJD
    QZFgb0XEMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAsGCWCGSAFl
    AwQDCgNIADBFAiEA0HI5WVq8ch27rQx7SO+hGwsQGLGHHvc34pfa7MQ3R4kCICJP
    7O7AR01io0/m4Hez90niWi1m+zeJS00hvuznD/Hp
    -----END CERTIFICATE-----
"#,
);

const SERVER_KEY: SigningKeySpec =
	SigningKeySpec::Bytes(&hex!("0101010101010101010101010101010101010101010101010101010101010101"));
const CLIENT_KEY: SigningKeySpec =
	SigningKeySpec::Bytes(&hex!("0202020202020202020202020202020202020202020202020202020202020202"));

// Client public key for server-side validation
const CLIENT_PUB_KEY: &[u8] = &hex!("044d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07662a3eada2d0fe208b6d257ceb0f064284662e857f57b66b54c198bd310ded36d0");
// Server-side pinning: validate incoming client certificates
const CLIENT_PINNING: PublicKeyPinning<1> = PublicKeyPinning::new([CLIENT_PUB_KEY]);

// ============================================================================
// Test Helpers
// ============================================================================

fn make_server_trust_store() -> Result<Arc<dyn CertificateTrust>, TightBeamError> {
	let server_cert = Certificate::try_from(SERVER_CERT)?;
	Ok(Arc::new(
		CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
			.with_certificate(server_cert)?
			.build(),
	))
}

// ============================================================================
// Message Types
// ============================================================================

#[derive(Clone, Debug, PartialEq, Beamable, Sequence)]
struct AuthRequest {
	client_id: String,
}

#[derive(Clone, Debug, PartialEq, Beamable, Sequence)]
struct AuthResponse {
	server_id: String,
	authenticated: bool,
}

// ============================================================================
// Mutual Authentication Servlet with X.509
// ============================================================================

servlet! {
	pub MutualAuthServlet<AuthRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |request, frame, _ctx| async move {
		let response = AuthResponse {
			server_id: "mutual-auth-server".to_string(),
			authenticated: request.client_id == "test-client-mutual-001",
		};

		let response_frame = compose! {
			V0: id: &frame.metadata.id,
			message: response
		}?;

		Ok(Some(response_frame))
	}
}

// ============================================================================
// Test Scenario
// ============================================================================

// Verification spec
tb_assert_spec! {
	MutualAuthSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(RESPONSE_RECEIVED, exactly!(1), equals!(IsSome)),
			(SERVER_ID, exactly!(1), equals!("mutual-auth-server")),
			(AUTHENTICATED, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: test_mutual_auth_with_servlet,
	spec: MutualAuthSpec,
	environment Servlet {
		start: |env| async move {
			let trace = Arc::new(env.trace);
			let servlet_conf = ServletConfig::<TokioListener, AuthRequest>::builder()
				.with_certificate(SERVER_CERT, SERVER_KEY.to_provider::<Secp256k1>()?, vec![Arc::new(CLIENT_PINNING)])?
				.with_config(Arc::new(()))
				.build();

			MutualAuthServlet::start(Arc::clone(&trace), Some(servlet_conf)).await
		},
		setup: |env| async move {
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(make_server_trust_store()?)
				.with_client_identity(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?
				.build();

			let client = builder.connect(env.addr).await?;
			Ok(client)
		},
		client: |env| async move {
			let (trace, mut client) = (env.trace, env.client);
			// Send authenticated request
			let request = AuthRequest {
				client_id: "test-client-mutual-001".to_string(),
			};

			let request_frame = compose! {
				V0: id: b"mutual-auth-req-001",
				message: request
			}?;

			// Emit trace events unconditionally - assertion spec validates them
			let response_frame: Option<Frame> = client.emit(request_frame, None).await?;
			trace.event_with(RESPONSE_RECEIVED, &[], Presence::of_option(&response_frame))?;

			let response_frame = response_frame.ok_or(TightBeamError::MissingResponse)?;
			let response: AuthResponse = decode(&response_frame.message)?;

			trace.event_with(SERVER_ID, &[], response.server_id)?;
			trace.event_with(AUTHENTICATED, &[], response.authenticated)?;

			Ok(())
		}
	}
}

/// Drive the lazy encryption handshake to a verdict: `connect` only
/// dials, so a certificate rejection surfaces on the first exchange.
/// Probes with a well-formed request so a decode failure cannot
/// masquerade as a handshake refusal. The client transport carries the
/// scenario collector so its own handshake verdicts are recorded.
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

// Negative test A: Invalid client certificate
tb_assert_spec! {
	pub InvalidClientSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(CLIENT_CERT_REJECTED, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: test_invalid_client_cert,
	spec: InvalidClientSpec,
	environment Servlet {
		start: |env| async move {
			let trace = Arc::new(env.trace);
			let servlet_conf = ServletConfig::<TokioListener, AuthRequest>::builder()
				.with_certificate(SERVER_CERT, SERVER_KEY.to_provider::<Secp256k1>()?, vec![Arc::new(CLIENT_PINNING)])?
				.with_config(Arc::new(()))
				.build();

			MutualAuthServlet::start(Arc::clone(&trace), Some(servlet_conf)).await
		},
		setup: |env| async move {
			use tightbeam::crypto::key::Secp256k1KeyProvider;
			use tightbeam::testing::utils::{create_test_signing_key, create_test_certificate};

			// Client identity outside the server's pin set: certificate
			// and signing provider share one fresh key, so the rejection
			// is the pin check and not a key/certificate mismatch.
			let invalid_key = create_test_signing_key();
			let invalid_cert = create_test_certificate(&invalid_key);

			let certificate = CertificateSpec::Built(Box::new(invalid_cert));
			let provider = Arc::new(Secp256k1KeyProvider::from(invalid_key));
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(make_server_trust_store()?)
				.with_client_identity(certificate, provider)?
				.build();

			// The pinning server must refuse this identity during the
			// handshake: a successful exchange records `false` and fails
			// the spec, so a wrongly-accepting handshake is visible.
			let rejected = handshake_rejected(builder, env.addr, &env.trace).await?;
			env.trace.event_with(CLIENT_CERT_REJECTED, &[], rejected)?;
			Ok(())
		},
		client: |_env| async move {
			Ok(())
		}
	}
}

// Negative test B: Invalid server certificate. The client transport
// carries the scenario collector, so the client-side rejection must also
// record the production audit event.
tb_assert_spec! {
	pub InvalidServerSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(SERVER_CERT_REJECTED, exactly!(1), equals!(true)),
			(events::SESSION_CERT_REJECTED, at_least!(1))
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
			use tightbeam::testing::utils::{create_test_signing_key, create_test_certificate};

			// Server presents a certificate outside the client's trust
			// store: certificate and signing provider share one fresh
			// key, so the rejection is the trust check and not a
			// key/certificate mismatch.
			let invalid_server_key = create_test_signing_key();
			let invalid_server_cert = create_test_certificate(&invalid_server_key);

			let certificate = CertificateSpec::Built(Box::new(invalid_server_cert));
			let provider = Arc::new(Secp256k1KeyProvider::from(invalid_server_key));
			let servlet_conf = ServletConfig::<TokioListener, AuthRequest>::builder()
				.with_certificate(certificate, provider, vec![Arc::new(CLIENT_PINNING)])?
				.with_config(Arc::new(()))
				.build();

			MutualAuthServlet::start(Arc::clone(&trace), Some(servlet_conf)).await
		},
		setup: |env| async move {
			// Client trusts only SERVER_CERT; the presented certificate
			// differs, so the client-side validation must refuse it.
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(make_server_trust_store()?)
				.with_client_identity(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?
				.build();

			// A successful exchange records `false` and fails the spec,
			// so a wrongly-accepting validation is visible.
			let rejected = handshake_rejected(builder, env.addr, &env.trace).await?;
			env.trace.event_with(SERVER_CERT_REJECTED, &[], rejected)?;
			Ok(())
		},
		client: |_env| async move {
			Ok(())
		}
	}
}
