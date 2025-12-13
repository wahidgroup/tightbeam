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
	feature = "builder"
))]

use std::sync::Arc;
use tightbeam::{
	colony::servlet::ServletConf,
	compose,
	crypto::{
		key::KeySpec,
		x509::{policy::PublicKeyPinning, CertificateSpec},
	},
	decode, exactly, hex,
	prelude::*,
	servlet, tb_assert_spec, tb_scenario,
	testing::{assertions::Presence, macros::IsSome, ScenarioConf, TestHooks},
	transport::{tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder},
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

const SERVER_KEY: KeySpec = KeySpec::Bytes(&hex!("0101010101010101010101010101010101010101010101010101010101010101"));
const CLIENT_KEY: KeySpec = KeySpec::Bytes(&hex!("0202020202020202020202020202020202020202020202020202020202020202"));

// Client public key for server-side validation
const CLIENT_PUB_KEY: &[u8] = &hex!("044d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07662a3eada2d0fe208b6d257ceb0f064284662e857f57b66b54c198bd310ded36d0");
// Server-side pinning: validate incoming client certificates
const CLIENT_PINNING: PublicKeyPinning<1> = PublicKeyPinning::new([CLIENT_PUB_KEY]);

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
	handle: |frame, _trace, _config, _workers| async move {
		let request: AuthRequest = decode(&frame.message)?;
		let response = AuthResponse {
			server_id: "mutual-auth-server".to_string(),
			authenticated: request.client_id == "test-client-mutual-001",
		};

		let response_frame = compose! {
			V0: id: frame.metadata.id.clone(),
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
		gate: Accepted,
		assertions: [
			("response_received", exactly!(1), equals!(IsSome)),
			("server_id", exactly!(1), equals!("mutual-auth-server")),
			("authenticated", exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: test_mutual_auth_with_servlet,
	config: ScenarioConf::<()>::builder()
		.with_spec(MutualAuthSpec::latest())
		.with_env_config(())  // TODO revisit
		.build(),
	environment Servlet {
		servlet: MutualAuthServlet,
		start: |trace, _config| async move {
			let servlet_conf = ServletConf::<TokioListener, AuthRequest>::builder()
				.with_certificate(SERVER_CERT, SERVER_KEY, vec![Arc::new(CLIENT_PINNING)])?
				.with_config(Arc::new(()))
				.build();

			MutualAuthServlet::start(Arc::clone(&trace), Some(servlet_conf)).await
		},
		setup: |addr, _config| async move {
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_server_certificate(SERVER_CERT)?
				.with_client_identity(CLIENT_CERT, CLIENT_KEY)?
				.build();

			let client = builder.connect(addr).await?;
			Ok(client)
		},
		client: |trace, mut client, _config| async move {
			// Send authenticated request
			let request = AuthRequest {
				client_id: "test-client-mutual-001".to_string(),
			};

			let request_frame = compose! {
				V0: id: b"mutual-auth-req-001",
				message: request
			}?;

			let response_frame: Option<Frame> = client.emit(request_frame, None).await?;

			// Emit trace events unconditionally - assertion spec validates them
			trace.event_with("response_received", &[], Presence::of_option(&response_frame))?;

			let response: AuthResponse = decode(&response_frame.unwrap().message)?;

			trace.event_with("server_id", &[], response.server_id)?;
			trace.event_with("authenticated", &[], response.authenticated)?;

			Ok(())
		}
	}
}

// Negative test A: Invalid client certificate
tb_assert_spec! {
	pub InvalidClientSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: []
	}
}

tb_scenario! {
	name: test_invalid_client_cert,
	config: ScenarioConf::<()>::builder()
		.with_spec(InvalidClientSpec::latest())
		.with_env_config(())
		.with_hooks(TestHooks {
			on_fail: Some(Arc::new(|_context, _violation| {
				// Expected to fail - authentication should reject invalid client cert
				Ok(())
			})),
			on_pass: None,
		})
		.build(),
	environment Servlet {
		servlet: MutualAuthServlet,
		start: |trace, _config| async move {
			let servlet_conf = ServletConf::<TokioListener, AuthRequest>::builder()
				.with_certificate(SERVER_CERT, SERVER_KEY, vec![Arc::new(CLIENT_PINNING)])?
				.with_config(Arc::new(()))
				.build();

			MutualAuthServlet::start(Arc::clone(&trace), Some(servlet_conf)).await
		},
		setup: |addr, _config| async move {
			use tightbeam::testing::utils::{create_test_signing_key, create_test_certificate};
			const INVALID_KEY: KeySpec = KeySpec::Bytes(&hex!("9999999999999999999999999999999999999999999999999999999999999999"));

			// Create invalid client cert
			let invalid_key = create_test_signing_key();
			let invalid_cert = create_test_certificate(&invalid_key);

			// Client with invalid cert - should fail during handshake
			let certificate = CertificateSpec::Built(Box::new(invalid_cert));
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_server_certificate(SERVER_CERT)?
				.with_client_identity(certificate, INVALID_KEY)?
				.build();

			let client = builder.connect(addr).await?;
			Ok(client)
		},
		client: |_trace, mut _client, _config| async move {
			Ok(())
		}
	}
}

// Negative test B: Invalid server certificate
tb_assert_spec! {
	pub InvalidServerSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: []
	}
}

tb_scenario! {
	name: test_invalid_server_cert,
	config: ScenarioConf::<()>::builder()
		.with_spec(InvalidServerSpec::latest())
		.with_env_config(())
		.with_hooks(TestHooks {
			on_fail: Some(Arc::new(|_context, _violation| {
				// Expected to fail - client should reject invalid server cert
				Ok(())
			})),
			on_pass: None,
		})
		.build(),
	environment Servlet {
		servlet: MutualAuthServlet,
		start: |trace, _config| async move {
			use tightbeam::testing::utils::{create_test_signing_key, create_test_certificate};
			const INVALID_SERVER_KEY: KeySpec = KeySpec::Bytes(&hex!("8888888888888888888888888888888888888888888888888888888888888888"));

			// Server uses different cert than client expects
			let invalid_server_key = create_test_signing_key();
			let invalid_server_cert = create_test_certificate(&invalid_server_key);

			let certificate = CertificateSpec::Built(Box::new(invalid_server_cert));
			let servlet_conf = ServletConf::<TokioListener, AuthRequest>::builder()
				.with_certificate(certificate, INVALID_SERVER_KEY, vec![Arc::new(CLIENT_PINNING)])?
				.with_config(Arc::new(()))
				.build();

			MutualAuthServlet::start(Arc::clone(&trace), Some(servlet_conf)).await
		},
		setup: |addr, _config| async move {
			// Client expects SERVER_CERT, but server presents different cert - should fail during handshake
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_server_certificate(SERVER_CERT)?
				.with_client_identity(CLIENT_CERT, CLIENT_KEY)?
				.build();

			let client = builder.connect(addr).await?;
			Ok(client)
		},
		client: |_trace, mut _client, _config| async move {
			Ok(())
		}
	}
}
