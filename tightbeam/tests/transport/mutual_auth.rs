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

use tightbeam::{
	compose,
	crypto::{
		key::KeySpec,
		x509::{policy::PublicKeyPinning, CertificateSpec},
	},
	decode, hex,
	macros::client::builder::ClientBuilder,
	prelude::*,
	servlet, tb_assert_spec, tb_scenario, Beamable,
};

// ============================================================================
// Static X.509 Configuration
// ============================================================================

const SERVER_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"
    -----BEGIN CERTIFICATE-----
    MIIBajCCAQ+gAwIBAgIBATALBglghkgBZQMEAwowHTEbMBkGA1UEAwwSU3RhdGlj
    IFRlc3QgU2VydmVyMB4XDTI1MTEyMTIwMDk0MloXDTM1MTExOTIwMDk0MlowHTEb
    MBkGA1UEAwwSU3RhdGljIFRlc3QgU2VydmVyMFYwEAYHKoZIzj0CAQYFK4EEAAoD
    QgAEG4TFVnsSZECZXT7VqroFZdceGDRgSBn/nBf16dXdB49wvq+PWItUFQf+1qZC
    xatC39+BIKf2Od5RItR6aajo0aNCMEAwHQYDVR0OBBYEFEOubLl6za81S4KG3bKb
    SSyV6VhwMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAsGCWCGSAFl
    AwQDCgNIADBFAiEAmYxdAPoWH4W7SRiJA8ZT/Nr05BS8FX7+MLqpN4vL5v4CIChY
    qCueHq1ts/ay2nKHXZp/lNFxqO0katvNQxyY8IRT
    -----END CERTIFICATE-----
"#,
);

const CLIENT_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"
    -----BEGIN CERTIFICATE-----
    MIIBaTCCAQ+gAwIBAgIBATALBglghkgBZQMEAwowHTEbMBkGA1UEAwwSU3RhdGlj
    IFRlc3QgQ2xpZW50MB4XDTI1MTEyMTIwMDk0MloXDTM1MTExOTIwMDk0MlowHTEb
    MBkGA1UEAwwSU3RhdGljIFRlc3QgQ2xpZW50MFYwEAYHKoZIzj0CAQYFK4EEAAoD
    QgAEG4TFVnsSZECZXT7VqroFZdceGDRgSBn/nBf16dXdB49wvq+PWItUFQf+1qZC
    xatC39+BIKf2Od5RItR6aajo0aNCMEAwHQYDVR0OBBYEFEOubLl6za81S4KG3bKb
    SSyV6VhwMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAsGCWCGSAFl
    AwQDCgNHADBEAiAPIoi/ZYamjnSS/+YkeIG53hEzWpL+UBf04jyWnpCG5wIgQrGE
    pC7NuhifPZO2kSFiLIAIrpc+UnsvwGrI7gMNjW8=
    -----END CERTIFICATE-----
"#,
);

const SERVER_KEY: KeySpec = KeySpec::Bytes(&hex!("0101010101010101010101010101010101010101010101010101010101010101"));
const CLIENT_KEY: KeySpec = KeySpec::Bytes(&hex!("0101010101010101010101010101010101010101010101010101010101010101"));

// Client public key for pinning validation (zero-copy, const-constructible)
const CLIENT_PUB_KEY: &[u8] = &hex!("041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1");
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
	pub MutualAuthServlet<AuthRequest>,
	protocol: tightbeam::transport::tcp::r#async::TokioListener,
	x509: {
		certificate: SERVER_CERT,
		key_provider: SERVER_KEY,
		client_validators: [CLIENT_PINNING]
	},
	handle: |frame, _trace| async move {
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
		assertions: []
	}
}

tb_scenario! {
	name: test_mutual_auth_with_servlet,
	spec: MutualAuthSpec,
	environment Servlet {
		servlet: MutualAuthServlet,
		start: |trace| async move {
			use core::convert::TryFrom;

			// Create servlet with x509 mutual auth
			let servlet = MutualAuthServlet::start(trace).await?;
			let server_addr = servlet.addr();

			// Convert specs to concrete types for client
			let server_cert = tightbeam::crypto::x509::Certificate::try_from(SERVER_CERT)?;
			let client_cert = tightbeam::crypto::x509::Certificate::try_from(CLIENT_CERT)?;
			let client_key = tightbeam::transport::handshake::HandshakeKeyManager::try_from(CLIENT_KEY)?;

			// Create client with mutual authentication
			let client = ClientBuilder::<tightbeam::transport::tcp::r#async::TokioListener>::connect(server_addr)
				.await?
				.with_server_certificate(server_cert)
				.with_client_identity(client_cert, client_key)
				.build()?;

			Ok((servlet, client))
		},
		client: |_trace, mut client| async move {
			// Send authenticated request
			let request = AuthRequest {
				client_id: "test-client-mutual-001".to_string(),
			};

			let request_frame = compose! {
				V0: id: b"mutual-auth-req-001",
				message: request
			}?;

			let response_frame = client.emit(request_frame, None).await?;

			// Validate response
			assert!(response_frame.is_some(), "Expected response from server");
			let response: AuthResponse = decode(&response_frame.unwrap().message)?;
			assert_eq!(response.server_id, "mutual-auth-server", "Server ID mismatch");
			assert!(response.authenticated, "Client should be authenticated");

			Ok(())
		}
	}
}
