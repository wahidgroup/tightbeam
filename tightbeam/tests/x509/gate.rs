//! Integration tests for certificate validation and mutual authentication

#![cfg(all(
	feature = "x509",
	feature = "std",
	feature = "transport-policy",
	feature = "tcp",
	feature = "tokio",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead"
))]

use core::time::Duration;
use std::sync::Arc;

use tightbeam::{
	client, compose,
	crypto::{
		key::{InMemoryKeyProvider, KeySpec},
		x509::{
			error::CertificateValidationError,
			policy::{CertificateValidation, ExpiryValidator},
			CertificateSpec,
		},
	},
	decode,
	error::Result,
	macros::client::builder::GenericClient,
	prelude::*,
	testing::create_expiring_test_certificate,
	transport::{tcp::r#async::TokioListener, X509ClientConfig},
	x509::Certificate,
	TightBeamError,
};

// Import common test helpers
use crate::common::x509::{create_test_cert_with_key, extract_cn, MutualAuthServer};

// ============================================================================
// Test Message Types
// ============================================================================

#[derive(Clone, Debug, PartialEq, Beamable, Sequence)]
struct PingMessage {
	data: String,
}

#[derive(Clone, Debug, PartialEq, Beamable, Sequence)]
struct PongMessage {
	echo: String,
}

// ============================================================================
// Certificate Validators
// ============================================================================

struct ClientValidator;
impl CertificateValidation for ClientValidator {
	fn evaluate(&self, cert: &Certificate) -> core::result::Result<(), CertificateValidationError> {
		if let Some(cn) = extract_cn(cert) {
			if cn == "Test Client" {
				Ok(())
			} else {
				Err(CertificateValidationError::InvalidCertificateEncoding)
			}
		} else {
			Err(CertificateValidationError::InvalidCertificateEncoding)
		}
	}
}

struct ServerValidator;
impl CertificateValidation for ServerValidator {
	fn evaluate(&self, cert: &Certificate) -> core::result::Result<(), CertificateValidationError> {
		if let Some(cn) = extract_cn(cert) {
			if cn == "Test Server" {
				Ok(())
			} else {
				Err(CertificateValidationError::InvalidCertificateEncoding)
			}
		} else {
			Err(CertificateValidationError::InvalidCertificateEncoding)
		}
	}
}

// ============================================================================
// Tests
// ============================================================================

/// Test mutual authentication with servlet and client
#[tokio::test]
async fn test_mutual_auth_with_servlet() -> Result<()> {
	let (server_cert, server_key) = create_test_cert_with_key("CN=Test Server", 365)?;
	let (client_cert, client_key) = create_test_cert_with_key("CN=Test Client", 365)?;

	let mut server = MutualAuthServer::new(
		server_cert.clone(),
		server_key,
		vec![
			Arc::new(ExpiryValidator) as Arc<dyn CertificateValidation>,
			Arc::new(ClientValidator) as Arc<dyn CertificateValidation>,
		],
	)
	.await?;

	// Convert cert and key to specs
	let client_cert_spec = CertificateSpec::Built(client_cert);
	let provider = InMemoryKeyProvider::from(client_key);
	let client_key_spec = KeySpec::Provider(Arc::new(provider));

	let mut client = client! {
		connect TokioListener: server.addr,
		identity: (client_cert_spec, client_key_spec),
		policies: {
			x509_gate: [ExpiryValidator, ServerValidator]
		}
	};

	let ping = PingMessage { data: "mutual-auth-test".to_string() };
	let request = compose! {
		V0: id: b"test-mutual-1",
		message: ping
	}?;

	let response = client.emit(request, None).await?;
	assert!(response.is_some(), "Should receive response with mutual auth");

	let response_frame = response.ok_or(TightBeamError::InvalidMetadata)?;
	let pong: PongMessage = decode(&response_frame.message)?;
	assert_eq!(pong.echo, "mutual-auth-test");

	let server_msg = server.expect_message(Duration::from_secs(1)).await;
	assert_eq!(server_msg.metadata.id, b"test-mutual-1");

	server.abort();
	Ok(())
}

/// Test that valid but unexpected client certificate is rejected by server validator
#[tokio::test]
async fn test_unexpected_client_cert_rejected() -> Result<()> {
	let (server_cert, server_key) = create_test_cert_with_key("CN=Test Server", 365)?;
	let (client_cert, client_key) = create_test_cert_with_key("CN=Unexpected Client", 365)?;

	let server = MutualAuthServer::new(
		server_cert.clone(),
		server_key,
		vec![
			Arc::new(ExpiryValidator) as Arc<dyn CertificateValidation>,
			Arc::new(ClientValidator) as Arc<dyn CertificateValidation>,
		],
	)
	.await?;

	// Try to create client and connect - this should fail during handshake
	let client_result: Result<()> = async {
		// Convert cert and key to specs
		let client_cert_spec = CertificateSpec::Built(client_cert);
		let provider = InMemoryKeyProvider::from(client_key);
		let client_key_spec = KeySpec::Provider(Arc::new(provider));

		let client = client! {
			connect TokioListener: server.addr,
			identity: (client_cert_spec, client_key_spec),
			policies: {
				x509_gate: [ExpiryValidator]
			}
		};
		let transport = client.into_transport().with_server_certificate(server_cert);
		let mut client = GenericClient::<TokioListener>::from_transport(transport);

		let ping = PingMessage { data: "test".to_string() };
		let request = compose! { V0: id: b"test-1", message: ping }?;

		client.emit(request, None).await?;

		Ok(())
	}
	.await;

	assert!(client_result.is_err(), "Should reject client certificate");
	server.abort();

	Ok(())
}

/// Test that client rejects expired server certificate
#[tokio::test]
async fn test_client_rejects_expired_server() -> Result<()> {
	let (server_cert, server_key) = create_expiring_test_certificate()?;
	let (client_cert, client_key) = create_test_cert_with_key("CN=Test Client", 365)?;

	let server = MutualAuthServer::new(server_cert, server_key, vec![]).await?;

	// Convert cert and key to specs
	let client_cert_spec = CertificateSpec::Built(client_cert);
	let provider = InMemoryKeyProvider::from(client_key);
	let client_key_spec = KeySpec::Provider(Arc::new(provider));

	let mut client = client! {
		connect TokioListener: server.addr,
		identity: (client_cert_spec, client_key_spec),
		policies: {
			x509_gate: [ExpiryValidator]
		}
	};

	let ping = PingMessage { data: "test".to_string() };
	let request = compose! { V0: id: b"test-1", message: ping }?;

	let result = client.emit(request, None).await;
	assert!(result.is_err(), "Should reject expired server certificate");

	server.abort();
	Ok(())
}
