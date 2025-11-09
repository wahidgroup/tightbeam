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
use std::{sync::Arc, time::Instant};

use tightbeam::{
	cert, client, compose,
	crypto::{
		sign::{
			ecdsa::{Secp256k1SigningKey, Secp256k1VerifyingKey},
			Sha3Signer,
		},
		x509::{
			error::CertificateValidationError,
			policy::{CertificateValidation, ExpiryValidator},
		},
	},
	decode,
	error::Result,
	prelude::collect::TokioListener,
	prelude::{policy::PolicyConf, *},
	server,
	spki::SubjectPublicKeyInfoOwned,
	testing::{create_expiring_test_certificate, create_test_signing_key},
	transport::{handshake::ServerHandshakeKey, EncryptedProtocol, TransportEncryptionConfig},
	x509::Certificate,
};

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
// Test Setup Helpers
// ============================================================================

fn create_test_cert_with_key(subject: &str, validity_days: u64) -> Result<(Certificate, Secp256k1SigningKey)> {
	let signing_key = create_test_signing_key();
	let verifying_key = Secp256k1VerifyingKey::from(&signing_key);
	let sha3_signer = Sha3Signer::from(&signing_key);
	let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;

	let not_before = Instant::now();
	let not_after = not_before + Duration::from_secs(validity_days * 24 * 60 * 60);

	let cert = cert! {
		profile: Root,
		subject: subject,
		serial: 1u32,
		validity: (not_before, not_after),
		signer: &sha3_signer,
		subject_public_key: spki
	}?;

	Ok((cert, signing_key))
}

fn create_server_config(
	cert: Certificate,
	key: Secp256k1SigningKey,
	validators: Vec<Arc<dyn CertificateValidation>>,
) -> TransportEncryptionConfig {
	TransportEncryptionConfig::new(cert, Arc::new(key) as Arc<dyn ServerHandshakeKey>)
		.with_client_validators(validators)
}

/// Test fixture that sets up a server with mutual authentication
struct MutualAuthServer {
	handle: tokio::task::JoinHandle<()>,
	addr: TightBeamSocketAddr,
	rx: tokio::sync::mpsc::Receiver<Frame>,
}

impl MutualAuthServer {
	async fn new(
		server_cert: Certificate,
		server_key: Secp256k1SigningKey,
		client_validators: Vec<Arc<dyn CertificateValidation>>,
	) -> Result<Self> {
		println!("Creating server with {} client validators", client_validators.len());
		let server_config = create_server_config(server_cert, server_key, client_validators);
		let bind_addr = TightBeamSocketAddr("127.0.0.1:0".parse().unwrap());
		let (listener, addr) = TokioListener::bind_with(bind_addr, server_config).await?;
		println!("Server listening on {:?}", addr);
		let (tx, rx) = tokio::sync::mpsc::channel(8);

		let handle = server! {
			protocol TokioListener: listener,
			handle: move |message: Frame| {
				let tx = tx.clone();
				async move {
					println!("Server received message: {:?}", String::from_utf8_lossy(&message.metadata.id));
					tx.send(message.clone()).await.ok()?;

					let ping: PingMessage = decode(&message.message).ok()?;
					let pong = PongMessage { echo: ping.data };

					Some(compose! {
						V0: id: message.metadata.id.clone(),
						message: pong
					}.ok()?)
				}
			}
		};

		Ok(Self { handle, addr, rx })
	}

	async fn expect_message(&mut self, timeout: Duration) -> Frame {
		tokio::time::timeout(timeout, self.rx.recv())
			.await
			.expect("Server should receive message within timeout")
			.expect("Message should not be None")
	}

	fn abort(self) {
		self.handle.abort();
	}
}

// ============================================================================
// Certificate Validators
// ============================================================================

/// Extract Common Name from certificate subject
fn extract_cn(cert: &Certificate) -> Option<String> {
	use der::asn1::{Ia5StringRef, PrintableStringRef, Utf8StringRef};

	// OID for Common Name (CN) is 2.5.4.3
	const CN_OID: &str = "2.5.4.3";

	// Iterate through RDN sequence to find CN
	for rdn in cert.tbs_certificate.subject.0.iter() {
		for attr in rdn.0.iter() {
			if attr.oid.to_string() == CN_OID {
				// The value is an Any type which can be various string types
				// Try UTF8String first
				if let Ok(utf8_str) = attr.value.decode_as::<Utf8StringRef>() {
					return Some(utf8_str.to_string());
				}
				// Try PrintableString
				if let Ok(printable) = attr.value.decode_as::<PrintableStringRef>() {
					return Some(printable.to_string());
				}
				// Try IA5String
				if let Ok(ia5) = attr.value.decode_as::<Ia5StringRef>() {
					return Some(ia5.to_string());
				}
			}
		}
	}
	None
}
struct ClientValidator;
impl CertificateValidation for ClientValidator {
	fn evaluate(&self, cert: &Certificate) -> core::result::Result<(), CertificateValidationError> {
		println!("ClientValidator: Starting evaluation");
		if let Some(cn) = extract_cn(cert) {
			println!("ClientValidator: Extracted CN: '{}'", cn);
			if cn == "Test Client" {
				println!("ClientValidator: ACCEPTED");
				Ok(())
			} else {
				println!("ClientValidator: REJECTED - CN mismatch");
				Err(CertificateValidationError::InvalidCertificateEncoding)
			}
		} else {
			println!("ClientValidator: REJECTED - No CN found");
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

	let mut client = client! {
		connect TokioListener: server.addr,
		identity: (client_cert, Arc::new(client_key) as Arc<dyn ServerHandshakeKey>),
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

	let pong: PongMessage = decode(&response.unwrap().message)?;
	assert_eq!(pong.echo, "mutual-auth-test");

	let server_msg = server.expect_message(Duration::from_secs(1)).await;
	assert_eq!(server_msg.metadata.id, b"test-mutual-1");

	server.abort();
	Ok(())
}

/// Test that valid but unexpected client certificate is rejected by server validator
#[tokio::test]
async fn test_unexpected_client_cert_rejected() -> Result<()> {
	use tightbeam::macros::client::builder::GenericClient;

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

	tokio::time::sleep(Duration::from_millis(100)).await;

	// Try to create client and connect - this should fail during handshake
	let client_result: Result<()> = async {
		println!("Attempting to create client with unexpected certificate...");
		let client = client! {
			connect TokioListener: server.addr,
			identity: (client_cert, Arc::new(client_key) as Arc<dyn ServerHandshakeKey>),
			policies: {
				x509_gate: [ExpiryValidator]
			}
		};
		let transport = client.into_transport().with_server_certificate(server_cert);
		let mut client = GenericClient::<TokioListener>::from_transport(transport);
		println!("Client created successfully (unexpected!)");

		let ping = PingMessage { data: "test".to_string() };
		let request = compose! { V0: id: b"test-1", message: ping }?;

		println!("Attempting to emit message...");
		let response = client.emit(request, None).await?;
		println!("Message emitted successfully: {:?}", response.is_some());

		Ok(())
	}
	.await;
	println!("Final result: {:?}", client_result);
	if let Err(e) = &client_result {
		println!("Error details: {:?}", e);
	}

	assert!(
		client_result.is_err(),
		"Should reject client certificate that doesn't contain 'Test Client', but got: {:?}",
		client_result
	);

	server.abort();
	Ok(())
}

/// Test that client rejects expired server certificate
#[ignore]
#[tokio::test]
async fn test_client_rejects_expired_server() -> Result<()> {
	let (server_cert, server_key) = create_expiring_test_certificate()?;
	let (client_cert, client_key) = create_test_cert_with_key("CN=Test Client", 365)?;

	let server = MutualAuthServer::new(server_cert, server_key, vec![]).await?;
	let mut client = client! {
		connect TokioListener: server.addr,
		identity: (client_cert, Arc::new(client_key) as Arc<dyn ServerHandshakeKey>),
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
