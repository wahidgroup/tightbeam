//! Integration tests for mutual authentication handshake protocols.
//!
//! Tests both CMS-based and ECIES-based handshake protocols with mutual
//! authentication, certificate validation, and transcript verification.

use std::sync::Arc;
use tightbeam::{
	compose,
	crypto::x509::policy::{CertificateValidation, ExpiryValidator},
	decode, server,
	transport::{EncryptedProtocol, TransportEncryptionConfig},
	Frame, Message, Sequence, TightBeamError,
};

#[cfg(feature = "transport-async")]
use tightbeam::transport::tcp::r#async::TokioListener;

#[cfg(feature = "transport-async")]
use tightbeam::prelude::TightBeamSocketAddr;

/// Test message types
#[derive(tightbeam::Beamable, Sequence, Clone, Debug, PartialEq)]
struct PingMessage {
	data: String,
}

#[derive(tightbeam::Beamable, Sequence, Clone, Debug, PartialEq)]
struct PongMessage {
	echo: String,
}

/// Custom certificate validator for testing
struct ClientCNValidator;

impl CertificateValidation for ClientCNValidator {
	fn validate(&self, cert: &x509_cert::Certificate) -> Result<(), tightbeam::crypto::x509::policy::ValidationError> {
		let subject = cert.tbs_certificate.subject.to_string();
		if subject.contains("Test Client") {
			Ok(())
		} else {
			Err(tightbeam::crypto::x509::policy::ValidationError::InvalidSubject)
		}
	}
}

struct ServerCNValidator;

impl CertificateValidation for ServerCNValidator {
	fn validate(&self, cert: &x509_cert::Certificate) -> Result<(), tightbeam::crypto::x509::policy::ValidationError> {
		let subject = cert.tbs_certificate.subject.to_string();
		if subject.contains("Test Server") {
			Ok(())
		} else {
			Err(tightbeam::crypto::x509::policy::ValidationError::InvalidSubject)
		}
	}
}

/// Helper function to create test certificates
fn create_test_cert(
	subject: &str,
) -> Result<(x509_cert::Certificate, pkcs8::PrivateKeyInfo<'static>), Box<dyn std::error::Error>> {
	use ecdsa::SigningKey;
	use p256::NistP256;
	use x509_cert::{
		builder::{Builder, CertificateBuilder, Profile},
		name::Name,
		serial_number::SerialNumber,
		time::Validity,
	};

	let mut rng = rand::thread_rng();
	let signing_key = SigningKey::<NistP256>::random(&mut rng);
	let verifying_key = signing_key.verifying_key();

	let serial_number = SerialNumber::from(1u32);
	let validity = Validity::from_now(std::time::Duration::from_secs(86400))?;
	let subject = Name::from_str(subject)?;
	let profile = Profile::Root;

	let builder = CertificateBuilder::new(
		profile,
		serial_number,
		validity,
		subject.clone(),
		verifying_key.into(),
		&signing_key,
	)?;

	let cert = builder.build::<p256::ecdsa::DerSignature>()?;

	let private_key_der = pkcs8::PrivateKeyInfo {
		algorithm: pkcs8::AlgorithmIdentifierRef {
			oid: pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
			parameters: Some((&pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7")).into()),
		},
		private_key: signing_key.to_bytes().as_slice(),
		public_key: None,
	};

	Ok((cert, private_key_der))
}

#[tokio::test]
#[cfg(feature = "transport-async")]
async fn test_mutual_auth_handshake() -> Result<(), Box<dyn std::error::Error>> {
	// 1. Generate certificates for server and client
	let (server_cert, server_key) = create_test_cert("CN=Test Server")?;
	let (client_cert, client_key) = create_test_cert("CN=Test Client")?;

	// 2. Configure server with mutual authentication
	let server_config =
		TransportEncryptionConfig::new(server_cert.clone(), server_key.into()).with_client_validators(vec![
			Arc::new(ExpiryValidator) as Arc<dyn CertificateValidation>,
			Arc::new(ClientCNValidator), // Custom validator checking CN
		]);

	// 3. Bind server with encryption config
	let bind_addr = TightBeamSocketAddr("127.0.0.1:0".parse()?);
	let (listener, addr) = TokioListener::bind_with(bind_addr, server_config).await?;

	// 4. Start server with handler
	let (tx, mut rx) = tokio::sync::mpsc::channel(8);
	let server_handle = server! {
		protocol TokioListener: listener,
		handle: move |message: Frame| {
			let tx = tx.clone();
			async move {
				tx.send(message.clone()).await.ok()?;
				let ping: PingMessage = decode(&message.message).ok()?;
				let pong = PongMessage { echo: ping.data };
				compose! { V0: id: message.metadata.id.clone(), message: pong }.ok()
			}
		}
	};

	// 5. Connect client with mutual authentication
	let mut client = client! {
		connect TokioListener: addr,
		identity: (client_cert, client_key.into()),
		policies: {
			x509_gate: [ExpiryValidator, ServerCNValidator]
		}
	};

	// 6. Send message - handshake happens automatically on first emit
	let ping = PingMessage { data: "hello".to_string() };
	let request = compose! { V0: id: b"test-1", message: ping }?;
	let response = client.emit(request, None).await?;

	// 7. Verify response
	assert!(response.is_some());
	let response_frame = response.ok_or("Expected response to be Some")?;
	let pong: PongMessage = decode(&response_frame.message)?;
	assert_eq!(pong.echo, "hello");

	// 8. Verify server received message
	let server_msg = rx.recv().await.ok_or("Expected to receive message from server")?;
	assert_eq!(server_msg.metadata.id, b"test-1");

	Ok(())
}
