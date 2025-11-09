//! Integration tests for certificate validation (with_x509_gate)
//!
//! Tests various certificate validation strategies using the with_x509_gate policy.

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
use std::time::Instant;

use tightbeam::{
	cert, compose,
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
	der::Encode,
	error::Result,
	pem,
	prelude::collect::TokioListener,
	prelude::policy::PolicyConf,
	prelude::*,
	spki::SubjectPublicKeyInfoOwned,
	test_container,
	testing::create_test_signing_key,
	transport::MessageEmitter,
	x509::Certificate,
};

#[derive(Clone, Debug, PartialEq, Beamable, Sequence)]
struct PingMessage {
	data: String,
}

#[derive(Clone, Debug, PartialEq, Beamable, Sequence)]
struct PongMessage {
	echo: String,
}

// Helper to create test certificate
fn create_test_cert(subject: &str, validity_days: u64) -> Result<(Certificate, Secp256k1SigningKey)> {
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

// Temporary test to print certificate PEM
#[tokio::test]
async fn print_test_cert_pem() -> Result<()> {
	let (cert, _key) = create_test_cert("CN=Test Print Cert", 365)?;
	let der = cert.to_der()?;
	let pem_str = tightbeam::der::pem::encode_string("CERTIFICATE", tightbeam::der::pem::LineEnding::LF, &der).unwrap();
	println!("\n\n=== CERTIFICATE PEM ===\n{}\n=== END CERTIFICATE ===\n", pem_str);
	Ok(())
}

// Test 6: test_container with auto-generated valid cert
test_container! {
	name: test_expiry_validator_in_transport,
	protocol: TokioListener,
	service_policies: {
		with_x509: [],
		with_x509_gate: [ExpiryValidator]
	},
	service: |message, tx| async move {
		tx.send(message.clone()).ok()?;
		let ping: PingMessage = decode(&message.message).ok()?;
		let pong = PongMessage { echo: ping.data };
		Some(compose! {
			V0: id: message.metadata.id.clone(),
				message: pong
		}.ok()?)
	},
	container: |client, channels| async move {
		let (_rx, _ok_rx, _reject_rx) = channels;

		let ping = PingMessage { data: "should-work".to_string() };
		let request = compose! {
			V0: id: b"test-4",
				message: ping
		}?;

		// The auto-generated cert should be valid
		let response = client.emit(request, None).await?;
		assert!(response.is_some(), "Should accept valid certificate");

		Ok(())
	}
}

// Helper for test certificate PEM
fn get_test_print_cert() -> Certificate {
	pem!(
		r#"
-----BEGIN CERTIFICATE-----
MIIBYzCCAQmgAwIBAgIBATALBglghkgBZQMEAwowGjEYMBYGA1UEAwwPVGVzdCBQ
cmludCBDZXJ0MB4XDTI1MTEwOTAxMzkyNloXDTI2MTEwOTAxMzkyNlowGjEYMBYG
A1UEAwwPVGVzdCBQcmludCBDZXJ0MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEG4TF
VnsSZECZXT7VqroFZdceGDRgSBn/nBf16dXdB49wvq+PWItUFQf+1qZCxatC39+B
IKf2Od5RItR6aajo0aNCMEAwHQYDVR0OBBYEFEOubLl6za81S4KG3bKbSSyV6Vhw
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAsGCWCGSAFlAwQDCgNH
ADBEAiAwaub9nRDpf8oI9vcjrJQhAPE7UgjR+GH7lmcqn6e+CwIgYOKFSR6ByVW3
JCTXPkK823PFWdcipuDPI7vtNhnCx80=
-----END CERTIFICATE-----
	"#
	)
	.unwrap()
}

// Test 3: Custom validator with explicit certificate passed via with_x509
struct CustomValidator {
	allowed_subject: String,
}

impl CertificateValidation for CustomValidator {
	fn evaluate(&self, cert: &Certificate) -> core::result::Result<(), CertificateValidationError> {
		// Extract subject from certificate
		let subject = &cert.tbs_certificate.subject;
		let subject_str = format!("{:?}", subject);

		if subject_str.contains(&self.allowed_subject) {
			Ok(())
		} else {
			Err(CertificateValidationError::InvalidCertificateEncoding)
		}
	}
}

test_container! {
	name: test_custom_validator,
	protocol: TokioListener,
	service_policies: {
		with_x509: [get_test_print_cert(), create_test_signing_key()]
	},
	client_policies: {
		with_x509_gate: [CustomValidator {
			allowed_subject: "Test Print Cert".to_string()
		}]
	},
	service: |message, tx| async move {
		tx.send(message.clone()).ok()?;
		let ping: PingMessage = decode(&message.message).ok()?;
		let pong = PongMessage { echo: ping.data };
		Some(compose! {
			V0: id: message.metadata.id.clone(),
				message: pong
		}.ok()?)
	},
	container: |client, channels| async move {
		let (rx, _ok_rx, _reject_rx) = channels;

		let ping = PingMessage { data: "custom".to_string() };
		let request = compose! {
			V0: id: b"test-3",
				message: ping
		}?;

		let response = client.emit(request, None).await?;
		assert!(response.is_some(), "Should accept certificate with allowed subject");

		let pong: PongMessage = decode(&response.unwrap().message)?;
		assert_eq!(pong.echo, "custom");

		// Check server received
		let server_msg = rx.recv_timeout(Duration::from_secs(1))?;
		assert_eq!(server_msg.metadata.id, b"test-3");

		Ok(())
	}
}
