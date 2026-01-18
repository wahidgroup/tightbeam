//! Certificate Forgery threat test.
//!
//! Tests that the handshake rejects invalid, forged, or untrusted certificates.
//! This validates the X.509 chain validation control.
//!
//! ## Control
//!
//! X.509 chain validation. Verify root of trust.
//! Note: Application responsibility - the application must configure validators.
//!
//! ## What This Test Proves
//!
//! 1. A certificate with wrong public key (forged) is rejected via pinning
//! 2. A valid certificate passes validation
//! 3. Certificate validation is enforced during handshake

use std::sync::Arc;

use tightbeam::{
	crypto::x509::{error::CertificateValidationError, policy::CertificateValidation, Certificate},
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{error::FdrConfigError, error::TestingError, ScenarioConf},
	trace::TraceCollector,
	transport::handshake::{client::EciesHandshakeClient, server::EciesHandshakeServer},
	TightBeamError,
};

use crate::security::common::{default_security_profile, ServerMaterials};

fn expectation_failure(reason: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError {
		field: "certificate_forgery",
		reason,
	}))
}

/// A validator that always rejects certificates (for testing rejection path).
#[derive(Debug, Clone, Copy)]
pub struct RejectAllValidator;

impl CertificateValidation for RejectAllValidator {
	fn evaluate(&self, _cert: &Certificate) -> Result<(), CertificateValidationError> {
		Err(CertificateValidationError::CertificateDenied)
	}
}

/// A validator that only accepts a specific public key.
#[derive(Debug)]
pub struct SingleKeyPinning {
	allowed_key: Vec<u8>,
}

impl SingleKeyPinning {
	pub fn new(cert: &Certificate) -> Self {
		let key = cert
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes()
			.to_vec();
		Self { allowed_key: key }
	}

	/// Create a pinning validator that accepts a DIFFERENT key (for testing rejection).
	pub fn wrong_key() -> Self {
		// Random bytes that won't match any real certificate
		Self { allowed_key: vec![0xDE; 65] }
	}
}

impl CertificateValidation for SingleKeyPinning {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		let pub_key_bytes = cert.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
		if pub_key_bytes == self.allowed_key.as_slice() {
			Ok(())
		} else {
			Err(CertificateValidationError::PublicKeyNotPinned)
		}
	}
}

tb_assert_spec! {
	pub CertificateForgerySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("cert_valid_accepted", exactly!(1u32)),
			("cert_wrong_key_rejected", exactly!(1u32)),
			("cert_reject_all_rejected", exactly!(1u32))
		]
	}
}

tb_process_spec! {
	pub CertificateForgeryProcess,
	events {
		observable {
			"cert_valid_accepted",
			"cert_wrong_key_rejected",
			"cert_reject_all_rejected"
		}
		hidden { }
	}
	states {
		Idle => { "cert_valid_accepted" => ValidDone },
		ValidDone => { "cert_wrong_key_rejected" => WrongKeyDone },
		WrongKeyDone => { "cert_reject_all_rejected" => Complete },
		Complete => { }
	}
	terminal { Complete }
	annotations { description: "Certificate Forgery: X.509 validation enforcement" }
}

tb_scenario! {
	name: certificate_forgery,
	config: ScenarioConf::<()>::builder()
		.with_spec(CertificateForgerySpec::latest())
		.with_csp(CertificateForgeryProcess)
		.build(),
	environment Bare {
		exec: |trace| async move {
			CertificateForgeryScenario::run((trace,)).await
		}
	}
}

job! {
	name: CertificateForgeryScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		use tightbeam::crypto::ecies::Secp256k1EciesMessage;
		use tightbeam::crypto::profiles::DefaultCryptoProvider;

		let materials = ServerMaterials::generate();
		let profile = default_security_profile();

		// ========================================
		// Test 1: Valid certificate with correct pinning - should SUCCEED
		// ========================================
		{
			// Create a validator that pins to the server's actual public key
			let valid_pinning = SingleKeyPinning::new(&materials.certificate);

			let mut server = EciesHandshakeServer::<DefaultCryptoProvider>::new(
				Arc::clone(&materials.key_provider),
				Arc::clone(&materials.certificate),
				None,
				None,
			)
			.with_supported_profiles(vec![profile]);

			let mut client = EciesHandshakeClient::<DefaultCryptoProvider, Secp256k1EciesMessage>::new(None)
				.with_certificate_validator(Arc::new(valid_pinning));

			// Perform handshake
			let client_hello = client.build_client_hello()?;
			let server_handshake = server.process_client_hello(&client_hello).await?;
			let client_kex = client.process_server_handshake(&server_handshake).await?;
			let _server_result = server.process_client_key_exchange(&client_kex).await;

			// If we got here without error, the valid certificate was accepted
			trace.event("cert_valid_accepted")?;
		}

		// ========================================
		// Test 2: Wrong public key pinning - should FAIL
		// ========================================
		{
			// Create a validator that expects a DIFFERENT public key
			let wrong_pinning = SingleKeyPinning::wrong_key();

			let mut server = EciesHandshakeServer::<DefaultCryptoProvider>::new(
				Arc::clone(&materials.key_provider),
				Arc::clone(&materials.certificate),
				None,
				None,
			)
			.with_supported_profiles(vec![profile]);

			let mut client = EciesHandshakeClient::<DefaultCryptoProvider, Secp256k1EciesMessage>::new(None)
				.with_certificate_validator(Arc::new(wrong_pinning));

			// Perform handshake - should fail at process_server_handshake
			let client_hello = client.build_client_hello()?;
			let server_handshake = server.process_client_hello(&client_hello).await?;

			match client.process_server_handshake(&server_handshake).await {
				Err(_) => {
					// Expected - certificate rejected due to wrong public key
					trace.event("cert_wrong_key_rejected")?;
				}
				Ok(_) => {
					return Err(expectation_failure("certificate with wrong pinned key should be rejected"));
				}
			}
		}

		// ========================================
		// Test 3: RejectAll validator - should FAIL
		// ========================================
		{
			let reject_all = RejectAllValidator;

			let mut server = EciesHandshakeServer::<DefaultCryptoProvider>::new(
				Arc::clone(&materials.key_provider),
				Arc::clone(&materials.certificate),
				None,
				None,
			)
			.with_supported_profiles(vec![profile]);

			let mut client = EciesHandshakeClient::<DefaultCryptoProvider, Secp256k1EciesMessage>::new(None)
				.with_certificate_validator(Arc::new(reject_all));

			// Perform handshake - should fail at process_server_handshake
			let client_hello = client.build_client_hello()?;
			let server_handshake = server.process_client_hello(&client_hello).await?;

			match client.process_server_handshake(&server_handshake).await {
				Err(_) => {
					// Expected - all certificates rejected
					trace.event("cert_reject_all_rejected")?;
				}
				Ok(_) => {
					return Err(expectation_failure("RejectAll validator should reject all certificates"));
				}
			}
		}

		Ok(())
	}
}
