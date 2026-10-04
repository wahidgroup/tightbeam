//! # Certificate forgery threat
//!
//! ## Weakness
//! If the handshake does not enforce a configured certificate validator, a
//! forged or untrusted certificate can pass validation and be accepted.
//!
//! ## Attack
//! A certificate bearing the wrong (forged) public key is presented during the
//! handshake alongside a genuine certificate, exercising the configured
//! validators (here, key pinning).
//!
//! ## Expected control
//! Certificate validation MUST be enforced during the handshake: a forged
//! certificate MUST be rejected and a valid certificate MUST pass. Validator
//! configuration is the application's responsibility.
//!
//! ## References
//! - CWE-295: Improper Certificate Validation <https://cwe.mitre.org/data/definitions/295.html>
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>
//! - CAPEC-459: Creating a Rogue Certification Authority Certificate
//!   <https://capec.mitre.org/data/definitions/459.html>
//! - RFC 5280 §6: Certification Path Validation

use std::sync::Arc;

use tightbeam::{
	crypto::x509::{error::CertificateValidationError, policy::CertificateValidation, Certificate},
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	transport::handshake::Handshake,
	utils::urn::Urn,
	TightBeamError,
};

use crate::common::security::{ecies_client_config, ecies_server_config};
use crate::security::common::{default_security_profile, expectation_failure, ServerMaterials};

pub(crate) const CERT_REJECT_ALL_REJECTED: Urn<'static> =
	tightbeam::urn!("test", "event:certificate-forgery/cert-reject-all-rejected");
pub(crate) const CERT_VALID_ACCEPTED: Urn<'static> =
	tightbeam::urn!("test", "event:certificate-forgery/cert-valid-accepted");
pub(crate) const CERT_WRONG_KEY_REJECTED: Urn<'static> =
	tightbeam::urn!("test", "event:certificate-forgery/cert-wrong-key-rejected");

/// A validator that rejects every certificate, for the rejection-path test.
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

	/// Create a pinning validator that accepts a DIFFERENT key, for the
	/// rejection test.
	pub fn wrong_key() -> Self {
		// These bytes match no real certificate.
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
		assertions: [
			(CERT_VALID_ACCEPTED, exactly!(1u32)),
			(CERT_WRONG_KEY_REJECTED, exactly!(1u32)),
			(CERT_REJECT_ALL_REJECTED, exactly!(1u32))
		]
	}
}

tb_process_spec! {
	pub CertificateForgeryProcess,
	events {
		observable {
			CERT_VALID_ACCEPTED,
			CERT_WRONG_KEY_REJECTED,
			CERT_REJECT_ALL_REJECTED
		}
		hidden { }
	}
	states {
		Idle => { CERT_VALID_ACCEPTED => ValidDone },
		ValidDone => { CERT_WRONG_KEY_REJECTED => WrongKeyDone },
		WrongKeyDone => { CERT_REJECT_ALL_REJECTED => Complete },
		Complete => { }
	}
	terminal { Complete }
	annotations { description: "Certificate Forgery: X.509 validation enforcement" }
}

tb_scenario! {
	name: certificate_forgery,
	config: ScenarioConfig::builder()
		.with_spec(CertificateForgerySpec::latest())
		.with_csp(CertificateForgeryProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			CertificateForgeryScenario::run((trace.into(),)).await
		}
	}
}

job! {
	name: CertificateForgeryScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		use tightbeam::crypto::profiles::DefaultCryptoProvider;

		let materials = ServerMaterials::generate();
		let profile = default_security_profile();

		// Test 1: A valid certificate with correct pinning succeeds.
		{
			let valid_pinning = SingleKeyPinning::new(&materials.certificate);

			let server_config = ecies_server_config::<DefaultCryptoProvider>(&materials, [profile]);
			let mut server = Handshake::server(server_config);

			let config = ecies_client_config::<DefaultCryptoProvider>(Arc::new(valid_pinning));
			let mut client = Handshake::client(config);

			let reply = server.reply(client.start()?).await?;
			let closing = client.respond(reply).await?;
			server.finish(closing).await?;

			// Reaching this point without an error means that the valid
			// certificate was accepted.
			trace.event(CERT_VALID_ACCEPTED)?;
		}

		// Test 2: Pinning a wrong public key fails the handshake.
		{
			let wrong_pinning = SingleKeyPinning::wrong_key();

			let server_config = ecies_server_config::<DefaultCryptoProvider>(&materials, [profile]);
			let mut server = Handshake::server(server_config);

			let config = ecies_client_config::<DefaultCryptoProvider>(Arc::new(wrong_pinning));
			let mut client = Handshake::client(config);

			// Run the handshake, which fails when the client reads the reply.
			let reply = server.reply(client.start()?).await?;
			match client.respond(reply).await {
				Err(_) => {
					trace.event(CERT_WRONG_KEY_REJECTED)?;
				}
				Ok(_) => {
					return Err(expectation_failure("certificate with wrong pinned key should be rejected"));
				}
			}
		}

		// Test 3: The RejectAll validator fails the handshake.
		{
			let reject_all = RejectAllValidator;

			let server_config = ecies_server_config::<DefaultCryptoProvider>(&materials, [profile]);
			let mut server = Handshake::server(server_config);

			let config = ecies_client_config::<DefaultCryptoProvider>(Arc::new(reject_all));
			let mut client = Handshake::client(config);

			// Run the handshake, which fails when the client reads the reply.
			let reply = server.reply(client.start()?).await?;
			match client.respond(reply).await {
				Err(_) => {
					trace.event(CERT_REJECT_ALL_REJECTED)?;
				}
				Ok(_) => {
					return Err(expectation_failure("RejectAll validator should reject all certificates"));
				}
			}
		}

		Ok(())
	}
}
