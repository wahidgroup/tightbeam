//! # Certificate forgery threat
//!
//! ## Weakness
//! If the handshake skips a configured certificate validator, a forged or
//! untrusted certificate can pass validation, and the endpoint accepts it.
//!
//! ## Attack
//! During the handshake, a peer presents a certificate that carries the wrong
//! (forged) public key, beside a genuine certificate, so the scenarios run the
//! configured validators (here, key pinning).
//!
//! ## Expected control
//! The handshake MUST enforce certificate validation: it MUST reject a forged
//! certificate, and a valid certificate MUST pass. Validator configuration is
//! the application's responsibility.
//!
//! The handshake carries the refusal of the validator:
//!
//! - `PublicKeyNotPinned` from the pin of a wrong key.
//! - `CertificateDenied` from the validator that refuses every certificate.
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
	crypto::x509::{
		error::CertificateValidationError::{self, CertificateDenied, PublicKeyNotPinned},
		policy::CertificateValidation,
		Certificate,
	},
	exactly,
	instrumentation::events,
	tb_assert_spec, tb_scenario,
	testing::SetupEnv,
	TightBeamError,
};

use crate::security::common::{HandshakeBackendKind, ServerMaterials};
use crate::security::live::LiveHandshake;

/// A validator that rejects every certificate, for the rejection-path test.
#[derive(Debug, Clone, Copy)]
pub struct RejectAllValidator;

impl CertificateValidation for RejectAllValidator {
	fn evaluate(&self, _cert: &Certificate) -> Result<(), CertificateValidationError> {
		Err(CertificateDenied)
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

	/// Create a pinning validator that accepts another key, for the rejection
	/// test.
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
			Err(PublicKeyNotPinned)
		}
	}
}

/// A live HPKE handshake whose client admits its server under the validator
/// that `policy` builds over the server certificate.
fn pinned_under<V>(policy: impl FnOnce(&Certificate) -> V) -> LiveHandshake
where
	V: CertificateValidation + 'static,
{
	let materials = ServerMaterials::generate();
	let validator: Arc<dyn CertificateValidation> = Arc::new(policy(&materials.certificate));
	LiveHandshake::new(HandshakeBackendKind::Hpke, materials).with_server_policy([validator])
}

tb_assert_spec! {
	pub ValidCertificateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2))
		]
	}
}

// A valid certificate under the matching pin completes the handshake on both
// endpoints.
tb_scenario! {
	name: certificate_forgery_valid_certificate_accepted,
	spec: ValidCertificateSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let handshake = pinned_under(SingleKeyPinning::new).audit_client(&trace).audit_server(&trace);
			let outcome = handshake.run().await?;
			let (_client, _server) = outcome.established()?;

			Ok::<(), TightBeamError>(())
		}
	}
}

tb_assert_spec! {
	pub WrongKeySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("certificate/public-key-not-pinned"))
		]
	}
}

// A pin on a wrong public key fails the handshake when the client reads the
// reply.
tb_scenario! {
	name: certificate_forgery_wrong_key_rejected,
	spec: WrongKeySpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let outcome = pinned_under(|_| SingleKeyPinning::wrong_key()).audit_client(&trace).run().await?;
			outcome.refused_by_client("certificate with wrong pinned key should be rejected")
		}
	}
}

tb_assert_spec! {
	pub RejectAllSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("certificate/certificate-denied"))
		]
	}
}

// The RejectAll validator fails the handshake when the client reads the reply.
tb_scenario! {
	name: certificate_forgery_reject_all_rejected,
	spec: RejectAllSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let outcome = pinned_under(|_| RejectAllValidator).audit_client(&trace).run().await?;
			outcome.refused_by_client("RejectAll validator should reject all certificates")
		}
	}
}
