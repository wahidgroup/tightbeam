//! # Certificate trust-anchoring threat
//!
//! ## Weakness
//! If a trust validator checks only certificate expiry, and neither consults
//! its configured `trust_chain` nor verifies a signature, it accepts any
//! unexpired certificate regardless of its issuer.
//!
//! ## Attack
//! An adversary presents a self-signed, unexpired certificate that does not
//! chain to any configured trust anchor, so a flawed validator enables
//! certificate substitution and adversary-in-the-middle impersonation.
//!
//! ## Expected control
//! A validator documented as full PKI validation MUST reject a certificate that
//! does not chain to a configured trust anchor (`CertificateNotTrusted`).
//!
//! ## References
//! - CWE-295: Improper Certificate Validation <https://cwe.mitre.org/data/definitions/295.html>
//! - CAPEC-94: Adversary in the Middle (AiTM) <https://capec.mitre.org/data/definitions/94.html>
//! - RFC 5280 §6: Certification Path Validation

use tightbeam::crypto::x509::{
	error::CertificateValidationError,
	policy::{CertificateValidation, DirectTrustValidator},
};

use crate::common::security::{deterministic_signing_key, random_signing_key, test_certificate};

/// Direct trust refuses a self-signed, unexpired certificate that is no
/// configured anchor.
#[test]
fn certificate_trust() {
	let trusted_cert = test_certificate(&deterministic_signing_key());

	// An attacker holds an unrelated, self-signed, unexpired certificate.
	let attacker_cert = test_certificate(&random_signing_key());
	let validator = DirectTrustValidator::default().with_trust_chain(vec![trusted_cert]);
	let verdict = validator.evaluate(&attacker_cert);

	assert!(
		matches!(verdict, Err(CertificateValidationError::CertificateNotTrusted)),
		"direct trust admitted a certificate outside its anchors"
	);
}
