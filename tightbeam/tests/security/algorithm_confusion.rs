//! # Signature algorithm-confusion threat
//!
//! ## Weakness
//! If `Secp256k1Policy::verify_signature` ignored its `algorithm_oid` argument
//! and verified the bytes as secp256k1 ECDSA unconditionally, an attacker could
//! make a relying party accept a signature under an algorithm it never agreed
//! to.
//!
//! ## Attack
//! An attacker takes a signature that verifies under the real ECDSA OID and
//! presents it under an unrelated algorithm OID (here AES-256-GCM). A flawed
//! policy accepts it.
//!
//! ## Expected control
//! A sound policy MUST reject an algorithm OID it does not support. It MUST
//! refuse under an unrelated OID (`UnsupportedAlgorithm`) the same key,
//! message, and signature that it accepts under the genuine ECDSA OID.
//!
//! ## References
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>
//! - CAPEC-475: Signature Spoofing by Improper Validation <https://capec.mitre.org/data/definitions/475.html>
//! - RFC 5280 §4.1.1.2: signatureAlgorithm identifier binding

use tightbeam::{
	crypto::{
		hash::Sha3_256,
		policy::{Secp256k1Policy, VerificationPolicy},
		sign::{ecdsa::Secp256k1Signature, CanonicalSigner},
		x509::error::CertificateValidationError::UnsupportedAlgorithm,
	},
	der::Encode,
	oids::{AES_256_GCM, SIGNER_ECDSA_WITH_SHA3_256},
	testing::{TestCertificate, TestKey},
};

use crate::common::result::TestResult;

/// The policy refuses, under an unrelated OID, the key, message, and
/// signature that it accepts under the genuine ECDSA OID.
#[test]
fn a_policy_refuses_a_signature_under_a_foreign_algorithm() -> TestResult {
	let signing_key = TestKey::insecure_fixed_signing();
	let cert = TestCertificate::self_signed(&signing_key);
	let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;

	let message: &[u8] = b"tbs-certificate-bytes";
	let signature: Secp256k1Signature = signing_key.sign_canonical::<Sha3_256>(message)?;
	let signature_bytes = signature.to_bytes();

	// The signature verifies under the real secp256k1 ECDSA OID.
	let policy = Secp256k1Policy::default();
	policy.verify_signature(&SIGNER_ECDSA_WITH_SHA3_256, &spki_der, message, signature_bytes.as_ref())?;

	// Under an unrelated algorithm OID a sound policy must refuse it. The
	// policy holds one algorithm, so it refuses the foreign OID by name before
	// it reads the key.
	let foreign = policy.verify_signature(&AES_256_GCM, &spki_der, message, signature_bytes.as_ref());
	assert!(matches!(foreign, Err(UnsupportedAlgorithm(oid)) if oid == AES_256_GCM));
	Ok(())
}
