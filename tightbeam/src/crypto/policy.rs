//! Cryptographic verification policies.
//!
//! This module provides traits for algorithm-agnostic signature verification.

use core::fmt::Debug;

#[cfg(feature = "x509")]
use crate::crypto::x509::error::CertificateValidationError;
use crate::der::oid::ObjectIdentifier;

/// Errors specific to cryptographic policy enforcement
///
/// Deliberately does not derive `Errorizable`: this module builds without
/// the `derive` feature, so the message strings live in exactly one place --
/// the `impl_error_display!` block below.
#[derive(Debug)]
pub enum CryptoPolicyError {
	/// Algorithm not supported by this policy
	UnsupportedAlgorithm(ObjectIdentifier),
}

crate::impl_error_display!(unconditional CryptoPolicyError {
	UnsupportedAlgorithm(oid) => "Unsupported algorithm: {oid}",
});

/// Trait for cryptographic verification policies.
///
/// This trait defines how to verify signatures in an object-safe manner.
/// Implementations handle algorithm-specific parsing and verification internally,
/// allowing callers to remain algorithm-agnostic.
///
/// # Object Safety
///
/// This trait is object-safe and can be used with `Arc<dyn VerificationPolicy>`.
#[cfg(feature = "x509")]
pub trait VerificationPolicy: Send + Sync + Debug {
	/// Verify a signature given algorithm OID, public key, message, and signature bytes.
	///
	/// The implementation handles all algorithm-specific logic internally:
	/// - Parsing public key bytes into the appropriate key type
	/// - Parsing signature bytes into the appropriate signature type
	/// - Performing the cryptographic verification
	///
	/// # Arguments
	/// * `algorithm_oid` - The signature algorithm OID from the certificate
	/// * `public_key_der` - DER-encoded public key of the signer
	/// * `message` - The message that was signed (e.g., TBS certificate DER)
	/// * `signature` - Raw signature bytes
	///
	/// # Returns
	/// * `Ok(())` if the signature is valid
	/// * `Err(CertificateValidationError)` if verification fails
	fn verify_signature(
		&self,
		algorithm_oid: &ObjectIdentifier,
		public_key_der: &[u8],
		message: &[u8],
		signature: &[u8],
	) -> Result<(), CertificateValidationError>;
}

// ============================================================================
// Secp256k1 Policy Implementation
// ============================================================================

/// Verification policy for secp256k1 ECDSA signatures.
///
/// Handles parsing and verification of secp256k1 signatures internally.
/// Supports ECDSA signatures on the secp256k1 curve.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct Secp256k1Policy;

#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
impl VerificationPolicy for Secp256k1Policy {
	fn verify_signature(
		&self,
		algorithm_oid: &ObjectIdentifier,
		public_key_der: &[u8],
		message: &[u8],
		signature: &[u8],
	) -> Result<(), CertificateValidationError> {
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};
		use crate::crypto::sign::verify_canonical;
		use crate::oids::SIGNER_ECDSA_WITH_SHA3_256;
		use crate::spki::DecodePublicKey;

		// This policy implements exactly one algorithm; refuse any other advertised OID.
		if algorithm_oid != &SIGNER_ECDSA_WITH_SHA3_256 {
			return Err(CertificateValidationError::UnsupportedAlgorithm(*algorithm_oid));
		}

		// RFC 5280 §6.1.3(a)(1): cryptographic signature verification primitive
		// under the canonical convention (SHA3-256 prehash).
		let verifying_key = Secp256k1VerifyingKey::from_public_key_der(public_key_der)?;
		let sig = Secp256k1Signature::try_from(signature)?;

		verify_canonical::<Sha3_256, _>(&verifying_key, message, &sig)?;
		Ok(())
	}
}

#[cfg(all(
	test,
	feature = "secp256k1",
	feature = "signature",
	feature = "x509",
	feature = "sha3"
))]
mod tests {
	use signature::DigestSigner;

	use super::{Secp256k1Policy, VerificationPolicy};
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
	use crate::oids::SIGNER_ECDSA_WITH_SHA3_256;
	use crate::spki::EncodePublicKey;
	use crate::testing::create_test_signing_key;

	/// Interop: a signature produced by the `ecdsa` crate's own
	/// `DigestSigner<Sha3_256>` path -- independent of this crate's
	/// `sign_canonical` -- must verify under the advertised
	/// ecdsa-with-SHA3-256 OID.
	#[test]
	fn verifies_independent_sha3_ecdsa_signature() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key: Secp256k1SigningKey = create_test_signing_key();
		let message = b"independent sha3-ecdsa interop";

		let mut digest = Sha3_256::default();
		digest::Digest::update(&mut digest, message);

		let signature: Secp256k1Signature = signing_key.try_sign_digest(digest)?;
		let public_key_der = signing_key.verifying_key().to_public_key_der()?;
		Secp256k1Policy.verify_signature(
			&SIGNER_ECDSA_WITH_SHA3_256,
			public_key_der.as_bytes(),
			message,
			&signature.to_bytes(),
		)?;

		Ok(())
	}
}
