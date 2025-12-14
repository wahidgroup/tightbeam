//! Cryptographic verification policies.
//!
//! This module provides traits for algorithm-agnostic signature verification.

use core::fmt::Debug;

use crate::crypto::x509::error::CertificateValidationError;
use crate::der::oid::ObjectIdentifier;

#[cfg(feature = "derive")]
use crate::Errorizable;

/// Errors specific to cryptographic policy enforcement
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum CryptoPolicyError {
	#[cfg_attr(feature = "derive", error("Unsupported algorithm: {0}"))]
	UnsupportedAlgorithm(ObjectIdentifier),
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for CryptoPolicyError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			CryptoPolicyError::UnsupportedAlgorithm(oid) => write!(f, "Unsupported algorithm: {}", oid),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for CryptoPolicyError {}

/// Trait for cryptographic verification policies.
///
/// This trait defines how to verify signatures in an object-safe manner.
/// Implementations handle algorithm-specific parsing and verification internally,
/// allowing callers to remain algorithm-agnostic.
///
/// # Object Safety
///
/// This trait is object-safe and can be used with `Arc<dyn VerificationPolicy>`.
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
#[cfg(all(feature = "secp256k1", feature = "signature"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct Secp256k1Policy;

#[cfg(all(feature = "secp256k1", feature = "signature"))]
impl VerificationPolicy for Secp256k1Policy {
	fn verify_signature(
		&self,
		_algorithm_oid: &ObjectIdentifier,
		public_key_der: &[u8],
		message: &[u8],
		signature: &[u8],
	) -> Result<(), CertificateValidationError> {
		use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};
		use crate::crypto::sign::Verifier;
		use crate::spki::DecodePublicKey;

		let verifying_key = Secp256k1VerifyingKey::from_public_key_der(public_key_der)?;
		let sig = Secp256k1Signature::try_from(signature)?;

		verifying_key.verify(message, &sig)?;
		Ok(())
	}
}
