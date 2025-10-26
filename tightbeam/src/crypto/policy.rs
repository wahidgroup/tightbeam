use crate::crypto::sign::elliptic_curve::{CurveArithmetic, PublicKey};
use crate::der::oid::ObjectIdentifier;

#[cfg(feature = "derive")]
use crate::Errorizable;

/// Errors specific to X.509 certificate validation
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum CryptoPolicyError {
	#[cfg_attr(feature = "derive", error("Unsupported algorithm: {0}"))]
	UnsupportedAlgorithm(ObjectIdentifier),
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for CertificateValidationError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			CryptoPolicyError::UnsupportedAlgorithm(oid) => write!(f, "Unsupported algorithm: {}", oid),
		}
	}
}

/// Trait for cryptographic verification policies
///
/// This trait defines how to map algorithm OIDs to concrete verification
/// operations. Implementations specify which algorithms are accepted and
/// how to verify signatures using those algorithms.
pub trait VerificationPolicy {
	/// Check if an algorithm OID is supported by this policy
	///
	/// # Arguments
	/// - `algorithm_oid` - The algorithm OID to check
	/// - `public_key_bytes` - The public key bytes to check
	fn to_verifying_key<C: CurveArithmetic>(
		&self,
		algorithm_oid: &ObjectIdentifier,
		public_key_bytes: &[u8],
	) -> Result<PublicKey<C>, CryptoPolicyError>;
}
