use crate::crypto::sign::SignatureEncoding;
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

/// Trait for cryptographic verification policies
///
/// This trait defines how to map algorithm OIDs to concrete verification
/// operations. Implementations specify which algorithms are accepted and
/// how to verify signatures using those algorithms.
pub trait VerificationPolicy {
	/// The type of verifying key this policy produces
	type VerifyingKey;
	type Signature: SignatureEncoding;

	/// Error type for policy operations
	type Error;

	/// Map an algorithm OID and public key bytes to a verifying key
	///
	/// # Arguments
	/// * `algorithm_oid` - The signature algorithm OID from the certificate
	/// * `public_key_bytes` - The raw public key bytes
	///
	/// # Returns
	/// * `Ok(VerifyingKey)` if the algorithm is supported and key is valid
	/// * `Err(Error)` if the algorithm is unsupported or key is invalid
	fn to_verifying_key(
		&self,
		algorithm_oid: &ObjectIdentifier,
		public_key_bytes: &[u8],
	) -> Result<Self::VerifyingKey, Self::Error>;
}
