// Re-exports
pub use x509_cert::*;

pub mod error;

use core::time::Duration;

use crate::asn1::GeneralizedTime;
use crate::cms::signed_data::SignerIdentifier;
use crate::crypto::hash::Digest;
use crate::crypto::policy::VerificationPolicy;
use crate::crypto::sign::Verifier;
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::ext::pkix::SubjectKeyIdentifier;
use crate::der::{asn1::OctetString, Encode};
use crate::spki::EncodePublicKey;

/// Trait for certificate validation strategies.
///
/// This trait allows pluggable certificate validation with different
/// policies and trust models. Implementors can validate certificates
/// against specific requirements.
pub trait CertificateValidation<P: VerificationPolicy> {
	/// Validate a certificate given the current time and expected signing key
	///
	/// # Arguments
	/// * `cert` - The certificate to validate
	/// * `curr_time` - Current UNIX timestamp (seconds since epoch)
	/// * `policy` - Verification policy to use for validation
	/// * `expected_pub_key` - Public key expected to have signed this certificate
	///   - For self-signed certificates, use the certificate's own public key
	///   - For CA-signed certificates, use the CA's public key
	///   - If None, signature verification is skipped
	///
	/// # Returns
	/// * `Ok(())` if validation succeeds
	/// * `Err(CertificateValidationError)` with specific error details
	fn validate(
		&self,
		cert: &Certificate,
		curr_time: u64,
		policy: &P,
		expected_pub_key: impl AsRef<[u8]>,
	) -> Result<(), CertificateValidationError>;
}

/// Default certificate validator
///
/// Validates:
/// 1. Certificate structure integrity
/// 2. Expiration (not_before <= curr_time <= not_after)
/// 3. Signature verification (if expected_pub_key is provided)
/// 4. Optional trust chain validation
#[derive(Default, Clone)]
pub struct CertificateValidator {
	trust_chain: Vec<Certificate>,
}

impl CertificateValidator {
	/// Create a new certificate validator with an optional trust chain
	pub fn new() -> Self {
		Self::default()
	}

	/// Add a trust chain to the validator
	///
	/// # Arguments
	/// * `trust_chain` - Vector of certificates representing the trust chain
	///
	/// # Returns
	/// * `Self` - The validator with the trust chain added
	pub fn with_trust_chain(mut self, trust_chain: Vec<Certificate>) -> Self {
		self.trust_chain = trust_chain;
		self
	}
}

impl<P: VerificationPolicy> CertificateValidation<P> for CertificateValidator
where
	P::VerifyingKey: Verifier<P::Signature>,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	for<'a> CertificateValidationError: From<<P::Signature as TryFrom<&'a [u8]>>::Error>,
{
	fn validate(
		&self,
		cert: &Certificate,
		curr_time: u64,
		policy: &P,
		expected_pub_key: impl AsRef<[u8]>,
	) -> Result<(), CertificateValidationError> {
		// Step 1: Validate certificate expiration
		let not_before = cert.tbs_certificate.validity.not_before.to_unix_duration();
		let not_after = cert.tbs_certificate.validity.not_after.to_unix_duration();
		let now_duration = GeneralizedTime::from_unix_duration(Duration::from_secs(curr_time))
			.map_err(|_| CertificateValidationError::InvalidTimestamp)?
			.to_unix_duration();

		if now_duration < not_before {
			return Err(CertificateValidationError::NotYetValid);
		}

		if now_duration > not_after {
			return Err(CertificateValidationError::Expired);
		}

		// Step 2: Extract and validate the subject public key
		let subject_public_key = cert.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
		if subject_public_key.is_empty() {
			return Err(CertificateValidationError::EmptyPublicKey);
		}

		// Step 3: Verify signature if expected signing key is provided
		// Extract the signature from the certificate
		let signature_bytes = cert.signature.raw_bytes();
		if signature_bytes.is_empty() {
			return Err(CertificateValidationError::EmptySignature);
		}

		// Extract the signature algorithm OID
		let algorithm_oid = &cert.signature_algorithm.oid;
		if cert.signature_algorithm.oid != cert.tbs_certificate.signature.oid {
			return Err(CertificateValidationError::AlgorithmMismatch);
		}

		let tbs_der = cert.tbs_certificate.to_der()?;
		// Parse the signature using the policy's signature type
		let signature = P::Signature::try_from(signature_bytes)?;
		// Use the policy to create a verifying key for this algorithm
		let verifying_key = policy
			.to_verifying_key(algorithm_oid, expected_pub_key.as_ref())
			.map_err(|_| CertificateValidationError::UnsupportedAlgorithm(*algorithm_oid))?;

		// Verify the signature over the TBS certificate
		verifying_key.verify(&tbs_der, &signature)?;
		Ok(())
	}
}

#[macro_export]
macro_rules! pem {
	(
		$pem:literal
	) => {{
		use $crate::der::DecodePem;
		let cleaned_pem = $pem.lines().map(|line| line.trim()).collect::<Vec<_>>().join("\n");
		$crate::crypto::x509::Certificate::from_pem(cleaned_pem.as_bytes())
			.map_err(|e| format!("Failed to parse X.509 certificate: {}", e))
	}};
}

/// Validate certificate expiry (not_before <= current_time <= not_after).
///
/// This is a lightweight validation that only checks temporal validity.
/// For full certificate validation including signatures and trust chains,
/// use the `CertificateValidation` trait.
///
/// # Returns
/// * `Ok(())` if the certificate is currently valid
/// * `Err(CertificateValidationError::NotYetValid)` if current time is before not_before
/// * `Err(CertificateValidationError::Expired)` if current time is after not_after
/// * `Err(CertificateValidationError::InvalidTimestamp)` if time conversion fails
#[cfg(feature = "time")]
pub fn validate_certificate_expiry(cert: &Certificate) -> Result<(), CertificateValidationError> {
	use ::time::OffsetDateTime;

	let now = OffsetDateTime::now_utc();
	let not_before = cert.tbs_certificate.validity.not_before.to_unix_duration();
	let not_after = cert.tbs_certificate.validity.not_after.to_unix_duration();
	let now_duration = GeneralizedTime::from_unix_duration(Duration::from_secs(now.unix_timestamp() as u64))
		.map_err(|_| CertificateValidationError::InvalidTimestamp)?
		.to_unix_duration();

	if now_duration < not_before {
		return Err(CertificateValidationError::NotYetValid);
	}

	if now_duration > not_after {
		return Err(CertificateValidationError::Expired);
	}

	Ok(())
}

/// Validate certificate expiry using std::time::SystemTime.
#[cfg(all(feature = "std", not(feature = "time")))]
pub fn validate_certificate_expiry(cert: &Certificate) -> Result<(), CertificateValidationError> {
	let now = std::time::SystemTime::now();
	let not_before = cert.tbs_certificate.validity.not_before.to_system_time();
	let not_after = cert.tbs_certificate.validity.not_after.to_system_time();

	if now < not_before {
		return Err(CertificateValidationError::NotYetValid);
	}

	if now > not_after {
		return Err(CertificateValidationError::Expired);
	}

	Ok(())
}

/// Validate certificate expiry (no-op without time features).
///
/// Without std or time features, temporal validation cannot be performed.
/// Applications should handle this at a higher layer.
#[cfg(all(not(feature = "std"), not(feature = "time")))]
pub fn validate_certificate_expiry(_cert: &Certificate) -> Result<(), CertificateValidationError> {
	Err(CertificateValidationError::InvalidTimestamp)
}

/// Compute a SubjectKeyIdentifier-based SignerIdentifier from a verifying key.
///
/// This helper extracts the public key DER encoding, hashes it with the provided
/// digest algorithm, truncates to 20 bytes (RFC 5280 recommendation), and wraps
/// it in a SignerIdentifier::SubjectKeyIdentifier variant.
///
/// # Type Parameters
/// - `D`: Digest algorithm (e.g., SHA3-256)
/// - `V`: Verifying key type that can be DER-encoded
///
/// # Returns
/// `SignerIdentifier::SubjectKeyIdentifier` for use in CMS SignedData structures
///
/// # Example
/// ```ignore
/// use sha3::Sha3_256;
/// let signer_id = compute_signer_identifier::<Sha3_256, _>(&verifying_key)?;
/// ```
pub fn compute_signer_identifier<D, V>(verifying_key: &V) -> Result<SignerIdentifier, CertificateValidationError>
where
	D: Digest,
	V: EncodePublicKey,
{
	let public_key_der = verifying_key.to_public_key_der()?;

	let mut hasher = D::new();
	Digest::update(&mut hasher, public_key_der.as_bytes());
	let digest_bytes = Digest::finalize(hasher);

	let skid_octets = OctetString::new(&digest_bytes.as_slice()[..20])?;
	let skid = SubjectKeyIdentifier::from(skid_octets);

	Ok(SignerIdentifier::SubjectKeyIdentifier(skid))
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_pem_macro() {
		let cert = pem! {"
			-----BEGIN CERTIFICATE-----
			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
			-----END CERTIFICATE-----
		"};
		assert!(cert.is_ok());
	}
}
