//! Certificate validation policies and strategies.
//!
//! This module provides various certificate validation policies that can be
//! used to validate X.509 certificates according to different trust models.

use core::marker::PhantomData;
use core::time::Duration;

use crate::asn1::GeneralizedTime;
use crate::crypto::hash::Digest;
use crate::crypto::policy::VerificationPolicy;
use crate::crypto::sign::Verifier;
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::utils::validate_certificate_expiry;
use crate::crypto::x509::Certificate;
use crate::der::Encode;

/// Trait for certificate validation strategies.
///
/// This trait allows pluggable certificate validation with different
/// policies and trust models. Implementors can validate certificates
/// against specific requirements.
///
/// For simple validation (pinning, denylists, expiry checks), implement
/// only this trait. For full PKI validation with signature verification,
/// also implement `SignatureVerification`.
pub trait CertificateValidation: Send + Sync {
	/// Perform certificate validation.
	///
	/// This method should perform all validation checks that don't require
	/// cryptographic signature verification (expiry, pinning, denylists, etc.).
	///
	/// # Arguments
	/// * `cert` - The certificate to validate
	///
	/// # Returns
	/// * `Ok(())` if validation succeeds
	/// * `Err(CertificateValidationError)` with specific error details
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError>;
}

/// Trait for certificate validation with cryptographic signature verification.
///
/// This trait extends `CertificateValidation` with the ability to verify
/// signatures. It should only be implemented by validators that perform
/// full PKI validation.
pub trait SignatureVerification: CertificateValidation {
	/// Perform full certificate validation with cryptographic verification.
	///
	/// This method verifies the certificate signature using the provided
	/// verification policy and expected public key.
	///
	/// # Arguments
	/// * `cert` - The certificate to validate
	/// * `curr_time` - Current UNIX timestamp (seconds since epoch)
	/// * `policy` - Verification policy to use for signature validation
	/// * `expected_pub_key` - Public key expected to have signed this certificate
	///
	/// # Returns
	/// * `Ok(())` if validation succeeds
	/// * `Err(CertificateValidationError)` with specific error details
	fn evaluate_with_crypto<P: VerificationPolicy>(
		&self,
		cert: &Certificate,
		curr_time: u64,
		policy: &P,
		expected_pub_key: &[u8],
	) -> Result<(), CertificateValidationError>
	where
		P::VerifyingKey: Verifier<P::Signature>,
		for<'a> P::Signature: TryFrom<&'a [u8]>,
		for<'a> CertificateValidationError: From<<P::Signature as TryFrom<&'a [u8]>>::Error>;
}

// ============================================================================
// Built-in Validators
// ============================================================================

/// Validate only certificate expiry.
///
/// This validator checks if the certificate is within its validity period
/// but does not verify signatures or perform other cryptographic checks.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExpiryValidator;

impl CertificateValidation for ExpiryValidator {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		validate_certificate_expiry(cert)
	}
}

/// Public key pinning validator with const-generic array
///
/// This validator is zero-copy and const-constructible, making it suitable
/// for use in static configurations.
///
/// The const generic parameter `N` specifies the number of pinned keys.
#[derive(Debug, Clone, Copy)]
pub struct PublicKeyPinning<const N: usize> {
	allowed_keys: [&'static [u8]; N],
}

impl<const N: usize> PublicKeyPinning<N> {
	/// Create a new public key pinning validator with the given allowed keys.
	///
	/// This is a const function, allowing creation in const contexts.
	pub const fn new(keys: [&'static [u8]; N]) -> Self {
		Self { allowed_keys: keys }
	}
}

impl<const N: usize> CertificateValidation for PublicKeyPinning<N> {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		let pub_key_bytes = cert.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
		for allowed_key in &self.allowed_keys {
			if *allowed_key == pub_key_bytes {
				return Ok(());
			}
		}

		Err(CertificateValidationError::PublicKeyNotPinned)
	}
}

/// Certificate fingerprint pinning validator with const-generic array.
///
/// This validator is const-constructible, making it suitable for use in static
/// configurations.
///
/// Generic over the digest algorithm and the number of pinned fingerprints.
#[derive(Debug, Clone, Copy)]
pub struct FingerprintPinning<D, const N: usize> {
	allowed_fingerprints: [&'static [u8]; N],
	_digest: PhantomData<D>,
}

impl<D, const N: usize> FingerprintPinning<D, N>
where
	D: Digest,
{
	/// Create a new fingerprint pinning validator with the given allowed fingerprints.
	///
	/// This is a const function, allowing creation in const contexts.
	pub const fn new(fingerprints: [&'static [u8]; N]) -> Self {
		Self { allowed_fingerprints: fingerprints, _digest: PhantomData }
	}
}

impl<D, const N: usize> CertificateValidation for FingerprintPinning<D, N>
where
	D: Digest + Send + Sync,
{
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		let cert_der = cert.to_der()?;
		let fingerprint = D::digest(&cert_der);
		for allowed_fp in &self.allowed_fingerprints {
			if *allowed_fp == fingerprint.as_ref() {
				return Ok(());
			}
		}

		Err(CertificateValidationError::CertificateNotPinned)
	}
}

/// Certificate fingerprint denylist validator with const-generic array.
///
/// This validator is const-constructible, making it suitable for use in
/// static configurations.
#[derive(Debug, Clone, Copy)]
pub struct FingerprintDenylist<D, const N: usize> {
	denied_fingerprints: [&'static [u8]; N],
	_digest: PhantomData<D>,
}

impl<D, const N: usize> FingerprintDenylist<D, N>
where
	D: Digest,
{
	/// Create a new fingerprint denylist validator with the given fingerprints.
	pub const fn new(fingerprints: [&'static [u8]; N]) -> Self {
		Self { denied_fingerprints: fingerprints, _digest: PhantomData }
	}
}

impl<D, const N: usize> CertificateValidation for FingerprintDenylist<D, N>
where
	D: Digest + Send + Sync,
{
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		let cert_der = cert.to_der()?;
		let fingerprint = D::digest(&cert_der);
		for denied_fp in &self.denied_fingerprints {
			if *denied_fp == fingerprint.as_ref() {
				return Err(CertificateValidationError::CertificateDenied);
			}
		}

		Ok(())
	}
}

/// Runtime certificate pinning validator.
///
/// Pins to a specific set of certificates using fingerprint comparison.
/// Unlike `FingerprintPinning<D, N>`, this validator can be created at runtime
/// with dynamic certificate lists, making it suitable for use in builders.
#[cfg(feature = "std")]
#[derive(Clone)]
pub struct RuntimeCertificatePinning<D> {
	fingerprints: Vec<Vec<u8>>,
	_digest: PhantomData<D>,
}

#[cfg(feature = "std")]
impl<D> RuntimeCertificatePinning<D>
where
	D: Digest,
{
	/// Create a new runtime certificate pinning validator from certificates.
	///
	/// Computes fingerprints for each certificate and stores them for validation.
	pub fn from_certificates(certs: impl IntoIterator<Item = Certificate>) -> Result<Self, CertificateValidationError> {
		let mut fingerprints = Vec::new();
		for cert in certs {
			let cert_der = cert.to_der()?;
			let fingerprint = D::digest(&cert_der);
			fingerprints.push(fingerprint.to_vec());
		}

		Ok(Self { fingerprints, _digest: PhantomData })
	}

	/// Create validator directly from pre-computed fingerprints.
	///
	/// This method allows creating a validator without cloning certificates,
	/// as fingerprints can be computed once and passed directly.
	pub fn from_fingerprints(fingerprints: impl IntoIterator<Item = Vec<u8>>) -> Self {
		Self { fingerprints: fingerprints.into_iter().collect(), _digest: PhantomData }
	}
}

#[cfg(feature = "std")]
impl<D> CertificateValidation for RuntimeCertificatePinning<D>
where
	D: Digest + Send + Sync,
{
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		let cert_der = cert.to_der()?;
		let fingerprint = D::digest(&cert_der);
		for allowed_fp in &self.fingerprints {
			if allowed_fp.as_slice() == fingerprint.as_ref() {
				return Ok(());
			}
		}

		Err(CertificateValidationError::CertificateNotPinned)
	}
}

/// Full PKI certificate validator.
///
/// Validates:
/// 1. Certificate expiration
/// 2. Signature verification with expected public key
/// 3. Optional trust chain validation
#[derive(Default, Clone)]
pub struct FullValidator {
	trust_chain: Vec<Certificate>,
}

impl FullValidator {
	/// Add a trust chain to the validator.
	///
	/// # Arguments
	/// * `trust_chain` - Vector of certificates representing the trust chain
	pub fn with_trust_chain(mut self, trust_chain: Vec<Certificate>) -> Self {
		self.trust_chain = trust_chain;
		self
	}
}

impl CertificateValidation for FullValidator {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		// Check expiry first (simple validation)
		validate_certificate_expiry(cert)
	}
}

impl SignatureVerification for FullValidator {
	fn evaluate_with_crypto<P: VerificationPolicy>(
		&self,
		cert: &Certificate,
		curr_time: u64,
		policy: &P,
		expected_pub_key: &[u8],
	) -> Result<(), CertificateValidationError>
	where
		P::VerifyingKey: Verifier<P::Signature>,
		for<'a> P::Signature: TryFrom<&'a [u8]>,
		for<'a> CertificateValidationError: From<<P::Signature as TryFrom<&'a [u8]>>::Error>,
	{
		use crate::der::Encode;

		// Validate expiration with provided time
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

		// Extract and validate the subject public key
		let subject_public_key = cert.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
		if subject_public_key.is_empty() {
			return Err(CertificateValidationError::EmptyPublicKey);
		}

		// Verify signature
		let signature_bytes = cert.signature.raw_bytes();
		if signature_bytes.is_empty() {
			return Err(CertificateValidationError::EmptySignature);
		}

		// Verify algorithm consistency
		let algorithm_oid = &cert.signature_algorithm.oid;
		if cert.signature_algorithm.oid != cert.tbs_certificate.signature.oid {
			return Err(CertificateValidationError::AlgorithmMismatch);
		}

		let tbs_der = cert.tbs_certificate.to_der()?;
		let signature = P::Signature::try_from(signature_bytes)?;
		let verifying_key = policy
			.to_verifying_key(algorithm_oid, expected_pub_key)
			.map_err(|_| CertificateValidationError::UnsupportedAlgorithm(*algorithm_oid))?;

		verifying_key.verify(&tbs_der, &signature)?;
		Ok(())
	}
}

/// Chain multiple validators together.
///
/// All validators must succeed for the certificate to be accepted.
/// Validators are evaluated in order. This validator only chains
/// simple `evaluate()` calls and does not support signature verification.
#[cfg(feature = "std")]
#[derive(Default)]
pub struct ChainValidator {
	validators: Vec<Box<dyn CertificateValidation>>,
}

#[cfg(feature = "std")]
impl ChainValidator {
	/// Add a validator to the chain.
	#[allow(clippy::should_implement_trait)]
	pub fn add(mut self, validator: Box<dyn CertificateValidation>) -> Self {
		self.validators.push(validator);
		self
	}
}

#[cfg(feature = "std")]
impl CertificateValidation for ChainValidator {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		for validator in &self.validators {
			validator.evaluate(cert)?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use crate::crypto::x509::Certificate;

	// Helper function to get an expired certificate
	fn get_expired_test_cert() -> Certificate {
		// This certificate expired on August 17, 2019
		crate::pem! {"
			-----BEGIN CERTIFICATE-----
			MIIF1TCCBVugAwIBAgIQdBJ26pggQyU+isEPM912FDAKBggqhkjOPQQDAzByMQsw
			CQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xETAP
			BgNVBAoMCFNTTCBDb3JwMS4wLAYDVQQDDCVTU0wuY29tIEVWIFNTTCBJbnRlcm1l
			ZGlhdGUgQ0EgRUNDIFIyMB4XDTE5MDgxNjIyMzU1N1oXDTE5MDgxNzIyMzU1N1ow
			gcgxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3Rv
			bjERMA8GA1UECgwIU1NMIENvcnAxFjAUBgNVBAUTDU5WMjAwODE2MTQyNDMxHzAd
			BgNVBAMMFmV4cGlyZWQtZWNjLWV2LnNzbC5jb20xHTAbBgNVBA8MFFByaXZhdGUg
			T3JnYW5pemF0aW9uMRcwFQYLKwYBBAGCNzwCAQIMBk5ldmFkYTETMBEGCysGAQQB
			gjc8AgEDEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABKFkgNgOHrsYyyJHlGXK
			6C6SupADk+CLOKpMuoIdduURE4k5aXkmQ2yacYNmfqTTgC4oss/c2swxX9KDZdjW
			PYpFXfeCkorzKcX6RDJdUjD/78TiAT7fIyqcNyxuRpr4bqOCA10wggNZMB8GA1Ud
			IwQYMBaAFITu+Hk+CGR2SGQ59bG/iwJeC7wnMH4GCCsGAQUFBwEBBHIwcDBMBggr
			BgEFBQcwAoZAaHR0cDovL3d3dy5zc2wuY29tL3JlcG9zaXRvcnkvU1NMY29tLVN1
			YkNBLUVWLVNTTC1FQ0MtMzg0LVIyLmNydDAgBggrBgEFBQcwAYYUaHR0cDovL29j
			c3BzLnNzbC5jb20wPQYDVR0RBDYwNIIWZXhwaXJlZC1lY2MtZXYuc3NsLmNvbYIa
			d3d3LmV4cGlyZWQtZWNjLWV2LnNzbC5jb20wXwYDVR0gBFgwVjAHBgVngQwBATAN
			BgsqhGgBhvZ3AgUBATA8BgwrBgEEAYKpMAEDAQQwLDAqBggrBgEFBQcCARYeaHR0
			cHM6Ly93d3cuc3NsLmNvbS9yZXBvc2l0b3J5MB0GA1UdJQQWMBQGCCsGAQUFBwMC
			BggrBgEFBQcDATBHBgNVHR8EQDA+MDygOqA4hjZodHRwOi8vY3Jscy5zc2wuY29t
			L1NTTGNvbS1TdWJDQS1FVi1TU0wtRUNDLTM4NC1SMi5jcmwwHQYDVR0OBBYEFNK1
			Fhn8lNacFjqY/nVutrEtu8JTMA4GA1UdDwEB/wQEAwIHgDCCAX0GCisGAQQB1nkC
			BAIEggFtBIIBaQFnAHUAdH7agzGtMxCRIZzOJU9CcMK//V5CIAjGNzV55hB7zFYA
			AAFsnJvm3QAABAMARjBEAiAN3B7UPSzzszy+uYfXAZXKfHp6X8vkFL6FsvDknpv9
			cQIgTcE3kmHDPlQRwhkccghbl/ekwgY8CZHOSYmQcZzAKhoAdgDuS723dc5guuFC
			aR+r4Z5mow9+X7By2IMAxHuJeqj9ywAAAWycm+XxAAAEAwBHMEUCIF8Z0jTHQ0bU
			xRMWFVkPo/Fq8taoiTMF9rAX4/QZtmdNAiEA2kodKU2CXO2WOT257aF0v2gBLh7T
			2f8rrj8MYf4A1soAdgBVgdTCFpA2AUrqC5tXPFPwwOQ4eHAlCBcvo6odBxPTDAAA
			AWycm+ZjAAAEAwBHMEUCIQC/j+yfrh55hcKfaGRBvIOX/Wf+NWy/AUep9UiQaV/0
			oQIgO2WX6jOEyXN9ZtBDTxaspPhIcCIWOXNfn9PkzrEzaWQwCgYIKoZIzj0EAwMD
			aAAwZQIxAIM0MOzr0GX3Zeg3OZCOEKYe/yIXT2FlDMMVAFK0WdHI+lMVwQGacR0A
			+9Cvs7zTlQIwLkVrf3XF+P3afMrGhljvWAqPNHpf/jJsddq0DmSHgITOWCJXfytT
			dLAFZesIxt4p
			-----END CERTIFICATE-----
		"}
		.expect("Failed to parse expired certificate")
	}

	// Test 4: Direct validation of expired certificate
	#[test]
	fn test_expiry_validator_rejects_expired_cert() {
		let expired_cert = get_expired_test_cert();
		let validator = ExpiryValidator;

		// This certificate expired on August 17, 2019, so it should be rejected
		let result = validator.evaluate(&expired_cert);
		assert!(result.is_err(), "Expired certificate should be rejected");

		// Verify it's specifically an expiry error
		match result {
			Err(CertificateValidationError::Expired) => {
				// Expected error
			}
			other => panic!("Expected Expired error, got: {other:?}"),
		}
	}
}
