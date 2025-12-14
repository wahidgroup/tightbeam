//! Certificate trust store
//!
//! This module provides a trait-based abstraction for certificate trust
//! verification, allowing custom implementations for different environments.

use core::fmt::Debug;

use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::utils::validate_certificate_expiry;
use crate::crypto::x509::Certificate;
use crate::der::Encode;

#[cfg(feature = "std")]
mod std_imports {
	pub use std::collections::{HashMap, HashSet};
	pub use std::sync::Arc;

	pub use crate::crypto::hash::Digest;
	pub use crate::crypto::hash::Sha3_256;
	pub use crate::crypto::policy::VerificationPolicy;
}

#[cfg(feature = "std")]
use std_imports::*;

/// Fingerprint type: SHA-256 hash (32 bytes)
pub type Fingerprint = [u8; 32];

// ============================================================================
// CertificateTrust Trait
// ============================================================================

/// Trait for certificate trust verification.
///
/// Extends `CertificateValidation` with trust-based operations.
/// Implementations can use fingerprints, PKI chains, or custom logic.
pub trait CertificateTrust: CertificateValidation + Debug + Send + Sync {
	/// Check if a certificate is trusted.
	fn is_trusted(&self, cert: &Certificate) -> bool;

	/// Verify a certificate chain with full cryptographic validation.
	///
	/// Performs:
	/// 1. Root trust anchor check
	/// 2. Expiry validation for all certificates
	/// 3. Issuer/subject DN chaining
	/// 4. Cryptographic signature verification
	///
	/// # Arguments
	/// * `chain` - Certificate chain ordered root -> intermediate -> leaf
	///
	/// # Returns
	/// - `Ok(())` if the chain is valid and terminates at a trusted root
	/// - `Err(_)` if validation fails
	fn verify_chain(&self, chain: &[Certificate]) -> Result<(), CertificateValidationError>;
}

// ============================================================================
// TrustBuilder Trait
// ============================================================================

/// Builder trait for constructing trust stores.
///
/// Validates structural correctness (expiry, issuer/subject chaining) on add.
/// The built store handles cryptographic verification at runtime.
pub trait TrustBuilder: Sized {
	/// The trust store type this builder produces
	type Store: CertificateTrust;

	/// Add a certificate chain with structural validation.
	///
	/// Validates expiry and issuer/subject chaining. All certificates
	/// in the chain are added to the trust store.
	fn with_chain(self, chain: Vec<Certificate>) -> Result<Self, CertificateValidationError>;

	/// Add a single trusted certificate (root anchor).
	fn with_certificate(self, cert: Certificate) -> Result<Self, CertificateValidationError>;

	/// Build the sealed trust store.
	fn build(self) -> Self::Store;
}

// ============================================================================
// CertificateTrustStore Implementation
// ============================================================================

/// Built-in trust store with cryptographic signature verification.
///
/// Uses a `VerificationPolicy` for runtime signature verification of
/// certificate chains. Stores trusted certificate fingerprints in a
/// `HashSet` for O(1) lookup.
#[cfg(feature = "std")]
pub struct CertificateTrustStore {
	/// Trusted certificate fingerprints (SHA-256 of DER)
	fingerprints: HashSet<Fingerprint>,
	/// Full certificates indexed by fingerprint
	certificates: HashMap<Fingerprint, Certificate>,
	/// Verification policy for signature verification
	policy: Arc<dyn VerificationPolicy>,
}

#[cfg(feature = "std")]
impl CertificateTrustStore {
	/// Compute SHA-256 fingerprint of a certificate's DER encoding.
	pub fn fingerprint(cert: &Certificate) -> Result<Fingerprint, CertificateValidationError> {
		let der_bytes = cert.to_der()?;
		let hash = Sha3_256::digest(&der_bytes);
		let mut fp = [0u8; 32];
		fp.copy_from_slice(hash.as_ref());

		Ok(fp)
	}

	/// Get a certificate by its fingerprint.
	pub fn to_certificate_ref(&self, fingerprint: &Fingerprint) -> Option<&Certificate> {
		self.certificates.get(fingerprint)
	}

	/// Get the number of trusted certificates.
	pub fn len(&self) -> usize {
		self.fingerprints.len()
	}

	/// Check if the trust store is empty.
	pub fn is_empty(&self) -> bool {
		self.fingerprints.is_empty()
	}
}

#[cfg(feature = "std")]
impl Debug for CertificateTrustStore {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("CertificateTrustStore")
			.field("fingerprints", &self.fingerprints.len())
			.field("certificates", &self.certificates.len())
			.finish_non_exhaustive()
	}
}

// ============================================================================
// CertificateValidation Implementation
// ============================================================================

#[cfg(feature = "std")]
impl CertificateValidation for CertificateTrustStore {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		if self.is_trusted(cert) {
			Ok(())
		} else {
			Err(CertificateValidationError::CertificateNotTrusted)
		}
	}
}

// ============================================================================
// CertificateTrust Implementation
// ============================================================================

#[cfg(feature = "std")]
impl CertificateTrust for CertificateTrustStore {
	fn is_trusted(&self, cert: &Certificate) -> bool {
		match Self::fingerprint(cert) {
			Ok(fp) => self.fingerprints.contains(&fp),
			Err(_) => false,
		}
	}

	fn verify_chain(&self, chain: &[Certificate]) -> Result<(), CertificateValidationError> {
		// Root must be in our trust store
		let root = chain.first().ok_or(CertificateValidationError::EmptyChain)?;
		if !self.is_trusted(root) {
			return Err(CertificateValidationError::CertificateNotTrusted);
		}

		// Validate expiry for all certificates
		chain.iter().try_for_each(validate_certificate_expiry)?;

		// Verify issuer/subject chaining and signatures via sliding window
		chain.windows(2).try_for_each(|pair| {
			let (issuer, cert) = (&pair[0], &pair[1]);

			// Verify issuer/subject DN chaining
			if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
				return Err(CertificateValidationError::InvalidChain);
			}

			// Verify cryptographic signature using policy
			let algorithm_oid = cert.signature_algorithm.oid;
			let public_key_der = issuer.tbs_certificate.subject_public_key_info.to_der()?;
			let message = cert.tbs_certificate.to_der()?;
			let signature_bytes = cert.signature.raw_bytes();

			self.policy
				.verify_signature(&algorithm_oid, &public_key_der, &message, signature_bytes)
		})
	}
}

// ============================================================================
// CertificateTrustBuilder Implementation
// ============================================================================

/// Builder for constructing `CertificateTrustStore`.
///
/// Validates structural correctness (expiry, issuer/subject chaining) at add time.
/// The resulting store handles cryptographic verification at runtime.
#[cfg(feature = "std")]
pub struct CertificateTrustBuilder {
	fingerprints: HashSet<Fingerprint>,
	certificates: HashMap<Fingerprint, Certificate>,
	policy: Arc<dyn VerificationPolicy>,
}

#[cfg(feature = "std")]
impl CertificateTrustBuilder {
	/// Create a new builder with the given verification policy.
	pub fn new(policy: Arc<dyn VerificationPolicy>) -> Self {
		Self { fingerprints: HashSet::new(), certificates: HashMap::new(), policy }
	}

	/// Add a single certificate (internal helper).
	fn add_certificate_internal(&mut self, cert: Certificate) -> Result<(), CertificateValidationError> {
		let fp = CertificateTrustStore::fingerprint(&cert)?;
		self.fingerprints.insert(fp);
		self.certificates.insert(fp, cert);
		Ok(())
	}
}

#[cfg(feature = "std")]
impl TrustBuilder for CertificateTrustBuilder {
	type Store = CertificateTrustStore;

	fn with_chain(mut self, chain: Vec<Certificate>) -> Result<Self, CertificateValidationError> {
		if chain.is_empty() {
			return Err(CertificateValidationError::EmptyChain);
		}

		// Validate expiry for all certificates
		chain.iter().try_for_each(validate_certificate_expiry)?;

		// Validate issuer/subject chaining (structural only, no crypto)
		chain.windows(2).try_for_each(|pair| {
			let (issuer, cert) = (&pair[0], &pair[1]);
			(cert.tbs_certificate.issuer == issuer.tbs_certificate.subject)
				.then_some(())
				.ok_or(CertificateValidationError::InvalidChain)
		})?;

		// Transfer ownership and add all certificates
		chain.into_iter().try_for_each(|cert| self.add_certificate_internal(cert))?;

		Ok(self)
	}

	fn with_certificate(mut self, cert: Certificate) -> Result<Self, CertificateValidationError> {
		validate_certificate_expiry(&cert)?;
		self.add_certificate_internal(cert)?;
		Ok(self)
	}

	fn build(self) -> Self::Store {
		CertificateTrustStore {
			fingerprints: self.fingerprints,
			certificates: self.certificates,
			policy: self.policy,
		}
	}
}

#[cfg(feature = "std")]
impl Debug for CertificateTrustBuilder {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("CertificateTrustBuilder")
			.field("fingerprints", &self.fingerprints.len())
			.field("certificates", &self.certificates.len())
			.finish_non_exhaustive()
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::sign::ecdsa::SigningKey;
	use crate::testing::create_test_signing_key;
	use crate::testing::utils::{create_test_certificate, create_test_certificate_chain};

	type TestResult = Result<(), Box<dyn std::error::Error>>;

	fn create_test_store() -> Result<CertificateTrustStore, CertificateValidationError> {
		let signing_key = create_test_signing_key();
		let cert = create_test_certificate(&signing_key);

		Ok(CertificateTrustBuilder::new(Arc::new(Secp256k1Policy))
			.with_certificate(cert)?
			.build())
	}

	#[test]
	fn trust_store_fingerprint() -> TestResult {
		let signing_key = create_test_signing_key();
		let cert = create_test_certificate(&signing_key);

		let fp = CertificateTrustStore::fingerprint(&cert)?;
		assert_eq!(fp.len(), 32);
		Ok(())
	}

	#[test]
	fn trust_store_is_trusted() -> TestResult {
		let signing_key = create_test_signing_key();
		let cert = create_test_certificate(&signing_key);

		let store = CertificateTrustBuilder::new(Arc::new(Secp256k1Policy))
			.with_certificate(cert.clone())?
			.build();
		assert!(store.is_trusted(&cert));

		// Different key produces different cert - should not be trusted
		let other_key = SigningKey::from_bytes(&[2u8; 32].into())?;
		let untrusted_cert = create_test_certificate(&other_key);
		assert!(!store.is_trusted(&untrusted_cert));
		Ok(())
	}

	#[test]
	fn trust_store_evaluate() -> TestResult {
		let signing_key = create_test_signing_key();
		let cert = create_test_certificate(&signing_key);

		let store = CertificateTrustBuilder::new(Arc::new(Secp256k1Policy))
			.with_certificate(cert.clone())?
			.build();
		assert!(store.evaluate(&cert).is_ok());

		// Different key produces different cert - should fail evaluate
		let other_key = SigningKey::from_bytes(&[2u8; 32].into())?;
		let untrusted_cert = create_test_certificate(&other_key);
		assert!(matches!(
			store.evaluate(&untrusted_cert),
			Err(CertificateValidationError::CertificateNotTrusted)
		));
		Ok(())
	}

	#[test]
	fn trust_store_verify_chain_empty() -> TestResult {
		let store = create_test_store()?;
		assert!(matches!(store.verify_chain(&[]), Err(CertificateValidationError::EmptyChain)));
		Ok(())
	}

	#[test]
	fn trust_store_verify_chain_untrusted_root() -> TestResult {
		let signing_key = create_test_signing_key();
		let root = create_test_certificate(&signing_key);

		// Empty store - root not trusted
		let store = CertificateTrustBuilder::new(Arc::new(Secp256k1Policy)).build();
		assert!(matches!(
			store.verify_chain(&[root]),
			Err(CertificateValidationError::CertificateNotTrusted)
		));
		Ok(())
	}

	#[test]
	fn trust_store_verify_chain_trusted_root() -> TestResult {
		let signing_key = create_test_signing_key();
		let root = create_test_certificate(&signing_key);

		let store = CertificateTrustBuilder::new(Arc::new(Secp256k1Policy))
			.with_certificate(root.clone())?
			.build();
		assert!(store.verify_chain(&[root]).is_ok());
		Ok(())
	}

	#[test]
	fn builder_validates_chain_structure() -> TestResult {
		let chain = create_test_certificate_chain();
		let result = CertificateTrustBuilder::new(Arc::new(Secp256k1Policy)).with_chain(vec![
			chain.root,
			chain.intermediate,
			chain.leaf,
		]);

		// Chain has proper issuer/subject chaining, should pass structural validation
		assert!(result.is_ok());
		Ok(())
	}

	#[test]
	fn verify_chain_with_valid_signatures() -> TestResult {
		let chain = create_test_certificate_chain();
		let store = CertificateTrustBuilder::new(Arc::new(Secp256k1Policy))
			.with_certificate(chain.root.clone())?
			.build();

		// Full chain verification (includes signature verification)
		let result = store.verify_chain(&[chain.root, chain.intermediate, chain.leaf]);
		assert!(result.is_ok());
		Ok(())
	}
}
