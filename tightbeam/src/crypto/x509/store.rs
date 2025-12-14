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

	/// Add a single trusted certificate (leaf certificate).
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
	pub fn to_fingerprint(cert: &Certificate) -> Result<Fingerprint, CertificateValidationError> {
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

#[cfg(feature = "std")]
impl CertificateValidation for CertificateTrustStore {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		validate_certificate_expiry(cert)?;

		// Fast path: direct fingerprint trust
		if self.is_trusted(cert) {
			return Ok(());
		}

		// Chain walk: find issuer by Subject DN match
		let issuer = self
			.certificates
			.values()
			.find(|c| c.tbs_certificate.subject == cert.tbs_certificate.issuer)
			.ok_or(CertificateValidationError::CertificateNotTrusted)?;

		// Verify signature against issuer
		let algorithm_oid = cert.signature_algorithm.oid;
		let public_key_der = issuer.tbs_certificate.subject_public_key_info.to_der()?;
		let message = cert.tbs_certificate.to_der()?;
		let signature = cert.signature.raw_bytes();

		self.policy
			.verify_signature(&algorithm_oid, &public_key_der, &message, signature)?;

		// Recursively validate issuer (terminates when issuer is directly trusted)
		self.evaluate(issuer)
	}
}

#[cfg(feature = "std")]
impl CertificateTrust for CertificateTrustStore {
	fn is_trusted(&self, cert: &Certificate) -> bool {
		match Self::to_fingerprint(cert) {
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
		let fp = CertificateTrustStore::to_fingerprint(&cert)?;

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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::sign::ecdsa::SigningKey;
	use crate::testing::create_test_signing_key;
	use crate::testing::utils::{create_test_certificate, create_test_certificate_chain, TestCertificateChain};

	type TestResult = Result<(), Box<dyn std::error::Error>>;

	// ========================================================================
	// Test Helpers
	// ========================================================================

	fn policy() -> Arc<dyn VerificationPolicy> {
		Arc::new(Secp256k1Policy)
	}

	/// Which certificates to add to the trust store
	#[derive(Debug, Clone, Copy)]
	enum StoreCerts {
		None,
		Root,
		RootAndIntermediate,
	}

	/// Which certificate to evaluate
	#[derive(Debug, Clone, Copy)]
	enum EvalTarget {
		Root,
		Intermediate,
		Leaf,
	}

	/// Build a trust store with the specified certificates from a chain
	fn build_store(
		chain: &TestCertificateChain,
		certs: StoreCerts,
	) -> Result<CertificateTrustStore, CertificateValidationError> {
		let mut builder = CertificateTrustBuilder::new(policy());
		builder = match certs {
			StoreCerts::None => builder,
			StoreCerts::Root => builder.with_certificate(chain.root.clone())?,
			StoreCerts::RootAndIntermediate => builder
				.with_certificate(chain.root.clone())?
				.with_certificate(chain.intermediate.clone())?,
		};
		Ok(builder.build())
	}

	/// Get the target certificate from a chain
	fn target_cert(chain: &TestCertificateChain, target: EvalTarget) -> &Certificate {
		match target {
			EvalTarget::Root => &chain.root,
			EvalTarget::Intermediate => &chain.intermediate,
			EvalTarget::Leaf => &chain.leaf,
		}
	}

	// ========================================================================
	// Basic Operations
	// ========================================================================

	#[test]
	fn fingerprint_is_32_bytes() -> TestResult {
		let cert = create_test_certificate(&create_test_signing_key());
		assert_eq!(CertificateTrustStore::to_fingerprint(&cert)?.len(), 32);
		Ok(())
	}

	#[test]
	fn is_trusted_matches_fingerprint() -> TestResult {
		let cert = create_test_certificate(&create_test_signing_key());
		let store = CertificateTrustBuilder::new(policy()).with_certificate(cert.clone())?.build();
		assert!(store.is_trusted(&cert));
		assert!(!store.is_trusted(&create_test_certificate(&SigningKey::from_bytes(&[2u8; 32].into())?)));
		Ok(())
	}

	#[test]
	fn builder_validates_chain_structure() -> TestResult {
		let chain = create_test_certificate_chain();
		assert!(CertificateTrustBuilder::new(policy())
			.with_chain(vec![chain.root, chain.intermediate, chain.leaf])
			.is_ok());

		Ok(())
	}

	/// Test cases for evaluate() with chain walking
	const EVALUATE_CASES: &[(StoreCerts, EvalTarget, bool)] = &[
		// Direct trust
		(StoreCerts::Root, EvalTarget::Root, true),
		// Chain walking: root trusts intermediate
		(StoreCerts::Root, EvalTarget::Intermediate, true),
		// Chain walking: root+intermediate trusts leaf
		(StoreCerts::RootAndIntermediate, EvalTarget::Leaf, true),
		// Fails: root alone cannot verify leaf (missing intermediate)
		(StoreCerts::Root, EvalTarget::Leaf, false),
		// Fails: empty store trusts nothing
		(StoreCerts::None, EvalTarget::Leaf, false),
	];

	#[test]
	fn evaluate_chain_walking() -> TestResult {
		let chain = create_test_certificate_chain();
		for (store_certs, eval_target, should_succeed) in EVALUATE_CASES {
			let store = build_store(&chain, *store_certs)?;
			let cert = target_cert(&chain, *eval_target);

			let result = store.evaluate(cert);
			assert_eq!(
				result.is_ok(),
				*should_succeed,
				"store={store_certs:?} target={eval_target:?}: expected {should_succeed}, got {result:?}"
			);
		}

		Ok(())
	}

	#[test]
	fn evaluate_rejects_cross_chain_cert() -> TestResult {
		// Store has one chain's root, evaluate leaf from different chain
		let store = CertificateTrustBuilder::new(policy())
			.with_certificate(create_test_certificate(&create_test_signing_key()))?
			.build();

		let other_chain = create_test_certificate_chain();
		assert!(store.evaluate(&other_chain.leaf).is_err());
		Ok(())
	}

	// ========================================================================
	// Chain Verification
	// ========================================================================

	#[test]
	fn verify_chain_cases() -> TestResult {
		let chain = create_test_certificate_chain();
		let cases: &[(StoreCerts, &[&Certificate], bool)] = &[
			// Empty chain fails
			(StoreCerts::Root, &[], false),
			// Untrusted root fails
			(StoreCerts::None, &[&chain.root], false),
			// Trusted root alone succeeds
			(StoreCerts::Root, &[&chain.root], true),
			// Full chain with trusted root succeeds
			(StoreCerts::Root, &[&chain.root, &chain.intermediate, &chain.leaf], true),
		];

		for (store_certs, chain_slice, should_succeed) in cases {
			let store = build_store(&chain, *store_certs)?;
			let chain_vec: Vec<_> = chain_slice.iter().map(|c| (*c).clone()).collect();

			let result: Result<(), CertificateValidationError> = store.verify_chain(&chain_vec);
			assert_eq!(
				result.is_ok(),
				*should_succeed,
				"verify_chain: store={store_certs:?} chain_len={}: expected {should_succeed}, got {result:?}",
				chain_slice.len()
			);
		}

		Ok(())
	}
}
