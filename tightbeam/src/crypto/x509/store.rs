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

	pub use crate::cms::signed_data::SignerIdentifier;
	pub use crate::crypto::hash::Digest;
	pub use crate::crypto::hash::Sha3_256;
	pub use crate::crypto::policy::VerificationPolicy;
	pub use crate::crypto::x509::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
	pub use crate::crypto::x509::utils::{certificate_extension, ensure_signature_algorithm_consistency};
}

#[cfg(feature = "std")]
use std_imports::*;

/// Fingerprint type: SHA3-256 hash (32 bytes)
pub type Fingerprint = [u8; 32];

/// Trait for certificate trust verification.
///
/// Extends `CertificateValidation` with trust-based operations.
/// Implementations can use fingerprints, PKI chains, or custom logic.
#[cfg(feature = "std")]
pub trait CertificateTrust: CertificateValidation + Debug + Send + Sync {
	/// Check if a certificate is trusted.
	fn is_trusted(&self, cert: &Certificate) -> bool;

	/// Verify a certificate chain (partial RFC 5280 §6.1 path validation).
	///
	/// Performs:
	/// 1. Root trust anchor check (RFC 5280 §6.1.1)
	/// 2. Expiry validation for all certificates (RFC 5280 §6.1.3(a)(2))
	/// 3. Issuer/subject DN chaining (RFC 5280 §6.1.3(a)(4))
	/// 4. Cryptographic signature verification (RFC 5280 §6.1.3(a)(1))
	/// 5. Issuer `basicConstraints.cA` / `keyUsage.keyCertSign` and
	///    `pathLenConstraint` (RFC 5280 §6.1.4(k),(m),(n))
	///
	/// Not yet enforced: extension criticality (RFC 5280 §6.1.3(f)), name
	/// constraints/policies (§6.1.3–§6.1.5), and revocation (CRL/OCSP). See
	/// <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1>.
	///
	/// # Arguments
	/// * `chain` - Certificate chain ordered root -> intermediate -> leaf
	///
	/// # Returns
	/// - `Ok(())` if the chain is valid and terminates at a trusted root
	/// - `Err(_)` if validation fails
	fn verify_chain(&self, chain: &[Certificate]) -> Result<(), CertificateValidationError>;

	/// Find a certificate by SignerInfo.
	///
	/// Used for frame signature verification - looks up the signer's certificate
	/// using the SignerInfo's identifier and digest algorithm.
	///
	/// # Arguments
	/// * `signer_info` - SignerInfo from the frame's nonrepudiation field
	///
	/// # Returns
	/// - `Some(&Certificate)` if a matching certificate is found
	/// - `None` if no certificate matches
	fn find_by_signer_info(&self, signer_info: &crate::SignerInfo) -> Option<&Certificate>;

	/// Get the verification policy for signature operations.
	fn to_policy_ref(&self) -> &dyn VerificationPolicy;
}

/// Trait for certificate trust verification (no_std version without SignerIdentifier).
#[cfg(not(feature = "std"))]
pub trait CertificateTrust: CertificateValidation + Debug + Send + Sync {
	/// Check if a certificate is trusted.
	fn is_trusted(&self, cert: &Certificate) -> bool;

	/// Verify a certificate chain with full cryptographic validation.
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

/// Enforce that an issuer certificate is permitted to sign certificates.
///
/// RFC 5280 §6.1.4(k): the issuer's `basicConstraints` extension MUST be
/// present with `cA` asserted. §6.1.4(n): when a `keyUsage` extension is
/// present it MUST assert `keyCertSign`.
/// <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.4>.
#[cfg(feature = "std")]
fn ensure_issuer_is_ca(issuer: &Certificate) -> Result<(), CertificateValidationError> {
	match certificate_extension::<BasicConstraints>(issuer)? {
		Some(basic_constraints) if basic_constraints.ca => {}
		_ => return Err(CertificateValidationError::IssuerNotCa),
	}

	if let Some(key_usage) = certificate_extension::<KeyUsage>(issuer)? {
		if !key_usage.0.contains(KeyUsages::KeyCertSign) {
			return Err(CertificateValidationError::MissingKeyCertSign);
		}
	}

	Ok(())
}

/// Enforce `pathLenConstraint` over an ordered chain (root -> leaf).
///
/// RFC 5280 §6.1.4(m): a CA certificate's `pathLenConstraint` bounds the number
/// of intermediate certificates that may follow it in the path before the
/// end-entity. `None` imposes no limit.
/// <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.4>.
#[cfg(feature = "std")]
fn ensure_path_len(chain: &[Certificate]) -> Result<(), CertificateValidationError> {
	for (index, cert) in chain.iter().enumerate() {
		let Some(basic_constraints) = certificate_extension::<BasicConstraints>(cert)? else {
			continue;
		};
		let Some(max_intermediates) = basic_constraints.path_len_constraint else {
			continue;
		};

		// Certificates strictly between this CA and the end-entity leaf.
		let intermediates_below = chain.len().saturating_sub(index + 2);
		if intermediates_below as u64 > u64::from(max_intermediates) {
			return Err(CertificateValidationError::PathLenExceeded);
		}
	}

	Ok(())
}

// ============================================================================
// CertificateTrustStore Implementation
// ============================================================================

/// SKID type: first 20 bytes of hash (RFC 5280)
pub type Skid = [u8; 20];

/// Built-in trust store with cryptographic signature verification.
///
/// Uses a `VerificationPolicy` for runtime signature verification of
/// certificate chains. Stores trusted certificate fingerprints in a
/// `HashSet` for O(1) lookup.
#[cfg(feature = "std")]
pub struct CertificateTrustStore {
	/// Trusted certificate fingerprints
	fingerprints: HashSet<Fingerprint>,
	/// Full certificates indexed by fingerprint
	certificates: HashMap<Fingerprint, Certificate>,
	/// Pre-computed SKID
	skid_index: HashMap<Skid, Fingerprint>,
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
		// Iterative issuer walk toward a trust anchor.
		let mut current = cert;
		let mut visited: HashSet<Fingerprint> = HashSet::new();

		loop {
			// RFC 5280 §6.1.3(a)(2): validity-period check.
			validate_certificate_expiry(current)?;

			// RFC 5280 §4.1.1.2: signatureAlgorithm must match tbsCertificate.signature.
			ensure_signature_algorithm_consistency(current)?;

			// RFC 5280 §6.1.1: terminate at a configured trust anchor.
			if self.is_trusted(current) {
				return Ok(());
			}

			// RFC 4158 §2.4.2 loop detection: revisiting a certificate means this
			// greedy branch loops without reaching an anchor.
			if !visited.insert(Self::to_fingerprint(current)?) {
				return Err(CertificateValidationError::InvalidChain);
			}

			// RFC 5280 §6.1.3(a)(4): name chaining - locate an issuer whose
			// subject DN matches the current certificate's issuer DN.
			let issuer = self
				.certificates
				.values()
				.find(|c| c.tbs_certificate.subject == current.tbs_certificate.issuer)
				.ok_or(CertificateValidationError::CertificateNotTrusted)?;

			// RFC 5280 §6.1.4(k),(n): the issuer must be a CA permitted to sign certs.
			ensure_issuer_is_ca(issuer)?;

			// RFC 5280 §6.1.3(a)(1): verify the signature using the issuer's key.
			let algorithm_oid = current.signature_algorithm.oid;
			let public_key_der = issuer.tbs_certificate.subject_public_key_info.to_der()?;
			let message = current.tbs_certificate.to_der()?;
			let signature = current.signature.raw_bytes();

			self.policy
				.verify_signature(&algorithm_oid, &public_key_der, &message, signature)?;

			current = issuer;
		}
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
		// RFC 5280 §6.1.1: the chain must terminate at a configured trust anchor.
		let root = chain.first().ok_or(CertificateValidationError::EmptyChain)?;
		if !self.is_trusted(root) {
			return Err(CertificateValidationError::CertificateNotTrusted);
		}

		// RFC 5280 §6.1.3(a)(2): every certificate must be within its validity period.
		chain.iter().try_for_each(validate_certificate_expiry)?;

		// RFC 5280 §4.1.1.2: signatureAlgorithm must match tbsCertificate.signature.
		chain.iter().try_for_each(ensure_signature_algorithm_consistency)?;

		// Verify issuer/subject chaining and signatures via sliding window
		chain.windows(2).try_for_each(|pair| {
			let (issuer, cert) = (&pair[0], &pair[1]);

			// RFC 5280 §6.1.3(a)(4): name chaining - issuer DN must equal the
			// preceding certificate's subject DN.
			if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
				return Err(CertificateValidationError::InvalidChain);
			}

			// RFC 5280 §6.1.4(k),(n): the issuer must be a CA permitted to sign certs.
			ensure_issuer_is_ca(issuer)?;

			// RFC 5280 §6.1.3(a)(1): verify the signature using the issuer's key.
			let algorithm_oid = cert.signature_algorithm.oid;
			let public_key_der = issuer.tbs_certificate.subject_public_key_info.to_der()?;
			let message = cert.tbs_certificate.to_der()?;
			let signature_bytes = cert.signature.raw_bytes();

			self.policy
				.verify_signature(&algorithm_oid, &public_key_der, &message, signature_bytes)
		})?;

		// RFC 5280 §6.1.4(m): enforce pathLenConstraint across the ordered chain.
		ensure_path_len(chain)
	}

	fn find_by_signer_info(&self, signer_info: &crate::SignerInfo) -> Option<&Certificate> {
		match &signer_info.sid {
			SignerIdentifier::IssuerAndSerialNumber(ias) => {
				// Find by issuer DN + serial number
				self.certificates.values().find(|cert| {
					cert.tbs_certificate.issuer == ias.issuer && cert.tbs_certificate.serial_number == ias.serial_number
				})
			}
			SignerIdentifier::SubjectKeyIdentifier(skid) => {
				// O(1) lookup via pre-indexed SKID
				let skid_bytes = skid.0.as_bytes();
				(skid_bytes.len() == 20)
					.then(|| {
						let mut key = [0u8; 20];
						key.copy_from_slice(skid_bytes);
						key
					})
					.and_then(|key| self.skid_index.get(&key))
					.and_then(|fp| self.certificates.get(fp))
			}
		}
	}

	fn to_policy_ref(&self) -> &dyn VerificationPolicy {
		&*self.policy
	}
}

// ============================================================================
// CertificateTrustBuilder Implementation
// ============================================================================

/// Builder for constructing `CertificateTrustStore`.
///
/// Generic over digest algorithm `D` which is used for SKID computation.
/// Validates structural correctness (expiry, issuer/subject chaining) on add.
/// The resulting store handles cryptographic verification at runtime.
#[cfg(feature = "std")]
pub struct CertificateTrustBuilder<D: Digest> {
	fingerprints: HashSet<Fingerprint>,
	certificates: HashMap<Fingerprint, Certificate>,
	skid_index: HashMap<Skid, Fingerprint>,
	policy: Arc<dyn VerificationPolicy>,
	_digest: core::marker::PhantomData<D>,
}

#[cfg(feature = "std")]
impl<D: Digest, P: VerificationPolicy + 'static> From<P> for CertificateTrustBuilder<D> {
	fn from(policy: P) -> Self {
		Self {
			fingerprints: HashSet::new(),
			certificates: HashMap::new(),
			skid_index: HashMap::new(),
			policy: Arc::new(policy),
			_digest: core::marker::PhantomData,
		}
	}
}

#[cfg(feature = "std")]
impl<D: Digest> CertificateTrustBuilder<D> {
	/// Add a single certificate (internal helper).
	fn add_certificate(&mut self, cert: Certificate) -> Result<(), CertificateValidationError> {
		let fp = CertificateTrustStore::to_fingerprint(&cert)?;

		// Compute SKID from public key
		let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
		let hash = D::digest(&spki_der);

		let mut skid = [0u8; 20];
		let skid_src = hash.as_ref().get(..20).ok_or(CertificateValidationError::DigestTooShort)?;
		skid.copy_from_slice(skid_src);

		// Collision detection: same SKID but different fingerprint
		if let Some(existing_fp) = self.skid_index.get(&skid) {
			if *existing_fp != fp {
				return Err(CertificateValidationError::SkidCollision);
			}
		}

		self.fingerprints.insert(fp);
		self.skid_index.insert(skid, fp);
		self.certificates.insert(fp, cert);

		Ok(())
	}
}

#[cfg(feature = "std")]
impl<D: Digest> TrustBuilder for CertificateTrustBuilder<D> {
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
		chain.into_iter().try_for_each(|cert| self.add_certificate(cert))?;

		Ok(self)
	}

	fn with_certificate(mut self, cert: Certificate) -> Result<Self, CertificateValidationError> {
		validate_certificate_expiry(&cert)?;
		self.add_certificate(cert)?;
		Ok(self)
	}

	fn build(self) -> Self::Store {
		CertificateTrustStore {
			fingerprints: self.fingerprints,
			certificates: self.certificates,
			skid_index: self.skid_index,
			policy: self.policy,
		}
	}
}

#[cfg(feature = "std")]
impl<D: Digest> Debug for CertificateTrustBuilder<D> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("CertificateTrustBuilder")
			.field("fingerprints", &self.fingerprints.len())
			.field("certificates", &self.certificates.len())
			.field("skid_index", &self.skid_index.len())
			.finish_non_exhaustive()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::sign::ecdsa::SigningKey;
	use crate::crypto::sign::Signatory;
	use crate::testing::create_test_signing_key;
	use crate::testing::utils::{
		ca_extensions, create_test_certificate, create_test_certificate_chain, TestCertificateChain,
	};

	type TestResult = Result<(), Box<dyn std::error::Error>>;

	/// Type alias for the builder with SHA3-256 digest (matches secp256k1 signer)
	type TestBuilder = CertificateTrustBuilder<Sha3_256>;

	// ========================================================================
	// Test Helpers
	// ========================================================================

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
		let builder: TestBuilder = Secp256k1Policy.into();
		let builder = match certs {
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
		let store = TestBuilder::from(Secp256k1Policy).with_certificate(cert.clone())?.build();
		assert!(store.is_trusted(&cert));
		assert!(!store.is_trusted(&create_test_certificate(&SigningKey::from_bytes(&[2u8; 32].into())?)));
		Ok(())
	}

	#[test]
	fn builder_validates_chain_structure() -> TestResult {
		let chain = create_test_certificate_chain();
		assert!(TestBuilder::from(Secp256k1Policy)
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
		let store = TestBuilder::from(Secp256k1Policy)
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

	// ========================================================================
	// RFC 5280 §6.1.4 Path Constraints
	// ========================================================================

	/// Each case replaces the root's extensions, then expects `verify_chain` to
	/// reject the otherwise-valid chain with the mapped error.
	const ISSUER_CONSTRAINT_CASES: &[(bool, bool, Option<u8>, CertificateValidationError)] = &[
		(false, true, None, CertificateValidationError::IssuerNotCa),
		(true, false, None, CertificateValidationError::MissingKeyCertSign),
		(true, true, Some(0), CertificateValidationError::PathLenExceeded),
	];

	#[test]
	fn verify_chain_enforces_issuer_constraints() -> TestResult {
		for (ca, key_cert_sign, path_len, expected) in ISSUER_CONSTRAINT_CASES {
			let chain = create_test_certificate_chain();
			let mut root = chain.root.clone();
			root.tbs_certificate.extensions = Some(ca_extensions(*ca, *key_cert_sign, *path_len));
			let store = TestBuilder::from(Secp256k1Policy).with_certificate(root.clone())?.build();

			let result = store.verify_chain(&[root, chain.intermediate, chain.leaf]);
			assert!(matches!(result, Err(ref e) if core::mem::discriminant(e) == core::mem::discriminant(expected)));
		}

		Ok(())
	}

	// ========================================================================
	// RFC 5280 §4.1.1.2 Algorithm Identifier Consistency
	// ========================================================================

	#[test]
	fn rejects_algorithm_identifier_mismatch() -> TestResult {
		let chain = create_test_certificate_chain();
		let mut leaf = chain.leaf.clone();
		leaf.signature_algorithm.oid = crate::oids::SIGNER_ECDSA_WITH_SHA256;

		// Both the recursive `evaluate` walk and `verify_chain` must reject it.
		let walk_store = build_store(&chain, StoreCerts::RootAndIntermediate)?;
		assert!(matches!(
			walk_store.evaluate(&leaf),
			Err(CertificateValidationError::AlgorithmMismatch)
		));

		let chain_store = build_store(&chain, StoreCerts::Root)?;
		let result = chain_store.verify_chain(&[chain.root, chain.intermediate, leaf]);
		assert!(matches!(result, Err(CertificateValidationError::AlgorithmMismatch)));
		Ok(())
	}

	// ========================================================================
	// Signer Lookup
	// ========================================================================

	#[test]
	fn find_by_signer_info_skid() -> TestResult {
		let key = create_test_signing_key();
		let cert = create_test_certificate(&key);
		let store = TestBuilder::from(Secp256k1Policy).with_certificate(cert.clone())?.build();

		// Create signer info via Signatory trait (uses SHA3-256 for SKID)
		let signer_info = key.to_signer_info(b"test")?;
		// Should find the certificate
		let Some(found) = store.find_by_signer_info(&signer_info) else {
			return Err(crate::testing::error::TestingError::InvariantViolated.into());
		};
		assert_eq!(
			CertificateTrustStore::to_fingerprint(found)?,
			CertificateTrustStore::to_fingerprint(&cert)?
		);

		Ok(())
	}

	#[test]
	fn find_by_signer_info_not_found() -> TestResult {
		let store = TestBuilder::from(Secp256k1Policy)
			.with_certificate(create_test_certificate(&create_test_signing_key()))?
			.build();

		// Different key
		let other_key = SigningKey::from_bytes(&[99u8; 32].into())?;
		let signer_info = other_key.to_signer_info(b"test")?;
		assert!(store.find_by_signer_info(&signer_info).is_none());

		Ok(())
	}
}
