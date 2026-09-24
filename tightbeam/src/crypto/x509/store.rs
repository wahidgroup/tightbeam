//! The certificate trust store.
//!
//! [`CertificateTrust`] abstracts certificate trust verification, so each
//! environment can supply its own implementation. [`CertificateTrustStore`] is
//! the built-in store.

use core::fmt::Debug;

use crate::cms::signed_data::SignerIdentifier;
use crate::crypto::policy::VerificationPolicy;
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::utils::compute_signer_identifier_from_der;
use crate::crypto::x509::Certificate;
use crate::der::Encode;

#[cfg(feature = "std")]
mod std_imports {
	pub use std::collections::{HashMap, HashSet};
	pub use std::sync::Arc;

	pub use crate::crypto::hash::{Digest, Sha3_256, U32};
	pub use crate::crypto::x509::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectAltName};
	pub use crate::crypto::x509::name::Name;
	pub use crate::crypto::x509::utils::{CertificateExt, Fingerprint, Skid};
	pub use crate::der::oid::AssociatedOid;
}

#[cfg(feature = "std")]
use std_imports::*;

/// SHA3-256 certificate fingerprint used by the built-in trust store.
#[cfg(feature = "std")]
type Sha3Fingerprint = Fingerprint<Sha3_256>;

/// Revocation status check for certificates within a certification path.
///
/// Path validation consults it once per certificate, which satisfies the
/// revocation step of RFC 5280 §6.1.3(a)(3). The shipped implementations are
/// [`NoRevocation`] and [`StaticRevocationList`].
///
/// # Fail closed
///
/// Implementations MUST fail closed:
///
/// - [`CertificateValidationError::CertificateRevoked`] for a revoked certificate.
/// - [`CertificateValidationError::RevocationStatusUnknown`] when the status cannot be established.
pub trait RevocationChecker: Debug + Send + Sync {
	/// Check the revocation status of `cert`, issued by `issuer`.
	///
	/// Trust anchors are checked with themselves as issuer.
	fn check(&self, issuer: &Certificate, cert: &Certificate) -> Result<(), CertificateValidationError>;
}

/// A [`RevocationChecker`] that treats every certificate as unrevoked.
///
/// It is the default for [`CertificateTrustStore`]. It is sound only for a
/// closed PKI with short-lived certificates, because a compromised key stays
/// trusted until the certificate expires or the operator re-pins the trust
/// store.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRevocation;

impl RevocationChecker for NoRevocation {
	fn check(&self, _issuer: &Certificate, _cert: &Certificate) -> Result<(), CertificateValidationError> {
		Ok(())
	}
}

/// An operator-pushed static revocation denylist.
///
/// It revokes by exact certificate fingerprint or by issuer-scoped serial
/// number.
#[cfg(feature = "std")]
#[derive(Debug, Default)]
pub struct StaticRevocationList {
	fingerprints: HashSet<Sha3Fingerprint>,
	/// Revoked serial numbers keyed by issuer DN DER. RFC 5280 §4.1.2.2
	/// guarantees serial uniqueness only within one CA, so an unscoped serial
	/// would falsely revoke unrelated certificates.
	serials: HashMap<Vec<u8>, HashSet<Vec<u8>>>,
}

#[cfg(feature = "std")]
impl StaticRevocationList {
	/// Revoke a certificate by its SHA3-256 DER fingerprint.
	pub fn with_fingerprint(mut self, fingerprint: Sha3Fingerprint) -> Self {
		self.fingerprints.insert(fingerprint);
		self
	}

	/// Revoke `cert` by the fingerprint computed from it.
	pub fn with_certificate(self, cert: &Certificate) -> Result<Self, CertificateValidationError> {
		let fingerprint = CertificateTrustStore::to_fingerprint(cert)?;
		Ok(self.with_fingerprint(fingerprint))
	}

	/// Revoke by issuer and raw serial-number bytes, the scope of a CRL entry.
	pub fn with_serial(mut self, issuer: &Name, serial: impl AsRef<[u8]>) -> Result<Self, CertificateValidationError> {
		self.serials
			.entry(issuer.to_der()?)
			.or_default()
			.insert(serial.as_ref().to_vec());
		Ok(self)
	}
}

#[cfg(feature = "std")]
impl RevocationChecker for StaticRevocationList {
	fn check(&self, _issuer: &Certificate, cert: &Certificate) -> Result<(), CertificateValidationError> {
		let fingerprint = CertificateTrustStore::to_fingerprint(cert)?;
		if self.fingerprints.contains(&fingerprint) {
			return Err(CertificateValidationError::CertificateRevoked);
		}
		if self.serials.is_empty() {
			return Ok(());
		}

		let issuer_der = cert.tbs_certificate.issuer.to_der()?;
		let revoked = self
			.serials
			.get(issuer_der.as_slice())
			.is_some_and(|serials| serials.contains(cert.tbs_certificate.serial_number.as_bytes()));
		if revoked {
			return Err(CertificateValidationError::CertificateRevoked);
		}

		Ok(())
	}
}

/// Outcome of verifying a frame signature against a trust store.
///
/// Distinguishes "no identity claimed" and "unknown identity claimed"
/// from "trusted identity claimed with a bad signature" so callers can
/// apply different consequences.
#[cfg(feature = "signature")]
#[must_use = "a dropped TrustVerification leaves the frame unauthenticated"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustVerification<'a> {
	/// The frame carries no nonrepudiation signature.
	MissingSignature,
	/// The trust store holds no certificate for the signer.
	UnknownSigner,
	/// The signer is trusted, and the signature fails verification.
	Invalid,
	/// The signature verified against the certificate that this store
	/// resolved.
	Verified(&'a Certificate),
}

/// Certificate trust verification.
///
/// It extends [`CertificateValidation`] with trust-based operations. An
/// implementation may use fingerprints, PKI chains, or custom logic.
/// [`CertificateTrustStore`] is the built-in store and needs `std`, so a
/// no_std consumer supplies its own implementation of this trait.
pub trait CertificateTrust: CertificateValidation + Debug + Send + Sync {
	/// Whether the store trusts `cert` by fingerprint.
	///
	/// This is certificate-object identity. Plane membership that must
	/// survive key re-issuance uses [`Self::trusts_public_key`].
	fn is_trusted(&self, cert: &Certificate) -> bool;

	/// Whether this store holds any certificate for `cert`'s public key.
	///
	/// Membership is the SubjectKeyIdentifier of the SPKI, resolved
	/// through [`Self::find_by_signer_identifier`]. A rotated certificate
	/// for an enrolled key still matches. Implementors that answer SID
	/// lookup correctly get this behavior without an override.
	#[must_use = "a dropped membership answer leaves the plane gate unenforced"]
	fn trusts_public_key(&self, cert: &Certificate) -> bool {
		let Ok(spki_der) = cert.tbs_certificate.subject_public_key_info.to_der() else {
			return false;
		};
		let Ok(sid) = compute_signer_identifier_from_der(spki_der.as_slice()) else {
			return false;
		};

		self.find_by_signer_identifier(&sid).is_some()
	}

	/// Verify a certificate chain with partial RFC 5280 §6.1 path validation.
	///
	/// `chain` is ordered root, then intermediates, then leaf. The call returns
	/// `Ok(())` when the chain is valid and terminates at a trusted root.
	///
	/// # Checks
	///
	/// 1. Root trust anchor check (RFC 5280 §6.1.1).
	/// 2. Expiry validation for all certificates (RFC 5280 §6.1.3(a)(2)).
	/// 3. Rejection of unprocessed critical extensions (RFC 5280 §4.2, §6.1.3(f)).
	/// 4. Issuer and subject DN chaining (RFC 5280 §6.1.3(a)(4)).
	/// 5. Cryptographic signature verification (RFC 5280 §6.1.3(a)(1)).
	/// 6. Issuer `basicConstraints.cA`, `keyUsage.keyCertSign`, and
	///    `pathLenConstraint` (RFC 5280 §6.1.4(k),(l),(m),(n)).
	///
	/// # Scope
	///
	/// Name constraints and policies (§6.1.3-§6.1.5) and CRL or OCSP fetching
	/// stay out of scope. Revocation runs through the configured
	/// [`RevocationChecker`]. See
	/// <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1>.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError`] when validation fails.
	fn verify_chain(&self, chain: &[Certificate]) -> Result<(), CertificateValidationError>;

	/// Find a certificate by CMS [`SignerIdentifier`].
	///
	/// This is the key-identity lookup frame verification and plane
	/// classification share. Issuer-and-serial and subject-key-identifier
	/// forms both resolve here.
	fn find_by_signer_identifier(&self, sid: &SignerIdentifier) -> Option<&Certificate>;

	/// Find a certificate by `SignerInfo`.
	///
	/// Frame signature verification uses it. It resolves through
	/// [`Self::find_by_signer_identifier`] on the info's `sid`.
	fn find_by_signer_info(&self, signer_info: &crate::SignerInfo) -> Option<&Certificate> {
		self.find_by_signer_identifier(&signer_info.sid)
	}

	/// The verification policy for signature operations.
	fn to_policy_ref(&self) -> &dyn VerificationPolicy;

	/// Verify `frame`'s nonrepudiation signature against this store.
	///
	/// Looks up the signer certificate via the frame's `SignerInfo` and
	/// verifies the signature over the frame's to-be-signed bytes. The
	/// verified arm returns that certificate so a later step does not
	/// resolve the signer again.
	#[cfg(feature = "signature")]
	#[must_use = "a dropped TrustVerification leaves the frame unauthenticated"]
	fn verify_frame<'a>(&'a self, frame: &crate::Frame) -> TrustVerification<'a> {
		let Some(signer_info) = frame.nonrepudiation() else {
			return TrustVerification::MissingSignature;
		};

		let Some(cert) = self.find_by_signer_info(signer_info) else {
			return TrustVerification::UnknownSigner;
		};

		let algorithm_oid = signer_info.signature_algorithm.oid;
		let signature = signer_info.signature.as_bytes();
		let Ok(public_key_der) = cert.tbs_certificate.subject_public_key_info.to_der() else {
			return TrustVerification::Invalid;
		};

		let Ok(message) = frame.to_tbs() else {
			return TrustVerification::Invalid;
		};

		match self
			.to_policy_ref()
			.verify_signature(&algorithm_oid, &public_key_der, &message, signature)
		{
			Ok(()) => TrustVerification::Verified(cert),
			Err(_) => TrustVerification::Invalid,
		}
	}
}

/// Builder trait for constructing trust stores.
///
/// Validates structural correctness (expiry, issuer/subject chaining) on add.
/// The built store handles cryptographic verification at runtime.
pub trait TrustBuilder: Sized {
	/// The trust store type that this builder produces.
	type Store: CertificateTrust;

	/// Add a certificate chain with structural validation.
	///
	/// Validates expiry and issuer/subject chaining. All certificates
	/// in the chain are added to the trust store.
	fn with_chain(self, chain: impl IntoIterator<Item = Certificate>) -> Result<Self, CertificateValidationError>;

	/// Add a single trusted leaf certificate.
	fn with_certificate(self, cert: Certificate) -> Result<Self, CertificateValidationError>;

	/// Build the sealed trust store.
	fn build(self) -> Self::Store;
}

/// Reject a certificate that bears a critical extension this validator does
/// not process.
///
/// RFC 5280 §4.2 says a certificate-using system MUST reject a certificate
/// when it encounters a critical extension it cannot process, and §6.1.3(f)
/// applies the same rule during path validation
/// (<https://datatracker.ietf.org/doc/html/rfc5280#section-4.2>).
///
/// # Processed extensions
///
/// - `basicConstraints` (§4.2.1.9).
/// - `keyUsage` (§4.2.1.3).
/// - `subjectAltName` (§4.2.1.6). Colony membership consumes it as the URI SAN
///   colony URN, and it MUST be critical when the subject DN is empty
///   (§4.1.2.6).
///
/// Any other critical extension fails closed. That includes `nameConstraints`
/// and `policyConstraints`, which are not implemented.
///
/// # Name-based verification
///
/// This validator performs no name-based endpoint verification. If one is
/// ever added, it MUST match against the SAN contents, because a SAN accepted
/// here is otherwise only consumed for colony membership.
#[cfg(feature = "std")]
fn ensure_critical_extensions_processed(cert: &Certificate) -> Result<(), CertificateValidationError> {
	let Some(extensions) = cert.tbs_certificate.extensions.as_ref() else {
		return Ok(());
	};

	for extension in extensions {
		let processed = extension.extn_id == BasicConstraints::OID
			|| extension.extn_id == KeyUsage::OID
			|| extension.extn_id == SubjectAltName::OID;
		if extension.critical && !processed {
			return Err(CertificateValidationError::UnprocessedCriticalExtension(extension.extn_id));
		}
	}

	Ok(())
}

/// Reject a presented identity certificate that asserts the CA bit.
///
/// This check goes beyond RFC 5280. The terminal certificate of a
/// multi-certificate path is the identity being authenticated, and an
/// identity that carries `basicConstraints.cA` (§4.2.1.9) is misissued for
/// that role.
#[cfg(feature = "std")]
fn ensure_terminal_is_end_entity(path: &[&Certificate]) -> Result<(), CertificateValidationError> {
	let [_, .., terminal] = path else {
		return Ok(());
	};

	match terminal.extension::<BasicConstraints>()? {
		Some(basic_constraints) if basic_constraints.ca => Err(CertificateValidationError::EndEntityIsCa),
		_ => Ok(()),
	}
}

/// Enforce that an issuer certificate is permitted to sign certificates.
///
/// - RFC 5280 §6.1.4(k): the issuer's `basicConstraints` extension MUST be
///   present with `cA` asserted.
/// - RFC 5280 §6.1.4(n): when a `keyUsage` extension is present, it MUST assert `keyCertSign`.
///
/// See <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.4>.
///
/// # Stricter than RFC 5280
///
/// The RFC makes (k) version-conditional, so v1/v2 CAs may be verified out
/// of band. This check enforces (k) unconditionally, so v1/v2 CA
/// certificates are rejected (see [`CertificateTrustStore::validate_path`]).
#[cfg(feature = "std")]
fn ensure_issuer_is_ca(issuer: &Certificate) -> Result<(), CertificateValidationError> {
	match issuer.extension::<BasicConstraints>()? {
		Some(basic_constraints) if basic_constraints.ca => {}
		_ => return Err(CertificateValidationError::IssuerNotCa),
	}

	if let Some(key_usage) = issuer.extension::<KeyUsage>()? {
		if !key_usage.0.contains(KeyUsages::KeyCertSign) {
			return Err(CertificateValidationError::MissingKeyCertSign);
		}
	}

	Ok(())
}

/// Enforce `pathLenConstraint` over a chain ordered from root to leaf.
///
/// RFC 5280 §6.1.4(l),(m): a CA certificate's `pathLenConstraint` bounds the
/// number of intermediate certificates that may follow it in the path before
/// the end-entity. `None` imposes no limit. See
/// <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.4>.
///
/// # Stricter than RFC 5280
///
/// Self-issued intermediates count toward the bound, although clause (l)
/// exempts them (see [`CertificateTrustStore::validate_path`]).
#[cfg(feature = "std")]
fn ensure_path_len(chain: &[&Certificate]) -> Result<(), CertificateValidationError> {
	for (index, cert) in chain.iter().enumerate() {
		let Some(basic_constraints) = cert.extension::<BasicConstraints>()? else {
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

/// The built-in trust store, with cryptographic signature verification.
///
/// It verifies certificate chain signatures at run time through a
/// [`VerificationPolicy`], and it keeps trusted certificate fingerprints in a
/// `HashSet` for O(1) lookup.
#[cfg(feature = "std")]
pub struct CertificateTrustStore {
	/// The trusted certificate fingerprints.
	fingerprints: HashSet<Sha3Fingerprint>,
	/// The full certificates, indexed by fingerprint.
	certificates: HashMap<Sha3Fingerprint, Certificate>,
	/// The precomputed SKID index, from each SKID to its certificate
	/// fingerprint.
	skid_index: HashMap<Skid, Sha3Fingerprint>,
	/// The verification policy that checks signatures.
	policy: Arc<dyn VerificationPolicy>,
	/// The revocation checker that path validation consults.
	revocation: Arc<dyn RevocationChecker>,
}

#[cfg(feature = "std")]
impl CertificateTrustStore {
	/// Compute the certificate fingerprint for digest `D`.
	pub fn to_fingerprint<D>(cert: &Certificate) -> Result<Fingerprint<D>, CertificateValidationError>
	where
		D: Digest<OutputSize = U32>,
	{
		Fingerprint::from_certificate(cert)
	}

	/// The certificate with `fingerprint`, if the store holds one.
	pub fn to_certificate_ref(&self, fingerprint: &Sha3Fingerprint) -> Option<&Certificate> {
		self.certificates.get(fingerprint)
	}

	/// The number of trusted certificates.
	pub fn len(&self) -> usize {
		self.fingerprints.len()
	}

	/// Whether the trust store is empty.
	pub fn is_empty(&self) -> bool {
		self.fingerprints.is_empty()
	}

	/// Validate an ordered certification path, issuer first, from anchor to
	/// leaf.
	///
	/// Both public entry points, [`CertificateValidation::evaluate`] and
	/// [`CertificateTrust::verify_chain`], share these
	/// [RFC 5280 §6.1][rfc5280-6.1] checks, so the two cannot diverge on
	/// validation strength, for example on `pathLenConstraint`.
	///
	/// # Checks
	///
	/// The routine performs these checks over the whole path:
	///
	/// 1. Validity period ([RFC 5280 §6.1.3(a)(2)][rfc5280-6.1.3]).
	/// 2. Rejection of unprocessed critical extensions ([RFC 5280 §4.2, §6.1.3(f)][rfc5280-4.2]).
	/// 3. Algorithm-identifier consistency ([RFC 5280 §4.1.1.2][rfc5280-4.1.1.2]).
	/// 4. Issuer and subject name chaining ([RFC 5280 §6.1.3(a)(4)][rfc5280-6.1.3]).
	/// 5. Issuer `basicConstraints.cA` and `keyUsage.keyCertSign` ([RFC 5280
	///    §6.1.4(k),(n)][rfc5280-6.1.4]).
	/// 6. Cryptographic signature verification ([RFC 5280 §6.1.3(a)(1)][rfc5280-6.1.3]).
	/// 7. Revocation through the configured [`RevocationChecker`] ([RFC 5280
	///    §6.1.3(a)(3)][rfc5280-6.1.3]).
	/// 8. `pathLenConstraint` ([RFC 5280 §6.1.4(l),(m)][rfc5280-6.1.4]).
	///
	/// Trust anchoring is the caller's responsibility. This routine validates
	/// path structure and cryptography only.
	///
	/// # Stricter than RFC 5280
	///
	/// The routine is deliberately stricter than RFC 5280 in five fail-closed
	/// ways. TightBeam runs a closed, self-managed PKI, so the interop these
	/// rules exist for (legacy web roots, cross-signing, cross-vendor DN
	/// encoding variance) never applies, and rejecting it removes attack
	/// surface:
	///
	/// - §6.1.4(k) applies to every issuer, not just v3, so v1/v2 CA
	///   certificates are rejected outright. The RFC permits the rejection.
	/// - Self-issued intermediates count against `pathLenConstraint`, although
	///   §6.1.4(l) exempts them, because key rollover here re-issues the trust
	///   store instead of cross-signing.
	/// - The trust anchor itself is subject to checks 1, 2, 3, 5, 7, and 8,
	///   although §6.1.1(d) treats it as exempt input. An expired, revoked, or
	///   non-CA pinned root fails loudly.
	/// - Name chaining is DER byte equality instead of §7.1 case-insensitive
	///   matching. Both encoders are in-house, and binary comparison forecloses
	///   canonicalization ambiguity.
	/// - The terminal certificate of a multi-certificate path must not assert
	///   `basicConstraints.cA`, so an authenticated identity misissued with CA
	///   power is rejected ([`ensure_terminal_is_end_entity`]).
	///
	/// [rfc5280-6.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1
	/// [rfc5280-6.1.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.3
	/// [rfc5280-6.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.4
	/// [rfc5280-4.2]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2
	/// [rfc5280-4.1.1.2]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2
	fn validate_path(&self, path: &[&Certificate]) -> Result<(), CertificateValidationError> {
		// RFC 5280 §6.1.3(a)(2): each certificate is within its validity
		// period.
		path.iter().try_for_each(|cert| cert.validate_expiry())?;

		// RFC 5280 §4.2, §6.1.3(f): an unprocessed critical extension fails
		// closed.
		path.iter().try_for_each(|cert| ensure_critical_extensions_processed(cert))?;

		// Defense in depth: the terminal identity must not assert the CA bit.
		ensure_terminal_is_end_entity(path)?;

		// RFC 5280 §4.1.1.2: `signatureAlgorithm` must match
		// `tbsCertificate.signature`.
		path.iter().try_for_each(|cert| cert.ensure_signature_algorithm_consistency())?;

		// A sliding window checks each issuer and subject pair.
		path.windows(2).try_for_each(|pair| {
			let (issuer, cert) = (pair[0], pair[1]);

			// RFC 5280 §6.1.3(a)(4): the issuer DN must equal the preceding
			// certificate's subject DN.
			if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
				return Err(CertificateValidationError::InvalidChain {
					issuer: cert.tbs_certificate.issuer.to_string(),
					subject: issuer.tbs_certificate.subject.to_string(),
				});
			}

			// RFC 5280 §6.1.4(k),(n): the issuer must be a CA that may sign
			// certificates.
			ensure_issuer_is_ca(issuer)?;

			// RFC 5280 §6.1.3(a)(1): the issuer's key verifies the signature.
			let algorithm_oid = cert.signature_algorithm.oid;
			let public_key_der = issuer.tbs_certificate.subject_public_key_info.to_der()?;
			let message = cert.tbs_certificate.to_der()?;
			let signature_bytes = cert.signature.raw_bytes();

			self.policy
				.verify_signature(&algorithm_oid, &public_key_der, &message, signature_bytes)
		})?;

		// RFC 5280 §6.1.3(a)(3): the configured checker runs revocation. The
		// anchor is checked against itself as issuer, which is stricter than
		// §6.1.1(d) and consistent with the anchor checks above.
		if let Some(anchor) = path.first() {
			self.revocation.check(anchor, anchor)?;
		}
		path.windows(2).try_for_each(|pair| self.revocation.check(pair[0], pair[1]))?;

		// RFC 5280 §6.1.4(m): `pathLenConstraint` holds across the path.
		ensure_path_len(path)
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
		// Walk the issuer hierarchy as far as the store material allows, then
		// validate the accumulated path with the shared routine.
		//
		// Issuer selection assumes at most one stored certificate per subject
		// DN. `find` commits to the first DN match and fails closed if that
		// candidate cannot verify. Full RFC 4158 path building, with
		// backtracking across same-DN candidates, is intentionally out of
		// scope.
		let mut path: Vec<&Certificate> = Vec::new();
		let mut visited: HashSet<Sha3Fingerprint> = HashSet::new();

		visited.insert(Self::to_fingerprint(cert)?);
		path.push(cert);

		let mut current = cert;
		loop {
			// RFC 5280 §6.1.3(a)(4): locate an issuer whose subject DN matches
			// the current certificate's issuer DN.
			let Some(issuer) = self
				.certificates
				.values()
				.find(|c| c.tbs_certificate.subject == current.tbs_certificate.issuer)
			else {
				break;
			};

			// A revisited certificate ends the walk. That covers a self-issued
			// root and RFC 4158 §2.4.2 loop detection.
			if !visited.insert(Self::to_fingerprint(issuer)?) {
				break;
			}

			path.push(issuer);
			current = issuer;
		}

		// RFC 5280 §6.1.1: the walk must reach a configured trust anchor.
		if !self.is_trusted(current) {
			return Err(CertificateValidationError::CertificateNotTrusted);
		}

		// Validate anchor first, issuer before subject, as `verify_chain` does.
		path.reverse();
		self.validate_path(&path)
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
		// RFC 5280 §6.1.1: the chain must end at a configured trust anchor.
		let root = chain.first().ok_or(CertificateValidationError::EmptyChain)?;
		if !self.is_trusted(root) {
			return Err(CertificateValidationError::CertificateNotTrusted);
		}

		// `evaluate` shares this path-validation routine, so the two entry
		// points cannot diverge.
		let path: Vec<&Certificate> = chain.iter().collect();
		self.validate_path(&path)
	}

	fn find_by_signer_identifier(&self, sid: &SignerIdentifier) -> Option<&Certificate> {
		match sid {
			SignerIdentifier::IssuerAndSerialNumber(ias) => self.certificates.values().find(|cert| {
				cert.tbs_certificate.issuer == ias.issuer && cert.tbs_certificate.serial_number == ias.serial_number
			}),
			SignerIdentifier::SubjectKeyIdentifier(skid) => {
				let key = Skid::parse(skid.0.as_bytes())?;
				self.skid_index.get(&key).and_then(|fp| self.certificates.get(fp))
			}
		}
	}

	fn to_policy_ref(&self) -> &dyn VerificationPolicy {
		&*self.policy
	}
}

/// The builder of a [`CertificateTrustStore`].
///
/// It validates structural correctness, which is expiry and issuer and
/// subject chaining, on each add. The resulting store handles cryptographic
/// verification at run time.
///
/// SKIDs are indexed through [`Skid::of_public_key`], the same home a signer
/// stamps from, so a store resolves the identifiers its peers actually send.
#[cfg(feature = "std")]
pub struct CertificateTrustBuilder {
	fingerprints: HashSet<Sha3Fingerprint>,
	certificates: HashMap<Sha3Fingerprint, Certificate>,
	skid_index: HashMap<Skid, Sha3Fingerprint>,
	policy: Arc<dyn VerificationPolicy>,
	revocation: Arc<dyn RevocationChecker>,
}

#[cfg(feature = "std")]
impl<P: VerificationPolicy + 'static> From<P> for CertificateTrustBuilder {
	fn from(policy: P) -> Self {
		Self {
			fingerprints: HashSet::new(),
			certificates: HashMap::new(),
			skid_index: HashMap::new(),
			policy: Arc::new(policy),
			revocation: Arc::new(NoRevocation),
		}
	}
}

#[cfg(feature = "std")]
impl CertificateTrustBuilder {
	/// Set the revocation checker consulted during path validation.
	///
	/// The default is [`NoRevocation`], the documented closed-PKI waiver.
	pub fn with_revocation_checker(mut self, checker: impl RevocationChecker + 'static) -> Self {
		self.revocation = Arc::new(checker);
		self
	}

	/// Index one certificate by fingerprint and by SKID.
	fn add_certificate(&mut self, cert: Certificate) -> Result<(), CertificateValidationError> {
		let fp = CertificateTrustStore::to_fingerprint::<Sha3_256>(&cert)?;

		let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
		let skid = Skid::of_public_key(&spki_der);
		if let Some(existing_fp) = self.skid_index.get(&skid) {
			// One SKID under two fingerprints is a collision.
			if *existing_fp != fp {
				return Err(CertificateValidationError::SkidCollision {
					skid: skid.as_bytes().iter().fold(String::new(), |mut acc, byte| {
						use core::fmt::Write;
						let _ = write!(acc, "{byte:02x}");
						acc
					}),
				});
			}
		}

		self.fingerprints.insert(fp);
		self.skid_index.insert(skid, fp);
		self.certificates.insert(fp, cert);

		Ok(())
	}
}

#[cfg(feature = "std")]
impl TrustBuilder for CertificateTrustBuilder {
	type Store = CertificateTrustStore;

	fn with_chain(mut self, chain: impl IntoIterator<Item = Certificate>) -> Result<Self, CertificateValidationError> {
		let chain: Vec<Certificate> = chain.into_iter().collect();
		if chain.is_empty() {
			return Err(CertificateValidationError::EmptyChain);
		}

		chain.iter().try_for_each(CertificateExt::validate_expiry)?;

		// The builder checks name chaining only, and signatures verify at run
		// time.
		chain.windows(2).try_for_each(|pair| {
			let (issuer, cert) = (&pair[0], &pair[1]);
			(cert.tbs_certificate.issuer == issuer.tbs_certificate.subject)
				.then_some(())
				.ok_or_else(|| CertificateValidationError::InvalidChain {
					issuer: cert.tbs_certificate.issuer.to_string(),
					subject: issuer.tbs_certificate.subject.to_string(),
				})
		})?;

		chain.into_iter().try_for_each(|cert| self.add_certificate(cert))?;

		Ok(self)
	}

	fn with_certificate(mut self, cert: Certificate) -> Result<Self, CertificateValidationError> {
		cert.validate_expiry()?;
		self.add_certificate(cert)?;
		Ok(self)
	}

	fn build(self) -> Self::Store {
		CertificateTrustStore {
			fingerprints: self.fingerprints,
			certificates: self.certificates,
			skid_index: self.skid_index,
			policy: self.policy,
			revocation: self.revocation,
		}
	}
}

#[cfg(feature = "std")]
impl Debug for CertificateTrustBuilder {
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
	use crate::testing::fixtures::{TestCertificate, TestCertificateChain};
	use crate::testing::TestKey;

	type TestResult = Result<(), Box<dyn std::error::Error>>;

	/// The certificates that a test adds to the trust store.
	#[derive(Debug, Clone, Copy)]
	enum StoreCerts {
		None,
		Root,
		RootAndIntermediate,
	}

	/// The certificate that a test evaluates.
	#[derive(Debug, Clone, Copy)]
	enum EvalTarget {
		Root,
		Intermediate,
		Leaf,
	}

	/// Build a trust store that holds `certs` from `chain`.
	fn build_store(
		chain: &TestCertificateChain,
		certs: StoreCerts,
	) -> Result<CertificateTrustStore, CertificateValidationError> {
		let builder: CertificateTrustBuilder = Secp256k1Policy.into();
		let builder = match certs {
			StoreCerts::None => builder,
			StoreCerts::Root => {
				let certificate = chain.root.to_owned();
				builder.with_certificate(certificate)?
			}
			StoreCerts::RootAndIntermediate => {
				let root = chain.root.to_owned();
				let intermediate = chain.intermediate.to_owned();
				builder.with_certificate(root)?.with_certificate(intermediate)?
			}
		};

		Ok(builder.build())
	}

	/// The certificate in `chain` that `target` names.
	fn target_cert(chain: &TestCertificateChain, target: EvalTarget) -> &Certificate {
		match target {
			EvalTarget::Root => &chain.root,
			EvalTarget::Intermediate => &chain.intermediate,
			EvalTarget::Leaf => &chain.leaf,
		}
	}

	#[test]
	fn fingerprint_is_32_bytes() -> TestResult {
		let cert = TestCertificate::self_signed(&TestKey::signing());
		assert_eq!(CertificateTrustStore::to_fingerprint::<Sha3_256>(&cert)?.as_slice().len(), 32);
		Ok(())
	}

	#[test]
	fn is_trusted_matches_fingerprint() -> TestResult {
		let cert = TestCertificate::self_signed(&TestKey::signing());
		let certificate = cert.to_owned();
		let store = CertificateTrustBuilder::from(Secp256k1Policy)
			.with_certificate(certificate)?
			.build();
		assert!(store.is_trusted(&cert));
		assert!(!store.is_trusted(&TestCertificate::self_signed(&SigningKey::from_bytes(&[2u8; 32].into())?)));
		Ok(())
	}

	#[test]
	fn trusts_public_key_matches_rotated_certificate() -> TestResult {
		let key = TestKey::signing();
		let enrolled = TestCertificate::with_cn_and_uri_sans(&key, "enrolled", &["urn:tightbeam:colony:test"]);
		let rotated = TestCertificate::with_cn_and_uri_sans(&key, "rotated", &["urn:tightbeam:colony:test"]);
		let store = CertificateTrustBuilder::from(Secp256k1Policy)
			.with_certificate(enrolled.clone())?
			.build();
		assert!(store.is_trusted(&enrolled));
		assert!(!store.is_trusted(&rotated));
		assert!(store.trusts_public_key(&rotated));
		assert!(!store.trusts_public_key(&TestCertificate::self_signed(&SigningKey::from_bytes(&[2u8; 32].into())?)));
		Ok(())
	}

	#[test]
	fn builder_validates_chain_structure() -> TestResult {
		let chain = TestCertificate::chain()?;
		let chain = vec![chain.root, chain.intermediate, chain.leaf];
		assert!(CertificateTrustBuilder::from(Secp256k1Policy).with_chain(chain).is_ok());
		Ok(())
	}

	/// Cases of `(store, target, passes)` for `evaluate` with chain walking.
	const EVALUATE_CASES: &[(StoreCerts, EvalTarget, bool)] = &[
		// A trusted root passes directly.
		(StoreCerts::Root, EvalTarget::Root, true),
		// The presented identity asserts the CA bit, so it fails with
		// `EndEntityIsCa`.
		(StoreCerts::Root, EvalTarget::Intermediate, false),
		// Chain walking lets the root and the intermediate trust the leaf.
		(StoreCerts::RootAndIntermediate, EvalTarget::Leaf, true),
		// The root alone cannot verify the leaf without the intermediate.
		(StoreCerts::Root, EvalTarget::Leaf, false),
		// An empty store trusts nothing.
		(StoreCerts::None, EvalTarget::Leaf, false),
	];

	#[test]
	fn evaluate_chain_walking() -> TestResult {
		let chain = TestCertificate::chain()?;
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
		// The store holds one chain's root, and the leaf comes from another
		// chain.
		let store = CertificateTrustBuilder::from(Secp256k1Policy)
			.with_certificate(TestCertificate::self_signed(&TestKey::signing()))?
			.build();

		let other_chain = TestCertificate::chain()?;
		assert!(store.evaluate(&other_chain.leaf).is_err());
		Ok(())
	}

	#[test]
	fn verify_chain_cases() -> TestResult {
		let chain = TestCertificate::chain()?;
		let cases: &[(StoreCerts, &[&Certificate], bool)] = &[
			// An empty chain fails.
			(StoreCerts::Root, &[], false),
			// An untrusted root fails.
			(StoreCerts::None, &[&chain.root], false),
			// A trusted root alone succeeds.
			(StoreCerts::Root, &[&chain.root], true),
			// A full chain with a trusted root succeeds.
			(StoreCerts::Root, &[&chain.root, &chain.intermediate, &chain.leaf], true),
		];

		for (store_certs, chain_slice, should_succeed) in cases {
			let store = build_store(&chain, *store_certs)?;
			let chain_vec: Vec<_> = chain_slice.iter().map(|c| (*c).to_owned()).collect();

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

	/// Cases for the RFC 5280 §6.1.4 path constraints.
	///
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
			let chain = TestCertificate::chain()?;

			let mut root = chain.root.to_owned();
			root.tbs_certificate.extensions = Some(TestCertificate::ca_extensions(*ca, *key_cert_sign, *path_len));

			let certificate = root.to_owned();
			let store = CertificateTrustBuilder::from(Secp256k1Policy)
				.with_certificate(certificate)?
				.build();
			let result = store.verify_chain(&[root, chain.intermediate, chain.leaf]);
			assert!(matches!(result, Err(ref e) if core::mem::discriminant(e) == core::mem::discriminant(expected)));
		}

		Ok(())
	}

	#[test]
	fn evaluate_enforces_path_len_constraint() -> TestResult {
		let chain = TestCertificate::chain()?;

		let mut root = chain.root.to_owned();
		root.tbs_certificate.extensions = Some(TestCertificate::ca_extensions(true, true, Some(0)));

		let store = CertificateTrustBuilder::from(Secp256k1Policy)
			.with_certificate(root)?
			.with_certificate(chain.intermediate)?
			.build();
		assert!(matches!(
			store.evaluate(&chain.leaf),
			Err(CertificateValidationError::PathLenExceeded)
		));
		Ok(())
	}

	/// Wrap an empty payload in an extension with the given OID and
	/// criticality, for the RFC 5280 §4.2 critical-extension tests.
	fn opaque_extension(oid: impl AsRef<str>, critical: bool) -> crate::x509::ext::Extension {
		let oid = oid.as_ref();
		crate::x509::ext::Extension {
			extn_id: crate::der::oid::ObjectIdentifier::new_unwrap(oid),
			critical,
			extn_value: crate::der::asn1::OctetString::new(Vec::new()).expect("empty payload fits an OCTET STRING"),
		}
	}

	#[test]
	fn rejects_unknown_critical_extension() {
		// nameConstraints (2.5.29.30) is not processed by this validator.
		let mut cert = TestCertificate::self_signed(&TestKey::signing());
		cert.tbs_certificate.extensions = Some(vec![opaque_extension("2.5.29.30", true)]);
		assert!(matches!(
			ensure_critical_extensions_processed(&cert),
			Err(CertificateValidationError::UnprocessedCriticalExtension(_))
		));
	}

	#[test]
	fn accepts_unknown_noncritical_extension() {
		let mut cert = TestCertificate::self_signed(&TestKey::signing());
		cert.tbs_certificate.extensions = Some(vec![opaque_extension("2.5.29.30", false)]);
		assert!(ensure_critical_extensions_processed(&cert).is_ok());
	}

	#[test]
	fn accepts_processed_critical_extensions() {
		let mut cert = TestCertificate::self_signed(&TestKey::signing());
		cert.tbs_certificate.extensions = Some(TestCertificate::ca_extensions(true, true, None));
		assert!(ensure_critical_extensions_processed(&cert).is_ok());
	}

	#[test]
	fn accepts_critical_subject_alt_name() {
		// subjectAltName (2.5.29.17) is processed for colony membership and
		// MUST be critical when the subject DN is empty (RFC 5280 §4.1.2.6).
		let mut cert = TestCertificate::self_signed(&TestKey::signing());
		cert.tbs_certificate.extensions = Some(vec![opaque_extension("2.5.29.17", true)]);
		assert!(ensure_critical_extensions_processed(&cert).is_ok());
	}

	#[test]
	fn verify_chain_rejects_unknown_critical_extension() -> TestResult {
		let chain = TestCertificate::chain()?;

		let mut leaf = chain.leaf.to_owned();
		leaf.tbs_certificate.extensions = Some(vec![opaque_extension("2.5.29.30", true)]);

		let store = build_store(&chain, StoreCerts::Root)?;
		let result = store.verify_chain(&[chain.root, chain.intermediate, leaf]);
		assert!(matches!(
			result,
			Err(CertificateValidationError::UnprocessedCriticalExtension(_))
		));
		Ok(())
	}

	// The end-entity CA-bit check is defense in depth.
	#[test]
	fn terminal_with_ca_bit_rejected() -> TestResult {
		let chain = TestCertificate::chain()?;
		// The intermediate carries `basicConstraints.cA = true` as the terminal
		// of `[root, intermediate]`.
		let path = [&chain.root, &chain.intermediate];
		assert!(matches!(
			ensure_terminal_is_end_entity(&path),
			Err(CertificateValidationError::EndEntityIsCa)
		));
		Ok(())
	}

	#[test]
	fn terminal_without_ca_bit_accepted() -> TestResult {
		let chain = TestCertificate::chain()?;
		let path = [&chain.root, &chain.intermediate, &chain.leaf];
		assert!(ensure_terminal_is_end_entity(&path).is_ok());
		Ok(())
	}

	#[test]
	fn single_certificate_path_exempt_from_ca_bit_check() -> TestResult {
		let chain = TestCertificate::chain()?;
		// A pinned CA root validating itself is the direct-trust model.
		let path = [&chain.root];
		assert!(ensure_terminal_is_end_entity(&path).is_ok());
		Ok(())
	}

	/// Build a store that trusts the chain root under `revocation`, for the
	/// RFC 5280 §6.1.3(a)(3) revocation tests.
	fn build_store_with_revocation(
		chain: &TestCertificateChain,
		revocation: StaticRevocationList,
	) -> Result<CertificateTrustStore, CertificateValidationError> {
		let root = chain.root.to_owned();
		Ok(CertificateTrustBuilder::from(Secp256k1Policy)
			.with_revocation_checker(revocation)
			.with_certificate(root)?
			.build())
	}

	#[test]
	fn static_revocation_list_passes_unlisted_certificate() -> TestResult {
		let chain = TestCertificate::chain()?;
		let revocation = StaticRevocationList::default().with_certificate(&chain.intermediate)?;
		assert!(revocation.check(&chain.intermediate, &chain.leaf).is_ok());
		Ok(())
	}

	#[test]
	fn verify_chain_rejects_leaf_revoked_by_fingerprint() -> TestResult {
		let chain = TestCertificate::chain()?;
		let revocation = StaticRevocationList::default().with_certificate(&chain.leaf)?;

		let store = build_store_with_revocation(&chain, revocation)?;
		let result = store.verify_chain(&[chain.root, chain.intermediate, chain.leaf]);
		assert!(matches!(result, Err(CertificateValidationError::CertificateRevoked)));
		Ok(())
	}

	#[test]
	fn verify_chain_rejects_leaf_revoked_by_serial() -> TestResult {
		let chain = TestCertificate::chain()?;
		let issuer = chain.leaf.tbs_certificate.issuer.to_owned();
		let serial = chain.leaf.tbs_certificate.serial_number.as_bytes().to_vec();
		let revocation = StaticRevocationList::default().with_serial(&issuer, serial)?;

		let store = build_store_with_revocation(&chain, revocation)?;
		let result = store.verify_chain(&[chain.root, chain.intermediate, chain.leaf]);
		assert!(matches!(result, Err(CertificateValidationError::CertificateRevoked)));
		Ok(())
	}

	#[test]
	fn serial_revocation_is_scoped_to_issuer() -> TestResult {
		let chain = TestCertificate::chain()?;
		let other_issuer = chain.leaf.tbs_certificate.subject.to_owned();
		let serial = chain.leaf.tbs_certificate.serial_number.as_bytes().to_vec();
		let revocation = StaticRevocationList::default().with_serial(&other_issuer, serial)?;

		let store = build_store_with_revocation(&chain, revocation)?;
		let result = store.verify_chain(&[chain.root, chain.intermediate, chain.leaf]);
		assert!(result.is_ok());
		Ok(())
	}

	#[test]
	fn verify_chain_rejects_revoked_anchor() -> TestResult {
		let chain = TestCertificate::chain()?;
		let revocation = StaticRevocationList::default().with_certificate(&chain.root)?;

		let store = build_store_with_revocation(&chain, revocation)?;
		let result = store.verify_chain(&[chain.root]);
		assert!(matches!(result, Err(CertificateValidationError::CertificateRevoked)));
		Ok(())
	}

	// RFC 5280 §4.1.1.2 requires algorithm identifier consistency.
	#[test]
	fn rejects_algorithm_identifier_mismatch() -> TestResult {
		let chain = TestCertificate::chain()?;

		let mut leaf = chain.leaf.to_owned();
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

	// A signer stamps its SubjectKeyIdentifier into the `SignerInfo`, and a
	// store indexes by the same value, so the two must come from one digest.
	#[test]
	fn a_signer_stamps_the_identifier_its_certificate_indexes_under() -> TestResult {
		let key = TestKey::signing();
		let cert = TestCertificate::self_signed(&key);
		let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;

		let stamped = key.to_signer_info(b"payload")?.sid;
		let indexed = compute_signer_identifier_from_der(&spki_der)?;

		assert_eq!(stamped, indexed);
		Ok(())
	}

	#[test]
	fn find_by_signer_info_skid() -> TestResult {
		let key = TestKey::signing();
		let cert = TestCertificate::self_signed(&key);
		let certificate = cert.to_owned();
		let store = CertificateTrustBuilder::from(Secp256k1Policy)
			.with_certificate(certificate)?
			.build();

		// The `Signatory` trait builds the signer info with a SHA3-256 SKID.
		let signer_info = key.to_signer_info(b"test")?;
		// The store must find the certificate.
		let Some(found) = store.find_by_signer_info(&signer_info) else {
			return Err(crate::testing::error::TestingError::InvariantViolated.into());
		};
		assert_eq!(
			CertificateTrustStore::to_fingerprint::<Sha3_256>(found)?,
			CertificateTrustStore::to_fingerprint::<Sha3_256>(&cert)?
		);

		Ok(())
	}

	#[test]
	fn find_by_signer_info_not_found() -> TestResult {
		let store = CertificateTrustBuilder::from(Secp256k1Policy)
			.with_certificate(TestCertificate::self_signed(&TestKey::signing()))?
			.build();

		// A different key signs.
		let other_key = SigningKey::from_bytes(&[99u8; 32].into())?;
		let signer_info = other_key.to_signer_info(b"test")?;
		assert!(store.find_by_signer_info(&signer_info).is_none());

		Ok(())
	}
}
