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
use crate::crypto::x509::{Certificate, ErasedSigning, PeerCertificate};
use crate::spki::SubjectPublicKeyInfoOwned;

#[cfg(feature = "signature")]
use crate::crypto::policy::VerifiedSignature;

#[cfg(feature = "std")]
mod std_imports {
	pub use std::collections::{HashMap, HashSet};
	pub use std::sync::Arc;

	pub use crate::crypto::hash::{Digest, Sha3_256, U32};
	pub use crate::crypto::x509::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier};
	pub use crate::crypto::x509::name::Name;
	pub use crate::crypto::x509::utils::{CertificateExt, Fingerprint};
	pub use crate::crypto::x509::KeyPurposes;
	pub use crate::der::Encode;
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
/// It distinguishes "no identity claimed" and "unknown identity claimed" from
/// "trusted identity claimed with a bad signature", so callers can apply
/// different consequences.
#[cfg(feature = "signature")]
#[must_use = "a dropped TrustVerification leaves the frame unauthenticated"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustVerification<'a> {
	/// The frame carries no nonrepudiation signature.
	MissingSignature,
	/// The trust store holds no certificate for the signer.
	UnknownSigner,
	/// The signer is trusted, and the signature fails verification.
	Invalid,
	/// The signature verified against the certificate that this store
	/// resolved, which it admitted for signing at enrolment. The verified
	/// signature is the replay key of the frame.
	Verified(&'a PeerCertificate<ErasedSigning>, VerifiedSignature),
}

/// Certificate trust verification.
///
/// It extends [`CertificateValidation`] with trust-based operations. An
/// implementation may use fingerprints, PKI chains, or custom logic.
/// [`CertificateTrustStore`] is the built-in store and needs `std`, so a
/// no_std consumer supplies its own implementation of this trait.
pub trait CertificateTrust: CertificateValidation + Debug + Send + Sync {
	/// Returns whether the store trusts `cert` by fingerprint.
	///
	/// This is certificate-object identity. Plane membership that must survive
	/// the re-issuance of a certificate for the same key uses
	/// [`Self::trusts_public_key`].
	fn is_trusted(&self, cert: &Certificate) -> bool;

	/// Returns whether this store holds any certificate for `cert`'s public
	/// key.
	///
	/// Membership is [`Self::enrolled_certificate`] answering for the key, so
	/// a rotated certificate for an enrolled key still matches. Implementors
	/// that answer [`Self::find_by_public_key`] correctly get this behavior
	/// without an override.
	#[must_use = "a dropped membership answer leaves the plane gate unenforced"]
	fn trusts_public_key(&self, cert: &Certificate) -> bool {
		self.enrolled_certificate(cert).is_some()
	}

	/// Returns the certificate this store holds for `cert`'s public key.
	///
	/// The lookup is the SubjectPublicKeyInfo, resolved through
	/// [`Self::find_by_public_key`]. A rotated certificate for an enrolled key
	/// therefore resolves to the enrolled one, which is the certificate a
	/// signature by that key verifies against.
	fn enrolled_certificate(&self, cert: &Certificate) -> Option<&Certificate> {
		self.find_by_public_key(&cert.tbs_certificate.subject_public_key_info)
	}

	/// Find a certificate by its SubjectPublicKeyInfo.
	///
	/// This is the key-identity lookup that plane membership uses. It matches
	/// the key whatever certificate carries it.
	fn find_by_public_key(&self, spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate>;

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
	/// - [`CertificateValidationError`] -- the chain fails validation.
	fn verify_chain(&self, chain: &[Certificate]) -> Result<(), CertificateValidationError>;

	/// Find a certificate admitted for signing by CMS [`SignerIdentifier`].
	///
	/// Frame verification resolves its signer here (RFC 5652 §5.3):
	///
	/// - The subject-key-identifier form matches a certificate's `subjectKeyIdentifier` extension value.
	/// - The issuer-and-serial form matches its issuer and serial number.
	///
	/// A store admits each certificate for signing once, at enrolment, so a
	/// certificate that only certifies others resolves no signer.
	fn find_by_signer_identifier(&self, sid: &SignerIdentifier) -> Option<&PeerCertificate<ErasedSigning>>;

	/// Find a certificate admitted for signing by `SignerInfo`.
	///
	/// Frame signature verification uses it. It resolves through
	/// [`Self::find_by_signer_identifier`] on the info's `sid`.
	fn find_by_signer_info(&self, signer_info: &crate::SignerInfo) -> Option<&PeerCertificate<ErasedSigning>> {
		self.find_by_signer_identifier(&signer_info.sid)
	}

	/// Returns the verification policy for signature operations.
	fn to_policy_ref(&self) -> &dyn VerificationPolicy;

	/// Verify `frame`'s nonrepudiation signature against this store.
	///
	/// The store looks up the signer certificate through the frame's
	/// `SignerInfo`, and the CMS signer verifies the signed attributes and the
	/// signature over the frame's to-be-signed bytes under this store's
	/// policy. The verified arm returns:
	///
	/// - The certificate, so a later step reuses it instead of a second lookup.
	/// - The verified signature, so a replay guard keys on its canonical form.
	#[cfg(feature = "signature")]
	#[must_use = "a dropped TrustVerification leaves the frame unauthenticated"]
	fn verify_frame<'a>(&'a self, frame: &crate::Frame) -> TrustVerification<'a> {
		let Some(signer_info) = frame.nonrepudiation() else {
			return TrustVerification::MissingSignature;
		};

		let Some(signer) = self.find_by_signer_info(signer_info) else {
			return TrustVerification::UnknownSigner;
		};

		match frame.verify_under(signer, self.to_policy_ref()) {
			Ok(signature) => TrustVerification::Verified(signer, signature),
			Err(_) => TrustVerification::Invalid,
		}
	}
}

/// A builder of trust stores.
///
/// The builder validates structural correctness, which is expiry and issuer and
/// subject chaining, on each add. The built store handles cryptographic
/// verification at run time.
pub trait TrustBuilder: Sized {
	/// The trust store type that this builder produces.
	type Store: CertificateTrust;

	/// Add a certificate chain after structural validation.
	///
	/// The builder validates expiry and issuer and subject chaining, then adds
	/// every certificate in the chain to the trust store.
	fn with_chain(self, chain: impl IntoIterator<Item = Certificate>) -> Result<Self, CertificateValidationError>;

	/// Add a single trusted certificate after an expiry check.
	fn with_certificate(self, cert: Certificate) -> Result<Self, CertificateValidationError>;

	/// Build the sealed trust store.
	fn build(self) -> Self::Store;
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
/// - RFC 5280 §6.1.4(k): the issuer's `basicConstraints` extension MUST be present with `cA` asserted.
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

		// This counts the certificates strictly between this CA and the
		// end-entity leaf.
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
	certificates: HashMap<Sha3Fingerprint, Arc<Certificate>>,
	/// The certificates admitted for signing at enrolment, indexed by
	/// fingerprint, each sharing its certificate with [`Self::certificates`].
	signers: HashMap<Sha3Fingerprint, PeerCertificate<ErasedSigning>>,
	/// The `subjectKeyIdentifier` extension values, each to its certificate
	/// fingerprint.
	skid_index: HashMap<Vec<u8>, Sha3Fingerprint>,
	/// The DER SubjectPublicKeyInfo of each certificate, to its fingerprint.
	key_index: HashMap<Vec<u8>, Sha3Fingerprint>,
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

	/// Returns the certificate with `fingerprint`, if the store holds one.
	pub fn to_certificate_ref(&self, fingerprint: &Sha3Fingerprint) -> Option<&Certificate> {
		self.certificates.get(fingerprint).map(Arc::as_ref)
	}

	/// Returns the number of trusted certificates.
	pub fn len(&self) -> usize {
		self.fingerprints.len()
	}

	/// Returns whether the trust store is empty.
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
	/// 2. Rejection of unprocessed critical extensions and of a repeated
	///    extension ([RFC 5280 §4.2, §6.1.3(f)][rfc5280-4.2]).
	/// 3. Algorithm-identifier consistency ([RFC 5280 §4.1.1.2][rfc5280-4.1.1.2]).
	/// 4. Issuer and subject name chaining ([RFC 5280 §6.1.3(a)(4)][rfc5280-6.1.3]).
	/// 5. Issuer `basicConstraints.cA` and `keyUsage.keyCertSign` ([RFC 5280 §6.1.4(k),(n)][rfc5280-6.1.4]).
	/// 6. Cryptographic signature verification ([RFC 5280 §6.1.3(a)(1)][rfc5280-6.1.3]).
	/// 7. Revocation through the configured [`RevocationChecker`] ([RFC 5280 §6.1.3(a)(3)][rfc5280-6.1.3]).
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
	/// - §6.1.4(k) applies to every issuer and not only to v3 issuers, so v1/v2
	///   CA certificates are rejected outright. The RFC permits the rejection.
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

		// RFC 5280 §4.2, §6.1.3(f): an unprocessed critical extension, or a
		// repeated extension, fails closed.
		path.iter().try_for_each(|cert| cert.ensure_critical_extensions_processed())?;
		path.iter().try_for_each(|cert| cert.ensure_unique_extensions())?;

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
				// A certificate signature is the key of no ledger, so its
				// canonical form drops here.
				.map(drop)
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
	/// Walk the issuer hierarchy as far as the store material allows, then
	/// validate the accumulated path with the shared path-validation routine.
	///
	/// # Issuer selection
	///
	/// Issuer selection assumes at most one stored certificate per subject DN.
	/// The walk commits to the first DN match and fails closed if that
	/// candidate cannot verify. Full RFC 4158 path building, with backtracking
	/// across same-DN candidates, is intentionally out of scope.
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		let mut path: Vec<&Certificate> = Vec::new();
		let mut visited: HashSet<Sha3Fingerprint> = HashSet::new();

		visited.insert(Self::to_fingerprint(cert)?);
		path.push(cert);

		let mut current = cert;
		loop {
			// RFC 5280 §6.1.3(a)(4): locate an issuer whose subject DN matches
			// the current certificate's issuer DN.
			let mut held = self.certificates.values().map(Arc::as_ref);
			let Some(issuer) = held.find(|c| c.tbs_certificate.subject == current.tbs_certificate.issuer) else {
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

	fn find_by_signer_identifier(&self, sid: &SignerIdentifier) -> Option<&PeerCertificate<ErasedSigning>> {
		match sid {
			SignerIdentifier::IssuerAndSerialNumber(_) => {
				let mut signers = self.signers.values();
				signers.find(|signer| signer.certificate().is_named_by(sid).is_ok_and(|named| named))
			}
			SignerIdentifier::SubjectKeyIdentifier(skid) => {
				let fingerprint = self.skid_index.get(skid.0.as_bytes())?;
				self.signers.get(fingerprint)
			}
		}
	}

	fn find_by_public_key(&self, spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate> {
		let spki_der = spki.to_der().ok()?;
		let fingerprint = self.key_index.get(&spki_der)?;
		self.certificates.get(fingerprint).map(Arc::as_ref)
	}

	fn to_policy_ref(&self) -> &dyn VerificationPolicy {
		&*self.policy
	}
}

/// The builder of a [`CertificateTrustStore`].
///
/// It validates structural correctness, which is expiry and issuer and
/// subject chaining, on each add. The resulting store handles cryptographic
/// verification at run time. It indexes each certificate twice:
///
/// - By its `subjectKeyIdentifier` value, which a `sid` resolves through (RFC 5652 §5.3).
/// - By its SubjectPublicKeyInfo, which plane membership reads.
///
/// [`TrustBuilder::build`] admits the signers among them under the signer
/// purpose of its [`KeyPurposes`].
#[cfg(feature = "std")]
pub struct CertificateTrustBuilder {
	fingerprints: HashSet<Sha3Fingerprint>,
	certificates: HashMap<Sha3Fingerprint, Arc<Certificate>>,
	purposes: KeyPurposes,
	skid_index: HashMap<Vec<u8>, Sha3Fingerprint>,
	key_index: HashMap<Vec<u8>, Sha3Fingerprint>,
	policy: Arc<dyn VerificationPolicy>,
	revocation: Arc<dyn RevocationChecker>,
}

#[cfg(feature = "std")]
impl<P: VerificationPolicy + 'static> From<P> for CertificateTrustBuilder {
	fn from(policy: P) -> Self {
		Self {
			fingerprints: HashSet::new(),
			certificates: HashMap::new(),
			purposes: KeyPurposes::default(),
			skid_index: HashMap::new(),
			key_index: HashMap::new(),
			policy: Arc::new(policy),
			revocation: Arc::new(NoRevocation),
		}
	}
}

/// `bytes` as lowercase hexadecimal, the form a collision error names its
/// index entry in.
#[cfg(feature = "std")]
fn to_hex(bytes: &[u8]) -> String {
	bytes.iter().fold(String::new(), |mut acc, byte| {
		use core::fmt::Write;
		// A write into a `String` always returns `Ok`.
		let _ = write!(acc, "{byte:02x}");
		acc
	})
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

	/// Set the key purposes the store admits its signers under, the
	/// [`KeyPurposes::signer`] purpose for a frame and colony signer.
	///
	/// The default is [`KeyPurposes::HOUSE`].
	pub fn with_key_purposes(mut self, purposes: KeyPurposes) -> Self {
		self.purposes = purposes;
		self
	}

	/// Index one certificate by fingerprint, by its `subjectKeyIdentifier`
	/// extension value when it carries one, and by its SubjectPublicKeyInfo.
	///
	/// One key under two fingerprints is a collision, and so is one extension
	/// value, because a lookup by either would name two certificates. Each
	/// collision names the index it hit.
	fn add_certificate(&mut self, cert: Certificate) -> Result<(), CertificateValidationError> {
		let fp = CertificateTrustStore::to_fingerprint::<Sha3_256>(&cert)?;

		let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
		let skid = cert.extension::<SubjectKeyIdentifier>()?.map(|skid| skid.0.into_bytes());
		let skid_holder = skid.as_ref().and_then(|skid| self.skid_index.get(skid));
		if let (Some(skid), Some(holder)) = (skid.as_deref(), skid_holder) {
			if *holder != fp {
				return Err(CertificateValidationError::SkidCollision { skid: to_hex(skid) });
			}
		}

		let key_holder = self.key_index.get(&spki_der);
		if key_holder.is_some_and(|holder| *holder != fp) {
			return Err(CertificateValidationError::PublicKeyCollision { public_key: to_hex(&spki_der) });
		}

		self.fingerprints.insert(fp);

		if let Some(skid) = skid {
			self.skid_index.insert(skid, fp);
		}

		self.key_index.insert(spki_der, fp);
		self.certificates.insert(fp, Arc::new(cert));

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
		// A certificate that the signer role refuses, such as an issuer that
		// asserts `keyCertSign` alone, stays a path certificate and resolves
		// no signer, so its refusal is the answer and drops here.
		let purpose = self.purposes.signer;
		let signers = self.certificates.iter().filter_map(|(fp, cert)| {
			let signer = PeerCertificate::<ErasedSigning>::parse(Arc::clone(cert), purpose);
			signer.ok().map(|signer| (*fp, signer))
		});

		CertificateTrustStore {
			signers: signers.collect(),
			fingerprints: self.fingerprints,
			certificates: self.certificates,
			skid_index: self.skid_index,
			key_index: self.key_index,
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
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, SigningKey};
	use crate::crypto::sign::{CmsSigner, SignedContent};
	use crate::der::asn1::{ObjectIdentifier, OctetString};
	use crate::der::oid::AssociatedOid;
	use crate::testing::fixtures::{TestCertificate, TestCertificateChain, TestIdentity};
	use crate::testing::{TestFrame, TestKey};

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
		let builder: CertificateTrustBuilder = Secp256k1Policy::default().into();
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

	/// Returns the certificate in `chain` that `target` names.
	fn target_cert(chain: &TestCertificateChain, target: EvalTarget) -> &Certificate {
		match target {
			EvalTarget::Root => &chain.root,
			EvalTarget::Intermediate => &chain.intermediate,
			EvalTarget::Leaf => &chain.leaf,
		}
	}

	#[test]
	fn fingerprint_is_32_bytes() -> TestResult {
		let cert = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		assert_eq!(CertificateTrustStore::to_fingerprint::<Sha3_256>(&cert)?.as_slice().len(), 32);
		Ok(())
	}

	#[test]
	fn is_trusted_matches_fingerprint() -> TestResult {
		let cert = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let certificate = cert.to_owned();
		let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(certificate)?
			.build();
		assert!(store.is_trusted(&cert));
		assert!(!store.is_trusted(&TestCertificate::self_signed(&SigningKey::from_bytes(&[2u8; 32].into())?)));
		Ok(())
	}

	#[test]
	fn trusts_public_key_matches_rotated_certificate() -> TestResult {
		let key = TestKey::insecure_fixed_signing();
		let enrolled = TestCertificate::with_cn_and_uri_sans(&key, "enrolled", &["urn:tightbeam:colony:test"]);
		let rotated = TestCertificate::with_cn_and_uri_sans(&key, "rotated", &["urn:tightbeam:colony:test"]);
		let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
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
		let chain = TestCertificate::insecure_fixed_chain()?;
		let chain = vec![chain.root, chain.intermediate, chain.leaf];
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
		assert!(builder.with_chain(chain).is_ok());
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
		let chain = TestCertificate::insecure_fixed_chain()?;
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
		let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(TestCertificate::self_signed(&TestKey::insecure_fixed_signing()))?
			.build();

		let other_chain = TestCertificate::insecure_fixed_chain()?;
		assert!(store.evaluate(&other_chain.leaf).is_err());
		Ok(())
	}

	#[test]
	fn verify_chain_cases() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
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
			let chain = TestCertificate::insecure_fixed_chain()?;

			let mut root = chain.root.to_owned();
			root.tbs_certificate.extensions = Some(TestCertificate::ca_extensions(*ca, *key_cert_sign, *path_len));

			let certificate = root.to_owned();
			let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
				.with_certificate(certificate)?
				.build();

			let result = store.verify_chain(&[root, chain.intermediate, chain.leaf]);
			assert!(matches!(result, Err(ref e) if core::mem::discriminant(e) == core::mem::discriminant(expected)));
		}

		Ok(())
	}

	#[test]
	fn evaluate_enforces_path_len_constraint() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;

		let mut root = chain.root.to_owned();
		root.tbs_certificate.extensions = Some(TestCertificate::ca_extensions(true, true, Some(0)));

		let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(root)?
			.with_certificate(chain.intermediate)?
			.build();
		assert!(matches!(
			store.evaluate(&chain.leaf),
			Err(CertificateValidationError::PathLenExceeded)
		));
		Ok(())
	}

	#[test]
	fn verify_chain_rejects_unknown_critical_extension() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let mut leaf = chain.leaf.to_owned();
		leaf.tbs_certificate.extensions = Some(vec![TestCertificate::opaque_extension("2.5.29.30", true)]);

		let store = build_store(&chain, StoreCerts::Root)?;
		let result = store.verify_chain(&[chain.root, chain.intermediate, leaf]);
		assert!(matches!(
			result,
			Err(CertificateValidationError::UnprocessedCriticalExtension(_))
		));
		Ok(())
	}

	/// A chain whose leaf repeats its `keyUsage` is refused (RFC 5280 §4.2).
	#[test]
	fn verify_chain_rejects_a_repeated_extension() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let mut leaf = chain.leaf.to_owned();
		let key_usage = TestCertificate::opaque_extension("2.5.29.15", true);
		let repeated = vec![key_usage.clone(), key_usage];

		leaf.tbs_certificate.extensions = Some(repeated);

		let store = build_store(&chain, StoreCerts::Root)?;
		let result = store.verify_chain(&[chain.root, chain.intermediate, leaf]);
		assert!(matches!(result, Err(CertificateValidationError::DuplicateExtension(_))));
		Ok(())
	}

	/// The issuer walk refuses a leaf that repeats an extension, as the chain
	/// path does (RFC 5280 §4.2).
	#[test]
	fn evaluate_rejects_a_repeated_extension() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let key_identifier = TestCertificate::opaque_extension("2.5.29.14", false);
		let leaf = TestCertificate::with_extension(chain.leaf.to_owned(), key_identifier.clone());
		let leaf = TestCertificate::with_extension(leaf, key_identifier);

		let store = build_store(&chain, StoreCerts::RootAndIntermediate)?;
		let refused = store.evaluate(&leaf);
		assert!(matches!(refused, Err(CertificateValidationError::DuplicateExtension(_))));
		Ok(())
	}

	/// The issuer walk refuses a leaf that bears a critical extension the
	/// crate does not process, as the chain path does (RFC 5280 §4.2).
	#[test]
	fn evaluate_rejects_an_unknown_critical_extension() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let name_constraints = TestCertificate::opaque_extension("2.5.29.30", true);
		let leaf = TestCertificate::with_extension(chain.leaf.to_owned(), name_constraints);

		let store = build_store(&chain, StoreCerts::RootAndIntermediate)?;
		let refused = store.evaluate(&leaf);
		assert!(matches!(
			refused,
			Err(CertificateValidationError::UnprocessedCriticalExtension(_))
		));
		Ok(())
	}

	// The end-entity CA-bit check is defense in depth.
	#[test]
	fn terminal_with_ca_bit_rejected() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
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
		let chain = TestCertificate::insecure_fixed_chain()?;
		let path = [&chain.root, &chain.intermediate, &chain.leaf];
		assert!(ensure_terminal_is_end_entity(&path).is_ok());
		Ok(())
	}

	#[test]
	fn single_certificate_path_exempt_from_ca_bit_check() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
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
		Ok(CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_revocation_checker(revocation)
			.with_certificate(root)?
			.build())
	}

	#[test]
	fn static_revocation_list_passes_unlisted_certificate() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let revocation = StaticRevocationList::default().with_certificate(&chain.intermediate)?;
		assert!(revocation.check(&chain.intermediate, &chain.leaf).is_ok());
		Ok(())
	}

	#[test]
	fn verify_chain_rejects_leaf_revoked_by_fingerprint() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let revocation = StaticRevocationList::default().with_certificate(&chain.leaf)?;

		let store = build_store_with_revocation(&chain, revocation)?;
		let result = store.verify_chain(&[chain.root, chain.intermediate, chain.leaf]);
		assert!(matches!(result, Err(CertificateValidationError::CertificateRevoked)));
		Ok(())
	}

	#[test]
	fn verify_chain_rejects_leaf_revoked_by_serial() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
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
		let chain = TestCertificate::insecure_fixed_chain()?;
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
		let chain = TestCertificate::insecure_fixed_chain()?;
		let revocation = StaticRevocationList::default().with_certificate(&chain.root)?;

		let store = build_store_with_revocation(&chain, revocation)?;
		let result = store.verify_chain(&[chain.root]);
		assert!(matches!(result, Err(CertificateValidationError::CertificateRevoked)));
		Ok(())
	}

	// RFC 5280 §4.1.1.2 requires algorithm identifier consistency.
	#[test]
	fn rejects_algorithm_identifier_mismatch() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;

		let mut leaf = chain.leaf.to_owned();
		leaf.signature_algorithm.oid = crate::oids::SIGNER_ECDSA_WITH_SHA256;

		// Both the `evaluate` walk and `verify_chain` must reject it.
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

	/// A `SignerInfo` that names a certificate by its `subjectKeyIdentifier`
	/// extension value resolves to that certificate (RFC 5652 §5.3).
	#[test]
	fn a_key_identifier_sid_resolves_through_the_extension() -> TestResult {
		let key = TestKey::insecure_fixed_signing();
		let cert = TestCertificate::self_signed(&key);
		let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(cert.to_owned())?
			.build();

		let signer = TestIdentity::certified(key);
		let signer_info = CmsSigner::sign_with::<Secp256k1Signature, _>(&signer, SignedContent::data(b"test"))?;

		let found = store.find_by_signer_info(&signer_info);
		let fingerprint = found.map(|signer| CertificateTrustStore::to_fingerprint::<Sha3_256>(signer.certificate()));
		assert_eq!(
			fingerprint.transpose()?,
			Some(CertificateTrustStore::to_fingerprint::<Sha3_256>(&cert)?)
		);
		Ok(())
	}

	/// An issuer-and-serial `sid` resolves to the certificate of that issuer
	/// and serial number.
	#[test]
	fn an_issuer_and_serial_sid_resolves_through_the_certificate() -> TestResult {
		let cert = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let cert = TestCertificate::without_extension(cert, SubjectKeyIdentifier::OID);

		let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(cert.to_owned())?
			.build();

		let sid = cert.signer_identifier()?;
		let found = store.find_by_signer_identifier(&sid);

		let fingerprint = found.map(|signer| CertificateTrustStore::to_fingerprint::<Sha3_256>(signer.certificate()));
		assert_eq!(
			fingerprint.transpose()?,
			Some(CertificateTrustStore::to_fingerprint::<Sha3_256>(&cert)?)
		);
		Ok(())
	}

	/// An authority whose `keyUsage` asserts `keyCertSign` alone stays a path
	/// certificate of the store, and resolves no signer.
	#[test]
	fn a_certificate_that_only_certifies_resolves_no_signer() -> TestResult {
		let key = TestKey::insecure_fixed_signing();
		let authority = TestCertificate::authority(&key, "Authority")?;
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
		let builder = builder.with_certificate(authority.to_owned())?;
		let store = builder.build();

		let sid = authority.signer_identifier()?;
		let found = store.find_by_signer_identifier(&sid);
		assert!(found.is_none());
		Ok(())
	}

	/// A certificate whose `extendedKeyUsage` names the server's purpose alone
	/// is no frame signer, so it resolves no signer (RFC 5280 §4.2.1.12).
	#[test]
	fn a_certificate_of_the_server_purpose_resolves_no_signer() -> TestResult {
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let certificate = TestCertificate::with_key_purposes(certificate, [KeyPurposes::HOUSE.server]);
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
		let store = builder.with_certificate(certificate.to_owned())?.build();

		let sid = certificate.signer_identifier()?;
		let found = store.find_by_signer_identifier(&sid);
		assert!(found.is_none());
		Ok(())
	}

	/// A store configured with an implementor's own signer purpose resolves
	/// a certificate that names it.
	#[test]
	fn a_certificate_of_a_configured_signer_purpose_resolves_its_signer() -> TestResult {
		let own = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.2");
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let certificate = TestCertificate::with_key_purposes(certificate, [own]);
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
		let builder = builder.with_key_purposes(KeyPurposes { signer: own, ..KeyPurposes::HOUSE });
		let store = builder.with_certificate(certificate.to_owned())?.build();

		let sid = certificate.signer_identifier()?;
		let found = store.find_by_signer_identifier(&sid);
		assert!(found.is_some());
		Ok(())
	}

	/// A key identifier the store holds no certificate for resolves to none.
	#[test]
	fn an_unknown_key_identifier_resolves_to_no_certificate() -> TestResult {
		let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(TestCertificate::self_signed(&TestKey::insecure_fixed_signing()))?
			.build();

		let other_key = crate::crypto::sign::ecdsa::Secp256k1SigningKey::from_bytes(&[99u8; 32].into())?;
		let signer = TestIdentity::certified(other_key);
		let signer_info = CmsSigner::sign_with::<Secp256k1Signature, _>(&signer, SignedContent::data(b"test"))?;

		let found = store.find_by_signer_info(&signer_info);
		assert!(found.is_none());
		Ok(())
	}

	/// The store resolves a `sid` by the certificate's extension value, which
	/// another method may have derived, and not by a key identifier it
	/// computes.
	#[test]
	fn a_sid_resolves_by_the_extension_value_as_written() -> TestResult {
		let key = TestKey::insecure_fixed_signing();
		let written = SubjectKeyIdentifier::from(OctetString::new([0x42u8; 20])?);
		let cert = TestCertificate::with_key_identifier(TestCertificate::self_signed(&key), written.clone());
		let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(cert.to_owned())?
			.build();

		let sid = SignerIdentifier::SubjectKeyIdentifier(written);
		let found = store.find_by_signer_identifier(&sid);
		assert!(found.is_some());
		Ok(())
	}

	/// A trust store verifies a frame under the certificate its `sid` names,
	/// and returns the verified signature.
	#[tokio::test]
	async fn a_trust_store_verifies_a_frame_of_a_certificate_it_holds() -> TestResult {
		let identity = TestIdentity::insecure_fixed();
		let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(identity.certificate().clone())?
			.build();

		let mut frame = TestFrame::with_integrity();
		frame.sign_with_provider(&identity).await?;

		let verification = store.verify_frame(&frame);
		assert!(matches!(verification, TrustVerification::Verified(_, _)));
		Ok(())
	}

	/// A trust store refuses a frame whose signer it holds only as a
	/// certificate the signing use refuses, so the key of an authority signs
	/// no frame the store accepts.
	#[tokio::test]
	async fn a_trust_store_resolves_no_signer_for_a_certifying_key() -> TestResult {
		let key = TestKey::insecure_fixed_signing();
		let authority = TestCertificate::authority(&key, "Authority")?;
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
		let builder = builder.with_certificate(authority)?;
		let store = builder.build();

		let mut frame = TestFrame::with_integrity();
		frame.sign_with_provider(&TestIdentity::insecure_fixed()).await?;

		let verification = store.verify_frame(&frame);
		assert!(matches!(verification, TrustVerification::UnknownSigner));
		Ok(())
	}

	/// Two certificates of two keys under one `subjectKeyIdentifier` value
	/// collide in the extension index, because a `sid` would name both.
	#[test]
	fn two_certificates_under_one_key_identifier_collide() -> TestResult {
		let first = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let other_key = SigningKey::from_bytes(&[3u8; 32].into())?;
		let identifier = first.extension::<SubjectKeyIdentifier>()?;
		let identifier = identifier.ok_or("the fixture carries a key identifier")?;
		let second = TestCertificate::with_key_identifier(TestCertificate::self_signed(&other_key), identifier);
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_certificate(first)?;

		let refused = builder.with_certificate(second);
		assert!(matches!(refused, Err(CertificateValidationError::SkidCollision { .. })));
		Ok(())
	}

	/// Two certificates of one key, the second with no key identifier,
	/// collide in the key index, because a key lookup would name both.
	#[test]
	fn two_certificates_of_one_key_collide() -> TestResult {
		let key = TestKey::insecure_fixed_signing();
		let first = TestCertificate::self_signed(&key);
		let mut second = TestCertificate::self_signed(&key);
		second.tbs_certificate.extensions = None;

		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_certificate(first)?;
		let refused = builder.with_certificate(second);
		assert!(matches!(refused, Err(CertificateValidationError::PublicKeyCollision { .. })));
		Ok(())
	}
}
