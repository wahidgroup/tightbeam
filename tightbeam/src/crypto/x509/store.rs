//! The certificate trust store.
//!
//! [`CertificateTrust`] abstracts certificate trust verification, so each
//! environment can supply its own implementation. [`CertificateTrustStore`] is
//! the built-in store.

use core::fmt::Debug;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

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
	pub use crate::crypto::x509::ext::pkix::{
		AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
	};
	pub use crate::crypto::x509::name::Name;
	pub use crate::crypto::x509::utils::{CertificateExt, Fingerprint};
	pub use crate::crypto::x509::KeyPurposes;
	pub use crate::der::asn1::{ObjectIdentifier, OctetStringRef};
	pub use crate::der::oid::AssociatedOid;
	pub use crate::der::{Decode, Encode, Reader, Sequence};
	pub use crate::x509::ext::pkix::name::GeneralNames;
	pub use crate::x509::serial_number::SerialNumber;
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

	/// Validate `cert` as [`CertificateValidation::evaluate`] does, and return
	/// the trust anchor at which its certification path ends, the anchor that
	/// RFC 5280 §6.1.1 (d) names as the input of path validation.
	///
	/// Two certificates of one server name one anchor when this returns one
	/// certificate for both.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError`] -- the certificate or its path fails validation.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::policy::Secp256k1Policy;
	/// use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
	/// use tightbeam::testing::fixtures::{TestCertificate, TestCertificateChain};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // The keys of the fixture chain are public, so it serves an example
	/// // alone.
	/// let chain = TestCertificate::insecure_fixed_chain()?;
	/// let TestCertificateChain { root, intermediate, leaf, .. } = chain;
	///
	/// // The store holds its own copy of the root, which the anchor is
	/// // compared with below.
	/// let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
	/// let builder = builder.with_certificate(root.to_owned())?;
	/// let builder = builder.with_certificate(intermediate)?;
	/// let store = builder.build();
	///
	/// // The path of the leaf runs through the intermediate to the root.
	/// let anchor = store.trust_anchor(&leaf)?;
	/// assert_eq!(*anchor, root);
	/// # Ok(())
	/// # }
	/// ```
	fn trust_anchor(&self, cert: &Certificate) -> Result<Arc<Certificate>, CertificateValidationError>;

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

/// A certificate the store holds, beside its key identifiers, which the
/// builder decodes once.
#[cfg(feature = "std")]
struct HeldCertificate {
	/// The certificate, which the signer admitted from it shares.
	certificate: Arc<Certificate>,
	/// Its key identifiers, which the issuer walk reads.
	identifiers: KeyIdentifiers,
}

/// The key identifiers of a held certificate that the issuer walk reads (RFC
/// 5280 §4.2.1.1, §4.2.1.2).
#[cfg(feature = "std")]
struct KeyIdentifiers {
	/// The `subjectKeyIdentifier` extension value, one allocation that the
	/// `sid` index of the store shares.
	subject: Option<Arc<[u8]>>,
	/// The key identifier that names the authority whose key signed the
	/// certificate, as [`KeyIdentifiers::authority_of`] reads it. A value equal
	/// to `subject` shares its allocation.
	authority: Option<Arc<[u8]>>,
}

/// The `subjectKeyIdentifier` extension (RFC 5280 §4.2.1.2), read in place.
#[cfg(feature = "std")]
struct SubjectKeyIdentifierRef<'a>(OctetStringRef<'a>);

#[cfg(feature = "std")]
impl AssociatedOid for SubjectKeyIdentifierRef<'_> {
	const OID: ObjectIdentifier = SubjectKeyIdentifier::OID;
}

#[cfg(feature = "std")]
impl<'a> Decode<'a> for SubjectKeyIdentifierRef<'a> {
	fn decode<R: Reader<'a>>(reader: &mut R) -> crate::der::Result<Self> {
		OctetStringRef::decode(reader).map(Self)
	}
}

/// The `authorityKeyIdentifier` extension (RFC 5280 §4.2.1.1), with its
/// `keyIdentifier` read in place. The issuer and the serial number decode as
/// the owned extension decodes them, so this read refuses what that one
/// refuses.
#[cfg(feature = "std")]
#[derive(Sequence)]
struct AuthorityKeyIdentifierRef<'a> {
	/// The key identifier of the authority's key.
	#[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
	key_identifier: Option<OctetStringRef<'a>>,
	/// The issuer name of the authority's certificate.
	#[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
	authority_cert_issuer: Option<GeneralNames>,
	/// The serial number of the authority's certificate.
	#[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
	authority_cert_serial_number: Option<SerialNumber>,
}

#[cfg(feature = "std")]
impl AssociatedOid for AuthorityKeyIdentifierRef<'_> {
	const OID: ObjectIdentifier = AuthorityKeyIdentifier::OID;
}

/// The rank RFC 4158 §3.5.12 gives a candidate issuer by its key identifier,
/// lowest first.
#[cfg(feature = "std")]
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum IssuerPriority {
	/// Its `subjectKeyIdentifier` differs from the key identifier of the
	/// authority.
	Mismatch,
	/// It, or the certificate below it, states no key identifier.
	Unstated,
	/// Its `subjectKeyIdentifier` is the key identifier of the authority.
	Match,
}

#[cfg(feature = "std")]
impl KeyIdentifiers {
	/// Decode the key identifiers of `cert`, which the store holds.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::EncodingError`] -- a key identifier extension fails to decode.
	/// - [`CertificateValidationError::DuplicateExtension`] -- a key identifier extension repeats.
	fn of(cert: &Certificate) -> Result<Self, CertificateValidationError> {
		let subject = cert.extension::<SubjectKeyIdentifierRef<'_>>()?;
		let subject = subject.map(|subject| Arc::<[u8]>::from(subject.0.as_bytes()));
		let authority = Self::authority_of(cert)?;
		// A self-signed certificate names its own key identifier for its
		// authority, and the two then share one allocation.
		let shared = subject.as_ref().filter(|_| authority == subject.as_deref());
		let authority = shared.map(Arc::clone).or_else(|| authority.map(Arc::from));
		Ok(Self { subject, authority })
	}

	/// The key identifier of the authority whose key signed `cert`, read in
	/// place: the `keyIdentifier` of its `authorityKeyIdentifier`. A
	/// self-signed certificate may omit it, and its own `subjectKeyIdentifier`
	/// then names that key (RFC 5280 §4.2.1.1), so that extension decodes
	/// only then.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::EncodingError`] -- a key identifier extension fails to decode.
	/// - [`CertificateValidationError::DuplicateExtension`] -- a key identifier extension repeats.
	fn authority_of(cert: &Certificate) -> Result<Option<&[u8]>, CertificateValidationError> {
		let stated = cert.extension::<AuthorityKeyIdentifierRef<'_>>()?;
		if let Some(key_identifier) = stated.and_then(|stated| stated.key_identifier) {
			return Ok(Some(key_identifier.as_bytes()));
		}

		let tbs = &cert.tbs_certificate;
		if tbs.subject != tbs.issuer {
			return Ok(None);
		}

		let own = cert.extension::<SubjectKeyIdentifierRef<'_>>()?;
		Ok(own.map(|own| own.0.as_bytes()))
	}

	/// The rank of a candidate of these identifiers as the issuer of a
	/// certificate that names `authority` for its authority (RFC 4158
	/// §3.5.12).
	fn priority(&self, authority: Option<&[u8]>) -> IssuerPriority {
		match (authority, self.subject.as_deref()) {
			(Some(authority), Some(subject)) if authority == subject => IssuerPriority::Match,
			(Some(_), Some(_)) => IssuerPriority::Mismatch,
			(None, _) | (_, None) => IssuerPriority::Unstated,
		}
	}
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
	/// The full certificates, indexed by fingerprint, each beside the key
	/// identifiers the builder decoded.
	certificates: HashMap<Sha3Fingerprint, HeldCertificate>,
	/// The certificates admitted for signing at enrolment, indexed by
	/// fingerprint, each sharing its certificate with [`Self::certificates`].
	signers: HashMap<Sha3Fingerprint, PeerCertificate<ErasedSigning>>,
	/// The `subjectKeyIdentifier` extension values, each to its certificate
	/// fingerprint, and each shared with the key identifiers of that
	/// certificate.
	skid_index: HashMap<Arc<[u8]>, Sha3Fingerprint>,
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
		self.certificates.get(fingerprint).map(|held| held.certificate.as_ref())
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
	/// Of the certificates the store holds under the issuer name, the walk
	/// takes the first in the order of RFC 4158 §3.5.12:
	///
	/// 1. A `subjectKeyIdentifier` equal to the `authorityKeyIdentifier` of the certificate below.
	/// 2. No `subjectKeyIdentifier`, or no `authorityKeyIdentifier` to compare it with.
	/// 3. A `subjectKeyIdentifier` that differs.
	///
	/// A self-signed certificate that omits its `authorityKeyIdentifier` names
	/// its own `subjectKeyIdentifier` (RFC 5280 §4.2.1.1), and of candidates of
	/// one rank it takes itself. The walk commits to its candidate, and the
	/// signature check of the path decides.
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		// The evaluation admits the certificate alone, so its anchor drops.
		self.validate_to_anchor(cert).map(drop)
	}
}

#[cfg(feature = "std")]
impl CertificateTrustStore {
	/// Walk the issuer hierarchy from `cert` as far as the store material
	/// allows, validate the accumulated path, and return the fingerprint of
	/// the trust anchor the walk ended at, a certificate this store holds.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::CertificateNotTrusted`] -- the walk ends at no anchor of this store.
	/// - The [`Self::validate_path`] set.
	fn validate_to_anchor(&self, cert: &Certificate) -> Result<Sha3Fingerprint, CertificateValidationError> {
		let mut path: Vec<&Certificate> = Vec::new();
		let mut visited: HashSet<Sha3Fingerprint> = HashSet::new();

		let mut anchor = Self::to_fingerprint(cert)?;
		visited.insert(anchor);
		path.push(cert);

		// The authority identifier of `cert` reads in place here, and those of
		// the held certificates decoded where the store was built.
		let mut current = cert;
		let mut authority = KeyIdentifiers::authority_of(cert)?;
		loop {
			// RFC 5280 §6.1.3(a)(4): locate the issuer of the current
			// certificate, whose fingerprint `anchor` holds.
			let Some((issuer_fingerprint, issuer)) = self.issuer_of(current, &anchor, authority) else {
				break;
			};

			// A revisited certificate ends the walk. That covers a self-issued
			// root and RFC 4158 §2.4.2 loop detection.
			if !visited.insert(*issuer_fingerprint) {
				break;
			}

			path.push(issuer.certificate.as_ref());
			current = issuer.certificate.as_ref();
			authority = issuer.identifiers.authority.as_deref();
			anchor = *issuer_fingerprint;
		}

		// RFC 5280 §6.1.1: the walk must reach a configured trust anchor.
		if !self.fingerprints.contains(&anchor) {
			return Err(CertificateValidationError::CertificateNotTrusted);
		}

		// Validate anchor first, issuer before subject, as `verify_chain` does.
		path.reverse();
		self.validate_path(&path)?;
		Ok(anchor)
	}

	/// The certificate this store holds that issued `cert`, beside its
	/// fingerprint, or `None` when it holds none.
	///
	/// - A candidate's subject is the issuer name of `cert` (RFC 5280 §6.1.3(a)(4)).
	/// - It takes the one of the highest [`IssuerPriority`] against `authority`, the identifier `cert` names.
	/// - Of candidates of one rank, it takes `cert` itself, whose fingerprint is `fingerprint`.
	fn issuer_of(
		&self,
		cert: &Certificate,
		fingerprint: &Sha3Fingerprint,
		authority: Option<&[u8]>,
	) -> Option<(&Sha3Fingerprint, &HeldCertificate)> {
		let issuer = &cert.tbs_certificate.issuer;
		let candidates = self.certificates.iter();
		let named = candidates.filter(|(_, held)| held.certificate.tbs_certificate.subject == *issuer);
		named.max_by_key(|&(held_fingerprint, held)| {
			let itself = held_fingerprint == fingerprint;
			(held.identifiers.priority(authority), itself)
		})
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

	/// The anchor is the certificate the issuer walk of
	/// [`CertificateValidation::evaluate`] ended at, as the store holds it.
	fn trust_anchor(&self, cert: &Certificate) -> Result<Arc<Certificate>, CertificateValidationError> {
		let anchor = self.validate_to_anchor(cert)?;
		let held = self.certificates.get(&anchor);
		let certificate = held.map(|held| Arc::clone(&held.certificate));
		certificate.ok_or(CertificateValidationError::CertificateNotTrusted)
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
		self.certificates.get(fingerprint).map(|held| held.certificate.as_ref())
	}

	fn to_policy_ref(&self) -> &dyn VerificationPolicy {
		&*self.policy
	}
}

/// The builder of a [`CertificateTrustStore`].
///
/// It validates expiry, issuer and subject chaining, and key identifiers on
/// each add. The resulting store handles cryptographic verification at run
/// time. It indexes each certificate twice:
///
/// - By its `subjectKeyIdentifier` value, which a `sid` resolves through (RFC 5652 §5.3).
/// - By its SubjectPublicKeyInfo, which plane membership reads.
///
/// [`TrustBuilder::build`] admits the signers among them under the signer
/// purpose of its [`KeyPurposes`].
#[cfg(feature = "std")]
pub struct CertificateTrustBuilder {
	fingerprints: HashSet<Sha3Fingerprint>,
	certificates: HashMap<Sha3Fingerprint, HeldCertificate>,
	purposes: KeyPurposes,
	skid_index: HashMap<Arc<[u8]>, Sha3Fingerprint>,
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
	/// extension value when it carries one, and by its SubjectPublicKeyInfo,
	/// and decode the key identifiers the issuer walk reads.
	///
	/// One key under two fingerprints is a collision, and so is one extension
	/// value, because a lookup by either would name two certificates. Each
	/// collision names the index it hit.
	fn add_certificate(&mut self, cert: Certificate) -> Result<(), CertificateValidationError> {
		let fp = CertificateTrustStore::to_fingerprint::<Sha3_256>(&cert)?;

		let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
		let identifiers = KeyIdentifiers::of(&cert)?;
		let skid = identifiers.subject.as_ref();
		let skid_holder = skid.and_then(|skid| self.skid_index.get(skid));
		if let (Some(skid), Some(holder)) = (skid, skid_holder) {
			if *holder != fp {
				return Err(CertificateValidationError::SkidCollision { skid: to_hex(skid) });
			}
		}

		let key_holder = self.key_index.get(&spki_der);
		if key_holder.is_some_and(|holder| *holder != fp) {
			return Err(CertificateValidationError::PublicKeyCollision { public_key: to_hex(&spki_der) });
		}

		self.fingerprints.insert(fp);

		// The index keys a `sid` lookup by the extension value, and the held
		// certificate keeps it for the issuer walk, so the two share one
		// allocation.
		if let Some(skid) = skid {
			self.skid_index.insert(Arc::clone(skid), fp);
		}

		self.key_index.insert(spki_der, fp);
		let held = HeldCertificate { certificate: Arc::new(cert), identifiers };
		self.certificates.insert(fp, held);

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
		let signers = self.certificates.iter().filter_map(|(fp, held)| {
			let signer = PeerCertificate::<ErasedSigning>::parse(Arc::clone(&held.certificate), purpose);
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
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, SigningKey};
	use crate::crypto::sign::{CmsSigner, SignedContent};
	use crate::der::asn1::{ObjectIdentifier, OctetString};
	use crate::der::oid::AssociatedOid;
	use crate::testing::fixtures::{TestCertificate, TestCertificateChain, TestIdentity};
	use crate::testing::{TestFrame, TestKey};
	use crate::x509::ext::pkix::name::GeneralName;
	use std::str::FromStr;

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

	/// Of two authorities of one subject name, the walk takes the one whose
	/// key identifier the leaf names (RFC 5280 §4.2.1.1). With one leaf under
	/// each authority, the check holds in any order the store keeps them in.
	#[test]
	fn the_walk_takes_the_authority_whose_key_signed_the_leaf() -> TestResult {
		let first_key = SigningKey::from_bytes(&[4u8; 32].into())?;
		let second_key = SigningKey::from_bytes(&[5u8; 32].into())?;
		let leaf_key = SigningKey::from_bytes(&[6u8; 32].into())?;
		let first = TestCertificate::authority(&first_key, "Rollover CA")?;
		let second = TestCertificate::authority(&second_key, "Rollover CA")?;
		let usage = KeyUsage(KeyUsages::DigitalSignature.into());
		let first_leaf = TestCertificate::issued(&first_key, "Rollover CA", &leaf_key, "Leaf", 2, usage)?;
		let second_leaf = TestCertificate::issued(&second_key, "Rollover CA", &leaf_key, "Leaf", 3, usage)?;
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_certificate(first.to_owned())?;
		let store = builder.with_certificate(second.to_owned())?.build();

		let first_anchor = store.trust_anchor(&first_leaf)?;
		let second_anchor = store.trust_anchor(&second_leaf)?;
		assert_eq!((first_anchor.as_ref(), second_anchor.as_ref()), (&first, &second));
		Ok(())
	}

	/// The anchor of a leaf under an intermediate is the root at which its
	/// path ends, and not the intermediate that issued it (RFC 5280 §6.1.1
	/// (d)).
	#[test]
	fn the_anchor_of_a_leaf_under_an_intermediate_is_its_root() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let store = build_store(&chain, StoreCerts::RootAndIntermediate)?;

		let anchor = store.trust_anchor(&chain.leaf)?;
		assert_eq!(anchor.as_ref(), &chain.root);
		Ok(())
	}

	/// A store of two authorities of one subject name, `Rollover CA`, beside
	/// the two: the authority of `named_key` with its key identifier, and the
	/// authority of `unnamed_key` with none.
	fn mixed_store(
		named_key: &Secp256k1SigningKey,
		unnamed_key: &Secp256k1SigningKey,
	) -> Result<(CertificateTrustStore, Certificate, Certificate), Box<dyn std::error::Error>> {
		let named = TestCertificate::authority(named_key, "Rollover CA")?;
		let unnamed = TestCertificate::authority(unnamed_key, "Rollover CA")?;
		let unnamed = TestCertificate::without_extension(unnamed, SubjectKeyIdentifier::OID);
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_certificate(named.to_owned())?;
		let store = builder.with_certificate(unnamed.to_owned())?.build();

		Ok((store, named, unnamed))
	}

	/// A leaf that the authority `Rollover CA` of `issuer_key` issues.
	fn rollover_leaf(issuer_key: &Secp256k1SigningKey) -> Result<Certificate, Box<dyn std::error::Error>> {
		let leaf_key = SigningKey::from_bytes(&[6u8; 32].into())?;
		let usage = KeyUsage(KeyUsages::DigitalSignature.into());
		Ok(TestCertificate::issued(issuer_key, "Rollover CA", &leaf_key, "Leaf", 2, usage)?)
	}

	/// Of two authorities of one subject name, the walk takes the one whose
	/// key identifier the leaf names over one that states none (RFC 4158
	/// §3.5.12).
	#[test]
	fn the_walk_takes_a_matching_authority_over_one_of_no_key_identifier() -> TestResult {
		let named_key = SigningKey::from_bytes(&[4u8; 32].into())?;
		let unnamed_key = SigningKey::from_bytes(&[5u8; 32].into())?;
		let (store, named, _) = mixed_store(&named_key, &unnamed_key)?;
		let leaf = rollover_leaf(&named_key)?;

		let anchor = store.trust_anchor(&leaf)?;
		assert_eq!(anchor.as_ref(), &named);
		Ok(())
	}

	/// Of two authorities of one subject name, the walk takes one that states
	/// no key identifier over one whose key identifier differs from the one
	/// the leaf names, and the self-signed authority it takes ends the walk
	/// (RFC 4158 §3.5.12, RFC 5280 §4.2.1.1).
	#[test]
	fn the_walk_takes_an_authority_of_no_key_identifier_over_one_that_differs() -> TestResult {
		let named_key = SigningKey::from_bytes(&[4u8; 32].into())?;
		let unnamed_key = SigningKey::from_bytes(&[5u8; 32].into())?;
		let (store, _, unnamed) = mixed_store(&named_key, &unnamed_key)?;
		let leaf = rollover_leaf(&unnamed_key)?;

		let anchor = store.trust_anchor(&leaf)?;
		assert_eq!(anchor.as_ref(), &unnamed);
		Ok(())
	}

	/// A self-signed certificate that omits its `authorityKeyIdentifier` names
	/// its own `subjectKeyIdentifier`, so the walk takes the authority of its
	/// key over another of its name (RFC 5280 §4.2.1.1).
	#[test]
	fn a_self_signed_certificate_names_the_authority_of_its_own_key() -> TestResult {
		let named_key = SigningKey::from_bytes(&[4u8; 32].into())?;
		let other_key = SigningKey::from_bytes(&[5u8; 32].into())?;
		let named = TestCertificate::authority(&named_key, "Rollover CA")?;
		let other = TestCertificate::authority(&other_key, "Rollover CA")?;
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_certificate(named.to_owned())?;
		let store = builder.with_certificate(other)?.build();
		let usage = KeyUsage(KeyUsages::DigitalSignature.into());
		let reissued = TestCertificate::issued(&named_key, "Rollover CA", &named_key, "Rollover CA", 7, usage)?;

		let anchor = store.trust_anchor(&reissued)?;
		assert_eq!(anchor.as_ref(), &named);
		Ok(())
	}

	/// The RFC 7093 §2 method 3 key identifier of the key of `certificate`:
	/// the leftmost 160 bits of the SHA-512 hash of its `subjectPublicKey`
	/// value. The fixtures derive theirs by method 1.
	fn method_three_identifier(certificate: &Certificate) -> Result<SubjectKeyIdentifier, Box<dyn std::error::Error>> {
		use k256::sha2::Sha512;

		let spki = &certificate.tbs_certificate.subject_public_key_info;
		let digest = Sha512::digest(spki.subject_public_key.raw_bytes());
		let leftmost = digest.get(..20).ok_or("a SHA-512 hash holds 160 bits")?;
		Ok(SubjectKeyIdentifier::from(OctetString::new(leftmost)?))
	}

	/// A key identifier sorts the candidates and the signature decides, so a
	/// leaf whose `authorityKeyIdentifier` one method derived validates under
	/// an authority whose `subjectKeyIdentifier` another method derived (RFC
	/// 4158 §3.5.12).
	#[test]
	fn the_walk_takes_an_authority_whose_key_identifier_another_method_derived() -> TestResult {
		let authority_key = SigningKey::from_bytes(&[4u8; 32].into())?;
		let authority = TestCertificate::authority(&authority_key, "Rollover CA")?;
		let identifier = method_three_identifier(&authority)?;
		let authority = TestCertificate::with_key_identifier(authority, identifier);
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
		let store = builder.with_certificate(authority.to_owned())?.build();
		let leaf = rollover_leaf(&authority_key)?;

		let anchor = store.trust_anchor(&leaf)?;
		assert_eq!(anchor.as_ref(), &authority);
		Ok(())
	}

	/// An `authorityKeyIdentifier` that also names the issuer and the serial
	/// number of the authority's certificate reads its key identifier in
	/// place (RFC 5280 §4.2.1.1).
	#[test]
	fn an_authority_identifier_of_issuer_and_serial_reads_its_key_identifier() -> TestResult {
		let issuer = GeneralName::DirectoryName(Name::from_str("CN=Rollover CA")?);
		let stated = AuthorityKeyIdentifier {
			key_identifier: Some(OctetString::new([0x42u8; 20])?),
			authority_cert_issuer: Some(vec![issuer]),
			authority_cert_serial_number: Some(SerialNumber::new(&[0x07])?),
		};
		let der = stated.to_der()?;

		let read = AuthorityKeyIdentifierRef::from_der(&der)?;
		let key_identifier = read.key_identifier.map(|read| read.as_bytes());
		assert_eq!(key_identifier, Some([0x42u8; 20].as_slice()));
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

	/// A store that holds the fixed self-signed test certificate, whose one
	/// key identifier extension is its `subjectKeyIdentifier`, beside the
	/// certificate's fingerprint.
	fn self_signed_store() -> Result<(CertificateTrustStore, Sha3Fingerprint), Box<dyn std::error::Error>> {
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let fingerprint = CertificateTrustStore::to_fingerprint::<Sha3_256>(&certificate)?;
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
		Ok((builder.with_certificate(certificate)?.build(), fingerprint))
	}

	/// The store holds each `subjectKeyIdentifier` value once, in one
	/// allocation that its `sid` index and the certificate's key identifiers
	/// share.
	#[test]
	fn the_sid_index_shares_the_key_identifier_of_its_certificate() -> TestResult {
		let (store, fingerprint) = self_signed_store()?;

		let held = store.certificates.get(&fingerprint).ok_or("a held certificate")?;
		let subject = held.identifiers.subject.as_ref().ok_or("a key identifier")?;
		let indexed = store.skid_index.keys().next().ok_or("an index entry")?;
		assert!(Arc::ptr_eq(subject, indexed));
		Ok(())
	}

	/// A self-signed certificate names its own key identifier for its
	/// authority (RFC 5280 §4.2.1.1), and the store holds the two in one
	/// allocation.
	#[test]
	fn a_self_signed_certificate_shares_its_key_identifier_with_its_authority() -> TestResult {
		let (store, fingerprint) = self_signed_store()?;

		let held = store.certificates.get(&fingerprint).ok_or("a held certificate")?;
		let subject = held.identifiers.subject.as_ref().ok_or("a key identifier")?;
		let authority = held.identifiers.authority.as_ref().ok_or("an authority identifier")?;
		assert!(Arc::ptr_eq(subject, authority));
		Ok(())
	}
}
