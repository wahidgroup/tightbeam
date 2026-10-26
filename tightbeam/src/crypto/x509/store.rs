//! The certificate trust store.
//!
//! [`CertificateTrust`] abstracts certificate trust verification, so each
//! environment can supply its own implementation. [`CertificateTrustStore`] is
//! the built-in store.

use core::fmt::Debug;
use core::slice;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

use crate::cms::signed_data::SignerIdentifier;
use crate::crypto::policy::VerificationPolicy;
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::{CanonicalKey, Certificate, ErasedSigning, PeerCertificate};
use crate::der::Decode;
use crate::spki::SubjectPublicKeyInfoOwned;

#[cfg(feature = "signature")]
use crate::crypto::policy::VerifiedSignature;

#[cfg(feature = "std")]
mod std_imports {
	pub use core::borrow::Borrow;
	pub use core::iter;
	pub use std::collections::{HashMap, HashSet};
	pub use std::sync::Arc;

	pub use crate::crypto::hash::{Digest, OutputSizeUser, Sha3_256};
	pub use crate::crypto::x509::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages};
	pub(super) use crate::crypto::x509::key::{KeyCurves, KeyIndex};
	pub use crate::crypto::x509::name::Name;
	pub(super) use crate::crypto::x509::utils::SubjectKeyIdentifierRef;
	pub use crate::crypto::x509::utils::{CertificateExt, Fingerprint};
	pub use crate::crypto::x509::KeyPurposes;
	pub use crate::der::asn1::{ObjectIdentifier, OctetStringRef};
	pub use crate::der::oid::AssociatedOid;
	pub use crate::der::{Encode, Sequence};
	pub use crate::x509::ext::pkix::name::GeneralNames;
	pub use crate::x509::serial_number::SerialNumber;
}

#[cfg(feature = "std")]
use std_imports::*;

/// The SHA3-256 certificate fingerprint that the built-in trust store uses.
#[cfg(feature = "std")]
type Sha3Fingerprint = Fingerprint<Sha3_256>;

/// A revocation status check for the certificates of a certification path.
///
/// Path validation consults it once per certificate, which satisfies the
/// revocation step of RFC 5280 §6.1.3(a)(3). The built-in store also consults
/// it over the path of each certificate a lookup answers with, at each frame
/// and each plane check. The shipped implementations are [`NoRevocation`] and
/// [`StaticRevocationList`].
///
/// # Fail closed
///
/// Implementations MUST fail closed:
///
/// - [`CertificateValidationError::CertificateRevoked`] for a revoked certificate.
/// - [`CertificateValidationError::RevocationStatusUnknown`] when the checker cannot establish the status.
pub trait RevocationChecker: Debug + Send + Sync {
	/// Check the revocation status of `cert`, issued by `issuer`.
	///
	/// For a trust anchor, `issuer` is the anchor itself.
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

/// A static revocation denylist that the operator pushes.
///
/// It revokes by fingerprint under the digest `D` that the operator's list
/// names, or by issuer-scoped serial number:
///
/// - A fingerprint revokes one DER encoding of a certificate. Under a policy
///   that accepts a high ECDSA `s`, anyone can present a revoked certificate
///   again with the `s` of its signature replaced by `n - s`, and the
///   fingerprint misses it (SEC 1 v2.0 §4.1.4).
/// - A serial number revokes every encoding of the certificates it names.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::hash::Sha3_256;
/// use tightbeam::crypto::x509::error::CertificateValidationError;
/// use tightbeam::crypto::x509::store::{RevocationChecker, StaticRevocationList};
/// use tightbeam::testing::fixtures::{TestCertificate, TestKey};
///
/// // A list under SHA3-256 revokes the certificate it names.
/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
/// let revoked = StaticRevocationList::<Sha3_256>::default().with_certificate(&certificate)?;
///
/// let refused = revoked.check(&certificate, &certificate);
/// assert!(matches!(refused, Err(CertificateValidationError::CertificateRevoked)));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[cfg(feature = "std")]
pub struct StaticRevocationList<D: OutputSizeUser> {
	fingerprints: HashSet<Fingerprint<D>>,
	/// The revoked serial numbers, keyed by the DER of the issuer DN.
	/// RFC 5280 §4.1.2.2 guarantees serial uniqueness only within one CA, so an
	/// unscoped serial would falsely revoke unrelated certificates.
	serials: HashMap<Vec<u8>, HashSet<Vec<u8>>>,
}

#[cfg(feature = "std")]
impl<D: OutputSizeUser> Default for StaticRevocationList<D> {
	fn default() -> Self {
		Self { fingerprints: HashSet::new(), serials: HashMap::new() }
	}
}

#[cfg(feature = "std")]
impl<D: OutputSizeUser> Debug for StaticRevocationList<D> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("StaticRevocationList")
			.field("fingerprints", &self.fingerprints)
			.field("serials", &self.serials)
			.finish()
	}
}

#[cfg(feature = "std")]
impl<D> StaticRevocationList<D>
where
	D: Digest,
{
	/// Revoke a certificate by its DER fingerprint under `D`.
	pub fn with_fingerprint(mut self, fingerprint: Fingerprint<D>) -> Self {
		self.fingerprints.insert(fingerprint);
		self
	}

	/// Revoke `cert` by its fingerprint under `D`.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::EncodingError`] -- the certificate fails to DER-encode.
	pub fn with_certificate(self, cert: &Certificate) -> Result<Self, CertificateValidationError> {
		let fingerprint = Fingerprint::<D>::from_certificate(cert)?;
		Ok(self.with_fingerprint(fingerprint))
	}

	/// Revoke by `issuer` and the raw bytes of `serial`, the scope of a CRL
	/// entry.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::EncodingError`] -- the issuer name fails to DER-encode.
	pub fn with_serial(mut self, issuer: &Name, serial: impl AsRef<[u8]>) -> Result<Self, CertificateValidationError> {
		self.serials
			.entry(issuer.to_der()?)
			.or_default()
			.insert(serial.as_ref().to_vec());
		Ok(self)
	}
}

#[cfg(feature = "std")]
impl<D> RevocationChecker for StaticRevocationList<D>
where
	D: Digest,
{
	/// The store consults the list at each lookup, so the list digests a
	/// certificate only when it holds a fingerprint. A certificate that fails
	/// to encode has no status the list can establish, so its check fails as
	/// [`CertificateValidationError::RevocationStatusUnknown`].
	fn check(&self, _issuer: &Certificate, cert: &Certificate) -> Result<(), CertificateValidationError> {
		if !self.fingerprints.is_empty() {
			let fingerprint = Fingerprint::<D>::from_certificate(cert);
			let fingerprint = fingerprint.map_err(|_| CertificateValidationError::RevocationStatusUnknown)?;
			if self.fingerprints.contains(&fingerprint) {
				return Err(CertificateValidationError::CertificateRevoked);
			}
		}
		if self.serials.is_empty() {
			return Ok(());
		}

		let issuer_der = cert.tbs_certificate.issuer.to_der();
		let issuer_der = issuer_der.map_err(|_| CertificateValidationError::RevocationStatusUnknown)?;
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

/// The outcome of a frame signature check against a trust store.
///
/// It tells a frame that claims no identity, or an unknown one, apart from a
/// frame of a trusted identity with a bad signature, so a caller can apply a
/// different consequence to each.
#[cfg(feature = "signature")]
#[must_use = "a dropped TrustVerification leaves the frame unauthenticated"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustVerification<'a> {
	/// The frame carries no nonrepudiation signature.
	MissingSignature,
	/// The trust store holds no certificate for the signer.
	UnknownSigner,
	/// The store trusts the signer, and the signature fails verification.
	Invalid,
	/// The signature verified against the certificate that this store
	/// resolved, which it admitted for signing at enrolment. The verified
	/// signature is the replay key of the frame.
	Verified(&'a PeerCertificate<ErasedSigning>, VerifiedSignature),
}

/// A store that verifies certificate trust.
///
/// It extends [`CertificateValidation`] with trust-based operations.
/// [`CertificateTrustStore`] is the built-in store and needs `std`, so a
/// no_std consumer supplies its own implementation of this trait.
///
/// # Contract
///
/// Every implementation keeps three rules, which the handshake and the colony
/// read through this trait:
///
/// - A store admits a certificate by its contents alone, whatever role the handshake reads it in.
/// - A check of a server's identity, such as a pin, belongs in the client's
///   server policy, which `with_server_policy` sets, and a check of a
///   client's identity belongs in the validators of the server's
///   `PeerAuthentication::mutual`.
/// - Wherever a method reads a key, two keys are one key exactly when they
///   share one [`CanonicalKey`] under the [`KeyCurves`] of the store.
///
/// The built-in store runs revocation at each admission:
///
/// - It runs path validation and revocation on each certificate that
///   [`CertificateValidation::evaluate`],
///   [`CertificateValidation::evaluate_presented`], [`Self::trust_anchor`],
///   [`Self::verify_chain`], or [`Self::verify_presented`] admits.
/// - Each of its lookups runs its [`RevocationChecker`] over the path of the
///   certificate it answers with, so a revoked certificate verifies no frame,
///   and no key lookup finds it.
/// - A check of every certificate, such as a denylist, belongs in that checker.
///
/// # Flows
///
/// Each handshake flow admits a certificate through one method:
///
/// - A CMS client, and an HPKE client of `LearnedTrust::anchored`, admit the
///   server's signing certificate through [`Self::verify_presented`], with
///   the issuers the reply presents. Its default reads [`Self::verify_chain`].
/// - A CMS client admits the pinned key-agreement certificate through
///   [`Self::trust_anchor`], or through [`Self::verify_chain`] for a pinned
///   chain.
/// - A mutual server admits its client through
///   [`CertificateValidation::evaluate_presented`], with the issuers the client
///   Finished presents. Its default reads [`CertificateValidation::evaluate`].
///
/// A check of the leaf that [`CertificateValidation::evaluate`] runs, such as
/// a denylist, belongs in each of these methods, because each flow reads its
/// method alone.
///
/// [`CanonicalKey`]: crate::crypto::x509::CanonicalKey
/// [`KeyCurves`]: crate::crypto::x509::KeyCurves
pub trait CertificateTrust: CertificateValidation + Debug + Send + Sync {
	/// Returns whether the store trusts `cert` by fingerprint.
	///
	/// A fingerprint names one certificate, so plane membership that must
	/// survive the re-issuance of a certificate for the same key uses
	/// [`Self::trusts_public_key`].
	fn is_trusted(&self, cert: &Certificate) -> bool;

	/// Returns whether this store holds a certificate for `cert`'s public key.
	///
	/// A key is a member when [`Self::enrolled_certificate`] answers for it,
	/// so a rotated certificate for an enrolled key matches too. An
	/// implementor whose [`Self::find_by_public_key`] keeps the key rule of
	/// the [contract](CertificateTrust#contract) gets this behavior with no
	/// override.
	#[must_use = "a dropped membership answer leaves the plane gate unenforced"]
	fn trusts_public_key(&self, cert: &Certificate) -> bool {
		self.enrolled_certificate(cert).is_some()
	}

	/// Returns the certificate this store holds for `cert`'s public key.
	///
	/// The lookup key is the SubjectPublicKeyInfo, resolved through
	/// [`Self::find_by_public_key`]. A rotated certificate for an enrolled key
	/// therefore resolves to the enrolled one, which is the certificate a
	/// signature by that key verifies against.
	fn enrolled_certificate(&self, cert: &Certificate) -> Option<&Certificate> {
		self.find_by_public_key(&cert.tbs_certificate.subject_public_key_info)
	}

	/// Find a certificate by its SubjectPublicKeyInfo.
	///
	/// This is the key-identity lookup that plane membership uses. It matches
	/// the key whatever certificate carries it, by the key rule of the
	/// [contract](CertificateTrust#contract).
	fn find_by_public_key(&self, spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate>;

	/// Find a certificate by `key`, the canonical form of its key, which is
	/// the form a session holds of the peer it proved.
	///
	/// - The default decodes the DER of `key` and calls [`Self::find_by_public_key`].
	/// - The built-in store finds `key` in its key index with no decode, so it
	///   answers at most what the default answers.
	/// - Under a store whose [`KeyCurves`] differ from [`KeyCurves::HOUSE`],
	///   the canonical form of an encoding off its curve depends on the curves
	///   that read it, so the built-in store can find no certificate where the
	///   default finds one. That narrower answer fails closed, because a key
	///   that names no certificate gets no trust.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::policy::Secp256k1Policy;
	/// use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
	/// use tightbeam::crypto::x509::CanonicalKey;
	/// use tightbeam::testing::fixtures::{TestCertificate, TestKey};
	///
	/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
	/// let store = builder.with_certificate(certificate.clone())?.build();
	///
	/// // The canonical form of the key names its certificate.
	/// let key = CanonicalKey::of(&certificate.tbs_certificate.subject_public_key_info)?;
	/// assert_eq!(store.find_by_canonical_key(&key), Some(&certificate));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	///
	/// [`KeyCurves`]: crate::crypto::x509::KeyCurves
	/// [`KeyCurves::HOUSE`]: crate::crypto::x509::KeyCurves::HOUSE
	fn find_by_canonical_key(&self, key: &CanonicalKey) -> Option<&Certificate> {
		// The DER of a canonical key is an encoding the crate wrote, and a key
		// whose DER fails to decode names no certificate.
		let spki = SubjectPublicKeyInfoOwned::from_der(key.as_der()).ok()?;
		self.find_by_public_key(&spki)
	}

	/// Verify a certificate chain with partial RFC 5280 §6.1 path validation,
	/// and return the trust anchor at which its path ends.
	///
	/// - `chain` is ordered issuer before subject, and it ends at the leaf.
	/// - `chain` may start at a trust anchor the store holds, or below one. A
	///   chain that starts below the anchor is the path a peer presents, and
	///   the built-in store walks the issuers it holds from the first
	///   certificate of `chain` up to an anchor.
	/// - The anchor is the one that [`Self::trust_anchor`] names for a
	///   certificate of the same path, so the two compare.
	///
	/// # Checks
	///
	/// 1. Trust anchor check: the walk over the store's issuers ends at a held anchor (RFC 5280 §6.1.1).
	/// 2. Expiry validation for all certificates (RFC 5280 §6.1.3(a)(2)).
	/// 3. Rejection of unprocessed critical extensions (RFC 5280 §4.2, §6.1.3(f)).
	/// 4. Issuer and subject DN chaining (RFC 5280 §6.1.3(a)(4)).
	/// 5. Issuer `basicConstraints.cA` and `keyUsage.keyCertSign` (RFC 5280 §6.1.4(k),(n)).
	/// 6. Cryptographic signature verification (RFC 5280 §6.1.3(a)(1)).
	/// 7. Issuer `pathLenConstraint` (RFC 5280 §6.1.4(l),(m)).
	///
	/// # Scope
	///
	/// Name constraints and policies (§6.1.3-§6.1.5), and the fetch of a CRL
	/// or an OCSP response, stay out of scope, and the built-in store refuses
	/// a path certificate that states name constraints. Revocation runs
	/// through the configured [`RevocationChecker`]. See
	/// <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1>.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError`] -- the chain fails validation.
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
	/// // The store holds the root alone, and the chain carries the path below
	/// // it.
	/// let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
	/// let store = builder.with_certificate(root.to_owned())?.build();
	///
	/// let path = [intermediate, leaf];
	/// let anchor = store.verify_chain(&path)?;
	/// assert_eq!(*anchor, root);
	/// # Ok(())
	/// # }
	/// ```
	fn verify_chain(&self, chain: &[Certificate]) -> Result<Arc<Certificate>, CertificateValidationError>;

	/// Verify the path a peer presents, `leaf` below `issuers`, and return the
	/// trust anchor at which the path ends. `issuers` holds the issuers above
	/// `leaf`, the top first, so the path verifies as [`Self::verify_chain`]
	/// verifies the chain of `issuers` then `leaf`.
	///
	/// A client admits its server's signing certificate here (RFC 5652 §5.1):
	///
	/// - The default lends `leaf` in place when `issuers` is empty, and copies
	///   the path into one slice for [`Self::verify_chain`] otherwise.
	/// - The built-in store reads both in place.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError`] -- the path fails validation.
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
	/// let TestCertificateChain { root, intermediate, leaf, .. } = TestCertificate::insecure_fixed_chain()?;
	///
	/// // The store holds the root alone, and the peer presents the
	/// // intermediate above its certificate.
	/// let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
	/// let store = builder.with_certificate(root.to_owned())?.build();
	///
	/// let anchor = store.verify_presented(&[intermediate], &leaf)?;
	/// assert_eq!(*anchor, root);
	/// # Ok(())
	/// # }
	/// ```
	fn verify_presented(
		&self,
		issuers: &[Certificate],
		leaf: &Certificate,
	) -> Result<Arc<Certificate>, CertificateValidationError> {
		if issuers.is_empty() {
			return self.verify_chain(slice::from_ref(leaf));
		}

		let path = [issuers, slice::from_ref(leaf)].concat();
		self.verify_chain(&path)
	}

	/// Validate `cert` as [`CertificateValidation::evaluate`] does, and return
	/// the trust anchor at which its certification path ends, the anchor that
	/// RFC 5280 §6.1.1(d) names as the input of path validation.
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

	/// Find a certificate admitted for signing by its CMS [`SignerIdentifier`].
	///
	/// Frame verification resolves its signer here (RFC 5652 §5.3):
	///
	/// - The subject-key-identifier form matches a certificate's `subjectKeyIdentifier` extension value.
	/// - The issuer-and-serial form matches its issuer and serial number.
	///
	/// A store admits each certificate for signing once, at enrolment, so a
	/// certificate that only certifies others resolves no signer. The built-in
	/// store resolves a signer while its [`RevocationChecker`] admits it.
	fn find_by_signer_identifier(&self, sid: &SignerIdentifier) -> Option<&PeerCertificate<ErasedSigning>>;

	/// Find a certificate admitted for signing by the `sid` of `signer_info`,
	/// through [`Self::find_by_signer_identifier`].
	///
	/// Frame signature verification resolves its signer here.
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
/// The builder validates structural correctness: expiry on each add, and issuer
/// and subject chaining on each chain it adds. The built store runs
/// cryptographic verification at run time.
pub trait TrustBuilder: Sized {
	/// The trust store type that this builder produces.
	type Store: CertificateTrust;

	/// Add a certificate chain after structural validation.
	///
	/// The builder validates expiry and issuer and subject chaining, then adds
	/// every certificate in the chain to the trust store.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::EmptyChain`] -- `chain` holds no certificate.
	/// - [`CertificateValidationError::InvalidChain`] -- the issuer name of a
	///   certificate differs from the subject name of the one before it.
	/// - The errors of [`Self::with_certificate`], for each certificate of `chain`.
	fn with_chain(self, chain: impl IntoIterator<Item = Certificate>) -> Result<Self, CertificateValidationError>;

	/// Add a single trusted certificate after an expiry check.
	///
	/// # Errors
	///
	/// - The errors of [`validate_expiry`](crate::crypto::x509::utils::CertificateExt::validate_expiry).
	/// - [`CertificateValidationError::EncodingError`] -- `cert` fails to
	///   DER-encode, or a key identifier extension fails to decode.
	/// - [`CertificateValidationError::DuplicateExtension`] -- a key identifier extension repeats.
	/// - [`CertificateValidationError::SkidCollision`] -- another certificate
	///   holds the same `subjectKeyIdentifier`.
	/// - [`CertificateValidationError::PublicKeyCollision`] -- another certificate holds the same key.
	fn with_certificate(self, cert: Certificate) -> Result<Self, CertificateValidationError>;

	/// Build the sealed trust store.
	fn build(self) -> Self::Store;
}

/// Reject a presented identity certificate that asserts the CA bit.
///
/// This check goes beyond RFC 5280. The terminal certificate of a
/// multi-certificate path is the identity that the path authenticates, and
/// an identity that carries `basicConstraints.cA` (§4.2.1.9) is misissued for
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
/// of band. This check enforces (k) unconditionally, so it rejects v1/v2 CA
/// certificates (see [`CertificateTrustStore::validate_path`]).
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
		let intermediates_below = chain.len().saturating_sub(index.saturating_add(2));
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
	/// The certificate, shared with the signer the store admitted from it.
	certificate: Arc<Certificate>,
	/// Its key identifiers, which the issuer walk reads.
	identifiers: KeyIdentifiers,
}

#[cfg(feature = "std")]
impl HeldCertificate {
	/// Returns the serial number in hex and the issuer of this certificate, the
	/// pair that names one certificate (RFC 5280 §4.1.2.2), as a collision
	/// error names the holder of a key.
	fn holder(&self) -> String {
		let tbs = &self.certificate.tbs_certificate;
		let serial = to_hex(tbs.serial_number.as_bytes());
		format!("serial number {serial} of issuer {}", tbs.issuer)
	}

	/// Returns the certification path of this certificate, which `held` holds
	/// under `fingerprint`: the issuers the walk finds among `held`, anchor
	/// first, then this certificate.
	fn path(
		&self,
		held: &HashMap<Sha3Fingerprint, HeldCertificate>,
		fingerprint: Sha3Fingerprint,
	) -> Box<[Arc<Certificate>]> {
		let authority = self.identifiers.authority.as_deref();
		let walk = IssuerWalk::new(held, &self.certificate, fingerprint, authority);

		let mut path: Vec<Arc<Certificate>> = walk.map(|issuer| Arc::clone(&issuer.certificate)).collect();
		path.reverse();
		path.push(Arc::clone(&self.certificate));
		path.into_boxed_slice()
	}
}

/// The walk up the issuers that a store holds above one certificate, nearest
/// first, which ends at the anchor of its path.
///
/// - Each step takes the certificate held under the issuer name of the
///   current one that ranks first in the order of RFC 4158 §3.5.12.
/// - Of candidates of one rank, a step takes the current certificate itself,
///   so a self-signed one ends the walk.
/// - A revisited certificate ends the walk (RFC 4158 §2.4.2).
#[cfg(feature = "std")]
struct IssuerWalk<'a> {
	/// The certificates the store holds, by fingerprint.
	held: &'a HashMap<Sha3Fingerprint, HeldCertificate>,
	/// The certificate whose issuer the next step finds.
	current: &'a Certificate,
	/// The fingerprint of [`Self::current`], the anchor of the walk so far.
	anchor: Sha3Fingerprint,
	/// The key identifier of the authority that [`Self::current`] names.
	authority: Option<&'a [u8]>,
	/// The fingerprints the walk has reached.
	visited: HashSet<Sha3Fingerprint>,
}

#[cfg(feature = "std")]
impl<'a> IssuerWalk<'a> {
	/// Starts a walk among `held` from `start`, whose fingerprint is
	/// `fingerprint` and whose authority key identifier is `authority`.
	fn new(
		held: &'a HashMap<Sha3Fingerprint, HeldCertificate>,
		start: &'a Certificate,
		fingerprint: Sha3Fingerprint,
		authority: Option<&'a [u8]>,
	) -> Self {
		let visited = HashSet::from([fingerprint]);
		Self { held, current: start, anchor: fingerprint, authority, visited }
	}

	/// Returns the fingerprint of the certificate the walk reached last, which
	/// is the anchor of the path once the walk ends.
	fn anchor(&self) -> Sha3Fingerprint {
		self.anchor
	}

	/// Returns the certificate held under the issuer name of the current
	/// certificate that ranks first, beside its fingerprint
	/// (RFC 5280 §6.1.3(a)(4)).
	fn issuer(&self) -> Option<(&'a Sha3Fingerprint, &'a HeldCertificate)> {
		let issuer = &self.current.tbs_certificate.issuer;
		let candidates = self.held.iter();
		let named = candidates.filter(|(_, held)| held.certificate.tbs_certificate.subject == *issuer);
		named.max_by_key(|&(fingerprint, held)| {
			let itself = *fingerprint == self.anchor;
			(held.identifiers.priority(self.authority), itself)
		})
	}
}

#[cfg(feature = "std")]
impl<'a> Iterator for IssuerWalk<'a> {
	type Item = &'a HeldCertificate;

	fn next(&mut self) -> Option<Self::Item> {
		let (fingerprint, issuer) = self.issuer()?;
		// A revisited certificate ends the walk. That rule covers a
		// self-issued root and the loop detection of RFC 4158 §2.4.2.
		if !self.visited.insert(*fingerprint) {
			return None;
		}

		self.current = issuer.certificate.as_ref();
		self.authority = issuer.identifiers.authority.as_deref();
		self.anchor = *fingerprint;
		Some(issuer)
	}
}

/// The key identifiers of a held certificate that the issuer walk reads
/// (RFC 5280 §4.2.1.1, §4.2.1.2).
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

	/// Returns the key identifier of the authority whose key signed `cert`,
	/// read in place: the `keyIdentifier` of its `authorityKeyIdentifier`. A
	/// self-signed certificate may omit it (RFC 5280 §4.2.1.1), so when the
	/// issuer of `cert` is its subject, its own `subjectKeyIdentifier` names
	/// that key, and that extension decodes only then.
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

	/// Returns the rank of a candidate of these identifiers as the issuer of a
	/// certificate that names `authority` for its authority
	/// (RFC 4158 §3.5.12).
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
	/// fingerprint. Each shares its certificate with [`Self::certificates`].
	signers: HashMap<Sha3Fingerprint, PeerCertificate<ErasedSigning>>,
	/// The `subjectKeyIdentifier` extension values, each to its certificate
	/// fingerprint, and each shared with the key identifiers of that
	/// certificate.
	skid_index: HashMap<Arc<[u8]>, Sha3Fingerprint>,
	/// The canonical form of the key of each certificate, to its
	/// fingerprint, so one key names one certificate by the key rule of the
	/// [`CertificateTrust`] contract.
	key_index: KeyIndex<Sha3Fingerprint>,
	/// The certification path of each certificate among the ones the store
	/// holds, anchor first, which the revocation check of a lookup reads.
	paths: HashMap<Sha3Fingerprint, Box<[Arc<Certificate>]>>,
	/// The verification policy that checks signatures.
	policy: Arc<dyn VerificationPolicy>,
	/// The revocation checker that path validation and each lookup consult.
	revocation: Arc<dyn RevocationChecker>,
}

#[cfg(feature = "std")]
impl CertificateTrustStore {
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
	/// Every public entry point that validates a path reaches these
	/// [RFC 5280 §6.1][rfc5280-6.1] checks through
	/// [`Self::validate_to_anchor`], so all of them apply one validation
	/// strength, for example on `pathLenConstraint`.
	///
	/// # Checks
	///
	/// The routine performs these checks over the whole path:
	///
	/// 1. Validity period ([RFC 5280 §6.1.3(a)(2)][rfc5280-6.1.3]).
	/// 2. Rejection of a `nameConstraints` extension of either criticality
	///    ([RFC 5280 §6.1.4(g)][rfc5280-6.1.4]).
	/// 3. Rejection of unprocessed critical extensions and of a repeated
	///    extension ([RFC 5280 §4.2, §6.1.3(f)][rfc5280-4.2]).
	/// 4. Algorithm-identifier consistency ([RFC 5280 §4.1.1.2][rfc5280-4.1.1.2]).
	/// 5. Issuer and subject name chaining ([RFC 5280 §6.1.3(a)(4)][rfc5280-6.1.3]).
	/// 6. Issuer `basicConstraints.cA` and `keyUsage.keyCertSign` ([RFC 5280 §6.1.4(k),(n)][rfc5280-6.1.4]).
	/// 7. Cryptographic signature verification ([RFC 5280 §6.1.3(a)(1)][rfc5280-6.1.3]).
	/// 8. Revocation through the configured [`RevocationChecker`] ([RFC 5280 §6.1.3(a)(3)][rfc5280-6.1.3]).
	/// 9. `pathLenConstraint` ([RFC 5280 §6.1.4(l),(m)][rfc5280-6.1.4]).
	///
	/// The caller checks the trust anchor. This routine validates path
	/// structure and cryptography only.
	///
	/// # Stricter than RFC 5280
	///
	/// The routine is deliberately stricter than RFC 5280 in six fail-closed
	/// ways. TightBeam runs a closed, self-managed PKI, so the interop these
	/// rules exist for (legacy web roots, cross-signing, cross-vendor DN
	/// encoding variance) never applies, and a refusal of it removes attack
	/// surface:
	///
	/// - §6.1.4(k) applies to every issuer and not only to v3 issuers, so the
	///   routine refuses v1/v2 CA certificates outright. The RFC permits the
	///   refusal.
	/// - Self-issued intermediates count against `pathLenConstraint`, although
	///   §6.1.4(l) exempts them, because key rollover here re-issues the trust
	///   store instead of cross-signing.
	/// - The trust anchor itself is subject to checks 1, 2, 3, 4, 8, and 9, and
	///   to check 6 when it issues the next certificate of the path, although
	///   §6.1.1(d) treats it as exempt input. An expired or revoked pinned root
	///   fails closed, and so does a non-CA root that issues a certificate.
	/// - Name chaining is DER byte equality instead of the case-insensitive
	///   match of §7.1. Both encoders are in-house, and a binary comparison
	///   leaves no canonicalization ambiguity.
	/// - The terminal certificate of a multi-certificate path must not assert
	///   `basicConstraints.cA`, so the routine refuses an authenticated
	///   identity misissued with CA power ([`ensure_terminal_is_end_entity`]).
	/// - The routine refuses a certificate that states name constraints, where
	///   §6.1.4(g) would apply them to the names below it.
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

		// RFC 5280 §6.1.4(g): name constraints stay out of scope, so a
		// certificate that states one fails closed, whatever its criticality.
		path.iter().try_for_each(|cert| cert.ensure_no_name_constraints())?;

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
		path.iter().zip(path.iter().skip(1)).try_for_each(|(issuer, cert)| {
			// RFC 5280 §6.1.3(a)(4): the issuer DN must equal the subject DN of
			// the certificate before it.
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
				// No ledger uses a certificate signature as its key, so its
				// canonical form drops here.
				.map(drop)
		})?;

		// RFC 5280 §6.1.3(a)(3): the configured checker runs revocation.
		self.check_revocation(path)?;

		// RFC 5280 §6.1.4(m): `pathLenConstraint` holds across the path.
		ensure_path_len(path)
	}

	/// Run the revocation checker over `path`, anchor first
	/// (RFC 5280 §6.1.3(a)(3)):
	///
	/// - The checker reads the anchor with itself as issuer, which is
	///   stricter than §6.1.1(d) and consistent with the anchor checks of
	///   path validation.
	/// - The checker reads each certificate after the anchor with the one before it as issuer.
	///
	/// # Errors
	///
	/// - The errors of [`RevocationChecker::check`].
	fn check_revocation<C: Borrow<Certificate>>(&self, path: &[C]) -> Result<(), CertificateValidationError> {
		if let Some(anchor) = path.first() {
			self.revocation.check(anchor.borrow(), anchor.borrow())?;
		}

		let mut pairs = path.iter().zip(path.iter().skip(1));
		pairs.try_for_each(|(issuer, cert)| self.revocation.check(issuer.borrow(), cert.borrow()))
	}

	/// Whether this store holds a certificate under `fingerprint` that its
	/// revocation checker admits, beside each issuer above it that the store
	/// holds, as path validation checks them.
	///
	/// Each lookup consults the checker, so a lookup finds no certificate the
	/// checker revokes, even one it revokes after the build.
	fn admits(&self, fingerprint: &Sha3Fingerprint) -> bool {
		let path = self.paths.get(fingerprint);
		path.is_some_and(|path| self.check_revocation(path).is_ok())
	}

	/// Returns the certificate this store holds under `fingerprint`, while
	/// [`Self::admits`] admits it.
	fn admitted(&self, fingerprint: &Sha3Fingerprint) -> Option<&Certificate> {
		let held = self.certificates.get(fingerprint)?;
		self.admits(fingerprint).then_some(held.certificate.as_ref())
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
	/// Walk the issuer hierarchy as far as the certificates the store holds
	/// allow, then validate the accumulated path with the shared
	/// path-validation routine.
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
	/// its own `subjectKeyIdentifier` (RFC 5280 §4.2.1.1), and of the
	/// candidates of one rank, the walk takes the certificate itself. The walk
	/// commits to its candidate, and the signature check of the path decides.
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		// The evaluation admits the certificate alone, so its anchor drops.
		self.validate_to_anchor(iter::once(cert)).map(drop)
	}

	/// Validate the path of `leaf` under `issuers` to an anchor of the store,
	/// as [`CertificateTrust::verify_presented`] validates it, with both read
	/// in place.
	fn evaluate_presented(
		&self,
		issuers: &[Certificate],
		leaf: &Certificate,
	) -> Result<(), CertificateValidationError> {
		// The evaluation admits the path alone, so its anchor drops.
		let presented = issuers.iter().chain(iter::once(leaf));
		self.validate_to_anchor(presented).map(drop)
	}
}

#[cfg(feature = "std")]
impl CertificateTrustStore {
	/// Walk the issuer hierarchy from the first certificate of `presented`,
	/// an anchor-first path lent in place, as far as the certificates this
	/// store holds allow. Validate the walked issuers followed by `presented`
	/// as one path, and return the fingerprint of the trust anchor the walk
	/// ended at, which this store holds.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::EmptyChain`] -- `presented` holds no certificate.
	/// - [`CertificateValidationError::CertificateNotTrusted`] -- the walk ends at no anchor of this store.
	/// - The errors of [`Self::validate_path`].
	fn validate_to_anchor<'c>(
		&'c self,
		mut presented: impl Iterator<Item = &'c Certificate>,
	) -> Result<Sha3Fingerprint, CertificateValidationError> {
		let start = presented.next().ok_or(CertificateValidationError::EmptyChain)?;
		let fingerprint = Sha3Fingerprint::from_certificate(start)?;

		// The authority identifier of `start` reads in place here, and the
		// builder decoded those of the held certificates.
		let authority = KeyIdentifiers::authority_of(start)?;
		let mut walk = IssuerWalk::new(&self.certificates, start, fingerprint, authority);
		let mut path: Vec<&Certificate> = walk.by_ref().map(|issuer| issuer.certificate.as_ref()).collect();
		let anchor = walk.anchor();

		// RFC 5280 §6.1.1: the walk must reach a configured trust anchor.
		if !self.fingerprints.contains(&anchor) {
			return Err(CertificateValidationError::CertificateNotTrusted);
		}

		// The path runs anchor first, issuer before subject: the walked issuers
		// from the top, then the presented path.
		path.reverse();
		path.push(start);
		path.extend(presented);
		self.validate_path(&path)?;
		Ok(anchor)
	}

	/// Returns the certificate this store holds under `fingerprint`, as a
	/// shared handle.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::CertificateNotTrusted`] -- the store holds no such certificate.
	fn held(&self, fingerprint: &Sha3Fingerprint) -> Result<Arc<Certificate>, CertificateValidationError> {
		let held = self.certificates.get(fingerprint);
		let certificate = held.map(|held| Arc::clone(&held.certificate));
		certificate.ok_or(CertificateValidationError::CertificateNotTrusted)
	}
}

#[cfg(feature = "std")]
impl CertificateTrust for CertificateTrustStore {
	/// The store trusts a certificate it holds while its revocation checker
	/// admits it and each issuer above it.
	fn is_trusted(&self, cert: &Certificate) -> bool {
		let fingerprint = Sha3Fingerprint::from_certificate(cert);
		fingerprint.is_ok_and(|fingerprint| self.admits(&fingerprint))
	}

	/// The anchor is the top of the issuer walk from the first certificate of
	/// the chain, as for [`Self::trust_anchor`], so a chain that starts below
	/// a held certificate names the anchor above it.
	fn verify_chain(&self, chain: &[Certificate]) -> Result<Arc<Certificate>, CertificateValidationError> {
		// RFC 5280 §6.1.1: the walk ends at a configured trust anchor, or the
		// chain fails. Every entry point shares this walk and its one path
		// validation, so the entry points agree.
		let anchor = self.validate_to_anchor(chain.iter())?;
		self.held(&anchor)
	}

	/// The store reads `issuers` and `leaf` in place.
	fn verify_presented(
		&self,
		issuers: &[Certificate],
		leaf: &Certificate,
	) -> Result<Arc<Certificate>, CertificateValidationError> {
		let presented = issuers.iter().chain(iter::once(leaf));
		let anchor = self.validate_to_anchor(presented)?;
		self.held(&anchor)
	}

	/// The anchor is the certificate the issuer walk of
	/// [`CertificateValidation::evaluate`] ended at, as the store holds it.
	fn trust_anchor(&self, cert: &Certificate) -> Result<Arc<Certificate>, CertificateValidationError> {
		let anchor = self.validate_to_anchor(iter::once(cert))?;
		self.held(&anchor)
	}

	/// The store resolves a signer while its revocation checker admits the
	/// signer and each issuer above it.
	fn find_by_signer_identifier(&self, sid: &SignerIdentifier) -> Option<&PeerCertificate<ErasedSigning>> {
		let (fingerprint, signer) = match sid {
			SignerIdentifier::IssuerAndSerialNumber(_) => {
				let mut signers = self.signers.iter();
				signers.find(|(_, signer)| signer.certificate().is_named_by(sid).is_ok_and(|named| named))?
			}
			SignerIdentifier::SubjectKeyIdentifier(skid) => {
				let fingerprint = self.skid_index.get(skid.0.as_bytes())?;
				self.signers.get_key_value(fingerprint)?
			}
		};
		self.admits(fingerprint).then_some(signer)
	}

	/// The store finds a certificate while its revocation checker admits the
	/// certificate and each issuer above it.
	fn find_by_public_key(&self, spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate> {
		let fingerprint = self.key_index.find(spki)?;
		self.admitted(fingerprint)
	}

	/// The store finds `key` in its key index as it stands, with no decode,
	/// while its revocation checker admits the certificate and each issuer
	/// above it.
	///
	/// A key that a handshake admits is a valid point or a key of another
	/// algorithm, whose canonical form is one under every [`KeyCurves`], so
	/// the store answers it as [`Self::find_by_public_key`] does.
	fn find_by_canonical_key(&self, key: &CanonicalKey) -> Option<&Certificate> {
		let fingerprint = self.key_index.get(key)?;
		self.admitted(fingerprint)
	}

	fn to_policy_ref(&self) -> &dyn VerificationPolicy {
		&*self.policy
	}
}

/// The builder of a [`CertificateTrustStore`].
///
/// It validates expiry and key identifiers on each add, and issuer and subject
/// chaining on each chain it adds. The built store runs cryptographic
/// verification at run time. It indexes each certificate three ways:
///
/// - By its fingerprint, which the trust and anchor checks read.
/// - By its `subjectKeyIdentifier` value when it carries one, which a `sid` resolves through (RFC 5652 §5.3).
/// - By the identity of its key, which plane membership reads.
///
/// [`TrustBuilder::build`] admits the signers among them under the signer
/// purpose of its [`KeyPurposes`].
#[cfg(feature = "std")]
pub struct CertificateTrustBuilder {
	fingerprints: HashSet<Sha3Fingerprint>,
	certificates: HashMap<Sha3Fingerprint, HeldCertificate>,
	purposes: KeyPurposes,
	skid_index: HashMap<Arc<[u8]>, Sha3Fingerprint>,
	key_index: KeyIndex<Sha3Fingerprint>,
	policy: Arc<dyn VerificationPolicy>,
	revocation: Arc<dyn RevocationChecker>,
}

/// Converts `policy` into a builder that verifies signatures under it and
/// reads each key under [`KeyCurves::HOUSE`].
#[cfg(feature = "std")]
impl<P: VerificationPolicy + 'static> From<P> for CertificateTrustBuilder {
	fn from(policy: P) -> Self {
		Self::new(policy, KeyCurves::HOUSE)
	}
}

/// Returns `bytes` as lowercase hexadecimal, the form in which a collision
/// error names its index entry.
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
	/// Returns a builder that verifies signatures under `policy` and reads each
	/// key under `curves`, so the decoder of a curve reads its off-curve
	/// encodings as their bits at enrolment and at each lookup.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::policy::Secp256k1Policy;
	/// use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
	/// use tightbeam::crypto::x509::KeyCurves;
	/// use tightbeam::testing::fixtures::{TestCertificate, TestKey};
	///
	/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE);
	/// let store = builder.with_certificate(certificate.clone())?.build();
	///
	/// // The store finds the key in its other SEC 1 form.
	/// let compressed = TestCertificate::with_compressed_key(certificate);
	/// let spki = &compressed.tbs_certificate.subject_public_key_info;
	/// assert!(store.find_by_public_key(spki).is_some());
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn new(policy: impl VerificationPolicy + 'static, curves: KeyCurves) -> Self {
		Self {
			fingerprints: HashSet::new(),
			certificates: HashMap::new(),
			purposes: KeyPurposes::default(),
			skid_index: HashMap::new(),
			key_index: KeyIndex::new(curves),
			policy: Arc::new(policy),
			revocation: Arc::new(NoRevocation),
		}
	}

	/// Set the revocation checker that the store consults during path
	/// validation and at each lookup.
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
	/// extension value when it carries one, and by the identity of its key,
	/// and decode the key identifiers the issuer walk reads.
	///
	/// One key under two fingerprints is a collision, and so is one extension
	/// value, because a lookup by either would name two certificates. Each
	/// collision names the index it hit.
	fn add_certificate(&mut self, cert: Certificate) -> Result<(), CertificateValidationError> {
		let fp = Sha3Fingerprint::from_certificate(&cert)?;

		let spki = &cert.tbs_certificate.subject_public_key_info;
		let identifiers = KeyIdentifiers::of(&cert)?;
		let skid = identifiers.subject.as_ref();
		let skid_holder = skid.and_then(|skid| self.skid_index.get(skid));
		if let (Some(skid), Some(holder)) = (skid, skid_holder) {
			if *holder != fp {
				return Err(CertificateValidationError::SkidCollision { skid: to_hex(skid) });
			}
		}

		let key_holder = self.key_index.find(spki);
		if let Some(holder) = key_holder.filter(|holder| **holder != fp) {
			let public_key = to_hex(&spki.to_der()?);
			// The key index and the held certificates gain each entry in one
			// add, so the index names a held certificate.
			let held = self.certificates.get(holder);
			let holder = held.map(HeldCertificate::holder).unwrap_or_default();
			return Err(CertificateValidationError::PublicKeyCollision { public_key, holder });
		}

		// The index is the one write that can fail, so it runs first. The
		// collision check above refused a key held under another fingerprint,
		// so the value it replaces, if any, is `fp` itself.
		self.key_index.insert(spki, fp)?;
		self.fingerprints.insert(fp);

		// The index keys a `sid` lookup by the extension value, and the held
		// certificate keeps it for the issuer walk, so the two share one
		// allocation.
		if let Some(skid) = skid {
			self.skid_index.insert(Arc::clone(skid), fp);
		}

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
		chain.iter().zip(chain.iter().skip(1)).try_for_each(|(issuer, cert)| {
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

		let signers = signers.collect();
		// The held certificates are fixed from here on, so the path of each
		// is too, and a lookup checks its revocation without a walk.
		let held = &self.certificates;
		let paths = held.iter().map(|(fp, certificate)| (*fp, certificate.path(held, *fp)));
		let paths = paths.collect();

		CertificateTrustStore {
			signers,
			paths,
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
	use crate::crypto::k256::sha2::{Sha256, Sha384};
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, SigningKey};
	use crate::crypto::sign::{CmsSigner, SignedContent, SigningIdentity};
	use crate::crypto::x509::error::CertificateValidationError::PublicKeyCollision;
	use crate::der::asn1::{ObjectIdentifier, OctetString};
	use crate::der::oid::AssociatedOid;
	use crate::der::Decode;
	use crate::oids::CURVE_NIST_P256;
	use crate::testing::fixtures::{TestCertificate, TestCertificateChain, TestIdentity};
	use crate::testing::{TestFrame, TestKey};
	use crate::x509::ext::pkix::name::GeneralName;
	use crate::x509::ext::pkix::SubjectKeyIdentifier;
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
		assert_eq!(Fingerprint::<Sha3_256>::from_certificate(&cert)?.as_slice().len(), 32);
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

	// The cases of `evaluate` over the issuer walk:
	//
	// - A trusted root passes directly.
	// - The presented intermediate asserts the CA bit, so it fails with `EndEntityIsCa`.
	// - The issuer walk lets a store of the root and the intermediate trust the leaf.
	// - A store of the root alone holds no issuer of the leaf, so the walk reaches no anchor.
	// - An empty store trusts nothing.
	crate::tb_cases! {
		fn evaluate_chain_walking((store_certs, eval_target, should_succeed): (StoreCerts, EvalTarget, bool))
			-> TestResult
		{
			let chain = TestCertificate::insecure_fixed_chain()?;
			let store = build_store(&chain, store_certs)?;
			let cert = target_cert(&chain, eval_target);

			let result = store.evaluate(cert);
			assert_eq!(
				result.is_ok(),
				should_succeed,
				"store={store_certs:?} target={eval_target:?}: expected {should_succeed}, got {result:?}"
			);
			Ok(())
		}
		cases {
			a_trusted_root => (StoreCerts::Root, EvalTarget::Root, true),
			an_intermediate_presented_as_an_end_entity => (StoreCerts::Root, EvalTarget::Intermediate, false),
			a_leaf_under_a_held_intermediate => (StoreCerts::RootAndIntermediate, EvalTarget::Leaf, true),
			a_leaf_with_no_held_issuer => (StoreCerts::Root, EvalTarget::Leaf, false),
			an_empty_store => (StoreCerts::None, EvalTarget::Leaf, false),
		}
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
	/// path ends, and not the intermediate that issued it
	/// (RFC 5280 §6.1.1(d)).
	#[test]
	fn the_anchor_of_a_leaf_under_an_intermediate_is_its_root() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let store = build_store(&chain, StoreCerts::RootAndIntermediate)?;

		let anchor = store.trust_anchor(&chain.leaf)?;
		assert_eq!(anchor.as_ref(), &chain.root);
		Ok(())
	}

	/// Returns a store of two authorities of one subject name, `Rollover CA`,
	/// beside the two: the authority of `named_key` with its key identifier,
	/// and the authority of `unnamed_key` with none.
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

	/// Returns a leaf that the authority `Rollover CA` of `issuer_key` issues.
	fn rollover_leaf(issuer_key: &Secp256k1SigningKey) -> Result<Certificate, Box<dyn std::error::Error>> {
		let leaf_key = SigningKey::from_bytes(&[6u8; 32].into())?;
		let usage = KeyUsage(KeyUsages::DigitalSignature.into());
		Ok(TestCertificate::issued(issuer_key, "Rollover CA", &leaf_key, "Leaf", 2, usage)?)
	}

	/// Of two authorities of one subject name, the walk takes the one whose
	/// key identifier the leaf names over one that states none
	/// (RFC 4158 §3.5.12).
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

	/// Returns the RFC 7093 §2 method 3 key identifier of the key of
	/// `certificate`: the leftmost 160 bits of the SHA-512 hash of its
	/// `subjectPublicKey` value. The fixtures derive theirs by method 1.
	fn method_three_identifier(certificate: &Certificate) -> Result<SubjectKeyIdentifier, Box<dyn std::error::Error>> {
		use k256::sha2::Sha512;

		let spki = &certificate.tbs_certificate.subject_public_key_info;
		let digest = Sha512::digest(spki.subject_public_key.raw_bytes());
		let leftmost = digest.get(..20).ok_or("a SHA-512 hash holds 160 bits")?;
		Ok(SubjectKeyIdentifier::from(OctetString::new(leftmost)?))
	}

	/// A key identifier sorts the candidates and the signature decides, so a
	/// leaf whose `authorityKeyIdentifier` one method derived validates under
	/// an authority whose `subjectKeyIdentifier` another method derived
	/// (RFC 4158 §3.5.12).
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

	/// One `verify_chain` case: the store, the certificates of the presented
	/// chain, and whether the chain passes.
	type ChainCase = (StoreCerts, &'static [EvalTarget], bool);

	crate::tb_cases! {
		fn verify_chain_cases((store_certs, presented, should_succeed): ChainCase) -> TestResult {
			let chain = TestCertificate::insecure_fixed_chain()?;
			let store = build_store(&chain, store_certs)?;
			let chain_vec: Vec<_> = presented.iter().map(|target| target_cert(&chain, *target).to_owned()).collect();

			let result: Result<Arc<Certificate>, CertificateValidationError> = store.verify_chain(&chain_vec);
			assert_eq!(
				result.is_ok(),
				should_succeed,
				"verify_chain: store={store_certs:?} chain_len={}: expected {should_succeed}, got {result:?}",
				presented.len()
			);
			Ok(())
		}
		cases {
			an_empty_chain => (StoreCerts::Root, &[], false),
			an_untrusted_root => (StoreCerts::None, &[EvalTarget::Root], false),
			a_trusted_root_alone => (StoreCerts::Root, &[EvalTarget::Root], true),
			a_full_chain_under_a_trusted_root => (
				StoreCerts::Root,
				&[EvalTarget::Root, EvalTarget::Intermediate, EvalTarget::Leaf],
				true,
			),
		}
	}

	/// One case of the RFC 5280 §6.1.4 path constraints: the CA bit, the
	/// `keyCertSign` bit, and the path length of the root, and the error that
	/// `verify_chain` returns for the otherwise-valid chain.
	type IssuerConstraintCase = (bool, bool, Option<u8>, CertificateValidationError);

	// Each case replaces the root's extensions, then expects `verify_chain` to
	// reject the otherwise-valid chain with the error that the case names.
	crate::tb_cases! {
		fn verify_chain_enforces_issuer_constraints((ca, key_cert_sign, path_len, expected): IssuerConstraintCase)
			-> TestResult
		{
			let chain = TestCertificate::insecure_fixed_chain()?;

			let mut root = chain.root.to_owned();
			root.tbs_certificate.extensions = Some(TestCertificate::ca_extensions(ca, key_cert_sign, path_len));

			let certificate = root.to_owned();
			let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
				.with_certificate(certificate)?
				.build();

			let result = store.verify_chain(&[root, chain.intermediate, chain.leaf]);
			assert!(matches!(result, Err(ref e) if core::mem::discriminant(e) == core::mem::discriminant(&expected)));
			Ok(())
		}
		cases {
			an_issuer_with_no_ca_bit => (false, true, None, CertificateValidationError::IssuerNotCa),
			an_issuer_with_no_key_cert_sign => (true, false, None, CertificateValidationError::MissingKeyCertSign),
			a_path_past_its_length => (true, true, Some(0), CertificateValidationError::PathLenExceeded),
		}
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
		leaf.tbs_certificate.extensions = Some(vec![TestCertificate::opaque_extension("2.5.29.36", true)]);

		let store = build_store(&chain, StoreCerts::Root)?;
		let result = store.verify_chain(&[chain.root, chain.intermediate, leaf]);
		assert!(matches!(
			result,
			Err(CertificateValidationError::UnprocessedCriticalExtension(_))
		));
		Ok(())
	}

	/// `verify_chain` refuses a chain whose leaf repeats its `keyUsage`
	/// (RFC 5280 §4.2).
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
		let policy_constraints = TestCertificate::opaque_extension("2.5.29.36", true);
		let leaf = TestCertificate::with_extension(chain.leaf.to_owned(), policy_constraints);

		let store = build_store(&chain, StoreCerts::RootAndIntermediate)?;
		let refused = store.evaluate(&leaf);
		assert!(matches!(
			refused,
			Err(CertificateValidationError::UnprocessedCriticalExtension(_))
		));
		Ok(())
	}

	/// Returns the intermediate of `chain` with a `nameConstraints` extension,
	/// critical when `critical` holds, which the root signs again, so its path
	/// passes every other check.
	fn constrained_intermediate(chain: &TestCertificateChain, critical: bool) -> Certificate {
		let constraints = TestCertificate::opaque_extension("2.5.29.30", critical);
		let intermediate = TestCertificate::with_extension(chain.intermediate.to_owned(), constraints);
		TestCertificate::signed_by(intermediate, &chain.root_key)
	}

	/// Path validation refuses a presented intermediate that states critical
	/// name constraints, because it does not apply them (RFC 5280 §6.1.4(g)).
	#[test]
	fn a_presented_intermediate_with_critical_name_constraints_is_refused() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let intermediate = constrained_intermediate(&chain, true);
		let store = build_store(&chain, StoreCerts::Root)?;

		let refused = store.verify_presented(&[intermediate], &chain.leaf);
		assert!(matches!(refused, Err(CertificateValidationError::NameConstraintsUnapplied)));
		Ok(())
	}

	/// Path validation refuses a presented intermediate that states name
	/// constraints in a non-critical extension too, because RFC 5280 §6.1.4(g)
	/// applies them whatever their criticality.
	#[test]
	fn a_presented_intermediate_with_noncritical_name_constraints_is_refused() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let intermediate = constrained_intermediate(&chain, false);
		let store = build_store(&chain, StoreCerts::Root)?;

		let refused = store.verify_presented(&[intermediate], &chain.leaf);
		assert!(matches!(refused, Err(CertificateValidationError::NameConstraintsUnapplied)));
		Ok(())
	}

	/// A store that holds the root alone validates the path a peer presents
	/// through the intermediate, and names the root as its anchor
	/// (RFC 5280 §6.1).
	#[test]
	fn a_store_of_the_root_alone_anchors_a_presented_path() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let store = build_store(&chain, StoreCerts::Root)?;

		let anchor = store.verify_presented(&[chain.intermediate], &chain.leaf)?;
		assert_eq!(anchor.as_ref(), &chain.root);
		Ok(())
	}

	/// A store that holds the root alone admits a client whose certificate
	/// the intermediate it presents issued.
	#[test]
	fn a_store_of_the_root_alone_evaluates_a_presented_path() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let store = build_store(&chain, StoreCerts::Root)?;
		store.evaluate_presented(&[chain.intermediate], &chain.leaf)?;
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
		// A pinned CA root that validates itself is the direct-trust model.
		let path = [&chain.root];
		assert!(ensure_terminal_is_end_entity(&path).is_ok());
		Ok(())
	}

	/// Build a store that trusts the chain root under `revocation`, for the
	/// RFC 5280 §6.1.3(a)(3) revocation tests.
	fn build_store_with_revocation(
		chain: &TestCertificateChain,
		revocation: impl RevocationChecker + 'static,
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
		let revocation = StaticRevocationList::<Sha3_256>::default().with_certificate(&chain.intermediate)?;
		assert!(revocation.check(&chain.intermediate, &chain.leaf).is_ok());
		Ok(())
	}

	/// Returns the verdict on the fixed chain of a store whose revocation list
	/// under `D` holds the fingerprint of the leaf.
	fn verdict_with_the_leaf_revoked_under<D>() -> Result<Arc<Certificate>, CertificateValidationError>
	where
		D: Digest + 'static,
	{
		let chain = TestCertificate::insecure_fixed_chain().expect("the fixed chain builds");
		let revocation = StaticRevocationList::<D>::default().with_certificate(&chain.leaf);
		let revocation = revocation.expect("the leaf has a fingerprint");
		let store = build_store_with_revocation(&chain, revocation).expect("the store holds the root");
		store.verify_chain(&[chain.root, chain.intermediate, chain.leaf])
	}

	/// A list under SHA3-256 revokes the leaf by its SHA3-256 fingerprint.
	#[test]
	fn verify_chain_rejects_leaf_revoked_by_fingerprint() {
		let verdict = verdict_with_the_leaf_revoked_under::<Sha3_256>();
		assert!(matches!(verdict, Err(CertificateValidationError::CertificateRevoked)));
	}

	/// A list under SHA-384 revokes the leaf by its 48-octet fingerprint.
	#[test]
	fn verify_chain_rejects_leaf_revoked_by_a_sha384_fingerprint() {
		let verdict = verdict_with_the_leaf_revoked_under::<Sha384>();
		assert!(matches!(verdict, Err(CertificateValidationError::CertificateRevoked)));
	}

	#[test]
	fn verify_chain_rejects_leaf_revoked_by_serial() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let issuer = chain.leaf.tbs_certificate.issuer.to_owned();
		let serial = chain.leaf.tbs_certificate.serial_number.as_bytes().to_vec();
		let revocation = StaticRevocationList::<Sha3_256>::default().with_serial(&issuer, serial)?;

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
		let revocation = StaticRevocationList::<Sha3_256>::default().with_serial(&other_issuer, serial)?;

		let store = build_store_with_revocation(&chain, revocation)?;
		let result = store.verify_chain(&[chain.root, chain.intermediate, chain.leaf]);
		assert!(result.is_ok());
		Ok(())
	}

	/// A list under SHA-256 revokes the leaf by its SHA-256 fingerprint, the
	/// digest an operator's list names.
	#[test]
	fn verify_chain_rejects_a_leaf_revoked_by_its_sha256_fingerprint() {
		let verdict = verdict_with_the_leaf_revoked_under::<Sha256>();
		assert!(matches!(verdict, Err(CertificateValidationError::CertificateRevoked)));
	}

	/// The P-256 key of RFC 6979 §A.2.5 reads as a SEC 1 point under a curve
	/// set with no decoder of P-256, so a store that holds it uncompressed
	/// finds it by its compressed form.
	#[test]
	fn a_store_finds_the_rfc6979_p256_key_by_its_compressed_form() -> TestResult {
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let point = &TestKey::RFC6979_P256_UNCOMPRESSED;
		let uncompressed = TestCertificate::with_curve_point(certificate.clone(), CURVE_NIST_P256, point);
		let point = &TestKey::RFC6979_P256_COMPRESSED;
		let compressed = TestCertificate::with_curve_point(certificate, CURVE_NIST_P256, point);
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
		let store = builder.with_certificate(uncompressed.clone())?.build();

		let found = store.find_by_public_key(&compressed.tbs_certificate.subject_public_key_info);
		assert_eq!(found, Some(&uncompressed));
		Ok(())
	}

	/// Returns a store that holds the certificate of `identity` under a
	/// revocation list of that certificate.
	fn store_revoking(identity: &SigningIdentity) -> Result<CertificateTrustStore, CertificateValidationError> {
		let revocation = StaticRevocationList::<Sha3_256>::default().with_certificate(identity.certificate())?;
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_revocation_checker(revocation);
		Ok(builder.with_certificate(identity.certificate().clone())?.build())
	}

	/// A store whose revocation list names a frame signer resolves no signer
	/// for its frame, so a revoked certificate verifies no frame.
	#[tokio::test]
	async fn a_revoked_signer_verifies_no_frame() -> TestResult {
		let identity = TestIdentity::insecure_fixed();
		let store = store_revoking(&identity)?;
		let mut frame = TestFrame::with_integrity();
		frame.sign_with_provider(&identity).await?;

		let verification = store.verify_frame(&frame);
		assert!(matches!(verification, TrustVerification::UnknownSigner));
		Ok(())
	}

	/// A store whose revocation list names a certificate holds no key of it,
	/// so a revoked certificate counts as enrolled for no plane.
	#[test]
	fn a_revoked_certificate_is_no_member_by_its_key() -> TestResult {
		let identity = TestIdentity::insecure_fixed();
		let store = store_revoking(&identity)?;

		let member = store.trusts_public_key(identity.certificate());
		assert!(!member);
		Ok(())
	}

	/// A store trusts no certificate that its revocation list names.
	#[test]
	fn a_store_trusts_no_revoked_certificate() -> TestResult {
		let identity = TestIdentity::insecure_fixed();
		let store = store_revoking(&identity)?;

		let trusted = store.is_trusted(identity.certificate());
		assert!(!trusted);
		Ok(())
	}

	/// A lookup runs revocation over the path of the certificate it finds, so
	/// the leaf under a revoked intermediate is no member by its key.
	#[test]
	fn a_certificate_under_a_revoked_issuer_is_no_member() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let revocation = StaticRevocationList::<Sha3_256>::default().with_certificate(&chain.intermediate)?;
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_revocation_checker(revocation);
		let held = [chain.root, chain.intermediate, chain.leaf.clone()];
		let store = builder.with_chain(held)?.build();

		let member = store.trusts_public_key(&chain.leaf);
		assert!(!member);
		Ok(())
	}

	/// A lookup runs revocation over the path of the certificate it finds
	/// alone, so a root above a revoked intermediate stays a member.
	#[test]
	fn a_certificate_above_a_revoked_issuer_stays_a_member() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let revocation = StaticRevocationList::<Sha3_256>::default().with_certificate(&chain.intermediate)?;
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_revocation_checker(revocation);
		let held = [chain.root.clone(), chain.intermediate, chain.leaf];
		let store = builder.with_chain(held)?.build();

		let member = store.trusts_public_key(&chain.root);
		assert!(member);
		Ok(())
	}

	#[test]
	fn verify_chain_rejects_revoked_anchor() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let revocation = StaticRevocationList::<Sha3_256>::default().with_certificate(&chain.root)?;

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
		let fingerprint = found.map(|signer| Fingerprint::<Sha3_256>::from_certificate(signer.certificate()));
		assert_eq!(
			fingerprint.transpose()?,
			Some(Fingerprint::<Sha3_256>::from_certificate(&cert)?)
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

		let fingerprint = found.map(|signer| Fingerprint::<Sha3_256>::from_certificate(signer.certificate()));
		assert_eq!(
			fingerprint.transpose()?,
			Some(Fingerprint::<Sha3_256>::from_certificate(&cert)?)
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

	/// A key collision names the certificate that holds the key by its serial
	/// number and its issuer (RFC 5280 §4.1.2.2).
	#[test]
	fn a_key_collision_names_the_holder_by_serial_and_issuer() -> TestResult {
		let key = TestKey::insecure_fixed_signing();
		let mut first = TestCertificate::self_signed(&key);
		first.tbs_certificate.issuer = Name::from_str("CN=held")?;
		let mut second = TestCertificate::self_signed(&key);
		second.tbs_certificate.extensions = None;
		second.tbs_certificate.serial_number = SerialNumber::new(&[0x2a])?;
		second.tbs_certificate.issuer = Name::from_str("CN=refused")?;

		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_certificate(first)?;
		let refused = builder.with_certificate(second);

		let expected = "serial number 01 of issuer CN=held";
		let names_holder = matches!(refused, Err(PublicKeyCollision { holder, .. }) if holder == expected);
		assert!(names_holder);
		Ok(())
	}

	/// One secp256k1 point in its compressed and its uncompressed form is one
	/// key, so two certificates of the two forms collide in the key index.
	#[test]
	fn two_certificates_of_one_point_in_two_forms_collide() -> TestResult {
		let key = TestKey::insecure_fixed_signing();
		let first = TestCertificate::self_signed(&key);
		let mut second = TestCertificate::with_compressed_key(TestCertificate::self_signed(&key));
		second.tbs_certificate.extensions = None;

		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_certificate(first)?;
		let refused = builder.with_certificate(second);
		assert!(matches!(refused, Err(CertificateValidationError::PublicKeyCollision { .. })));
		Ok(())
	}

	/// A store that holds a secp256k1 key in the uncompressed form holds it in
	/// the compressed form too, so a re-issued certificate of the other form
	/// stays a member.
	#[test]
	fn a_store_holds_its_key_in_the_compressed_form() -> TestResult {
		let (store, _) = self_signed_store()?;
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let compressed = TestCertificate::with_compressed_key(certificate);
		assert!(store.trusts_public_key(&compressed));
		Ok(())
	}

	/// A point and its negation are two keys, so a store that holds one
	/// holds no certificate of the other.
	#[test]
	fn a_store_holds_no_negation_of_its_key() -> TestResult {
		let (store, _) = self_signed_store()?;
		let negation = TestKey::negation_of(&TestKey::insecure_fixed_signing());
		let negated = TestCertificate::self_signed(&negation);
		assert!(!store.trusts_public_key(&negated));
		Ok(())
	}

	/// An encoding of the x-coordinate and the y parity of the held key that
	/// is no point of its curve names another key, so the store finds no
	/// certificate by it (SEC 1 v2.0 §2.3.4).
	#[test]
	fn a_store_finds_no_certificate_by_an_off_curve_alias_of_its_key() -> TestResult {
		let (store, _) = self_signed_store()?;
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let alias = TestCertificate::with_off_curve_key(certificate);

		let found = store.find_by_public_key(&alias.tbs_certificate.subject_public_key_info);
		assert!(found.is_none());
		Ok(())
	}

	/// Returns a store that holds the fixed self-signed test certificate,
	/// whose one key identifier extension is its `subjectKeyIdentifier`,
	/// beside the certificate's fingerprint.
	fn self_signed_store() -> Result<(CertificateTrustStore, Sha3Fingerprint), Box<dyn std::error::Error>> {
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let fingerprint = Fingerprint::<Sha3_256>::from_certificate(&certificate)?;
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
