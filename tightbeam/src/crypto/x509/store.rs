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
	pub use core::cmp::Reverse;
	pub use core::iter;
	pub use std::collections::{HashMap, HashSet};
	pub use std::sync::Arc;

	pub use crate::clock::Clock;
	pub use crate::crypto::hash::{Digest, OutputSizeUser, Sha3_256};
	pub use crate::crypto::x509::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages};
	pub(super) use crate::crypto::x509::key::{KeyCurves, KeyIndex};
	pub use crate::crypto::x509::name::Name;
	pub use crate::crypto::x509::utils::{CertificateExt, Fingerprint};
	pub(super) use crate::crypto::x509::utils::{SubjectKeyIdentifierRef, ValidityClock};
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
/// Path validation consults it once per certificate, as the revocation step
/// of RFC 5280 §6.1.3(a)(3). The built-in store also consults it over the path
/// of each certificate a lookup answers with, at each frame and each plane
/// check. The crate ships [`NoRevocation`] and [`StaticRevocationList`].
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
/// A store states this waiver at [`CertificateTrustBuilder::new`]. It is sound
/// only for a closed PKI with short-lived certificates, because a compromised
/// key stays trusted until its certificate expires or the operator re-pins the
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
	/// The revoked serial numbers, keyed by the DER of the issuer DN. A serial
	/// is unique only within one CA (RFC 5280 §4.1.2.2), so an unscoped serial
	/// would revoke unrelated certificates.
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
	/// to encode has no status, so its check fails as
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
	/// The signature verified against the certificate this store resolved and
	/// admitted for signing at enrolment. The verified signature is the
	/// frame's replay key.
	Verified(&'a PeerCertificate<ErasedSigning>, VerifiedSignature),
}

/// A store that verifies certificate trust.
///
/// It extends [`CertificateValidation`] with trust operations.
/// [`CertificateTrustStore`] is the built-in store and needs `std`, so a
/// no_std consumer implements this trait itself.
///
/// # Contract
///
/// The handshake and the colony rely on three rules of every implementation:
///
/// - A store admits a certificate by its contents alone, whatever role the handshake reads it in.
/// - A check of a server's identity, such as a pin, belongs in the client's
///   server policy (`with_server_policy`). A check of a client's identity
///   belongs in the validators of the server's `PeerAuthentication::mutual`.
/// - Wherever a method reads a key, two keys are one key exactly when they
///   share one [`CanonicalKey`] under the [`KeyCurves`] of the store.
///
/// The built-in store runs revocation at each admission:
///
/// - It runs path validation and revocation on each certificate that
///   [`CertificateValidation::evaluate`],
///   [`CertificateValidation::evaluate_presented`], [`Self::trust_anchor`],
///   [`Self::verify_chain`], or [`Self::verify_presented`] admits.
/// - Each lookup runs its [`RevocationChecker`] over the path of the
///   certificate it answers with, so a revoked certificate verifies no frame
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
	/// It looks up the SubjectPublicKeyInfo through
	/// [`Self::find_by_public_key`], so a rotated certificate for an enrolled
	/// key resolves to the enrolled one, the certificate a signature by that
	/// key verifies against.
	fn enrolled_certificate(&self, cert: &Certificate) -> Option<&Certificate> {
		self.find_by_public_key(&cert.tbs_certificate.subject_public_key_info)
	}

	/// Find a certificate by its SubjectPublicKeyInfo.
	///
	/// Plane membership uses this key-identity lookup. It matches the key
	/// whatever certificate carries it, by the key rule of the
	/// [contract](CertificateTrust#contract).
	fn find_by_public_key(&self, spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate>;

	/// Find a certificate by `key`, the canonical form of its key, which a
	/// session holds of the peer it proved.
	///
	/// - The default decodes the DER of `key` and calls [`Self::find_by_public_key`].
	/// - The built-in store finds `key` in its key index with no decode, so it
	///   answers at most what the default answers.
	/// - Under [`KeyCurves`] other than [`KeyCurves::HOUSE`], the canonical
	///   form of an off-curve encoding depends on the curves that read it, so
	///   the built-in store can miss a certificate the default finds. That
	///   narrower answer fails closed, because a key that names no certificate
	///   gets no trust.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::policy::Secp256k1Policy;
	/// use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
	/// use tightbeam::crypto::x509::{CanonicalKey, KeyCurves};
	/// use tightbeam::testing::fixtures::{TestCertificate, TestKey};
	///
	/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
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
	/// - `chain` may start at a held trust anchor or below one, as the path a
	///   peer presents. The built-in store walks its held issuers from the
	///   first certificate of `chain` up to an anchor.
	/// - The anchor is the one [`Self::trust_anchor`] names for a certificate
	///   of the same path, so the two compare.
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
	/// Name constraints, policies (§6.1.3-§6.1.5), and CRL or OCSP fetches are
	/// out of scope. The built-in store refuses a path certificate that states
	/// name constraints. Revocation runs through the configured
	/// [`RevocationChecker`]. See
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
	/// use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
	/// use tightbeam::crypto::x509::KeyCurves;
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
	/// let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
	/// let store = builder.with_certificate(root.to_owned())?.build();
	///
	/// let path = [intermediate, leaf];
	/// let anchor = store.verify_chain(&path)?;
	/// assert_eq!(*anchor, root);
	/// # Ok(())
	/// # }
	/// ```
	fn verify_chain(&self, chain: &[Certificate]) -> Result<Arc<Certificate>, CertificateValidationError>;

	/// Verify the path a peer presents, `leaf` below `issuers` (top first), and
	/// return the trust anchor at which the path ends. The path verifies as
	/// [`Self::verify_chain`] verifies `issuers` then `leaf`.
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
	/// use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
	/// use tightbeam::crypto::x509::KeyCurves;
	/// use tightbeam::testing::fixtures::{TestCertificate, TestCertificateChain};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // The keys of the fixture chain are public, so it serves an example
	/// // alone.
	/// let TestCertificateChain { root, intermediate, leaf, .. } = TestCertificate::insecure_fixed_chain()?;
	///
	/// // The store holds the root alone, and the peer presents the
	/// // intermediate above its certificate.
	/// let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
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
	/// the trust anchor at which its certification path ends, the input of
	/// path validation in RFC 5280 §6.1.1(d).
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
	/// use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
	/// use tightbeam::crypto::x509::KeyCurves;
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
	/// let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
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
	/// store resolves a signer while each certificate of its path is within
	/// its validity period and its [`RevocationChecker`] admits it.
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

	/// Add every certificate of a chain after the expiry and chaining checks.
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
	/// - The errors of the expiry check, as
	///   [`validate_expiry_at`](crate::crypto::x509::utils::CertificateExt::validate_expiry_at)
	///   names them.
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
/// multi-certificate path is the identity it authenticates, and an identity
/// with `basicConstraints.cA` (§4.2.1.9) is misissued for that role.
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

		// The certificates strictly between this CA and the end-entity leaf.
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
/// - Of candidates of one rank otherwise, a step takes the one of the lower
///   fingerprint, so one store gives one walk in every process.
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

	/// Starts a walk among `held` from `start`, the first certificate of a
	/// presented path, whose fingerprint is `fingerprint`. `policy` verifies
	/// the signature of a self-issued `start`.
	///
	/// The authority of `start` ranks the candidates under its issuer name
	/// alone, so the walk reads it where it ranks one:
	///
	/// - A `start` that `held` holds takes the identifiers that the builder decoded at enrolment.
	/// - Another `start` reads its own when `held` holds a certificate under its issuer name.
	///
	/// # Errors
	///
	/// - The errors of [`KeyIdentifiers::authority_of`].
	fn presented(
		held: &'a HashMap<Sha3Fingerprint, HeldCertificate>,
		start: &'a Certificate,
		fingerprint: Sha3Fingerprint,
		policy: &dyn VerificationPolicy,
	) -> Result<Self, CertificateValidationError> {
		if let Some(enrolled) = held.get(&fingerprint) {
			let authority = enrolled.identifiers.authority.as_deref();
			return Ok(Self::new(held, start, fingerprint, authority));
		}

		let mut walk = Self::new(held, start, fingerprint, None);
		let ranked = walk.named().next().is_some();
		if ranked {
			walk.authority = KeyIdentifiers::authority_of(start, policy)?;
		}

		Ok(walk)
	}

	/// Returns the fingerprint of the certificate the walk reached last, which
	/// is the anchor of the path once the walk ends.
	fn anchor(&self) -> Sha3Fingerprint {
		self.anchor
	}

	/// Returns the certificates held under the issuer name of the current
	/// certificate, each beside its fingerprint (RFC 5280 §6.1.3(a)(4)).
	fn named(&self) -> impl Iterator<Item = (&'a Sha3Fingerprint, &'a HeldCertificate)> + 'a {
		let current: &'a Certificate = self.current;
		let issuer = &current.tbs_certificate.issuer;
		let candidates = self.held.iter();
		candidates.filter(move |(_, held)| held.certificate.tbs_certificate.subject == *issuer)
	}

	/// Returns the certificate of [`Self::named`] that ranks first, beside its
	/// fingerprint. The fingerprint breaks a tie of rank, so the pick is the
	/// same whatever order the store holds its certificates in.
	fn issuer(&self) -> Option<(&'a Sha3Fingerprint, &'a HeldCertificate)> {
		self.named().max_by_key(|&(fingerprint, held)| {
			let itself = *fingerprint == self.anchor;
			let lower = Reverse(fingerprint.as_slice());
			(held.identifiers.priority(self.authority), itself, lower)
		})
	}
}

#[cfg(feature = "std")]
impl<'a> Iterator for IssuerWalk<'a> {
	type Item = &'a HeldCertificate;

	fn next(&mut self) -> Option<Self::Item> {
		let (fingerprint, issuer) = self.issuer()?;
		// A revisited certificate, such as a self-issued root, ends the walk
		// (RFC 4158 §2.4.2).
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
	/// Decode the key identifiers of `cert`, which the store holds, with
	/// `policy` as the verifier of a self-issued certificate.
	///
	/// # Errors
	///
	/// - The errors of [`Self::authority_of`].
	fn of(cert: &Certificate, policy: &dyn VerificationPolicy) -> Result<Self, CertificateValidationError> {
		let subject = cert.extension::<SubjectKeyIdentifierRef<'_>>()?;
		let subject = subject.map(|subject| Arc::<[u8]>::from(subject.0.as_bytes()));
		let authority = Self::authority_of(cert, policy)?;
		// A self-signed certificate names its own key identifier for its
		// authority, and the two then share one allocation.
		let shared = subject.as_ref().filter(|_| authority == subject.as_deref());
		let authority = shared.map(Arc::clone).or_else(|| authority.map(Arc::from));
		Ok(Self { subject, authority })
	}

	/// Returns the key identifier of the authority whose key signed `cert`,
	/// read in place.
	///
	/// - The `keyIdentifier` of its `authorityKeyIdentifier` names that key.
	/// - A self-signed certificate may omit that identifier
	///   (RFC 5280 §4.2.1.1). When the issuer of `cert` is its subject, its
	///   own `subjectKeyIdentifier` names that key once its own key verifies
	///   its signature under `policy`. That extension decodes only then, and
	///   the signature counts only for a `cert` that carries it.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::EncodingError`] -- a key identifier extension fails to decode.
	/// - [`CertificateValidationError::DuplicateExtension`] -- a key identifier extension repeats.
	/// - The errors of [`Self::signs_itself`].
	fn authority_of<'c>(
		cert: &'c Certificate,
		policy: &dyn VerificationPolicy,
	) -> Result<Option<&'c [u8]>, CertificateValidationError> {
		let stated = cert.extension::<AuthorityKeyIdentifierRef<'_>>()?;
		if let Some(key_identifier) = stated.and_then(|stated| stated.key_identifier) {
			return Ok(Some(key_identifier.as_bytes()));
		}

		let tbs = &cert.tbs_certificate;
		if tbs.subject != tbs.issuer {
			return Ok(None);
		}
		let Some(own) = cert.extension::<SubjectKeyIdentifierRef<'_>>()? else {
			return Ok(None);
		};
		if !Self::signs_itself(cert, policy)? {
			return Ok(None);
		}

		Ok(Some(own.0.as_bytes()))
	}

	/// Returns whether the key of `cert` verifies the signature of `cert`
	/// under `policy`, which makes a self-issued certificate a self-signed
	/// one (RFC 5280 §3.2).
	///
	/// Each refusal of `policy` answers `false`, because a signature that the
	/// key of `cert` does not verify makes `cert` self-issued alone.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::EncodingError`] -- the key or the `tbsCertificate` fails to encode.
	fn signs_itself(cert: &Certificate, policy: &dyn VerificationPolicy) -> Result<bool, CertificateValidationError> {
		let public_key_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
		let message = cert.tbs_certificate.to_der()?;
		let algorithm = &cert.signature_algorithm.oid;
		let verified = policy.verify_signature(algorithm, &public_key_der, &message, cert.signature.raw_bytes());
		Ok(verified.is_ok())
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
	/// fingerprint and shared with that certificate's key identifiers.
	skid_index: HashMap<Arc<[u8]>, Sha3Fingerprint>,
	/// The canonical form of the key of each certificate, to its
	/// fingerprint, so one key names one certificate by the key rule of the
	/// [`CertificateTrust`] contract.
	key_index: KeyIndex<Sha3Fingerprint>,
	/// The certification path of each held certificate, anchor first, which the
	/// validity and revocation checks of a lookup read.
	paths: HashMap<Sha3Fingerprint, Box<[Arc<Certificate>]>>,
	/// The verification policy that checks signatures.
	policy: Arc<dyn VerificationPolicy>,
	/// The revocation checker that path validation and each lookup consult.
	revocation: Arc<dyn RevocationChecker>,
	/// The clock that path validation and each lookup read the validity
	/// period of a certificate on.
	clock: ValidityClock,
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

	/// Validates an ordered certification path, issuer first, from anchor to
	/// leaf.
	///
	/// Every public entry point that validates a path reaches these
	/// [RFC 5280 §6.1][rfc5280-6.1] checks through
	/// [`Self::validate_to_anchor`], so all of them apply one strength,
	/// `pathLenConstraint` included.
	///
	/// # Checks
	///
	/// Each check covers the whole path:
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
	/// The caller checks the trust anchor, and this routine checks only path
	/// structure and cryptography.
	///
	/// # Stricter than RFC 5280
	///
	/// TightBeam runs a closed, self-managed PKI, so the interop these RFC
	/// rules serve (legacy web roots, cross-signing, cross-vendor DN encodings)
	/// never applies. The routine refuses closed in six more ways, and each
	/// removes attack surface:
	///
	/// - §6.1.4(k) applies to v1 and v2 issuers too, so their CA certificates fail, as the RFC permits.
	/// - Self-issued intermediates count against `pathLenConstraint`, which
	///   §6.1.4(l) exempts, because key rollover here re-issues the trust store
	///   instead of cross-signing.
	/// - Checks 1 to 4, 8, and 9 apply to the trust anchor, and check 6 when it
	///   issues the next certificate, where §6.1.1(d) exempts it. An expired,
	///   revoked, or non-CA issuing root fails.
	/// - Name chaining is DER byte equality, not the case-insensitive match of
	///   §7.1. Both encoders are in-house, so a binary comparison leaves no
	///   canonicalization ambiguity.
	/// - The terminal certificate of a multi-certificate path must not assert
	///   `basicConstraints.cA`, so an identity misissued with CA power fails
	///   ([`ensure_terminal_is_end_entity`]).
	/// - A certificate with name constraints fails, where §6.1.4(g) would apply them to the names below it.
	///
	/// [rfc5280-6.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1
	/// [rfc5280-6.1.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.3
	/// [rfc5280-6.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.4
	/// [rfc5280-4.2]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2
	/// [rfc5280-4.1.1.2]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2
	fn validate_path(&self, path: &[&Certificate]) -> Result<(), CertificateValidationError> {
		// RFC 5280 §6.1.3(a)(2): each certificate is within its validity
		// period.
		path.iter().try_for_each(|cert| self.clock.admits(cert))?;

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
	/// - The checker reads the anchor as its own issuer, stricter than
	///   §6.1.1(d) and like the anchor checks of path validation.
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

	/// Whether this store holds a certificate under `fingerprint` whose path
	/// passes two checks of path validation. The path is the certificate and
	/// each issuer above it that the store holds.
	///
	/// - Each certificate is within its validity period on the clock of the store (RFC 5280 §6.1.3(a)(2)).
	/// - The revocation checker admits each certificate (RFC 5280 §6.1.3(a)(3)).
	///
	/// Each lookup runs both, so a lookup finds no certificate whose period
	/// ends or that the checker revokes after the build (CWE-324).
	fn admits(&self, fingerprint: &Sha3Fingerprint) -> bool {
		let path = self.paths.get(fingerprint);
		path.is_some_and(|path| {
			let in_validity = path.iter().try_for_each(|cert| self.clock.admits(cert));
			in_validity.is_ok() && self.check_revocation(path).is_ok()
		})
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
	/// Walk the issuer hierarchy as far as the held certificates allow, then
	/// validate the walked path.
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
	/// Of the candidates of one rank, the walk takes the first of:
	///
	/// 1. The certificate itself, since a self-signed certificate that omits
	///    its `authorityKeyIdentifier` names its own `subjectKeyIdentifier`
	///    (RFC 5280 §4.2.1.1).
	/// 2. The certificate of the lower fingerprint.
	///
	/// The walk commits to its candidate, and the signature check of the path
	/// decides.
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
	/// Walk the issuer hierarchy from the first certificate of `presented`, an
	/// anchor-first path lent in place, as far as the held certificates allow.
	/// Validate the walked issuers then `presented` as one path, and return the
	/// fingerprint of the held trust anchor the walk ended at.
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

		// The walk reads the authority identifier of `start` where it ranks a
		// candidate, and the builder decoded those of the held certificates.
		let mut walk = IssuerWalk::presented(&self.certificates, start, fingerprint, self.policy.as_ref())?;
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
	/// The store trusts a certificate it holds while it and each issuer above
	/// it are within their validity periods and its revocation checker admits
	/// them.
	fn is_trusted(&self, cert: &Certificate) -> bool {
		let fingerprint = Sha3Fingerprint::from_certificate(cert);
		fingerprint.is_ok_and(|fingerprint| self.admits(&fingerprint))
	}

	/// The anchor is the top of the issuer walk from the first certificate of
	/// the chain, as for [`Self::trust_anchor`], so a chain that starts below
	/// a held certificate names the anchor above it.
	fn verify_chain(&self, chain: &[Certificate]) -> Result<Arc<Certificate>, CertificateValidationError> {
		// RFC 5280 §6.1.1: the walk ends at a configured trust anchor, or the
		// chain fails.
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

	/// The store resolves a signer while the signer and each issuer above it
	/// are within their validity periods and its revocation checker admits
	/// them.
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

	/// The store finds a certificate while it and each issuer above it are
	/// within their validity periods and its revocation checker admits them.
	fn find_by_public_key(&self, spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate> {
		let fingerprint = self.key_index.find(spki)?;
		self.admitted(fingerprint)
	}

	/// The store finds `key` in its key index as it stands, with no decode,
	/// while the certificate and each issuer above it are within their
	/// validity periods and its revocation checker admits them.
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
	clock: ValidityClock,
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
	/// Returns a builder that verifies signatures under `policy`, reads each
	/// key under `curves`, and consults `revocation` during path validation
	/// and at each lookup. The decoder of a curve in `curves` reads its
	/// off-curve encodings as their bits at enrolment and at each lookup.
	///
	/// This is the one constructor, so every store states its revocation
	/// checker where it is built:
	///
	/// - [`NoRevocation`] is the waiver of a closed PKI with short-lived certificates.
	/// - [`StaticRevocationList`] is a denylist that the operator pushes.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::hash::Sha3_256;
	/// use tightbeam::crypto::policy::Secp256k1Policy;
	/// use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation};
	/// use tightbeam::crypto::x509::store::{StaticRevocationList, TrustBuilder};
	/// use tightbeam::crypto::x509::KeyCurves;
	/// use tightbeam::testing::fixtures::{TestCertificate, TestKey};
	///
	/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	///
	/// // A closed PKI states the waiver, and its store trusts the certificate.
	/// let waived = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
	/// let waived = waived.with_certificate(certificate.clone())?.build();
	/// assert!(waived.is_trusted(&certificate));
	///
	/// // A list that names the certificate revokes it in the store.
	/// let revoked = StaticRevocationList::<Sha3_256>::default().with_certificate(&certificate)?;
	/// let listed = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, revoked);
	/// let listed = listed.with_certificate(certificate.clone())?.build();
	/// assert!(!listed.is_trusted(&certificate));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn new(
		policy: impl VerificationPolicy + 'static,
		curves: KeyCurves,
		revocation: impl RevocationChecker + 'static,
	) -> Self {
		Self {
			fingerprints: HashSet::new(),
			certificates: HashMap::new(),
			purposes: KeyPurposes::default(),
			skid_index: HashMap::new(),
			key_index: KeyIndex::new(curves),
			policy: Arc::new(policy),
			revocation: Arc::new(revocation),
			clock: ValidityClock::default(),
		}
	}

	/// Set the key purposes the store admits its signers under, the
	/// [`KeyPurposes::signer`] purpose for a frame and colony signer.
	///
	/// The default is [`KeyPurposes::HOUSE`].
	pub fn with_key_purposes(mut self, purposes: KeyPurposes) -> Self {
		self.purposes = purposes;
		self
	}

	/// Set the clock that every validity check of the store reads, in place of
	/// the crate clock `UnixMillis::now`:
	///
	/// - The check of each certificate that this builder adds after this call.
	/// - The check of each path, at path validation and at each lookup.
	///
	/// A gateway on `ClusterConfig::clock` builds its stores on that clock, so
	/// one admission reads one time.
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	/// use std::sync::Arc;
	///
	/// use tightbeam::clock::{Clock, ManualClock, UnixMillis};
	/// use tightbeam::crypto::policy::Secp256k1Policy;
	/// use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
	/// use tightbeam::crypto::x509::KeyCurves;
	/// use tightbeam::testing::fixtures::{TestCertificate, TestKey};
	///
	/// // The test certificate is valid through Unix time 2,000,000,000.
	/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// let clock = Arc::new(ManualClock::default());
	///
	/// let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
	/// let builder = builder.with_clock(Arc::clone(&clock) as Arc<dyn Clock>);
	/// let store = builder.with_certificate(certificate.clone())?.build();
	/// assert!(store.is_trusted(&certificate));
	///
	/// // Once the clock of the store passes the end of the period, the store
	/// // refuses the certificate.
	/// let since_epoch = clock.unix().saturating_since(UnixMillis::new(0));
	/// clock.advance(Duration::from_secs(2_000_000_001).saturating_sub(since_epoch));
	/// assert!(!store.is_trusted(&certificate));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn with_clock(mut self, clock: Arc<dyn Clock + Send + Sync>) -> Self {
		self.clock = ValidityClock::new(clock);
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
		let identifiers = KeyIdentifiers::of(&cert, self.policy.as_ref())?;
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

		chain.iter().try_for_each(|cert| self.clock.admits(cert))?;

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
		self.clock.admits(&cert)?;
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
			clock: self.clock,
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
	use core::str::FromStr;
	use core::sync::atomic::{AtomicUsize, Ordering};
	use core::time::Duration;

	use crate::crypto::k256::sha2::{Sha256, Sha384};
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
	use crate::crypto::sign::{CmsSigner, SignedContent, SigningIdentity};
	use crate::crypto::x509::error::CertificateValidationError::{
		DuplicateExtension, PublicKeyCollision, UnprocessedCriticalExtension,
	};
	use crate::crypto::x509::fixtures::{Refusal, Verdict};
	use crate::der::asn1::{GeneralizedTime, ObjectIdentifier, OctetString};
	use crate::der::oid::db::rfc5280::{ID_CE_KEY_USAGE, ID_CE_POLICY_CONSTRAINTS, ID_CE_SUBJECT_KEY_IDENTIFIER};
	use crate::der::oid::AssociatedOid;
	use crate::der::Decode;
	use crate::oids::{CURVE_NIST_P256, SIGNER_ECDSA_WITH_SHA256};
	use crate::testing::fixtures::{TestCertificate, TestCertificateChain, TestClock, TestIdentity, TestStore};
	use crate::testing::{TestFrame, TestKey, TestResult};
	use crate::x509::ext::pkix::name::GeneralName;
	use crate::x509::ext::pkix::SubjectKeyIdentifier;
	use crate::x509::time::Time;

	use super::*;

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
	fn build_store(chain: &TestCertificateChain, certs: StoreCerts) -> CertificateTrustStore {
		let held = match certs {
			StoreCerts::None => vec![],
			StoreCerts::Root => vec![chain.root.to_owned()],
			StoreCerts::RootAndIntermediate => vec![chain.root.to_owned(), chain.intermediate.to_owned()],
		};

		TestStore::holding(held)
	}

	/// Returns the certificate in `chain` that `target` names.
	fn target_cert(chain: &TestCertificateChain, target: EvalTarget) -> &Certificate {
		match target {
			EvalTarget::Root => &chain.root,
			EvalTarget::Intermediate => &chain.intermediate,
			EvalTarget::Leaf => &chain.leaf,
		}
	}

	/// Returns the certificates in `chain` that `targets` name, in their
	/// order.
	fn path_of<'c>(chain: &'c TestCertificateChain, targets: &[EvalTarget]) -> Vec<&'c Certificate> {
		targets.iter().map(|target| target_cert(chain, *target)).collect()
	}

	/// Returns the chain that a peer presents of the certificates in `chain`
	/// that `targets` name.
	fn presented(chain: &TestCertificateChain, targets: &[EvalTarget]) -> Vec<Certificate> {
		path_of(chain, targets).into_iter().cloned().collect()
	}

	/// A SHA3-256 certificate fingerprint holds the 32 octets of its digest.
	#[test]
	fn a_sha3_fingerprint_holds_32_octets() -> TestResult {
		let fingerprint = Fingerprint::<Sha3_256>::from_certificate(&TestCertificate::insecure_fixed())?;
		assert_eq!(fingerprint.as_slice().len(), 32);
		Ok(())
	}

	/// A membership query of a store, by fingerprint or by key.
	type Query = fn(&CertificateTrustStore, &Certificate) -> bool;

	/// The membership query by fingerprint, which names one certificate.
	const BY_FINGERPRINT: Query = CertificateTrustStore::is_trusted;

	/// The membership query by key, which each certificate of a held key
	/// passes.
	const BY_KEY: Query = CertificateTrustStore::trusts_public_key;

	/// One membership case: the certificate that the store holds, the
	/// certificate that the query names, the query, and its answer.
	type MembershipCase = (fn() -> Certificate, fn() -> Certificate, Query, bool);

	/// The certificate `enrolled` of the fixed key, with the URI of a colony.
	fn enrolled() -> Certificate {
		let key = TestKey::insecure_fixed_signing();
		TestCertificate::with_cn_and_uri_sans(&key, "enrolled", &["urn:tightbeam:colony:test"])
	}

	/// The certificate `rotated` of the fixed key, which re-issues
	/// [`enrolled`] for the same key.
	fn rotated() -> Certificate {
		let key = TestKey::insecure_fixed_signing();
		TestCertificate::with_cn_and_uri_sans(&key, "rotated", &["urn:tightbeam:colony:test"])
	}

	/// The self-signed certificate of the key of [`STRANGER_SEED`], a key
	/// apart from each key that a store of these tests holds.
	fn stranger() -> Certificate {
		TestCertificate::self_signed(&TestKey::fixed(STRANGER_SEED))
	}

	// A store trusts a certificate it holds by its fingerprint, and each
	// certificate of a key it holds by that key.
	crate::tb_cases! {
		fn a_store_trusts_what_it_holds((held, subject, query, expected): MembershipCase) {
			let store = TestStore::holding([held()]);

			let member = query(&store, &subject());
			assert_eq!(member, expected);
		}
		cases {
			a_held_certificate_by_fingerprint => (
				TestCertificate::insecure_fixed,
				TestCertificate::insecure_fixed,
				BY_FINGERPRINT,
				true,
			),
			a_stranger_by_fingerprint => (TestCertificate::insecure_fixed, stranger, BY_FINGERPRINT, false),
			an_enrolled_certificate_by_fingerprint => (enrolled, enrolled, BY_FINGERPRINT, true),
			a_rotated_certificate_by_fingerprint => (enrolled, rotated, BY_FINGERPRINT, false),
			a_rotated_certificate_by_key => (enrolled, rotated, BY_KEY, true),
			a_stranger_by_key => (enrolled, stranger, BY_KEY, false),
		}
	}

	/// A builder takes a chain whose issuer names link each certificate to
	/// the one above it.
	#[test]
	fn a_builder_takes_a_well_formed_chain() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;

		TestStore::empty().with_chain([chain.root, chain.intermediate, chain.leaf])?;
		Ok(())
	}

	/// One walk case: the store, the certificate that the walk starts from,
	/// and the verdict on its path.
	type WalkCase = (StoreCerts, EvalTarget, Verdict);

	// The cases run `evaluate` over the issuer walk. An intermediate presented
	// as an end entity asserts the CA bit (`EndEntityIsCa`), and a leaf with no
	// held issuer reaches no anchor.
	crate::tb_cases! {
		fn the_walk_reaches_an_anchor((store_certs, eval_target, expected): WalkCase) -> TestResult {
			let chain = TestCertificate::insecure_fixed_chain()?;
			let store = build_store(&chain, store_certs);

			let verdict = store.evaluate(target_cert(&chain, eval_target));
			assert!(expected(&verdict));
			Ok(())
		}
		cases {
			a_trusted_root => (StoreCerts::Root, EvalTarget::Root, |verdict| matches!(verdict, Ok(()))),
			an_intermediate_presented_as_an_end_entity => (
				StoreCerts::Root,
				EvalTarget::Intermediate,
				|verdict| matches!(verdict, Err(CertificateValidationError::EndEntityIsCa)),
			),
			a_leaf_under_a_held_intermediate => (
				StoreCerts::RootAndIntermediate,
				EvalTarget::Leaf,
				|verdict| matches!(verdict, Ok(())),
			),
			a_leaf_with_no_held_issuer => (
				StoreCerts::Root,
				EvalTarget::Leaf,
				|verdict| matches!(verdict, Err(CertificateValidationError::CertificateNotTrusted)),
			),
			an_empty_store => (
				StoreCerts::None,
				EvalTarget::Leaf,
				|verdict| matches!(verdict, Err(CertificateValidationError::CertificateNotTrusted)),
			),
		}
	}

	/// The issuer walk refuses a leaf whose issuers the store lacks, though
	/// the store holds another certificate of the key of the leaf's root.
	#[test]
	fn evaluate_rejects_cross_chain_cert() -> TestResult {
		let store = TestStore::holding([TestCertificate::insecure_fixed()]);
		let other_chain = TestCertificate::insecure_fixed_chain()?;

		let refused = store.evaluate(&other_chain.leaf);
		assert!(matches!(refused, Err(CertificateValidationError::CertificateNotTrusted)));
		Ok(())
	}

	/// Returns the authority `Rollover CA` of the key of `seed`, beside that
	/// key.
	fn rollover_authority(seed: u8) -> (Secp256k1SigningKey, Certificate) {
		let key = TestKey::fixed(seed);
		let authority = TestCertificate::authority(&key, "Rollover CA");
		(key, authority.expect("a test authority signs its own certificate"))
	}

	/// Returns a leaf of the key of the seed 6 with `serial` as its serial
	/// number, which the authority `Rollover CA` of `issuer_key` issues.
	fn rollover_leaf(issuer_key: &Secp256k1SigningKey, serial: u8) -> Certificate {
		let usage = KeyUsage(KeyUsages::DigitalSignature.into());
		let leaf = TestCertificate::issued(issuer_key, "Rollover CA", &TestKey::fixed(6), "Leaf", serial, usage);
		leaf.expect("a test authority issues a leaf")
	}

	/// Of two authorities of one subject name, the walk takes the one whose
	/// key identifier the leaf names (RFC 5280 §4.2.1.1). With one leaf under
	/// each authority, the check holds in any order the store keeps them in.
	#[test]
	fn the_walk_takes_the_authority_whose_key_signed_the_leaf() -> TestResult {
		let (first_key, first) = rollover_authority(4);
		let (second_key, second) = rollover_authority(5);
		let first_leaf = rollover_leaf(&first_key, 2);
		let second_leaf = rollover_leaf(&second_key, 3);
		let store = TestStore::holding([first.clone(), second.clone()]);

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
		let store = build_store(&chain, StoreCerts::RootAndIntermediate);

		let anchor = store.trust_anchor(&chain.leaf)?;
		assert_eq!(anchor.as_ref(), &chain.root);
		Ok(())
	}

	/// One of the two authorities of the subject name `Rollover CA` that
	/// [`mixed_store`] holds, each of which issues the leaf of one walk.
	#[derive(Debug, Clone, Copy)]
	enum Issuer {
		/// The authority of the seed 4, with its key identifier.
		Named,
		/// The authority of the seed 5, with no key identifier.
		Unnamed,
	}

	impl Issuer {
		/// The seed of the key of the authority.
		fn seed(self) -> u8 {
			match self {
				Issuer::Named => 4,
				Issuer::Unnamed => 5,
			}
		}

		/// The certificate of the authority, as [`mixed_store`] holds it.
		fn authority(self) -> Certificate {
			let (_, authority) = rollover_authority(self.seed());
			match self {
				Issuer::Named => authority,
				Issuer::Unnamed => TestCertificate::without_extension(authority, SubjectKeyIdentifier::OID),
			}
		}
	}

	/// Returns a store that holds the authority of each [`Issuer`].
	fn mixed_store() -> CertificateTrustStore {
		TestStore::holding([Issuer::Named.authority(), Issuer::Unnamed.authority()])
	}

	// Of two authorities of one subject name, the walk ranks the one whose key
	// identifier the leaf names first, then one that states none, then one
	// whose key identifier differs (RFC 4158 §3.5.12).
	crate::tb_cases! {
		fn the_walk_between_a_named_and_an_unnamed_authority(issuer: Issuer) -> TestResult {
			let leaf = rollover_leaf(&TestKey::fixed(issuer.seed()), 2);
			let anchor = mixed_store().trust_anchor(&leaf)?;
			assert_eq!(anchor.as_ref(), &issuer.authority());
			Ok(())
		}
		cases {
			/// The walk takes the authority whose key identifier the leaf
			/// names over one that states none.
			takes_the_matching_named_authority => Issuer::Named,
			/// The walk takes an authority that states no key identifier over
			/// one whose key identifier differs from the one the leaf names,
			/// and the self-signed authority it takes ends the walk
			/// (RFC 5280 §4.2.1.1).
			takes_the_unnamed_over_one_that_differs => Issuer::Unnamed,
		}
	}

	/// Returns the two authorities of the name `Rollover CA` of the keys of
	/// the seeds 4 and 5, which state no key identifier, so the walk ranks
	/// them alike below every leaf. Each comes beside its key, the authority
	/// of the lower fingerprint first.
	fn tied_authorities() -> [(Certificate, Secp256k1SigningKey); 2] {
		let tied = |seed: u8| {
			let (key, authority) = rollover_authority(seed);
			(TestCertificate::without_extension(authority, SubjectKeyIdentifier::OID), key)
		};
		let fingerprint = |authority: &Certificate| {
			let fingerprint = Sha3Fingerprint::from_certificate(authority).expect("a test authority encodes");
			fingerprint.as_slice().to_vec()
		};

		let mut tied = [tied(4), tied(5)];
		tied.sort_by_cached_key(|(authority, _)| fingerprint(authority));
		tied
	}

	/// Of two authorities of one subject name and one rank, the walk takes the
	/// one of the lower fingerprint, whichever one the store took first, so
	/// one store gives one path in every process.
	#[test]
	fn the_walk_takes_the_lower_fingerprint_of_two_equal_rank_authorities() -> TestResult {
		let [(lower, lower_key), (higher, _)] = tied_authorities();
		let leaf = rollover_leaf(&lower_key, 2);
		let lower_first = TestStore::holding([lower.clone(), higher.clone()]);
		let higher_first = TestStore::holding([higher, lower.clone()]);

		let anchors = (lower_first.trust_anchor(&leaf)?, higher_first.trust_anchor(&leaf)?);
		assert_eq!((anchors.0.as_ref(), anchors.1.as_ref()), (&lower, &lower));
		Ok(())
	}

	/// A self-signed certificate that omits its `authorityKeyIdentifier` names
	/// its own `subjectKeyIdentifier`, so the walk takes the authority of its
	/// key over another of its name (RFC 5280 §4.2.1.1).
	#[test]
	fn a_self_signed_certificate_names_the_authority_of_its_own_key() -> TestResult {
		let (named_key, named) = rollover_authority(4);
		let (_, other) = rollover_authority(5);
		let store = TestStore::holding([named.clone(), other]);
		let usage = KeyUsage(KeyUsages::DigitalSignature.into());
		let reissued = TestCertificate::issued(&named_key, "Rollover CA", &named_key, "Rollover CA", 7, usage)?;

		let anchor = store.trust_anchor(&reissued)?;
		assert_eq!(anchor.as_ref(), &named);
		Ok(())
	}

	/// Returns a self-issued certificate of the name `Rollover CA` for the key
	/// of `subject_key`, which `issuer_key` signs, with no
	/// `authorityKeyIdentifier`.
	fn self_issued_without_authority(
		issuer_key: &Secp256k1SigningKey,
		subject_key: &Secp256k1SigningKey,
	) -> Certificate {
		let usage = KeyUsage(KeyUsages::KeyCertSign.into());
		let issued = TestCertificate::issued(issuer_key, "Rollover CA", subject_key, "Rollover CA", 7, usage);
		let issued = issued.expect("a test authority issues a certificate");
		let certificate = TestCertificate::without_extension(issued, AuthorityKeyIdentifier::OID);

		TestCertificate::signed_by(certificate, issuer_key)
	}

	/// A self-issued certificate that another key signs is no self-signed
	/// one, so an absent `authorityKeyIdentifier` names no authority
	/// (RFC 5280 §4.2.1.1).
	#[test]
	fn a_self_issued_certificate_that_another_key_signs_names_no_authority() -> TestResult {
		let certificate = self_issued_without_authority(&TestKey::fixed(5), &TestKey::fixed(4));
		let authority: Option<&[u8]> = KeyIdentifiers::authority_of(&certificate, &Secp256k1Policy::default())?;
		assert_eq!(authority, None);
		Ok(())
	}

	/// The self-signed fixture verifies under its own key, so its own
	/// `subjectKeyIdentifier` names its authority (RFC 5280 §4.2.1.1).
	#[test]
	fn the_self_signed_fixture_names_its_own_key_for_its_authority() -> TestResult {
		let certificate = TestCertificate::insecure_fixed();
		let own = certificate.extension::<SubjectKeyIdentifierRef<'_>>()?;
		let own = own.ok_or("the fixture carries its key identifier")?;

		let authority = KeyIdentifiers::authority_of(&certificate, &Secp256k1Policy::default())?;
		assert_eq!(authority, Some(own.0.as_bytes()));
		Ok(())
	}

	/// A [`VerificationPolicy`] that counts the signature checks it runs and
	/// lets [`Secp256k1Policy`] decide each one, because the count of checks a
	/// trust path spends is the cost these tests pin.
	#[derive(Debug, Default)]
	struct CountingPolicy {
		checks: Arc<AtomicUsize>,
	}

	impl VerificationPolicy for CountingPolicy {
		fn verify_signature(
			&self,
			algorithm_oid: &ObjectIdentifier,
			public_key_der: &[u8],
			message: &[u8],
			signature: &[u8],
		) -> Result<VerifiedSignature, CertificateValidationError> {
			self.checks.fetch_add(1, Ordering::SeqCst);
			Secp256k1Policy::default().verify_signature(algorithm_oid, public_key_der, message, signature)
		}

		fn digest(
			&self,
			signature_oid: &ObjectIdentifier,
			digest_oid: &ObjectIdentifier,
			content: &[u8],
		) -> Result<Vec<u8>, CertificateValidationError> {
			Secp256k1Policy::default().digest(signature_oid, digest_oid, content)
		}
	}

	/// The seed of the key of the authority `Held Root`, which
	/// [`checks_to_answer`] holds.
	const HELD_ROOT_SEED: u8 = 7;

	/// The seed of the key of each stranger, a key apart from each key that a
	/// store of these tests holds.
	const STRANGER_SEED: u8 = 9;

	/// Returns whether a store that holds the authority `Held Root` trusts the
	/// chain of `presented` alone, beside the count of the signature checks
	/// that its answer spends.
	fn checks_to_answer(presented: Certificate) -> (bool, usize) {
		let held = TestCertificate::authority(&TestKey::fixed(HELD_ROOT_SEED), "Held Root");
		let held = held.expect("the authority issues");
		let checks = Arc::new(AtomicUsize::new(0));
		let policy = CountingPolicy { checks: Arc::clone(&checks) };
		let builder = CertificateTrustBuilder::new(policy, KeyCurves::HOUSE, NoRevocation).with_certificate(held);
		let store = builder.expect("the authority enrols").build();
		checks.store(0, Ordering::SeqCst);

		let trusted = store.verify_chain(&[presented]).is_ok();
		(trusted, checks.load(Ordering::SeqCst))
	}

	/// A path that starts at a root the store holds reads the key identifiers
	/// that the store decoded at enrolment, so the walk spends no check on the
	/// signature of that root.
	#[test]
	fn a_held_root_presented_first_spends_no_check_on_its_own_signature() -> TestResult {
		let held = TestCertificate::authority(&TestKey::fixed(HELD_ROOT_SEED), "Held Root")?;
		assert_eq!(checks_to_answer(held), (true, 0));
		Ok(())
	}

	/// The authority of a certificate ranks the candidates under its issuer
	/// name, so a self-issued certificate under a name the store does not hold
	/// is refused with no check of its signature.
	#[test]
	fn a_self_issued_stranger_under_a_name_the_store_lacks_spends_no_check() -> TestResult {
		let stranger = TestCertificate::authority(&TestKey::fixed(STRANGER_SEED), "Stranger Root")?;
		assert_eq!(checks_to_answer(stranger), (false, 0));
		Ok(())
	}

	/// A self-issued certificate with no `subjectKeyIdentifier` names no
	/// authority whatever its signature, so the walk spends no check on that
	/// signature (RFC 5280 §4.2.1.1).
	#[test]
	fn a_self_issued_certificate_with_no_key_identifier_spends_no_check() -> TestResult {
		let stranger_key = TestKey::fixed(STRANGER_SEED);
		let named = TestCertificate::authority(&stranger_key, "Held Root")?;
		let unnamed = TestCertificate::without_extension(named, SubjectKeyIdentifier::OID);
		let unnamed = TestCertificate::signed_by(unnamed, &stranger_key);
		assert_eq!(checks_to_answer(unnamed), (false, 0));
		Ok(())
	}

	/// Returns the RFC 7093 §2 method 3 key identifier of the key of
	/// `certificate`: the leftmost 160 bits of the SHA-512 hash of its
	/// `subjectPublicKey` value. The fixtures derive theirs by method 1.
	fn method_three_identifier(certificate: &Certificate) -> SubjectKeyIdentifier {
		use crate::crypto::k256::sha2::Sha512;

		let spki = &certificate.tbs_certificate.subject_public_key_info;
		let digest = Sha512::digest(spki.subject_public_key.raw_bytes());
		let leftmost = digest.get(..20).expect("a SHA-512 hash holds 160 bits");
		SubjectKeyIdentifier::from(OctetString::new(leftmost).expect("160 bits fit an octet string"))
	}

	/// A key identifier sorts the candidates and the signature decides, so a
	/// leaf whose `authorityKeyIdentifier` one method derived validates under
	/// an authority whose `subjectKeyIdentifier` another method derived
	/// (RFC 4158 §3.5.12).
	#[test]
	fn the_walk_takes_an_authority_whose_key_identifier_another_method_derived() -> TestResult {
		let (authority_key, authority) = rollover_authority(4);
		let identifier = method_three_identifier(&authority);
		let authority = TestCertificate::with_key_identifier(authority, identifier);
		let store = TestStore::holding([authority.clone()]);
		let leaf = rollover_leaf(&authority_key, 2);

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
	/// chain, and the verdict on the chain.
	type ChainCase = (StoreCerts, &'static [EvalTarget], Verdict);

	// `verify_chain` validates the chain a peer presents to an anchor that
	// the store holds.
	crate::tb_cases! {
		fn verify_chain_validates_a_presented_chain((store_certs, targets, expected): ChainCase) -> TestResult {
			let chain = TestCertificate::insecure_fixed_chain()?;
			let store = build_store(&chain, store_certs);
			let presented_chain = presented(&chain, targets);

			let verdict = store.verify_chain(&presented_chain).map(drop);
			assert!(expected(&verdict));
			Ok(())
		}
		cases {
			an_empty_chain => (
				StoreCerts::Root,
				&[],
				|verdict| matches!(verdict, Err(CertificateValidationError::EmptyChain)),
			),
			an_untrusted_root => (
				StoreCerts::None,
				&[EvalTarget::Root],
				|verdict| matches!(verdict, Err(CertificateValidationError::CertificateNotTrusted)),
			),
			a_trusted_root_alone => (StoreCerts::Root, &[EvalTarget::Root], |verdict| matches!(verdict, Ok(()))),
			a_full_chain_under_a_trusted_root => (
				StoreCerts::Root,
				&[EvalTarget::Root, EvalTarget::Intermediate, EvalTarget::Leaf],
				|verdict| matches!(verdict, Ok(())),
			),
		}
	}

	/// One case of the RFC 5280 §6.1.4 path constraints: the CA bit, the
	/// `keyCertSign` bit, and the path length of the root, and the refusal
	/// that `verify_chain` returns for the otherwise-valid chain.
	type IssuerConstraintCase = (bool, bool, Option<u8>, Refusal);

	// Each case replaces the root's extensions, then expects `verify_chain` to
	// reject the otherwise-valid chain with the error that the case names.
	crate::tb_cases! {
		fn verify_chain_enforces_issuer_constraints((ca, key_cert_sign, path_len, refusal): IssuerConstraintCase)
			-> TestResult
		{
			let chain = TestCertificate::insecure_fixed_chain()?;
			let mut root = chain.root;
			root.tbs_certificate.extensions = Some(TestCertificate::ca_extensions(ca, key_cert_sign, path_len));

			let store = TestStore::holding([root.clone()]);
			let refused = store.verify_chain(&[root, chain.intermediate, chain.leaf]);
			assert!(matches!(refused, Err(ref error) if refusal(error)));
			Ok(())
		}
		cases {
			an_issuer_with_no_ca_bit => (
				false,
				true,
				None,
				|error| matches!(error, CertificateValidationError::IssuerNotCa),
			),
			an_issuer_with_no_key_cert_sign => (
				true,
				false,
				None,
				|error| matches!(error, CertificateValidationError::MissingKeyCertSign),
			),
			a_path_past_its_length => (
				true,
				true,
				Some(0),
				|error| matches!(error, CertificateValidationError::PathLenExceeded),
			),
		}
	}

	/// The issuer walk holds the leaf to the path length of the root it
	/// reaches (RFC 5280 §4.2.1.9).
	#[test]
	fn evaluate_enforces_path_len_constraint() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let mut root = chain.root;
		root.tbs_certificate.extensions = Some(TestCertificate::ca_extensions(true, true, Some(0)));

		let store = TestStore::holding([root, chain.intermediate]);
		let refused = store.evaluate(&chain.leaf);
		assert!(matches!(refused, Err(CertificateValidationError::PathLenExceeded)));
		Ok(())
	}

	/// One malformed leaf case: the change to the leaf, and the refusal that
	/// names it.
	type MalformedLeaf = (fn(Certificate) -> Certificate, Refusal);

	/// `leaf` with one critical `policyConstraints` extension in place of its
	/// extensions. The crate leaves `policyConstraints` unprocessed.
	fn with_only_critical_policy_constraints(mut leaf: Certificate) -> Certificate {
		leaf.tbs_certificate.extensions = Some(vec![TestCertificate::opaque_extension("2.5.29.36", true)]);
		leaf
	}

	/// `leaf` with two `keyUsage` extensions in place of its extensions.
	fn with_only_a_repeated_key_usage(mut leaf: Certificate) -> Certificate {
		let key_usage = TestCertificate::opaque_extension("2.5.29.15", true);
		leaf.tbs_certificate.extensions = Some(vec![key_usage.clone(), key_usage]);
		leaf
	}

	/// `leaf` with a critical `policyConstraints` extension after its own, so
	/// the walk still reads its `authorityKeyIdentifier`. The store refuses a
	/// `nameConstraints` extension before it reads criticality.
	fn with_critical_policy_constraints(leaf: Certificate) -> Certificate {
		let policy_constraints = TestCertificate::opaque_extension("2.5.29.36", true);
		TestCertificate::with_extension(leaf, policy_constraints)
	}

	/// `leaf` with an outer signature algorithm that differs from the one its
	/// `tbsCertificate` names (RFC 5280 §4.1.1.2).
	fn with_a_mismatched_algorithm(mut leaf: Certificate) -> Certificate {
		leaf.signature_algorithm.oid = SIGNER_ECDSA_WITH_SHA256;
		leaf
	}

	// `verify_chain` refuses a presented chain whose leaf repeats an extension
	// or bears a critical extension the crate leaves unprocessed (RFC 5280
	// §4.2), or names two signature algorithms (RFC 5280 §4.1.1.2).
	crate::tb_cases! {
		fn verify_chain_refuses_a_malformed_leaf((malformed, refusal): MalformedLeaf) -> TestResult {
			let chain = TestCertificate::insecure_fixed_chain()?;
			let store = build_store(&chain, StoreCerts::Root);
			let leaf = malformed(chain.leaf);

			let refused = store.verify_chain(&[chain.root, chain.intermediate, leaf]);
			assert!(matches!(refused, Err(ref error) if refusal(error)));
			Ok(())
		}
		cases {
			an_unknown_critical_extension => (
				with_only_critical_policy_constraints,
				|error| matches!(error, UnprocessedCriticalExtension(oid) if *oid == ID_CE_POLICY_CONSTRAINTS),
			),
			/// `verify_chain` refuses a chain whose leaf repeats its
			/// `keyUsage`.
			a_repeated_extension => (
				with_only_a_repeated_key_usage,
				|error| matches!(error, DuplicateExtension(oid) if *oid == ID_CE_KEY_USAGE),
			),
			a_mismatched_algorithm => (
				with_a_mismatched_algorithm,
				|error| matches!(error, CertificateValidationError::AlgorithmMismatch),
			),
		}
	}

	// The issuer walk refuses a malformed leaf as the chain path does.
	crate::tb_cases! {
		fn evaluate_refuses_a_malformed_leaf((malformed, refusal): MalformedLeaf) -> TestResult {
			let chain = TestCertificate::insecure_fixed_chain()?;
			let store = build_store(&chain, StoreCerts::RootAndIntermediate);
			let leaf = malformed(chain.leaf);

			let refused = store.evaluate(&leaf);
			assert!(matches!(refused, Err(ref error) if refusal(error)));
			Ok(())
		}
		cases {
			a_repeated_extension => (
				|leaf| TestCertificate::with_repeated_extension(leaf, "2.5.29.14"),
				|error| matches!(error, DuplicateExtension(oid) if *oid == ID_CE_SUBJECT_KEY_IDENTIFIER),
			),
			an_unknown_critical_extension => (
				with_critical_policy_constraints,
				|error| matches!(error, UnprocessedCriticalExtension(oid) if *oid == ID_CE_POLICY_CONSTRAINTS),
			),
			a_mismatched_algorithm => (
				with_a_mismatched_algorithm,
				|error| matches!(error, CertificateValidationError::AlgorithmMismatch),
			),
		}
	}

	/// Returns the intermediate of `chain` with a `nameConstraints` extension,
	/// critical when `critical` holds, which the root signs again, so its path
	/// passes every other check.
	fn constrained_intermediate(chain: &TestCertificateChain, critical: bool) -> Certificate {
		let constraints = TestCertificate::opaque_extension("2.5.29.30", critical);
		let intermediate = TestCertificate::with_extension(chain.intermediate.to_owned(), constraints);
		TestCertificate::signed_by(intermediate, &chain.root_key)
	}

	// Path validation refuses a presented intermediate that states name
	// constraints, because it applies none (RFC 5280 §6.1.4(g)).
	crate::tb_cases! {
		fn a_presented_intermediate_with_name_constraints_is_refused(critical: bool) -> TestResult {
			let chain = TestCertificate::insecure_fixed_chain()?;
			let intermediate = constrained_intermediate(&chain, critical);
			let store = build_store(&chain, StoreCerts::Root);

			let refused = store.verify_presented(&[intermediate], &chain.leaf);
			assert!(matches!(refused, Err(CertificateValidationError::NameConstraintsUnapplied)));
			Ok(())
		}
		cases {
			critical => true,
			/// RFC 5280 §6.1.4(g) applies name constraints whatever their
			/// criticality, so a non-critical extension is refused too.
			noncritical => false,
		}
	}

	/// A store that holds the root alone validates the path a peer presents
	/// through the intermediate, and names the root as its anchor
	/// (RFC 5280 §6.1).
	#[test]
	fn a_store_of_the_root_alone_anchors_a_presented_path() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let store = build_store(&chain, StoreCerts::Root);

		let anchor = store.verify_presented(&[chain.intermediate], &chain.leaf)?;
		assert_eq!(anchor.as_ref(), &chain.root);
		Ok(())
	}

	/// A store that holds the root alone admits a client whose certificate
	/// the intermediate it presents issued.
	#[test]
	fn a_store_of_the_root_alone_evaluates_a_presented_path() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let store = build_store(&chain, StoreCerts::Root);
		store.evaluate_presented(&[chain.intermediate], &chain.leaf)?;
		Ok(())
	}

	// The end-entity CA-bit check is defense in depth. The terminal of a
	// multi-certificate path is the identity it authenticates.
	crate::tb_cases! {
		fn a_path_ends_at_an_end_entity((targets, expected): (&'static [EvalTarget], Verdict)) -> TestResult {
			let chain = TestCertificate::insecure_fixed_chain()?;
			let path = path_of(&chain, targets);

			let verdict = ensure_terminal_is_end_entity(&path);
			assert!(expected(&verdict));
			Ok(())
		}
		cases {
			/// The intermediate carries `basicConstraints.cA = true` as the
			/// terminal of `[root, intermediate]`.
			a_ca_terminal_is_refused => (
				&[EvalTarget::Root, EvalTarget::Intermediate],
				|verdict| matches!(verdict, Err(CertificateValidationError::EndEntityIsCa)),
			),
			an_end_entity_terminal_passes => (
				&[EvalTarget::Root, EvalTarget::Intermediate, EvalTarget::Leaf],
				|verdict| matches!(verdict, Ok(())),
			),
			/// A pinned CA root that validates itself is the direct-trust
			/// model.
			a_lone_pinned_root_is_exempt => (&[EvalTarget::Root], |verdict| matches!(verdict, Ok(()))),
		}
	}

	/// A revocation list passes a certificate outside the list.
	#[test]
	fn static_revocation_list_passes_unlisted_certificate() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let revocation = StaticRevocationList::<Sha3_256>::default().with_certificate(&chain.intermediate)?;
		revocation.check(&chain.intermediate, &chain.leaf)?;
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

		let store = TestStore::revoking([chain.root.to_owned()], revocation);
		store.verify_chain(&[chain.root, chain.intermediate, chain.leaf])
	}

	// A revocation list under a digest revokes the leaf by its fingerprint
	// under that digest (RFC 5280 §6.1.3(a)(3)).
	crate::tb_cases! {
		fn verify_chain_rejects_a_leaf_revoked_by_its_fingerprint(
			verdict_of: fn() -> Result<Arc<Certificate>, CertificateValidationError>
		) {
			let verdict = verdict_of();
			assert!(matches!(verdict, Err(CertificateValidationError::CertificateRevoked)));
		}
		cases {
			/// A list under SHA3-256 revokes the leaf by its SHA3-256
			/// fingerprint.
			sha3_256 => verdict_with_the_leaf_revoked_under::<Sha3_256>,
			/// A list under SHA-384 revokes the leaf by its 48-octet
			/// fingerprint.
			sha384 => verdict_with_the_leaf_revoked_under::<Sha384>,
			/// A list under SHA-256 revokes the leaf by its SHA-256
			/// fingerprint, the digest an operator's list names.
			sha256 => verdict_with_the_leaf_revoked_under::<Sha256>,
		}
	}

	// A revocation list names a serial under one issuer, so the serial of the
	// leaf revokes the leaf under the issuer of the leaf alone.
	crate::tb_cases! {
		fn serial_revocation_is_scoped_to_its_issuer((issuer_of, expected): (fn(&Certificate) -> Name, Verdict))
			-> TestResult
		{
			let chain = TestCertificate::insecure_fixed_chain()?;
			let issuer = issuer_of(&chain.leaf);
			let serial = chain.leaf.tbs_certificate.serial_number.as_bytes().to_vec();
			let revocation = StaticRevocationList::<Sha3_256>::default().with_serial(&issuer, serial)?;
			let store = TestStore::revoking([chain.root.to_owned()], revocation);

			let verdict = store.verify_chain(&[chain.root, chain.intermediate, chain.leaf]).map(drop);
			assert!(expected(&verdict));
			Ok(())
		}
		cases {
			under_the_issuer_of_the_leaf => (
				|leaf| leaf.tbs_certificate.issuer.to_owned(),
				|verdict| matches!(verdict, Err(CertificateValidationError::CertificateRevoked)),
			),
			under_another_issuer => (
				|leaf| leaf.tbs_certificate.subject.to_owned(),
				|verdict| matches!(verdict, Ok(())),
			),
		}
	}

	/// The P-256 key of RFC 6979 §A.2.5 reads as a SEC 1 point under a curve
	/// set with no decoder of P-256, so a store that holds it uncompressed
	/// finds it by its compressed form.
	#[test]
	fn a_store_finds_the_rfc6979_p256_key_by_its_compressed_form() {
		let certificate = TestCertificate::insecure_fixed();
		let point = &TestKey::RFC6979_P256_UNCOMPRESSED;
		let uncompressed = TestCertificate::with_curve_point(certificate.clone(), CURVE_NIST_P256, point);
		let point = &TestKey::RFC6979_P256_COMPRESSED;
		let compressed = TestCertificate::with_curve_point(certificate, CURVE_NIST_P256, point);
		let store = TestStore::holding([uncompressed.clone()]);

		let found = store.find_by_public_key(&compressed.tbs_certificate.subject_public_key_info);
		assert_eq!(found, Some(&uncompressed));
	}

	/// The end of the validity period of an [`expiring`] certificate, in Unix
	/// seconds: after [`TestClock::START`], and before the end of the test
	/// validity window at 2,000,000,000.
	const END_OF_PERIOD: u64 = 1_999_999_000;

	/// `certificate` with a validity period that ends at [`END_OF_PERIOD`],
	/// signed again by `issuer_key`.
	fn expiring(mut certificate: Certificate, issuer_key: &Secp256k1SigningKey) -> Certificate {
		let not_after = GeneralizedTime::from_unix_duration(Duration::from_secs(END_OF_PERIOD));
		let not_after = not_after.expect("the end of the period is a time");

		certificate.tbs_certificate.validity.not_after = Time::GeneralTime(not_after);
		TestCertificate::signed_by(certificate, issuer_key)
	}

	/// A store on a manual clock that holds `certificates`, as it stands once
	/// the clock passes [`END_OF_PERIOD`].
	///
	/// The store admits each certificate inside its period, so the clock
	/// moves past the period after the build.
	fn store_past_expiry(certificates: impl IntoIterator<Item = Certificate>) -> CertificateTrustStore {
		let clock = TestClock::manual();
		let builder = TestStore::empty().with_clock(TestClock::erased(&clock));
		let builder = certificates.into_iter().try_fold(builder, TrustBuilder::with_certificate);
		let store = builder.expect("the store admits each certificate inside its period").build();

		let past = TestClock::past(END_OF_PERIOD).unix();
		clock.advance(past.saturating_since(clock.unix()));
		store
	}

	/// The store of a lapsed certificate, beside the identity that presents
	/// that certificate.
	type Lapsed = fn() -> (CertificateTrustStore, SigningIdentity);

	/// Returns the fixed identity beside a store that holds its certificate
	/// under a revocation list of that certificate.
	fn revoked() -> (CertificateTrustStore, SigningIdentity) {
		let identity = TestIdentity::insecure_fixed();
		let revocation = StaticRevocationList::<Sha3_256>::default().with_certificate(identity.certificate());
		let revocation = revocation.expect("a test certificate has a fingerprint");
		let store = TestStore::revoking([identity.certificate().clone()], revocation);

		(store, identity)
	}

	/// Returns an identity of the fixed key under an [`expiring`] certificate,
	/// beside a store that holds that certificate past [`END_OF_PERIOD`].
	fn expired() -> (CertificateTrustStore, SigningIdentity) {
		let key = TestKey::insecure_fixed_signing();
		let certificate = expiring(TestCertificate::insecure_fixed(), &key);
		let store = store_past_expiry([certificate.clone()]);

		(store, TestIdentity::presenting(certificate, &key))
	}

	// A store resolves no signer whose certificate its revocation list names
	// or whose validity period ended on its own clock, so a lapsed
	// certificate verifies no frame.
	crate::tb_cases! {
		fn a_lapsed_signer_verifies_no_frame(lapsed: Lapsed) {
			let (store, identity) = lapsed();
			let frame = TestFrame::signed_by(TestFrame::with_integrity(), &identity);

			let verification = store.verify_frame(&frame);
			assert!(matches!(verification, TrustVerification::UnknownSigner));
		}
		cases {
			/// A store whose revocation list names a frame signer resolves no
			/// signer for its frame.
			revoked => revoked,
			/// A store resolves no signer whose certificate is past its
			/// validity period (RFC 5280 §6.1.3(a)(2), CWE-324).
			expired => expired,
		}
	}

	// A store holds no certificate that its revocation list names or whose
	// validity period ended on its own clock, by fingerprint or by key, so a
	// lapsed certificate counts as enrolled for no plane.
	crate::tb_cases! {
		fn a_lapsed_certificate_is_no_member((lapsed, query): (Lapsed, Query)) {
			let (store, identity) = lapsed();
			let member = query(&store, identity.certificate());
			assert!(!member);
		}
		cases {
			revoked_by_key => (revoked, BY_KEY),
			revoked_by_fingerprint => (revoked, BY_FINGERPRINT),
			/// A store reads the validity period of a certificate on the clock
			/// it was built on, so a certificate whose period ends on that
			/// clock is refused while the host clock reads a time inside the
			/// period.
			expired_by_fingerprint => (expired, BY_FINGERPRINT),
			expired_by_key => (expired, BY_KEY),
		}
	}

	/// One lookup case: the store of the fixed chain, the certificate that
	/// the lookup names, and its answer.
	type LookupCase = (fn(&TestCertificateChain) -> CertificateTrustStore, EvalTarget, bool);

	/// Returns a store that holds `chain` under a revocation list of its
	/// intermediate.
	fn revoking_the_intermediate(chain: &TestCertificateChain) -> CertificateTrustStore {
		let revocation = StaticRevocationList::<Sha3_256>::default().with_certificate(&chain.intermediate);
		let revocation = revocation.expect("a test certificate has a fingerprint");
		let held = [chain.root.to_owned(), chain.intermediate.to_owned(), chain.leaf.to_owned()];

		TestStore::revoking(held, revocation)
	}

	/// Returns a store that holds `chain` with an [`expiring`] intermediate,
	/// past [`END_OF_PERIOD`].
	fn expiring_the_intermediate(chain: &TestCertificateChain) -> CertificateTrustStore {
		let intermediate = expiring(chain.intermediate.to_owned(), &chain.root_key);
		store_past_expiry([chain.root.to_owned(), intermediate, chain.leaf.to_owned()])
	}

	// A lookup runs revocation and validity over the path of the certificate
	// it finds alone, so a lapsed intermediate ends the membership of the leaf
	// under it and leaves the root above it a member.
	crate::tb_cases! {
		fn a_lookup_judges_the_path_of_the_certificate_it_finds((store_of, subject, expected): LookupCase)
			-> TestResult
		{
			let chain = TestCertificate::insecure_fixed_chain()?;
			let store = store_of(&chain);

			let member = store.trusts_public_key(target_cert(&chain, subject));
			assert_eq!(member, expected);
			Ok(())
		}
		cases {
			under_a_revoked_issuer => (revoking_the_intermediate, EvalTarget::Leaf, false),
			above_a_revoked_issuer => (revoking_the_intermediate, EvalTarget::Root, true),
			under_an_expired_issuer => (expiring_the_intermediate, EvalTarget::Leaf, false),
		}
	}

	/// A store refuses a chain whose anchor its revocation list names
	/// (RFC 5280 §6.1.3(a)(3)).
	#[test]
	fn verify_chain_rejects_revoked_anchor() -> TestResult {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let revocation = StaticRevocationList::<Sha3_256>::default().with_certificate(&chain.root)?;

		let store = TestStore::revoking([chain.root.to_owned()], revocation);
		let result = store.verify_chain(&[chain.root]);
		assert!(matches!(result, Err(CertificateValidationError::CertificateRevoked)));
		Ok(())
	}

	/// A `SignerInfo` that names a certificate by its `subjectKeyIdentifier`
	/// extension value resolves to that certificate (RFC 5652 §5.3).
	#[test]
	fn a_key_identifier_sid_resolves_through_the_extension() -> TestResult {
		let cert = TestCertificate::insecure_fixed();
		let store = TestStore::holding([cert.to_owned()]);

		let signer = TestIdentity::certified(TestKey::insecure_fixed_signing());
		let signer_info = CmsSigner::sign_with::<Secp256k1Signature, _>(&signer, SignedContent::data(b"test"))?;

		let found = store.find_by_signer_info(&signer_info);
		assert_eq!(found.map(|signer| signer.certificate().as_ref()), Some(&cert));
		Ok(())
	}

	/// An issuer-and-serial `sid` resolves to the certificate of that issuer
	/// and serial number.
	#[test]
	fn an_issuer_and_serial_sid_resolves_through_the_certificate() -> TestResult {
		let cert = TestCertificate::without_extension(TestCertificate::insecure_fixed(), SubjectKeyIdentifier::OID);
		let store = TestStore::holding([cert.to_owned()]);

		let sid = cert.signer_identifier()?;
		let found = store.find_by_signer_identifier(&sid);
		assert_eq!(found.map(|signer| signer.certificate().as_ref()), Some(&cert));
		Ok(())
	}

	/// The authority `Authority` of the fixed key, whose `keyUsage` asserts
	/// `keyCertSign` alone.
	fn certifying_authority() -> Certificate {
		let authority = TestCertificate::authority(&TestKey::insecure_fixed_signing(), "Authority");
		authority.expect("a test authority signs its own certificate")
	}

	/// The fixed certificate with the server's purpose alone in its
	/// `extendedKeyUsage`.
	fn server_certificate() -> Certificate {
		TestCertificate::with_key_purposes(TestCertificate::insecure_fixed(), [KeyPurposes::HOUSE.server])
	}

	// A store holds a certificate that the signing use refuses as a path
	// certificate alone, so its `sid` resolves no signer.
	crate::tb_cases! {
		fn a_non_signing_certificate_resolves_no_signer(certificate: fn() -> Certificate) -> TestResult {
			let certificate = certificate();
			let store = TestStore::holding([certificate.to_owned()]);

			let sid = certificate.signer_identifier()?;
			let found = store.find_by_signer_identifier(&sid);
			assert!(found.is_none());
			Ok(())
		}
		cases {
			/// An authority whose `keyUsage` asserts `keyCertSign` alone
			/// stays a path certificate of the store.
			one_that_only_certifies => certifying_authority,
			/// A certificate whose `extendedKeyUsage` names the server's
			/// purpose alone is no frame signer (RFC 5280 §4.2.1.12).
			one_of_the_server_purpose => server_certificate,
		}
	}

	/// A store configured with an implementor's own signer purpose resolves
	/// a certificate that names it.
	#[test]
	fn a_certificate_of_a_configured_signer_purpose_resolves_its_signer() -> TestResult {
		let own = TestIdentity::OWN_SIGNER;
		let certificate = TestCertificate::with_key_purposes(TestCertificate::insecure_fixed(), [own]);
		let builder = TestStore::empty();
		let builder = builder.with_key_purposes(KeyPurposes { signer: own, ..KeyPurposes::HOUSE });
		let store = builder.with_certificate(certificate.to_owned())?.build();

		let sid = certificate.signer_identifier()?;
		let found = store.find_by_signer_identifier(&sid);
		assert_eq!(found.map(|signer| signer.certificate().as_ref()), Some(&certificate));
		Ok(())
	}

	/// A key identifier the store holds no certificate for resolves to none.
	#[test]
	fn an_unknown_key_identifier_resolves_to_no_certificate() -> TestResult {
		let store = TestStore::holding([TestCertificate::insecure_fixed()]);
		let signer = TestIdentity::certified(TestKey::fixed(99));
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
		let written = SubjectKeyIdentifier::from(OctetString::new([0x42u8; 20])?);
		let cert = TestCertificate::with_key_identifier(TestCertificate::insecure_fixed(), written.clone());
		let store = TestStore::holding([cert.to_owned()]);

		let sid = SignerIdentifier::SubjectKeyIdentifier(written);
		let found = store.find_by_signer_identifier(&sid);
		assert_eq!(found.map(|signer| signer.certificate().as_ref()), Some(&cert));
		Ok(())
	}

	/// A trust store verifies a frame under the certificate its `sid` names,
	/// and returns the verified signature.
	#[test]
	fn a_trust_store_verifies_a_frame_of_a_certificate_it_holds() {
		let identity = TestIdentity::insecure_fixed();
		let store = TestStore::holding([identity.certificate().clone()]);
		let frame = TestFrame::signed_by(TestFrame::with_integrity(), &identity);

		let verification = store.verify_frame(&frame);
		assert!(matches!(verification, TrustVerification::Verified(_, _)));
	}

	/// A trust store refuses a frame whose signer it holds only as a
	/// certificate the signing use refuses, so the key of an authority signs
	/// no frame the store accepts.
	#[test]
	fn a_trust_store_resolves_no_signer_for_a_certifying_key() {
		let store = TestStore::holding([certifying_authority()]);
		let frame = TestFrame::signed_by(TestFrame::with_integrity(), &TestIdentity::insecure_fixed());

		let verification = store.verify_frame(&frame);
		assert!(matches!(verification, TrustVerification::UnknownSigner));
	}

	/// Returns the builder of a house store that holds `first`, the
	/// certificate that a second certificate collides with.
	fn builder_holding(first: Certificate) -> CertificateTrustBuilder {
		let builder = TestStore::empty().with_certificate(first);
		builder.expect("the empty store admits the first certificate")
	}

	/// Two certificates of two keys under one `subjectKeyIdentifier` value
	/// collide in the extension index, because a `sid` would name both. The
	/// refusal names that value in hex, so the operator finds the entry.
	#[test]
	fn two_certificates_under_one_key_identifier_collide() -> TestResult {
		let first = TestCertificate::insecure_fixed();
		let identifier = first.extension::<SubjectKeyIdentifier>()?;
		let identifier = identifier.ok_or("the fixture carries a key identifier")?;
		let second = TestCertificate::with_key_identifier(TestCertificate::self_signed(&TestKey::fixed(3)), identifier);
		let builder = builder_holding(first);

		let refused = builder.with_certificate(second);
		let named = "c0c5e0d927e4ccbb5bbf03d50dae76a79114a296";
		assert!(matches!(refused, Err(CertificateValidationError::SkidCollision { skid }) if skid == named));
		Ok(())
	}

	/// Two certificates of one key, the second with no key identifier,
	/// collide in the key index, because a key lookup would name both.
	#[test]
	fn two_certificates_of_one_key_collide() {
		let second = TestCertificate::without_extensions(TestCertificate::insecure_fixed());

		let builder = builder_holding(TestCertificate::insecure_fixed());
		let refused = builder.with_certificate(second);
		assert!(matches!(refused, Err(CertificateValidationError::PublicKeyCollision { .. })));
	}

	/// A key collision names the certificate that holds the key by its serial
	/// number and its issuer (RFC 5280 §4.1.2.2).
	#[test]
	fn a_key_collision_names_the_holder_by_serial_and_issuer() -> TestResult {
		let mut first = TestCertificate::insecure_fixed();
		first.tbs_certificate.issuer = Name::from_str("CN=held")?;

		let mut second = TestCertificate::without_extensions(TestCertificate::insecure_fixed());
		second.tbs_certificate.serial_number = SerialNumber::new(&[0x2a])?;
		second.tbs_certificate.issuer = Name::from_str("CN=refused")?;

		let builder = builder_holding(first);
		let refused = builder.with_certificate(second);

		let expected = "serial number 01 of issuer CN=held";
		let names_holder = matches!(refused, Err(PublicKeyCollision { holder, .. }) if holder == expected);
		assert!(names_holder);
		Ok(())
	}

	/// One secp256k1 point in its compressed and its uncompressed form is one
	/// key, so two certificates of the two forms collide in the key index.
	#[test]
	fn two_certificates_of_one_point_in_two_forms_collide() {
		let compressed = TestCertificate::with_compressed_key(TestCertificate::insecure_fixed());
		let second = TestCertificate::without_extensions(compressed);

		let builder = builder_holding(TestCertificate::insecure_fixed());
		let refused = builder.with_certificate(second);
		assert!(matches!(refused, Err(CertificateValidationError::PublicKeyCollision { .. })));
	}

	// A store holds its key in each encoding of the point, and the negation of
	// the point is another key.
	crate::tb_cases! {
		fn membership_follows_the_point_of_the_held_key((certificate, expected): (fn() -> Certificate, bool)) {
			let (store, _) = self_signed_store();
			let member = store.trusts_public_key(&certificate());
			assert_eq!(member, expected);
		}
		cases {
			/// A store that holds a secp256k1 key in the uncompressed form
			/// holds it in the compressed form too, so a re-issued certificate
			/// of the other form stays a member.
			the_compressed_form => (|| TestCertificate::with_compressed_key(TestCertificate::insecure_fixed()), true),
			/// A point and its negation are two keys, so a store that holds
			/// one holds no certificate of the other.
			the_negation => (TestCertificate::insecure_fixed_negation, false),
		}
	}

	/// An encoding of the x-coordinate and the y parity of the held key that
	/// is no point of its curve names another key, so the store finds no
	/// certificate by it (SEC 1 v2.0 §2.3.4).
	#[test]
	fn a_store_finds_no_certificate_by_an_off_curve_alias_of_its_key() {
		let (store, _) = self_signed_store();
		let alias = TestCertificate::with_off_curve_key(TestCertificate::insecure_fixed());

		let found = store.find_by_public_key(&alias.tbs_certificate.subject_public_key_info);
		assert!(found.is_none());
	}

	/// Returns a store that holds a self-signed test authority of the fixed
	/// key, whose one key identifier extension is its `subjectKeyIdentifier`,
	/// beside the certificate's fingerprint.
	fn self_signed_store() -> (CertificateTrustStore, Sha3Fingerprint) {
		let certificate = TestCertificate::authority(&TestKey::insecure_fixed_signing(), "Self-Signed CA");
		let certificate = certificate.expect("a test authority signs its own certificate");
		let fingerprint = Fingerprint::<Sha3_256>::from_certificate(&certificate);
		let fingerprint = fingerprint.expect("a test certificate has a fingerprint");
		(TestStore::holding([certificate]), fingerprint)
	}

	/// The store holds each `subjectKeyIdentifier` value once, in one
	/// allocation that its `sid` index and the certificate's key identifiers
	/// share.
	#[test]
	fn the_sid_index_shares_the_key_identifier_of_its_certificate() -> TestResult {
		let (store, fingerprint) = self_signed_store();
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
		let (store, fingerprint) = self_signed_store();
		let held = store.certificates.get(&fingerprint).ok_or("a held certificate")?;

		let subject = held.identifiers.subject.as_ref().ok_or("a key identifier")?;
		let authority = held.identifiers.authority.as_ref().ok_or("an authority identifier")?;
		assert!(Arc::ptr_eq(subject, authority));
		Ok(())
	}
}
