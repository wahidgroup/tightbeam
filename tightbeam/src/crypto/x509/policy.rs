//! Certificate validation policies and strategies.
//!
//! [`CertificateValidation`] checks one X.509 certificate, and
//! [`SignatureVerification`] adds a check of its signature under an issuer
//! key. The built-in validators check expiry, pin keys or fingerprints, deny
//! fingerprints, anchor direct trust, and chain other validators.

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::clock::Clock;
use crate::crypto::hash::{Digest, OutputSizeUser, Sha3_256};
use crate::crypto::policy::VerificationPolicy;
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::utils::{CertificateExt, Fingerprint, ValidityClock};
use crate::crypto::x509::Certificate;
use crate::crypto::x509::{KeyCurves, KeyList, KeyListError};
use crate::der::Encode;

/// A certificate validation strategy.
///
/// An implementor checks one certificate against its own policy and trust
/// model.
///
/// For a check that needs no signature, such as pinning, a denylist, or
/// expiry, implement only this trait. For PKI validation with signature
/// verification, also implement [`SignatureVerification`].
pub trait CertificateValidation: Send + Sync {
	/// Validate `cert` against this policy.
	///
	/// An implementor runs every check that needs no signature verification,
	/// such as expiry, pinning, and denylists.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError`] -- `cert` fails a check of this policy.
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError>;

	/// Validate `leaf`, the certificate a peer presents, beside the `issuers`
	/// it presents above it. They run from the top down, so each issues the
	/// next and the last issues `leaf`.
	///
	/// A mutual server admits its client here, with the issuers its client
	/// Finished presents (RFC 5652 §5.1):
	///
	/// - The default runs [`Self::evaluate`] on `leaf` alone.
	/// - [`CertificateTrustStore`] overrides it, and validates the path of
	///   `leaf` under `issuers` to one of its trust anchors (RFC 5280 §6.1).
	/// - `ChainValidator` overrides it, and runs it on each validator it holds.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError`] -- `leaf` or its path fails a check of this policy.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::policy::Secp256k1Policy;
	/// use tightbeam::crypto::x509::policy::CertificateValidation;
	/// use tightbeam::crypto::x509::store::{CertificateTrustBuilder, NoRevocation, TrustBuilder};
	/// use tightbeam::crypto::x509::KeyCurves;
	/// use tightbeam::testing::fixtures::{TestCertificate, TestCertificateChain};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // The keys of the fixture chain are public, so it serves an example
	/// // alone.
	/// let TestCertificateChain { root, intermediate, leaf, .. } = TestCertificate::insecure_fixed_chain()?;
	///
	/// // The store holds the root alone, and the peer presents the
	/// // intermediate beside its certificate.
	/// let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
	/// let store = builder.with_certificate(root)?.build();
	/// store.evaluate_presented(&[intermediate], &leaf)?;
	/// # Ok(())
	/// # }
	/// ```
	///
	/// [`CertificateTrustStore`]: crate::crypto::x509::store::CertificateTrustStore
	fn evaluate_presented(
		&self,
		issuers: &[Certificate],
		leaf: &Certificate,
	) -> Result<(), CertificateValidationError> {
		// The default reads the leaf alone, as `evaluate` does, so the issuers
		// drop here.
		let _ = issuers;
		self.evaluate(leaf)
	}
}

/// A certificate validation strategy that also verifies the signature of the
/// certificate, under a verification policy the caller supplies.
pub trait SignatureVerification: CertificateValidation {
	/// Validate `cert` in full, with a check of its signature under the
	/// issuer's public key through `policy`.
	///
	/// - `curr_time`: the current UNIX time, in seconds since the epoch.
	/// - `issuer_pub_key`: the DER-encoded public key of the issuer.
	/// - `policy`: the verification policy that checks the signature.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError`] -- `cert` fails a check, or its signature does not verify.
	fn verify_with_policy(
		&self,
		cert: &Certificate,
		curr_time: u64,
		issuer_pub_key: &[u8],
		policy: &dyn VerificationPolicy,
	) -> Result<(), CertificateValidationError>;
}

// The pinning and denylist validators below implement direct-trust models
// (trust-on-first-use and key pinning, as in RFC 7469). The certification-path
// validation of RFC 5280 §6.1 belongs to `CertificateTrustStore`.

/// A validator that checks certificate expiry alone, at the reading of its
/// clock.
///
/// - [`Default`] reads the crate clock, the system clock where the host has one.
/// - [`Self::with_clock`] sets the clock it reads.
///
/// A signature check belongs to a [`SignatureVerification`] validator.
#[derive(Debug, Clone, Default)]
pub struct ExpiryValidator {
	/// The clock that the check reads.
	clock: ValidityClock,
}

impl ExpiryValidator {
	/// Set the clock that the check reads, in place of the crate clock.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::x509::error::CertificateValidationError;
	/// use tightbeam::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	/// use tightbeam::testing::{TestCertificate, TestKey};
	///
	/// // The system clock reads a time inside the period of the test
	/// // certificate, and the clock of the validator a time past its end.
	/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// ExpiryValidator::default().evaluate(&certificate)?;
	///
	/// let validator = ExpiryValidator::default().with_clock(TestCertificate::clock_past_validity());
	/// let refused = validator.evaluate(&certificate);
	/// assert!(matches!(refused, Err(CertificateValidationError::Expired)));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[must_use]
	pub fn with_clock(mut self, clock: Arc<dyn Clock + Send + Sync>) -> Self {
		self.clock = ValidityClock::new(clock);
		self
	}
}

impl CertificateValidation for ExpiryValidator {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		// The check covers the validity period of RFC 5280 §6.1.3(a)(2) alone.
		self.clock.admits(cert)
	}
}

/// A validator that admits a certificate whose key one of its pins names.
///
/// - A pin is the DER of a SubjectPublicKeyInfo, which names a key with its
///   algorithm and curve (RFC 5280 §4.1.2.7).
/// - The validator reads each pin once, and the key of each certificate it checks, under one [`KeyCurves`].
/// - It admits two keys that are one key by the rule of [`CanonicalKey`], so a
///   pin admits a key of its own curve alone.
///
/// [`CanonicalKey`]: crate::crypto::x509::CanonicalKey
#[derive(Debug, Clone)]
pub struct PublicKeyPinning {
	keys: KeyList,
}

impl PublicKeyPinning {
	/// A validator that admits a key one of `keys` pins, each pin the DER of a
	/// SubjectPublicKeyInfo, read under [`KeyCurves::HOUSE`].
	///
	/// # Errors
	///
	/// - The errors of [`Self::with_curves`], under [`KeyCurves::HOUSE`].
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::x509::policy::{CertificateValidation, PublicKeyPinning};
	/// use tightbeam::der::Encode;
	/// use tightbeam::testing::fixtures::{TestCertificate, TestKey};
	///
	/// // The pin is the SubjectPublicKeyInfo of the certificate it admits.
	/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// let pin = certificate.tbs_certificate.subject_public_key_info.to_der()?;
	/// let pinning = PublicKeyPinning::new([pin])?;
	///
	/// pinning.evaluate(&certificate)?;
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn new<I, K>(keys: I) -> Result<Self, KeyListError>
	where
		I: IntoIterator<Item = K>,
		K: AsRef<[u8]>,
	{
		Self::with_curves(KeyCurves::HOUSE, keys)
	}

	/// A validator that admits a key one of `keys` pins, each pin the DER of a
	/// SubjectPublicKeyInfo, read under `curves`, so the decoder of a curve
	/// refuses its off-curve encodings.
	///
	/// # Errors
	///
	/// - [`KeyListError::Unreadable`] -- a pin is no SubjectPublicKeyInfo DER,
	///   or its canonical form exceeds the DER length cap.
	/// - [`KeyListError::NoPoint`] -- a pin names an elliptic-curve key that reads as no point.
	/// - [`KeyListError::NoDecoder`] -- a pin names a point on a curve that `curves` holds no decoder for.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::x509::policy::{CertificateValidation, PublicKeyPinning};
	/// use tightbeam::crypto::x509::KeyCurves;
	/// use tightbeam::der::Encode;
	/// use tightbeam::oids::CURVE_NIST_P256;
	/// use tightbeam::testing::fixtures::{TestCertificate, TestKey, TestP256Points};
	///
	/// // A set that reads the points of P-256.
	/// const P256: KeyCurves = KeyCurves::new(&[&TestP256Points]);
	///
	/// // A pin of the compressed point of RFC 6979 §A.2.5 admits the key in
	/// // its uncompressed form.
	/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// let compressed = &TestKey::RFC6979_P256_COMPRESSED;
	/// let pinned = TestCertificate::with_curve_point(certificate.clone(), CURVE_NIST_P256, compressed);
	/// let pin = pinned.tbs_certificate.subject_public_key_info.to_der()?;
	/// let pinning = PublicKeyPinning::with_curves(P256, [pin])?;
	///
	/// let uncompressed = &TestKey::RFC6979_P256_UNCOMPRESSED;
	/// let presented = TestCertificate::with_curve_point(certificate, CURVE_NIST_P256, uncompressed);
	/// pinning.evaluate(&presented)?;
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn with_curves<I, K>(curves: KeyCurves, keys: I) -> Result<Self, KeyListError>
	where
		I: IntoIterator<Item = K>,
		K: AsRef<[u8]>,
	{
		let keys = KeyList::read(curves, keys)?;
		Ok(Self { keys })
	}
}

impl CertificateValidation for PublicKeyPinning {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		let pinned = self.keys.holds(&cert.tbs_certificate.subject_public_key_info);
		pinned.then_some(()).ok_or(CertificateValidationError::PublicKeyNotPinned)
	}
}

/// A validator that pins certificate fingerprints in a const-generic array.
///
/// `D` is the digest algorithm, and `N` is the number of pinned fingerprints.
/// Each pin is a [`Fingerprint`] under `D`, so a pin of another width fails
/// where it is read, through [`Fingerprint::try_from`].
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::hash::Sha3_256;
/// use tightbeam::crypto::x509::policy::{CertificateValidation, FingerprintPinning};
/// use tightbeam::crypto::x509::utils::Fingerprint;
/// use tightbeam::testing::{TestCertificate, TestKey};
///
/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
/// let pin = Fingerprint::<Sha3_256>::from_certificate(&certificate)?;
///
/// let pinning = FingerprintPinning::new([pin]);
/// pinning.evaluate(&certificate)?;
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct FingerprintPinning<D: OutputSizeUser, const N: usize> {
	allowed_fingerprints: [Fingerprint<D>; N],
}

impl<D: OutputSizeUser, const N: usize> FingerprintPinning<D, N> {
	/// Create a validator that admits a certificate whose fingerprint
	/// `fingerprints` pins.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::hash::Sha3_512;
	/// use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
	/// use tightbeam::crypto::x509::policy::{CertificateValidation, FingerprintPinning};
	/// use tightbeam::crypto::x509::utils::Fingerprint;
	/// use tightbeam::random::OsRng;
	/// use tightbeam::testing::{TestCertificate, TestKey};
	///
	/// let pinned = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// let other = TestCertificate::self_signed(&Secp256k1SigningKey::random(&mut OsRng));
	/// let pin = Fingerprint::<Sha3_512>::from_certificate(&pinned)?;
	///
	/// let pinning = FingerprintPinning::new([pin]);
	/// assert!(pinning.evaluate(&other).is_err());
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn new(fingerprints: [Fingerprint<D>; N]) -> Self {
		Self { allowed_fingerprints: fingerprints }
	}
}

impl<D, const N: usize> CertificateValidation for FingerprintPinning<D, N>
where
	D: Digest,
{
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		let fingerprint = Fingerprint::<D>::from_certificate(cert)?;
		let pinned = self.allowed_fingerprints.contains(&fingerprint);
		pinned.then_some(()).ok_or(CertificateValidationError::CertificateNotPinned)
	}
}

/// A validator that denies certificate fingerprints in a const-generic array.
///
/// Each entry is a [`Fingerprint`] under `D`, so an entry of another width
/// fails where it is read, through [`Fingerprint::try_from`]. A list of raw
/// octets would instead hold an entry that matches no certificate.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::hash::Sha3_256;
/// use tightbeam::crypto::x509::error::CertificateValidationError;
/// use tightbeam::crypto::x509::policy::{CertificateValidation, FingerprintDenylist};
/// use tightbeam::crypto::x509::utils::Fingerprint;
/// use tightbeam::testing::{TestCertificate, TestKey};
///
/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
/// let denied = Fingerprint::<Sha3_256>::from_certificate(&certificate)?;
///
/// let denylist = FingerprintDenylist::new([denied]);
/// let refused = denylist.evaluate(&certificate);
/// assert!(matches!(refused, Err(CertificateValidationError::CertificateDenied)));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct FingerprintDenylist<D: OutputSizeUser, const N: usize> {
	denied_fingerprints: [Fingerprint<D>; N],
}

impl<D: OutputSizeUser, const N: usize> FingerprintDenylist<D, N> {
	/// Create a validator that refuses a certificate whose fingerprint
	/// `fingerprints` lists.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::hash::Sha3_512;
	/// use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
	/// use tightbeam::crypto::x509::policy::{CertificateValidation, FingerprintDenylist};
	/// use tightbeam::crypto::x509::utils::Fingerprint;
	/// use tightbeam::random::OsRng;
	/// use tightbeam::testing::{TestCertificate, TestKey};
	///
	/// let denied = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// let other = TestCertificate::self_signed(&Secp256k1SigningKey::random(&mut OsRng));
	/// let entry = Fingerprint::<Sha3_512>::from_certificate(&denied)?;
	///
	/// let denylist = FingerprintDenylist::new([entry]);
	/// denylist.evaluate(&other)?;
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn new(fingerprints: [Fingerprint<D>; N]) -> Self {
		Self { denied_fingerprints: fingerprints }
	}
}

impl<D, const N: usize> CertificateValidation for FingerprintDenylist<D, N>
where
	D: Digest,
{
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		let fingerprint = Fingerprint::<D>::from_certificate(cert)?;
		let is_denied = self.denied_fingerprints.contains(&fingerprint);
		if is_denied {
			Err(CertificateValidationError::CertificateDenied)
		} else {
			Ok(())
		}
	}
}

/// A validator that pins certificates by their fingerprints, in a list whose
/// length the caller sets at runtime.
///
/// A builder can create it from the certificates it holds at runtime, where
/// [`FingerprintPinning`] takes a fixed array.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::hash::Sha3_512;
/// use tightbeam::crypto::x509::policy::{CertificateValidation, RuntimeCertificatePinning};
/// use tightbeam::testing::{TestCertificate, TestKey};
///
/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
/// let pinning = RuntimeCertificatePinning::<Sha3_512>::from_certificates([certificate.clone()])?;
/// pinning.evaluate(&certificate)?;
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[cfg(feature = "std")]
#[derive(Clone)]
pub struct RuntimeCertificatePinning<D: OutputSizeUser> {
	fingerprints: Vec<Fingerprint<D>>,
}

#[cfg(feature = "std")]
impl<D> RuntimeCertificatePinning<D>
where
	D: Digest,
{
	/// Create a validator that pins `certs`.
	///
	/// It computes the fingerprint of each certificate once, at construction.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::EncodingError`] -- a certificate fails to DER-encode.
	pub fn from_certificates(certs: impl IntoIterator<Item = Certificate>) -> Result<Self, CertificateValidationError> {
		let fingerprints = certs
			.into_iter()
			.map(|cert| Fingerprint::<D>::from_certificate(&cert))
			.collect::<Result<Vec<_>, _>>()?;

		Ok(Self { fingerprints })
	}

	/// Create a validator from fingerprints that
	/// [`Fingerprint::from_certificate`] computed.
	///
	/// [`Fingerprint::from_certificate`]: crate::crypto::x509::utils::Fingerprint::from_certificate
	pub fn from_fingerprints(fingerprints: impl IntoIterator<Item = Fingerprint<D>>) -> Self {
		Self { fingerprints: fingerprints.into_iter().collect() }
	}
}

#[cfg(feature = "std")]
impl<D> CertificateValidation for RuntimeCertificatePinning<D>
where
	D: Digest,
{
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		let fingerprint = Fingerprint::<D>::from_certificate(cert)?;
		let pinned = self.fingerprints.contains(&fingerprint);
		pinned.then_some(()).ok_or(CertificateValidationError::CertificateNotPinned)
	}
}

/// A validator that trusts a certificate when it is itself a configured trust
/// anchor (direct trust, RFC 5280 §6.1.1).
///
/// It checks the presented certificate alone. Path building, name chaining,
/// and the `basicConstraints` and `keyUsage` checks of RFC 5280 §6.1 belong
/// to the certification-path validation of [`CertificateTrustStore`].
///
/// - [`CertificateValidation::evaluate`] checks the validity period
///   (RFC 5280 §6.1.3(a)(2)) at the reading of its clock, and admits a
///   configured trust anchor alone, by its SHA3-256 fingerprint. With no
///   anchor, as under `Default`, it refuses every certificate.
///   [`Self::with_trust_chain`] configures the anchors, and
///   [`Self::with_clock`] the clock, which is the crate clock under `Default`.
/// - [`SignatureVerification::verify_with_policy`] checks the validity of one
///   certificate, the consistency of its algorithm identifiers
///   (RFC 5280 §4.1.1.2), and its signature under an issuer key that the
///   caller supplies (RFC 5280 §6.1.3(a)(1)).
/// - Both refuse a certificate that repeats an extension or bears a critical
///   extension the crate does not process (RFC 5280 §4.2), as path validation
///   does.
///
/// See <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1>.
///
/// [`CertificateTrustStore`]: crate::crypto::x509::store::CertificateTrustStore
#[derive(Default, Clone)]
pub struct DirectTrustValidator {
	/// The fingerprint of each trust anchor, which the install decides once.
	anchors: Vec<Fingerprint<Sha3_256>>,
	/// The clock that [`CertificateValidation::evaluate`] reads the validity
	/// period on.
	clock: ValidityClock,
}

impl DirectTrustValidator {
	/// Replace the trust anchors of the validator with the certificates of
	/// `trust_chain`, each held by its SHA3-256 fingerprint.
	///
	/// An empty chain leaves the validator with no anchor, so
	/// [`CertificateValidation::evaluate`] refuses every certificate, as under
	/// `Default`.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::EncodingError`] -- a certificate fails to DER-encode.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
	/// use tightbeam::crypto::x509::policy::{CertificateValidation, DirectTrustValidator};
	/// use tightbeam::random::OsRng;
	/// use tightbeam::testing::{TestCertificate, TestKey};
	///
	/// let anchor = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// let other = TestCertificate::self_signed(&Secp256k1SigningKey::random(&mut OsRng));
	/// let validator = DirectTrustValidator::default().with_trust_chain([anchor.clone()])?;
	///
	/// validator.evaluate(&anchor)?;
	/// assert!(validator.evaluate(&other).is_err());
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn with_trust_chain(
		mut self,
		trust_chain: impl IntoIterator<Item = Certificate>,
	) -> Result<Self, CertificateValidationError> {
		let anchors = trust_chain.into_iter().map(|anchor| Fingerprint::from_certificate(&anchor));
		self.anchors = anchors.collect::<Result<Vec<_>, _>>()?;
		Ok(self)
	}

	/// Set the clock that [`CertificateValidation::evaluate`] reads the
	/// validity period on, in place of the crate clock.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::x509::error::CertificateValidationError;
	/// use tightbeam::crypto::x509::policy::{CertificateValidation, DirectTrustValidator};
	/// use tightbeam::testing::{TestCertificate, TestKey};
	///
	/// // The clock of the validator reads a time past the end of the period
	/// // of the anchor.
	/// let anchor = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// let validator = DirectTrustValidator::default().with_trust_chain([anchor.clone()])?;
	/// let validator = validator.with_clock(TestCertificate::clock_past_validity());
	///
	/// let refused = validator.evaluate(&anchor);
	/// assert!(matches!(refused, Err(CertificateValidationError::Expired)));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[must_use]
	pub fn with_clock(mut self, clock: Arc<dyn Clock + Send + Sync>) -> Self {
		self.clock = ValidityClock::new(clock);
		self
	}
}

impl CertificateValidation for DirectTrustValidator {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		// RFC 5280 §6.1.3(a)(2): the current time must fall within the
		// certificate's validity period.
		self.clock.admits(cert)?;

		// RFC 5280 §4.2: a repeated extension, or an unprocessed critical one,
		// fails closed.
		cert.ensure_unique_extensions()?;
		cert.ensure_critical_extensions_processed()?;

		// RFC 5280 §6.1.1 direct trust is a path of one certificate. An empty
		// anchor set fails closed and never degrades to the expiry-only check
		// of `ExpiryValidator` (CWE-1188, insecure default).
		let fingerprint = Fingerprint::<Sha3_256>::from_certificate(cert)?;
		let anchored = self.anchors.contains(&fingerprint);
		anchored.then_some(()).ok_or(CertificateValidationError::CertificateNotTrusted)
	}
}

impl SignatureVerification for DirectTrustValidator {
	fn verify_with_policy(
		&self,
		cert: &Certificate,
		curr_time: u64,
		public_key_der: &[u8],
		policy: &dyn VerificationPolicy,
	) -> Result<(), CertificateValidationError> {
		cert.validate_expiry_at(curr_time)?;
		cert.ensure_unique_extensions()?;
		cert.ensure_critical_extensions_processed()?;

		// RFC 5280 §4.1.2.7: the subjectPublicKeyInfo must carry a key.
		let subject_public_key = cert.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
		if subject_public_key.is_empty() {
			return Err(CertificateValidationError::EmptyPublicKey);
		}

		// RFC 5280 §4.1.1.3: the signatureValue must be present.
		let signature_bytes = cert.signature.raw_bytes();
		if signature_bytes.is_empty() {
			return Err(CertificateValidationError::EmptySignature);
		}

		// RFC 5280 §4.1.1.2: the signatureAlgorithm must match the
		// tbsCertificate.signature field.
		cert.ensure_signature_algorithm_consistency()?;

		// RFC 5280 §6.1.3(a)(1): verify the signature with the issuer's key.
		// No ledger uses a certificate signature as its key, so its canonical
		// form drops here.
		let message = cert.tbs_certificate.to_der()?;
		let verified =
			policy.verify_signature(&cert.signature_algorithm.oid, public_key_der, &message, signature_bytes);
		verified.map(drop)
	}
}

/// A validator that chains other validators.
///
/// The validators run in order, and the certificate passes only when every
/// one of them succeeds. The chain runs each check it is asked on each
/// validator. Signature verification belongs to a [`SignatureVerification`]
/// validator outside it.
#[cfg(feature = "std")]
#[derive(Default)]
pub struct ChainValidator {
	validators: Vec<Box<dyn CertificateValidation>>,
}

#[cfg(feature = "std")]
impl ChainValidator {
	/// Add a validator to the chain.
	///
	/// It boxes the validator, as [`crate::policy::GateChain::push`] does.
	#[allow(clippy::should_implement_trait)]
	pub fn add(mut self, validator: impl CertificateValidation + 'static) -> Self {
		self.validators.push(Box::new(validator));
		self
	}
}

#[cfg(feature = "std")]
impl CertificateValidation for ChainValidator {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		self.validators.iter().try_for_each(|v| v.evaluate(cert))
	}

	/// Each validator runs its own `evaluate_presented` on `leaf` beside
	/// `issuers`, so a store in the chain validates the path the peer
	/// presents.
	fn evaluate_presented(
		&self,
		issuers: &[Certificate],
		leaf: &Certificate,
	) -> Result<(), CertificateValidationError> {
		self.validators.iter().try_for_each(|v| v.evaluate_presented(issuers, leaf))
	}
}

#[cfg(test)]
mod tests {
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use crate::testing::TestCertificate;

	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509", feature = "std"))]
	use crate::crypto::x509::policy::DirectTrustValidator;
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509", feature = "std"))]
	use crate::crypto::x509::Certificate;

	/// A direct-trust validator that holds each of `anchors` as a trust
	/// anchor.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509", feature = "std"))]
	fn anchored(anchors: impl IntoIterator<Item = Certificate>) -> DirectTrustValidator {
		let validator = DirectTrustValidator::default().with_trust_chain(anchors);
		validator.expect("a test anchor encodes")
	}

	/// The expiry validator refuses a certificate past its validity period.
	#[test]
	fn the_expiry_validator_refuses_an_expired_certificate() {
		let refused = ExpiryValidator::default().evaluate(&TestCertificate::expired());
		assert!(matches!(refused, Err(CertificateValidationError::Expired)));
	}

	/// Each validator that checks a validity period reads it on the clock it
	/// holds. On a clock past the end of the period, each refuses a
	/// certificate whose period the host clock reads as current.
	#[cfg(all(host_clock, feature = "secp256k1", feature = "signature", feature = "x509"))]
	mod clock {
		use super::*;

		// Each row names the validator that holds the clock, and the fixed test
		// certificate is the one whose period the host clock reads as current.
		crate::tb_cases! {
			fn the_clock_of(validator: Box<dyn CertificateValidation>) {
				let refused = validator.evaluate(&TestCertificate::insecure_fixed());
				assert!(matches!(refused, Err(CertificateValidationError::Expired)));
			}
			cases {
				an_expiry_validator_judges_validity => Box::new(
					ExpiryValidator::default().with_clock(TestCertificate::clock_past_validity()),
				),
				a_direct_trust_validator_judges_validity => Box::new(
					anchored([TestCertificate::insecure_fixed()]).with_clock(TestCertificate::clock_past_validity()),
				),
			}
		}
	}

	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	mod fingerprint_lists {
		use crate::crypto::hash::{Sha3_256, Sha3_512};
		use crate::crypto::x509::policy::{FingerprintDenylist, FingerprintPinning};
		use crate::crypto::x509::utils::Fingerprint;
		use crate::error::ReceivedExpectedError;
		use crate::testing::{TestKey, TestResult};

		use super::*;

		/// The fingerprint reader refuses a denylist entry one octet short of
		/// its digest's output, before any denylist holds it.
		#[test]
		fn a_31_octet_denylist_entry_is_refused_at_construction() {
			let entry = Fingerprint::<Sha3_256>::try_from(&[0x5a; 31][..]);
			let width = ReceivedExpectedError { received: 31, expected: 32 };
			assert!(matches!(entry, Err(CertificateValidationError::FingerprintLength(found)) if found == width));
		}

		/// A denylist under SHA3-512 refuses a certificate by its 64-octet
		/// fingerprint.
		#[test]
		fn a_sha3_512_denylist_refuses_the_certificate_it_lists() -> TestResult {
			let certificate = TestCertificate::insecure_fixed();
			let denied = Fingerprint::<Sha3_512>::from_certificate(&certificate)?;

			let refused = FingerprintDenylist::new([denied]).evaluate(&certificate);
			assert!(matches!(refused, Err(CertificateValidationError::CertificateDenied)));
			Ok(())
		}

		/// A pin under SHA3-512 refuses a certificate whose 64-octet
		/// fingerprint it does not hold.
		#[test]
		fn a_sha3_512_pin_refuses_a_certificate_it_does_not_pin() -> TestResult {
			let pin = Fingerprint::<Sha3_512>::from_certificate(&TestCertificate::insecure_fixed())?;
			let other = TestCertificate::with_cn_and_uri_sans(&TestKey::insecure_fixed_signing(), "Other", &[]);

			let refused = FingerprintPinning::new([pin]).evaluate(&other);
			assert!(matches!(refused, Err(CertificateValidationError::CertificateNotPinned)));
			Ok(())
		}
	}

	#[cfg(all(
		feature = "std",
		feature = "aead",
		feature = "signature",
		feature = "kdf",
		feature = "ecdh"
	))]
	mod chain {
		use crate::crypto::x509::policy::ChainValidator;
		use crate::testing::fixtures::{TestCertificateChain, TestStore};
		use crate::testing::TestResult;

		use super::*;

		/// A chain that holds a store of the root alone admits a leaf beside
		/// the intermediate it presents, so the chain hands each validator the
		/// presented issuers.
		#[test]
		fn a_chained_store_admits_a_client_beside_its_presented_issuers() -> TestResult {
			let TestCertificateChain { root, intermediate, leaf, .. } = TestCertificate::insecure_fixed_chain()?;
			let store = TestStore::holding([root]);
			let chain = ChainValidator::default().add(ExpiryValidator::default()).add(store);
			chain.evaluate_presented(&[intermediate], &leaf)?;
			Ok(())
		}
	}

	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	mod public_key_pinning {
		use crate::crypto::x509::policy::PublicKeyPinning;
		use crate::crypto::x509::{Certificate, KeyListError};
		use crate::oids::CURVE_NIST_P256;
		use crate::testing::TestResult;

		use super::*;

		/// A pinning of the key of each of `pinned`, each pin the DER of the
		/// SubjectPublicKeyInfo of its certificate.
		fn pinning(pinned: impl IntoIterator<Item = Certificate>) -> PublicKeyPinning {
			let pins = pinned.into_iter().map(|certificate| TestCertificate::spki_der(&certificate));
			PublicKeyPinning::new(pins).expect("a test pin is a SubjectPublicKeyInfo")
		}

		// A pinning admits a key that one of its pins names, in either SEC 1
		// form of its point.
		crate::tb_cases! {
			fn a_pinning_admits((pinned, presented): (Vec<Certificate>, Certificate)) -> TestResult {
				let validator = pinning(pinned);

				validator.evaluate(&presented)?;
				Ok(())
			}
			cases {
				/// A pin of the compressed point admits the certificate of that
				/// point in the uncompressed form.
				the_uncompressed_key_by_its_compressed_pin => (
					vec![TestCertificate::with_compressed_key(TestCertificate::insecure_fixed())],
					TestCertificate::insecure_fixed(),
				),
				/// A pinning admits a key that any one of its pins names, so a
				/// second pin of the key admits it after a first pin of another
				/// key.
				a_key_by_its_second_pin => (
					vec![TestCertificate::insecure_fixed_negation(), TestCertificate::insecure_fixed()],
					TestCertificate::insecure_fixed(),
				),
			}
		}

		// A pinning refuses a key that its pin names with another point or
		// another curve.
		crate::tb_cases! {
			fn a_pinning_refuses((pinned, presented): (Certificate, Certificate)) {
				let validator = pinning([pinned]);
				let refused = validator.evaluate(&presented);
				assert!(matches!(refused, Err(CertificateValidationError::PublicKeyNotPinned)));
			}
			cases {
				/// A pin of the negated point names another key, so it refuses
				/// the certificate.
				a_key_by_the_pin_of_its_negation => (
					TestCertificate::insecure_fixed_negation(),
					TestCertificate::insecure_fixed(),
				),
				/// An encoding of the x-coordinate and the y parity of the
				/// pinned key that is no point of its curve names another key,
				/// so the pin refuses it (SEC 1 v2.0 §2.3.4).
				an_off_curve_alias_of_its_key => (
					TestCertificate::insecure_fixed(),
					TestCertificate::with_off_curve_key(TestCertificate::insecure_fixed()),
				),
				/// A pin names its key with its curve, so a secp256k1 pin
				/// refuses a P-256 certificate that holds the same uncompressed
				/// point bits (RFC 5280 §4.1.2.7).
				the_same_bits_on_p256 => (
					TestCertificate::insecure_fixed(),
					TestCertificate::with_named_curve(TestCertificate::insecure_fixed(), CURVE_NIST_P256),
				),
				/// The curve separates the two keys in the compressed form too.
				the_same_compressed_bits_on_p256 => (
					TestCertificate::with_compressed_key(TestCertificate::insecure_fixed()),
					TestCertificate::with_named_curve(
						TestCertificate::with_compressed_key(TestCertificate::insecure_fixed()),
						CURVE_NIST_P256,
					),
				),
			}
		}

		/// A pin that is no SubjectPublicKeyInfo fails the construction, and
		/// the error names its position.
		#[test]
		fn a_malformed_pin_fails_at_construction_with_its_index() {
			let pins = [
				TestCertificate::spki_der(&TestCertificate::insecure_fixed()),
				b"no key".to_vec(),
			];

			let refused = PublicKeyPinning::new(pins);
			assert_eq!(refused.err(), Some(KeyListError::Unreadable { index: 1 }));
		}
	}

	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509", feature = "std"))]
	mod direct_trust {
		use crate::crypto::policy::Secp256k1Policy;
		use crate::crypto::x509::error::CertificateValidationError::{
			DuplicateExtension, UnprocessedCriticalExtension,
		};
		use crate::crypto::x509::fixtures::Refusal;
		use crate::crypto::x509::policy::SignatureVerification;
		use crate::der::asn1::ObjectIdentifier;
		use crate::der::oid::db::rfc5280::ID_CE_NAME_CONSTRAINTS;
		use crate::oids::{SIGNER_ECDSA_WITH_SHA256, SIGNER_ECDSA_WITH_SHA3_256};
		use crate::spki::EncodePublicKey;
		use crate::testing::{TestKey, TestResult};

		use super::*;

		/// The fixed test certificate with `outer` as its `signatureAlgorithm`
		/// and `inner` as the `signature` field of its `tbsCertificate`.
		fn with_signature_oids(outer: ObjectIdentifier, inner: ObjectIdentifier) -> Certificate {
			let mut certificate = TestCertificate::insecure_fixed();
			certificate.signature_algorithm.oid = outer;
			certificate.tbs_certificate.signature.oid = inner;
			certificate
		}

		/// The validator admits a certificate it holds as a trust anchor.
		#[test]
		fn evaluate_admits_a_configured_anchor() -> TestResult {
			let validator = anchored([TestCertificate::insecure_fixed()]);
			validator.evaluate(&TestCertificate::insecure_fixed())?;
			Ok(())
		}

		// The validator admits a configured trust anchor alone.
		crate::tb_cases! {
			fn evaluate_refuses((validator, certificate): (DirectTrustValidator, Certificate)) {
				let refused = validator.evaluate(&certificate);
				assert!(matches!(refused, Err(CertificateValidationError::CertificateNotTrusted)));
			}
			cases {
				a_certificate_that_is_no_anchor => (
					anchored([TestCertificate::insecure_fixed()]),
					TestCertificate::self_signed(&TestKey::fixed(0x07)),
				),
				/// A validator that `Default` builds holds no anchor and must
				/// fail closed. If it admitted every in-date certificate, a
				/// forgotten `with_trust_chain` would become a silent
				/// authentication bypass (CWE-1188). `ExpiryValidator` is the
				/// expiry-only check.
				every_certificate_with_no_anchor => (
					DirectTrustValidator::default(),
					TestCertificate::insecure_fixed(),
				),
			}
		}

		// The validator refuses an anchor that breaks an extension rule, so the
		// anchor match does not stand in for the extension rules (RFC 5280
		// §4.2). Each row builds its anchor anew for the validator and for the
		// evaluation.
		crate::tb_cases! {
			fn evaluate_refuses_an_anchor((anchor, refusal): (fn() -> Certificate, Refusal)) {
				let validator = anchored([anchor()]);
				let refused = validator.evaluate(&anchor());
				assert!(matches!(refused, Err(ref error) if refusal(error)));
			}
			cases {
				that_repeats_an_extension => (
					|| TestCertificate::with_repeated_extension(TestCertificate::insecure_fixed(), "2.5.29.30"),
					|e| matches!(e, DuplicateExtension(oid) if *oid == ID_CE_NAME_CONSTRAINTS),
				),
				with_an_unknown_critical_extension => (
					|| TestCertificate::with_unknown_critical_extension(TestCertificate::insecure_fixed()),
					|e| matches!(e, UnprocessedCriticalExtension(oid) if *oid == ID_CE_NAME_CONSTRAINTS),
				),
			}
		}

		// The signature check under the issuer key refuses a certificate whose
		// algorithm identifiers disagree or name an algorithm the policy
		// refuses, and one that breaks an extension rule (RFC 5280 §4.1.1.2,
		// §4.2).
		crate::tb_cases! {
			fn verify_refuses((certificate, refusal): (Certificate, Refusal)) -> TestResult {
				let issuer = TestKey::insecure_fixed_signing().verifying_key().to_public_key_der()?;
				let validator = DirectTrustValidator::default();
				let policy = Secp256k1Policy::default();

				let refused = validator.verify_with_policy(&certificate, 1_000, issuer.as_bytes(), &policy);
				assert!(matches!(refused, Err(ref error) if refusal(error)));
				Ok(())
			}
			cases {
				/// `signatureAlgorithm` and `tbsCertificate.signature`
				/// disagree, which RFC 5280 §4.1.1.2 forbids.
				a_certificate_whose_algorithm_identifiers_disagree => (
					with_signature_oids(SIGNER_ECDSA_WITH_SHA256, SIGNER_ECDSA_WITH_SHA3_256),
					|e| matches!(e, CertificateValidationError::AlgorithmMismatch),
				),
				/// The identifiers agree on an algorithm that the default
				/// policy refuses.
				a_certificate_of_an_algorithm_the_policy_refuses => (
					with_signature_oids(SIGNER_ECDSA_WITH_SHA256, SIGNER_ECDSA_WITH_SHA256),
					|e| matches!(e, CertificateValidationError::UnsupportedAlgorithm(_)),
				),
				a_certificate_that_repeats_an_extension => (
					TestCertificate::with_repeated_extension(TestCertificate::insecure_fixed(), "2.5.29.30"),
					|e| matches!(e, DuplicateExtension(oid) if *oid == ID_CE_NAME_CONSTRAINTS),
				),
				a_certificate_with_an_unknown_critical_extension => (
					TestCertificate::with_unknown_critical_extension(TestCertificate::insecure_fixed()),
					|e| matches!(e, UnprocessedCriticalExtension(oid) if *oid == ID_CE_NAME_CONSTRAINTS),
				),
			}
		}
	}
}
