//! Certificate validation policies and strategies.
//!
//! [`CertificateValidation`] checks one X.509 certificate, and
//! [`SignatureVerification`] adds a check of its signature under an issuer
//! key. The built-in validators check expiry, pin keys or fingerprints, deny
//! fingerprints, anchor direct trust, and chain other validators.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::crypto::hash::{Digest, OutputSizeUser};
use crate::crypto::policy::VerificationPolicy;
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::utils::{CertificateExt, Fingerprint};
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

	/// Validate `leaf`, the certificate a peer presents, beside `issuers`,
	/// the issuers above it that the peer presents, the top first, so each
	/// issues the one after it and the last issues `leaf`.
	///
	/// A mutual server admits its client here, with the issuers its client
	/// Finished presents (RFC 5652 §5.1):
	///
	/// - The default runs [`Self::evaluate`] on `leaf` alone.
	/// - [`CertificateTrustStore`] overrides it, and validates the path of
	///   `leaf` under `issuers` to one of its trust anchors (RFC 5280 §6.1).
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
	/// use tightbeam::crypto::x509::store::{CertificateTrustBuilder, TrustBuilder};
	/// use tightbeam::testing::fixtures::{TestCertificate, TestCertificateChain};
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// // The keys of the fixture chain are public, so it serves an example
	/// // alone.
	/// let TestCertificateChain { root, intermediate, leaf, .. } = TestCertificate::insecure_fixed_chain()?;
	///
	/// // The store holds the root alone, and the peer presents the
	/// // intermediate beside its certificate.
	/// let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
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

/// A certificate validation strategy that also verifies the cryptographic
/// signature of the certificate.
///
/// It extends [`CertificateValidation`] with a check of the certificate's
/// signature under a verification policy the caller supplies.
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

/// A validator that checks certificate expiry alone.
///
/// Its one check is that the certificate is within its validity period, so a
/// signature check belongs to a [`SignatureVerification`] validator.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExpiryValidator;

impl CertificateValidation for ExpiryValidator {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		// The check covers the validity period of RFC 5280 §6.1.3(a)(2) alone.
		cert.validate_expiry()
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

/// A validator that trusts a certificate when the certificate is itself a
/// configured trust anchor (direct trust, RFC 5280 §6.1.1).
///
/// It checks the presented certificate alone. Path building, name chaining,
/// and the `basicConstraints` and `keyUsage` checks of RFC 5280 §6.1 belong
/// to the certification-path validation of [`CertificateTrustStore`].
///
/// - [`CertificateValidation::evaluate`] checks the validity period
///   (RFC 5280 §6.1.3(a)(2)) and requires the presented certificate to be a
///   configured trust anchor. With no anchors configured, as under `Default`,
///   it refuses every certificate. [`Self::with_trust_chain`] configures the
///   anchors.
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
	trust_chain: Vec<Certificate>,
}

impl DirectTrustValidator {
	/// Replace the trust anchors of the validator with the certificates of
	/// `trust_chain`.
	///
	/// An empty chain leaves the validator with no anchor, so
	/// [`CertificateValidation::evaluate`] refuses every certificate, as under
	/// `Default`.
	pub fn with_trust_chain(mut self, trust_chain: impl IntoIterator<Item = Certificate>) -> Self {
		self.trust_chain = trust_chain.into_iter().collect();
		self
	}
}

impl CertificateValidation for DirectTrustValidator {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		// RFC 5280 §6.1.3(a)(2): the current time must fall within the
		// certificate's validity period.
		cert.validate_expiry()?;

		// RFC 5280 §4.2: a repeated extension, or an unprocessed critical one,
		// fails closed.
		cert.ensure_unique_extensions()?;
		cert.ensure_critical_extensions_processed()?;

		// RFC 5280 §6.1.1 direct trust: the presented certificate must itself
		// be a configured trust anchor, a path of one certificate. An empty
		// anchor set therefore trusts nothing, so the validator fails closed
		// and never degrades to an expiry-only check (CWE-1188, insecure
		// default). `ExpiryValidator` is the deliberate expiry-only check.
		let cert_der = cert.to_der()?;
		for anchor in &self.trust_chain {
			if anchor.to_der()? == cert_der {
				return Ok(());
			}
		}

		Err(CertificateValidationError::CertificateNotTrusted)
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
/// one of them succeeds. The chain runs [`CertificateValidation::evaluate`]
/// alone, so signature verification belongs to a [`SignatureVerification`]
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
}

#[cfg(test)]
mod tests {
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use crate::testing::TestCertificate;

	/// The expiry validator refuses a certificate past its validity period.
	#[test]
	fn the_expiry_validator_refuses_an_expired_certificate() {
		let refused = ExpiryValidator.evaluate(&TestCertificate::expired());
		assert!(matches!(refused, Err(CertificateValidationError::Expired)));
	}

	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	mod fingerprint_lists {
		use crate::crypto::hash::{Sha3_256, Sha3_512};
		use crate::crypto::x509::error::CertificateValidationError;
		use crate::crypto::x509::policy::{CertificateValidation, FingerprintDenylist, FingerprintPinning};
		use crate::crypto::x509::utils::Fingerprint;
		use crate::error::ReceivedExpectedError;
		use crate::testing::fixtures::{TestCertificate, TestKey};

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
		fn a_sha3_512_denylist_refuses_the_certificate_it_lists() -> Result<(), CertificateValidationError> {
			let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
			let denied = Fingerprint::<Sha3_512>::from_certificate(&certificate)?;

			let refused = FingerprintDenylist::new([denied]).evaluate(&certificate);
			assert!(matches!(refused, Err(CertificateValidationError::CertificateDenied)));
			Ok(())
		}

		/// A pin under SHA3-512 refuses a certificate whose 64-octet
		/// fingerprint it does not hold.
		#[test]
		fn a_sha3_512_pin_refuses_a_certificate_it_does_not_pin() -> Result<(), CertificateValidationError> {
			let pinned = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
			let pin = Fingerprint::<Sha3_512>::from_certificate(&pinned)?;
			let other = TestCertificate::with_cn_and_uri_sans(&TestKey::insecure_fixed_signing(), "Other", &[]);

			let refused = FingerprintPinning::new([pin]).evaluate(&other);
			assert!(matches!(refused, Err(CertificateValidationError::CertificateNotPinned)));
			Ok(())
		}
	}

	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	mod public_key_pinning {
		use crate::crypto::x509::error::CertificateValidationError;
		use crate::crypto::x509::policy::{CertificateValidation, PublicKeyPinning};
		use crate::crypto::x509::{Certificate, KeyListError};
		use crate::der::Encode;
		use crate::oids::CURVE_NIST_P256;
		use crate::testing::fixtures::{TestCertificate, TestKey};

		/// The certificate of the fixed test key, whose point is in the
		/// uncompressed form.
		fn uncompressed() -> Certificate {
			TestCertificate::self_signed(&TestKey::insecure_fixed_signing())
		}

		/// The pin of the key of `certificate`: the DER of its
		/// SubjectPublicKeyInfo.
		fn pin_of(certificate: &Certificate) -> Vec<u8> {
			let spki = &certificate.tbs_certificate.subject_public_key_info;
			spki.to_der().expect("a test SubjectPublicKeyInfo encodes")
		}

		/// `certificate` with its point read under P-256, the bits of its
		/// secp256k1 key under another named curve.
		fn on_p256(certificate: Certificate) -> Certificate {
			let spki = &certificate.tbs_certificate.subject_public_key_info;
			let point = spki.subject_public_key.raw_bytes().to_vec();
			TestCertificate::with_curve_point(certificate, CURVE_NIST_P256, &point)
		}

		/// A pin of the compressed point admits the certificate of that point
		/// in the uncompressed form.
		#[test]
		fn a_compressed_pin_admits_the_uncompressed_key() -> Result<(), Box<dyn core::error::Error>> {
			let compressed = TestCertificate::with_compressed_key(uncompressed());
			let pinning = PublicKeyPinning::new([pin_of(&compressed)])?;

			pinning.evaluate(&uncompressed())?;
			Ok(())
		}

		/// A pin of the negated point names another key, so it refuses the
		/// certificate.
		#[test]
		fn a_pin_of_the_negated_point_refuses_the_key() -> Result<(), KeyListError> {
			let negation = TestKey::negation_of(&TestKey::insecure_fixed_signing());
			let pinning = PublicKeyPinning::new([pin_of(&TestCertificate::self_signed(&negation))])?;

			let refused = pinning.evaluate(&uncompressed());
			assert!(matches!(refused, Err(CertificateValidationError::PublicKeyNotPinned)));
			Ok(())
		}

		/// A pinning admits a key that any one of its pins names, so a second
		/// pin of the key admits it after a first pin of another key.
		#[test]
		fn the_second_pin_admits_its_key() -> Result<(), Box<dyn core::error::Error>> {
			let negation = TestKey::negation_of(&TestKey::insecure_fixed_signing());
			let other = pin_of(&TestCertificate::self_signed(&negation));
			let pinning = PublicKeyPinning::new([other, pin_of(&uncompressed())])?;

			pinning.evaluate(&uncompressed())?;
			Ok(())
		}

		/// An encoding of the x-coordinate and the y parity of the pinned key
		/// that is no point of its curve names another key, so the pin refuses
		/// it (SEC 1 v2.0 §2.3.4).
		#[test]
		fn a_pin_refuses_an_off_curve_alias_of_its_key() -> Result<(), KeyListError> {
			let pinning = PublicKeyPinning::new([pin_of(&uncompressed())])?;
			let alias = TestCertificate::with_off_curve_key(uncompressed());

			let refused = pinning.evaluate(&alias);
			assert!(matches!(refused, Err(CertificateValidationError::PublicKeyNotPinned)));
			Ok(())
		}

		/// A pin names its key with its curve, so a secp256k1 pin refuses a
		/// P-256 certificate that holds the same uncompressed point bits
		/// (RFC 5280 §4.1.2.7).
		#[test]
		fn a_secp256k1_pin_refuses_the_same_bits_on_p256() -> Result<(), KeyListError> {
			let pinning = PublicKeyPinning::new([pin_of(&uncompressed())])?;

			let refused = pinning.evaluate(&on_p256(uncompressed()));
			assert!(matches!(refused, Err(CertificateValidationError::PublicKeyNotPinned)));
			Ok(())
		}

		/// The curve separates the two keys in the compressed form too.
		#[test]
		fn a_secp256k1_pin_refuses_the_same_compressed_bits_on_p256() -> Result<(), KeyListError> {
			let compressed = TestCertificate::with_compressed_key(uncompressed());
			let pinning = PublicKeyPinning::new([pin_of(&compressed)])?;

			let refused = pinning.evaluate(&on_p256(compressed));
			assert!(matches!(refused, Err(CertificateValidationError::PublicKeyNotPinned)));
			Ok(())
		}

		/// A pin that is no SubjectPublicKeyInfo fails the construction, and
		/// the error names its position.
		#[test]
		fn a_malformed_pin_fails_at_construction_with_its_index() {
			let refused = PublicKeyPinning::new([pin_of(&uncompressed()), b"no key".to_vec()]);
			assert_eq!(refused.err(), Some(KeyListError::Unreadable { index: 1 }));
		}
	}

	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509", feature = "std"))]
	mod direct_trust {
		use k256::ecdsa::SigningKey;

		use crate::crypto::policy::Secp256k1Policy;
		use crate::crypto::x509::error::CertificateValidationError;
		use crate::crypto::x509::policy::{CertificateValidation, DirectTrustValidator, SignatureVerification};
		use crate::crypto::x509::Certificate;
		use crate::oids::SIGNER_ECDSA_WITH_SHA256;
		use crate::spki::EncodePublicKey;
		use crate::testing::fixtures::{TestCertificate, TestKey};

		fn test_cert() -> Certificate {
			TestCertificate::self_signed(&TestKey::insecure_fixed_signing())
		}

		/// Run the default [`Secp256k1Policy`] over `cert`, with the issuer key
		/// that matches `signing_key`.
		fn verify(signing_key: &SigningKey, cert: &Certificate) -> Result<(), CertificateValidationError> {
			let issuer_pub = signing_key.verifying_key().to_public_key_der()?;
			let policy = Secp256k1Policy::default();
			DirectTrustValidator::default().verify_with_policy(cert, 1_000, issuer_pub.as_bytes(), &policy)
		}

		#[test]
		fn accepts_configured_anchor() {
			let cert = test_cert();
			let trust_chain = vec![cert.clone()];
			let validator = DirectTrustValidator::default().with_trust_chain(trust_chain);
			assert!(validator.evaluate(&cert).is_ok());
		}

		#[test]
		fn rejects_non_anchor() -> Result<(), Box<dyn core::error::Error>> {
			let validator = DirectTrustValidator::default().with_trust_chain(vec![test_cert()]);
			let other = TestCertificate::self_signed(&SigningKey::from_bytes(&[7u8; 32].into())?);
			assert!(matches!(
				validator.evaluate(&other),
				Err(CertificateValidationError::CertificateNotTrusted)
			));
			Ok(())
		}

		/// A validator that `Default` builds holds no anchor and must fail
		/// closed. If it admitted every in-date certificate, a forgotten
		/// `with_trust_chain` would become a silent authentication bypass
		/// (CWE-1188). `ExpiryValidator` is the expiry-only check.
		#[test]
		fn without_anchor_fails_closed() {
			assert!(matches!(
				DirectTrustValidator::default().evaluate(&test_cert()),
				Err(CertificateValidationError::CertificateNotTrusted)
			));
		}

		#[test]
		fn rejects_algorithm_mismatch() {
			let key = TestKey::insecure_fixed_signing();
			let mut cert = TestCertificate::self_signed(&key);
			// signatureAlgorithm and tbsCertificate.signature disagree, which
			// RFC 5280 §4.1.1.2 forbids.
			cert.signature_algorithm.oid = SIGNER_ECDSA_WITH_SHA256;
			assert!(matches!(
				verify(&key, &cert),
				Err(CertificateValidationError::AlgorithmMismatch)
			));
		}

		#[test]
		fn rejects_foreign_algorithm() {
			let key = TestKey::insecure_fixed_signing();
			let mut cert = TestCertificate::self_signed(&key);
			// The identifiers agree on an algorithm that the default policy
			// refuses.
			cert.signature_algorithm.oid = SIGNER_ECDSA_WITH_SHA256;
			cert.tbs_certificate.signature.oid = SIGNER_ECDSA_WITH_SHA256;
			assert!(matches!(
				verify(&key, &cert),
				Err(CertificateValidationError::UnsupportedAlgorithm(_))
			));
		}

		/// [`test_cert`] with the extension `oid` twice.
		fn with_repeated(oid: &str) -> Certificate {
			let extension = TestCertificate::opaque_extension(oid, false);
			let cert = TestCertificate::with_extension(test_cert(), extension.clone());
			TestCertificate::with_extension(cert, extension)
		}

		/// [`test_cert`] with `nameConstraints`, which the crate does not
		/// process, as a critical extension.
		fn with_unknown_critical() -> Certificate {
			let extension = TestCertificate::opaque_extension("2.5.29.30", true);
			TestCertificate::with_extension(test_cert(), extension)
		}

		/// The validator refuses an anchor that repeats an extension, so the
		/// anchor match does not stand in for the extension rules
		/// (RFC 5280 §4.2).
		#[test]
		fn evaluate_refuses_an_anchor_that_repeats_an_extension() {
			let cert = with_repeated("2.5.29.30");
			let validator = DirectTrustValidator::default().with_trust_chain([cert.clone()]);

			let refused = validator.evaluate(&cert);
			assert!(matches!(refused, Err(CertificateValidationError::DuplicateExtension(_))));
		}

		#[test]
		fn evaluate_refuses_an_anchor_with_an_unknown_critical_extension() {
			let cert = with_unknown_critical();
			let validator = DirectTrustValidator::default().with_trust_chain([cert.clone()]);

			let refused = validator.evaluate(&cert);
			assert!(matches!(
				refused,
				Err(CertificateValidationError::UnprocessedCriticalExtension(_))
			));
		}

		#[test]
		fn verify_refuses_a_certificate_that_repeats_an_extension() {
			let key = TestKey::insecure_fixed_signing();
			let refused = verify(&key, &with_repeated("2.5.29.30"));
			assert!(matches!(refused, Err(CertificateValidationError::DuplicateExtension(_))));
		}

		#[test]
		fn verify_refuses_a_certificate_with_an_unknown_critical_extension() {
			let key = TestKey::insecure_fixed_signing();
			let refused = verify(&key, &with_unknown_critical());
			assert!(matches!(
				refused,
				Err(CertificateValidationError::UnprocessedCriticalExtension(_))
			));
		}
	}
}
