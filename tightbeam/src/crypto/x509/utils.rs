//! X.509 certificate utility functions and helpers.

use core::fmt::{self, Debug, Formatter};
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;
use core::time::Duration;

use crate::cms::signed_data::SignerIdentifier;
use crate::crypto::hash::{Digest, Sha3_256, U32};
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::ext::pkix::SubjectKeyIdentifier;
use crate::crypto::x509::Certificate;
use crate::der::asn1::{GeneralizedTime, OctetString};
use crate::der::oid::AssociatedOid;
use crate::der::{DecodeOwned, Encode};
use crate::spki::EncodePublicKey;
use crate::x509::certificate::{CertificateInner, Profile};

/// A 32-byte certificate fingerprint bound to the digest that produced it.
///
/// [`Fingerprint::from_certificate`] digests the certificate DER under `D`.
pub struct Fingerprint<D> {
	bytes: [u8; 32],
	_digest: PhantomData<fn() -> D>,
}

impl<D> Copy for Fingerprint<D> {}

impl<D> Clone for Fingerprint<D> {
	fn clone(&self) -> Self {
		*self
	}
}

impl<D> Debug for Fingerprint<D> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Fingerprint").field("bytes", &self.bytes).finish()
	}
}

impl<D> PartialEq for Fingerprint<D> {
	fn eq(&self, other: &Self) -> bool {
		self.bytes == other.bytes
	}
}

impl<D> Eq for Fingerprint<D> {}

impl<D> Hash for Fingerprint<D> {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.bytes.hash(state);
	}
}

impl<D> Fingerprint<D> {
	/// The fingerprint bytes.
	pub fn as_slice(&self) -> &[u8] {
		&self.bytes
	}
}

impl<D> Fingerprint<D>
where
	D: Digest<OutputSize = U32>,
{
	/// Digest the certificate DER and bind the result to `D`.
	///
	/// # Errors
	///
	/// - DER encode failures from the certificate
	pub fn from_certificate(cert: &Certificate) -> Result<Self, CertificateValidationError> {
		let der_bytes = cert.to_der()?;
		let hash = D::digest(&der_bytes);

		let mut bytes = [0u8; 32];
		bytes.copy_from_slice(hash.as_ref());

		Ok(Self { bytes, _digest: PhantomData })
	}
}

/// The digest a tightbeam SubjectKeyIdentifier is taken from.
///
/// RFC 5280 leaves the derivation to the issuer, so the protocol fixes one:
/// every SKID this crate computes, indexes, or resolves is
/// `SHA3-256(SPKI)[..20]`. A signer and a trust store that chose their own
/// digests would never resolve each other.
pub type SkidDigest = Sha3_256;

/// The 20-byte SubjectKeyIdentifier truncation of a digest (RFC 5280).
///
/// [`Skid::of_public_key`] takes the window from a public key's digest.
/// [`Skid::parse`] reads an exact 20-byte window already on the wire.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Skid([u8; 20]);

impl Skid {
	/// The SubjectKeyIdentifier of a DER-encoded public key.
	///
	/// The digest is [`SkidDigest`], a protocol constant: a signer stamps
	/// this value into the `SignerInfo` it puts on the wire, and a trust
	/// store indexes by it, so neither side may choose its own digest.
	pub fn of_public_key(public_key_der: impl AsRef<[u8]>) -> Self {
		let digest: [u8; 32] = <SkidDigest as Digest>::digest(public_key_der.as_ref()).into();
		let mut bytes = [0u8; 20];
		bytes.copy_from_slice(&digest[..20]);

		Self(bytes)
	}

	/// Read a SKID that is already exactly 20 bytes.
	pub fn parse(bytes: impl AsRef<[u8]>) -> Option<Self> {
		let bytes: &[u8; 20] = bytes.as_ref().try_into().ok()?;
		Some(Self(*bytes))
	}

	/// The SKID bytes.
	pub fn as_bytes(&self) -> &[u8; 20] {
		&self.0
	}
}

#[macro_export]
macro_rules! pem {
	(
		$pem:literal
	) => {{
		use $crate::der::DecodePem;
		let cleaned_pem = $pem.lines().map(|line| line.trim()).collect::<Vec<_>>().join("\n");
		$crate::crypto::x509::Certificate::from_pem(cleaned_pem.as_bytes())
	}};
}

/// Certificate checks this crate runs before trusting a peer.
///
/// `Certificate` is defined in `x509-cert`, so these are trait methods
/// rather than inherent ones. Every check still reaches the certificate
/// through the certificate itself.
pub trait CertificateExt {
	/// Validate certificate expiry (`not_before <= now <= not_after`).
	/// Implements the validity-period check of RFC 5280 §6.1.3(a)(2) over
	/// the `Validity` field (§4.1.2.5):
	/// <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.3>.
	/// Temporal validity only. Signature and trust chains belong to the
	/// `CertificateValidation` trait.
	///
	/// # Errors
	/// - [`CertificateValidationError::NotYetValid`] before `not_before`
	/// - [`CertificateValidationError::Expired`] after `not_after`
	/// - [`CertificateValidationError::InvalidTimestamp`] when the build
	///   carries no clock, so a higher layer owns temporal validation
	fn validate_expiry(&self) -> Result<(), CertificateValidationError>;

	/// Validate expiry against a caller-supplied Unix timestamp.
	///
	/// The same comparison [`CertificateExt::validate_expiry`] runs, with
	/// `now_unix` in place of the local clock. A path that already knows
	/// the time, such as receipt verification, uses this so the two cannot
	/// diverge.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::NotYetValid`] before `not_before`
	/// - [`CertificateValidationError::Expired`] after `not_after`
	/// - [`CertificateValidationError::InvalidTimestamp`] when `now_unix`
	///   does not convert to a certificate time
	fn validate_expiry_at(&self, now_unix: u64) -> Result<(), CertificateValidationError>;

	/// Raw public key bytes from the certificate's SPKI.
	fn verifying_key_bytes(&self) -> &[u8];

	/// Enforce algorithm-identifier consistency within the certificate.
	/// RFC 5280 §4.1.1.2: the outer `signatureAlgorithm` field MUST carry
	/// the same algorithm identifier as `tbsCertificate.signature`
	/// (§4.1.2.3).
	/// <https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2>.
	///
	/// # Errors
	/// - [`CertificateValidationError::AlgorithmMismatch`] on disagreement
	fn ensure_signature_algorithm_consistency(&self) -> Result<(), CertificateValidationError>;

	/// Decode a typed X.509 extension by its associated OID, if present.
	/// Locates the extension (RFC 5280 §4.2) whose `extnID` matches the
	/// requested type's [`AssociatedOid`] and decodes its `extnValue`.
	/// `Ok(None)` when the certificate carries no such extension.
	///
	/// # Errors
	/// - Decode failures from the extension's `extnValue`
	fn extension<T>(&self) -> Result<Option<T>, CertificateValidationError>
	where
		T: AssociatedOid + DecodeOwned;
}

impl<P: Profile> CertificateExt for CertificateInner<P> {
	fn validate_expiry_at(&self, now_unix: u64) -> Result<(), CertificateValidationError> {
		let not_before = self.tbs_certificate.validity.not_before.to_unix_duration();
		let not_after = self.tbs_certificate.validity.not_after.to_unix_duration();
		let now_duration = GeneralizedTime::from_unix_duration(Duration::from_secs(now_unix))
			.map_err(|_| CertificateValidationError::InvalidTimestamp)?
			.to_unix_duration();

		if now_duration < not_before {
			return Err(CertificateValidationError::NotYetValid);
		}
		if now_duration > not_after {
			return Err(CertificateValidationError::Expired);
		}

		Ok(())
	}

	#[cfg(feature = "time")]
	fn validate_expiry(&self) -> Result<(), CertificateValidationError> {
		use crate::time::OffsetDateTime;

		let now = OffsetDateTime::now_utc().unix_timestamp();
		if now < 0 {
			return Err(CertificateValidationError::InvalidTimestamp);
		}

		self.validate_expiry_at(now as u64)
	}

	#[cfg(all(feature = "std", not(feature = "time")))]
	fn validate_expiry(&self) -> Result<(), CertificateValidationError> {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map_err(|_| CertificateValidationError::InvalidTimestamp)?;

		self.validate_expiry_at(now.as_secs())
	}

	#[cfg(all(not(feature = "std"), not(feature = "time")))]
	fn validate_expiry(&self) -> Result<(), CertificateValidationError> {
		Err(CertificateValidationError::InvalidTimestamp)
	}

	/// Raw `subjectPublicKey` bits, borrowed from the certificate.
	///
	/// The bits stay unparsed here. A profile turns them into a key of its
	/// own curve in `HandshakeVerifyingKey::verifying_key`.
	fn verifying_key_bytes(&self) -> &[u8] {
		self.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes()
	}

	/// Enforce algorithm-identifier consistency within a certificate.
	///
	/// RFC 5280 §4.1.1.2: the outer `signatureAlgorithm` field MUST contain the
	/// same algorithm identifier (OID and parameters) as `tbsCertificate.signature`
	/// (§4.1.2.3). <https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2>.
	fn ensure_signature_algorithm_consistency(&self) -> Result<(), CertificateValidationError> {
		if self.signature_algorithm != self.tbs_certificate.signature {
			return Err(CertificateValidationError::AlgorithmMismatch);
		}

		Ok(())
	}

	/// Decode a typed X.509 extension by its associated OID, if present.
	///
	/// Locates the certificate extension (RFC 5280 §4.2) whose `extnID` matches the
	/// requested type's [`AssociatedOid`] and decodes its `extnValue`. Returns
	/// `Ok(None)` when the certificate carries no such extension.
	/// <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2>.
	fn extension<T>(&self) -> Result<Option<T>, CertificateValidationError>
	where
		T: AssociatedOid + DecodeOwned,
	{
		let Some(extensions) = self.tbs_certificate.extensions.as_ref() else {
			return Ok(None);
		};

		for extension in extensions {
			if extension.extn_id == T::OID {
				return Ok(Some(T::from_der(extension.extn_value.as_bytes())?));
			}
		}

		Ok(None)
	}
}

/// Compute a SubjectKeyIdentifier-based SignerIdentifier from a verifying key.
///
/// This helper extracts the public key DER encoding, hashes it with the provided
/// digest algorithm, truncates to 20 bytes (RFC 5280 recommendation), and wraps
/// it in a SignerIdentifier::SubjectKeyIdentifier variant.
///
/// # Type Parameters
/// - `D`: Digest algorithm (e.g., SHA3-256)
/// - `V`: Verifying key type that can be DER-encoded
///
/// # Returns
/// `SignerIdentifier::SubjectKeyIdentifier` for use in CMS SignedData structures
///
/// # Example
/// ```ignore
/// use sha3::Sha3_256;
/// let signer_id = compute_signer_identifier(&verifying_key)?;
/// ```
pub fn compute_signer_identifier<V>(verifying_key: &V) -> Result<SignerIdentifier, CertificateValidationError>
where
	V: EncodePublicKey,
{
	let public_key_der = verifying_key.to_public_key_der()?;
	compute_signer_identifier_from_der(public_key_der.as_bytes())
}

/// Compute a SubjectKeyIdentifier-based SignerIdentifier from DER-encoded public key bytes.
///
/// This is the byte-based variant for use with `KeyProvider::to_public_key_bytes()`.
pub fn compute_signer_identifier_from_der(
	public_key_der: impl AsRef<[u8]>,
) -> Result<SignerIdentifier, CertificateValidationError> {
	let skid = Skid::of_public_key(public_key_der);
	let skid_octets = OctetString::new(skid.as_bytes().as_slice())?;
	let skid = SubjectKeyIdentifier::from(skid_octets);
	Ok(SignerIdentifier::SubjectKeyIdentifier(skid))
}

#[cfg(test)]
mod tests {
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use crate::testing::TestCertificate;

	#[test]
	fn test_pem_macro() {
		let cert = pem! {"
			-----BEGIN CERTIFICATE-----
			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
			-----END CERTIFICATE-----
		"};
		assert!(cert.is_ok());
	}

	#[test]
	fn test_expiry_validator_rejects_expired_cert() {
		let expired_cert = TestCertificate::expired();
		let validator = ExpiryValidator;

		// This certificate expired on August 17, 2019, so it should be rejected
		let result = validator.evaluate(&expired_cert);
		assert!(result.is_err(), "Expired certificate should be rejected");

		// Verify it's specifically an expiry error
		match result {
			Err(CertificateValidationError::Expired) => {
				// Expected error
			}
			other => panic!("Expected Expired error, got: {other:?}"),
		}
	}

	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509", feature = "std"))]
	mod certificate_extension {
		use crate::crypto::x509::ext::pkix::BasicConstraints;
		use crate::crypto::x509::utils::CertificateExt;
		use crate::testing::fixtures::TestCertificate;

		#[test]
		fn reads_basic_constraints() -> Result<(), Box<dyn core::error::Error>> {
			let chain = TestCertificate::chain()?;
			let basic_constraints = &chain
				.root
				.extension::<BasicConstraints>()?
				.ok_or(crate::testing::error::TestingError::InvariantViolated)?;
			assert!(basic_constraints.ca);
			Ok(())
		}

		#[test]
		fn absent_returns_none() -> Result<(), Box<dyn core::error::Error>> {
			let chain = TestCertificate::chain()?;
			assert!(&chain.leaf.extension::<BasicConstraints>()?.is_none());
			Ok(())
		}
	}
}
