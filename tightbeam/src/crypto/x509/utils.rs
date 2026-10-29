//! X.509 certificate fingerprints, SubjectKeyIdentifiers, and certificate
//! checks.

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::collections::BTreeSet;
#[cfg(feature = "std")]
use std::sync::Arc;

use core::fmt::{self, Debug, Formatter};
use core::hash::{Hash, Hasher};
use core::time::Duration;

use crate::asn1::admission::DerAdmission;
use crate::clock::Clock;
use crate::cms::cert::IssuerAndSerialNumber;
use crate::cms::enveloped_data::RecipientIdentifier;
use crate::cms::signed_data::SignerIdentifier;
use crate::crypto::common::Output;
use crate::crypto::hash::{Digest, DigestWriter, OutputSizeUser};
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::ext::pkix::{
	BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, NameConstraints, SubjectAltName, SubjectKeyIdentifier,
};
use crate::crypto::x509::Certificate;
use crate::der::asn1::{GeneralizedTime, ObjectIdentifier, OctetString, OctetStringRef};
use crate::der::oid::db::rfc5280::ANY_EXTENDED_KEY_USAGE;
use crate::der::oid::AssociatedOid;
use crate::der::{Decode, Encode, Reader};
use crate::error::ReceivedExpectedError;
use crate::x509::certificate::{CertificateInner, Profile};
use crate::x509::serial_number::SerialNumber;

#[cfg(any(host_clock, feature = "time"))]
use crate::clock::UnixMillis;
#[cfg(feature = "secp256k1")]
use crate::spki::SubjectPublicKeyInfoOwned;

/// A certificate fingerprint bound to the digest that produced it, as wide
/// as the output of that digest.
///
/// [`Fingerprint::from_certificate`] digests the certificate DER under `D`.
/// [`Fingerprint::try_from`] reads a fingerprint an operator configured, and
/// refuses one of another width, so a list under SHA-384 or SHA-512 names
/// its entries at the width of its digest.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::hash::Sha3_256;
/// use tightbeam::crypto::x509::error::CertificateValidationError;
/// use tightbeam::crypto::x509::utils::Fingerprint;
/// use tightbeam::testing::{TestCertificate, TestKey};
///
/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
/// let fingerprint = Fingerprint::<Sha3_256>::from_certificate(&certificate)?;
///
/// let configured = Fingerprint::<Sha3_256>::try_from(fingerprint.as_slice())?;
/// assert_eq!(configured, fingerprint);
///
/// let short = Fingerprint::<Sha3_256>::try_from(&[0u8; 31][..]);
/// assert!(matches!(short, Err(CertificateValidationError::FingerprintLength(_))));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Fingerprint<D: OutputSizeUser> {
	bytes: Output<D>,
}

/// A fingerprint copies wherever its digest output copies, which holds for
/// the output of every digest.
impl<D: OutputSizeUser> Copy for Fingerprint<D> where Output<D>: Copy {}

impl<D: OutputSizeUser> Clone for Fingerprint<D> {
	fn clone(&self) -> Self {
		Self { bytes: self.bytes.clone() }
	}
}

impl<D: OutputSizeUser> Debug for Fingerprint<D> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Fingerprint").field("bytes", &self.bytes).finish()
	}
}

impl<D: OutputSizeUser> PartialEq for Fingerprint<D> {
	fn eq(&self, other: &Self) -> bool {
		self.bytes == other.bytes
	}
}

impl<D: OutputSizeUser> Eq for Fingerprint<D> {}

impl<D: OutputSizeUser> Hash for Fingerprint<D> {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.bytes.as_slice().hash(state);
	}
}

impl<D: OutputSizeUser> Fingerprint<D> {
	/// Return the fingerprint bytes.
	pub fn as_slice(&self) -> &[u8] {
		&self.bytes
	}
}

impl<D: Digest> Fingerprint<D> {
	/// Digest the certificate DER and bind the result to `D`.
	///
	/// The encoder streams the certificate DER into the digest as it writes.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::EncodingError`] -- the certificate fails to DER-encode.
	pub fn from_certificate(cert: &Certificate) -> Result<Self, CertificateValidationError> {
		let mut digest = DigestWriter(D::new());
		cert.encode(&mut digest)?;

		let bytes = digest.0.finalize();
		Ok(Self { bytes })
	}
}

impl<D: OutputSizeUser> TryFrom<&[u8]> for Fingerprint<D> {
	type Error = CertificateValidationError;

	/// Read `bytes` as a fingerprint under `D`.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::FingerprintLength`] -- `bytes` differs
	///   in width from the output of `D`, so it names no certificate.
	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let width = ReceivedExpectedError { received: bytes.len(), expected: D::output_size() };
		let read = Output::<D>::from_exact_iter(bytes.iter().copied());

		let bytes = read.ok_or(CertificateValidationError::FingerprintLength(width))?;
		Ok(Self { bytes })
	}
}

/// A 20-octet key identifier by RFC 7093 §2 method 1: the leftmost 160 bits
/// of the SHA-256 hash of the `subjectPublicKey` BIT STRING value.
///
/// Every certificate the crate creates carries its key's identifier as its
/// `subjectKeyIdentifier`, and an issued one carries its issuer's as its
/// `authorityKeyIdentifier`.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Skid([u8; 20]);

impl Skid {
	/// Returns the RFC 7093 §2 method 1 identifier of `spki`'s public key.
	///
	/// The hash input is the BIT STRING value alone, without the tag, the
	/// length, and the unused-bits octet.
	#[cfg(feature = "secp256k1")]
	pub fn of_public_key(spki: &SubjectPublicKeyInfoOwned) -> Self {
		use k256::sha2::Sha256;

		let digest: [u8; 32] = Sha256::digest(spki.subject_public_key.raw_bytes()).into();
		let mut bytes = [0u8; 20];
		bytes.copy_from_slice(&digest[..20]);

		Self(bytes)
	}

	/// Read `bytes` as a SKID, or return `None` unless they are exactly 20
	/// octets.
	pub fn parse(bytes: impl AsRef<[u8]>) -> Option<Self> {
		let bytes: &[u8; 20] = bytes.as_ref().try_into().ok()?;
		Some(Self(*bytes))
	}

	/// Return the SKID bytes.
	pub fn as_bytes(&self) -> &[u8; 20] {
		&self.0
	}
}

/// A SKID as the `subjectKeyIdentifier` extension value (RFC 5280 §4.2.1.2).
///
/// # Errors
///
/// - [`der::Error`] -- the 20 SKID bytes do not fit an `OCTET STRING`, which
///   the `der` length rules make unreachable here.
impl TryFrom<Skid> for SubjectKeyIdentifier {
	type Error = crate::der::Error;

	fn try_from(skid: Skid) -> Result<Self, Self::Error> {
		let octets = OctetString::new(skid.as_bytes().as_slice())?;
		Ok(SubjectKeyIdentifier::from(octets))
	}
}

/// The `subjectKeyIdentifier` extension (RFC 5280 §4.2.1.2), read in place.
///
/// [`CertificateExt::is_named_by`] and the trust store each read the value
/// through it, so a reader of the identifier borrows the certificate.
pub(crate) struct SubjectKeyIdentifierRef<'a>(pub(crate) OctetStringRef<'a>);

impl AssociatedOid for SubjectKeyIdentifierRef<'_> {
	const OID: ObjectIdentifier = SubjectKeyIdentifier::OID;
}

impl<'a> Decode<'a> for SubjectKeyIdentifierRef<'a> {
	fn decode<R: Reader<'a>>(reader: &mut R) -> crate::der::Result<Self> {
		OctetStringRef::decode(reader).map(Self)
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

/// The certificate checks this crate runs before it trusts a peer.
///
/// The `x509-cert` crate defines `Certificate`, so the checks are trait
/// methods that a caller calls on the certificate itself.
pub trait CertificateExt {
	/// Validate certificate expiry (`not_before <= now <= not_after`).
	///
	/// It runs the validity-period check of RFC 5280 §6.1.3(a)(2) over the
	/// `Validity` field (§4.1.2.5) and covers temporal validity alone.
	/// Signature and trust chains belong to the
	/// [`CertificateValidation`](super::policy::CertificateValidation) trait.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::NotYetValid`] -- the current time is before `not_before`.
	/// - [`CertificateValidationError::Expired`] -- the current time is after `not_after`.
	/// - [`CertificateValidationError::InvalidTimestamp`] -- the build carries
	///   no clock, so a higher layer owns temporal validation, or the clock
	///   reading does not convert to a certificate time.
	///
	/// # Sources
	///
	/// - RFC 5280 §6.1.3, basic certificate processing:
	///   <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.3>
	fn validate_expiry(&self) -> Result<(), CertificateValidationError>;

	/// Validate expiry against a caller-supplied Unix timestamp.
	///
	/// It runs the comparison of [`CertificateExt::validate_expiry`] with
	/// `now_unix` in place of the local clock. A path that already knows the
	/// time, such as receipt verification, uses it so the two cannot diverge.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::NotYetValid`] -- `now_unix` is before `not_before`.
	/// - [`CertificateValidationError::Expired`] -- `now_unix` is after `not_after`.
	/// - [`CertificateValidationError::InvalidTimestamp`] -- `now_unix` does
	///   not convert to a certificate time.
	fn validate_expiry_at(&self, now_unix: u64) -> Result<(), CertificateValidationError>;

	/// Enforce algorithm-identifier consistency within the certificate.
	///
	/// Per RFC 5280 §4.1.1.2, the outer `signatureAlgorithm` field MUST carry
	/// the same algorithm identifier (OID and parameters) as
	/// `tbsCertificate.signature` (§4.1.2.3).
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::AlgorithmMismatch`] -- the two identifiers disagree.
	///
	/// # Sources
	///
	/// - RFC 5280 §4.1.1.2, signatureAlgorithm:
	///   <https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2>
	fn ensure_signature_algorithm_consistency(&self) -> Result<(), CertificateValidationError>;

	/// Decode a typed X.509 extension by its associated OID, if present.
	///
	/// It decodes the `extnValue` of the extension (RFC 5280 §4.2) whose
	/// `extnID` is the [`AssociatedOid`] of `T`, or returns `Ok(None)` when the
	/// certificate carries none. A type that borrows, such as one over
	/// `OctetStringRef`, reads the value in place.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::DuplicateExtension`] -- the certificate carries the extension twice.
	/// - [`CertificateValidationError::EncodingError`] -- the extension's
	///   `extnValue` fails to decode, or a SET in it holds its elements out of
	///   DER order.
	///
	/// # Sources
	///
	/// - RFC 5280 §4.2, certificate extensions: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2>
	fn extension<'a, T>(&'a self) -> Result<Option<T>, CertificateValidationError>
	where
		T: AssociatedOid + Decode<'a>;

	/// The CMS `SignerIdentifier` that names this certificate
	/// (RFC 5652 §5.3).
	///
	/// It is the `subjectKeyIdentifier` extension value when the certificate
	/// carries one, and the issuer and serial number when it carries none.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::EncodingError`] -- the extension value
	///   or the serial number fails to decode.
	fn signer_identifier(&self) -> Result<SignerIdentifier, CertificateValidationError>;

	/// The CMS `RecipientIdentifier` that names this certificate
	/// (RFC 9629 §3), under the rule of [`Self::signer_identifier`].
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::EncodingError`] -- the extension value
	///   or the serial number fails to decode.
	fn recipient_identifier(&self) -> Result<RecipientIdentifier, CertificateValidationError>;

	/// Whether `sid` names this certificate: a `subjectKeyIdentifier` form by
	/// the value of this certificate's extension, an issuer-and-serial form
	/// by its issuer and serial number (RFC 5652 §5.3). It compares the
	/// extension value in place.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::EncodingError`] -- the extension value fails to decode.
	fn is_named_by(&self, sid: &SignerIdentifier) -> Result<bool, CertificateValidationError>;

	/// Refuse this certificate unless its `keyUsage` extension is present and
	/// asserts `usage` (RFC 5280 §4.2.1.3). For `keyAgreement`, the
	/// extension must also leave out `decipherOnly`, which restricts the key
	/// to decipherment.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::MissingKeyUsage`] -- the extension is absent, or it lacks `usage`.
	/// - [`CertificateValidationError::ExcludedKeyUsage`] -- `usage` is
	///   `keyAgreement`, and `decipherOnly` is asserted.
	/// - [`CertificateValidationError::DuplicateExtension`] -- the extension repeats.
	/// - [`CertificateValidationError::EncodingError`] -- the extension value fails to decode.
	fn require_key_usage(&self, usage: KeyUsages) -> Result<(), CertificateValidationError>;

	/// Refuse this certificate when it carries more than one instance of an
	/// extension, which RFC 5280 §4.2 forbids.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::DuplicateExtension`] -- an extension repeats.
	fn ensure_unique_extensions(&self) -> Result<(), CertificateValidationError>;

	/// Refuse this certificate when it bears a critical extension the crate
	/// does not process (RFC 5280 §4.2, §6.1.3(f)).
	///
	/// The processed extensions are `basicConstraints` (§4.2.1.9), `keyUsage`
	/// (§4.2.1.3), `extendedKeyUsage` (§4.2.1.12), and `subjectAltName`
	/// (§4.2.1.6). Colony membership reads the URI of a `subjectAltName`,
	/// which §4.1.2.6 marks critical when the subject is empty.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::UnprocessedCriticalExtension`] -- a
	///   critical extension is outside the processed set.
	fn ensure_critical_extensions_processed(&self) -> Result<(), CertificateValidationError>;

	/// Refuse this certificate when it carries a `nameConstraints` extension
	/// (RFC 5280 §4.2.1.10), critical or not.
	///
	/// RFC 5280 §6.1.4(g) applies the extension whatever its criticality,
	/// and name constraints stay out of the scope of the store's path
	/// validation, so a certificate that states one fails closed.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::NameConstraintsUnapplied`] -- the
	///   certificate carries a `nameConstraints` extension.
	fn ensure_no_name_constraints(&self) -> Result<(), CertificateValidationError>;

	/// Refuse this certificate for a use whose `keyUsage` bit is `usage`. Every
	/// admission of a certificate for a use runs these checks, in order:
	///
	/// 1. No extension repeats, and every critical extension is processed (RFC 5280 §4.2).
	/// 2. The `keyUsage` extension is present and admits `usage` (RFC 5280 §4.2.1.3).
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::DuplicateExtension`] -- an extension repeats.
	/// - [`CertificateValidationError::UnprocessedCriticalExtension`] -- a
	///   critical extension is outside the processed set.
	/// - The errors of [`CertificateExt::require_key_usage`].
	fn require_use(&self, usage: KeyUsages) -> Result<(), CertificateValidationError>;

	/// Refuse this certificate for a role whose key purpose is `purpose`
	/// (RFC 5280 §4.2.1.12). A certificate with no `extendedKeyUsage`, or one
	/// that names `anyExtendedKeyUsage`, serves every role.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::ExcludedKeyPurpose`] --
	///   `extendedKeyUsage` names neither `purpose` nor `anyExtendedKeyUsage`.
	/// - [`CertificateValidationError::DuplicateExtension`] -- the extension repeats.
	/// - [`CertificateValidationError::EncodingError`] -- the extension value fails to decode.
	fn require_purpose(&self, purpose: ObjectIdentifier) -> Result<(), CertificateValidationError>;
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

	/// Runs the check at the reading of [`UnixMillis::now`], so certificate
	/// validity reads the same clock as every other time decision in the
	/// crate, on each target that has one.
	#[cfg(any(host_clock, feature = "time"))]
	fn validate_expiry(&self) -> Result<(), CertificateValidationError> {
		let now = UnixMillis::now();
		let now_unix = Duration::from_millis(now.get()).as_secs();
		self.validate_expiry_at(now_unix)
	}

	/// A build with no clock has no current time, so every certificate fails
	/// closed with [`CertificateValidationError::InvalidTimestamp`].
	#[cfg(all(not(feature = "time"), not(host_clock)))]
	fn validate_expiry(&self) -> Result<(), CertificateValidationError> {
		Err(CertificateValidationError::InvalidTimestamp)
	}

	/// Enforce algorithm-identifier consistency within a certificate.
	///
	/// [`CertificateExt::ensure_signature_algorithm_consistency`] owns the
	/// RFC 5280 §4.1.1.2 contract.
	fn ensure_signature_algorithm_consistency(&self) -> Result<(), CertificateValidationError> {
		if self.signature_algorithm != self.tbs_certificate.signature {
			return Err(CertificateValidationError::AlgorithmMismatch);
		}

		Ok(())
	}

	/// Decode a typed X.509 extension by its associated OID, if present.
	///
	/// [`CertificateExt::extension`] owns the RFC 5280 §4.2 contract.
	fn extension<'a, T>(&'a self) -> Result<Option<T>, CertificateValidationError>
	where
		T: AssociatedOid + Decode<'a>,
	{
		let Some(extensions) = self.tbs_certificate.extensions.as_ref() else {
			return Ok(None);
		};

		let mut matching = extensions.iter().filter(|extension| extension.extn_id == T::OID);
		let Some(extension) = matching.next() else {
			return Ok(None);
		};
		if matching.next().is_some() {
			return Err(CertificateValidationError::DuplicateExtension(T::OID));
		}

		let value = extension.extn_value.as_bytes();
		Ok(Some(DerAdmission::SetOrder.decode(value)?))
	}

	/// Name this certificate as a CMS signer.
	///
	/// [`CertificateExt::signer_identifier`] owns the RFC 5652 §5.3 contract.
	fn signer_identifier(&self) -> Result<SignerIdentifier, CertificateValidationError> {
		if let Some(key_identifier) = self.extension::<SubjectKeyIdentifier>()? {
			return Ok(SignerIdentifier::SubjectKeyIdentifier(key_identifier));
		}

		let issuer = self.tbs_certificate.issuer.clone();
		let serial_number = SerialNumber::new(self.tbs_certificate.serial_number.as_bytes())?;
		let named = IssuerAndSerialNumber { issuer, serial_number };
		Ok(SignerIdentifier::IssuerAndSerialNumber(named))
	}

	/// Name this certificate as a CMS recipient.
	///
	/// [`CertificateExt::recipient_identifier`] owns the RFC 9629 §3 contract.
	fn recipient_identifier(&self) -> Result<RecipientIdentifier, CertificateValidationError> {
		let sid = self.signer_identifier()?;
		Ok(recipient_identifier_of(&sid))
	}

	/// Match `sid` against this certificate.
	///
	/// [`CertificateExt::is_named_by`] owns the RFC 5652 §5.3 contract.
	fn is_named_by(&self, sid: &SignerIdentifier) -> Result<bool, CertificateValidationError> {
		match sid {
			SignerIdentifier::IssuerAndSerialNumber(named) => {
				let tbs = &self.tbs_certificate;
				Ok(tbs.issuer == named.issuer && tbs.serial_number.as_bytes() == named.serial_number.as_bytes())
			}
			SignerIdentifier::SubjectKeyIdentifier(named) => {
				let own = self.extension::<SubjectKeyIdentifierRef<'_>>()?;
				Ok(own.is_some_and(|own| own.0.as_bytes() == named.0.as_bytes()))
			}
		}
	}

	/// Check `usage` against the `keyUsage` this certificate asserts.
	///
	/// [`CertificateExt::require_key_usage`] owns the RFC 5280 §4.2.1.3
	/// contract.
	fn require_key_usage(&self, usage: KeyUsages) -> Result<(), CertificateValidationError> {
		let Some(KeyUsage(asserted)) = self.extension::<KeyUsage>()? else {
			return Err(CertificateValidationError::MissingKeyUsage(usage));
		};
		if !asserted.contains(usage) {
			return Err(CertificateValidationError::MissingKeyUsage(usage));
		}
		if usage == KeyUsages::KeyAgreement && asserted.contains(KeyUsages::DecipherOnly) {
			return Err(CertificateValidationError::ExcludedKeyUsage(KeyUsages::DecipherOnly));
		}

		Ok(())
	}

	/// Find the first extension that an earlier one repeats, in O(n log n)
	/// over the extension count, which the certificate's sender chooses.
	///
	/// [`CertificateExt::ensure_unique_extensions`] owns the RFC 5280 §4.2
	/// contract.
	fn ensure_unique_extensions(&self) -> Result<(), CertificateValidationError> {
		let Some(extensions) = self.tbs_certificate.extensions.as_ref() else {
			return Ok(());
		};

		let mut seen = BTreeSet::new();
		let repeated = extensions.iter().find(|extension| !seen.insert(extension.extn_id));
		match repeated {
			Some(extension) => Err(CertificateValidationError::DuplicateExtension(extension.extn_id)),
			None => Ok(()),
		}
	}

	/// Find the first critical extension outside the processed set.
	///
	/// [`CertificateExt::ensure_critical_extensions_processed`] owns the
	/// RFC 5280 §4.2 contract.
	fn ensure_critical_extensions_processed(&self) -> Result<(), CertificateValidationError> {
		let Some(extensions) = self.tbs_certificate.extensions.as_ref() else {
			return Ok(());
		};

		let processed = [BasicConstraints::OID, KeyUsage::OID, ExtendedKeyUsage::OID, SubjectAltName::OID];
		let unprocessed = extensions
			.iter()
			.find(|extension| extension.critical && !processed.contains(&extension.extn_id));
		match unprocessed {
			Some(extension) => Err(CertificateValidationError::UnprocessedCriticalExtension(extension.extn_id)),
			None => Ok(()),
		}
	}

	/// Find a `nameConstraints` extension of either criticality.
	///
	/// [`CertificateExt::ensure_no_name_constraints`] owns the
	/// RFC 5280 §6.1.4(g) contract.
	fn ensure_no_name_constraints(&self) -> Result<(), CertificateValidationError> {
		let Some(extensions) = self.tbs_certificate.extensions.as_ref() else {
			return Ok(());
		};

		let constrained = extensions.iter().any(|extension| extension.extn_id == NameConstraints::OID);
		if constrained {
			return Err(CertificateValidationError::NameConstraintsUnapplied);
		}

		Ok(())
	}

	/// Run the checks of one use, in the order the contract lists them.
	///
	/// [`CertificateExt::require_use`] owns the RFC 5280 §4.2 and §4.2.1.3
	/// contract.
	fn require_use(&self, usage: KeyUsages) -> Result<(), CertificateValidationError> {
		self.ensure_unique_extensions()?;
		self.ensure_critical_extensions_processed()?;
		self.require_key_usage(usage)
	}

	/// Check `purpose` against the key purposes this certificate names.
	///
	/// [`CertificateExt::require_purpose`] owns the RFC 5280 §4.2.1.12
	/// contract.
	fn require_purpose(&self, purpose: ObjectIdentifier) -> Result<(), CertificateValidationError> {
		let Some(ExtendedKeyUsage(named)) = self.extension::<ExtendedKeyUsage>()? else {
			return Ok(());
		};

		let admitted = named.iter().any(|named| *named == purpose || *named == ANY_EXTENDED_KEY_USAGE);
		if !admitted {
			return Err(CertificateValidationError::ExcludedKeyPurpose);
		}

		Ok(())
	}
}

/// The clock that a validity check reads: the clock its owner sets, or the
/// crate clock ([`UnixMillis::now`]) when the owner sets none.
///
/// `C` is the clock as its owner holds it:
///
/// - A validator and a trust store are `Send + Sync`, so each holds `dyn Clock + Send + Sync`.
/// - A handshake holds the clock of its endpoint, `dyn Clock`.
///
/// [`UnixMillis::now`]: crate::clock::UnixMillis::now
pub(crate) struct ValidityClock<C: ?Sized = dyn Clock + Send + Sync>(Option<Arc<C>>);

impl<C: ?Sized> ValidityClock<C> {
	/// The checks on the crate clock, which an owner that sets no clock reads.
	pub(crate) const CRATE: Self = Self(None);
}

impl<C: Clock + ?Sized> ValidityClock<C> {
	/// The checks on `clock`.
	pub(crate) fn new(clock: Arc<C>) -> Self {
		Self(Some(clock))
	}

	/// Refuse `cert` outside its validity period at the reading of this clock
	/// (RFC 5280 §6.1.3(a)(2)).
	///
	/// # Errors
	///
	/// - The errors of [`CertificateExt::validate_expiry_at`], or of
	///   [`CertificateExt::validate_expiry`] when no clock is set.
	pub(crate) fn admits(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		let Some(clock) = self.0.as_ref() else {
			return cert.validate_expiry();
		};

		let now = Duration::from_millis(clock.unix().get()).as_secs();
		cert.validate_expiry_at(now)
	}
}

impl<C: ?Sized> Clone for ValidityClock<C> {
	fn clone(&self) -> Self {
		Self(self.0.as_ref().map(Arc::clone))
	}
}

impl<C: ?Sized> Default for ValidityClock<C> {
	fn default() -> Self {
		Self::CRATE
	}
}

impl<C: Clock + ?Sized> Debug for ValidityClock<C> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("ValidityClock").field(&self.0).finish()
	}
}

/// The CMS `RecipientIdentifier` that names the certificate `sid` names.
///
/// A `rid` and a `sid` share their two arms (RFC 9629 §3, RFC 5652 §5.3), so
/// one rule names a certificate as a signer and as a recipient.
pub(crate) fn recipient_identifier_of(sid: &SignerIdentifier) -> RecipientIdentifier {
	match sid {
		SignerIdentifier::SubjectKeyIdentifier(skid) => RecipientIdentifier::SubjectKeyIdentifier(skid.clone()),
		SignerIdentifier::IssuerAndSerialNumber(issuer) => RecipientIdentifier::IssuerAndSerialNumber(issuer.clone()),
	}
}

#[cfg(test)]
mod tests {
	use super::{CertificateExt, Fingerprint, Skid};
	use crate::asn1::admission::fixtures::{tlv, DESCENDING_LEN};
	use crate::crypto::hash::{Digest, Sha3_256};
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::crypto::x509::error::CertificateValidationError::EncodingError;
	use crate::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use crate::crypto::x509::Certificate;
	use crate::der::asn1::OctetString;
	use crate::der::oid::AssociatedOid;
	use crate::der::{Encode, ErrorKind, Tag, TagNumber};
	use crate::testing::{TestCertificate, TestKey};
	use crate::x509::ext::pkix::{IssuerAltName, SubjectKeyIdentifier};
	use crate::x509::ext::Extension;

	/// The self-signed test certificate with an `issuerAltName` extension
	/// around `value`. The lookup of an extension reads the extensions alone,
	/// so the stale signature leaves the lookup as it is.
	fn with_issuer_alt_name(value: Vec<u8>) -> Certificate {
		let mut certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let extn_value = OctetString::new(value).expect("a test value fits an OCTET STRING");
		let extension = Extension { extn_id: IssuerAltName::OID, critical: false, extn_value };
		let extensions = certificate.tbs_certificate.extensions.get_or_insert_with(Vec::new);
		extensions.push(extension);
		certificate
	}

	/// The `GeneralNames` of one `directoryName` whose one RDN holds
	/// [`DESCENDING_LEN`] common names in descending order, which `der`
	/// decodes and sorts.
	fn descending_general_names() -> Vec<u8> {
		let common_name = tlv(Tag::ObjectIdentifier, &[0x55, 0x04, 0x03]);
		let entries = (0..DESCENDING_LEN).rev().map(|value| {
			let value = tlv(Tag::OctetString, &value.to_be_bytes());
			tlv(Tag::Sequence, &[common_name.as_slice(), &value].concat())
		});
		let rdn = tlv(Tag::Set, &entries.collect::<Vec<_>>().concat());
		let directory_name = Tag::ContextSpecific { constructed: true, number: TagNumber::N4 };
		tlv(Tag::Sequence, &tlv(directory_name, &tlv(Tag::Sequence, &rdn)))
	}

	/// The one decoder of extension values runs the DER admission on the
	/// value before the name in it decodes and sorts its RDN, so it refuses a
	/// SET out of DER order.
	#[test]
	fn an_extension_of_a_descending_set_is_refused() {
		let certificate = with_issuer_alt_name(descending_general_names());

		let refused = certificate.extension::<IssuerAltName>();
		let set_ordering = matches!(refused, Err(EncodingError(error)) if error.kind() == ErrorKind::SetOrdering);
		assert!(set_ordering);
	}

	/// A fingerprint that the encoder streams into the digest equals the
	/// digest of the whole DER, which the encoder writes outside the code
	/// under test.
	#[test]
	fn a_fingerprint_is_the_digest_of_the_certificate_der() -> Result<(), CertificateValidationError> {
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let expected = Sha3_256::digest(certificate.to_der()?);

		let fingerprint = Fingerprint::<Sha3_256>::from_certificate(&certificate)?;
		assert_eq!(fingerprint.as_slice(), expected.as_slice());
		Ok(())
	}

	/// The extension value a SKID converts to carries the SKID bytes whole,
	/// so a certificate the crate creates holds the 20 bytes its key names.
	#[test]
	fn a_skid_converts_to_the_extension_value_that_carries_it() -> Result<(), crate::der::Error> {
		let skid = Skid::parse([0x5au8; 20]).ok_or(crate::der::Tag::OctetString.value_error())?;
		let identifier = SubjectKeyIdentifier::try_from(skid)?;
		assert_eq!(identifier.0.as_bytes(), skid.as_bytes());
		Ok(())
	}

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
		let validator = ExpiryValidator::default();

		// This certificate expired on August 17, 2019, so the validator rejects
		// it.
		let result = validator.evaluate(&expired_cert);
		assert!(result.is_err(), "Expired certificate should be rejected");

		match result {
			Err(CertificateValidationError::Expired) => {
				// This arm is the expected error.
			}
			other => panic!("Expected Expired error, got: {other:?}"),
		}
	}

	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509", feature = "std"))]
	mod certificate_extension {
		use crate::crypto::x509::error::CertificateValidationError;
		use crate::crypto::x509::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
		use crate::crypto::x509::utils::CertificateExt;
		use crate::der::oid::db::rfc5280::{ANY_EXTENDED_KEY_USAGE, ID_KP_CLIENT_AUTH, ID_KP_TIME_STAMPING};
		use crate::der::oid::AssociatedOid;
		use crate::testing::fixtures::TestCertificate;
		use crate::testing::TestKey;
		use crate::x509::Certificate;

		/// A self-signed certificate of the fixed test key, whose `keyUsage`
		/// carries `digitalSignature` and `keyAgreement`.
		fn both_uses() -> Certificate {
			TestCertificate::self_signed(&TestKey::insecure_fixed_signing())
		}

		/// [`both_uses`] with an `extendedKeyUsage` of `purposes` alone.
		fn with_purposes(purposes: Vec<crate::der::asn1::ObjectIdentifier>) -> Certificate {
			TestCertificate::with_key_purposes(both_uses(), purposes)
		}

		#[test]
		fn rejects_unknown_critical_extension() {
			// nameConstraints (2.5.29.30) sits outside the processed set.
			let mut cert = both_uses();
			cert.tbs_certificate.extensions = Some(vec![TestCertificate::opaque_extension("2.5.29.30", true)]);
			assert!(matches!(
				cert.ensure_critical_extensions_processed(),
				Err(CertificateValidationError::UnprocessedCriticalExtension(_))
			));
		}

		#[test]
		fn accepts_unknown_noncritical_extension() {
			let mut cert = both_uses();
			cert.tbs_certificate.extensions = Some(vec![TestCertificate::opaque_extension("2.5.29.30", false)]);
			assert!(cert.ensure_critical_extensions_processed().is_ok());
		}

		#[test]
		fn accepts_processed_critical_extensions() {
			let mut cert = both_uses();
			cert.tbs_certificate.extensions = Some(TestCertificate::ca_extensions(true, true, None));
			assert!(cert.ensure_critical_extensions_processed().is_ok());
		}

		/// The crate processes `extendedKeyUsage`, so it admits a critical one
		/// (RFC 5280 §4.2.1.12).
		#[test]
		fn accepts_a_critical_extended_key_usage() {
			let extension = TestCertificate::extension(&ExtendedKeyUsage(vec![ID_KP_CLIENT_AUTH]), true);
			let cert = TestCertificate::with_extension(both_uses(), extension);
			assert!(cert.ensure_critical_extensions_processed().is_ok());
		}

		/// The uniqueness check refuses a certificate with two `keyUsage`
		/// extensions (RFC 5280 §4.2).
		#[test]
		fn rejects_a_repeated_extension() {
			let mut cert = both_uses();
			let key_usage = TestCertificate::opaque_extension("2.5.29.15", true);
			let repeated = vec![key_usage.clone(), key_usage];

			cert.tbs_certificate.extensions = Some(repeated);

			let refused = cert.ensure_unique_extensions();
			assert!(matches!(refused, Err(CertificateValidationError::DuplicateExtension(_))));
		}

		#[test]
		fn accepts_one_instance_of_each_extension() {
			let cert = both_uses();
			assert!(cert.ensure_unique_extensions().is_ok());
		}

		#[test]
		fn accepts_critical_subject_alt_name() {
			// Colony membership reads subjectAltName (2.5.29.17), which
			// RFC 5280 §4.1.2.6 marks critical when the subject DN is empty.
			let mut cert = both_uses();
			cert.tbs_certificate.extensions = Some(vec![TestCertificate::opaque_extension("2.5.29.17", true)]);
			assert!(cert.ensure_critical_extensions_processed().is_ok());
		}

		/// The read of one extension refuses a certificate that carries it
		/// twice, so no reader takes the first of two values (RFC 5280 §4.2).
		#[test]
		fn reading_an_extension_carried_twice_is_refused() {
			let key_usage = KeyUsage(KeyUsages::DigitalSignature.into());
			let cert = TestCertificate::with_extension(both_uses(), TestCertificate::extension(&key_usage, true));

			let refused = cert.extension::<KeyUsage>();
			assert!(
				matches!(refused, Err(CertificateValidationError::DuplicateExtension(oid)) if oid == KeyUsage::OID)
			);
		}

		/// Each use admits a certificate whose `keyUsage` carries both bits.
		#[test]
		fn a_certificate_with_both_bits_is_admitted_for_signing() {
			assert!(both_uses().require_use(KeyUsages::DigitalSignature).is_ok());
		}

		#[test]
		fn a_certificate_with_both_bits_is_admitted_for_key_agreement() {
			assert!(both_uses().require_use(KeyUsages::KeyAgreement).is_ok());
		}

		/// The signing use refuses a certificate whose `keyUsage` carries
		/// `keyAgreement` alone.
		#[test]
		fn a_key_agreement_certificate_is_refused_for_signing() {
			let cert = TestCertificate::with_key_usage(both_uses(), KeyUsage(KeyUsages::KeyAgreement.into()));
			let refused = cert.require_use(KeyUsages::DigitalSignature);
			assert!(matches!(
				refused,
				Err(CertificateValidationError::MissingKeyUsage(KeyUsages::DigitalSignature))
			));
		}

		/// The key-agreement use refuses a certificate whose `keyUsage`
		/// carries `digitalSignature` alone.
		#[test]
		fn a_signing_certificate_is_refused_for_key_agreement() {
			let cert = TestCertificate::with_key_usage(both_uses(), KeyUsage(KeyUsages::DigitalSignature.into()));
			let refused = cert.require_use(KeyUsages::KeyAgreement);
			assert!(matches!(
				refused,
				Err(CertificateValidationError::MissingKeyUsage(KeyUsages::KeyAgreement))
			));
		}

		/// An `extendedKeyUsage` that omits a purpose refuses its role
		/// (RFC 5280 §4.2.1.12).
		#[test]
		fn a_purpose_the_extended_key_usage_omits_is_refused() {
			let cert = with_purposes(vec![ID_KP_TIME_STAMPING]);
			let refused = cert.require_purpose(ID_KP_CLIENT_AUTH);
			assert!(matches!(refused, Err(CertificateValidationError::ExcludedKeyPurpose)));
		}

		/// An `extendedKeyUsage` that names a purpose among others admits its
		/// role.
		#[test]
		fn a_purpose_the_extended_key_usage_names_is_admitted() {
			let cert = with_purposes(vec![ID_KP_TIME_STAMPING, ID_KP_CLIENT_AUTH]);
			assert!(cert.require_purpose(ID_KP_CLIENT_AUTH).is_ok());
		}

		/// `anyExtendedKeyUsage` admits every role (RFC 5280 §4.2.1.12).
		#[test]
		fn any_extended_key_usage_admits_the_role() {
			let cert = with_purposes(vec![ANY_EXTENDED_KEY_USAGE]);
			assert!(cert.require_purpose(ID_KP_CLIENT_AUTH).is_ok());
		}

		/// A certificate with no `extendedKeyUsage` serves every role.
		#[test]
		fn a_certificate_without_extended_key_usage_admits_the_role() {
			assert!(both_uses().require_purpose(ID_KP_CLIENT_AUTH).is_ok());
		}

		/// The use refuses a repeated extension before it reads `keyUsage`,
		/// so it refuses a certificate with no `keyUsage` for the repeat.
		#[test]
		fn a_use_refuses_a_repeated_extension() {
			let extension = TestCertificate::opaque_extension("2.5.29.30", false);
			let cert = TestCertificate::without_extension(both_uses(), KeyUsage::OID);
			let cert = TestCertificate::with_extension(cert, extension.clone());
			let cert = TestCertificate::with_extension(cert, extension);

			let refused = cert.require_use(KeyUsages::DigitalSignature);
			assert!(matches!(refused, Err(CertificateValidationError::DuplicateExtension(_))));
		}

		/// The use refuses a critical extension the crate does not process.
		#[test]
		fn a_use_refuses_an_unknown_critical_extension() {
			let extension = TestCertificate::opaque_extension("2.5.29.30", true);
			let cert = TestCertificate::with_extension(both_uses(), extension);

			let refused = cert.require_use(KeyUsages::KeyAgreement);
			assert!(matches!(
				refused,
				Err(CertificateValidationError::UnprocessedCriticalExtension(_))
			));
		}

		#[test]
		fn reads_basic_constraints() -> Result<(), Box<dyn core::error::Error>> {
			let chain = TestCertificate::insecure_fixed_chain()?;
			let basic_constraints = &chain
				.root
				.extension::<BasicConstraints>()?
				.ok_or(crate::testing::error::TestingError::InvariantViolated)?;
			assert!(basic_constraints.ca);
			Ok(())
		}

		#[test]
		fn absent_returns_none() -> Result<(), Box<dyn core::error::Error>> {
			let chain = TestCertificate::insecure_fixed_chain()?;
			assert!(&chain.leaf.extension::<BasicConstraints>()?.is_none());
			Ok(())
		}
	}
}
