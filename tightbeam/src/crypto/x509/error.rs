pub type Result<T> = core::result::Result<T, CertificateValidationError>;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::String;

use crate::Errorizable;

/// Errors that X.509 certificate validation returns.
#[derive(Errorizable, Debug)]
#[non_exhaustive]
pub enum CertificateValidationError {
	/// The certificate has expired.
	#[error("Certificate has expired")]
	Expired,

	/// The certificate is not yet valid.
	#[error("Certificate is not yet valid")]
	NotYetValid,

	/// The certificate has an empty subject public key.
	#[error("Certificate has empty subject public key")]
	EmptyPublicKey,

	/// The certificate has an empty signature.
	#[error("Certificate has empty signature")]
	EmptySignature,

	/// The validation timestamp is invalid, or the build has no clock.
	#[error("Invalid timestamp")]
	InvalidTimestamp,

	/// The signature algorithm is not supported.
	#[error("Unsupported signature algorithm: {0}")]
	UnsupportedAlgorithm(der::asn1::ObjectIdentifier),

	/// DER encoding or decoding failed.
	#[error("DER encoding error: {0}")]
	EncodingError(der::Error),

	/// The signature algorithm of the TBS certificate differs from the one on
	/// the certificate.
	#[error("Signature algorithm mismatch between TBS certificate and certificate")]
	AlgorithmMismatch,

	/// The SubjectPublicKeyInfo (SPKI) layer reported an error.
	#[error("SPKI error: {0}")]
	SpkiError(spki::Error),

	/// The public key is not in the pinned set.
	#[error("Public key not in pinned set")]
	PublicKeyNotPinned,

	/// The certificate fingerprint is not in the pinned set.
	#[error("Certificate fingerprint not in pinned set")]
	CertificateNotPinned,

	/// The certificate is in the denylist.
	#[error("Certificate is denied")]
	CertificateDenied,

	/// A configured fingerprint differs in width from the output of its
	/// digest, so it names no certificate.
	#[error("Fingerprint length mismatch: {0}")]
	FingerprintLength(crate::error::ReceivedExpectedError<usize, usize>),

	/// The certificate encoding is invalid.
	#[error("Invalid certificate encoding")]
	InvalidCertificateEncoding,

	/// The trust store does not hold the certificate.
	#[error("Certificate not trusted")]
	CertificateNotTrusted,

	/// The certificate chain is invalid, because the issuer name of a
	/// certificate differs from the subject name of the certificate above it.
	#[error("Certificate chain broken at issuer {issuer} and subject {subject}")]
	InvalidChain {
		/// The issuer name of the lower certificate.
		issuer: String,
		/// The subject name of the certificate the chain reached above it.
		subject: String,
	},

	/// Two certificates of a presented path carry the issuer name of one
	/// certificate as their subject, so the path names no single issuer above
	/// that certificate. A self-issued certificate names itself as its issuer,
	/// so a chain that sets another certificate of the same name above it
	/// holds two.
	#[error("Certificate path holds two issuers named {issuer}")]
	AmbiguousIssuer {
		/// The issuer name that two certificates carry.
		issuer: String,
	},

	/// A presented path returns to a certificate it holds, so it reaches no
	/// trust anchor.
	#[error("Certificate path returns to the issuer {issuer}")]
	PathCycle {
		/// The issuer name at which the path returns.
		issuer: String,
	},

	/// The certificate chain is empty.
	#[error("Empty certificate chain")]
	EmptyChain,

	/// Two certificates with different fingerprints have the same SKID.
	///
	/// The error carries the key identifier of the collision, so the operator
	/// can find the store entry.
	#[error("SKID collision: two certificates share key identifier {skid}")]
	SkidCollision {
		/// The key identifier both certificates carry, in hex.
		skid: String,
	},

	/// Two certificates with different fingerprints hold the same public key,
	/// by the key rule of the
	/// [`CertificateTrust`](super::store::CertificateTrust#contract) contract.
	///
	/// The error carries the SubjectPublicKeyInfo DER of the refused
	/// certificate in hex, and the serial number and issuer of the held one,
	/// so the operator can find both certificates.
	#[error("Public key collision: SubjectPublicKeyInfo {public_key} holds the key of the certificate of {holder}")]
	PublicKeyCollision {
		/// The SubjectPublicKeyInfo DER of the second certificate, in hex.
		public_key: String,
		/// The serial number in hex and the issuer of the certificate that
		/// holds the key, the pair that names one certificate (RFC 5280
		/// §4.1.2.2).
		holder: String,
	},

	/// The issuer certificate is not a CA (RFC 5280 §6.1.4(k)).
	#[error("Issuer certificate is not a CA")]
	IssuerNotCa,

	/// The `keyUsage` extension of the issuer does not assert `keyCertSign`
	/// (RFC 5280 §6.1.4(n)).
	#[error("Issuer keyUsage does not permit certificate signing")]
	MissingKeyCertSign,

	/// The `keyUsage` extension is absent, or it does not assert the usage the
	/// certificate's role needs (RFC 5280 §4.2.1.3).
	#[error("Certificate keyUsage does not assert {0:?}")]
	MissingKeyUsage(crate::crypto::x509::ext::pkix::KeyUsages),

	/// The `keyUsage` extension asserts a bit that narrows the use the
	/// certificate is read for, as `decipherOnly` narrows `keyAgreement` to
	/// decipherment (RFC 5280 §4.2.1.3).
	#[error("Certificate keyUsage restricts the use with {0:?}")]
	ExcludedKeyUsage(crate::crypto::x509::ext::pkix::KeyUsages),

	/// The `extendedKeyUsage` extension names neither the purpose of the role
	/// the certificate is read for nor `anyExtendedKeyUsage`
	/// (RFC 5280 §4.2.1.12).
	#[error("Certificate extendedKeyUsage excludes the role")]
	ExcludedKeyPurpose,

	/// The certificate carries more than one instance of an extension
	/// (RFC 5280 §4.2).
	#[error("Duplicate extension: {0}")]
	DuplicateExtension(der::asn1::ObjectIdentifier),

	/// The certification path is longer than a constraint allows: the
	/// `pathLenConstraint` of an issuer (RFC 5280 §6.1.4(m)), or the
	/// [`MAX_PRESENTED_PATH`](crate::constants::MAX_PRESENTED_PATH)
	/// certificates a reader takes from one `SignedData`.
	#[error("Certification path length constraint exceeded")]
	PathLenExceeded,

	/// The certificate carries a critical extension that this validator does
	/// not process (RFC 5280 §4.2).
	#[error("Unprocessed critical extension: {0}")]
	UnprocessedCriticalExtension(der::asn1::ObjectIdentifier),

	/// A certificate of the path carries a `nameConstraints` extension, which
	/// RFC 5280 §6.1.4(g) applies whatever its criticality, and which the
	/// store's path validation does not apply.
	#[error("Certificate states name constraints that path validation does not apply")]
	NameConstraintsUnapplied,

	/// The end-entity certificate asserts `basicConstraints.cA`.
	#[error("End-entity certificate asserts the CA basic constraint")]
	EndEntityIsCa,

	/// The certificate is revoked (RFC 5280 §6.1.3(a)(3)).
	#[error("Certificate is revoked")]
	CertificateRevoked,

	/// The revocation status could not be established.
	#[error("Certificate revocation status could not be established")]
	RevocationStatusUnknown,

	/// The public key is invalid.
	#[cfg(feature = "signature")]
	#[error("Invalid public key: {0}")]
	PublicKeyError(crate::crypto::sign::elliptic_curve::Error),

	/// Signature verification failed.
	#[cfg(feature = "signature")]
	#[error("Signature verification failed: {0}")]
	SignatureVerificationFailed(signature::Error),
}

crate::impl_from!(der::Error => CertificateValidationError::EncodingError);
crate::impl_from!(spki::Error => CertificateValidationError::SpkiError);

#[cfg(feature = "signature")]
crate::impl_from!(crate::crypto::sign::elliptic_curve::Error => CertificateValidationError::PublicKeyError);
#[cfg(feature = "signature")]
crate::impl_from!(signature::Error => CertificateValidationError::SignatureVerificationFailed);
