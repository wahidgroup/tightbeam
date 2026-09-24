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

	/// The timestamp provided for validation is invalid.
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

	/// The certificate encoding is invalid.
	#[error("Invalid certificate encoding")]
	InvalidCertificateEncoding,

	/// The trust store does not hold the certificate.
	#[error("Certificate not trusted")]
	CertificateNotTrusted,

	/// The certificate chain is invalid, because a certificate's issuer does
	/// not name the subject of the certificate above it.
	#[error("Certificate chain broken: issuer {issuer} does not match subject {subject}")]
	InvalidChain { issuer: String, subject: String },

	/// The certificate chain is empty.
	#[error("Empty certificate chain")]
	EmptyChain,

	/// Two certificates with different fingerprints have the same SKID.
	///
	/// The error carries the colliding key identifier, so the store entry can
	/// be found.
	#[error("SKID collision: two certificates share key identifier {skid}")]
	SkidCollision { skid: String },

	/// The issuer certificate is not a CA (RFC 5280 §6.1.4(k)).
	#[error("Issuer certificate is not a CA")]
	IssuerNotCa,

	/// The issuer keyUsage extension does not assert keyCertSign
	/// (RFC 5280 §6.1.4(n)).
	#[error("Issuer keyUsage does not permit certificate signing")]
	MissingKeyCertSign,

	/// The certification path exceeds the pathLenConstraint of an issuer
	/// (RFC 5280 §6.1.4(m)).
	#[error("Certification path length constraint exceeded")]
	PathLenExceeded,

	/// The certificate carries a critical extension that this validator does
	/// not process (RFC 5280 §4.2).
	#[error("Unprocessed critical extension: {0}")]
	UnprocessedCriticalExtension(der::asn1::ObjectIdentifier),

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
