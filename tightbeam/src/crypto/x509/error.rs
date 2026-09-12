pub type Result<T> = core::result::Result<T, CertificateValidationError>;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::String;

use crate::Errorizable;

/// Errors specific to X.509 certificate validation
#[derive(Errorizable, Debug)]
#[non_exhaustive]
pub enum CertificateValidationError {
	/// Certificate has expired
	#[error("Certificate has expired")]
	Expired,

	/// Certificate is not yet valid
	#[error("Certificate is not yet valid")]
	NotYetValid,

	/// Certificate has an empty subject public key
	#[error("Certificate has empty subject public key")]
	EmptyPublicKey,

	/// Certificate has an empty signature
	#[error("Certificate has empty signature")]
	EmptySignature,

	/// Invalid timestamp provided for validation
	#[error("Invalid timestamp")]
	InvalidTimestamp,

	/// Signature algorithm not supported
	#[error("Unsupported signature algorithm: {0}")]
	UnsupportedAlgorithm(der::asn1::ObjectIdentifier),

	/// DER encoding/decoding error
	#[error("DER encoding error: {0}")]
	EncodingError(der::Error),

	/// Signature algorithm mismatch between TBS and certificate
	#[error("Signature algorithm mismatch between TBS certificate and certificate")]
	AlgorithmMismatch,

	/// SPKI error
	#[error("SPKI error: {0}")]
	SpkiError(spki::Error),

	/// Public key not in pinned set
	#[error("Public key not in pinned set")]
	PublicKeyNotPinned,

	/// Certificate fingerprint not in pinned set
	#[error("Certificate fingerprint not in pinned set")]
	CertificateNotPinned,

	/// Certificate is in denylist
	#[error("Certificate is denied")]
	CertificateDenied,

	/// Invalid certificate encoding
	#[error("Invalid certificate encoding")]
	InvalidCertificateEncoding,

	/// Trust store is sealed and cannot be modified
	#[error("Trust store is sealed")]
	StoreSealed,

	/// Certificate not found in trust store
	#[error("Certificate not trusted")]
	CertificateNotTrusted,

	/// Invalid certificate chain: a certificate's issuer does not name the
	/// subject of the certificate above it.
	#[error("Certificate chain broken: issuer {issuer} does not match subject {subject}")]
	InvalidChain { issuer: String, subject: String },

	/// Empty certificate chain provided
	#[error("Empty certificate chain")]
	EmptyChain,

	/// Operation not supported by this validator
	#[error("Operation not supported")]
	UnsupportedOperation,

	/// Certificates with different fingerprints have the same SKID
	///
	/// Carries the colliding key identifier, so the store entry can be found.
	#[error("SKID collision: two certificates share key identifier {skid}")]
	SkidCollision { skid: String },

	/// Configured digest produces fewer than the 20 bytes required for a SKID
	#[error("Digest output too short for SKID")]
	DigestTooShort,

	/// Issuer certificate is not a CA (RFC 5280 §6.1.4(k))
	#[error("Issuer certificate is not a CA")]
	IssuerNotCa,

	/// Issuer keyUsage extension does not assert keyCertSign (RFC 5280 §6.1.4(n))
	#[error("Issuer keyUsage does not permit certificate signing")]
	MissingKeyCertSign,

	/// Certification path exceeds an issuer's pathLenConstraint (RFC 5280 §6.1.4(m))
	#[error("Certification path length constraint exceeded")]
	PathLenExceeded,

	/// Certificate carries a critical extension this validator does not process (RFC 5280 §4.2)
	#[error("Unprocessed critical extension: {0}")]
	UnprocessedCriticalExtension(der::asn1::ObjectIdentifier),

	/// End-entity certificate asserts `basicConstraints.cA`
	#[error("End-entity certificate asserts the CA basic constraint")]
	EndEntityIsCa,

	/// Certificate is revoked (RFC 5280 §6.1.3(a)(3))
	#[error("Certificate is revoked")]
	CertificateRevoked,

	/// Revocation status could not be established
	#[error("Certificate revocation status could not be established")]
	RevocationStatusUnknown,

	/// Invalid public key
	#[cfg(feature = "signature")]
	#[error("Invalid public key: {0}")]
	PublicKeyError(crate::crypto::sign::elliptic_curve::Error),

	/// Signature verification failed
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
