pub type Result<T> = core::result::Result<T, CertificateValidationError>;

/// Errors specific to X.509 certificate validation
///
/// Deliberately does not derive `Errorizable`: this module builds without
/// the `derive` feature, so the message strings live in exactly one place --
/// the `impl_error_display!` block below.
#[derive(Debug)]
pub enum CertificateValidationError {
	/// Certificate has expired
	Expired,

	/// Certificate is not yet valid
	NotYetValid,

	/// Certificate has an empty subject public key
	EmptyPublicKey,

	/// Certificate has an empty signature
	EmptySignature,

	/// Invalid timestamp provided for validation
	InvalidTimestamp,

	/// Signature algorithm not supported
	UnsupportedAlgorithm(der::asn1::ObjectIdentifier),

	/// DER encoding/decoding error
	EncodingError(der::Error),

	/// Signature algorithm mismatch between TBS and certificate
	AlgorithmMismatch,

	/// SPKI error
	SpkiError(spki::Error),

	/// Public key not in pinned set
	PublicKeyNotPinned,

	/// Certificate fingerprint not in pinned set
	CertificateNotPinned,

	/// Certificate is in denylist
	CertificateDenied,

	/// Invalid certificate encoding
	InvalidCertificateEncoding,

	/// Trust store is sealed and cannot be modified
	StoreSealed,

	/// Certificate not found in trust store
	CertificateNotTrusted,

	/// Invalid certificate chain (broken chain or untrusted root)
	InvalidChain,

	/// Empty certificate chain provided
	EmptyChain,

	/// Operation not supported by this validator
	UnsupportedOperation,

	/// Certificates with different fingerprints have the same SKID
	SkidCollision,

	/// Configured digest produces fewer than the 20 bytes required for a SKID
	DigestTooShort,

	/// Issuer certificate is not a CA (RFC 5280 §6.1.4(k))
	IssuerNotCa,

	/// Issuer keyUsage extension does not assert keyCertSign (RFC 5280 §6.1.4(n))
	MissingKeyCertSign,

	/// Certification path exceeds an issuer's pathLenConstraint (RFC 5280 §6.1.4(m))
	PathLenExceeded,

	/// Certificate carries a critical extension this validator does not process (RFC 5280 §4.2)
	UnprocessedCriticalExtension(der::asn1::ObjectIdentifier),

	/// End-entity certificate asserts `basicConstraints.cA`
	EndEntityIsCa,

	/// Certificate is revoked (RFC 5280 §6.1.3(a)(3))
	CertificateRevoked,

	/// Revocation status could not be established
	RevocationStatusUnknown,

	/// Invalid public key
	#[cfg(feature = "signature")]
	PublicKeyError(crate::crypto::sign::elliptic_curve::Error),

	/// Signature verification failed
	#[cfg(feature = "signature")]
	SignatureVerificationFailed(signature::Error),
}

crate::impl_error_display!(unconditional CertificateValidationError {
	Expired => "Certificate has expired",
	NotYetValid => "Certificate is not yet valid",
	EmptyPublicKey => "Certificate has empty subject public key",
	EmptySignature => "Certificate has empty signature",
	InvalidTimestamp => "Invalid timestamp",
	UnsupportedAlgorithm(oid) => "Unsupported signature algorithm: {oid}",
	EncodingError(e) => "DER encoding error: {e}",
	AlgorithmMismatch => "Signature algorithm mismatch between TBS certificate and certificate",
	SpkiError(e) => "SPKI error: {e}",
	PublicKeyNotPinned => "Public key not in pinned set",
	CertificateNotPinned => "Certificate fingerprint not in pinned set",
	CertificateDenied => "Certificate is denied",
	InvalidCertificateEncoding => "Invalid certificate encoding",
	StoreSealed => "Trust store is sealed",
	CertificateNotTrusted => "Certificate not trusted",
	InvalidChain => "Invalid certificate chain",
	EmptyChain => "Empty certificate chain",
	UnsupportedOperation => "Operation not supported",
	SkidCollision => "SKID collision detected",
	DigestTooShort => "Digest output too short for SKID",
	IssuerNotCa => "Issuer certificate is not a CA",
	MissingKeyCertSign => "Issuer keyUsage does not permit certificate signing",
	PathLenExceeded => "Certification path length constraint exceeded",
	UnprocessedCriticalExtension(oid) => "Unprocessed critical extension: {oid}",
	EndEntityIsCa => "End-entity certificate asserts the CA basic constraint",
	CertificateRevoked => "Certificate is revoked",
	RevocationStatusUnknown => "Certificate revocation status could not be established",

	#[cfg(feature = "signature")]
	PublicKeyError(e) => "Invalid public key: {e}",
	#[cfg(feature = "signature")]
	SignatureVerificationFailed(e) => "Signature verification failed: {e}",
});

crate::impl_from!(der::Error => CertificateValidationError::EncodingError);
crate::impl_from!(spki::Error => CertificateValidationError::SpkiError);

#[cfg(feature = "signature")]
crate::impl_from!(crate::crypto::sign::elliptic_curve::Error => CertificateValidationError::PublicKeyError);
#[cfg(feature = "signature")]
crate::impl_from!(signature::Error => CertificateValidationError::SignatureVerificationFailed);
