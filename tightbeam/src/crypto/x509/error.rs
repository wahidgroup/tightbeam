#[cfg(feature = "derive")]
use crate::Errorizable;

pub type Result<T> = core::result::Result<T, CertificateValidationError>;

/// Errors specific to X.509 certificate validation
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum CertificateValidationError {
	/// Certificate has expired
	#[cfg_attr(feature = "derive", error("Certificate has expired"))]
	Expired,

	/// Certificate is not yet valid
	#[cfg_attr(feature = "derive", error("Certificate is not yet valid"))]
	NotYetValid,

	/// Certificate has an empty subject public key
	#[cfg_attr(feature = "derive", error("Certificate has empty subject public key"))]
	EmptyPublicKey,

	/// Certificate has an empty signature
	#[cfg_attr(feature = "derive", error("Certificate has empty signature"))]
	EmptySignature,

	/// Invalid timestamp provided for validation
	#[cfg_attr(feature = "derive", error("Invalid timestamp"))]
	InvalidTimestamp,

	/// Signature algorithm not supported
	#[cfg_attr(feature = "derive", error("Unsupported signature algorithm: {0}"))]
	UnsupportedAlgorithm(der::asn1::ObjectIdentifier),

	#[cfg_attr(feature = "derive", error("Invalid public key: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	PublicKeyError(crate::crypto::sign::elliptic_curve::Error),

	/// Signature verification failed
	#[cfg_attr(feature = "derive", error("Signature verification failed: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	SignatureVerificationFailed(signature::Error),

	/// DER encoding/decoding error
	#[cfg_attr(feature = "derive", error("DER encoding error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	EncodingError(der::Error),

	/// Signature algorithm mismatch between TBS and certificate
	#[cfg_attr(
		feature = "derive",
		error("Signature algorithm mismatch between TBS certificate and certificate")
	)]
	AlgorithmMismatch,

	/// SPKI error
	#[cfg_attr(feature = "derive", error("SPKI error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	SpkiError(spki::Error),

	/// Public key not in pinned set
	#[cfg_attr(feature = "derive", error("Public key not in pinned set"))]
	PublicKeyNotPinned,

	/// Certificate fingerprint not in pinned set
	#[cfg_attr(feature = "derive", error("Certificate fingerprint not in pinned set"))]
	CertificateNotPinned,

	/// Certificate is in denylist
	#[cfg_attr(feature = "derive", error("Certificate is denied"))]
	CertificateDenied,

	/// Invalid certificate encoding
	#[cfg_attr(feature = "derive", error("Invalid certificate encoding"))]
	InvalidCertificateEncoding,

	/// Trust store is sealed and cannot be modified
	#[cfg_attr(feature = "derive", error("Trust store is sealed"))]
	StoreSealed,

	/// Certificate not found in trust store
	#[cfg_attr(feature = "derive", error("Certificate not trusted"))]
	CertificateNotTrusted,

	/// Invalid certificate chain (broken chain or untrusted root)
	#[cfg_attr(feature = "derive", error("Invalid certificate chain"))]
	InvalidChain,

	/// Empty certificate chain provided
	#[cfg_attr(feature = "derive", error("Empty certificate chain"))]
	EmptyChain,

	/// Operation not supported by this validator
	#[cfg_attr(feature = "derive", error("Operation not supported"))]
	UnsupportedOperation,
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for CertificateValidationError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			CertificateValidationError::Expired => write!(f, "Certificate has expired"),
			CertificateValidationError::NotYetValid => write!(f, "Certificate is not yet valid"),
			CertificateValidationError::EmptyPublicKey => write!(f, "Certificate has empty subject public key"),
			CertificateValidationError::EmptySignature => write!(f, "Certificate has empty signature"),
			CertificateValidationError::InvalidTimestamp => write!(f, "Invalid timestamp"),
			CertificateValidationError::UnsupportedAlgorithm(oid) => {
				write!(f, "Unsupported signature algorithm: {}", oid)
			}
			CertificateValidationError::PublicKeyError(e) => write!(f, "Invalid public key: {}", e),
			CertificateValidationError::SignatureVerificationFailed(e) => {
				write!(f, "Signature verification failed: {}", e)
			}
			CertificateValidationError::EncodingError(e) => write!(f, "DER encoding error: {}", e),
			CertificateValidationError::AlgorithmMismatch => {
				write!(f, "Signature algorithm mismatch between TBS certificate and certificate")
			}
			CertificateValidationError::SpkiError(e) => write!(f, "SPKI error: {}", e),
			CertificateValidationError::PublicKeyNotPinned => write!(f, "Public key not in pinned set"),
			CertificateValidationError::CertificateNotPinned => {
				write!(f, "Certificate fingerprint not in pinned set")
			}
			CertificateValidationError::CertificateDenied => write!(f, "Certificate is denied"),
			CertificateValidationError::InvalidCertificateEncoding => write!(f, "Invalid certificate encoding"),
			CertificateValidationError::StoreSealed => write!(f, "Trust store is sealed"),
			CertificateValidationError::CertificateNotTrusted => write!(f, "Certificate not trusted"),
			CertificateValidationError::InvalidChain => write!(f, "Invalid certificate chain"),
			CertificateValidationError::EmptyChain => write!(f, "Empty certificate chain"),
			CertificateValidationError::UnsupportedOperation => write!(f, "Operation not supported"),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for CertificateValidationError {}
