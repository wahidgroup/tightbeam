#[cfg(feature = "derive")]
use crate::Errorizable;

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
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for CertificateValidationError {}
