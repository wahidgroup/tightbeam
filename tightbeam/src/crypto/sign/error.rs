//! Errors of the CMS signer and the signing identity.

use crate::cms::content_info::CmsVersion;
use crate::der::asn1::ObjectIdentifier;
use crate::error::ReceivedExpectedError;
use crate::Errorizable;

/// Errors from building or verifying a CMS signature.
#[derive(Errorizable, Debug)]
pub enum SignerError {
	/// A CMS structure or an attribute failed to encode or decode.
	#[error("CMS encoding error: {0}")]
	Encoding(crate::der::Error),

	/// A public key failed to encode or decode as a SubjectPublicKeyInfo.
	#[error("Public key error: {0}")]
	PublicKey(crate::spki::Error),

	/// The key provider failed to sign or to return its public key.
	#[error("Key provider error: {0}")]
	Key(crate::crypto::key::KeyError),

	/// The certificate failed to name its signer, or a policy refused the
	/// signature.
	#[error("Certificate error: {0}")]
	Certificate(crate::crypto::x509::error::CertificateValidationError),

	/// The signature value is not the encoding of its algorithm, or it fails
	/// to verify.
	#[error("Signature error: {0}")]
	Signature(crate::crypto::sign::Error),

	/// The `SignerInfo` names a digest or signature algorithm other than the
	/// verifier's.
	#[error("Unexpected algorithm: {0:?}")]
	UnexpectedAlgorithm(ReceivedExpectedError<ObjectIdentifier, ObjectIdentifier>),

	/// The `SignerInfo` version differs from the one its `sid` demands (RFC
	/// 5652 §5.3).
	#[error("SignerInfo version differs from the RFC 5652 §5.3 rule: {0:?}")]
	SignerInfoVersion(ReceivedExpectedError<CmsVersion, CmsVersion>),

	/// The `SignedData` version differs from the one its parts demand (RFC
	/// 5652 §5.1).
	#[error("SignedData version differs from the RFC 5652 §5.1 rule: {0:?}")]
	SignedDataVersion(ReceivedExpectedError<CmsVersion, CmsVersion>),

	/// An attribute of the profile repeats the OID of another signed
	/// attribute (RFC 5652 §11.1, §11.2, RFC 6211 §2).
	#[error("The signed attribute {0} occurs twice")]
	DuplicateAttribute(ObjectIdentifier),

	/// The crate has no canonical form for the signature algorithm on the
	/// key's curve.
	#[error("Unsupported signature algorithm: {0}")]
	UnsupportedAlgorithm(ObjectIdentifier),

	/// The `SignerInfo` names a signer other than the expected certificate.
	#[error("The SignerInfo names another signer")]
	SignerIdentifier,

	/// The signed attributes are absent, or they differ from the set the
	/// content and its profile require.
	#[error("The signed attributes differ from the required set")]
	SignedAttributes,

	/// The `digestAlgorithms` SET of a `SignedData` omits the digest algorithm
	/// of one of its signers (RFC 5652 §5.1).
	#[error("The digestAlgorithms SET omits a signer's digest algorithm")]
	DigestAlgorithms,

	/// The `SignedData` holds no content, or content of another type.
	#[error("The SignedData content is absent or of another type")]
	Content,

	/// The key's public half differs from the certificate's
	/// SubjectPublicKeyInfo.
	#[error("The key differs from the certificate's public key")]
	KeyMismatch,
}

crate::impl_from!(crate::der::Error => SignerError::Encoding);
crate::impl_from!(crate::spki::Error => SignerError::PublicKey);
crate::impl_from!(crate::crypto::key::KeyError => SignerError::Key);
crate::impl_from!(crate::crypto::x509::error::CertificateValidationError => SignerError::Certificate);
crate::impl_from!(crate::crypto::sign::Error => SignerError::Signature);
