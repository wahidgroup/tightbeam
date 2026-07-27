//! Builder-specific errors for CMS handshake construction.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;

/// Errors that can occur during KARI builder construction.
#[derive(Debug, crate::Errorizable)]
pub enum KariBuilderError {
	/// Sender private key not set
	#[error("Sender private key not set")]
	MissingSenderPrivateKey,

	/// Sender public key SPKI not set
	#[error("Sender public key SPKI not set")]
	MissingSenderPublicKeySpki,

	/// Recipient public key not set
	#[error("Recipient public key not set")]
	MissingRecipientPublicKey,

	/// Recipient identifier not set
	#[error("Recipient identifier not set")]
	MissingRecipientIdentifier,

	/// User Keying Material (UKM) not set
	#[error("User Keying Material (UKM) not set")]
	MissingUkm,

	/// Key encryption algorithm not set
	#[error("Key encryption algorithm not set")]
	MissingKeyEncryptionAlgorithm,

	/// DER encoding/decoding error
	#[error("DER error: {0}")]
	#[from]
	DerError(crate::der::Error),

	/// CMS builder error
	#[error("CMS builder error: {0}")]
	#[from]
	CmsBuilderError(crate::cms::builder::Error),
}

/// Narrows [`KariBuilderError`] into the foreign [`crate::cms::builder::Error`].
/// `Missing*` config variants lack a structured `cms` counterpart, so collapse
/// into [`Builder`](crate::cms::builder::Error::Builder) via their `Display`.
impl From<KariBuilderError> for crate::cms::builder::Error {
	fn from(err: KariBuilderError) -> Self {
		match err {
			KariBuilderError::DerError(e) => crate::cms::builder::Error::Asn1(e),
			KariBuilderError::CmsBuilderError(e) => e,
			other => crate::cms::builder::Error::Builder(other.to_string()),
		}
	}
}
