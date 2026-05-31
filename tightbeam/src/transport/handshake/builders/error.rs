//! Builder-specific errors for CMS handshake construction.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;

/// Errors that can occur during KARI builder construction.
#[cfg_attr(feature = "derive", derive(crate::Errorizable))]
#[derive(Debug)]
pub enum KariBuilderError {
	/// Sender private key not set
	#[cfg_attr(feature = "derive", error("Sender private key not set"))]
	MissingSenderPrivateKey,

	/// Sender public key SPKI not set
	#[cfg_attr(feature = "derive", error("Sender public key SPKI not set"))]
	MissingSenderPublicKeySpki,

	/// Recipient public key not set
	#[cfg_attr(feature = "derive", error("Recipient public key not set"))]
	MissingRecipientPublicKey,

	/// Recipient identifier not set
	#[cfg_attr(feature = "derive", error("Recipient identifier not set"))]
	MissingRecipientIdentifier,

	/// User Keying Material (UKM) not set
	#[cfg_attr(feature = "derive", error("User Keying Material (UKM) not set"))]
	MissingUkm,

	/// Key encryption algorithm not set
	#[cfg_attr(feature = "derive", error("Key encryption algorithm not set"))]
	MissingKeyEncryptionAlgorithm,

	/// DER encoding/decoding error
	#[cfg_attr(feature = "derive", error("DER error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	DerError(crate::der::Error),

	/// CMS builder error
	#[cfg_attr(feature = "derive", error("CMS builder error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	CmsBuilderError(crate::cms::builder::Error),
}

crate::impl_error_display!(KariBuilderError {
	MissingSenderPrivateKey => "Sender private key not set",
	MissingSenderPublicKeySpki => "Sender public key SPKI not set",
	MissingRecipientPublicKey => "Recipient public key not set",
	MissingRecipientIdentifier => "Recipient identifier not set",
	MissingUkm => "User Keying Material (UKM) not set",
	MissingKeyEncryptionAlgorithm => "Key encryption algorithm not set",
	DerError(e) => "DER error: {e}",
	CmsBuilderError(e) => "CMS builder error: {e}",
});

#[cfg(not(feature = "derive"))]
crate::impl_from!(der::Error => KariBuilderError::DerError);
#[cfg(not(feature = "derive"))]
crate::impl_from!(crate::cms::builder::Error => KariBuilderError::CmsBuilderError);

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
