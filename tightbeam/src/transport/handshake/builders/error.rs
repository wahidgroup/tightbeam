//! Builder-specific errors for CMS handshake construction.

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

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for KariBuilderError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			KariBuilderError::MissingSenderPrivateKey => write!(f, "Sender private key not set"),
			KariBuilderError::MissingSenderPublicKeySpki => write!(f, "Sender public key SPKI not set"),
			KariBuilderError::MissingRecipientPublicKey => write!(f, "Recipient public key not set"),
			KariBuilderError::MissingRecipientIdentifier => write!(f, "Recipient identifier not set"),
			KariBuilderError::MissingUkm => write!(f, "User Keying Material (UKM) not set"),
			KariBuilderError::MissingKeyEncryptionAlgorithm => write!(f, "Key encryption algorithm not set"),
			KariBuilderError::DerError(e) => write!(f, "DER error: {}", e),
			KariBuilderError::CmsBuilderError(e) => write!(f, "CMS builder error: {}", e),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for KariBuilderError {}

#[cfg(not(feature = "derive"))]
crate::impl_from!(der::Error => KariBuilderError::DerError);
#[cfg(not(feature = "derive"))]
crate::impl_from!(crate::cms::builder::Error => KariBuilderError::CmsBuilderError);
