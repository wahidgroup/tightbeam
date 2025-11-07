//! Builder-specific errors for CMS handshake construction.

/// Errors that can occur during KARI builder construction.
#[cfg_attr(feature = "derive", derive(crate::Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
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
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for KariBuilderError {}
