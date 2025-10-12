pub mod ecdsa {
	pub use ecdsa::der;
	pub use ecdsa::{Signature, SigningKey, VerifyingKey};
	#[cfg(feature = "secp256k1")]
	pub use k256::ecdsa::{
		Signature as Secp256k1Signature, SigningKey as Secp256k1SigningKey, VerifyingKey as Secp256k1VerifyingKey,
	};
	#[cfg(feature = "secp256k1")]
	pub use k256::{schnorr, Secp256k1};
}

#[cfg(feature = "signature")]
pub use signature::*;

// Local wrapper that supplies the SHA3-256 ECDSA AlgorithmIdentifier
pub struct Sha3Signer<'a, S>(&'a S);

impl<'a, S> crate::spki::DynSignatureAlgorithmIdentifier for Sha3Signer<'a, S> {
	fn signature_algorithm_identifier(&self) -> crate::spki::Result<crate::spki::AlgorithmIdentifierOwned> {
		Ok(crate::spki::AlgorithmIdentifierOwned {
			oid: crate::der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.10"), // ecdsa-with-SHA3-256
			parameters: None,
		})
	}
}

impl<'a, S> signature::Keypair for Sha3Signer<'a, S>
where
	S: signature::Keypair,
{
	type VerifyingKey = <S as signature::Keypair>::VerifyingKey;

	fn verifying_key(&self) -> Self::VerifyingKey {
		self.0.verifying_key()
	}
}

impl<'a, S, Sig> signature::Signer<Sig> for Sha3Signer<'a, S>
where
	S: signature::Signer<Sig>,
{
	fn try_sign(&self, msg: &[u8]) -> core::result::Result<Sig, signature::Error> {
		self.0.try_sign(msg)
	}
}

impl<'a, S> From<&'a S> for Sha3Signer<'a, S> {
	fn from(s: &'a S) -> Self {
		Sha3Signer(s)
	}
}
