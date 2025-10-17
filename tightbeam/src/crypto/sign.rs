pub mod ecdsa {
	pub use ecdsa::der;
	pub use ecdsa::{Signature, SigningKey, VerifyingKey};

	#[cfg(feature = "secp256k1")]
	pub use k256::{
		ecdsa::{
			Signature as Secp256k1Signature, SigningKey as Secp256k1SigningKey, VerifyingKey as Secp256k1VerifyingKey,
		},
		schnorr, Secp256k1,
	};
}

// Re-exports
pub use signature::*;

use crate::cms::content_info::CmsVersion;
use crate::cms::signed_data::{SignatureValue, SignerIdentifier, SignerInfo};
use crate::crypto::hash::Digest;
use crate::der::asn1::OctetString;
use crate::der::oid::AssociatedOid;
use crate::spki::AlgorithmIdentifierOwned;
use crate::x509::ext::pkix::SubjectKeyIdentifier;

/// TODO Petition RustCypto to adopt AssociatedOid for all
pub trait Signatory<S>: Signer<S> + Keypair
where
	S: SignatureEncoding,
{
	/// The digest algorithm used by this signer
	type DigestAlgorithm: Digest + AssociatedOid;

	/// Sign data and return the signature information
	fn to_signer_info(&self, data: &[u8]) -> crate::Result<SignerInfo> {
		// Compute digest first
		let mut hasher = Self::DigestAlgorithm::new();
		hasher.update(data);
		hasher.finalize();

		// Sign the data
		let signature: S = self.try_sign(data)?;
		let signature_bytes = signature.to_bytes();
		let signature_value = SignatureValue::new(signature_bytes.as_ref())?;

		// Build digest algorithm identifier
		let digest_alg = AlgorithmIdentifierOwned { oid: Self::DigestAlgorithm::OID, parameters: None };

		// Get signature algorithm
		let signature_algorithm = self.signature_algorithm();
		// Get signer identifier
		let sid = self.signer_identifier()?;

		Ok(SignerInfo {
			version: CmsVersion::V1,
			sid,
			digest_alg,
			signed_attrs: None,
			signature_algorithm,
			signature: signature_value,
			unsigned_attrs: None,
		})
	}

	/// Get the signature algorithm identifier
	/// Get the signature algorithm identifier
	fn signature_algorithm(&self) -> AlgorithmIdentifierOwned;

	/// Get the signer's identifier
	fn signer_identifier(&self) -> crate::Result<SignerIdentifier>;
}

#[cfg(feature = "secp256k1")]
impl Signatory<ecdsa::Signature<ecdsa::Secp256k1>> for ecdsa::SigningKey<ecdsa::Secp256k1> {
	type DigestAlgorithm = sha3::Sha3_256;

	fn signature_algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: crate::SIGNER_ECDSA_WITH_SHA3_256_OID, parameters: None }
	}

	fn signer_identifier(&self) -> crate::Result<SignerIdentifier> {
		let verifying_key = self.verifying_key();
		let encoded_point = verifying_key.to_encoded_point(false);
		let octet_string = OctetString::new(encoded_point.as_bytes())?;
		Ok(SignerIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier::from(octet_string)))
	}
}

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
