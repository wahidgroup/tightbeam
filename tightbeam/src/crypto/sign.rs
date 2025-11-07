pub mod ecdsa {
	pub use ecdsa::der;
	pub use ecdsa::{Error, Signature, SigningKey, VerifyingKey};

	#[cfg(feature = "secp256k1")]
	pub use k256;
	#[cfg(feature = "secp256k1")]
	pub use k256::{
		ecdsa::{
			Signature as Secp256k1Signature, SigningKey as Secp256k1SigningKey, VerifyingKey as Secp256k1VerifyingKey,
		},
		schnorr, Secp256k1,
	};
}

// Re-exports
pub use elliptic_curve;
pub use signature::*;

use crate::cms::content_info::CmsVersion;
use crate::cms::signed_data::{SignatureValue, SignerIdentifier, SignerInfo};
use crate::crypto::hash::Digest;
use crate::der::asn1::OctetString;
use crate::der::oid::AssociatedOid;
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey};
use crate::x509::ext::pkix::SubjectKeyIdentifier;

/// TODO Petition RustCrypto to adopt AssociatedOid for all
pub trait Signatory<S>: Signer<S> + Keypair
where
	S: SignatureEncoding,
{
	/// The digest algorithm used by this signer
	type DigestAlgorithm: Digest + AssociatedOid;

	/// Sign data and return the signature information
	fn to_signer_info(&self, data: impl AsRef<[u8]>) -> crate::error::Result<SignerInfo> {
		// Compute digest first
		let mut hasher = Self::DigestAlgorithm::new();
		hasher.update(&data);
		hasher.finalize();

		// Sign the data
		let signature: S = self.try_sign(data.as_ref())?;
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
	fn signer_identifier(&self) -> crate::error::Result<SignerIdentifier>;
}

#[cfg(feature = "secp256k1")]
impl Signatory<ecdsa::Signature<ecdsa::Secp256k1>> for ecdsa::SigningKey<ecdsa::Secp256k1> {
	type DigestAlgorithm = sha3::Sha3_256;

	fn signature_algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: crate::SIGNER_ECDSA_WITH_SHA3_256_OID, parameters: None }
	}

	fn signer_identifier(&self) -> crate::error::Result<SignerIdentifier> {
		let verifying_key = self.verifying_key();
		let public_key_der = verifying_key
			.to_public_key_der()
			.map_err(|_| crate::error::TightBeamError::SignatureEncodingError)?;
		let mut hasher = Self::DigestAlgorithm::new();
		hasher.update(public_key_der.as_bytes());
		let skid_bytes = hasher.finalize();
		let octet_string = OctetString::new(&skid_bytes[..20])?;
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

/// Compute the SubjectKeyIdentifier-based SignerIdentifier for a Secp256k1 verifying key.
#[cfg(feature = "secp256k1")]
pub fn secp256k1_signer_identifier(
	verifying_key: &ecdsa::VerifyingKey<ecdsa::Secp256k1>,
) -> crate::error::Result<SignerIdentifier> {
	let public_key_der = verifying_key
		.to_public_key_der()
		.map_err(|_| crate::error::TightBeamError::SignatureEncodingError)?;
	let mut hasher = sha3::Sha3_256::new();
	hasher.update(public_key_der.as_bytes());
	let skid_bytes = hasher.finalize();
	let octet_string =
		OctetString::new(&skid_bytes[..20]).map_err(|e| crate::error::TightBeamError::SerializationError(e))?;
	Ok(SignerIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier::from(octet_string)))
}

/// Trait for verifying signatures in SignedData structures.
///
/// Implementations provide signature verification for specific algorithms.
pub trait SignatureVerifier {
	/// Verify a signature over the given content.
	///
	/// # Parameters
	/// - `content`: The content that was signed
	/// - `signature`: The signature bytes to verify
	/// - `signer_id`: The signer identifier from SignerInfo
	///
	/// # Returns
	/// `Ok(())` if signature is valid, `Err` otherwise
	fn verify_signature(
		&self,
		content: &[u8],
		signature: &[u8],
		signer_id: &SignerIdentifier,
	) -> crate::error::Result<()>;
}

/// Concrete implementation of `SignatureVerifier` for ECDSA signatures.
///
/// Uses a verifying key to check ECDSA signatures with a specific digest algorithm.
#[cfg(all(feature = "signature", feature = "secp256k1"))]
pub struct EcdsaSignatureVerifier<V, S, D>
where
	V: Verifier<S>,
	S: SignatureEncoding,
	D: Digest,
{
	verifying_key: V,
	expected_sid: Option<SignerIdentifier>,
	_phantom: core::marker::PhantomData<(S, D)>,
}

#[cfg(all(feature = "signature", feature = "secp256k1"))]
impl<V, S, D> EcdsaSignatureVerifier<V, S, D>
where
	V: Verifier<S>,
	S: SignatureEncoding,
	D: Digest,
{
	/// Create a new ECDSA signature verifier from a signing key.
	///
	/// Uses the `Signatory` trait to get the proper signer identifier.
	///
	/// # Parameters
	/// - `signing_key`: The signing key to derive the expected identifier from
	pub fn from_signing_key<K>(signing_key: &K) -> crate::error::Result<Self>
	where
		K: Signatory<S>,
		K::VerifyingKey: Into<V>,
	{
		let verifying_key = signing_key.verifying_key().into();
		let expected_sid = signing_key.signer_identifier()?;

		Ok(Self {
			verifying_key,
			expected_sid: Some(expected_sid),
			_phantom: core::marker::PhantomData,
		})
	}

	/// Create a verifier from a verifying key with proper SID checking.
	///
	/// Constructs the expected SubjectKeyIdentifier from the verifying key.
	/// This is the recommended method when you only have a verifying key.
	pub fn from_verifying_key_with_sid(verifying_key: V, expected_sid: SignerIdentifier) -> Self {
		Self {
			verifying_key,
			expected_sid: Some(expected_sid),
			_phantom: core::marker::PhantomData,
		}
	}
}

#[cfg(all(feature = "signature", feature = "secp256k1"))]
impl<V, S, D> SignatureVerifier for EcdsaSignatureVerifier<V, S, D>
where
	V: Verifier<S>,
	S: SignatureEncoding,
	D: Digest,
{
	fn verify_signature(
		&self,
		content: &[u8],
		signature_bytes: &[u8],
		signer_id: &SignerIdentifier,
	) -> crate::error::Result<()> {
		// 1. Validate SID if expected
		if let Some(ref expected_sid) = self.expected_sid {
			if signer_id != expected_sid {
				return Err(crate::error::TightBeamError::SignatureEncodingError);
			}
		}

		// 2. Hash the content
		let mut hasher = D::new();
		hasher.update(content);
		let digest = hasher.finalize();

		// 3. Parse and verify signature
		let signature =
			S::try_from(signature_bytes).map_err(|_| crate::error::TightBeamError::SignatureEncodingError)?;
		self.verifying_key
			.verify(digest.as_slice(), &signature)
			.map_err(|_| crate::error::TightBeamError::SignatureEncodingError)?;

		Ok(())
	}
}
