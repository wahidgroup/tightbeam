pub mod ecdsa {
	pub use ecdsa::der;
	pub use ecdsa::hazmat::{DigestPrimitive, SignPrimitive, VerifyPrimitive};
	pub use ecdsa::{Error, Signature, SignatureSize, SigningKey, VerifyingKey};

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
pub use signature::hazmat::{PrehashSigner, PrehashVerifier};
pub use signature::{Error, Keypair, SignatureEncoding, Signer, Verifier};

use crate::cms::content_info::CmsVersion;
use crate::cms::signed_data::{SignatureValue, SignerIdentifier, SignerInfo};
use crate::crypto::hash::Digest;
use crate::der::asn1::{ObjectIdentifier, OctetString};
use crate::der::oid::AssociatedOid;
use crate::error::{Result, TightBeamError};
use crate::oids::SIGNER_ECDSA_WITH_SHA3_256;
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey};
use crate::x509::ext::pkix::SubjectKeyIdentifier;

/// Trait for signature types that have an associated algorithm OID.
///
/// This allows generic code to work with different signature algorithms
/// (e.g., ECDSA-SHA256, ECDSA-SHA3-256, Ed25519) without hardcoding OIDs.
pub trait SignatureAlgorithmIdentifier {
	/// The OID for this signature algorithm.
	/// For example, ECDSA with SHA-256 is `1.2.840.10045.4.3.2`.
	const ALGORITHM_OID: ObjectIdentifier;
}

/// Canonical bytes-to-sign derivation: hash `content` exactly once with `D`
/// and sign the resulting digest as an ECDSA prehash.
pub fn sign_canonical<D, S>(signer: &impl PrehashSigner<S>, content: impl AsRef<[u8]>) -> core::result::Result<S, Error>
where
	D: Digest,
{
	let mut hasher = D::new();
	hasher.update(content.as_ref());

	signer.sign_prehash(&hasher.finalize())
}

/// Verify a signature produced under the canonical convention: hash
/// `content` once with `D`, verify the signature against that prehash.
///
/// Counterpart of [`sign_canonical`]: every tightbeam verifier must route
/// through this function so producers and verifiers cannot diverge on the
/// bytes-to-sign formula.
pub fn verify_canonical<D, S>(
	verifier: &impl PrehashVerifier<S>,
	content: impl AsRef<[u8]>,
	signature: &S,
) -> core::result::Result<(), Error>
where
	D: Digest,
{
	let mut hasher = D::new();
	hasher.update(content.as_ref());

	verifier.verify_prehash(&hasher.finalize(), signature)
}

/// Signing key that can emit a CMS [`SignerInfo`] over content.
pub trait Signatory<S>: PrehashSigner<S> + Keypair
where
	S: SignatureEncoding,
{
	/// The digest algorithm used by this signer
	type DigestAlgorithm: Digest + AssociatedOid;

	/// Sign data and return the signature information
	fn to_signer_info(&self, data: impl AsRef<[u8]>) -> Result<SignerInfo>
	where
		Self: Sized,
	{
		let signature: S = sign_canonical::<Self::DigestAlgorithm, S>(self, data)?;

		// Build digest algorithm identifier
		let digest_alg = AlgorithmIdentifierOwned { oid: Self::DigestAlgorithm::OID, parameters: None };

		// Get signature algorithm
		let signature_algorithm = self.signature_algorithm();
		// Get signer identifier
		let sid = self.signer_identifier()?;

		SignerInfo::from_parts(signature.to_bytes(), signature_algorithm, digest_alg, sid)
	}

	/// Get the signature algorithm identifier
	fn signature_algorithm(&self) -> AlgorithmIdentifierOwned;

	/// Get the signer's identifier
	fn signer_identifier(&self) -> Result<SignerIdentifier>;
}

/// Assemble a CMS [`SignerInfo`] from a precomputed signature.
///
/// Enables detached / two-phase signing: the to-be-signed bytes come from
/// `Frame::to_tbs`, get signed by any external backend (HSM, KMS, etc.),
/// then the resulting signature is reattached without tightbeam ever holding
/// the private key.
pub trait SignerInfoExt: Sized {
	/// Build a [`SignerInfo`] from a precomputed signature and its identifiers.
	fn from_parts(
		signature: impl AsRef<[u8]>,
		signature_algorithm: AlgorithmIdentifierOwned,
		digest_alg: AlgorithmIdentifierOwned,
		sid: SignerIdentifier,
	) -> Result<Self>;
}

impl SignerInfoExt for SignerInfo {
	fn from_parts(
		signature: impl AsRef<[u8]>,
		signature_algorithm: AlgorithmIdentifierOwned,
		digest_alg: AlgorithmIdentifierOwned,
		sid: SignerIdentifier,
	) -> Result<Self> {
		let signature = SignatureValue::new(signature.as_ref())?;

		Ok(SignerInfo {
			version: CmsVersion::V1,
			sid,
			digest_alg,
			signed_attrs: None,
			signature_algorithm,
			signature,
			unsigned_attrs: None,
		})
	}
}

#[cfg(feature = "secp256k1")]
impl Signatory<ecdsa::Signature<ecdsa::Secp256k1>> for ecdsa::SigningKey<ecdsa::Secp256k1> {
	type DigestAlgorithm = sha3::Sha3_256;

	fn signature_algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None }
	}

	fn signer_identifier(&self) -> Result<SignerIdentifier> {
		let verifying_key = self.verifying_key();
		let public_key_der = verifying_key
			.to_public_key_der()
			.map_err(|_| TightBeamError::SignatureEncodingError)?;

		let mut hasher = Self::DigestAlgorithm::new();
		hasher.update(public_key_der.as_bytes());

		let skid_bytes = hasher.finalize();
		let octet_string = OctetString::new(&skid_bytes[..20])?;
		Ok(SignerIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier::from(octet_string)))
	}
}

/// Local wrapper that signs under the canonical SHA3-256 convention and
/// supplies the matching `ecdsa-with-SHA3-256` AlgorithmIdentifier.
///
/// Used for X.509 building, where the `x509-cert` builders hand raw TBS
/// bytes to a [`Signer`].
pub struct Sha3Signer<'a, S>(&'a S);

impl<'a, S> crate::spki::DynSignatureAlgorithmIdentifier for Sha3Signer<'a, S> {
	fn signature_algorithm_identifier(&self) -> crate::spki::Result<crate::spki::AlgorithmIdentifierOwned> {
		Ok(crate::spki::AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None })
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
	S: PrehashSigner<Sig>,
{
	fn try_sign(&self, msg: &[u8]) -> core::result::Result<Sig, signature::Error> {
		sign_canonical::<sha3::Sha3_256, Sig>(self.0, msg)
	}
}

impl<'a, S> From<&'a S> for Sha3Signer<'a, S> {
	fn from(s: &'a S) -> Self {
		Sha3Signer(s)
	}
}

/// Compute the SubjectKeyIdentifier-based SignerIdentifier for a Secp256k1 verifying key.
#[cfg(feature = "secp256k1")]
pub fn secp256k1_signer_identifier(verifying_key: &ecdsa::VerifyingKey<ecdsa::Secp256k1>) -> Result<SignerIdentifier> {
	let public_key_der = verifying_key
		.to_public_key_der()
		.map_err(|_| TightBeamError::SignatureEncodingError)?;

	let mut hasher = sha3::Sha3_256::new();
	hasher.update(public_key_der.as_bytes());

	let skid_bytes = hasher.finalize();
	let octet_string = OctetString::new(&skid_bytes[..20]).map_err(TightBeamError::SerializationError)?;
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
	fn verify_signature(&self, content: &[u8], signature: &[u8], signer_id: &SignerIdentifier) -> Result<()>;
}

/// Concrete implementation of `SignatureVerifier` for ECDSA signatures.
///
/// Uses a verifying key to check ECDSA signatures with a specific digest algorithm.
#[cfg(all(feature = "signature", feature = "secp256k1"))]
pub struct EcdsaSignatureVerifier<V, S, D>
where
	V: PrehashVerifier<S>,
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
	V: PrehashVerifier<S>,
	S: SignatureEncoding,
	D: Digest,
{
	/// Create a new ECDSA signature verifier from a signing key.
	///
	/// Uses the `Signatory` trait to get the proper signer identifier.
	///
	/// # Parameters
	/// - `signing_key`: The signing key to derive the expected identifier from
	pub fn from_signing_key<K>(signing_key: &K) -> Result<Self>
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
	V: PrehashVerifier<S>,
	S: SignatureEncoding,
	D: Digest,
{
	fn verify_signature(&self, content: &[u8], signature_bytes: &[u8], signer_id: &SignerIdentifier) -> Result<()> {
		// Validate SID if expected
		if let Some(ref expected_sid) = self.expected_sid {
			if signer_id != expected_sid {
				return Err(TightBeamError::SignatureEncodingError);
			}
		}

		let signature = S::try_from(signature_bytes).map_err(|_| TightBeamError::SignatureEncodingError)?;
		verify_canonical::<D, S>(&self.verifying_key, content, &signature)
			.map_err(|_| TightBeamError::SignatureEncodingError)?;

		Ok(())
	}
}

// ============================================================================
// SignatureAlgorithmIdentifier implementations
// ============================================================================

#[cfg(feature = "secp256k1")]
impl SignatureAlgorithmIdentifier for ecdsa::Secp256k1Signature {
	/// ECDSA with SHA3-256: `2.16.840.1.101.3.4.3.10`
	const ALGORITHM_OID: ObjectIdentifier = SIGNER_ECDSA_WITH_SHA3_256;
}

#[cfg(all(test, feature = "secp256k1"))]
mod tests {
	use signature::hazmat::PrehashVerifier;

	use super::*;
	use crate::crypto::hash::Sha3_256;
	use crate::random::OsRng;

	type SigningKey = ecdsa::Secp256k1SigningKey;
	type Signature = ecdsa::Secp256k1Signature;
	type VerifyingKey = ecdsa::Secp256k1VerifyingKey;

	const CONTENT: &[u8] = b"cross-convention signing content";

	// One canonical bytes-to-sign convention: a SignerInfo produced by
	// `to_signer_info` must verify through `EcdsaSignatureVerifier` over the
	// same content.
	#[test]
	fn signer_info_verifies_through_ecdsa_verifier() -> crate::error::Result<()> {
		let signing_key = SigningKey::random(&mut OsRng);
		let signer_info = signing_key.to_signer_info(CONTENT)?;

		let verifier = EcdsaSignatureVerifier::<VerifyingKey, Signature, Sha3_256>::from_signing_key(&signing_key)?;
		verifier.verify_signature(CONTENT, signer_info.signature.as_bytes(), &signer_info.sid)?;

		Ok(())
	}

	// The advertised OID is ecdsa-with-SHA3-256, so a spec-conformant
	// external verifier checks the signature against the SHA3-256 prehash of
	// the content. Anything else is an algorithm-identifier lie on the wire.
	#[test]
	fn signature_matches_advertised_sha3_oid() -> crate::error::Result<()> {
		let signing_key = SigningKey::random(&mut OsRng);
		let signer_info = signing_key.to_signer_info(CONTENT)?;

		let mut hasher = Sha3_256::new();
		hasher.update(CONTENT);

		let prehash = hasher.finalize();
		let signature = Signature::from_slice(signer_info.signature.as_bytes())?;
		signing_key.verifying_key().verify_prehash(&prehash, &signature)?;

		Ok(())
	}
}
