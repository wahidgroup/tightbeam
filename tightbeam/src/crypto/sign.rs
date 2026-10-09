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

pub use elliptic_curve;
pub use signature::hazmat::{PrehashSigner, PrehashVerifier};
pub use signature::{Error, Keypair, SignatureEncoding, Signer, Verifier};

use core::marker::PhantomData;

use crate::cms::content_info::CmsVersion;
use crate::cms::signed_data::{SignatureValue, SignerIdentifier, SignerInfo};
use crate::crypto::hash::Digest;
use crate::crypto::x509::utils::Skid;
use crate::der::asn1::ObjectIdentifier;
use crate::der::oid::AssociatedOid;
use crate::error::{Result, TightBeamError};
use crate::oids::SIGNER_ECDSA_WITH_SHA3_256;
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey};

/// A signature type that names its algorithm OID.
///
/// Generic code reads the OID from the type, so one code path serves different
/// signature algorithms such as ECDSA-SHA256, ECDSA-SHA3-256, and Ed25519.
pub trait SignatureAlgorithmIdentifier {
	/// The OID for this signature algorithm. For example, ECDSA with SHA-256 is
	/// `1.2.840.10045.4.3.2`.
	const ALGORITHM_OID: ObjectIdentifier;
}

/// Sign `content` under the canonical bytes-to-sign derivation, which hashes
/// `content` exactly once with `D` and signs the resulting digest as an ECDSA
/// prehash.
pub fn sign_canonical<D, S>(signer: &impl PrehashSigner<S>, content: impl AsRef<[u8]>) -> core::result::Result<S, Error>
where
	D: Digest,
{
	let mut hasher = D::new();
	hasher.update(content.as_ref());
	signer.sign_prehash(&hasher.finalize())
}

/// A signature encoding that has one valid scalar form.
///
/// ECDSA accepts both `(r, s)` and `(r, n - s)` unless the verifier refuses
/// the high form. Tightbeam verification requires the low form so a relay
/// cannot rewrite one signed frame into a second valid frame.
pub trait LowSEncoding {
	/// Returns `true` when `s` is in the low half of the curve order.
	fn is_low_s(&self) -> bool;

	/// Refuse a high-s encoding, then verify `prehash` under `verifier`.
	///
	/// Paths that already hold a digest (receipt attributes, ECIES auth)
	/// use this so they share the same low-s gate as [`verify_canonical`].
	fn verify_prehash<V>(&self, verifier: &V, prehash: impl AsRef<[u8]>) -> core::result::Result<(), Error>
	where
		Self: Sized,
		V: PrehashVerifier<Self>,
	{
		if !self.is_low_s() {
			return Err(Error::new());
		}

		verifier.verify_prehash(prehash.as_ref(), self)
	}
}

#[cfg(feature = "secp256k1")]
impl LowSEncoding for ecdsa::Signature<ecdsa::Secp256k1> {
	fn is_low_s(&self) -> bool {
		self.normalize_s().is_none()
	}
}

/// Verify a signature produced under the canonical convention, which hashes
/// `content` once with `D` and verifies the signature against that prehash.
///
/// This function is the counterpart of [`sign_canonical`]. Every tightbeam
/// verifier must route through it, so producers and verifiers agree on the
/// bytes-to-sign formula.
///
/// # Low-s
///
/// The signature MUST be low-s. [`LowSEncoding`] is the check, and the `k256`
/// verifier also refuses a high-s encoding.
pub fn verify_canonical<D, S>(
	verifier: &impl PrehashVerifier<S>,
	content: impl AsRef<[u8]>,
	signature: &S,
) -> core::result::Result<(), Error>
where
	D: Digest,
	S: LowSEncoding,
{
	let mut hasher = D::new();
	hasher.update(content.as_ref());
	signature.verify_prehash(verifier, hasher.finalize())
}

/// Signing key that can emit a CMS [`SignerInfo`] over content.
pub trait Signatory<S>: PrehashSigner<S> + Keypair
where
	S: SignatureEncoding,
{
	/// The digest algorithm that this signer hashes the content with.
	type DigestAlgorithm: Digest + AssociatedOid;

	/// Sign `data` under the canonical convention and return its CMS
	/// [`SignerInfo`].
	fn to_signer_info(&self, data: impl AsRef<[u8]>) -> Result<SignerInfo>
	where
		Self: Sized,
	{
		let signature: S = sign_canonical::<Self::DigestAlgorithm, S>(self, data)?;
		let digest_alg = AlgorithmIdentifierOwned { oid: Self::DigestAlgorithm::OID, parameters: None };
		let signature_algorithm = self.signature_algorithm();
		let sid = self.signer_identifier()?;

		SignerInfo::from_parts(signature.to_bytes(), signature_algorithm, digest_alg, sid)
	}

	/// Returns the signature algorithm identifier that the [`SignerInfo`]
	/// carries.
	fn signature_algorithm(&self) -> AlgorithmIdentifierOwned;

	/// Returns the identifier that names this signer in the [`SignerInfo`].
	fn signer_identifier(&self) -> Result<SignerIdentifier>;
}

/// Assemble a CMS [`SignerInfo`] from a precomputed signature.
///
/// The trait enables detached, two-phase signing. The to-be-signed bytes come
/// from `Frame::to_tbs`, an external backend such as an HSM or a KMS signs
/// them, and the caller reattaches the signature, so the private key stays
/// outside tightbeam.
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
		secp256k1_signer_identifier(self.verifying_key())
	}
}

/// A wrapper that signs under the canonical SHA3-256 convention and supplies
/// the matching `ecdsa-with-SHA3-256` AlgorithmIdentifier.
///
/// X.509 building uses it, because the `x509-cert` builders hand raw TBS bytes
/// to a [`Signer`].
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

/// Compute the SubjectKeyIdentifier-based SignerIdentifier for a Secp256k1
/// verifying key.
#[cfg(feature = "secp256k1")]
pub fn secp256k1_signer_identifier(verifying_key: &ecdsa::VerifyingKey<ecdsa::Secp256k1>) -> Result<SignerIdentifier> {
	let encoded = verifying_key.to_public_key_der();
	let public_key_der = encoded.map_err(|_| TightBeamError::SignatureEncodingError)?;
	let skid = Skid::of_public_key(public_key_der);

	SignerIdentifier::try_from(skid).map_err(|_| TightBeamError::SignatureEncodingError)
}

/// A verifier for the signatures in SignedData structures.
///
/// Each implementation verifies the signatures of one algorithm.
pub trait SignatureVerifier {
	/// Verify `signature` over `content` for the signer that `signer_id` names.
	///
	/// - `signer_id`: the signer identifier from the SignerInfo.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the signature is not valid for the content and the signer.
	fn verify_signature(&self, content: &[u8], signature: &[u8], signer_id: &SignerIdentifier) -> Result<()>;
}

/// A [`SignatureVerifier`] for ECDSA signatures.
///
/// It checks each signature with the verifying key `V` under the digest
/// algorithm `D`.
#[cfg(all(feature = "signature", feature = "secp256k1"))]
pub struct EcdsaSignatureVerifier<V, S, D>
where
	V: PrehashVerifier<S>,
	S: SignatureEncoding,
	D: Digest,
{
	verifying_key: V,
	expected_sid: SignerIdentifier,
	_phantom: core::marker::PhantomData<(S, D)>,
}

#[cfg(all(feature = "signature", feature = "secp256k1"))]
impl<V, S, D> EcdsaSignatureVerifier<V, S, D>
where
	V: PrehashVerifier<S>,
	S: SignatureEncoding,
	D: Digest,
{
	/// Create an ECDSA signature verifier from a signing key.
	///
	/// The verifier takes its verifying key and its expected signer identifier
	/// from `signing_key` through [`Signatory`].
	pub fn from_signing_key<K>(signing_key: &K) -> Result<Self>
	where
		K: Signatory<S>,
		K::VerifyingKey: Into<V>,
	{
		let verifying_key = signing_key.verifying_key().into();
		let expected_sid = signing_key.signer_identifier()?;
		Ok(Self { verifying_key, expected_sid, _phantom: PhantomData })
	}

	/// Create a verifier from a verifying key and the signer identifier that it
	/// expects.
	///
	/// The caller supplies `expected_sid`, and verification refuses a signature
	/// that names any other signer. This is the recommended constructor when
	/// only a verifying key is available.
	pub fn from_verifying_key_with_sid(verifying_key: V, expected_sid: SignerIdentifier) -> Self {
		Self { verifying_key, expected_sid, _phantom: PhantomData }
	}
}

#[cfg(all(feature = "signature", feature = "secp256k1"))]
impl<V, S, D> SignatureVerifier for EcdsaSignatureVerifier<V, S, D>
where
	V: PrehashVerifier<S>,
	S: SignatureEncoding + LowSEncoding,
	D: Digest,
{
	fn verify_signature(&self, content: &[u8], signature_bytes: &[u8], signer_id: &SignerIdentifier) -> Result<()> {
		if signer_id != &self.expected_sid {
			return Err(TightBeamError::SignatureEncodingError);
		}

		let signature = S::try_from(signature_bytes).map_err(|_| TightBeamError::SignatureEncodingError)?;
		verify_canonical::<D, S>(&self.verifying_key, content, &signature)
			.map_err(|_| TightBeamError::SignatureEncodingError)?;

		Ok(())
	}
}

#[cfg(feature = "secp256k1")]
impl SignatureAlgorithmIdentifier for ecdsa::Secp256k1Signature {
	/// ECDSA with SHA3-256 is `2.16.840.1.101.3.4.3.10`.
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

	// The crate has one canonical bytes-to-sign convention, so a SignerInfo
	// produced by `to_signer_info` must verify through `EcdsaSignatureVerifier`
	// over the same content.
	#[test]
	fn signer_info_verifies_through_ecdsa_verifier() -> crate::error::Result<()> {
		let signing_key = SigningKey::random(&mut OsRng);
		let signer_info = signing_key.to_signer_info(CONTENT)?;

		let verifier = EcdsaSignatureVerifier::<VerifyingKey, Signature, Sha3_256>::from_signing_key(&signing_key)?;
		verifier.verify_signature(CONTENT, signer_info.signature.as_bytes(), &signer_info.sid)?;

		Ok(())
	}

	// The advertised OID is ecdsa-with-SHA3-256, so a spec-conformant external
	// verifier checks the signature against the SHA3-256 prehash of the
	// content. A signature over any other digest contradicts that identifier.
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

	// ECDSA accepts both (r, s) and (r, n - s) unless the verifier refuses the
	// high form. One signature must have one valid encoding, so a relay cannot
	// rewrite a signed frame into a second valid frame.
	#[test]
	fn a_high_s_signature_is_refused() -> crate::error::Result<()> {
		let signing_key = SigningKey::random(&mut OsRng);
		let low: Signature = sign_canonical::<Sha3_256, _>(&signing_key, CONTENT)?;
		let (r, s) = low.split_scalars();
		let high = Signature::from_scalars(r, -s)?;
		assert!(low.normalize_s().is_none());
		assert!(high.normalize_s().is_some());
		assert!(verify_canonical::<Sha3_256, _>(signing_key.verifying_key(), CONTENT, &low).is_ok());
		assert!(verify_canonical::<Sha3_256, _>(signing_key.verifying_key(), CONTENT, &high).is_err());

		Ok(())
	}
}
