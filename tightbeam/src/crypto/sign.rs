//! Signatures: the ECDSA primitives, the CMS signer, and the signing
//! identity.
//!
//! - [`CmsSigner`] builds and verifies every `SignerInfo`, and every `SignedData` that holds one.
//! - [`SigningIdentity`] pairs a signing certificate with the key provider that proves it.
//! - [`CertifiedKey`] pairs a certificate with a key that signs in place.
//! - [`VerifiedSignature`] is what a successful verification returns, in its canonical form.
//!
//! ## Signature values
//!
//! An ECDSA signature value is the DER `ECDSA-Sig-Value` (RFC 3279 §2.2.3,
//! RFC 5753 §2.1.1) with `s` in the low half of the curve order. The signer
//! brings every value a key returns to that form before it attaches it. A
//! verifier parses DER alone, takes the low-s form, and then verifies, so a
//! high-s value from another signer verifies (SEC 1 v2.0 §4.1.4).

pub mod ecdsa {
	pub use ecdsa::der;
	pub use ecdsa::hazmat::{DigestPrimitive, SignPrimitive, VerifyPrimitive};
	pub use ecdsa::{Error, Signature, SignatureSize, SigningKey, VerifyingKey};

	#[cfg(feature = "secp256k1")]
	pub use k256;
	#[cfg(feature = "secp256k1")]
	pub use k256::{
		ecdsa::{
			DerSignature as Secp256k1Signature, SigningKey as Secp256k1SigningKey,
			VerifyingKey as Secp256k1VerifyingKey,
		},
		schnorr, Secp256k1,
	};
}

pub use elliptic_curve;
pub use signature::hazmat::{PrehashSigner, PrehashVerifier};
pub use signature::{Error, Keypair, SignatureEncoding, Signer, Verifier};

pub use crate::crypto::policy::{CanonicalForm, VerifiedSignature};
pub use crate::frame::Signed;

mod error;
mod identity;
mod signer;

pub use error::SignerError;
pub use identity::{CertifiedKey, SigningIdentity};
pub(crate) use signer::SignerSeal;
pub use signer::{CmsSigner, SignedContent, SignerInfoDraft};

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) use signer::CertifiedSigner;
#[cfg(test)]
pub(crate) use signer::CmsAlgorithmProtection;

use crate::crypto::hash::Digest;
use crate::der::asn1::ObjectIdentifier;
use crate::der::oid::AssociatedOid;
use crate::oids::SIGNER_ECDSA_WITH_SHA3_256;

/// Create a SignatureInfo by signing data.
#[macro_export]
#[cfg(feature = "signature")]
macro_rules! sign {
	($signer:expr, $data:expr) => {{
		let unsigned_bytes = $crate::encode(&$data)?;
		$signer(&unsigned_bytes)
	}};
}

/// A signature type that names its algorithm OID and the digest that OID
/// names.
///
/// Generic code reads both from the type, so one code path serves different
/// signature algorithms such as ECDSA-SHA256, ECDSA-SHA3-256, and Ed25519.
pub trait SignatureAlgorithmIdentifier {
	/// The OID for this signature algorithm. For example, ECDSA with SHA-256 is
	/// `1.2.840.10045.4.3.2`.
	const ALGORITHM_OID: ObjectIdentifier;

	/// The digest algorithm the OID names, which a CMS signer of this
	/// algorithm digests under (RFC 5753 §2.1.1).
	type Digest: Digest + AssociatedOid;
}

/// A signer that signs under the canonical bytes-to-sign derivation.
///
/// Every [`PrehashSigner`] is one. [`VerifiedSignature::verify`] is the
/// counterpart over the same prehash.
pub trait CanonicalSigner<S>: PrehashSigner<S> {
	/// Sign `content` under the canonical derivation, which hashes `content`
	/// exactly once with `D` and signs the resulting digest as an ECDSA
	/// prehash.
	///
	/// # Errors
	///
	/// - [`Error`] -- the signer refused the prehash.
	fn sign_canonical<D>(&self, content: impl AsRef<[u8]>) -> core::result::Result<S, Error>
	where
		D: Digest,
	{
		let mut hasher = D::new();
		hasher.update(content.as_ref());
		self.sign_prehash(&hasher.finalize())
	}
}

impl<S, T> CanonicalSigner<S> for T where T: PrehashSigner<S> + ?Sized {}

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
		self.0.sign_canonical::<sha3::Sha3_256>(msg)
	}
}

impl<'a, S> From<&'a S> for Sha3Signer<'a, S> {
	fn from(s: &'a S) -> Self {
		Sha3Signer(s)
	}
}

#[cfg(feature = "secp256k1")]
impl SignatureAlgorithmIdentifier for ecdsa::Secp256k1Signature {
	/// ECDSA with SHA3-256 is `2.16.840.1.101.3.4.3.10`.
	const ALGORITHM_OID: ObjectIdentifier = SIGNER_ECDSA_WITH_SHA3_256;

	type Digest = sha3::Sha3_256;
}

#[cfg(all(test, feature = "secp256k1"))]
mod tests;
