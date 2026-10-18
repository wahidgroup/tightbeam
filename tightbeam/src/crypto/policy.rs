//! Cryptographic verification policies.
//!
//! This module provides traits for algorithm-agnostic signature verification,
//! and [`VerifiedSignature`], the one value a successful verification returns.

#[cfg(all(feature = "x509", not(feature = "std")))]
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "x509")]
use core::fmt::Debug;
#[cfg(feature = "signature")]
use core::marker::PhantomData;

#[cfg(feature = "x509")]
use ecdsa::signature::hazmat::PrehashVerifier;
#[cfg(feature = "x509")]
use ecdsa::signature::{Error, SignatureEncoding};

#[cfg(feature = "signature")]
use crate::crypto::profiles::SigningProvider;
#[cfg(feature = "x509")]
use crate::crypto::x509::error::CertificateValidationError;
#[cfg(feature = "x509")]
use crate::der::oid::ObjectIdentifier;
#[cfg(feature = "signature")]
use crate::spki::DecodePublicKey;

/// A signature encoding that has one canonical form for each signature.
///
/// ECDSA verifies `(r, s)` and `(r, n - s)` alike (SEC 1 v2.0 §4.1.4), so a
/// verifier accepts both and brings each to one form before it verifies.
#[cfg(feature = "x509")]
pub trait CanonicalForm: Sized {
	/// Parse `encoded` as this encoding alone, and return its canonical form.
	///
	/// # Errors
	///
	/// - [`Error`] -- `encoded` is not this encoding, or a value in it is out of range.
	fn canonical(encoded: &[u8]) -> Result<Self, Error>;
}

/// An ECDSA-Sig-Value in DER (RFC 3279 §2.2.3) with `s` in the low half of
/// the curve order.
///
/// The parse accepts DER alone, so a raw `r || s` value is refused.
#[cfg(all(feature = "x509", feature = "secp256k1"))]
impl CanonicalForm for ecdsa::der::Signature<k256::Secp256k1> {
	fn canonical(encoded: &[u8]) -> Result<Self, Error> {
		let parsed = Self::from_bytes(encoded)?;
		let scalars = ecdsa::Signature::<k256::Secp256k1>::try_from(parsed)?;
		let low = scalars.normalize_s().unwrap_or(scalars);
		Ok(low.to_der())
	}
}

/// A signature that verified, in its canonical form.
///
/// [`Self::verify`] is the one producer. A replay guard or a ledger keys on
/// this value, so a signature and its `(r, n - s)` twin are one key.
#[cfg(feature = "x509")]
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct VerifiedSignature(Box<[u8]>);

#[cfg(feature = "x509")]
impl VerifiedSignature {
	/// Parse `encoded` as `S`, bring it to its canonical form, and verify it
	/// over `prehash` under `verifier`.
	///
	/// # Errors
	///
	/// - [`Error`] -- `encoded` is not an `S` encoding, or the signature fails to verify.
	pub fn verify<S, V>(verifier: &V, prehash: impl AsRef<[u8]>, encoded: impl AsRef<[u8]>) -> Result<Self, Error>
	where
		S: CanonicalForm + SignatureEncoding,
		V: PrehashVerifier<S> + ?Sized,
	{
		let canonical = S::canonical(encoded.as_ref())?;
		verifier.verify_prehash(prehash.as_ref(), &canonical)?;

		Ok(Self(canonical.to_vec().into_boxed_slice()))
	}

	/// The canonical encoding of the signature.
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}
}

/// Trait for cryptographic verification policies.
///
/// This trait defines how to verify signatures in an object-safe manner.
/// Implementations handle algorithm-specific parsing and verification
/// internally, allowing callers to remain algorithm-agnostic.
///
/// # Object Safety
///
/// This trait is object-safe and can be used with `Arc<dyn VerificationPolicy>`.
#[cfg(feature = "x509")]
pub trait VerificationPolicy: Send + Sync + Debug {
	/// Verify a signature given algorithm OID, public key, message, and
	/// signature bytes.
	///
	/// The implementation handles all algorithm-specific logic internally:
	/// - Parsing public key bytes into the appropriate key type
	/// - Parsing signature bytes into the appropriate signature type
	/// - Performing the cryptographic verification
	///
	/// It returns the signature in its canonical form, as
	/// [`VerifiedSignature::verify`] produces it.
	///
	/// # Arguments
	/// * `algorithm_oid` - The signature algorithm OID from the certificate
	/// * `public_key_der` - DER-encoded public key of the signer
	/// * `message` - The message that was signed (e.g., TBS certificate DER)
	/// * `signature` - Encoded signature bytes
	///
	/// # Errors
	///
	/// - [`CertificateValidationError`] -- the algorithm is unsupported, or
	///   the key, the signature, or the verification fails.
	fn verify_signature(
		&self,
		algorithm_oid: &ObjectIdentifier,
		public_key_der: &[u8],
		message: &[u8],
		signature: &[u8],
	) -> Result<VerifiedSignature, CertificateValidationError>;

	/// Digest `content` under `digest_oid`, the digest algorithm of a CMS
	/// signer whose signature algorithm is `signature_oid`.
	///
	/// A CMS signer digests its content under its `digestAlgorithm` (RFC 5652
	/// §5.4), which MUST be the digest its signature algorithm names (RFC 5753
	/// §2.1.1). A verifier of the message-digest attribute asks the policy.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::UnsupportedAlgorithm`] -- the policy holds no such pair.
	fn digest(
		&self,
		signature_oid: &ObjectIdentifier,
		digest_oid: &ObjectIdentifier,
		content: &[u8],
	) -> Result<Vec<u8>, CertificateValidationError>;
}

// ============================================================================
// Secp256k1 Policy Implementation
// ============================================================================

/// The house verification policy: ECDSA with SHA3-256 on secp256k1, the
/// policy of [`DefaultCryptoProvider`].
///
/// [`DefaultCryptoProvider`]: crate::crypto::profiles::DefaultCryptoProvider
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
pub type Secp256k1Policy = ProviderPolicy<crate::crypto::profiles::DefaultCryptoProvider>;

/// The verification policy of a [`SigningProvider`] `P`: it verifies the
/// signature type of `P` under the verifying key of `P`, decoded from a
/// SubjectPublicKeyInfo, and digests under the digest that signature names.
///
/// It is the one policy, so an implementor's provider verifies as the house
/// provider does, and a signing identity keeps a `'static` one.
#[cfg(feature = "signature")]
pub struct ProviderPolicy<P>(PhantomData<fn() -> P>);

#[cfg(feature = "signature")]
impl<P> ProviderPolicy<P> {
	/// The policy of `P`.
	pub const fn new() -> Self {
		Self(PhantomData)
	}
}

#[cfg(feature = "signature")]
impl<P> Default for ProviderPolicy<P> {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(feature = "signature")]
impl<P> Clone for ProviderPolicy<P> {
	fn clone(&self) -> Self {
		*self
	}
}

#[cfg(feature = "signature")]
impl<P> Copy for ProviderPolicy<P> {}

/// The provider names the policy, since the type holds no value.
#[cfg(feature = "signature")]
impl<P> Debug for ProviderPolicy<P> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_tuple("ProviderPolicy").field(&core::any::type_name::<P>()).finish()
	}
}

#[cfg(feature = "signature")]
impl<P> VerificationPolicy for ProviderPolicy<P>
where
	P: SigningProvider,
	P::VerifyingKey: DecodePublicKey,
{
	fn verify_signature(
		&self,
		algorithm_oid: &ObjectIdentifier,
		bytes: &[u8],
		content: &[u8],
		signature: &[u8],
	) -> Result<VerifiedSignature, CertificateValidationError> {
		use crate::crypto::hash::Digest;
		use crate::crypto::sign::SignatureAlgorithmIdentifier;

		type SignatureDigest<P> = <<P as SigningProvider>::Signature as SignatureAlgorithmIdentifier>::Digest;

		// The policy implements exactly one algorithm, so it refuses any
		// other advertised OID.
		if *algorithm_oid != P::Signature::ALGORITHM_OID {
			return Err(CertificateValidationError::UnsupportedAlgorithm(*algorithm_oid));
		}

		// RFC 5280 §6.1.3(a)(1): cryptographic signature verification primitive
		// under the canonical convention (the prehash of the named digest).
		let verifier = P::VerifyingKey::from_public_key_der(bytes)?;
		let prehash = SignatureDigest::<P>::digest(content);

		Ok(VerifiedSignature::verify::<P::Signature, _>(&verifier, prehash, signature)?)
	}

	/// The policy holds one pair: its signature algorithm and the digest that
	/// algorithm names.
	fn digest(
		&self,
		signature_oid: &ObjectIdentifier,
		digest_oid: &ObjectIdentifier,
		content: &[u8],
	) -> Result<Vec<u8>, CertificateValidationError> {
		use crate::crypto::hash::Digest;
		use crate::crypto::sign::SignatureAlgorithmIdentifier;
		use crate::der::oid::AssociatedOid;

		type SignatureDigest<P> = <<P as SigningProvider>::Signature as SignatureAlgorithmIdentifier>::Digest;

		if *signature_oid != P::Signature::ALGORITHM_OID {
			return Err(CertificateValidationError::UnsupportedAlgorithm(*signature_oid));
		}
		if *digest_oid != SignatureDigest::<P>::OID {
			return Err(CertificateValidationError::UnsupportedAlgorithm(*digest_oid));
		}

		Ok(SignatureDigest::<P>::digest(content).to_vec())
	}
}

#[cfg(all(
	test,
	feature = "secp256k1",
	feature = "signature",
	feature = "x509",
	feature = "sha3"
))]
mod tests {
	use signature::DigestSigner;

	use super::{CanonicalForm, Secp256k1Policy, VerificationPolicy, VerifiedSignature};
	use crate::crypto::hash::{Digest, Sha3_256};
	use crate::crypto::sign::ecdsa::{Secp256k1, Secp256k1Signature, Secp256k1SigningKey, Signature};
	use crate::crypto::sign::CanonicalSigner;
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::oids::{HASH_SHA3_256, HASH_SHA3_512, SIGNER_ECDSA_WITH_SHA256, SIGNER_ECDSA_WITH_SHA3_256};
	use crate::spki::EncodePublicKey;
	use crate::testing::TestKey;

	/// Content whose raw `s` under the fixed test key lies in the high half,
	/// so a signer that skips the low-s rule fails the tests that sign it.
	const CONTENT: &[u8] = b"cms signer content";

	/// The low-s signature the fixed test key makes over [`CONTENT`], with the
	/// `(r, n - s)` twin that an external signer may emit for it.
	fn low_and_high() -> (Signature<Secp256k1>, Signature<Secp256k1>) {
		let signing_key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let low: Secp256k1Signature = signing_key.sign_canonical::<Sha3_256>(CONTENT).expect("the test key signs");
		let low = Signature::<Secp256k1>::try_from(low).expect("a DER signature holds two scalars");
		let (r, s) = low.split_scalars();
		let high = Signature::<Secp256k1>::from_scalars(r, -s).expect("n - s is a scalar");

		(low, high)
	}

	/// Interop: a signature produced by the `ecdsa` crate's own
	/// `DigestSigner<Sha3_256>` path -- independent of this crate's
	/// `sign_canonical` -- must verify under the advertised
	/// ecdsa-with-SHA3-256 OID.
	#[test]
	fn verifies_independent_sha3_ecdsa_signature() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let message = b"independent sha3-ecdsa interop";

		let mut digest = Sha3_256::default();
		digest::Digest::update(&mut digest, message);

		let signature: Signature<Secp256k1> = signing_key.try_sign_digest(digest)?;
		let public_key_der = signing_key.verifying_key().to_public_key_der()?;
		Secp256k1Policy::default().verify_signature(
			&SIGNER_ECDSA_WITH_SHA3_256,
			public_key_der.as_bytes(),
			message,
			signature.to_der().as_bytes(),
		)?;

		Ok(())
	}

	/// The crate signs with `s` in the low half of the curve order.
	#[test]
	fn the_crate_signs_low_s() {
		let (low, _) = low_and_high();
		assert!(low.normalize_s().is_none());
	}

	/// A high-s value from an external signer verifies (SEC 1 v2.0 §4.1.4).
	#[test]
	fn a_high_s_signature_verifies() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let (_, high) = low_and_high();

		let prehash = Sha3_256::digest(CONTENT);
		let encoded = high.to_der();
		VerifiedSignature::verify::<Secp256k1Signature, _>(signing_key.verifying_key(), prehash, encoded)?;

		Ok(())
	}

	/// A signature and its `(r, n - s)` twin verify to one canonical value, so
	/// a ledger that keys on it keys the two as one.
	#[test]
	fn a_signature_and_its_high_s_twin_verify_to_one_value() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let (low, high) = low_and_high();
		let prehash = Sha3_256::digest(CONTENT);
		let verifier = signing_key.verifying_key();

		let from_low = VerifiedSignature::verify::<Secp256k1Signature, _>(verifier, prehash, low.to_der())?;
		let from_high = VerifiedSignature::verify::<Secp256k1Signature, _>(verifier, prehash, high.to_der())?;
		assert_eq!(from_low, from_high);
		Ok(())
	}

	/// A raw `r || s` value is no ECDSA-Sig-Value, so the parse refuses it.
	#[test]
	fn a_raw_r_s_value_is_refused() {
		let (low, _) = low_and_high();
		let raw = low.to_bytes();

		let parsed = Secp256k1Signature::canonical(&raw);
		assert!(parsed.is_err());
	}

	/// The DER of a high-s value comes back as the DER of its low-s twin.
	#[test]
	fn the_canonical_form_of_a_high_s_value_is_its_low_s_twin() -> Result<(), Box<dyn std::error::Error>> {
		let (low, high) = low_and_high();
		let canonical = Secp256k1Signature::canonical(high.to_der().as_bytes())?;
		assert_eq!(canonical.as_bytes(), low.to_der().as_bytes());
		Ok(())
	}

	/// RFC 6979 known answer: the fixed test key signs [`CONTENT`] under the
	/// SHA3-256 prehash to one DER value with a low `s`.
	///
	/// NIST CAVP publishes no secp256k1 vector, and RFC 6979 Appendix A holds
	/// none for this curve. An independent computation gives the value, and
	/// its raw `s` lies in the high half, so the value pins the low-s rule:
	///
	/// - RFC 6979 §3.2 with HMAC-SHA-256 over the SHA3-256 prehash.
	/// - The ECDSA equations of SEC 1 v2.0 §4.1.3, and the low-s rule.
	/// - The DER of RFC 3279 §2.2.3.
	#[test]
	fn the_signature_matches_its_rfc_6979_known_answer() -> Result<(), Box<dyn std::error::Error>> {
		const EXPECTED: [u8; 71] = [
			0x30, 0x45, 0x02, 0x21, 0x00, 0xf5, 0x73, 0x23, 0xf4, 0x99, 0xab, 0x6c, 0xc6, 0x03, 0x60, 0x2a, 0x78, 0x93,
			0x5d, 0x50, 0x54, 0x2c, 0xa8, 0x73, 0xdf, 0x00, 0x8b, 0xd7, 0xd6, 0x87, 0x08, 0x0d, 0xe7, 0x25, 0xb9, 0x6a,
			0xc9, 0x02, 0x20, 0x7d, 0x29, 0x30, 0x29, 0xd0, 0x3d, 0xac, 0x47, 0x14, 0x03, 0xc3, 0xae, 0x27, 0x66, 0xd0,
			0x12, 0x30, 0x08, 0xad, 0xbd, 0x2b, 0x66, 0x97, 0xba, 0xdf, 0x78, 0x72, 0xc2, 0xd6, 0xac, 0x1b, 0x61,
		];

		let signing_key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let signature: Secp256k1Signature = signing_key.sign_canonical::<Sha3_256>(CONTENT)?;
		assert_eq!(signature.as_bytes(), EXPECTED.as_slice());
		Ok(())
	}

	/// The policy refuses a digest its signature algorithm does not name (RFC
	/// 5753 §2.1.1).
	#[test]
	fn the_policy_refuses_a_digest_its_signature_algorithm_does_not_name() {
		let refused = Secp256k1Policy::default().digest(&SIGNER_ECDSA_WITH_SHA3_256, &HASH_SHA3_512, CONTENT);
		assert!(matches!(refused, Err(CertificateValidationError::UnsupportedAlgorithm(oid)) if oid == HASH_SHA3_512));
	}

	/// The policy refuses a signature algorithm other than its own, even
	/// beside the digest it implements.
	#[test]
	fn the_policy_refuses_a_signature_algorithm_it_does_not_hold() {
		let refused = Secp256k1Policy::default().digest(&SIGNER_ECDSA_WITH_SHA256, &HASH_SHA3_256, CONTENT);
		let unsupported = matches!(
			refused,
			Err(CertificateValidationError::UnsupportedAlgorithm(oid)) if oid == SIGNER_ECDSA_WITH_SHA256
		);
		assert!(unsupported);
	}
}
