//! Pluggable key backends for tightbeam transport encryption.
//!
//! The [`SigningKeyProvider`] trait abstracts the cryptographic key
//! operations, so a backend may hold its keys in memory, in an HSM, in a KMS,
//! or in an enclave.
//!
//! The trait is algorithm-agnostic and carries every value as bytes. A
//! concrete implementation such as [`EcdsaKeyProvider`] handles the
//! algorithm-specific encoding and decoding.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(all(not(feature = "std"), any(feature = "signature", feature = "aead")))]
use alloc::{boxed::Box, sync::Arc, vec::Vec};

use core::fmt::Debug;

#[cfg(feature = "aead")]
use core::future::Future;
#[cfg(feature = "aead")]
use core::pin::Pin;

use crate::Errorizable;

#[cfg(feature = "signature")]
use crate::utils::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
#[cfg(all(feature = "signature", feature = "ecdh"))]
use crate::zeroize::Zeroizing;
#[cfg(all(feature = "std", any(feature = "signature", feature = "aead")))]
use std::sync::Arc;

#[cfg(feature = "signature")]
mod signing {
	pub use crate::crypto::sign::ecdsa::{
		DigestPrimitive, Secp256k1, SignPrimitive, Signature, SignatureSize, SigningKey, VerifyPrimitive,
	};
	pub use crate::crypto::sign::elliptic_curve::generic_array::{ArrayLength, GenericArray};
	pub use crate::crypto::sign::elliptic_curve::ops::{Invert, Reduce};
	pub use crate::crypto::sign::elliptic_curve::point::PointCompression;
	pub use crate::crypto::sign::elliptic_curve::scalar::Scalar;
	pub use crate::crypto::sign::elliptic_curve::sec1::ModulusSize;
	pub use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
	pub use crate::crypto::sign::elliptic_curve::subtle::CtOption;
	pub use crate::crypto::sign::elliptic_curve::{
		AffinePoint, CurveArithmetic, Error as EllipticCurveError, FieldBytesSize, PrimeCurve,
	};
	pub use crate::crypto::sign::{
		Error as SignatureError, Keypair, PrehashSigner, SignatureAlgorithmIdentifier, SignatureEncoding,
	};

	#[cfg(feature = "ecdh")]
	pub use crate::crypto::sign::elliptic_curve::ecdh::diffie_hellman;
	#[cfg(feature = "ecdh")]
	pub use crate::crypto::sign::elliptic_curve::PublicKey;
}

#[cfg(feature = "signature")]
use signing::*;

#[cfg(feature = "aead")]
mod encryption {
	pub use crate::crypto::aead::{Aead, AeadAlgorithm, AeadCore, Aes128Gcm, Aes256Gcm, Error as AeadError, Nonce};
}

#[cfg(feature = "aead")]
use encryption::*;

#[cfg(any(feature = "signature", feature = "aead"))]
mod common {
	pub use crate::crypto::common::typenum::Unsigned;
	pub use crate::der::oid::AssociatedOid;
	pub use crate::spki::AlgorithmIdentifierOwned;

	#[cfg(feature = "signature")]
	pub use crate::spki::EncodePublicKey;
}

#[cfg(any(feature = "signature", feature = "aead"))]
use common::*;

#[cfg(any(feature = "signature", feature = "aead"))]
use crate::crypto::secret::SecretSlice;

/// Errors from key provider operations.
#[derive(Errorizable, Debug)]
pub enum KeyError {
	/// SPKI encoding or decoding failed.
	#[error("SPKI error: {0}")]
	SpkiError(crate::spki::Error),

	/// An elliptic curve operation failed.
	#[cfg(feature = "signature")]
	#[error("Elliptic curve error: {0}")]
	EllipticCurveError(EllipticCurveError),

	/// A signature or ECDSA operation failed, for example on invalid key bytes.
	#[cfg(feature = "signature")]
	#[error("Signature error: {0}")]
	SignatureError(SignatureError),

	/// AEAD encryption or decryption failed.
	#[cfg(feature = "aead")]
	#[error("AEAD error: {0}")]
	AeadError(AeadError),

	/// The nonce length differs from the cipher's nonce size.
	#[cfg(feature = "aead")]
	#[error("Nonce length mismatch: {0}")]
	NonceLengthError(crate::error::ReceivedExpectedError<usize, usize>),

	/// The signing key material has the wrong length for the curve.
	#[cfg(feature = "signature")]
	#[error("Signing key length mismatch: {0}")]
	KeyLengthError(crate::error::ReceivedExpectedError<usize, usize>),

	/// This key provider does not support the operation.
	#[error("Operation not supported by this key provider")]
	UnsupportedOperation,
}

crate::impl_from!(crate::spki::Error => KeyError::SpkiError);
crate::impl_from!(#[cfg(feature = "signature")] EllipticCurveError => KeyError::EllipticCurveError);
crate::impl_from!(#[cfg(feature = "signature")] SignatureError => KeyError::SignatureError);
crate::impl_from!(#[cfg(feature = "aead")] AeadError => KeyError::AeadError);

/// A signing key given as raw bytes or as a key provider.
///
/// Both forms suit configuration in const contexts, such as the `servlet!`
/// macro.
#[cfg(feature = "signature")]
#[derive(Debug, Clone)]
pub enum SigningKeySpec {
	/// Raw key bytes, such as a 32-byte secp256k1 scalar.
	Bytes(&'static [u8]),

	/// A key provider instance, such as an HSM or KMS backend.
	Provider(Arc<dyn SigningKeyProvider>),
}

#[cfg(feature = "signature")]
impl SigningKeySpec {
	/// Convert this key specification to a key provider for the ECDSA curve
	/// `C`.
	///
	/// - [`SigningKeySpec::Bytes`] builds an ECDSA signing key from the raw
	///   bytes and wraps it in an [`EcdsaKeyProvider`].
	/// - [`SigningKeySpec::Provider`] returns a clone of the existing provider handle.
	///
	/// # Type Parameters
	///
	/// - `C`: the elliptic curve type, such as `k256::Secp256k1`.
	///
	/// # Errors
	///
	/// - [`KeyError::KeyLengthError`] when the bytes are not the curve's field size.
	/// - [`KeyError::SignatureError`] when the bytes are not a valid signing key.
	pub fn to_provider<C>(&self) -> Result<Arc<dyn SigningKeyProvider>, KeyError>
	where
		C: PrimeCurve + CurveArithmetic + DigestPrimitive + PointCompression + AssociatedOid + Send + Sync + 'static,
		Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C> + Reduce<C::Uint>,
		SignatureSize<C>: ArrayLength<u8>,
		FieldBytesSize<C>: ModulusSize,
		AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
		SigningKey<C>: PrehashSigner<Signature<C>> + Keypair + Send + Sync + Debug + 'static,
		<SigningKey<C> as Keypair>::VerifyingKey: EncodePublicKey,
		Signature<C>: SignatureEncoding + SignatureAlgorithmIdentifier + Send + Sync + 'static,
	{
		match self {
			SigningKeySpec::Bytes(bytes) => {
				let expected = FieldBytesSize::<C>::USIZE;
				if bytes.len() != expected {
					return Err(KeyError::KeyLengthError((bytes.len(), expected).into()));
				}

				let field_bytes = GenericArray::from_slice(bytes);
				let signing_key = SigningKey::<C>::from_bytes(field_bytes)?;
				Ok(Arc::new(EcdsaKeyProvider::from(signing_key)))
			}
			SigningKeySpec::Provider(provider) => Ok(Arc::clone(provider)),
		}
	}
}

/// A pluggable backend for private key operations.
///
/// An implementation provides key agreement and signing without exposing the
/// raw key material. Hardware Security Modules (HSMs), Key Management Services
/// (KMS), and secure enclaves can therefore hold private keys inside their
/// secure boundary.
///
/// # Security Properties
///
/// - **Key encapsulation**: private keys stay inside the provider boundary.
/// - **Uniform interface**: in-memory and remote backends use identical APIs.
/// - **Async by default**: every operation is async, so a remote backend fits the same API.
/// - **Algorithm agnostic**: the byte encoding admits any signature or key algorithm.
///
/// # Threading
///
/// `Send`/`Sync` are required on every target except `wasm32`, where the
/// single-threaded executor lets JavaScript-backed providers (WebAuthn,
/// wallets, remote KMS bridges) implement the trait.
#[cfg(feature = "signature")]
pub trait SigningKeyProvider: MaybeSend + MaybeSync + Debug {
	/// Returns the algorithm identifier for this key.
	fn algorithm(&self) -> AlgorithmIdentifierOwned;

	/// Returns the public key as DER-encoded bytes.
	///
	/// # Errors
	///
	/// - [`KeyError`] when the backend fails to retrieve the public key.
	fn to_public_key_bytes(&self) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>>;

	/// Signs a precomputed digest (prehash) with this provider's private key.
	///
	/// The canonical tightbeam convention hashes content exactly once (see
	/// `crypto::sign::sign_canonical`). Providers MUST sign the given prehash
	/// directly, so the produced signature matches the advertised
	/// signature-algorithm OID whatever the backend. The result is the
	/// DER-encoded signature.
	///
	/// - `prehash`: the digest of the content to sign.
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>>;

	/// Performs key agreement, such as ECDH or X25519.
	///
	/// It computes a shared secret for session key derivation from this
	/// provider's private key and the peer's public key. The result is a
	/// [`SecretSlice`], so the secret zeroizes on drop (CWE-212).
	///
	/// - `peer_public_key`: the peer's public key bytes, SEC1 or DER encoded.
	///
	/// # Default
	///
	/// The default returns [`KeyError::UnsupportedOperation`], because some
	/// key types have no key agreement.
	fn key_agreement(&self, _peer_public_key: &[u8]) -> MaybeSendFuture<'_, Result<SecretSlice<u8>, KeyError>> {
		Box::pin(async { Err(KeyError::UnsupportedOperation) })
	}
}

/// A shared provider is a provider, so one handle serves every endpoint that
/// signs with the same key.
#[cfg(feature = "signature")]
impl<T: SigningKeyProvider + ?Sized> SigningKeyProvider for Arc<T> {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		T::algorithm(self)
	}

	fn to_public_key_bytes(&self) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		T::to_public_key_bytes(self)
	}

	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		T::sign_prehash(self, prehash)
	}

	fn key_agreement(&self, peer_public_key: &[u8]) -> MaybeSendFuture<'_, Result<SecretSlice<u8>, KeyError>> {
		T::key_agreement(self, peer_public_key)
	}
}

/// An ECDSA key provider that signs and runs ECDH key agreement.
///
/// It wraps an ECDSA signing key on any curve `C`. It is the recommended
/// provider for TLS handshakes.
///
/// # Type Parameters
///
/// - `C`: the elliptic curve type, such as `k256::Secp256k1` or `p256::NistP256`.
#[cfg(all(feature = "signature", feature = "secp256k1"))]
pub struct EcdsaKeyProvider<C>
where
	C: PrimeCurve + CurveArithmetic,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>,
{
	signing_key: SigningKey<C>,
}

#[cfg(all(feature = "signature", feature = "secp256k1"))]
impl<C> From<SigningKey<C>> for EcdsaKeyProvider<C>
where
	C: PrimeCurve + CurveArithmetic,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>,
{
	fn from(signing_key: SigningKey<C>) -> Self {
		EcdsaKeyProvider { signing_key }
	}
}

#[cfg(all(feature = "signature", feature = "secp256k1"))]
impl<C> Debug for EcdsaKeyProvider<C>
where
	C: PrimeCurve + CurveArithmetic,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>,
{
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("EcdsaKeyProvider")
			.field("curve", &core::any::type_name::<C>())
			.finish_non_exhaustive()
	}
}

#[cfg(all(feature = "signature", feature = "secp256k1"))]
impl<C> SigningKeyProvider for EcdsaKeyProvider<C>
where
	C: PrimeCurve + CurveArithmetic + DigestPrimitive + PointCompression + AssociatedOid + Send + Sync + 'static,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C> + Reduce<C::Uint>,
	SignatureSize<C>: ArrayLength<u8>,
	FieldBytesSize<C>: ModulusSize,
	AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
	SigningKey<C>: PrehashSigner<Signature<C>> + Keypair + Send + Sync + Debug,
	<SigningKey<C> as Keypair>::VerifyingKey: EncodePublicKey,
	Signature<C>: SignatureEncoding + SignatureAlgorithmIdentifier + Send + Sync,
{
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: Signature::<C>::ALGORITHM_OID, parameters: None }
	}

	fn to_public_key_bytes(&self) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let result = self
			.signing_key
			.verifying_key()
			.to_public_key_der()
			.map(|der| der.into_vec())
			.map_err(KeyError::from);

		Box::pin(async move { result })
	}

	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let result = self
			.signing_key
			.sign_prehash(prehash)
			.map(|signature: Signature<C>| signature.to_bytes().as_ref().to_vec())
			.map_err(KeyError::from);

		Box::pin(async move { result })
	}

	#[cfg(feature = "ecdh")]
	fn key_agreement(&self, peer_public_key: &[u8]) -> MaybeSendFuture<'_, Result<SecretSlice<u8>, KeyError>> {
		let pk_result = PublicKey::<C>::from_sec1_bytes(peer_public_key);
		// The scalar copy lives across the await, so `Zeroizing` wraps it. A
		// cancelled agreement then drops the copy wiped, and no freed future
		// holds the private key (CWE-226).
		let secret_key = Zeroizing::new(*self.signing_key.as_nonzero_scalar());

		Box::pin(async move {
			let pk = pk_result?;
			let shared_secret = diffie_hellman(*secret_key, pk.as_affine());
			Ok(SecretSlice::from(shared_secret.raw_secret_bytes().to_vec()))
		})
	}
}

/// The ECDSA key provider on secp256k1, with ECDH.
#[cfg(feature = "signature")]
pub type Secp256k1KeyProvider = EcdsaKeyProvider<Secp256k1>;

/// A pluggable backend for symmetric encryption keys.
///
/// An implementation provides symmetric encryption and decryption without
/// exposing the raw key material. Hardware Security Modules (HSMs), Key
/// Management Services (KMS), and secure enclaves can therefore hold
/// encryption keys inside their secure boundary.
///
/// # Security Properties
///
/// - **Key encapsulation**: encryption keys stay inside the provider boundary.
/// - **Uniform interface**: in-memory and remote backends use identical APIs.
/// - **Async by default**: every operation is async, so a remote backend fits the same API.
/// - **Algorithm agnostic**: the byte encoding admits any AEAD cipher.
#[cfg(feature = "aead")]
pub trait EncryptingKeyProvider: Send + Sync + Debug {
	/// Returns the algorithm identifier for this encryption key.
	fn algorithm(&self) -> AlgorithmIdentifierOwned;

	/// Encrypts `plaintext` under `nonce`.
	///
	/// The result is the ciphertext, which includes the authentication tag for
	/// AEAD ciphers.
	///
	/// - `nonce`: the nonce or IV for this operation. The caller MUST ensure
	///   each `(key, nonce)` pair is unique for AEAD ciphers.
	/// - `plaintext`: the data to encrypt.
	fn encrypt(
		&self,
		nonce: &[u8],
		plaintext: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>>;

	/// Decrypts `ciphertext` under `nonce`.
	///
	/// The result is the plaintext, which wipes when it drops.
	///
	/// - `nonce`: the nonce or IV used for encryption.
	/// - `ciphertext`: the encrypted data.
	fn decrypt(
		&self,
		nonce: &[u8],
		ciphertext: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<SecretSlice<u8>, KeyError>> + Send + '_>>;
}

/// A shared provider is a provider, as for [`SigningKeyProvider`].
#[cfg(feature = "aead")]
impl<T: EncryptingKeyProvider + ?Sized> EncryptingKeyProvider for Arc<T> {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		T::algorithm(self)
	}

	fn encrypt(
		&self,
		nonce: &[u8],
		plaintext: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		T::encrypt(self, nonce, plaintext)
	}

	fn decrypt(
		&self,
		nonce: &[u8],
		ciphertext: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<SecretSlice<u8>, KeyError>> + Send + '_>> {
		T::decrypt(self, nonce, ciphertext)
	}
}

/// An in-memory encryption key provider over any RustCrypto AEAD cipher.
///
/// This is the reference implementation of [`EncryptingKeyProvider`], and it
/// stores the encryption key in memory. It suits development, testing, and
/// applications that need no HSM or KMS integration.
///
/// # Type Parameters
///
/// - `A`: the AEAD cipher type, such as `Aes256Gcm` or `Aes128Gcm`. The cipher
///   type names the algorithm identifier that the provider reports.
///
/// # Security
///
/// For zeroization on drop, use keys that implement `ZeroizeOnDrop`.
#[cfg(feature = "aead")]
pub struct InMemoryEncryptingKeyProvider<A>
where
	A: AeadAlgorithm + Send + Sync + 'static,
{
	cipher: A,
}

#[cfg(feature = "aead")]
impl<A> From<A> for InMemoryEncryptingKeyProvider<A>
where
	A: AeadAlgorithm + Send + Sync + 'static,
{
	fn from(cipher: A) -> Self {
		InMemoryEncryptingKeyProvider { cipher }
	}
}

#[cfg(feature = "aead")]
impl<A> Debug for InMemoryEncryptingKeyProvider<A>
where
	A: AeadAlgorithm + Send + Sync + 'static,
{
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("InMemoryEncryptingKeyProvider")
			.field("algorithm", &<A::Oid as AssociatedOid>::OID)
			.finish_non_exhaustive()
	}
}

#[cfg(feature = "aead")]
impl<A> EncryptingKeyProvider for InMemoryEncryptingKeyProvider<A>
where
	A: AeadAlgorithm + Send + Sync + 'static,
{
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: <A::Oid as AssociatedOid>::OID, parameters: None }
	}

	fn encrypt(
		&self,
		nonce: &[u8],
		plaintext: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		let nonce_size = <<A as AeadCore>::NonceSize as Unsigned>::USIZE;
		let received_len = nonce.len();
		if received_len != nonce_size {
			return Box::pin(async move {
				Err(KeyError::NonceLengthError(crate::error::ReceivedExpectedError::from((
					received_len,
					nonce_size,
				))))
			});
		}

		let nonce_ref = Nonce::<A>::from_slice(nonce);
		let result = self.cipher.encrypt(nonce_ref, plaintext).map_err(KeyError::from);
		Box::pin(async move { result })
	}

	fn decrypt(
		&self,
		nonce: &[u8],
		ciphertext: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<SecretSlice<u8>, KeyError>> + Send + '_>> {
		let nonce_size = <<A as AeadCore>::NonceSize as Unsigned>::USIZE;
		let received_len = nonce.len();
		if received_len != nonce_size {
			return Box::pin(async move {
				Err(KeyError::NonceLengthError(crate::error::ReceivedExpectedError::from((
					received_len,
					nonce_size,
				))))
			});
		}

		let nonce_ref = Nonce::<A>::from_slice(nonce);
		let result = self
			.cipher
			.decrypt(nonce_ref, ciphertext)
			.map(SecretSlice::from)
			.map_err(KeyError::from);
		Box::pin(async move { result })
	}
}

#[cfg(all(feature = "aead", feature = "aes-gcm"))]
/// The in-memory AES-256-GCM encryption key provider.
pub type Aes256GcmKeyProvider = InMemoryEncryptingKeyProvider<Aes256Gcm>;

#[cfg(all(feature = "aead", feature = "aes-gcm"))]
/// The in-memory AES-128-GCM encryption key provider.
pub type Aes128GcmKeyProvider = InMemoryEncryptingKeyProvider<Aes128Gcm>;

#[cfg(test)]
mod tests {
	use rand_core::OsRng;

	use super::*;
	use crate::crypto::hash::{Digest, Sha3_256};
	use crate::crypto::secret::ToInsecure;
	use crate::crypto::sign::ecdsa::k256::ecdsa::SigningKey;
	use crate::crypto::sign::ecdsa::Secp256k1Signature;
	use crate::crypto::sign::PrehashVerifier;

	fn prehash(data: impl AsRef<[u8]>) -> Vec<u8> {
		let data = data.as_ref();
		let mut hasher = Sha3_256::new();
		hasher.update(data);
		hasher.finalize().to_vec()
	}

	#[tokio::test]
	async fn test_secp256k1_provider_public_key() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key = SigningKey::random(&mut OsRng);
		let provider = Secp256k1KeyProvider::from(signing_key);

		let public_key_bytes = provider.to_public_key_bytes().await?;
		// A DER-encoded secp256k1 SPKI is 88 bytes.
		assert_eq!(public_key_bytes.len(), 88);
		Ok(())
	}

	#[tokio::test]
	async fn test_secp256k1_provider_sign() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key = SigningKey::random(&mut OsRng);
		let provider = Secp256k1KeyProvider::from(signing_key.clone());

		let digest = prehash(b"test data to sign");
		let signature_bytes = provider.sign_prehash(&digest).await?;

		let signature = Secp256k1Signature::from_slice(&signature_bytes)?;
		signing_key.verifying_key().verify_prehash(&digest, &signature)?;

		Ok(())
	}

	#[tokio::test]
	async fn test_secp256k1_provider_key_agreement() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key1 = SigningKey::random(&mut OsRng);
		let signing_key2 = SigningKey::random(&mut OsRng);

		let provider1 = Secp256k1KeyProvider::from(signing_key1.clone());
		let provider2 = Secp256k1KeyProvider::from(signing_key2.clone());

		// This provider's `key_agreement` parses SEC1 public keys only, so the
		// test passes SEC1 points instead of DER SPKI.
		let public1 = signing_key1.verifying_key().to_encoded_point(false).as_bytes().to_vec();
		let public2 = signing_key2.verifying_key().to_encoded_point(false).as_bytes().to_vec();

		// Both sides must compute the same shared secret.
		let shared1 = provider1.key_agreement(&public2).await?.to_insecure();
		let shared2 = provider2.key_agreement(&public1).await?.to_insecure();

		assert_eq!(shared1, shared2);
		assert_eq!(shared1.len(), 32); // secp256k1 shared secret is 32 bytes
		Ok(())
	}

	#[tokio::test]
	async fn test_arc_secp256k1_provider() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key = SigningKey::random(&mut OsRng);
		let provider = Arc::new(Secp256k1KeyProvider::from(signing_key.clone()));

		// `Arc<Secp256k1KeyProvider>` implements `SigningKeyProvider`.
		let public_key_bytes = provider.to_public_key_bytes().await?;
		// A DER-encoded secp256k1 SPKI is 88 bytes.
		assert_eq!(public_key_bytes.len(), 88);

		let digest = prehash(b"test");
		let signature_bytes = provider.sign_prehash(&digest).await?;

		let signature = Secp256k1Signature::from_slice(&signature_bytes)?;
		signing_key.verifying_key().verify_prehash(&digest, &signature)?;

		// The one blanket impl serves a shared trait object as well.
		let shared: Arc<dyn SigningKeyProvider> = provider;
		assert_eq!(shared.to_public_key_bytes().await?, public_key_bytes);

		Ok(())
	}

	#[tokio::test]
	async fn test_algorithm_identifier() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key = SigningKey::random(&mut OsRng);
		let provider = Secp256k1KeyProvider::from(signing_key);

		let alg = provider.algorithm();
		assert_eq!(alg.oid, Secp256k1Signature::ALGORITHM_OID);
		Ok(())
	}

	/// Short key material reaches a typed refusal ahead of the
	/// fixed-size conversion's assert.
	#[test]
	fn short_signing_key_bytes_are_refused() {
		let spec = SigningKeySpec::Bytes(&[0u8; 5]);
		let refused = spec.to_provider::<crate::crypto::sign::ecdsa::k256::Secp256k1>();
		assert!(matches!(refused, Err(KeyError::KeyLengthError(_))));
	}
}
