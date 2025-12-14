//! Pluggable key backend abstraction for tightbeam transport encryption.
//!
//! This module provides the [`KeyProvider`] trait, which abstracts cryptographic
//! key operations to enable flexible backend integration (in-memory, HSM, KMS, enclave).
//!
//! The trait is algorithm-agnostic, using byte representations for all values.
//! Concrete implementations (e.g., [`InMemoryKeyProvider`]) handle algorithm-specific
//! encoding/decoding.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};

#[cfg(feature = "std")]
use std::sync::Arc;

use core::fmt::Debug;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;

#[cfg(feature = "signature")]
mod signing {
	pub use crate::crypto::sign::ecdsa::{
		DigestPrimitive, Secp256k1, Secp256k1Signature, Secp256k1SigningKey, SignPrimitive, Signature, SignatureSize,
		SigningKey, VerifyPrimitive,
	};
	pub use crate::crypto::sign::elliptic_curve::ecdh::diffie_hellman;
	pub use crate::crypto::sign::elliptic_curve::generic_array::{ArrayLength, GenericArray};
	pub use crate::crypto::sign::elliptic_curve::ops::{Invert, Reduce};
	pub use crate::crypto::sign::elliptic_curve::point::PointCompression;
	pub use crate::crypto::sign::elliptic_curve::scalar::Scalar;
	pub use crate::crypto::sign::elliptic_curve::sec1::ModulusSize;
	pub use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
	pub use crate::crypto::sign::elliptic_curve::subtle::CtOption;
	pub use crate::crypto::sign::elliptic_curve::{
		AffinePoint, CurveArithmetic, Error as EllipticCurveError, FieldBytesSize, PrimeCurve, PublicKey,
	};
	pub use crate::crypto::sign::{
		Error as SignatureError, Keypair, SignatureAlgorithmIdentifier, SignatureEncoding, Signer,
	};
}

#[cfg(feature = "signature")]
use signing::*;

#[cfg(feature = "aead")]
mod encryption {
	pub use crate::crypto::aead::{
		Aead, AeadCore, Aes128Gcm, Aes128cmOid, Aes256Gcm, Aes256GcmOid, Error as AeadError, Nonce,
	};
	pub use crate::crypto::common::typenum::Unsigned;
}

#[cfg(feature = "aead")]
use encryption::*;

mod common {
	pub use crate::der::oid::AssociatedOid;
	pub use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey};
}

use common::*;

#[cfg(feature = "derive")]
use crate::Errorizable;

// =============================================================================
// KeyError
// =============================================================================

/// Errors from key provider operations.
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum KeyError {
	/// SPKI encoding/decoding error
	#[cfg_attr(feature = "derive", error("SPKI error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	SpkiError(crate::spki::Error),

	/// Elliptic curve operation error
	#[cfg(feature = "signature")]
	#[cfg_attr(feature = "derive", error("Elliptic curve error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	EllipticCurveError(EllipticCurveError),

	/// Signature/ECDSA error (e.g., invalid key bytes)
	#[cfg(feature = "signature")]
	#[cfg_attr(feature = "derive", error("Signature error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	SignatureError(SignatureError),

	/// AEAD encryption/decryption error
	#[cfg(feature = "aead")]
	#[cfg_attr(feature = "derive", error("AEAD error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	AeadError(AeadError),

	/// Nonce length mismatch
	#[cfg(feature = "aead")]
	#[cfg_attr(
		feature = "derive",
		error("Nonce length mismatch: expected {expected}, got {received}")
	)]
	NonceLengthError(crate::error::ReceivedExpectedError<usize, usize>),

	/// Operation not supported by this key provider
	#[cfg_attr(feature = "derive", error("Operation not supported by this key provider"))]
	UnsupportedOperation,
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for KeyError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			KeyError::SpkiError(e) => write!(f, "SPKI error: {}", e),
			#[cfg(feature = "signature")]
			KeyError::EllipticCurveError(e) => write!(f, "Elliptic curve error: {}", e),
			#[cfg(feature = "signature")]
			KeyError::SignatureError(e) => write!(f, "Signature error: {}", e),
			#[cfg(feature = "aead")]
			KeyError::AeadError(e) => write!(f, "AEAD error: {}", e),
			#[cfg(feature = "aead")]
			KeyError::NonceLengthError(e) => write!(f, "Nonce length mismatch: {}", e),
			KeyError::UnsupportedOperation => write!(f, "Operation not supported by this key provider"),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for KeyError {}

/// Specification for providing a cryptographic signing key in various formats.
///
/// This enum allows keys to be specified in multiple ways for flexible
/// configuration in const contexts (e.g., servlet! macro).
#[cfg(feature = "signature")]
#[derive(Debug, Clone)]
pub enum SigningKeySpec {
	/// Raw key bytes (e.g., secp256k1 scalar - 32 bytes)
	Bytes(&'static [u8]),

	/// Key provider instance (for HSM/KMS)
	Provider(Arc<dyn SigningKeyProvider>),
}

#[cfg(feature = "signature")]
impl SigningKeySpec {
	/// Convert this key specification to a key provider for the given ECDSA curve.
	///
	/// For `KeySpec::Bytes`, constructs an ECDSA signing key from the raw bytes
	/// and wraps it in an `InMemoryKeyProvider`. For `KeySpec::Provider`, returns
	/// a clone of the existing provider Arc.
	///
	/// # Type Parameters
	///
	/// * `C` - The elliptic curve type (e.g., `k256::Secp256k1`)
	pub fn to_provider<C>(&self) -> Result<Arc<dyn SigningKeyProvider>, KeyError>
	where
		C: PrimeCurve + CurveArithmetic + DigestPrimitive + PointCompression + AssociatedOid + Send + Sync + 'static,
		Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C> + Reduce<C::Uint>,
		SignatureSize<C>: ArrayLength<u8>,
		FieldBytesSize<C>: ModulusSize,
		AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
		SigningKey<C>: Signer<Signature<C>> + Keypair + Send + Sync + Debug + 'static,
		<SigningKey<C> as Keypair>::VerifyingKey: EncodePublicKey,
		Signature<C>: SignatureEncoding + SignatureAlgorithmIdentifier + Send + Sync + 'static,
	{
		match self {
			SigningKeySpec::Bytes(bytes) => {
				let field_bytes = GenericArray::from_slice(bytes);
				let signing_key = SigningKey::<C>::from_bytes(field_bytes)?;
				Ok(Arc::new(EcdsaKeyProvider::from(signing_key)))
			}
			SigningKeySpec::Provider(provider) => Ok(Arc::clone(provider)),
		}
	}
}

/// Trait for pluggable cryptographic key backends.
///
/// Implementations of this trait provide access to private key operations
/// (key agreement, signing) without exposing the raw key material. This
/// enables integration with Hardware Security Modules (HSMs), Key Management
/// Services (KMS), and secure enclaves where private keys cannot leave the
/// secure boundary.
///
/// # Security Properties
///
/// - **Key Encapsulation**: Private keys never leave the provider boundary
/// - **Uniform Interface**: In-memory and remote backends use identical APIs
/// - **Async by Default**: All operations async for maximum flexibility
/// - **Algorithm Agnostic**: Byte encoding allows any signature/key algorithm
#[cfg(feature = "signature")]
pub trait SigningKeyProvider: Send + Sync + Debug {
	/// Returns the algorithm identifier for this key.
	fn algorithm(&self) -> AlgorithmIdentifierOwned;

	/// Returns the public key as DER-encoded bytes.
	///
	/// # Errors
	///
	/// Returns [`KeyError`] if the backend cannot retrieve the public key.
	fn to_public_key_bytes(&self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>>;

	/// Signs data using this provider's private key.
	///
	/// # Arguments
	///
	/// * `data` - The data to sign (typically a message or hash)
	///
	/// # Returns
	///
	/// DER-encoded signature bytes.
	fn sign(&self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>>;

	/// Performs key agreement (ECDH, X25519, etc).
	///
	/// Computes a shared secret from this provider's private key and the peer's
	/// public key. The shared secret is used for session key derivation.
	///
	/// # Arguments
	///
	/// * `peer_public_key` - The peer's public key bytes (SEC1 or DER encoded)
	///
	/// # Returns
	///
	/// The computed shared secret bytes.
	///
	/// # Default
	///
	/// Returns `UnsupportedOperation` - not all key types support key agreement.
	fn key_agreement(
		&self,
		_peer_public_key: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		Box::pin(async { Err(KeyError::UnsupportedOperation) })
	}
}

/// In-memory key provider generic over any RustCrypto signing key.
///
/// This is the reference implementation for [`KeyProvider`], storing the private
/// key directly in memory. Suitable for development, testing, and applications
/// where HSM/KMS integration is not required.
///
/// # Type Parameters
///
/// * `K` - The signing key type (e.g., `Secp256k1SigningKey`, `Ed25519SigningKey`)
/// * `S` - The signature type produced by `K`
///
/// # Security
///
/// For zeroization on drop, use keys that implement `ZeroizeOnDrop`
/// (e.g., k256's `SigningKey`).
#[cfg(feature = "signature")]
pub struct InMemorySigningKeyProvider<K, S>
where
	K: Signer<S> + Keypair,
	S: SignatureEncoding,
{
	signing_key: K,
	_sig: PhantomData<S>,
}

#[cfg(feature = "signature")]
impl<K, S> From<K> for InMemorySigningKeyProvider<K, S>
where
	K: Signer<S> + Keypair,
	S: SignatureEncoding,
{
	fn from(signing_key: K) -> Self {
		InMemorySigningKeyProvider { signing_key, _sig: PhantomData }
	}
}

#[cfg(feature = "signature")]
impl<K, S> Debug for InMemorySigningKeyProvider<K, S>
where
	K: Signer<S> + Keypair + Debug,
	S: SignatureEncoding,
{
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("InMemoryKeyProvider")
			.field("signing_key", &self.signing_key)
			.finish()
	}
}

#[cfg(feature = "signature")]
impl<K, S> SigningKeyProvider for InMemorySigningKeyProvider<K, S>
where
	K: Signer<S> + Keypair + Send + Sync + Debug + 'static,
	K::VerifyingKey: EncodePublicKey,
	S: SignatureEncoding + SignatureAlgorithmIdentifier + Send + Sync + 'static,
{
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: S::ALGORITHM_OID, parameters: None }
	}

	fn to_public_key_bytes(&self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		let result = self
			.signing_key
			.verifying_key()
			.to_public_key_der()
			.map(|der| der.into_vec())
			.map_err(KeyError::from);
		Box::pin(async move { result })
	}

	fn sign(&self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		let signature: S = self.signing_key.sign(data);
		let bytes = signature.to_bytes().as_ref().to_vec();
		Box::pin(async move { Ok(bytes) })
	}
}

// Implement KeyProvider for Arc<InMemoryKeyProvider<K, S>> for convenience
#[cfg(feature = "signature")]
impl<K, S> SigningKeyProvider for Arc<InMemorySigningKeyProvider<K, S>>
where
	K: Signer<S> + Keypair + Send + Sync + Debug + 'static,
	K::VerifyingKey: EncodePublicKey,
	S: SignatureEncoding + SignatureAlgorithmIdentifier + Send + Sync + 'static,
{
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.as_ref().algorithm()
	}

	fn to_public_key_bytes(&self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		self.as_ref().to_public_key_bytes()
	}

	fn sign(&self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		self.as_ref().sign(data)
	}
}

/// Type alias for secp256k1 key provider (signing only, no ECDH)
#[cfg(all(feature = "signature", feature = "secp256k1"))]
pub type Secp256k1Provider = InMemorySigningKeyProvider<Secp256k1SigningKey, Secp256k1Signature>;

// ============================================================================
// ECDSA Key Provider with ECDH Support (Generic)
// ============================================================================

/// Generic ECDSA key provider with signing and key agreement (ECDH) support.
///
/// This provider wraps an ECDSA signing key for any curve `C` and provides both
/// signing and ECDH operations. This is the recommended provider for TLS handshakes.
///
/// # Type Parameters
///
/// * `C` - The elliptic curve type (e.g., `k256::Secp256k1`, `p256::NistP256`)
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
	SigningKey<C>: Signer<Signature<C>> + Keypair + Send + Sync + Debug,
	<SigningKey<C> as Keypair>::VerifyingKey: EncodePublicKey,
	Signature<C>: SignatureEncoding + SignatureAlgorithmIdentifier + Send + Sync,
{
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: Signature::<C>::ALGORITHM_OID, parameters: None }
	}

	fn to_public_key_bytes(&self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		let result = self
			.signing_key
			.verifying_key()
			.to_public_key_der()
			.map(|der| der.into_vec())
			.map_err(KeyError::from);
		Box::pin(async move { result })
	}

	fn sign(&self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		let signature: Signature<C> = self.signing_key.sign(data);
		let bytes: Vec<u8> = signature.to_bytes().as_ref().to_vec();
		Box::pin(async move { Ok(bytes) })
	}

	fn key_agreement(
		&self,
		peer_public_key: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		let pk_result = PublicKey::<C>::from_sec1_bytes(peer_public_key);
		let secret_key = *self.signing_key.as_nonzero_scalar();

		Box::pin(async move {
			let pk = pk_result?;
			let shared_secret = diffie_hellman(secret_key, pk.as_affine());
			Ok(shared_secret.raw_secret_bytes().to_vec())
		})
	}
}

#[cfg(all(feature = "signature", feature = "secp256k1"))]
impl<C> SigningKeyProvider for Arc<EcdsaKeyProvider<C>>
where
	C: PrimeCurve + CurveArithmetic + DigestPrimitive + PointCompression + AssociatedOid + Send + Sync + 'static,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C> + Reduce<C::Uint>,
	SignatureSize<C>: ArrayLength<u8>,
	FieldBytesSize<C>: ModulusSize,
	AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
	SigningKey<C>: Signer<Signature<C>> + Keypair + Send + Sync + Debug,
	<SigningKey<C> as Keypair>::VerifyingKey: EncodePublicKey,
	Signature<C>: SignatureEncoding + SignatureAlgorithmIdentifier + Send + Sync,
{
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.as_ref().algorithm()
	}

	fn to_public_key_bytes(&self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		self.as_ref().to_public_key_bytes()
	}

	fn sign(&self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		self.as_ref().sign(data)
	}

	fn key_agreement(
		&self,
		peer_public_key: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		self.as_ref().key_agreement(peer_public_key)
	}
}

/// Type alias for secp256k1-specific ECDSA key provider with ECDH
#[cfg(feature = "signature")]
pub type Secp256k1KeyProvider = EcdsaKeyProvider<Secp256k1>;

// ============================================================================
// EncryptingKeyProvider Trait
// ============================================================================

/// Trait for pluggable symmetric encryption key backends.
///
/// Implementations of this trait provide access to symmetric encryption
/// and decryption operations without exposing the raw key material. This
/// enables integration with Hardware Security Modules (HSMs), Key Management
/// Services (KMS), and secure enclaves where encryption keys cannot leave the
/// secure boundary.
///
/// # Security Properties
///
/// - **Key Encapsulation**: Encryption keys never leave the provider boundary
/// - **Uniform Interface**: In-memory and remote backends use identical APIs
/// - **Async by Default**: All operations async for maximum flexibility
/// - **Algorithm Agnostic**: Byte encoding allows any AEAD cipher
#[cfg(feature = "aead")]
pub trait EncryptingKeyProvider: Send + Sync + Debug {
	/// Returns the algorithm identifier for this encryption key.
	fn algorithm(&self) -> AlgorithmIdentifierOwned;

	/// Encrypts plaintext using the provided nonce.
	///
	/// # Arguments
	///
	/// * `nonce` - The nonce/IV for this encryption operation
	/// * `plaintext` - The data to encrypt
	///
	/// # Returns
	///
	/// Encrypted ciphertext bytes (includes authentication tag for AEAD ciphers).
	fn encrypt(
		&self,
		nonce: &[u8],
		plaintext: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>>;

	/// Decrypts ciphertext using the provided nonce.
	///
	/// # Arguments
	///
	/// * `nonce` - The nonce/IV used for encryption
	/// * `ciphertext` - The encrypted data to decrypt
	///
	/// # Returns
	///
	/// Decrypted plaintext bytes.
	fn decrypt(
		&self,
		nonce: &[u8],
		ciphertext: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>>;
}

// =============================================================================
// InMemoryEncryptingKeyProvider
// =============================================================================

/// In-memory encryption key provider generic over any RustCrypto AEAD cipher.
///
/// This is the reference implementation for [`EncryptingKeyProvider`], storing the
/// encryption key directly in memory. Suitable for development, testing, and applications
/// where HSM/KMS integration is not required.
///
/// # Type Parameters
///
/// * `A` - The AEAD cipher type (e.g., `Aes256Gcm`, `Aes128Gcm`)
/// * `O` - The OID type associated with this cipher (e.g., `Aes256GcmOid`)
///
/// # Security
///
/// For zeroization on drop, use keys that implement `ZeroizeOnDrop`.
#[cfg(feature = "aead")]
pub struct InMemoryEncryptingKeyProvider<A, O>
where
	A: Aead + Send + Sync + 'static,
	O: AssociatedOid + Send + Sync,
{
	cipher: A,
	_oid: PhantomData<O>,
}

#[cfg(feature = "aead")]
impl<A, O> From<A> for InMemoryEncryptingKeyProvider<A, O>
where
	A: Aead + Send + Sync + 'static,
	O: AssociatedOid + Send + Sync,
{
	fn from(cipher: A) -> Self {
		InMemoryEncryptingKeyProvider { cipher, _oid: PhantomData }
	}
}

#[cfg(feature = "aead")]
impl<A, O> Debug for InMemoryEncryptingKeyProvider<A, O>
where
	A: Aead + Send + Sync + 'static,
	O: AssociatedOid + Send + Sync,
{
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("InMemoryEncryptingKeyProvider")
			.field("algorithm", &O::OID)
			.finish_non_exhaustive()
	}
}

#[cfg(feature = "aead")]
impl<A, O> EncryptingKeyProvider for InMemoryEncryptingKeyProvider<A, O>
where
	A: Aead + Send + Sync + 'static,
	O: AssociatedOid + Send + Sync,
{
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: O::OID, parameters: None }
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
		let result = self.cipher.decrypt(nonce_ref, ciphertext).map_err(KeyError::from);
		Box::pin(async move { result })
	}
}

#[cfg(feature = "aead")]
impl<A, O> EncryptingKeyProvider for Arc<InMemoryEncryptingKeyProvider<A, O>>
where
	A: Aead + Send + Sync + 'static,
	O: AssociatedOid + Send + Sync,
{
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.as_ref().algorithm()
	}

	fn encrypt(
		&self,
		nonce: &[u8],
		plaintext: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		self.as_ref().encrypt(nonce, plaintext)
	}

	fn decrypt(
		&self,
		nonce: &[u8],
		ciphertext: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		self.as_ref().decrypt(nonce, ciphertext)
	}
}

// =============================================================================
// AES Type Aliases
// =============================================================================

#[cfg(all(feature = "aead", feature = "aes-gcm"))]
/// Type alias for AES-256-GCM encryption key provider
pub type Aes256GcmKeyProvider = InMemoryEncryptingKeyProvider<Aes256Gcm, Aes256GcmOid>;

#[cfg(all(feature = "aead", feature = "aes-gcm"))]
/// Type alias for AES-128-GCM encryption key provider
pub type Aes128GcmKeyProvider = InMemoryEncryptingKeyProvider<Aes128Gcm, Aes128cmOid>;

#[cfg(test)]
mod tests {
	use rand_core::OsRng;

	use super::*;
	use crate::crypto::sign::ecdsa::k256::ecdsa::SigningKey;
	use crate::crypto::sign::Verifier;

	#[tokio::test]
	async fn test_secp256k1_provider_public_key() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key = SigningKey::random(&mut OsRng);
		let provider = Secp256k1KeyProvider::from(signing_key);

		let public_key_bytes = provider.to_public_key_bytes().await?;
		// DER-encoded SPKI for secp256k1 is 88 bytes
		assert_eq!(public_key_bytes.len(), 88);
		Ok(())
	}

	#[tokio::test]
	async fn test_secp256k1_provider_sign() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key = SigningKey::random(&mut OsRng);
		let provider = Secp256k1KeyProvider::from(signing_key.clone());

		let data = b"test data to sign";
		let signature_bytes = provider.sign(data).await?;

		// Verify signature using the public key
		let signature = Secp256k1Signature::from_slice(&signature_bytes)?;
		signing_key.verifying_key().verify(data, &signature)?;

		Ok(())
	}

	#[tokio::test]
	async fn test_secp256k1_provider_key_agreement() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key1 = SigningKey::random(&mut OsRng);
		let signing_key2 = SigningKey::random(&mut OsRng);

		let provider1 = Secp256k1KeyProvider::from(signing_key1.clone());
		let provider2 = Secp256k1KeyProvider::from(signing_key2.clone());

		// key_agreement expects SEC1 encoded public keys (not DER/SPKI)
		let public1 = signing_key1.verifying_key().to_encoded_point(false).as_bytes().to_vec();
		let public2 = signing_key2.verifying_key().to_encoded_point(false).as_bytes().to_vec();

		// Both sides should compute the same shared secret
		let shared1 = provider1.key_agreement(&public2).await?;
		let shared2 = provider2.key_agreement(&public1).await?;

		assert_eq!(shared1, shared2);
		assert_eq!(shared1.len(), 32); // secp256k1 shared secret is 32 bytes
		Ok(())
	}

	#[tokio::test]
	async fn test_generic_provider_sign() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key = SigningKey::random(&mut OsRng);
		let provider: Secp256k1Provider = InMemorySigningKeyProvider::from(signing_key.clone());

		let data = b"test data to sign";
		let signature_bytes = provider.sign(data).await?;

		// Verify signature using the public key
		let signature = Secp256k1Signature::from_slice(&signature_bytes)?;
		signing_key.verifying_key().verify(data, &signature)?;

		Ok(())
	}

	#[tokio::test]
	async fn test_arc_secp256k1_provider() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key = SigningKey::random(&mut OsRng);
		let provider = Arc::new(Secp256k1KeyProvider::from(signing_key.clone()));

		// Test that Arc<Secp256k1KeyProvider> implements KeyProvider
		let public_key_bytes = provider.to_public_key_bytes().await?;
		// DER-encoded SPKI for secp256k1 is 88 bytes
		assert_eq!(public_key_bytes.len(), 88);

		let data = b"test";
		let signature_bytes = provider.sign(data).await?;

		let signature = Secp256k1Signature::from_slice(&signature_bytes)?;
		signing_key.verifying_key().verify(data, &signature)?;

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
}
