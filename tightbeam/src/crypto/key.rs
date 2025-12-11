//! Pluggable key backend abstraction for tightbeam transport encryption.
//!
//! This module provides the [`KeyProvider`] trait, which abstracts cryptographic
//! key operations to enable flexible backend integration (in-memory, HSM, KMS, enclave).

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

#[cfg(feature = "std")]
use std::sync::Arc;

use core::fmt::Debug;
use core::future::Future;
use core::pin::Pin;

use crate::crypto::profiles::CryptoProvider;
use crate::crypto::sign::ecdsa::k256::PublicKey;
use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
use crate::crypto::sign::elliptic_curve::ecdh::diffie_hellman;
use crate::crypto::sign::Signer as SignerTrait;
use crate::error::TightBeamError;

#[cfg(feature = "x509")]
use crate::transport::handshake::HandshakeKeyManager;
#[cfg(feature = "zeroize")]
use crate::zeroize::ZeroizeOnDrop;

/// Specification for providing a cryptographic key in various formats.
///
/// This enum allows keys to be specified in multiple ways for flexible
/// configuration in const contexts (e.g., servlet! macro).
#[derive(Debug, Clone)]
pub enum KeySpec {
	/// Raw key bytes (e.g., secp256k1 scalar - 32 bytes)
	Bytes(&'static [u8]),

	/// Key provider instance (for HSM/KMS)
	Provider(Arc<dyn KeyProvider>),
}

#[cfg(feature = "x509")]
impl<P: CryptoProvider + Send + Sync + 'static> TryFrom<KeySpec> for HandshakeKeyManager<P> {
	type Error = TightBeamError;

	fn try_from(spec: KeySpec) -> Result<Self, Self::Error> {
		match spec {
			KeySpec::Bytes(bytes) => {
				let signing_key = Secp256k1SigningKey::from_bytes(bytes.into())?;
				let provider = InMemoryKeyProvider::from(signing_key);
				Ok(HandshakeKeyManager::new(Arc::new(provider)))
			}
			KeySpec::Provider(provider) => Ok(HandshakeKeyManager::new(provider)),
		}
	}
}

/// Trait for pluggable cryptographic key backends.
///
/// Implementations of this trait provide access to private key operations
/// (ECDH, signing) without exposing the raw key material. This enables
/// integration with Hardware Security Modules (HSMs), Key Management Services
/// (KMS), and secure enclaves where private keys cannot leave the secure boundary.
///
/// All operations return boxed futures to maintain object safety.
///
/// # Security Properties
///
/// - **Key Encapsulation**: Private keys never leave the provider boundary
/// - **Uniform Interface**: In-memory and remote backends use identical APIs
/// - **Async by Default**: All operations async for maximum flexibility
pub trait KeyProvider: Send + Sync + Debug {
	/// Returns the public key corresponding to this provider's private key.
	///
	/// # Errors
	///
	/// Returns [`TightBeamError`] if the backend cannot retrieve the public key.
	fn to_public_key(&self) -> Pin<Box<dyn Future<Output = Result<PublicKey, TightBeamError>> + Send + '_>>;

	/// Performs Elliptic Curve Diffie-Hellman key agreement.
	///
	/// Computes a shared secret from this provider's private key and the peer's
	/// public key. The shared secret is used for session key derivation.
	///
	/// # Arguments
	///
	/// * `peer_public_key` - The peer's public key for ECDH
	///
	/// # Returns
	///
	/// The computed shared secret (32 bytes for secp256k1).
	fn ecdh(
		&self,
		peer_public_key: &PublicKey,
	) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, TightBeamError>> + Send + '_>>;

	/// Signs data using this provider's private key.
	///
	/// # Arguments
	///
	/// * `data` - The data to sign (typically a hash)
	///
	/// # Returns
	///
	/// An ECDSA signature over the input data.
	fn sign(
		&self,
		data: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<Secp256k1Signature, TightBeamError>> + Send + '_>>;
}

/// In-memory secp256k1 key provider.
///
/// This is the reference implementation for [`KeyProvider`], storing the private
/// key directly in memory. Suitable for development, testing, and applications
/// where HSM/KMS integration is not required.
///
/// **Note**: This implementation is specific to secp256k1. For other curves,
/// implement your own provider that converts to/from k256 types at the trait boundary.
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
pub struct InMemoryKeyProvider {
	signing_key: Secp256k1SigningKey,
}

impl From<Secp256k1SigningKey> for InMemoryKeyProvider {
	fn from(signing_key: Secp256k1SigningKey) -> Self {
		InMemoryKeyProvider { signing_key }
	}
}

impl Debug for InMemoryKeyProvider {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("InMemoryKeyProvider")
			.field("public_key", &self.signing_key.verifying_key().to_encoded_point(true))
			.finish()
	}
}

impl KeyProvider for InMemoryKeyProvider {
	fn to_public_key(&self) -> Pin<Box<dyn Future<Output = Result<PublicKey, TightBeamError>> + Send + '_>> {
		let public_key = self.signing_key.verifying_key().to_encoded_point(false);
		Box::pin(async move { Ok(PublicKey::from_sec1_bytes(public_key.as_bytes())?) })
	}

	fn ecdh(
		&self,
		peer_public_key: &PublicKey,
	) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, TightBeamError>> + Send + '_>> {
		let secret_key = self.signing_key.as_nonzero_scalar();
		let public_key = *peer_public_key;

		Box::pin(async move {
			let shared_secret = diffie_hellman(secret_key, public_key.as_affine());
			Ok(shared_secret.raw_secret_bytes().to_vec())
		})
	}

	fn sign(
		&self,
		data: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<Secp256k1Signature, TightBeamError>> + Send + '_>> {
		let signature: Secp256k1Signature = self.signing_key.sign(data);
		Box::pin(async move { Ok(signature) })
	}
}

// Implement KeyProvider for Arc<InMemoryKeyProvider> for convenience
impl KeyProvider for Arc<InMemoryKeyProvider> {
	fn to_public_key(&self) -> Pin<Box<dyn Future<Output = Result<PublicKey, TightBeamError>> + Send + '_>> {
		self.as_ref().to_public_key()
	}

	fn ecdh(
		&self,
		peer_public_key: &PublicKey,
	) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, TightBeamError>> + Send + '_>> {
		self.as_ref().ecdh(peer_public_key)
	}

	fn sign(
		&self,
		data: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<Secp256k1Signature, TightBeamError>> + Send + '_>> {
		self.as_ref().sign(data)
	}
}

#[cfg(test)]
mod tests {
	use rand_core::OsRng;

	use super::*;
	use crate::crypto::sign::ecdsa::k256::ecdsa::SigningKey;
	use crate::crypto::sign::ecdsa::VerifyingKey;
	use crate::crypto::sign::Verifier;

	#[tokio::test]
	async fn test_in_memory_provider_public_key() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key = SigningKey::random(&mut OsRng);
		let expected_public = PublicKey::from(signing_key.verifying_key());
		let provider = InMemoryKeyProvider::from(signing_key);

		let public_key = provider.to_public_key().await?;
		assert_eq!(public_key, expected_public);

		Ok(())
	}

	#[tokio::test]
	async fn test_in_memory_provider_sign() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key = SigningKey::random(&mut OsRng);
		let provider = InMemoryKeyProvider::from(signing_key.clone());

		let data = b"test data to sign";
		let signature = provider.sign(data).await?;

		// Verify signature using the public key
		use ecdsa::signature::Verifier;
		signing_key.verifying_key().verify(data, &signature)?;

		Ok(())
	}

	#[tokio::test]
	async fn test_in_memory_provider_ecdh() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key1 = SigningKey::random(&mut OsRng);
		let signing_key2 = SigningKey::random(&mut OsRng);

		let provider1 = InMemoryKeyProvider::from(signing_key1);
		let provider2 = InMemoryKeyProvider::from(signing_key2);

		let public1 = provider1.to_public_key().await?;
		let public2 = provider2.to_public_key().await?;

		// Both sides should compute the same shared secret
		let shared1 = provider1.ecdh(&public2).await?;
		let shared2 = provider2.ecdh(&public1).await?;

		assert_eq!(shared1, shared2);
		assert_eq!(shared1.len(), 32); // secp256k1 shared secret is 32 bytes

		Ok(())
	}

	#[tokio::test]
	async fn test_from_signing_key() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key = SigningKey::random(&mut OsRng);
		let expected_public = PublicKey::from(signing_key.verifying_key());
		let provider: InMemoryKeyProvider = signing_key.into();

		let public_key = provider.to_public_key().await?;
		assert_eq!(public_key, expected_public);

		Ok(())
	}

	#[tokio::test]
	async fn test_arc_provider() -> Result<(), Box<dyn std::error::Error>> {
		let signing_key = SigningKey::random(&mut OsRng);
		let provider = Arc::new(InMemoryKeyProvider::from(signing_key));

		// Test that Arc<InMemoryKeyProvider> implements KeyProvider
		let public_key = provider.to_public_key().await?;
		let data = b"test";
		let signature = provider.sign(data).await?;

		let verifying_key = VerifyingKey::from(&public_key);
		let result = verifying_key.verify(data, &signature);
		assert!(result.is_ok());

		Ok(())
	}
}
