//! Core KARI (Key Agreement Recipient Info) cryptographic operations.
//!
//! Provides unified ECDH + HKDF + AES Key Wrap / Unwrap logic for CMS handshakes.
//! Both builder (sender side) and recipient processor (receiver side) call into
//! these functions instead of duplicating derivation and key wrapping code.
//!
//! Security properties:
//! - Single derivation path audited in one place.
//! - KEK zeroized after use (if `zeroize` feature enabled).
//! - Optional constant-time integrity reinforcement: after unwrapping CEK we
//!   re-wrap it and constant-time compare with original wrapped bytes.
//!
//! NOTE: AES Key Wrap already provides integrity via RFC 3394. The re-wrap
//! check reduces timing surface differences across error paths.
//!
//! # Hybrid Key Agreement
//!
//! The `kari_wrap_hybrid` and `kari_unwrap_hybrid` functions combine classical
//! ECDH with post-quantum KEM shared secrets for hybrid security. This is useful
//! for protocols like PQXDH that require both classical and post-quantum strength.

use crate::crypto::profiles::CryptoProvider;
use crate::crypto::secret::Secret;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::subtle::ConstantTimeEq;
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey, SecretKey};
use crate::transport::handshake::error::HandshakeError;

#[cfg(feature = "ecdh")]
use crate::crypto::sign::elliptic_curve::ecdh::diffie_hellman;
#[cfg(feature = "zeroize")]
use crate::zeroize::Zeroize;

/// Derive the shared secret via ECDH and wrap in Secret<Vec<u8>> for automatic zeroization.
fn derive_shared_secret<C>(priv_key: &SecretKey<C>, peer_pub: &PublicKey<C>) -> Result<Secret<Vec<u8>>, HandshakeError>
where
	C: Curve + CurveArithmetic,
	<C as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
	let shared = diffie_hellman(priv_key.to_nonzero_scalar(), peer_pub.as_affine());
	let vec = shared.raw_secret_bytes().as_ref().to_vec();
	Ok(vec.into())
}

/// Derive a 32-byte KEK using provider's HKDF (shared_secret, UKM as salt, info).
fn derive_kek<P>(
	provider: &P,
	shared_secret: &Secret<Vec<u8>>,
	ukm: &[u8],
	kdf_info: &[u8],
) -> Result<[u8; 32], HandshakeError>
where
	P: CryptoProvider,
{
	if ukm.is_empty() {
		return Err(HandshakeError::MissingUkm);
	}

	let kdf = provider.as_key_deriver::<HandshakeError, 32>();
	shared_secret.with(|ss| kdf(ss.as_ref(), ukm, kdf_info))?
}

/// Wrap a CEK (sender side) producing RFC 3394 wrapped bytes.
pub fn kari_wrap<P, C>(
	provider: &P,
	sender_priv: &SecretKey<C>,
	recipient_pub: &PublicKey<C>,
	ukm: &[u8],
	kdf_info: &[u8],
	cek: &[u8],
) -> Result<Vec<u8>, HandshakeError>
where
	P: CryptoProvider,
	C: Curve + CurveArithmetic,
	<C as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
	// ECDH
	let shared_secret = derive_shared_secret(sender_priv, recipient_pub)?;
	// HKDF -> KEK
	let mut kek = derive_kek(provider, &shared_secret, ukm, kdf_info)?;
	// Wrap
	let wrapper = provider.as_key_wrapper_32::<HandshakeError>();
	let wrapped = wrapper(cek, &kek)?;

	// Zeroize KEK
	#[cfg(feature = "zeroize")]
	kek.zeroize();

	Ok(wrapped)
}

/// Unwrap a wrapped CEK (recipient side) verifying integrity constant-time.
pub fn kari_unwrap<P, C>(
	provider: &P,
	recipient_priv: &SecretKey<C>,
	originator_pub: &PublicKey<C>,
	ukm: &[u8],
	kdf_info: &[u8],
	wrapped: &[u8],
) -> Result<Vec<u8>, HandshakeError>
where
	P: CryptoProvider,
	C: Curve + CurveArithmetic,
	<C as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
	// ECDH
	let shared_secret = derive_shared_secret(recipient_priv, originator_pub)?;
	// HKDF -> KEK
	let mut kek = derive_kek(provider, &shared_secret, ukm, kdf_info)?;
	// Unwrap
	let unwrapper = provider.as_key_unwrapper_32::<HandshakeError>();
	let cek = unwrapper(wrapped, &kek)?;
	// Re-wrap for constant-time validation
	let wrapper = provider.as_key_wrapper_32::<HandshakeError>();
	let rewrapped = wrapper(&cek, &kek)?;

	core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
	let valid: bool = rewrapped.as_slice().ct_eq(wrapped).into();
	core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

	// Zeroize KEK
	#[cfg(feature = "zeroize")]
	kek.zeroize();

	if !valid {
		return Err(HandshakeError::AesKeyWrap(
			crate::crypto::aead::aes_kw::Error::IntegrityCheckFailed,
		));
	}

	Ok(cek)
}

// ============================================================================
// Hybrid Key Agreement (ECDH + KEM)
// ============================================================================

/// Wrap CEK using hybrid EC-DH + KEM shared secrets.
///
/// Combines classical ECDH with a post-quantum KEM shared secret using multi-input KDF.
/// This provides hybrid classical+PQ security for protocols like PQXDH.
///
/// # Parameters
/// - `provider`: Cryptographic provider for KDF and key wrapping
/// - `sender_ec_priv`: Sender's ephemeral EC private key
/// - `recipient_ec_pub`: Recipient's EC public key
/// - `kem_shared_secret`: Shared secret from KEM encapsulation
/// - `ukm`: User Keying Material (nonce/salt)
/// - `kdf_info`: Context string for KDF
/// - `cek`: Content Encryption Key to wrap
///
/// # Returns
/// Wrapped CEK bytes (RFC 3394 format)
#[cfg(feature = "kem")]
pub fn kari_wrap_hybrid<P, C>(
	provider: &P,
	sender_ec_priv: &SecretKey<C>,
	recipient_ec_pub: &PublicKey<C>,
	kem_shared_secret: &[u8],
	ukm: &[u8],
	kdf_info: &[u8],
	cek: &[u8],
) -> Result<Vec<u8>, HandshakeError>
where
	P: CryptoProvider,
	C: Curve + CurveArithmetic,
	<C as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
	use crate::transport::handshake::primitives::multi_input_kdf;

	// ECDH
	let ecdh_secret = derive_shared_secret(sender_ec_priv, recipient_ec_pub)?;
	// Combine ECDH + KEM secrets via multi-input KDF
	let combined_key = ecdh_secret.with(|ecdh| multi_input_kdf::<P>(&[ecdh, kem_shared_secret], ukm, kdf_info))??;

	// Wrap CEK with combined key
	let wrapper = provider.as_key_wrapper_32::<HandshakeError>();
	let wrapped = wrapper(cek, &combined_key)?;
	Ok(wrapped)
}

/// Unwrap CEK using hybrid EC-DH + KEM shared secrets.
///
/// Combines classical ECDH with a post-quantum KEM shared secret using multi-input KDF.
/// This provides hybrid classical+PQ security for protocols like PQXDH.
///
/// # Parameters
/// - `provider`: Cryptographic provider for KDF and key unwrapping
/// - `recipient_ec_priv`: Recipient's EC private key
/// - `originator_ec_pub`: Originator's ephemeral EC public key
/// - `kem_shared_secret`: Shared secret from KEM decapsulation
/// - `ukm`: User Keying Material (nonce/salt)
/// - `kdf_info`: Context string for KDF
/// - `wrapped`: Wrapped CEK bytes (RFC 3394 format)
///
/// # Returns
/// Unwrapped CEK bytes
#[cfg(feature = "kem")]
pub fn kari_unwrap_hybrid<P, C>(
	provider: &P,
	recipient_ec_priv: &SecretKey<C>,
	originator_ec_pub: &PublicKey<C>,
	kem_shared_secret: &[u8],
	ukm: &[u8],
	kdf_info: &[u8],
	wrapped: &[u8],
) -> Result<Vec<u8>, HandshakeError>
where
	P: CryptoProvider,
	C: Curve + CurveArithmetic,
	<C as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
	use crate::transport::handshake::primitives::multi_input_kdf;

	// ECDH
	let ecdh_secret = derive_shared_secret(recipient_ec_priv, originator_ec_pub)?;
	// Combine ECDH + KEM secrets via multi-input KDF
	let mut combined_key =
		ecdh_secret.with(|ecdh| multi_input_kdf::<P>(&[ecdh, kem_shared_secret], ukm, kdf_info))??;

	// Unwrap CEK
	let unwrapper = provider.as_key_unwrapper_32::<HandshakeError>();
	let cek = unwrapper(wrapped, &combined_key)?;

	// Re-wrap for constant-time validation
	let wrapper = provider.as_key_wrapper_32::<HandshakeError>();
	let rewrapped = wrapper(&cek, &combined_key)?;

	core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
	let valid: bool = rewrapped.as_slice().ct_eq(wrapped).into();
	core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

	// Zeroize combined key
	#[cfg(feature = "zeroize")]
	combined_key.zeroize();

	if !valid {
		return Err(HandshakeError::HybridKariIntegrityCheckFailed);
	}

	Ok(cek)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::constants::TIGHTBEAM_KARI_KDF_INFO;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::ecdsa::k256::SecretKey as K256SecretKey;
	use crate::random::OsRng;

	#[test]
	fn wrap_unwrap_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
		let provider = DefaultCryptoProvider::default();
		let sender = K256SecretKey::random(&mut OsRng);
		let recipient = K256SecretKey::random(&mut OsRng);
		let recipient_pub = recipient.public_key();
		let sender_pub = sender.public_key();
		let ukm = [0x55u8; 64];
		let cek = [0x42u8; 32];

		let wrapped = kari_wrap(&provider, &sender, &recipient_pub, &ukm, TIGHTBEAM_KARI_KDF_INFO, &cek)?;
		assert!(wrapped.len() > cek.len());

		let unwrapped = kari_unwrap(&provider, &recipient, &sender_pub, &ukm, TIGHTBEAM_KARI_KDF_INFO, &wrapped)?;
		assert_eq!(unwrapped, cek);
		Ok(())
	}

	#[test]
	fn unwrap_fail_with_wrong_key() -> Result<(), Box<dyn std::error::Error>> {
		let provider = DefaultCryptoProvider::default();
		let sender = K256SecretKey::random(&mut OsRng);
		let recipient = K256SecretKey::random(&mut OsRng);
		let wrong_recipient = K256SecretKey::random(&mut OsRng);
		let recipient_pub = recipient.public_key();
		let sender_pub = sender.public_key();
		let ukm = [0x33u8; 64];
		let cek = [0xABu8; 32];
		let wrapped = kari_wrap(
			&provider,
			&sender,
			&recipient_pub,
			&ukm,
			crate::constants::TIGHTBEAM_KARI_KDF_INFO,
			&cek,
		)?;

		// Attempt unwrap with wrong recipient key should fail
		let bad = kari_unwrap(
			&provider,
			&wrong_recipient,
			&sender_pub,
			&ukm,
			crate::constants::TIGHTBEAM_KARI_KDF_INFO,
			&wrapped,
		);
		assert!(bad.is_err());
		Ok(())
	}
}
