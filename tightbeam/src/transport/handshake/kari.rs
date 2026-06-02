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

use crate::crypto::kdf::KdfFunction;
use crate::crypto::profiles::{CryptoProvider, SecurityProfile};
use crate::crypto::secret::Secret;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::subtle::ConstantTimeEq;
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey, SecretKey};
use crate::der::asn1::ObjectIdentifier;
use crate::oids::{AES_128_WRAP, AES_192_WRAP, AES_256_WRAP};
use crate::transport::handshake::error::HandshakeError;
use crate::zeroize::Zeroizing;

#[cfg(feature = "ecdh")]
use crate::crypto::sign::elliptic_curve::ecdh::diffie_hellman;

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

/// Map a negotiated AES key-wrap OID to its KEK byte length.
///
/// RFC 3394 AES Key Wrap requires the KEK length to equal the AES key size of
/// the wrap algorithm: 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes.
fn key_wrap_key_size_from_oid(oid: ObjectIdentifier) -> Result<usize, HandshakeError> {
	if oid == AES_128_WRAP {
		Ok(16)
	} else if oid == AES_192_WRAP {
		Ok(24)
	} else if oid == AES_256_WRAP {
		Ok(32)
	} else {
		Err(HandshakeError::UnsupportedKeyWrapAlgorithm)
	}
}

/// Resolve the KEK byte length from the provider profile's negotiated key-wrap OID.
pub(crate) fn key_wrap_key_size<P: CryptoProvider>() -> Result<usize, HandshakeError> {
	let oid = <P::Profile as SecurityProfile>::KEY_WRAP_OID.ok_or(HandshakeError::MissingKeyWrapAlgorithm)?;
	key_wrap_key_size_from_oid(oid)
}

/// Derive a KEK of `key_size` bytes using the provider's HKDF
/// (shared_secret as IKM, UKM as salt, info as context).
pub(crate) fn derive_kek<P>(
	shared_secret: &Secret<Vec<u8>>,
	ukm: &[u8],
	kdf_info: &[u8],
	key_size: usize,
) -> Result<Zeroizing<Vec<u8>>, HandshakeError>
where
	P: CryptoProvider,
{
	if ukm.is_empty() {
		return Err(HandshakeError::MissingUkm);
	}

	let kek = shared_secret
		.with(|ss| <P::Kdf as KdfFunction>::derive_dynamic_key(ss.as_ref(), kdf_info, Some(ukm), key_size))??;
	Ok(kek)
}

/// Dispatch a keyed AES-KW operation to the variant matching the KEK length.
///
/// `$op16`/`$op24`/`$op32` are the provider's size-specific wrapper or unwrapper
/// method names.
macro_rules! dispatch_aes_kw {
	($provider:expr, $kek:expr, $data:expr, $op16:ident, $op24:ident, $op32:ident) => {{
		match $kek.len() {
			16 => {
				let kek: &[u8; 16] = $kek.try_into().map_err(|_| HandshakeError::UnsupportedKeyWrapAlgorithm)?;
				($provider.$op16::<HandshakeError>())($data, kek)
			}
			24 => {
				let kek: &[u8; 24] = $kek.try_into().map_err(|_| HandshakeError::UnsupportedKeyWrapAlgorithm)?;
				($provider.$op24::<HandshakeError>())($data, kek)
			}
			32 => {
				let kek: &[u8; 32] = $kek.try_into().map_err(|_| HandshakeError::UnsupportedKeyWrapAlgorithm)?;
				($provider.$op32::<HandshakeError>())($data, kek)
			}
			_ => Err(HandshakeError::UnsupportedKeyWrapAlgorithm),
		}
	}};
}

/// Wrap a CEK with a KEK, dispatching to the AES-KW variant matching the KEK length.
pub(crate) fn wrap_with_kek<P: CryptoProvider>(
	provider: &P,
	kek: &[u8],
	cek: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
	dispatch_aes_kw!(provider, kek, cek, as_key_wrapper_16, as_key_wrapper_24, as_key_wrapper_32)
}

/// Unwrap a wrapped CEK with a KEK, dispatching to the AES-KW variant matching the KEK length.
pub(crate) fn unwrap_with_kek<P: CryptoProvider>(
	provider: &P,
	kek: &[u8],
	wrapped: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
	dispatch_aes_kw!(
		provider,
		kek,
		wrapped,
		as_key_unwrapper_16,
		as_key_unwrapper_24,
		as_key_unwrapper_32
	)
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
	// KEK sized to the negotiated key-wrap algorithm; HKDF derives it.
	let key_size = key_wrap_key_size::<P>()?;
	let kek = derive_kek::<P>(&shared_secret, ukm, kdf_info, key_size)?;

	// Wrap (KEK is zeroized on drop).
	wrap_with_kek(provider, kek.as_slice(), cek)
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
	// KEK sized to the negotiated key-wrap algorithm; HKDF derives it.
	let key_size = key_wrap_key_size::<P>()?;
	let kek = derive_kek::<P>(&shared_secret, ukm, kdf_info, key_size)?;
	// Unwrap
	let cek = unwrap_with_kek(provider, kek.as_slice(), wrapped)?;
	// Re-wrap for constant-time validation
	let rewrapped = wrap_with_kek(provider, kek.as_slice(), &cek)?;

	core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
	let valid: bool = rewrapped.as_slice().ct_eq(wrapped).into();
	core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

	// KEK is zeroized on drop.
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
	// Combine ECDH + KEM secrets via multi-input KDF, sized to the negotiated key-wrap algorithm.
	let key_size = key_wrap_key_size::<P>()?;
	let combined_key =
		ecdh_secret.with(|ecdh| multi_input_kdf::<P>(&[ecdh, kem_shared_secret], ukm, kdf_info, key_size))??;

	// Wrap CEK with combined key (zeroized on drop).
	wrap_with_kek(provider, combined_key.as_slice(), cek)
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
	// Combine ECDH + KEM secrets via multi-input KDF, sized to the negotiated key-wrap algorithm.
	let key_size = key_wrap_key_size::<P>()?;
	let combined_key =
		ecdh_secret.with(|ecdh| multi_input_kdf::<P>(&[ecdh, kem_shared_secret], ukm, kdf_info, key_size))??;

	// Unwrap CEK
	let cek = unwrap_with_kek(provider, combined_key.as_slice(), wrapped)?;

	// Re-wrap for constant-time validation
	let rewrapped = wrap_with_kek(provider, combined_key.as_slice(), &cek)?;

	core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
	let valid: bool = rewrapped.as_slice().ct_eq(wrapped).into();
	core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

	// Combined key is zeroized on drop.
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

	#[test]
	fn key_wrap_oid_maps_to_kek_size() -> Result<(), Box<dyn std::error::Error>> {
		let cases = [
			(crate::oids::AES_128_WRAP, 16usize),
			(crate::oids::AES_192_WRAP, 24),
			(crate::oids::AES_256_WRAP, 32),
		];
		for (oid, expected) in cases {
			assert_eq!(key_wrap_key_size_from_oid(oid)?, expected);
		}
		Ok(())
	}

	#[test]
	fn key_wrap_oid_rejects_non_wrap_oid() {
		let result = key_wrap_key_size_from_oid(crate::oids::AES_256_GCM);
		assert!(matches!(result, Err(HandshakeError::UnsupportedKeyWrapAlgorithm)));
	}

	#[test]
	fn wrap_unwrap_roundtrip_all_kek_sizes() -> Result<(), Box<dyn std::error::Error>> {
		let provider = DefaultCryptoProvider::default();
		let cek = [0x42u8; 32];
		for size in [16usize, 24, 32] {
			let kek = vec![0x11u8; size];
			let wrapped = wrap_with_kek(&provider, &kek, &cek)?;
			let unwrapped = unwrap_with_kek(&provider, &kek, &wrapped)?;
			assert_eq!(unwrapped, cek);
		}
		Ok(())
	}
}
