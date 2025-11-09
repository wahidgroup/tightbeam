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

use crate::crypto::profiles::CryptoProvider;
use crate::crypto::secret::Secret;
use crate::crypto::sign::elliptic_curve::ecdh::diffie_hellman;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, PublicKey, SecretKey};
use crate::transport::handshake::error::HandshakeError;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Derive the shared secret via ECDH and wrap in Secret<Vec<u8>> for automatic zeroization.
fn derive_shared_secret<C>(priv_key: &SecretKey<C>, peer_pub: &PublicKey<C>) -> Result<Secret<Vec<u8>>, HandshakeError>
where
	C: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
	<C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
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
	shared_secret
		.with(|ss| kdf(ss.as_ref(), ukm, kdf_info))
		.map_err(|_| HandshakeError::KdfError)
}

/// Constant-time equality check.
#[inline]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}

	let mut diff: u8 = 0;
	for (x, y) in a.iter().zip(b.iter()) {
		diff |= x ^ y;
	}

	diff == 0
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
	C: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
	<C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
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
	C: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
	<C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
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
	let valid = ct_eq(rewrapped.as_slice(), wrapped);

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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::constants::TIGHTBEAM_KARI_KDF_INFO;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::ecdsa::k256::SecretKey as K256SecretKey;
	use crate::random::OsRng;

	#[test]
	fn wrap_unwrap_roundtrip() {
		let provider = DefaultCryptoProvider::default();
		let sender = K256SecretKey::random(&mut OsRng);
		let recipient = K256SecretKey::random(&mut OsRng);
		let recipient_pub = recipient.public_key();
		let sender_pub = sender.public_key();
		let ukm = [0x55u8; 64];
		let cek = [0x42u8; 32];

		let wrapped = kari_wrap(&provider, &sender, &recipient_pub, &ukm, TIGHTBEAM_KARI_KDF_INFO, &cek).unwrap();
		assert!(wrapped.len() > cek.len());

		let unwrapped =
			kari_unwrap(&provider, &recipient, &sender_pub, &ukm, TIGHTBEAM_KARI_KDF_INFO, &wrapped).unwrap();
		assert_eq!(unwrapped, cek);
	}

	#[test]
	fn unwrap_fail_with_wrong_key() {
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
		)
		.unwrap();
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
	}
}
