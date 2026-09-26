//! Core KARI (Key Agreement Recipient Info) cryptographic operations.
//!
//! The sender-side builder and the receiver-side processor both call these
//! ECDH, HKDF and AES key wrap operations, so derivation and key wrapping have
//! one home.
//!
//! # Security properties
//!
//! - One derivation path, audited in one place.
//! - The KEK is zeroized after use when the `zeroize` feature is on.
//! - A recipient confirms each unwrapped CEK by re-wrapping it and comparing
//!   the result with the original wrapped bytes in constant time
//!   (`Kek::unwrap_verified`).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::crypto::kdf::KdfFunction;
use crate::crypto::profiles::{CryptoProvider, SecurityProfile};
use crate::crypto::secret::SecretSlice;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey, SecretKey};
use crate::crypto::subtle::ConstantTimeEq;
use crate::der::asn1::ObjectIdentifier;
use crate::oids::{AES_128_WRAP, AES_192_WRAP, AES_256_WRAP};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::primitives::{KdfInfo, KdfSalt};
use crate::ZeroizingBytes;

#[cfg(feature = "ecdh")]
use crate::crypto::sign::elliptic_curve::ecdh::diffie_hellman;

/// ECDH key agreement on the handshake plane.
pub(crate) trait HandshakeAgreement<C>
where
	C: Curve + CurveArithmetic,
{
	/// Derive the shared secret via ECDH and wrap in [`SecretSlice`] for
	/// automatic zeroization.
	fn shared_secret(&self, peer: &PublicKey<C>) -> Result<SecretSlice<u8>, HandshakeError>;
}

impl<C> HandshakeAgreement<C> for SecretKey<C>
where
	C: Curve + CurveArithmetic,
	<C as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
	fn shared_secret(&self, peer: &PublicKey<C>) -> Result<SecretSlice<u8>, HandshakeError> {
		let shared = diffie_hellman(self.to_nonzero_scalar(), peer.as_affine());
		// Move the copy straight into a SecretSlice so that no plain binding
		// outlives this line.
		Ok(SecretSlice::from(shared.raw_secret_bytes().as_ref().to_vec()))
	}
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

/// Resolve the KEK byte length from the provider profile's negotiated key-wrap
/// OID.
fn key_wrap_key_size<P: CryptoProvider>() -> Result<usize, HandshakeError> {
	let oid = <P::Profile as SecurityProfile>::KEY_WRAP_OID.ok_or(HandshakeError::MissingKeyWrapAlgorithm)?;
	key_wrap_key_size_from_oid(oid)
}

/// Dispatch a keyed AES-KW operation to the variant matching the KEK length.
///
/// `$op16`/`$op24`/`$op32` are the provider's size-specific wrapper or
/// unwrapper method names.
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

/// A derived key-encryption key, ready to wrap or unwrap a CEK.
///
/// The KEK and the bytes it protects are both byte slices, so a caller that
/// holds them loose can swap them and still compile. The key travels as its
/// own type, so no call site can swap it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Kek<'a>(&'a [u8]);

impl<'a> Kek<'a> {
	/// Wrap `kek` as the key-encryption key for one wrap or unwrap.
	pub(crate) fn new(kek: &'a (impl AsRef<[u8]> + ?Sized)) -> Self {
		Self(kek.as_ref())
	}

	/// Return the key bytes for the provider call that consumes them.
	fn as_bytes(&self) -> &'a [u8] {
		self.0
	}

	/// Wrap a CEK with a KEK, dispatching to the AES-KW variant matching the
	/// KEK length.
	pub(crate) fn wrap<P: CryptoProvider>(
		&self,
		provider: &P,
		cek: impl AsRef<[u8]>,
	) -> Result<Vec<u8>, HandshakeError> {
		let kek = self.as_bytes();
		let cek = cek.as_ref();
		dispatch_aes_kw!(provider, kek, cek, as_key_wrapper_16, as_key_wrapper_24, as_key_wrapper_32)
	}

	/// Unwrap a wrapped CEK with a KEK, dispatching to the AES-KW variant
	/// matching the KEK length.
	///
	/// The key wrap hands back a plain buffer, so the CEK enters its wiping
	/// wrapper on the line it is produced and travels no further unwiped
	/// (CWE-226).
	fn unwrap_key<P: CryptoProvider>(
		&self,
		provider: &P,
		wrapped: impl AsRef<[u8]>,
	) -> Result<SecretSlice<u8>, HandshakeError> {
		let kek = self.as_bytes();
		let wrapped = wrapped.as_ref();
		let cek: Vec<u8> = dispatch_aes_kw!(
			provider,
			kek,
			wrapped,
			as_key_unwrapper_16,
			as_key_unwrapper_24,
			as_key_unwrapper_32
		)?;

		Ok(SecretSlice::from(cek))
	}

	/// Unwrap a CEK under an already-derived KEK and confirm integrity by
	/// re-wrapping and comparing in constant time.
	///
	/// # Shared check
	///
	/// The synchronous recipient path
	/// ([`TightBeamKariRecipient::process_kari`]) and the async key-provider
	/// orchestrator share this, so both keep the same check. AES key wrap
	/// already provides integrity (RFC 3394), and the re-wrap compare reduces
	/// timing differences across error paths.
	///
	/// [`TightBeamKariRecipient::process_kari`]: crate::transport::handshake::TightBeamKariRecipient::process_kari
	pub(crate) fn unwrap_verified<P: CryptoProvider>(
		&self,
		provider: &P,
		wrapped: impl AsRef<[u8]>,
	) -> Result<SecretSlice<u8>, HandshakeError> {
		let wrapped = wrapped.as_ref();
		let cek = self.unwrap_key(provider, wrapped)?;
		let rewrapped = cek.with(|cek| self.wrap(provider, cek))?;

		let valid: bool = rewrapped.as_slice().ct_eq(wrapped).into();
		if !valid {
			return Err(HandshakeError::AesKeyWrap(
				crate::crypto::aead::aes_kw::Error::IntegrityCheckFailed,
			));
		}

		Ok(cek)
	}
}

/// KEK derivation over a shared secret on the handshake plane.
pub(crate) trait HandshakeKek {
	/// Derive a KEK sized to the negotiated key-wrap algorithm using the
	/// provider's HKDF (shared_secret as IKM, UKM as salt, info as context).
	fn derive_kek<P>(&self, ukm: KdfSalt<'_>, kdf_info: KdfInfo<'_>) -> Result<ZeroizingBytes, HandshakeError>
	where
		P: CryptoProvider;
}

impl HandshakeKek for SecretSlice<u8> {
	fn derive_kek<P>(&self, ukm: KdfSalt<'_>, kdf_info: KdfInfo<'_>) -> Result<ZeroizingBytes, HandshakeError>
	where
		P: CryptoProvider,
	{
		if ukm.as_bytes().is_empty() {
			return Err(HandshakeError::MissingUkm);
		}

		let key_size = key_wrap_key_size::<P>()?;
		let kek = self
			.with(|shared| P::Kdf::derive_dynamic_key(shared, kdf_info.as_bytes(), Some(ukm.as_bytes()), key_size))?;
		Ok(kek)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::secret::ToInsecure;

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
		let ukm_salt = KdfSalt::new(&ukm);
		let label = KdfInfo::new(TIGHTBEAM_KARI_KDF_INFO);

		let sender_secret = sender.shared_secret(&recipient_pub)?;
		let sender_kek = sender_secret.derive_kek::<DefaultCryptoProvider>(ukm_salt, label)?;
		let wrapped = Kek::new(sender_kek.as_slice()).wrap(&provider, cek)?;
		assert!(wrapped.len() > cek.len());

		let recipient_secret = recipient.shared_secret(&sender_pub)?;
		let recipient_kek = recipient_secret.derive_kek::<DefaultCryptoProvider>(ukm_salt, label)?;
		let unwrapped = Kek::new(recipient_kek.as_slice()).unwrap_verified(&provider, &wrapped)?;
		assert_eq!(unwrapped.to_insecure().as_slice(), cek.as_slice());
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
		let ukm_salt = KdfSalt::new(&ukm);
		let label = KdfInfo::new(TIGHTBEAM_KARI_KDF_INFO);
		let sender_secret = sender.shared_secret(&recipient_pub)?;
		let sender_kek = sender_secret.derive_kek::<DefaultCryptoProvider>(ukm_salt, label)?;
		let wrapped = Kek::new(sender_kek.as_slice()).wrap(&provider, cek)?;

		// An unwrap with the wrong recipient key fails.
		let wrong_secret = wrong_recipient.shared_secret(&sender_pub)?;
		let wrong_kek = wrong_secret.derive_kek::<DefaultCryptoProvider>(ukm_salt, label)?;
		let bad = Kek::new(wrong_kek.as_slice()).unwrap_verified(&provider, &wrapped);
		assert!(bad.is_err());
		Ok(())
	}

	#[test]
	fn the_kek_matches_the_profile_key_wrap_length() -> Result<(), HandshakeError> {
		let shared_secret = SecretSlice::from(vec![0x33u8; 48]);
		let ukm = [0x44u8; 64];
		let label = KdfInfo::new(TIGHTBEAM_KARI_KDF_INFO);

		let kek = shared_secret.derive_kek::<DefaultCryptoProvider>(KdfSalt::new(&ukm), label)?;
		assert_eq!(kek.as_slice().len(), 32);
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

	const ROUND_TRIP_CEK: [u8; 32] = [0x42u8; 32];

	/// The CEK after a wrap and unwrap under a KEK of `kek_size` bytes.
	fn round_trip_under_kek(kek_size: usize) -> SecretSlice<u8> {
		let provider = DefaultCryptoProvider::default();
		let kek = vec![0x11u8; kek_size];
		let wrapped = Kek::new(&kek).wrap(&provider, ROUND_TRIP_CEK).expect("the CEK wraps");
		Kek::new(&kek).unwrap_key(&provider, &wrapped).expect("the wrapped CEK unwraps")
	}

	#[test]
	fn a_128_bit_kek_round_trips_the_cek() {
		assert_eq!(round_trip_under_kek(16).to_insecure().as_slice(), ROUND_TRIP_CEK);
	}

	#[test]
	fn a_192_bit_kek_round_trips_the_cek() {
		assert_eq!(round_trip_under_kek(24).to_insecure().as_slice(), ROUND_TRIP_CEK);
	}

	#[test]
	fn a_256_bit_kek_round_trips_the_cek() {
		assert_eq!(round_trip_under_kek(32).to_insecure().as_slice(), ROUND_TRIP_CEK);
	}
}
