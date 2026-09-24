//! Key derivation functions (KDF).
//!
//! This module provides HKDF key derivation per [RFC 5869][rfc5869], with
//! SHA3-256 as the default hash. It serves as a general-purpose KDF and as the
//! KDF of ECIES constructions that require distinct encryption and MAC keys.
//!
//! # Properties
//!
//! - The default provider is HKDF ([RFC 5869][rfc5869]) with SHA3-256.
//! - Derivation is deterministic and domain-separated by the `info` parameter
//!   ([RFC 5869 §3.2][rfc5869-3.2]).
//! - Key material stays in `Zeroizing` and `ZeroizingArray` buffers.
//! - Input validation covers the shared secret, which [`EcdhSecret`] fixes at
//!   32 bytes, and the salt, which is 16 bytes or more. The ephemeral public
//!   key is length-framed into SharedInfo, and the ECIES message parser checks
//!   its length before it reaches the KDF.
//!
//! # Providers
//!
//! - HKDF providers honor the optional `salt` parameter per [RFC 5869 §2.2][rfc5869-2.2].
//! - ANSI X9.63 providers ignore `salt`. Their derivation depends on the shared
//!   secret Z and the `info` (SharedInfo) context bytes only ([SECG SEC 1 v2.0
//!   §3.6][sec1-3.6]).
//!
//! # ECIES
//!
//! - ECIES profiles such as [SECG SEC 1 v2.0 §5.1][sec1-5.1], [IEEE Std
//!   1363a-2004][ieee1363a], and [ISO/IEC 18033-2:2006][iso18033] mandate
//!   separate symmetric encryption and MAC keys.
//!   [`DualKeyKdf::derive_dual_keys`] enforces that key separation with one
//!   expansion split into two disjoint keys ([SECG SEC 1 v2.0
//!   §5.1.3][sec1-5.1.3]).
//! - The KDF is a parameter of ECIES ([SECG SEC 1 v2.0 §5.1][sec1-5.1], [IEEE
//!   Std 1363a-2004][ieee1363a]). This library instantiates ECIES with
//!   HKDF-SHA3-256 per [RFC 5869][rfc5869], with key separation and context
//!   binding through `info`. A profile that mandates the ANSI X9.63 KDF
//!   supplies a [`KdfFunction`] that implements that KDF.
//!
//! # Sources
//!
//! - [RFC 5869][rfc5869]: HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
//! - [NIST SP 800-56A Rev. 3 §5.8][sp800-56a]: Key-Derivation Methods for Key-Agreement Schemes.
//! - [NIST SP 800-56C Rev. 2 §5][sp800-56c]: Two-Step Key Derivation (Extraction-then-Expansion).
//! - [SECG SEC 1 v2.0 §5.1][sec1-5.1]: Elliptic Curve Integrated Encryption Scheme (ECIES).
//! - [IEEE Std 1363a-2004][ieee1363a]: Public-Key Cryptography, Amendment 1
//!   (Additional Techniques).
//! - [ISO/IEC 18033-2:2006][iso18033]: Encryption algorithms, Part 2: Asymmetric ciphers.
//!
//! [rfc5869]: https://datatracker.ietf.org/doc/html/rfc5869
//! [rfc5869-2.2]: https://datatracker.ietf.org/doc/html/rfc5869#section-2.2
//! [rfc5869-3.2]: https://datatracker.ietf.org/doc/html/rfc5869#section-3.2
//! [sp800-56a]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf#page=64
//! [sp800-56c]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf#page=25
//! [sec1-3.6]: https://www.secg.org/sec1-v2.pdf#page=37
//! [sec1-5.1]: https://www.secg.org/sec1-v2.pdf#page=57
//! [sec1-5.1.3]: https://www.secg.org/sec1-v2.pdf#page=59
//! [ieee1363a]: https://standards.ieee.org/standard/1363a-2004.html
//! [iso18033]: https://www.iso.org/standard/37971.html

use core::cmp::min;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub use crate::crypto::hkdf::Hkdf;

use crate::constants::{ECDH_SHARED_SECRET_SIZE, MAX_HKDF_OUTPUT_SIZE, MIN_KEY_SIZE, MIN_SALT_SIZE};
use crate::crypto::hash::{Digest, Sha3_256};
use crate::crypto::hkdf::InvalidLength;
use crate::crypto::secret::{Secret, SecretSlice, ToInsecure};
use crate::der::asn1::ObjectIdentifier;
use crate::der::oid::AssociatedOid;
use crate::oids::HASH_SHA3_256;
use crate::zeroize::Zeroizing;
use crate::Errorizable;
use crate::{ZeroizingArray, ZeroizingBytes};

/// The result of a KDF operation.
pub type Result<T> = ::core::result::Result<T, KdfError>;

/// A key derivation function that a provider type implements.
///
/// A consumer plugs in a RustCrypto KDF or a custom KDF through this trait.
pub trait KdfFunction {
	/// Derive a key of `N` bytes.
	fn derive_key<const N: usize>(ikm: &[u8], info: &[u8], salt: Option<&[u8]>) -> Result<ZeroizingArray<N>>;

	/// Derive a key whose size is known only at run time.
	///
	/// A negotiated security profile sets the key size, so a const generic
	/// cannot carry it. Each provider uses its own digest algorithm.
	///
	/// - `ikm`: the input key material.
	/// - `info`: the context string for domain separation.
	/// - `salt`: an optional salt, 16 bytes or more when present.
	/// - `key_size`: the output key size in bytes.
	///
	/// # Errors
	///
	/// - [`KdfError::DerivationFailed`] when `key_size` is outside the valid range.
	fn derive_dynamic_key(ikm: &[u8], info: &[u8], salt: Option<&[u8]>, key_size: usize) -> Result<ZeroizingBytes>;
}

/// Dual-key derivation through any [`KdfFunction`].
///
/// The blanket implementation is the only one, so a KDF identifier names one
/// dual-key output whichever type implements it.
pub trait DualKeyKdf: KdfFunction {
	/// Derive an ECIES encryption key and MAC key of `N` bytes each.
	///
	/// ECIES standards such as [SECG SEC 1 v2.0 §5.1][sec1-5.1],
	/// [IEEE Std 1363a-2004][ieee1363a], and [ISO/IEC 18033-2:2006][iso18033]
	/// require distinct symmetric keys for encryption and for message
	/// authentication, so no key is reused across primitives. One construction
	/// serves every KDF:
	///
	/// 1. Expand `2 * N` bytes once through [`KdfFunction::derive_dynamic_key`].
	/// 2. Split the output into two non-overlapping keys ([SECG SEC 1 v2.0 §5.1.3][sec1-5.1.3]).
	///
	/// # Errors
	///
	/// - [`KdfError::DerivationFailed`] when `N` is below [`MIN_KEY_SIZE`], or
	///   when the KDF refuses `2 * N` bytes or returns another length.
	///
	/// # Sources
	///
	/// - [RFC 5869 §3.2][rfc5869-3.2]: `info` for context separation.
	/// - [NIST SP 800-56C Rev. 2 §5][sp800-56c]: extraction-then-expansion and context binding.
	/// - [SECG SEC 1 v2.0 §5.1.3][sec1-5.1.3]: ECIES encryption and MAC key separation.
	///
	/// [rfc5869-3.2]: https://datatracker.ietf.org/doc/html/rfc5869#section-3.2
	/// [sp800-56c]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf#page=25
	/// [sec1-5.1]: https://www.secg.org/sec1-v2.pdf#page=57
	/// [sec1-5.1.3]: https://www.secg.org/sec1-v2.pdf#page=59
	/// [ieee1363a]: https://standards.ieee.org/standard/1363a-2004.html
	/// [iso18033]: https://www.iso.org/standard/37971.html
	fn derive_dual_keys<const N: usize>(
		ikm: &[u8],
		info: &[u8],
		salt: Option<&[u8]>,
	) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)>;
}

impl<K: KdfFunction> DualKeyKdf for K {
	fn derive_dual_keys<const N: usize>(
		ikm: &[u8],
		info: &[u8],
		salt: Option<&[u8]>,
	) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)> {
		assert_min_key_size(N)?;

		let combined_len = N.checked_mul(2).ok_or(KdfError::DerivationFailed(InvalidLength))?;
		let combined = K::derive_dynamic_key(ikm, info, salt, combined_len)?;
		let (enc_bytes, mac_bytes) = combined
			.split_at_checked(N)
			.filter(|(_, mac_bytes)| mac_bytes.len() == N)
			.ok_or(KdfError::DerivationFailed(InvalidLength))?;

		let mut k_enc = Zeroizing::new([0u8; N]);
		let mut k_mac = Zeroizing::new([0u8; N]);
		k_enc.copy_from_slice(enc_bytes);
		k_mac.copy_from_slice(mac_bytes);

		Ok((k_enc, k_mac))
	}
}

/// The default KDF provider, which is HKDF over SHA3-256.
pub struct HkdfSha3_256;

/// No standard OID exists for HKDF-SHA3-256, so the profile negotiates it
/// under the NIST SHA3-256 digest OID.
impl AssociatedOid for HkdfSha3_256 {
	const OID: ObjectIdentifier = HASH_SHA3_256;
}

/// Reject a key size below [`MIN_KEY_SIZE`], which is too weak for
/// cryptographic use.
///
/// The const-generic and dynamic entry points of every provider share this
/// check, so the two apply one validation.
#[inline]
fn assert_min_key_size(key_size: usize) -> Result<()> {
	if key_size < MIN_KEY_SIZE {
		return Err(KdfError::DerivationFailed(InvalidLength));
	}

	Ok(())
}

/// Reject a key size outside `[MIN_KEY_SIZE, MAX_HKDF_OUTPUT_SIZE]`.
///
/// This is the HKDF counterpart of [`assert_min_key_size`]. The crate policy
/// [`MAX_HKDF_OUTPUT_SIZE`] also caps HKDF output.
#[inline]
fn assert_hkdf_key_size(key_size: usize) -> Result<()> {
	if !(MIN_KEY_SIZE..=MAX_HKDF_OUTPUT_SIZE).contains(&key_size) {
		return Err(KdfError::DerivationFailed(InvalidLength));
	}

	Ok(())
}

impl KdfFunction for HkdfSha3_256 {
	fn derive_key<const N: usize>(ikm: &[u8], info: &[u8], salt: Option<&[u8]>) -> Result<ZeroizingArray<N>> {
		assert_hkdf_key_size(N)?;

		let hk = Hkdf::<Sha3_256>::new(salt, ikm);
		let mut output = Zeroizing::new([0u8; N]);

		hk.expand(info, &mut output[..]).map_err(KdfError::DerivationFailed)?;

		Ok(output)
	}

	fn derive_dynamic_key(ikm: &[u8], info: &[u8], salt: Option<&[u8]>, key_size: usize) -> Result<ZeroizingBytes> {
		assert_hkdf_key_size(key_size)?;

		let hk = Hkdf::<Sha3_256>::new(salt, ikm);
		let mut okm = vec![0u8; key_size];
		hk.expand(info, &mut okm).map_err(KdfError::DerivationFailed)?;

		Ok(Zeroizing::new(okm))
	}
}

/// The ANSI X9.63 concatenation KDF over SHA3-256.
pub struct X963Sha3_256;

impl KdfFunction for X963Sha3_256 {
	fn derive_key<const N: usize>(ikm: &[u8], info: &[u8], _salt: Option<&[u8]>) -> Result<ZeroizingArray<N>> {
		assert_min_key_size(N)?;

		let mut out = Zeroizing::new([0u8; N]);
		Self::expand(&mut out[..], ikm, info)?;

		Ok(out)
	}

	fn derive_dynamic_key(ikm: &[u8], info: &[u8], _salt: Option<&[u8]>, key_size: usize) -> Result<ZeroizingBytes> {
		assert_min_key_size(key_size)?;

		let mut out = vec![0u8; key_size];
		Self::expand(&mut out, ikm, info)?;

		Ok(Zeroizing::new(out))
	}
}

impl X963Sha3_256 {
	/// ANSI X9.63 concatenation: `K(i) = Hash(Z || Counter_i || SharedInfo)`.
	///
	/// `Counter_i` starts at 1. A counter that would overflow `u32` fails the
	/// derivation, so the counter never wraps.
	fn expand(out: &mut [u8], ikm: &[u8], info: &[u8]) -> Result<()> {
		let mut offset = 0usize;
		let mut counter: u32 = 1;
		while offset < out.len() {
			let mut hasher = Sha3_256::new();
			hasher.update(ikm);
			hasher.update(counter.to_be_bytes());
			hasher.update(info);

			let block = hasher.finalize();
			let take = min(block.len(), out.len() - offset);

			out[offset..offset + take].copy_from_slice(&block[..take]);

			offset += take;

			if offset < out.len() {
				counter = counter.checked_add(1).ok_or(KdfError::DerivationFailed(InvalidLength))?;
			}
		}

		Ok(())
	}
}

/// An error from a KDF operation.
#[derive(Errorizable, Debug, Clone)]
pub enum KdfError {
	/// Key derivation failed. The output length is out of range, or HKDF
	/// expansion failed.
	#[error("Key derivation failed: {0}")]
	DerivationFailed(InvalidLength),

	/// The shared secret is not 32 bytes. The field holds the received length.
	#[error("Invalid shared secret length: expected 32 bytes, got {0}")]
	InvalidSharedSecretLength(usize),

	/// A non-empty salt is shorter than 16 bytes. The field holds the received
	/// length.
	#[error("Invalid salt length: must be at least 16 bytes, got {0}")]
	InvalidSaltLength(usize),
}

/// An ECDH shared secret on a 256-bit curve.
///
/// The length is part of the type, so a derivation that takes one runs no
/// length check of its own. It wipes on drop like every [`Secret`].
pub type EcdhSecret = Secret<[u8; ECDH_SHARED_SECRET_SIZE]>;

impl TryFrom<SecretSlice<u8>> for EcdhSecret {
	type Error = KdfError;

	/// # Errors
	///
	/// - [`KdfError::InvalidSharedSecretLength`] when the secret is not
	///   [`ECDH_SHARED_SECRET_SIZE`] bytes.
	fn try_from(secret: SecretSlice<u8>) -> Result<Self> {
		let bytes = secret.to_insecure();
		let sized: [u8; ECDH_SHARED_SECRET_SIZE] = bytes
			.as_slice()
			.try_into()
			.map_err(|_| KdfError::InvalidSharedSecretLength(bytes.len()))?;

		Ok(Secret::from(sized))
	}
}

/// Bind `info` and `ephemeral_pubkey` into one unambiguous ECIES SharedInfo.
///
/// Each part carries an 8-byte big-endian length, so no two distinct
/// `(info, ephemeral_pubkey)` pairs produce the same SharedInfo and derive
/// the same key. A separator byte string cannot promise that, because either
/// part may contain the separator: `("ctx", "A|epk|B")` and
/// `("ctx|epk|A", "B")` concatenate to the same bytes.
fn shared_info(info: &[u8], ephemeral_pubkey: &[u8]) -> Vec<u8> {
	const FRAME: usize = 2 * core::mem::size_of::<u64>();

	let mut framed = Vec::with_capacity(FRAME + info.len() + ephemeral_pubkey.len());
	framed.extend_from_slice(&(info.len() as u64).to_be_bytes());
	framed.extend_from_slice(info);
	framed.extend_from_slice(&(ephemeral_pubkey.len() as u64).to_be_bytes());
	framed.extend_from_slice(ephemeral_pubkey);
	framed
}

/// Reject a non-empty salt shorter than [`MIN_SALT_SIZE`], which is 16 bytes.
#[inline]
fn assert_valid_salt(salt: Option<&[u8]>) -> Result<()> {
	if let Some(salt_bytes) = salt {
		if !salt_bytes.is_empty() && salt_bytes.len() < MIN_SALT_SIZE {
			return Err(KdfError::InvalidSaltLength(salt_bytes.len()));
		}
	}

	Ok(())
}

/// ECIES key derivation over a shared secret.
///
/// - [`Self::ecies_kdf`] and [`Self::ecies_kdf_with_size`] take an `(info,
///   ephemeral_pubkey)` pair and length-frame the two parts into SharedInfo
///   themselves.
/// - The `with_shared_info` methods take a finished SharedInfo instead, for
///   context that pair cannot express, so keeping it unambiguous belongs to the
///   caller: two different inputs that concatenate to the same bytes derive the
///   same key.
///
/// # Sources
///
/// - [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) (HKDF). A strict
///   ECIES profile that mandates the X9.63 KDF ([SECG SEC 1 v2.0
///   §3.6.1](https://www.secg.org/sec1-v2.pdf#page=38)) supplies that
///   [`KdfFunction`].
/// - [NIST SP 800-56C Rev. 2 §5][sp800-56c]: extraction-then-expansion and FixedInfo.
/// - [SECG SEC 1 v2.0 §5.1.3](https://www.secg.org/sec1-v2.pdf#page=59): ECIES
///   encryption and MAC key separation.
///
/// [sp800-56c]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf#page=25
pub trait EciesKdf {
	/// Derive a key of exactly `key_size` bytes, binding `info` and
	/// `ephemeral_pubkey` as SharedInfo. The ECDH result is the input key
	/// material.
	///
	/// # Errors
	///
	/// - [`KdfError::InvalidSaltLength`] when a non-empty `salt` is shorter than [`MIN_SALT_SIZE`].
	/// - [`KdfError::DerivationFailed`] when the KDF refuses `key_size`, or returns another length.
	fn ecies_kdf<P: KdfFunction>(
		self,
		ephemeral_pubkey: impl AsRef<[u8]>,
		info: impl AsRef<[u8]>,
		salt: Option<&[u8]>,
		key_size: usize,
	) -> Result<ZeroizingBytes>;

	/// Derive an encryption and MAC key pair of `N` bytes each, binding `info`
	/// and `ephemeral_pubkey` as SharedInfo.
	///
	/// The KDF's own output bound applies to `2 * N`. HKDF caps it at
	/// [`MAX_HKDF_OUTPUT_SIZE`], and X9.63 imposes no cap.
	///
	/// # Errors
	///
	/// - [`KdfError::InvalidSaltLength`] when a non-empty `salt` is shorter than [`MIN_SALT_SIZE`].
	/// - [`KdfError::DerivationFailed`] when expansion fails.
	fn ecies_kdf_with_size<P: KdfFunction, const N: usize>(
		self,
		ephemeral_pubkey: impl AsRef<[u8]>,
		info: impl AsRef<[u8]>,
		salt: Option<&[u8]>,
	) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)>;

	/// Derive a key of exactly `key_size` bytes from SharedInfo the caller
	/// assembled.
	///
	/// # Errors
	///
	/// - [`KdfError::InvalidSaltLength`] when a non-empty `salt` is shorter than [`MIN_SALT_SIZE`].
	/// - [`KdfError::DerivationFailed`] when the KDF refuses `key_size`, or returns another length.
	fn ecies_kdf_with_shared_info<P: KdfFunction>(
		self,
		shared_info: impl AsRef<[u8]>,
		salt: Option<&[u8]>,
		key_size: usize,
	) -> Result<ZeroizingBytes>;

	/// Derive an encryption and MAC key pair of `N` bytes each from SharedInfo
	/// the caller assembled.
	///
	/// # Errors
	///
	/// - [`KdfError::InvalidSaltLength`] when a non-empty `salt` is shorter than [`MIN_SALT_SIZE`].
	/// - [`KdfError::DerivationFailed`] when `N` is outside
	///   [`MIN_KEY_SIZE`]`..=`[`MAX_HKDF_OUTPUT_SIZE`], or expansion fails.
	fn ecies_kdf_with_shared_info_and_size<P: KdfFunction, const N: usize>(
		self,
		shared_info: impl AsRef<[u8]>,
		salt: Option<&[u8]>,
	) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)>;
}

impl EciesKdf for EcdhSecret {
	fn ecies_kdf<P: KdfFunction>(
		self,
		ephemeral_pubkey: impl AsRef<[u8]>,
		info: impl AsRef<[u8]>,
		salt: Option<&[u8]>,
		key_size: usize,
	) -> Result<ZeroizingBytes> {
		let shared_info = shared_info(info.as_ref(), ephemeral_pubkey.as_ref());
		self.ecies_kdf_with_shared_info::<P>(shared_info, salt, key_size)
	}

	fn ecies_kdf_with_size<P: KdfFunction, const N: usize>(
		self,
		ephemeral_pubkey: impl AsRef<[u8]>,
		info: impl AsRef<[u8]>,
		salt: Option<&[u8]>,
	) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)> {
		let shared_info = shared_info(info.as_ref(), ephemeral_pubkey.as_ref());
		self.ecies_kdf_with_shared_info_and_size::<P, N>(shared_info, salt)
	}

	fn ecies_kdf_with_shared_info<P: KdfFunction>(
		self,
		shared_info: impl AsRef<[u8]>,
		salt: Option<&[u8]>,
		key_size: usize,
	) -> Result<ZeroizingBytes> {
		let shared_info = shared_info.as_ref();
		assert_valid_salt(salt)?;
		let key = self.with(|secret| P::derive_dynamic_key(secret, shared_info, salt, key_size))?;

		// The length is the caller's cipher geometry, so a provider that
		// returns another length fails here rather than at the cipher.
		if key.len() != key_size {
			return Err(KdfError::DerivationFailed(InvalidLength));
		}

		Ok(key)
	}

	fn ecies_kdf_with_shared_info_and_size<P: KdfFunction, const N: usize>(
		self,
		shared_info: impl AsRef<[u8]>,
		salt: Option<&[u8]>,
	) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)> {
		let shared_info = shared_info.as_ref();
		assert_valid_salt(salt)?;
		self.with(|secret| P::derive_dual_keys::<N>(secret, shared_info, salt))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::secret::Secret;

	#[track_caller]
	fn assert_key_length(key: &[u8], expected_len: usize) {
		assert_eq!(key.len(), expected_len, "Key length mismatch");
	}

	#[track_caller]
	fn assert_keys_equal(key1: &[u8], key2: &[u8]) {
		assert_eq!(key1[..], key2[..], "Keys should be equal");
	}

	#[track_caller]
	fn assert_keys_different(key1: &[u8], key2: &[u8]) {
		assert_ne!(key1[..], key2[..], "Keys should be different");
	}

	macro_rules! assert_key_pair_lengths {
		($enc:expr, $mac:expr, $size:expr) => {
			assert_eq!($enc.len(), $size, "Encryption key length mismatch");
			assert_eq!($mac.len(), $size, "MAC key length mismatch");
		};
	}

	macro_rules! assert_keys_different {
		($key1:expr, $key2:expr) => {
			assert_ne!($key1[..], $key2[..], "Keys should be different");
		};
	}

	macro_rules! assert_key_length {
		($key:expr, $size:expr) => {
			assert_eq!($key.len(), $size, "Key length mismatch");
		};
	}

	fn shared_secret_32() -> EcdhSecret {
		Secret::from(*b"shared_secret_32_bytes__________")
	}

	const EPHEMERAL_PUBKEY_33: &[u8] = b"ephemeral_public_key_33_bytes____";
	const EPHEMERAL_PUBKEY_33_ALT: &[u8] = b"different_ephemeral_key_33_bytes_";
	const INFO_V1: &[u8] = b"tightbeam-ecies-v1";
	const INFO_V2: &[u8] = b"protocol-v2";
	const SALT: &[u8] = b"random_salt_value";

	// The ECIES KDF derives a deterministic 32-byte key that changes with the
	// public key, the info, and the salt. A 65-byte uncompressed public key
	// also derives a 32-byte key.
	#[test]
	fn test_ecies_kdf_basic_functionality() -> crate::error::Result<()> {
		let basic_key = shared_secret_32().ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, INFO_V1, None, 32)?;
		let same_key = shared_secret_32().ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, INFO_V1, None, 32)?;
		let different_pubkey =
			shared_secret_32().ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33_ALT, INFO_V1, None, 32)?;
		let different_info = shared_secret_32().ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, INFO_V2, None, 32)?;
		let with_salt = shared_secret_32().ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, INFO_V1, Some(SALT), 32)?;

		let mut uncompressed_pubkey = [0u8; 65];
		uncompressed_pubkey[0] = 0x04; // Uncompressed marker
		for (i, byte) in uncompressed_pubkey.iter_mut().enumerate().skip(1) {
			*byte = (i % 256) as u8;
		}

		let uncompressed_result = shared_secret_32().ecies_kdf::<HkdfSha3_256>(uncompressed_pubkey, INFO_V1, None, 32);

		assert_key_length(&basic_key, 32);
		assert_keys_equal(&basic_key, &same_key);
		assert_keys_different(&basic_key, &different_pubkey); // Different pubkey
		assert_keys_different(&basic_key, &different_info); // Different info
		assert_keys_different(&basic_key, &with_salt); // With vs without salt
		assert!(uncompressed_result.is_ok());
		assert_key_length(&uncompressed_result?, 32);

		Ok(())
	}

	// ECIES dual keys derive at 16, 32, and 64 bytes, and the encryption key
	// differs from the MAC key.
	#[test]
	fn test_ecies_kdf_size_variations() -> crate::error::Result<()> {
		let keys_16 = shared_secret_32().ecies_kdf_with_size::<HkdfSha3_256, 16>(EPHEMERAL_PUBKEY_33, INFO_V1, None)?;
		let keys_32 = shared_secret_32().ecies_kdf_with_size::<HkdfSha3_256, 32>(EPHEMERAL_PUBKEY_33, INFO_V1, None)?;
		let keys_64 = shared_secret_32().ecies_kdf_with_size::<HkdfSha3_256, 64>(EPHEMERAL_PUBKEY_33, INFO_V1, None)?;

		let (k_enc_16, k_mac_16) = keys_16;
		let (k_enc_32, k_mac_32) = keys_32;
		let (k_enc_64, k_mac_64) = keys_64;
		assert_key_pair_lengths!(k_enc_16, k_mac_16, 16);
		assert_key_pair_lengths!(k_enc_32, k_mac_32, 32);
		assert_key_pair_lengths!(k_enc_64, k_mac_64, 64);
		assert_keys_different!(k_enc_32, k_mac_32);

		Ok(())
	}

	// `EcdhSecret` refuses a shared secret of the wrong length, so every
	// derivation runs on exactly 32 bytes.
	#[test]
	fn a_shared_secret_of_the_wrong_length_is_refused() {
		let short = EcdhSecret::try_from(SecretSlice::from(b"short".to_vec()));
		let long = EcdhSecret::try_from(SecretSlice::from(b"shared_secret_that_is_too_long____".to_vec()));
		assert!(matches!(short, Err(KdfError::InvalidSharedSecretLength(5))));
		assert!(matches!(long, Err(KdfError::InvalidSharedSecretLength(34))));
	}

	// Under a separator byte string, a caller can shift the boundary between
	// the two parts, so distinct inputs concatenate to one SharedInfo and
	// derive one key. Length framing must keep them apart.
	#[test]
	fn a_shifted_context_boundary_derives_a_different_key() -> crate::error::Result<()> {
		let mut shifted_into_info = INFO_V1.to_vec();
		shifted_into_info.extend_from_slice(b"|epk|AAAA");

		let in_pubkey = shared_secret_32().ecies_kdf::<HkdfSha3_256>(b"AAAA|epk|BBBB", INFO_V1, None, 32)?;
		let in_info = shared_secret_32().ecies_kdf::<HkdfSha3_256>(b"BBBB", &shifted_into_info, None, 32)?;
		assert_ne!(in_pubkey[..], in_info[..]);
		Ok(())
	}

	// A salt shorter than the floor is refused, so a derivation never runs
	// with weak salt entropy.
	#[test]
	fn a_short_salt_is_refused() {
		let result = shared_secret_32().ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, INFO_V1, Some(b"short"), 32);
		assert!(matches!(result, Err(KdfError::InvalidSaltLength(5))));
	}

	// General-purpose HKDF derives 16, 32, and 64-byte keys. The same inputs
	// derive the same key, and a different IKM derives a different key.
	#[test]
	fn test_hkdf_sha3_256_basic() -> crate::error::Result<()> {
		let ikm = b"input_key_material";
		let info = b"test_info";

		let key_16 = HkdfSha3_256::derive_key::<16>(ikm, info, None)?;
		let key_32 = HkdfSha3_256::derive_key::<32>(ikm, info, None)?;
		let key_64 = HkdfSha3_256::derive_key::<64>(ikm, info, None)?;

		let key_32_again = HkdfSha3_256::derive_key::<32>(ikm, info, None)?;
		let key_different = HkdfSha3_256::derive_key::<32>(b"different_ikm", info, None)?;

		assert_key_length!(key_16, 16);
		assert_key_length!(key_32, 32);
		assert_key_length!(key_64, 64);
		assert_eq!(key_32[..], key_32_again[..]);
		assert_keys_different!(key_32, key_different);

		Ok(())
	}

	// A dual-key size of 64 bytes expands to 128 bytes, which equals
	// `MAX_HKDF_OUTPUT_SIZE`, so it derives. A size of 65 bytes expands to 130
	// bytes, which is past the cap, so it fails with `DerivationFailed`.
	#[test]
	fn test_ecies_kdf_bounds_checking() -> crate::error::Result<()> {
		let max_size_result =
			shared_secret_32().ecies_kdf_with_size::<HkdfSha3_256, 64>(EPHEMERAL_PUBKEY_33, INFO_V1, None);
		let oversized_result =
			shared_secret_32().ecies_kdf_with_size::<HkdfSha3_256, 65>(EPHEMERAL_PUBKEY_33, INFO_V1, None);

		assert!(max_size_result.is_ok());

		let (k_enc, k_mac) = max_size_result?;
		assert_key_pair_lengths!(k_enc, k_mac, 64);

		assert!(oversized_result.is_err());
		assert!(matches!(oversized_result, Err(KdfError::DerivationFailed(_))));

		Ok(())
	}

	// The ANSI X9.63 provider over SHA3-256 is deterministic and binds the
	// info.
	#[test]
	fn test_x963_ecies_kdf_basic() -> crate::error::Result<()> {
		let key1 = shared_secret_32().ecies_kdf::<X963Sha3_256>(EPHEMERAL_PUBKEY_33, INFO_V1, None, 32)?;
		let key1_again = shared_secret_32().ecies_kdf::<X963Sha3_256>(EPHEMERAL_PUBKEY_33, INFO_V1, None, 32)?;
		let key_diff_info = shared_secret_32().ecies_kdf::<X963Sha3_256>(EPHEMERAL_PUBKEY_33, INFO_V2, None, 32)?;
		// X9.63 ignores the salt, so a salted key equals the unsalted key.
		let key_with_salt =
			shared_secret_32().ecies_kdf::<X963Sha3_256>(EPHEMERAL_PUBKEY_33, INFO_V1, Some(SALT), 32)?;

		assert_key_length(&key1, 32);
		assert_keys_equal(&key1, &key1_again);
		assert_keys_different(&key1, &key_diff_info);
		assert_keys_equal(&key1, &key_with_salt);
		Ok(())
	}

	#[test]
	fn test_x963_ecies_kdf_size_variations() -> crate::error::Result<()> {
		let keys_16 = shared_secret_32().ecies_kdf_with_size::<X963Sha3_256, 16>(EPHEMERAL_PUBKEY_33, INFO_V1, None)?;
		let keys_32 = shared_secret_32().ecies_kdf_with_size::<X963Sha3_256, 32>(EPHEMERAL_PUBKEY_33, INFO_V1, None)?;

		let (k_enc_16, k_mac_16) = keys_16;
		let (k_enc_32, k_mac_32) = keys_32;
		assert_key_pair_lengths!(k_enc_16, k_mac_16, 16);
		assert_key_pair_lengths!(k_enc_32, k_mac_32, 32);
		assert_keys_different!(k_enc_32, k_mac_32);
		Ok(())
	}

	// Both `derive_key` entry points must enforce the same bounds as their
	// `derive_dynamic_key` counterparts. Both providers reject an output below
	// `MIN_KEY_SIZE`, and the HKDF provider also rejects an output past
	// `MAX_HKDF_OUTPUT_SIZE`.
	#[test]
	fn test_derive_key_bounds_match_dynamic() {
		let hkdf_below_min = HkdfSha3_256::derive_key::<8>(b"ikm", b"info", None);
		let hkdf_above_max = HkdfSha3_256::derive_key::<129>(b"ikm", b"info", None);
		let x963_below_min = X963Sha3_256::derive_key::<8>(b"ikm", b"info", None);
		assert!(matches!(hkdf_below_min, Err(KdfError::DerivationFailed(_))));
		assert!(matches!(hkdf_above_max, Err(KdfError::DerivationFailed(_))));
		assert!(matches!(x963_below_min, Err(KdfError::DerivationFailed(_))));
	}

	// A SharedInfo longer than 256 bytes must derive without a panic, so no
	// fixed 256-byte buffer holds it.
	#[test]
	fn test_x963_dual_keys_large_shared_info() -> crate::error::Result<()> {
		let large_info = vec![0xABu8; 300];
		let (k_enc, k_mac) =
			shared_secret_32().ecies_kdf_with_shared_info_and_size::<X963Sha3_256, 32>(&large_info, None)?;

		assert_key_pair_lengths!(k_enc, k_mac, 32);
		assert_keys_different!(k_enc, k_mac);
		Ok(())
	}

	// The HKDF dual-key output is the interoperable ECIES key schedule, which
	// is the two halves of one RFC 5869 expansion.
	#[test]
	fn an_hkdf_dual_key_pair_is_one_expansion_split_in_half() -> crate::error::Result<()> {
		let mut expected = [0u8; 64];
		Hkdf::<Sha3_256>::new(Some(SALT), b"ikm")
			.expand(INFO_V1, &mut expected)
			.map_err(KdfError::DerivationFailed)?;

		let (k_enc, k_mac) = HkdfSha3_256::derive_dual_keys::<32>(b"ikm", INFO_V1, Some(SALT))?;
		assert_eq!(k_enc[..], expected[..32]);
		assert_eq!(k_mac[..], expected[32..]);
		Ok(())
	}

	// X9.63 dual keys split one expansion the same way.
	#[test]
	fn an_x963_dual_key_pair_is_one_expansion_split_in_half() -> crate::error::Result<()> {
		let expected = X963Sha3_256::derive_dynamic_key(b"ikm", INFO_V1, None, 64)?;
		let (k_enc, k_mac) = X963Sha3_256::derive_dual_keys::<32>(b"ikm", INFO_V1, None)?;
		assert_eq!(k_enc[..], expected[..32]);
		assert_eq!(k_mac[..], expected[32..]);
		Ok(())
	}

	#[test]
	fn a_dual_key_below_the_minimum_size_is_refused() {
		let result = X963Sha3_256::derive_dual_keys::<8>(b"ikm", INFO_V1, None);
		assert!(matches!(result, Err(KdfError::DerivationFailed(_))));
	}
}
