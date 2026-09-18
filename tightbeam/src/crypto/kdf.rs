//! Key Derivation Functions (KDF)
//!
//! This module provides HKDF-based key derivation following
//! [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869), using
//! SHA3-256 as the default hash. It’s used both as a general-purpose KDF and
//! for ECIES-style constructions where distinct encryption and MAC keys are
//! required.
//!
//! Key properties
//! - HKDF ([RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)) with SHA3-256
//! - Deterministic and domain-separated via the `info` parameter
//!   ([RFC 5869 §3.2](https://datatracker.ietf.org/doc/html/rfc5869#section-3.2))
//! - Secure memory handling via `Zeroizing`/`ZeroizingArray`
//! - Input validation for ephemeral public key (33/65), shared secret (32), and salt (>=16)
//!
//! Provider notes
//! - HKDF providers honor the optional `salt` parameter per
//!   [RFC 5869 §2.2](https://datatracker.ietf.org/doc/html/rfc5869#section-2.2).
//! - ANSI X9.63 providers ignore `salt` entirely; derivation depends on the
//!   shared secret Z and the `info`/SharedInfo context bytes
//!   ([SECG SEC 1 v2.0 §3.6](https://www.secg.org/sec1-v2.pdf#page=37)).
//!
//! ECIES note
//! - Many ECIES profiles (e.g.,
//!   [SECG SEC 1 v2.0 §5.1](https://www.secg.org/sec1-v2.pdf#page=57),
//!   [IEEE Std 1363a-2004](https://standards.ieee.org/standard/1363a-2004.html),
//!   [ISO/IEC 18033-2:2006](https://www.iso.org/standard/37971.html))
//!   mandate separate symmetric encryption and MAC keys. This module enforces
//!   key separation by performing one expansion and splitting the output into
//!   two disjoint keys
//!   ([SECG SEC 1 v2.0 §5.1.3](https://www.secg.org/sec1-v2.pdf#page=59)).
//! - ECIES is parameterized by the KDF (see
//!   [SECG SEC 1 v2.0 §5.1](https://www.secg.org/sec1-v2.pdf#page=57),
//!   [IEEE Std 1363a-2004](https://standards.ieee.org/standard/1363a-2004.html)).
//!   This library provides a proper ECIES instantiation using HKDF per
//!   [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) with SHA3-256,
//!   enforcing key separation and context binding via `info`.
//!   If you must target a profile that mandates ANSI X9.63 KDF, supply a
//!   `KdfProvider` that implements that KDF.
//!
//! References
//! - [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869): HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
//! - [NIST SP 800-56A Rev. 3 §5.8](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf#page=64): Key-Derivation Methods for Key-Agreement Schemes
//! - [NIST SP 800-56C Rev. 2 §5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf#page=25): Two-Step Key Derivation (Extraction-then-Expansion)
//! - [SECG SEC 1 v2.0 §5.1](https://www.secg.org/sec1-v2.pdf#page=57): Elliptic Curve Integrated Encryption Scheme (ECIES)
//! - [IEEE Std 1363a-2004](https://standards.ieee.org/standard/1363a-2004.html): Public-Key Cryptography - Amendment 1 (Additional Techniques)
//! - [ISO/IEC 18033-2:2006](https://www.iso.org/standard/37971.html): Encryption algorithms - Part 2: Asymmetric ciphers

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

pub type Result<T> = ::core::result::Result<T, KdfError>;

/// Trait for Key Derivation Function providers
///
/// This trait allows consumers to plug in different KDF implementations
/// from the RustCrypto ecosystem or custom implementations.
pub trait KdfFunction {
	/// Derive a key of the specified length
	fn derive_key<const N: usize>(ikm: &[u8], info: &[u8], salt: Option<&[u8]>) -> Result<ZeroizingArray<N>>;

	/// Derive a key with dynamic (runtime-determined) size
	///
	/// Used when key size comes from negotiated security profile rather than
	/// compile-time const generic. Each provider uses its own digest algorithm.
	///
	/// # Parameters
	/// - `ikm`: Input key material
	/// - `info`: Context/domain separation string
	/// - `salt`: Optional salt (>= 16 bytes if provided)
	/// - `key_size`: Desired output key size in bytes
	///
	/// # Returns
	/// Derived key bytes in a zeroizing buffer
	///
	/// # Errors
	/// Returns `KdfError::DerivationFailed` if key_size is outside valid range.
	fn derive_dynamic_key(ikm: &[u8], info: &[u8], salt: Option<&[u8]>, key_size: usize) -> Result<ZeroizingBytes>;
}

/// Dual-key derivation through any [`KdfFunction`].
///
/// The blanket implementation is the only one, so a KDF identifier names one
/// dual-key output whichever type implements it.
pub trait DualKeyKdf: KdfFunction {
	/// Derive two keys of the specified length (for ECIES encryption + MAC)
	///
	/// ECIES standards (e.g.,
	/// [SECG SEC 1 v2.0 §5.1](https://www.secg.org/sec1-v2.pdf#page=57),
	/// [IEEE Std 1363a-2004](https://standards.ieee.org/standard/1363a-2004.html),
	/// [ISO/IEC 18033-2:2006](https://www.iso.org/standard/37971.html))
	/// require key separation: distinct symmetric keys must be derived for
	/// encryption and for message authentication to avoid key reuse across
	/// primitives.
	///
	/// One construction serves every KDF: a single expansion of `2 * N`
	/// bytes through [`KdfFunction::derive_dynamic_key`], split into two
	/// non-overlapping keys
	/// ([SECG SEC 1 v2.0 §5.1.3](https://www.secg.org/sec1-v2.pdf#page=59)).
	///
	/// # Errors
	///
	/// - [`KdfError::DerivationFailed`] when `N` is below [`MIN_KEY_SIZE`], or
	///   when the KDF refuses `2 * N` bytes or returns another length.
	///
	/// References
	/// - [RFC 5869 §3.2](https://datatracker.ietf.org/doc/html/rfc5869#section-3.2): `info` for context separation
	/// - [NIST SP 800-56C Rev. 2 §5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf#page=25): extraction-then-expansion and context binding
	/// - [SECG SEC 1 v2.0 §5.1.3](https://www.secg.org/sec1-v2.pdf#page=59): ECIES encryption/MAC key separation
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

/// Default HKDF-SHA3-256 provider
pub struct HkdfSha3_256;

/// No standard OID exists for HKDF-SHA3-256, so the profile negotiates it
/// under the NIST SHA3-256 digest OID.
impl AssociatedOid for HkdfSha3_256 {
	const OID: ObjectIdentifier = HASH_SHA3_256;
}

/// Reject key sizes below `MIN_KEY_SIZE` (too weak for cryptographic use).
///
/// Shared by the const-generic and dynamic entry points of every provider so
/// the two cannot diverge on validation.
#[inline]
fn assert_min_key_size(key_size: usize) -> Result<()> {
	if key_size < MIN_KEY_SIZE {
		return Err(KdfError::DerivationFailed(InvalidLength));
	}

	Ok(())
}

/// Reject key sizes outside `[MIN_KEY_SIZE, MAX_HKDF_OUTPUT_SIZE]`.
///
/// HKDF-provider counterpart of [`assert_min_key_size`]: HKDF output is
/// additionally capped by this crate's `MAX_HKDF_OUTPUT_SIZE` policy.
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

/// ANSI X9.63 Concatenation KDF using SHA3-256
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
	/// `Counter_i` starts at 1. A counter that would overflow `u32` is a
	/// derivation failure, not a wrap.
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

/// Errors specific to KDF operations
#[derive(Errorizable, Debug, Clone)]
pub enum KdfError {
	/// Key derivation failed (HKDF expansion error)
	#[error("Key derivation failed: {0}")]
	DerivationFailed(InvalidLength),

	/// Invalid shared secret length
	#[error("Invalid shared secret length: expected 32 bytes, got {0}")]
	InvalidSharedSecretLength(usize),

	/// Invalid salt length
	#[error("Invalid salt length: must be at least 16 bytes, got {0}")]
	InvalidSaltLength(usize),

	/// Secret material was unavailable during derivation
	#[error("Secret unavailable: {0}")]
	SecretUnavailable(crate::crypto::secret::SecretError),
}

crate::impl_from!(crate::crypto::secret::SecretError => KdfError::SecretUnavailable);

/// An ECDH shared secret on a 256-bit curve.
///
/// The length is part of the type, so a derivation that takes one runs no
/// length check of its own. It wipes on drop like every [`Secret`].
pub type EcdhSecret = Secret<[u8; ECDH_SHARED_SECRET_SIZE]>;

impl TryFrom<SecretSlice<u8>> for EcdhSecret {
	type Error = KdfError;

	/// # Errors
	///
	/// - [`KdfError::InvalidSharedSecretLength`] when the secret is not [`ECDH_SHARED_SECRET_SIZE`] bytes.
	/// - [`KdfError::SecretUnavailable`] when the secret was already taken.
	fn try_from(secret: SecretSlice<u8>) -> Result<Self> {
		let bytes = secret.to_insecure()?;
		let sized: [u8; ECDH_SHARED_SECRET_SIZE] = bytes
			.as_ref()
			.try_into()
			.map_err(|_| KdfError::InvalidSharedSecretLength(bytes.len()))?;

		Ok(Secret::from(sized))
	}
}

// ============================================================================
// Input Validation Helpers
// ============================================================================

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

/// Validate salt length if provided (minimum 16 bytes for security).
#[inline]
fn assert_valid_salt(salt: Option<&[u8]>) -> Result<()> {
	if let Some(salt_bytes) = salt {
		if !salt_bytes.is_empty() && salt_bytes.len() < MIN_SALT_SIZE {
			return Err(KdfError::InvalidSaltLength(salt_bytes.len()));
		}
	}

	Ok(())
}

/// Generic ECIES-style KDF using any `KdfProvider`.
///
/// Inputs
/// - `ephemeral_pubkey`: the sender's ephemeral public key, bound as context
/// - `shared_secret`: the ECDH result on a 256-bit curve
/// - `info`: application- or protocol-specific context string
/// - `salt`: optional HKDF salt; if provided and non-empty, must be >= 16 bytes
///
/// Output
/// - 32-byte key suitable for symmetric encryption or MAC, depending on use
///
/// Errors
/// - `InvalidSaltLength`
/// - `DerivationFailed` if HKDF expansion fails
///
/// Standards notes
/// - Uses [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) (HKDF)
///   with SHA3-256. For strict ECIES profiles that mandate X9.63 KDF
///   ([SECG SEC 1 v2.0 §3.6.1](https://www.secg.org/sec1-v2.pdf#page=38)),
///   provide a custom `KdfProvider`.
pub fn ecies_kdf<P: KdfFunction>(
	ephemeral_pubkey: impl AsRef<[u8]>,
	shared_secret: EcdhSecret,
	info: impl AsRef<[u8]>,
	salt: Option<&[u8]>,
) -> Result<ZeroizingArray<32>> {
	assert_valid_salt(salt)?;

	// ECIES: IKM = Z; SharedInfo binds context and the ephemeral public key.
	let shared_info = shared_info(info.as_ref(), ephemeral_pubkey.as_ref());
	shared_secret.with(|secret| P::derive_key::<32>(secret, &shared_info, salt))?
}

/// General-purpose HKDF
/// ([RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)) using any
/// `KdfProvider`.
///
/// Inputs
/// - `ikm`: input key material
/// - `info`: context string for domain separation
///   ([RFC 5869 §3.2](https://datatracker.ietf.org/doc/html/rfc5869#section-3.2))
/// - `salt`: optional HKDF salt
///   ([RFC 5869 §2.2](https://datatracker.ietf.org/doc/html/rfc5869#section-2.2));
///   if provided and non-empty, must be >= 16 bytes
///
/// Output
/// - Key of length `N`
///
/// Safety
/// - `N` MUST be >= [`MIN_KEY_SIZE`]; the provider rejects smaller sizes
///   with [`KdfError::DerivationFailed`].
pub fn hkdf<P: KdfFunction, const N: usize>(
	ikm: impl AsRef<[u8]>,
	info: impl AsRef<[u8]>,
	salt: Option<&[u8]>,
) -> Result<ZeroizingArray<N>> {
	let (ikm, info) = (ikm.as_ref(), info.as_ref());
	P::derive_key::<N>(ikm, info, salt)
}

/// ECIES-style dual-key derivation with configurable key size.
///
/// Inputs
/// - `ephemeral_pubkey`: 33-byte compressed or 65-byte uncompressed
/// - `shared_secret`: 32 bytes
/// - `info`: context string
/// - `salt`: optional salt (>= 16 bytes if non-empty)
///
/// Output
/// - `(k_enc, k_mac)`, each `N` bytes
///
/// Constraints
/// - The KDF's own output bound applies to `2 * N`. HKDF caps it at
///   `MAX_HKDF_OUTPUT_SIZE`, and X9.63 imposes no cap.
///
/// References
/// - [RFC 5869 §3.2](https://datatracker.ietf.org/doc/html/rfc5869#section-3.2): `info` context binding
/// - [NIST SP 800-56C Rev. 2 §5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf#page=25): extraction-then-expansion / FixedInfo
/// - [SECG SEC 1 v2.0 §5.1.3](https://www.secg.org/sec1-v2.pdf#page=59): ECIES encryption/MAC key separation
pub fn ecies_kdf_with_size<P: KdfFunction, const N: usize>(
	ephemeral_pubkey: impl AsRef<[u8]>,
	shared_secret: EcdhSecret,
	info: impl AsRef<[u8]>,
	salt: Option<&[u8]>,
) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)> {
	assert_valid_salt(salt)?;

	// ECIES: IKM = Z; SharedInfo binds context and the ephemeral public key.
	let shared_info = shared_info(info.as_ref(), ephemeral_pubkey.as_ref());
	shared_secret.with(|secret| P::derive_dual_keys::<N>(secret, &shared_info, salt))?
}

/// ECIES key derivation over a shared secret, from SharedInfo the caller
/// assembled.
///
/// [`ecies_kdf`] takes an `(info, ephemeral_pubkey)` pair and length-frames
/// the two parts itself. These methods take the finished SharedInfo instead,
/// for context that pair cannot express, so keeping it unambiguous belongs to
/// the caller: two different inputs that concatenate to the same bytes derive
/// the same key.
pub trait EciesKdf {
	/// Derive a 32-byte key from SharedInfo the caller assembled.
	///
	/// # Errors
	///
	/// - [`KdfError::InvalidSaltLength`] when a non-empty `salt` is shorter than [`MIN_SALT_SIZE`].
	/// - [`KdfError::DerivationFailed`] when expansion fails.
	/// - [`KdfError::SecretUnavailable`] when the secret was already taken.
	fn ecies_kdf_with_shared_info<P: KdfFunction>(
		self,
		shared_info: impl AsRef<[u8]>,
		salt: Option<&[u8]>,
	) -> Result<ZeroizingArray<32>>;

	/// Derive an encryption and MAC key pair of `N` bytes each from SharedInfo
	/// the caller assembled.
	///
	/// # Errors
	///
	/// - [`KdfError::InvalidSaltLength`] when a non-empty `salt` is shorter than [`MIN_SALT_SIZE`].
	/// - [`KdfError::DerivationFailed`] when `N` is outside
	///   [`MIN_KEY_SIZE`]`..=`[`MAX_HKDF_OUTPUT_SIZE`], or expansion fails.
	/// - [`KdfError::SecretUnavailable`] when the secret was already taken.
	fn ecies_kdf_with_shared_info_and_size<P: KdfFunction, const N: usize>(
		self,
		shared_info: impl AsRef<[u8]>,
		salt: Option<&[u8]>,
	) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)>;
}

impl EciesKdf for EcdhSecret {
	fn ecies_kdf_with_shared_info<P: KdfFunction>(
		self,
		shared_info: impl AsRef<[u8]>,
		salt: Option<&[u8]>,
	) -> Result<ZeroizingArray<32>> {
		let shared_info = shared_info.as_ref();
		assert_valid_salt(salt)?;
		self.with(|secret| P::derive_key::<32>(secret, shared_info, salt))?
	}

	fn ecies_kdf_with_shared_info_and_size<P: KdfFunction, const N: usize>(
		self,
		shared_info: impl AsRef<[u8]>,
		salt: Option<&[u8]>,
	) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)> {
		let shared_info = shared_info.as_ref();
		assert_valid_salt(salt)?;
		self.with(|secret| P::derive_dual_keys::<N>(secret, shared_info, salt))?
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::secret::Secret;

	// Test assertion helpers for common patterns
	#[track_caller]
	fn assert_key_length<const N: usize>(key: &ZeroizingArray<N>, expected_len: usize) {
		assert_eq!(key.len(), expected_len, "Key length mismatch");
	}

	#[track_caller]
	fn assert_keys_equal<const N: usize>(key1: &ZeroizingArray<N>, key2: &ZeroizingArray<N>) {
		assert_eq!(key1[..], key2[..], "Keys should be equal");
	}

	#[track_caller]
	fn assert_keys_different<const N: usize>(key1: &ZeroizingArray<N>, key2: &ZeroizingArray<N>) {
		assert_ne!(key1[..], key2[..], "Keys should be different");
	}

	// Key assertion macros for common test patterns
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

	// Test data constants
	const EPHEMERAL_PUBKEY_33: &[u8] = b"ephemeral_public_key_33_bytes____";
	const EPHEMERAL_PUBKEY_33_ALT: &[u8] = b"different_ephemeral_key_33_bytes_";
	const INFO_V1: &[u8] = b"tightbeam-ecies-v1";
	const INFO_V2: &[u8] = b"protocol-v2";
	const SALT: &[u8] = b"random_salt_value";

	// Consolidated test for ECIES KDF basic functionality
	#[test]
	fn test_ecies_kdf_basic_functionality() -> crate::error::Result<()> {
		// Test cases for basic functionality and determinism
		let basic_key = ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V1, None)?;
		let same_key = ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V1, None)?;
		// Test cases for input variation (different inputs should produce different outputs)
		let different_pubkey = ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33_ALT, shared_secret_32(), INFO_V1, None)?;
		let different_info = ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V2, None)?;
		let with_salt = ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V1, Some(SALT))?;

		// Test case for uncompressed pubkey (65 bytes)
		let mut uncompressed_pubkey = [0u8; 65];
		uncompressed_pubkey[0] = 0x04; // Uncompressed marker
		for (i, byte) in uncompressed_pubkey.iter_mut().enumerate().skip(1) {
			*byte = (i % 256) as u8;
		}

		let uncompressed_result = ecies_kdf::<HkdfSha3_256>(uncompressed_pubkey, shared_secret_32(), INFO_V1, None);

		// Basic functionality: key should be 32 bytes
		assert_key_length(&basic_key, 32);
		// Determinism: same inputs produce same outputs
		assert_keys_equal(&basic_key, &same_key);
		// Input variation: different inputs produce different outputs
		assert_keys_different(&basic_key, &different_pubkey); // Different pubkey
		assert_keys_different(&basic_key, &different_info); // Different info
		assert_keys_different(&basic_key, &with_salt); // With vs without salt
												 // Uncompressed pubkey: should work and produce 32-byte key
		assert!(uncompressed_result.is_ok());
		assert_key_length(&uncompressed_result?, 32);

		Ok(())
	}

	// Consolidated test for ECIES KDF size variations
	#[test]
	fn test_ecies_kdf_size_variations() -> crate::error::Result<()> {
		// Test different key sizes
		let keys_16 = ecies_kdf_with_size::<HkdfSha3_256, 16>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V1, None)?;
		let keys_32 = ecies_kdf_with_size::<HkdfSha3_256, 32>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V1, None)?;
		let keys_64 = ecies_kdf_with_size::<HkdfSha3_256, 64>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V1, None)?;

		let (k_enc_16, k_mac_16) = keys_16;
		let (k_enc_32, k_mac_32) = keys_32;
		let (k_enc_64, k_mac_64) = keys_64;
		assert_key_pair_lengths!(k_enc_16, k_mac_16, 16);
		assert_key_pair_lengths!(k_enc_32, k_mac_32, 32);
		assert_key_pair_lengths!(k_enc_64, k_mac_64, 64);
		// Encryption and MAC keys should be different
		assert_keys_different!(k_enc_32, k_mac_32);

		Ok(())
	}

	// A shared secret of the wrong length never becomes an `EcdhSecret`, so
	// no derivation can run on it.
	#[test]
	fn a_shared_secret_of_the_wrong_length_is_refused() {
		let short = EcdhSecret::try_from(SecretSlice::from(b"short".to_vec()));
		let long = EcdhSecret::try_from(SecretSlice::from(b"shared_secret_that_is_too_long____".to_vec()));
		assert!(matches!(short, Err(KdfError::InvalidSharedSecretLength(5))));
		assert!(matches!(long, Err(KdfError::InvalidSharedSecretLength(34))));
	}

	// A separator byte string let a caller shift the boundary between the two
	// parts, so distinct inputs concatenated to one SharedInfo and derived one
	// key. Length framing must keep them apart.
	#[test]
	fn a_shifted_context_boundary_derives_a_different_key() -> crate::error::Result<()> {
		let mut shifted_into_info = INFO_V1.to_vec();
		shifted_into_info.extend_from_slice(b"|epk|AAAA");

		let in_pubkey = ecies_kdf::<HkdfSha3_256>(b"AAAA|epk|BBBB", shared_secret_32(), INFO_V1, None)?;
		let in_info = ecies_kdf::<HkdfSha3_256>(b"BBBB", shared_secret_32(), &shifted_into_info, None)?;
		assert_ne!(in_pubkey[..], in_info[..]);
		Ok(())
	}

	// A salt shorter than the floor is refused, so a derivation never runs
	// with weak salt entropy.
	#[test]
	fn a_short_salt_is_refused() {
		let result = ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V1, Some(b"short"));
		assert!(matches!(result, Err(KdfError::InvalidSaltLength(5))));
	}

	// Consolidated test for general-purpose HKDF
	#[test]
	fn test_hkdf_sha3_256_basic() -> crate::error::Result<()> {
		let ikm = b"input_key_material";
		let info = b"test_info";

		// Test different key sizes
		let key_16 = hkdf::<HkdfSha3_256, 16>(ikm, info, None)?;
		let key_32 = hkdf::<HkdfSha3_256, 32>(ikm, info, None)?;
		let key_64 = hkdf::<HkdfSha3_256, 64>(ikm, info, None)?;

		// Determinism test
		let key_32_again = hkdf::<HkdfSha3_256, 32>(ikm, info, None)?;
		// Different inputs test
		let key_different = hkdf::<HkdfSha3_256, 32>(b"different_ikm", info, None)?;

		// Check key lengths
		assert_key_length!(key_16, 16);
		assert_key_length!(key_32, 32);
		assert_key_length!(key_64, 64);
		// Same inputs should produce same outputs (determinism)
		assert_eq!(key_32[..], key_32_again[..]);
		// Different inputs should produce different outputs
		assert_keys_different!(key_32, key_different);

		Ok(())
	}

	// Test bounds checking for dual key derivation
	#[test]
	fn test_ecies_kdf_bounds_checking() -> crate::error::Result<()> {
		// Test maximum allowed key size (64 bytes * 2 = 128 bytes = MAX_HKDF_OUTPUT_SIZE)
		let max_size_result =
			ecies_kdf_with_size::<HkdfSha3_256, 64>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V1, None);
		// Test oversized key size that should fail (65 bytes * 2 = 130 bytes > MAX_HKDF_OUTPUT_SIZE)
		let oversized_result =
			ecies_kdf_with_size::<HkdfSha3_256, 65>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V1, None);

		// Maximum allowed size should work
		assert!(max_size_result.is_ok());

		let (k_enc, k_mac) = max_size_result?;
		assert_key_pair_lengths!(k_enc, k_mac, 64);

		// Oversized key should fail with DerivationFailed
		assert!(oversized_result.is_err());
		assert!(matches!(oversized_result, Err(KdfError::DerivationFailed(_))));

		Ok(())
	}

	// Smoke tests for ANSI X9.63 provider over SHA3-256
	#[test]
	fn test_x963_ecies_kdf_basic() -> crate::error::Result<()> {
		let key1 = ecies_kdf::<X963Sha3_256>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V1, None)?;
		let key1_again = ecies_kdf::<X963Sha3_256>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V1, None)?;
		let key_diff_info = ecies_kdf::<X963Sha3_256>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V2, None)?;
		// Salt is ignored by X9.63; with vs without salt should be equal
		let key_with_salt = ecies_kdf::<X963Sha3_256>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V1, Some(SALT))?;

		assert_key_length(&key1, 32);
		assert_keys_equal(&key1, &key1_again);
		assert_keys_different(&key1, &key_diff_info);
		// Salt should have no effect in X9.63
		assert_keys_equal(&key1, &key_with_salt);
		Ok(())
	}

	#[test]
	fn test_x963_ecies_kdf_size_variations() -> crate::error::Result<()> {
		let keys_16 = ecies_kdf_with_size::<X963Sha3_256, 16>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V1, None)?;
		let keys_32 = ecies_kdf_with_size::<X963Sha3_256, 32>(EPHEMERAL_PUBKEY_33, shared_secret_32(), INFO_V1, None)?;

		let (k_enc_16, k_mac_16) = keys_16;
		let (k_enc_32, k_mac_32) = keys_32;
		assert_key_pair_lengths!(k_enc_16, k_mac_16, 16);
		assert_key_pair_lengths!(k_enc_32, k_mac_32, 32);
		assert_keys_different!(k_enc_32, k_mac_32);
		Ok(())
	}

	// Both derive_key entry points must enforce the same bounds as their
	// derive_dynamic_key counterparts: sub-MIN_KEY_SIZE outputs are rejected
	// for both providers, and the HKDF provider also rejects outputs beyond
	// MAX_HKDF_OUTPUT_SIZE.
	#[test]
	fn test_derive_key_bounds_match_dynamic() {
		let hkdf_below_min = HkdfSha3_256::derive_key::<8>(b"ikm", b"info", None);
		let hkdf_above_max = HkdfSha3_256::derive_key::<129>(b"ikm", b"info", None);
		let x963_below_min = X963Sha3_256::derive_key::<8>(b"ikm", b"info", None);
		assert!(matches!(hkdf_below_min, Err(KdfError::DerivationFailed(_))));
		assert!(matches!(hkdf_above_max, Err(KdfError::DerivationFailed(_))));
		assert!(matches!(x963_below_min, Err(KdfError::DerivationFailed(_))));
	}

	// SharedInfo longer than the former fixed 256-byte buffer must derive
	// without panicking.
	#[test]
	fn test_x963_dual_keys_large_shared_info() -> crate::error::Result<()> {
		let large_info = vec![0xABu8; 300];
		let (k_enc, k_mac) =
			shared_secret_32().ecies_kdf_with_shared_info_and_size::<X963Sha3_256, 32>(&large_info, None)?;

		assert_key_pair_lengths!(k_enc, k_mac, 32);
		assert_keys_different!(k_enc, k_mac);
		Ok(())
	}

	// The HKDF dual-key output is the ECIES wire key schedule: the halves of
	// one RFC 5869 expansion.
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
