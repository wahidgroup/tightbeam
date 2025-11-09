//! Key Derivation Functions (KDF)
//!
//! This module provides HKDF-based key derivation following RFC 5869, using
//! SHA3-256 as the default hash. It’s used both as a general-purpose KDF and
//! for ECIES-style constructions where distinct encryption and MAC keys are required.
//!
//! Key properties
//! - HKDF (RFC 5869) with SHA3-256
//! - Deterministic and domain-separated via the `info` parameter
//! - Secure memory handling via `Zeroizing`/`ZeroizingArray`
//! - Input validation for ephemeral public key (33/65), shared secret (32), and salt (>=16)
//!
//! Provider notes
//! - HKDF providers honor the optional `salt` parameter per RFC 5869.
//! - ANSI X9.63 providers ignore `salt` entirely; derivation depends on the
//!   shared secret Z and the `info`/SharedInfo context bytes.
//!
//! ECIES note
//! - Many ECIES profiles (e.g., SECG SEC 1, IEEE 1363a, ISO/IEC 18033-2) mandate
//!   separate symmetric encryption and MAC keys. This module enforces key separation
//!   by either (a) running two HKDF expansions with distinct `info` labels or
//!   (b) performing one HKDF expansion and splitting the output into two disjoint keys.
//! - ECIES is parameterized by the KDF (see SECG SEC 1, IEEE 1363a). This
//!   library provides a proper ECIES instantiation using HKDF per RFC 5869
//!   with SHA3-256, enforcing key separation and context binding via `info`.
//!   If you must target a profile that mandates ANSI X9.63 KDF, supply a
//!   `KdfProvider` that implements that KDF.
//!
//! References
//! - RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
//! - NIST SP 800-56A Rev. 3: Recommendation for Pair-Wise Key Establishment Schemes
//! - NIST SP 800-56C Rev. 2: Recommendation for KDFs using HMAC
//! - SECG SEC 1 v2.0: Elliptic Curve Cryptography (ECIES)
//! - IEEE 1363a: Standard Specifications for Public-Key Cryptography (ECIES/KEM-DEM)
//! - ISO/IEC 18033-2: Asymmetric ciphers (ECIES)

pub use hkdf::Hkdf;

use crate::crypto::hash::{Digest, Sha3_256};
use crate::zeroize::Zeroizing;
use crate::ZeroizingArray;

pub type Result<T> = ::core::result::Result<T, KdfError>;

/// Temporary buffer limit for optimized dual-key expansion in the default provider.
/// Ensures `2*N <= 128` when deriving (enc, mac) via a single HKDF-Expand.
const MAX_HKDF_OUTPUT_SIZE: usize = 128;
/// Minimum secure key size in bytes
const MIN_KEY_SIZE: usize = 16;

/// Trait for Key Derivation Function providers
///
/// This trait allows consumers to plug in different KDF implementations
/// from the RustCrypto ecosystem or custom implementations.
pub trait KdfProvider {
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
	/// Zeroizing vector containing derived key bytes
	///
	/// # Errors
	/// Returns `KdfError::DerivationFailed` if key_size is outside valid range.
	fn derive_dynamic_key(ikm: &[u8], info: &[u8], salt: Option<&[u8]>, key_size: usize) -> Result<Zeroizing<Vec<u8>>>;

	/// Derive two keys of the specified length (for ECIES encryption + MAC)
	///
	/// ECIES standards (e.g., SECG SEC 1, IEEE 1363a, ISO/IEC 18033-2) require
	/// key separation: distinct symmetric keys must be derived for encryption
	/// and for message authentication to avoid key reuse across primitives.
	///
	/// Default behavior
	/// - Performs two HKDF-Expand operations with different `info` labels:
	///   `{info}-encryption` and `{info}-mac`.
	/// - This yields two independent keys while preserving RFC 5869 domain separation.
	///
	/// Provider override
	/// - Implementations MAY override this with a single HKDF-Expand that
	///   produces 2*N bytes and split the output into two keys, preserving
	///   independence by non-overlapping segments. This is equivalent in
	///   security if the underlying HKDF is robust and the segments do not
	///   overlap.
	///
	/// References
	/// - RFC 5869 (HKDF): Section 2.2 (the `info` field for context separation)
	/// - NIST SP 800-56C Rev. 2: HMAC-based KDFs and context information (“OtherInfo”)
	/// - SECG SEC 1 v2.0 / IEEE 1363a / ISO/IEC 18033-2: ECIES key separation requirement
	fn derive_dual_keys<const N: usize>(
		ikm: &[u8],
		info: &[u8],
		salt: Option<&[u8]>,
	) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)> {
		// Use separate info strings for encryption and MAC keys as recommended
		// by ECIES standards. This prevents key reuse between encryption and
		// authentication operations.
		let mut enc_info = Vec::with_capacity(info.len() + 11);
		enc_info.extend_from_slice(info);
		enc_info.extend_from_slice(b"-encryption");

		let mut mac_info = Vec::with_capacity(info.len() + 4);
		mac_info.extend_from_slice(info);
		mac_info.extend_from_slice(b"-mac");

		let k_enc = Self::derive_key::<N>(ikm, &enc_info, salt)?;
		let k_mac = Self::derive_key::<N>(ikm, &mac_info, salt)?;

		Ok((k_enc, k_mac))
	}
}
/// Default HKDF-SHA3-256 provider
pub struct HkdfSha3_256;

impl KdfProvider for HkdfSha3_256 {
	fn derive_key<const N: usize>(ikm: &[u8], info: &[u8], salt: Option<&[u8]>) -> Result<ZeroizingArray<N>> {
		let hk = Hkdf::<Sha3_256>::new(salt, ikm);
		let mut output = Zeroizing::new([0u8; N]);
		hk.expand(info, &mut output[..]).map_err(KdfError::DerivationFailed)?;
		Ok(output)
	}

	fn derive_dynamic_key(ikm: &[u8], info: &[u8], salt: Option<&[u8]>, key_size: usize) -> Result<Zeroizing<Vec<u8>>> {
		if key_size < MIN_KEY_SIZE || key_size > MAX_HKDF_OUTPUT_SIZE {
			return Err(KdfError::DerivationFailed(hkdf::InvalidLength));
		}

		let hk = Hkdf::<Sha3_256>::new(salt, ikm);
		let mut okm = vec![0u8; key_size];
		hk.expand(info, &mut okm).map_err(KdfError::DerivationFailed)?;

		Ok(Zeroizing::new(okm))
	}

	/// Optimized: single HKDF-Expand to 2*N bytes, then split into (enc, mac).
	/// Note: bounded by `MAX_HKDF_OUTPUT_SIZE` for the temporary buffer.
	fn derive_dual_keys<const N: usize>(
		ikm: &[u8],
		info: &[u8],
		salt: Option<&[u8]>,
	) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)> {
		// Provider-specific safety bound for the temporary buffer used below.
		if N * 2 > MAX_HKDF_OUTPUT_SIZE {
			return Err(KdfError::DerivationFailed(hkdf::InvalidLength));
		}
		// Optimized implementation: single HKDF expansion for both keys
		// This is functionally equivalent to separate derivations but more
		// efficient ECIES standards require separate encryption/MAC keys,
		// which this provides by splitting the expanded output into two
		// distinct key portions
		let hk = Hkdf::<Sha3_256>::new(salt, ikm);
		let mut combined = Zeroizing::new([0u8; MAX_HKDF_OUTPUT_SIZE]);
		hk.expand(info, &mut combined[..N * 2]).map_err(KdfError::DerivationFailed)?;

		let mut k_enc = Zeroizing::new([0u8; N]);
		let mut k_mac = Zeroizing::new([0u8; N]);
		k_enc[..].copy_from_slice(&combined[..N]);
		k_mac[..].copy_from_slice(&combined[N..N * 2]);
		Ok((k_enc, k_mac))
	}
}

/// ANSI X9.63 Concatenation KDF using SHA3-256
pub struct X963Sha3_256;

impl KdfProvider for X963Sha3_256 {
	fn derive_key<const N: usize>(ikm: &[u8], info: &[u8], _salt: Option<&[u8]>) -> Result<ZeroizingArray<N>> {
		// K(i) = Hash( Z || Counter_i || SharedInfo ), Counter_i starts at 1
		let mut out = Zeroizing::new([0u8; N]);
		let mut offset = 0usize;
		let mut counter: u32 = 1;
		while offset < N {
			let mut hasher = Sha3_256::new();
			hasher.update(ikm); // Z only
			hasher.update(counter.to_be_bytes());
			hasher.update(info); // SharedInfo/OtherInfo
			let block = hasher.finalize();
			let take = core::cmp::min(block.len(), N - offset);
			out[offset..offset + take].copy_from_slice(&block[..take]);
			offset += take;
			counter = counter.wrapping_add(1);
		}
		Ok(out)
	}

	fn derive_dynamic_key(
		ikm: &[u8],
		info: &[u8],
		_salt: Option<&[u8]>,
		key_size: usize,
	) -> Result<Zeroizing<Vec<u8>>> {
		if key_size < MIN_KEY_SIZE {
			return Err(KdfError::DerivationFailed(hkdf::InvalidLength));
		}

		// K(i) = Hash( Z || Counter_i || SharedInfo ), Counter_i starts at 1
		let mut out = vec![0u8; key_size];
		let mut offset = 0usize;
		let mut counter: u32 = 1;
		while offset < key_size {
			let mut hasher = Sha3_256::new();
			hasher.update(ikm);
			hasher.update(counter.to_be_bytes());
			hasher.update(info);
			let block = hasher.finalize();
			let take = core::cmp::min(block.len(), key_size - offset);
			out[offset..offset + take].copy_from_slice(&block[..take]);
			offset += take;
			counter = counter.wrapping_add(1);
		}
		Ok(Zeroizing::new(out))
	}

	fn derive_dual_keys<const N: usize>(
		ikm: &[u8],
		info: &[u8],
		_salt: Option<&[u8]>,
	) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)> {
		// Derive two independent keys via distinct SharedInfo labels
		let mut enc_info = Vec::with_capacity(info.len() + 11);
		enc_info.extend_from_slice(info);
		enc_info.extend_from_slice(b"-encryption");

		let mut mac_info = Vec::with_capacity(info.len() + 4);
		mac_info.extend_from_slice(info);
		mac_info.extend_from_slice(b"-mac");

		let k_enc = Self::derive_key::<N>(ikm, &enc_info, None)?;
		let k_mac = Self::derive_key::<N>(ikm, &mac_info, None)?;
		Ok((k_enc, k_mac))
	}
}

/// Errors specific to KDF operations
#[cfg_attr(feature = "derive", derive(crate::Errorizable))]
#[derive(Debug, Clone)]
pub enum KdfError {
	/// Key derivation failed (HKDF expansion error)
	#[cfg_attr(feature = "derive", error("Key derivation failed: {0}"))]
	DerivationFailed(hkdf::InvalidLength),

	/// Invalid ephemeral public key length
	#[cfg_attr(
		feature = "derive",
		error("Invalid ephemeral public key length: expected 33 or 65 bytes, got {0}")
	)]
	InvalidPublicKeyLength(usize),

	/// Invalid shared secret length
	#[cfg_attr(
		feature = "derive",
		error("Invalid shared secret length: expected 32 bytes, got {0}")
	)]
	InvalidSharedSecretLength(usize),

	/// Invalid salt length
	#[cfg_attr(
		feature = "derive",
		error("Invalid salt length: must be at least 16 bytes, got {0}")
	)]
	InvalidSaltLength(usize),
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for KdfError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			KdfError::DerivationFailed(e) => write!(f, "Key derivation failed: {}", e),
			KdfError::InvalidPublicKeyLength(len) => {
				write!(f, "Invalid ephemeral public key length: expected 33 or 65 bytes, got {}", len)
			}
			KdfError::InvalidSharedSecretLength(len) => {
				write!(f, "Invalid shared secret length: expected 32 bytes, got {}", len)
			}
			KdfError::InvalidSaltLength(len) => {
				write!(f, "Invalid salt length: must be at least 16 bytes, got {}", len)
			}
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for KdfError {}

/// Validate common KDF inputs (ephemeral pubkey, shared secret, and optional salt)
#[inline]
fn assert_valid_kdf_inputs(ephemeral_pubkey: &[u8], shared_secret: &[u8], salt: Option<&[u8]>) -> Result<()> {
	// Validate ephemeral public key length for secp256k1 (33 bytes compressed, 65 bytes uncompressed)
	if ephemeral_pubkey.len() != 33 && ephemeral_pubkey.len() != 65 {
		return Err(KdfError::InvalidPublicKeyLength(ephemeral_pubkey.len()));
	}

	// Validate shared secret length (32 bytes for 256-bit curves)
	if shared_secret.len() != 32 {
		return Err(KdfError::InvalidSharedSecretLength(shared_secret.len()));
	}

	// Validate salt length if provided (minimum 16 bytes for security)
	if let Some(salt_bytes) = salt {
		if !salt_bytes.is_empty() && salt_bytes.len() < MIN_KEY_SIZE {
			return Err(KdfError::InvalidSaltLength(salt_bytes.len()));
		}
	}

	Ok(())
}

/// Generic ECIES-style KDF using any `KdfProvider`.
///
/// Inputs
/// - `ephemeral_pubkey`: 33-byte compressed or 65-byte uncompressed
/// - `shared_secret`: 32 bytes (e.g., ECDH result on a 256-bit curve)
/// - `info`: application- or protocol-specific context string
/// - `salt`: optional HKDF salt; if provided and non-empty, must be >= 16 bytes
///
/// Output
/// - 32-byte key suitable for symmetric encryption or MAC, depending on use
///
/// Errors
/// - `InvalidPublicKeyLength`, `InvalidSharedSecretLength`, `InvalidSaltLength`
/// - `DerivationFailed` if HKDF expansion fails
///
/// Standards notes
/// - Uses RFC 5869 (HKDF) with SHA3-256. For strict ECIES profiles that mandate
///   X9.63 KDF, provide a custom `KdfProvider`.
pub fn ecies_kdf<P: KdfProvider>(
	ephemeral_pubkey: impl AsRef<[u8]>,
	shared_secret: impl AsRef<[u8]>,
	info: impl AsRef<[u8]>,
	salt: Option<&[u8]>,
) -> Result<ZeroizingArray<32>> {
	let (ephemeral_pubkey, shared_secret, info) = (ephemeral_pubkey.as_ref(), shared_secret.as_ref(), info.as_ref());
	assert_valid_kdf_inputs(ephemeral_pubkey, shared_secret, salt)?;
	// ECIES: IKM = Z; SharedInfo binds context and the ephemeral public key
	let mut shared_info = Vec::with_capacity(info.len() + 5 + ephemeral_pubkey.len());
	shared_info.extend_from_slice(info);
	shared_info.extend_from_slice(b"|epk|");
	shared_info.extend_from_slice(ephemeral_pubkey);
	P::derive_key::<32>(shared_secret, &shared_info, salt)
}

/// General-purpose HKDF (RFC 5869) using any `KdfProvider`.
///
/// Inputs
/// - `ikm`: input key material
/// - `info`: context string for domain separation
/// - `salt`: optional HKDF salt; if provided and non-empty, must be >= 16 bytes
///
/// Output
/// - Key of length `N`
///
/// Safety
/// - `N` SHOULD be >= 16 bytes for cryptographic use.
pub fn hkdf<P: KdfProvider, const N: usize>(
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
/// - Provider-scoped bounds MAY apply. For example, the default HKDF provider
///   performs an optimized single-expand-and-split and enforces `2*N` within its
///   own internal temporary buffer limit. Other providers (e.g., X9.63) may not
///   impose the same bound.
///
/// References
/// - RFC 5869 (HKDF), NIST SP 800-56C (context/OtherInfo), ECIES profiles (key separation)
pub fn ecies_kdf_with_size<P: KdfProvider, const N: usize>(
	ephemeral_pubkey: impl AsRef<[u8]>,
	shared_secret: impl AsRef<[u8]>,
	info: impl AsRef<[u8]>,
	salt: Option<&[u8]>,
) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)> {
	let (ephemeral_pubkey, shared_secret, info) = (ephemeral_pubkey.as_ref(), shared_secret.as_ref(), info.as_ref());
	assert_valid_kdf_inputs(ephemeral_pubkey, shared_secret, salt)?;
	// ECIES: IKM = Z; SharedInfo binds context and the ephemeral public key
	let mut shared_info = Vec::with_capacity(info.len() + 5 + ephemeral_pubkey.len());
	shared_info.extend_from_slice(info);
	shared_info.extend_from_slice(b"|epk|");
	shared_info.extend_from_slice(ephemeral_pubkey);
	P::derive_dual_keys::<N>(shared_secret, &shared_info, salt)
}

/// ECIES with raw SharedInfo: caller supplies exact SharedInfo/OtherInfo bytes (no EPK auto-append).
/// IKM is the shared secret Z.
pub fn ecies_kdf_with_shared_info<P: KdfProvider>(
	shared_secret: impl AsRef<[u8]>,
	shared_info: impl AsRef<[u8]>,
	salt: Option<&[u8]>,
) -> Result<ZeroizingArray<32>> {
	let (shared_secret, shared_info) = (shared_secret.as_ref(), shared_info.as_ref());
	if shared_secret.len() != 32 {
		return Err(KdfError::InvalidSharedSecretLength(shared_secret.len()));
	}

	if let Some(salt_bytes) = salt {
		if !salt_bytes.is_empty() && salt_bytes.len() < MIN_KEY_SIZE {
			return Err(KdfError::InvalidSaltLength(salt_bytes.len()));
		}
	}

	P::derive_key::<32>(shared_secret, shared_info, salt)
}

/// ECIES dual-key with raw SharedInfo: caller supplies exact SharedInfo/OtherInfo bytes.
/// IKM is the shared secret Z. Provider-specific bounds may apply.
pub fn ecies_kdf_with_shared_info_and_size<P: KdfProvider, const N: usize>(
	shared_secret: impl AsRef<[u8]>,
	shared_info: impl AsRef<[u8]>,
	salt: Option<&[u8]>,
) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)> {
	let (shared_secret, shared_info) = (shared_secret.as_ref(), shared_info.as_ref());
	if shared_secret.len() != 32 {
		return Err(KdfError::InvalidSharedSecretLength(shared_secret.len()));
	}

	if let Some(salt_bytes) = salt {
		if !salt_bytes.is_empty() && salt_bytes.len() < MIN_KEY_SIZE {
			return Err(KdfError::InvalidSaltLength(salt_bytes.len()));
		}
	}

	P::derive_dual_keys::<N>(shared_secret, shared_info, salt)
}

#[cfg(test)]
mod tests {
	use super::*;

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

	// Error assertion macros for cleaner test code
	macro_rules! assert_kdf_error {
		($result:expr, $variant:ident($value:expr)) => {
			assert!(matches!($result, Err(KdfError::$variant(v)) if v == $value),
				"Expected KdfError::{}({}), got {:?}", stringify!($variant), $value, $result);
		};
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

	// Test data constants
	const EPHEMERAL_PUBKEY_33: &[u8] = b"ephemeral_public_key_33_bytes____";
	const EPHEMERAL_PUBKEY_33_ALT: &[u8] = b"different_ephemeral_key_33_bytes_";
	const SHARED_SECRET_32: &[u8] = b"shared_secret_32_bytes__________";
	const INFO_V1: &[u8] = b"tightbeam-ecies-v1";
	const INFO_V2: &[u8] = b"protocol-v2";
	const SALT: &[u8] = b"random_salt_value";

	// Consolidated test for ECIES KDF basic functionality, determinism, input variation, and uncompressed pubkey
	crate::test_case! {
		name: test_ecies_kdf_basic_functionality,
		setup: || {
			// Test cases for basic functionality and determinism
			let basic_key = ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, SHARED_SECRET_32, INFO_V1, None).unwrap();
			let same_key = ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, SHARED_SECRET_32, INFO_V1, None).unwrap();
			// Test cases for input variation (different inputs should produce different outputs)
			let different_pubkey = ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33_ALT, SHARED_SECRET_32, INFO_V1, None).unwrap();
			let different_info = ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, SHARED_SECRET_32, INFO_V2, None).unwrap();
			let with_salt = ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, SHARED_SECRET_32, INFO_V1, Some(SALT)).unwrap();

			// Test case for uncompressed pubkey (65 bytes)
			let mut uncompressed_pubkey = [0u8; 65];
			uncompressed_pubkey[0] = 0x04; // Uncompressed marker
			for (i, byte) in uncompressed_pubkey.iter_mut().enumerate().skip(1) {
				*byte = (i % 256) as u8;
			}

			let uncompressed_result = ecies_kdf::<HkdfSha3_256>(uncompressed_pubkey, SHARED_SECRET_32, INFO_V1, None);
			(basic_key, same_key, different_pubkey, different_info, with_salt, uncompressed_result)
		},
		assertions: |(basic_key, same_key, different_pubkey, different_info, with_salt, uncompressed_result)| {
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
			assert_key_length(&uncompressed_result.unwrap(), 32);

			Ok(())
		}
	}

	// Consolidated test for ECIES KDF size variations
	crate::test_case! {
		name: test_ecies_kdf_size_variations,
		setup: || {
			// Test different key sizes
			let keys_16 = ecies_kdf_with_size::<HkdfSha3_256, 16>(EPHEMERAL_PUBKEY_33, SHARED_SECRET_32, INFO_V1, None).unwrap();
			let keys_32 = ecies_kdf_with_size::<HkdfSha3_256, 32>(EPHEMERAL_PUBKEY_33, SHARED_SECRET_32, INFO_V1, None).unwrap();
			let keys_64 = ecies_kdf_with_size::<HkdfSha3_256, 64>(EPHEMERAL_PUBKEY_33, SHARED_SECRET_32, INFO_V1, None).unwrap();

			(keys_16, keys_32, keys_64)
		},
		assertions: |(keys_16, keys_32, keys_64)| {
			let (k_enc_16, k_mac_16) = keys_16;
			let (k_enc_32, k_mac_32) = keys_32;
			let (k_enc_64, k_mac_64) = keys_64;

			// Check key lengths
			assert_key_pair_lengths!(k_enc_16, k_mac_16, 16);
			assert_key_pair_lengths!(k_enc_32, k_mac_32, 32);
			assert_key_pair_lengths!(k_enc_64, k_mac_64, 64);
			// Encryption and MAC keys should be different
			assert_keys_different!(k_enc_32, k_mac_32);

			Ok(())
		}
	}

	// Consolidated test for input validation
	crate::test_case! {
		name: test_ecies_kdf_input_validation,
		setup: || {
			// Invalid input test cases
			let short_pubkey_result = ecies_kdf::<HkdfSha3_256>(b"short", SHARED_SECRET_32, INFO_V1, None);
			let wrong_size_pubkey_result = ecies_kdf::<HkdfSha3_256>(b"wrong_size_ephemeral_key_34_bytes_", SHARED_SECRET_32, INFO_V1, None);
			let short_secret_result = ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, b"short", INFO_V1, None);
			let long_secret_result = ecies_kdf::<HkdfSha3_256>(EPHEMERAL_PUBKEY_33, b"shared_secret_that_is_too_long____", INFO_V1, None);

			(short_pubkey_result, wrong_size_pubkey_result, short_secret_result, long_secret_result)
		},
		assertions: |(short_pubkey_result, wrong_size_pubkey_result, short_secret_result, long_secret_result)| {
			// Invalid public key lengths
			assert_kdf_error!(short_pubkey_result, InvalidPublicKeyLength(5));
			assert_kdf_error!(wrong_size_pubkey_result, InvalidPublicKeyLength(34));
			// Invalid shared secret lengths
			assert_kdf_error!(short_secret_result, InvalidSharedSecretLength(5));
			assert_kdf_error!(long_secret_result, InvalidSharedSecretLength(34));

			Ok(())
		}
	}

	// Consolidated test for general-purpose HKDF
	crate::test_case! {
		name: test_hkdf_sha3_256_basic,
		setup: || {
			let ikm = b"input_key_material";
			let info = b"test_info";

			// Test different key sizes
			let key_16 = hkdf::<HkdfSha3_256, 16>(ikm, info, None).unwrap();
			let key_32 = hkdf::<HkdfSha3_256, 32>(ikm, info, None).unwrap();
			let key_64 = hkdf::<HkdfSha3_256, 64>(ikm, info, None).unwrap();

			// Determinism test
			let key_32_again = hkdf::<HkdfSha3_256, 32>(ikm, info, None).unwrap();
			// Different inputs test
			let key_different = hkdf::<HkdfSha3_256, 32>(b"different_ikm", info, None).unwrap();

			(key_16, key_32, key_64, key_32_again, key_different)
		},
		assertions: |(key_16, key_32, key_64, key_32_again, key_different)| {
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
	}

	// Test bounds checking for dual key derivation
	crate::test_case! {
		name: test_ecies_kdf_bounds_checking,
		setup: || {
			// Test maximum allowed key size (64 bytes * 2 = 128 bytes = MAX_HKDF_OUTPUT_SIZE)
			let max_size_result = ecies_kdf_with_size::<HkdfSha3_256, 64>(EPHEMERAL_PUBKEY_33, SHARED_SECRET_32, INFO_V1, None);
			// Test oversized key size that should fail (65 bytes * 2 = 130 bytes > MAX_HKDF_OUTPUT_SIZE)
			let oversized_result = ecies_kdf_with_size::<HkdfSha3_256, 65>(EPHEMERAL_PUBKEY_33, SHARED_SECRET_32, INFO_V1, None);

			(max_size_result, oversized_result)
		},
		assertions: |(max_size_result, oversized_result)| {
			// Maximum allowed size should work
			assert!(max_size_result.is_ok());
			let (k_enc, k_mac) = max_size_result.unwrap();
			assert_key_pair_lengths!(k_enc, k_mac, 64);

			// Oversized key should fail with DerivationFailed
			assert!(oversized_result.is_err());
			assert!(matches!(oversized_result, Err(KdfError::DerivationFailed(_))));

			Ok(())
		}
	}

	// Smoke tests for ANSI X9.63 provider over SHA3-256
	crate::test_case! {
		name: test_x963_ecies_kdf_basic,
		setup: || {
			let key1 = ecies_kdf::<X963Sha3_256>(EPHEMERAL_PUBKEY_33, SHARED_SECRET_32, INFO_V1, None).unwrap();
			let key1_again = ecies_kdf::<X963Sha3_256>(EPHEMERAL_PUBKEY_33, SHARED_SECRET_32, INFO_V1, None).unwrap();
			let key_diff_info = ecies_kdf::<X963Sha3_256>(EPHEMERAL_PUBKEY_33, SHARED_SECRET_32, INFO_V2, None).unwrap();
			// Salt is ignored by X9.63; with vs without salt should be equal
			let key_with_salt = ecies_kdf::<X963Sha3_256>(EPHEMERAL_PUBKEY_33, SHARED_SECRET_32, INFO_V1, Some(SALT)).unwrap();
			(key1, key1_again, key_diff_info, key_with_salt)
		},
		assertions: |(key1, key1_again, key_diff_info, key_with_salt)| {
			assert_key_length(&key1, 32);
			assert_keys_equal(&key1, &key1_again);
			assert_keys_different(&key1, &key_diff_info);
			// Salt should have no effect in X9.63
			assert_keys_equal(&key1, &key_with_salt);
			Ok(())
		}
	}

	crate::test_case! {
		name: test_x963_ecies_kdf_size_variations,
		setup: || {
			let keys_16 = ecies_kdf_with_size::<X963Sha3_256, 16>(EPHEMERAL_PUBKEY_33, SHARED_SECRET_32, INFO_V1, None).unwrap();
			let keys_32 = ecies_kdf_with_size::<X963Sha3_256, 32>(EPHEMERAL_PUBKEY_33, SHARED_SECRET_32, INFO_V1, None).unwrap();
			(keys_16, keys_32)
		},
		assertions: |(keys_16, keys_32)| {
			let (k_enc_16, k_mac_16) = keys_16;
			let (k_enc_32, k_mac_32) = keys_32;
			assert_key_pair_lengths!(k_enc_16, k_mac_16, 16);
			assert_key_pair_lengths!(k_enc_32, k_mac_32, 32);
			assert_keys_different!(k_enc_32, k_mac_32);
			Ok(())
		}
	}
}
