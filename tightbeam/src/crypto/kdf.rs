//! Key Derivation Functions (KDF)
//!
//! This module provides cryptographic key derivation functions following
//! industry standards like RFC 5869 (HKDF) and NIST SP 800-56C.

pub use hkdf::Hkdf;

use crate::crypto::hash::Sha3_256;
use crate::zeroize::Zeroizing;

pub type SafeSpace<const N: usize> = Zeroizing<[u8; N]>;
pub type UnboundSafeSpace = Zeroizing<Vec<u8>>;

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

/// A specialized Result type for KDF operations
pub type Result<T> = core::result::Result<T, KdfError>;

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
		if !salt_bytes.is_empty() && salt_bytes.len() < 16 {
			return Err(KdfError::InvalidSaltLength(salt_bytes.len()));
		}
	}

	Ok(())
}

/// ECIES Key Derivation Function using SHA3-256
///
/// Derives a 32-byte encryption key from an ephemeral public key and
/// shared secret using HKDF with SHA3-256 as the hash function.
///
/// This function implements the ECIES key derivation as specified in
/// IEEE P1363a §15.6.1, which includes the ephemeral public key (C0) in the
/// key derivation material to provide non-malleability and resistance to
/// adaptive chosen ciphertext attacks.
///
/// Note: This function derives only an encryption key (k_enc) since we use
/// AES-256-GCM for authenticated encryption, which provides both confidentiality
/// and authentication without requiring a separate MAC key.
///
/// # Security Properties
///
/// - **Non-malleable**: Including C0 prevents attackers from modifying the ephemeral key
/// - **CCA-secure**: Provides chosen-ciphertext attack resistance
/// - **Domain separation**: The `info` parameter enables protocol-specific key derivation
/// - **Forward secrecy**: Each ephemeral key produces unique derived keys
/// - **Input validation**: Enforces correct key lengths (33/65 bytes for pubkey, 32 bytes for secret)
/// - **Side-channel resistance**: Uses fixed-size arrays to avoid timing variations from allocations
///
/// # Algorithm
///
/// 1. Validate input lengths (ephemeral_pubkey: 33 or 65 bytes, shared_secret: 32 bytes)
/// 2. Concatenate ephemeral public key and shared secret: `IKM = C0 || S`
/// 3. Apply HKDF-Extract with optional salt: `PRK = HKDF-Extract(salt, IKM)`
/// 4. Apply HKDF-Expand to derive 32 bytes: `k_enc = HKDF-Expand(PRK, info, 32)`
///
/// # Parameters
///
/// - `ephemeral_pubkey`: The ephemeral public key (C0) from ECIES encryption.
///   Must be 33 bytes (compressed) or 65 bytes (uncompressed) for secp256k1.
/// - `shared_secret`: The ECDH shared secret (S = r·P or d·R).
///   Must be exactly 32 bytes for 256-bit curves.
/// - `info`: Application-specific context and domain separation string.
/// - `salt`: Optional salt for HKDF-Extract. Provides additional randomness
///   for enhanced security. Use `None` for standard ECIES (salt-free).
///
/// # Returns
///
/// A 32-byte encryption key wrapped in `Zeroizing` for automatic memory clearing.
/// This key is suitable for AES-256-GCM authenticated encryption.
///
/// # Errors
///
/// - [`KdfError::InvalidPublicKeyLength`] if ephemeral_pubkey is not 33 or 65 bytes
/// - [`KdfError::InvalidSharedSecretLength`] if shared_secret is not 32 bytes
/// - [`KdfError::DerivationFailed`] if HKDF expansion fails
///
/// # Standards Compliance
///
/// - **RFC 5869**: HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
/// - **NIST SP 800-56C**: Recommendation for Key-Derivation Methods
/// - **IEEE P1363a**: DHAES mode with C0 inclusion for non-malleability
/// - **FIPS 202**: SHA3-256 cryptographic hash function
pub fn ecies_kdf_sha256(
	ephemeral_pubkey: impl AsRef<[u8]>,
	shared_secret: impl AsRef<[u8]>,
	info: impl AsRef<[u8]>,
	salt: Option<&[u8]>,
) -> Result<SafeSpace<32>> {
	let ephemeral_pubkey = ephemeral_pubkey.as_ref();
	let shared_secret = shared_secret.as_ref();
	let info = info.as_ref();

	// Validate all inputs
	assert_valid_kdf_inputs(ephemeral_pubkey, shared_secret, salt)?;

	// Use fixed-size array for IKM to avoid dynamic allocation and potential timing variations
	// Maximum size: 65 (uncompressed pubkey) + 32 (shared secret) = 97 bytes
	let ikm_len = ephemeral_pubkey.len() + shared_secret.len();
	let mut ikm = Zeroizing::new([0u8; 97]);
	ikm[..ephemeral_pubkey.len()].copy_from_slice(ephemeral_pubkey);
	ikm[ephemeral_pubkey.len()..ikm_len].copy_from_slice(shared_secret);

	// HKDF-Extract with optional salt
	let hk = Hkdf::<Sha3_256>::new(salt, &ikm[..ikm_len]);
	let mut okm = Zeroizing::new([0u8; 32]);
	hk.expand(info, &mut okm[..]).map_err(KdfError::DerivationFailed)?;
	Ok(okm)
}

/// ECIES Key Derivation Function using SHA3-256 with configurable key size
///
/// This is the generic version of [`ecies_kdf_sha256`] that allows specifying
/// custom key sizes. For the common case of 32-byte keys (AES-256-GCM), use
/// [`ecies_kdf_sha256`] instead.
///
/// # Type Parameters
///
/// - `N`: The size in bytes for each derived key. Must be at least 16 bytes.
///   Common values:
///   - `16`: AES-128-GCM
///   - `32`: AES-256-GCM (use [`ecies_kdf_sha256`] for this)
pub fn ecies_kdf_sha256_with_size<const N: usize>(
	ephemeral_pubkey: impl AsRef<[u8]>,
	shared_secret: impl AsRef<[u8]>,
	info: impl AsRef<[u8]>,
	salt: Option<&[u8]>,
) -> Result<(SafeSpace<N>, SafeSpace<N>)> {
	// Enforce minimum key size for security
	const { assert!(N >= 16, "Key size must be at least 16 bytes for security") };

	// Extract references
	let ephemeral_pubkey = ephemeral_pubkey.as_ref();
	let shared_secret = shared_secret.as_ref();
	let info = info.as_ref();

	// Validate all inputs
	assert_valid_kdf_inputs(ephemeral_pubkey, shared_secret, salt)?;

	// Use fixed-size array for IKM to avoid dynamic allocation and potential timing variations
	// Maximum size: 65 (uncompressed pubkey) + 32 (shared secret) = 97 bytes
	let ikm_len = ephemeral_pubkey.len() + shared_secret.len();
	let mut ikm = Zeroizing::new([0u8; 97]);
	ikm[..ephemeral_pubkey.len()].copy_from_slice(ephemeral_pubkey);
	ikm[ephemeral_pubkey.len()..ikm_len].copy_from_slice(shared_secret);

	// HKDF-Extract with optional salt
	let hk = Hkdf::<Sha3_256>::new(salt, &ikm[..ikm_len]);

	// HKDF-Expand: derive 2*N bytes total (N bytes for encryption key + N bytes for MAC key)
	// Maximum size: 2 * 64 bytes = 128 bytes (for N <= 64)
	let mut okm = Zeroizing::new([0u8; 128]);
	hk.expand(info, &mut okm[..N * 2]).map_err(KdfError::DerivationFailed)?;

	// Split into two N-byte keys
	let mut k_enc = Zeroizing::new([0u8; N]);
	let mut k_mac = Zeroizing::new([0u8; N]);
	k_enc[..].copy_from_slice(&okm[..N]);
	k_mac[..].copy_from_slice(&okm[N..N * 2]);

	Ok((k_enc, k_mac))
}

#[cfg(test)]
mod tests {
	use super::*;

	// Test data constants
	const EPHEMERAL_PUBKEY_33: &[u8] = b"ephemeral_public_key_33_bytes____";
	const EPHEMERAL_PUBKEY_33_ALT: &[u8] = b"different_ephemeral_key_33_bytes_";
	const SHARED_SECRET_32: &[u8] = b"shared_secret_32_bytes__________";
	const INFO_V1: &[u8] = b"tightbeam-ecies-v1";
	const INFO_V2: &[u8] = b"protocol-v2";
	const SALT: &[u8] = b"random_salt_value";

	#[test]
	fn test_ecies_kdf_sha256_all_cases() {
		enum TestCase {
			// Valid test cases
			Valid {
				name: &'static str,
				ephemeral: &'static [u8],
				secret: &'static [u8],
				info: &'static [u8],
				salt: Option<&'static [u8]>,
				key_size: usize,
				// Optional comparison with another call
				compare_with: Option<Box<TestCase>>,
				should_match: bool,
			},
			// Invalid input test cases
			Invalid {
				name: &'static str,
				ephemeral: &'static [u8],
				secret: &'static [u8],
				expected_error: fn(&KdfError) -> bool,
			},
		}

		let test_cases = vec![
			// Basic properties tests
			TestCase::Valid {
				name: "standard 32-byte keys (compressed pubkey)",
				ephemeral: EPHEMERAL_PUBKEY_33,
				secret: SHARED_SECRET_32,
				info: INFO_V1,
				salt: None,
				key_size: 32,
				compare_with: None,
				should_match: false,
			},
			TestCase::Valid {
				name: "determinism check",
				ephemeral: EPHEMERAL_PUBKEY_33,
				secret: SHARED_SECRET_32,
				info: INFO_V1,
				salt: None,
				key_size: 32,
				compare_with: Some(Box::new(TestCase::Valid {
					name: "same inputs",
					ephemeral: EPHEMERAL_PUBKEY_33,
					secret: SHARED_SECRET_32,
					info: INFO_V1,
					salt: None,
					key_size: 32,
					compare_with: None,
					should_match: false,
				})),
				should_match: true,
			},
			// Input variation tests
			TestCase::Valid {
				name: "different ephemeral pubkey",
				ephemeral: EPHEMERAL_PUBKEY_33,
				secret: SHARED_SECRET_32,
				info: INFO_V1,
				salt: None,
				key_size: 32,
				compare_with: Some(Box::new(TestCase::Valid {
					name: "alt ephemeral",
					ephemeral: EPHEMERAL_PUBKEY_33_ALT,
					secret: SHARED_SECRET_32,
					info: INFO_V1,
					salt: None,
					key_size: 32,
					compare_with: None,
					should_match: false,
				})),
				should_match: false,
			},
			TestCase::Valid {
				name: "different info",
				ephemeral: EPHEMERAL_PUBKEY_33,
				secret: SHARED_SECRET_32,
				info: INFO_V1,
				salt: None,
				key_size: 32,
				compare_with: Some(Box::new(TestCase::Valid {
					name: "alt info",
					ephemeral: EPHEMERAL_PUBKEY_33,
					secret: SHARED_SECRET_32,
					info: INFO_V2,
					salt: None,
					key_size: 32,
					compare_with: None,
					should_match: false,
				})),
				should_match: false,
			},
			TestCase::Valid {
				name: "with salt vs without",
				ephemeral: EPHEMERAL_PUBKEY_33,
				secret: SHARED_SECRET_32,
				info: INFO_V1,
				salt: None,
				key_size: 32,
				compare_with: Some(Box::new(TestCase::Valid {
					name: "with salt",
					ephemeral: EPHEMERAL_PUBKEY_33,
					secret: SHARED_SECRET_32,
					info: INFO_V1,
					salt: Some(SALT),
					key_size: 32,
					compare_with: None,
					should_match: false,
				})),
				should_match: false,
			},
			// Different key sizes
			TestCase::Valid {
				name: "16-byte keys (AES-128)",
				ephemeral: EPHEMERAL_PUBKEY_33,
				secret: SHARED_SECRET_32,
				info: INFO_V1,
				salt: None,
				key_size: 16,
				compare_with: None,
				should_match: false,
			},
			TestCase::Valid {
				name: "64-byte keys (high security)",
				ephemeral: EPHEMERAL_PUBKEY_33,
				secret: SHARED_SECRET_32,
				info: INFO_V1,
				salt: None,
				key_size: 64,
				compare_with: None,
				should_match: false,
			},
			// Invalid inputs
			TestCase::Invalid {
				name: "ephemeral pubkey too short",
				ephemeral: b"too_short",
				secret: SHARED_SECRET_32,
				expected_error: |e| matches!(e, KdfError::InvalidPublicKeyLength(9)),
			},
			TestCase::Invalid {
				name: "ephemeral pubkey wrong size (34 bytes)",
				ephemeral: b"wrong_size_ephemeral_key_34_bytes_",
				secret: SHARED_SECRET_32,
				expected_error: |e| matches!(e, KdfError::InvalidPublicKeyLength(34)),
			},
			TestCase::Invalid {
				name: "shared secret too short",
				ephemeral: EPHEMERAL_PUBKEY_33,
				secret: b"too_short",
				expected_error: |e| matches!(e, KdfError::InvalidSharedSecretLength(9)),
			},
			TestCase::Invalid {
				name: "shared secret too long",
				ephemeral: EPHEMERAL_PUBKEY_33,
				secret: b"shared_secret_that_is_too_long____",
				expected_error: |e| matches!(e, KdfError::InvalidSharedSecretLength(34)),
			},
		];

		// Helper function to derive keys for a test case
		fn derive_keys(tc: &TestCase) -> Result<(UnboundSafeSpace, UnboundSafeSpace)> {
			match tc {
				TestCase::Valid { ephemeral, secret, info, salt, key_size, .. } => {
					macro_rules! derive_with_size {
						($size:expr) => {{
							let (k_enc, k_mac) = ecies_kdf_sha256_with_size::<$size>(ephemeral, secret, info, *salt)?;
							Ok((Zeroizing::new(k_enc.to_vec()), Zeroizing::new(k_mac.to_vec())))
						}};
					}

					match *key_size {
						16 => derive_with_size!(16),
						32 => derive_with_size!(32),
						64 => derive_with_size!(64),
						size => panic!("Unsupported key size: {size}"),
					}
				}
				TestCase::Invalid { .. } => {
					panic!("Cannot derive keys for invalid test case")
				}
			}
		}

		// Execute test cases
		for tc in &test_cases {
			match tc {
				TestCase::Valid { name, key_size, compare_with, should_match, .. } => {
					// Derive keys for this test case
					let result = derive_keys(tc);
					if let Err(e) = &result {
						panic!("{name}: {e:?}");
					}

					let (k_enc, k_mac) = result.unwrap();
					// Check basic properties
					assert_eq!(k_enc.len(), *key_size, "{name}");
					assert_eq!(k_mac.len(), *key_size, "{name}");
					assert_ne!(&k_enc[..], &k_mac[..], "{name}");

					// If there's a comparison case, test against it
					if let Some(ref compare_tc) = compare_with {
						let compare_result = derive_keys(compare_tc);
						if let Err(e) = &compare_result {
							panic!("{name} (comparison): {e:?}");
						}

						let (k_enc_cmp, _) = compare_result.unwrap();
						if *should_match {
							assert_eq!(&k_enc[..], &k_enc_cmp[..], "{name}");
						} else {
							assert_ne!(&k_enc[..], &k_enc_cmp[..], "{name}");
						}
					}
				}
				TestCase::Invalid { name, ephemeral, secret, expected_error } => {
					let result = ecies_kdf_sha256(ephemeral, secret, INFO_V1, None);
					assert!(result.is_err(), "{name}");
					assert!(expected_error(&result.unwrap_err()), "{name}");
				}
			}
		}
	}

	#[test]
	fn test_ecies_kdf_sha256_uncompressed_pubkey() -> Result<()> {
		// Test with 65-byte uncompressed public key (special case)
		let mut ephemeral_pubkey = [0u8; 65];
		ephemeral_pubkey[0] = 0x04; // Uncompressed marker
		for (i, byte) in ephemeral_pubkey.iter_mut().enumerate().skip(1) {
			*byte = (i % 256) as u8;
		}

		let k_enc = ecies_kdf_sha256(ephemeral_pubkey, SHARED_SECRET_32, INFO_V1, None)?;
		assert_eq!(k_enc.len(), 32);

		Ok(())
	}
}
