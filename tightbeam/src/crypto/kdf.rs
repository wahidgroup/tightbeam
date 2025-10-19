//! Key Derivation Functions (KDF)
//!
//! This module provides cryptographic key derivation functions following
//! industry standards like RFC 5869 (HKDF) and NIST SP 800-56C.

pub use hkdf::Hkdf;

use crate::zeroize::Zeroizing;

/// Errors specific to KDF operations
#[cfg_attr(feature = "derive", derive(crate::Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfError {
	/// Key derivation failed
	#[cfg_attr(feature = "derive", error("Key derivation failed"))]
	DerivationFailed,
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for KdfError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			KdfError::DerivationFailed => write!(f, "Key derivation failed"),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for KdfError {}

/// A specialized Result type for KDF operations
pub type Result<T> = core::result::Result<T, KdfError>;

/// HKDF-based key derivation function with configurable hash function and output size
///
/// Derives key material using HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
/// as specified in RFC 5869. The output is split into two equal-sized keys.
///
/// # Standards Compliance
///
/// - **RFC 5869**: HKDF specification
/// - **NIST SP 800-56C**: Recommendation for Key-Derivation Methods
/// - **IEEE P1363a**: Standard for public-key cryptography (DHAES mode)
///
/// # Security Properties
///
/// - Derives uniformly random keys from non-uniform inputs
/// - Provides domain separation via `info` parameter
/// - Supports protocol versioning and context binding
/// - No salt required (uses None) for most applications
///
/// # Type Parameters
///
/// * `D` - Hash function implementing `Digest` trait (SHA2-256, SHA3-256, BLAKE2, etc.)
/// * `N` - Output size in bytes per key (total output is 2*N bytes)
///
/// # Arguments
///
/// * `input_key_material` - High-entropy input (e.g., shared secret, ephemeral key)
/// * `info` - Optional context/domain separation info (protocol version, purpose, etc.)
///
/// # Returns
///
/// Two N-byte keys derived from the input material:
/// - First key: Typically used for encryption
/// - Second key: Typically used for authentication/MAC
///
/// # Examples
///
/// ```ignore
/// use sha3::Sha3_256;
///
/// // Derive 32-byte keys for AES-256-GCM
/// let (k_enc, k_mac) = hkdf_derive::<Sha3_256, 32>(
///     shared_secret,
///     b"myprotocol-v1"
/// )?;
///
/// // Derive 16-byte keys for AES-128-GCM
/// let (k_enc, k_mac) = hkdf_derive::<Sha256, 16>(
///     shared_secret,
///     b"myprotocol-v1"
/// )?;
/// ```
pub fn hkdf_derive<D, const N: usize>(
	input_key_material: impl AsRef<[u8]>,
	info: impl AsRef<[u8]>,
) -> Result<(Zeroizing<[u8; N]>, Zeroizing<[u8; N]>)>
where
	D: OutputSizeUser,
{
	// Ensure N is valid
	const { assert!(N > 0, "Output size must be greater than 0") };

	let ikm = input_key_material.as_ref();
	let info = info.as_ref();

	// HKDF Extract + Expand
	let hk = Hkdf::<D>::new(None, ikm);

	// HKDF can expand to any length regardless of hash output size.
	// We derive 2*N bytes total to split into two N-byte keys
	let mut okm = Zeroizing::new(vec![0u8; N * 2]);
	hk.expand(info, &mut okm[..]).map_err(|_| KdfError::DerivationFailed)?;

	// Split into two keys (both N bytes)
	let mut key1 = Zeroizing::new([0u8; N]);
	let mut key2 = Zeroizing::new([0u8; N]);
	key1[..].copy_from_slice(&okm[..N]);
	key2[..].copy_from_slice(&okm[N..N * 2]);

	Ok((key1, key2))
}

/// ECIES-specific KDF following IEEE P1363a "DHAES mode"
///
/// This is a specialized KDF for Elliptic Curve Integrated Encryption Scheme (ECIES)
/// that includes the ephemeral public key (C0) in the key derivation for non-malleability.
///
/// # Standards Compliance
///
/// Following IEEE P1363a "DHAES mode" and ECIES security considerations (§15.6.1):
/// - Includes C0 (ephemeral public key) for non-malleability
/// - Includes shared secret from ECDH
/// - Uses HKDF without salt (standard ECIES practice)
///
/// # Security Benefits
///
/// Including C0 in the KDF:
/// 1. **Non-malleability**: Prevents adaptive chosen ciphertext attacks
/// 2. **Tighter security reduction**: Reduces from qKDF·qD to qKDF DDH oracle calls
/// 3. **Protocol binding**: Binds keys to specific ephemeral keypair
///
/// # Type Parameters
///
/// * `D` - Hash function implementing `Digest` trait
/// * `N` - Output size in bytes per key
///
/// # Arguments
///
/// * `ephemeral_pubkey` - Ephemeral public key bytes (C0)
/// * `shared_secret` - ECDH shared secret bytes
/// * `info` - Context/domain separation info for protocol versioning
///
/// # Returns
///
/// Two N-byte keys:
/// - First key: Encryption key
/// - Second key: MAC key
pub fn ecies_kdf<D, const N: usize>(
	ephemeral_pubkey: impl AsRef<[u8]>,
	shared_secret: impl AsRef<[u8]>,
	info: impl AsRef<[u8]>,
) -> Result<(Zeroizing<[u8; N]>, Zeroizing<[u8; N]>)>
where
	D: OutputSizeUser,
{
	// Ensure N is valid
	const { assert!(N > 0, "Output size must be greater than 0") };

	let ephemeral_pubkey = ephemeral_pubkey.as_ref();
	let shared_secret = shared_secret.as_ref();
	let info = info.as_ref();

	// Concatenate C0 || shared_secret as input key material (IKM)
	// This is critical for non-malleability per IEEE P1363a
	let mut ikm = Zeroizing::new(Vec::with_capacity(ephemeral_pubkey.len() + shared_secret.len()));
	ikm.extend_from_slice(ephemeral_pubkey);
	ikm.extend_from_slice(shared_secret);

	let hk = Hkdf::<D>::new(None, &ikm);

	// HKDF can expand to any length regardless of hash output size.
	// We derive 2*N bytes total to split into two N-byte keys
	let mut okm = Zeroizing::new(vec![0u8; N * 2]);
	hk.expand(info, &mut okm[..]).map_err(|_| KdfError::DerivationFailed)?;

	// Split into encryption key and MAC key (both N bytes)
	let mut k_enc = Zeroizing::new([0u8; N]);
	let mut k_mac = Zeroizing::new([0u8; N]);
	k_enc[..].copy_from_slice(&okm[..N]);
	k_mac[..].copy_from_slice(&okm[N..N * 2]);

	Ok((k_enc, k_mac))
}

#[cfg(test)]
mod tests {
	use super::*;
	use sha3::Sha3_256;

	#[test]
	fn test_hkdf_derive_32() -> Result<()> {
		let ikm = b"test input key material";
		let info = b"test-protocol-v1";

		let (k1, k2) = hkdf_derive::<Sha3_256, 32>(ikm, info)?;

		// Keys should be different
		assert_ne!(&k1[..], &k2[..]);

		// Keys should be deterministic
		let (k1_2, k2_2) = hkdf_derive::<Sha3_256, 32>(ikm, info)?;
		assert_eq!(&k1[..], &k1_2[..]);
		assert_eq!(&k2[..], &k2_2[..]);

		Ok(())
	}

	#[test]
	fn test_hkdf_derive_16() -> Result<()> {
		let ikm = b"test input key material";
		let info = b"test-protocol-v1";

		let (k1, k2) = hkdf_derive::<Sha3_256, 16>(ikm, info)?;

		assert_ne!(&k1[..], &k2[..]);
		assert_eq!(k1.len(), 16);
		assert_eq!(k2.len(), 16);

		Ok(())
	}

	#[test]
	fn test_ecies_kdf() -> Result<()> {
		let ephemeral_pubkey = b"ephemeral_public_key_33_bytes___";
		let shared_secret = b"shared_secret_32_bytes_______";
		let info = b"tightbeam-ecies-v1";

		let (k_enc, k_mac) = ecies_kdf::<Sha3_256, 32>(ephemeral_pubkey, shared_secret, info)?;

		// Keys should be different
		assert_ne!(&k_enc[..], &k_mac[..]);

		// Keys should be deterministic
		let (k_enc2, k_mac2) = ecies_kdf::<Sha3_256, 32>(ephemeral_pubkey, shared_secret, info)?;
		assert_eq!(&k_enc[..], &k_enc2[..]);
		assert_eq!(&k_mac[..], &k_mac2[..]);

		// Different ephemeral key should produce different keys
		let different_eph = b"different_ephemeral_key_33_bytes";
		let (k_enc3, _) = ecies_kdf::<Sha3_256, 32>(different_eph, shared_secret, info)?;
		assert_ne!(&k_enc[..], &k_enc3[..]);

		Ok(())
	}

	#[test]
	fn test_info_parameter_changes_output() -> Result<()> {
		let ikm = b"test input";
		let info1 = b"protocol-v1";
		let info2 = b"protocol-v2";

		let (k1_v1, _) = hkdf_derive::<Sha3_256, 32>(ikm, info1)?;
		let (k1_v2, _) = hkdf_derive::<Sha3_256, 32>(ikm, info2)?;

		// Different info should produce different keys
		assert_ne!(&k1_v1[..], &k1_v2[..]);

		Ok(())
	}
}
