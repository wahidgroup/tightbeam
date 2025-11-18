//! Multi-input key derivation functions for hybrid key agreement.
//!
//! Provides composable KDF primitives for protocols that combine multiple
//! shared secrets (e.g., ECDH + KEM in PQXDH).

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::crypto::kdf::KdfFunction;
use crate::crypto::profiles::CryptoProvider;
use crate::transport::handshake::error::HandshakeError;

/// Multi-input HKDF combining multiple secrets with length prefixing.
///
/// Concatenates all input secrets with 4-byte big-endian length prefixes,
/// then derives a 32-byte key using the provider's KDF.
///
/// # Length Prefixing
/// Each input is prefixed with its length as `u32` in big-endian format.
/// This prevents ambiguity in concatenation (e.g., "ab" + "cd" vs "abc" + "d").
///
/// # Parameters
/// - `inputs`: Array of input secret slices to combine
/// - `salt`: Salt bytes for KDF (minimum 16 bytes recommended)
/// - `info`: Application-specific context string
///
/// # Returns
/// 32-byte derived key
///
/// # Example
/// ```rust,ignore
/// let dh_secret = [0x42u8; 32];
/// let kem_secret = [0x99u8; 32];
/// let salt = [0xAAu8; 32];
///
/// let combined = multi_input_kdf::<DefaultCryptoProvider>(
///     &[&dh_secret, &kem_secret],
///     &salt,
///     b"MyApp-PQXDH-v1"
/// )?;
/// ```
pub fn multi_input_kdf<P: CryptoProvider>(
	inputs: &[&[u8]],
	salt: &[u8],
	info: &[u8],
) -> Result<[u8; 32], HandshakeError> {
	// Concatenate all inputs with length prefixes
	let mut combined = Vec::new();
	for input in inputs {
		combined.extend_from_slice(&(input.len() as u32).to_be_bytes());
		combined.extend_from_slice(input);
	}

	// Derive 32-byte key using provider's KDF
	let derived = P::Kdf::derive_dynamic_key(&combined, info, Some(salt), 32)?;

	let mut result = [0u8; 32];
	result.copy_from_slice(&derived);
	Ok(result)
}

/// Chain multiple KDF operations where each output becomes the next salt.
///
/// Implements key derivation chaining as used in protocols like PQXDH:
/// ```text
/// KDF₁(input₁, salt₀, info₁) → output₁
/// KDF₂(input₂, output₁, info₂) → output₂
/// ...
/// ```
///
/// Each stage uses the previous stage's output as salt, creating a
/// dependency chain that incorporates all prior inputs.
///
/// # Parameters
/// - `stages`: Array of (input, info) pairs for each KDF stage
/// - `initial_salt`: Initial salt for first KDF stage
///
/// # Returns
/// Final derived key (32 bytes)
///
/// # Example
/// ```rust,ignore
/// let dh1 = [0x11u8; 32];
/// let dh2 = [0x22u8; 32];
/// let dh3 = [0x33u8; 32];
/// let kem_ss = [0x44u8; 32];
///
/// let final_key = kdf_chain::<DefaultCryptoProvider>(
///     &[
///         (&dh1, b"DH1"),
///         (&dh2, b"DH2"),
///         (&dh3, b"DH3"),
///         (&kem_ss, b"KEM"),
///     ],
///     b"InitialSalt"
/// )?;
/// ```
pub fn kdf_chain<P: CryptoProvider>(stages: &[(&[u8], &[u8])], initial_salt: &[u8]) -> Result<Vec<u8>, HandshakeError> {
	let mut current_salt = initial_salt.to_vec();
	let mut current_key = Vec::new();
	for (input, info) in stages {
		let derived = P::Kdf::derive_dynamic_key(input, info, Some(&current_salt), 32)?;
		current_key = derived.to_vec();
		current_salt = derived.to_vec(); // Next salt is previous output
	}

	Ok(current_key)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::profiles::DefaultCryptoProvider;

	#[test]
	fn test_multi_input_kdf() {
		let input1 = [0x42u8; 32];
		let input2 = [0x99u8; 32];
		let salt = [0xAAu8; 32];

		let result = multi_input_kdf::<DefaultCryptoProvider>(&[&input1, &input2], &salt, b"test-info");
		assert!(result.is_ok());

		let key = result.unwrap();
		assert_eq!(key.len(), 32);
	}

	#[test]
	fn test_multi_input_kdf_different_lengths() {
		let input1 = [0x42u8; 16];
		let input2 = [0x99u8; 48];
		let salt = [0xAAu8; 32];

		let result = multi_input_kdf::<DefaultCryptoProvider>(&[&input1, &input2], &salt, b"test-info");
		assert!(result.is_ok());
	}

	#[test]
	fn test_kdf_chain() {
		let input1 = [0x11u8; 32];
		let input2 = [0x22u8; 32];
		let initial_salt = [0xFFu8; 32];

		let result = kdf_chain::<DefaultCryptoProvider>(&[(&input1, b"stage1"), (&input2, b"stage2")], &initial_salt);
		assert!(result.is_ok());

		let key = result.unwrap();
		assert_eq!(key.len(), 32);
	}

	#[test]
	fn test_kdf_chain_single_stage() {
		let input = [0x42u8; 32];
		let salt = [0xAAu8; 32];

		let result = kdf_chain::<DefaultCryptoProvider>(&[(&input, b"single")], &salt);
		assert!(result.is_ok());
	}
}
