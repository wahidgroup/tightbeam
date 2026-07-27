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
use crate::zeroize::Zeroizing;
use crate::ZeroizingBytes;

/// Multi-input HKDF: length-prefixed concatenation of secrets, then provider KDF.
///
/// Each input is prefixed with its length as big-endian `u32`, preventing
/// concatenation ambiguity (e.g. "ab"+"cd" vs "abc"+"d").
pub fn multi_input_kdf<P: CryptoProvider>(
	inputs: &[&[u8]],
	salt: &[u8],
	info: &[u8],
	key_size: usize,
) -> Result<ZeroizingBytes, HandshakeError> {
	// Concatenate all inputs with length prefixes. The buffer holds secret
	// material, so it is zeroized on drop.
	let mut combined = Zeroizing::new(Vec::new());
	for input in inputs {
		let len = u32::try_from(input.len()).map_err(|_| HandshakeError::IntegerOutOfRange)?;
		combined.extend_from_slice(&len.to_be_bytes());
		combined.extend_from_slice(input);
	}

	Ok(P::Kdf::derive_dynamic_key(&combined, info, Some(salt), key_size)?)
}

/// Chained KDF: each stage's output becomes the next stage's salt (PQXDH-style).
pub fn kdf_chain<P: CryptoProvider>(
	stages: &[(&[u8], &[u8])],
	initial_salt: &[u8],
) -> Result<ZeroizingBytes, HandshakeError> {
	if stages.is_empty() {
		return Ok(Zeroizing::new(Vec::new()));
	}

	// Each intermediate output is key material. Keep every stage in a
	// Zeroizing buffer so nothing lingers in the allocator.
	let mut current = Zeroizing::new(initial_salt.to_vec());
	for (input, info) in stages {
		current = P::Kdf::derive_dynamic_key(input, info, Some(&current), 32)?;
	}

	Ok(current)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::profiles::DefaultCryptoProvider;

	#[test]
	fn test_multi_input_kdf() -> Result<(), Box<dyn core::error::Error>> {
		let input1 = [0x42u8; 32];
		let input2 = [0x99u8; 32];
		let salt = [0xAAu8; 32];

		let result = multi_input_kdf::<DefaultCryptoProvider>(&[&input1, &input2], &salt, b"test-info", 32);
		assert!(result.is_ok());

		let key = result?;
		assert_eq!(key.len(), 32);

		Ok(())
	}

	#[test]
	fn test_multi_input_kdf_different_lengths() {
		let input1 = [0x42u8; 16];
		let input2 = [0x99u8; 48];
		let salt = [0xAAu8; 32];

		let result = multi_input_kdf::<DefaultCryptoProvider>(&[&input1, &input2], &salt, b"test-info", 32);
		assert!(result.is_ok());
	}

	#[test]
	fn test_kdf_chain() -> Result<(), Box<dyn core::error::Error>> {
		let input1 = [0x11u8; 32];
		let input2 = [0x22u8; 32];
		let initial_salt = [0xFFu8; 32];

		let result = kdf_chain::<DefaultCryptoProvider>(&[(&input1, b"stage1"), (&input2, b"stage2")], &initial_salt);
		assert!(result.is_ok());

		let key = result?;
		assert_eq!(key.len(), 32);

		Ok(())
	}

	#[test]
	fn test_kdf_chain_single_stage() {
		let input = [0x42u8; 32];
		let salt = [0xAAu8; 32];

		let result = kdf_chain::<DefaultCryptoProvider>(&[(&input, b"single")], &salt);
		assert!(result.is_ok());
	}
}
