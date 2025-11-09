//! Utility functions for handshake operations.
//!
//! Provides common cryptographic utilities used across handshake builders and processors.

use crate::crypto::secret::Secret;
use crate::transport::handshake::error::HandshakeError;
use spki::AlgorithmIdentifierOwned;

/// Generate a random 32-byte CEK for AES-256-GCM.
///
/// Returns the CEK wrapped in `Secret<[u8; 32]>` for automatic zeroization.
pub fn generate_cek() -> Result<Secret<[u8; 32]>, HandshakeError> {
	use rand_core::RngCore;
	let mut cek = [0u8; 32];
	rand_core::OsRng.fill_bytes(&mut cek);
	Ok(Secret::from(Box::new(cek)))
}

/// AES-256-GCM encryption function.
///
/// # Parameters
/// - `key`: 32-byte AES-256 key
/// - `plaintext`: Data to encrypt
/// - `aad`: Optional additional authenticated data
///
/// # Returns
/// Concatenated: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, HandshakeError> {
	use aes_gcm::aead::{Aead, Payload};
	use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
	use rand_core::RngCore;

	if key.len() != 32 {
		return Err(HandshakeError::InvalidKeySize { expected: 32, received: key.len() });
	}

	let cipher = Aes256Gcm::new_from_slice(key)?;

	// Generate random 12-byte nonce
	let mut nonce_bytes = [0u8; 12];
	rand_core::OsRng.fill_bytes(&mut nonce_bytes);
	let nonce = Nonce::from_slice(&nonce_bytes);

	// Encrypt
	let ciphertext = cipher.encrypt(nonce, Payload { msg: plaintext, aad: aad.unwrap_or(&[]) })?;

	// Preallocate exact required capacity: nonce (12) + ciphertext+tag
	let mut result = Vec::with_capacity(12 + ciphertext.len());
	result.extend_from_slice(&nonce_bytes);
	result.extend_from_slice(&ciphertext);

	Ok(result)
}

/// AES-256-GCM decryption function.
///
/// # Parameters
/// - `key`: 32-byte AES-256 key
/// - `ciphertext`: Encrypted data (nonce || ciphertext || tag)
/// - `aad`: Optional additional authenticated data
///
/// # Returns
/// Decrypted plaintext
pub fn aes_gcm_decrypt(key: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, HandshakeError> {
	use aes_gcm::aead::{Aead, Payload};
	use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

	if key.len() != 32 {
		return Err(HandshakeError::InvalidKeySize { expected: 32, received: key.len() });
	}

	if ciphertext.len() < 12 + 16 {
		// Need at least nonce (12) + tag (16)
		return Err(HandshakeError::InvalidKeySize {
			expected: 28, // minimum size
			received: ciphertext.len(),
		});
	}

	let cipher = Aes256Gcm::new_from_slice(key)?;

	// Extract nonce and ciphertext
	let nonce = Nonce::from_slice(&ciphertext[..12]);
	let ct = &ciphertext[12..];

	// Decrypt
	let plaintext = cipher.decrypt(nonce, Payload { msg: ct, aad: aad.unwrap_or(&[]) })?;
	Ok(plaintext)
}

/// AES-256-GCM algorithm identifier.
///
/// OID: 2.16.840.1.101.3.4.1.46 (aes256-GCM)
pub fn aes_256_gcm_algorithm() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned {
		oid: der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.46"),
		parameters: None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_aes_gcm_roundtrip() -> Result<(), HandshakeError> {
		let key = [0x42u8; 32];
		let plaintext = b"Hello, World!";
		let aad = Some(b"additional data".as_slice());

		let ciphertext = aes_gcm_encrypt(&key, plaintext, aad)?;
		let decrypted = aes_gcm_decrypt(&key, &ciphertext, aad)?;
		assert_eq!(plaintext, decrypted.as_slice());
		Ok(())
	}

	#[test]
	fn test_aes_gcm_wrong_key() -> Result<(), HandshakeError> {
		let key = [0x42u8; 32];
		let wrong_key = [0x43u8; 32];
		let plaintext = b"Secret message";

		let ciphertext = aes_gcm_encrypt(&key, plaintext, None)?;
		let result = aes_gcm_decrypt(&wrong_key, &ciphertext, None);
		assert!(result.is_err());
		Ok(())
	}

	#[test]
	fn test_aes_gcm_wrong_aad() -> Result<(), HandshakeError> {
		let key = [0x42u8; 32];
		let plaintext = b"Authenticated data";
		let aad = Some(b"correct aad".as_slice());
		let wrong_aad = Some(b"wrong aad".as_slice());

		let ciphertext = aes_gcm_encrypt(&key, plaintext, aad)?;
		let result = aes_gcm_decrypt(&key, &ciphertext, wrong_aad);
		assert!(result.is_err());
		Ok(())
	}

	#[test]
	fn test_cek_generation() -> Result<(), HandshakeError> {
		let cek1 = generate_cek()?;
		let cek2 = generate_cek()?;

		// Verify both CEKs are 32 bytes by accessing them via Secret.with()
		cek1.with(|bytes| assert_eq!(bytes.len(), 32));
		cek2.with(|bytes| assert_eq!(bytes.len(), 32));

		// Verify they're different (probabilistically)
		let bytes1 = cek1.with(|b| *b);
		let bytes2 = cek2.with(|b| *b);
		assert_ne!(bytes1, bytes2);

		Ok(())
	}
}
