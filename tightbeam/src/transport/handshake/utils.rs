//! Utility functions for handshake operations.
//!
//! Provides common cryptographic and state management utilities used across
//! handshake builders, processors, and orchestrators.

use crate::asn1::OctetString;
use crate::crypto::secret::Secret;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
use crate::transport::handshake::error::HandshakeError;
use crate::x509::Certificate;
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
	use crate::oids::AES_256_GCM;
	AlgorithmIdentifierOwned { oid: AES_256_GCM, parameters: None }
}

// ============================================================================
// Orchestrator Utilities (State, Certificates, Data Conversion)
// ============================================================================

/// Validate that the current state matches the expected state.
///
/// This is a generic state validation utility used across all handshake
/// orchestrators to enforce state machine transitions.
///
/// # Parameters
/// - `current`: The current state value
/// - `expected`: The expected state value
///
/// # Returns
/// - `Ok(())` if states match
/// - `Err(HandshakeError::InvalidState)` if states don't match
#[inline]
pub fn validate_state<S: PartialEq>(current: S, expected: S) -> Result<(), HandshakeError> {
	if current != expected {
		Err(HandshakeError::InvalidState)
	} else {
		Ok(())
	}
}

/// Extract a verifying public key from an X.509 certificate.
///
/// Extracts the subject public key from the certificate's SPKI and parses it
/// into a curve-specific `PublicKey`. Used for signature verification in both
/// ECIES and CMS handshakes.
///
/// # Type Parameters
/// - `C`: The elliptic curve type (e.g., `k256::Secp256k1`)
///
/// # Parameters
/// - `cert`: The X.509 certificate containing the public key
///
/// # Returns
/// Parsed public key ready for cryptographic operations
///
/// # Errors
/// - `HandshakeError`: If key extraction or parsing fails
pub fn extract_verifying_key_from_cert<C>(cert: &Certificate) -> Result<PublicKey<C>, HandshakeError>
where
	C: Curve + CurveArithmetic,
	<C as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
	let pubkey_bytes = crate::crypto::x509::utils::extract_verifying_key_bytes(cert);
	Ok(PublicKey::<C>::from_sec1_bytes(pubkey_bytes)?)
}

/// Convert an ASN.1 OctetString to a fixed 32-byte array.
///
/// Used in ECIES handshakes to convert random nonces from wire format
/// (OctetString) to internal format ([u8; 32]).
///
/// # Parameters
/// - `octet_string`: The ASN.1 OctetString to convert
///
/// # Returns
/// Fixed-size 32-byte array
///
/// # Errors
/// - `HandshakeError::OctetStringLengthError` if length is not exactly 32 bytes
pub fn octet_string_to_32_byte_array(octet_string: &OctetString) -> Result<[u8; 32], HandshakeError> {
	let bytes = octet_string.as_bytes();
	if bytes.len() != 32 {
		return Err(HandshakeError::OctetStringLengthError((bytes.len(), 32).into()));
	}
	let mut out = [0u8; 32];
	out.copy_from_slice(bytes);
	Ok(out)
}

/// Compute a 32-byte transcript digest from arbitrary data.
///
/// Generic digest computation utility used by both ECIES and CMS handshakes.
/// The digest algorithm is parameterized via the type parameter `D`.
///
/// # Type Parameters
/// - `D`: The digest algorithm (e.g., `Sha3_256`)
///
/// # Parameters
/// - `data`: The data to hash
///
/// # Returns
/// 32-byte digest array
///
/// # Note
/// This function assumes the digest algorithm produces at least 32 bytes.
/// It will truncate to 32 bytes if the digest is longer.
pub fn compute_transcript_digest<D>(data: &[u8]) -> [u8; 32]
where
	D: crate::crypto::hash::Digest,
{
	let digest_arr = D::digest(data);
	let mut digest = [0u8; 32];
	digest.copy_from_slice(&digest_arr[..32]);
	digest
}

/// Clear sensitive session data by zeroizing and dropping.
///
/// Used in ECIES handshakes to securely erase ephemeral key material
/// after session establishment. Zeroizes all provided optional values.
///
/// # Parameters
/// - `base_session_key`: Optional base session key to clear
/// - `client_random`: Optional client random to clear
/// - `server_random`: Optional server random to clear
///
/// # Security
/// This function ensures sensitive data is overwritten before deallocation,
/// preventing potential memory scraping attacks.
pub fn clear_session_randoms(
	base_session_key: &mut Option<[u8; 32]>,
	client_random: &mut Option<[u8; 32]>,
	server_random: &mut Option<[u8; 32]>,
) {
	if let Some(mut bk) = base_session_key.take() {
		bk.fill(0);
	}
	if let Some(mut cr) = client_random.take() {
		cr.fill(0);
	}
	if let Some(mut sr) = server_random.take() {
		sr.fill(0);
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
	fn test_cek_generation() -> Result<(), Box<dyn std::error::Error>> {
		let cek1 = generate_cek()?;
		let cek2 = generate_cek()?;

		// Verify both CEKs are 32 bytes by accessing them via Secret.with()
		cek1.with(|bytes| assert_eq!(bytes.len(), 32))?;
		cek2.with(|bytes| assert_eq!(bytes.len(), 32))?;

		// Verify they're different (probabilistically)
		let bytes1 = cek1.with(|b| *b)?;
		let bytes2 = cek2.with(|b| *b)?;
		assert_ne!(bytes1, bytes2);

		Ok(())
	}
}
