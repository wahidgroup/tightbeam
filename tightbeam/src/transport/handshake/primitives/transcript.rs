//! Transcript hashing utilities for handshake protocols.
//!
//! Provides functions for computing cryptographic hashes over handshake
//! message sequences, ensuring transcript integrity.

use crate::crypto::hash::Digest;
use crate::crypto::profiles::CryptoProvider;
use crate::transport::handshake::error::HandshakeError;

/// Width of a transcript hash in bytes.
pub const TRANSCRIPT_HASH_LEN: usize = 32;

/// Convert a digest output into the fixed transcript-hash array.
///
/// Digests wider than [`TRANSCRIPT_HASH_LEN`] are *deliberately* truncated to
/// their leading 32 bytes, following the NIST SHA-512/256 construction: the
/// wire format carries exactly 32 bytes and the leading bytes of a wider
/// digest retain full 256-bit collision resistance. Digests narrower than 32
/// bytes cannot fill the array and are rejected (CWE-1240; the previous
/// unchecked slice panicked here).
pub(crate) fn digest_output_to_array(bytes: &[u8]) -> Result<[u8; TRANSCRIPT_HASH_LEN], HandshakeError> {
	if bytes.len() < TRANSCRIPT_HASH_LEN {
		return Err(HandshakeError::TranscriptDigestLength { expected: TRANSCRIPT_HASH_LEN, received: bytes.len() });
	}
	let mut out = [0u8; TRANSCRIPT_HASH_LEN];
	out.copy_from_slice(&bytes[..TRANSCRIPT_HASH_LEN]);
	Ok(out)
}

/// Compute a transcript hash over a sequence of messages.
///
/// Hashes all messages in order using the provider's digest algorithm.
///
/// # Parameters
/// - `messages`: Array of message slices in chronological order
///
/// # Returns
/// 32-byte transcript hash
///
/// # Errors
/// - `TranscriptDigestLength`: The provider digest produces fewer than 32 bytes
pub fn transcript_hash<P: CryptoProvider>(messages: &[&[u8]]) -> Result<[u8; TRANSCRIPT_HASH_LEN], HandshakeError> {
	let mut hasher = P::Digest::default();
	for message in messages {
		hasher.update(message);
	}

	digest_output_to_array(&hasher.finalize())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::profiles::DefaultCryptoProvider;

	#[test]
	fn test_transcript_hash_single_message() -> Result<(), HandshakeError> {
		let msg = b"Hello, World!";
		let hash = transcript_hash::<DefaultCryptoProvider>(&[msg])?;
		assert_eq!(hash.len(), 32);
		Ok(())
	}

	#[test]
	fn test_transcript_hash_multiple_messages() -> Result<(), HandshakeError> {
		let msg1 = b"Message 1";
		let msg2 = b"Message 2";
		let msg3 = b"Message 3";

		let hash = transcript_hash::<DefaultCryptoProvider>(&[msg1, msg2, msg3])?;
		assert_eq!(hash.len(), 32);
		Ok(())
	}

	#[test]
	fn test_transcript_hash_deterministic() -> Result<(), HandshakeError> {
		let msg1 = b"Test";
		let msg2 = b"Data";

		let hash1 = transcript_hash::<DefaultCryptoProvider>(&[msg1, msg2])?;
		let hash2 = transcript_hash::<DefaultCryptoProvider>(&[msg1, msg2])?;
		assert_eq!(hash1, hash2);
		Ok(())
	}

	#[test]
	fn test_transcript_hash_order_matters() -> Result<(), HandshakeError> {
		let msg1 = b"First";
		let msg2 = b"Second";

		let hash_forward = transcript_hash::<DefaultCryptoProvider>(&[msg1, msg2])?;
		let hash_reverse = transcript_hash::<DefaultCryptoProvider>(&[msg2, msg1])?;
		assert_ne!(hash_forward, hash_reverse);
		Ok(())
	}

	#[test]
	fn test_digest_output_narrow_rejected_wide_truncated() -> Result<(), HandshakeError> {
		let narrow = [0u8; 28];
		assert!(matches!(
			digest_output_to_array(&narrow),
			Err(HandshakeError::TranscriptDigestLength { expected: 32, received: 28 })
		));

		let mut wide = [0u8; 64];
		for (i, byte) in wide.iter_mut().enumerate() {
			*byte = i as u8;
		}

		let truncated = digest_output_to_array(&wide)?;
		assert_eq!(truncated, wide[..32]);
		Ok(())
	}
}
