//! Transcript hashing utilities for handshake protocols.
//!
//! Provides functions for computing cryptographic hashes over handshake
//! message sequences, ensuring transcript integrity.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::crypto::hash::Digest;
use crate::crypto::profiles::CryptoProvider;

/// Compute a transcript hash over a sequence of messages.
///
/// Concatenates all messages and hashes them using the provider's digest algorithm.
/// Returns a 32-byte hash suitable for use in key derivation or signature verification.
///
/// # Parameters
/// - `messages`: Array of message slices in chronological order
///
/// # Returns
/// 32-byte transcript hash
///
/// # Example
/// ```rust,ignore
/// let client_hello = b"ClientHello...";
/// let server_hello = b"ServerHello...";
/// let key_exchange = b"KeyExchange...";
///
/// let hash = transcript_hash::<DefaultCryptoProvider>(&[
///     client_hello,
///     server_hello,
///     key_exchange,
/// ]);
/// ```
pub fn transcript_hash<P: CryptoProvider>(messages: &[&[u8]]) -> [u8; 32] {
	let mut hasher = P::Digest::default();
	for message in messages {
		hasher.update(message);
	}

	let hash_result = hasher.finalize();
	let mut hash_array = [0u8; 32];
	hash_array.copy_from_slice(&hash_result);
	hash_array
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::profiles::DefaultCryptoProvider;

	#[test]
	fn test_transcript_hash_single_message() {
		let msg = b"Hello, World!";
		let hash = transcript_hash::<DefaultCryptoProvider>(&[msg]);
		assert_eq!(hash.len(), 32);
	}

	#[test]
	fn test_transcript_hash_multiple_messages() {
		let msg1 = b"Message 1";
		let msg2 = b"Message 2";
		let msg3 = b"Message 3";

		let hash = transcript_hash::<DefaultCryptoProvider>(&[msg1, msg2, msg3]);
		assert_eq!(hash.len(), 32);
	}

	#[test]
	fn test_transcript_hash_deterministic() {
		let msg1 = b"Test";
		let msg2 = b"Data";

		let hash1 = transcript_hash::<DefaultCryptoProvider>(&[msg1, msg2]);
		let hash2 = transcript_hash::<DefaultCryptoProvider>(&[msg1, msg2]);
		assert_eq!(hash1, hash2);
	}

	#[test]
	fn test_transcript_hash_order_matters() {
		let msg1 = b"First";
		let msg2 = b"Second";

		let hash_forward = transcript_hash::<DefaultCryptoProvider>(&[msg1, msg2]);
		let hash_reverse = transcript_hash::<DefaultCryptoProvider>(&[msg2, msg1]);
		assert_ne!(hash_forward, hash_reverse);
	}
}
