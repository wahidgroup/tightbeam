//! Utility functions for handshake operations.
//!
//! Provides common cryptographic and state management utilities used across
//! handshake builders, processors, and orchestrators.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(all(not(feature = "std"), feature = "transport-ecies"))]
use alloc::vec::Vec;

use crate::spki::AlgorithmIdentifierOwned;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::error::HandshakeError;

#[cfg(feature = "transport-ecies")]
use crate::asn1::OctetString;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::x509::Certificate;

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
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
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
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
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
#[cfg(feature = "transport-ecies")]
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
/// 32-byte digest array. Wider digests (e.g. SHA3-512) are truncated to their
/// leading 32 bytes (SHA-512/256 style; retains 256-bit collision resistance).
///
/// # Errors
/// - `TranscriptDigestLength`: `D` produces fewer than 32 bytes
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub fn compute_transcript_digest<D>(data: &[u8]) -> Result<[u8; 32], HandshakeError>
where
	D: crate::crypto::hash::Digest,
{
	use crate::transport::handshake::primitives::transcript::digest_output_to_array;

	digest_output_to_array(&D::digest(data))
}

/// Compute the ECIES client mutual-auth digest.
///
/// Binds the transcript hash, the ECIES-encrypted key exchange payload, and
/// the client certificate into a single digest that the client signs. This
/// prevents splicing a valid client signature onto a different key exchange
/// or a different identity (CWE-347).
///
/// # Type Parameters
/// - `D`: The digest algorithm (e.g., `Sha3_256`)
///
/// # Parameters
/// - `transcript_hash`: The 32-byte handshake transcript hash
/// - `encrypted_data`: The ECIES-encrypted key exchange bytes
/// - `client_cert_der`: DER encoding of the client certificate
///
/// # Errors
/// - `TranscriptDigestLength`: `D` produces fewer than 32 bytes
#[cfg(feature = "transport-ecies")]
pub fn compute_client_auth_digest<D>(
	transcript_hash: &[u8; 32],
	encrypted_data: &[u8],
	client_cert_der: &[u8],
) -> Result<[u8; 32], HandshakeError>
where
	D: crate::crypto::hash::Digest,
{
	let mut data = Vec::with_capacity(32 + encrypted_data.len() + client_cert_der.len());
	data.extend_from_slice(transcript_hash);
	data.extend_from_slice(encrypted_data);
	data.extend_from_slice(client_cert_der);

	compute_transcript_digest::<D>(&data)
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
/// Zeroizes each array in place (the `Option<Z>` impl clears the payload
/// before setting `None`), so the original stack slots are overwritten
/// rather than a moved copy (CWE-226).
#[cfg(feature = "transport-ecies")]
pub fn clear_session_randoms(
	base_session_key: &mut Option<[u8; 32]>,
	client_random: &mut Option<[u8; 32]>,
	server_random: &mut Option<[u8; 32]>,
) {
	use crate::zeroize::Zeroize;

	base_session_key.zeroize();
	client_random.zeroize();
	server_random.zeroize();
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[test]
	fn test_compute_transcript_digest_widths() -> Result<(), HandshakeError> {
		use crate::crypto::hash::{Digest, Sha3_256, Sha3_512};

		let digest = compute_transcript_digest::<Sha3_256>(b"transcript")?;
		assert_eq!(digest.len(), 32);

		// Wider digests truncate to their leading 32 bytes (SHA-512/256 style).
		let wide = compute_transcript_digest::<Sha3_512>(b"transcript")?;
		assert_eq!(wide.as_slice(), &Sha3_512::digest(b"transcript")[..32]);

		Ok(())
	}
}
