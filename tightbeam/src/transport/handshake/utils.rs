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
mod transport {
	#[cfg(any(
		feature = "transport-ecies",
		all(feature = "transport-multiplex", feature = "transport-cms")
	))]
	pub use crate::asn1::OctetString;
	pub use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
	pub use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
	pub use crate::transport::handshake::error::HandshakeError;
	pub use crate::x509::Certificate;
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use transport::*;

/// AES-256-GCM algorithm identifier.
///
/// OID: 2.16.840.1.101.3.4.1.46 (aes256-GCM)
pub fn aes_256_gcm_algorithm() -> AlgorithmIdentifierOwned {
	use crate::oids::AES_256_GCM;
	AlgorithmIdentifierOwned { oid: AES_256_GCM, parameters: None }
}

// ============================================================================
// Orchestrator utilities
// ============================================================================

/// Enforce a single expected handshake state; mismatch yields `InvalidState`.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
#[inline]
pub fn validate_state<S: PartialEq>(current: S, expected: S) -> Result<(), HandshakeError> {
	if current != expected {
		Err(HandshakeError::InvalidState)
	} else {
		Ok(())
	}
}

/// Parse the certificate SPKI into a curve `PublicKey` for
/// signature verification.
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

/// Fixed 32-byte view of an ECIES wire nonce.
/// Wrong length fails closed.
#[cfg(any(
	feature = "transport-ecies",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
pub fn octet_string_to_32_byte_array(octet_string: &OctetString) -> Result<[u8; 32], HandshakeError> {
	let bytes = octet_string.as_bytes();
	if bytes.len() != 32 {
		return Err(HandshakeError::OctetStringLengthError((bytes.len(), 32).into()));
	}

	let mut out = [0u8; 32];
	out.copy_from_slice(bytes);
	Ok(out)
}

/// 32-byte transcript digest under digest algorithm `D`.
///
/// Wider digests (e.g. SHA3-512) truncate to the leading 32 bytes.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub fn compute_transcript_digest<D>(data: &[u8]) -> Result<[u8; 32], HandshakeError>
where
	D: crate::crypto::hash::Digest,
{
	use crate::transport::handshake::primitives::transcript::digest_output_to_array;

	digest_output_to_array(&D::digest(data))
}

/// Compute the ECIES handshake transcript hash from its ordered legs.
///
/// Both roles derive this identically. A divergence here is a protocol break,
/// so the concatenation order lives in one place. Binds the client hello,
/// server random, server SPKI, and both accept encodings (CWE-347).
///
/// # Type Parameters
/// - `D`: The digest algorithm (e.g., `Sha3_256`)
///
/// # Parameters
/// - `client_hello`: DER of the client hello message
/// - `server_random`: The 32-byte server random
/// - `spki_bytes`: DER of the server SubjectPublicKeyInfo
/// - `accept_der`: DER of the handshake accept
/// - `transport_accept_der`: DER of the transport accept
///
/// # Errors
/// - `TranscriptDigestLength`: `D` produces fewer than 32 bytes
#[cfg(feature = "transport-ecies")]
pub fn compute_ecies_transcript_hash<D>(
	client_hello: &[u8],
	server_random: &[u8; 32],
	spki_bytes: &[u8],
	accept_der: &[u8],
	transport_accept_der: &[u8],
) -> Result<[u8; 32], HandshakeError>
where
	D: crate::crypto::hash::Digest,
{
	let mut data =
		Vec::with_capacity(client_hello.len() + 32 + spki_bytes.len() + accept_der.len() + transport_accept_der.len());
	data.extend_from_slice(client_hello);
	data.extend_from_slice(server_random);
	data.extend_from_slice(spki_bytes);
	data.extend_from_slice(accept_der);
	data.extend_from_slice(transport_accept_der);

	compute_transcript_digest::<D>(&data)
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

/// Erase ephemeral ECIES key material after session establishment (CWE-226).
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
