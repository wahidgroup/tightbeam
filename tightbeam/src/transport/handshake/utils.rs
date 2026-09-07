//! Utility functions for handshake operations.
//!
//! Provides common cryptographic and state management utilities used across
//! handshake builders, processors, and orchestrators.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(all(not(feature = "std"), feature = "transport-ecies"))]
use alloc::vec::Vec;

use crate::spki::AlgorithmIdentifierOwned;

#[cfg(any(
	feature = "transport-ecies",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
use crate::asn1::OctetString;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::x509::utils::CertificateExt;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::error::HandshakeError;
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
// Orchestrator utilities
// ============================================================================

/// Enforce a single expected handshake state. A mismatch yields `InvalidState`.
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
/// Fixed 32-byte view of an ECIES wire nonce.
/// Wrong length fails closed.
/// 32-byte transcript digest under digest algorithm `D`.
///
/// Wider digests (e.g. SHA3-512) truncate to the leading 32 bytes.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
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

/// Fixed-width views of a DER `OctetString`.
#[cfg(any(
	feature = "transport-ecies",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
pub trait HandshakeOctets {
	/// Fixed 32-byte view of an ECIES wire nonce.
	///
	/// # Errors
	///
	/// - [`HandshakeError::OctetStringLengthError`] on any other length,
	///   so a short or long nonce fails closed
	fn to_32_byte_array(&self) -> Result<[u8; 32], HandshakeError>;
}

#[cfg(any(
	feature = "transport-ecies",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
impl HandshakeOctets for OctetString {
	fn to_32_byte_array(&self) -> Result<[u8; 32], HandshakeError> {
		let bytes = self.as_bytes();
		if bytes.len() != 32 {
			return Err(HandshakeError::OctetStringLengthError((bytes.len(), 32).into()));
		}

		let mut out = [0u8; 32];
		out.copy_from_slice(bytes);
		Ok(out)
	}
}

/// Public-key extraction from a certificate.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub trait HandshakeVerifyingKey {
	/// Public key parsed from this certificate's SPKI, on curve `C`.
	///
	/// # Errors
	///
	/// - SEC1 decode failures over the certificate's key bytes
	fn verifying_key<C>(&self) -> Result<PublicKey<C>, HandshakeError>
	where
		C: Curve + CurveArithmetic,
		<C as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>;
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl HandshakeVerifyingKey for Certificate {
	fn verifying_key<C>(&self) -> Result<PublicKey<C>, HandshakeError>
	where
		C: Curve + CurveArithmetic,
		<C as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
	{
		let pubkey_bytes = self.verifying_key_bytes();
		Ok(PublicKey::<C>::from_sec1_bytes(pubkey_bytes)?)
	}
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
