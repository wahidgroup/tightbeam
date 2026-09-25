//! Shared functions for handshake operations.
//!
//! Handshake builders, processors, and orchestrators share these
//! cryptographic and state management helpers.

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

/// Compute the 32-byte transcript digest under digest algorithm `D`.
///
/// A wider digest, such as SHA3-512, truncates to its leading 32 bytes.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub fn compute_transcript_digest<D>(data: impl AsRef<[u8]>) -> Result<[u8; 32], HandshakeError>
where
	D: crate::crypto::hash::Digest,
{
	use crate::transport::handshake::primitives::transcript::digest_output_to_array;

	let data = data.as_ref();
	digest_output_to_array(D::digest(data))
}

/// Compute the ECIES handshake transcript hash from its ordered legs.
///
/// Both roles derive this identically. A divergence here is a protocol break,
/// so the concatenation order lives in one place. The hash binds the client
/// hello, the server random, the server SPKI, and both accept encodings
/// (CWE-347).
///
/// # Type parameters
///
/// - `D`: the digest algorithm, such as `Sha3_256`.
///
/// # Parameters
///
/// - `client_hello`: the DER of the client hello message.
/// - `server_random`: the 32-byte server random.
/// - `spki_bytes`: the DER of the server SubjectPublicKeyInfo.
/// - `accept_der`: the DER of the handshake accept.
/// - `transport_accept_der`: the DER of the transport accept.
///
/// # Errors
///
/// - `TranscriptDigestLength` -- `D` produces fewer than 32 bytes.
#[cfg(feature = "transport-ecies")]
pub fn compute_ecies_transcript_hash<D>(
	client_hello: impl AsRef<[u8]>,
	server_random: &[u8; 32],
	spki_bytes: impl AsRef<[u8]>,
	accept_der: impl AsRef<[u8]>,
	transport_accept_der: impl AsRef<[u8]>,
) -> Result<[u8; 32], HandshakeError>
where
	D: crate::crypto::hash::Digest,
{
	let client_hello = client_hello.as_ref();
	let spki_bytes = spki_bytes.as_ref();
	let accept_der = accept_der.as_ref();
	let transport_accept_der = transport_accept_der.as_ref();

	let len = client_hello.len() + 32 + spki_bytes.len() + accept_der.len() + transport_accept_der.len();
	let mut data = Vec::with_capacity(len);
	data.extend_from_slice(client_hello);
	data.extend_from_slice(server_random);
	data.extend_from_slice(spki_bytes);
	data.extend_from_slice(accept_der);
	data.extend_from_slice(transport_accept_der);

	compute_transcript_digest::<D>(&data)
}

/// Compute the ECIES client mutual-auth digest.
///
/// The digest binds the transcript hash, the ECIES-encrypted key exchange
/// payload, and the client certificate into a single value that the client
/// signs. A valid client signature therefore cannot be spliced onto a
/// different key exchange or a different identity (CWE-347).
///
/// # Type parameters
///
/// - `D`: the digest algorithm, such as `Sha3_256`.
///
/// # Parameters
///
/// - `transcript_hash`: the 32-byte handshake transcript hash.
/// - `encrypted_data`: the ECIES-encrypted key exchange bytes.
/// - `client_cert_der`: the DER encoding of the client certificate.
///
/// # Errors
///
/// - `TranscriptDigestLength` -- `D` produces fewer than 32 bytes.
#[cfg(feature = "transport-ecies")]
pub fn compute_client_auth_digest<D>(
	transcript_hash: &[u8; 32],
	encrypted_data: impl AsRef<[u8]>,
	client_cert_der: impl AsRef<[u8]>,
) -> Result<[u8; 32], HandshakeError>
where
	D: crate::crypto::hash::Digest,
{
	let encrypted_data = encrypted_data.as_ref();
	let client_cert_der = client_cert_der.as_ref();
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
	/// Fixed 32-byte view of an ECIES wire nonce or other public value.
	///
	/// # Errors
	///
	/// - [`HandshakeError::OctetStringLengthError`] on any other length, so a
	///   short or long nonce fails closed
	fn to_32_byte_array(&self) -> Result<[u8; 32], HandshakeError>;

	/// Copy the 32 bytes into `out`, which may be a wiping buffer, so a key
	/// never passes through a plain array on the way.
	///
	/// # Errors
	///
	/// - [`HandshakeError::OctetStringLengthError`] on any other length
	fn copy_to_32_byte_array(&self, out: &mut [u8; 32]) -> Result<(), HandshakeError>;
}

#[cfg(any(
	feature = "transport-ecies",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
impl HandshakeOctets for OctetString {
	fn to_32_byte_array(&self) -> Result<[u8; 32], HandshakeError> {
		let mut out = [0u8; 32];
		self.copy_to_32_byte_array(&mut out)?;
		Ok(out)
	}

	fn copy_to_32_byte_array(&self, out: &mut [u8; 32]) -> Result<(), HandshakeError> {
		let bytes = self.as_bytes();
		if bytes.len() != out.len() {
			return Err(HandshakeError::OctetStringLengthError((bytes.len(), out.len()).into()));
		}

		out.copy_from_slice(bytes);
		Ok(())
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
