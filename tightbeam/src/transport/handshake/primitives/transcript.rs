//! Transcript hashing for handshake protocols.
//!
//! The module computes cryptographic hashes over handshake message
//! sequences, which protects transcript integrity.

#[cfg(all(
	not(feature = "std"),
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use alloc::vec::Vec;

#[cfg(feature = "transport-cms")]
use crate::constants::{TIGHTBEAM_CLIENT_FINISHED_DOMAIN, TIGHTBEAM_SERVER_FINISHED_DOMAIN};

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
/// digest retain full 256-bit collision resistance (CWE-1240).
fn digest_output_to_array(bytes: impl AsRef<[u8]>) -> Result<[u8; TRANSCRIPT_HASH_LEN], HandshakeError> {
	let bytes = bytes.as_ref();
	if bytes.len() < TRANSCRIPT_HASH_LEN {
		return Err(HandshakeError::TranscriptDigestLength { expected: TRANSCRIPT_HASH_LEN, received: bytes.len() });
	}

	let mut out = [0u8; TRANSCRIPT_HASH_LEN];
	out.copy_from_slice(&bytes[..TRANSCRIPT_HASH_LEN]);
	Ok(out)
}

/// Compute a transcript hash over a sequence of messages.
///
/// The function hashes `messages` in chronological order with the digest
/// algorithm of the provider and returns the 32-byte transcript hash.
///
/// # Errors
///
/// - `TranscriptDigestLength` -- the provider digest produces fewer than 32 bytes.
pub fn transcript_hash<P: CryptoProvider>(messages: &[&[u8]]) -> Result<[u8; TRANSCRIPT_HASH_LEN], HandshakeError> {
	let mut hasher = P::Digest::default();
	for message in messages {
		hasher.update(message);
	}

	digest_output_to_array(hasher.finalize())
}

/// The bytes a handshake binds, and then their hash once sealed.
///
/// Only an open transcript accepts bytes, so nothing reaches the transcript
/// after both Finished messages fixed their hash. The state stays private, so
/// a hash exists only where [`Transcript::seal`] computed it.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) struct Transcript(State);

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
enum State {
	/// The messages exchanged so far, in the order both endpoints hash them.
	Open(Vec<u8>),
	/// The transcript hash both Finished messages sign. `Transcript::hash`
	/// reads it back for the CMS Finished exchange.
	#[cfg_attr(not(feature = "transport-cms"), allow(dead_code))]
	Sealed([u8; TRANSCRIPT_HASH_LEN]),
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl Transcript {
	/// Compute the 32-byte transcript digest under digest algorithm `D`.
	///
	/// A wider digest, such as SHA3-512, truncates to its leading 32 bytes.
	pub(crate) fn digest<D: Digest>(bytes: impl AsRef<[u8]>) -> Result<[u8; TRANSCRIPT_HASH_LEN], HandshakeError> {
		let bytes = bytes.as_ref();
		digest_output_to_array(D::digest(bytes))
	}

	/// Open the ECIES handshake transcript over its ordered legs.
	///
	/// Both roles derive this identically. A divergence here is a protocol
	/// break, so the concatenation order lives in one place. The hash binds the
	/// client hello, the server random, the server SPKI, and both accept
	/// encodings (CWE-347).
	///
	/// # Parameters
	///
	/// - `client_hello`: the DER of the client hello message.
	/// - `server_random`: the 32-byte server random.
	/// - `spki`: the DER of the server SubjectPublicKeyInfo.
	/// - `security_accept_der`: the DER of the handshake accept.
	/// - `transport_accept_der`: the DER of the transport accept.
	#[cfg(feature = "transport-ecies")]
	pub(crate) fn ecies_handshake(
		client_hello: impl AsRef<[u8]>,
		server_random: &[u8; 32],
		spki: impl AsRef<[u8]>,
		security_accept_der: impl AsRef<[u8]>,
		transport_accept_der: impl AsRef<[u8]>,
	) -> Self {
		let client_hello = client_hello.as_ref();
		let spki = spki.as_ref();
		let security_accept_der = security_accept_der.as_ref();
		let transport_accept_der = transport_accept_der.as_ref();
		let len = client_hello.len() + 32 + spki.len() + security_accept_der.len() + transport_accept_der.len();

		let mut buffer = Vec::with_capacity(len);
		buffer.extend_from_slice(client_hello);
		buffer.extend_from_slice(server_random);
		buffer.extend_from_slice(spki);
		buffer.extend_from_slice(security_accept_der);
		buffer.extend_from_slice(transport_accept_der);
		Self(State::Open(buffer))
	}

	/// Open the ECIES client mutual-auth transcript.
	///
	/// The digest binds the transcript hash, the ECIES-encrypted key exchange
	/// payload, and the client certificate into a single value that the client
	/// signs. A valid client signature therefore cannot be spliced onto a
	/// different key exchange or a different identity (CWE-347).
	///
	/// # Parameters
	///
	/// - `transcript_hash`: the 32-byte handshake transcript hash.
	/// - `encrypted_data`: the ECIES-encrypted key exchange bytes.
	/// - `client_cert_der`: the DER encoding of the client certificate.
	#[cfg(feature = "transport-ecies")]
	pub(crate) fn ecies_client_auth(
		transcript_hash: &[u8; 32],
		encrypted_data: impl AsRef<[u8]>,
		client_cert_der: impl AsRef<[u8]>,
	) -> Self {
		let encrypted_data = encrypted_data.as_ref();
		let client_cert_der = client_cert_der.as_ref();

		let mut buffer = Vec::with_capacity(32 + encrypted_data.len() + client_cert_der.len());
		buffer.extend_from_slice(transcript_hash);
		buffer.extend_from_slice(encrypted_data);
		buffer.extend_from_slice(client_cert_der);
		Self(State::Open(buffer))
	}

	/// Create an open transcript that holds no bytes.
	#[cfg(feature = "transport-cms")]
	pub(crate) const fn new() -> Self {
		Self(State::Open(Vec::new()))
	}

	/// Append the next message to an open transcript.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the transcript is sealed.
	#[cfg(feature = "transport-cms")]
	pub(crate) fn append(&mut self, bytes: impl AsRef<[u8]>) -> Result<(), HandshakeError> {
		match &mut self.0 {
			State::Open(buffer) => {
				buffer.extend_from_slice(bytes.as_ref());
				Ok(())
			}
			State::Sealed(_) => Err(HandshakeError::InvalidState),
		}
	}

	/// Fix the hash over the bytes appended so far under digest `D`, and
	/// return it.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the transcript is already sealed.
	/// - [`HandshakeError::TranscriptDigestLength`] -- `D` produces fewer than 32 bytes.
	pub(crate) fn seal<D: Digest>(&mut self) -> Result<[u8; TRANSCRIPT_HASH_LEN], HandshakeError> {
		let State::Open(buffer) = &self.0 else {
			return Err(HandshakeError::InvalidState);
		};

		let hash = Self::digest::<D>(buffer)?;
		self.0 = State::Sealed(hash);
		Ok(hash)
	}

	/// Return the sealed transcript hash.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidTranscriptHash`] -- the transcript is still open.
	#[cfg(feature = "transport-cms")]
	pub(crate) fn hash(&self) -> Result<[u8; TRANSCRIPT_HASH_LEN], HandshakeError> {
		match &self.0 {
			State::Sealed(hash) => Ok(*hash),
			State::Open(_) => Err(HandshakeError::InvalidTranscriptHash),
		}
	}
}

/// The endpoint that signed a CMS Finished.
///
/// Both Finished messages sign the same transcript hash, so the signed content
/// names its role ahead of the hash. A Finished one endpoint signed then cannot
/// verify as the other endpoint's, and a peer cannot reflect a Finished back.
#[cfg(feature = "transport-cms")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FinishedRole {
	/// The server Finished, signed with the server certificate's key.
	Server,
	/// The client Finished, signed with the client's key.
	Client,
}

#[cfg(feature = "transport-cms")]
impl FinishedRole {
	/// Return the domain label this role signs ahead of the transcript hash.
	const fn domain(self) -> &'static [u8] {
		match self {
			Self::Server => TIGHTBEAM_SERVER_FINISHED_DOMAIN,
			Self::Client => TIGHTBEAM_CLIENT_FINISHED_DOMAIN,
		}
	}

	/// Build the content a Finished of this role signs, which is the role's
	/// domain label followed by the transcript hash.
	pub(crate) fn content(self, transcript_hash: &[u8; TRANSCRIPT_HASH_LEN]) -> Vec<u8> {
		[self.domain(), transcript_hash.as_slice()].concat()
	}

	/// Read the transcript hash that a Finished of this role signed.
	///
	/// Content that names another role, or carries a hash of another length,
	/// yields `None`.
	pub(crate) fn transcript_hash(self, content: &[u8]) -> Option<[u8; TRANSCRIPT_HASH_LEN]> {
		let hash = content.strip_prefix(self.domain())?;
		hash.try_into().ok()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::profiles::DefaultCryptoProvider;

	#[cfg(feature = "transport-cms")]
	use crate::crypto::hash::Sha3_256;

	#[cfg(feature = "transport-cms")]
	#[test]
	fn a_sealed_transcript_refuses_more_bytes() -> Result<(), HandshakeError> {
		let mut transcript = Transcript::new();
		transcript.append(b"key exchange")?;

		let sealed = transcript.seal::<Sha3_256>()?;
		let refusal = transcript.append(b"server finished");
		assert!(matches!(refusal, Err(HandshakeError::InvalidState)));
		assert_eq!(transcript.hash()?, sealed);
		Ok(())
	}

	#[cfg(feature = "transport-cms")]
	#[test]
	fn an_open_transcript_has_no_hash() {
		let transcript = Transcript::new();
		assert!(matches!(transcript.hash(), Err(HandshakeError::InvalidTranscriptHash)));
	}

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

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[test]
	fn test_transcript_digest_widths() -> Result<(), HandshakeError> {
		use crate::crypto::hash::{Sha3_256, Sha3_512};

		let digest = Transcript::digest::<Sha3_256>(b"transcript")?;
		assert_eq!(digest.len(), 32);

		// Wider digests truncate to their leading 32 bytes (SHA-512/256 style).
		let wide = Transcript::digest::<Sha3_512>(b"transcript")?;
		assert_eq!(wide.as_slice(), &Sha3_512::digest(b"transcript")[..32]);

		Ok(())
	}

	#[test]
	fn test_digest_output_narrow_rejected_wide_truncated() -> Result<(), HandshakeError> {
		let narrow = [0u8; 28];
		assert!(matches!(
			digest_output_to_array(narrow),
			Err(HandshakeError::TranscriptDigestLength { expected: 32, received: 28 })
		));

		let mut wide = [0u8; 64];
		for (i, byte) in wide.iter_mut().enumerate() {
			*byte = i as u8;
		}

		let truncated = digest_output_to_array(wide)?;
		assert_eq!(truncated, wide[..32]);
		Ok(())
	}
}
