//! Transcript hashing for handshake protocols.
//!
//! The module computes cryptographic hashes over handshake message
//! sequences, which protects transcript integrity.

#[cfg(all(
	not(feature = "std"),
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use alloc::vec::Vec;

#[cfg(feature = "transport-ecies")]
use crate::constants::EC_PUBKEY_COMPRESSED_SIZE;
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
	/// break, so the concatenation order lives in one place. The hash binds
	/// every leg (CWE-347), and the fixed-width ephemeral leg keeps the
	/// variable-length legs beside it in their positions.
	#[cfg(feature = "transport-ecies")]
	pub(crate) fn ecies_handshake(legs: EciesHandshakeLegs<'_>) -> Self {
		let EciesHandshakeLegs {
			client_hello,
			server_random,
			server_ephemeral,
			spki,
			security_accept_der,
			transport_accept_der,
		} = legs;
		let fixed = server_random.len() + server_ephemeral.len();
		let len = client_hello.len() + fixed + spki.len() + security_accept_der.len() + transport_accept_der.len();

		let mut buffer = Vec::with_capacity(len);
		buffer.extend_from_slice(client_hello);
		buffer.extend_from_slice(server_random);
		buffer.extend_from_slice(server_ephemeral);
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

	/// Append the server Finished legs in the order both endpoints bind them.
	///
	/// The server appends the bytes it is about to send and the client the
	/// bytes it received, so the order lives here once and a drift on either
	/// side fails the Finished signature.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the transcript is sealed.
	#[cfg(feature = "transport-cms")]
	pub(crate) fn append_server_finished(&mut self, legs: ServerFinishedLegs) -> Result<(), HandshakeError> {
		let ServerFinishedLegs { security_accept, transport_accept, server_ephemeral } = legs;
		if let Some(accept) = security_accept {
			self.append(accept)?;
		}
		if let Some(accept) = transport_accept {
			self.append(accept)?;
		}

		self.append(server_ephemeral)
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

/// The ECIES handshake legs the transcript binds, in the order both roles
/// hash them. [`Transcript::ecies_handshake`] fixes that order.
#[cfg(feature = "transport-ecies")]
pub(crate) struct EciesHandshakeLegs<'a> {
	/// The DER of the ClientHello as it was sent and received.
	pub(crate) client_hello: &'a [u8],
	/// The 32-byte server random.
	pub(crate) server_random: &'a [u8; 32],
	/// The compressed SEC1 server ephemeral public key.
	pub(crate) server_ephemeral: &'a [u8; EC_PUBKEY_COMPRESSED_SIZE],
	/// The DER of the server SubjectPublicKeyInfo.
	pub(crate) spki: &'a [u8],
	/// The DER of the security accept, empty when the server sent none.
	pub(crate) security_accept_der: &'a [u8],
	/// The DER of the transport accept, empty when the server sent none.
	pub(crate) transport_accept_der: &'a [u8],
}

/// The server Finished attributes the CMS transcript binds, as encoded bytes.
///
/// The accepts are present when negotiation produced them, and the server
/// ephemeral public key is mandatory, so every sealed transcript binds one.
/// [`Transcript::append_server_finished`] fixes the order.
#[cfg(feature = "transport-cms")]
pub(crate) struct ServerFinishedLegs {
	/// The `SecurityAccept` attribute value, when a profile was negotiated.
	pub(crate) security_accept: Option<Vec<u8>>,
	/// The `TransportAccept` attribute value, when transport terms were
	/// negotiated.
	pub(crate) transport_accept: Option<Vec<u8>>,
	/// The `OriginatorPublicKey` attribute value carrying the server
	/// ephemeral.
	pub(crate) server_ephemeral: Vec<u8>,
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

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
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

	/// The CMS transcript hash of a key exchange followed by server Finished
	/// legs that carry `server_ephemeral`.
	#[cfg(feature = "transport-cms")]
	fn cms_hash_with_ephemeral(server_ephemeral: &[u8]) -> Result<[u8; 32], HandshakeError> {
		let mut transcript = Transcript::new();
		transcript.append(b"key exchange")?;
		transcript.append_server_finished(ServerFinishedLegs {
			security_accept: Some(b"accept".to_vec()),
			transport_accept: None,
			server_ephemeral: server_ephemeral.to_vec(),
		})?;
		transcript.seal::<Sha3_256>()
	}

	/// Two CMS transcripts that differ only in the server ephemeral hash
	/// differently, so the Finished signature binds the ephemeral.
	#[cfg(feature = "transport-cms")]
	#[test]
	fn the_cms_transcript_binds_the_server_ephemeral() -> Result<(), HandshakeError> {
		let first = cms_hash_with_ephemeral(&[0x02u8; 33])?;
		let second = cms_hash_with_ephemeral(&[0x03u8; 33])?;
		assert_ne!(first, second);
		Ok(())
	}

	/// The ECIES transcript hash of fixed legs around `server_ephemeral`.
	#[cfg(feature = "transport-ecies")]
	fn ecies_hash_with_ephemeral(server_ephemeral: &[u8; 33]) -> Result<[u8; 32], HandshakeError> {
		let legs = EciesHandshakeLegs {
			client_hello: b"client hello",
			server_random: &[0x01u8; 32],
			server_ephemeral,
			spki: b"spki",
			security_accept_der: b"accept",
			transport_accept_der: b"",
		};

		let mut transcript = Transcript::ecies_handshake(legs);
		transcript.seal::<Sha3_256>()
	}

	/// Two ECIES transcripts that differ only in the server ephemeral hash
	/// differently, so the server signature binds the ephemeral.
	#[cfg(feature = "transport-ecies")]
	#[test]
	fn the_ecies_transcript_binds_the_server_ephemeral() -> Result<(), HandshakeError> {
		let first = ecies_hash_with_ephemeral(&[0x02u8; 33])?;
		let second = ecies_hash_with_ephemeral(&[0x03u8; 33])?;
		assert_ne!(first, second);
		Ok(())
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
