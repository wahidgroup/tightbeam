//! Transcript hashing for handshake protocols.
//!
//! The module computes cryptographic hashes over handshake message
//! sequences, which protects transcript integrity.

use core::fmt;

#[cfg(all(not(feature = "std"), any(feature = "transport-cms", feature = "transport-hpke")))]
use alloc::vec::Vec;

use digest::Output;

use crate::crypto::hash::Digest;
use crate::crypto::profiles::CryptoProvider;
use crate::der::asn1::ObjectIdentifier;
use crate::der::oid::AssociatedOid;
use crate::transport::handshake::error::HandshakeError;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::asn1::DigestInfo;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::der::asn1::OctetString;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::spki::AlgorithmIdentifierOwned;

#[cfg(feature = "transport-hpke")]
use crate::constants::{
	EC_PUBKEY_COMPRESSED_SIZE, TIGHTBEAM_HPKE_CLIENT_AUTH_DOMAIN, TIGHTBEAM_HPKE_SERVER_AUTH_DOMAIN,
};
#[cfg(feature = "transport-cms")]
use crate::constants::{TIGHTBEAM_CLIENT_FINISHED_DOMAIN, TIGHTBEAM_SERVER_FINISHED_DOMAIN};

/// The width of the narrowest digest output the handshake runs, in bytes, as
/// a 256-bit digest such as SHA3-256 gives.
const MIN_DIGEST_OUTPUT_LEN: usize = 32;

/// The width of the widest digest output the handshake runs, in bytes, as a
/// 512-bit digest such as SHA3-512 gives.
const MAX_DIGEST_OUTPUT_LEN: usize = 64;

/// A byte string as wide as the output of a digest the handshake runs, from 32
/// to 64 bytes.
///
/// [`Self::parse`] is the one width rule. A transcript hash and a
/// key-confirmation tag each hold one.
#[derive(Clone, Copy)]
pub(crate) struct DigestOutput {
	bytes: [u8; MAX_DIGEST_OUTPUT_LEN],
	len: usize,
}

impl DigestOutput {
	/// The digest output `output`, whole.
	///
	/// # Errors
	///
	/// - [`HandshakeError::TranscriptDigestLength`] -- `output` is not 32 to 64 bytes wide.
	pub(crate) fn parse(output: impl AsRef<[u8]>) -> Result<Self, HandshakeError> {
		let output = output.as_ref();
		let received = output.len();
		if !(MIN_DIGEST_OUTPUT_LEN..=MAX_DIGEST_OUTPUT_LEN).contains(&received) {
			let (min, max) = (MIN_DIGEST_OUTPUT_LEN, MAX_DIGEST_OUTPUT_LEN);
			return Err(HandshakeError::TranscriptDigestLength { min, max, received });
		}

		let mut bytes = [0u8; MAX_DIGEST_OUTPUT_LEN];
		bytes[..received].copy_from_slice(output);
		Ok(Self { bytes, len: received })
	}

	/// The output bytes.
	pub(crate) fn as_bytes(&self) -> &[u8] {
		&self.bytes[..self.len]
	}
}

/// Two outputs are equal when their bytes are, whatever the buffer holds past
/// them.
impl PartialEq for DigestOutput {
	fn eq(&self, other: &Self) -> bool {
		self.as_bytes() == other.as_bytes()
	}
}

impl Eq for DigestOutput {}

/// Debug output prints the output bytes alone.
impl fmt::Debug for DigestOutput {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("DigestOutput").field(&self.as_bytes()).finish()
	}
}

/// The hash of a handshake transcript: the whole output of the digest that
/// computed it, beside the identifier of that digest.
///
/// A transcript sealed under SHA3-256 holds 32 bytes, and one sealed under
/// SHA3-512 holds 64. The output of a digest narrower than 32 bytes or wider
/// than 64 is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranscriptHash {
	algorithm: ObjectIdentifier,
	output: DigestOutput,
}

impl TranscriptHash {
	/// The transcript hash that is the output `output` of digest `D`, whole.
	///
	/// The output is typed by `D`, so its bytes and the identifier the hash
	/// names come from one digest.
	///
	/// # Errors
	///
	/// - [`HandshakeError::TranscriptDigestLength`] -- `output` is not 32 to 64 bytes wide.
	pub(crate) fn from_output<D: Digest + AssociatedOid>(output: Output<D>) -> Result<Self, HandshakeError> {
		let output = DigestOutput::parse(output)?;
		Ok(Self { algorithm: D::OID, output })
	}

	/// The hash bytes, as wide as the digest output.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		self.output.as_bytes()
	}

	/// The hash as the `DigestInfo` a session receipt carries: the identifier
	/// of its digest with absent parameters, and the whole output.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DerError`] -- the output fails to encode as an OCTET STRING.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn digest_info(&self) -> Result<DigestInfo, HandshakeError> {
		let algorithm = AlgorithmIdentifierOwned { oid: self.algorithm, parameters: None };
		let digest = OctetString::new(self.as_bytes())?;
		Ok(DigestInfo { algorithm, digest })
	}
}

impl AsRef<[u8]> for TranscriptHash {
	fn as_ref(&self) -> &[u8] {
		self.as_bytes()
	}
}

/// Compute a transcript hash over a sequence of messages.
///
/// The function hashes `messages` in chronological order with the digest
/// algorithm of the provider and returns the whole digest output.
///
/// # Errors
///
/// - [`HandshakeError::TranscriptDigestLength`] -- the provider digest is not 32 to 64 bytes wide.
pub fn transcript_hash<P: CryptoProvider>(messages: &[&[u8]]) -> Result<TranscriptHash, HandshakeError> {
	let mut hasher = P::Digest::default();
	for message in messages {
		hasher.update(message);
	}

	TranscriptHash::from_output::<P::Digest>(hasher.finalize())
}

/// The bytes a handshake binds, until their hash is sealed.
///
/// Only an open transcript accepts bytes, so nothing reaches the transcript
/// after its hash is fixed. The state stays private, so a hash exists only
/// where [`Transcript::seal`] computed it.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) struct Transcript(State);

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
enum State {
	/// The messages exchanged so far, in the order both endpoints hash them.
	Open(Vec<u8>),
	/// The hash is fixed, and [`Transcript::seal`] returned it.
	Sealed,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl Transcript {
	/// Compute the transcript digest of `bytes` under digest algorithm `D`.
	///
	/// The hash is the whole digest output, so SHA3-512 gives 64 bytes.
	pub(crate) fn digest<D: Digest + AssociatedOid>(bytes: impl AsRef<[u8]>) -> Result<TranscriptHash, HandshakeError> {
		let bytes = bytes.as_ref();
		TranscriptHash::from_output::<D>(D::digest(bytes))
	}

	/// Open the HPKE handshake transcript over its ordered legs.
	///
	/// Both roles derive this identically. A divergence here is a protocol
	/// break, so the concatenation order lives in one place. The hash binds
	/// every leg (CWE-347), and the fixed-width ephemeral leg keeps the
	/// variable-length legs beside it in their positions.
	#[cfg(feature = "transport-hpke")]
	pub(crate) fn hpke_handshake(legs: HpkeHandshakeLegs<'_>) -> Self {
		let HpkeHandshakeLegs {
			client_hello,
			server_random,
			server_ephemeral,
			server_public_key,
			security_accept_der,
			client_cert_required,
			transport_accept_der,
		} = legs;
		let demand = [u8::from(client_cert_required)];
		let fixed = server_random.len() + server_ephemeral.len() + demand.len();
		let accepts = security_accept_der.len() + transport_accept_der.len();
		let len = client_hello.len() + fixed + server_public_key.len() + accepts;

		let mut buffer = Vec::with_capacity(len);
		buffer.extend_from_slice(client_hello);
		buffer.extend_from_slice(server_random);
		buffer.extend_from_slice(server_ephemeral);
		buffer.extend_from_slice(server_public_key);
		buffer.extend_from_slice(security_accept_der);
		buffer.extend_from_slice(&demand);
		buffer.extend_from_slice(transport_accept_der);
		Self(State::Open(buffer))
	}

	/// Open the HPKE client mutual-auth transcript.
	///
	/// The digest binds a domain label, the transcript hash, the client
	/// ephemeral, and the client certificate into the one value the client
	/// signs. The signature therefore binds to this handshake, this agreement,
	/// and this identity, and replays to no other server (CWE-347).
	///
	/// # Parameters
	///
	/// - `transcript_hash`: the handshake transcript hash.
	/// - `client_ephemeral`: the compressed SEC1 client ephemeral `R`.
	/// - `client_cert_der`: the DER encoding of the client certificate.
	#[cfg(feature = "transport-hpke")]
	pub(crate) fn hpke_client_auth(
		transcript_hash: &TranscriptHash,
		client_ephemeral: &[u8; EC_PUBKEY_COMPRESSED_SIZE],
		client_cert_der: impl AsRef<[u8]>,
	) -> Self {
		let client_cert_der = client_cert_der.as_ref();
		let transcript_hash = transcript_hash.as_bytes();
		let fixed = TIGHTBEAM_HPKE_CLIENT_AUTH_DOMAIN.len() + transcript_hash.len() + client_ephemeral.len();

		let mut buffer = Vec::with_capacity(fixed + client_cert_der.len());
		buffer.extend_from_slice(TIGHTBEAM_HPKE_CLIENT_AUTH_DOMAIN);
		buffer.extend_from_slice(transcript_hash);
		buffer.extend_from_slice(client_ephemeral);
		buffer.extend_from_slice(client_cert_der);
		Self(State::Open(buffer))
	}

	/// Open the bytes an HPKE server signs over its reply.
	///
	/// The digest binds a domain label and the transcript hash, so the reply
	/// signature reads as no other signed message of the crate. Both roles
	/// derive it here, the server to sign and the client to verify.
	#[cfg(feature = "transport-hpke")]
	pub(crate) fn hpke_server_auth(transcript_hash: &TranscriptHash) -> Self {
		let transcript_hash = transcript_hash.as_bytes();
		let len = TIGHTBEAM_HPKE_SERVER_AUTH_DOMAIN.len() + transcript_hash.len();

		let mut buffer = Vec::with_capacity(len);
		buffer.extend_from_slice(TIGHTBEAM_HPKE_SERVER_AUTH_DOMAIN);
		buffer.extend_from_slice(transcript_hash);
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
			State::Sealed => Err(HandshakeError::InvalidState),
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
	/// - [`HandshakeError::TranscriptDigestLength`] -- the output of `D` is not 32 to 64 bytes.
	pub(crate) fn seal<D: Digest + AssociatedOid>(&mut self) -> Result<TranscriptHash, HandshakeError> {
		let State::Open(buffer) = &self.0 else {
			return Err(HandshakeError::InvalidState);
		};

		let hash = Self::digest::<D>(buffer)?;
		self.0 = State::Sealed;
		Ok(hash)
	}
}

/// The HPKE handshake legs the transcript binds, in the order both roles
/// hash them. [`Transcript::hpke_handshake`] fixes that order.
#[cfg(feature = "transport-hpke")]
pub(crate) struct HpkeHandshakeLegs<'a> {
	/// The DER of the ClientHello as it was sent and received.
	pub(crate) client_hello: &'a [u8],
	/// The 32-byte server random.
	pub(crate) server_random: &'a [u8; 32],
	/// The compressed SEC1 server ephemeral public key.
	pub(crate) server_ephemeral: &'a [u8; EC_PUBKEY_COMPRESSED_SIZE],
	/// The raw `subjectPublicKey` bits of the server certificate.
	pub(crate) server_public_key: &'a [u8],
	/// The DER of the security accept, empty when the server sent none.
	pub(crate) security_accept_der: &'a [u8],
	/// Whether the server demands a client certificate. It enters as one byte,
	/// `0x01` for a demand and `0x00` for none. Each accept beside it is a DER
	/// SEQUENCE that begins with `0x30`, so the byte reads as part of neither.
	pub(crate) client_cert_required: bool,
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
	pub(crate) fn content(self, transcript_hash: &TranscriptHash) -> Vec<u8> {
		[self.domain(), transcript_hash.as_bytes()].concat()
	}

	/// Read the transcript hash that a Finished of this role signed, as the
	/// bytes after the role's domain label.
	///
	/// Content that names another role yields `None`.
	pub(crate) fn transcript_hash(self, content: &[u8]) -> Option<&[u8]> {
		content.strip_prefix(self.domain())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::profiles::DefaultCryptoProvider;

	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	use crate::crypto::hash::{Sha3_256, Sha3_512};
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	use crate::oids::HASH_SHA3_512;
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	use crate::testing::Aes256Sha3_512Provider;
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	use crate::transport::handshake::tests::fixture_transcript;

	#[cfg(feature = "transport-cms")]
	#[test]
	fn a_sealed_transcript_refuses_more_bytes() -> Result<(), HandshakeError> {
		let mut transcript = Transcript::new();
		transcript.append(b"key exchange")?;
		transcript.seal::<Sha3_256>()?;

		let refusal = transcript.append(b"server finished");
		assert!(matches!(refusal, Err(HandshakeError::InvalidState)));
		Ok(())
	}

	#[cfg(feature = "transport-cms")]
	#[test]
	fn a_sealed_transcript_refuses_a_second_seal() -> Result<(), HandshakeError> {
		let mut transcript = Transcript::new();
		transcript.append(b"key exchange")?;
		transcript.seal::<Sha3_256>()?;

		let refusal = transcript.seal::<Sha3_256>();
		assert!(matches!(refusal, Err(HandshakeError::InvalidState)));
		Ok(())
	}

	/// The CMS transcript hash of a key exchange followed by server Finished
	/// legs that carry `server_ephemeral`.
	#[cfg(feature = "transport-cms")]
	fn cms_hash_with_ephemeral(server_ephemeral: &[u8]) -> Result<TranscriptHash, HandshakeError> {
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

	/// The HPKE transcript hash of fixed legs around `server_ephemeral`.
	#[cfg(feature = "transport-hpke")]
	fn hpke_hash_with_ephemeral(server_ephemeral: &[u8; 33]) -> Result<TranscriptHash, HandshakeError> {
		let legs = HpkeHandshakeLegs {
			client_hello: b"client hello",
			server_random: &[0x01u8; 32],
			server_ephemeral,
			server_public_key: b"spki",
			security_accept_der: b"accept",
			client_cert_required: false,
			transport_accept_der: b"",
		};

		let mut transcript = Transcript::hpke_handshake(legs);
		transcript.seal::<Sha3_256>()
	}

	/// Two HPKE transcripts that differ only in the server ephemeral hash
	/// differently, so the server signature binds the ephemeral.
	#[cfg(feature = "transport-hpke")]
	#[test]
	fn the_hpke_transcript_binds_the_server_ephemeral() -> Result<(), HandshakeError> {
		let first = hpke_hash_with_ephemeral(&[0x02u8; 33])?;
		let second = hpke_hash_with_ephemeral(&[0x03u8; 33])?;
		assert_ne!(first, second);
		Ok(())
	}

	#[test]
	fn test_transcript_hash_single_message() -> Result<(), HandshakeError> {
		let msg = b"Hello, World!";
		let hash = transcript_hash::<DefaultCryptoProvider>(&[msg])?;
		assert_eq!(hash.as_bytes().len(), 32);
		Ok(())
	}

	#[test]
	fn test_transcript_hash_multiple_messages() -> Result<(), HandshakeError> {
		let msg1 = b"Message 1";
		let msg2 = b"Message 2";
		let msg3 = b"Message 3";

		let hash = transcript_hash::<DefaultCryptoProvider>(&[msg1, msg2, msg3])?;
		assert_eq!(hash.as_bytes().len(), 32);
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

	/// A SHA3-512 transcript hash is the whole 64-byte digest.
	///
	/// The expected bytes come from an independent SHA3-512 (Python's
	/// `hashlib`), so a truncation to any width fails here.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[test]
	fn a_sha3_512_transcript_hash_is_the_whole_digest() -> Result<(), HandshakeError> {
		use crate::crypto::hash::Sha3_512;

		let wide = Transcript::digest::<Sha3_512>(b"transcript")?;
		let expected = [
			0x7a, 0x03, 0x50, 0x48, 0xdf, 0x98, 0xb5, 0x57, 0xe4, 0xa6, 0x77, 0x2a, 0x7b, 0x5f, 0x78, 0x17, 0x94, 0xcc,
			0x4f, 0xde, 0xc8, 0x16, 0x39, 0x4f, 0x56, 0x6d, 0x20, 0x4a, 0x68, 0x9f, 0xe1, 0xf1, 0x36, 0x70, 0xca, 0x10,
			0x6d, 0x8a, 0x7a, 0x82, 0xc4, 0xf8, 0xd7, 0xea, 0xba, 0x53, 0x04, 0x3e, 0x23, 0x25, 0xd8, 0x2e, 0x92, 0x4f,
			0xc1, 0x37, 0xc2, 0x07, 0x7c, 0x0a, 0x9a, 0x0c, 0x8f, 0x5b,
		];
		assert_eq!(wide.as_bytes(), expected);
		Ok(())
	}

	/// The HPKE transcript hashes its legs in one fixed order: the hello, the
	/// server random, the server ephemeral, the server key, the security
	/// accept, the certificate demand, and the transport accept.
	///
	/// Both peers sign and verify this digest, so the expected value is a
	/// literal that no code of the crate computes.
	#[cfg(feature = "transport-hpke")]
	#[test]
	fn the_hpke_transcript_hashes_its_legs_in_wire_order() -> Result<(), HandshakeError> {
		let legs = HpkeHandshakeLegs {
			client_hello: b"client hello",
			server_random: &[0x11; 32],
			server_ephemeral: &[0x22; EC_PUBKEY_COMPRESSED_SIZE],
			server_public_key: b"server spki",
			security_accept_der: b"security accept",
			client_cert_required: true,
			transport_accept_der: b"transport accept",
		};

		let hash = Transcript::hpke_handshake(legs).seal::<Sha3_256>()?;
		let expected = [
			0x96, 0x45, 0xa4, 0x4b, 0x7b, 0x7e, 0x7d, 0x93, 0xeb, 0x00, 0x1b, 0x25, 0xc1, 0xd7, 0xcc, 0xbc, 0xb7, 0xe5,
			0x4e, 0x90, 0x29, 0x8e, 0xba, 0x64, 0xc6, 0xb7, 0x3e, 0x4b, 0x90, 0x28, 0x73, 0x03,
		];
		assert_eq!(hash.as_bytes(), expected);
		Ok(())
	}

	/// The HPKE possession digest is SHA3-256 over its domain, the transcript
	/// hash, the client ephemeral, and the certificate DER, in that order.
	///
	/// The expected bytes come from an independent SHA3-256, so a leg dropped
	/// or moved on both sides of the signature fails here.
	#[cfg(feature = "transport-hpke")]
	#[test]
	fn the_hpke_possession_digest_matches_its_known_answer() -> Result<(), HandshakeError> {
		let client_ephemeral = [0x02u8; EC_PUBKEY_COMPRESSED_SIZE];
		let transcript_hash = fixture_transcript::<Sha3_256>([0x07u8; 32]);
		let mut signed = Transcript::hpke_client_auth(&transcript_hash, &client_ephemeral, b"client certificate");

		let digest = signed.seal::<Sha3_256>()?;
		let expected = [
			0xe9, 0x68, 0xba, 0xd7, 0x78, 0xf6, 0x05, 0xea, 0xe8, 0x45, 0xc1, 0x28, 0xee, 0xad, 0xbf, 0x47, 0xc5, 0xc7,
			0x62, 0x80, 0x72, 0x02, 0x99, 0x7a, 0x0f, 0x93, 0x6b, 0xc9, 0xe8, 0x80, 0xcb, 0x42,
		];
		assert_eq!(digest.as_bytes(), expected);
		Ok(())
	}

	/// The HPKE server digest is SHA3-256 over its domain and the transcript
	/// hash, in that order.
	///
	/// The expected bytes come from an independent SHA3-256, so a label or a
	/// hash dropped on both sides of the reply signature fails here.
	#[cfg(feature = "transport-hpke")]
	#[test]
	fn the_hpke_server_digest_matches_its_known_answer() -> Result<(), HandshakeError> {
		let transcript_hash = fixture_transcript::<Sha3_256>([0x07u8; 32]);
		let mut signed = Transcript::hpke_server_auth(&transcript_hash);

		let digest = signed.seal::<Sha3_256>()?;
		let expected = [
			0x97, 0x0a, 0x31, 0x56, 0x9b, 0x68, 0xef, 0x0b, 0xbc, 0x13, 0xf1, 0x8a, 0x03, 0x76, 0x20, 0xd6, 0x72, 0x8b,
			0xac, 0x17, 0x3f, 0x67, 0xcd, 0xde, 0xcc, 0xd2, 0xfc, 0x4c, 0x64, 0x1c, 0x08, 0x1c,
		];
		assert_eq!(digest.as_bytes(), expected);
		Ok(())
	}

	/// Under SHA3-512, the HPKE possession digest covers all 64 bytes of the
	/// transcript hash.
	///
	/// The expected bytes come from an independent SHA3-512 (Python's
	/// `hashlib`), so a transcript hash cut to 32 bytes fails here.
	#[cfg(feature = "transport-hpke")]
	#[test]
	fn a_sha3_512_possession_digest_matches_its_known_answer() -> Result<(), HandshakeError> {
		let client_ephemeral = [0x02u8; EC_PUBKEY_COMPRESSED_SIZE];
		let transcript_hash = fixture_transcript::<Sha3_512>([0x07u8; 64]);
		let mut signed = Transcript::hpke_client_auth(&transcript_hash, &client_ephemeral, b"client certificate");

		let digest = signed.seal::<Sha3_512>()?;
		let expected = [
			0x1a, 0x30, 0x2d, 0x54, 0x50, 0x47, 0x2b, 0x29, 0xcc, 0x21, 0xc3, 0x94, 0xeb, 0xb6, 0xb8, 0x37, 0xf5, 0x2c,
			0x8d, 0x9e, 0x17, 0x0d, 0x83, 0x33, 0x83, 0x31, 0x17, 0x4b, 0x2d, 0x21, 0x5d, 0x97, 0xde, 0x3a, 0x7f, 0x9f,
			0xf7, 0x32, 0x46, 0x4d, 0x2b, 0x06, 0x77, 0xf5, 0xa8, 0xd8, 0xcd, 0x92, 0xa5, 0x1a, 0xf8, 0xce, 0x5e, 0x50,
			0x91, 0xf7, 0x1b, 0x5b, 0xb4, 0x9d, 0x48, 0xbd, 0xab, 0x35,
		];
		assert_eq!(digest.as_bytes(), expected);
		Ok(())
	}

	/// Under SHA3-512, the HPKE server digest covers all 64 bytes of the
	/// transcript hash.
	///
	/// The expected bytes come from an independent SHA3-512 (Python's
	/// `hashlib`), so a transcript hash cut to 32 bytes fails here.
	#[cfg(feature = "transport-hpke")]
	#[test]
	fn a_sha3_512_server_digest_matches_its_known_answer() -> Result<(), HandshakeError> {
		let transcript_hash = fixture_transcript::<Sha3_512>([0x07u8; 64]);
		let mut signed = Transcript::hpke_server_auth(&transcript_hash);

		let digest = signed.seal::<Sha3_512>()?;
		let expected = [
			0x53, 0x23, 0xef, 0x75, 0x43, 0x59, 0x3e, 0x49, 0x59, 0x27, 0x98, 0xe5, 0xba, 0x50, 0xad, 0x26, 0x61, 0x18,
			0x91, 0x5b, 0x37, 0x13, 0x5c, 0x0c, 0x1a, 0x1c, 0x25, 0x4a, 0x73, 0x3a, 0xfc, 0xca, 0x46, 0x19, 0x2e, 0x24,
			0x3f, 0x5b, 0x2c, 0x13, 0x84, 0xda, 0x66, 0x17, 0x05, 0x86, 0x8f, 0xe1, 0x86, 0x43, 0xdc, 0x04, 0x6b, 0x09,
			0xd2, 0xfa, 0xa0, 0x38, 0x5b, 0xf9, 0xbb, 0xeb, 0xaf, 0x28,
		];
		assert_eq!(digest.as_bytes(), expected);
		Ok(())
	}

	/// The output of a digest narrower than 256 bits is refused.
	#[test]
	fn a_digest_output_narrower_than_32_bytes_is_refused() {
		let narrow = DigestOutput::parse([0u8; 28]);
		assert!(matches!(
			narrow,
			Err(HandshakeError::TranscriptDigestLength { min: 32, max: 64, received: 28 })
		));
	}

	/// The output of a digest wider than 512 bits is refused.
	#[test]
	fn a_digest_output_wider_than_64_bytes_is_refused() {
		let wide = DigestOutput::parse([0u8; 65]);
		assert!(matches!(
			wide,
			Err(HandshakeError::TranscriptDigestLength { min: 32, max: 64, received: 65 })
		));
	}

	/// The `DigestInfo` of a 64-byte transcript hash carries all 64 bytes.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[test]
	fn a_sha3_512_digest_info_carries_all_64_bytes() -> Result<(), HandshakeError> {
		let info = fixture_transcript::<Sha3_512>([0x07u8; 64]).digest_info()?;
		assert_eq!(info.digest.as_bytes(), [0x07u8; 64]);
		Ok(())
	}

	/// The `DigestInfo` of a transcript hash names the digest that computed
	/// it.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[test]
	fn a_digest_info_names_the_digest_of_its_hash() -> Result<(), HandshakeError> {
		let info = Transcript::digest::<Sha3_512>(b"transcript")?.digest_info()?;
		assert_eq!(info.algorithm.oid, HASH_SHA3_512);
		Ok(())
	}

	/// The transcript hash of a provider names the digest of that provider.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[test]
	fn a_provider_transcript_hash_names_the_provider_digest() -> Result<(), HandshakeError> {
		let hash = transcript_hash::<Aes256Sha3_512Provider>(&[b"transcript"])?;

		let info = hash.digest_info()?;
		assert_eq!(info.algorithm.oid, HASH_SHA3_512);
		Ok(())
	}
}
