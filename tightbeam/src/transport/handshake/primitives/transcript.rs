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
use crate::der::asn1::{Any, OctetString, SetOfVec};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::der::{Encode, Writer};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::oids::HANDSHAKE_TRANSCRIPT_HASH;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::spki::AlgorithmIdentifierOwned;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::x509::attr::Attribute;

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
		for (slot, octet) in bytes.iter_mut().zip(output) {
			*slot = *octet;
		}
		Ok(Self { bytes, len: received })
	}

	/// The output of digest `D` over the DER of `value`, which encodes
	/// straight into the digest.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DerError`] -- `value` fails to encode.
	/// - [`HandshakeError::TranscriptDigestLength`] -- the output of `D` is not 32 to 64 bytes wide.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn of_der<D: Digest>(value: &impl Encode) -> Result<Self, HandshakeError> {
		let mut writer = DigestWriter(D::new());
		value.encode(&mut writer)?;
		Self::parse(writer.0.finalize())
	}

	/// The output bytes.
	#[expect(
		clippy::indexing_slicing,
		reason = "`parse` holds `len` to 32..=64, within the 64 octets of `bytes`"
	)]
	pub(crate) fn as_bytes(&self) -> &[u8] {
		&self.bytes[..self.len]
	}
}

/// A DER writer that feeds digest `D`, so a value hashes as its encoding
/// with no buffer between the two.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
struct DigestWriter<D>(D);

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<D: Digest> Writer for DigestWriter<D> {
	fn write(&mut self, slice: &[u8]) -> crate::der::Result<()> {
		self.0.update(slice);
		Ok(())
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

	/// The hash as the attribute of `HANDSHAKE_TRANSCRIPT_HASH`, whose one
	/// value is the hash as an OCTET STRING. A seal of the handshake secret
	/// authenticates it, and the HPKE reply signs it.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DerError`] -- the attribute fails to encode.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn attribute(&self) -> Result<Attribute, HandshakeError> {
		let hash = OctetString::new(self.as_bytes())?;
		let values = SetOfVec::try_from(vec![Any::encode_from(&hash)?])?;
		Ok(Attribute { oid: HANDSHAKE_TRANSCRIPT_HASH, values })
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
/// Only an open transcript accepts bytes, so the hash covers every byte the
/// transcript ever held. The state stays private, so a hash exists only
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

	/// Create an open transcript that holds no bytes.
	pub(crate) const fn new() -> Self {
		Self(State::Open(Vec::new()))
	}

	/// Append the next message to an open transcript.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the transcript is sealed.
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
	pub(crate) fn append_server_finished(&mut self, legs: ServerFinishedLegs<'_>) -> Result<(), HandshakeError> {
		let ServerFinishedLegs { security_accept, transport_accept, server_ephemeral, certificates } = legs;
		if let Some(accept) = security_accept {
			self.append(accept)?;
		}
		if let Some(accept) = transport_accept {
			self.append(accept)?;
		}

		self.append(server_ephemeral)?;

		self.append(certificates)
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

/// The server Finished legs the CMS transcript binds: its attributes as
/// encoded bytes, then the DER of the `certificates` field it carries.
///
/// The accepts are present when negotiation produced them, and the server
/// ephemeral public key and the field are mandatory, so every sealed
/// transcript binds both. [`Transcript::append_server_finished`] fixes the
/// order.
#[cfg(feature = "transport-cms")]
pub(crate) struct ServerFinishedLegs<'a> {
	/// The `SecurityAccept` attribute value, when a profile was negotiated.
	pub(crate) security_accept: Option<Vec<u8>>,
	/// The `TransportAccept` attribute value, when transport terms were
	/// negotiated.
	pub(crate) transport_accept: Option<Vec<u8>>,
	/// The `OriginatorPublicKey` attribute value that carries the server
	/// ephemeral.
	pub(crate) server_ephemeral: Vec<u8>,
	/// The DER of the `certificates` field the Finished carries, which holds
	/// the signing certificate its `sid` names and the issuers above it: the
	/// server's as its identity encoded it once, the client's as the bytes
	/// arrived (RFC 9846 §4.5.2).
	pub(crate) certificates: &'a [u8],
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

	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[test]
	fn a_sealed_transcript_refuses_more_bytes() -> Result<(), HandshakeError> {
		let mut transcript = Transcript::new();
		transcript.append(b"key exchange")?;
		transcript.seal::<Sha3_256>()?;

		let refusal = transcript.append(b"server finished");
		assert!(matches!(refusal, Err(HandshakeError::InvalidState)));
		Ok(())
	}

	/// The transcript-hash attribute is `HANDSHAKE_TRANSCRIPT_HASH` with the
	/// hash as its one OCTET STRING value.
	///
	/// The expected DER is built by hand in Python from the RFC 5652 § 5.3
	/// `Attribute` module and the OID `1.3.6.1.4.1.64586.1.8`.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[test]
	fn the_transcript_hash_attribute_encodes_as_its_known_answer() -> Result<(), Box<dyn core::error::Error>> {
		use crate::der::Encode;

		let attribute = fixture_transcript::<Sha3_256>([0x07u8; 32]).attribute()?;
		let sequence = [0x30, 0x30];
		let oid = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xf8, 0x4a, 0x01, 0x08];
		let values = [0x31, 0x22, 0x04, 0x20];

		let expected = [sequence.as_slice(), &oid, &values, &[0x07u8; 32]].concat();
		assert_eq!(attribute.to_der()?, expected);
		Ok(())
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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
	/// legs that carry `server_ephemeral` and `certificates`.
	#[cfg(feature = "transport-cms")]
	fn cms_hash_of(server_ephemeral: &[u8], certificates: &[u8]) -> Result<TranscriptHash, HandshakeError> {
		let mut transcript = Transcript::new();
		transcript.append(b"key exchange")?;
		transcript.append_server_finished(ServerFinishedLegs {
			security_accept: Some(b"accept".to_vec()),
			transport_accept: None,
			server_ephemeral: server_ephemeral.to_vec(),
			certificates,
		})?;
		transcript.seal::<Sha3_256>()
	}

	/// The CMS transcript hash of a key exchange followed by server Finished
	/// legs that carry `server_ephemeral` and a fixed `certificates` field.
	#[cfg(feature = "transport-cms")]
	fn cms_hash_with_ephemeral(server_ephemeral: &[u8]) -> Result<TranscriptHash, HandshakeError> {
		cms_hash_of(server_ephemeral, b"certificates")
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

	/// The CMS transcript binds the server's `certificates` field after the
	/// server ephemeral, so the expected hash is SHA3-256 of the legs in that
	/// order, computed by the `sha3` crate outside the transcript.
	#[cfg(feature = "transport-cms")]
	#[test]
	fn the_cms_transcript_binds_the_certificates_after_the_ephemeral() -> Result<(), HandshakeError> {
		let bound = cms_hash_of(&[0x02u8; 33], b"certificates")?;
		let legs = [b"key exchange".as_slice(), b"accept", &[0x02u8; 33], b"certificates"].concat();
		let expected = Sha3_256::digest(&legs);
		assert_eq!(bound.as_bytes(), expected.as_slice());
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
