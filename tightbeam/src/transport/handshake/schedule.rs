//! The key schedule of a handshake.
//!
//! Both flows and both roles derive through these owners:
//!
//! - [`HandshakeSecret`] is the one secret a session derives from. Its input
//!   is the [`ExchangeSecret`] of the key exchange, followed in the CMS flow by
//!   a `BaseSecret`.
//! - [`Terms`] holds what negotiation fixed: the profile, the multiplexing
//!   terms, the transcript hash, and the protocol's salt.
//! - [`Agreed`] derives everything a session takes from the handshake secret.
//!
//! # Key schedule
//!
//! The schedule reads these inputs:
//!
//! - `ee` is the shared secret of the ephemeral key exchange.
//! - `base` is the random secret the CMS client seals to the server's key-agreement certificate.
//! - `S` is the protocol's salt.
//! - `H` is the negotiated digest, whose output is `Hash.length` bytes wide.
//! - `HKDF` is the KDF of the profile, HKDF-SHA3-256 in the default profile.
//!
//! ```text
//! hs      = HKDF(ee || base, salt = S, info = "tb/session/kdf/v1")    CMS
//! hs      = HKDF(ee, salt = S, info = "tb/session/kdf/v1")            HPKE
//! k_c2s   = HKDF(hs, S, "tb/session/kdf/c2s/v1")
//! k_s2c   = HKDF(hs, S, "tb/session/kdf/s2c/v1")
//! epoch_0 = HKDF(hs, S, "tb/session/kdf/epoch/v1")
//! k_ack   = HKDF(hs, S, "tb/session/kdf/ack/v1")
//! k_close = HKDF(hs, S, "tb/session/kdf/closing/v1")
//! mac_c   = HKDF-Expand-H(HKDF-Extract-H(S, hs), "tb/handshake/finished/client/mac/v1", Hash.length)
//! mac_s   = HKDF-Expand-H(HKDF-Extract-H(S, hs), "tb/handshake/finished/server/mac/v1", Hash.length)
//! confirm = HMAC-H(mac_c, transcript_hash)
//! server  = HMAC-H(mac_s, transcript_hash || SignerInfo.signature)    HPKE
//! ```
//!
//! - `ee || base` is the hybrid shared secret `Z′ = Z || T` of NIST SP 800-56C Rev. 2 § 2.
//! - `k_c2s` and `k_s2c` are the key-encryption keys of each direction's
//!   records, at the key size of the provider's wrap.
//! - `confirm` and `server` follow the Finished construction of
//!   RFC 9846 § 4.5.3, one `MacKey` per role, with the crate's label as the
//!   HKDF-Expand info in place of `HkdfLabel`. `server` covers the transcript
//!   through the octets of the reply's signature.
//!
//! [Forward secrecy](crate::transport::handshake#forward-secrecy) states what
//! this schedule withholds from a holder of the server's static key.

use core::fmt;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use core::num::NonZeroUsize;

#[cfg(all(not(feature = "std"), any(feature = "transport-cms", feature = "transport-hpke")))]
use alloc::vec::Vec;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::asn1::WireDer;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::cms::signed_data::SignedData;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::constants::{
	pairwise_prefix_free, prefix_free, TIGHTBEAM_ACK_KDF_INFO, TIGHTBEAM_ACK_KEY_ID_DOMAIN, TIGHTBEAM_C2S_KDF_INFO,
	TIGHTBEAM_CLIENT_FINISHED_DOMAIN, TIGHTBEAM_CLIENT_FINISHED_KEY_INFO, TIGHTBEAM_CLOSING_KDF_INFO,
	TIGHTBEAM_CLOSING_KEY_ID_DOMAIN, TIGHTBEAM_EPOCH_KDF_INFO, TIGHTBEAM_S2C_KDF_INFO,
	TIGHTBEAM_SERVER_FINISHED_DOMAIN, TIGHTBEAM_SERVER_FINISHED_KEY_INFO, TIGHTBEAM_SESSION_KDF_INFO,
};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::aead::{DirectionalCiphers, RuntimeAead, SessionKeys};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::cms::{
	AttributesExt, AuthEnvelopedData, ContentEncryption, EnvelopeError, Opener, OwnedKek, Recipient,
};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::common::typenum::Unsigned;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::hash::Digest;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::kdf::{KdfError, KdfFunction, KdfSalt, ZeroizingHkdf, ZeroizingHmac};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::profiles::{CryptoProvider, KeyWrapAlgorithm};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::secret::SecretSlice;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::sign::SignedDataSigners;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::subtle::ConstantTimeEq;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::der::asn1::{ObjectIdentifier, OctetStringRef};
#[cfg(mux_rekey)]
use crate::der::oid::AssociatedOid;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Result as DerResult, Tag, Writer};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::oids::HANDSHAKE_TRANSCRIPT_HASH;
#[cfg(feature = "transport-cms")]
use crate::random::{generate_nonce, CryptoRngCore};
#[cfg(mux_rekey)]
use crate::transport::handshake::ephemeral::DistinctSecret;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::ephemeral::ExchangeSecret;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::error::HandshakeError;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::flow::ServerConfirmed;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::negotiation::{MuxSettings, RunnableProfile};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::peer::PeerIdentity;
#[cfg(mux_rekey)]
use crate::transport::handshake::primitives::multi_input_kdf;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::primitives::transcript::DigestOutput;
#[cfg(mux_rekey)]
use crate::transport::handshake::primitives::transcript::Transcript;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::primitives::KdfInfo;
#[cfg(feature = "transport-hpke")]
use crate::transport::handshake::primitives::RandomsSalt;
use crate::transport::handshake::primitives::TranscriptHash;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::receipt::StoredReceipt;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::{Arc, EstablishedSession, HandshakeProvider, SessionPeer};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::x509::attr::Attributes;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::x509::Certificate;
#[cfg(feature = "transport-cms")]
use crate::ZeroizingArray;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::ZeroizingBytes;

/// The 32-byte random secret the CMS client seals to the server's
/// certificate key.
///
/// It is the second input of [`HandshakeSecret::hybrid`] and the content of
/// the CMS opening. The type fixes the length, so a parse into it refuses
/// every other length.
#[cfg(feature = "transport-cms")]
pub(crate) struct BaseSecret(ZeroizingArray<BASE_SECRET_SIZE>);

/// The length of the base secret, in bytes.
#[cfg(feature = "transport-cms")]
const BASE_SECRET_SIZE: usize = 32;

#[cfg(feature = "transport-cms")]
impl BaseSecret {
	/// Draws a fresh base secret from `rng`, or from the OS random source when
	/// `rng` is `None`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::RandomGenerationFailed`] -- the random source failed.
	pub(crate) fn random(rng: Option<&mut dyn CryptoRngCore>) -> Result<Self, HandshakeError> {
		let bytes = generate_nonce::<BASE_SECRET_SIZE>(rng)?;
		Ok(Self(ZeroizingArray::new(bytes)))
	}

	/// The secret bytes, for the one derivation and the one seal that read
	/// them.
	pub(crate) fn as_bytes(&self) -> &[u8] {
		self.0.as_slice()
	}
}

/// Parses the opened key-exchange content as the base secret.
#[cfg(feature = "transport-cms")]
impl TryFrom<SecretSlice<u8>> for BaseSecret {
	type Error = HandshakeError;

	/// # Errors
	///
	/// - [`HandshakeError::InvalidKeySize`] -- the content is not [`BASE_SECRET_SIZE`] bytes.
	fn try_from(content: SecretSlice<u8>) -> Result<Self, Self::Error> {
		let received = content.with(Vec::len);
		if received != BASE_SECRET_SIZE {
			return Err(HandshakeError::InvalidKeySize { expected: BASE_SECRET_SIZE, received });
		}

		// The copy lands directly in a `ZeroizingArray`, so the secret sits
		// only in memory that wipes on drop (CWE-226).
		let mut sized = ZeroizingArray::new([0u8; BASE_SECRET_SIZE]);
		content.with(|bytes| sized.copy_from_slice(bytes));
		Ok(Self(sized))
	}
}

/// The secret both endpoints agree on: the shared secret of the ephemeral key
/// exchange, followed in the CMS flow by the client's base secret, extracted
/// under the protocol salt.
///
/// Every session key derives from it. `hybrid` derives the CMS secret, and
/// `ephemeral` the HPKE one.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct HandshakeSecret(ZeroizingBytes);

/// The length of the handshake secret, in bytes.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const HANDSHAKE_SECRET_SIZE: usize = 32;

/// The size in octets of the stack buffer of the hybrid secret `ee || base`:
/// the 66 octets of the P-521 field, the widest curve the suites run, and
/// the 32 of the base secret. A wider secret goes on the heap.
#[cfg(feature = "transport-cms")]
const HYBRID_INLINE_SIZE: usize = 66 + BASE_SECRET_SIZE;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl HandshakeSecret {
	/// Derives the CMS handshake secret from the hybrid shared secret
	/// `Z′ = ee || base`, extracted under `salt` (NIST SP 800-56C Rev. 2 § 2).
	///
	/// - `ee` is the shared secret `Z` of the ephemeral key exchange, at the one width its exchange gives it.
	/// - `base` is the auxiliary secret `T` that follows it, 32 bytes.
	///
	/// Each part has a fixed width for one provider, so the concatenation is
	/// unambiguous.
	///
	/// # Errors
	///
	/// - [`HandshakeError::IntegerOutOfRange`] -- the width of `ee || base` passes `usize`.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
	#[cfg(feature = "transport-cms")]
	pub(crate) fn hybrid<P>(ee: &ExchangeSecret, base: &BaseSecret, salt: KdfSalt<'_>) -> Result<Self, HandshakeError>
	where
		P: CryptoProvider,
	{
		ee.with(|ee| {
			let sum = ee.len().checked_add(BASE_SECRET_SIZE);
			let width = sum.ok_or(HandshakeError::IntegerOutOfRange)?;
			let octets = ee.iter().chain(base.as_bytes());

			// Each buffer wipes on drop (CWE-226). The hybrid secret of a named
			// curve up to P-521 fits the stack buffer, and a wider one goes on
			// the heap at its final capacity.
			let mut inline = ZeroizingArray::new([0u8; HYBRID_INLINE_SIZE]);
			match inline.get_mut(..width) {
				Some(hybrid) => {
					hybrid.iter_mut().zip(octets).for_each(|(slot, octet)| *slot = *octet);
					Self::extract::<P>(hybrid, salt)
				}
				None => {
					let mut hybrid = ZeroizingBytes::new(Vec::with_capacity(width));
					hybrid.extend(octets);
					Self::extract::<P>(&hybrid, salt)
				}
			}
		})
	}

	/// Derives the HPKE handshake secret from the shared secret `Z = ee` alone,
	/// extracted under `salt`.
	///
	/// Both ephemerals serve this one agreement, so forward secrecy rests on
	/// them alone, as for the ECDHE secret of TLS 1.3 (RFC 9846 § 7.1).
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
	#[cfg(any(test, feature = "transport-hpke"))]
	pub(crate) fn ephemeral<P>(ee: &ExchangeSecret, salt: KdfSalt<'_>) -> Result<Self, HandshakeError>
	where
		P: CryptoProvider,
	{
		ee.with(|shared| Self::extract::<P>(shared, salt))
	}

	/// Extracts the handshake secret from the shared secret `ikm` under `salt`,
	/// the one derivation both constructors run.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
	fn extract<P>(ikm: &[u8], salt: KdfSalt<'_>) -> Result<Self, HandshakeError>
	where
		P: CryptoProvider,
	{
		let label = KdfInfo::new(TIGHTBEAM_SESSION_KDF_INFO);
		let secret = P::Kdf::derive_dynamic_key(ikm, label.as_bytes(), Some(salt), HANDSHAKE_SECRET_SIZE)?;
		Ok(Self(secret))
	}

	/// The single-use seal of `purpose` under this secret, bound to the
	/// transcript it answers.
	///
	/// - The key-encryption key is `HKDF(hs, salt, label)` under the purpose's label, of `P`'s wrap size.
	/// - The `kekid` is the purpose's domain followed by `transcript_hash`,
	///   and the hash is an authenticated attribute, so a seal commits to its
	///   session.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the key length.
	/// - [`HandshakeError::KeyError`] -- the derived key is not the key size of the wrap of `P`.
	pub(crate) fn sealer<P>(
		&self,
		purpose: SecretSeal,
		salt: KdfSalt<'_>,
		transcript_hash: &TranscriptHash,
	) -> Result<Sealer<P>, HandshakeError>
	where
		P: CryptoProvider,
	{
		let kek_size = <<P::KeyWrap as KeyWrapAlgorithm>::KekSize as Unsigned>::USIZE;
		let derived = P::Kdf::derive_dynamic_key(&self.0, purpose.label(), Some(salt), kek_size)?;
		let kek = OwnedKek::try_from(derived.as_slice())?;
		Ok(Sealer { kek, transcript_hash: *transcript_hash, purpose })
	}

	/// Derives the key-confirmation tag of the client Finished over
	/// `transcript_hash`, under the `MacKey` of [`FinishedRole::Client`].
	///
	/// ```text
	/// mac_c = HKDF-Expand-H(HKDF-Extract-H(salt, hs), "tb/handshake/finished/client/mac/v1", Hash.length)
	/// tag   = HMAC-H(mac_c, transcript_hash)
	/// ```
	///
	/// The client owns no static key-establishment key, so this tag falls
	/// outside the key confirmation of NIST SP 800-56A Rev. 3 § 5.9.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- HKDF refused the length of `mac_c`.
	/// - [`HandshakeError::TranscriptDigestLength`] -- the digest of `P` is not 32 to 64 bytes.
	pub(crate) fn confirmation<P>(
		&self,
		salt: KdfSalt<'_>,
		transcript_hash: &TranscriptHash,
	) -> Result<KeyConfirmation, HandshakeError>
	where
		P: CryptoProvider,
	{
		self.finished::<P>(FinishedRole::Client, salt, &[transcript_hash.as_bytes()])
	}

	/// Derives the server Finished over `transcript_hash` and the octets of
	/// the one `SignerInfo.signature` of `reply`, under the `MacKey` of
	/// [`FinishedRole::Server`] (RFC 9846 § 4.5.3).
	///
	/// ```text
	/// mac_s  = HKDF-Expand-H(HKDF-Extract-H(salt, hs), "tb/handshake/finished/server/mac/v1", Hash.length)
	/// server = HMAC-H(mac_s, transcript_hash || SignerInfo.signature)
	/// ```
	///
	/// # Errors
	///
	/// - [`HandshakeError::SignatureVerificationFailed`] -- `reply` does not have exactly one signer.
	/// - [`HandshakeError::KdfError`] -- HKDF refused the length of `mac_s`.
	/// - [`HandshakeError::TranscriptDigestLength`] -- the digest of `P` is not 32 to 64 bytes.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn server_confirmation<P>(
		&self,
		salt: KdfSalt<'_>,
		transcript_hash: &TranscriptHash,
		reply: &SignedData,
	) -> Result<KeyConfirmation, HandshakeError>
	where
		P: CryptoProvider,
	{
		let signer_info = reply.sole_signer()?;

		let signature = signer_info.signature.as_bytes();
		self.finished::<P>(FinishedRole::Server, salt, &[transcript_hash.as_bytes(), signature])
	}

	/// Verifies that `received` is the server Finished of this secret over
	/// `transcript_hash` and the signature of `reply`, and returns the secret.
	///
	/// # Errors
	///
	/// - [`HandshakeError`] -- an error of [`Self::server_confirmation`].
	/// - [`HandshakeError::KeyConfirmationFailed`] -- the tags differ, so the
	///   server derived another handshake secret or MACed another transcript or
	///   signature.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn confirm_server<P>(
		self,
		salt: KdfSalt<'_>,
		transcript_hash: &TranscriptHash,
		reply: &SignedData,
		received: &KeyConfirmation,
	) -> Result<Self, HandshakeError>
	where
		P: CryptoProvider,
	{
		let expected = self.server_confirmation::<P>(salt, transcript_hash, reply)?;
		expected.verify(received)?;

		Ok(self)
	}

	/// The Finished MAC of `role` over `parts` in order, under the role's
	/// `MacKey` and the digest `H` of `P`.
	///
	/// A 32-byte `hs` is too short a PRK for a 64-byte `H` (RFC 5869 § 2.3), so
	/// `H` extracts one first. Each role expands its `MacKey` under its own
	/// label, so the two tags of one handshake use distinct keys.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- HKDF refused the length of the `MacKey`.
	/// - [`HandshakeError::TranscriptDigestLength`] -- the digest of `P` is not 32 to 64 bytes.
	fn finished<P>(
		&self,
		role: FinishedRole,
		salt: KdfSalt<'_>,
		parts: &[&[u8]],
	) -> Result<KeyConfirmation, HandshakeError>
	where
		P: CryptoProvider,
	{
		// 1. Extract the PRK of the secret, and expand the role's `MacKey` from it.
		let prk = ZeroizingHkdf::<P::Digest>::new(salt.as_bytes(), &self.0);
		let mut mac_key = ZeroizingBytes::new(vec![0u8; <P::Digest as Digest>::output_size()]);
		let expanded = prk.expand(role.key_label(), &mut mac_key);
		expanded.map_err(KdfError::DerivationFailed)?;

		// 2. MAC the parts in order under the `MacKey`.
		let mac = ZeroizingHmac::<P::Digest>::new(&mac_key);
		let mac = parts.iter().fold(mac, |mac, part| mac.chain_update(part));
		let tag = mac.finalize();
		Ok(KeyConfirmation(DigestOutput::parse(tag.as_slice())?))
	}

	/// Verifies that `received` is the key-confirmation tag of this secret over
	/// `transcript_hash`, and returns the secret as confirmed. It consumes the
	/// secret, so a [`ConfirmedSecret`] is the only copy.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- HKDF refused the length of the tag's key.
	/// - [`HandshakeError::TranscriptDigestLength`] -- the digest of `P` is not 32 to 64 bytes.
	/// - [`HandshakeError::KeyConfirmationFailed`] -- the tags differ, so the
	///   peer derived another handshake secret or confirmed another transcript.
	pub(crate) fn confirmed<P>(
		self,
		salt: KdfSalt<'_>,
		transcript_hash: &TranscriptHash,
		received: &KeyConfirmation,
	) -> Result<ConfirmedSecret, HandshakeError>
	where
		P: CryptoProvider,
	{
		let expected = self.confirmation::<P>(salt, transcript_hash)?;
		expected.verify(received)?;

		Ok(ConfirmedSecret(self))
	}
}

/// The `Debug` output redacts the handshake secret.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl fmt::Debug for HandshakeSecret {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("HandshakeSecret").finish_non_exhaustive()
	}
}

/// What a key of the handshake secret seals, one key per purpose.
///
/// Each purpose holds its KDF label, the domain that leads its `kekid`, its
/// padding, and the error an open failure returns. One message of each purpose
/// travels per handshake, so each key is single-use.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SecretSeal {
	/// The client's countersignature of the receipt, sealed in the closing.
	Ack,
	/// The closing of both flows: the client Finished, which carries the
	/// client certificate, or the attributes of an anonymous client.
	Closing,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl SecretSeal {
	/// The KDF label the key of this purpose derives under.
	pub(crate) const fn label(self) -> &'static [u8] {
		match self {
			Self::Ack => TIGHTBEAM_ACK_KDF_INFO,
			Self::Closing => TIGHTBEAM_CLOSING_KDF_INFO,
		}
	}

	/// The domain that leads the `kekid`, ahead of the transcript hash.
	pub(crate) const fn domain(self) -> &'static [u8] {
		match self {
			Self::Ack => TIGHTBEAM_ACK_KEY_ID_DOMAIN,
			Self::Closing => TIGHTBEAM_CLOSING_KEY_ID_DOMAIN,
		}
	}

	/// The padding of the sealed plaintext, or `None` for a purpose sealed
	/// bare.
	///
	/// Every other field of a closing has a fixed width, so an unpadded closing
	/// reveals the length of the client certificate. Padding to a step with a
	/// floor gives one length to the closings of a fleet with one issuer.
	const fn padding(self) -> Option<Padding> {
		match self {
			Self::Ack => None,
			Self::Closing => Some(Padding { floor: 1024, step: CLOSING_STEP }),
		}
	}

	/// The error an envelope refusal of this purpose returns, with the refusal
	/// inside.
	pub(crate) fn refusal(self, error: EnvelopeError) -> HandshakeError {
		match self {
			Self::Ack => HandshakeError::ReceiptAckCipher(error),
			Self::Closing => HandshakeError::SealedClosing(error),
		}
	}

	/// The sealed envelope `der` carries, for a [`Sealer`] of this purpose to
	/// open. The CMS rules of the admission walk admit it, and it decodes once.
	///
	/// # Errors
	///
	/// - The [`Self::refusal`] of [`EnvelopeError::Encoding`] -- `der` is no
	///   DER `AuthEnvelopedData` that the walk admits.
	pub(crate) fn admit(self, der: impl AsRef<[u8]>) -> Result<WireDer<AuthEnvelopedData>, HandshakeError> {
		let admitted = WireDer::try_from(der.as_ref());
		admitted.map_err(|error| self.refusal(EnvelopeError::Encoding(error)))
	}

	/// The frame of `plaintext` that the seal of this purpose encrypts.
	///
	/// A purpose with no padding seals the plaintext bare, in its own buffer. A
	/// padded purpose seals a big-endian `u16` length, the plaintext, and zero
	/// bytes up to its padded length, so the opener finds the end of the
	/// plaintext from the prefix alone.
	///
	/// # Errors
	///
	/// - [`HandshakeError::SealedFrame`] -- the plaintext of a padded purpose
	///   is longer than a `u16` length names, or its padded length overflows.
	pub(crate) fn frame(self, plaintext: impl Into<Vec<u8>>) -> Result<ZeroizingBytes, HandshakeError> {
		let plaintext = ZeroizingBytes::new(plaintext.into());
		let Some(padding) = self.padding() else {
			return Ok(plaintext);
		};

		let length = u16::try_from(plaintext.len()).map_err(|_| HandshakeError::SealedFrame)?;
		let padded_len = padding.padded_len(plaintext.len()).ok_or(HandshakeError::SealedFrame)?;
		let mut framed = ZeroizingBytes::new(Vec::with_capacity(padded_len));
		framed.extend_from_slice(&length.to_be_bytes());
		framed.extend_from_slice(&plaintext);
		framed.resize(padded_len, 0);
		Ok(framed)
	}

	/// The plaintext inside an opened frame. Only a frame that [`Self::frame`]
	/// could write opens.
	///
	/// # Errors
	///
	/// - [`HandshakeError::SealedFrame`] -- the length runs past the end of the
	///   frame, a padding byte is non-zero, or the frame length differs from
	///   the padded length of its plaintext.
	fn unframe(self, framed: &[u8]) -> Result<SecretSlice<u8>, HandshakeError> {
		let Some(padding) = self.padding() else {
			return Ok(SecretSlice::from(framed.to_vec()));
		};

		let prefixed = framed.split_first_chunk::<FRAME_LENGTH_SIZE>();
		let (prefix, rest) = prefixed.ok_or(HandshakeError::SealedFrame)?;
		let length = usize::from(u16::from_be_bytes(*prefix));
		let (plaintext, pad) = rest.split_at_checked(length).ok_or(HandshakeError::SealedFrame)?;

		let padded = pad.iter().all(|byte| *byte == 0);
		let conforming = padding.padded_len(length) == Some(framed.len());
		if !padded || !conforming {
			return Err(HandshakeError::SealedFrame);
		}

		Ok(SecretSlice::from(plaintext.to_vec()))
	}
}

/// The width of the length that leads a padded frame.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const FRAME_LENGTH_SIZE: usize = 2;

/// The step a closing pads to, 512 octets.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const CLOSING_STEP: NonZeroUsize = match NonZeroUsize::new(512) {
	Some(step) => step,
	None => panic!("the closing step takes one octet or more"),
};

/// The length a framed plaintext pads to: the next multiple of `step`, and at
/// least `floor`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Padding {
	floor: usize,
	step: NonZeroUsize,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl Padding {
	/// The padded length of the frame of a `plaintext`-byte plaintext, with its
	/// length prefix, or `None` when that length overflows a `usize`.
	fn padded_len(self, plaintext: usize) -> Option<usize> {
		let framed = plaintext.checked_add(FRAME_LENGTH_SIZE)?;
		let step = self.step.get();
		let stepped = framed.div_ceil(step).checked_mul(step)?;
		Some(stepped.max(self.floor))
	}
}

// The acknowledgement and the closing derive two keys from one secret, so
// their labels must differ (RFC 5869 § 3.2), which `prefix_free` implies.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const _: () = assert!(prefix_free(SecretSeal::Ack.label(), SecretSeal::Closing.label()));

// When the negotiated digest is the KDF's hash, every key named below expands
// from one PRK of the handshake secret under the protocol salt, so the labels
// must differ pairwise (RFC 5869 § 3.2), which `pairwise_prefix_free` implies.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const _: () = assert!(pairwise_prefix_free(&[
	TIGHTBEAM_CLIENT_FINISHED_KEY_INFO,
	TIGHTBEAM_SERVER_FINISHED_KEY_INFO,
	TIGHTBEAM_C2S_KDF_INFO,
	TIGHTBEAM_S2C_KDF_INFO,
	TIGHTBEAM_EPOCH_KDF_INFO,
	TIGHTBEAM_ACK_KDF_INFO,
	TIGHTBEAM_CLOSING_KDF_INFO,
]));

/// The single-use seal of one [`SecretSeal`] purpose: an `AuthEnvelopedData`
/// with one `KEKRecipientInfo` (RFC 5652 §6.2.3) under the purpose's key and
/// the algorithms of `P`.
///
/// [`HandshakeSecret::sealer`] is its one constructor. `seal` and `open` take
/// it by value, so one key seals or opens one message. Each seal draws its own
/// content key and nonce.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct Sealer<P: CryptoProvider> {
	kek: OwnedKek<P::KeyWrap>,
	transcript_hash: TranscriptHash,
	purpose: SecretSeal,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P: HandshakeProvider> Sealer<P> {
	/// Seals `plaintext`, framed and padded as its purpose demands, as an
	/// `AuthEnvelopedData` of type `content_type` whose authenticated
	/// attributes carry the transcript hash.
	///
	/// The framed buffer moves into the envelope, which encrypts it in place.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ReceiptAckCipher`] -- the envelope refused to seal an acknowledgement.
	/// - [`HandshakeError::SealedClosing`] -- the envelope refused to seal a closing.
	/// - [`HandshakeError::SealedFrame`] -- the closing is longer than a `u16`
	///   length names, or its padded length overflows.
	/// - [`HandshakeError::DerError`] -- the transcript hash attribute fails to encode.
	pub(crate) fn seal(
		self,
		content_type: ObjectIdentifier,
		plaintext: impl Into<Vec<u8>>,
	) -> Result<AuthEnvelopedData, HandshakeError> {
		let mut framed = self.purpose.frame(plaintext)?;
		let transcript = self.transcript_hash.attribute()?;
		let key_identifier = self.key_identifier();
		let recipient = Recipient::Kek { kek: self.kek.kek(), key_identifier: &key_identifier };

		let content = core::mem::take(&mut *framed);
		let sealed = AuthEnvelopedData::seal::<P>(recipient, content_type, content, [transcript], None);
		sealed.map_err(|error| self.purpose.refusal(error))
	}

	/// Opens `sealed`, an `AuthEnvelopedData` of type `content_type` that a
	/// sealer of the same secret, purpose, and transcript sealed, and strips
	/// its frame.
	///
	/// The open checks the transcript hash attribute before the content
	/// decrypts, and the tag then covers it and the content type.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ReceiptAckCipher`] -- an acknowledgement fails to
	///   open, so its sealer held another handshake secret or another
	///   transcript, or the acknowledgement changed in flight.
	/// - [`HandshakeError::SealedClosing`] -- a closing fails to open.
	/// - [`HandshakeError::SealedFrame`] -- the opened frame of a closing is malformed.
	/// - [`HandshakeError::DerError`] -- the transcript hash attribute fails to encode.
	pub(crate) async fn open(
		self,
		sealed: WireDer<AuthEnvelopedData>,
		content_type: ObjectIdentifier,
	) -> Result<SecretSlice<u8>, HandshakeError> {
		let (der, envelope) = sealed.into_parts();

		// 1. Refuse another transcript before the content decrypts.
		self.refuse_unbound(envelope.auth_attrs.as_ref())?;
		let key_identifier = self.key_identifier();
		let opener = Opener::Kek { kek: self.kek.kek(), key_identifier: &key_identifier };

		// 2. Open the content under the tag, which covers the attributes.
		let opened = envelope.open::<P>(&der, &opener, content_type).await;
		let opened = opened.map_err(|error| self.purpose.refusal(error))?;
		opened.with(|framed| self.purpose.unframe(framed))
	}

	/// What an outside CMS reader opens the seal of `plaintext` with: the
	/// key-encryption key, the `kekid`, and the frame of `plaintext` under the
	/// purpose of this sealer.
	#[cfg(test)]
	pub(crate) fn kek_opening(&self, plaintext: &[u8]) -> crate::testing::fixtures::KekOpening {
		let framed = self.purpose.frame(plaintext).expect("the plaintext fits its frame");
		let kek = self.kek.kek().as_array().to_vec();
		crate::testing::fixtures::KekOpening::new(kek, self.key_identifier(), framed.to_vec())
	}

	/// The `kekid` of this seal: the purpose's domain, then the transcript
	/// hash.
	fn key_identifier(&self) -> Vec<u8> {
		[self.purpose.domain(), self.transcript_hash.as_bytes()].concat()
	}

	/// Refuses `auth_attrs` unless it carries the transcript hash attribute of
	/// this sealer, once under its OID.
	///
	/// # Errors
	///
	/// - [`HandshakeError`] -- the attribute is absent, repeated, or names
	///   another transcript. The error is the [`SecretSeal::refusal`] of
	///   [`EnvelopeError::AuthenticatedAttribute`].
	/// - [`HandshakeError::DerError`] -- the expected attribute fails to encode.
	fn refuse_unbound(&self, auth_attrs: Option<&Attributes>) -> Result<(), HandshakeError> {
		let expected = self.transcript_hash.attribute()?;
		let unbound = || self.purpose.refusal(EnvelopeError::AuthenticatedAttribute);
		let attrs = auth_attrs.ok_or_else(unbound)?;

		let carried = attrs.single(HANDSHAKE_TRANSCRIPT_HASH, unbound())?;
		let bound = carried == Some(&expected);
		bound.then_some(()).ok_or_else(unbound)
	}
}

/// A handshake secret the peer proved it derived.
///
/// [`HandshakeSecret::confirmed`] is its one producer, so a step that takes
/// a `ConfirmedSecret` runs only after the key-confirmation tag verified.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct ConfirmedSecret(HandshakeSecret);

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl ConfirmedSecret {
	/// The confirmed secret, for the one seal that opens under it.
	pub(crate) fn secret(&self) -> &HandshakeSecret {
		&self.0
	}

	/// Takes the secret out, for the session that derives from it.
	pub(crate) fn into_secret(self) -> HandshakeSecret {
		self.0
	}
}

/// The proof that an endpoint derived the handshake secret of one transcript.
///
/// [`HandshakeSecret::confirmation`] derives the client tag, and
/// [`HandshakeSecret::server_confirmation`] the server Finished, each as wide
/// as the negotiated digest. A received tag decodes as an OCTET STRING of 32
/// to 64 bytes, and a tag of another digest's width fails the comparison.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[derive(Clone, Copy)]
pub struct KeyConfirmation(DigestOutput);

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl KeyConfirmation {
	/// Verifies in constant time that `received` is this tag.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyConfirmationFailed`] -- the tags differ, so the
	///   peer derived another handshake secret or confirmed another transcript.
	pub(crate) fn verify(&self, received: &Self) -> Result<(), HandshakeError> {
		let is_confirmed: bool = self.0.as_bytes().ct_eq(received.0.as_bytes()).into();
		if !is_confirmed {
			return Err(HandshakeError::KeyConfirmationFailed);
		}

		Ok(())
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl FixedTag for KeyConfirmation {
	const TAG: Tag = Tag::OctetString;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl EncodeValue for KeyConfirmation {
	fn value_len(&self) -> DerResult<Length> {
		Length::try_from(self.0.as_bytes().len())
	}

	fn encode_value(&self, writer: &mut impl Writer) -> DerResult<()> {
		writer.write(self.0.as_bytes())
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<'a> DecodeValue<'a> for KeyConfirmation {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> DerResult<Self> {
		let octets = OctetStringRef::decode_value(reader, header)?;
		let tag = DigestOutput::parse(octets.as_bytes()).map_err(|_| Tag::OctetString.length_error())?;
		Ok(Self(tag))
	}
}

/// The endpoint that sent a Finished.
///
/// Both Finished messages cover the same transcript hash, so each role has its
/// own signing label and `MacKey` label. A Finished then verifies only as one
/// of the endpoint that made it, so a Finished a peer reflects back fails.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FinishedRole {
	/// The server Finished: the CMS server's signature, and the MAC the reply
	/// of either flow carries.
	Server,
	/// The client Finished, signed with the client's key, and the
	/// key-confirmation tag of the closing.
	Client,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl FinishedRole {
	/// The domain label this role signs ahead of the transcript hash.
	const fn domain(self) -> &'static [u8] {
		match self {
			Self::Server => TIGHTBEAM_SERVER_FINISHED_DOMAIN,
			Self::Client => TIGHTBEAM_CLIENT_FINISHED_DOMAIN,
		}
	}

	/// The HKDF-Expand label of this role's `MacKey`.
	pub(crate) const fn key_label(self) -> &'static [u8] {
		match self {
			Self::Server => TIGHTBEAM_SERVER_FINISHED_KEY_INFO,
			Self::Client => TIGHTBEAM_CLIENT_FINISHED_KEY_INFO,
		}
	}

	/// Builds the content a signed Finished of this role signs: the role's
	/// domain label, the transcript hash, and for the client Finished the
	/// digest `D` of `certificate`, the certificate it carries
	/// (RFC 9846 § 4.5.2).
	///
	/// The CMS transcript binds the server's certificate as the server sent it,
	/// so the server Finished binds the role and the transcript alone.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DerError`] -- `certificate` fails to encode.
	/// - [`HandshakeError::TranscriptDigestLength`] -- the output of `D` is not 32 to 64 bytes wide.
	pub(crate) fn content<D: Digest>(
		self,
		transcript_hash: &TranscriptHash,
		certificate: &Certificate,
	) -> Result<Vec<u8>, HandshakeError> {
		match self {
			Self::Server => Ok([self.domain(), transcript_hash.as_bytes()].concat()),
			Self::Client => {
				let certificate = DigestOutput::of_der::<D>(certificate)?;
				Ok([self.domain(), transcript_hash.as_bytes(), certificate.as_bytes()].concat())
			}
		}
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod sealed {
	/// Closes [`TrafficSecret`](super::TrafficSecret) to this module.
	pub trait Sealed {}
}

/// A secret that traffic keys derive from.
///
/// The directional derivation takes the handshake secret or the epoch secret
/// that rotates from it. The trait is sealed, so those two are its only inputs.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) trait TrafficSecret: sealed::Sealed {
	/// The secret bytes, for the provider KDF that extracts from them.
	fn as_bytes(&self) -> &[u8];
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl sealed::Sealed for HandshakeSecret {}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl TrafficSecret for HandshakeSecret {
	fn as_bytes(&self) -> &[u8] {
		&self.0
	}
}

/// One link of the rekey KDF chain, zeroized on drop and on rotation.
///
/// It has two constructors. [`EpochMaterials::derive`] derives epoch 0 from
/// the [`HandshakeSecret`], and [`Self::next`] derives each next link from the
/// previous one and a fresh agreement.
#[cfg(mux_rekey)]
pub(crate) struct EpochSecret(ZeroizingBytes);

#[cfg(mux_rekey)]
impl sealed::Sealed for EpochSecret {}

#[cfg(mux_rekey)]
impl TrafficSecret for EpochSecret {
	fn as_bytes(&self) -> &[u8] {
		&self.0
	}
}

#[cfg(mux_rekey)]
impl EpochSecret {
	/// The next link of the rekey KDF chain: this link and `shared`, the secret
	/// of a fresh exchange, extracted under `salt` and the epoch label.
	///
	/// ```text
	/// epoch_next = HKDF(u32be(32) || epoch || u32be(Ndh) || ee, salt, "tb/session/kdf/epoch/v1")
	/// ```
	///
	/// - `Ndh` is the width of `ee`, the one width the exchange of `P` gives it.
	/// - `shared` is a [`DistinctSecret`], so it comes from an exchange on a
	///   share that each side checked against the static keys of its peer. Even
	///   a holder of this link who records the whole renewal needs the private
	///   half of a rekey share to derive the next.
	/// - `shared` drops here, so it is wiped before any later await of the caller.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
	/// - [`HandshakeError::IntegerOutOfRange`] -- an input is too long for its `u32` length prefix.
	pub(crate) fn next<P>(&self, shared: DistinctSecret, salt: KdfSalt<'_>) -> Result<Self, HandshakeError>
	where
		P: CryptoProvider,
	{
		let label = KdfInfo::new(TIGHTBEAM_EPOCH_KDF_INFO);
		let secret = shared.as_ref().with(|shared| {
			let inputs: [&[u8]; 2] = [&self.0, shared];
			multi_input_kdf::<P>(&inputs, salt, label, EPOCH_SECRET_SIZE)
		})?;

		Ok(Self(secret))
	}
}

/// The epoch state that outlives the handshake for an in-band rekey.
///
/// [`Handshake::complete`](crate::transport::handshake::Handshake::complete)
/// produces it alongside the session keys, for either role. The epoch secret
/// seeds the rekey KDF chain, and the transcript hash is the chain root
/// `hash_0`. The handshake secret itself drops at completion.
///
/// A rekey installs the next secret, counter, and chain hash together.
pub struct EpochMaterials {
	/// The current epoch secret, zeroized on drop and on rotation
	/// (RFC 9846 § 7.2). Only a build with the mux rekey, its reader, has it.
	#[cfg(mux_rekey)]
	secret: EpochSecret,
	/// The epoch counter. It is 0 at the handshake and increments on each
	/// rekey install.
	epoch: u32,
	/// The chained transcript hash. `hash_0` is the handshake transcript hash.
	transcript_hash: TranscriptHash,
}

impl EpochMaterials {
	/// Returns the current epoch number.
	pub fn epoch(&self) -> u32 {
		self.epoch
	}

	/// Returns the current chained transcript hash, at the full width of the
	/// negotiated digest.
	pub fn transcript_hash(&self) -> TranscriptHash {
		self.transcript_hash
	}
}

/// The `Debug` output redacts the epoch secret.
impl fmt::Debug for EpochMaterials {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("EpochMaterials")
			.field("epoch", &self.epoch)
			.field("transcript_hash", &self.transcript_hash)
			.finish_non_exhaustive()
	}
}

#[cfg(mux_rekey)]
impl EpochMaterials {
	/// Derives the epoch-0 secret from the handshake secret under the epoch
	/// info label.
	///
	/// It reads the `secret` and `salt` of the directional traffic keys. The
	/// distinct label yields an independent secret (RFC 5869 domain
	/// separation), so the traffic keys keep their strength while the session
	/// retains it.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
	pub(crate) fn derive<P>(
		secret: &HandshakeSecret,
		salt: KdfSalt<'_>,
		transcript_hash: TranscriptHash,
	) -> Result<Self, HandshakeError>
	where
		P: CryptoProvider,
	{
		let input_key = secret.as_bytes();
		let secret = P::Kdf::derive_dynamic_key(input_key, TIGHTBEAM_EPOCH_KDF_INFO, Some(salt), EPOCH_SECRET_SIZE)?;

		let materials = Self { secret: EpochSecret(secret), epoch: HANDSHAKE_EPOCH, transcript_hash };
		Ok(materials)
	}
}

#[cfg(mux_rekey)]
impl EpochMaterials {
	/// The next link of the chain: this epoch's secret and `shared`, the
	/// secret of a fresh exchange, under `salt`, as [`EpochSecret::next`]
	/// derives it.
	///
	/// # Errors
	///
	/// - The errors of [`EpochSecret::next`].
	pub(crate) fn next_secret<P>(
		&self,
		shared: DistinctSecret,
		salt: KdfSalt<'_>,
	) -> Result<EpochSecret, HandshakeError>
	where
		P: CryptoProvider,
	{
		self.secret.next::<P>(shared, salt)
	}

	/// Installs `next` as the current link, with `next_hash` as its chain
	/// root, and derives its directional ciphers under `salt`, the salt that
	/// derived it.
	///
	/// - The traffic keys come from `next` under the directional labels of
	///   handshake finalization, and both ciphers take the next epoch.
	/// - The ciphers derive before any field changes, so a refused derivation leaves the link whole.
	/// - The assignment of `next` drops the prior secret, which zeroizes on drop (RFC 9846 § 7.2).
	/// - Each rekey half maps the ciphers to its own role.
	///
	/// # Errors
	///
	/// - [`HandshakeError::IntegerOutOfRange`] -- the epoch counter is at its last value.
	/// - The errors of [`DirectionalCiphers::derive`].
	pub(crate) fn install<P>(
		&mut self,
		next: EpochSecret,
		salt: KdfSalt<'_>,
		next_hash: TranscriptHash,
	) -> Result<DirectionalCiphers<RuntimeAead>, HandshakeError>
	where
		P: HandshakeProvider,
	{
		let next_epoch = self.epoch.checked_add(1).ok_or(HandshakeError::IntegerOutOfRange)?;
		let directional = DirectionalCiphers::derive::<P, _>(&next, salt, next_epoch)?;

		self.secret = next;
		self.epoch = next_epoch;
		self.transcript_hash = next_hash;

		Ok(directional)
	}

	/// The current epoch secret, which unit tests read.
	#[cfg(test)]
	pub(crate) fn secret(&self) -> &EpochSecret {
		&self.secret
	}

	/// The pin an epoch receipt commits to:
	/// `H(hash || request_der || server_random || server_share)`.
	///
	/// The pin is computable before the receipt exists, so the receipt's
	/// `transcript_hash` commits to the exchange without circularity. It covers
	/// both rekey shares:
	///
	/// - the client's share, inside `request_der`, and
	/// - the server's share, as the last leg, so the concatenation frames it at any width.
	///
	/// # Errors
	///
	/// - [`HandshakeError::TranscriptDigestLength`] -- the output of `D` is not 32 to 64 bytes.
	pub(crate) fn exchange_pin<D: Digest + AssociatedOid>(
		&self,
		request_der: impl AsRef<[u8]>,
		server_random: &[u8; 32],
		server_share: impl AsRef<[u8]>,
	) -> Result<TranscriptHash, HandshakeError> {
		let hash = self.transcript_hash.as_bytes();
		let legs: [&[u8]; 4] = [hash, request_der.as_ref(), server_random, server_share.as_ref()];
		Transcript::digest::<D>(legs.concat())
	}

	/// The chain hash after a completed exchange:
	/// `H(hash || request_der || response_der || ack_der)`.
	///
	/// Every epoch receipt then commits to the whole session history back to
	/// the handshake transcript.
	///
	/// # Errors
	///
	/// - [`HandshakeError::TranscriptDigestLength`] -- the output of `D` is not 32 to 64 bytes.
	pub(crate) fn advanced<D: Digest + AssociatedOid>(
		&self,
		request_der: impl AsRef<[u8]>,
		response_der: impl AsRef<[u8]>,
		ack_der: impl AsRef<[u8]>,
	) -> Result<TranscriptHash, HandshakeError> {
		let legs: [&[u8]; 4] = [
			self.transcript_hash.as_bytes(),
			request_der.as_ref(),
			response_der.as_ref(),
			ack_der.as_ref(),
		];
		Transcript::digest::<D>(legs.concat())
	}
}

/// The length of the epoch secret, in bytes: one 256-bit link of the KDF
/// chain.
#[cfg(mux_rekey)]
const EPOCH_SECRET_SIZE: usize = 32;

/// The epoch of the keys a handshake installs, which each rekey counts up
/// from.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const HANDSHAKE_EPOCH: u32 = 0;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl DirectionalCiphers<RuntimeAead> {
	/// Derives the directional record keys of provider `P` from a traffic
	/// secret, for `epoch`.
	///
	/// Handshake finalization and epoch rotation share this derivation. Each
	/// key is a key-encryption key at the provider's wrap size, under a salt
	/// that [`KdfSalt`] holds at the floor. The [`TrafficSecret`] bound admits
	/// the handshake secret and its epoch chain.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the KDF refused the key size.
	/// - [`HandshakeError::KeyError`] -- the derived key is not the key size of the wrap of `P`.
	pub(crate) fn derive<P, S>(secret: &S, salt: KdfSalt<'_>, epoch: u32) -> Result<Self, HandshakeError>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption> + 'static,
		S: TrafficSecret,
	{
		let key_size = <<P::KeyWrap as KeyWrapAlgorithm>::KekSize as Unsigned>::USIZE;
		let input_key = secret.as_bytes();
		let c2s_label = KdfInfo::new(TIGHTBEAM_C2S_KDF_INFO);
		let s2c_label = KdfInfo::new(TIGHTBEAM_S2C_KDF_INFO);

		let client_to_server = derive_labeled_key::<P>(input_key, salt, c2s_label, key_size)?;
		let server_to_client = derive_labeled_key::<P>(input_key, salt, s2c_label, key_size)?;
		Ok(Self { client_to_server, server_to_client, epoch })
	}
}

/// Derives one direction's record key under the KDF info label `info`.
///
/// # Errors
///
/// - [`HandshakeError::KdfError`] -- the KDF refused `key_size`.
/// - [`HandshakeError::KeyError`] -- the derived key is not the key size of the wrap of `P`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn derive_labeled_key<P>(
	input_key: &[u8],
	salt: KdfSalt<'_>,
	info: KdfInfo<'_>,
	key_size: usize,
) -> Result<RuntimeAead, HandshakeError>
where
	P: CryptoProvider<AeadCipher: ContentEncryption> + 'static,
{
	let key_bytes = P::Kdf::derive_dynamic_key(input_key, info.as_bytes(), Some(salt), key_size)?;
	let key = RuntimeAead::new::<P>(key_bytes)?;
	Ok(key)
}

/// The KDF salt of a flow.
///
/// Each protocol salts every derivation of one handshake with one value, and
/// [`Terms::kdf_salt`] yields it.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct Salt(SaltSource);

/// Where the salt of a flow comes from.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
enum SaltSource {
	/// The concatenation `client_random || server_random`.
	#[cfg(feature = "transport-hpke")]
	Randoms(RandomsSalt),
	/// The transcript hash that the [`Terms`] hold.
	#[cfg(feature = "transport-cms")]
	TranscriptHash,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl Salt {
	/// The HPKE salt, `client_random || server_random`.
	#[cfg(feature = "transport-hpke")]
	pub(crate) fn randoms(client_random: &[u8; 32], server_random: &[u8; 32]) -> Self {
		Self(SaltSource::Randoms(RandomsSalt::new(client_random, server_random)))
	}

	/// The CMS salt, the transcript hash that the [`Terms`] hold.
	#[cfg(feature = "transport-cms")]
	pub(crate) fn transcript_hash() -> Self {
		Self(SaltSource::TranscriptHash)
	}
}

/// What both sides hold once negotiation is done.
///
/// The handshake fixes every field at the leg that seals the transcript, so a
/// handshake that holds terms holds all of them.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct Terms<P: HandshakeProvider> {
	profile: RunnableProfile<P>,
	mux: Option<MuxSettings>,
	transcript_hash: TranscriptHash,
	salt: Salt,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P: HandshakeProvider> Terms<P> {
	/// Fixes the terms of one handshake.
	///
	/// - `mux` is `None` for a single-flight session.
	/// - `transcript_hash` is the sealed hash both sides sign over.
	pub(crate) fn new(
		profile: RunnableProfile<P>,
		mux: Option<MuxSettings>,
		transcript_hash: TranscriptHash,
		salt: Salt,
	) -> Self {
		Self { profile, mux, transcript_hash, salt }
	}

	/// The profile both sides agreed.
	pub(crate) fn profile(&self) -> RunnableProfile<P> {
		self.profile
	}

	/// The multiplexing terms both sides agreed, if any.
	pub(crate) fn mux(&self) -> Option<MuxSettings> {
		self.mux
	}

	/// The sealed transcript hash.
	pub(crate) fn transcript_hash(&self) -> &TranscriptHash {
		&self.transcript_hash
	}

	/// The salt every derivation of this handshake runs under.
	///
	/// # Errors
	///
	/// - [`KdfError::SaltTooShort`] -- the salt is shorter than the floor of [`KdfSalt`].
	pub(crate) fn kdf_salt(&self) -> Result<KdfSalt<'_>, KdfError> {
		match &self.salt.0 {
			#[cfg(feature = "transport-hpke")]
			SaltSource::Randoms(randoms) => randoms.as_kdf_salt(),
			#[cfg(feature = "transport-cms")]
			SaltSource::TranscriptHash => KdfSalt::try_from(self.transcript_hash.as_bytes()),
		}
	}

	/// The key-confirmation tag of `secret` over the transcript of these
	/// terms.
	///
	/// # Errors
	///
	/// - [`HandshakeError`] -- the errors of [`Self::kdf_salt`] and [`HandshakeSecret::confirmation`].
	pub(crate) fn confirmation(&self, secret: &HandshakeSecret) -> Result<KeyConfirmation, HandshakeError> {
		secret.confirmation::<P>(self.kdf_salt()?, self.transcript_hash())
	}

	/// `secret`, once `received` confirms it over the transcript of these
	/// terms.
	///
	/// # Errors
	///
	/// - [`HandshakeError`] -- the errors of [`Self::kdf_salt`] and [`HandshakeSecret::confirmed`].
	pub(crate) fn confirm(
		&self,
		secret: HandshakeSecret,
		received: &KeyConfirmation,
	) -> Result<ConfirmedSecret, HandshakeError> {
		secret.confirmed::<P>(self.kdf_salt()?, self.transcript_hash(), received)
	}

	/// The server Finished of `secret` over the transcript of these terms and
	/// the signature of `reply`.
	///
	/// # Errors
	///
	/// - [`HandshakeError`] -- the errors of [`Self::kdf_salt`] and [`HandshakeSecret::server_confirmation`].
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn server_confirmation(
		&self,
		secret: &HandshakeSecret,
		reply: &SignedData,
	) -> Result<KeyConfirmation, HandshakeError> {
		secret.server_confirmation::<P>(self.kdf_salt()?, self.transcript_hash(), reply)
	}

	/// `secret`, once `received` is its server Finished over the transcript of
	/// these terms and the signature of `reply`.
	///
	/// # Errors
	///
	/// - [`HandshakeError`] -- the errors of [`Self::kdf_salt`] and [`HandshakeSecret::confirm_server`].
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn confirm_server(
		&self,
		secret: HandshakeSecret,
		reply: &SignedData,
		received: &KeyConfirmation,
	) -> Result<HandshakeSecret, HandshakeError> {
		secret.confirm_server::<P>(self.kdf_salt()?, self.transcript_hash(), reply, received)
	}

	/// The single-use seal of `purpose` under `secret`, bound to the salt and
	/// the transcript of these terms.
	///
	/// # Errors
	///
	/// - [`HandshakeError`] -- the errors of [`Self::kdf_salt`] and [`HandshakeSecret::sealer`].
	pub(crate) fn sealer(&self, secret: &HandshakeSecret, purpose: SecretSeal) -> Result<Sealer<P>, HandshakeError> {
		secret.sealer::<P>(purpose, self.kdf_salt()?, self.transcript_hash())
	}
}

/// What both sides hold once the handshake secret exists.
///
/// [`Self::complete`] consumes it, so one handshake derives one session.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct Agreed<P: HandshakeProvider> {
	terms: Terms<P>,
	secret: HandshakeSecret,
	receipt: Option<StoredReceipt>,
	peer: Option<SessionPeer>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P: HandshakeProvider> Agreed<P> {
	/// Gathers what a server agreed: the secret whose client tag verified,
	/// and the client that `peer`, the admitted party, records.
	///
	/// `receipt` is the dual-signed receipt of a budget-bearing session, and
	/// `None` for an unmetered one.
	pub(crate) fn server(
		terms: Terms<P>,
		secret: ConfirmedSecret,
		receipt: Option<StoredReceipt>,
		peer: impl PeerIdentity,
	) -> Self {
		Self { terms, secret: secret.into_secret(), receipt, peer: peer.into_peer() }
	}

	/// Gathers what a client agreed: the secret of a server whose reply
	/// signature and server Finished verified, and the server that `peer`,
	/// the admitted party, records.
	///
	/// `receipt` is the dual-signed receipt of a budget-bearing session, and
	/// `None` for an unmetered one.
	pub(crate) fn client(
		terms: Terms<P>,
		confirmed: ServerConfirmed,
		receipt: Option<StoredReceipt>,
		peer: impl PeerIdentity,
	) -> Self {
		Self { terms, secret: confirmed.into_secret(), receipt, peer: peer.into_peer() }
	}

	/// The negotiated terms.
	pub(crate) fn terms(&self) -> &Terms<P> {
		&self.terms
	}

	/// The dual-signed receipt of a budget-bearing session.
	pub(crate) fn receipt(&self) -> Option<&StoredReceipt> {
		self.receipt.as_ref()
	}

	/// The peer this role recorded.
	pub(crate) fn peer(&self) -> Option<&SessionPeer> {
		self.peer.as_ref()
	}

	/// Derives everything a session takes from the handshake secret, and hands
	/// it over.
	///
	/// Both protocols and both roles run this one sequence: the epoch-0 rekey
	/// materials, then the directional traffic keys, each under the protocol's
	/// salt.
	///
	/// - `keys` maps the directional ciphers to the keys of the caller's role.
	/// - A build with the mux rekey derives the epoch and hands it to the session.
	/// - The handshake secret drops when this returns.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InsufficientSaltEntropy`] -- the salt of the terms is
	///   shorter than the floor of [`KdfSalt`].
	/// - [`HandshakeError::KdfError`] -- the KDF refused a key length.
	/// - [`HandshakeError::KeyError`] -- the derived key is not the key size of the wrap of `P`.
	pub(crate) fn complete(
		self,
		keys: fn(DirectionalCiphers<RuntimeAead>) -> SessionKeys,
	) -> Result<EstablishedSession, HandshakeError> {
		let Self { terms, secret, receipt, peer } = self;
		let salt = terms.kdf_salt()?;
		#[cfg(mux_rekey)]
		let epoch = EpochMaterials::derive::<P>(&secret, salt, terms.transcript_hash)?;
		let ciphers = DirectionalCiphers::derive::<P, _>(&secret, salt, HANDSHAKE_EPOCH)?;
		let receipt = receipt.map(Arc::new);

		let session = EstablishedSession::new(keys(ciphers), terms.mux, receipt, peer);
		#[cfg(mux_rekey)]
		let session = session.with_epoch(epoch);
		Ok(session)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(mux_rekey)]
	use core::marker::PhantomData;

	#[cfg(mux_rekey)]
	use p256::NistP256;
	#[cfg(mux_rekey)]
	use p384::NistP384;
	#[cfg(mux_rekey)]
	use p521::NistP521;

	use crate::asn1::admission::fixtures::{der_refusal, descending_attribute, tlv};
	use crate::cms::signed_data::{SignerInfo, SignerInfos};
	use crate::constants::TIGHTBEAM_ACK_KEY_ID_DOMAIN;
	use crate::crypto::aead::{RecordDirection, RecvCipher, SendCipher};
	use crate::crypto::hash::{Sha3_256, Sha3_512};
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::der::asn1::{OctetString, SetOfVec};
	use crate::der::{Decode, Encode, ErrorKind};
	use crate::oids::DATA;
	use crate::testing::{unhex, Aes256Sha3_512Provider, EnvelopeRecipient, TestCertificate, TestKey, TestResult};
	use crate::transport::handshake::tests::{
		create_test_signed_data, derive_handshake_secret, fixture_agreement, fixture_base_secret,
		fixture_handshake_secret, fixture_salt, fixture_transcript, fixture_transcript_hash, wide_transcript_hash,
		FIXTURE_SALT,
	};

	#[cfg(mux_rekey)]
	use crate::crypto::aead::{Aes256Gcm, Aes256GcmOid};
	#[cfg(mux_rekey)]
	use crate::crypto::exchange::{Ecdhe, EcdheShare, HandshakeCurve};
	#[cfg(mux_rekey)]
	use crate::crypto::hpke::DhKemSecp256k1;
	#[cfg(mux_rekey)]
	use crate::crypto::kdf::HkdfSha3_256;
	#[cfg(mux_rekey)]
	use crate::crypto::profiles::{
		AeadProvider, Aes256Wrap, DigestProvider, KdfProvider, KeyExchangeProvider, KeyWrapProvider, SecurityProfile,
		SecurityStrength, SigningProvider,
	};
	#[cfg(mux_rekey)]
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	#[cfg(mux_rekey)]
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};
	#[cfg(mux_rekey)]
	use crate::crypto::sign::elliptic_curve::{CurveArithmetic, NonZeroScalar, Scalar, SecretKey};
	#[cfg(mux_rekey)]
	use crate::transport::handshake::ephemeral::PeerStatics;

	/// The directional record keys of the default provider from `secret`
	/// under `salt`, at epoch 0.
	fn derive_directional(
		secret: &HandshakeSecret,
		salt: &[u8],
	) -> Result<DirectionalCiphers<RuntimeAead>, HandshakeError> {
		DirectionalCiphers::derive::<DefaultCryptoProvider, _>(secret, KdfSalt::try_from(salt)?, 0)
	}

	// Each row derives the handshake secret of the fixture inputs `0x11` and
	// `0x42` with one input changed, and the secret changes with that input.
	crate::tb_cases! {
		fn the_handshake_secret_depends_on_the((shared, base): (u8, u8)) -> TestResult {
			let fixture = fixture_handshake_secret(0x42);
			let base = fixture_base_secret(base);

			let other = derive_handshake_secret(&fixture_agreement(shared), Some(&base), fixture_salt())?;
			assert_ne!(fixture.as_bytes(), other.as_bytes());
			Ok(())
		}
		cases {
			/// The handshake secret changes with the ephemeral-ephemeral
			/// output, so a holder of the base secret alone derives another
			/// secret.
			ephemeral_agreement => (0x12, 0x42),
			/// The handshake secret changes with the base secret, so the
			/// client's random contribution counts beside the agreement.
			base_secret => (0x11, 0x43),
		}
	}

	/// The parse refuses a base secret of any other length.
	#[cfg(feature = "transport-cms")]
	#[test]
	fn a_base_secret_of_another_length_is_refused() {
		let short = BaseSecret::try_from(SecretSlice::from(vec![0x42u8; 31]));
		assert!(matches!(
			short,
			Err(HandshakeError::InvalidKeySize { expected: 32, received: 31 })
		));
	}

	/// An epoch secret of 32 `fill` bytes, in place of a link the chain
	/// derived.
	#[cfg(mux_rekey)]
	fn epoch_secret(fill: u8) -> EpochSecret {
		EpochSecret(ZeroizingBytes::new(vec![fill; 32]))
	}

	/// The materials of epoch 0 under the epoch secret `0x42` × 32, whose
	/// chain hash is `transcript_hash`.
	#[cfg(mux_rekey)]
	fn epoch_materials(transcript_hash: TranscriptHash) -> EpochMaterials {
		EpochMaterials { secret: epoch_secret(0x42), epoch: 0, transcript_hash }
	}

	/// The chain step is HKDF-SHA3-256 over the framed pair of the epoch
	/// secret and the agreement output, under the salt and the epoch label.
	///
	/// Both endpoints derive this value, so the expected one is a literal that
	/// no code of the crate computes.
	#[cfg(mux_rekey)]
	#[test]
	fn the_epoch_chain_step_matches_its_known_answer() -> TestResult {
		let epoch = epoch_secret(0x42);
		let shared = DistinctSecret::fixture(vec![0x11u8; 32]);
		let salt = [0x99u8; 64];

		let next = epoch.next::<DefaultCryptoProvider>(shared, KdfSalt::try_from(salt.as_slice())?)?;
		let expected = unhex("ad8e999c3c4889e62889c798f7919707dc45575977a16531426abb9c2101b434");
		assert_eq!(next.0.as_slice(), expected);
		Ok(())
	}

	/// The server ephemeral leg of the known answers of the pin: every octet
	/// `0x02`, at the width of a compressed secp256k1 point. The pin hashes the
	/// leg as it is, so the octets name no point.
	#[cfg(mux_rekey)]
	fn pin_ephemeral_leg() -> [u8; 33] {
		[0x02u8; 33]
	}

	/// The rekey pin under the digest `D` of the epoch whose chain hash is
	/// `transcript_hash`, over a request, the server random `0x21` × 32, and
	/// [`pin_ephemeral_leg`].
	#[cfg(mux_rekey)]
	fn exchange_pin<D: Digest + AssociatedOid>(
		transcript_hash: TranscriptHash,
	) -> Result<TranscriptHash, HandshakeError> {
		epoch_materials(transcript_hash).exchange_pin::<D>(b"request der", &[0x21u8; 32], pin_ephemeral_leg())
	}

	// The rekey pin is the digest over the chain hash, the request, the server
	// random, and the server ephemeral, in that order. The server signs it and
	// the client recomputes it, so each expected pin is a literal that no code
	// of the crate computes.
	crate::tb_cases! {
		fn the_exchange_pin_matches_its_known_answer(
			(pin, expected): (Result<TranscriptHash, HandshakeError>, &str)
		) -> TestResult {
			assert_eq!(pin?.as_bytes(), unhex(expected));
			Ok(())
		}
		cases {
			#[cfg(mux_rekey)]
			under_sha3_256 => (
				exchange_pin::<Sha3_256>(fixture_transcript_hash()),
				"63366b7a2da7b47be9c34cca3908119f61c2589dc745848b2ad855c7a7dc83de",
			),
			/// Under SHA3-512, the pin covers the whole 64-byte chain hash.
			/// The expected bytes come from an independent SHA3-512 (Python's
			/// `hashlib`), so a chain hash cut to 32 bytes fails here.
			#[cfg(mux_rekey)]
			under_sha3_512 => (
				exchange_pin::<Sha3_512>(wide_transcript_hash()),
				"703d409e9cc26679b23239ffc5c67d1b485f63580f5429c3e840aa55d751c106\
					84773290e02c54f783aef48994e137e519e31bcb5bfe4059caea2d866359a4ba",
			),
		}
	}

	/// Under SHA3-512, the next chain hash is SHA3-512 over the whole 64-byte
	/// chain hash, the request, the response, and the acknowledgement.
	///
	/// The expected bytes come from an independent SHA3-512 (Python's
	/// `hashlib`), so a chain hash cut to 32 bytes fails here.
	#[cfg(mux_rekey)]
	#[test]
	fn a_sha3_512_chain_link_matches_its_known_answer() -> TestResult {
		let materials = epoch_materials(wide_transcript_hash());

		let link = materials.advanced::<Sha3_512>(b"request der", b"response der", b"ack der")?;
		let expected = unhex(
			"e47710156894cf9bc29a2b6893ca28f4bd8f83a799cb6cb884403c1679505932\
				e51fb1ef03d2051192cfaad670dc395a540675e1a205786293aa0d4d55175057",
		);
		assert_eq!(link.as_bytes(), expected);
		Ok(())
	}

	// The handshake secret is HKDF-SHA3-256 under the salt and the session
	// label over the exchange secret `0x11` × 32, followed by the base secret
	// `0x42` × 32 when the flow carries one. The expected bytes come from an
	// independent HKDF (Python's `hmac` and `hashlib`).
	crate::tb_cases! {
		fn the_handshake_secret_matches_its_known_answer((base, expected): (Option<BaseSecret>, &str)) -> TestResult {
			let secret = derive_handshake_secret(&fixture_agreement(0x11), base.as_ref(), fixture_salt())?;
			assert_eq!(secret.as_bytes(), unhex(expected));
			Ok(())
		}
		cases {
			/// The HPKE secret derives from the exchange secret alone, so a
			/// base secret mixed into the HPKE input fails here.
			over_the_exchange_secret_alone => (
				None,
				"aa37221e40aa14c2090a1aebecf85e682975e539a3ffbc80a282127902705ff8",
			),
			/// The CMS secret derives from the hybrid secret, the plain
			/// concatenation of the two parts, so a swap of the two, or a
			/// length prefix on either, fails here.
			over_the_hybrid_secret => (
				Some(fixture_base_secret(0x42)),
				"5e7731477b05fb2382637082fccc4e85d88c75e05188289f7b0081a249323f55",
			),
		}
	}

	/// The client tag that [`fixed_secret`] derives under the provider `P` and
	/// the fixture salt over `transcript_hash`.
	fn fixed_confirmation<P: CryptoProvider>(
		transcript_hash: &TranscriptHash,
	) -> Result<KeyConfirmation, HandshakeError> {
		fixed_secret().confirmation::<P>(fixture_salt(), transcript_hash)
	}

	// The key-confirmation tag is HMAC over the transcript hash, keyed by the
	// bytes HKDF expands under the client Finished label from the PRK the
	// salt extracts of the handshake secret, each under the digest of the
	// provider. The expected bytes come from an independent HKDF and HMAC
	// (Python's `hmac` and `hashlib`), so no code of the crate computes them.
	crate::tb_cases! {
		fn the_key_confirmation_matches_its_known_answer(
			(tag, expected): (Result<KeyConfirmation, HandshakeError>, &str)
		) -> TestResult {
			assert_eq!(tag?.0.as_bytes(), unhex(expected));
			Ok(())
		}
		cases {
			/// Under SHA3-256, the tag is HMAC-SHA3-256, keyed by the 32 bytes
			/// HKDF-SHA3-256 expands.
			under_sha3_256 => (
				fixed_confirmation::<DefaultCryptoProvider>(&fixture_transcript_hash()),
				"b698a4e374eccedf1ec11258efa09225503c6f8101e4b5fa64089613e5fa4802",
			),
			/// Under a SHA3-512 provider, the tag is HMAC-SHA3-512, keyed by
			/// the 64 bytes HKDF-SHA3-512 expands, over a 64-byte transcript
			/// hash, so a tag or a key cut to 32 bytes fails here.
			under_sha3_512 => (
				fixed_confirmation::<Aes256Sha3_512Provider>(&wide_transcript_hash()),
				"3607b0cc6b271df95d2699a8f289745604ef55d9c614309957705da1bfd6971a\
					09297a9ef4ccc071a07bf660c65317a20730bc501f22fef7281a20984a148e16",
			),
		}
	}

	/// The signature octets of the reply a server Finished known answer MACs:
	/// the 70 bytes `0x30` to `0x75`.
	const REPLY_SIGNATURE: core::ops::Range<u8> = 0x30..0x76;

	/// A reply whose one `SignerInfo` carries `signature`. The server Finished
	/// reads the signature octets alone, so no key signs them.
	fn reply_signed_as(signature: impl AsRef<[u8]>) -> SignedData {
		let mut reply = create_test_signed_data(b"reply");
		let signature = OctetString::new(signature.as_ref()).expect("bytes are an OCTET STRING");
		let signers = core::mem::take(&mut reply.signer_infos.0).into_vec();
		let resign = |signer| SignerInfo { signature: signature.clone(), ..signer };
		let resigned: Vec<SignerInfo> = signers.into_iter().map(resign).collect();

		let resigned = SetOfVec::try_from(resigned).expect("one signer is a SET");
		reply.signer_infos = SignerInfos(resigned);
		reply
	}

	/// The reply the server Finished known answers MAC, whose signature is
	/// [`REPLY_SIGNATURE`].
	fn signed_reply() -> SignedData {
		reply_signed_as(REPLY_SIGNATURE.collect::<Vec<_>>())
	}

	/// The client Finished signs its domain label, the transcript hash, and
	/// the SHA3-256 of the DER of the certificate it carries.
	///
	/// The certificate is the fixed self-signed test certificate of the fixed
	/// test key. The expected digest comes from Python's `hashlib` over its
	/// 289 DER bytes, so no code of the crate computes it.
	#[test]
	fn the_client_finished_content_matches_its_known_answer() -> TestResult {
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let content = FinishedRole::Client.content::<Sha3_256>(&fixture_transcript_hash(), &certificate)?;

		let certificate_digest = unhex("ec636319b64960969b307426b727616ab7692df941b0a96b52a9c13f1f077b4c");
		let domain = b"tb/handshake/finished/client/v1".as_slice();
		let expected = [domain, &[0x07u8; 32], certificate_digest.as_slice()].concat();
		assert_eq!(content, expected);
		Ok(())
	}

	/// The server Finished that [`fixed_secret`] derives under the provider `P`
	/// and the fixture salt over `transcript_hash` and the signature of
	/// `reply`.
	fn fixed_server_finished<P: CryptoProvider>(
		transcript_hash: &TranscriptHash,
		reply: &SignedData,
	) -> Result<KeyConfirmation, HandshakeError> {
		fixed_secret().server_confirmation::<P>(fixture_salt(), transcript_hash, reply)
	}

	/// The server Finished of the CMS flow over [`signed_reply`], keyed by the
	/// hybrid secret the CMS flow derives: the exchange secret `0x11` × 32,
	/// then the base secret `0x42` × 32, under the fixture transcript hash as
	/// the salt.
	fn cms_server_finished() -> Result<KeyConfirmation, HandshakeError> {
		let transcript_hash = fixture_transcript_hash();
		let salt = KdfSalt::try_from(transcript_hash.as_bytes())?;
		let secret = derive_handshake_secret(&fixture_agreement(0x11), Some(&fixture_base_secret(0x42)), salt)?;
		secret.server_confirmation::<DefaultCryptoProvider>(salt, &transcript_hash, &signed_reply())
	}

	// The server Finished is HMAC over the transcript hash followed by the
	// octets of the reply's signature, keyed by the bytes HKDF expands under
	// the server Finished label. The expected bytes come from an independent
	// HKDF and HMAC (Python's `hmac` and `hashlib`), so no code of the crate
	// computes them.
	crate::tb_cases! {
		fn the_server_finished_matches_its_known_answer(
			(server, expected): (Result<KeyConfirmation, HandshakeError>, &str)
		) -> TestResult {
			assert_eq!(server?.0.as_bytes(), unhex(expected));
			Ok(())
		}
		cases {
			/// The CMS reply carries the server Finished of the HPKE reply,
			/// keyed by the hybrid secret the CMS flow derives.
			of_the_cms_reply => (
				cms_server_finished(),
				"735f782bbc9670a19c5e57b3ed51e3b21b120da02cc249f2d258f90ea636b1d9",
			),
			/// Under SHA3-256, the MAC is HMAC-SHA3-256, so a dropped
			/// signature or a swapped label fails here.
			under_sha3_256 => (
				fixed_server_finished::<DefaultCryptoProvider>(&fixture_transcript_hash(), &signed_reply()),
				"33487a72da3cbfdb4dd0c35675f721220259d54791de952fee6f0119ddcc1fc3",
			),
			/// Under a SHA3-512 provider, the server Finished is HMAC-SHA3-512
			/// over the 64-byte transcript hash and the signature octets, so a
			/// tag or a key cut to 32 bytes fails here.
			under_sha3_512 => (
				fixed_server_finished::<Aes256Sha3_512Provider>(&wide_transcript_hash(), &signed_reply()),
				"0c6b091669350aca9b769faca10da2cb3efeb5de85b938f112008dcfada1b546\
					79d18cda7dc5e940ded90f7bd1de6fc70043e35b10a9f866b582dcbb08fb1de8",
			),
		}
	}

	/// The two Finished MACs run under two keys: over a reply whose signature
	/// is empty, the server Finished MACs the transcript hash alone, as the
	/// client's tag does, yet the two differ.
	#[test]
	fn the_server_finished_and_the_client_tag_differ_by_key() -> TestResult {
		let transcript_hash = fixture_transcript_hash();
		let reply = reply_signed_as([]);

		let client = fixed_confirmation::<DefaultCryptoProvider>(&transcript_hash)?;
		let server = fixed_server_finished::<DefaultCryptoProvider>(&transcript_hash, &reply)?;
		assert_ne!(client.0.as_bytes(), server.0.as_bytes());
		Ok(())
	}

	/// A secret confirms the server Finished it derives itself, and hands
	/// itself back.
	#[test]
	fn a_server_finished_confirms_its_own_secret() -> TestResult {
		let transcript_hash = fixture_transcript_hash();
		let reply = signed_reply();
		let server = fixed_server_finished::<DefaultCryptoProvider>(&transcript_hash, &reply)?;

		let confirming = HandshakeSecret::confirm_server::<DefaultCryptoProvider>;
		let confirmed = confirming(fixed_secret(), fixture_salt(), &transcript_hash, &reply, &server)?;
		assert_eq!(confirmed.as_bytes(), fixed_secret().as_bytes());
		Ok(())
	}

	// A server Finished confirms its secret over one reply signature and one
	// role, so a tag over another signature, or a tag of the other role,
	// fails.
	crate::tb_cases! {
		fn the_server_finished_refuses((reply, received): (SignedData, KeyConfirmation)) -> TestResult {
			let confirming = HandshakeSecret::confirm_server::<DefaultCryptoProvider>;
			let refused = confirming(fixed_secret(), fixture_salt(), &fixture_transcript_hash(), &reply, &received);
			assert!(matches!(refused, Err(HandshakeError::KeyConfirmationFailed)));
			Ok(())
		}
		cases {
			/// A server Finished over the signature of another reply fails, so
			/// the MAC covers the transcript through the signature.
			a_tag_over_another_signature => (
				reply_signed_as(REPLY_SIGNATURE.rev().collect::<Vec<_>>()),
				fixed_server_finished::<DefaultCryptoProvider>(&fixture_transcript_hash(), &signed_reply())?,
			),
			/// The client's tag is no server Finished, so a reflected tag
			/// fails.
			a_reflected_client_tag => (
				reply_signed_as([]),
				fixed_confirmation::<DefaultCryptoProvider>(&fixture_transcript_hash())?,
			),
		}
	}

	/// The server Finished refuses a reply of two signers, because the reply
	/// has one signature to cover.
	#[test]
	fn a_server_finished_over_two_signers_is_refused() -> TestResult {
		let mut reply = create_test_signed_data(b"reply");
		let second = create_test_signed_data(b"second reply");

		reply.signer_infos.0.insert(second.sole_signer()?.clone())?;

		let refused = fixed_server_finished::<DefaultCryptoProvider>(&fixture_transcript_hash(), &reply);
		assert!(matches!(refused, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// A tag of another digest's width fails the comparison, so a peer under
	/// another digest confirms nothing.
	#[test]
	fn a_key_confirmation_of_another_width_is_refused() -> TestResult {
		let tag = fixed_confirmation::<DefaultCryptoProvider>(&fixture_transcript_hash())?;
		let wide = KeyConfirmation(DigestOutput::parse([tag.0.as_bytes(), tag.0.as_bytes()].concat())?);

		let refused = tag.verify(&wide);
		assert!(matches!(refused, Err(HandshakeError::KeyConfirmationFailed)));
		Ok(())
	}

	/// A received tag decodes at the width of a 512-bit digest.
	#[test]
	fn a_64_byte_key_confirmation_decodes() -> TestResult {
		let der = OctetString::new([0x07u8; 64])?.to_der()?;
		let decoded = KeyConfirmation::from_der(&der)?;
		assert_eq!(decoded.0.as_bytes(), [0x07u8; 64]);
		Ok(())
	}

	/// A received tag wider than any digest output the handshake runs fails
	/// to decode, as an OCTET STRING of the wrong length.
	#[test]
	fn a_key_confirmation_wider_than_64_bytes_fails_to_decode() -> TestResult {
		let der = OctetString::new([0x07u8; 65])?.to_der()?;
		let refused = KeyConfirmation::from_der(&der);
		assert_eq!(der_refusal(refused), Some(ErrorKind::Length { tag: Tag::OctetString }));
		Ok(())
	}

	/// A tag verifies against itself and against no other tag.
	#[test]
	fn a_key_confirmation_verifies_against_itself_alone() -> TestResult {
		let secret = fixture_handshake_secret(0x42);
		let base = fixture_base_secret(0x42);
		let other = derive_handshake_secret(&fixture_agreement(0x12), Some(&base), fixture_salt())?;
		let transcript_hash = fixture_transcript_hash();

		let tag = secret.confirmation::<DefaultCryptoProvider>(fixture_salt(), &transcript_hash)?;
		let same = secret.confirmation::<DefaultCryptoProvider>(fixture_salt(), &transcript_hash)?;
		let foreign = other.confirmation::<DefaultCryptoProvider>(fixture_salt(), &transcript_hash)?;

		let verdicts = (tag.verify(&same), tag.verify(&foreign));
		assert!(matches!(verdicts, (Ok(()), Err(HandshakeError::KeyConfirmationFailed))));
		Ok(())
	}

	/// The sealer of `purpose` under `secret`, the fixture salt, and
	/// `transcript_hash`.
	fn sealer_of(
		secret: &HandshakeSecret,
		purpose: SecretSeal,
		transcript_hash: &TranscriptHash,
	) -> Sealer<DefaultCryptoProvider> {
		let sealer = secret.sealer::<DefaultCryptoProvider>(purpose, fixture_salt(), transcript_hash);
		sealer.expect("the fixture secret derives a sealer")
	}

	/// A fixed handshake secret, so a known-answer vector reads no KDF of the
	/// handshake itself.
	fn fixed_secret() -> HandshakeSecret {
		HandshakeSecret(ZeroizingBytes::new(vec![0x42u8; 32]))
	}

	/// The sealer of `purpose` under [`fixed_secret`], the fixture salt, and
	/// the fixture transcript hash.
	fn fixed_sealer(purpose: SecretSeal) -> Sealer<DefaultCryptoProvider> {
		sealer_of(&fixed_secret(), purpose, &fixture_transcript_hash())
	}

	/// The plaintext of the fixture acknowledgement.
	const SETTLEMENT_ANSWER: &[u8] = b"settlement answer";

	/// The plaintext of the fixture closing.
	const CLIENT_IDENTITY: &[u8] = b"client identity";

	/// The acknowledgement of [`SETTLEMENT_ANSWER`] that [`fixed_sealer`]
	/// seals.
	fn sealed_ack() -> AuthEnvelopedData {
		let sealed = fixed_sealer(SecretSeal::Ack).seal(DATA, SETTLEMENT_ANSWER);
		sealed.expect("the fixed sealer seals an acknowledgement")
	}

	/// The closing of `plaintext` that [`fixed_sealer`] seals.
	fn sealed_closing(plaintext: impl Into<Vec<u8>>) -> AuthEnvelopedData {
		let sealed = fixed_sealer(SecretSeal::Closing).seal(DATA, plaintext);
		sealed.expect("the fixed sealer seals a closing")
	}

	/// A transcript hash other than the fixture one: 32 octets of `0x08` as a
	/// SHA3-256 output.
	fn other_transcript_hash() -> TranscriptHash {
		fixture_transcript::<Sha3_256>([0x08u8; 32])
	}

	/// The `kekid.keyIdentifier` of the one recipient of `sealed`.
	fn key_identifier_of(sealed: &AuthEnvelopedData) -> Vec<u8> {
		let kek = sealed.kek_recipient();
		kek.kek_id.kek_identifier.as_bytes().to_vec()
	}

	/// `sealed` with a transcript hash attribute that names `transcript_hash`
	/// in place of its own, under the same `kekid`.
	fn with_transcript_attribute(mut sealed: AuthEnvelopedData, transcript_hash: &TranscriptHash) -> AuthEnvelopedData {
		let attribute = transcript_hash.attribute().expect("the attribute encodes");
		let attrs = sealed.auth_attrs.take().expect("a seal carries authenticated attributes");
		let attrs = attrs.into_vec().into_iter();
		let kept = attrs.filter(|attr| attr.oid != HANDSHAKE_TRANSCRIPT_HASH);
		let attrs = kept.chain([attribute]).collect::<Vec<_>>();
		sealed.auth_attrs = Some(Attributes::try_from(attrs).expect("distinct attributes are a SET"));
		sealed
	}

	/// The length of the encrypted content of `sealed`, which carries its tag
	/// in `mac`.
	fn content_len(sealed: &AuthEnvelopedData) -> Option<usize> {
		let content = sealed.auth_encrypted_content_info.encrypted_content.as_ref();
		content.map(|content| content.as_bytes().len())
	}

	/// A sealed acknowledgement arrives inside an OCTET STRING, which the walk
	/// of the closing reads as octets, so its own admission walks it before
	/// its decode sorts a set in it (X.690 § 11.6).
	#[test]
	fn a_sealed_ack_of_a_descending_set_is_refused() {
		let refused = SecretSeal::Ack.admit(tlv(Tag::Sequence, &descending_attribute()));
		assert!(matches!(
			refused,
			Err(HandshakeError::ReceiptAckCipher(EnvelopeError::Encoding(error)))
				if error.kind() == ErrorKind::SetOrdering
		));
	}

	// A seal opens under a sealer of the same secret, purpose, salt, and
	// transcript, and the open of a closing strips its frame.
	crate::tb_cases! {
		async fn a_seal_opens_to_its_plaintext((purpose, plaintext): (SecretSeal, &[u8])) -> TestResult {
			let sealed = fixed_sealer(purpose).seal(DATA, plaintext)?;
			let opened = fixed_sealer(purpose).open(WireDer::new(sealed)?, DATA).await?;
			assert_eq!(opened.with(Vec::clone), plaintext);
			Ok(())
		}
		cases {
			/// An acknowledgement sealed under one handshake secret opens
			/// under the same secret, salt, and transcript.
			for_an_ack => (SecretSeal::Ack, SETTLEMENT_ANSWER),
			/// The open of a closing strips the frame and returns the
			/// plaintext.
			for_a_closing => (SecretSeal::Closing, CLIENT_IDENTITY),
			/// A closing whose length prefix carries its frame past the floor
			/// opens to its plaintext.
			for_a_closing_whose_prefix_crosses_the_floor => (SecretSeal::Closing, &[0x01; 1023]),
		}
	}

	/// An acknowledgement sealed under one handshake secret does not open
	/// under another, so a recorded session plus the base secret alone reads
	/// nothing.
	#[tokio::test]
	async fn a_sealed_ack_refuses_another_handshake_secret() -> TestResult {
		let secret = fixture_handshake_secret(0x42);
		let base = fixture_base_secret(0x42);
		let other = derive_handshake_secret(&fixture_agreement(0x12), Some(&base), fixture_salt())?;
		let sealed = sealer_of(&secret, SecretSeal::Ack, &fixture_transcript_hash()).seal(DATA, SETTLEMENT_ANSWER)?;

		let opener = sealer_of(&other, SecretSeal::Ack, &fixture_transcript_hash());
		let refused = opener.open(WireDer::new(sealed)?, DATA).await;
		assert!(matches!(
			refused,
			Err(HandshakeError::ReceiptAckCipher(EnvelopeError::KeyUnwrap))
		));
		Ok(())
	}

	// An opener checks the transcript hash attribute of a seal against its
	// own transcript before the content decrypts, so a seal bound to another
	// transcript fails to open.
	crate::tb_cases! {
		async fn a_sealed_ack_refuses(
			(sealed, opener): (AuthEnvelopedData, Sealer<DefaultCryptoProvider>)
		) -> TestResult {
			let refused = opener.open(WireDer::new(sealed)?, DATA).await;
			assert!(matches!(
				refused,
				Err(HandshakeError::ReceiptAckCipher(EnvelopeError::AuthenticatedAttribute))
			));
			Ok(())
		}
		cases {
			/// An acknowledgement sealed over one transcript does not open
			/// under another, so the envelope commits to the session it
			/// closes.
			another_transcript => (sealed_ack(), sealer_of(&fixed_secret(), SecretSeal::Ack, &other_transcript_hash())),
			/// The opener refuses a seal whose transcript hash attribute names
			/// another transcript before its content decrypts, though its
			/// `kekid` is the opener's.
			a_transcript_attribute_that_differs => (
				with_transcript_attribute(sealed_ack(), &other_transcript_hash()),
				fixed_sealer(SecretSeal::Ack),
			),
			/// A seal binds every byte of a 64-byte transcript hash, so it
			/// refuses a hash that differs in its last byte alone.
			a_64_byte_transcript_that_differs_in_its_last_byte => (
				sealer_of(&fixed_secret(), SecretSeal::Ack, &wide_transcript_hash()).seal(DATA, SETTLEMENT_ANSWER)?,
				sealer_of(
					&fixed_secret(),
					SecretSeal::Ack,
					&fixture_transcript::<Sha3_512>([[0x07u8; 63].as_slice(), &[0x08u8]].concat()),
				),
			),
		}
	}

	// The key-encryption key of each purpose is HKDF-SHA3-256 of the
	// handshake secret under the salt and the label of that purpose. The
	// expected bytes come from an independent HKDF (Python's `hmac` and
	// `hashlib`), so no code of the crate computes them.
	crate::tb_cases! {
		fn the_seal_key_matches_its_known_answer((purpose, expected): (SecretSeal, &str)) {
			let sealer = fixed_sealer(purpose);
			assert_eq!(sealer.kek.kek().as_array().as_slice(), unhex(expected));
		}
		cases {
			for_an_ack => (SecretSeal::Ack, "3a57c895dcadc114412635e7e519b6ecc531e20754fe04de8378e1d8f4a4e4b5"),
			for_a_closing => (SecretSeal::Closing, "0c7c840e0015fb07ee635c21db3fd75320167de585bfae2d726d233a9011c52d"),
		}
	}

	/// The `kekid` of a seal is its purpose domain followed by the transcript
	/// hash.
	#[test]
	fn a_seal_names_its_key_by_its_purpose_and_its_transcript() {
		let sealed = sealed_ack();
		let expected = [TIGHTBEAM_ACK_KEY_ID_DOMAIN, [0x07u8; 32].as_slice()].concat();
		assert_eq!(key_identifier_of(&sealed), expected);
	}

	/// A seal carries the transcript hash as an authenticated attribute.
	#[test]
	fn a_seal_authenticates_its_transcript_hash() -> TestResult {
		let sealed = sealed_ack();
		let attrs = sealed.auth_attrs.as_ref();
		let carried = attrs.into_iter().flat_map(|attrs| attrs.iter());
		let mut named = carried.filter(|attribute| attribute.oid == HANDSHAKE_TRANSCRIPT_HASH);

		let value = named.next().and_then(|attribute| attribute.values.iter().next());
		let hash = value.map(|value| value.decode_as::<OctetString>()).transpose()?;
		assert_eq!(hash.as_ref().map(OctetString::as_bytes), Some([0x07u8; 32].as_slice()));
		Ok(())
	}

	// A seal pads its content by its purpose: an acknowledgement seals bare,
	// and a closing frames its plaintext with its length and pads it with
	// zero bytes to the floor of 1024 octets, or past it to the next step.
	crate::tb_cases! {
		fn a_seal_pads_its_content_by_purpose((sealed, len): (AuthEnvelopedData, usize)) {
			assert_eq!(content_len(&sealed), Some(len));
		}
		cases {
			/// An acknowledgement seals bare, so its encrypted content is as
			/// long as the plaintext.
			ack_unframed => (sealed_ack(), SETTLEMENT_ANSWER.len()),
			/// The closing seal frames the plaintext with its length and pads
			/// it with zero bytes to 1024, so its encrypted content is 1024
			/// octets.
			closing_to_the_floor => (sealed_closing(CLIENT_IDENTITY), 1024),
			/// A closing past the floor pads to the next step.
			closing_past_the_floor_to_the_next_step => (sealed_closing([0x01u8; 1100]), 1536),
		}
	}

	/// Two closings whose lengths differ within one padding step seal to one
	/// length, so the length does not tell the two clients apart.
	#[test]
	fn two_closings_within_one_step_seal_to_one_length() -> TestResult {
		let short = sealed_closing([0x01u8; 600]);
		let long = sealed_closing([0x01u8; 900]);
		assert_eq!(short.to_der()?.len(), long.to_der()?.len());
		Ok(())
	}

	/// The two purposes derive two keys, so a closing does not open under the
	/// acknowledgement key.
	#[tokio::test]
	async fn a_closing_does_not_open_under_the_ack_key() -> TestResult {
		let sealed = sealed_closing(CLIENT_IDENTITY);

		let opener = fixed_sealer(SecretSeal::Ack);
		let refused = opener.open(WireDer::new(sealed)?, DATA).await;
		assert!(matches!(
			refused,
			Err(HandshakeError::ReceiptAckCipher(EnvelopeError::KeyIdentifier))
		));
		Ok(())
	}

	// Only a frame that the seal of a closing could write opens, so `unframe`
	// refuses each frame below.
	crate::tb_cases! {
		fn the_closing_unframe_refuses_a_frame(framed: Vec<u8>) {
			let refused = SecretSeal::Closing.unframe(&framed);
			assert!(matches!(refused, Err(HandshakeError::SealedFrame)));
		}
		cases {
			/// `unframe` refuses a frame of its padded length whose padding
			/// holds a non-zero byte.
			with_a_non_zero_pad => [[0x00u8, 0x01, 0xaa].as_slice(), &[0x00; 1020], &[0x01]].concat(),
			/// `unframe` refuses a frame whose length runs past its end.
			whose_length_runs_past_its_end => vec![0x00, 0x09, 0xaa, 0x00],
			/// `unframe` refuses a frame that holds its plaintext and zero
			/// bytes but runs past its padded length.
			longer_than_its_padded_length => [[0x00u8, 0x01, 0xaa].as_slice(), &[0x00; 1533]].concat(),
			/// `unframe` refuses a frame that holds its plaintext and zero
			/// bytes but falls short of its padded length.
			shorter_than_its_padded_length => vec![0x00, 0x01, 0xaa, 0x00],
		}
	}

	/// The seal refuses a closing past the `u16` length of the frame.
	#[test]
	fn a_closing_past_the_frame_length_is_refused() {
		let oversized = vec![0x01u8; usize::from(u16::MAX) + 1];
		let refused = fixed_sealer(SecretSeal::Closing).seal(DATA, oversized);
		assert!(matches!(refused, Err(HandshakeError::SealedFrame)));
	}

	/// The first client-to-server record of epoch 0 that `key` seals over
	/// `plaintext`, as its DER.
	fn sealed_under(key: RuntimeAead, plaintext: &[u8]) -> Vec<u8> {
		let sender = SendCipher::new(key, 0, RecordDirection::ClientToServer);
		let record = sender.encrypt_next(plaintext).expect("a derived key seals a record");
		record.to_der().expect("the record encodes")
	}

	/// What `key` opens of `record`, as the first client-to-server record of
	/// epoch 0.
	fn opened_under(key: RuntimeAead, record: &[u8]) -> Result<Vec<u8>, crate::TightBeamError> {
		let mut arrived = record.to_vec();
		let opened = RecvCipher::new(key, 0, RecordDirection::ClientToServer).open(&mut arrived)?;
		Ok(opened.to_vec())
	}

	/// The info labels separate the keys of the two directions, so a record
	/// of one direction fails to open under the other, even named as the
	/// first.
	#[test]
	fn a_record_of_one_direction_fails_to_open_under_the_other() -> TestResult {
		let ciphers = derive_directional(&fixture_handshake_secret(0x42), FIXTURE_SALT)?;

		let record = sealed_under(ciphers.client_to_server, b"directional key separation");
		let crossed = opened_under(ciphers.server_to_client, &record);
		assert!(matches!(
			crossed,
			Err(crate::TightBeamError::EnvelopeError(EnvelopeError::KeyUnwrap))
		));
		Ok(())
	}

	/// Two derivations from one secret and salt agree, so two endpoints derive
	/// the same directional keys from shared input material.
	#[test]
	fn the_directional_keys_derive_deterministically() -> TestResult {
		let secret = fixture_handshake_secret(0x42);
		let first = derive_directional(&secret, FIXTURE_SALT)?;
		let second = derive_directional(&secret, FIXTURE_SALT)?;

		let record = sealed_under(first.client_to_server, b"deterministic derivation");
		let opened = opened_under(second.client_to_server, &record)?;
		assert_eq!(opened, b"deterministic derivation");
		Ok(())
	}

	/// The directional derivation refuses a salt shorter than the 16-byte
	/// floor of a KDF salt.
	#[test]
	fn a_directional_salt_under_the_floor_is_refused() {
		let refused = derive_directional(&fixture_handshake_secret(0x42), &[0x99u8; 8]);
		assert!(matches!(
			refused,
			Err(HandshakeError::InsufficientSaltEntropy { actual: 8, minimum: 16 })
		));
	}

	/// The terms of a fixture handshake over `transcript_hash` under `salt`.
	fn terms_with(transcript_hash: &TranscriptHash, salt: Salt) -> Terms<DefaultCryptoProvider> {
		Terms::new(RunnableProfile::native(), None, *transcript_hash, salt)
	}

	/// The terms derive one key per purpose, so a closing they seal does not
	/// open under their acknowledgement key.
	#[cfg(feature = "transport-cms")]
	#[tokio::test]
	async fn the_terms_seal_each_purpose_under_its_own_key() -> TestResult {
		let terms = terms_with(&fixture_transcript_hash(), Salt::transcript_hash());
		let secret = fixed_secret();
		let sealed = terms.sealer(&secret, SecretSeal::Closing)?.seal(DATA, CLIENT_IDENTITY)?;

		let refused = terms.sealer(&secret, SecretSeal::Ack)?.open(WireDer::new(sealed)?, DATA).await;
		assert!(matches!(
			refused,
			Err(HandshakeError::ReceiptAckCipher(EnvelopeError::KeyIdentifier))
		));
		Ok(())
	}

	// Each flow salts every derivation of its handshake with one value: the
	// CMS flow with all of its transcript hash, the HPKE flow with the client
	// random followed by the server random.
	crate::tb_cases! {
		fn the_terms_salt_each_derivation_with(
			(terms, expected): (Terms<DefaultCryptoProvider>, Vec<u8>)
		) -> TestResult {
			let salt = terms.kdf_salt()?;
			assert_eq!(salt.as_bytes(), expected);
			Ok(())
		}
		cases {
			/// A CMS handshake salts every derivation with its transcript hash.
			#[cfg(feature = "transport-cms")]
			the_transcript_hash => (terms_with(&fixture_transcript_hash(), Salt::transcript_hash()), vec![0x07; 32]),
			/// A CMS handshake under a 512-bit digest salts every derivation
			/// with all 64 bytes of its transcript hash.
			#[cfg(feature = "transport-cms")]
			all_64_bytes_of_a_wide_transcript_hash => (
				terms_with(&wide_transcript_hash(), Salt::transcript_hash()),
				vec![0x07; 64],
			),
			/// An HPKE handshake salts every derivation with the client random
			/// followed by the server random.
			#[cfg(feature = "transport-hpke")]
			the_client_random_then_the_server_random => (
				terms_with(&fixture_transcript_hash(), Salt::randoms(&[0x01; 32], &[0x02; 32])),
				[[0x01; 32], [0x02; 32]].concat(),
			),
		}
	}

	/// The epoch-0 materials count from zero, take the handshake transcript
	/// hash as the chain root, and hold a 32-byte epoch secret.
	#[cfg(mux_rekey)]
	#[test]
	fn the_first_epoch_starts_at_zero_on_the_handshake_transcript() -> TestResult {
		let secret = fixture_handshake_secret(0x42);
		let transcript = fixture_transcript_hash();

		let materials = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, fixture_salt(), transcript)?;
		assert_eq!(materials.epoch(), 0);
		assert_eq!(materials.transcript_hash(), transcript);
		assert_eq!(materials.secret.as_bytes().len(), 32);

		Ok(())
	}

	/// Two derivations of the epoch secret from one handshake secret agree,
	/// so both endpoints root one rekey chain.
	#[cfg(mux_rekey)]
	#[test]
	fn the_epoch_secret_derives_deterministically() -> TestResult {
		let secret = fixture_handshake_secret(0x42);
		let transcript = fixture_transcript_hash();

		let first = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, fixture_salt(), transcript)?;
		let second = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, fixture_salt(), transcript)?;
		assert_eq!(first.secret.as_bytes(), second.secret.as_bytes());

		Ok(())
	}

	// Each row derives the epoch secret of the fixture handshake secret and
	// salt with one input changed, and the epoch secret changes with that
	// input.
	crate::tb_cases! {
		fn the_epoch_secret_depends_on_the((secret, salt): (HandshakeSecret, &[u8])) -> TestResult {
			let fixture = fixture_handshake_secret(0x42);
			let transcript = fixture_transcript_hash();
			let salt = KdfSalt::try_from(salt)?;

			let derived = EpochMaterials::derive::<DefaultCryptoProvider>(&fixture, fixture_salt(), transcript)?;
			let other = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, salt, transcript)?;
			assert_ne!(derived.secret.as_bytes(), other.secret.as_bytes());
			Ok(())
		}
		cases {
			#[cfg(mux_rekey)]
			handshake_secret => (fixture_handshake_secret(0x43), FIXTURE_SALT),
			#[cfg(mux_rekey)]
			salt => (fixture_handshake_secret(0x42), &[0x9a; 32]),
		}
	}

	/// An install moves the counter by one and roots the chain at the hash of
	/// the exchange, so the next pin and the next advance read the link it
	/// installed.
	#[cfg(mux_rekey)]
	#[test]
	fn an_install_advances_the_epoch_by_one_under_the_next_hash() -> TestResult {
		let mut materials = epoch_materials(fixture_transcript_hash());
		let next = epoch_secret(0x43);
		let next_hash = other_transcript_hash();

		let _ciphers = materials.install::<DefaultCryptoProvider>(next, fixture_salt(), next_hash)?;
		assert_eq!((materials.epoch(), materials.transcript_hash()), (1, next_hash));
		Ok(())
	}

	/// The house profile on the curve `C`: the house digest, AEAD, signature,
	/// KDF, and key wrap.
	#[cfg(mux_rekey)]
	#[derive(Debug, Default, Clone, Copy)]
	struct HouseProfileOn<C>(PhantomData<C>);

	#[cfg(mux_rekey)]
	impl<C: HandshakeCurve> SecurityProfile for HouseProfileOn<C> {
		type Digest = Sha3_256;
		type AeadOid = Aes256GcmOid;
		type SignatureAlg = Secp256k1Signature;
		type Kdf = HkdfSha3_256;
		type KeyExchange = Ecdhe<C>;
		type KeyWrapOid = Aes256Wrap;
	}

	/// The house provider on the curve `C`, so the schedule derives from an
	/// agreement on `C` under the house KDF.
	#[cfg(mux_rekey)]
	#[derive(Debug, Default, Clone, Copy)]
	struct HouseOn<C> {
		profile: HouseProfileOn<C>,
	}

	#[cfg(mux_rekey)]
	impl<C> DigestProvider for HouseOn<C> {
		type Digest = Sha3_256;
	}

	#[cfg(mux_rekey)]
	impl<C> AeadProvider for HouseOn<C> {
		type AeadCipher = Aes256Gcm;
	}

	#[cfg(mux_rekey)]
	impl<C> KeyWrapProvider for HouseOn<C> {
		type KeyWrap = Aes256Wrap;
	}

	#[cfg(mux_rekey)]
	impl<C> SigningProvider for HouseOn<C> {
		type Signature = Secp256k1Signature;
		type VerifyingKey = Secp256k1VerifyingKey;
	}

	#[cfg(mux_rekey)]
	impl<C> KdfProvider for HouseOn<C> {
		type Kdf = HkdfSha3_256;
	}

	#[cfg(mux_rekey)]
	impl<C: HandshakeCurve> KeyExchangeProvider for HouseOn<C> {
		type KeyExchange = Ecdhe<C>;
	}

	#[cfg(mux_rekey)]
	impl<C: HandshakeCurve + Default + Copy> CryptoProvider for HouseOn<C> {
		type Profile = HouseProfileOn<C>;
		type Kem = DhKemSecp256k1;

		fn profile(&self) -> &Self::Profile {
			&self.profile
		}
	}

	/// The secret key of the small scalar `value` on the curve `C`.
	#[cfg(mux_rekey)]
	fn small_scalar<C: CurveArithmetic>(value: u64) -> SecretKey<C> {
		let scalar: Option<NonZeroScalar<C>> = NonZeroScalar::new(Scalar::<C>::from(value)).into();
		let scalar = scalar.expect("a small nonzero value is a scalar of every curve");
		SecretKey::from(scalar)
	}

	/// The known answers of one curve, as hex: the agreement of the scalar 2
	/// with the point of the scalar 3, which is the x-coordinate of 6G, and
	/// what the schedule derives from it.
	#[cfg(mux_rekey)]
	struct AgreementVector {
		agreement: &'static str,
		hpke: &'static str,
		cms: &'static str,
		rekey: &'static str,
	}

	/// The known answers on secp256k1.
	#[cfg(mux_rekey)]
	const SECP256K1_AGREEMENT: AgreementVector = AgreementVector {
		agreement: "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
		hpke: "b50f5d5d3b69e72242449f9fb0b528e51425800771e2aab5f7e83f01c9905042",
		cms: "43e546f3ed7a3363f3b70e12deea471d49f2fbeafc7d7c360ef0b156a1c853ad",
		rekey: "0472a313d531959ac8b9306af7f0b18bdba9a9d6a7f6ae052232d874992f6741",
	};

	/// The known answers on P-256.
	#[cfg(mux_rekey)]
	const P256_AGREEMENT: AgreementVector = AgreementVector {
		agreement: "b01a172a76a4602c92d3242cb897dde3024c740debb215b4c6b0aae93c2291a9",
		hpke: "92bd0ff885f671ed5c87c673c046c2ce076bbddd0f5fc8513d96646d1b0693bc",
		cms: "96b6ea4f3ed40dc7434aa76c5c7c2c036eaa3f1cae47c19a1df424cee0d0781b",
		rekey: "442869a4ed8b7566a6446039fb93b56777bb4ea39deb0844a62d512b24a4d6fd",
	};

	/// The known answers on P-384, whose agreement is 48 bytes.
	#[cfg(mux_rekey)]
	const P384_AGREEMENT: AgreementVector = AgreementVector {
		agreement: "627be1acd064d2b2226fe0d26f2d15d3c33ebcbb7f0f5da51cbd41f262573830\
			21317d7202ff30e50937f0854e35c5df",
		hpke: "ceb7a075c0c23ff64bbb934fe387d29b7733cc20bd40d14c82a35c56c7afebe3",
		cms: "3133dc2fdf9d210a086098ab6bb686b2123a3762dc32f658fbf23bdc4cc069d9",
		rekey: "5449b832f46338219d8ce8eca678bb6667bf79de510f4815b19d1ad76e52854c",
	};

	/// The known answers on P-521, whose agreement is 66 bytes.
	#[cfg(mux_rekey)]
	const P521_AGREEMENT: AgreementVector = AgreementVector {
		agreement: "01ee4569d6cdb59219532eff34f94480d195623d30977fd71cf3981506ade4ab\
			01525fbcca16153f7394e0727a239531be8c2f66e95657f380ae23731bedf79206b9",
		hpke: "088e3032a39e88ae4538d9a44ac7d9d3ab7b2985cfbbbff124b0530e6e05fb49",
		cms: "b63acaaecd27c0909268fe7ea91061bee89d1636142ae3ccaffb7b676fdb9333",
		rekey: "9c6fc77432c39cf194171077e90586b61ac3d636c265acaa94dc7f7a88238e24",
	};

	/// What the schedule makes of one agreement: the agreement itself, the
	/// HPKE and the CMS handshake secrets, and the next rekey link.
	#[cfg(mux_rekey)]
	#[derive(Debug, PartialEq)]
	struct Scheduled {
		agreement: Vec<u8>,
		hpke: Vec<u8>,
		cms: Vec<u8>,
		rekey: Vec<u8>,
	}

	#[cfg(mux_rekey)]
	impl Scheduled {
		/// What `vector` publishes.
		fn published(vector: &AgreementVector) -> Self {
			Self {
				agreement: unhex(vector.agreement),
				hpke: unhex(vector.hpke),
				cms: unhex(vector.cms),
				rekey: unhex(vector.rekey),
			}
		}

		/// What the house schedule on `C` derives from the agreement of the
		/// scalar 2 with the point of the scalar 3: the HPKE secret, the CMS
		/// secret over the base secret `0x42` × 32, and the rekey link that
		/// follows the epoch secret `0x42` × 32.
		fn on<C>() -> Result<Self, HandshakeError>
		where
			C: HandshakeCurve + Default + Copy,
		{
			let local = small_scalar::<C>(2);
			let peer = EcdheShare::from(small_scalar::<C>(3).public_key());
			let peer = PeerStatics::<Ecdhe<C>>::none().server_ephemeral(peer)?;
			let agreement = peer.complete::<Ecdhe<C>>(&local)?;
			let salt = fixture_salt();

			let published = agreement.as_ref().with(<[u8]>::to_vec);
			let hpke = HandshakeSecret::ephemeral::<HouseOn<C>>(agreement.as_ref(), salt)?;
			let cms = HandshakeSecret::hybrid::<HouseOn<C>>(agreement.as_ref(), &fixture_base_secret(0x42), salt)?;
			let epoch = epoch_secret(0x42);
			let rekey = epoch.next::<HouseOn<C>>(agreement, KdfSalt::try_from([0x99u8; 64].as_slice())?)?;
			Ok(Self {
				agreement: published,
				hpke: hpke.as_bytes().to_vec(),
				cms: cms.as_bytes().to_vec(),
				rekey: rekey.0.to_vec(),
			})
		}
	}

	// On each curve the schedule derives the known answers of the agreement of
	// the scalar 2 with the point of the scalar 3. The expected bytes come
	// from an independent ECDH and HKDF (Python's `cryptography`, `hmac`, and
	// `hashlib`).
	crate::tb_cases! {
		fn an_agreement_derives_its_known_answers(
			(scheduled, vector): (Result<Scheduled, HandshakeError>, AgreementVector)
		) -> TestResult {
			assert_eq!(scheduled?, Scheduled::published(&vector));
			Ok(())
		}
		cases {
			/// On secp256k1 the agreement is 32 bytes, and the schedule
			/// derives the known answers of [`SECP256K1_AGREEMENT`].
			#[cfg(mux_rekey)]
			on_secp256k1 => (Scheduled::on::<Secp256k1>(), SECP256K1_AGREEMENT),
			/// On P-256 the agreement is 32 bytes, and the schedule derives
			/// the known answers of [`P256_AGREEMENT`].
			#[cfg(mux_rekey)]
			on_p256 => (Scheduled::on::<NistP256>(), P256_AGREEMENT),
			/// On P-384 the agreement is the whole 48-byte x-coordinate, and
			/// each derivation takes all of it: the CMS secret extracts from
			/// 80 bytes.
			#[cfg(mux_rekey)]
			on_p384 => (Scheduled::on::<NistP384>(), P384_AGREEMENT),
			/// On P-521 the agreement is the whole 66-byte x-coordinate, and
			/// each derivation takes all of it: the CMS secret extracts from
			/// 98 bytes.
			#[cfg(mux_rekey)]
			on_p521 => (Scheduled::on::<NistP521>(), P521_AGREEMENT),
		}
	}

	/// A profile on P-521 reports the strength its 521-bit order rates, 256
	/// bits, in [`RunnableProfile::strength`], which the strength floor reads.
	#[cfg(mux_rekey)]
	#[test]
	fn a_p521_profile_reports_the_strength_of_its_exchange() {
		let strength = RunnableProfile::<HouseOn<NistP521>>::native().strength();
		assert_eq!(strength.key_exchange, SecurityStrength::BITS_256);
	}
}
