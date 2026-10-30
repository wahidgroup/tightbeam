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

	/// The key-encryption key and the `kekid` an outside CMS reader opens
	/// this seal with.
	#[cfg(test)]
	pub(crate) fn kek_opening(&self) -> (Vec<u8>, Vec<u8>) {
		(self.kek.kek().as_array().to_vec(), self.key_identifier())
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
	use crate::asn1::admission::fixtures::{descending_attribute, tlv};
	use crate::cms::signed_data::{SignerInfo, SignerInfos};
	use crate::constants::TIGHTBEAM_ACK_KEY_ID_DOMAIN;
	use crate::crypto::aead::{RecordDirection, RecvCipher, SendCipher};
	use crate::crypto::hash::{Sha3_256, Sha3_512};
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::elliptic_curve::CurveArithmetic;
	use crate::der::asn1::{OctetString, SetOfVec};
	use crate::der::{Decode, Encode, ErrorKind};
	use crate::oids::DATA;
	use crate::testing::{Aes256Sha3_512Provider, EnvelopeRecipient, TestCertificate, TestKey};
	use crate::transport::handshake::tests::{
		create_test_signed_data, fixture_agreement, fixture_transcript, FIXTURE_SALT,
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
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};
	#[cfg(mux_rekey)]
	use crate::crypto::sign::elliptic_curve::{NonZeroScalar, Scalar, SecretKey};
	#[cfg(mux_rekey)]
	use crate::testing::unhex;
	#[cfg(mux_rekey)]
	use crate::transport::handshake::ephemeral::PeerStatics;
	#[cfg(mux_rekey)]
	use core::marker::PhantomData;
	#[cfg(mux_rekey)]
	use p256::NistP256;
	#[cfg(mux_rekey)]
	use p384::NistP384;
	#[cfg(mux_rekey)]
	use p521::NistP521;

	/// A base secret of 32 bytes, each `fill`.
	fn base_secret(fill: u8) -> BaseSecret {
		BaseSecret::try_from(SecretSlice::from(vec![fill; 32])).expect("32 bytes make a base secret")
	}

	/// The handshake secret of the fixture inputs `shared` and `base` under
	/// `salt`.
	fn handshake_secret(shared: u8, base: u8, salt: &[u8]) -> HandshakeSecret {
		let shared = fixture_agreement(shared);
		let base = base_secret(base);
		let salt = KdfSalt::try_from(salt).expect("a fixture salt meets the floor");
		let secret = HandshakeSecret::hybrid::<DefaultCryptoProvider>(&shared, &base, salt);
		secret.expect("fixture inputs derive a handshake secret")
	}

	/// The directional record keys of the default provider from `secret`
	/// under `salt`, at epoch 0.
	fn derive_directional(
		secret: &HandshakeSecret,
		salt: &[u8],
	) -> Result<DirectionalCiphers<RuntimeAead>, HandshakeError> {
		DirectionalCiphers::derive::<DefaultCryptoProvider, _>(secret, KdfSalt::try_from(salt)?, 0)
	}

	#[test]
	fn test_derive_directional_aead_success() {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x11, 0x42, &salt);
		let result = derive_directional(&secret, &salt);
		assert!(result.is_ok());
	}

	/// The handshake secret changes with the ephemeral-ephemeral output, so a
	/// holder of the base secret alone derives another secret.
	#[test]
	fn the_handshake_secret_depends_on_the_ephemeral_agreement() {
		let salt = [0x99u8; 32];
		let first = handshake_secret(0x11, 0x42, &salt);
		let second = handshake_secret(0x12, 0x42, &salt);
		assert_ne!(first.as_bytes(), second.as_bytes());
	}

	/// The handshake secret changes with the base secret, so the client's
	/// random contribution counts beside the agreement.
	#[test]
	fn the_handshake_secret_depends_on_the_base_secret() {
		let salt = [0x99u8; 32];
		let first = handshake_secret(0x11, 0x42, &salt);
		let second = handshake_secret(0x11, 0x43, &salt);
		assert_ne!(first.as_bytes(), second.as_bytes());
	}

	/// The parse refuses a base secret of any other length.
	#[test]
	fn a_base_secret_of_another_length_is_refused() {
		let short = BaseSecret::try_from(SecretSlice::from(vec![0x42u8; 31]));
		assert!(matches!(
			short,
			Err(HandshakeError::InvalidKeySize { expected: 32, received: 31 })
		));
	}

	/// The transcript hash that a fixture seals its acknowledgement over.
	fn ack_transcript() -> TranscriptHash {
		fixture_transcript::<Sha3_256>([0x07u8; 32])
	}

	/// The chain step is HKDF-SHA3-256 over the framed pair of the epoch
	/// secret and the agreement output, under the salt and the epoch label.
	///
	/// Both endpoints derive this value, so the expected one is a literal that
	/// no code of the crate computes.
	#[cfg(mux_rekey)]
	#[test]
	fn the_epoch_chain_step_matches_its_known_answer() -> Result<(), HandshakeError> {
		let epoch = EpochSecret(ZeroizingBytes::new(vec![0x42u8; 32]));
		let shared = DistinctSecret::fixture(vec![0x11u8; 32]);
		let salt = [0x99u8; 64];

		let next = epoch.next::<DefaultCryptoProvider>(shared, KdfSalt::try_from(salt.as_slice())?)?;
		let expected = [
			0xad, 0x8e, 0x99, 0x9c, 0x3c, 0x48, 0x89, 0xe6, 0x28, 0x89, 0xc7, 0x98, 0xf7, 0x91, 0x97, 0x07, 0xdc, 0x45,
			0x57, 0x59, 0x77, 0xa1, 0x65, 0x31, 0x42, 0x6a, 0xbb, 0x9c, 0x21, 0x01, 0xb4, 0x34,
		];
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

	/// The rekey pin is SHA3-256 over the chain hash, the request, the server
	/// random, and the server ephemeral, in that order.
	///
	/// The server signs this value and the client recomputes it, so the
	/// expected one is a literal that no code of the crate computes.
	#[cfg(mux_rekey)]
	#[test]
	fn the_exchange_pin_matches_its_known_answer() -> Result<(), HandshakeError> {
		let secret = EpochSecret(ZeroizingBytes::new(vec![0x42u8; 32]));
		let transcript_hash = ack_transcript();
		let materials = EpochMaterials { secret, epoch: 0, transcript_hash };

		let leg = pin_ephemeral_leg();
		let pin = materials.exchange_pin::<Sha3_256>(b"request der", &[0x21u8; 32], leg)?;
		let expected = [
			0x63, 0x36, 0x6b, 0x7a, 0x2d, 0xa7, 0xb4, 0x7b, 0xe9, 0xc3, 0x4c, 0xca, 0x39, 0x08, 0x11, 0x9f, 0x61, 0xc2,
			0x58, 0x9d, 0xc7, 0x45, 0x84, 0x8b, 0x2a, 0xd8, 0x55, 0xc7, 0xa7, 0xdc, 0x83, 0xde,
		];
		assert_eq!(pin.as_bytes(), expected);
		Ok(())
	}

	/// The materials of an epoch whose chain hash is the 64 bytes of a
	/// SHA3-512 transcript.
	#[cfg(mux_rekey)]
	fn wide_materials() -> EpochMaterials {
		let secret = EpochSecret(ZeroizingBytes::new(vec![0x42u8; 32]));
		let transcript_hash = fixture_transcript::<Sha3_512>([0x07u8; 64]);
		EpochMaterials { secret, epoch: 0, transcript_hash }
	}

	/// Under SHA3-512, the rekey pin is SHA3-512 over the whole 64-byte chain
	/// hash, the request, the server random, and the server ephemeral.
	///
	/// The expected bytes come from an independent SHA3-512 (Python's
	/// `hashlib`), so a chain hash cut to 32 bytes fails here.
	#[cfg(mux_rekey)]
	#[test]
	fn a_sha3_512_exchange_pin_matches_its_known_answer() -> Result<(), HandshakeError> {
		let leg = pin_ephemeral_leg();
		let pin = wide_materials().exchange_pin::<Sha3_512>(b"request der", &[0x21u8; 32], leg)?;
		let expected = [
			0x70, 0x3d, 0x40, 0x9e, 0x9c, 0xc2, 0x66, 0x79, 0xb2, 0x32, 0x39, 0xff, 0xc5, 0xc6, 0x7d, 0x1b, 0x48, 0x5f,
			0x63, 0x58, 0x0f, 0x54, 0x29, 0xc3, 0xe8, 0x40, 0xaa, 0x55, 0xd7, 0x51, 0xc1, 0x06, 0x84, 0x77, 0x32, 0x90,
			0xe0, 0x2c, 0x54, 0xf7, 0x83, 0xae, 0xf4, 0x89, 0x94, 0xe1, 0x37, 0xe5, 0x19, 0xe3, 0x1b, 0xcb, 0x5b, 0xfe,
			0x40, 0x59, 0xca, 0xea, 0x2d, 0x86, 0x63, 0x59, 0xa4, 0xba,
		];
		assert_eq!(pin.as_bytes(), expected);
		Ok(())
	}

	/// Under SHA3-512, the next chain hash is SHA3-512 over the whole 64-byte
	/// chain hash, the request, the response, and the acknowledgement.
	///
	/// The expected bytes come from an independent SHA3-512 (Python's
	/// `hashlib`), so a chain hash cut to 32 bytes fails here.
	#[cfg(mux_rekey)]
	#[test]
	fn a_sha3_512_chain_link_matches_its_known_answer() -> Result<(), HandshakeError> {
		let link = wide_materials().advanced::<Sha3_512>(b"request der", b"response der", b"ack der")?;
		let expected = [
			0xe4, 0x77, 0x10, 0x15, 0x68, 0x94, 0xcf, 0x9b, 0xc2, 0x9a, 0x2b, 0x68, 0x93, 0xca, 0x28, 0xf4, 0xbd, 0x8f,
			0x83, 0xa7, 0x99, 0xcb, 0x6c, 0xb8, 0x84, 0x40, 0x3c, 0x16, 0x79, 0x50, 0x59, 0x32, 0xe5, 0x1f, 0xb1, 0xef,
			0x03, 0xd2, 0x05, 0x11, 0x92, 0xcf, 0xaa, 0xd6, 0x70, 0xdc, 0x39, 0x5a, 0x54, 0x06, 0x75, 0xe1, 0xa2, 0x05,
			0x78, 0x62, 0x93, 0xaa, 0x0d, 0x4d, 0x55, 0x17, 0x50, 0x57,
		];
		assert_eq!(link.as_bytes(), expected);
		Ok(())
	}

	/// The HPKE handshake secret is HKDF-SHA3-256 under the salt and the
	/// session label over the exchange secret `0x11` × 32 alone.
	///
	/// The expected bytes come from an independent HKDF (Python's `hmac` and
	/// `hashlib`), so a base secret mixed into the HPKE input fails here.
	#[test]
	fn the_ephemeral_handshake_secret_matches_its_known_answer() -> Result<(), HandshakeError> {
		let shared = fixture_agreement(0x11);

		let secret = HandshakeSecret::ephemeral::<DefaultCryptoProvider>(&shared, KdfSalt::try_from(FIXTURE_SALT)?)?;
		let expected = [
			0xaa, 0x37, 0x22, 0x1e, 0x40, 0xaa, 0x14, 0xc2, 0x09, 0x0a, 0x1a, 0xeb, 0xec, 0xf8, 0x5e, 0x68, 0x29, 0x75,
			0xe5, 0x39, 0xa3, 0xff, 0xbc, 0x80, 0xa2, 0x82, 0x12, 0x79, 0x02, 0x70, 0x5f, 0xf8,
		];
		assert_eq!(secret.as_bytes(), expected);
		Ok(())
	}

	/// The handshake secret is HKDF-SHA3-256 under the salt and the session
	/// label over the hybrid secret, the plain concatenation of the ECDH
	/// output `0x11` × 32 and the base secret `0x42` × 32.
	///
	/// The expected bytes come from an independent HKDF (Python's `hmac` and
	/// `hashlib`), so a swap of the two parts, or a length prefix on either,
	/// fails here.
	#[test]
	fn the_hybrid_handshake_secret_matches_its_known_answer() {
		let secret = handshake_secret(0x11, 0x42, &[0x99u8; 32]);

		let expected = [
			0x5e, 0x77, 0x31, 0x47, 0x7b, 0x05, 0xfb, 0x23, 0x82, 0x63, 0x70, 0x82, 0xfc, 0xcc, 0x4e, 0x85, 0xd8, 0x8c,
			0x75, 0xe0, 0x51, 0x88, 0x28, 0x9f, 0x7b, 0x00, 0x81, 0xa2, 0x49, 0x32, 0x3f, 0x55,
		];
		assert_eq!(secret.as_bytes(), expected);
	}

	/// The key-confirmation tag is HMAC-SHA3-256 over the transcript hash,
	/// keyed by the 32 bytes HKDF-SHA3-256 expands under the client Finished
	/// label from the PRK the salt extracts of the handshake secret.
	///
	/// The expected bytes come from an independent HKDF and HMAC (Python's
	/// `hmac` and `hashlib`), so no code of the crate computes them.
	#[test]
	fn the_key_confirmation_matches_its_known_answer() -> Result<(), HandshakeError> {
		let salt = KdfSalt::try_from(FIXTURE_SALT)?;
		let transcript_hash = ack_transcript();

		let tag = fixed_secret().confirmation::<DefaultCryptoProvider>(salt, &transcript_hash)?;
		let expected = [
			0xb6, 0x98, 0xa4, 0xe3, 0x74, 0xec, 0xce, 0xdf, 0x1e, 0xc1, 0x12, 0x58, 0xef, 0xa0, 0x92, 0x25, 0x50, 0x3c,
			0x6f, 0x81, 0x01, 0xe4, 0xb5, 0xfa, 0x64, 0x08, 0x96, 0x13, 0xe5, 0xfa, 0x48, 0x02,
		];
		assert_eq!(tag.0.as_bytes(), expected);
		Ok(())
	}

	/// Under a SHA3-512 provider, the key-confirmation tag is HMAC-SHA3-512,
	/// keyed by the 64 bytes HKDF-SHA3-512 expands, over a 64-byte transcript
	/// hash.
	///
	/// The expected bytes come from an independent HKDF and HMAC (Python's
	/// `hmac` and `hashlib`), so a tag or a key cut to 32 bytes fails here.
	#[test]
	fn a_sha3_512_key_confirmation_matches_its_known_answer() -> Result<(), HandshakeError> {
		let salt = KdfSalt::try_from(FIXTURE_SALT)?;
		let transcript_hash = fixture_transcript::<Sha3_512>([0x07u8; 64]);

		let tag = fixed_secret().confirmation::<Aes256Sha3_512Provider>(salt, &transcript_hash)?;
		let expected = [
			0x36, 0x07, 0xb0, 0xcc, 0x6b, 0x27, 0x1d, 0xf9, 0x5d, 0x26, 0x99, 0xa8, 0xf2, 0x89, 0x74, 0x56, 0x04, 0xef,
			0x55, 0xd9, 0xc6, 0x14, 0x30, 0x99, 0x57, 0x70, 0x5d, 0xa1, 0xbf, 0xd6, 0x97, 0x1a, 0x09, 0x29, 0x7a, 0x9e,
			0xf4, 0xcc, 0xc0, 0x71, 0xa0, 0x7b, 0xf6, 0x60, 0xc6, 0x53, 0x17, 0xa2, 0x07, 0x30, 0xbc, 0x50, 0x1f, 0x22,
			0xfe, 0xf7, 0x28, 0x1a, 0x20, 0x98, 0x4a, 0x14, 0x8e, 0x16,
		];
		assert_eq!(tag.0.as_bytes(), expected);
		Ok(())
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

	/// The client Finished signs its domain label, the transcript hash, and
	/// the SHA3-256 of the DER of the certificate it carries.
	///
	/// The certificate is the fixed self-signed test certificate of the fixed
	/// test key. The expected digest comes from Python's `hashlib` over its
	/// 289 DER bytes, so no code of the crate computes it.
	#[test]
	fn the_client_finished_content_matches_its_known_answer() -> Result<(), HandshakeError> {
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let content = FinishedRole::Client.content::<Sha3_256>(&ack_transcript(), &certificate)?;

		let certificate_digest = [
			0xec, 0x63, 0x63, 0x19, 0xb6, 0x49, 0x60, 0x96, 0x9b, 0x30, 0x74, 0x26, 0xb7, 0x27, 0x61, 0x6a, 0xb7, 0x69,
			0x2d, 0xf9, 0x41, 0xb0, 0xa9, 0x6b, 0x52, 0xa9, 0xc1, 0x3f, 0x1f, 0x07, 0x7b, 0x4c,
		];
		let domain = b"tb/handshake/finished/client/v1".as_slice();
		let expected = [domain, &[0x07u8; 32], &certificate_digest].concat();
		assert_eq!(content, expected);
		Ok(())
	}

	/// The CMS reply carries the server Finished of the HPKE reply, keyed by
	/// the hybrid secret the CMS flow derives: the exchange secret `0x11` × 32,
	/// then the base secret `0x42` × 32, under the transcript hash `0x07` × 32
	/// as the salt.
	///
	/// The expected bytes come from an independent HKDF and HMAC (Python's
	/// `hmac` and `hashlib`), so no code of the crate computes them.
	#[test]
	fn the_cms_server_finished_matches_its_known_answer() -> Result<(), HandshakeError> {
		let transcript_hash = ack_transcript();
		let secret = handshake_secret(0x11, 0x42, transcript_hash.as_bytes());
		let reply = reply_signed_as(REPLY_SIGNATURE.collect::<Vec<_>>());

		let salt = KdfSalt::try_from(transcript_hash.as_bytes())?;
		let server = secret.server_confirmation::<DefaultCryptoProvider>(salt, &transcript_hash, &reply)?;
		let expected = [
			0x73, 0x5f, 0x78, 0x2b, 0xbc, 0x96, 0x70, 0xa1, 0x9c, 0x5e, 0x57, 0xb3, 0xed, 0x51, 0xe3, 0xb2, 0x1b, 0x12,
			0x0d, 0xa0, 0x2c, 0xc2, 0x49, 0xf2, 0xd2, 0x58, 0xf9, 0x0e, 0xa6, 0x36, 0xb1, 0xd9,
		];
		assert_eq!(server.0.as_bytes(), expected);
		Ok(())
	}

	/// The server Finished is HMAC-SHA3-256 over the transcript hash followed
	/// by the octets of the reply's signature, keyed by the 32 bytes
	/// HKDF-SHA3-256 expands under the server Finished label.
	///
	/// The expected bytes come from an independent HKDF and HMAC (Python's
	/// `hmac` and `hashlib`), so a dropped signature or a swapped label fails
	/// here.
	#[test]
	fn the_server_finished_matches_its_known_answer() -> Result<(), HandshakeError> {
		let salt = KdfSalt::try_from(FIXTURE_SALT)?;
		let transcript_hash = ack_transcript();
		let reply = reply_signed_as(REPLY_SIGNATURE.collect::<Vec<_>>());

		let server = fixed_secret().server_confirmation::<DefaultCryptoProvider>(salt, &transcript_hash, &reply)?;
		let expected = [
			0x33, 0x48, 0x7a, 0x72, 0xda, 0x3c, 0xbf, 0xdb, 0x4d, 0xd0, 0xc3, 0x56, 0x75, 0xf7, 0x21, 0x22, 0x02, 0x59,
			0xd5, 0x47, 0x91, 0xde, 0x95, 0x2f, 0xee, 0x6f, 0x01, 0x19, 0xdd, 0xcc, 0x1f, 0xc3,
		];
		assert_eq!(server.0.as_bytes(), expected);
		Ok(())
	}

	/// Under a SHA3-512 provider, the server Finished is HMAC-SHA3-512 over
	/// the 64-byte transcript hash and the signature octets.
	///
	/// The expected bytes come from an independent HKDF and HMAC (Python's
	/// `hmac` and `hashlib`), so a tag or a key cut to 32 bytes fails here.
	#[test]
	fn a_sha3_512_server_finished_matches_its_known_answer() -> Result<(), HandshakeError> {
		let salt = KdfSalt::try_from(FIXTURE_SALT)?;
		let transcript_hash = fixture_transcript::<Sha3_512>([0x07u8; 64]);
		let reply = reply_signed_as(REPLY_SIGNATURE.collect::<Vec<_>>());

		let server = fixed_secret().server_confirmation::<Aes256Sha3_512Provider>(salt, &transcript_hash, &reply)?;
		let expected = [
			0x0c, 0x6b, 0x09, 0x16, 0x69, 0x35, 0x0a, 0xca, 0x9b, 0x76, 0x9f, 0xac, 0xa1, 0x0d, 0xa2, 0xcb, 0x3e, 0xfe,
			0xb5, 0xde, 0x85, 0xb9, 0x38, 0xf1, 0x12, 0x00, 0x8d, 0xcf, 0xad, 0xa1, 0xb5, 0x46, 0x79, 0xd1, 0x8c, 0xda,
			0x7d, 0xc5, 0xe9, 0x40, 0xde, 0xd9, 0x0f, 0x7b, 0xd1, 0xde, 0x6f, 0xc7, 0x00, 0x43, 0xe3, 0x5b, 0x10, 0xa9,
			0xf8, 0x66, 0xb5, 0x82, 0xdc, 0xbb, 0x08, 0xfb, 0x1d, 0xe8,
		];
		assert_eq!(server.0.as_bytes(), expected);
		Ok(())
	}

	/// The two Finished MACs run under two keys: over a reply whose signature
	/// is empty, the server Finished MACs the transcript hash alone, as the
	/// client's tag does, yet the two differ.
	#[test]
	fn the_server_finished_and_the_client_tag_differ_by_key() -> Result<(), HandshakeError> {
		let salt = KdfSalt::try_from(FIXTURE_SALT)?;
		let transcript_hash = ack_transcript();
		let reply = reply_signed_as([]);

		let client = fixed_secret().confirmation::<DefaultCryptoProvider>(salt, &transcript_hash)?;
		let server = fixed_secret().server_confirmation::<DefaultCryptoProvider>(salt, &transcript_hash, &reply)?;
		assert_ne!(client.0.as_bytes(), server.0.as_bytes());
		Ok(())
	}

	/// A secret confirms the server Finished it derives itself, and hands
	/// itself back.
	#[test]
	fn a_server_finished_confirms_its_own_secret() -> Result<(), HandshakeError> {
		let salt = KdfSalt::try_from(FIXTURE_SALT)?;
		let transcript_hash = ack_transcript();
		let reply = reply_signed_as(REPLY_SIGNATURE.collect::<Vec<_>>());
		let server = fixed_secret().server_confirmation::<DefaultCryptoProvider>(salt, &transcript_hash, &reply)?;

		let confirming = HandshakeSecret::confirm_server::<DefaultCryptoProvider>;
		let confirmed = confirming(fixed_secret(), salt, &transcript_hash, &reply, &server)?;
		assert_eq!(confirmed.as_bytes(), fixed_secret().as_bytes());
		Ok(())
	}

	/// A server Finished over the signature of another reply fails, so the
	/// MAC covers the transcript through the signature.
	#[test]
	fn a_server_finished_over_another_signature_is_refused() -> Result<(), HandshakeError> {
		let salt = KdfSalt::try_from(FIXTURE_SALT)?;
		let transcript_hash = ack_transcript();
		let signed = reply_signed_as(REPLY_SIGNATURE.collect::<Vec<_>>());
		let other = reply_signed_as(REPLY_SIGNATURE.rev().collect::<Vec<_>>());
		let server = fixed_secret().server_confirmation::<DefaultCryptoProvider>(salt, &transcript_hash, &signed)?;

		let confirming = HandshakeSecret::confirm_server::<DefaultCryptoProvider>;
		let refused = confirming(fixed_secret(), salt, &transcript_hash, &other, &server);
		assert!(matches!(refused, Err(HandshakeError::KeyConfirmationFailed)));
		Ok(())
	}

	/// The client's tag is no server Finished, so a reflected tag fails.
	#[test]
	fn a_client_tag_is_refused_as_the_server_finished() -> Result<(), HandshakeError> {
		let salt = KdfSalt::try_from(FIXTURE_SALT)?;
		let transcript_hash = ack_transcript();
		let reply = reply_signed_as([]);
		let client = fixed_secret().confirmation::<DefaultCryptoProvider>(salt, &transcript_hash)?;

		let confirming = HandshakeSecret::confirm_server::<DefaultCryptoProvider>;
		let refused = confirming(fixed_secret(), salt, &transcript_hash, &reply, &client);
		assert!(matches!(refused, Err(HandshakeError::KeyConfirmationFailed)));
		Ok(())
	}

	/// The one signer of a fresh test `SignedData`.
	fn fresh_signer() -> SignerInfo {
		let signers = create_test_signed_data(b"reply").signer_infos.0.into_vec();
		let [signer] = <[SignerInfo; 1]>::try_from(signers).expect("a test SignedData has one signer");
		signer
	}

	/// The server Finished refuses a reply of two signers, because the reply
	/// has one signature to cover.
	#[test]
	fn a_server_finished_over_two_signers_is_refused() -> Result<(), Box<dyn core::error::Error>> {
		let salt = KdfSalt::try_from(FIXTURE_SALT)?;
		let mut reply = create_test_signed_data(b"reply");
		reply.signer_infos.0.insert(fresh_signer())?;

		let refused = fixed_secret().server_confirmation::<DefaultCryptoProvider>(salt, &ack_transcript(), &reply);
		assert!(matches!(refused, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// A tag of another digest's width fails the comparison, so a peer under
	/// another digest confirms nothing.
	#[test]
	fn a_key_confirmation_of_another_width_is_refused() -> Result<(), HandshakeError> {
		let salt = KdfSalt::try_from(FIXTURE_SALT)?;
		let transcript_hash = ack_transcript();
		let tag = fixed_secret().confirmation::<DefaultCryptoProvider>(salt, &transcript_hash)?;
		let wide = KeyConfirmation(DigestOutput::parse([tag.0.as_bytes(), tag.0.as_bytes()].concat())?);

		let refused = tag.verify(&wide);
		assert!(matches!(refused, Err(HandshakeError::KeyConfirmationFailed)));
		Ok(())
	}

	/// A received tag decodes at the width of a 512-bit digest.
	#[test]
	fn a_64_byte_key_confirmation_decodes() -> Result<(), Box<dyn core::error::Error>> {
		let der = OctetString::new([0x07u8; 64])?.to_der()?;

		let decoded = KeyConfirmation::from_der(&der)?;
		assert_eq!(decoded.0.as_bytes(), [0x07u8; 64]);
		Ok(())
	}

	/// A received tag wider than any digest output the handshake runs fails
	/// to decode.
	#[test]
	fn a_key_confirmation_wider_than_64_bytes_fails_to_decode() -> Result<(), Box<dyn core::error::Error>> {
		let der = OctetString::new([0x07u8; 65])?.to_der()?;

		let refused = KeyConfirmation::from_der(&der);
		assert!(refused.is_err());
		Ok(())
	}

	/// A tag verifies against itself and against no other tag.
	#[test]
	fn a_key_confirmation_verifies_against_itself_alone() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x11, 0x42, &salt);
		let other = handshake_secret(0x12, 0x42, &salt);
		let transcript_hash = ack_transcript();
		let kdf_salt = KdfSalt::try_from(salt.as_slice())?;

		let tag = secret.confirmation::<DefaultCryptoProvider>(kdf_salt, &transcript_hash)?;
		let same = secret.confirmation::<DefaultCryptoProvider>(kdf_salt, &transcript_hash)?;
		let foreign = other.confirmation::<DefaultCryptoProvider>(kdf_salt, &transcript_hash)?;
		assert!(tag.verify(&same).is_ok());
		assert!(matches!(tag.verify(&foreign), Err(HandshakeError::KeyConfirmationFailed)));
		Ok(())
	}

	/// The sealer of `purpose` under `secret`, the fixture salt, and
	/// `transcript_hash`.
	fn sealer_of(
		secret: &HandshakeSecret,
		purpose: SecretSeal,
		transcript_hash: &TranscriptHash,
	) -> Sealer<DefaultCryptoProvider> {
		let salt = [0x99u8; 32];
		let salt = KdfSalt::try_from(salt.as_slice()).expect("the fixture salt meets the floor");
		let sealer = secret.sealer::<DefaultCryptoProvider>(purpose, salt, transcript_hash);
		sealer.expect("the fixture secret derives a sealer")
	}

	/// A fixed handshake secret, so a known-answer vector reads no KDF of the
	/// handshake itself.
	fn fixed_secret() -> HandshakeSecret {
		HandshakeSecret(ZeroizingBytes::new(vec![0x42u8; 32]))
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
		assert_eq!(ack_encoding_refusal(refused), Some(ErrorKind::SetOrdering));
	}

	/// The kind of the DER error that refused an acknowledgement, or `None`
	/// for another outcome.
	fn ack_encoding_refusal<T>(outcome: Result<T, HandshakeError>) -> Option<ErrorKind> {
		match outcome {
			Err(HandshakeError::ReceiptAckCipher(EnvelopeError::Encoding(error))) => Some(error.kind()),
			_ => None,
		}
	}

	/// An acknowledgement sealed under one handshake secret opens under the
	/// same secret, salt, and transcript.
	#[tokio::test]
	async fn a_sealed_ack_opens_under_the_same_handshake_secret() -> Result<(), HandshakeError> {
		let secret = fixed_secret();
		let sealed = sealer_of(&secret, SecretSeal::Ack, &ack_transcript()).seal(DATA, b"settlement answer")?;

		let opener = sealer_of(&secret, SecretSeal::Ack, &ack_transcript());
		let opened = opener.open(WireDer::new(sealed)?, DATA).await?;
		assert!(opened.with(|bytes| bytes.as_slice() == b"settlement answer"));
		Ok(())
	}

	/// An acknowledgement sealed under one handshake secret does not open
	/// under another, so a recorded session plus the base secret alone reads
	/// nothing.
	#[tokio::test]
	async fn a_sealed_ack_refuses_another_handshake_secret() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x11, 0x42, &salt);
		let other = handshake_secret(0x12, 0x42, &salt);
		let sealed = sealer_of(&secret, SecretSeal::Ack, &ack_transcript()).seal(DATA, b"settlement answer")?;

		let opener = sealer_of(&other, SecretSeal::Ack, &ack_transcript());
		let refused = opener.open(WireDer::new(sealed)?, DATA).await;
		assert!(matches!(
			refused,
			Err(HandshakeError::ReceiptAckCipher(EnvelopeError::KeyUnwrap))
		));
		Ok(())
	}

	/// An acknowledgement sealed over one transcript does not open under
	/// another, so the envelope commits to the session it closes.
	#[tokio::test]
	async fn a_sealed_ack_refuses_another_transcript() -> Result<(), HandshakeError> {
		let secret = fixed_secret();
		let other_transcript = fixture_transcript::<Sha3_256>([0x08u8; 32]);
		let sealed = sealer_of(&secret, SecretSeal::Ack, &ack_transcript()).seal(DATA, b"settlement answer")?;

		let opener = sealer_of(&secret, SecretSeal::Ack, &other_transcript);
		let refused = opener.open(WireDer::new(sealed)?, DATA).await;
		assert!(matches!(
			refused,
			Err(HandshakeError::ReceiptAckCipher(EnvelopeError::AuthenticatedAttribute))
		));
		Ok(())
	}

	/// The opener refuses a seal whose transcript hash attribute names another
	/// transcript before its content decrypts, though its `kekid` is the
	/// opener's.
	#[tokio::test]
	async fn a_seal_whose_transcript_attribute_differs_is_refused() -> Result<(), HandshakeError> {
		let secret = fixed_secret();
		let sealed = sealer_of(&secret, SecretSeal::Ack, &ack_transcript()).seal(DATA, b"settlement answer")?;
		let other_transcript = fixture_transcript::<Sha3_256>([0x08u8; 32]);
		let sealed = with_transcript_attribute(sealed, &other_transcript);

		let opener = sealer_of(&secret, SecretSeal::Ack, &ack_transcript());
		let refused = opener.open(WireDer::new(sealed)?, DATA).await;
		assert!(matches!(
			refused,
			Err(HandshakeError::ReceiptAckCipher(EnvelopeError::AuthenticatedAttribute))
		));
		Ok(())
	}

	/// A seal binds every byte of a 64-byte transcript hash, so it refuses a
	/// hash that differs in its last byte alone.
	#[tokio::test]
	async fn a_seal_refuses_a_64_byte_transcript_that_differs_in_its_last_byte() -> Result<(), HandshakeError> {
		let transcript = fixture_transcript::<Sha3_512>([0x07u8; 64]);
		let last_byte_differs = fixture_transcript::<Sha3_512>([[0x07u8; 63].as_slice(), &[0x08u8]].concat());
		let sealed = sealer_of(&fixed_secret(), SecretSeal::Ack, &transcript).seal(DATA, b"settlement answer")?;

		let opener = sealer_of(&fixed_secret(), SecretSeal::Ack, &last_byte_differs);
		let refused = opener.open(WireDer::new(sealed)?, DATA).await;
		assert!(matches!(
			refused,
			Err(HandshakeError::ReceiptAckCipher(EnvelopeError::AuthenticatedAttribute))
		));
		Ok(())
	}

	/// The acknowledgement key-encryption key is HKDF-SHA3-256 of the
	/// handshake secret under the salt and the acknowledgement label.
	///
	/// The expected bytes come from an independent HKDF (Python's `hmac` and
	/// `hashlib`), so no code of the crate computes them.
	#[test]
	fn the_ack_key_matches_its_known_answer() {
		let sealer = sealer_of(&fixed_secret(), SecretSeal::Ack, &ack_transcript());

		let expected = [
			0x3a, 0x57, 0xc8, 0x95, 0xdc, 0xad, 0xc1, 0x14, 0x41, 0x26, 0x35, 0xe7, 0xe5, 0x19, 0xb6, 0xec, 0xc5, 0x31,
			0xe2, 0x07, 0x54, 0xfe, 0x04, 0xde, 0x83, 0x78, 0xe1, 0xd8, 0xf4, 0xa4, 0xe4, 0xb5,
		];
		assert_eq!(sealer.kek.kek().as_array().as_slice(), expected);
	}

	/// The closing key-encryption key is HKDF-SHA3-256 of the handshake
	/// secret under the salt and the closing label.
	///
	/// The expected bytes come from an independent HKDF (Python's `hmac` and
	/// `hashlib`), so no code of the crate computes them.
	#[test]
	fn the_closing_key_matches_its_known_answer() {
		let sealer = sealer_of(&fixed_secret(), SecretSeal::Closing, &ack_transcript());

		let expected = [
			0x0c, 0x7c, 0x84, 0x0e, 0x00, 0x15, 0xfb, 0x07, 0xee, 0x63, 0x5c, 0x21, 0xdb, 0x3f, 0xd7, 0x53, 0x20, 0x16,
			0x7d, 0xe5, 0x85, 0xbf, 0xae, 0x2d, 0x72, 0x6d, 0x23, 0x3a, 0x90, 0x11, 0xc5, 0x2d,
		];
		assert_eq!(sealer.kek.kek().as_array().as_slice(), expected);
	}

	/// The `kekid` of a seal is its purpose domain followed by the transcript
	/// hash.
	#[test]
	fn a_seal_names_its_key_by_its_purpose_and_its_transcript() -> Result<(), HandshakeError> {
		let sealed = sealer_of(&fixed_secret(), SecretSeal::Ack, &ack_transcript()).seal(DATA, b"settlement answer")?;

		let expected = [TIGHTBEAM_ACK_KEY_ID_DOMAIN, [0x07u8; 32].as_slice()].concat();
		assert_eq!(key_identifier_of(&sealed), expected);
		Ok(())
	}

	/// A seal carries the transcript hash as an authenticated attribute.
	#[test]
	fn a_seal_authenticates_its_transcript_hash() -> Result<(), HandshakeError> {
		let sealed = sealer_of(&fixed_secret(), SecretSeal::Ack, &ack_transcript()).seal(DATA, b"settlement answer")?;
		let attrs = sealed.auth_attrs.as_ref();
		let carried = attrs.into_iter().flat_map(|attrs| attrs.iter());
		let mut named = carried.filter(|attribute| attribute.oid == HANDSHAKE_TRANSCRIPT_HASH);

		let value = named.next().and_then(|attribute| attribute.values.iter().next());
		let hash = value.map(|value| value.decode_as::<OctetString>()).transpose()?;
		assert_eq!(hash.as_ref().map(OctetString::as_bytes), Some([0x07u8; 32].as_slice()));
		Ok(())
	}

	/// An acknowledgement seals bare, so its encrypted content is as long as
	/// the plaintext.
	#[test]
	fn an_ack_seals_unframed() -> Result<(), HandshakeError> {
		let sealed = sealer_of(&fixed_secret(), SecretSeal::Ack, &ack_transcript()).seal(DATA, b"settlement answer")?;
		assert_eq!(content_len(&sealed), Some(b"settlement answer".len()));
		Ok(())
	}

	/// The closing seal frames the plaintext with its length and pads it with
	/// zero bytes to 1024, so its encrypted content is 1024 octets.
	#[test]
	fn a_closing_seals_padded_to_the_floor() -> Result<(), HandshakeError> {
		let sealer = sealer_of(&fixed_secret(), SecretSeal::Closing, &ack_transcript());
		let sealed = sealer.seal(DATA, b"client identity")?;
		assert_eq!(content_len(&sealed), Some(1024));
		Ok(())
	}

	/// The open of a closing strips the frame and returns the plaintext.
	#[tokio::test]
	async fn a_sealed_closing_opens_to_its_plaintext() -> Result<(), HandshakeError> {
		let secret = fixed_secret();
		let sealed = sealer_of(&secret, SecretSeal::Closing, &ack_transcript()).seal(DATA, b"client identity")?;

		let opener = sealer_of(&secret, SecretSeal::Closing, &ack_transcript());
		let opened = opener.open(WireDer::new(sealed)?, DATA).await?;

		assert!(opened.with(|bytes| bytes.as_slice() == b"client identity"));
		Ok(())
	}

	/// Two closings whose lengths differ within one padding step seal to one
	/// length, so the length does not tell the two clients apart.
	#[test]
	fn two_closings_within_one_step_seal_to_one_length() -> Result<(), HandshakeError> {
		let secret = fixed_secret();

		let short = sealer_of(&secret, SecretSeal::Closing, &ack_transcript()).seal(DATA, [0x01u8; 600])?;
		let long = sealer_of(&secret, SecretSeal::Closing, &ack_transcript()).seal(DATA, [0x01u8; 900])?;
		assert_eq!(short.to_der()?.len(), long.to_der()?.len());
		Ok(())
	}

	/// A closing past the floor pads to the next step.
	#[test]
	fn a_closing_past_the_floor_pads_to_the_next_step() -> Result<(), HandshakeError> {
		let sealed = sealer_of(&fixed_secret(), SecretSeal::Closing, &ack_transcript()).seal(DATA, [0x01u8; 1100])?;
		assert_eq!(content_len(&sealed), Some(1536));
		Ok(())
	}

	/// The two purposes derive two keys, so a closing does not open under the
	/// acknowledgement key.
	#[tokio::test]
	async fn a_closing_does_not_open_under_the_ack_key() -> Result<(), HandshakeError> {
		let secret = fixed_secret();
		let sealed = sealer_of(&secret, SecretSeal::Closing, &ack_transcript()).seal(DATA, b"client identity")?;

		let opener = sealer_of(&secret, SecretSeal::Ack, &ack_transcript());
		let refused = opener.open(WireDer::new(sealed)?, DATA).await;
		assert!(matches!(
			refused,
			Err(HandshakeError::ReceiptAckCipher(EnvelopeError::KeyIdentifier))
		));
		Ok(())
	}

	/// `unframe` refuses a frame of its padded length whose padding holds a
	/// non-zero byte.
	#[test]
	fn a_frame_with_a_non_zero_pad_is_refused() {
		let mut framed = vec![0x00u8; 1024];
		framed[..3].copy_from_slice(&[0x00, 0x01, 0xaa]);
		framed[1023] = 0x01;

		let refused = SecretSeal::Closing.unframe(&framed);
		assert!(matches!(refused, Err(HandshakeError::SealedFrame)));
	}

	/// `unframe` refuses a frame whose length runs past its end.
	#[test]
	fn a_frame_whose_length_runs_past_its_end_is_refused() {
		let framed = [0x00, 0x09, 0xaa, 0x00];
		let refused = SecretSeal::Closing.unframe(&framed);
		assert!(matches!(refused, Err(HandshakeError::SealedFrame)));
	}

	/// `unframe` refuses a frame that holds its plaintext and zero bytes but
	/// runs past its padded length.
	#[test]
	fn a_frame_longer_than_its_padded_length_is_refused() {
		let mut framed = vec![0x00u8; 1536];
		framed[..3].copy_from_slice(&[0x00, 0x01, 0xaa]);

		let refused = SecretSeal::Closing.unframe(&framed);
		assert!(matches!(refused, Err(HandshakeError::SealedFrame)));
	}

	/// A closing whose length prefix carries its frame past the floor opens to
	/// its plaintext.
	#[tokio::test]
	async fn a_closing_whose_prefix_crosses_the_floor_opens() -> Result<(), HandshakeError> {
		let secret = fixed_secret();
		let identity = [0x01u8; 1023];
		let sealed = sealer_of(&secret, SecretSeal::Closing, &ack_transcript()).seal(DATA, identity)?;

		let opener = sealer_of(&secret, SecretSeal::Closing, &ack_transcript());
		let opened = opener.open(WireDer::new(sealed)?, DATA).await?;

		assert!(opened.with(|bytes| bytes.as_slice() == identity));
		Ok(())
	}

	/// `unframe` refuses a frame that holds its plaintext and zero bytes but
	/// falls short of its padded length.
	#[test]
	fn a_frame_shorter_than_its_padded_length_is_refused() {
		let framed = [0x00, 0x01, 0xaa, 0x00];
		let refused = SecretSeal::Closing.unframe(&framed);
		assert!(matches!(refused, Err(HandshakeError::SealedFrame)));
	}

	/// The seal refuses a closing past the `u16` length of the frame.
	#[test]
	fn a_closing_past_the_frame_length_is_refused() {
		let oversized = vec![0x01u8; usize::from(u16::MAX) + 1];
		let refused = sealer_of(&fixed_secret(), SecretSeal::Closing, &ack_transcript()).seal(DATA, oversized);
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

	#[test]
	fn test_derive_directional_aead_directions_differ() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x11, 0x42, &salt);
		let ciphers = derive_directional(&secret, &salt)?;

		// The info labels separate the keys, so a record of one direction
		// does not open under the other, even named as the first.
		let record = sealed_under(ciphers.client_to_server, b"directional key separation");
		let crossed = opened_under(ciphers.server_to_client, &record);
		assert!(matches!(
			crossed,
			Err(crate::TightBeamError::EnvelopeError(EnvelopeError::KeyUnwrap))
		));
		Ok(())
	}

	#[test]
	fn test_derive_directional_aead_is_deterministic() -> Result<(), crate::TightBeamError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x11, 0x42, &salt);
		let first = derive_directional(&secret, &salt)?;
		let second = derive_directional(&secret, &salt)?;

		// Both derivations agree, so two independent endpoints derive the
		// same directional keys from shared input material.
		let record = sealed_under(first.client_to_server, b"deterministic derivation");
		let opened = opened_under(second.client_to_server, &record)?;
		assert_eq!(opened, b"deterministic derivation");
		Ok(())
	}

	#[test]
	fn test_derive_directional_aead_insufficient_salt() {
		let salt = [0x99u8; 8];
		let secret = handshake_secret(0x11, 0x42, &[0x99u8; 32]);
		let result = derive_directional(&secret, &salt);
		assert!(matches!(
			result,
			Err(HandshakeError::InsufficientSaltEntropy { actual: 8, minimum: 16 })
		));
	}

	/// The terms of a fixture handshake over `transcript_hash` under `salt`.
	fn terms_with(transcript_hash: &TranscriptHash, salt: Salt) -> Terms<DefaultCryptoProvider> {
		Terms::new(RunnableProfile::native(), None, *transcript_hash, salt)
	}

	/// The terms derive one key per purpose, so a closing they seal does not
	/// open under their acknowledgement key.
	#[tokio::test]
	async fn the_terms_seal_each_purpose_under_its_own_key() -> Result<(), HandshakeError> {
		let terms = terms_with(&ack_transcript(), Salt::transcript_hash());
		let secret = fixed_secret();
		let sealed = terms.sealer(&secret, SecretSeal::Closing)?.seal(DATA, b"client identity")?;

		let refused = terms.sealer(&secret, SecretSeal::Ack)?.open(WireDer::new(sealed)?, DATA).await;
		assert!(matches!(
			refused,
			Err(HandshakeError::ReceiptAckCipher(EnvelopeError::KeyIdentifier))
		));
		Ok(())
	}

	/// A CMS handshake salts every derivation with its transcript hash.
	#[test]
	fn a_transcript_salt_is_the_transcript_hash() -> Result<(), KdfError> {
		let terms = terms_with(&ack_transcript(), Salt::transcript_hash());
		let salt = terms.kdf_salt()?;
		assert_eq!(salt.as_bytes(), [0x07u8; 32]);
		Ok(())
	}

	/// A CMS handshake under a 512-bit digest salts every derivation with all
	/// 64 bytes of its transcript hash.
	#[test]
	fn a_transcript_salt_carries_all_64_bytes_of_the_hash() -> Result<(), KdfError> {
		let transcript = fixture_transcript::<Sha3_512>([0x07u8; 64]);
		let terms = terms_with(&transcript, Salt::transcript_hash());
		let salt = terms.kdf_salt()?;
		assert_eq!(salt.as_bytes(), [0x07u8; 64]);
		Ok(())
	}

	/// An HPKE handshake salts every derivation with the client random
	/// followed by the server random.
	#[test]
	fn a_randoms_salt_is_the_client_random_then_the_server_random() -> Result<(), KdfError> {
		let terms = terms_with(&ack_transcript(), Salt::randoms(&[0x01u8; 32], &[0x02u8; 32]));
		let salt = terms.kdf_salt()?;
		assert_eq!(salt.as_bytes(), [[0x01u8; 32], [0x02u8; 32]].concat());
		Ok(())
	}

	#[cfg(mux_rekey)]
	#[test]
	fn test_derive_epoch_materials_shape() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x11, 0x42, &salt);
		let transcript = ack_transcript();
		let kdf_salt = KdfSalt::try_from(salt.as_slice())?;

		let materials = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, kdf_salt, transcript)?;
		assert_eq!(materials.epoch(), 0);
		assert_eq!(materials.transcript_hash(), transcript);
		assert_eq!(materials.secret.as_bytes().len(), EPOCH_SECRET_SIZE);

		Ok(())
	}

	#[cfg(mux_rekey)]
	#[test]
	fn test_derive_epoch_materials_is_deterministic() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x11, 0x42, &salt);
		let transcript = ack_transcript();
		let kdf_salt = KdfSalt::try_from(salt.as_slice())?;

		let first = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, kdf_salt, transcript)?;
		let second = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, kdf_salt, transcript)?;
		assert_eq!(first.secret.as_bytes(), second.secret.as_bytes());

		Ok(())
	}

	#[cfg(mux_rekey)]
	#[test]
	fn test_derive_epoch_materials_separates_inputs() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let other_salt = [0x9Au8; 32];
		let secret = handshake_secret(0x11, 0x42, &salt);
		let other_secret = handshake_secret(0x11, 0x43, &salt);
		let transcript = ack_transcript();

		let shared_salt = KdfSalt::try_from(salt.as_slice())?;
		let changed_salt = KdfSalt::try_from(other_salt.as_slice())?;
		let base = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, shared_salt, transcript)?;
		let keyed = EpochMaterials::derive::<DefaultCryptoProvider>(&other_secret, shared_salt, transcript)?;
		let salted = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, changed_salt, transcript)?;
		assert_ne!(base.secret.as_bytes(), keyed.secret.as_bytes());
		assert_ne!(base.secret.as_bytes(), salted.secret.as_bytes());

		Ok(())
	}

	/// An install moves the counter by one and roots the chain at the hash of
	/// the exchange, so the next pin and the next advance read the link it
	/// installed.
	#[cfg(mux_rekey)]
	#[test]
	fn an_install_advances_the_epoch_by_one_under_the_next_hash() -> Result<(), HandshakeError> {
		let secret = EpochSecret(ZeroizingBytes::new(vec![0x42u8; 32]));
		let mut materials = EpochMaterials { secret, epoch: 0, transcript_hash: ack_transcript() };
		let next = EpochSecret(ZeroizingBytes::new(vec![0x43u8; 32]));
		let next_hash = fixture_transcript::<Sha3_256>([0x08u8; 32]);

		let _ciphers = materials.install::<DefaultCryptoProvider>(next, KdfSalt::try_from(FIXTURE_SALT)?, next_hash)?;
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
			let salt = KdfSalt::try_from(FIXTURE_SALT)?;

			let published = agreement.as_ref().with(<[u8]>::to_vec);
			let hpke = HandshakeSecret::ephemeral::<HouseOn<C>>(agreement.as_ref(), salt)?;
			let cms = HandshakeSecret::hybrid::<HouseOn<C>>(agreement.as_ref(), &base_secret(0x42), salt)?;
			let epoch = EpochSecret(ZeroizingBytes::new(vec![0x42u8; 32]));
			let rekey = epoch.next::<HouseOn<C>>(agreement, KdfSalt::try_from([0x99u8; 64].as_slice())?)?;
			Ok(Self {
				agreement: published,
				hpke: hpke.as_bytes().to_vec(),
				cms: cms.as_bytes().to_vec(),
				rekey: rekey.0.to_vec(),
			})
		}
	}

	/// On secp256k1 the agreement is 32 bytes, and the schedule derives the
	/// known answers of [`SECP256K1_AGREEMENT`].
	///
	/// The expected bytes come from an independent ECDH and HKDF (Python's
	/// `cryptography`, `hmac`, and `hashlib`).
	#[cfg(mux_rekey)]
	#[test]
	fn a_secp256k1_agreement_derives_its_known_answers() -> Result<(), HandshakeError> {
		let scheduled = Scheduled::on::<Secp256k1>()?;
		assert_eq!(scheduled, Scheduled::published(&SECP256K1_AGREEMENT));
		Ok(())
	}

	/// On P-256 the agreement is 32 bytes, and the schedule derives the known
	/// answers of [`P256_AGREEMENT`].
	///
	/// The expected bytes come from an independent ECDH and HKDF (Python's
	/// `cryptography`, `hmac`, and `hashlib`).
	#[cfg(mux_rekey)]
	#[test]
	fn a_p256_agreement_derives_its_known_answers() -> Result<(), HandshakeError> {
		let scheduled = Scheduled::on::<NistP256>()?;
		assert_eq!(scheduled, Scheduled::published(&P256_AGREEMENT));
		Ok(())
	}

	/// On P-384 the agreement is the whole 48-byte x-coordinate, and each
	/// derivation takes all of it: the CMS secret extracts from 80 bytes.
	///
	/// The expected bytes come from an independent ECDH and HKDF (Python's
	/// `cryptography`, `hmac`, and `hashlib`).
	#[cfg(mux_rekey)]
	#[test]
	fn a_p384_agreement_derives_its_known_answers() -> Result<(), HandshakeError> {
		let scheduled = Scheduled::on::<NistP384>()?;
		assert_eq!(scheduled, Scheduled::published(&P384_AGREEMENT));
		Ok(())
	}

	/// On P-521 the agreement is the whole 66-byte x-coordinate, and each
	/// derivation takes all of it: the CMS secret extracts from 98 bytes.
	///
	/// The expected bytes come from an independent ECDH and HKDF (Python's
	/// `cryptography`, `hmac`, and `hashlib`).
	#[cfg(mux_rekey)]
	#[test]
	fn a_p521_agreement_derives_its_known_answers() -> Result<(), HandshakeError> {
		let scheduled = Scheduled::on::<NistP521>()?;
		assert_eq!(scheduled, Scheduled::published(&P521_AGREEMENT));
		Ok(())
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
