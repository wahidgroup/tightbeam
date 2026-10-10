//! The key schedule of a handshake.
//!
//! Both flows and both roles derive through these owners:
//!
//! - [`Agreement`] derives the [`HandshakeSecret`], the one secret a session
//!   derives from, out of a [`BaseSecret`] and the [`EcdhSecret`] that
//!   [`HandshakeAgreement`] produces.
//! - [`Terms`] holds what negotiation fixed: the profile, the multiplexing
//!   terms, the transcript hash, and the protocol's salt.
//! - [`Agreed`] derives everything a session takes from the handshake secret.
//!
//! # Key schedule
//!
//! Both protocols and both roles run the same schedule. `base` is the random
//! secret the client seals to the server's static key, `ee` is the
//! ephemeral-ephemeral ECDH output, `S` is the protocol's salt, and `u32be(n)`
//! is the 4-byte big-endian length prefix of the input that follows it.
//!
//! ```text
//! hs      = HKDF(u32be(32) || base || u32be(32) || ee, salt = S, info = "tb/session/kdf/v1")
//! k_c2s   = HKDF(hs, S, "tb/session/kdf/c2s/v1")
//! k_s2c   = HKDF(hs, S, "tb/session/kdf/s2c/v1")
//! epoch_0 = HKDF(hs, S, "tb/session/kdf/epoch/v1")
//! k_ack   = HKDF(hs, S, "tb/session/kdf/ack/v1")
//! confirm = HKDF(hs, S, "tb/session/kdf/confirm/v1" || transcript_hash)
//! ```
//!
//! [Forward secrecy](crate::transport::handshake#forward-secrecy) states what
//! this schedule withholds from a holder of the server's static key.

use core::fmt;

#[cfg(all(
	not(feature = "std"),
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use alloc::vec::Vec;

#[cfg(any(
	feature = "transport-ecies",
	all(feature = "transport-cms", feature = "transport-multiplex")
))]
use crate::constants::EC_PUBKEY_COMPRESSED_SIZE;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::constants::{
	MIN_SALT_ENTROPY_BYTES, TIGHTBEAM_ACK_AAD_DOMAIN, TIGHTBEAM_ACK_KDF_INFO, TIGHTBEAM_C2S_KDF_INFO,
	TIGHTBEAM_CONFIRM_KDF_INFO, TIGHTBEAM_EPOCH_KDF_INFO, TIGHTBEAM_S2C_KDF_INFO, TIGHTBEAM_SESSION_KDF_INFO,
};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::aead::{Aead, DirectionalCiphers, KeyInit, Nonce, Payload, SessionKeys};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::common::KeySizeUser;
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use crate::crypto::hash::Digest;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::kdf::{EcdhSecret, KdfFunction};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::profiles::CryptoProvider;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::secret::SecretSlice;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::sign::elliptic_curve::ecdh::{diffie_hellman, EphemeralSecret};
#[cfg(any(
	feature = "transport-ecies",
	all(feature = "transport-cms", feature = "transport-multiplex")
))]
use crate::crypto::sign::elliptic_curve::sec1::ToEncodedPoint;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::sign::elliptic_curve::{CurveArithmetic, PublicKey, SecretKey};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::subtle::ConstantTimeEq;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::x509::utils::CertificateExt;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::der::asn1::OctetStringRef;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Result as DerResult, Tag, Writer};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::random::{generate_nonce, CryptoRngCore};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::error::HandshakeError;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::negotiation::{MuxSettings, RunnableProfile};
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use crate::transport::handshake::primitives::transcript::Transcript;
#[cfg(feature = "transport-ecies")]
use crate::transport::handshake::primitives::RandomsSalt;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::primitives::{multi_input_kdf, KdfInfo, KdfSalt};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::receipt::StoredReceipt;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::{Arc, EstablishedSession, HandshakeCurve, HandshakeProvider};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::utils::marker::{MaybeSend, MaybeSync};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::x509::Certificate;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::{ZeroizingArray, ZeroizingBytes};

/// The 32-byte random secret the client seals to the server's static key.
///
/// It is one of the two inputs of [`HandshakeSecret::derive`]. ECIES carries
/// it inside the key-exchange payload, and CMS as the content of the
/// key-exchange envelope. The length is part of the type, so a parse that
/// lands here has already refused every other length.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) struct BaseSecret(ZeroizingArray<BASE_SECRET_SIZE>);

/// Base secret length in bytes.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
const BASE_SECRET_SIZE: usize = 32;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl BaseSecret {
	/// Draw a fresh base secret from `rng`, or from the OS random source when
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

/// Parse the opened key-exchange content as the base secret.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
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

		// The copy lands in its wiping buffer directly, so no plain array of
		// the secret exists on the way (CWE-226).
		let mut sized = ZeroizingArray::new([0u8; BASE_SECRET_SIZE]);
		content.with(|bytes| sized.copy_from_slice(bytes));
		Ok(Self(sized))
	}
}

/// The secret both endpoints agree on: the client's base secret and the
/// ephemeral-ephemeral ECDH output, extracted under the protocol salt.
///
/// Every session key derives from this one value, and the crate's one
/// constructor for it takes the two inputs named above.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub struct HandshakeSecret(ZeroizingBytes);

/// Handshake secret length in bytes.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
const HANDSHAKE_SECRET_SIZE: usize = 32;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl HandshakeSecret {
	/// Derive the handshake secret from `base` and the ephemeral-ephemeral
	/// ECDH output `shared`, extracted under `salt`.
	///
	/// [`Agreement::settle`] is its one caller. The two inputs enter
	/// [`multi_input_kdf`] length-prefixed, in this order.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
	/// - [`HandshakeError::IntegerOutOfRange`] -- an input exceeds the framing prefix.
	fn derive<P>(base: &BaseSecret, shared: &EcdhSecret, salt: KdfSalt<'_>) -> Result<Self, HandshakeError>
	where
		P: CryptoProvider,
	{
		let label = KdfInfo::new(TIGHTBEAM_SESSION_KDF_INFO);
		let secret = shared.with(|shared| {
			let inputs: [&[u8]; 2] = [base.as_bytes(), shared];
			multi_input_kdf::<P>(&inputs, salt, label, HANDSHAKE_SECRET_SIZE)
		})?;
		Ok(Self(secret))
	}

	/// Seal the receipt acknowledgement under a key derived from this secret,
	/// bound to the transcript it answers.
	///
	/// - The key is `HKDF(hs, salt, "tb/session/kdf/ack/v1")` at the negotiated AEAD key size.
	/// - One acknowledgement travels per handshake, so the key is single-use
	///   and the nonce is fixed at zero (RFC 5116 § 3.2).
	/// - The associated data is [`TIGHTBEAM_ACK_AAD_DOMAIN`] followed by
	///   `transcript_hash`, so the ciphertext commits to the session it closes.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the key length.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused the derived key.
	/// - [`HandshakeError::ReceiptAckCipher`] -- the AEAD refused to seal.
	pub(crate) fn seal_ack<P>(
		&self,
		salt: KdfSalt<'_>,
		transcript_hash: &[u8; 32],
		plaintext: impl AsRef<[u8]>,
	) -> Result<Vec<u8>, HandshakeError>
	where
		P: CryptoProvider,
		P::AeadCipher: KeyInit,
	{
		let cipher = self.ack_cipher::<P>(salt)?;
		let nonce = Nonce::<P::AeadCipher>::default();
		let aad = Self::ack_aad(transcript_hash);
		let payload = Payload { msg: plaintext.as_ref(), aad: &aad };
		cipher.encrypt(&nonce, payload).map_err(HandshakeError::ReceiptAckCipher)
	}

	/// Open a receipt acknowledgement that [`Self::seal_ack`] sealed over
	/// `transcript_hash`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the key length.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused the derived key.
	/// - [`HandshakeError::ReceiptAckCipher`] -- the AEAD refused the
	///   ciphertext, so it was sealed under another handshake secret or another
	///   transcript, or altered in flight.
	pub(crate) fn open_ack<P>(
		&self,
		salt: KdfSalt<'_>,
		transcript_hash: &[u8; 32],
		ciphertext: impl AsRef<[u8]>,
	) -> Result<SecretSlice<u8>, HandshakeError>
	where
		P: CryptoProvider,
		P::AeadCipher: KeyInit,
	{
		let cipher = self.ack_cipher::<P>(salt)?;
		let nonce = Nonce::<P::AeadCipher>::default();
		let aad = Self::ack_aad(transcript_hash);
		let payload = Payload { msg: ciphertext.as_ref(), aad: &aad };

		let plaintext = cipher.decrypt(&nonce, payload).map_err(HandshakeError::ReceiptAckCipher)?;
		Ok(SecretSlice::from(plaintext))
	}

	/// Derive the key-confirmation tag of this secret over `transcript_hash`.
	///
	/// The tag is `HKDF(hs, salt, info)`, where `info` is
	/// [`TIGHTBEAM_CONFIRM_KDF_INFO`] followed by `transcript_hash`. It proves
	/// that its sender derived this secret for this transcript, and it yields
	/// nothing of either (NIST SP 800-56A Rev. 3 § 5.9).
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
	pub(crate) fn confirmation<P>(
		&self,
		salt: KdfSalt<'_>,
		transcript_hash: &[u8; 32],
	) -> Result<KeyConfirmation, HandshakeError>
	where
		P: CryptoProvider,
	{
		let info = [TIGHTBEAM_CONFIRM_KDF_INFO, transcript_hash.as_slice()].concat();
		let tag = P::Kdf::derive_key::<KEY_CONFIRMATION_SIZE>(&self.0, &info, Some(salt.as_bytes()))?;
		Ok(KeyConfirmation(*tag))
	}

	/// Verify that `received` is the key-confirmation tag of this secret over
	/// `transcript_hash`, and hand the secret back as confirmed.
	///
	/// The secret is consumed, so a caller that holds a [`ConfirmedSecret`]
	/// holds no unconfirmed copy beside it.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
	/// - [`HandshakeError::KeyConfirmationFailed`] -- the tags differ, so the
	///   peer derived another handshake secret or confirmed another transcript.
	pub(crate) fn confirmed<P>(
		self,
		salt: KdfSalt<'_>,
		transcript_hash: &[u8; 32],
		received: &KeyConfirmation,
	) -> Result<ConfirmedSecret, HandshakeError>
	where
		P: CryptoProvider,
	{
		let expected = self.confirmation::<P>(salt, transcript_hash)?;
		expected.verify(received)?;

		Ok(ConfirmedSecret(self))
	}

	/// The associated data of the acknowledgement seal:
	/// [`TIGHTBEAM_ACK_AAD_DOMAIN`] followed by the transcript hash.
	fn ack_aad(transcript_hash: &[u8; 32]) -> Vec<u8> {
		let mut aad = Vec::with_capacity(TIGHTBEAM_ACK_AAD_DOMAIN.len() + transcript_hash.len());
		aad.extend_from_slice(TIGHTBEAM_ACK_AAD_DOMAIN);
		aad.extend_from_slice(transcript_hash);
		aad
	}

	/// The AEAD that seals and opens the receipt acknowledgement.
	fn ack_cipher<P>(&self, salt: KdfSalt<'_>) -> Result<P::AeadCipher, HandshakeError>
	where
		P: CryptoProvider,
		P::AeadCipher: KeyInit,
	{
		let key_size = <P::AeadCipher as KeySizeUser>::key_size();
		let key = P::Kdf::derive_dynamic_key(&self.0, TIGHTBEAM_ACK_KDF_INFO, Some(salt.as_bytes()), key_size)?;
		let cipher = P::AeadCipher::new_from_slice(&key)?;
		Ok(cipher)
	}
}

/// Debug output redacts the handshake secret.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl fmt::Debug for HandshakeSecret {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("HandshakeSecret").finish_non_exhaustive()
	}
}

/// A handshake secret the peer proved it derived.
///
/// [`HandshakeSecret::confirmed`] is its one producer, so a step that takes
/// a `ConfirmedSecret` runs only after the key-confirmation tag verified.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub struct ConfirmedSecret(HandshakeSecret);

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl ConfirmedSecret {
	/// The confirmed secret, for the one seal that opens under it.
	pub(crate) fn secret(&self) -> &HandshakeSecret {
		&self.0
	}

	/// Take the secret out, for the session that derives from it.
	pub(crate) fn into_secret(self) -> HandshakeSecret {
		self.0
	}
}

/// The proof that an endpoint derived the handshake secret of one transcript.
///
/// [`HandshakeSecret::confirmation`] derives the tag an endpoint sends or
/// expects. A received tag decodes as a 32-byte OCTET STRING, and another
/// width fails to decode, so every tag has the one width.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
#[derive(Clone)]
pub struct KeyConfirmation([u8; KEY_CONFIRMATION_SIZE]);

/// Key-confirmation tag length in bytes.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
const KEY_CONFIRMATION_SIZE: usize = 32;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl KeyConfirmation {
	/// Verify in constant time that `received` is this tag.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyConfirmationFailed`] -- the tags differ, so the
	///   peer derived another handshake secret or confirmed another transcript.
	pub(crate) fn verify(&self, received: &Self) -> Result<(), HandshakeError> {
		let is_confirmed: bool = self.0.ct_eq(&received.0).into();
		if !is_confirmed {
			return Err(HandshakeError::KeyConfirmationFailed);
		}

		Ok(())
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl FixedTag for KeyConfirmation {
	const TAG: Tag = Tag::OctetString;
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl EncodeValue for KeyConfirmation {
	fn value_len(&self) -> DerResult<Length> {
		Length::try_from(self.0.len())
	}

	fn encode_value(&self, writer: &mut impl Writer) -> DerResult<()> {
		writer.write(&self.0)
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl<'a> DecodeValue<'a> for KeyConfirmation {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> DerResult<Self> {
		let octets = OctetStringRef::decode_value(reader, header)?;
		let tag = octets.as_bytes().try_into().map_err(|_| Tag::OctetString.length_error())?;
		Ok(Self(tag))
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
mod sealed {
	/// Closes [`TrafficSecret`](super::TrafficSecret) to this module.
	pub trait Sealed {}
}

/// A secret that traffic keys derive from.
///
/// The directional derivation takes an implementor, and the implementors are
/// the handshake secret and the epoch secret that rotates from it. The trait
/// is sealed, so those two are the only inputs the derivation has.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) trait TrafficSecret: sealed::Sealed {
	/// The secret bytes, for the provider KDF that extracts from them.
	fn as_bytes(&self) -> &[u8];
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl sealed::Sealed for HandshakeSecret {}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl TrafficSecret for HandshakeSecret {
	fn as_bytes(&self) -> &[u8] {
		&self.0
	}
}

/// One link of the rekey KDF chain, zeroized on drop and on rotation.
///
/// Epoch 0 derives from the [`HandshakeSecret`] through
/// [`EpochMaterials::derive`], and each rotation derives the next link from
/// the previous one and a fresh agreement through [`Self::next`]. Those two
/// are its constructors.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) struct EpochSecret(ZeroizingBytes);

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl sealed::Sealed for EpochSecret {}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl TrafficSecret for EpochSecret {
	fn as_bytes(&self) -> &[u8] {
		&self.0
	}
}

#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
impl EpochSecret {
	/// The next link of the rekey KDF chain: this link and a fresh agreement
	/// between `local` and `peer`, extracted under `salt` and the epoch label.
	///
	/// ```text
	/// epoch_next = HKDF(u32be(32) || epoch || u32be(32) || ee, salt, "tb/session/kdf/epoch/v1")
	/// ```
	///
	/// The agreement runs here, so no later link exists without a rekey
	/// scalar. A holder of this link who records the whole renewal derives
	/// nothing of the next one.
	///
	/// - `local` is a single-use scalar, moved in. It is wiped where this
	///   function returns, so its holder cannot keep it across a later await.
	/// - `peer` is a [`PeerPoint`], so the point passed [`PeerEphemeral`].
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the
	///   derivation, or the curve's shared secret is not 32 bytes.
	/// - [`HandshakeError::IntegerOutOfRange`] -- an input exceeds the framing prefix.
	pub(crate) fn next<P>(
		&self,
		local: Box<EphemeralSecret<P::Curve>>,
		peer: &PeerPoint<P::Curve>,
		salt: KdfSalt<'_>,
	) -> Result<Self, HandshakeError>
	where
		P: HandshakeProvider,
	{
		let shared = local.shared_secret(peer.as_public_key())?;

		// The scalar served its one agreement, so its box drops here and the
		// scalar is wiped in place before the derivation runs.
		drop(local);

		self.chained::<P>(&shared, salt)
	}

	/// The chain step over the agreement output `shared`: the framed pair of
	/// this link and `shared`, extracted under `salt` and the epoch label.
	///
	/// [`Self::next`] is its one caller, and it holds the formula alone, so
	/// a known-answer test pins the formula with no scalar.
	fn chained<P>(&self, shared: &EcdhSecret, salt: KdfSalt<'_>) -> Result<Self, HandshakeError>
	where
		P: HandshakeProvider,
	{
		let label = KdfInfo::new(TIGHTBEAM_EPOCH_KDF_INFO);
		let secret = shared.with(|shared| {
			let inputs: [&[u8]; 2] = [&self.0, shared];
			multi_input_kdf::<P>(&inputs, salt, label, EPOCH_SECRET_SIZE)
		})?;

		Ok(Self(secret))
	}
}

/// Epoch state retained past handshake completion for in-band rekeying.
///
/// [`Handshake::complete`](crate::transport::handshake::Handshake::complete)
/// produces it alongside the session keys, for either role. The epoch secret
/// seeds the rekey KDF chain, and the transcript hash is the chain root
/// `hash_0`. The handshake secret itself drops at completion.
pub struct EpochMaterials {
	/// Current epoch secret, zeroized on drop and on rotation
	/// (RFC 9846, 7.2). Only `transport::rekey` reads it, and a build can
	/// include the handshake without the `transport-multiplex` consumers.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[allow(dead_code)]
	pub(crate) secret: EpochSecret,
	/// Epoch counter. It is 0 at handshake and increments on each rekey
	/// install.
	pub(crate) epoch: u32,
	/// Chained transcript hash. `hash_0` is the handshake transcript.
	pub(crate) transcript_hash: [u8; 32],
}

impl EpochMaterials {
	/// Return the current epoch number.
	pub fn epoch(&self) -> u32 {
		self.epoch
	}

	/// Return the current chained transcript hash.
	pub fn transcript_hash(&self) -> [u8; 32] {
		self.transcript_hash
	}
}

/// Debug output redacts the epoch secret.
impl fmt::Debug for EpochMaterials {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("EpochMaterials")
			.field("epoch", &self.epoch)
			.field("transcript_hash", &self.transcript_hash)
			.finish_non_exhaustive()
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl EpochMaterials {
	/// Derive the epoch-0 secret from the handshake secret under the
	/// dedicated epoch info label.
	///
	/// The derivation uses the same `secret` and `salt` pair as the
	/// directional traffic keys. The distinct label yields an independent
	/// secret (RFC 5869 domain separation), so retaining it never weakens the
	/// traffic keys.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
	pub(crate) fn derive<P>(
		secret: &HandshakeSecret,
		salt: KdfSalt<'_>,
		transcript_hash: [u8; 32],
	) -> Result<Self, HandshakeError>
	where
		P: CryptoProvider,
	{
		let input_key = secret.as_bytes();
		let kdf_salt = Some(salt.as_bytes());
		let secret = P::Kdf::derive_dynamic_key(input_key, TIGHTBEAM_EPOCH_KDF_INFO, kdf_salt, EPOCH_SECRET_SIZE)?;
		let materials = Self { secret: EpochSecret(secret), epoch: 0, transcript_hash };
		Ok(materials)
	}
}

#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
impl EpochMaterials {
	/// The pin an epoch receipt commits to:
	/// `H(hash || request_der || server_random || server_ephemeral)`.
	///
	/// The pin is computable before the receipt exists, so the receipt's
	/// `transcript_hash` commits to the exchange without circularity. It
	/// covers both rekey ephemerals: the client's inside `request_der`, and
	/// the server's as its last leg.
	///
	/// # Errors
	///
	/// - [`HandshakeError::TranscriptDigestLength`] -- `D` produces fewer than 32 bytes.
	pub(crate) fn exchange_pin<D: Digest>(
		&self,
		request_der: impl AsRef<[u8]>,
		server_random: &[u8; 32],
		server_ephemeral: &[u8; EC_PUBKEY_COMPRESSED_SIZE],
	) -> Result<[u8; 32], HandshakeError> {
		let legs: [&[u8]; 4] = [&self.transcript_hash, request_der.as_ref(), server_random, server_ephemeral];
		Transcript::digest::<D>(legs.concat())
	}

	/// The chain hash after a completed exchange:
	/// `H(hash || request_der || response_der || ack_der)`.
	///
	/// Every epoch receipt therefore commits to the whole session history
	/// back to the handshake transcript.
	///
	/// # Errors
	///
	/// - [`HandshakeError::TranscriptDigestLength`] -- `D` produces fewer than 32 bytes.
	pub(crate) fn advanced<D: Digest>(
		&self,
		request_der: impl AsRef<[u8]>,
		response_der: impl AsRef<[u8]>,
		ack_der: impl AsRef<[u8]>,
	) -> Result<[u8; 32], HandshakeError> {
		let legs: [&[u8]; 4] = [
			&self.transcript_hash,
			request_der.as_ref(),
			response_der.as_ref(),
			ack_der.as_ref(),
		];
		Transcript::digest::<D>(legs.concat())
	}
}

/// Epoch secret length in bytes: one 256-bit KDF chain link.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
const EPOCH_SECRET_SIZE: usize = 32;

/// The compressed SEC1 encoding of an ephemeral public key.
///
/// The ECIES transcript and the rekey pin take the point at this width, so an
/// ephemeral of any other length fails before the signature check rather than
/// hashing as a variable-length leg.
#[cfg(any(
	feature = "transport-ecies",
	all(feature = "transport-cms", feature = "transport-multiplex")
))]
pub(crate) trait CompressedPoint {
	/// The compressed SEC1 bytes of this point.
	///
	/// # Errors
	///
	/// - [`HandshakeError::OctetStringLengthError`] -- the curve's compressed
	///   point is not [`EC_PUBKEY_COMPRESSED_SIZE`] bytes wide.
	fn compressed_point(&self) -> Result<[u8; EC_PUBKEY_COMPRESSED_SIZE], HandshakeError>;
}

#[cfg(any(
	feature = "transport-ecies",
	all(feature = "transport-cms", feature = "transport-multiplex")
))]
impl<C: HandshakeCurve> CompressedPoint for PublicKey<C> {
	fn compressed_point(&self) -> Result<[u8; EC_PUBKEY_COMPRESSED_SIZE], HandshakeError> {
		let point = self.to_encoded_point(true);
		let bytes = point.as_bytes();
		let sized = bytes
			.try_into()
			.map_err(|_| HandshakeError::OctetStringLengthError((bytes.len(), EC_PUBKEY_COMPRESSED_SIZE).into()))?;
		Ok(sized)
	}
}

/// A peer's ephemeral point that [`PeerEphemeral`] admitted: it is on the
/// curve, it is not the identity, and it is not the peer's static key.
///
/// [`PeerEphemeral::distinct_ephemeral`] is its one producer, so an agreement
/// that takes a `PeerPoint` runs on no other point.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub struct PeerPoint<C: CurveArithmetic>(PublicKey<C>);

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl<C: CurveArithmetic> PeerPoint<C> {
	/// The admitted point, for the scalar multiplication that reads it.
	pub(crate) fn as_public_key(&self) -> &PublicKey<C> {
		&self.0
	}
}

/// A peer's ephemeral public key, parsed beside the static key it must differ
/// from.
///
/// The parser refuses a malformed, off-curve, or identity point, so no scalar
/// multiplication runs on an invalid one. A point equal to the static key
/// `self` is refused as well, because the agreement would then collapse into
/// the static one that key recovers.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) trait PeerEphemeral<C>
where
	C: CurveArithmetic,
{
	/// Parse `sec1` as an ephemeral of the peer that holds the static key
	/// `self`, or `None` when the point is that static key.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- `sec1` is not a point on the curve.
	fn distinct_ephemeral(&self, sec1: &[u8]) -> Result<Option<PeerPoint<C>>, HandshakeError>;

	/// Parse `sec1` as the ephemeral of the server that holds the static key
	/// `self`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- `sec1` is not a point on the curve.
	/// - [`HandshakeError::ServerEphemeralIsStatic`] -- the point is the server's static key.
	fn server_ephemeral(&self, sec1: &[u8]) -> Result<PeerPoint<C>, HandshakeError> {
		let distinct = self.distinct_ephemeral(sec1)?;
		distinct.ok_or(HandshakeError::ServerEphemeralIsStatic)
	}

	/// Parse `sec1` as the rekey ephemeral of the client that holds the
	/// static key `self`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- `sec1` is not a point on the curve.
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- the point is the client's static key.
	#[cfg(feature = "transport-multiplex")]
	fn client_ephemeral(&self, sec1: &[u8]) -> Result<PeerPoint<C>, HandshakeError> {
		let distinct = self.distinct_ephemeral(sec1)?;
		distinct.ok_or(HandshakeError::ClientEphemeralIsStatic)
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl<C: HandshakeCurve> PeerEphemeral<C> for PublicKey<C> {
	fn distinct_ephemeral(&self, sec1: &[u8]) -> Result<Option<PeerPoint<C>>, HandshakeError> {
		let ephemeral = PublicKey::<C>::from_sec1_bytes(sec1)?;
		if ephemeral == *self {
			return Ok(None);
		}

		Ok(Some(PeerPoint(ephemeral)))
	}
}

/// ECDH key agreement on the handshake plane.
///
/// - The KARI static step runs it with the client's [`SecretKey`] against the server's static key.
/// - The ephemeral-ephemeral step runs it with the same [`SecretKey`] on the
///   client, or with the [`EphemeralSecret`] the server drew for one handshake.
///
/// Every peer arrives as a parsed [`PublicKey`], so each point has passed
/// `from_sec1_bytes` before it reaches a scalar multiplication.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) trait HandshakeAgreement<C>
where
	C: CurveArithmetic,
{
	/// ECDH with `peer`, sized to the shared secret the key schedule takes.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the curve's shared secret is not 32 bytes.
	fn shared_secret(&self, peer: &PublicKey<C>) -> Result<EcdhSecret, HandshakeError>;
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl<C> HandshakeAgreement<C> for EphemeralSecret<C>
where
	C: CurveArithmetic,
{
	fn shared_secret(&self, peer: &PublicKey<C>) -> Result<EcdhSecret, HandshakeError> {
		Ok(EcdhSecret::try_from(self.diffie_hellman(peer))?)
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl<C> HandshakeAgreement<C> for SecretKey<C>
where
	C: CurveArithmetic,
{
	fn shared_secret(&self, peer: &PublicKey<C>) -> Result<EcdhSecret, HandshakeError> {
		let shared = diffie_hellman(self.to_nonzero_scalar(), peer.as_affine());
		Ok(EcdhSecret::try_from(shared)?)
	}
}

/// The base secret beside the peer point it is agreed with, borrowed for one
/// settlement.
///
/// Each protocol builds one where both halves exist, and [`Self::settle`] is
/// the one derivation of the [`HandshakeSecret`].
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) struct Agreement<'a, P: HandshakeProvider> {
	base: &'a BaseSecret,
	peer: &'a PublicKey<P::Curve>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl<'a, P: HandshakeProvider> Agreement<'a, P> {
	/// Pair `base` with the point `peer` it is agreed with.
	pub(crate) fn new(base: &'a BaseSecret, peer: &'a PublicKey<P::Curve>) -> Self {
		Self { base, peer }
	}

	/// Run the agreement of `local` with the peer point, and derive the
	/// handshake secret from the base secret and that output under `salt`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the shared secret is not 32 bytes, or
	///   the provider KDF refused the derivation.
	/// - [`HandshakeError::IntegerOutOfRange`] -- an input exceeds the framing prefix.
	pub(crate) fn settle(
		self,
		local: &impl HandshakeAgreement<P::Curve>,
		salt: KdfSalt<'_>,
	) -> Result<HandshakeSecret, HandshakeError> {
		let shared = local.shared_secret(self.peer)?;
		HandshakeSecret::derive::<P>(self.base, &shared, salt)
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl<C> DirectionalCiphers<C>
where
	C: KeyInit,
{
	/// Derive the directional AEAD ciphers of provider `P` from a traffic
	/// secret.
	///
	/// This is the single derivation path that handshake finalization and epoch
	/// rotation share. The provider's cipher type fixes the key length, the
	/// salt floor applies at every derivation, and the [`TrafficSecret`] bound
	/// admits only the handshake secret and the epoch chain it seeds.
	pub(crate) fn derive<P, S>(secret: &S, salt: KdfSalt<'_>) -> Result<Self, HandshakeError>
	where
		P: CryptoProvider<AeadCipher = C>,
		S: TrafficSecret,
	{
		let key_size = <C as KeySizeUser>::key_size();
		let salt_len = salt.as_bytes().len();
		if salt_len < MIN_SALT_ENTROPY_BYTES {
			return Err(HandshakeError::InsufficientSaltEntropy { actual: salt_len, minimum: MIN_SALT_ENTROPY_BYTES });
		}

		let input_key = secret.as_bytes();
		let c2s_label = KdfInfo::new(TIGHTBEAM_C2S_KDF_INFO);
		let s2c_label = KdfInfo::new(TIGHTBEAM_S2C_KDF_INFO);

		let client_to_server = derive_labeled_cipher::<P>(input_key, salt, c2s_label, key_size)?;
		let server_to_client = derive_labeled_cipher::<P>(input_key, salt, s2c_label, key_size)?;
		Ok(Self { client_to_server, server_to_client })
	}
}

/// Derive one direction's cipher under the given KDF info label.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn derive_labeled_cipher<P>(
	input_key: &[u8],
	salt: KdfSalt<'_>,
	info: KdfInfo<'_>,
	key_size: usize,
) -> Result<P::AeadCipher, HandshakeError>
where
	P: CryptoProvider,
	P::AeadCipher: KeyInit,
{
	let key_bytes = P::Kdf::derive_dynamic_key(input_key, info.as_bytes(), Some(salt.as_bytes()), key_size)?;
	let cipher = P::AeadCipher::new_from_slice(&key_bytes[..])?;
	Ok(cipher)
}

/// The KDF salt of a flow.
///
/// Each protocol salts every derivation of one handshake with one value, and
/// [`Terms::kdf_salt`] yields it.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub struct Salt(SaltSource);

/// Where the salt of a flow comes from.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
enum SaltSource {
	/// The concatenation `client_random || server_random`.
	#[cfg(feature = "transport-ecies")]
	Randoms(RandomsSalt),
	/// The transcript hash that the [`Terms`] hold.
	#[cfg(feature = "transport-cms")]
	TranscriptHash,
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl Salt {
	/// The ECIES salt, `client_random || server_random`.
	#[cfg(feature = "transport-ecies")]
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
/// The fields are fixed together at the leg that seals the transcript, so a
/// handshake that holds terms holds all of them.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub struct Terms<P: HandshakeProvider> {
	profile: RunnableProfile<P>,
	mux: Option<MuxSettings>,
	transcript_hash: [u8; 32],
	salt: Salt,
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl<P: HandshakeProvider> Terms<P> {
	/// Fix the terms of one handshake.
	///
	/// - `mux` is `None` for a single-flight session.
	/// - `transcript_hash` is the sealed hash both sides sign over.
	pub(crate) fn new(
		profile: RunnableProfile<P>,
		mux: Option<MuxSettings>,
		transcript_hash: [u8; 32],
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
	pub(crate) fn transcript_hash(&self) -> &[u8; 32] {
		&self.transcript_hash
	}

	/// The salt every derivation of this handshake runs under.
	pub(crate) fn kdf_salt(&self) -> KdfSalt<'_> {
		match &self.salt.0 {
			#[cfg(feature = "transport-ecies")]
			SaltSource::Randoms(randoms) => randoms.as_kdf_salt(),
			#[cfg(feature = "transport-cms")]
			SaltSource::TranscriptHash => KdfSalt::new(&self.transcript_hash),
		}
	}
}

/// The certificate a role records as its peer.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub trait PeerIdentity: MaybeSend + MaybeSync + 'static {
	/// The certificate the session records, or `None` when the peer proved no
	/// identity.
	fn certificate(&self) -> Option<&Arc<Certificate>>;
}

/// What both sides hold once the handshake secret exists.
///
/// [`Self::complete`] consumes it, so one handshake derives one session.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub struct Agreed<P: HandshakeProvider, Peer: PeerIdentity> {
	terms: Terms<P>,
	secret: HandshakeSecret,
	receipt: Option<StoredReceipt>,
	peer: Peer,
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl<P: HandshakeProvider, Peer: PeerIdentity> Agreed<P, Peer> {
	/// Gather what one handshake agreed.
	///
	/// `receipt` is the dual-signed receipt of a budget-bearing session, and
	/// `None` for an unmetered one.
	pub(crate) fn new(terms: Terms<P>, secret: HandshakeSecret, receipt: Option<StoredReceipt>, peer: Peer) -> Self {
		Self { terms, secret, receipt, peer }
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
	pub(crate) fn peer(&self) -> &Peer {
		&self.peer
	}

	/// Derive everything a session takes from the handshake secret, and hand
	/// it over.
	///
	/// This is the one key-schedule sequence of both protocols and both roles:
	/// the directional traffic keys, then the epoch-0 rekey materials, each
	/// under the protocol's salt. `keys` maps the directional ciphers to the
	/// keys of the calling role. The handshake secret drops when this returns.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InsufficientSaltEntropy`] -- the salt is shorter than [`MIN_SALT_ENTROPY_BYTES`].
	/// - [`HandshakeError::KdfError`] -- the KDF refused a key length.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused the derived key.
	pub(crate) fn complete(
		self,
		keys: fn(DirectionalCiphers<P::AeadCipher>) -> SessionKeys,
	) -> Result<EstablishedSession, HandshakeError> {
		let Self { terms, secret, receipt, peer } = self;
		let salt = terms.kdf_salt();
		let ciphers = DirectionalCiphers::derive::<P, _>(&secret, salt)?;
		let epoch = EpochMaterials::derive::<P>(&secret, salt, terms.transcript_hash)?;

		let receipt = receipt.map(Arc::new);
		let peer = peer.certificate().map(Arc::clone);
		let session = EstablishedSession::new(keys(ciphers), terms.mux, receipt, peer, Some(epoch));
		Ok(session)
	}
}

/// Public-key extraction from a certificate.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub trait HandshakeVerifyingKey {
	/// Public key parsed from this certificate's SPKI, on curve `C`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- the certificate key bytes fail SEC1 decoding.
	fn verifying_key<C: HandshakeCurve>(&self) -> Result<PublicKey<C>, HandshakeError>;
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl HandshakeVerifyingKey for Certificate {
	fn verifying_key<C: HandshakeCurve>(&self) -> Result<PublicKey<C>, HandshakeError> {
		let pubkey_bytes = self.verifying_key_bytes();
		Ok(PublicKey::<C>::from_sec1_bytes(pubkey_bytes)?)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[cfg(feature = "transport-multiplex")]
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::profiles::{AeadProvider, DefaultCryptoProvider};

	/// A base secret of `fill` bytes.
	fn base_secret(fill: u8) -> BaseSecret {
		BaseSecret::try_from(SecretSlice::from(vec![fill; 32])).expect("32 bytes make a base secret")
	}

	/// The handshake secret of fixture inputs `base` and `shared` under
	/// `salt`.
	fn handshake_secret(base: u8, shared: u8, salt: &[u8]) -> HandshakeSecret {
		let base = base_secret(base);
		let shared = EcdhSecret::from([shared; 32]);
		HandshakeSecret::derive::<DefaultCryptoProvider>(&base, &shared, KdfSalt::new(salt))
			.expect("fixture inputs derive a handshake secret")
	}

	/// The directional ciphers of the default provider from `secret` under
	/// `salt`.
	fn derive_directional(
		secret: &HandshakeSecret,
		salt: &[u8],
	) -> Result<DirectionalCiphers<<DefaultCryptoProvider as AeadProvider>::AeadCipher>, HandshakeError> {
		DirectionalCiphers::derive::<DefaultCryptoProvider, _>(secret, KdfSalt::new(salt))
	}

	#[test]
	fn test_derive_directional_aead_success() {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);
		let result = derive_directional(&secret, &salt);
		assert!(result.is_ok());
	}

	/// The handshake secret changes with the ephemeral-ephemeral output, so a
	/// holder of the base secret alone derives another secret.
	#[test]
	fn the_handshake_secret_depends_on_the_ephemeral_agreement() {
		let salt = [0x99u8; 32];
		let first = handshake_secret(0x42, 0x11, &salt);
		let second = handshake_secret(0x42, 0x12, &salt);
		assert_ne!(first.as_bytes(), second.as_bytes());
	}

	/// The handshake secret changes with the base secret, so the client's
	/// random contribution stays load-bearing beside the agreement.
	#[test]
	fn the_handshake_secret_depends_on_the_base_secret() {
		let salt = [0x99u8; 32];
		let first = handshake_secret(0x42, 0x11, &salt);
		let second = handshake_secret(0x43, 0x11, &salt);
		assert_ne!(first.as_bytes(), second.as_bytes());
	}

	/// A base secret of any other length is refused at the parse.
	#[test]
	fn a_base_secret_of_another_length_is_refused() {
		let short = BaseSecret::try_from(SecretSlice::from(vec![0x42u8; 31]));
		assert!(matches!(
			short,
			Err(HandshakeError::InvalidKeySize { expected: 32, received: 31 })
		));
	}

	/// The transcript hash a fixture acknowledgement is sealed over.
	const ACK_TRANSCRIPT: [u8; 32] = [0x07u8; 32];

	/// The chain step is HKDF-SHA3-256 over the framed pair of the epoch
	/// secret and the agreement output, under the salt and the epoch label.
	///
	/// Both endpoints derive this value, so the expected one is a literal that
	/// no code of the crate computes.
	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn the_epoch_chain_step_matches_its_known_answer() -> Result<(), HandshakeError> {
		let epoch = EpochSecret(ZeroizingBytes::new(vec![0x42u8; 32]));
		let shared = EcdhSecret::from([0x11u8; 32]);
		let salt = [0x99u8; 64];

		let next = epoch.chained::<DefaultCryptoProvider>(&shared, KdfSalt::new(&salt))?;
		let expected = [
			0xad, 0x8e, 0x99, 0x9c, 0x3c, 0x48, 0x89, 0xe6, 0x28, 0x89, 0xc7, 0x98, 0xf7, 0x91, 0x97, 0x07, 0xdc, 0x45,
			0x57, 0x59, 0x77, 0xa1, 0x65, 0x31, 0x42, 0x6a, 0xbb, 0x9c, 0x21, 0x01, 0xb4, 0x34,
		];
		assert_eq!(next.0.as_slice(), expected);
		Ok(())
	}

	/// The rekey pin is SHA3-256 over the chain hash, the request, the server
	/// random, and the server ephemeral, in that order.
	///
	/// The server signs this value and the client recomputes it, so the
	/// expected one is a literal that no code of the crate computes.
	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn the_exchange_pin_matches_its_known_answer() -> Result<(), HandshakeError> {
		let secret = EpochSecret(ZeroizingBytes::new(vec![0x42u8; 32]));
		let materials = EpochMaterials { secret, epoch: 0, transcript_hash: ACK_TRANSCRIPT };

		let pin = materials.exchange_pin::<Sha3_256>(b"request der", &[0x21u8; 32], &[0x02u8; 33])?;
		let expected = [
			0x63, 0x36, 0x6b, 0x7a, 0x2d, 0xa7, 0xb4, 0x7b, 0xe9, 0xc3, 0x4c, 0xca, 0x39, 0x08, 0x11, 0x9f, 0x61, 0xc2,
			0x58, 0x9d, 0xc7, 0x45, 0x84, 0x8b, 0x2a, 0xd8, 0x55, 0xc7, 0xa7, 0xdc, 0x83, 0xde,
		];
		assert_eq!(pin, expected);
		Ok(())
	}

	/// The key-confirmation tag is HKDF-SHA3-256 of the handshake secret under
	/// the salt, with the confirmation label followed by the transcript hash as
	/// its info.
	///
	/// Both endpoints derive this tag, so the expected value is a literal that
	/// no code of the crate computes.
	#[test]
	fn the_key_confirmation_matches_its_known_answer() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);

		let tag = secret.confirmation::<DefaultCryptoProvider>(KdfSalt::new(&salt), &ACK_TRANSCRIPT)?;
		let expected = [
			0xcf, 0x60, 0x90, 0x89, 0xce, 0xa6, 0x5d, 0xf9, 0xf3, 0xf7, 0xc7, 0x77, 0x5a, 0xdd, 0x63, 0xdf, 0x40, 0x36,
			0x07, 0x52, 0xf6, 0x95, 0xe7, 0xb2, 0xa8, 0x66, 0x7c, 0xd0, 0xb0, 0x62, 0x40, 0xa6,
		];
		assert_eq!(tag.0, expected);
		Ok(())
	}

	/// A tag verifies against itself and against no other tag.
	#[test]
	fn a_key_confirmation_verifies_against_itself_alone() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);
		let other = handshake_secret(0x42, 0x12, &salt);

		let tag = secret.confirmation::<DefaultCryptoProvider>(KdfSalt::new(&salt), &ACK_TRANSCRIPT)?;
		let same = secret.confirmation::<DefaultCryptoProvider>(KdfSalt::new(&salt), &ACK_TRANSCRIPT)?;
		let foreign = other.confirmation::<DefaultCryptoProvider>(KdfSalt::new(&salt), &ACK_TRANSCRIPT)?;
		assert!(tag.verify(&same).is_ok());
		assert!(matches!(tag.verify(&foreign), Err(HandshakeError::KeyConfirmationFailed)));
		Ok(())
	}

	/// An acknowledgement sealed under one handshake secret opens under the
	/// same secret, salt, and transcript.
	#[test]
	fn a_sealed_ack_opens_under_the_same_handshake_secret() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);
		let sealed =
			secret.seal_ack::<DefaultCryptoProvider>(KdfSalt::new(&salt), &ACK_TRANSCRIPT, b"settlement answer")?;

		let opened = secret.open_ack::<DefaultCryptoProvider>(KdfSalt::new(&salt), &ACK_TRANSCRIPT, &sealed)?;
		assert!(opened.with(|bytes| bytes.as_slice() == b"settlement answer"));
		Ok(())
	}

	/// An acknowledgement sealed under one handshake secret does not open
	/// under another, so a recording plus the base secret alone reads nothing.
	#[test]
	fn a_sealed_ack_refuses_another_handshake_secret() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);
		let other = handshake_secret(0x42, 0x12, &salt);
		let sealed =
			secret.seal_ack::<DefaultCryptoProvider>(KdfSalt::new(&salt), &ACK_TRANSCRIPT, b"settlement answer")?;

		let refused = other.open_ack::<DefaultCryptoProvider>(KdfSalt::new(&salt), &ACK_TRANSCRIPT, &sealed);
		assert!(matches!(refused, Err(HandshakeError::ReceiptAckCipher(_))));
		Ok(())
	}

	/// An acknowledgement sealed over one transcript does not open under
	/// another, so the ciphertext commits to the session it closes.
	#[test]
	fn a_sealed_ack_refuses_another_transcript() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);
		let other_transcript = [0x08u8; 32];
		let sealed =
			secret.seal_ack::<DefaultCryptoProvider>(KdfSalt::new(&salt), &ACK_TRANSCRIPT, b"settlement answer")?;

		let refused = secret.open_ack::<DefaultCryptoProvider>(KdfSalt::new(&salt), &other_transcript, &sealed);
		assert!(matches!(refused, Err(HandshakeError::ReceiptAckCipher(_))));
		Ok(())
	}

	/// Seal a fixture plaintext under a zero nonce with the given cipher.
	fn seal(cipher: &<DefaultCryptoProvider as AeadProvider>::AeadCipher, plaintext: impl AsRef<[u8]>) -> Vec<u8> {
		let plaintext = plaintext.as_ref();
		use crate::crypto::aead::Aead;

		let nonce = [0u8; 12];
		cipher
			.encrypt((&nonce).into(), plaintext)
			.expect("fixture encryption with a freshly derived cipher")
	}

	#[test]
	fn test_derive_directional_aead_directions_differ() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);
		let ciphers = derive_directional(&secret, &salt)?;

		// The info labels separate the keys, so the same nonce and plaintext
		// must produce different ciphertexts under the two directions.
		let plaintext = b"directional key separation";
		let c2s_ciphertext = seal(&ciphers.client_to_server, plaintext.as_slice());
		let s2c_ciphertext = seal(&ciphers.server_to_client, plaintext.as_slice());
		assert_ne!(c2s_ciphertext, s2c_ciphertext);
		Ok(())
	}

	#[test]
	fn test_derive_directional_aead_is_deterministic() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);
		let first = derive_directional(&secret, &salt)?;
		let second = derive_directional(&secret, &salt)?;

		// Both derivations agree, so two independent endpoints derive the
		// same directional keys from shared input material.
		let plaintext = b"deterministic derivation";
		let first_ciphertext = seal(&first.client_to_server, plaintext.as_slice());
		let second_ciphertext = seal(&second.client_to_server, plaintext.as_slice());
		assert_eq!(first_ciphertext, second_ciphertext);
		Ok(())
	}

	#[test]
	fn test_derive_directional_aead_insufficient_salt() {
		let salt = [0x99u8; 8];
		let secret = handshake_secret(0x42, 0x11, &[0x99u8; 32]);
		let result = derive_directional(&secret, &salt);
		assert!(matches!(
			result,
			Err(HandshakeError::InsufficientSaltEntropy { actual: 8, minimum: 16 })
		));
	}

	/// The terms of a fixture handshake over `transcript_hash` under `salt`.
	fn terms_with(transcript_hash: [u8; 32], salt: Salt) -> Terms<DefaultCryptoProvider> {
		Terms::new(RunnableProfile::native(), None, transcript_hash, salt)
	}

	/// A CMS handshake salts every derivation with its transcript hash.
	#[test]
	fn a_transcript_salt_is_the_transcript_hash() {
		let terms = terms_with([0x07u8; 32], Salt::transcript_hash());
		assert_eq!(terms.kdf_salt().as_bytes(), [0x07u8; 32]);
	}

	/// An ECIES handshake salts every derivation with the client random
	/// followed by the server random.
	#[test]
	fn a_randoms_salt_is_the_client_random_then_the_server_random() {
		let terms = terms_with([0x07u8; 32], Salt::randoms(&[0x01u8; 32], &[0x02u8; 32]));
		assert_eq!(terms.kdf_salt().as_bytes(), [[0x01u8; 32], [0x02u8; 32]].concat());
	}

	#[test]
	fn test_derive_epoch_materials_shape() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);
		let transcript = [0x07u8; 32];

		let materials = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, KdfSalt::new(&salt), transcript)?;
		assert_eq!(materials.epoch(), 0);
		assert_eq!(materials.transcript_hash(), transcript);
		assert_eq!(materials.secret.as_bytes().len(), EPOCH_SECRET_SIZE);

		Ok(())
	}

	#[test]
	fn test_derive_epoch_materials_is_deterministic() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);
		let transcript = [0x07u8; 32];

		let first = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, KdfSalt::new(&salt), transcript)?;
		let second = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, KdfSalt::new(&salt), transcript)?;
		assert_eq!(first.secret.as_bytes(), second.secret.as_bytes());

		Ok(())
	}

	#[test]
	fn test_derive_epoch_materials_separates_inputs() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let other_salt = [0x9Au8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);
		let other_secret = handshake_secret(0x43, 0x11, &salt);
		let transcript = [0x07u8; 32];

		let shared_salt = KdfSalt::new(&salt);
		let changed_salt = KdfSalt::new(&other_salt);
		let base = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, shared_salt, transcript)?;
		let keyed = EpochMaterials::derive::<DefaultCryptoProvider>(&other_secret, shared_salt, transcript)?;
		let salted = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, changed_salt, transcript)?;
		assert_ne!(base.secret.as_bytes(), keyed.secret.as_bytes());
		assert_ne!(base.secret.as_bytes(), salted.secret.as_bytes());

		Ok(())
	}
}
