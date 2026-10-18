//! The key schedule of a handshake.
//!
//! Both flows and both roles derive through these owners:
//!
//! - [`Agreement`] derives the [`HandshakeSecret`], the one secret a session
//!   derives from, out of the [`EcdhSecret`] that [`HandshakeAgreement`]
//!   produces and a [`BaseSecret`].
//! - [`Terms`] holds what negotiation fixed: the profile, the multiplexing
//!   terms, the transcript hash, and the protocol's salt.
//! - [`Agreed`] derives everything a session takes from the handshake secret.
//!
//! # Key schedule
//!
//! Both protocols and both roles run the same schedule. `ee` is the
//! ephemeral-ephemeral ECDH output, `base` is the random secret the client
//! seals to the server's static key, `S` is the protocol's salt, and `H` is
//! the negotiated digest, whose output is `Hash.length` bytes wide. `HKDF` is
//! the KDF of the profile, HKDF-SHA3-256 in the default profile.
//!
//! ```text
//! hs      = HKDF(ee || base, salt = S, info = "tb/session/kdf/v1")
//! k_c2s   = HKDF(hs, S, "tb/session/kdf/c2s/v1")
//! k_s2c   = HKDF(hs, S, "tb/session/kdf/s2c/v1")
//! epoch_0 = HKDF(hs, S, "tb/session/kdf/epoch/v1")
//! k_ack   = HKDF(hs, S, "tb/session/kdf/ack/v1")
//! k_id    = HKDF(hs, S, "tb/session/kdf/identity/v1")
//! mac_key = HKDF-Expand-H(HKDF-Extract-H(S, hs), "tb/handshake/finished/v1", Hash.length)
//! confirm = HMAC-H(mac_key, transcript_hash)
//! ```
//!
//! - `ee || base` is the hybrid shared secret `Z′ = Z || T` of NIST SP 800-56C Rev. 2 § 2.
//! - `confirm` follows the Finished construction of RFC 9846 § 4.5.3, with the
//!   crate's label as the HKDF-Expand info in place of `HkdfLabel`.
//!
//! [Forward secrecy](crate::transport::handshake#forward-secrecy) states what
//! this schedule withholds from a holder of the server's static key.

use core::fmt;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use core::marker::PhantomData;

#[cfg(all(not(feature = "std"), any(feature = "transport-cms", feature = "transport-hpke")))]
use alloc::vec::Vec;

#[cfg(any(
	feature = "transport-hpke",
	all(feature = "transport-cms", feature = "transport-multiplex")
))]
use crate::constants::EC_PUBKEY_COMPRESSED_SIZE;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::constants::{
	prefix_free, ECDH_SHARED_SECRET_SIZE, MIN_SALT_ENTROPY_BYTES, TIGHTBEAM_ACK_KDF_INFO, TIGHTBEAM_ACK_KEY_ID_DOMAIN,
	TIGHTBEAM_C2S_KDF_INFO, TIGHTBEAM_EPOCH_KDF_INFO, TIGHTBEAM_FINISHED_KEY_INFO, TIGHTBEAM_IDENTITY_KDF_INFO,
	TIGHTBEAM_IDENTITY_KEY_ID_DOMAIN, TIGHTBEAM_S2C_KDF_INFO, TIGHTBEAM_SESSION_KDF_INFO,
};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::aead::{DirectionalCiphers, KeyInit, SessionKeys};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::cms::{AttributesExt, AuthEnvelopedData, EnvelopeError, Opener, Recipient};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::common::typenum::Unsigned;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::common::KeySizeUser;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::hash::Digest;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::hkdf::hmac::{Mac, SimpleHmac};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::hkdf::{InvalidLength, SimpleHkdf};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::kdf::{EcdhSecret, KdfError, KdfFunction};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::profiles::{CryptoProvider, KeyWrapAlgorithm};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::secret::SecretSlice;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::sign::elliptic_curve::ecdh::EphemeralSecret;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::sign::elliptic_curve::sec1::ToEncodedPoint;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::sign::elliptic_curve::{CurveArithmetic, PublicKey, SecretKey};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::subtle::ConstantTimeEq;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::utils::CertificateExt;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::der::asn1::{Any, OctetString, OctetStringRef, SetOfVec};
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
use crate::der::oid::AssociatedOid;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::der::{
	Decode, DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Result as DerResult, Tag, Writer,
};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::oids::{DATA, HANDSHAKE_TRANSCRIPT_HASH};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::random::{generate_nonce, CryptoRngCore};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::error::HandshakeError;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::negotiation::{MuxSettings, RunnableProfile};
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
use crate::transport::handshake::primitives::multi_input_kdf;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::primitives::transcript::DigestOutput;
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
use crate::transport::handshake::primitives::transcript::Transcript;
#[cfg(feature = "transport-hpke")]
use crate::transport::handshake::primitives::RandomsSalt;
use crate::transport::handshake::primitives::TranscriptHash;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::primitives::{KdfInfo, KdfSalt};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::receipt::StoredReceipt;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::{Arc, EstablishedSession, HandshakeCurve, HandshakeProvider};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::utils::marker::{MaybeSend, MaybeSync};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::x509::attr::{Attribute, Attributes};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::x509::Certificate;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::{ZeroizingArray, ZeroizingBytes};

/// The 32-byte random secret the client seals to the server's static key.
///
/// It is the second input of [`HandshakeSecret::hybrid`]. HPKE carries it
/// inside the key-exchange payload, and CMS as the content of the key-exchange
/// envelope. The length is part of the type, so a parse that lands here has
/// already refused every other length.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) struct BaseSecret(ZeroizingArray<BASE_SECRET_SIZE>);

/// Base secret length in bytes.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const BASE_SECRET_SIZE: usize = 32;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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

/// The secret both endpoints agree on: the ephemeral-ephemeral ECDH output and
/// the client's base secret, extracted under the protocol salt.
///
/// Every session key derives from this one value, and the crate's one
/// constructor for it takes the two inputs named above.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct HandshakeSecret(ZeroizingBytes);

/// Handshake secret length in bytes.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const HANDSHAKE_SECRET_SIZE: usize = 32;

/// Length in bytes of the hybrid shared secret `ee || base`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const HYBRID_SECRET_SIZE: usize = ECDH_SHARED_SECRET_SIZE + BASE_SECRET_SIZE;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl HandshakeSecret {
	/// Derive the handshake secret from the hybrid shared secret
	/// `Z′ = ee || base`, extracted under `salt`.
	///
	/// `ee` is the ephemeral-ephemeral ECDH output, the shared secret `Z` of
	/// the key-establishment scheme, and `base` is the auxiliary secret `T`
	/// that follows it (NIST SP 800-56C Rev. 2 § 2). Each part has a fixed
	/// width, so the plain concatenation is unambiguous.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
	fn hybrid<P>(ee: &EcdhSecret, base: &BaseSecret, salt: KdfSalt<'_>) -> Result<Self, HandshakeError>
	where
		P: CryptoProvider,
	{
		// The copy lands in its wiping buffer directly (CWE-226).
		let mut hybrid = ZeroizingArray::new([0u8; HYBRID_SECRET_SIZE]);
		let (shared, auxiliary) = hybrid.split_at_mut(ECDH_SHARED_SECRET_SIZE);
		ee.with(|ee| shared.copy_from_slice(ee));
		auxiliary.copy_from_slice(base.as_bytes());

		let label = KdfInfo::new(TIGHTBEAM_SESSION_KDF_INFO);
		let salt = Some(salt.as_bytes());
		let secret = P::Kdf::derive_dynamic_key(hybrid.as_slice(), label.as_bytes(), salt, HANDSHAKE_SECRET_SIZE)?;
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
		let kek = P::Kdf::derive_dynamic_key(&self.0, purpose.label(), Some(salt.as_bytes()), kek_size)?;
		Ok(Sealer { kek, transcript_hash: *transcript_hash, purpose, provider: PhantomData })
	}

	/// Derive the key-confirmation tag over `transcript_hash`. It follows the
	/// Finished construction of RFC 9846 § 4.5.3 under the digest `H` of `P`,
	/// with the crate's label as the HKDF-Expand info in place of `HkdfLabel`.
	///
	/// ```text
	/// mac_key = HKDF-Expand-H(HKDF-Extract-H(salt, hs), "tb/handshake/finished/v1", Hash.length)
	/// tag     = HMAC-H(mac_key, transcript_hash)
	/// ```
	///
	/// A 32-byte `hs` is too short a PRK for a 64-byte `H` (RFC 5869 § 2.3), so
	/// `H` extracts one first. The client owns no static key-establishment key,
	/// so the key confirmation of NIST SP 800-56A Rev. 3 § 5.9 is not claimed.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- HKDF refused the length of `mac_key`.
	/// - [`HandshakeError::TranscriptDigestLength`] -- the digest of `P` is not 32 to 64 bytes.
	pub(crate) fn confirmation<P>(
		&self,
		salt: KdfSalt<'_>,
		transcript_hash: &TranscriptHash,
	) -> Result<KeyConfirmation, HandshakeError>
	where
		P: CryptoProvider,
	{
		// 1. Extract the PRK of the secret, and expand `mac_key` from it.
		let prk = SimpleHkdf::<P::Digest>::new(Some(salt.as_bytes()), &self.0);
		let mut mac_key = ZeroizingBytes::new(vec![0u8; <P::Digest as Digest>::output_size()]);
		let expanded = prk.expand(TIGHTBEAM_FINISHED_KEY_INFO, &mut mac_key);
		expanded.map_err(KdfError::DerivationFailed)?;

		// 2. MAC the transcript hash under `mac_key`.
		let mac = <SimpleHmac<P::Digest> as KeyInit>::new_from_slice(&mac_key);
		let mac = mac.map_err(|_| KdfError::DerivationFailed(InvalidLength))?;
		let tag = mac.chain_update(transcript_hash.as_bytes()).finalize();
		Ok(KeyConfirmation(DigestOutput::parse(tag.into_bytes())?))
	}

	/// Verify that `received` is the key-confirmation tag of this secret over
	/// `transcript_hash`, and hand the secret back as confirmed.
	///
	/// The secret is consumed, so a caller that holds a [`ConfirmedSecret`]
	/// holds no unconfirmed copy beside it.
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

/// Debug output redacts the handshake secret.
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
	/// The client certificate and its proof of possession, sealed in the
	/// closing.
	Identity,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl SecretSeal {
	/// The KDF label the key of this purpose derives under.
	pub(crate) const fn label(self) -> &'static [u8] {
		match self {
			Self::Ack => TIGHTBEAM_ACK_KDF_INFO,
			Self::Identity => TIGHTBEAM_IDENTITY_KDF_INFO,
		}
	}

	/// The domain that leads the `kekid`, ahead of the transcript hash.
	pub(crate) const fn domain(self) -> &'static [u8] {
		match self {
			Self::Ack => TIGHTBEAM_ACK_KEY_ID_DOMAIN,
			Self::Identity => TIGHTBEAM_IDENTITY_KEY_ID_DOMAIN,
		}
	}

	/// The padding of the sealed plaintext, or `None` for a purpose sealed
	/// bare.
	///
	/// Every field around the identity has a fixed width, so its length would
	/// be the length of the certificate. Padding to a step with a floor gives a
	/// fleet whose certificates come from one issuer one length.
	const fn padding(self) -> Option<Padding> {
		match self {
			Self::Ack => None,
			Self::Identity => Some(Padding { floor: 1024, step: 512 }),
		}
	}

	/// The error an envelope refusal of this purpose returns, carrying the
	/// refusal.
	pub(crate) fn refusal(self, error: EnvelopeError) -> HandshakeError {
		match self {
			Self::Ack => HandshakeError::ReceiptAckCipher(error),
			Self::Identity => HandshakeError::SealedIdentity(error),
		}
	}

	/// The plaintext as it is sealed.
	///
	/// A purpose with no padding seals the plaintext bare. A padded purpose
	/// seals a big-endian `u16` length, the plaintext, and zero bytes up to its
	/// padded length, so the opener finds the plaintext without reading it.
	pub(crate) fn frame(self, plaintext: &[u8]) -> Result<ZeroizingBytes, HandshakeError> {
		let Some(padding) = self.padding() else {
			return Ok(ZeroizingBytes::new(plaintext.to_vec()));
		};

		let length = u16::try_from(plaintext.len()).map_err(|_| HandshakeError::SealedFrame)?;
		let padded_len = padding.padded_len(plaintext.len());
		let mut framed = ZeroizingBytes::new(Vec::with_capacity(padded_len));
		framed.extend_from_slice(&length.to_be_bytes());
		framed.extend_from_slice(plaintext);
		framed.resize(padded_len, 0);
		Ok(framed)
	}

	/// The plaintext inside an opened frame. A length past the end of the
	/// frame, a non-zero byte in its padding, or a frame of another padded
	/// length is refused, so only a frame [`Self::frame`] could write opens.
	fn unframe(self, framed: &[u8]) -> Result<SecretSlice<u8>, HandshakeError> {
		let Some(padding) = self.padding() else {
			return Ok(SecretSlice::from(framed.to_vec()));
		};

		let prefixed = framed.split_first_chunk::<FRAME_LENGTH_SIZE>();
		let (prefix, rest) = prefixed.ok_or(HandshakeError::SealedFrame)?;
		let length = usize::from(u16::from_be_bytes(*prefix));
		let (plaintext, pad) = rest.split_at_checked(length).ok_or(HandshakeError::SealedFrame)?;

		let padded = pad.iter().all(|byte| *byte == 0);
		let conforming = framed.len() == padding.padded_len(length);
		if !padded || !conforming {
			return Err(HandshakeError::SealedFrame);
		}

		Ok(SecretSlice::from(plaintext.to_vec()))
	}
}

/// The width of the length that leads a padded frame.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const FRAME_LENGTH_SIZE: usize = 2;

/// The length a framed plaintext pads to: the next multiple of `step`, and at
/// least `floor`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Padding {
	floor: usize,
	step: usize,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl Padding {
	/// The padded length of the frame of a plaintext of `plaintext` bytes,
	/// whose length prefix the frame adds ahead of it.
	fn padded_len(self, plaintext: usize) -> usize {
		let framed = FRAME_LENGTH_SIZE + plaintext;
		let stepped = framed.div_ceil(self.step) * self.step;
		stepped.max(self.floor)
	}
}

// The acknowledgement and the identity derive two keys from one secret, so
// their labels must differ (RFC 5869 § 3.2), which `prefix_free` implies.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const _: () = assert!(prefix_free(SecretSeal::Ack.label(), SecretSeal::Identity.label()));

// When the negotiated digest is the hash of the profile's KDF, `mac_key`
// expands from the PRK that the traffic, epoch, acknowledgement, and identity
// keys extract from the handshake secret under the protocol salt. Its label
// must then differ from each of theirs (RFC 5869 § 3.2), which `prefix_free`
// implies.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const _: () = assert!(
	prefix_free(TIGHTBEAM_FINISHED_KEY_INFO, TIGHTBEAM_C2S_KDF_INFO)
		&& prefix_free(TIGHTBEAM_FINISHED_KEY_INFO, TIGHTBEAM_S2C_KDF_INFO)
		&& prefix_free(TIGHTBEAM_FINISHED_KEY_INFO, TIGHTBEAM_EPOCH_KDF_INFO)
		&& prefix_free(TIGHTBEAM_FINISHED_KEY_INFO, TIGHTBEAM_ACK_KDF_INFO)
		&& prefix_free(TIGHTBEAM_FINISHED_KEY_INFO, TIGHTBEAM_IDENTITY_KDF_INFO)
);

/// The single-use seal of one [`SecretSeal`] purpose: an `AuthEnvelopedData`
/// with one `KEKRecipientInfo` (RFC 5652 §6.2.3) under the purpose's key and
/// the algorithms of `P`.
///
/// [`HandshakeSecret::sealer`] is its one constructor. `seal` and `open` take
/// it by value, so one key seals or opens one message. Each seal draws its own
/// content key and nonce.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct Sealer<P> {
	kek: ZeroizingBytes,
	transcript_hash: TranscriptHash,
	purpose: SecretSeal,
	provider: PhantomData<fn() -> P>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P: HandshakeProvider> Sealer<P> {
	/// Seal `plaintext`, framed and padded as its purpose demands, as an
	/// `AuthEnvelopedData` of type `id-data` whose authenticated attributes
	/// carry the transcript hash.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ReceiptAckCipher`] -- the envelope refused to seal an acknowledgement.
	/// - [`HandshakeError::SealedIdentity`] -- the envelope refused to seal an identity.
	/// - [`HandshakeError::SealedFrame`] -- the identity exceeds the frame.
	/// - [`HandshakeError::DerError`] -- the transcript hash attribute fails to encode.
	pub(crate) fn seal(self, plaintext: impl AsRef<[u8]>) -> Result<AuthEnvelopedData, HandshakeError> {
		let framed = self.purpose.frame(plaintext.as_ref())?;
		let transcript = self.transcript_attribute()?;
		let key_identifier = self.key_identifier();
		let recipient = Recipient::Kek { kek: &self.kek, key_identifier: &key_identifier };

		let sealed = AuthEnvelopedData::seal::<P>(recipient, DATA, framed.as_slice(), [transcript], None);
		sealed.map_err(|error| self.purpose.refusal(error))
	}

	/// Open the `AuthEnvelopedData` whose DER is `der`, which a sealer of the
	/// same secret, purpose, and transcript sealed, and strip its frame.
	///
	/// The transcript hash attribute is checked before the content decrypts,
	/// and the tag then covers it.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ReceiptAckCipher`] -- an acknowledgement fails to
	///   open, so it was sealed under another handshake secret or another
	///   transcript, or altered in flight.
	/// - [`HandshakeError::SealedIdentity`] -- an identity fails to open.
	/// - [`HandshakeError::SealedFrame`] -- the opened frame of an identity is malformed.
	/// - [`HandshakeError::DerError`] -- the transcript hash attribute fails to encode.
	pub(crate) async fn open(self, der: impl AsRef<[u8]>) -> Result<SecretSlice<u8>, HandshakeError> {
		let der = der.as_ref();
		let envelope = AuthEnvelopedData::from_der(der);
		let envelope = envelope.map_err(|error| self.purpose.refusal(EnvelopeError::Encoding(error)))?;

		// 1. Refuse another transcript before the content decrypts.
		self.refuse_unbound(envelope.auth_attrs.as_ref())?;
		let key_identifier = self.key_identifier();
		let opener = Opener::Kek { kek: &self.kek, key_identifier: &key_identifier };

		// 2. Open the content under the tag, which covers the attributes.
		let opened = envelope.open::<P>(der, &opener, DATA).await;
		let opened = opened.map_err(|error| self.purpose.refusal(error))?;
		opened.with(|framed| self.purpose.unframe(framed))
	}

	/// The key-encryption key and the `kekid` an outside CMS reader opens
	/// this seal with.
	#[cfg(test)]
	pub(crate) fn kek_opening(&self) -> (Vec<u8>, Vec<u8>) {
		(self.kek.to_vec(), self.key_identifier())
	}

	/// The `kekid` of this seal: the purpose's domain, then the transcript
	/// hash.
	fn key_identifier(&self) -> Vec<u8> {
		[self.purpose.domain(), self.transcript_hash.as_bytes()].concat()
	}

	/// The authenticated attribute that carries the transcript hash.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DerError`] -- the attribute fails to encode.
	fn transcript_attribute(&self) -> Result<Attribute, HandshakeError> {
		let hash = OctetString::new(self.transcript_hash.as_bytes())?;
		let values = SetOfVec::try_from(vec![Any::encode_from(&hash)?])?;
		Ok(Attribute { oid: HANDSHAKE_TRANSCRIPT_HASH, values })
	}

	/// Refuse `auth_attrs` unless it carries the transcript hash attribute of
	/// this sealer, once under its OID.
	///
	/// # Errors
	///
	/// - The refusal of the purpose -- the attribute is absent, repeated, or names another transcript.
	/// - [`HandshakeError::DerError`] -- the expected attribute fails to encode.
	fn refuse_unbound(&self, auth_attrs: Option<&Attributes>) -> Result<(), HandshakeError> {
		let expected = self.transcript_attribute()?;
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

	/// Take the secret out, for the session that derives from it.
	pub(crate) fn into_secret(self) -> HandshakeSecret {
		self.0
	}
}

/// The proof that an endpoint derived the handshake secret of one transcript.
///
/// [`HandshakeSecret::confirmation`] derives the tag an endpoint sends or
/// expects, as wide as the output of the negotiated digest. A received tag
/// decodes as an OCTET STRING of a digest output width, from 32 to 64 bytes,
/// and a tag of another digest's width fails the comparison.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[derive(Clone, Copy)]
pub struct KeyConfirmation(DigestOutput);

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl KeyConfirmation {
	/// Verify in constant time that `received` is this tag.
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

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod sealed {
	/// Closes [`TrafficSecret`](super::TrafficSecret) to this module.
	pub trait Sealed {}
}

/// A secret that traffic keys derive from.
///
/// The directional derivation takes an implementor, and the implementors are
/// the handshake secret and the epoch secret that rotates from it. The trait
/// is sealed, so those two are the only inputs the derivation has.
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
/// Epoch 0 derives from the [`HandshakeSecret`] through
/// [`EpochMaterials::derive`], and each rotation derives the next link from
/// the previous one and a fresh agreement through [`Self::next`]. Those two
/// are its constructors.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) struct EpochSecret(ZeroizingBytes);

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl sealed::Sealed for EpochSecret {}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl TrafficSecret for EpochSecret {
	fn as_bytes(&self) -> &[u8] {
		&self.0
	}
}

#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
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
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
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
		let shared = local.shared_secret(peer.as_public_key());

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
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[allow(dead_code)]
	pub(crate) secret: EpochSecret,
	/// Epoch counter. It is 0 at handshake and increments on each rekey
	/// install.
	pub(crate) epoch: u32,
	/// Chained transcript hash. `hash_0` is the handshake transcript.
	pub(crate) transcript_hash: TranscriptHash,
}

impl EpochMaterials {
	/// Return the current epoch number.
	pub fn epoch(&self) -> u32 {
		self.epoch
	}

	/// Return the current chained transcript hash, at the full width of the
	/// negotiated digest.
	pub fn transcript_hash(&self) -> TranscriptHash {
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

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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
		transcript_hash: TranscriptHash,
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
	any(feature = "transport-cms", feature = "transport-hpke")
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
	/// - [`HandshakeError::TranscriptDigestLength`] -- the output of `D` is not 32 to 64 bytes.
	pub(crate) fn exchange_pin<D: Digest + AssociatedOid>(
		&self,
		request_der: impl AsRef<[u8]>,
		server_random: &[u8; 32],
		server_ephemeral: &[u8; EC_PUBKEY_COMPRESSED_SIZE],
	) -> Result<TranscriptHash, HandshakeError> {
		let hash = self.transcript_hash.as_bytes();
		let legs: [&[u8]; 4] = [hash, request_der.as_ref(), server_random, server_ephemeral];
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

/// Epoch secret length in bytes: one 256-bit KDF chain link.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const EPOCH_SECRET_SIZE: usize = 32;

/// The compressed SEC1 encoding of an ephemeral public key.
///
/// The HPKE transcript and the rekey pin take the point at this width, so an
/// ephemeral of any other length fails before the signature check rather than
/// hashing as a variable-length leg.
#[cfg(any(
	feature = "transport-hpke",
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
	feature = "transport-hpke",
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

/// A peer's ephemeral as a point of the curve other than the identity, the
/// one input [`Agreement`] takes.
///
/// [`Self::parse`] admits any such point, and [`PeerEphemeral`] admits one
/// whose x-coordinate differs from a static key known before the agreement.
/// A server learns its client's static key only after the agreement, so the
/// server's `Offer` refuses a collapsed client ephemeral instead.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct PeerPoint<C: CurveArithmetic>(PublicKey<C>);

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<C: HandshakeCurve> PeerPoint<C> {
	/// Parse `sec1` as a peer ephemeral. It is the one parse of an ephemeral
	/// that the handshake secret agrees with, and [`PeerEphemeral`] runs it
	/// before its comparison.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- `sec1` is not a point on the curve.
	pub(crate) fn parse(sec1: impl AsRef<[u8]>) -> Result<Self, HandshakeError> {
		let point = PublicKey::<C>::from_sec1_bytes(sec1.as_ref())?;
		Ok(Self(point))
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<C: CurveArithmetic> PeerPoint<C> {
	/// The admitted point, for the scalar multiplication that reads it.
	pub(crate) fn as_public_key(&self) -> &PublicKey<C> {
		&self.0
	}
}

/// The static key a peer's ephemeral is admitted against, when the peer holds
/// one.
///
/// The parse refuses a malformed, off-curve, or identity point, so no scalar
/// multiplication runs on an invalid one. A point with the x-coordinate of the
/// static key is refused as well. ECDH keeps the x-coordinate alone, so that
/// point and its negation both collapse the agreement into the static one.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) trait PeerEphemeral<C>
where
	C: HandshakeCurve,
{
	/// Admit `point` as an ephemeral of this peer, or `None` when it collapses
	/// into the peer's static key.
	fn distinct(&self, point: PublicKey<C>) -> Option<PeerPoint<C>>;

	/// Parse `sec1` as an ephemeral of this peer, or `None` when the point
	/// collapses into the peer's static key.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- `sec1` is not a point on the curve.
	fn distinct_ephemeral(&self, sec1: &[u8]) -> Result<Option<PeerPoint<C>>, HandshakeError> {
		let PeerPoint(point) = PeerPoint::parse(sec1)?;
		Ok(self.distinct(point))
	}

	/// Parse `sec1` as the ephemeral of this server.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- `sec1` is not a point on the curve.
	/// - [`HandshakeError::ServerEphemeralIsStatic`] -- the point collapses into the server's static key.
	fn server_ephemeral(&self, sec1: &[u8]) -> Result<PeerPoint<C>, HandshakeError> {
		let distinct = self.distinct_ephemeral(sec1)?;
		distinct.ok_or(HandshakeError::ServerEphemeralIsStatic)
	}

	/// Parse `sec1` as the ephemeral of this client at a rekey, where the
	/// client's static key is known before the agreement.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- `sec1` is not a point on the curve.
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- the point collapses into the client's static key.
	#[cfg(feature = "transport-multiplex")]
	fn client_ephemeral(&self, sec1: &[u8]) -> Result<PeerPoint<C>, HandshakeError> {
		let distinct = self.distinct_ephemeral(sec1)?;
		distinct.ok_or(HandshakeError::ClientEphemeralIsStatic)
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<C: HandshakeCurve> PeerEphemeral<C> for PublicKey<C> {
	fn distinct(&self, point: PublicKey<C>) -> Option<PeerPoint<C>> {
		let ephemeral = point.to_encoded_point(false);
		let static_key = self.to_encoded_point(false);
		if ephemeral.x() == static_key.x() {
			return None;
		}

		Some(PeerPoint(point))
	}
}

/// ECDH key agreement on the handshake plane.
///
/// The ephemeral-ephemeral step runs it with the client's [`SecretKey`], or
/// with the [`EphemeralSecret`] the server drew for one handshake.
///
/// Every peer arrives as a parsed [`PublicKey`], so each point has passed
/// `from_sec1_bytes` before it reaches a scalar multiplication.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) trait HandshakeAgreement<C>
where
	C: HandshakeCurve,
{
	/// ECDH with `peer`, as the shared secret the key schedule takes. A
	/// handshake curve fixes that secret at 32 bytes, which is the width of
	/// [`EcdhSecret`].
	fn shared_secret(&self, peer: &PublicKey<C>) -> EcdhSecret;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<C> HandshakeAgreement<C> for EphemeralSecret<C>
where
	C: HandshakeCurve,
{
	fn shared_secret(&self, peer: &PublicKey<C>) -> EcdhSecret {
		EcdhSecret::from(self.diffie_hellman(peer))
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<C> HandshakeAgreement<C> for SecretKey<C>
where
	C: HandshakeCurve,
{
	fn shared_secret(&self, peer: &PublicKey<C>) -> EcdhSecret {
		EcdhSecret::agree(self, peer)
	}
}

/// The peer point beside the base secret that follows its agreement output,
/// borrowed for one settlement.
///
/// Each protocol builds one where both halves exist, and [`Self::settle`] is
/// the one derivation of the [`HandshakeSecret`].
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) struct Agreement<'a, P: HandshakeProvider> {
	peer: &'a PeerPoint<P::Curve>,
	base: &'a BaseSecret,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<'a, P: HandshakeProvider> Agreement<'a, P> {
	/// Pair the ephemeral `peer` with the `base` that follows its agreement.
	pub(crate) fn new(peer: &'a PeerPoint<P::Curve>, base: &'a BaseSecret) -> Self {
		Self { peer, base }
	}

	/// Run the agreement of `local` with the peer point, and derive the hybrid
	/// handshake secret of that output and the base secret under `salt`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
	pub(crate) fn settle(
		self,
		local: &impl HandshakeAgreement<P::Curve>,
		salt: KdfSalt<'_>,
	) -> Result<HandshakeSecret, HandshakeError> {
		let shared = local.shared_secret(self.peer.as_public_key());
		HandshakeSecret::hybrid::<P>(&shared, self.base, salt)
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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
/// The fields are fixed together at the leg that seals the transcript, so a
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
	/// Fix the terms of one handshake.
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
	pub(crate) fn kdf_salt(&self) -> KdfSalt<'_> {
		match &self.salt.0 {
			#[cfg(feature = "transport-hpke")]
			SaltSource::Randoms(randoms) => randoms.as_kdf_salt(),
			#[cfg(feature = "transport-cms")]
			SaltSource::TranscriptHash => KdfSalt::new(self.transcript_hash.as_bytes()),
		}
	}

	/// The key-confirmation tag of `secret` over the transcript of these
	/// terms.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- HKDF refused the length of the tag's key.
	pub(crate) fn confirmation(&self, secret: &HandshakeSecret) -> Result<KeyConfirmation, HandshakeError> {
		secret.confirmation::<P>(self.kdf_salt(), self.transcript_hash())
	}

	/// `secret`, once `received` confirms it over the transcript of these
	/// terms.
	///
	/// # Errors
	///
	/// - The [`HandshakeSecret::confirmed`] set.
	pub(crate) fn confirm(
		&self,
		secret: HandshakeSecret,
		received: &KeyConfirmation,
	) -> Result<ConfirmedSecret, HandshakeError> {
		secret.confirmed::<P>(self.kdf_salt(), self.transcript_hash(), received)
	}

	/// The single-use seal of `purpose` under `secret`, bound to the salt and
	/// the transcript of these terms.
	///
	/// # Errors
	///
	/// - The [`HandshakeSecret::sealer`] set.
	pub(crate) fn sealer(&self, secret: &HandshakeSecret, purpose: SecretSeal) -> Result<Sealer<P>, HandshakeError> {
		secret.sealer::<P>(purpose, self.kdf_salt(), self.transcript_hash())
	}
}

/// The certificate a role records as its peer.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub trait PeerIdentity: MaybeSend + MaybeSync + 'static {
	/// The certificate the session records, or `None` when the peer proved no
	/// identity.
	fn certificate(&self) -> Option<&Arc<Certificate>>;
}

/// What both sides hold once the handshake secret exists.
///
/// [`Self::complete`] consumes it, so one handshake derives one session.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct Agreed<P: HandshakeProvider, Peer: PeerIdentity> {
	terms: Terms<P>,
	secret: HandshakeSecret,
	receipt: Option<StoredReceipt>,
	peer: Peer,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub trait HandshakeVerifyingKey {
	/// Public key parsed from this certificate's SPKI, on curve `C`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- the certificate key bytes fail SEC1 decoding.
	fn verifying_key<C: HandshakeCurve>(&self) -> Result<PublicKey<C>, HandshakeError>;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl HandshakeVerifyingKey for Certificate {
	fn verifying_key<C: HandshakeCurve>(&self) -> Result<PublicKey<C>, HandshakeError> {
		let pubkey_bytes = self.verifying_key_bytes();
		Ok(PublicKey::<C>::from_sec1_bytes(pubkey_bytes)?)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::constants::TIGHTBEAM_ACK_KEY_ID_DOMAIN;
	use crate::crypto::hash::{Sha3_256, Sha3_512};
	use crate::crypto::profiles::{AeadProvider, DefaultCryptoProvider};
	use crate::crypto::secret::ToInsecure;
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::der::asn1::OctetString;
	use crate::der::{Decode, Encode};
	use crate::random::OsRng;
	use crate::testing::{Aes256Sha3_512Provider, EnvelopeRecipient};
	use crate::transport::handshake::tests::{create_test_certificate, fixture_transcript, negated};

	/// A base secret of `fill` bytes.
	fn base_secret(fill: u8) -> BaseSecret {
		BaseSecret::try_from(SecretSlice::from(vec![fill; 32])).expect("32 bytes make a base secret")
	}

	/// The handshake secret of fixture inputs `shared` and `base` under
	/// `salt`.
	fn handshake_secret(shared: u8, base: u8, salt: &[u8]) -> HandshakeSecret {
		let shared = EcdhSecret::from([shared; 32]);
		let base = base_secret(base);
		let secret = HandshakeSecret::hybrid::<DefaultCryptoProvider>(&shared, &base, KdfSalt::new(salt));
		secret.expect("fixture inputs derive a handshake secret")
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
		let secret = handshake_secret(0x11, 0x42, &salt);
		let result = derive_directional(&secret, &salt);
		assert!(result.is_ok());
	}

	/// The static key of a fresh test certificate.
	fn static_key() -> PublicKey<Secp256k1> {
		let client = create_test_certificate();
		PublicKey::from(client.signing_key.verifying_key())
	}

	/// The parse knows no static key, so any point of the curve parses as a
	/// peer point.
	#[test]
	fn any_point_of_the_curve_parses_as_a_peer_point() -> Result<(), HandshakeError> {
		let key = static_key();
		let point = key.to_encoded_point(true);

		let parsed = PeerPoint::<Secp256k1>::parse(point.as_bytes())?;
		assert_eq!(parsed.as_public_key(), &key);
		Ok(())
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn a_client_ephemeral_equal_to_the_client_static_key_is_refused() {
		let static_key = static_key();
		let point = static_key.to_encoded_point(true);

		let refused = static_key.client_ephemeral(point.as_bytes());
		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn a_client_ephemeral_other_than_the_static_key_is_admitted() -> Result<(), HandshakeError> {
		let static_key = static_key();
		let other_key = SecretKey::<Secp256k1>::random(&mut OsRng).public_key();
		let point = other_key.to_encoded_point(true);

		let admitted = static_key.client_ephemeral(point.as_bytes())?;
		assert_eq!(admitted.as_public_key(), &other_key);
		Ok(())
	}

	/// ECDH keeps the x-coordinate alone, so the negation of a static key
	/// agrees to the secret the key itself agrees to.
	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn the_negation_of_the_client_static_key_is_refused_as_its_ephemeral() {
		let static_key = static_key();
		let point = negated(&static_key).to_encoded_point(true);

		let refused = static_key.client_ephemeral(point.as_bytes());
		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
	}

	#[test]
	fn the_negation_of_the_server_static_key_is_refused_as_its_ephemeral() {
		let static_key = static_key();
		let point = negated(&static_key).to_encoded_point(true);

		let refused = static_key.server_ephemeral(point.as_bytes());
		assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
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
	/// random contribution stays load-bearing beside the agreement.
	#[test]
	fn the_handshake_secret_depends_on_the_base_secret() {
		let salt = [0x99u8; 32];
		let first = handshake_secret(0x11, 0x42, &salt);
		let second = handshake_secret(0x11, 0x43, &salt);
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
	fn ack_transcript() -> TranscriptHash {
		fixture_transcript::<Sha3_256>([0x07u8; 32])
	}

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
		let transcript_hash = ack_transcript();
		let materials = EpochMaterials { secret, epoch: 0, transcript_hash };

		let pin = materials.exchange_pin::<Sha3_256>(b"request der", &[0x21u8; 32], &[0x02u8; 33])?;
		let expected = [
			0x63, 0x36, 0x6b, 0x7a, 0x2d, 0xa7, 0xb4, 0x7b, 0xe9, 0xc3, 0x4c, 0xca, 0x39, 0x08, 0x11, 0x9f, 0x61, 0xc2,
			0x58, 0x9d, 0xc7, 0x45, 0x84, 0x8b, 0x2a, 0xd8, 0x55, 0xc7, 0xa7, 0xdc, 0x83, 0xde,
		];
		assert_eq!(pin.as_bytes(), expected);
		Ok(())
	}

	/// The materials of an epoch whose chain hash is the 64 bytes of a
	/// SHA3-512 transcript.
	#[cfg(feature = "transport-multiplex")]
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
	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn a_sha3_512_exchange_pin_matches_its_known_answer() -> Result<(), HandshakeError> {
		let pin = wide_materials().exchange_pin::<Sha3_512>(b"request der", &[0x21u8; 32], &[0x02u8; 33])?;
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
	#[cfg(feature = "transport-multiplex")]
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

	/// The handshake secret is HKDF-SHA3-256 under the salt and the session
	/// label over the hybrid secret, the plain concatenation of the ECDH
	/// output `0x11` × 32 and the base secret `0x42` × 32.
	///
	/// The expected bytes come from an independent HKDF (Python's `hmac` and
	/// `hashlib`), so a swap of the two parts or a framing fails here.
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
	/// keyed by the 32 bytes HKDF-SHA3-256 expands under the Finished label
	/// from the PRK the salt extracts of the handshake secret.
	///
	/// The expected bytes come from an independent HKDF and HMAC (Python's
	/// `hmac` and `hashlib`), so no code of the crate computes them.
	#[test]
	fn the_key_confirmation_matches_its_known_answer() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let transcript_hash = ack_transcript();

		let tag = fixed_secret().confirmation::<DefaultCryptoProvider>(KdfSalt::new(&salt), &transcript_hash)?;
		let expected = [
			0x3c, 0x06, 0xdc, 0xe1, 0x71, 0xc7, 0xc0, 0xc4, 0x21, 0x78, 0x10, 0xf0, 0x10, 0xfd, 0x0a, 0x0e, 0xe5, 0xa1,
			0x83, 0xed, 0xa5, 0x5a, 0xf6, 0xa3, 0x3f, 0x3f, 0x06, 0xf4, 0x66, 0x04, 0x9d, 0xee,
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
		let salt = [0x99u8; 32];
		let transcript_hash = fixture_transcript::<Sha3_512>([0x07u8; 64]);

		let tag = fixed_secret().confirmation::<Aes256Sha3_512Provider>(KdfSalt::new(&salt), &transcript_hash)?;
		let expected = [
			0x73, 0x23, 0xc0, 0x00, 0x68, 0x56, 0xaf, 0xbf, 0x60, 0x4b, 0xd8, 0x71, 0xf0, 0x66, 0xe6, 0xe0, 0x4b, 0x55,
			0x61, 0x91, 0x40, 0x63, 0xc8, 0xcd, 0x09, 0x90, 0x4e, 0xfa, 0xd4, 0xbf, 0xc1, 0xb5, 0xb0, 0x9c, 0x10, 0x95,
			0x6b, 0xa6, 0xb9, 0x2f, 0x19, 0xfc, 0xce, 0x3b, 0x07, 0x5b, 0xca, 0xdc, 0x6a, 0x44, 0x55, 0x22, 0x55, 0xf4,
			0x7a, 0xdb, 0xc1, 0x49, 0xc0, 0xe2, 0x3b, 0x61, 0xc4, 0x40,
		];
		assert_eq!(tag.0.as_bytes(), expected);
		Ok(())
	}

	/// A tag of another digest's width fails the comparison, so a peer under
	/// another digest confirms nothing.
	#[test]
	fn a_key_confirmation_of_another_width_is_refused() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let transcript_hash = ack_transcript();
		let tag = fixed_secret().confirmation::<DefaultCryptoProvider>(KdfSalt::new(&salt), &transcript_hash)?;
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

		let tag = secret.confirmation::<DefaultCryptoProvider>(KdfSalt::new(&salt), &transcript_hash)?;
		let same = secret.confirmation::<DefaultCryptoProvider>(KdfSalt::new(&salt), &transcript_hash)?;
		let foreign = other.confirmation::<DefaultCryptoProvider>(KdfSalt::new(&salt), &transcript_hash)?;
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
		let sealer = secret.sealer::<DefaultCryptoProvider>(purpose, KdfSalt::new(&salt), transcript_hash);
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

	/// `sealed` with the transcript hash attribute naming `transcript_hash`
	/// in place of its own, under the same `kekid`.
	fn with_transcript_attribute(mut sealed: AuthEnvelopedData, transcript_hash: &TranscriptHash) -> AuthEnvelopedData {
		let other = sealer_of(&fixed_secret(), SecretSeal::Ack, transcript_hash);
		let attribute = other.transcript_attribute().expect("the attribute encodes");
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

	/// An acknowledgement sealed under one handshake secret opens under the
	/// same secret, salt, and transcript.
	#[tokio::test]
	async fn a_sealed_ack_opens_under_the_same_handshake_secret() -> Result<(), HandshakeError> {
		let secret = fixed_secret();
		let sealed = sealer_of(&secret, SecretSeal::Ack, &ack_transcript()).seal(b"settlement answer")?;

		let opener = sealer_of(&secret, SecretSeal::Ack, &ack_transcript());
		let opened = opener.open(sealed.to_der()?).await?;
		assert!(opened.with(|bytes| bytes.as_slice() == b"settlement answer"));
		Ok(())
	}

	/// An acknowledgement sealed under one handshake secret does not open
	/// under another, so a recording plus the base secret alone reads nothing.
	#[tokio::test]
	async fn a_sealed_ack_refuses_another_handshake_secret() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x11, 0x42, &salt);
		let other = handshake_secret(0x12, 0x42, &salt);
		let sealed = sealer_of(&secret, SecretSeal::Ack, &ack_transcript()).seal(b"settlement answer")?;

		let opener = sealer_of(&other, SecretSeal::Ack, &ack_transcript());
		let refused = opener.open(sealed.to_der()?).await;
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
		let sealed = sealer_of(&secret, SecretSeal::Ack, &ack_transcript()).seal(b"settlement answer")?;

		let opener = sealer_of(&secret, SecretSeal::Ack, &other_transcript);
		let refused = opener.open(sealed.to_der()?).await;
		assert!(matches!(
			refused,
			Err(HandshakeError::ReceiptAckCipher(EnvelopeError::AuthenticatedAttribute))
		));
		Ok(())
	}

	/// A seal whose transcript hash attribute names another transcript is
	/// refused before its content decrypts, though its `kekid` is the
	/// opener's.
	#[tokio::test]
	async fn a_seal_whose_transcript_attribute_differs_is_refused() -> Result<(), HandshakeError> {
		let secret = fixed_secret();
		let sealed = sealer_of(&secret, SecretSeal::Ack, &ack_transcript()).seal(b"settlement answer")?;
		let other_transcript = fixture_transcript::<Sha3_256>([0x08u8; 32]);
		let sealed = with_transcript_attribute(sealed, &other_transcript);

		let opener = sealer_of(&secret, SecretSeal::Ack, &ack_transcript());
		let refused = opener.open(sealed.to_der()?).await;
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
		let sealed = sealer_of(&fixed_secret(), SecretSeal::Ack, &transcript).seal(b"settlement answer")?;

		let opener = sealer_of(&fixed_secret(), SecretSeal::Ack, &last_byte_differs);
		let refused = opener.open(sealed.to_der()?).await;
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
		assert_eq!(*sealer.kek, expected);
	}

	/// The identity key-encryption key is HKDF-SHA3-256 of the handshake
	/// secret under the salt and the identity label.
	///
	/// The expected bytes come from an independent HKDF (Python's `hmac` and
	/// `hashlib`), so no code of the crate computes them.
	#[test]
	fn the_identity_key_matches_its_known_answer() {
		let sealer = sealer_of(&fixed_secret(), SecretSeal::Identity, &ack_transcript());

		let expected = [
			0xae, 0x1f, 0x8a, 0xa6, 0x84, 0x93, 0xcf, 0xc4, 0x31, 0x4d, 0xfd, 0xc3, 0xe3, 0xb9, 0xa5, 0x3a, 0x5c, 0x4c,
			0xed, 0x34, 0x92, 0x67, 0x49, 0xa1, 0x1b, 0x86, 0x41, 0x6b, 0xa7, 0x37, 0x70, 0xda,
		];
		assert_eq!(*sealer.kek, expected);
	}

	/// The `kekid` of a seal is its purpose domain followed by the transcript
	/// hash.
	#[test]
	fn a_seal_names_its_key_by_its_purpose_and_its_transcript() -> Result<(), HandshakeError> {
		let sealed = sealer_of(&fixed_secret(), SecretSeal::Ack, &ack_transcript()).seal(b"settlement answer")?;

		let expected = [TIGHTBEAM_ACK_KEY_ID_DOMAIN, [0x07u8; 32].as_slice()].concat();
		assert_eq!(key_identifier_of(&sealed), expected);
		Ok(())
	}

	/// A seal carries the transcript hash as an authenticated attribute.
	#[test]
	fn a_seal_authenticates_its_transcript_hash() -> Result<(), HandshakeError> {
		let sealed = sealer_of(&fixed_secret(), SecretSeal::Ack, &ack_transcript()).seal(b"settlement answer")?;
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
		let sealed = sealer_of(&fixed_secret(), SecretSeal::Ack, &ack_transcript()).seal(b"settlement answer")?;
		assert_eq!(content_len(&sealed), Some(b"settlement answer".len()));
		Ok(())
	}

	/// The identity seal frames the plaintext with its length and pads it with
	/// zero bytes to 1024, so its encrypted content is 1024 octets.
	#[test]
	fn an_identity_seals_padded_to_the_floor() -> Result<(), HandshakeError> {
		let sealed = sealer_of(&fixed_secret(), SecretSeal::Identity, &ack_transcript()).seal(b"client identity")?;
		assert_eq!(content_len(&sealed), Some(1024));
		Ok(())
	}

	/// An identity opens to the plaintext it sealed, without its frame.
	#[tokio::test]
	async fn a_sealed_identity_opens_to_its_plaintext() -> Result<(), HandshakeError> {
		let secret = fixed_secret();
		let sealed = sealer_of(&secret, SecretSeal::Identity, &ack_transcript()).seal(b"client identity")?;

		let opener = sealer_of(&secret, SecretSeal::Identity, &ack_transcript());
		let opened = opener.open(sealed.to_der()?).await?;

		assert!(opened.with(|bytes| bytes.as_slice() == b"client identity"));
		Ok(())
	}

	/// Two identities whose lengths differ within one padding step seal to
	/// one length, so the length does not tell the two clients apart.
	#[test]
	fn two_identities_within_one_step_seal_to_one_length() -> Result<(), HandshakeError> {
		let secret = fixed_secret();

		let short = sealer_of(&secret, SecretSeal::Identity, &ack_transcript()).seal([0x01u8; 600])?;
		let long = sealer_of(&secret, SecretSeal::Identity, &ack_transcript()).seal([0x01u8; 900])?;
		assert_eq!(short.to_der()?.len(), long.to_der()?.len());
		Ok(())
	}

	/// An identity past the floor pads to the next step.
	#[test]
	fn an_identity_past_the_floor_pads_to_the_next_step() -> Result<(), HandshakeError> {
		let sealed = sealer_of(&fixed_secret(), SecretSeal::Identity, &ack_transcript()).seal([0x01u8; 1100])?;
		assert_eq!(content_len(&sealed), Some(1536));
		Ok(())
	}

	/// The two purposes derive two keys, so an identity does not open under
	/// the acknowledgement key.
	#[tokio::test]
	async fn an_identity_does_not_open_under_the_ack_key() -> Result<(), HandshakeError> {
		let secret = fixed_secret();
		let sealed = sealer_of(&secret, SecretSeal::Identity, &ack_transcript()).seal(b"client identity")?;

		let opener = sealer_of(&secret, SecretSeal::Ack, &ack_transcript());
		let refused = opener.open(sealed.to_der()?).await;
		assert!(matches!(
			refused,
			Err(HandshakeError::ReceiptAckCipher(EnvelopeError::KeyIdentifier))
		));
		Ok(())
	}

	/// A frame of its padded length whose padding holds a non-zero byte is
	/// refused.
	#[test]
	fn a_frame_with_a_non_zero_pad_is_refused() {
		let mut framed = vec![0x00u8; 1024];
		framed[..3].copy_from_slice(&[0x00, 0x01, 0xaa]);
		framed[1023] = 0x01;

		let refused = SecretSeal::Identity.unframe(&framed);
		assert!(matches!(refused, Err(HandshakeError::SealedFrame)));
	}

	/// A frame whose length runs past its end is refused.
	#[test]
	fn a_frame_whose_length_runs_past_its_end_is_refused() {
		let framed = [0x00, 0x09, 0xaa, 0x00];
		let refused = SecretSeal::Identity.unframe(&framed);
		assert!(matches!(refused, Err(HandshakeError::SealedFrame)));
	}

	/// A frame that holds its plaintext and zero bytes, but runs past its
	/// padded length, is refused.
	#[test]
	fn a_frame_longer_than_its_padded_length_is_refused() {
		let mut framed = vec![0x00u8; 1536];
		framed[..3].copy_from_slice(&[0x00, 0x01, 0xaa]);

		let refused = SecretSeal::Identity.unframe(&framed);
		assert!(matches!(refused, Err(HandshakeError::SealedFrame)));
	}

	/// An identity whose length prefix carries its frame past the floor opens
	/// to the plaintext it sealed.
	#[tokio::test]
	async fn an_identity_whose_prefix_crosses_the_floor_opens() -> Result<(), HandshakeError> {
		let secret = fixed_secret();
		let identity = [0x01u8; 1023];
		let sealed = sealer_of(&secret, SecretSeal::Identity, &ack_transcript()).seal(identity)?;

		let opener = sealer_of(&secret, SecretSeal::Identity, &ack_transcript());
		let opened = opener.open(sealed.to_der()?).await?;

		assert!(opened.with(|bytes| bytes.as_slice() == identity));
		Ok(())
	}

	/// A frame that holds its plaintext and zero bytes, but falls short of its
	/// padded length, is refused.
	#[test]
	fn a_frame_shorter_than_its_padded_length_is_refused() {
		let framed = [0x00, 0x01, 0xaa, 0x00];
		let refused = SecretSeal::Identity.unframe(&framed);
		assert!(matches!(refused, Err(HandshakeError::SealedFrame)));
	}

	/// An identity past the `u16` length of the frame is refused at the seal.
	#[test]
	fn an_identity_past_the_frame_length_is_refused() {
		let oversized = vec![0x01u8; usize::from(u16::MAX) + 1];
		let refused = sealer_of(&fixed_secret(), SecretSeal::Identity, &ack_transcript()).seal(oversized);
		assert!(matches!(refused, Err(HandshakeError::SealedFrame)));
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
		let secret = handshake_secret(0x11, 0x42, &salt);
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
		let secret = handshake_secret(0x11, 0x42, &salt);
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

	/// The terms derive one key per purpose, so an identity they seal does
	/// not open under their acknowledgement key.
	#[tokio::test]
	async fn the_terms_seal_each_purpose_under_its_own_key() -> Result<(), HandshakeError> {
		let terms = terms_with(&ack_transcript(), Salt::transcript_hash());
		let secret = fixed_secret();
		let sealed = terms.sealer(&secret, SecretSeal::Identity)?.seal(b"client identity")?;

		let refused = terms.sealer(&secret, SecretSeal::Ack)?.open(sealed.to_der()?).await;
		assert!(matches!(
			refused,
			Err(HandshakeError::ReceiptAckCipher(EnvelopeError::KeyIdentifier))
		));
		Ok(())
	}

	/// A CMS handshake salts every derivation with its transcript hash.
	#[test]
	fn a_transcript_salt_is_the_transcript_hash() {
		let terms = terms_with(&ack_transcript(), Salt::transcript_hash());
		assert_eq!(terms.kdf_salt().as_bytes(), [0x07u8; 32]);
	}

	/// A CMS handshake under a 512-bit digest salts every derivation with all
	/// 64 bytes of its transcript hash.
	#[test]
	fn a_transcript_salt_carries_all_64_bytes_of_the_hash() {
		let transcript = fixture_transcript::<Sha3_512>([0x07u8; 64]);
		let terms = terms_with(&transcript, Salt::transcript_hash());
		assert_eq!(terms.kdf_salt().as_bytes(), [0x07u8; 64]);
	}

	/// An HPKE handshake salts every derivation with the client random
	/// followed by the server random.
	#[test]
	fn a_randoms_salt_is_the_client_random_then_the_server_random() {
		let terms = terms_with(&ack_transcript(), Salt::randoms(&[0x01u8; 32], &[0x02u8; 32]));
		assert_eq!(terms.kdf_salt().as_bytes(), [[0x01u8; 32], [0x02u8; 32]].concat());
	}

	#[test]
	fn test_derive_epoch_materials_shape() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x11, 0x42, &salt);
		let transcript = ack_transcript();

		let materials = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, KdfSalt::new(&salt), transcript)?;
		assert_eq!(materials.epoch(), 0);
		assert_eq!(materials.transcript_hash(), transcript);
		assert_eq!(materials.secret.as_bytes().len(), EPOCH_SECRET_SIZE);

		Ok(())
	}

	#[test]
	fn test_derive_epoch_materials_is_deterministic() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x11, 0x42, &salt);
		let transcript = ack_transcript();

		let first = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, KdfSalt::new(&salt), transcript)?;
		let second = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, KdfSalt::new(&salt), transcript)?;
		assert_eq!(first.secret.as_bytes(), second.secret.as_bytes());

		Ok(())
	}

	#[test]
	fn test_derive_epoch_materials_separates_inputs() -> Result<(), HandshakeError> {
		let salt = [0x99u8; 32];
		let other_salt = [0x9Au8; 32];
		let secret = handshake_secret(0x11, 0x42, &salt);
		let other_secret = handshake_secret(0x11, 0x43, &salt);
		let transcript = ack_transcript();

		let shared_salt = KdfSalt::new(&salt);
		let changed_salt = KdfSalt::new(&other_salt);
		let base = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, shared_salt, transcript)?;
		let keyed = EpochMaterials::derive::<DefaultCryptoProvider>(&other_secret, shared_salt, transcript)?;
		let salted = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, changed_salt, transcript)?;
		assert_ne!(base.secret.as_bytes(), keyed.secret.as_bytes());
		assert_ne!(base.secret.as_bytes(), salted.secret.as_bytes());

		Ok(())
	}

	/// The ephemeral holder converts the curve's own output, and the static
	/// holder multiplies in [`EcdhSecret::agree`], which HPKE also runs. Both
	/// reach one secret for one pair of keys.
	#[test]
	fn every_agreement_path_reaches_one_secret() {
		let ephemeral = EphemeralSecret::<Secp256k1>::random(&mut OsRng);
		let fixed = SecretKey::<Secp256k1>::random(&mut OsRng);
		let ephemeral_public = ephemeral.public_key();
		let fixed_public = fixed.public_key();

		let from_ephemeral = ephemeral.shared_secret(&fixed_public).to_insecure();
		let from_static = fixed.shared_secret(&ephemeral_public).to_insecure();
		assert_eq!(from_ephemeral, from_static);
	}
}
