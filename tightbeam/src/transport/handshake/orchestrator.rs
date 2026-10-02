//! Common traits and key-schedule types for handshake orchestrators.
//!
//! The CMS and ECIES client and server implementations share these:
//!
//! - [`HandshakeNegotiation`] negotiates the profile on the server side.
//! - [`HandshakeFinalization`] finalizes the AEAD session keys for every orchestrator.
//! - [`HandshakeAlertHandler`] processes alert attributes for every orchestrator.
//! - [`HandshakeSecret`] is the one secret a session derives from. Its two
//!   inputs are a [`BaseSecret`] and the [`EcdhSecret`] that
//!   [`HandshakeAgreement`] produces.
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
//! ```
//!
//! What this schedule withholds from a holder of the server's static key is
//! stated once, under
//! [forward secrecy](crate::transport::handshake#forward-secrecy).

use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::constants::{MIN_SALT_ENTROPY_BYTES, TIGHTBEAM_C2S_KDF_INFO, TIGHTBEAM_S2C_KDF_INFO};
use crate::crypto::aead::{DirectionalCiphers, KeyInit};
use crate::crypto::common::KeySizeUser;
use crate::crypto::kdf::KdfFunction;
use crate::crypto::profiles::{CryptoProvider, SecurityProfileDesc};
use crate::crypto::x509::attr::Attributes;
use crate::oids::HANDSHAKE_ABORT_ALERT;
use crate::transport::handshake::attributes::HandshakeAttributes;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{
	DefaultStrengthFloor, NegotiationError, ProfileStrengthPolicy, RunnableProfile, SecurityOffer,
};
use crate::transport::handshake::primitives::{KdfInfo, KdfSalt};
use crate::ZeroizingBytes;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use core::mem;

#[cfg(feature = "transport-ecies")]
use crate::constants::EC_PUBKEY_COMPRESSED_SIZE;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::constants::{
	TIGHTBEAM_ACK_AAD_DOMAIN, TIGHTBEAM_ACK_KDF_INFO, TIGHTBEAM_EPOCH_KDF_INFO, TIGHTBEAM_SESSION_KDF_INFO,
};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::aead::{Aead, Nonce, Payload};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::kdf::EcdhSecret;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::secret::SecretSlice;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::sign::elliptic_curve::ecdh::{diffie_hellman, EphemeralSecret};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey, SecretKey};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::x509::utils::CertificateExt;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::random::{generate_nonce, CryptoRngCore};
use crate::transport::handshake::attributes::HandshakeAlertAttribute;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::primitives::multi_input_kdf;
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use crate::transport::handshake::primitives::{kdf_chain, KdfStage};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::x509::Certificate;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::ZeroizingArray;

/// Provides profile negotiation logic for server-side handshake orchestrators.
///
/// A server must implement [`Self::supported_profiles`] to expose its
/// configured security profiles. The trait provides the default negotiation
/// logic for both the client-offered mode and the dealer's choice mode.
///
/// # Usage
///
/// - **Negotiation mode**: the client sends a [`SecurityOffer`], and the server
///   selects the first mutual profile in *server* preference order.
/// - **Dealer's choice mode**: the client sends no offer, and the server uses
///   its first configured profile that meets the strength policy.
///
/// # Security
///
/// Both modes filter profiles through [`ProfileStrengthPolicy`] before
/// selection, so a weak profile left in [`Self::supported_profiles`] for
/// compatibility cannot be negotiated (CWE-757 downgrade resistance).
pub trait HandshakeNegotiation<P>
where
	P: CryptoProvider,
{
	/// Return the profiles in server preference order, most preferred first.
	fn supported_profiles(&self) -> &[SecurityProfileDesc];

	/// Minimum-strength policy applied before selection.
	///
	/// Defaults to [`DefaultStrengthFloor`], which requires a 256-bit AEAD key
	/// and a digest of 256 bits or more.
	fn strength_policy(&self) -> &dyn ProfileStrengthPolicy {
		&DefaultStrengthFloor
	}

	/// Negotiate a security profile with the peer.
	///
	/// Only a configured profile that `P` runs is eligible, so the selection
	/// names only algorithms the provider runs.
	///
	/// # Errors
	///
	/// Each [`NegotiationError`] arrives wrapped in
	/// [`HandshakeError::NegotiationError`].
	///
	/// - [`HandshakeError::NoSupportedProfiles`] -- the server has no configured profile.
	/// - [`NegotiationError::UnrunnableProfile`] -- no configured profile runs on `P`.
	/// - [`NegotiationError::BelowStrengthFloor`] -- no runnable profile meets the policy.
	/// - [`NegotiationError::EmptyOffer`] -- the peer sent an empty offer.
	/// - [`NegotiationError::OfferTooLarge`] -- the offer holds too many profiles.
	/// - [`NegotiationError::NoMutualProfile`] -- no mutually supported profile exists.
	fn negotiate_profile(&self, offer: Option<&SecurityOffer>) -> Result<RunnableProfile<P>, HandshakeError> {
		let supported = self.supported_profiles();
		if supported.is_empty() {
			return Err(HandshakeError::NoSupportedProfiles);
		}

		let runnable: Vec<RunnableProfile<P>> = supported
			.iter()
			.filter_map(|descriptor| RunnableProfile::try_from(*descriptor).ok())
			.collect();
		if runnable.is_empty() {
			return Err(NegotiationError::UnrunnableProfile.into());
		}

		let policy = self.strength_policy();
		let eligible: Vec<SecurityProfileDesc> = runnable
			.iter()
			.filter(|profile| policy.meets_floor(&profile.strength()))
			.map(RunnableProfile::descriptor)
			.collect();

		let dealers_choice = eligible.first().copied().ok_or(NegotiationError::BelowStrengthFloor)?;
		let selected = match offer {
			Some(offer) => offer.select_profile(&eligible)?,
			None => dealers_choice,
		};
		Ok(RunnableProfile::try_from(selected)?)
	}
}

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
pub struct HandshakeSecret(ZeroizingBytes);

/// Handshake secret length in bytes.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
const HANDSHAKE_SECRET_SIZE: usize = 32;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl HandshakeSecret {
	/// Derive the handshake secret from `base` and the ephemeral-ephemeral
	/// ECDH output `shared`, extracted under `salt`.
	///
	/// Both protocols on both sides call it exactly once. The two inputs enter
	/// [`multi_input_kdf`] length-prefixed, in this order.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
	/// - [`HandshakeError::IntegerOutOfRange`] -- an input exceeds the framing prefix.
	pub(crate) fn derive<P>(base: &BaseSecret, shared: &EcdhSecret, salt: KdfSalt<'_>) -> Result<Self, HandshakeError>
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
	/// - [`HandshakeError::ReceiptAckCipher`] -- the AEAD refused the ciphertext, so it was sealed under
	///   another handshake secret or another transcript, or altered in flight.
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
impl fmt::Debug for HandshakeSecret {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("HandshakeSecret").finish_non_exhaustive()
	}
}

mod sealed {
	/// Closes [`TrafficSecret`](super::TrafficSecret) to this module.
	pub trait Sealed {}
}

/// A secret that traffic keys derive from.
///
/// The directional derivation takes an implementor, and the implementors are
/// the handshake secret and the epoch secret that rotates from it. The trait
/// is sealed, so those two are the only inputs the derivation has.
pub(crate) trait TrafficSecret: sealed::Sealed {
	/// The secret bytes, for the provider KDF that extracts from them.
	fn as_bytes(&self) -> &[u8];
}

impl sealed::Sealed for HandshakeSecret {}

impl TrafficSecret for HandshakeSecret {
	fn as_bytes(&self) -> &[u8] {
		&self.0
	}
}

/// One link of the rekey KDF chain, zeroized on drop and on rotation.
///
/// Epoch 0 derives from the [`HandshakeSecret`] through
/// [`EpochMaterials::derive`], and each rotation derives the next link from
/// the previous one through [`Self::next`]. Those two are its constructors.
pub(crate) struct EpochSecret(ZeroizingBytes);

impl sealed::Sealed for EpochSecret {}

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
	/// The next link of the rekey KDF chain, extracted from this one under
	/// `salt` and the epoch label.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
	pub(crate) fn next<P>(&self, salt: KdfSalt<'_>) -> Result<Self, HandshakeError>
	where
		P: CryptoProvider,
	{
		let stage = KdfStage { input: &self.0, info: KdfInfo::new(TIGHTBEAM_EPOCH_KDF_INFO) };
		let secret = kdf_chain::<P>(&[stage], salt)?;
		Ok(Self(secret))
	}
}

/// The secret an orchestrator holds for the phase its handshake is in.
///
/// - One value holds the pending material or the handshake secret, so an orchestrator holds one of them.
/// - The schedule advances `Idle`, `Pending`, `Consumed`, `Derived`, `Consumed`,
///   and each transition checks the variant it leaves, so a second key exchange
///   or a second derivation fails with [`HandshakeError::InvalidState`].
/// - Every take leaves [`Self::Consumed`] behind, so completion is the one read of the handshake secret.
/// - A take that finds another variant fails with [`HandshakeError::InvalidState`]
///   and leaves [`Self::Consumed`] behind, so a failed step has nothing to
///   derive from.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) enum KeySchedule<Pending> {
	/// No key material yet.
	Idle,
	/// What the side holds between its first secret and the agreement.
	Pending(Pending),
	/// The handshake secret, from the agreement to completion.
	Derived(HandshakeSecret),
	/// Completion took the handshake secret.
	Consumed,
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl<Pending> KeySchedule<Pending> {
	/// Hold `pending` from the first secret to the agreement.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the schedule already left [`Self::Idle`].
	pub(crate) fn pend(&mut self, pending: Pending) -> Result<(), HandshakeError> {
		if !matches!(self, Self::Idle) {
			return Err(HandshakeError::InvalidState);
		}

		*self = Self::Pending(pending);
		Ok(())
	}

	/// Hold `secret` from the agreement to completion. The agreement took the
	/// pending material first, so the store follows [`Self::Consumed`].
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the pending material was not taken.
	pub(crate) fn store(&mut self, secret: HandshakeSecret) -> Result<(), HandshakeError> {
		if !matches!(self, Self::Consumed) {
			return Err(HandshakeError::InvalidState);
		}

		*self = Self::Derived(secret);
		Ok(())
	}

	/// Take the pending material for the agreement.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the schedule holds no pending material.
	pub(crate) fn take_pending(&mut self) -> Result<Pending, HandshakeError> {
		let Self::Pending(pending) = mem::replace(self, Self::Consumed) else {
			return Err(HandshakeError::InvalidState);
		};

		Ok(pending)
	}

	/// The handshake secret, for the CMS acknowledgement seal and open ahead
	/// of completion.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the schedule holds no handshake secret.
	#[cfg(feature = "transport-cms")]
	pub(crate) fn derived(&self) -> Result<&HandshakeSecret, HandshakeError> {
		let Self::Derived(secret) = self else {
			return Err(HandshakeError::InvalidState);
		};

		Ok(secret)
	}

	/// Take the handshake secret for completion.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the schedule holds no handshake secret.
	pub(crate) fn take_derived(&mut self) -> Result<HandshakeSecret, HandshakeError> {
		let Self::Derived(secret) = mem::replace(self, Self::Consumed) else {
			return Err(HandshakeError::InvalidState);
		};

		Ok(secret)
	}
}

/// Epoch state retained past handshake completion for in-band rekeying.
///
/// Each orchestrator's `complete()` produces it alongside the session keys.
/// The epoch secret seeds the rekey KDF chain, and the transcript hash is
/// the chain root `hash_0`. The handshake secret itself drops at completion.
pub struct EpochMaterials {
	/// Current epoch secret, zeroized on drop and on rotation
	/// (RFC 9846, 7.2). Only `transport::rekey` reads it, and a build can
	/// include the handshake without the `transport-multiplex` consumers.
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

/// Epoch secret length in bytes: one 256-bit KDF chain link.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
const EPOCH_SECRET_SIZE: usize = 32;

/// The compressed SEC1 encoding of a handshake ephemeral public key.
///
/// The ECIES transcript takes the point at this width, so an ephemeral of any
/// other length fails before the signature check rather than hashing as a
/// variable-length leg beside the SPKI.
#[cfg(feature = "transport-ecies")]
pub(crate) trait CompressedPoint {
	/// The compressed SEC1 bytes of this point.
	///
	/// # Errors
	///
	/// - [`HandshakeError::OctetStringLengthError`] -- the curve's compressed
	///   point is not [`EC_PUBKEY_COMPRESSED_SIZE`] bytes wide.
	fn compressed_point(&self) -> Result<[u8; EC_PUBKEY_COMPRESSED_SIZE], HandshakeError>;
}

#[cfg(feature = "transport-ecies")]
impl<C> CompressedPoint for PublicKey<C>
where
	C: Curve + CurveArithmetic,
	<C as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
	fn compressed_point(&self) -> Result<[u8; EC_PUBKEY_COMPRESSED_SIZE], HandshakeError> {
		let point = self.to_encoded_point(true);
		let bytes = point.as_bytes();
		let sized = bytes
			.try_into()
			.map_err(|_| HandshakeError::OctetStringLengthError((bytes.len(), EC_PUBKEY_COMPRESSED_SIZE).into()))?;
		Ok(sized)
	}
}

/// A peer's ephemeral public key, parsed beside the static key it must differ
/// from.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) trait ServerEphemeral<C>
where
	C: CurveArithmetic,
{
	/// Parse `sec1` as the server's ephemeral for an agreement with this
	/// client's ephemeral.
	///
	/// The parser refuses a malformed, off-curve, or identity point, so no
	/// scalar multiplication runs on an invalid one, and the ephemeral is
	/// refused when it equals the static key `self`, because the agreement
	/// would then collapse into the static one the server's key recovers.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- `sec1` is not a point on the curve.
	/// - [`HandshakeError::ServerEphemeralIsStatic`] -- the point is the server's static key.
	fn server_ephemeral(&self, sec1: &[u8]) -> Result<PublicKey<C>, HandshakeError>;
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl<C> ServerEphemeral<C> for PublicKey<C>
where
	C: Curve + CurveArithmetic,
	<C as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
	fn server_ephemeral(&self, sec1: &[u8]) -> Result<PublicKey<C>, HandshakeError> {
		let ephemeral = PublicKey::<C>::from_sec1_bytes(sec1)?;
		if ephemeral == *self {
			return Err(HandshakeError::ServerEphemeralIsStatic);
		}

		Ok(ephemeral)
	}
}

/// ECDH key agreement on the handshake plane.
///
/// The KARI static step runs it with the client's [`SecretKey`] against the
/// server's static key, and the ephemeral-ephemeral step runs it with the same
/// [`SecretKey`] on the client or the [`EphemeralSecret`] the server drew for
/// one handshake. Every peer arrives as a parsed [`PublicKey`], so each point
/// has passed `from_sec1_bytes` before it reaches a scalar multiplication.
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

/// Provides session key finalization logic for all handshake orchestrators.
///
/// An orchestrator must implement [`Self::selected_profile`] to expose the
/// negotiated security profile. The trait provides the default HKDF-based key
/// derivation with entropy validation.
///
/// # Security properties
///
/// - The derivation enforces at least [`MIN_SALT_ENTROPY_BYTES`] of salt entropy.
/// - HKDF runs with per-direction domain separation ([`TIGHTBEAM_C2S_KDF_INFO`],
///   [`TIGHTBEAM_S2C_KDF_INFO`]), the RFC 5869 info-label pattern behind the
///   TLS 1.3 directional traffic secrets (RFC 9846, § 7.3).
/// - The key size follows the negotiated AEAD cipher profile.
/// - The underlying crypto primitives supply constant-time operations.
pub trait HandshakeFinalization<P>
where
	P: CryptoProvider,
{
	/// Return the profile negotiated through offer and accept, if any.
	fn selected_profile(&self) -> Option<RunnableProfile<P>>;

	/// Derive directional AEAD ciphers from the handshake secret and the
	/// context salt.
	///
	/// # Salt contract
	///
	/// - **CMS**: the transcript hash (32 bytes).
	/// - **ECIES**: `client_random || server_random` (64 bytes).
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- no profile is selected.
	/// - [`HandshakeError::InsufficientSaltEntropy`] -- the salt is shorter than [`MIN_SALT_ENTROPY_BYTES`].
	/// - [`HandshakeError::KdfError`] -- the KDF refused the key length.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused the derived key.
	fn derive_directional_aead(
		&self,
		secret: &HandshakeSecret,
		salt: KdfSalt<'_>,
	) -> Result<DirectionalCiphers<P::AeadCipher>, HandshakeError>
	where
		P::AeadCipher: KeyInit,
	{
		// A selected profile names the provider's own cipher, so the keys
		// derive under the identity the peer negotiated.
		self.selected_profile().ok_or(HandshakeError::InvalidState)?;
		DirectionalCiphers::derive::<P, _>(secret, salt)
	}
}

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

/// Provides alert attribute processing for all handshake orchestrators.
///
/// Every orchestrator implements this trait through a blanket impl. Call
/// [`Self::check_for_alert`] early in message processing to detect an abort
/// alert that the peer sent.
///
/// # Alert types
///
/// The codes of [`HandshakeAlert`](super::HandshakeAlert) are:
///
/// - `AuthRequired`: the peer requires mutual authentication.
/// - `VersionMismatch`: the protocol version is incompatible.
/// - `AlgorithmMismatch`: no mutual cryptographic algorithm exists.
/// - `DecryptFail`: decryption or signature verification failed.
/// - `FinishedIntegrityFail`: the transcript hash does not match.
pub trait HandshakeAlertHandler {
	/// Check `attrs` for an abort alert from the peer.
	///
	/// Abort alerts live in unprotected attributes, so they are advisory and
	/// unauthenticated.
	///
	/// # Errors
	///
	/// - [`HandshakeError::AbortReceived`] -- an alert with a known code is present.
	/// - [`HandshakeError::DuplicateAttribute`] -- the alert attribute repeats.
	/// - [`HandshakeError::InvalidAttributeArity`] -- the alert attribute is malformed.
	/// - [`HandshakeError::InvalidIntegerEncoding`] -- the alert code is not a valid INTEGER.
	/// - [`HandshakeError::IntegerOutOfRange`] -- the alert code is above `u8::MAX`.
	/// - [`HandshakeError::UnknownAlertCode`] -- the code names no alert.
	fn check_for_alert(&self, attrs: Option<&Attributes>) -> Result<(), HandshakeError> {
		if let Some(attrs) = attrs {
			if let Some(alert_attr) = attrs.find_unsigned_attr(HANDSHAKE_ABORT_ALERT)? {
				let alert = alert_attr.handshake_alert()?;
				return Err(HandshakeError::AbortReceived(alert));
			}
		}
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
	/// - [`HandshakeError::InvalidPublicKey`] -- the certificate key bytes fail SEC1 decoding.
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
	use crate::crypto::profiles::{AeadProvider, DefaultCryptoProvider};
	use crate::crypto::x509::attr::Attribute;
	use crate::der::asn1::{Any, SetOfVec};
	use crate::oids::AES_128_GCM;
	use crate::transport::handshake::negotiation::{NegotiationError, ProfileStrength};
	use crate::transport::handshake::HandshakeAlert;
	use std::error::Error;

	/// A policy that refuses every profile.
	struct RefuseAll;

	impl ProfileStrengthPolicy for RefuseAll {
		fn meets_floor(&self, _strength: &ProfileStrength) -> bool {
			false
		}
	}

	struct MockServer {
		profiles: Vec<SecurityProfileDesc>,
		refuse_all: bool,
	}

	impl HandshakeNegotiation<DefaultCryptoProvider> for MockServer {
		fn supported_profiles(&self) -> &[SecurityProfileDesc] {
			&self.profiles
		}

		fn strength_policy(&self) -> &dyn ProfileStrengthPolicy {
			match self.refuse_all {
				true => &RefuseAll,
				false => &DefaultStrengthFloor,
			}
		}
	}

	struct MockClient {
		profile: Option<RunnableProfile<DefaultCryptoProvider>>,
	}

	impl HandshakeFinalization<DefaultCryptoProvider> for MockClient {
		fn selected_profile(&self) -> Option<RunnableProfile<DefaultCryptoProvider>> {
			self.profile
		}
	}

	fn native_profile() -> SecurityProfileDesc {
		RunnableProfile::<DefaultCryptoProvider>::native().descriptor()
	}

	/// A descriptor that names an AEAD the default provider does not run.
	fn foreign_profile() -> SecurityProfileDesc {
		SecurityProfileDesc { aead: Some(AES_128_GCM), ..native_profile() }
	}

	fn mock_server(profiles: impl IntoIterator<Item = SecurityProfileDesc>) -> MockServer {
		MockServer { profiles: profiles.into_iter().collect(), refuse_all: false }
	}

	fn mock_client() -> MockClient {
		MockClient { profile: Some(RunnableProfile::native()) }
	}

	#[test]
	fn an_offer_selects_the_profile_the_provider_runs() -> Result<(), Box<dyn Error>> {
		let server = mock_server([foreign_profile(), native_profile()]);
		let offer = SecurityOffer::new(vec![foreign_profile(), native_profile()]);
		let selected = server.negotiate_profile(Some(&offer))?;
		assert_eq!(selected.descriptor(), native_profile());
		Ok(())
	}

	#[test]
	fn dealers_choice_skips_a_profile_the_provider_does_not_run() -> Result<(), Box<dyn Error>> {
		let server = mock_server([foreign_profile(), native_profile()]);
		let selected = server.negotiate_profile(None)?;
		assert_eq!(selected.descriptor(), native_profile());
		Ok(())
	}

	#[test]
	fn a_server_with_no_runnable_profile_refuses_to_negotiate() {
		let server = mock_server([foreign_profile()]);
		let result = server.negotiate_profile(None);
		assert!(matches!(
			result,
			Err(HandshakeError::NegotiationError(NegotiationError::UnrunnableProfile))
		));
	}

	#[test]
	fn a_runnable_profile_below_the_floor_is_refused() {
		let server = MockServer { profiles: vec![native_profile()], refuse_all: true };
		let result = server.negotiate_profile(None);
		assert!(matches!(
			result,
			Err(HandshakeError::NegotiationError(NegotiationError::BelowStrengthFloor))
		));
	}

	#[test]
	fn test_negotiate_profile_no_supported() {
		let server = mock_server([]);
		let result = server.negotiate_profile(None);
		assert!(matches!(result, Err(HandshakeError::NoSupportedProfiles)));
	}

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

	fn derive_directional(
		client: &MockClient,
		secret: &HandshakeSecret,
		salt: &[u8],
	) -> Result<DirectionalCiphers<<DefaultCryptoProvider as AeadProvider>::AeadCipher>, HandshakeError> {
		client.derive_directional_aead(secret, KdfSalt::new(salt))
	}

	#[test]
	fn test_derive_directional_aead_success() {
		let client = mock_client();

		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);
		let result = derive_directional(&client, &secret, &salt);
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

	/// A key schedule holds one pending value: a second `pend` is refused and
	/// the first value stays in place, so one handshake runs one agreement.
	#[test]
	fn a_second_pending_value_is_refused() -> Result<(), HandshakeError> {
		let mut schedule = KeySchedule::<u8>::Idle;
		schedule.pend(1)?;

		let refused = schedule.pend(2);
		assert!(matches!(refused, Err(HandshakeError::InvalidState)));
		assert!(matches!(schedule, KeySchedule::Pending(1)));
		Ok(())
	}

	/// A handshake secret is stored only after the pending take, so a store
	/// ahead of the agreement is refused and the schedule stays `Idle`.
	#[test]
	fn a_store_ahead_of_the_agreement_is_refused() {
		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);
		let mut schedule = KeySchedule::<u8>::Idle;

		let refused = schedule.store(secret);
		assert!(matches!(refused, Err(HandshakeError::InvalidState)));
		assert!(matches!(schedule, KeySchedule::Idle));
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
		let client = mock_client();

		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);
		let ciphers = derive_directional(&client, &secret, &salt)?;

		// Same nonce and plaintext under both directions must produce
		// different ciphertexts, proving the info labels separate the keys.
		let plaintext = b"directional key separation";
		let c2s_ciphertext = seal(&ciphers.client_to_server, plaintext.as_slice());
		let s2c_ciphertext = seal(&ciphers.server_to_client, plaintext.as_slice());
		assert_ne!(c2s_ciphertext, s2c_ciphertext);
		Ok(())
	}

	#[test]
	fn test_derive_directional_aead_is_deterministic() -> Result<(), HandshakeError> {
		let client = mock_client();

		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);
		let first = derive_directional(&client, &secret, &salt)?;
		let second = derive_directional(&client, &secret, &salt)?;

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
		let client = mock_client();

		let salt = [0x99u8; 8];
		let secret = handshake_secret(0x42, 0x11, &[0x99u8; 32]);
		let result = derive_directional(&client, &secret, &salt);
		assert!(matches!(
			result,
			Err(HandshakeError::InsufficientSaltEntropy { actual: 8, minimum: 16 })
		));
	}

	#[test]
	fn test_derive_directional_aead_no_profile() {
		let client = MockClient { profile: None };

		let salt = [0x99u8; 32];
		let secret = handshake_secret(0x42, 0x11, &salt);
		let result = derive_directional(&client, &secret, &salt);
		assert!(matches!(result, Err(HandshakeError::InvalidState)));
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

	/// An orchestrator stand-in that keeps the provided alert check.
	struct AlertProbe;

	impl HandshakeAlertHandler for AlertProbe {}

	/// An abort-alert attribute carrying `code`, as a peer sends it.
	fn abort_alert(code: u8) -> Result<Attribute, Box<dyn Error>> {
		let code = Any::encode_from(&code)?;
		Ok(Attribute { oid: HANDSHAKE_ABORT_ALERT, values: SetOfVec::try_from(vec![code])? })
	}

	#[test]
	fn an_abort_alert_attribute_aborts_the_handshake() -> Result<(), Box<dyn Error>> {
		let attrs = Attributes::try_from(vec![abort_alert(3)?])?;

		let checked = AlertProbe.check_for_alert(Some(&attrs));
		let expected = HandshakeAlert::AlgorithmMismatch;
		assert!(matches!(checked, Err(HandshakeError::AbortReceived(alert)) if alert == expected));
		Ok(())
	}

	/// A repeated abort alert fails closed as a duplicate attribute rather
	/// than reading as no alert and letting processing continue into the
	/// message body.
	#[test]
	fn a_duplicate_abort_alert_fails_closed() -> Result<(), Box<dyn Error>> {
		let attrs = Attributes::try_from(vec![abort_alert(3)?, abort_alert(4)?])?;
		let checked = AlertProbe.check_for_alert(Some(&attrs));
		assert!(matches!(checked, Err(HandshakeError::DuplicateAttribute)));
		Ok(())
	}
}
