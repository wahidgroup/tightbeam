//! Common traits for handshake orchestrators.
//!
//! The CMS and ECIES client and server implementations share these traits:
//!
//! - [`HandshakeNegotiation`] negotiates the profile on the server side.
//! - [`HandshakeFinalization`] finalizes the AEAD session keys for every orchestrator.
//! - [`HandshakeAlertHandler`] processes alert attributes for every orchestrator.

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
use crate::constants::TIGHTBEAM_EPOCH_KDF_INFO;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::x509::utils::CertificateExt;
use crate::transport::handshake::attributes::HandshakeAlertAttribute;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::x509::Certificate;

/// Provides profile negotiation logic for server-side handshake orchestrators.
///
/// A server must implement `supported_profiles()` to expose its configured
/// security profiles. The trait provides the default negotiation logic for
/// both the client-offered mode and the dealer's choice mode.
///
/// # Usage
///
/// - **Negotiation mode**: the client sends a `SecurityOffer`, and the server
///   selects the first mutual profile in *server* preference order.
/// - **Dealer's choice mode**: the client sends no offer, and the server uses
///   its first configured profile that meets the strength policy.
///
/// # Security
///
/// Both modes filter profiles through [`ProfileStrengthPolicy`] before
/// selection, so a weak profile left in `supported_profiles()` for
/// compatibility cannot be negotiated (CWE-757 downgrade resistance).
pub trait HandshakeNegotiation<P>
where
	P: CryptoProvider,
{
	/// Return the profiles in server preference order, most preferred first.
	fn supported_profiles(&self) -> &[SecurityProfileDesc];

	/// Minimum-strength policy applied before selection.
	///
	/// Defaults to [`DefaultStrengthFloor`] (256-bit AEAD key, >= 256-bit
	/// digest).
	fn strength_policy(&self) -> &dyn ProfileStrengthPolicy {
		&DefaultStrengthFloor
	}

	/// Negotiate a security profile with the peer.
	///
	/// Only a configured profile that `P` runs is eligible, so the selection
	/// never names an algorithm the provider does not run.
	///
	/// # Errors
	///
	/// - `NoSupportedProfiles` -- the server has no configured profile.
	/// - `NegotiationError(UnrunnableProfile)` -- no configured profile runs on `P`.
	/// - `NegotiationError(BelowStrengthFloor)` -- no runnable profile meets the policy.
	/// - `NegotiationError` -- no mutually supported profile exists.
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

/// Epoch state retained past handshake completion for in-band rekeying.
///
/// Each orchestrator's `complete()` produces it alongside the session keys.
/// The epoch secret seeds the rekey KDF chain, and the transcript hash is
/// the chain root `hash_0`. The raw handshake secret keeps its
/// zeroize-at-complete lifecycle.
pub struct EpochMaterials {
	/// Current epoch secret, zeroized on drop and on rotation
	/// (RFC 9846, 7.2). Only `transport::rekey` reads it, and a build can
	/// include the handshake without the `transport-multiplex` consumers.
	#[allow(dead_code)]
	pub(crate) secret: ZeroizingBytes,
	/// Epoch counter: 0 at handshake, incremented per rekey install.
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
	/// Derive the epoch-0 secret from handshake key material under the
	/// dedicated epoch info label.
	///
	/// The derivation uses the same `input_key` and `salt` pair as the
	/// directional traffic keys. The distinct label yields an independent
	/// secret (RFC 5869 domain separation), so retaining it never weakens the
	/// traffic keys.
	pub(crate) fn derive<P>(
		input_key: impl AsRef<[u8]>,
		salt: KdfSalt<'_>,
		transcript_hash: [u8; 32],
	) -> Result<Self, HandshakeError>
	where
		P: CryptoProvider,
	{
		let input_key = input_key.as_ref();
		let kdf_salt = Some(salt.as_bytes());
		let secret = P::Kdf::derive_dynamic_key(input_key, TIGHTBEAM_EPOCH_KDF_INFO, kdf_salt, EPOCH_SECRET_SIZE)?;
		let materials = Self { secret, epoch: 0, transcript_hash };
		Ok(materials)
	}
}

/// Epoch secret length in bytes: one 256-bit KDF chain link.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
const EPOCH_SECRET_SIZE: usize = 32;

/// Provides session key finalization logic for all handshake orchestrators.
///
/// An orchestrator must implement `selected_profile()` to expose the
/// negotiated security profile. The trait provides the default HKDF-based key
/// derivation with entropy validation.
///
/// # Security properties
///
/// - The derivation enforces at least `MIN_SALT_ENTROPY_BYTES` of salt entropy.
/// - HKDF runs with per-direction domain separation (`TIGHTBEAM_C2S_KDF_INFO`,
///   `TIGHTBEAM_S2C_KDF_INFO`), the RFC 5869 info-label pattern behind the TLS
///   1.3 directional traffic secrets (RFC 9846, § 7.3).
/// - The key size follows the negotiated AEAD cipher profile.
/// - The underlying crypto primitives supply constant-time operations.
pub trait HandshakeFinalization<P>
where
	P: CryptoProvider,
{
	/// Return the profile negotiated through offer and accept, if any.
	fn selected_profile(&self) -> Option<RunnableProfile<P>>;

	/// Derive directional AEAD ciphers from input key material and context
	/// salt.
	///
	/// # Salt contract
	///
	/// - **CMS**: the transcript hash (32 bytes).
	/// - **ECIES**: `client_random || server_random` (64 bytes).
	///
	/// # Errors
	///
	/// - `InvalidState` -- no profile is selected.
	/// - `InsufficientSaltEntropy` -- the salt is shorter than `MIN_SALT_ENTROPY_BYTES`.
	/// - `KdfError` -- the KDF refused the key length.
	/// - `InvalidKeyMaterialLength` -- the cipher refused the derived key.
	fn derive_directional_aead(
		&self,
		input_key: &[u8],
		salt: KdfSalt<'_>,
	) -> Result<DirectionalCiphers<P::AeadCipher>, HandshakeError>
	where
		P::AeadCipher: KeyInit,
	{
		// A selected profile names the provider's own cipher, so the keys
		// derive under the identity the peer negotiated.
		self.selected_profile().ok_or(HandshakeError::InvalidState)?;
		DirectionalCiphers::derive::<P>(input_key, salt)
	}
}

impl<C> DirectionalCiphers<C>
where
	C: KeyInit,
{
	/// Derive the directional AEAD ciphers of provider `P` from input key
	/// material.
	///
	/// This is the single derivation path that handshake finalization and epoch
	/// rotation share. The provider's cipher type fixes the key length, and the
	/// salt floor applies at every derivation.
	pub(crate) fn derive<P>(input_key: &[u8], salt: KdfSalt<'_>) -> Result<Self, HandshakeError>
	where
		P: CryptoProvider<AeadCipher = C>,
	{
		let key_size = <C as KeySizeUser>::key_size();
		let salt_len = salt.as_bytes().len();
		if salt_len < MIN_SALT_ENTROPY_BYTES {
			return Err(HandshakeError::InsufficientSaltEntropy { actual: salt_len, minimum: MIN_SALT_ENTROPY_BYTES });
		}

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
/// `check_for_alert()` early in message processing to detect an abort alert
/// that the peer sent.
///
/// # Alert types
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
	/// - `AbortReceived` -- an alert with a specific alert code is present.
	/// - `InvalidAttributeArity` -- the alert attribute is malformed.
	/// - `InvalidIntegerEncoding` -- the alert code is not a valid INTEGER.
	fn check_for_alert(&self, attrs: Option<&Attributes>) -> Result<(), HandshakeError> {
		if let Some(attrs) = attrs {
			if let Ok(Some(alert_attr)) = attrs.find_unsigned_attr(HANDSHAKE_ABORT_ALERT) {
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

	fn derive_directional(
		client: &MockClient,
		input_key: &[u8],
		salt: &[u8],
	) -> Result<DirectionalCiphers<<DefaultCryptoProvider as AeadProvider>::AeadCipher>, HandshakeError> {
		client.derive_directional_aead(input_key, KdfSalt::new(salt))
	}

	#[test]
	fn test_derive_directional_aead_success() {
		let client = mock_client();

		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 32];
		let result = derive_directional(&client, &input_key, &salt);
		assert!(result.is_ok());
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

		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 32];
		let ciphers = derive_directional(&client, &input_key, &salt)?;

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

		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 32];
		let first = derive_directional(&client, &input_key, &salt)?;
		let second = derive_directional(&client, &input_key, &salt)?;

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

		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 8]; // Only 8 bytes
		let result = derive_directional(&client, &input_key, &salt);
		assert!(matches!(
			result,
			Err(HandshakeError::InsufficientSaltEntropy { actual: 8, minimum: 16 })
		));
	}

	#[test]
	fn test_derive_directional_aead_no_profile() {
		let client = MockClient { profile: None };

		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 32];
		let result = derive_directional(&client, &input_key, &salt);
		assert!(matches!(result, Err(HandshakeError::InvalidState)));
	}

	#[test]
	fn test_derive_epoch_materials_shape() -> Result<(), HandshakeError> {
		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 32];
		let transcript = [0x07u8; 32];

		let materials = EpochMaterials::derive::<DefaultCryptoProvider>(&input_key, KdfSalt::new(&salt), transcript)?;
		assert_eq!(materials.epoch(), 0);
		assert_eq!(materials.transcript_hash(), transcript);
		assert_eq!(materials.secret.len(), EPOCH_SECRET_SIZE);

		Ok(())
	}

	#[test]
	fn test_derive_epoch_materials_is_deterministic() -> Result<(), HandshakeError> {
		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 32];
		let transcript = [0x07u8; 32];

		let first = EpochMaterials::derive::<DefaultCryptoProvider>(&input_key, KdfSalt::new(&salt), transcript)?;
		let second = EpochMaterials::derive::<DefaultCryptoProvider>(&input_key, KdfSalt::new(&salt), transcript)?;
		assert_eq!(first.secret, second.secret);

		Ok(())
	}

	#[test]
	fn test_derive_epoch_materials_separates_inputs() -> Result<(), HandshakeError> {
		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 32];
		let other_key = [0x43u8; 32];
		let other_salt = [0x9Au8; 32];
		let transcript = [0x07u8; 32];

		let shared_salt = KdfSalt::new(&salt);
		let changed_salt = KdfSalt::new(&other_salt);
		let base = EpochMaterials::derive::<DefaultCryptoProvider>(&input_key, shared_salt, transcript)?;
		let keyed = EpochMaterials::derive::<DefaultCryptoProvider>(&other_key, shared_salt, transcript)?;
		let salted = EpochMaterials::derive::<DefaultCryptoProvider>(&input_key, changed_salt, transcript)?;
		assert_ne!(base.secret, keyed.secret);
		assert_ne!(base.secret, salted.secret);

		Ok(())
	}

	/// An orchestrator stand-in that keeps the provided alert check.
	struct AlertProbe;

	impl HandshakeAlertHandler for AlertProbe {}

	#[test]
	fn an_abort_alert_attribute_aborts_the_handshake() -> Result<(), Box<dyn Error>> {
		let code = Any::encode_from(&3u8)?;
		let alert = Attribute { oid: HANDSHAKE_ABORT_ALERT, values: SetOfVec::try_from(vec![code])? };
		let attrs = Attributes::try_from(vec![alert])?;

		let checked = AlertProbe.check_for_alert(Some(&attrs));
		let expected = HandshakeAlert::AlgorithmMismatch;
		assert!(matches!(checked, Err(HandshakeError::AbortReceived(alert)) if alert == expected));
		Ok(())
	}
}
